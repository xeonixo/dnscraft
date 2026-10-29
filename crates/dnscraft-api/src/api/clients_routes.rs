//! `/api/v1/clients` and `/api/v1/clients/manual` routes.
//!
//! Manual IP/CIDR entries are versioned config. The synced directory is engine
//! state: the binary implements [`ClientDirectory`] over the real `ClientEngine`
//! (GA6). Without one, `GET /clients` reports only the manual entries and
//! `POST /clients/sync` answers `clients.sync.not_configured`.

use std::net::IpAddr;
use std::sync::Arc;

use axum::Extension;
use axum::Json;
use axum::extract::rejection::JsonRejection;
use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::response::IntoResponse;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::api::auth::Authenticated;
use crate::api::config_routes::{
    actor, array, array_mut, if_match, json_body, module_error, relay_config_family_write, service,
    stored_snapshot, valid_ip_or_cidr,
};
use crate::api::response::success;
use crate::error::ControlApiError;
use crate::server::AppState;
use crate::unifi_secrets::{has_api_key, set_api_key};

/// One entry of the synced client directory (UniFi or manual), in the public
/// shape of `GET /api/v1/clients` (D5). Built by the binary's adapter.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirectoryClient {
    /// Stable client id.
    pub id: String,
    /// Display name.
    pub name: String,
    /// Normalised single DNS label.
    pub dns_label: String,
    /// Parent domain used for the client's FQDN.
    pub local_domain: String,
    /// `"unifi"` or `"manual"`.
    pub source: &'static str,
    /// Known addresses.
    pub ips: Vec<IpAddr>,
    /// Known MAC addresses, canonical text.
    pub macs: Vec<String>,
    /// 802.1Q VLAN id, when known.
    pub vlan: Option<u16>,
    /// Whether the client is currently online.
    pub online: bool,
    /// RFC 3339 time of the last observation, when known.
    pub last_seen: Option<String>,
}

/// Outcome of one UniFi sync, as reported by `POST /clients/sync`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SyncSummary {
    /// Lookup generation after the attempt.
    pub generation: u64,
    /// Whether the snapshot was rebuilt.
    pub rebuilt: bool,
    /// Clients in the lookup after the attempt.
    pub client_count: usize,
    /// IP claims resolved by dropping a loser during the merge.
    pub ip_conflicts: u64,
}

/// UniFi directory snapshot for cluster uplink / push.
#[derive(Clone, Debug)]
pub struct DirectoryExport {
    /// Bound UniFi profile id.
    pub profile_id: String,
    /// Engine generation after the last successful sync.
    pub generation: u64,
    /// Serialised observations (clients cache wire shape).
    pub observations: Value,
    /// Serialised networks (clients cache wire shape).
    pub networks: Value,
}

/// Read and sync access to the client directory (GA6). Implementations map
/// engine failures to their stable `clients.*` codes; no secret material is
/// ever returned.
#[async_trait::async_trait]
pub trait ClientDirectory: Send + Sync {
    /// The current directory entries.
    fn clients(&self) -> Vec<DirectoryClient>;
    /// Runs one sync now.
    async fn sync(&self) -> Result<SyncSummary, ControlApiError>;

    /// Installs or clears the in-memory UniFi API key (`SecretPush` / local PUT).
    fn set_api_key(&self, _key: Option<String>) {}

    /// Applies a cluster `ClientsDirectoryPush` when bound and not sync_owner.
    async fn apply_directory_push(
        &self,
        _profile_id: &str,
        _observations: Value,
        _networks: Value,
    ) -> Result<(), ControlApiError> {
        Ok(())
    }

    /// Cached UniFi directory for uplink after a successful owner sync.
    fn directory_export(&self) -> Option<DirectoryExport> {
        None
    }

    /// Whether this node is sync_owner of its bound UniFi profile.
    fn is_sync_owner(&self) -> bool {
        false
    }

    /// Fires on every installed directory snapshot, so background polls reach
    /// the cluster too (not only the manual sync route).
    fn subscribe_changes(&self) -> Option<tokio::sync::watch::Receiver<u64>> {
        None
    }
}

fn directory(state: &AppState) -> Option<&Arc<dyn ClientDirectory>> {
    state.client_directory()
}

fn client_json(client: &DirectoryClient) -> Value {
    json!({
        "id": client.id,
        "name": client.name,
        "dns_label": client.dns_label,
        "local_domain": client.local_domain,
        "source": client.source,
        "ips": client.ips.iter().map(ToString::to_string).collect::<Vec<_>>(),
        "macs": client.macs,
        "vlan": client.vlan,
        "online": client.online,
        "last_seen": client.last_seen,
    })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ManualEntryBody {
    name: String,
    #[serde(default)]
    ip: Option<String>,
    #[serde(default)]
    cidr: Option<String>,
    #[serde(default)]
    domain: Option<String>,
}

impl ManualEntryBody {
    pub(crate) fn into_json(self) -> Result<Value, ControlApiError> {
        if self.name.is_empty() {
            return Err(module_error(
                "clients.config.invalid",
                "manual entry name must not be empty",
            ));
        }
        let identity = match (self.ip.as_deref(), self.cidr.as_deref()) {
            (Some(ip), None) => {
                ip.parse::<IpAddr>().map_err(|_| {
                    module_error("clients.config.invalid", "ip is not a valid address")
                })?;
                ip.to_owned()
            }
            (None, Some(cidr)) => {
                if cidr.split_once('/').is_none() || !valid_ip_or_cidr(cidr) {
                    return Err(module_error(
                        "clients.config.invalid",
                        "cidr is not a valid CIDR range",
                    ));
                }
                cidr.to_owned()
            }
            _ => {
                return Err(module_error(
                    "clients.config.invalid",
                    "exactly one of ip or cidr is required",
                ));
            }
        };
        Ok(json!({
            "name": self.name,
            "ip": self.ip,
            "cidr": self.cidr,
            "domain": self.domain,
            "identity": identity,
        }))
    }
}

fn identity(entry: &Value) -> Option<&str> {
    entry.get("identity").and_then(Value::as_str)
}

pub(crate) fn name(entry: &Value) -> Option<&str> {
    entry.get("name").and_then(Value::as_str)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NameBody {
    name: String,
}

/// `GET /api/v1/clients/manual`.
pub(crate) async fn list_manual(
    State(state): State<AppState>,
) -> Result<impl IntoResponse, ControlApiError> {
    let snapshot = stored_snapshot(service(&state)?).await?;
    Ok(success(json!({
        "manual": array(&snapshot, "clients", "manual"),
    })))
}

/// `GET /api/v1/clients` — the synced directory (empty without an adapter)
/// plus the manual entries from config.
pub(crate) async fn list_clients(
    State(state): State<AppState>,
) -> Result<impl IntoResponse, ControlApiError> {
    let snapshot = stored_snapshot(service(&state)?).await?;
    let clients: Vec<Value> = directory(&state)
        .map(|dir| dir.clients().iter().map(client_json).collect())
        .unwrap_or_default();
    Ok(success(json!({
        "clients": clients,
        "manual": array(&snapshot, "clients", "manual"),
    })))
}

/// `POST /api/v1/clients/manual` — add an entry; the name must be new.
pub(crate) async fn create_manual(
    State(state): State<AppState>,
    auth: Option<Extension<Authenticated>>,
    headers: HeaderMap,
    body: Result<Json<ManualEntryBody>, JsonRejection>,
) -> Result<impl IntoResponse, ControlApiError> {
    let entry = json_body(body, "clients.config.invalid")?.into_json()?;
    if let Some(response) = relay_config_family_write(
        &state,
        "POST",
        "/api/v1/clients/manual",
        entry.clone(),
        auth.clone(),
        &headers,
    )
    .await?
    {
        return Ok(response.into_response());
    }
    let service = service(&state)?;
    let mut snapshot = stored_snapshot(service).await?;
    let entries = array_mut(&mut snapshot, "clients", "manual")?;
    let entry_name = entry["name"].as_str().unwrap_or_default();
    if entries
        .iter()
        .any(|existing| name(existing) == Some(entry_name))
    {
        return Err(module_error(
            "clients.name.collision",
            "a manual entry with that name already exists",
        ));
    }
    reject_conflict(entries, &entry, None)?;
    entries.push(entry.clone());
    let version = service
        .replace(snapshot, &actor(auth), if_match(&headers))
        .await?;
    Ok(success(json!({ "version": version, "entry": entry })).into_response())
}

/// `PUT /api/v1/clients/manual` — create or replace an entry by name.
pub(crate) async fn put_manual(
    State(state): State<AppState>,
    auth: Option<Extension<Authenticated>>,
    headers: HeaderMap,
    body: Result<Json<ManualEntryBody>, JsonRejection>,
) -> Result<impl IntoResponse, ControlApiError> {
    let entry = json_body(body, "clients.config.invalid")?.into_json()?;
    if let Some(response) = relay_config_family_write(
        &state,
        "PUT",
        "/api/v1/clients/manual",
        entry.clone(),
        auth.clone(),
        &headers,
    )
    .await?
    {
        return Ok(response.into_response());
    }
    let service = service(&state)?;
    let mut snapshot = stored_snapshot(service).await?;
    let entries = array_mut(&mut snapshot, "clients", "manual")?;
    let entry_name = entry["name"].as_str().unwrap_or_default();
    reject_conflict(entries, &entry, Some(entry_name))?;
    let replaced = if let Some(existing) = entries
        .iter_mut()
        .find(|existing| name(existing) == Some(entry_name))
    {
        *existing = entry.clone();
        true
    } else {
        entries.push(entry.clone());
        false
    };
    let version = service
        .replace(snapshot, &actor(auth), if_match(&headers))
        .await?;
    Ok(success(json!({
        "version": version,
        "entry": entry,
        "created": !replaced,
    }))
    .into_response())
}

/// `DELETE /api/v1/clients/manual` — body `{ "name": "..." }`.
pub(crate) async fn delete_manual(
    State(state): State<AppState>,
    auth: Option<Extension<Authenticated>>,
    headers: HeaderMap,
    body: Result<Json<NameBody>, JsonRejection>,
) -> Result<impl IntoResponse, ControlApiError> {
    let body = json_body(body, "clients.config.invalid")?;
    if let Some(response) = relay_config_family_write(
        &state,
        "DELETE",
        "/api/v1/clients/manual",
        json!({ "name": body.name }),
        auth.clone(),
        &headers,
    )
    .await?
    {
        return Ok(response.into_response());
    }
    let service = service(&state)?;
    let mut snapshot = stored_snapshot(service).await?;
    let entries = array_mut(&mut snapshot, "clients", "manual")?;
    let index = entries
        .iter()
        .position(|entry| name(entry) == Some(body.name.as_str()))
        .ok_or_else(|| ControlApiError::NotFound {
            what: format!("manual entry {}", body.name),
        })?;
    entries.remove(index);
    let version = service
        .replace(snapshot, &actor(auth), if_match(&headers))
        .await?;
    Ok(success(json!({
        "version": version,
        "deleted": true,
        "name": body.name,
    }))
    .into_response())
}

/// `POST /api/v1/clients/sync` — trigger a UniFi sync and report its outcome.
///
/// Without a [`ClientDirectory`] the request is rejected with
/// `clients.sync.not_configured`.
pub(crate) async fn sync_clients(
    State(state): State<AppState>,
) -> Result<impl IntoResponse, ControlApiError> {
    let _ = service(&state)?;
    let Some(dir) = directory(&state) else {
        return Err(module_error(
            "clients.sync.not_configured",
            "no UniFi client engine is configured",
        ));
    };
    let report = dir.sync().await?;
    publish_directory_after_sync(&state, dir.as_ref()).await;
    Ok(success(json!({
        "generation": report.generation,
        "rebuilt": report.rebuilt,
        "client_count": report.client_count,
        "ip_conflicts": report.ip_conflicts,
    })))
}

/// After a sync_owner sync: fan-out on the master, or uplink from a sub-node.
pub(crate) async fn publish_directory_after_sync(state: &AppState, dir: &dyn ClientDirectory) {
    if !dir.is_sync_owner() {
        return;
    }
    let Some(export) = dir.directory_export() else {
        return;
    };
    if let Some(broadcast) = state.cluster_broadcast() {
        broadcast.push_clients_directory(
            &export.profile_id,
            export.generation,
            &export.observations,
            &export.networks,
        );
        return;
    }
    if let Some(client) = state.cluster_uplink()
        && let Err(error) = client
            .post_clients_directory(
                &export.profile_id,
                export.generation,
                &export.observations,
                &export.networks,
            )
            .await
    {
        tracing::warn!(error = %error, "clients directory uplink failed");
    }
}

/// `GET /api/v1/clients/unifi` — profiles, bindings, and `has_api_key` (no secrets).
pub(crate) async fn get_unifi(
    State(state): State<AppState>,
) -> Result<impl IntoResponse, ControlApiError> {
    let service = service(&state)?;
    let snapshot = stored_snapshot(service).await?;
    let clients = snapshot
        .get("clients")
        .cloned()
        .unwrap_or_else(|| json!({}));
    let profiles = clients
        .get("unifi_profiles")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let bindings = clients
        .get("unifi_bindings")
        .cloned()
        .unwrap_or_else(|| json!({}));
    let db = state.db().ok_or_else(|| ControlApiError::NotReady {
        module: "database".into(),
    })?;
    let mut enriched = Vec::with_capacity(profiles.len());
    for profile in profiles {
        let id = profile
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_owned();
        let mut row = profile;
        if let Some(obj) = row.as_object_mut() {
            obj.insert(
                "has_api_key".into(),
                Value::Bool(has_api_key(db, &id).await?),
            );
        }
        enriched.push(row);
    }
    // Legacy flat unifi when profiles are empty.
    if enriched.is_empty()
        && let Some(unifi) = clients.get("unifi").cloned()
    {
        let mut row = unifi;
        if let Some(obj) = row.as_object_mut() {
            obj.insert("id".into(), json!("default"));
            obj.insert(
                "has_api_key".into(),
                Value::Bool(has_api_key(db, "default").await?),
            );
        }
        enriched.push(row);
    }
    Ok(success(json!({
        "profiles": enriched,
        "bindings": bindings,
        "local_domain": clients.get("local_domain"),
        "local_domain_mode": clients.get("local_domain_mode"),
    })))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ApiKeyBody {
    /// Write-only: omit to keep, `null` to clear, string to set.
    #[serde(default)]
    api_key: OptionalApiKey,
}

#[derive(Default)]
enum OptionalApiKey {
    #[default]
    Absent,
    Clear,
    Set(String),
}

impl<'de> Deserialize<'de> for OptionalApiKey {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        match Option::<String>::deserialize(deserializer)? {
            None => Ok(Self::Clear),
            Some(value) => Ok(Self::Set(value)),
        }
    }
}

/// `PUT /api/v1/clients/unifi-profiles/{id}/api-key` — write-only UniFi API key.
pub(crate) async fn put_unifi_api_key(
    State(state): State<AppState>,
    Path(id): Path<String>,
    body: Result<Json<ApiKeyBody>, JsonRejection>,
) -> Result<impl IntoResponse, ControlApiError> {
    let _ = service(&state)?;
    if id.trim().is_empty() {
        return Err(module_error(
            "clients.config.invalid",
            "profile id must not be empty",
        ));
    }
    let Json(body) = match body {
        Ok(v) => v,
        Err(rejection) => return Err(ControlApiError::config(rejection.body_text())),
    };
    let db = state.db().ok_or_else(|| ControlApiError::NotReady {
        module: "database".into(),
    })?;
    let (updated, has_key, push_key) = match body.api_key {
        OptionalApiKey::Absent => {
            return Ok(success(json!({ "id": id, "updated": false })));
        }
        OptionalApiKey::Clear => {
            set_api_key(db, &id, None).await?;
            if let Some(dir) = directory(&state) {
                dir.set_api_key(None);
            }
            (true, false, None)
        }
        OptionalApiKey::Set(value) => {
            set_api_key(db, &id, Some(value.as_str())).await?;
            if let Some(dir) = directory(&state) {
                dir.set_api_key(Some(value.clone()));
            }
            (true, true, Some(value))
        }
    };
    push_unifi_secret_to_owner(&state, &id, push_key.as_deref()).await;
    Ok(success(json!({
        "id": id,
        "updated": updated,
        "has_api_key": has_key,
    })))
}

/// Looks up `sync_owner` for `profile_id` and pushes the key over the cluster stream.
async fn push_unifi_secret_to_owner(state: &AppState, profile_id: &str, api_key: Option<&str>) {
    let Some(broadcast) = state.cluster_broadcast() else {
        return;
    };
    let Ok(service) = service(state) else {
        return;
    };
    let Ok(snapshot) = stored_snapshot(service).await else {
        return;
    };
    let Some(owner) = snapshot
        .get("clients")
        .and_then(|c| c.get("unifi_profiles"))
        .and_then(|p| p.as_array())
        .and_then(|profiles| {
            profiles.iter().find_map(|profile| {
                (profile.get("id").and_then(|v| v.as_str()) == Some(profile_id))
                    .then(|| {
                        profile
                            .get("sync_owner")
                            .and_then(|v| v.as_str())
                            .map(str::to_owned)
                    })
                    .flatten()
            })
        })
    else {
        return;
    };
    broadcast.push_unifi_secret(&owner, profile_id, api_key);
}

/// Rejects an identity (`ip`/`cidr`) already used by another manual entry.
///
/// `skip_name` excludes the entry being replaced, so a PUT may keep its own
/// address.
pub(crate) fn reject_conflict(
    entries: &[Value],
    candidate: &Value,
    skip_name: Option<&str>,
) -> Result<(), ControlApiError> {
    let Some(candidate_identity) = identity(candidate) else {
        return Ok(());
    };
    if entries
        .iter()
        .any(|entry| identity(entry) == Some(candidate_identity) && name(entry) != skip_name)
    {
        return Err(module_error(
            "clients.ip.conflict",
            "another manual entry already uses that address or range",
        ));
    }
    Ok(())
}
