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
use axum::extract::State;
use axum::extract::rejection::JsonRejection;
use axum::http::HeaderMap;
use axum::response::IntoResponse;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::api::auth::Authenticated;
use crate::api::config_routes::{
    actor, array, array_mut, if_match, json_body, module_error, service, stored_snapshot,
    valid_ip_or_cidr,
};
use crate::api::response::success;
use crate::error::ControlApiError;
use crate::server::AppState;

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

/// Read and sync access to the client directory (GA6). Implementations map
/// engine failures to their stable `clients.*` codes; no secret material is
/// ever returned.
#[async_trait::async_trait]
pub trait ClientDirectory: Send + Sync {
    /// The current directory entries.
    fn clients(&self) -> Vec<DirectoryClient>;
    /// Runs one sync now.
    async fn sync(&self) -> Result<SyncSummary, ControlApiError>;
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
    Ok(success(json!({ "version": version, "entry": entry })))
}

/// `PUT /api/v1/clients/manual` — create or replace an entry by name.
pub(crate) async fn put_manual(
    State(state): State<AppState>,
    auth: Option<Extension<Authenticated>>,
    headers: HeaderMap,
    body: Result<Json<ManualEntryBody>, JsonRejection>,
) -> Result<impl IntoResponse, ControlApiError> {
    let entry = json_body(body, "clients.config.invalid")?.into_json()?;
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
    })))
}

/// `DELETE /api/v1/clients/manual` — body `{ "name": "..." }`.
pub(crate) async fn delete_manual(
    State(state): State<AppState>,
    auth: Option<Extension<Authenticated>>,
    headers: HeaderMap,
    body: Result<Json<NameBody>, JsonRejection>,
) -> Result<impl IntoResponse, ControlApiError> {
    let body = json_body(body, "clients.config.invalid")?;
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
    })))
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
    Ok(success(json!({
        "generation": report.generation,
        "rebuilt": report.rebuilt,
        "client_count": report.client_count,
        "ip_conflicts": report.ip_conflicts,
    })))
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
