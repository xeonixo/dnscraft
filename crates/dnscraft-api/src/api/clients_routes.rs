//! `/api/v1/clients` and `/api/v1/clients/manual` routes.
//!
//! Manual IP/CIDR entries are versioned config. The client directory itself is
//! engine state, so `GET /clients` reports the manual entries it owns and an
//! empty synced directory until a `ClientEngine` adapter is wired in.

use std::net::IpAddr;

use axum::Extension;
use axum::Json;
use axum::extract::State;
use axum::extract::rejection::JsonRejection;
use axum::http::HeaderMap;
use axum::http::header::IF_MATCH;
use axum::response::IntoResponse;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::api::auth::Authenticated;
use crate::api::config_routes::{
    array, array_mut, json_body, module_error, service, stored_snapshot,
};
use crate::api::response::success;
use crate::config_apply::ConfigActor;
use crate::error::ControlApiError;
use crate::server::AppState;

fn actor(auth: Option<Extension<Authenticated>>) -> ConfigActor {
    match auth {
        Some(Extension(auth)) => ConfigActor::new(auth.actor_id(), auth.actor_type().as_str()),
        None => ConfigActor::local(),
    }
}

fn if_match(headers: &HeaderMap) -> Option<&str> {
    headers.get(IF_MATCH).and_then(|value| value.to_str().ok())
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
                if !valid_cidr(cidr) {
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

fn valid_cidr(value: &str) -> bool {
    let Some((address, prefix)) = value.split_once('/') else {
        return false;
    };
    let Ok(address) = address.parse::<IpAddr>() else {
        return false;
    };
    let Ok(prefix) = prefix.parse::<u8>() else {
        return false;
    };
    prefix <= if address.is_ipv4() { 32 } else { 128 }
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

/// `GET /api/v1/clients` — manual entries plus the (not yet wired) directory.
pub(crate) async fn list_clients(
    State(state): State<AppState>,
) -> Result<impl IntoResponse, ControlApiError> {
    let snapshot = stored_snapshot(service(&state)?).await?;
    Ok(success(json!({
        "clients": Vec::<Value>::new(),
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

/// `POST /api/v1/clients/sync` — trigger a UniFi sync.
///
/// No `ClientEngine` adapter is wired into this build yet, so the request is
/// rejected with the module-namespaced `clients.sync.not_configured`.
pub(crate) async fn sync_clients(
    State(state): State<AppState>,
) -> Result<Json<Value>, ControlApiError> {
    let _ = service(&state)?;
    Err(module_error(
        "clients.sync.not_configured",
        "no UniFi client engine is configured",
    ))
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
