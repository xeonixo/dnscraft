//! `/api/v1/listeners` CRUD.
//!
//! Listener entries are versioned config. Validation mirrors the listeners
//! module's own rules and forwards its stable codes (`listeners.config.*`)
//! rather than a generic control-api code.

use std::net::SocketAddr;

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
    IdBody, actor, array, array_mut, if_match, json_body, module_error, relay_config_family_write,
    remove_by_id, service, stored_snapshot, upsert_by_id, valid_id,
};
use crate::api::response::success;
use crate::error::ControlApiError;
use crate::server::AppState;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ListenerBody {
    id: String,
    protocol: String,
    address: String,
    #[serde(default)]
    exposure: Option<String>,
    #[serde(default)]
    h3: bool,
    /// Cluster node ids that bind this listener; empty = every node.
    #[serde(default)]
    nodes: Vec<String>,
}

impl ListenerBody {
    pub(crate) fn into_json(self) -> Result<Value, ControlApiError> {
        if !valid_id(&self.id) {
            return Err(module_error(
                "listeners.config.invalid",
                "listener id must match [a-z0-9-]{1,64}",
            ));
        }
        if !matches!(
            self.protocol.as_str(),
            "udp53" | "tcp53" | "dot" | "doh" | "doq"
        ) {
            return Err(module_error(
                "listeners.config.invalid",
                "protocol must be one of udp53, tcp53, dot, doh, doq",
            ));
        }
        let address: SocketAddr = self.address.parse().map_err(|_| {
            module_error(
                "listeners.config.invalid",
                "address must be a socket address such as 127.0.0.1:53",
            )
        })?;
        let exposure = self.exposure.as_deref().unwrap_or("local");
        if !matches!(exposure, "local" | "public") {
            return Err(module_error(
                "listeners.config.invalid",
                "exposure must be local or public",
            ));
        }
        if exposure == "public" && matches!(self.protocol.as_str(), "udp53" | "tcp53") {
            return Err(module_error(
                "listeners.config.public_plaintext",
                "plaintext DNS must not be exposed publicly",
            ));
        }
        if self.h3 && self.protocol != "doh" {
            return Err(module_error(
                "listeners.config.invalid",
                "h3 is only valid for protocol doh",
            ));
        }
        let mut nodes = Vec::new();
        for node in &self.nodes {
            let trimmed = node.trim();
            if trimmed.is_empty() {
                continue;
            }
            if !valid_id(trimmed) {
                return Err(module_error(
                    "listeners.config.invalid",
                    "node id must match [a-z0-9-]{1,64}",
                ));
            }
            if !nodes.iter().any(|n| n == trimmed) {
                nodes.push(trimmed.to_owned());
            }
        }
        Ok(json!({
            "id": self.id,
            "protocol": self.protocol,
            "address": address.to_string(),
            "exposure": exposure,
            "h3": self.h3,
            "nodes": nodes,
        }))
    }
}

/// Maps legacy serde enum names (`Udp53`, `Local`) to the wire form the UI expects.
fn normalize_listener_wire(listener: &mut Value) {
    let Some(obj) = listener.as_object_mut() else {
        return;
    };
    if let Some(protocol) = obj.get("protocol").and_then(Value::as_str) {
        let canonical = match protocol {
            "Udp53" | "udp53" => "udp53",
            "Tcp53" | "tcp53" => "tcp53",
            "Dot" | "dot" => "dot",
            "Doh" | "doh" => "doh",
            "Doq" | "doq" => "doq",
            other => other,
        };
        obj.insert("protocol".to_owned(), json!(canonical));
    }
    if let Some(exposure) = obj.get("exposure").and_then(Value::as_str) {
        let canonical = match exposure {
            "Local" | "local" => "local",
            "Public" | "public" => "public",
            other => other,
        };
        obj.insert("exposure".to_owned(), json!(canonical));
    }
}

/// `GET /api/v1/listeners`.
pub(crate) async fn list_listeners(
    State(state): State<AppState>,
) -> Result<impl IntoResponse, ControlApiError> {
    let snapshot = stored_snapshot(service(&state)?).await?;
    let mut listeners = array(&snapshot, "listeners", "listeners");
    for row in &mut listeners {
        normalize_listener_wire(row);
    }
    Ok(success(json!({
        "listeners": listeners,
    })))
}

/// `POST|PUT /api/v1/listeners` — create or replace a listener by id.
pub(crate) async fn put_listener(
    State(state): State<AppState>,
    auth: Option<Extension<Authenticated>>,
    headers: HeaderMap,
    body: Result<Json<ListenerBody>, JsonRejection>,
) -> Result<impl IntoResponse, ControlApiError> {
    let listener = json_body(body, "listeners.config.invalid")?.into_json()?;
    let id = listener["id"].as_str().unwrap_or_default().to_owned();
    if let Some(response) = relay_config_family_write(
        &state,
        "PUT",
        "/api/v1/listeners",
        listener.clone(),
        auth.clone(),
        &headers,
    )
    .await?
    {
        return Ok(response.into_response());
    }
    let service = service(&state)?;
    let mut snapshot = stored_snapshot(service).await?;
    // GL2: creating/updating a public listener opens the public gate. The UI
    // has no separate toggle; refusing the write when the gate is closed was a
    // dead end for operators.
    if listener
        .get("exposure")
        .and_then(Value::as_str)
        .is_some_and(|e| e == "public")
    {
        ensure_public_gate_enabled(&mut snapshot);
    }
    let replaced = upsert_by_id(
        array_mut(&mut snapshot, "listeners", "listeners")?,
        &id,
        listener.clone(),
    );
    let version = service
        .replace(snapshot, &actor(auth), if_match(&headers))
        .await?;
    Ok(success(json!({
        "version": version,
        "listener": listener,
        "created": !replaced,
    }))
    .into_response())
}

/// Sets `listeners.public.enabled = true` on the versioned snapshot.
fn ensure_public_gate_enabled(snapshot: &mut Value) {
    let Some(root) = snapshot.as_object_mut() else {
        return;
    };
    let listeners = root
        .entry("listeners")
        .or_insert_with(|| json!({ "listeners": [], "public": {} }));
    let Some(obj) = listeners.as_object_mut() else {
        return;
    };
    let public = obj.entry("public").or_insert_with(|| json!({}));
    if let Some(public) = public.as_object_mut() {
        public.insert("enabled".to_owned(), Value::Bool(true));
    }
}

/// `DELETE /api/v1/listeners` — body `{ "id": "..." }`.
pub(crate) async fn delete_listener(
    State(state): State<AppState>,
    auth: Option<Extension<Authenticated>>,
    headers: HeaderMap,
    body: Result<Json<IdBody>, JsonRejection>,
) -> Result<impl IntoResponse, ControlApiError> {
    let body = json_body(body, "listeners.config.invalid")?;
    if let Some(response) = relay_config_family_write(
        &state,
        "DELETE",
        "/api/v1/listeners",
        json!({ "id": body.id }),
        auth.clone(),
        &headers,
    )
    .await?
    {
        return Ok(response.into_response());
    }
    let service = service(&state)?;
    let mut snapshot = stored_snapshot(service).await?;
    remove_by_id(
        array_mut(&mut snapshot, "listeners", "listeners")?,
        &body.id,
    )
    .ok_or_else(|| ControlApiError::NotFound {
        what: format!("listener {}", body.id),
    })?;
    let version = service
        .replace(snapshot, &actor(auth), if_match(&headers))
        .await?;
    Ok(success(json!({ "version": version, "deleted": true, "id": body.id })).into_response())
}
