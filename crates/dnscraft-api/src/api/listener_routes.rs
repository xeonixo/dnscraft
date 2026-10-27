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
    IdBody, actor, array, array_mut, if_match, json_body, module_error, remove_by_id, service,
    stored_snapshot, upsert_by_id, valid_id,
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
        Ok(json!({
            "id": self.id,
            "protocol": self.protocol,
            "address": address.to_string(),
            "exposure": exposure,
            "h3": self.h3,
        }))
    }
}

/// `GET /api/v1/listeners`.
pub(crate) async fn list_listeners(
    State(state): State<AppState>,
) -> Result<impl IntoResponse, ControlApiError> {
    let snapshot = stored_snapshot(service(&state)?).await?;
    Ok(success(json!({
        "listeners": array(&snapshot, "listeners", "listeners"),
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
    let service = service(&state)?;
    let mut snapshot = stored_snapshot(service).await?;
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
    })))
}

/// `DELETE /api/v1/listeners` — body `{ "id": "..." }`.
pub(crate) async fn delete_listener(
    State(state): State<AppState>,
    auth: Option<Extension<Authenticated>>,
    headers: HeaderMap,
    body: Result<Json<IdBody>, JsonRejection>,
) -> Result<impl IntoResponse, ControlApiError> {
    let body = json_body(body, "listeners.config.invalid")?;
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
    Ok(success(
        json!({ "version": version, "deleted": true, "id": body.id }),
    ))
}
