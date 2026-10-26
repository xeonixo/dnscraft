//! `/api/v1/tls` configuration (singleton).
//!
//! The TLS section is validated against the `tls` module's documented rules
//! before the atomic apply, forwarding `tls.config.invalid`. The Cloudflare API
//! token is supplied out-of-band and never accepted here; it is redacted on
//! store anyway.

use axum::Extension;
use axum::Json;
use axum::extract::State;
use axum::extract::rejection::JsonRejection;
use axum::http::HeaderMap;
use axum::http::header::IF_MATCH;
use axum::response::IntoResponse;
use serde_json::{Map, Value, json};

use crate::api::auth::Authenticated;
use crate::api::config_routes::{json_body, module_error, service, stored_snapshot};
use crate::api::response::success;
use crate::config_apply::ConfigActor;
use crate::error::ControlApiError;
use crate::server::AppState;

/// Keys accepted inside the TLS config object.
const TLS_KEYS: [&str; 8] = [
    "public_domain",
    "extra_sans",
    "key_type",
    "renew_before",
    "expiry_warn",
    "acme",
    "cloudflare",
    "dyndns",
];

fn actor(auth: Option<Extension<Authenticated>>) -> ConfigActor {
    match auth {
        Some(Extension(auth)) => ConfigActor::new(auth.actor_id(), auth.actor_type().as_str()),
        None => ConfigActor::local(),
    }
}

fn if_match(headers: &HeaderMap) -> Option<&str> {
    headers.get(IF_MATCH).and_then(|value| value.to_str().ok())
}

/// Validates the TLS config object, forwarding `tls.config.invalid`.
fn validate_tls(value: &Value) -> Result<(), ControlApiError> {
    let Some(map) = value.as_object() else {
        return Err(module_error(
            "tls.config.invalid",
            "TLS config must be a JSON object",
        ));
    };
    for key in map.keys() {
        if !TLS_KEYS.contains(&key.as_str()) {
            return Err(module_error(
                "tls.config.invalid",
                &format!("unknown field `{key}`"),
            ));
        }
    }
    require_string(map, "public_domain")?;
    if let Some(sans) = map.get("extra_sans") {
        let Some(sans) = sans.as_array() else {
            return Err(module_error(
                "tls.config.invalid",
                "extra_sans must be an array",
            ));
        };
        if !sans.is_empty() {
            return Err(module_error(
                "tls.config.invalid",
                "extra_sans must be empty in v1",
            ));
        }
    }
    if let Some(key_type) = map.get("key_type") {
        let valid = matches!(
            key_type.as_str(),
            Some("ecdsa_p256" | "ecdsa_p384" | "p256" | "p384")
        );
        if !valid {
            return Err(module_error(
                "tls.config.invalid",
                "key_type must be ecdsa_p256 or ecdsa_p384",
            ));
        }
    }
    if let Some(acme) = map.get("acme") {
        let Some(acme) = acme.as_object() else {
            return Err(module_error("tls.config.invalid", "acme must be an object"));
        };
        let enabled = acme.get("enabled").and_then(Value::as_bool).unwrap_or(true);
        if enabled {
            let email = acme.get("email").and_then(Value::as_str).unwrap_or("");
            if email.is_empty() {
                return Err(module_error(
                    "tls.config.invalid",
                    "acme.email is required when ACME is enabled",
                ));
            }
        }
    }
    if let Some(dyndns) = map.get("dyndns") {
        let Some(dyndns) = dyndns.as_object() else {
            return Err(module_error(
                "tls.config.invalid",
                "dyndns must be an object",
            ));
        };
        if dyndns.get("proxied").and_then(Value::as_bool) == Some(true) {
            return Err(module_error(
                "tls.config.invalid",
                "dyndns.proxied must be false",
            ));
        }
        let enabled = dyndns
            .get("enabled")
            .and_then(Value::as_bool)
            .unwrap_or(true);
        let hostname = dyndns.get("hostname").and_then(Value::as_str).unwrap_or("");
        if enabled && hostname.is_empty() {
            return Err(module_error(
                "tls.config.invalid",
                "dyndns.hostname is required when DynDNS is enabled",
            ));
        }
    }
    Ok(())
}

fn require_string(map: &Map<String, Value>, key: &str) -> Result<(), ControlApiError> {
    match map.get(key) {
        Some(Value::String(value)) if !value.is_empty() => Ok(()),
        _ => Err(module_error(
            "tls.config.invalid",
            &format!("`{key}` must be a non-empty string"),
        )),
    }
}

/// `GET /api/v1/tls`.
pub(crate) async fn get_tls(
    State(state): State<AppState>,
) -> Result<impl IntoResponse, ControlApiError> {
    let snapshot = stored_snapshot(service(&state)?).await?;
    let tls = snapshot.get("tls").cloned().unwrap_or_else(|| json!({}));
    Ok(success(json!({ "tls": tls })))
}

/// `PUT|POST /api/v1/tls` — replace the TLS config section.
pub(crate) async fn put_tls(
    State(state): State<AppState>,
    auth: Option<Extension<Authenticated>>,
    headers: HeaderMap,
    body: Result<Json<Value>, JsonRejection>,
) -> Result<impl IntoResponse, ControlApiError> {
    let tls = json_body(body, "tls.config.invalid")?;
    validate_tls(&tls)?;
    let service = service(&state)?;
    let mut snapshot = stored_snapshot(service).await?;
    let section = snapshot
        .get_mut("tls")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| ControlApiError::Internal {
            message: "stored config snapshot is malformed".to_owned(),
        })?;
    *section = tls.as_object().cloned().unwrap_or_default();
    let version = service
        .replace(snapshot, &actor(auth), if_match(&headers))
        .await?;
    Ok(success(json!({ "version": version, "tls": tls })))
}

/// `DELETE /api/v1/tls` — clear the TLS config section.
pub(crate) async fn delete_tls(
    State(state): State<AppState>,
    auth: Option<Extension<Authenticated>>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, ControlApiError> {
    let service = service(&state)?;
    let mut snapshot = stored_snapshot(service).await?;
    let section = snapshot
        .get_mut("tls")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| ControlApiError::Internal {
            message: "stored config snapshot is malformed".to_owned(),
        })?;
    let removed = !section.is_empty();
    section.clear();
    let version = service
        .replace(snapshot, &actor(auth), if_match(&headers))
        .await?;
    Ok(success(json!({ "version": version, "deleted": removed })))
}
