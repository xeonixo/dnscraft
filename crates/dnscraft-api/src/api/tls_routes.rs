//! `/api/v1/tls` configuration (singleton) plus the TLS admin actions.
//!
//! The TLS section is validated against the `tls` module's documented rules
//! before the atomic apply, forwarding `tls.config.invalid`. The Cloudflare API
//! token is supplied out-of-band and never accepted here; it is redacted on
//! store anyway.
//!
//! The action endpoints (`renew`, `revoke`, `rotate`, `preflight`, `dyndns`,
//! manual certificate upload) delegate to [`crate::TlsAdmin`], audit every
//! mutation through the shared config service, and never return private-key or
//! Cloudflare token material.

use std::sync::Arc;

use axum::Extension;
use axum::Json;
use axum::extract::State;
use axum::extract::rejection::JsonRejection;
use axum::http::HeaderMap;
use axum::response::IntoResponse;
use serde::Deserialize;
use serde_json::{Map, Value, json};

use crate::Secret;
use crate::api::auth::Authenticated;
use crate::api::config_routes::{
    actor, if_match, json_body, module_error, service, stored_snapshot,
};
use crate::api::response::success;
use crate::config_apply::ConfigActor;
use crate::error::ControlApiError;
use crate::notifications::{EVENT_CERT_EXPIRING, EVENT_DYNDNS_FAILURE, TlsWebhook};
use crate::server::AppState;
use crate::tls::{TlsAdmin, TlsMode};

/// Keys accepted inside the TLS config object.
const TLS_KEYS: [&str; 13] = [
    "public_domain",
    "extra_sans",
    "key_type",
    "renew_before",
    "expiry_warn",
    "acme",
    "cloudflare",
    "dyndns",
    "mode",
    "manual",
    "trust_pin",
    "dns_provider",
    "notifications",
];

/// Keys accepted inside `tls.notifications`.
const NOTIFICATION_KEYS: [&str; 3] = ["webhook_url", "on_expiry", "on_dyndns_failure"];

/// Validates the TLS config object, forwarding `tls.config.invalid`.
pub(crate) fn validate_tls(value: &Value) -> Result<(), ControlApiError> {
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
    if let Some(notifications) = map.get("notifications") {
        let Some(notifications) = notifications.as_object() else {
            return Err(module_error(
                "tls.config.invalid",
                "notifications must be an object",
            ));
        };
        for key in notifications.keys() {
            if !NOTIFICATION_KEYS.contains(&key.as_str()) {
                return Err(module_error(
                    "tls.config.invalid",
                    &format!("unknown field `notifications.{key}`"),
                ));
            }
        }
        if let Some(url) = notifications.get("webhook_url") {
            let Some(url) = url.as_str() else {
                return Err(module_error(
                    "tls.config.invalid",
                    "notifications.webhook_url must be a string",
                ));
            };
            let valid = url::Url::parse(url)
                .ok()
                .is_some_and(|url| url.scheme() == "https");
            if !valid {
                return Err(module_error(
                    "tls.config.invalid",
                    "notifications.webhook_url must be an https URL",
                ));
            }
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

// ---------------------------------------------------------------------------
// TLS admin actions
// ---------------------------------------------------------------------------

/// Body of `PUT /api/v1/tls/certificate`.
///
/// The private key is moved into a [`Secret`] before it reaches the engine, so
/// it is zeroized on drop and can never be serialized or logged.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ManualCertBody {
    cert_pem: String,
    key_pem: String,
    #[serde(default)]
    chain_pem: Option<String>,
}

/// Body of `POST /api/v1/tls/revoke`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RevokeBody {
    reason: String,
}

/// The attached admin surface, or `control_api.not_ready` when the embedding
/// did not wire a TLS engine.
fn tls_admin(state: &AppState) -> Result<&Arc<dyn TlsAdmin>, ControlApiError> {
    state.tls_admin().ok_or_else(|| ControlApiError::NotReady {
        module: "tls".to_owned(),
    })
}

/// Records one mutating TLS action through the shared config audit path.
async fn audit(state: &AppState, actor: &ConfigActor, action: &str, error_code: Option<&str>) {
    if let Ok(config) = service(state) {
        config
            .record_action(actor, action, None, None, error_code)
            .await;
    }
}

/// The configured webhook, if any.
async fn webhook(state: &AppState) -> Option<TlsWebhook> {
    let config = service(state).ok()?;
    let snapshot = stored_snapshot(config).await.ok()?;
    TlsWebhook::from_tls_section(snapshot.get("tls")?)
}

/// Injection order for the webhook `time` field.
fn now_rfc3339(state: &AppState) -> String {
    time::OffsetDateTime::from(state.clock().now())
        .format(time::macros::format_description!(
            "[year]-[month]-[day]T[hour]:[minute]:[second]Z"
        ))
        .unwrap_or_default()
}

/// `GET /api/v1/tls/status` — the typed TLS DTO (contract § G).
pub(crate) async fn get_tls_status(
    State(state): State<AppState>,
) -> Result<impl IntoResponse, ControlApiError> {
    let status = state
        .tls_status_async()
        .await
        .ok_or_else(|| ControlApiError::NotReady {
            module: "tls".to_owned(),
        })?;
    Ok(success(status))
}

/// `PUT /api/v1/tls/certificate` — install an operator-uploaded certificate.
pub(crate) async fn put_tls_certificate(
    State(state): State<AppState>,
    auth: Option<Extension<Authenticated>>,
    body: Result<Json<ManualCertBody>, JsonRejection>,
) -> Result<impl IntoResponse, ControlApiError> {
    let ManualCertBody {
        cert_pem,
        key_pem,
        chain_pem,
    } = json_body(body, "tls.cert.manual.invalid")?;
    let actor = actor(auth);
    if let Err(error) = validate_manual_cert(&cert_pem, &key_pem, chain_pem.as_deref()) {
        audit(&state, &actor, "tls.certificate.upload", Some(error.code())).await;
        return Err(error);
    }
    let key = Secret::new(key_pem);
    let result = tls_admin(&state)?
        .upload_manual_cert(&cert_pem, &key, chain_pem.as_deref())
        .await;
    audit(
        &state,
        &actor,
        "tls.certificate.upload",
        result.as_ref().err().map(ControlApiError::code),
    )
    .await;
    result?;
    Ok(success(json!({ "mode": TlsMode::Manual.as_str() })))
}

/// Checks that the uploaded material looks like a PEM certificate + key.
fn validate_manual_cert(
    cert_pem: &str,
    key_pem: &str,
    chain_pem: Option<&str>,
) -> Result<(), ControlApiError> {
    // Certificate fields must not smuggle key material (GA25): a key appended
    // to the certificate or chain would otherwise be stored outside `key_pem`.
    let is_cert =
        |pem: &str| pem.contains("-----BEGIN CERTIFICATE-----") && !pem.contains("PRIVATE KEY");
    if !is_cert(cert_pem) {
        return Err(module_error(
            "tls.cert.manual.invalid",
            "cert_pem must contain a PEM certificate",
        ));
    }
    if !key_pem.contains("PRIVATE KEY") {
        return Err(module_error(
            "tls.cert.manual.invalid",
            "key_pem must contain a PEM private key",
        ));
    }
    if let Some(chain) = chain_pem
        && !chain.trim().is_empty()
        && !is_cert(chain)
    {
        return Err(module_error(
            "tls.cert.manual.invalid",
            "chain_pem must contain PEM certificates only",
        ));
    }
    Ok(())
}

/// `GET /api/v1/tls/certificate` — fullchain PEM export, certificates only.
pub(crate) async fn get_tls_certificate(
    State(state): State<AppState>,
) -> Result<impl IntoResponse, ControlApiError> {
    let pem = tls_admin(&state)?.export_cert()?;
    // Defence in depth: a certificate export must never carry key material.
    if pem.to_ascii_uppercase().contains("PRIVATE KEY") {
        return Err(ControlApiError::Internal {
            message: "certificate export contained private key material".to_owned(),
        });
    }
    Ok(success(json!({ "fullchain_pem": pem })))
}

/// `POST /api/v1/tls/renew` — trigger an issuance/renewal now.
pub(crate) async fn trigger_tls_renew(
    State(state): State<AppState>,
    auth: Option<Extension<Authenticated>>,
) -> Result<impl IntoResponse, ControlApiError> {
    let actor = actor(auth);
    let result = tls_admin(&state)?.renew_now().await;
    let error_code = result.as_ref().err().map(ControlApiError::code);
    audit(&state, &actor, "tls.cert.renew", error_code).await;

    if let Some(webhook) = webhook(&state).await
        && webhook.on_expiry()
    {
        let expiring = matches!(error_code, Some("tls.cert.expiring" | "tls.cert.expired"))
            || state
                .tls_status_async()
                .await
                .is_some_and(|status| status.cert_expiring || status.cert_expired);
        if expiring {
            let code = error_code
                .filter(|code| matches!(*code, "tls.cert.expiring" | "tls.cert.expired"))
                .unwrap_or("tls.cert.expiring");
            webhook
                .send(
                    EVENT_CERT_EXPIRING,
                    code,
                    "certificate is expiring or expired",
                    &now_rfc3339(&state),
                )
                .await;
        }
    }

    result?;
    Ok(success(json!({ "started": true })))
}

/// `POST /api/v1/tls/revoke` — revoke the active certificate.
pub(crate) async fn trigger_tls_revoke(
    State(state): State<AppState>,
    auth: Option<Extension<Authenticated>>,
    body: Result<Json<RevokeBody>, JsonRejection>,
) -> Result<impl IntoResponse, ControlApiError> {
    let RevokeBody { reason } = json_body(body, "tls.config.invalid")?;
    let actor = actor(auth);
    if reason.trim().is_empty() || reason.len() > 256 {
        let error = module_error(
            "tls.config.invalid",
            "reason must be a non-empty string of at most 256 characters",
        );
        audit(&state, &actor, "tls.cert.revoke", Some(error.code())).await;
        return Err(error);
    }
    let result = tls_admin(&state)?.revoke(reason.trim()).await;
    audit(
        &state,
        &actor,
        "tls.cert.revoke",
        result.as_ref().err().map(ControlApiError::code),
    )
    .await;
    result?;
    Ok(success(json!({ "revoked": true })))
}

/// `POST /api/v1/tls/rotate` — force a re-issue with a fresh key pair.
pub(crate) async fn trigger_tls_rotate(
    State(state): State<AppState>,
    auth: Option<Extension<Authenticated>>,
) -> Result<impl IntoResponse, ControlApiError> {
    let actor = actor(auth);
    let result = tls_admin(&state)?.rotate_key().await;
    audit(
        &state,
        &actor,
        "tls.cert.rotate",
        result.as_ref().err().map(ControlApiError::code),
    )
    .await;
    result?;
    Ok(success(json!({ "rotated": true })))
}

/// `POST /api/v1/tls/preflight` — dry-run connectivity / configuration check.
pub(crate) async fn trigger_tls_preflight(
    State(state): State<AppState>,
) -> Result<impl IntoResponse, ControlApiError> {
    let report = tls_admin(&state)?.preflight().await?;
    Ok(success(report))
}

/// `POST /api/v1/tls/dyndns` — trigger a DynDNS update now.
pub(crate) async fn trigger_tls_dyndns(
    State(state): State<AppState>,
    auth: Option<Extension<Authenticated>>,
) -> Result<impl IntoResponse, ControlApiError> {
    let actor = actor(auth);
    let result = tls_admin(&state)?.dyndns_now().await;
    let error_code = result.as_ref().err().map(ControlApiError::code);
    audit(&state, &actor, "tls.dyndns.update", error_code).await;

    if let Err(error) = &result
        && let Some(webhook) = webhook(&state).await
        && webhook.on_dyndns_failure()
    {
        webhook
            .send(
                EVENT_DYNDNS_FAILURE,
                error.code(),
                "DynDNS update failed",
                &now_rfc3339(&state),
            )
            .await;
    }

    Ok(success(result?))
}

/// `GET /api/v1/tls/records` — expected DNS record inventory and check.
pub(crate) async fn get_tls_records(
    State(state): State<AppState>,
) -> Result<impl IntoResponse, ControlApiError> {
    let records = tls_admin(&state)?.record_inventory().await?;
    Ok(success(records))
}

/// `GET /api/v1/tls/account` — ACME account status.
pub(crate) async fn get_tls_account(
    State(state): State<AppState>,
) -> Result<impl IntoResponse, ControlApiError> {
    let account = tls_admin(&state)?.account_status().await?;
    Ok(success(account))
}

/// `GET /api/v1/tls/order` — current ACME order / progress.
pub(crate) async fn get_tls_order(
    State(state): State<AppState>,
) -> Result<impl IntoResponse, ControlApiError> {
    let order = tls_admin(&state)?.order_status()?;
    Ok(success(order))
}

/// `GET /api/v1/tls/audit` — DynDNS audit trail.
pub(crate) async fn get_tls_audit(
    State(state): State<AppState>,
) -> Result<impl IntoResponse, ControlApiError> {
    let audit = tls_admin(&state)?.dyndns_audit().await?;
    Ok(success(audit))
}
