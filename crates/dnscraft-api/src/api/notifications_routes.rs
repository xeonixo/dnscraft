//! `GET|PUT /api/v1/notifications` and `POST /api/v1/notifications/test` (WX7).
//!
//! Channel definitions are versioned config (`notifications` section), so a
//! write gets a config version, an audit row and the same serialized apply lock
//! as any other section. The webhook secret is write-only: it is stored in the
//! `kv` table, reported as `has_secret`, and never returned or audited. Every
//! egress rule is in [`crate::webhooks`].

use axum::Extension;
use axum::Json;
use axum::extract::State;
use axum::extract::rejection::JsonRejection;
use axum::http::HeaderMap;
use axum::response::IntoResponse;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::api::auth::Authenticated;
use crate::api::config_routes::{actor, if_match, service, stored_snapshot};
use crate::api::response::success;
use crate::audit::{Audit, ConfigChangeRecord};
use crate::error::ControlApiError;
use crate::server::AppState;
use crate::system::unix_now;
use crate::webhooks::{
    EVENT_CATALOG, MAX_SECRET_BYTES, NotificationError, SECTION, channel_secret, deliver,
    parse_channel_url, payload, redacted_url, secret_key, validate_section,
};

const INVALID: &str = "control_api.notifications.invalid";
const HOST_NOT_ALLOWED: &str = "control_api.notifications.host_not_allowed";

/// The `allowed_hosts` entries of a stored section.
fn allowed_hosts(section: &Value) -> Vec<String> {
    section
        .get("allowed_hosts")
        .and_then(Value::as_array)
        .map(|hosts| {
            hosts
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

/// Fails closed: every channel host must match `allowed_hosts`.
fn check_hosts(section: &Value) -> Result<(), NotificationError> {
    let allowed = allowed_hosts(section);
    for channel in section
        .get("channels")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let url = channel
            .get("url")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let parsed = parse_channel_url(url)?;
        let host = parsed.host_str().unwrap_or_default();
        if !crate::webhooks::host_allowed(host, &allowed) {
            return Err(NotificationError::new(
                HOST_NOT_ALLOWED,
                "host is not in notifications.allowed_hosts",
            ));
        }
    }
    Ok(())
}

/// `GET /api/v1/notifications` — channels without URL query, userinfo or secrets.
pub(crate) async fn get_notifications(
    State(state): State<AppState>,
) -> Result<impl IntoResponse, ControlApiError> {
    let snapshot = stored_snapshot(service(&state)?).await?;
    let section = snapshot.get(SECTION).cloned().unwrap_or(json!({}));
    let mut channels = Vec::new();
    for channel in section
        .get("channels")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let id = channel
            .get("id")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let has_secret = match state.db() {
            Some(db) => channel_secret(db, id).await?.is_some(),
            None => false,
        };
        channels.push(json!({
            "id": id,
            "type": "webhook",
            "enabled": channel.get("enabled").and_then(Value::as_bool).unwrap_or(true),
            "url": channel.get("url").and_then(Value::as_str).and_then(redacted_url),
            "has_secret": has_secret,
            "events": channel.get("events").cloned().unwrap_or(json!([])),
        }));
    }
    Ok(success(json!({
        "channels": channels,
        "allowed_hosts": allowed_hosts(&section),
        "allow_private_destinations": section
            .get("allow_private_destinations")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        "event_catalog": EVENT_CATALOG,
    })))
}

/// `PUT /api/v1/notifications` — replaces the channel set atomically.
///
/// Each channel may carry `secret`: a string sets it, `null` clears it, and an
/// omitted key keeps the stored value.
pub(crate) async fn put_notifications(
    State(state): State<AppState>,
    auth: Option<Extension<Authenticated>>,
    headers: HeaderMap,
    body: Result<Json<Value>, JsonRejection>,
) -> Result<impl IntoResponse, ControlApiError> {
    let Json(body) =
        body.map_err(|rejection| NotificationError::new(INVALID, rejection.body_text()))?;
    let channels = match body.get("channels") {
        None => Vec::new(),
        Some(Value::Array(list)) => list.clone(),
        Some(_) => return Err(NotificationError::new(INVALID, "channels must be a list").into()),
    };
    let mut clean_channels = Vec::with_capacity(channels.len());
    let mut secret_ops: Vec<(String, Option<String>)> = Vec::new();
    for channel in channels {
        let mut clean = channel;
        let id = clean
            .get("id")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        let secret = clean.as_object_mut().and_then(|map| map.remove("secret"));
        match secret {
            None => {}
            Some(Value::Null) => secret_ops.push((id, None)),
            Some(Value::String(value)) if !value.is_empty() && value.len() <= MAX_SECRET_BYTES => {
                secret_ops.push((id, Some(value)));
            }
            Some(_) => {
                return Err(NotificationError::new(
                    INVALID,
                    "secret must be a non-empty string of at most 256 bytes, or null",
                )
                .into());
            }
        }
        clean_channels.push(clean);
    }
    let section = json!({
        "allowed_hosts": body.get("allowed_hosts").cloned().unwrap_or(json!([])),
        "allow_private_destinations": body
            .get("allow_private_destinations")
            .cloned()
            .unwrap_or(json!(false)),
        "channels": clean_channels,
    });
    validate_section(&section)?;
    check_hosts(&section)?;

    let service = service(&state)?;
    let mut snapshot = stored_snapshot(service).await?;
    let previous: Vec<String> = snapshot
        .get(SECTION)
        .and_then(|section| section.get("channels"))
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|channel| channel.get("id").and_then(Value::as_str).map(str::to_owned))
        .collect();
    snapshot
        .as_object_mut()
        .ok_or_else(|| ControlApiError::Internal {
            message: "stored config is not an object".to_owned(),
        })?
        .insert(SECTION.to_owned(), section.clone());
    let version = service
        .replace(snapshot, &actor(auth), if_match(&headers))
        .await?;

    if let Some(db) = state.db() {
        for (id, value) in secret_ops {
            match value {
                Some(secret) => db.kv_set(&secret_key(&id), &secret).await?,
                None => db.kv_delete(&secret_key(&id)).await?,
            }
        }
        let kept: Vec<String> = section
            .get("channels")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|channel| channel.get("id").and_then(Value::as_str).map(str::to_owned))
            .collect();
        for removed in previous.iter().filter(|id| !kept.contains(id)) {
            db.kv_delete(&secret_key(removed)).await?;
        }
    }
    Ok(success(json!({ "config_version": version })))
}

/// Body of `POST /api/v1/notifications/test`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TestBody {
    channel_id: String,
}

/// `POST /api/v1/notifications/test` — one synthetic delivery; audited without
/// the URL or the secret.
pub(crate) async fn post_notification_test(
    State(state): State<AppState>,
    auth: Option<Extension<Authenticated>>,
    body: Result<Json<TestBody>, JsonRejection>,
) -> Result<impl IntoResponse, ControlApiError> {
    let Json(body) =
        body.map_err(|rejection| NotificationError::new(INVALID, rejection.body_text()))?;
    let service = service(&state)?;
    let snapshot = stored_snapshot(service).await?;
    let section = snapshot.get(SECTION).cloned().unwrap_or(json!({}));
    let channel = section
        .get("channels")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .find(|channel| channel.get("id").and_then(Value::as_str) == Some(body.channel_id.as_str()))
        .cloned()
        .ok_or_else(|| {
            NotificationError::new(
                "control_api.notifications.unknown_channel",
                "no such channel",
            )
        })?;
    let url = parse_channel_url(
        channel
            .get("url")
            .and_then(Value::as_str)
            .unwrap_or_default(),
    )?;
    let secret = match state.db() {
        Some(db) => channel_secret(db, &body.channel_id).await?,
        None => None,
    };
    let message = payload(
        "notifications.test",
        "info",
        "notifications",
        json!({ "channel_id": body.channel_id }),
        unix_now(&state),
    );
    let allow_private = section
        .get("allow_private_destinations")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let result = deliver(
        &url,
        &allowed_hosts(&section),
        allow_private,
        secret.as_deref(),
        &message,
    )
    .await;

    if let Some(db) = state.db() {
        let who = actor(auth);
        let record = ConfigChangeRecord {
            node_id: service.node_id().to_owned(),
            actor_id: who.actor_id.clone(),
            actor_type: who.actor_type.clone(),
            action: "notifications.test".to_owned(),
            config_version: None,
            before: None,
            after: Some(json!({ "channel_id": body.channel_id })),
            result: if result.is_ok() { "ok" } else { "error" }.to_owned(),
            error_code: result.as_ref().err().map(|error| error.code.to_owned()),
        };
        if let Err(error) = Audit::new(db.clone()).record_config_change(record).await {
            tracing::error!(error = %error, "notification test audit failed");
        }
    }
    let delivery = result?;
    Ok(success(json!({
        "channel_id": body.channel_id,
        "delivered": true,
        "status": delivery.status,
        "latency_ms": delivery.latency_ms,
    })))
}
