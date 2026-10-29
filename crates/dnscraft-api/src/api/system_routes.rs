//! `GET /api/v1/update/check` (WP2), `GET /api/v1/backups` and
//! `PUT /api/v1/backups/settings` (WP3). Logic lives in [`crate::system`].
//!
//! The update check is viewer-readable and answers `enabled: false` without any
//! outbound call while the opt-in `control_api_settings.update_check` is off.
//! Backups are admin-only (RBAC maps `/api/v1/backups` to `ApiAdmin`), because
//! the response exposes a filesystem path.

use axum::Extension;
use axum::Json;
use axum::extract::State;
use axum::extract::rejection::JsonRejection;
use axum::http::HeaderMap;
use axum::response::IntoResponse;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::api::auth::Authenticated;
use crate::api::config_routes::{actor, if_match, json_body, service, stored_snapshot};
use crate::api::response::{success, unix_rfc3339};
use crate::error::ControlApiError;
use crate::server::AppState;
use crate::system::{
    BACKUP_RETENTION_MAX, BackupSettings, SETTINGS_SECTION, backup_files, backup_settings,
    cached_latest_release, is_newer, last_backup, next_run_at, unix_now, update_check_enabled,
    web_access_public,
};

/// Version of the running binary, as reported by the update check.
const CURRENT_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Invalid `PUT /api/v1/backups/settings` body.
const BACKUPS_INVALID: &str = "control_api.backups.invalid";

/// `GET /api/v1/update/check` — opt-in latest-release notice (WP2).
pub(crate) async fn get_update_check(
    State(state): State<AppState>,
) -> Result<impl IntoResponse, ControlApiError> {
    let snapshot = match state.config_service() {
        Some(service) => service.current().await?.1.unwrap_or(Value::Null),
        None => Value::Null,
    };
    if !update_check_enabled(&snapshot) {
        return Ok(success(json!({
            "enabled": false,
            "current": CURRENT_VERSION,
            "latest": null,
            "update_available": false,
            "release_url": null,
            "checked_at": null,
        })));
    }
    let checked_at = unix_rfc3339(unix_now(&state));
    match cached_latest_release(&state).await {
        Ok(release) => Ok(success(json!({
            "enabled": true,
            "current": CURRENT_VERSION,
            "latest": release.latest,
            "update_available": is_newer(&release.latest, CURRENT_VERSION),
            "release_url": release.url,
            "checked_at": checked_at,
        }))),
        // An unreachable release service is a coded field, not a server error.
        Err(code) => Ok(success(json!({
            "enabled": true,
            "current": CURRENT_VERSION,
            "latest": null,
            "update_available": false,
            "release_url": null,
            "checked_at": checked_at,
            "error": { "code": code },
        }))),
    }
}

/// `GET /api/v1/backups` — backup status and retention (WP3, admin).
pub(crate) async fn get_backups(
    State(state): State<AppState>,
) -> Result<impl IntoResponse, ControlApiError> {
    let db = state.db().ok_or_else(|| ControlApiError::NotFound {
        what: "database".to_owned(),
    })?;
    let dir = state
        .backup_dir()
        .ok_or_else(|| ControlApiError::NotFound {
            what: "backup directory".to_owned(),
        })?;
    let snapshot = stored_snapshot(service(&state)?).await?;
    let settings = backup_settings(&snapshot);
    let last = last_backup(db).await?;
    let now = unix_now(&state);
    let next_run = settings
        .enabled
        .then(|| unix_rfc3339(next_run_at(last.as_ref(), now)));
    let files = backup_files(dir)?.len();
    Ok(success(json!({
        "enabled": settings.enabled,
        "directory": dir.to_string_lossy(),
        "retention_count": settings.retention_count,
        "files": files,
        "last_run": last,
        "next_run": next_run,
    })))
}

/// Body of `PUT /api/v1/web-access`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct WebAccessBody {
    public_enabled: bool,
}

/// `GET /api/v1/web-access` — whether public sources may reach the web UI (admin).
pub(crate) async fn get_web_access(
    State(state): State<AppState>,
) -> Result<impl IntoResponse, ControlApiError> {
    let snapshot = stored_snapshot(service(&state)?).await?;
    Ok(success(
        json!({ "public_enabled": web_access_public(&snapshot) }),
    ))
}

/// `PUT /api/v1/web-access` — opt in or out of public web access (admin). Applied live.
pub(crate) async fn put_web_access(
    State(state): State<AppState>,
    auth: Option<Extension<Authenticated>>,
    headers: HeaderMap,
    body: Result<Json<WebAccessBody>, JsonRejection>,
) -> Result<impl IntoResponse, ControlApiError> {
    let body = json_body(body, "control_api.web_access.invalid")?;
    let service = service(&state)?;
    let mut snapshot = stored_snapshot(service).await?;
    snapshot
        .as_object_mut()
        .ok_or_else(|| ControlApiError::Internal {
            message: "stored config is not an object".to_owned(),
        })?
        .entry(SETTINGS_SECTION)
        .or_insert_with(|| json!({}))
        .as_object_mut()
        .ok_or_else(|| ControlApiError::Internal {
            message: "control_api_settings is not an object".to_owned(),
        })?
        .insert(
            "web_access".to_owned(),
            json!({ "public_enabled": body.public_enabled }),
        );
    let version = service
        .replace(snapshot, &actor(auth), if_match(&headers))
        .await?;
    Ok(success(json!({
        "version": version,
        "public_enabled": body.public_enabled,
    })))
}

/// `GET /api/v1/web-bans` — sources currently banned, soonest expiry first (admin).
pub(crate) async fn get_web_bans(
    State(state): State<AppState>,
) -> Result<impl IntoResponse, ControlApiError> {
    let bans = state.web_bans().ok_or_else(|| ControlApiError::NotFound {
        what: "ban table".to_owned(),
    })?;
    let mut list = bans.banned();
    list.sort_by_key(|b| b.until_unix);
    let items: Vec<Value> = list
        .iter()
        .map(|b| json!({ "ip": b.ip.to_string(), "until": unix_rfc3339(b.until_unix) }))
        .collect();
    Ok(success(json!({ "items": items })))
}

/// `DELETE /api/v1/web-bans/{ip}` — lifts a ban (admin).
pub(crate) async fn delete_web_ban(
    State(state): State<AppState>,
    axum::extract::Path(ip): axum::extract::Path<String>,
) -> Result<impl IntoResponse, ControlApiError> {
    let bans = state.web_bans().ok_or_else(|| ControlApiError::NotFound {
        what: "ban table".to_owned(),
    })?;
    let ip: std::net::IpAddr = ip.parse().map_err(|_| ControlApiError::Module {
        code: "control_api.web_bans.invalid",
        params: Some(json!({ "reason": "not an IP address" })),
    })?;
    if !bans.unban(ip) {
        return Err(ControlApiError::NotFound {
            what: "ban".to_owned(),
        });
    }
    tracing::info!(%ip, "web ban lifted");
    Ok(success(json!({ "ip": ip.to_string() })))
}

/// Body of `PUT /api/v1/backups/settings`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BackupSettingsBody {
    enabled: bool,
    retention_count: u32,
}

/// `PUT /api/v1/backups/settings` — enablement and retention (WP3, admin).
pub(crate) async fn put_backup_settings(
    State(state): State<AppState>,
    auth: Option<Extension<Authenticated>>,
    headers: HeaderMap,
    body: Result<Json<BackupSettingsBody>, JsonRejection>,
) -> Result<impl IntoResponse, ControlApiError> {
    let body = json_body(body, BACKUPS_INVALID)?;
    if body.retention_count == 0 || body.retention_count > BACKUP_RETENTION_MAX {
        return Err(ControlApiError::Module {
            code: BACKUPS_INVALID,
            params: Some(json!({
                "reason": format!("retention_count must be 1..={BACKUP_RETENTION_MAX}")
            })),
        });
    }
    if state.backup_dir().is_none() {
        return Err(ControlApiError::NotFound {
            what: "backup directory".to_owned(),
        });
    }
    let service = service(&state)?;
    let mut snapshot = stored_snapshot(service).await?;
    let settings = BackupSettings {
        enabled: body.enabled,
        retention_count: body.retention_count,
    };
    let section = snapshot
        .as_object_mut()
        .ok_or_else(|| ControlApiError::Internal {
            message: "stored config is not an object".to_owned(),
        })?
        .entry(SETTINGS_SECTION)
        .or_insert_with(|| json!({}));
    let section = section
        .as_object_mut()
        .ok_or_else(|| ControlApiError::Internal {
            message: "control_api_settings is not an object".to_owned(),
        })?;
    section.insert("backups".to_owned(), json!(settings));
    let version = service
        .replace(snapshot, &actor(auth), if_match(&headers))
        .await?;
    Ok(success(json!({
        "version": version,
        "enabled": settings.enabled,
        "retention_count": settings.retention_count,
    })))
}
