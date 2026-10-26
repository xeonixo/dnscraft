//! `/api/v1/config` routes.
//!
//! All handlers delegate to [`crate::ConfigService`]; they only translate HTTP
//! concerns (auth extension, `If-Match`, pagination, envelope) into service
//! calls. RBAC already restricts non-GET requests to `admin`.

use axum::Extension;
use axum::Json;
use axum::extract::rejection::JsonRejection;
use axum::extract::{Path, Query, State};
use axum::http::HeaderMap;
use axum::http::header::IF_MATCH;
use axum::response::IntoResponse;
use serde_json::{Value, json};

use crate::api::auth::Authenticated;
use crate::api::pagination::{Pagination, RawPagination};
use crate::api::response::success;
use crate::config_apply::ConfigActor;
use crate::config_apply::ConfigService;
use crate::error::ControlApiError;
use crate::server::AppState;

/// The actor for this request; falls back to the embedded `local` actor when the
/// API runs without authentication configured.
fn actor(auth: Option<Extension<Authenticated>>) -> ConfigActor {
    match auth {
        Some(Extension(auth)) => ConfigActor::new(auth.actor_id(), auth.actor_type().as_str()),
        None => ConfigActor::local(),
    }
}

/// The configured service, or an internal error if the route was mounted
/// without one (the router only mounts these routes when a service exists).
pub(crate) fn service(state: &AppState) -> Result<&ConfigService, ControlApiError> {
    state
        .config_service()
        .ok_or_else(|| ControlApiError::Internal {
            message: "config service is not configured".to_owned(),
        })
}

/// Parses an `If-Match` header value, if present and representable as UTF-8.
fn if_match(headers: &HeaderMap) -> Option<&str> {
    headers.get(IF_MATCH).and_then(|value| value.to_str().ok())
}

/// `GET /api/v1/config` — current version plus the stored snapshot.
///
/// Snapshots are redacted when stored, so secrets are never returned.
pub(crate) async fn get_config(
    State(state): State<AppState>,
) -> Result<impl IntoResponse, ControlApiError> {
    let (version, config) = service(&state)?.current().await.map_err(read_error)?;
    Ok(success(json!({
        "version": version,
        "config": config,
    })))
}

/// `PUT /api/v1/config` — validate, apply atomically, store a new version.
pub(crate) async fn put_config(
    State(state): State<AppState>,
    auth: Option<Extension<Authenticated>>,
    headers: HeaderMap,
    body: Result<Json<Value>, JsonRejection>,
) -> Result<impl IntoResponse, ControlApiError> {
    let Json(body) = body.map_err(|rejection| ControlApiError::ConfigInvalid {
        reason: rejection.body_text(),
    })?;
    let version = service(&state)?
        .replace(body, &actor(auth), if_match(&headers))
        .await?;
    Ok(success(json!({ "version": version })))
}

/// `GET /api/v1/config/versions` — newest first, paginated.
pub(crate) async fn list_versions(
    State(state): State<AppState>,
    query: Query<RawPagination>,
) -> Result<impl IntoResponse, ControlApiError> {
    let page = Pagination::from_query(query)?;
    let service = service(&state)?;
    let current_version = service.current().await.map_err(read_error)?.0;
    // Fetch one extra row to expose `has_more` without a second query.
    let mut rows = service
        .versions(page.limit + 1, page.offset)
        .await
        .map_err(read_error)?;
    let fetched = rows.len();
    let has_more = page.has_more(fetched);
    let next_offset = page.next_offset(fetched);
    rows.truncate(page.limit as usize);
    let versions: Vec<Value> = rows
        .into_iter()
        .map(|(version, created_at)| json!({ "version": version, "created_at": created_at }))
        .collect();
    Ok(success(json!({
        "current_version": current_version,
        "versions": versions,
        "has_more": has_more,
        "next_offset": next_offset,
    })))
}

/// `POST /api/v1/config/versions/{version}/rollback` — restore a stored version.
pub(crate) async fn rollback(
    State(state): State<AppState>,
    auth: Option<Extension<Authenticated>>,
    headers: HeaderMap,
    Path(version): Path<String>,
) -> Result<impl IntoResponse, ControlApiError> {
    let target = version
        .parse::<u64>()
        .map_err(|_| ControlApiError::ConfigUnknownVersion { version: 0 })?;
    let outcome = service(&state)?
        .rollback(target, &actor(auth), if_match(&headers))
        .await?;
    Ok(success(json!({
        "version": outcome.version,
        "restored_from": outcome.restored_from,
    })))
}

/// Maps a read failure to the documented `control_api.config.read` code.
fn read_error(err: ControlApiError) -> ControlApiError {
    ControlApiError::ConfigRead {
        message: err.to_string(),
    }
}
