//! Statistics dashboards and streaming query-log export (A13).
//!
//! All routes here are plain `/api/v1` `GET`s, so the RBAC middleware maps them
//! to the viewer-accessible `Requirement::Api`; no `roles.rs` changes.

use std::sync::Arc;

use axum::extract::{Query, State};
use axum::http::header;
use axum::response::{IntoResponse, Response};
use serde::Deserialize;

use crate::api::query_log_routes::{RawQueryLogParams, parse_timestamp};
use crate::api::response::success;
use crate::error::ControlApiError;
use crate::query_log::QueryLog;
use crate::server::AppState;
use crate::stats::{ExportFormat, TOP_CLIENTS_MAX, TOP_DOMAINS_MAX, TopBy, export_body};

/// Stats query parameters, kept as strings so malformed values map to the
/// documented error envelopes instead of axum rejections.
#[derive(Debug, Default, Deserialize)]
pub(crate) struct RawStatsParams {
    from: Option<String>,
    to: Option<String>,
    limit: Option<String>,
    by: Option<String>,
}

impl RawStatsParams {
    fn window(&self) -> Result<(Option<i64>, Option<i64>), ControlApiError> {
        let from = self
            .from
            .as_deref()
            .map(|raw| parse_timestamp(raw, "from"))
            .transpose()?;
        let to = self
            .to
            .as_deref()
            .map(|raw| parse_timestamp(raw, "to"))
            .transpose()?;
        Ok((from, to))
    }
}

/// Parses a top-N `limit`: default when absent, clamped to `cap` when present.
fn parse_limit(raw: Option<&str>, cap: u32, default: u32) -> Result<u32, ControlApiError> {
    match raw {
        None => Ok(default),
        Some(raw) => {
            let value: u32 =
                raw.trim()
                    .parse()
                    .map_err(|_| ControlApiError::PaginationInvalid {
                        reason: format!("limit must be a non-negative integer, got `{raw}`"),
                    })?;
            if value == 0 {
                return Err(ControlApiError::PaginationInvalid {
                    reason: "limit must be at least 1".to_owned(),
                });
            }
            Ok(value.min(cap))
        }
    }
}

/// Parses `by=queries|blocked`.
fn parse_top_by(raw: Option<&str>) -> Result<TopBy, ControlApiError> {
    match raw.map(str::trim) {
        None | Some("queries") => Ok(TopBy::Queries),
        Some("blocked") => Ok(TopBy::Blocked),
        Some(_) => Err(ControlApiError::QueryLogInvalid {
            reason: "`by` must be queries or blocked".to_owned(),
        }),
    }
}

/// Returns the configured query log or the documented 404.
fn query_log(state: &AppState) -> Result<&Arc<QueryLog>, ControlApiError> {
    state.query_log().ok_or_else(|| ControlApiError::NotFound {
        what: "query log".to_owned(),
    })
}

/// `GET /api/v1/stats/overview` — aggregated dashboard counters.
pub(crate) async fn stats_overview(
    State(state): State<AppState>,
    Query(params): Query<RawStatsParams>,
) -> Result<impl IntoResponse, ControlApiError> {
    let log = query_log(&state)?;
    let (from, to) = params.window()?;
    Ok(success(log.stats_overview(from, to).await?))
}

/// `GET /api/v1/stats/top_clients` — top N clients by queries or blocked count.
pub(crate) async fn stats_top_clients(
    State(state): State<AppState>,
    Query(params): Query<RawStatsParams>,
) -> Result<impl IntoResponse, ControlApiError> {
    let log = query_log(&state)?;
    let (from, to) = params.window()?;
    let limit = parse_limit(params.limit.as_deref(), TOP_CLIENTS_MAX, 10)?;
    let by = parse_top_by(params.by.as_deref())?;
    Ok(success(log.top_clients(from, to, limit, by).await?))
}

/// `GET /api/v1/stats/top_domains` — top N queried domains.
pub(crate) async fn stats_top_domains(
    State(state): State<AppState>,
    Query(params): Query<RawStatsParams>,
) -> Result<impl IntoResponse, ControlApiError> {
    let log = query_log(&state)?;
    let (from, to) = params.window()?;
    let limit = parse_limit(params.limit.as_deref(), TOP_DOMAINS_MAX, 10)?;
    Ok(success(log.top_domains(from, to, limit).await?))
}

/// `GET /api/v1/stats/cache` — cache hit ratio.
pub(crate) async fn stats_cache(
    State(state): State<AppState>,
    Query(params): Query<RawStatsParams>,
) -> Result<impl IntoResponse, ControlApiError> {
    let log = query_log(&state)?;
    let (from, to) = params.window()?;
    Ok(success(log.cache_stats(from, to).await?))
}

/// `GET /api/v1/query-log/export.ndjson` — streaming NDJSON export.
pub(crate) async fn export_ndjson(
    State(state): State<AppState>,
    Query(params): Query<RawQueryLogParams>,
) -> Result<Response, ControlApiError> {
    export(&state, params, ExportFormat::Ndjson).await
}

/// `GET /api/v1/query-log/export.csv` — streaming CSV export of the same set.
pub(crate) async fn export_csv(
    State(state): State<AppState>,
    Query(params): Query<RawQueryLogParams>,
) -> Result<Response, ControlApiError> {
    export(&state, params, ExportFormat::Csv).await
}

/// Shared export handler: validates the A12 filter, then streams the body.
async fn export(
    state: &AppState,
    params: RawQueryLogParams,
    format: ExportFormat,
) -> Result<Response, ControlApiError> {
    let log = Arc::clone(query_log(state)?);
    let filter = params.into_filter()?;
    let body = export_body(log, filter, format).await?;
    let mut response = body.into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        header::HeaderValue::from_static(format.content_type()),
    );
    let disposition = format!("attachment; filename=\"{}\"", format.file_name());
    if let Ok(value) = header::HeaderValue::from_str(&disposition) {
        response
            .headers_mut()
            .insert(header::CONTENT_DISPOSITION, value);
    }
    Ok(response)
}
