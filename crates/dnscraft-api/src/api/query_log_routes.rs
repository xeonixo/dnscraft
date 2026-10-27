//! `GET /api/v1/query-log` and `/api/v1/query-log/{id}` (A12).
//!
//! Both routes are viewer-accessible reads (the centralized RBAC middleware
//! maps every non-config `GET` under `/api/v1` to `Requirement::Api`).

use axum::extract::{Path, Query, State};
use axum::response::IntoResponse;
use serde::Deserialize;
use serde_json::json;

use crate::api::pagination::Pagination;
use crate::api::response::success;
use crate::error::ControlApiError;
use crate::query_log::{Order, OrderBy, QueryLogFilter};
use crate::server::AppState;

/// Raw query parameters, kept as strings so malformed values map to the
/// documented error envelope instead of axum's generic rejection.
#[derive(Debug, Default, Deserialize)]
pub(crate) struct RawQueryLogParams {
    from: Option<String>,
    to: Option<String>,
    client_id: Option<String>,
    client_name_substr: Option<String>,
    domain: Option<String>,
    domain_substr: Option<String>,
    protocol: Option<String>,
    view_id: Option<String>,
    profile_id: Option<String>,
    status: Option<String>,
    only_blocked: Option<String>,
    only_with_clients: Option<String>,
    order_by: Option<String>,
    order: Option<String>,
    limit: Option<String>,
    offset: Option<String>,
}

impl RawQueryLogParams {
    pub(crate) fn into_filter(self) -> Result<QueryLogFilter, ControlApiError> {
        let page = Pagination::parse_unbounded(self.limit.as_deref(), self.offset.as_deref())?;
        let from_us = self
            .from
            .as_deref()
            .map(|raw| parse_timestamp(raw, "from"))
            .transpose()?;
        let to_us = self
            .to
            .as_deref()
            .map(|raw| parse_timestamp(raw, "to"))
            .transpose()?;
        if let (Some(from), Some(to)) = (from_us, to_us)
            && from > to
        {
            return Err(ControlApiError::QueryLogInvalid {
                reason: "`from` must not be after `to`".to_owned(),
            });
        }
        Ok(QueryLogFilter {
            from_us,
            to_us,
            client_id: non_empty(self.client_id),
            client_name_substr: non_empty(self.client_name_substr),
            domain: non_empty(self.domain),
            domain_substr: non_empty(self.domain_substr),
            protocol: non_empty(self.protocol),
            view_id: non_empty(self.view_id),
            profile_id: non_empty(self.profile_id),
            status: non_empty(self.status),
            only_blocked: parse_bool(self.only_blocked.as_deref(), "only_blocked")?,
            only_with_clients: parse_bool(self.only_with_clients.as_deref(), "only_with_clients")?,
            order_by: parse_order_by(self.order_by.as_deref())?,
            order: parse_order(self.order.as_deref())?,
            limit: page.limit,
            offset: page.offset,
        })
    }
}

fn non_empty(value: Option<String>) -> Option<String> {
    value.filter(|value| !value.is_empty())
}

/// Parses an RFC 3339 timestamp into unix microseconds.
pub(crate) fn parse_timestamp(raw: &str, field: &str) -> Result<i64, ControlApiError> {
    use time::OffsetDateTime;
    use time::format_description::well_known::Rfc3339;
    OffsetDateTime::parse(raw.trim(), &Rfc3339)
        .map(|time| (time.unix_timestamp_nanos() / 1000) as i64)
        .map_err(|_| ControlApiError::QueryLogInvalid {
            reason: format!("`{field}` must be an RFC 3339 timestamp"),
        })
}

fn parse_bool(raw: Option<&str>, field: &str) -> Result<bool, ControlApiError> {
    match raw.map(str::trim) {
        None => Ok(false),
        Some("true" | "1") => Ok(true),
        Some("false" | "0") => Ok(false),
        Some(_) => Err(ControlApiError::QueryLogInvalid {
            reason: format!("`{field}` must be a boolean"),
        }),
    }
}

fn parse_order_by(raw: Option<&str>) -> Result<OrderBy, ControlApiError> {
    match raw.map(str::trim) {
        None | Some("time") => Ok(OrderBy::Time),
        Some("client") => Ok(OrderBy::Client),
        Some("domain") => Ok(OrderBy::Domain),
        Some("rcode") => Ok(OrderBy::Rcode),
        Some(_) => Err(ControlApiError::QueryLogInvalid {
            reason: "`order_by` must be time, client, domain or rcode".to_owned(),
        }),
    }
}

fn parse_order(raw: Option<&str>) -> Result<Order, ControlApiError> {
    match raw.map(str::trim) {
        None | Some("desc") => Ok(Order::Desc),
        Some("asc") => Ok(Order::Asc),
        Some(_) => Err(ControlApiError::QueryLogInvalid {
            reason: "`order` must be asc or desc".to_owned(),
        }),
    }
}

/// `GET /api/v1/query-log` — filtered, ordered and paginated search.
pub(crate) async fn list_query_log(
    State(state): State<AppState>,
    Query(params): Query<RawQueryLogParams>,
) -> Result<impl IntoResponse, ControlApiError> {
    let log = state.query_log().ok_or_else(|| ControlApiError::NotFound {
        what: "query log".to_owned(),
    })?;
    let filter = params.into_filter()?;
    let page = log.list(&filter).await?;
    Ok(success(json!({
        "queries": page.records,
        "has_more": page.has_more,
        "next_offset": page.next_offset,
    })))
}

/// `GET /api/v1/query-log/{id}` — full record for "why blocked?".
pub(crate) async fn get_query_log(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, ControlApiError> {
    let log = state.query_log().ok_or_else(|| ControlApiError::NotFound {
        what: "query log".to_owned(),
    })?;
    let record = log
        .get(&id)
        .await?
        .ok_or_else(|| ControlApiError::NotFound {
            what: format!("query log entry {id}"),
        })?;
    Ok(success(record))
}
