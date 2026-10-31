//! `GET /api/v1/query-log` and `/api/v1/query-log/{id}` (A12).
//!
//! Both routes are viewer-accessible reads (the centralized RBAC middleware
//! maps every non-config `GET` under `/api/v1` to `Requirement::Api`).

use std::sync::Arc;
use std::time::Duration;

use axum::Extension;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderValue, header};
use axum::response::{IntoResponse, Response};
use dnscraft_filtering::TrackerDb;
use hyper::body::Bytes;
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::sync::{broadcast, mpsc};
use tokio::time::Instant;

use crate::api::auth::Authenticated;
use crate::stats::ChannelBody;

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
    node_id: Option<String>,
    client_id: Option<String>,
    client_name_substr: Option<String>,
    device_id: Option<String>,
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
            node_id: non_empty(self.node_id),
            client_id: non_empty(self.client_id),
            client_name_substr: non_empty(self.client_name_substr),
            device_id: non_empty(self.device_id),
            domain: non_empty(self.domain),
            domain_substr: non_empty(self.domain_substr),
            protocol: enum_value(self.protocol, "protocol", &PROTOCOLS)?,
            view_id: non_empty(self.view_id),
            profile_id: non_empty(self.profile_id),
            status: enum_value(self.status, "status", &STATUSES)?,
            only_blocked: parse_bool(self.only_blocked.as_deref(), "only_blocked")?,
            only_with_clients: parse_bool(self.only_with_clients.as_deref(), "only_with_clients")?,
            order_by: parse_order_by(self.order_by.as_deref())?,
            order: parse_order(self.order.as_deref())?,
            limit: page.limit,
            offset: page.offset,
        })
    }
}

/// Wire values of the record `protocol` field (SPEC-control-api § Record schema).
const PROTOCOLS: [&str; 5] = ["udp53", "tcp53", "dot", "doh", "doq"];
/// Wire values of the record `status` field (SPEC-control-api § Record schema).
const STATUSES: [&str; 4] = ["allowed", "blocked", "dnssec_bogus", "servfail"];

/// An optional filter value that must be one of `allowed` (GA23). Empty means
/// no filter.
fn enum_value(
    value: Option<String>,
    field: &str,
    allowed: &[&str],
) -> Result<Option<String>, ControlApiError> {
    match non_empty(value) {
        Some(value) if !allowed.contains(&value.as_str()) => {
            Err(ControlApiError::QueryLogInvalid {
                reason: format!("`{field}` must be one of {}", allowed.join(", ")),
            })
        }
        other => Ok(other),
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
    let mut page = log.list(&filter).await?;
    let trackers = state.filter_engine().and_then(|f| f.trackers());
    for record in &mut page.records {
        add_tracker_labels(record, trackers.as_deref());
    }
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
    let mut record = log
        .get(&id)
        .await?
        .ok_or_else(|| ControlApiError::NotFound {
            what: format!("query log entry {id}"),
        })?;
    add_tracker_labels(
        &mut record,
        state.filter_engine().and_then(|f| f.trackers()).as_deref(),
    );
    Ok(success(record))
}

/// Adds `tracker` (`name`, `category`, `url`) to the queried name and to every
/// CNAME hop whose name is a known tracker. Read-time only: the stored record
/// is unchanged, so a newer tracker database also labels old rows.
fn add_tracker_labels(record: &mut Value, db: Option<&TrackerDb>) {
    let Some(db) = db else {
        return;
    };
    let label = |name: &str| {
        db.lookup(name)
            .map(|t| json!({ "name": t.name, "category": t.category, "url": t.url }))
    };
    if let Some(t) = record["query"]["name"].as_str().and_then(label) {
        record["tracker"] = t;
    }
    let Some(steps) = record["steps"].as_array_mut() else {
        return;
    };
    for hop in steps
        .iter_mut()
        .filter_map(|step| step["hops"].as_array_mut())
        .flatten()
    {
        if let Some(t) = hop["name"].as_str().and_then(label) {
            hop["tracker"] = t;
        }
    }
}

/// Live stream: close after this long without a row (WX2 idle close).
const STREAM_IDLE: Duration = Duration::from_secs(30 * 60);
/// Heartbeat interval (WX2 `: ping`).
const STREAM_PING: Duration = Duration::from_secs(15);
/// Rows fetched per filter query when the stream is behind.
const STREAM_BATCH: usize = 256;

/// `GET /api/v1/query-log/stream` — live rows as Server-Sent Events (WX2).
///
/// Same filter parameters as the list (paging parameters are ignored). Live
/// only, no replay. Rows arrive as `event: row` with the stored record as data;
/// a subscriber that falls behind gets `event: lagged` with the dropped count.
pub(crate) async fn stream_query_log(
    State(state): State<AppState>,
    auth: Option<Extension<Authenticated>>,
    Query(params): Query<RawQueryLogParams>,
) -> Result<Response, ControlApiError> {
    let log = Arc::clone(state.query_log().ok_or_else(|| ControlApiError::NotFound {
        what: "query log".to_owned(),
    })?);
    let filter = params.into_filter()?;
    let principal = auth
        .as_ref()
        .map_or("anonymous", |Extension(who)| who.actor_id())
        .to_owned();
    let guard = log
        .acquire_stream(&principal)
        .ok_or(ControlApiError::QueryLogStreamLimit)?;
    let mut rows = log.subscribe_stream();
    let filter_engine = state.filter_engine().cloned();
    let (tx, rx) = mpsc::channel::<Result<Bytes, ControlApiError>>(16);
    tokio::spawn(async move {
        let _guard = guard;
        if !send_text(&tx, ": open\n\n").await {
            return;
        }
        let mut ping = tokio::time::interval_at(Instant::now() + STREAM_PING, STREAM_PING);
        let idle = tokio::time::sleep(STREAM_IDLE);
        tokio::pin!(idle);
        loop {
            tokio::select! {
                received = rows.recv() => {
                    let mut ids = Vec::new();
                    match received {
                        Ok(id) => ids.push(id),
                        Err(broadcast::error::RecvError::Lagged(dropped)) => {
                            log.record_stream_dropped(dropped);
                            if !send_lagged(&tx, dropped).await {
                                return;
                            }
                            continue;
                        }
                        Err(broadcast::error::RecvError::Closed) => return,
                    }
                    while ids.len() < STREAM_BATCH {
                        match rows.try_recv() {
                            Ok(id) => ids.push(id),
                            Err(broadcast::error::TryRecvError::Lagged(dropped)) => {
                                log.record_stream_dropped(dropped);
                                if !send_lagged(&tx, dropped).await {
                                    return;
                                }
                            }
                            Err(_) => break,
                        }
                    }
                    let records = match log.stream_rows(&filter, &ids).await {
                        Ok(records) => records,
                        Err(error) => {
                            tracing::warn!(error = %error, "query-log stream read failed");
                            return;
                        }
                    };
                    let trackers = filter_engine.as_ref().and_then(|f| f.trackers());
                    for mut record in records {
                        if let Some(db) = trackers.as_deref()
                            && let Ok(mut value) = serde_json::from_str::<Value>(&record)
                        {
                            add_tracker_labels(&mut value, Some(db));
                            record = value.to_string();
                        }
                        if !send_text(&tx, &format!("event: row\ndata: {record}\n\n")).await {
                            return;
                        }
                    }
                    idle.as_mut().reset(Instant::now() + STREAM_IDLE);
                }
                _ = ping.tick() => {
                    if !send_text(&tx, ": ping\n\n").await {
                        return;
                    }
                }
                () = &mut idle => return,
            }
        }
    });
    let mut response = Response::new(axum::body::Body::new(ChannelBody { rx }));
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/event-stream"),
    );
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert("x-accel-buffering", HeaderValue::from_static("no"));
    Ok(response)
}

/// Sends one SSE chunk; `false` when the client has gone.
async fn send_text(tx: &mpsc::Sender<Result<Bytes, ControlApiError>>, text: &str) -> bool {
    tx.send(Ok(Bytes::from(text.to_owned()))).await.is_ok()
}

/// Sends the `lagged` event; `false` when the client has gone.
async fn send_lagged(tx: &mpsc::Sender<Result<Bytes, ControlApiError>>, dropped: u64) -> bool {
    send_text(
        tx,
        &format!("event: lagged\ndata: {{\"dropped\":{dropped}}}\n\n"),
    )
    .await
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn tracker_labels_cover_the_queried_name_and_cname_hops() {
        let db = TrackerDb::parse(
            r#"{"categories": {"4": "advertising"},
                "trackers": {"ga": {"name": "Ad Co", "categoryId": 4}},
                "trackerDomains": {"ads.example": "ga"}}"#,
        )
        .unwrap();
        let mut record = json!({
            "query": {"name": "a.ads.example"},
            "steps": [
                {"stage": "selected"},
                {"stage": "cname_chain", "hops": [
                    {"name": "a.ads.example"}, {"name": "cdn.other.example"}
                ]}
            ]
        });
        add_tracker_labels(&mut record, Some(&db));
        assert_eq!(record["tracker"]["name"], "Ad Co");
        assert_eq!(record["tracker"]["category"], "advertising");
        assert_eq!(record["steps"][1]["hops"][0]["tracker"]["name"], "Ad Co");
        assert!(record["steps"][1]["hops"][1].get("tracker").is_none());

        let mut plain = json!({"query": {"name": "a.ads.example"}});
        add_tracker_labels(&mut plain, None);
        assert!(plain.get("tracker").is_none());
    }

    #[test]
    fn protocol_and_status_filters_must_be_known_values() {
        assert_eq!(
            enum_value(Some("doh".into()), "protocol", &PROTOCOLS).unwrap(),
            Some("doh".to_owned())
        );
        assert_eq!(
            enum_value(Some(String::new()), "status", &STATUSES).unwrap(),
            None
        );
        for bad in ["DoH", "udp", "blocked;DROP"] {
            let err = enum_value(Some(bad.into()), "protocol", &PROTOCOLS).unwrap_err();
            assert_eq!(err.code(), "control_api.query_log.invalid", "{bad}");
        }
        let err = enum_value(Some("nxdomain".into()), "status", &STATUSES).unwrap_err();
        assert_eq!(err.code(), "control_api.query_log.invalid");
    }
}
