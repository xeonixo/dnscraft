//! Statistics rollups, dashboard aggregations and query-log export (A13).
//!
//! ## Rollups
//!
//! [`QueryLog::run_rollup`] folds the raw query log into the `stats_hourly`
//! and `stats_daily` tables (one row per bucket, profile, protocol and answer
//! origin) and prunes rollups older than [`ROLLUP_RETENTION_DAYS`]. It is an
//! explicit, idempotent pass driven by the injected clock, so callers (the
//! binary's scheduler, or a `ManualClock` test) decide when it runs. Raw rows
//! stay the source for ad-hoc filtering (retention default 30 days); rollups
//! keep dashboard counters for up to a year.
//!
//! ## Endpoint aggregations
//!
//! The dashboard endpoints aggregate the raw query log inside the requested
//! window, and therefore cover the raw retention window. Cardinality is capped
//! per the spec: [`TOP_CLIENTS_MAX`] and [`TOP_DOMAINS_MAX`].
//!
//! ## Export
//!
//! [`export_body`] streams the stored records for one [`QueryLogFilter`] page
//! by page, so a large export never sits in memory as a whole. NDJSON is the
//! primary format (one stored record per line); CSV is a convenience projection
//! of the documented record schema.

use std::collections::BTreeMap;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use axum::body::Body;
use hyper::body::{Body as HttpBody, Bytes, Frame};
use rusqlite::params;
use serde::Serialize;
use serde_json::Value as Json;
use tokio::sync::mpsc;

use crate::error::ControlApiError;
use crate::query_log::{QueryLog, QueryLogFilter};
use crate::storage::{Db, db_err};

/// Maximum `top_clients` entries returned per window.
pub const TOP_CLIENTS_MAX: u32 = 1000;
/// Maximum `top_domains` entries returned per window.
pub const TOP_DOMAINS_MAX: u32 = 10_000;
/// Rollup retention in days (the spec's 365-day dashboard window).
pub const ROLLUP_RETENTION_DAYS: i64 = 365;

const MICROS_PER_HOUR: i64 = 3_600_000_000;
const SECONDS_PER_HOUR: i64 = 3_600;
const SECONDS_PER_DAY: i64 = 86_400;
const DEFAULT_WINDOW_HOURS: i64 = 24;
const EXPORT_PAGE_ROWS: u32 = 512;
const EXPORT_CHANNEL_DEPTH: usize = 16;

/// CSV columns exported for the documented query-log record schema.
const CSV_COLUMNS: &[&str] = &[
    "id",
    "time",
    "node_id",
    "listener_id",
    "protocol",
    "source_ip",
    "source_ip_truncated",
    "client_id",
    "client_name",
    "query_name",
    "query_type",
    "query_class",
    "view_id",
    "profile_id",
    "answer_source",
    "dnssec",
    "rcode",
    "answer_size",
];

/// Which rollup table to read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RollupWindow {
    /// Hourly rollups (`stats_hourly`).
    Hourly,
    /// Daily rollups (`stats_daily`).
    Daily,
}

impl RollupWindow {
    /// Returns `(table, bucket expression)` for this window.
    fn sql(self) -> (&'static str, &'static str) {
        match self {
            Self::Hourly => ("stats_hourly", "hour"),
            Self::Daily => ("stats_daily", "day"),
        }
    }
}

/// One stored rollup row.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RollupRow {
    /// Unix hour for [`RollupWindow::Hourly`], unix day for [`RollupWindow::Daily`].
    pub bucket: i64,
    /// Originating node id (`""` for rows written before the dimension existed).
    pub node_id: String,
    /// Policy profile id.
    pub profile_id: String,
    /// Transport (`udp53`, `tcp53`, `dot`, `doh`, `doq`).
    pub protocol: String,
    /// Decision answer origin (`resolver`, `filter_block`, …).
    pub answer_source: String,
    /// Queries counted in this bucket.
    pub query_count: i64,
}

/// Aggregated dashboard statistics for one window.
#[derive(Clone, Debug, Serialize)]
pub struct StatsOverview {
    /// Window start (RFC 3339).
    pub from: String,
    /// Window end (RFC 3339).
    pub to: String,
    /// Total queries in the window.
    pub total: i64,
    /// Queries with outcome `allowed`.
    pub allowed: i64,
    /// Queries with outcome `blocked`.
    pub blocked: i64,
    /// `allowed / total` (`0.0` for an empty window).
    pub allowed_ratio: f64,
    /// Query counts by transport.
    pub by_protocol: BTreeMap<String, i64>,
    /// Query counts by policy view.
    pub by_view: BTreeMap<String, i64>,
    /// Query counts by policy profile.
    pub by_profile: BTreeMap<String, i64>,
    /// Query counts by decision answer origin.
    pub by_answer_source: BTreeMap<String, i64>,
    /// Query counts by response code.
    pub by_rcode: BTreeMap<String, i64>,
    /// Query counts by DNSSEC outcome (`secure`, `insecure`, `bogus`, …).
    pub dnssec: BTreeMap<String, i64>,
}

/// One `top_clients` entry.
#[derive(Clone, Debug, Serialize)]
pub struct TopClient {
    /// Client id from the query log (`DoH`/`DoT` id or directory id).
    pub client_id: String,
    /// Client display name, or an empty string when the directory had none.
    pub client_name: String,
    /// Queries attributed to the client.
    pub queries: i64,
    /// Queries of those that were blocked.
    pub blocked: i64,
}

/// `top_clients` rows plus the resolved window.
#[derive(Clone, Debug, Serialize)]
pub struct TopClients {
    /// Window start (RFC 3339).
    pub from: String,
    /// Window end (RFC 3339).
    pub to: String,
    /// Up to [`TOP_CLIENTS_MAX`] clients.
    pub clients: Vec<TopClient>,
}

/// One `top_domains` entry.
#[derive(Clone, Debug, Serialize)]
pub struct TopDomain {
    /// Normalized owner name (lowercase, no trailing dot).
    pub domain: String,
    /// Queries for the name.
    pub queries: i64,
    /// Queries for the name that were blocked.
    pub blocked: i64,
}

/// `top_domains` rows plus the resolved window.
#[derive(Clone, Debug, Serialize)]
pub struct TopDomains {
    /// Window start (RFC 3339).
    pub from: String,
    /// Window end (RFC 3339).
    pub to: String,
    /// Up to [`TOP_DOMAINS_MAX`] domains.
    pub domains: Vec<TopDomain>,
}

/// Cache hit statistics for one window.
#[derive(Clone, Debug, Serialize)]
pub struct CacheStats {
    /// Window start (RFC 3339).
    pub from: String,
    /// Window end (RFC 3339).
    pub to: String,
    /// Resolved queries answered from cache.
    pub hits: i64,
    /// Resolved queries not answered from cache (recursion or stale).
    pub misses: i64,
    /// `hits / (hits + misses)` (`0.0` when nothing resolved).
    pub hit_ratio: f64,
}

/// How to order `top_clients`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum TopBy {
    /// Most queries first (default).
    #[default]
    Queries,
    /// Most blocked queries first.
    Blocked,
}

impl TopBy {
    /// The wire name (`queries` | `blocked`).
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Queries => "queries",
            Self::Blocked => "blocked",
        }
    }
}

/// Export wire format.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ExportFormat {
    /// Streaming NDJSON (one stored record per line).
    Ndjson,
    /// Streaming CSV projection of the documented record schema.
    Csv,
}

impl ExportFormat {
    /// Response content type.
    pub(crate) fn content_type(self) -> &'static str {
        match self {
            Self::Ndjson => "application/x-ndjson",
            Self::Csv => "text/csv; charset=utf-8",
        }
    }

    /// Download file name.
    pub(crate) fn file_name(self) -> &'static str {
        match self {
            Self::Ndjson => "query-log.ndjson",
            Self::Csv => "query-log.csv",
        }
    }
}

impl QueryLog {
    /// Folds the raw query log into the hourly and daily rollup tables and
    /// prunes rollups older than [`ROLLUP_RETENTION_DAYS`].
    ///
    /// Idempotent: counts are the maximum of the stored and recomputed value,
    /// so running the pass again never double-counts. Callers trigger it on a
    /// schedule; tests drive it after inserting fixed-time events.
    pub async fn run_rollup(&self) -> Result<(), ControlApiError> {
        let now = self.db().now_unix();
        let cutoff_seconds = now.saturating_sub(ROLLUP_RETENTION_DAYS * SECONDS_PER_DAY);
        let hour_cutoff = cutoff_seconds.div_euclid(SECONDS_PER_HOUR);
        let day_cutoff = cutoff_seconds.div_euclid(SECONDS_PER_DAY);
        self.db()
            .with_conn(move |conn| {
                let tx = conn.transaction().map_err(db_err)?;
                // The `WHERE 1 = 1` clause disambiguates the UPSERT parser
                // after an INSERT ... SELECT.
                tx.execute(
                    "INSERT INTO stats_hourly (
                         hour, node_id, profile_id, protocol, answer_source, query_count
                     )
                     SELECT time / 3600000000, node_id, profile_id, protocol, answer_source, COUNT(*)
                     FROM query_log
                     WHERE 1 = 1
                     GROUP BY 1, 2, 3, 4, 5
                     ON CONFLICT(hour, node_id, profile_id, protocol, answer_source)
                     DO UPDATE SET query_count = MAX(query_count, excluded.query_count)",
                    [],
                )
                .map_err(db_err)?;
                tx.execute(
                    "INSERT INTO stats_daily (
                         day, node_id, profile_id, protocol, answer_source, query_count
                     )
                     SELECT time / 86400000000, node_id, profile_id, protocol, answer_source, COUNT(*)
                     FROM query_log
                     WHERE 1 = 1
                     GROUP BY 1, 2, 3, 4, 5
                     ON CONFLICT(day, node_id, profile_id, protocol, answer_source)
                     DO UPDATE SET query_count = MAX(query_count, excluded.query_count)",
                    [],
                )
                .map_err(db_err)?;
                tx.execute(
                    "DELETE FROM stats_hourly WHERE hour < ?1",
                    params![hour_cutoff],
                )
                .map_err(db_err)?;
                tx.execute("DELETE FROM stats_daily WHERE day < ?1", params![day_cutoff])
                    .map_err(db_err)?;
                tx.commit().map_err(db_err)?;
                Ok(())
            })
            .await
    }

    /// Returns every stored rollup row for `window`, ordered by bucket.
    pub async fn rollup_rows(
        &self,
        window: RollupWindow,
    ) -> Result<Vec<RollupRow>, ControlApiError> {
        let (table, bucket) = window.sql();
        // `table`/`bucket` are fixed constants, never user input.
        let sql = format!(
            "SELECT {bucket}, node_id, profile_id, protocol, answer_source, query_count
             FROM {table} ORDER BY {bucket}, node_id, profile_id, protocol, answer_source"
        );
        self.db()
            .with_conn(move |conn| {
                let mut stmt = conn.prepare(&sql).map_err(db_err)?;
                let rows = stmt
                    .query_map([], |row| {
                        Ok(RollupRow {
                            bucket: row.get(0)?,
                            node_id: row.get(1)?,
                            profile_id: row.get(2)?,
                            protocol: row.get(3)?,
                            answer_source: row.get(4)?,
                            query_count: row.get(5)?,
                        })
                    })
                    .map_err(db_err)?;
                rows.collect::<Result<Vec<_>, _>>().map_err(db_err)
            })
            .await
    }

    /// Aggregated dashboard counters for `[from_us, to_us]`, optionally
    /// restricted to one `node_id`.
    ///
    /// Absent bounds default to the last 24 hours, measured on the injected
    /// clock. `from > to` is `control_api.query_log.invalid`.
    pub async fn stats_overview(
        &self,
        from_us: Option<i64>,
        to_us: Option<i64>,
        node_id: Option<&str>,
    ) -> Result<StatsOverview, ControlApiError> {
        let db = self.db();
        let (from, to) = resolve_window(db, from_us, to_us)?;
        let node_id = node_id.map(str::to_owned);
        let totals_node_id = node_id.clone();
        let (total, allowed, blocked) = db
            .with_conn(move |conn| {
                conn.query_row(
                    "SELECT COUNT(*),
                            COALESCE(SUM(CASE WHEN status = 'allowed' THEN 1 ELSE 0 END), 0),
                            COALESCE(SUM(CASE WHEN status = 'blocked' THEN 1 ELSE 0 END), 0)
                     FROM query_log
                     WHERE time >= ?1 AND time <= ?2
                       AND (?3 IS NULL OR node_id = ?3)",
                    params![from, to, totals_node_id],
                    |row| {
                        Ok((
                            row.get::<_, i64>(0)?,
                            row.get::<_, i64>(1)?,
                            row.get::<_, i64>(2)?,
                        ))
                    },
                )
                .map_err(db_err)
            })
            .await?;
        let by_protocol = counts_by(db, "protocol", from, to, node_id.clone()).await?;
        let by_view = counts_by(db, "view_id", from, to, node_id.clone()).await?;
        let by_profile = counts_by(db, "profile_id", from, to, node_id.clone()).await?;
        let by_answer_source = counts_by(db, "answer_source", from, to, node_id.clone()).await?;
        let by_rcode = counts_by(db, "rcode", from, to, node_id.clone()).await?;
        let dnssec = counts_by(db, "json_extract(record, '$.dnssec')", from, to, node_id).await?;
        Ok(StatsOverview {
            from: format_micros(from),
            to: format_micros(to),
            total,
            allowed,
            blocked,
            allowed_ratio: ratio(allowed, total),
            by_protocol,
            by_view,
            by_profile,
            by_answer_source,
            by_rcode,
            dnssec,
        })
    }

    /// Top clients by query or blocked count for `[from_us, to_us]`.
    ///
    /// `limit` is clamped to `1..=TOP_CLIENTS_MAX`. Rows without a client id
    /// are excluded (they are not attributable to a client).
    pub async fn top_clients(
        &self,
        from_us: Option<i64>,
        to_us: Option<i64>,
        node_id: Option<&str>,
        limit: u32,
        by: TopBy,
    ) -> Result<TopClients, ControlApiError> {
        let db = self.db();
        let (from, to) = resolve_window(db, from_us, to_us)?;
        let node_id = node_id.map(str::to_owned);
        let limit = i64::from(limit.clamp(1, TOP_CLIENTS_MAX));
        let order = match by {
            TopBy::Queries => "queries DESC, client_id ASC",
            TopBy::Blocked => "blocked DESC, queries DESC, client_id ASC",
        };
        let clients = db
            .with_conn(move |conn| {
                let sql = format!(
                    "SELECT client_id,
                            COALESCE(client_name, ''),
                            COUNT(*) AS queries,
                            COALESCE(SUM(CASE WHEN status = 'blocked' THEN 1 ELSE 0 END), 0)
                                AS blocked
                     FROM query_log
                     WHERE time >= ?1 AND time <= ?2 AND client_id IS NOT NULL
                       AND (?4 IS NULL OR node_id = ?4)
                     GROUP BY client_id, client_name
                     ORDER BY {order}
                     LIMIT ?3"
                );
                let mut stmt = conn.prepare(&sql).map_err(db_err)?;
                let rows = stmt
                    .query_map(params![from, to, limit, node_id], |row| {
                        Ok(TopClient {
                            client_id: row.get(0)?,
                            client_name: row.get(1)?,
                            queries: row.get(2)?,
                            blocked: row.get(3)?,
                        })
                    })
                    .map_err(db_err)?;
                rows.collect::<Result<Vec<_>, _>>().map_err(db_err)
            })
            .await?;
        Ok(TopClients {
            from: format_micros(from),
            to: format_micros(to),
            clients,
        })
    }

    /// Top domains by query count for `[from_us, to_us]`.
    ///
    /// `limit` is clamped to `1..=TOP_DOMAINS_MAX`.
    pub async fn top_domains(
        &self,
        from_us: Option<i64>,
        to_us: Option<i64>,
        node_id: Option<&str>,
        limit: u32,
    ) -> Result<TopDomains, ControlApiError> {
        let db = self.db();
        let (from, to) = resolve_window(db, from_us, to_us)?;
        let node_id = node_id.map(str::to_owned);
        let limit = i64::from(limit.clamp(1, TOP_DOMAINS_MAX));
        let domains = db
            .with_conn(move |conn| {
                let mut stmt = conn
                    .prepare(
                        "SELECT query_name,
                                COUNT(*) AS queries,
                                COALESCE(SUM(CASE WHEN status = 'blocked' THEN 1 ELSE 0 END), 0)
                                    AS blocked
                         FROM query_log
                         WHERE time >= ?1 AND time <= ?2
                           AND (?4 IS NULL OR node_id = ?4)
                         GROUP BY query_name
                         ORDER BY queries DESC, query_name ASC
                         LIMIT ?3",
                    )
                    .map_err(db_err)?;
                let rows = stmt
                    .query_map(params![from, to, limit, node_id], |row| {
                        Ok(TopDomain {
                            domain: row.get(0)?,
                            queries: row.get(1)?,
                            blocked: row.get(2)?,
                        })
                    })
                    .map_err(db_err)?;
                rows.collect::<Result<Vec<_>, _>>().map_err(db_err)
            })
            .await?;
        Ok(TopDomains {
            from: format_micros(from),
            to: format_micros(to),
            domains,
        })
    }

    /// Top domains by blocked count for `[from_us, to_us]`.
    ///
    /// `limit` is clamped to `1..=TOP_DOMAINS_MAX`.
    pub async fn top_blocked_domains(
        &self,
        from_us: Option<i64>,
        to_us: Option<i64>,
        node_id: Option<&str>,
        limit: u32,
    ) -> Result<TopDomains, ControlApiError> {
        let db = self.db();
        let (from, to) = resolve_window(db, from_us, to_us)?;
        let node_id = node_id.map(str::to_owned);
        let limit = i64::from(limit.clamp(1, TOP_DOMAINS_MAX));
        let domains = db
            .with_conn(move |conn| {
                let mut stmt = conn
                    .prepare(
                        "SELECT query_name,
                                COUNT(*) AS queries,
                                COALESCE(SUM(CASE WHEN status = 'blocked' THEN 1 ELSE 0 END), 0)
                                    AS blocked
                         FROM query_log
                         WHERE time >= ?1 AND time <= ?2
                           AND (?4 IS NULL OR node_id = ?4)
                         GROUP BY query_name
                         ORDER BY blocked DESC, queries DESC, query_name ASC
                         LIMIT ?3",
                    )
                    .map_err(db_err)?;
                let rows = stmt
                    .query_map(params![from, to, limit, node_id], |row| {
                        Ok(TopDomain {
                            domain: row.get(0)?,
                            queries: row.get(1)?,
                            blocked: row.get(2)?,
                        })
                    })
                    .map_err(db_err)?;
                rows.collect::<Result<Vec<_>, _>>().map_err(db_err)
            })
            .await?;
        Ok(TopDomains {
            from: format_micros(from),
            to: format_micros(to),
            domains,
        })
    }

    /// Cache hit statistics for `[from_us, to_us]`.
    ///
    /// Counts the `resolve` pipeline step stored in each record: `cache` is a
    /// hit, everything else (`recursion`, `stale`) is a miss.
    pub async fn cache_stats(
        &self,
        from_us: Option<i64>,
        to_us: Option<i64>,
        node_id: Option<&str>,
    ) -> Result<CacheStats, ControlApiError> {
        let db = self.db();
        let (from, to) = resolve_window(db, from_us, to_us)?;
        let node_id = node_id.map(str::to_owned);
        let (hits, misses) = db
            .with_conn(move |conn| {
                conn.query_row(
                    "SELECT
                         COALESCE(SUM(CASE WHEN json_extract(step.value, '$.source') = 'cache'
                                           THEN 1 ELSE 0 END), 0),
                         COALESCE(SUM(CASE WHEN json_extract(step.value, '$.source') <> 'cache'
                                           THEN 1 ELSE 0 END), 0)
                     FROM query_log AS q, json_each(q.record, '$.steps') AS step
                     WHERE q.time >= ?1 AND q.time <= ?2
                       AND (?3 IS NULL OR q.node_id = ?3)
                       AND json_extract(step.value, '$.stage') = 'resolve'",
                    params![from, to, node_id],
                    |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
                )
                .map_err(db_err)
            })
            .await?;
        Ok(CacheStats {
            from: format_micros(from),
            to: format_micros(to),
            hits,
            misses,
            hit_ratio: ratio(hits, hits.saturating_add(misses)),
        })
    }
}

/// Resolves `from`/`to` defaults (last 24 hours) on the injected clock.
fn resolve_window(
    db: &Db,
    from_us: Option<i64>,
    to_us: Option<i64>,
) -> Result<(i64, i64), ControlApiError> {
    let now_us = db.now_unix().saturating_mul(1_000_000);
    let to = to_us.unwrap_or(now_us);
    let from = from_us.unwrap_or_else(|| to.saturating_sub(DEFAULT_WINDOW_HOURS * MICROS_PER_HOUR));
    if from > to {
        // Keep the A12 code: stats windows are query-log filters.
        return Err(ControlApiError::QueryLogInvalid {
            reason: "`from` must not be after `to`".to_owned(),
        });
    }
    Ok((from, to))
}

/// Counts rows in `[from, to]` grouped by the fixed SQL expression `expr`.
async fn counts_by(
    db: &Db,
    expr: &'static str,
    from: i64,
    to: i64,
    node_id: Option<String>,
) -> Result<BTreeMap<String, i64>, ControlApiError> {
    db.with_conn(move |conn| {
        // `expr` is always a constant from this module, never user input.
        let sql = format!(
            "SELECT COALESCE({expr}, ''), COUNT(*) FROM query_log
             WHERE time >= ?1 AND time <= ?2
               AND (?3 IS NULL OR node_id = ?3) GROUP BY 1"
        );
        let mut stmt = conn.prepare(&sql).map_err(db_err)?;
        let rows = stmt
            .query_map(params![from, to, node_id], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
            })
            .map_err(db_err)?;
        let mut counts = BTreeMap::new();
        for row in rows {
            let (key, count) = row.map_err(db_err)?;
            counts.insert(key, count);
        }
        Ok(counts)
    })
    .await
}

/// Streams the filtered query log as a response body.
///
/// The first page is fetched before the response is built so a storage failure
/// is a normal `control_api.query_log.export` 500; later pages are streamed
/// from SQLite in `rowid` order and written to the body incrementally.
pub(crate) async fn export_body(
    log: Arc<QueryLog>,
    filter: QueryLogFilter,
    format: ExportFormat,
) -> Result<Body, ControlApiError> {
    let first_page = log.export_records(&filter, 0, EXPORT_PAGE_ROWS).await?;
    let (tx, rx) = mpsc::channel::<Result<Bytes, ControlApiError>>(EXPORT_CHANNEL_DEPTH);
    tokio::spawn(async move {
        stream_export(&log, &filter, first_page, format, &tx).await;
    });
    Ok(Body::new(ChannelBody { rx }))
}

/// Writes the header (CSV) and every page to `tx` until the export ends or the
/// client disconnects.
async fn stream_export(
    log: &QueryLog,
    filter: &QueryLogFilter,
    first_page: Vec<(i64, String)>,
    format: ExportFormat,
    tx: &mpsc::Sender<Result<Bytes, ControlApiError>>,
) {
    if format == ExportFormat::Csv {
        let header = format!("{}\n", CSV_COLUMNS.join(","));
        if tx.send(Ok(Bytes::from(header))).await.is_err() {
            return;
        }
    }
    let mut page = first_page;
    while !page.is_empty() {
        let cursor = page.last().map_or(0, |(rowid, _)| *rowid);
        let chunk = match format {
            ExportFormat::Ndjson => Ok(ndjson_chunk(&page)),
            ExportFormat::Csv => csv_chunk(&page),
        };
        match chunk {
            Ok(chunk) => {
                if tx.send(Ok(Bytes::from(chunk))).await.is_err() {
                    return;
                }
            }
            Err(error) => {
                let _ = tx.send(Err(error)).await;
                return;
            }
        }
        page = match log.export_records(filter, cursor, EXPORT_PAGE_ROWS).await {
            Ok(page) => page,
            Err(error) => {
                let _ = tx.send(Err(error)).await;
                return;
            }
        };
    }
}

/// Renders one NDJSON chunk (stored records, one per line).
fn ndjson_chunk(page: &[(i64, String)]) -> String {
    let mut chunk = String::new();
    for (_, raw) in page {
        chunk.push_str(raw);
        chunk.push('\n');
    }
    chunk
}

/// Renders one CSV chunk.
fn csv_chunk(page: &[(i64, String)]) -> Result<String, ControlApiError> {
    let mut chunk = String::new();
    for (_, raw) in page {
        chunk.push_str(&csv_row(raw)?);
    }
    Ok(chunk)
}

/// Projects one stored record onto [`CSV_COLUMNS`].
fn csv_row(raw: &str) -> Result<String, ControlApiError> {
    let record: Json =
        serde_json::from_str(raw).map_err(|error| ControlApiError::QueryLogExport {
            message: format!("stored query-log record is not valid JSON: {error}"),
        })?;
    let fields = [
        json_field(&record, &["id"]),
        json_field(&record, &["time"]),
        json_field(&record, &["node_id"]),
        json_field(&record, &["listener_id"]),
        json_field(&record, &["protocol"]),
        json_field(&record, &["source_ip"]),
        json_field(&record, &["source_ip_truncated"]),
        json_field(&record, &["client_id"]),
        json_field(&record, &["client", "display_name"]),
        json_field(&record, &["query", "name"]),
        json_field(&record, &["query", "type"]),
        json_field(&record, &["query", "class"]),
        json_field(&record, &["view_id"]),
        json_field(&record, &["profile_id"]),
        json_field(&record, &["answer_source"]),
        json_field(&record, &["dnssec"]),
        json_field(&record, &["rcode"]),
        json_field(&record, &["answer_size"]),
    ];
    let mut row = fields
        .iter()
        .map(|field| csv_escape(field))
        .collect::<Vec<_>>()
        .join(",");
    row.push('\n');
    Ok(row)
}

/// Reads a nested JSON scalar as text (`""` for absent/null).
fn json_field(record: &Json, path: &[&str]) -> String {
    let mut current = record;
    for key in path {
        match current.get(*key) {
            Some(value) => current = value,
            None => return String::new(),
        }
    }
    match current {
        Json::Null => String::new(),
        Json::String(value) => value.clone(),
        other => other.to_string(),
    }
}

/// Quotes a CSV field when it contains a comma, quote or line break, and
/// neutralises spreadsheet formula injection (a leading `=`, `+`, `-`, `@`,
/// tab or CR) with the standard single-quote prefix.
fn csv_escape(field: &str) -> String {
    let field = if field
        .chars()
        .next()
        .is_some_and(|c| matches!(c, '=' | '+' | '-' | '@' | '\t' | '\r'))
    {
        format!("'{field}")
    } else {
        field.to_owned()
    };
    if field
        .chars()
        .any(|ch| matches!(ch, ',' | '"' | '\n' | '\r'))
    {
        format!("\"{}\"", field.replace('"', "\"\""))
    } else {
        field
    }
}

/// Formats unix microseconds as RFC 3339 (or the raw value if out of range).
fn format_micros(micros: i64) -> String {
    time::OffsetDateTime::from_unix_timestamp_nanos(i128::from(micros) * 1_000)
        .ok()
        .and_then(|time| {
            time.format(time::macros::format_description!(
                "[year]-[month]-[day]T[hour]:[minute]:[second].[subsecond digits:6]Z"
            ))
            .ok()
        })
        .unwrap_or_else(|| format!("{micros}us"))
}

/// `part / whole`, or `0.0` when `whole` is not positive.
fn ratio(part: i64, whole: i64) -> f64 {
    if whole <= 0 {
        0.0
    } else {
        part as f64 / whole as f64
    }
}

/// Response body backed by a bounded channel of rendered chunks.
struct ChannelBody {
    rx: mpsc::Receiver<Result<Bytes, ControlApiError>>,
}

impl HttpBody for ChannelBody {
    type Data = Bytes;
    type Error = ControlApiError;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        match self.get_mut().rx.poll_recv(cx) {
            Poll::Ready(Some(Ok(bytes))) => Poll::Ready(Some(Ok(Frame::data(bytes)))),
            Poll::Ready(Some(Err(error))) => Poll::Ready(Some(Err(error))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn csv_escape_quotes_only_when_needed() {
        assert_eq!(csv_escape("plain"), "plain");
        assert_eq!(csv_escape("a,b"), "\"a,b\"");
        assert_eq!(csv_escape("a\"b"), "\"a\"\"b\"");
        assert_eq!(csv_escape("a\nb"), "\"a\nb\"");
    }

    #[test]
    fn csv_escape_neutralises_formula_injection() {
        for field in [
            "=1+1",
            "+cmd|' /C calc'!A0",
            "-2+3",
            "@SUM(A1)",
            "\t=HYPERLINK(\"http://example.net\")",
        ] {
            let escaped = csv_escape(field);
            assert!(
                !escaped.starts_with(&['=', '+', '-', '@', '\t'][..]),
                "{field:?} escaped to {escaped:?}"
            );
        }
        assert_eq!(csv_escape("=1+1"), "'=1+1");
        assert_eq!(csv_escape("+1+1"), "'+1+1");
    }

    #[test]
    fn json_field_reads_nested_scalars() {
        let record = serde_json::json!({
            "client": { "display_name": "iPhone" },
            "client_id": null,
            "answer_size": 184,
        });
        assert_eq!(json_field(&record, &["client", "display_name"]), "iPhone");
        assert_eq!(json_field(&record, &["client_id"]), "");
        assert_eq!(json_field(&record, &["missing"]), "");
        assert_eq!(json_field(&record, &["answer_size"]), "184");
    }

    #[test]
    fn ratio_is_zero_for_an_empty_denominator() {
        assert_eq!(ratio(0, 0), 0.0);
        assert_eq!(ratio(1, 4), 0.25);
    }
}
