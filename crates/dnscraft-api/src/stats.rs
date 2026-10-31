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

use std::collections::{BTreeMap, HashMap};
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
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
/// Raw-log days each rollup pass recomputes; covers rows a node delivers late after being offline.
const ROLLUP_RECOMPUTE_DAYS: i64 = 3;

const MICROS_PER_HOUR: i64 = 3_600_000_000;
const SECONDS_PER_HOUR: i64 = 3_600;
const SECONDS_PER_DAY: i64 = 86_400;
/// Rules listed in the overview's `filter_hits.top_rules`.
const OVERVIEW_TOP_RULES: i64 = 10;
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

/// One blocking rule and how often it fired in the window.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RuleHits {
    /// Rule text as written in its list or custom set.
    pub rule: String,
    /// Queries blocked by the rule.
    pub hits: i64,
}

/// Filter hits (blocked queries) broken down by source for one window.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct FilterHits {
    /// Queries that hit any filter rule.
    pub total: i64,
    /// Hits by filter list id (custom, service and MCP rules have no list).
    pub by_list: BTreeMap<String, i64>,
    /// Hits by rule provenance (`list`, `custom`, `service`, …).
    pub by_reason: BTreeMap<String, i64>,
    /// Most-hit rules, at most [`OVERVIEW_TOP_RULES`].
    pub top_rules: Vec<RuleHits>,
}

/// Aggregated dashboard statistics for one window.
///
/// `source` is `raw` when the window lies inside the raw query-log retention
/// and `rollup` otherwise. Rollups keep only protocol, profile, answer origin
/// and node, so in `rollup` mode `by_view`, `by_rcode` and `dnssec` are empty,
/// `active_clients` and `filter_hits` are `null`, and `blocked` counts the
/// `filter_block` answer origin. Windows are day-granular in rollup mode.
#[derive(Clone, Debug, Serialize)]
pub struct StatsOverview {
    /// `raw` or `rollup`: which storage answered the request.
    pub source: &'static str,
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
    /// Distinct attributed clients in the window (`null` in rollup mode).
    pub active_clients: Option<i64>,
    /// Events dropped by the query-log sink since process start (node-local).
    pub query_log_dropped: u64,
    /// Live-stream events skipped by lagging subscribers since process start.
    pub query_log_stream_dropped: u64,
    /// Filter-hit breakdown (`null` in rollup mode).
    pub filter_hits: Option<FilterHits>,
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
    ///
    /// Only the last [`ROLLUP_RECOMPUTE_DAYS`] are re-read (everything on the
    /// first pass, while the rollups are empty): the pass holds the single
    /// writer connection, and a full-table scan would stall config saves and
    /// log ingestion for as long as it runs.
    pub async fn run_rollup(&self) -> Result<(), ControlApiError> {
        let now = self.db().now_unix();
        let cutoff_seconds = now.saturating_sub(ROLLUP_RETENTION_DAYS * SECONDS_PER_DAY);
        let hour_cutoff = cutoff_seconds.div_euclid(SECONDS_PER_HOUR);
        let day_cutoff = cutoff_seconds.div_euclid(SECONDS_PER_DAY);
        let recent_us = now
            .saturating_sub(ROLLUP_RECOMPUTE_DAYS * SECONDS_PER_DAY)
            .saturating_mul(1_000_000);
        self.db()
            .with_conn(move |conn| {
                let tx = conn.transaction().map_err(db_err)?;
                let seeded: bool = tx
                    .query_row("SELECT EXISTS(SELECT 1 FROM stats_daily)", [], |row| {
                        row.get(0)
                    })
                    .map_err(db_err)?;
                let since_us = if seeded { recent_us } else { 0 };
                tx.execute(
                    "INSERT INTO stats_hourly (
                         hour, node_id, profile_id, protocol, answer_source, query_count
                     )
                     SELECT time / 3600000000, node_id, profile_id, protocol, answer_source, COUNT(*)
                     FROM query_log
                     WHERE time >= ?1
                     GROUP BY 1, 2, 3, 4, 5
                     ON CONFLICT(hour, node_id, profile_id, protocol, answer_source)
                     DO UPDATE SET query_count = MAX(query_count, excluded.query_count)",
                    params![since_us],
                )
                .map_err(db_err)?;
                tx.execute(
                    "INSERT INTO stats_daily (
                         day, node_id, profile_id, protocol, answer_source, query_count
                     )
                     SELECT time / 86400000000, node_id, profile_id, protocol, answer_source, COUNT(*)
                     FROM query_log
                     WHERE time >= ?1
                     GROUP BY 1, 2, 3, 4, 5
                     ON CONFLICT(day, node_id, profile_id, protocol, answer_source)
                     DO UPDATE SET query_count = MAX(query_count, excluded.query_count)",
                    params![since_us],
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
            .with_read_conn(move |conn| {
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
    /// clock. `from > to` is `control_api.query_log.invalid`. A window that
    /// starts before the raw retention horizon is answered from the daily
    /// rollups (GA16), see [`StatsOverview`].
    pub async fn stats_overview(
        &self,
        from_us: Option<i64>,
        to_us: Option<i64>,
        node_id: Option<&str>,
    ) -> Result<StatsOverview, ControlApiError> {
        self.stats_overview_scoped(
            from_us,
            to_us,
            StatsScope {
                node_id,
                profile_id: None,
            },
        )
        .await
    }

    /// [`Self::stats_overview`] restricted by a [`StatsScope`] (GM6 profile filter).
    pub async fn stats_overview_scoped(
        &self,
        from_us: Option<i64>,
        to_us: Option<i64>,
        scope: StatsScope<'_>,
    ) -> Result<StatsOverview, ControlApiError> {
        let db = self.db();
        let (from, to) = resolve_window(db, from_us, to_us)?;
        let scope = Scope::from(scope);
        let dropped = self.sink_dropped();
        let stream_dropped = self.stream_dropped();
        let retention_secs =
            i64::from(self.config().retention_days).saturating_mul(SECONDS_PER_DAY);
        let raw_horizon = db
            .now_unix()
            .saturating_sub(retention_secs)
            .saturating_mul(1_000_000);
        if from < raw_horizon {
            let rolled =
                rollup_overview(db, from, to, scope.clone(), dropped, stream_dropped).await?;
            // Rollups can lag (or be empty before the first pass): never show
            // less than the raw rows that exist in the window.
            let raw_total = raw_counts(db, from, to, &scope).await?.total;
            if raw_total <= rolled.total {
                return Ok(rolled);
            }
        }
        let counts = raw_counts(db, from, to, &scope).await?;
        let RawCounts {
            total,
            allowed,
            blocked,
            by_protocol,
            by_view,
            by_profile,
            by_answer_source,
            by_rcode,
            dnssec,
            by_list,
            by_reason,
        } = counts;
        let active_clients = db
            .with_read_conn({
                let scope = scope.clone();
                move |conn| {
                    conn.query_row(
                        "SELECT COUNT(DISTINCT COALESCE(device_id, client_id, client_name)) FROM query_log
                         WHERE time >= ?1 AND time <= ?2
                           AND COALESCE(device_id, client_id, client_name) IS NOT NULL
                           AND (?3 IS NULL OR node_id = ?3)
                           AND (?4 IS NULL OR profile_id = ?4)",
                        params![from, to, scope.node_id, scope.profile_id],
                        |row| row.get::<_, i64>(0),
                    )
                    .map_err(db_err)
                }
            })
            .await?;
        let filter_hits = filter_hits(db, from, to, &scope, by_list, by_reason).await?;
        Ok(StatsOverview {
            source: "raw",
            from: format_micros(from),
            to: format_micros(to),
            total,
            allowed,
            blocked,
            allowed_ratio: ratio(allowed, total),
            active_clients: Some(active_clients),
            query_log_dropped: dropped,
            query_log_stream_dropped: stream_dropped,
            filter_hits: Some(filter_hits),
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
    /// `limit` is clamped to `1..=TOP_CLIENTS_MAX`. A device is its client id, else its directory
    /// name, else its source address.
    pub async fn top_clients(
        &self,
        from_us: Option<i64>,
        to_us: Option<i64>,
        node_id: Option<&str>,
        limit: u32,
        by: TopBy,
    ) -> Result<TopClients, ControlApiError> {
        let scope = StatsScope {
            node_id,
            profile_id: None,
        };
        self.top_clients_scoped(from_us, to_us, scope, limit, by)
            .await
    }

    /// [`Self::top_clients`] restricted by a [`StatsScope`].
    pub async fn top_clients_scoped(
        &self,
        from_us: Option<i64>,
        to_us: Option<i64>,
        scope: StatsScope<'_>,
        limit: u32,
        by: TopBy,
    ) -> Result<TopClients, ControlApiError> {
        let db = self.db();
        let (from, to) = resolve_window(db, from_us, to_us)?;
        let scope = Scope::from(scope);
        let limit = i64::from(limit.clamp(1, TOP_CLIENTS_MAX));
        let order = match by {
            TopBy::Queries => "queries DESC, cid ASC",
            TopBy::Blocked => "blocked DESC, queries DESC, cid ASC",
        };
        let clients = db
            .with_read_conn(move |conn| {
                let sql = format!(
                    // A device is its directory client id, else its client id, else its directory
                    // name, else its source address (LAN clients carry no client id). `cid` is the
                    // id, or the address when the row has neither id nor name.
                    "SELECT COALESCE(device_id, client_id, CASE WHEN client_name IS NULL THEN source_ip ELSE '' END) AS cid,
                            COALESCE(MAX(client_name), ''),
                            COUNT(*) AS queries,
                            COALESCE(SUM(CASE WHEN status = 'blocked' THEN 1 ELSE 0 END), 0)
                                AS blocked
                     FROM query_log
                     WHERE time >= ?1 AND time <= ?2
                       AND (?4 IS NULL OR node_id = ?4)
                       AND (?5 IS NULL OR profile_id = ?5)
                     GROUP BY COALESCE(device_id, client_id, client_name, source_ip)
                     ORDER BY {order}
                     LIMIT ?3"
                );
                let mut stmt = conn.prepare(&sql).map_err(db_err)?;
                let rows = stmt
                    .query_map(
                        params![from, to, limit, scope.node_id, scope.profile_id],
                        |row| {
                            Ok(TopClient {
                                client_id: row.get(0)?,
                                client_name: row.get(1)?,
                                queries: row.get(2)?,
                                blocked: row.get(3)?,
                            })
                        },
                    )
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
        let scope = StatsScope {
            node_id,
            profile_id: None,
        };
        self.top_domains_scoped(from_us, to_us, scope, limit).await
    }

    /// [`Self::top_domains`] restricted by a [`StatsScope`].
    pub async fn top_domains_scoped(
        &self,
        from_us: Option<i64>,
        to_us: Option<i64>,
        scope: StatsScope<'_>,
        limit: u32,
    ) -> Result<TopDomains, ControlApiError> {
        self.ranked_domains(from_us, to_us, scope, limit, "queries DESC, query_name ASC")
            .await
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
        let scope = StatsScope {
            node_id,
            profile_id: None,
        };
        self.top_blocked_domains_scoped(from_us, to_us, scope, limit)
            .await
    }

    /// [`Self::top_blocked_domains`] restricted by a [`StatsScope`].
    pub async fn top_blocked_domains_scoped(
        &self,
        from_us: Option<i64>,
        to_us: Option<i64>,
        scope: StatsScope<'_>,
        limit: u32,
    ) -> Result<TopDomains, ControlApiError> {
        self.ranked_domains(
            from_us,
            to_us,
            scope,
            limit,
            "blocked DESC, queries DESC, query_name ASC",
        )
        .await
    }

    /// Shared body of the two domain rankings; `order` is a fixed constant.
    async fn ranked_domains(
        &self,
        from_us: Option<i64>,
        to_us: Option<i64>,
        scope: StatsScope<'_>,
        limit: u32,
        order: &'static str,
    ) -> Result<TopDomains, ControlApiError> {
        let db = self.db();
        let (from, to) = resolve_window(db, from_us, to_us)?;
        let scope = Scope::from(scope);
        let limit = i64::from(limit.clamp(1, TOP_DOMAINS_MAX));
        let domains = db
            .with_read_conn(move |conn| {
                // `order` is always one of the constants passed above.
                let sql = format!(
                    "SELECT query_name,
                            COUNT(*) AS queries,
                            COALESCE(SUM(CASE WHEN status = 'blocked' THEN 1 ELSE 0 END), 0)
                                AS blocked
                     FROM query_log
                     WHERE time >= ?1 AND time <= ?2
                       AND (?4 IS NULL OR node_id = ?4)
                       AND (?5 IS NULL OR profile_id = ?5)
                     GROUP BY query_name
                     ORDER BY {order}
                     LIMIT ?3"
                );
                let mut stmt = conn.prepare(&sql).map_err(db_err)?;
                let rows = stmt
                    .query_map(
                        params![from, to, limit, scope.node_id, scope.profile_id],
                        |row| {
                            Ok(TopDomain {
                                domain: row.get(0)?,
                                queries: row.get(1)?,
                                blocked: row.get(2)?,
                            })
                        },
                    )
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
        let scope = StatsScope {
            node_id,
            profile_id: None,
        };
        self.cache_stats_scoped(from_us, to_us, scope).await
    }

    /// [`Self::cache_stats`] restricted by a [`StatsScope`].
    pub async fn cache_stats_scoped(
        &self,
        from_us: Option<i64>,
        to_us: Option<i64>,
        scope: StatsScope<'_>,
    ) -> Result<CacheStats, ControlApiError> {
        let db = self.db();
        let (from, to) = resolve_window(db, from_us, to_us)?;
        let scope = Scope::from(scope);
        let (hits, misses) = db
            .with_read_conn(move |conn| {
                conn.query_row(
                    "SELECT
                         COALESCE(SUM(CASE WHEN json_extract(step.value, '$.source') = 'cache'
                                           THEN 1 ELSE 0 END), 0),
                         COALESCE(SUM(CASE WHEN json_extract(step.value, '$.source') <> 'cache'
                                           THEN 1 ELSE 0 END), 0)
                     FROM query_log AS q, json_each(q.record, '$.steps') AS step
                     WHERE q.time >= ?1 AND q.time <= ?2
                       AND (?3 IS NULL OR q.node_id = ?3)
                       AND (?4 IS NULL OR q.profile_id = ?4)
                       AND json_extract(step.value, '$.stage') = 'resolve'",
                    params![from, to, scope.node_id, scope.profile_id],
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

/// Optional node and profile filters shared by the dashboard aggregations
/// (GM6 adds the profile dimension; `None` means "all").
#[derive(Clone, Copy, Debug, Default)]
pub struct StatsScope<'a> {
    /// Exact `node_id` filter.
    pub node_id: Option<&'a str>,
    /// Exact policy profile filter.
    pub profile_id: Option<&'a str>,
}

/// Owned form of [`StatsScope`] for moving into `with_conn` closures.
#[derive(Clone, Debug, Default)]
struct Scope {
    node_id: Option<String>,
    profile_id: Option<String>,
}

impl From<StatsScope<'_>> for Scope {
    fn from(scope: StatsScope<'_>) -> Self {
        Self {
            node_id: scope.node_id.map(str::to_owned),
            profile_id: scope.profile_id.map(str::to_owned),
        }
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

/// Filter-hit breakdown over the raw log for `[from, to]`.
async fn filter_hits(
    db: &Db,
    from: i64,
    to: i64,
    scope: &Scope,
    by_list: BTreeMap<String, i64>,
    by_reason: BTreeMap<String, i64>,
) -> Result<FilterHits, ControlApiError> {
    let scope = scope.clone();
    let top_rules = db
        .with_read_conn(move |conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT json_extract(record, '$.filter.rule_text') AS rule, COUNT(*) AS hits
                     FROM query_log
                     WHERE time >= ?1 AND time <= ?2
                       AND json_extract(record, '$.filter.rule_text') IS NOT NULL
                       AND (?3 IS NULL OR node_id = ?3)
                       AND (?4 IS NULL OR profile_id = ?4)
                     GROUP BY rule
                     ORDER BY hits DESC, rule ASC
                     LIMIT ?5",
                )
                .map_err(db_err)?;
            let rows = stmt
                .query_map(
                    params![
                        from,
                        to,
                        scope.node_id,
                        scope.profile_id,
                        OVERVIEW_TOP_RULES
                    ],
                    |row| {
                        Ok(RuleHits {
                            rule: row.get(0)?,
                            hits: row.get(1)?,
                        })
                    },
                )
                .map_err(db_err)?;
            rows.collect::<Result<Vec<_>, _>>().map_err(db_err)
        })
        .await?;
    let total = by_reason.values().sum();
    Ok(FilterHits {
        total,
        by_list,
        by_reason,
        top_rules,
    })
}

/// Raw-window counts for the overview, gathered in one pass over the log.
///
/// Rows are wide (the `record` JSON), so every separate `GROUP BY` re-reads the whole window; one
/// grouped scan answers all breakdowns. `json_extract` takes several paths at once so the JSON is
/// parsed once per row.
struct RawCounts {
    total: i64,
    allowed: i64,
    blocked: i64,
    by_protocol: BTreeMap<String, i64>,
    by_view: BTreeMap<String, i64>,
    by_profile: BTreeMap<String, i64>,
    by_answer_source: BTreeMap<String, i64>,
    by_rcode: BTreeMap<String, i64>,
    dnssec: BTreeMap<String, i64>,
    /// Filter hits by list id (unfiltered rows excluded).
    by_list: BTreeMap<String, i64>,
    /// Filter hits by rule provenance (unfiltered rows excluded).
    by_reason: BTreeMap<String, i64>,
}

async fn raw_counts(
    db: &Db,
    from: i64,
    to: i64,
    scope: &Scope,
) -> Result<RawCounts, ControlApiError> {
    let scope = scope.clone();
    db.with_read_conn(move |conn| {
        let mut stmt = conn
            .prepare(
                "SELECT protocol, view_id, profile_id, answer_source, rcode, status,
                        json_extract(record, '$.dnssec', '$.filter.list_id', '$.filter.reason'),
                        COUNT(*)
                 FROM query_log
                 WHERE time >= ?1 AND time <= ?2
                   AND (?3 IS NULL OR node_id = ?3)
                   AND (?4 IS NULL OR profile_id = ?4)
                 GROUP BY 1, 2, 3, 4, 5, 6, 7",
            )
            .map_err(db_err)?;
        let rows = stmt
            .query_map(params![from, to, scope.node_id, scope.profile_id], |row| {
                Ok((
                    [
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, String>(5)?,
                    ],
                    row.get::<_, Option<String>>(6)?,
                    row.get::<_, i64>(7)?,
                ))
            })
            .map_err(db_err)?;
        let mut out = RawCounts {
            total: 0,
            allowed: 0,
            blocked: 0,
            by_protocol: BTreeMap::new(),
            by_view: BTreeMap::new(),
            by_profile: BTreeMap::new(),
            by_answer_source: BTreeMap::new(),
            by_rcode: BTreeMap::new(),
            dnssec: BTreeMap::new(),
            by_list: BTreeMap::new(),
            by_reason: BTreeMap::new(),
        };
        for row in rows {
            let ([protocol, view, profile, answer_source, rcode, status], json, count) =
                row.map_err(db_err)?;
            out.total += count;
            match status.as_str() {
                "allowed" => out.allowed += count,
                "blocked" => out.blocked += count,
                _ => {}
            }
            // `[dnssec, filter.list_id, filter.reason]`, each `null` when absent.
            let paths: Vec<Json> = json
                .as_deref()
                .and_then(|text| serde_json::from_str(text).ok())
                .unwrap_or_default();
            let text_at = |index: usize| {
                paths
                    .get(index)
                    .and_then(Json::as_str)
                    .unwrap_or_default()
                    .to_owned()
            };
            *out.by_protocol.entry(protocol).or_default() += count;
            *out.by_view.entry(view).or_default() += count;
            *out.by_profile.entry(profile).or_default() += count;
            *out.by_answer_source.entry(answer_source).or_default() += count;
            *out.by_rcode.entry(rcode).or_default() += count;
            *out.dnssec.entry(text_at(0)).or_default() += count;
            for (map, key) in [
                (&mut out.by_list, text_at(1)),
                (&mut out.by_reason, text_at(2)),
            ] {
                if !key.is_empty() {
                    *map.entry(key).or_default() += count;
                }
            }
        }
        Ok(out)
    })
    .await
}

/// Overview answered from the daily rollups (see [`StatsOverview`]).
async fn rollup_overview(
    db: &Db,
    from: i64,
    to: i64,
    scope: Scope,
    dropped: u64,
    stream_dropped: u64,
) -> Result<StatsOverview, ControlApiError> {
    let from_day = from.div_euclid(MICROS_PER_DAY);
    let to_day = to.div_euclid(MICROS_PER_DAY);
    let (total, blocked) = db
        .with_read_conn({
            let scope = scope.clone();
            move |conn| {
                conn.query_row(
                    "SELECT COALESCE(SUM(query_count), 0),
                            COALESCE(SUM(CASE WHEN answer_source = 'filter_block'
                                              THEN query_count ELSE 0 END), 0)
                     FROM stats_daily
                     WHERE day >= ?1 AND day <= ?2
                       AND (?3 IS NULL OR node_id = ?3)
                       AND (?4 IS NULL OR profile_id = ?4)",
                    params![from_day, to_day, scope.node_id, scope.profile_id],
                    |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
                )
                .map_err(db_err)
            }
        })
        .await?;
    let by_protocol = rollup_counts_by(db, "protocol", from_day, to_day, &scope).await?;
    let by_profile = rollup_counts_by(db, "profile_id", from_day, to_day, &scope).await?;
    let by_answer_source = rollup_counts_by(db, "answer_source", from_day, to_day, &scope).await?;
    Ok(StatsOverview {
        source: "rollup",
        from: format_micros(from),
        to: format_micros(to),
        total,
        allowed: total - blocked,
        blocked,
        allowed_ratio: ratio(total - blocked, total),
        active_clients: None,
        query_log_dropped: dropped,
        query_log_stream_dropped: stream_dropped,
        filter_hits: None,
        by_protocol,
        by_view: BTreeMap::new(),
        by_profile,
        by_answer_source,
        by_rcode: BTreeMap::new(),
        dnssec: BTreeMap::new(),
    })
}

/// Sums rollup `query_count` per the fixed column `expr` over whole days.
async fn rollup_counts_by(
    db: &Db,
    expr: &'static str,
    from_day: i64,
    to_day: i64,
    scope: &Scope,
) -> Result<BTreeMap<String, i64>, ControlApiError> {
    let scope = scope.clone();
    db.with_read_conn(move |conn| {
        // `expr` is always a constant from this module, never user input.
        let sql = format!(
            "SELECT {expr}, COALESCE(SUM(query_count), 0) FROM stats_daily
             WHERE day >= ?1 AND day <= ?2
               AND (?3 IS NULL OR node_id = ?3)
               AND (?4 IS NULL OR profile_id = ?4) GROUP BY 1"
        );
        let mut stmt = conn.prepare(&sql).map_err(db_err)?;
        let rows = stmt
            .query_map(
                params![from_day, to_day, scope.node_id, scope.profile_id],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)),
            )
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
pub(crate) struct ChannelBody {
    pub(crate) rx: mpsc::Receiver<Result<Bytes, ControlApiError>>,
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

/// Microseconds per day, for the query log's `time` column.
const MICROS_PER_DAY: i64 = 86_400_000_000;
/// Clients listed per domain (WX5).
const DOMAIN_TOP_CLIENTS: i64 = 10;

impl QueryLog {
    /// Per-domain detail over the raw query log (WX5). `None` when the name is
    /// not seen inside retention. `days` bounds the counts, the daily series and
    /// the top clients; `first_seen` and `last_seen` cover the whole retention.
    pub async fn domain_detail(
        &self,
        domain: &str,
        days: u32,
    ) -> Result<Option<Json>, ControlApiError> {
        let db = self.db();
        let name = domain.to_owned();
        let now_us = db.now_unix().saturating_mul(1_000_000);
        let from = now_us.saturating_sub(i64::from(days) * MICROS_PER_DAY);
        db.with_read_conn(move |conn| {
            use rusqlite::OptionalExtension as _;
            let (first, last): (Option<i64>, Option<i64>) = conn
                .query_row(
                    "SELECT MIN(time), MAX(time) FROM query_log WHERE query_name = ?1",
                    params![name],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .map_err(db_err)?;
            let (Some(first), Some(last)) = (first, last) else {
                return Ok(None);
            };
            let (total, blocked): (i64, i64) = conn
                .query_row(
                    "SELECT COUNT(*), COALESCE(SUM(CASE WHEN status = 'blocked' THEN 1 ELSE 0 END), 0)
                     FROM query_log WHERE query_name = ?1 AND time >= ?2",
                    params![name, from],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .map_err(db_err)?;

            let mut stmt = conn
                .prepare(
                    "SELECT COALESCE(client_name, client_id, source_ip) AS who, COUNT(*)
                     FROM query_log WHERE query_name = ?1 AND time >= ?2
                     GROUP BY who ORDER BY COUNT(*) DESC, who ASC LIMIT ?3",
                )
                .map_err(db_err)?;
            let clients: Vec<Json> = stmt
                .query_map(params![name, from, DOMAIN_TOP_CLIENTS], |row| {
                    Ok(serde_json::json!({
                        "client": row.get::<_, String>(0)?,
                        "queries": row.get::<_, i64>(1)?,
                    }))
                })
                .map_err(db_err)?
                .collect::<Result<_, _>>()
                .map_err(db_err)?;

            let mut stmt = conn
                .prepare(
                    "SELECT time / ?4 AS day, COUNT(*),
                            COALESCE(SUM(CASE WHEN status = 'blocked' THEN 1 ELSE 0 END), 0)
                     FROM query_log WHERE query_name = ?1 AND time >= ?2
                     GROUP BY day ORDER BY day",
                )
                .map_err(db_err)?;
            let daily: Vec<Json> = stmt
                .query_map(params![name, from, MICROS_PER_DAY, MICROS_PER_DAY], |row| {
                    let day: i64 = row.get(0)?;
                    Ok(serde_json::json!({
                        "day": format_day(day),
                        "total": row.get::<_, i64>(1)?,
                        "blocked": row.get::<_, i64>(2)?,
                    }))
                })
                .map_err(db_err)?
                .collect::<Result<_, _>>()
                .map_err(db_err)?;

            let last_decision = conn
                .query_row(
                    "SELECT id, time, status, record FROM query_log
                     WHERE query_name = ?1 ORDER BY time DESC, id DESC LIMIT 1",
                    params![name],
                    |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, i64>(1)?,
                            row.get::<_, String>(2)?,
                            row.get::<_, String>(3)?,
                        ))
                    },
                )
                .optional()
                .map_err(db_err)?
                .map(|(id, time, status, record)| {
                    let filter = serde_json::from_str::<Json>(&record)
                        .ok()
                        .and_then(|value| value.get("filter").cloned())
                        .unwrap_or(Json::Null);
                    serde_json::json!({
                        "id": id,
                        "time": format_micros(time),
                        "status": status,
                        "rule_text": filter.get("rule_text").cloned().unwrap_or(Json::Null),
                        "source": filter.get("reason").cloned().unwrap_or(Json::Null),
                    })
                });

            Ok(Some(serde_json::json!({
                "domain": name,
                "retention_limited": true,
                "first_seen": format_micros(first),
                "last_seen": format_micros(last),
                "counts": { "total": total, "blocked": blocked, "allowed": total - blocked },
                "top_clients": clients,
                "daily": daily,
                "last_decision": last_decision,
            })))
        })
        .await
    }
}

/// `YYYY-MM-DD` for a day index (days since the Unix epoch).
fn format_day(day: i64) -> String {
    time::OffsetDateTime::from_unix_timestamp(day.saturating_mul(86_400))
        .map(|t| t.date().to_string())
        .unwrap_or_default()
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

type MemoSlot = Arc<tokio::sync::Mutex<Option<(i64, Json)>>>;

/// Short-lived answers of the dashboard aggregations (one slot per request shape).
///
/// Each aggregation scans the whole window, and the dashboard asks for seven of them every poll
/// (from every open tab). A slot is also a lock, so identical concurrent requests compute once.
#[derive(Default)]
pub(crate) struct StatsMemo(Mutex<HashMap<String, MemoSlot>>);

impl QueryLog {
    /// Returns the answer for `key`, computing it only when none younger than `ttl_secs` exists.
    /// Errors are never kept.
    pub(crate) async fn memoized<T, F>(
        &self,
        key: String,
        ttl_secs: i64,
        compute: F,
    ) -> Result<Json, ControlApiError>
    where
        T: Serialize,
        F: Future<Output = Result<T, ControlApiError>>,
    {
        let slot = {
            let mut map = self
                .stats_memo
                .0
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            // Keys embed the window, so they drift; a bounded map is enough.
            if map.len() > 128 && !map.contains_key(&key) {
                map.clear();
            }
            Arc::clone(map.entry(key).or_default())
        };
        let mut guard = slot.lock().await;
        let now = self.db().now_unix();
        if let Some((at, value)) = guard.as_ref()
            && now.saturating_sub(*at) < ttl_secs
        {
            return Ok(value.clone());
        }
        let value =
            serde_json::to_value(compute.await?).map_err(|error| ControlApiError::Internal {
                message: error.to_string(),
            })?;
        *guard = Some((now, value.clone()));
        Ok(value)
    }
}
