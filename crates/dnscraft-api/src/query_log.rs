//! Query-log consumer, storage, filtering and "why blocked?" data (A12).
//!
//! The listener set publishes bounded [`QueryEvent`]s through
//! [`QueryLog::channel`]'s [`QueryLogSink`]. The sink never blocks: when the
//! bounded channel is full (or closed) it drops the event and increments its
//! [`QueryLogSink::dropped`] counter, which is surfaced as the stable
//! `control_api.query_log.dropped` code. [`QueryLog::run`] (or
//! [`QueryLog::flush_ready`] in tests) drains the channel and batch-inserts
//! into SQLite.
//!
//! Records are stored as one JSON document per row plus denormalised columns
//! for filtering and ordering. The document contains the full
//! [`dnscraft_policy::DecisionRecord`] (pipeline steps, filter hit, timings),
//! which backs the "why blocked?" endpoint.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use chrono::{DateTime, SecondsFormat, Utc};
use dnscraft_filtering::{BlockMode, RuleSource};
use dnscraft_listeners::{QueryEvent, QueryEventSink};
use dnscraft_policy::{
    AnswerOrigin, DecisionRecord, DecisionStep, DnsProtocol, FilterHit, SelectionCause,
};
use dnscraft_proto::Rcode;
use dnscraft_resolver::{AnswerSource, DnssecStatus};
use ring::rand::{SecureRandom, SystemRandom};
use rusqlite::params;
use rusqlite::params_from_iter;
use rusqlite::types::Value;
use serde_json::{Value as Json, json};
use tokio::sync::mpsc;

use crate::config::{IpTruncate, QueryLogConfig};
use crate::error::ControlApiError;
use crate::storage::{Db, db_err};

/// Largest batch drained from the channel before one SQLite transaction.
const BATCH_MAX: usize = 1024;

/// Milliseconds in a day, used to turn [`QueryLogConfig::retention_days`] into
/// a microsecond window.
const MICROS_PER_DAY: i64 = 86_400_000_000;

/// Client-directory data attached to a query-log record.
///
/// Control-api does not own a client directory; the binary supplies an
/// implementation of [`ClientEnricher`] backed by its `clients` engine. Keeping
/// this a narrow trait mirrors the other module adapters in
/// [`crate::modules`].
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ClientView {
    /// Directory client id.
    pub id: String,
    /// Display name (`"iPhone"`).
    pub display_name: String,
    /// Provenance (`"manual"` or `"unifi"`).
    pub source: String,
    /// MAC addresses in canonical form.
    pub macs: Vec<String>,
    /// VLAN id, when known.
    pub vlan_id: Option<u16>,
    /// VLAN name, when known.
    pub vlan_name: Option<String>,
    /// Per-client parent domain, when known.
    pub local_domain: Option<String>,
}

/// Resolves a source IP to client-directory data.
///
/// Called on the blocking pool for every inserted record; implementations must
/// be fast and allocation-light (a snapshot lookup, not network I/O).
pub trait ClientEnricher: Send + Sync {
    /// Returns the client matching `ip`, if any.
    fn by_ip(&self, ip: IpAddr) -> Option<ClientView>;
}

/// Column used to order query-log results.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum OrderBy {
    /// Record time (default).
    #[default]
    Time,
    /// Client display name (falling back to the client id).
    Client,
    /// Queried name.
    Domain,
    /// Response code.
    Rcode,
}

/// Sort direction.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Order {
    /// Ascending.
    Asc,
    /// Descending (default).
    #[default]
    Desc,
}

/// Validated query-log filter and pagination parameters.
///
/// Built by the HTTP route or directly by an in-process caller (for example the
/// MCP backend). Times are unix microseconds.
#[derive(Clone, Debug, Default)]
pub struct QueryLogFilter {
    /// Lower time bound (inclusive).
    pub from_us: Option<i64>,
    /// Upper time bound (inclusive).
    pub to_us: Option<i64>,
    /// Exact client id (DoH/DoT client id or directory id).
    pub client_id: Option<String>,
    /// Case-insensitive substring of the client display name.
    pub client_name_substr: Option<String>,
    /// Exact normalized owner name (no trailing dot).
    pub domain: Option<String>,
    /// Case-insensitive substring of the owner name.
    pub domain_substr: Option<String>,
    /// Transport (`udp53`, `tcp53`, `dot`, `doh`, `doq`).
    pub protocol: Option<String>,
    /// Exact policy view id.
    pub view_id: Option<String>,
    /// Exact policy profile id.
    pub profile_id: Option<String>,
    /// Derived outcome (`allowed`, `blocked`, `dnssec_bogus`, `servfail`).
    pub status: Option<String>,
    /// Shorthand for `status = blocked`.
    pub only_blocked: bool,
    /// Return only rows with client-directory data.
    pub only_with_clients: bool,
    /// Sort column.
    pub order_by: OrderBy,
    /// Sort direction.
    pub order: Order,
    /// Page size; clamped to the configured `max_rows_per_request`.
    pub limit: u32,
    /// Rows to skip.
    pub offset: u64,
}

/// One page of query-log records.
#[derive(Clone, Debug)]
pub struct QueryLogPage {
    /// Full record JSON documents (one per row).
    pub records: Vec<Json>,
    /// Whether at least one more row exists after this page.
    pub has_more: bool,
    /// Offset to request for the next page.
    pub next_offset: Option<u64>,
}

/// Sink half of the bounded query-log channel.
///
/// `try_send` never waits: a full or closed channel drops the event and
/// increments the counter behind [`Self::dropped`].
#[derive(Debug)]
pub struct QueryLogSink {
    tx: mpsc::Sender<QueryEvent>,
    dropped: AtomicU64,
}

impl QueryLogSink {
    /// Events dropped because the bounded channel was full or closed.
    ///
    /// This is the value surfaced as the informational
    /// `control_api.query_log.dropped` counter.
    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }
}

impl QueryEventSink for QueryLogSink {
    fn try_send(&self, event: QueryEvent) -> bool {
        // `emit_event` already filters, but stay defensive: a non-loggable
        // event is never a drop.
        if !event.loggable {
            return true;
        }
        match self.tx.try_send(event) {
            Ok(()) => true,
            Err(_) => {
                self.dropped.fetch_add(1, Ordering::Relaxed);
                false
            }
        }
    }

    fn events_dropped(&self) -> u64 {
        self.dropped()
    }
}

/// Query-log consumer, reader and retention owner.
pub struct QueryLog {
    db: Db,
    config: QueryLogConfig,
    node_id: String,
    enricher: Option<Arc<dyn ClientEnricher>>,
}

impl QueryLog {
    /// Creates a query log over `db` with the given retention/privacy policy.
    pub fn new(db: Db, config: QueryLogConfig, node_id: impl Into<String>) -> Self {
        Self {
            db,
            config,
            node_id: node_id.into(),
            enricher: None,
        }
    }

    /// Attaches the client-directory enricher used at write time.
    pub fn with_client_enricher(mut self, enricher: Arc<dyn ClientEnricher>) -> Self {
        self.enricher = Some(enricher);
        self
    }

    /// The active query-log configuration.
    pub fn config(&self) -> &QueryLogConfig {
        &self.config
    }

    /// Creates the bounded channel and its non-blocking sink.
    pub fn channel(capacity: usize) -> (Arc<QueryLogSink>, mpsc::Receiver<QueryEvent>) {
        let (tx, rx) = mpsc::channel(capacity.max(1));
        (
            Arc::new(QueryLogSink {
                tx,
                dropped: AtomicU64::new(0),
            }),
            rx,
        )
    }

    /// Drains `rx` forever, batch-inserting each burst until the channel closes.
    pub async fn run(self: Arc<Self>, mut rx: mpsc::Receiver<QueryEvent>) {
        loop {
            let Some(first) = rx.recv().await else {
                break;
            };
            let mut events = Vec::with_capacity(BATCH_MAX.min(64));
            events.push(first);
            while events.len() < BATCH_MAX {
                match rx.try_recv() {
                    Ok(event) => events.push(event),
                    Err(_) => break,
                }
            }
            if let Err(error) = self.insert_batch(events).await {
                tracing::error!(error = %error, "query-log batch insert failed");
            }
        }
    }

    /// Inserts every event currently buffered in `rx` in one transaction.
    ///
    /// Returns the number of rows written. Deterministic counterpart of
    /// [`Self::run`] for tests (no wall-clock waits).
    pub async fn flush_ready(
        &self,
        rx: &mut mpsc::Receiver<QueryEvent>,
    ) -> Result<usize, ControlApiError> {
        let mut events = Vec::new();
        while events.len() < BATCH_MAX {
            match rx.try_recv() {
                Ok(event) => events.push(event),
                Err(_) => break,
            }
        }
        if events.is_empty() {
            return Ok(0);
        }
        self.insert_batch(events).await
    }

    /// Batch-inserts `events`, applying IP truncation, client enrichment and
    /// retention. Non-loggable events are skipped.
    pub async fn insert_batch(&self, events: Vec<QueryEvent>) -> Result<usize, ControlApiError> {
        let db = self.db.clone();
        let config = self.config.clone();
        let node_id = self.node_id.clone();
        let enricher = self.enricher.clone();
        let now_us = self.db.now_unix().saturating_mul(1_000_000);
        db.with_conn(move |conn| {
            let mut rows = Vec::with_capacity(events.len());
            for event in &events {
                if event.loggable {
                    rows.push(prepare_row(event, &node_id, &config, enricher.as_deref())?);
                }
            }
            let cutoff = now_us
                .saturating_sub(i64::from(config.retention_days).saturating_mul(MICROS_PER_DAY));
            let tx = conn.transaction().map_err(db_err)?;
            // Retention is an indexed range delete; running it with each batch
            // keeps the window bounded without an extra timer task.
            tx.execute("DELETE FROM query_log WHERE time < ?1", params![cutoff])
                .map_err(db_err)?;
            {
                let mut stmt = tx
                    .prepare(
                        "INSERT INTO query_log (
                             id, time, node_id, source_ip, query_name, listener_id,
                             protocol, source_ip_truncated, client_id, client_name,
                             query_type, query_class, view_id, profile_id, status,
                             answer_source, rcode, record
                         ) VALUES (
                             ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10,
                             ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18
                         )",
                    )
                    .map_err(db_err)?;
                for row in &rows {
                    stmt.execute(params![
                        row.id,
                        row.time_us,
                        row.node_id,
                        row.source_ip,
                        row.query_name,
                        row.listener_id,
                        row.protocol,
                        row.source_ip_truncated,
                        row.client_id,
                        row.client_name,
                        row.query_type,
                        row.query_class,
                        row.view_id,
                        row.profile_id,
                        row.status,
                        row.answer_source,
                        row.rcode,
                        row.record,
                    ])
                    .map_err(db_err)?;
                }
            }
            tx.commit().map_err(db_err)?;
            Ok(rows.len())
        })
        .await
    }

    /// Deletes rows older than the configured retention window.
    ///
    /// Returns the number of deleted rows.
    pub async fn apply_retention(&self) -> Result<usize, ControlApiError> {
        let window = i64::from(self.config.retention_days).saturating_mul(MICROS_PER_DAY);
        let cutoff = self
            .db
            .now_unix()
            .saturating_mul(1_000_000)
            .saturating_sub(window);
        self.db
            .with_conn(move |conn| {
                conn.execute("DELETE FROM query_log WHERE time < ?1", params![cutoff])
                    .map_err(db_err)
            })
            .await
    }

    /// Runs one filtered, ordered and paginated query.
    pub async fn list(&self, filter: &QueryLogFilter) -> Result<QueryLogPage, ControlApiError> {
        let limit = filter
            .limit
            .clamp(1, self.config.max_rows_per_request.max(1));
        let offset = i64::try_from(filter.offset).unwrap_or(i64::MAX);

        let mut sql = String::from("SELECT record FROM query_log WHERE 1 = 1");
        let mut values: Vec<Value> = Vec::new();
        if let Some(from_us) = filter.from_us {
            sql.push_str(" AND time >= ?");
            values.push(Value::Integer(from_us));
        }
        if let Some(to_us) = filter.to_us {
            sql.push_str(" AND time <= ?");
            values.push(Value::Integer(to_us));
        }
        if let Some(client_id) = &filter.client_id {
            sql.push_str(" AND client_id = ?");
            values.push(Value::Text(client_id.clone()));
        }
        if let Some(needle) = &filter.client_name_substr {
            sql.push_str(" AND LOWER(client_name) LIKE ? ESCAPE '\\'");
            values.push(Value::Text(like_contains(needle)));
        }
        if let Some(domain) = &filter.domain {
            sql.push_str(" AND query_name = ?");
            values.push(Value::Text(normalize_name(domain)));
        }
        if let Some(needle) = &filter.domain_substr {
            sql.push_str(" AND query_name LIKE ? ESCAPE '\\'");
            values.push(Value::Text(like_contains(needle)));
        }
        if let Some(protocol) = &filter.protocol {
            sql.push_str(" AND protocol = ?");
            values.push(Value::Text(protocol.clone()));
        }
        if let Some(view_id) = &filter.view_id {
            sql.push_str(" AND view_id = ?");
            values.push(Value::Text(view_id.clone()));
        }
        if let Some(profile_id) = &filter.profile_id {
            sql.push_str(" AND profile_id = ?");
            values.push(Value::Text(profile_id.clone()));
        }
        if let Some(status) = &filter.status {
            sql.push_str(" AND status = ?");
            values.push(Value::Text(status.clone()));
        }
        if filter.only_blocked {
            sql.push_str(" AND status = 'blocked'");
        }
        if filter.only_with_clients {
            sql.push_str(" AND client_name IS NOT NULL");
        }
        let column = match filter.order_by {
            OrderBy::Time => "time",
            OrderBy::Client => "COALESCE(client_name, client_id, '')",
            OrderBy::Domain => "query_name",
            OrderBy::Rcode => "rcode",
        };
        let direction = match filter.order {
            Order::Asc => "ASC",
            Order::Desc => "DESC",
        };
        // Only constant strings from the matches above are interpolated.
        sql.push_str(&format!(
            " ORDER BY {column} {direction}, id {direction} LIMIT ? OFFSET ?"
        ));
        // Probe one extra row to expose `has_more` without a COUNT.
        values.push(Value::Integer(i64::from(limit) + 1));
        values.push(Value::Integer(offset));

        let fetched = self
            .db
            .with_conn(move |conn| {
                let mut stmt = conn.prepare(&sql).map_err(db_err)?;
                let rows = stmt
                    .query_map(params_from_iter(values), |row| row.get::<_, String>(0))
                    .map_err(db_err)?;
                rows.collect::<Result<Vec<String>, _>>().map_err(db_err)
            })
            .await?;

        let has_more = fetched.len() > limit as usize;
        let mut records = Vec::with_capacity(fetched.len().min(limit as usize));
        for raw in fetched.into_iter().take(limit as usize) {
            match serde_json::from_str::<Json>(&raw) {
                Ok(record) => records.push(record),
                Err(_) => {
                    return Err(ControlApiError::QueryLogRead {
                        message: "stored query-log record is not valid JSON".to_owned(),
                    });
                }
            }
        }
        Ok(QueryLogPage {
            records,
            has_more,
            next_offset: has_more.then_some(filter.offset + u64::from(limit)),
        })
    }

    /// Loads one record by id, or `None` when it is absent (or aged out).
    pub async fn get(&self, id: &str) -> Result<Option<Json>, ControlApiError> {
        let id = id.to_owned();
        let raw = self
            .db
            .with_conn(move |conn| {
                use rusqlite::OptionalExtension as _;
                conn.query_row(
                    "SELECT record FROM query_log WHERE id = ?1",
                    params![id],
                    |row| row.get::<_, String>(0),
                )
                .optional()
                .map_err(db_err)
            })
            .await?;
        match raw {
            None => Ok(None),
            Some(raw) => {
                serde_json::from_str(&raw)
                    .map(Some)
                    .map_err(|_| ControlApiError::QueryLogRead {
                        message: "stored query-log record is not valid JSON".to_owned(),
                    })
            }
        }
    }
}

/// Denormalised insert row plus its full JSON record.
struct PreparedRow {
    id: String,
    time_us: i64,
    node_id: String,
    source_ip: String,
    query_name: String,
    listener_id: String,
    protocol: &'static str,
    source_ip_truncated: bool,
    client_id: Option<String>,
    client_name: Option<String>,
    query_type: String,
    query_class: String,
    view_id: String,
    profile_id: String,
    status: &'static str,
    answer_source: &'static str,
    rcode: String,
    record: String,
}

fn prepare_row(
    event: &QueryEvent,
    node_id: &str,
    config: &QueryLogConfig,
    enricher: Option<&dyn ClientEnricher>,
) -> Result<PreparedRow, ControlApiError> {
    let id = new_id()?;
    let (source_ip, truncated) = truncate_ip(event.source, config.ip_truncate);
    let client = enricher.and_then(|enricher| enricher.by_ip(event.source));
    let client_id = event
        .client_id
        .as_ref()
        .or(event.decision.client_id.as_ref())
        .map(|id| id.as_str().to_owned());
    let client_name = client.as_ref().map(|client| client.display_name.clone());
    let query_name = normalize_name(&event.query.name.to_string());
    let query_type = event.query.qtype.to_string();
    let query_class = event.query.qclass.to_string();
    let protocol = protocol_str(event.protocol);
    let status = status_str(&event.decision, event.rcode);
    let answer_source = answer_origin_str(event.decision.answer_source);
    let rcode = event.rcode.to_string();
    let decision = &event.decision;
    let record = json!({
        "id": id,
        "node_id": node_id,
        "listener_id": event.listener_id.as_str(),
        "protocol": protocol,
        "source_ip": source_ip.to_string(),
        "source_ip_truncated": truncated,
        "client_id": client_id,
        "client": client.as_ref().map(client_json),
        "query": {
            "name": query_name,
            "type": query_type,
            "class": query_class,
        },
        "view_id": decision.view_id.as_str(),
        "profile_id": decision.profile_id.as_str(),
        "filter_set": decision.filter_set.as_str(),
        "selection": selection_json(decision.selection),
        "steps": decision.steps.iter().map(step_json).collect::<Vec<_>>(),
        "answer_source": answer_source,
        "filter": decision.filter.as_ref().map(filter_json),
        "dnssec": decision.dnssec.map(dnssec_str),
        "forward_zone": decision.forward_zone.as_ref().map(|zone| zone.as_str()),
        "rcode": rcode,
        "answer_size": event.answer_size,
        "timings": {
            "select_us": decision.timings.select_us,
            "filter_us": decision.timings.filter_us,
            "resolve_us": decision.timings.resolve_us,
            "total_us": decision.timings.total_us,
        },
        "time": DateTime::<Utc>::from(event.time)
            .to_rfc3339_opts(SecondsFormat::Micros, true),
    })
    .to_string();
    Ok(PreparedRow {
        id,
        time_us: system_time_micros(event.time),
        node_id: node_id.to_owned(),
        source_ip: source_ip.to_string(),
        query_name,
        listener_id: event.listener_id.as_str().to_owned(),
        protocol,
        source_ip_truncated: truncated,
        client_id,
        client_name,
        query_type,
        query_class,
        view_id: decision.view_id.as_str().to_owned(),
        profile_id: decision.profile_id.as_str().to_owned(),
        status,
        answer_source,
        rcode,
        record,
    })
}

/// Applies the configured truncation to one source address.
///
/// `last_octet` only affects IPv4 (`x.x.x.0`); `last_group` only affects IPv6
/// (first 48 bits). The boolean is true when the address was actually changed.
fn truncate_ip(ip: IpAddr, mode: IpTruncate) -> (IpAddr, bool) {
    match (ip, mode) {
        (IpAddr::V4(v4), IpTruncate::LastOctet) => {
            let octets = v4.octets();
            (
                IpAddr::V4(Ipv4Addr::new(octets[0], octets[1], octets[2], 0)),
                true,
            )
        }
        (IpAddr::V6(v6), IpTruncate::LastGroup) => {
            let segments = v6.segments();
            (
                IpAddr::V6(Ipv6Addr::new(
                    segments[0],
                    segments[1],
                    segments[2],
                    0,
                    0,
                    0,
                    0,
                    0,
                )),
                true,
            )
        }
        (ip, _) => (ip, false),
    }
}

/// Normalizes an owner name for storage/filtering (lowercase, no trailing dot).
fn normalize_name(name: &str) -> String {
    name.trim_end_matches('.').to_ascii_lowercase()
}

/// Builds a `LIKE` needle that treats `%`, `_` and `\` as literals.
fn like_contains(raw: &str) -> String {
    let mut escaped = String::with_capacity(raw.len() + 2);
    escaped.push('%');
    for ch in raw.chars() {
        if matches!(ch, '%' | '_' | '\\') {
            escaped.push('\\');
        }
        escaped.push(ch.to_ascii_lowercase());
    }
    escaped.push('%');
    escaped
}

fn protocol_str(protocol: DnsProtocol) -> &'static str {
    match protocol {
        DnsProtocol::Udp53 => "udp53",
        DnsProtocol::Tcp53 => "tcp53",
        DnsProtocol::DoT => "dot",
        DnsProtocol::DoH => "doh",
        DnsProtocol::DoQ => "doq",
        _ => "unknown",
    }
}

/// Derives the documented outcome label from the decision and response code.
fn status_str(decision: &DecisionRecord, rcode: Rcode) -> &'static str {
    if decision
        .filter
        .as_ref()
        .is_some_and(|hit| hit.block_mode.is_some())
    {
        "blocked"
    } else if rcode == Rcode::SERVFAIL {
        "servfail"
    } else if decision.dnssec == Some(DnssecStatus::Bogus) {
        "dnssec_bogus"
    } else {
        "allowed"
    }
}

fn answer_origin_str(origin: AnswerOrigin) -> &'static str {
    match origin {
        AnswerOrigin::Resolver => "resolver",
        AnswerOrigin::SynthAny => "synth_any",
        AnswerOrigin::ResolveError => "resolve_error",
        AnswerOrigin::LocalView => "local_view",
        AnswerOrigin::LocalClient => "local_client",
        AnswerOrigin::Bypass => "bypass",
        AnswerOrigin::Filter => "filter_block",
        AnswerOrigin::ListenerDdr => "listener_ddr",
        _ => "unknown",
    }
}

fn answer_source_str(source: AnswerSource) -> &'static str {
    match source {
        AnswerSource::Cache => "cache",
        AnswerSource::Recursion => "recursion",
        AnswerSource::Stale => "stale",
    }
}

fn dnssec_str(status: DnssecStatus) -> &'static str {
    match status {
        DnssecStatus::Secure => "secure",
        DnssecStatus::Insecure => "insecure",
        DnssecStatus::Bogus => "bogus",
        DnssecStatus::Indeterminate => "indeterminate",
    }
}

fn block_mode_str(mode: BlockMode) -> &'static str {
    match mode {
        BlockMode::Refused => "refused",
        BlockMode::NxDomain => "nxdomain",
        BlockMode::NullIp => "null_ip",
        BlockMode::CustomIp { .. } => "custom_ip",
        _ => "unknown",
    }
}

fn client_json(client: &ClientView) -> Json {
    json!({
        "id": client.id,
        "display_name": client.display_name,
        "source": client.source,
        "macs": client.macs,
        "vlan_id": client.vlan_id,
        "vlan_name": client.vlan_name,
        "local_domain": client.local_domain,
    })
}

fn selection_json(cause: SelectionCause) -> Json {
    match cause {
        SelectionCause::ClientId => json!({ "cause": "client_id" }),
        SelectionCause::Subnet {
            network,
            prefix_len,
        } => json!({
            "cause": "subnet",
            "prefix": format!("{network}/{prefix_len}"),
        }),
        SelectionCause::Default => json!({ "cause": "default" }),
        _ => json!({ "cause": "unknown" }),
    }
}

fn filter_json(hit: &FilterHit) -> Json {
    let (source, list_id) = match &hit.reason.source {
        RuleSource::List { list, .. } => ("list", Some(list.as_str().to_owned())),
        RuleSource::Custom { .. } => ("custom", None),
        RuleSource::Service { id } => ("service", Some(id.to_string())),
        RuleSource::TemporaryAllow => ("temporary_allow", None),
        RuleSource::Mcp { .. } => ("mcp", None),
        _ => ("unknown", None),
    };
    json!({
        // The spec calls this a filter reason; the engine exposes provenance
        // (list/custom/service/temporary_allow/mcp) rather than a category.
        "reason": source,
        "block_mode": hit.block_mode.map(block_mode_str),
        "rule_text": hit.reason.rule.as_ref(),
        "list_id": list_id,
        "important": hit.reason.important,
    })
}

fn step_json(step: &DecisionStep) -> Json {
    match step {
        DecisionStep::Selected { cause } => json!({
            "stage": "select",
            "verdict": "selected",
            "selection": selection_json(*cause),
        }),
        DecisionStep::AnySynth => json!({ "stage": "any_synth", "verdict": "synth" }),
        DecisionStep::LocalView => json!({ "stage": "local_view", "verdict": "answered" }),
        DecisionStep::LocalClient => json!({ "stage": "local_client", "verdict": "answered" }),
        DecisionStep::SpecialUseNxdomain => {
            json!({ "stage": "special_use_nxdomain", "verdict": "nxdomain" })
        }
        DecisionStep::Bypass => json!({ "stage": "bypass", "verdict": "answered" }),
        DecisionStep::ProtectionPaused { .. } => {
            json!({ "stage": "protection_paused", "verdict": "paused" })
        }
        DecisionStep::FilterBlocked => {
            json!({ "stage": "filter_qname", "verdict": "blocked" })
        }
        DecisionStep::FilterRewrite => {
            json!({ "stage": "filter_qname", "verdict": "rewritten" })
        }
        DecisionStep::FilterSkipped { reason } => {
            json!({ "stage": "filter_qname", "verdict": "skipped", "reason": reason })
        }
        DecisionStep::AnswerChainBlocked => {
            json!({ "stage": "answer_chain", "verdict": "blocked" })
        }
        DecisionStep::AnswerIpBlocked => {
            json!({ "stage": "answer_ip", "verdict": "blocked" })
        }
        DecisionStep::RebindSkipped { .. } => {
            json!({ "stage": "rebind", "verdict": "skipped" })
        }
        DecisionStep::RebindStripped { count } => {
            json!({ "stage": "rebind", "verdict": "stripped", "count": count })
        }
        DecisionStep::AaaaSuppressed => {
            json!({ "stage": "aaaa_suppressed", "verdict": "suppressed" })
        }
        DecisionStep::Resolve { source, dnssec } => json!({
            "stage": "resolve",
            "verdict": "resolved",
            "source": answer_source_str(*source),
            "dnssec": dnssec_str(*dnssec),
        }),
        DecisionStep::ResolveFailed { cause_code } => json!({
            "stage": "resolve",
            "verdict": "failed",
            "cause_code": cause_code,
        }),
        DecisionStep::SafeSearchRewrite { provider, target } => json!({
            "stage": "safesearch",
            "verdict": "rewritten",
            "provider": provider.as_ref(),
            "target": target.as_ref(),
        }),
        DecisionStep::ScheduleActive { id, filter_set } => json!({
            "stage": "schedule",
            "verdict": "active",
            "id": id.as_ref(),
            "filter_set": filter_set.as_str(),
        }),
        _ => json!({ "stage": "unknown", "verdict": "unknown" }),
    }
}

/// Returns microseconds since the unix epoch (negative before it).
fn system_time_micros(time: SystemTime) -> i64 {
    match time.duration_since(UNIX_EPOCH) {
        Ok(delta) => i64::try_from(delta.as_micros()).unwrap_or(i64::MAX),
        Err(error) => -i64::try_from(error.duration().as_micros()).unwrap_or(i64::MAX),
    }
}

/// Generates an opaque, UUID-shaped record id (16 random bytes, v4 layout).
fn new_id() -> Result<String, ControlApiError> {
    let mut bytes = [0u8; 16];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| ControlApiError::Internal {
            message: "query-log id generation failed".to_owned(),
        })?;
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Ok(format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0],
        bytes[1],
        bytes[2],
        bytes[3],
        bytes[4],
        bytes[5],
        bytes[6],
        bytes[7],
        bytes[8],
        bytes[9],
        bytes[10],
        bytes[11],
        bytes[12],
        bytes[13],
        bytes[14],
        bytes[15],
    ))
}
