//! [`McpBackend`](dnscraft_mcp::backend::McpBackend) implementation backed by
//! the control-api services and module engines.

use std::net::IpAddr;
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use dnscraft_filtering::{
    BlockMode, DomainName, FilterEngine, RecordTypeSel, RuleAction, RuleSpec, SetId, TempAllow,
    Verdict, build_rule,
};
use dnscraft_mcp::ProtectedDomains;
use dnscraft_mcp::backend::{BackendError, McpBackend};
use dnscraft_mcp::dto::{
    AddRuleParams, AddRuleResult, AnswerRecord, AuditEntry, AuditResult, DnssecCounts,
    ExplainBlockResult, ExplainReason, FilteringStatus, ListRulesParams, ListRulesResult,
    McpRuleInfo, NodeStatus, PauseDuration, PauseInfo, PauseParams, PauseResult, QType,
    QueryClient, QueryDetail, QueryLogEntry, QueryLogFilter as McpQueryLogFilter, QueryLogResult,
    QueryLogSearch, QueryName, QueryTimings, RemoveRuleParams, RemoveRuleResult, ResolverStatus,
    ResumeResult, Selection, StatsParams, StatsPeriod, StatsResult, SynthesizedAnswer,
    TempAllowInfo, TempAllowParams, TempAllowResult, TestQueryFilter, TestQueryResult, TlsStatus,
    TokenInfo, TokenScope,
};
use dnscraft_policy::RequestContext;
use serde_json::{Value, json};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::api::auth::roles::Scope;
use crate::api::query_log_routes::parse_timestamp;
use crate::audit::Audit;
use crate::clock::Clock;
use crate::config_apply::{ConfigActor, ConfigService, MutationAudit};
use crate::error::ControlApiError;
use crate::query_log::{Order, OrderBy, QueryLog, QueryLogFilter};
use crate::server::AppState;
use crate::stats::TopBy;
use crate::tls::TlsStatusProvider;

/// Master broadcast handle shared with [`AppState`](crate::AppState).
///
/// Starts empty: a standalone node or sub-node never attaches a handle, and
/// every broadcast is then a no-op.
pub(crate) type SharedClusterBroadcast = Arc<Mutex<Option<dnscraft_cluster::ClusterBroadcast>>>;

/// Service handles the MCP backend needs.
///
/// The production assembler builds this with [`mcp_backend_inner`] and attaches
/// it with [`AppState::with_mcp_backend`](crate::AppState::with_mcp_backend).
#[derive(Clone)]
pub struct McpBackendInner {
    pub(crate) policy: Option<Arc<dnscraft_policy::PolicyEngine>>,
    pub(crate) filter: Option<Arc<FilterEngine>>,
    pub(crate) query_log: Option<Arc<QueryLog>>,
    pub(crate) tokens: Option<crate::api::auth::TokenStore>,
    pub(crate) audit: Option<Arc<Audit>>,
    pub(crate) config: Option<Arc<ConfigService>>,
    pub(crate) clock: Arc<dyn Clock>,
    pub(crate) tls: Option<Arc<dyn TlsStatusProvider>>,
    pub(crate) resolver_cache_size: Arc<AtomicU64>,
    pub(crate) node_id: String,
    pub(crate) version: String,
    pub(crate) start_time: std::time::Instant,
    /// MCP limits, protected-domain additions and the write-tools gate.
    pub(crate) mcp_config: dnscraft_mcp::McpConfig,
    /// OIDC issuer URL whose host is protected, when OIDC is enabled.
    pub(crate) oidc_issuer: Option<String>,
    /// Master broadcast handle; `None` on a standalone or sub-node runtime.
    pub(crate) cluster_broadcast: SharedClusterBroadcast,
}

/// Builds the production MCP backend's inner handle (D3).
///
/// The `dnscraft` binary is the only caller. It hands over the live engines and
/// stores plus the status providers the tools read; no secret material (token
/// plaintext, OIDC client secret, TLS private key) is accepted or stored. The
/// backend validates tokens against `tokens` and writes through `config` under
/// its apply lock.
///
/// `query_log` is `None` until the SQLite query-log consumer lands (AS12);
/// the log-reading tools then report `control_api.internal` until it is wired.
/// A standalone node leaves the cluster broadcast handle empty.
#[allow(clippy::too_many_arguments)]
pub fn mcp_backend_inner(
    filter: Arc<FilterEngine>,
    policy: Arc<dnscraft_policy::PolicyEngine>,
    query_log: Option<Arc<QueryLog>>,
    config: Arc<ConfigService>,
    audit: Arc<Audit>,
    tokens: crate::api::auth::TokenStore,
    clock: Arc<dyn Clock>,
    tls: Option<Arc<dyn TlsStatusProvider>>,
    node_id: impl Into<String>,
    version: impl Into<String>,
    mcp_config: dnscraft_mcp::McpConfig,
    oidc_issuer: Option<String>,
) -> Arc<McpBackendInner> {
    Arc::new(McpBackendInner {
        policy: Some(policy),
        filter: Some(filter),
        query_log,
        tokens: Some(tokens),
        audit: Some(audit),
        config: Some(config),
        clock,
        tls,
        resolver_cache_size: Arc::new(AtomicU64::new(0)),
        node_id: node_id.into(),
        version: version.into(),
        start_time: std::time::Instant::now(),
        mcp_config,
        oidc_issuer,
        cluster_broadcast: Arc::new(Mutex::new(None)),
    })
}

impl McpBackendInner {
    /// Attaches (or replaces) the master broadcast handle.
    pub(crate) fn attach_cluster_broadcast(&self, broadcast: dnscraft_cluster::ClusterBroadcast) {
        *self
            .cluster_broadcast
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(broadcast);
    }

    /// Pushes a volatile runtime command to connected sub-nodes, if master.
    fn broadcast_runtime_command(&self, kind: &str, payload: &Value) {
        let broadcast = self
            .cluster_broadcast
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        if let Some(broadcast) = broadcast {
            broadcast.broadcast_runtime_command(kind, payload);
        }
    }
}

pub(crate) struct ControlMcpBackend {
    inner: Arc<McpBackendInner>,
}

impl ControlMcpBackend {
    pub fn new(inner: Arc<McpBackendInner>) -> Self {
        Self { inner }
    }

    fn filter_engine(&self) -> Result<&Arc<FilterEngine>, BackendError> {
        self.inner
            .filter
            .as_ref()
            .ok_or_else(|| BackendError::Internal {
                message: "filter engine not configured".into(),
            })
    }

    fn policy_engine(&self) -> Result<&Arc<dnscraft_policy::PolicyEngine>, BackendError> {
        self.inner
            .policy
            .as_ref()
            .ok_or_else(|| BackendError::Internal {
                message: "policy engine not configured".into(),
            })
    }

    fn config_service(&self) -> Result<&Arc<ConfigService>, BackendError> {
        self.inner
            .config
            .as_ref()
            .ok_or_else(|| BackendError::Internal {
                message: "config service not configured".into(),
            })
    }

    /// The current stored config snapshot, if any.
    async fn current_snapshot(&self) -> Result<Option<Value>, BackendError> {
        match &self.inner.config {
            Some(service) => Ok(service
                .current()
                .await
                .map(|(_, snapshot)| snapshot)
                .map_err(|e| BackendError::Internal {
                    message: e.code().to_owned(),
                })?),
            None => Ok(None),
        }
    }

    /// Protected domains from the current config plus the owner's additions.
    fn protected(&self, snapshot: Option<&Value>) -> Result<ProtectedDomains, BackendError> {
        protected_for(
            snapshot,
            self.inner.oidc_issuer.as_deref(),
            self.inner.mcp_config.protected_domains.iter().cloned(),
        )
        .map_err(backend_error)
    }
}

/// Builds a read-only backend over `query_log` for integration tests.
///
/// Engines and stores that the read tools do not need are left unconfigured.
#[doc(hidden)]
pub fn mcp_backend_for_test(query_log: Option<Arc<QueryLog>>) -> Arc<dyn McpBackend> {
    Arc::new(ControlMcpBackend::new(Arc::new(McpBackendInner {
        policy: None,
        filter: None,
        query_log,
        tokens: None,
        audit: None,
        config: None,
        clock: Arc::new(crate::clock::SystemClock),
        tls: None,
        resolver_cache_size: Arc::new(AtomicU64::new(0)),
        node_id: "test".to_owned(),
        version: "0.0.0".to_owned(),
        start_time: std::time::Instant::now(),
        mcp_config: dnscraft_mcp::McpConfig::default(),
        oidc_issuer: None,
        cluster_broadcast: Arc::new(Mutex::new(None)),
    })))
}

/// Builds a fully-wired backend with the write-side services, for integration
/// tests only.
///
/// [`mcp_backend_for_test`] deliberately leaves the write services unconfigured
/// (the read tools never touch them). This variant wires the engines and stores
/// the read and write tools need, so the real backend can be exercised without
/// a production assembler. Not part of the supported public API.
#[doc(hidden)]
#[allow(clippy::too_many_arguments)]
pub fn mcp_backend_for_test_writes(
    filter: Arc<FilterEngine>,
    policy: Option<Arc<dnscraft_policy::PolicyEngine>>,
    query_log: Option<Arc<QueryLog>>,
    config: Arc<ConfigService>,
    audit: Option<Arc<Audit>>,
    tokens: Option<crate::api::auth::TokenStore>,
    clock: Arc<dyn Clock>,
    mcp_config: dnscraft_mcp::McpConfig,
    oidc_issuer: Option<String>,
) -> Arc<dyn McpBackend> {
    mcp_backend_for_test_writes_with_broadcast(
        filter,
        policy,
        query_log,
        config,
        audit,
        tokens,
        clock,
        mcp_config,
        oidc_issuer,
        Arc::new(Mutex::new(None)),
    )
}

/// [`mcp_backend_for_test_writes`] sharing a caller-supplied broadcast handle,
/// so a test master can attach its [`ClusterBroadcast`](dnscraft_cluster::ClusterBroadcast).
#[doc(hidden)]
#[allow(clippy::too_many_arguments)]
pub fn mcp_backend_for_test_writes_with_broadcast(
    filter: Arc<FilterEngine>,
    policy: Option<Arc<dnscraft_policy::PolicyEngine>>,
    query_log: Option<Arc<QueryLog>>,
    config: Arc<ConfigService>,
    audit: Option<Arc<Audit>>,
    tokens: Option<crate::api::auth::TokenStore>,
    clock: Arc<dyn Clock>,
    mcp_config: dnscraft_mcp::McpConfig,
    oidc_issuer: Option<String>,
    cluster_broadcast: Arc<Mutex<Option<dnscraft_cluster::ClusterBroadcast>>>,
) -> Arc<dyn McpBackend> {
    Arc::new(ControlMcpBackend::new(Arc::new(McpBackendInner {
        policy,
        filter: Some(filter),
        query_log,
        tokens,
        audit,
        config: Some(config),
        clock,
        tls: None,
        resolver_cache_size: Arc::new(AtomicU64::new(0)),
        node_id: "test".to_owned(),
        version: "0.0.0".to_owned(),
        start_time: std::time::Instant::now(),
        mcp_config,
        oidc_issuer,
        cluster_broadcast,
    })))
}

// ---- helpers ----

pub(crate) fn rfc3339(ts: SystemTime) -> String {
    let d = ts.duration_since(UNIX_EPOCH).unwrap_or(Duration::ZERO);
    OffsetDateTime::from_unix_timestamp_nanos((d.as_nanos() as i128).min(i64::MAX as i128))
        .unwrap_or(OffsetDateTime::UNIX_EPOCH)
        .format(&Rfc3339)
        .unwrap_or_default()
}

fn duration_secs(d: PauseDuration) -> Duration {
    Duration::from_secs(d.seconds())
}

fn map_mcp_scope(scope: Scope) -> TokenScope {
    match scope {
        Scope::McpRead => TokenScope::McpRead,
        Scope::McpWrite => TokenScope::McpWrite,
        _ => TokenScope::McpRead,
    }
}

fn filter_qtype(qtype: QType) -> u16 {
    match qtype {
        QType::A => 1,
        QType::Aaaa => 28,
        QType::Cname => 5,
        QType::Mx => 15,
        QType::Txt => 16,
        QType::Srv => 33,
        QType::Https => 65,
    }
}

fn record_qtype(rt: dnscraft_proto::RecordType) -> QType {
    match rt.0 {
        28 => QType::Aaaa,
        5 => QType::Cname,
        15 => QType::Mx,
        16 => QType::Txt,
        33 => QType::Srv,
        65 => QType::Https,
        _ => QType::A,
    }
}

fn block_mode_str(m: &BlockMode) -> String {
    match m {
        BlockMode::Refused => "refused".to_owned(),
        BlockMode::NxDomain => "nxdomain".to_owned(),
        BlockMode::NullIp => "null_ip".to_owned(),
        BlockMode::CustomIp { .. } => "custom_ip".to_owned(),
    }
}

fn reason_source_str(src: &dnscraft_filtering::RuleSource) -> String {
    match src {
        dnscraft_filtering::RuleSource::List { list, line } => format!("list:{list}:line {line}"),
        dnscraft_filtering::RuleSource::Custom { set, line } => format!("set:{set}:line {line}"),
        dnscraft_filtering::RuleSource::Mcp { set, id } => format!("mcp:{set}:{id}"),
        dnscraft_filtering::RuleSource::Service { id } => format!("service:{id}"),
        _ => "unknown".to_owned(),
    }
}

fn policy_protocol(s: &str) -> dnscraft_policy::DnsProtocol {
    match s {
        "tcp53" => dnscraft_policy::DnsProtocol::Tcp53,
        "dot" => dnscraft_policy::DnsProtocol::DoT,
        "doh" => dnscraft_policy::DnsProtocol::DoH,
        "doq" => dnscraft_policy::DnsProtocol::DoQ,
        _ => dnscraft_policy::DnsProtocol::Udp53,
    }
}

fn dnssec_status_str(s: &dnscraft_resolver::DnssecStatus) -> &'static str {
    match s {
        dnscraft_resolver::DnssecStatus::Secure => "secure",
        dnscraft_resolver::DnssecStatus::Insecure => "insecure",
        dnscraft_resolver::DnssecStatus::Bogus => "bogus",
        dnscraft_resolver::DnssecStatus::Indeterminate => "indeterminate",
    }
}

fn json_str(val: &Value, key: &str) -> String {
    val[key].as_str().unwrap_or_default().to_owned()
}

fn json_opt_str(val: &Value, key: &str) -> Option<String> {
    val[key].as_str().map(str::to_owned)
}

fn non_empty(value: Option<String>) -> Option<String> {
    value.filter(|value| !value.is_empty())
}

fn parse_time(raw: Option<&str>, field: &str) -> Result<Option<i64>, BackendError> {
    raw.map(|raw| parse_timestamp(raw, field))
        .transpose()
        .map_err(|e| BackendError::Coded {
            code: e.code().to_owned(),
            params: None,
        })
}

fn query_order_by(raw: &str) -> OrderBy {
    match raw {
        "client" => OrderBy::Client,
        "domain" => OrderBy::Domain,
        "rcode" => OrderBy::Rcode,
        _ => OrderBy::Time,
    }
}

fn query_order(raw: &str) -> Order {
    match raw {
        "asc" => Order::Asc,
        _ => Order::Desc,
    }
}

/// Maps a stored query-type string (`RecordType`'s display form) to a DTO type.
fn qtype_from_str(raw: &str) -> QType {
    match raw {
        "AAAA" => QType::Aaaa,
        "CNAME" => QType::Cname,
        "MX" => QType::Mx,
        "TXT" => QType::Txt,
        "SRV" => QType::Srv,
        "HTTPS" => QType::Https,
        _ => QType::A,
    }
}

fn query_entry(record: &Value) -> QueryLogEntry {
    let client = &record["client"];
    let query = &record["query"];
    QueryLogEntry {
        id: json_str(record, "id"),
        time: json_str(record, "time"),
        client: QueryClient {
            id: json_str(client, "id"),
            display_name: json_str(client, "display_name"),
            source: json_str(client, "source"),
        },
        query: QueryName {
            name: json_str(query, "name"),
            qtype: qtype_from_str(&json_str(query, "type")),
        },
        profile_id: json_str(record, "profile_id"),
        answer_source: json_str(record, "answer_source"),
        filter: record
            .get("filter")
            .filter(|filter| !filter.is_null())
            .map(|filter| McpQueryLogFilter {
                reason: json_str(filter, "reason"),
                rule_text: json_opt_str(filter, "rule_text"),
                list_id: json_opt_str(filter, "list_id"),
            }),
        rcode: json_str(record, "rcode"),
        timings: QueryTimings {
            total_us: record["timings"]["total_us"].as_u64().unwrap_or(0),
        },
    }
}

fn code_err(code: &str, domain: &str) -> BackendError {
    BackendError::Coded {
        code: code.to_owned(),
        params: Some(json!({ "domain": domain })),
    }
}

fn rdata_str(rdata: &dnscraft_proto::RData) -> String {
    match rdata {
        dnscraft_proto::RData::A(ip) => ip.to_string(),
        dnscraft_proto::RData::AAAA(ip) => ip.to_string(),
        dnscraft_proto::RData::CNAME(name) => name.to_string(),
        dnscraft_proto::RData::NS(name) => name.to_string(),
        dnscraft_proto::RData::PTR(name) => name.to_string(),
        dnscraft_proto::RData::MX {
            preference,
            exchange,
        } => {
            format!("{preference} {exchange}")
        }
        dnscraft_proto::RData::TXT(_) => "<TXT>".to_owned(),
        dnscraft_proto::RData::SOA { .. } => "<SOA>".to_owned(),
        dnscraft_proto::RData::SRV { .. } => "<SRV>".to_owned(),
        _ => "<rdata>".to_owned(),
    }
}

fn selection_cause_json(cause: &dnscraft_policy::SelectionCause) -> Selection {
    match cause {
        dnscraft_policy::SelectionCause::ClientId => Selection {
            cause: "client_id".to_owned(),
            prefix: None,
            client_id: None,
        },
        dnscraft_policy::SelectionCause::Subnet {
            network,
            prefix_len,
        } => Selection {
            cause: "subnet".to_owned(),
            prefix: Some(format!("{network}/{prefix_len}")),
            client_id: None,
        },
        dnscraft_policy::SelectionCause::Default => Selection {
            cause: "default".to_owned(),
            prefix: None,
            client_id: None,
        },
    }
}

/// Maps a control-api error onto the MCP backend's coded-error shape.
fn backend_error(err: ControlApiError) -> BackendError {
    match err {
        ControlApiError::Module { code, params } => BackendError::Coded {
            code: code.to_owned(),
            params,
        },
        other => BackendError::Internal {
            message: other.code().to_owned(),
        },
    }
}

/// Builds a forwarded module error with non-secret `params`.
pub(crate) fn mcp_error(code: &'static str, params: Value) -> ControlApiError {
    ControlApiError::Module {
        code,
        params: Some(params),
    }
}

/// `policy.config.unknown_filter_set` for `id`.
pub(crate) fn unknown_set(id: &str) -> ControlApiError {
    mcp_error(
        "policy.config.unknown_filter_set",
        json!({ "filter_set_id": id }),
    )
}

/// Maps a filtering builder error onto its forwarded module code.
pub(crate) fn build_error(err: dnscraft_filtering::BuildError) -> ControlApiError {
    let params = err
        .params()
        .into_iter()
        .map(|(key, value)| (key.to_owned(), Value::String(value)))
        .collect::<serde_json::Map<_, _>>();
    mcp_error(err.code(), Value::Object(params))
}

/// Strictly parses a write target set id (default `default`).
///
/// Unlike the read-side [`resolve_set`], an invalid id is an error: a write
/// must never silently land in the default set.
pub(crate) fn parse_set(id: Option<&str>) -> Result<SetId, ControlApiError> {
    let raw = id.unwrap_or("default");
    SetId::new(raw).map_err(|_| unknown_set(raw))
}

/// Validates the non-snapshot parts of an `add_rule` request.
///
/// Returns the target set, canonical domain, reported rule text and the
/// requested lifetime. Doing this before the audited mutation lets every
/// rejection be audited by the caller.
fn prepare_add(
    params: &AddRuleParams,
    maximum: Duration,
) -> Result<(SetId, DomainName, String, Duration), ControlApiError> {
    let set = parse_set(params.filter_set_id.as_deref())?;
    let (domain, rule_text) = canonical_block_rule(&params.domain, params.include_subdomains)?;
    let requested = Duration::from_secs(params.lifetime_seconds);
    if requested.is_zero() || requested > maximum {
        return Err(duration_exceeds(requested, maximum));
    }
    Ok((set, domain, rule_text, requested))
}

/// Validates the non-snapshot parts of a `remove_rule` request.
fn prepare_remove(params: &RemoveRuleParams) -> Result<(SetId, DomainName), ControlApiError> {
    let set = parse_set(params.filter_set_id.as_deref())?;
    let domain = DomainName::parse(&params.domain).map_err(|_| {
        mcp_error(
            "filter_name.invalid_char",
            json!({ "domain": params.domain }),
        )
    })?;
    Ok((set, domain))
}

/// A mutable filter set from the stored snapshot, if it exists.
pub(crate) fn set_mut<'a>(snapshot: &'a mut Value, id: &str) -> Option<&'a mut Value> {
    snapshot
        .get_mut("filtering")?
        .get_mut("sets")?
        .as_array_mut()?
        .iter_mut()
        .find(|set| set.get("id").and_then(Value::as_str) == Some(id))
}

/// Whether a stored rule has not expired at `now`.
pub(crate) fn active_rule(rule: &Value, now: SystemTime) -> bool {
    rule.get("expires_at")
        .and_then(stored_time)
        .is_none_or(|expires| expires > now)
}

/// Protected domains derived from `snapshot` plus the owner's additions.
pub(crate) fn protected_for(
    snapshot: Option<&Value>,
    oidc_issuer: Option<&str>,
    extra: impl IntoIterator<Item = String>,
) -> Result<ProtectedDomains, ControlApiError> {
    crate::protected_list::derive_protected_domains(snapshot, oidc_issuer, extra).map_err(|err| {
        ControlApiError::Module {
            code: err.code(),
            params: err.params(),
        }
    })
}

/// Rejects a target covered by the protected-domain list.
///
/// The error names only the submitted target; the matched protected entry is
/// logged server-side and never returned, so a derived infrastructure host
/// (OIDC issuer, forward-zone apex, filter-list host, …) cannot be read back
/// through the error `params`.
pub(crate) fn reject_protected(
    protected: &ProtectedDomains,
    domain: &str,
    include: bool,
) -> Result<(), ControlApiError> {
    if let Some(hit) = protected.check(domain, include) {
        tracing::warn!(
            submitted = %domain,
            matched = %hit,
            "protected domain rejected"
        );
        return Err(mcp_error(
            "mcp.protected_domain",
            json!({ "domain": domain }),
        ));
    }
    Ok(())
}

/// Canonicalises a temporary-allow target with the filtering builder.
pub(crate) fn canonical_allow_domain(raw: &str) -> Result<DomainName, ControlApiError> {
    let spec = RuleSpec {
        action: RuleAction::Allow,
        domain: raw.to_owned(),
        include_subdomains: false,
        record_types: RecordTypeSel::default(),
        important: false,
        rewrite: None,
    }
    .normalized()
    .map_err(build_error)?;
    let domain = DomainName::parse(&spec.domain)
        .map_err(|_| mcp_error("filter_name.invalid_char", json!({ "domain": raw })))?;
    if domain.label_count() < 2 {
        return Err(mcp_error(
            "mcp.domain_too_broad",
            json!({ "domain": domain.as_str() }),
        ));
    }
    Ok(domain)
}

/// Canonicalises a block-rule target and builds its rule text.
///
/// Returns the canonical domain and the `|`/`||` rule text the MCP tool
/// reports, using the same filtering builder as the config path so the two
/// cannot drift.
pub(crate) fn canonical_block_rule(
    raw: &str,
    include_subdomains: bool,
) -> Result<(DomainName, String), ControlApiError> {
    let spec = RuleSpec {
        action: RuleAction::Block,
        domain: raw.to_owned(),
        include_subdomains,
        record_types: RecordTypeSel::default(),
        important: false,
        rewrite: None,
    }
    .normalized()
    .map_err(build_error)?;
    let domain = DomainName::parse(&spec.domain)
        .map_err(|_| mcp_error("filter_name.invalid_char", json!({ "domain": spec.domain })))?;
    if domain.label_count() < 2 {
        return Err(mcp_error(
            "mcp.invalid_input",
            json!({ "reason": "a block rule needs a domain with at least two labels" }),
        ));
    }
    let rule_text = build_rule(&spec).map_err(build_error)?;
    Ok((domain, rule_text))
}

/// `mcp.duration_exceeds_maximum` for a requested and a configured maximum
/// duration.
pub(crate) fn duration_exceeds(requested: Duration, maximum: Duration) -> ControlApiError {
    mcp_error(
        "mcp.duration_exceeds_maximum",
        json!({
            "requested": iso_duration(requested),
            "maximum": iso_duration(maximum),
        }),
    )
}

/// Rejects a fixed-set duration above the configured maximum.
pub(crate) fn duration_error(requested_secs: u64, maximum: Duration) -> Option<ControlApiError> {
    (requested_secs > maximum.as_secs())
        .then(|| duration_exceeds(Duration::from_secs(requested_secs), maximum))
}

/// Renders a duration in its canonical ISO 8601 form.
pub(crate) fn iso_duration(duration: Duration) -> String {
    match duration.as_secs() {
        300 => "PT5M".to_owned(),
        900 => "PT15M".to_owned(),
        3600 => "PT1H".to_owned(),
        seconds => format!("PT{seconds}S"),
    }
}

/// Maps a filtering engine error; anything but an unknown set is internal.
pub(crate) fn engine_error(err: dnscraft_filtering::FilterError, set: &str) -> ControlApiError {
    match err {
        dnscraft_filtering::FilterError::UnknownSet(_) => unknown_set(set),
        other => ControlApiError::Internal {
            message: other.to_string(),
        },
    }
}

/// Appends one MCP block rule to a filter set in `snapshot`.
///
/// Expired entries are pruned first, so the stored array cannot grow without
/// bound and the cap counts only rules that are still active. The cap is
/// enforced here, inside the caller's config apply lock, so two concurrent
/// adds cannot both pass.
#[allow(clippy::too_many_arguments)]
pub(crate) fn add_rule_to_snapshot(
    snapshot: &mut Value,
    set: &SetId,
    domain: &DomainName,
    include_subdomains: bool,
    rule_id: &str,
    created_secs: i64,
    expires_secs: i64,
    token_id: &str,
    cap: usize,
    now: SystemTime,
) -> Result<(), ControlApiError> {
    let set_value = set_mut(snapshot, set.as_str()).ok_or_else(|| unknown_set(set.as_str()))?;
    let rules = set_value
        .as_object_mut()
        .ok_or_else(|| ControlApiError::Internal {
            message: "filter set is not an object".to_owned(),
        })?
        .entry("mcp_rules")
        .or_insert_with(|| Value::Array(Vec::new()))
        .as_array_mut()
        .ok_or_else(|| ControlApiError::Internal {
            message: "mcp_rules is not an array".to_owned(),
        })?;
    rules.retain(|rule| active_rule(rule, now));
    if rules.len() >= cap {
        return Err(mcp_error(
            "mcp.rule_limit_exceeded",
            json!({ "filter_set_id": set.as_str(), "max": cap }),
        ));
    }
    rules.push(json!({
        "id": rule_id,
        "domain": domain.as_str(),
        "include_subdomains": include_subdomains,
        "created_at": created_secs,
        "expires_at": expires_secs,
        "token_id": token_id,
    }));
    Ok(())
}

/// Removes every stored MCP rule for `domain` from a filter set.
///
/// Returns whether anything was removed. Each matched rule is checked against
/// `protected` with its own stored `include_subdomains` flag (not a caller
/// value); one protected hit aborts the whole removal.
pub(crate) fn remove_rule_from_snapshot(
    snapshot: &mut Value,
    set: &SetId,
    domain: &DomainName,
    protected: &ProtectedDomains,
) -> Result<bool, ControlApiError> {
    let set_value = set_mut(snapshot, set.as_str()).ok_or_else(|| unknown_set(set.as_str()))?;
    let Some(rules) = set_value
        .as_object_mut()
        .and_then(|set| set.get_mut("mcp_rules"))
        .and_then(Value::as_array_mut)
    else {
        return Ok(false);
    };
    let existing = std::mem::take(rules);
    let mut kept = Vec::with_capacity(existing.len());
    let mut removed = false;
    for rule in existing {
        let matches = rule
            .get("domain")
            .and_then(Value::as_str)
            .and_then(|raw| DomainName::parse(raw).ok())
            .is_some_and(|stored| stored.as_str() == domain.as_str());
        if !matches {
            kept.push(rule);
            continue;
        }
        let include = rule
            .get("include_subdomains")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        // The stored flag decides coverage, not the request.
        reject_protected(protected, domain.as_str(), include)?;
        removed = true;
    }
    *rules = kept;
    Ok(removed)
}

fn paginate<T: Clone>(all: Vec<T>, limit: u32, offset: u32) -> (Vec<T>, bool, Option<u32>) {
    let skip = (offset as usize).min(all.len());
    let page = &all[skip..];
    let count = page.len().min(limit as usize);
    let has_more = count < page.len();
    (
        page[..count].to_vec(),
        has_more,
        has_more.then(|| offset.saturating_add(count as u32)),
    )
}

/// Parses a stored `created_at`/`expires_at`: unix seconds or RFC 3339.
pub(crate) fn stored_time(value: &Value) -> Option<SystemTime> {
    match value {
        Value::Number(number) => number
            .as_u64()
            .map(|seconds| UNIX_EPOCH + Duration::from_secs(seconds)),
        Value::String(raw) => OffsetDateTime::parse(raw, &Rfc3339)
            .ok()
            .and_then(|time| u64::try_from(time.unix_timestamp()).ok())
            .map(|seconds| UNIX_EPOCH + Duration::from_secs(seconds)),
        _ => None,
    }
}

/// Resolves `explain_block`'s `profile_id` to the filter set configured on that
/// profile (the same `profile.filter_set` the policy engine applies).
///
/// A missing `profile_id` means the default filter set. An unknown or
/// unparsable profile is `policy.config.invalid`; a profile whose `filter_set`
/// is not a valid set id is `policy.config.unknown_filter_set`.
fn explain_target(
    snapshot: Option<&Value>,
    profile_id: Option<&str>,
) -> Result<(String, SetId), ControlApiError> {
    let Some(profile_id) = profile_id else {
        let set = parse_set(None)?;
        let name = set.as_str().to_owned();
        return Ok((name, set));
    };
    let profile = snapshot
        .and_then(|snapshot| snapshot.get("policy"))
        .and_then(|policy| policy.get("profiles"))
        .and_then(Value::as_array)
        .and_then(|profiles| {
            profiles
                .iter()
                .find(|profile| profile.get("id").and_then(Value::as_str) == Some(profile_id))
        })
        .ok_or_else(|| {
            mcp_error(
                "policy.config.invalid",
                json!({ "reason": "unknown profile", "id": profile_id }),
            )
        })?;
    let raw = profile
        .get("filter_set")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            mcp_error(
                "policy.config.invalid",
                json!({ "reason": "profile has no filter_set", "id": profile_id }),
            )
        })?;
    let set = SetId::new(raw).map_err(|_| unknown_set(raw))?;
    Ok((profile_id.to_owned(), set))
}

/// Explains a filtered name against the current filtering engine state.
///
/// Shared by the MCP tool and `POST /api/v1/filtering/explain-block` so the two
/// surfaces cannot drift. `profile_id` names a policy profile; its configured
/// `filter_set` is what the engine is asked about.
pub(crate) fn explain(
    filter: &FilterEngine,
    snapshot: Option<&Value>,
    now: SystemTime,
    domain: &str,
    profile_id: Option<&str>,
    qtype: QType,
) -> Result<ExplainBlockResult, ControlApiError> {
    let name = DomainName::parse(domain).map_err(|_| ControlApiError::Module {
        code: "filter_name.invalid_char",
        params: Some(json!({ "domain": domain })),
    })?;
    let (profile_out, set) = explain_target(snapshot, profile_id)?;
    let verdict = filter
        .match_name(&set, &name, filter_qtype(qtype), now)
        .map_err(|_| unknown_set(set.as_str()))?;
    let set_str = set.as_str().to_owned();
    let (verdict, reason) = match &verdict {
        Verdict::Pass | Verdict::Allowed(_) => ("allowed".to_owned(), None),
        Verdict::Blocked(reason) => (
            "blocked".to_owned(),
            Some(ExplainReason {
                rule_text: reason.rule.to_string(),
                source: reason_source_str(&reason.source),
                important: reason.important,
                block_mode: String::new(),
            }),
        ),
        Verdict::Rewrite(_, _) => ("allowed".to_owned(), None),
    };
    Ok(ExplainBlockResult {
        domain: name.as_str().to_owned(),
        profile_id: profile_out,
        filter_set_id: set_str,
        verdict,
        reason,
    })
}

/// Lists MCP-managed entries for one filter set.
///
/// Shared by the MCP tool and `GET /api/v1/filtering/mcp-rules`. Stored rules
/// are read from `snapshot`; temporary allows and pauses come from the engine.
pub(crate) fn list_mcp_rules(
    filter: &FilterEngine,
    snapshot: Option<&Value>,
    now: SystemTime,
    params: &ListRulesParams,
) -> Result<ListRulesResult, ControlApiError> {
    let set = parse_set(params.filter_set_id.as_deref())?;
    let set_str = set.as_str().to_owned();
    let mut result = ListRulesResult {
        filter_set_id: set_str.clone(),
        kind: params.kind.clone(),
        ..Default::default()
    };
    match params.kind.as_str() {
        "temporary_allows" => {
            let allows = filter
                .list_temporary_allows(&set, now)
                .map_err(|_| unknown_set(set.as_str()))?;
            let all: Vec<_> = allows
                .into_iter()
                .map(|allow| TempAllowInfo {
                    domain: allow.domain.to_string(),
                    include_subdomains: allow.include_subdomains,
                    created_at: rfc3339(allow.created_at),
                    expires_at: rfc3339(allow.until),
                    filter_set_id: set_str.clone(),
                })
                .collect();
            let (page, has_more, next_offset) = paginate(all, params.limit, params.offset);
            result.temporary_allows = page;
            result.has_more = has_more;
            result.next_offset = next_offset;
        }
        "pauses" => {
            if let Some(until) = filter.paused_until(&set) {
                result.pauses = vec![PauseInfo {
                    filter_set_id: set_str.clone(),
                    paused_until: rfc3339(until),
                }];
            }
        }
        "rules" => {
            let stored = snapshot.and_then(|snapshot| {
                snapshot
                    .get("filtering")
                    .and_then(|section| section.get("sets"))
                    .and_then(Value::as_array)
                    .and_then(|sets| {
                        sets.iter()
                            .find(|set| set.get("id").and_then(Value::as_str) == Some(&set_str))
                    })
            });
            if snapshot.is_some() && stored.is_none() {
                return Err(unknown_set(set.as_str()));
            }
            let all: Vec<_> = stored
                .and_then(|set| set.get("mcp_rules"))
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(|rule| rule_info(rule, &set_str, now))
                .collect();
            let (page, has_more, next_offset) = paginate(all, params.limit, params.offset);
            result.rules = page;
            result.has_more = has_more;
            result.next_offset = next_offset;
        }
        _ => {
            return Err(ControlApiError::Module {
                code: "mcp.invalid_input",
                params: Some(json!({
                    "reason": "kind must be rules, temporary_allows or pauses"
                })),
            });
        }
    }
    Ok(result)
}

/// Converts one stored `mcp_rules[]` entry, dropping expired or malformed ones.
fn rule_info(rule: &Value, set_str: &str, now: SystemTime) -> Option<McpRuleInfo> {
    let expires_at = stored_time(rule.get("expires_at")?)?;
    if expires_at <= now {
        return None;
    }
    stored_rule_info(rule, set_str)
}

/// Converts one stored `mcp_rules[]` entry regardless of expiry.
///
/// `find_mcp_rule` uses this so an expired rule can still be removed (the tool
/// then checks its stored coverage flag before deleting it).
fn stored_rule_info(rule: &Value, set_str: &str) -> Option<McpRuleInfo> {
    let domain = DomainName::parse(rule.get("domain")?.as_str()?).ok()?;
    let include_subdomains = rule.get("include_subdomains")?.as_bool()?;
    let created_at = stored_time(rule.get("created_at")?)?;
    let expires_at = stored_time(rule.get("expires_at")?)?;
    Some(McpRuleInfo {
        id: rule
            .get("id")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
        domain: domain.to_string(),
        include_subdomains,
        rule_text: format!("{}{}^", if include_subdomains { "||" } else { "|" }, domain),
        created_at: rfc3339(created_at),
        expires_at: rfc3339(expires_at),
        filter_set_id: set_str.to_owned(),
    })
}

/// Finds the stored rule for `domain` in `set`, expired or not.
///
/// An existing snapshot without the set is `policy.config.unknown_filter_set`,
/// matching every other per-set operation. A snapshot with no set at all (a
/// fresh install) simply has no rule.
fn find_stored_rule<'a>(
    snapshot: &'a Value,
    set: &SetId,
    domain: &DomainName,
) -> Result<Option<&'a Value>, ControlApiError> {
    let Some(stored_set) = snapshot
        .get("filtering")
        .and_then(|section| section.get("sets"))
        .and_then(Value::as_array)
        .and_then(|sets| {
            sets.iter()
                .find(|set_value| set_value.get("id").and_then(Value::as_str) == Some(set.as_str()))
        })
    else {
        return Err(unknown_set(set.as_str()));
    };
    Ok(stored_set
        .get("mcp_rules")
        .and_then(Value::as_array)
        .and_then(|rules| {
            rules.iter().find(|rule| {
                rule.get("domain")
                    .and_then(Value::as_str)
                    .and_then(|raw| DomainName::parse(raw).ok())
                    .is_some_and(|stored| stored.as_str() == domain.as_str())
            })
        }))
}

/// Runs a dry-run query and returns the tool-shaped result plus the full
/// decision record (including the synthesized answer).
pub(crate) async fn run_test_query(
    policy: &dnscraft_policy::PolicyEngine,
    params: &dnscraft_mcp::dto::TestQueryParams,
) -> Result<(TestQueryResult, Value), ControlApiError> {
    let source_ip: IpAddr = params
        .source_ip
        .as_deref()
        .and_then(|s| s.parse().ok())
        .unwrap_or(IpAddr::from([127, 0, 0, 1]));
    let listener_id =
        dnscraft_policy::ListenerId::new("mcp-test").map_err(|_| ControlApiError::Internal {
            message: "invalid listener id".to_owned(),
        })?;
    let name =
        dnscraft_proto::Name::from_ascii(&params.domain).map_err(|_| ControlApiError::Module {
            code: "filter_name.invalid_char",
            params: Some(json!({ "domain": params.domain })),
        })?;
    let ctx = RequestContext {
        source_ip,
        protocol: policy_protocol(&params.protocol),
        listener_id,
        client_id: params
            .client_id
            .as_deref()
            .and_then(|id| dnscraft_policy::ClientId::new(id).ok()),
        query: dnscraft_resolver::Query {
            name,
            qtype: dnscraft_proto::RecordType(filter_qtype(params.qtype)),
            qclass: dnscraft_proto::Class::IN,
        },
        flags: dnscraft_policy::ClientFlags::default(),
        test_query: true,
    };
    let answer = policy
        .handle(ctx)
        .await
        .map_err(|e| ControlApiError::Module {
            code: e.code(),
            params: None,
        })?;
    let record = &answer.record;
    let verdict = record.filter.as_ref().map_or("allowed", |_| "blocked");
    let filter_dto = record.filter.as_ref().map(|f| TestQueryFilter {
        rule_text: f.reason.rule.to_string(),
        list_id: None,
        block_mode: f
            .block_mode
            .as_ref()
            .map(block_mode_str)
            .unwrap_or_default(),
    });
    let records: Vec<AnswerRecord> = answer
        .message
        .answers
        .iter()
        .map(|r| AnswerRecord {
            name: r.name.to_string(),
            qtype: record_qtype(r.rtype()),
            ttl: r.ttl,
            data: rdata_str(&r.rdata),
        })
        .collect();
    let rcode = answer.message.rcode().to_string();
    let records_json = serde_json::to_value(&records).map_err(|e| ControlApiError::Internal {
        message: format!("serialize test-query answer: {e}"),
    })?;
    let mut decision = crate::query_log::decision_record_json(record);
    decision["answer"] = json!({ "rcode": rcode, "records": records_json });
    let sel = selection_cause_json(&record.selection);
    let result = TestQueryResult {
        view_id: record.view_id.to_string(),
        profile_id: record.profile_id.to_string(),
        selection: Selection {
            cause: sel.cause,
            prefix: sel.prefix,
            client_id: record.client_id.as_ref().map(|id| id.to_string()),
        },
        verdict: verdict.to_owned(),
        filter: filter_dto,
        answer: SynthesizedAnswer { rcode, records },
        dnssec: record
            .dnssec
            .as_ref()
            .map(|s| dnssec_status_str(s).to_owned()),
        timings: dnscraft_mcp::dto::DecisionTimings {
            select_us: record.timings.select_us,
            filter_us: record.timings.filter_us,
            total_us: record.timings.select_us
                + record.timings.filter_us
                + record.timings.resolve_us,
        },
    };
    Ok((result, decision))
}

// ---- trait impl ----

#[async_trait]
impl McpBackend for ControlMcpBackend {
    async fn validate_token(&self, token: &str) -> Result<TokenInfo, BackendError> {
        let store = self.inner.tokens.as_ref().ok_or(BackendError::Internal {
            message: "token store not configured".into(),
        })?;
        match store.authenticate(token).await {
            Ok(principal) => {
                if principal.scope().family() != crate::api::auth::EndpointFamily::Mcp {
                    return Err(BackendError::InvalidScope);
                }
                Ok(TokenInfo {
                    token_id: principal.id().to_owned(),
                    scope: map_mcp_scope(principal.scope()),
                    actor_id: principal.actor_id().to_owned(),
                })
            }
            Err(ControlApiError::AuthUnauthenticated) => Err(BackendError::Unauthenticated),
            Err(e) => Err(BackendError::Internal {
                message: format!("token validation: {}", e.code()),
            }),
        }
    }

    async fn search_query_log(
        &self,
        params: QueryLogSearch,
    ) -> Result<QueryLogResult, BackendError> {
        let log = self
            .inner
            .query_log
            .as_ref()
            .ok_or(BackendError::Internal {
                message: "query log not configured".into(),
            })?;
        let from_us = parse_time(params.from.as_deref(), "from")?;
        // The MCP bound is exclusive; the query-log filter's is inclusive.
        let to_us = parse_time(params.to.as_deref(), "to")?.map(|to| to.saturating_sub(1));
        let filter = QueryLogFilter {
            from_us,
            to_us,
            node_id: None,
            client_id: non_empty(params.client_id),
            client_name_substr: non_empty(params.client_name_substr),
            domain: non_empty(params.domain),
            domain_substr: non_empty(params.domain_substr),
            protocol: non_empty(params.protocol),
            view_id: non_empty(params.view_id),
            profile_id: non_empty(params.profile_id),
            status: non_empty(params.status),
            only_blocked: params.only_blocked,
            only_with_clients: false,
            order_by: query_order_by(&params.order_by),
            order: query_order(&params.order),
            limit: params.limit,
            offset: u64::from(params.offset),
        };
        let page = log
            .list(&filter)
            .await
            .map_err(|e| BackendError::Internal {
                message: format!("query-log list: {}", e.code()),
            })?;
        Ok(QueryLogResult {
            queries: page.records.iter().map(query_entry).collect(),
            has_more: page.has_more,
            next_offset: page.next_offset.map(|offset| offset as u32),
        })
    }

    async fn get_query(&self, id: &str) -> Result<QueryDetail, BackendError> {
        let log = self
            .inner
            .query_log
            .as_ref()
            .ok_or(BackendError::Internal {
                message: "query log not configured".into(),
            })?;
        let row = log.get(id).await.map_err(|e| BackendError::Internal {
            message: format!("query-log get: {}", e.code()),
        })?;
        let row = row.ok_or(BackendError::NotFound {
            what: format!("query {id}"),
        })?;
        Ok(QueryDetail {
            id: json_str(&row, "id"),
            view_id: json_str(&row, "view_id"),
            profile_id: json_str(&row, "profile_id"),
            selection: Selection {
                cause: json_str(&row["selection"], "cause"),
                prefix: json_opt_str(&row["selection"], "prefix"),
                client_id: json_opt_str(&row["selection"], "client_id"),
            },
            steps: row["steps"]
                .as_array()
                .map(|steps| {
                    steps
                        .iter()
                        .map(|s| dnscraft_mcp::dto::DecisionStep {
                            stage: json_str(s, "stage"),
                            verdict: json_str(s, "verdict"),
                            rule: json_opt_str(s, "rule"),
                            list_id: json_opt_str(s, "list_id"),
                        })
                        .collect()
                })
                .unwrap_or_default(),
            filter: json_opt_filter(row.get("filter")),
            dnssec: json_opt_str(&row, "dnssec"),
            answer_source: json_str(&row, "answer_source"),
            rcode: json_str(&row, "rcode"),
            timings: dnscraft_mcp::dto::DecisionTimings {
                select_us: row["timings"]["select_us"].as_u64().unwrap_or(0),
                filter_us: row["timings"]["filter_us"].as_u64().unwrap_or(0),
                total_us: row["timings"]["total_us"].as_u64().unwrap_or(0),
            },
        })
    }

    async fn explain_block(
        &self,
        domain: &str,
        profile_id: Option<&str>,
        qtype: QType,
    ) -> Result<ExplainBlockResult, BackendError> {
        let snapshot = self.current_snapshot().await?;
        explain(
            self.filter_engine()?,
            snapshot.as_ref(),
            self.inner.clock.now(),
            domain,
            profile_id,
            qtype,
        )
        .map_err(backend_error)
    }

    async fn test_query(
        &self,
        params: dnscraft_mcp::dto::TestQueryParams,
    ) -> Result<TestQueryResult, BackendError> {
        run_test_query(self.policy_engine()?, &params)
            .await
            .map(|(result, _)| result)
            .map_err(backend_error)
    }

    async fn get_stats(&self, params: StatsParams) -> Result<StatsResult, BackendError> {
        let log = self
            .inner
            .query_log
            .as_ref()
            .ok_or(BackendError::Internal {
                message: "query log not configured".into(),
            })?;
        let from_us = parse_time(params.from.as_deref(), "from")?;
        // The MCP bound is exclusive; the stats window is inclusive.
        let to_us = parse_time(params.to.as_deref(), "to")?.map(|to| to.saturating_sub(1));
        let stats_err = |what: &str, e: ControlApiError| BackendError::Internal {
            message: format!("{what}: {}", e.code()),
        };
        let overview = log
            .stats_overview(from_us, to_us, None)
            .await
            .map_err(|e| stats_err("stats overview", e))?;
        let top_clients = log
            .top_clients(from_us, to_us, None, 10, TopBy::Queries)
            .await
            .map_err(|e| stats_err("stats top clients", e))?;
        let top_blocked = log
            .top_blocked_domains(from_us, to_us, None, 10)
            .await
            .map_err(|e| stats_err("stats top blocked domains", e))?;
        let cache = log
            .cache_stats(from_us, to_us, None)
            .await
            .map_err(|e| stats_err("stats cache", e))?;
        let count = |key: &str| overview.dnssec.get(key).copied().unwrap_or(0).max(0) as u64;
        Ok(StatsResult {
            period: StatsPeriod {
                from: overview.from.clone(),
                to: overview.to.clone(),
            },
            total_queries: overview.total.max(0) as u64,
            blocked_queries: overview.blocked.max(0) as u64,
            allowed_queries: overview.allowed.max(0) as u64,
            blocked_ratio: if overview.total <= 0 {
                0.0
            } else {
                overview.blocked as f64 / overview.total as f64
            },
            top_blocked_domains: top_blocked
                .domains
                .into_iter()
                .map(|domain| dnscraft_mcp::dto::TopDomain {
                    domain: domain.domain,
                    count: domain.blocked.max(0) as u64,
                })
                .collect(),
            top_clients: top_clients
                .clients
                .into_iter()
                .map(|client| dnscraft_mcp::dto::TopClient {
                    client_name: client.client_name,
                    queries: client.queries.max(0) as u64,
                })
                .collect(),
            cache_hit_ratio: cache.hit_ratio,
            dnssec: DnssecCounts {
                secure: count("secure"),
                insecure: count("insecure"),
                bogus: count("bogus"),
            },
        })
    }

    async fn list_clients(
        &self,
        _params: dnscraft_mcp::dto::ClientListParams,
    ) -> Result<dnscraft_mcp::dto::ClientListResult, BackendError> {
        Ok(dnscraft_mcp::dto::ClientListResult {
            clients: vec![],
            has_more: false,
            next_offset: None,
        })
    }

    async fn get_status(&self) -> Result<NodeStatus, BackendError> {
        let uptime = self.inner.start_time.elapsed().as_secs();
        let cache_size = self
            .inner
            .resolver_cache_size
            .load(std::sync::atomic::Ordering::Relaxed);
        let tls = self
            .inner
            .tls
            .as_ref()
            .map(|p| {
                let status = p.status();
                TlsStatus {
                    mode: status.mode.as_str().to_owned(),
                    cert_expiry: String::new(),
                    fingerprint: status.fingerprint,
                }
            })
            .unwrap_or_default();
        Ok(NodeStatus {
            node_id: self.inner.node_id.clone(),
            version: self.inner.version.clone(),
            uptime_seconds: uptime,
            resolver: ResolverStatus {
                primed: cache_size > 0,
                cache_size,
            },
            listeners: vec![],
            tls,
            filtering: FilteringStatus {
                lists_loaded: 0,
                rules_active: 0,
                last_update: String::new(),
            },
        })
    }

    async fn list_mcp_rules(
        &self,
        params: ListRulesParams,
    ) -> Result<ListRulesResult, BackendError> {
        let snapshot = match &self.inner.config {
            Some(service) => {
                service
                    .current()
                    .await
                    .map_err(|e| BackendError::Internal {
                        message: e.code().to_owned(),
                    })?
                    .1
            }
            None => None,
        };
        list_mcp_rules(
            self.filter_engine()?,
            snapshot.as_ref(),
            self.inner.clock.now(),
            &params,
        )
        .map_err(backend_error)
    }

    async fn allow_temporarily(
        &self,
        params: TempAllowParams,
    ) -> Result<TempAllowResult, BackendError> {
        let filter = self.filter_engine()?;
        if let Some(error) = duration_error(
            params.duration.seconds(),
            self.inner.mcp_config.max_temporary_allow_duration,
        ) {
            return Err(backend_error(error));
        }
        let domain = canonical_allow_domain(&params.domain).map_err(backend_error)?;
        let set = parse_set(params.filter_set_id.as_deref()).map_err(backend_error)?;

        // Hold the config apply lock across the snapshot read, the protected
        // check and the engine mutation, so a concurrent config replace cannot
        // swap the snapshot between the check and the allow (TOCTOU).
        let service = self.inner.config.as_ref();
        let _guard = match service {
            Some(service) => Some(service.apply_guard().await),
            None => None,
        };
        let snapshot = match service {
            Some(service) => {
                service
                    .current()
                    .await
                    .map_err(|e| BackendError::Internal {
                        message: e.code().to_owned(),
                    })?
                    .1
            }
            None => None,
        };
        let protected = self.protected(snapshot.as_ref())?;
        reject_protected(&protected, domain.as_str(), params.include_subdomains)
            .map_err(backend_error)?;

        let now = self.inner.clock.now();
        let until = now + duration_secs(params.duration);
        let rule = TempAllow {
            domain: domain.clone(),
            include_subdomains: params.include_subdomains,
            until,
            created_at: now,
        };
        filter
            .allow_temporarily(&set, rule)
            .map_err(|err| backend_error(engine_error(err, set.as_str())))?;
        self.inner.broadcast_runtime_command(
            "temporary_allow",
            &json!({
                "filter_set_id": set.as_str(),
                "domain": domain.as_str(),
                "include_subdomains": params.include_subdomains,
                "expires_at": rfc3339(until),
            }),
        );
        Ok(TempAllowResult {
            created_at: rfc3339(now),
            expires_at: rfc3339(until),
            filter_set_id: set.as_str().to_owned(),
        })
    }

    async fn add_custom_rule(&self, params: AddRuleParams) -> Result<AddRuleResult, BackendError> {
        let service = self.config_service()?;
        let actor = ConfigActor::new(params.token_id.clone(), "token");
        let failure_after = json!({
            "domain": params.domain.clone(),
            "include_subdomains": params.include_subdomains,
            "filter_set_id": params.filter_set_id.clone(),
            "reason": params.reason.clone(),
        });

        // Everything before the mutation is validated up front so its failure
        // can be audited; the mutation closure then only depends on the locked
        // snapshot (protected coverage + cap).
        let (set, domain, rule_text, lifetime) =
            match prepare_add(&params, self.inner.mcp_config.max_block_rule_lifetime) {
                Ok(prepared) => prepared,
                Err(err) => {
                    service
                        .record_action(
                            &actor,
                            "mcp.add_rule",
                            None,
                            Some(&failure_after),
                            Some(err.code()),
                        )
                        .await;
                    return Err(backend_error(err));
                }
            };
        let now = self.inner.clock.now();
        let expires_at = now + lifetime;
        let created_secs = crate::clock::unix_seconds(now);
        let expires_secs = crate::clock::unix_seconds(expires_at);
        let rule_id = crate::query_log::new_id().map_err(backend_error)?;
        let cap = self.inner.mcp_config.max_custom_rules_per_set as usize;
        let include = params.include_subdomains;
        let token_id = params.token_id.clone();
        let reason = params.reason.clone();
        let issuer = self.inner.oidc_issuer.clone();
        let extra = self.inner.mcp_config.protected_domains.clone();
        let rule_id_for_audit = rule_id.clone();
        let rule_text_for_audit = rule_text.clone();
        let set_str = set.as_str().to_owned();
        let set_for_audit = set_str.clone();
        let domain_for_audit = domain.as_str().to_owned();
        let created_for_audit = rfc3339(now);
        let expires_for_audit = rfc3339(expires_at);

        let version = service
            .mutate_audited(
                &actor,
                "mcp.add_rule",
                Some(failure_after),
                move |snapshot| {
                    let protected = protected_for(Some(snapshot), issuer.as_deref(), extra)?;
                    reject_protected(&protected, domain.as_str(), include)?;
                    add_rule_to_snapshot(
                        snapshot,
                        &set,
                        &domain,
                        include,
                        &rule_id_for_audit,
                        created_secs,
                        expires_secs,
                        &token_id,
                        cap,
                        now,
                    )?;
                    Ok(Some(MutationAudit {
                        before: None,
                        after: json!({
                            "domain": domain_for_audit,
                            "include_subdomains": include,
                            "filter_set_id": set_for_audit,
                            "reason": reason,
                            "rule_text": rule_text_for_audit,
                            "rule_id": rule_id_for_audit,
                            "created_at": created_for_audit,
                            "expires_at": expires_for_audit,
                            "config_version": Value::Null,
                        }),
                    }))
                },
            )
            .await
            .map_err(backend_error)?;
        let version = version
            .and_then(|version| u64::try_from(version).ok())
            .ok_or_else(|| BackendError::Internal {
                message: "custom-rule mutation stored no config version".into(),
            })?;
        Ok(AddRuleResult {
            rule_id,
            rule_text,
            filter_set_id: set_str,
            created_at: rfc3339(now),
            expires_at: rfc3339(expires_at),
            config_version: Some(version),
        })
    }

    async fn find_mcp_rule(
        &self,
        domain: &str,
        filter_set_id: Option<&str>,
    ) -> Result<Option<dnscraft_mcp::dto::McpRuleInfo>, BackendError> {
        let set = parse_set(filter_set_id).map_err(backend_error)?;
        let domain =
            DomainName::parse(domain).map_err(|_| code_err("filter_name.invalid_char", domain))?;
        let Some(snapshot) = self.current_snapshot().await? else {
            return Ok(None);
        };
        let rule = find_stored_rule(&snapshot, &set, &domain).map_err(backend_error)?;
        Ok(rule.and_then(|rule| stored_rule_info(rule, set.as_str())))
    }

    async fn remove_custom_rule(
        &self,
        params: RemoveRuleParams,
    ) -> Result<RemoveRuleResult, BackendError> {
        let service = self.config_service()?;
        let actor = ConfigActor::new(params.token_id.clone(), "token");
        let failure_after = json!({
            "domain": params.domain.clone(),
            "filter_set_id": params.filter_set_id.clone(),
            "removed": false,
            "config_version": Value::Null,
        });
        let (set, domain) = match prepare_remove(&params) {
            Ok(prepared) => prepared,
            Err(err) => {
                service
                    .record_action(
                        &actor,
                        "mcp.remove_rule",
                        None,
                        Some(&failure_after),
                        Some(err.code()),
                    )
                    .await;
                return Err(backend_error(err));
            }
        };
        let set_str = set.as_str().to_owned();
        let issuer = self.inner.oidc_issuer.clone();
        let extra = self.inner.mcp_config.protected_domains.clone();
        let version = service
            .mutate_audited(
                &actor,
                "mcp.remove_rule",
                Some(failure_after),
                move |snapshot| {
                    let protected = protected_for(Some(snapshot), issuer.as_deref(), extra)?;
                    let stored = find_stored_rule(snapshot, &set, &domain)?;
                    let before = stored.map(|rule| {
                        json!({
                            "domain": rule
                                .get("domain")
                                .and_then(Value::as_str)
                                .unwrap_or(domain.as_str()),
                            "include_subdomains": rule
                                .get("include_subdomains")
                                .and_then(Value::as_bool)
                                .unwrap_or(false),
                            "filter_set_id": set.as_str(),
                            "rule_id": rule.get("id").and_then(Value::as_str).unwrap_or_default(),
                        })
                    });
                    let removed = remove_rule_from_snapshot(snapshot, &set, &domain, &protected)?;
                    if !removed {
                        return Ok(None);
                    }
                    let rule_id = before
                        .as_ref()
                        .and_then(|before| before.get("rule_id"))
                        .cloned()
                        .unwrap_or(Value::Null);
                    Ok(Some(MutationAudit {
                        before,
                        after: json!({
                            "domain": domain.as_str(),
                            "filter_set_id": set.as_str(),
                            "removed": true,
                            "rule_id": rule_id,
                            "config_version": Value::Null,
                        }),
                    }))
                },
            )
            .await
            .map_err(backend_error)?;
        let removed = version.is_some();
        let config_version = version
            .map(|version| {
                u64::try_from(version).map_err(|_| BackendError::Internal {
                    message: "negative config version".into(),
                })
            })
            .transpose()?;
        Ok(RemoveRuleResult {
            removed,
            filter_set_id: set_str,
            config_version,
        })
    }

    async fn pause_filter_set(&self, params: PauseParams) -> Result<PauseResult, BackendError> {
        if let Some(error) = duration_error(
            params.duration.seconds(),
            self.inner.mcp_config.max_pause_duration,
        ) {
            return Err(backend_error(error));
        }
        let set = parse_set(params.filter_set_id.as_deref()).map_err(backend_error)?;
        let until = self.inner.clock.now() + duration_secs(params.duration);
        self.filter_engine()?
            .set_paused_until(&set, Some(until))
            .map_err(|err| backend_error(engine_error(err, set.as_str())))?;
        self.inner.broadcast_runtime_command(
            "pause",
            &json!({
                "filter_set_id": set.as_str(),
                "expires_at": rfc3339(until),
            }),
        );
        Ok(PauseResult {
            filter_set_id: set.as_str().to_owned(),
            paused_until: rfc3339(until),
        })
    }

    async fn resume_filter_set(
        &self,
        filter_set_id: Option<&str>,
    ) -> Result<ResumeResult, BackendError> {
        let set = parse_set(filter_set_id).map_err(backend_error)?;
        let filter = self.filter_engine()?;
        let was = filter.paused_until(&set).map(rfc3339);
        filter
            .set_paused_until(&set, None)
            .map_err(|err| backend_error(engine_error(err, set.as_str())))?;
        self.inner
            .broadcast_runtime_command("resume", &json!({ "filter_set_id": set.as_str() }));
        Ok(ResumeResult {
            filter_set_id: set.as_str().to_owned(),
            resumed: was.is_some(),
            was_paused_until: was,
        })
    }

    async fn record_audit(&self, entry: AuditEntry) -> Result<(), BackendError> {
        let audit = self.inner.audit.as_ref().ok_or(BackendError::Internal {
            message: "audit log not configured".into(),
        })?;
        let result = match entry.result {
            AuditResult::Success => "success".to_owned(),
            AuditResult::Error => "error".to_owned(),
        };
        // The audit DTO has no `config_version` field. A committed add/remove
        // reports its new version inside `after`, so lift it into the stored
        // record instead of losing it.
        let config_version = entry.after.get("config_version").and_then(Value::as_i64);
        audit
            .record_config_change(crate::audit::ConfigChangeRecord {
                node_id: self.inner.node_id.clone(),
                actor_id: entry.actor_id,
                actor_type: "token".to_owned(),
                action: entry.action,
                before: entry.before,
                after: Some(entry.after),
                config_version,
                result,
                error_code: entry.error_code,
            })
            .await
            .map_err(|_| BackendError::Internal {
                message: "audit write failed".into(),
            })?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Cluster runtime commands (volatile state, never a config version)
// ---------------------------------------------------------------------------

impl AppState {
    /// Applies a volatile cluster runtime command to the local filter engine.
    ///
    /// `kind` is `"pause"`, `"resume"` or `"temporary_allow"`. `payload` carries
    /// `filter_set_id` and, for `pause`/`temporary_allow`, a `duration`
    /// (`PT5M`/`PT15M`/`PT1H`) and/or an absolute `expires_at`;
    /// `temporary_allow` also carries `domain` and `include_subdomains`.
    ///
    /// Runtime commands change no config version and write no audit entry: they
    /// are volatile, last-command-wins state applied straight to the
    /// [`FilterEngine`], using the same limits and engine calls as the MCP
    /// write tools. Module error codes are returned unchanged.
    pub async fn apply_runtime_command(
        &self,
        kind: &str,
        payload: &Value,
    ) -> Result<(), ControlApiError> {
        match kind {
            "pause" => self.apply_runtime_pause(payload).await,
            "resume" => self.apply_runtime_resume(payload),
            "temporary_allow" => self.apply_runtime_temporary_allow(payload).await,
            other => Err(mcp_error(
                "mcp.invalid_input",
                json!({ "reason": format!("unknown runtime command kind: {other}") }),
            )),
        }
    }

    fn runtime_filter(&self) -> Result<&Arc<FilterEngine>, ControlApiError> {
        self.filter_engine()
            .ok_or_else(|| ControlApiError::Internal {
                message: "filter engine is not configured".to_owned(),
            })
    }

    async fn apply_runtime_pause(&self, payload: &Value) -> Result<(), ControlApiError> {
        let set = parse_set(payload.get("filter_set_id").and_then(Value::as_str))?;
        let until = runtime_until(
            payload,
            self.clock().now(),
            self.mcp_config().max_pause_duration,
        )?;
        self.runtime_filter()?
            .set_paused_until(&set, Some(until))
            .map_err(|err| engine_error(err, set.as_str()))
    }

    fn apply_runtime_resume(&self, payload: &Value) -> Result<(), ControlApiError> {
        let set = parse_set(payload.get("filter_set_id").and_then(Value::as_str))?;
        self.runtime_filter()?
            .set_paused_until(&set, None)
            .map_err(|err| engine_error(err, set.as_str()))
    }

    async fn apply_runtime_temporary_allow(&self, payload: &Value) -> Result<(), ControlApiError> {
        let duration = runtime_duration(payload, self.mcp_config().max_temporary_allow_duration)?;
        let domain = canonical_allow_domain(runtime_str(payload, "domain")?)?;
        let include_subdomains = payload
            .get("include_subdomains")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let set = parse_set(payload.get("filter_set_id").and_then(Value::as_str))?;
        let until = runtime_until_with(
            duration,
            runtime_expires_at(payload)?,
            self.clock().now(),
            self.mcp_config().max_temporary_allow_duration,
        )?;

        // Same sequence as `ControlMcpBackend::allow_temporarily`: hold the
        // apply lock across the snapshot read, the protected check and the
        // engine mutation so a concurrent config replace cannot interleave.
        let _guard = match self.config_service() {
            Some(service) => Some(service.apply_guard().await),
            None => None,
        };
        let snapshot = match self.config_service() {
            Some(service) => service.current().await?.1,
            None => None,
        };
        let protected = protected_for(
            snapshot.as_ref(),
            self.oidc_issuer(),
            self.mcp_config().protected_domains.iter().cloned(),
        )?;
        reject_protected(&protected, domain.as_str(), include_subdomains)?;

        let rule = TempAllow {
            domain,
            include_subdomains,
            until,
            created_at: self.clock().now(),
        };
        self.runtime_filter()?
            .allow_temporarily(&set, rule)
            .map_err(|err| engine_error(err, set.as_str()))
    }
}

fn runtime_str<'a>(payload: &'a Value, field: &str) -> Result<&'a str, ControlApiError> {
    payload.get(field).and_then(Value::as_str).ok_or_else(|| {
        mcp_error(
            "mcp.invalid_input",
            json!({ "reason": format!("`{field}` is required") }),
        )
    })
}

/// Parses the fixed MCP duration set and applies the configured maximum.
fn runtime_duration(
    payload: &Value,
    maximum: Duration,
) -> Result<Option<PauseDuration>, ControlApiError> {
    let Some(raw) = payload.get("duration") else {
        return Ok(None);
    };
    let duration: PauseDuration = serde_json::from_value(raw.clone()).map_err(|_| {
        mcp_error(
            "mcp.invalid_input",
            json!({ "reason": "`duration` must be one of PT5M, PT15M, PT1H" }),
        )
    })?;
    if let Some(error) = duration_error(duration.seconds(), maximum) {
        return Err(error);
    }
    Ok(Some(duration))
}

fn runtime_expires_at(payload: &Value) -> Result<Option<SystemTime>, ControlApiError> {
    payload
        .get("expires_at")
        .map(|value| {
            stored_time(value).ok_or_else(|| {
                mcp_error(
                    "mcp.invalid_input",
                    json!({ "reason": "`expires_at` must be unix seconds or an RFC 3339 timestamp" }),
                )
            })
        })
        .transpose()
}

/// Resolves and validates the absolute deadline of a runtime command.
fn runtime_until(
    payload: &Value,
    now: SystemTime,
    maximum: Duration,
) -> Result<SystemTime, ControlApiError> {
    runtime_until_with(
        runtime_duration(payload, maximum)?,
        runtime_expires_at(payload)?,
        now,
        maximum,
    )
}

/// `duration` is validated against `maximum` exactly like the MCP write tools.
/// `expires_at` is the master's broadcast deadline; when both are present it
/// may only shorten the local deadline, never extend it. Without a `duration`
/// the remaining lifetime still has to fit the configured maximum.
fn runtime_until_with(
    duration: Option<PauseDuration>,
    expires_at: Option<SystemTime>,
    now: SystemTime,
    maximum: Duration,
) -> Result<SystemTime, ControlApiError> {
    match (duration, expires_at) {
        (Some(duration), Some(expires_at)) => {
            let latest = now + Duration::from_secs(duration.seconds());
            if expires_at > latest {
                return Err(mcp_error(
                    "mcp.invalid_input",
                    json!({ "reason": "`expires_at` extends past `duration`" }),
                ));
            }
            Ok(expires_at)
        }
        (Some(duration), None) => Ok(now + Duration::from_secs(duration.seconds())),
        (None, Some(expires_at)) => {
            let remaining = expires_at.duration_since(now).unwrap_or(Duration::ZERO);
            if remaining > maximum {
                return Err(duration_exceeds(remaining, maximum));
            }
            Ok(expires_at)
        }
        (None, None) => Err(mcp_error(
            "mcp.invalid_input",
            json!({ "reason": "`duration` or `expires_at` is required" }),
        )),
    }
}

fn json_opt_filter(opt: Option<&Value>) -> Option<dnscraft_mcp::dto::DecisionFilter> {
    let f = opt?;
    Some(dnscraft_mcp::dto::DecisionFilter {
        reason: f
            .get("reason")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_owned(),
        block_mode: f
            .get("block_mode")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_owned(),
        rule_text: f
            .get("rule_text")
            .and_then(|v| v.as_str())
            .map(str::to_owned),
        list_id: f.get("list_id").and_then(|v| v.as_str()).map(str::to_owned),
        important: f
            .get("important")
            .and_then(|v| v.as_bool())
            .unwrap_or(false),
    })
}
