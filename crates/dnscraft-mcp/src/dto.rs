//! Boundary DTOs for [`McpBackend`](crate::backend::McpBackend).
//!
//! Every type here is owned by this crate so that `control-api` can implement
//! the backend without `dnscraft-mcp` depending on it. Ids are `String`
//! values and domains are `String` in the canonical form described by
//! `SPEC-mcp.md`; no DNSCraft module type crosses the boundary.
//!
//! The read-tool shapes mirror `SPEC-mcp.md` § Read tools field for field; the
//! tools serialize them with fixed field names and sanitized values.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// DNS record type accepted by the read tools.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum QType {
    /// IPv4 address record.
    #[default]
    #[serde(rename = "A")]
    A,
    /// IPv6 address record.
    #[serde(rename = "AAAA")]
    Aaaa,
    /// Canonical name record.
    #[serde(rename = "CNAME")]
    Cname,
    /// Mail exchange record.
    #[serde(rename = "MX")]
    Mx,
    /// Text record.
    #[serde(rename = "TXT")]
    Txt,
    /// Service locator record.
    #[serde(rename = "SRV")]
    Srv,
    /// HTTPS service binding record.
    #[serde(rename = "HTTPS")]
    Https,
}

impl QType {
    /// The uppercase wire name used in tool output.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::A => "A",
            Self::Aaaa => "AAAA",
            Self::Cname => "CNAME",
            Self::Mx => "MX",
            Self::Txt => "TXT",
            Self::Srv => "SRV",
            Self::Https => "HTTPS",
        }
    }
}

/// Scope carried by an MCP bearer token.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TokenScope {
    /// Read tools only.
    #[serde(rename = "mcp:read")]
    McpRead,
    /// Read and write tools.
    #[serde(rename = "mcp:write")]
    McpWrite,
}

/// Result of validating an MCP bearer token.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenInfo {
    /// Stable token id (never the token secret).
    pub token_id: String,
    /// Token scope.
    pub scope: TokenScope,
    /// Actor that owns the token.
    pub actor_id: String,
}

/// The three durations accepted by `allow_temporarily` and
/// `pause_filter_set`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum PauseDuration {
    /// Five minutes.
    #[default]
    #[serde(rename = "PT5M")]
    Pt5M,
    /// Fifteen minutes.
    #[serde(rename = "PT15M")]
    Pt15M,
    /// One hour.
    #[serde(rename = "PT1H")]
    Pt1H,
}

impl PauseDuration {
    /// The ISO 8601 representation used on the wire.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pt5M => "PT5M",
            Self::Pt15M => "PT15M",
            Self::Pt1H => "PT1H",
        }
    }

    /// The duration in seconds.
    pub fn seconds(self) -> u64 {
        match self {
            Self::Pt5M => 5 * 60,
            Self::Pt15M => 15 * 60,
            Self::Pt1H => 60 * 60,
        }
    }
}

/// Resolver state reported by `get_status`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolverStatus {
    /// Whether the resolver has primed its root hints.
    pub primed: bool,
    /// Number of cached entries.
    pub cache_size: u64,
}

/// One listener binding reported by `get_status`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListenerStatus {
    /// Listener id from configuration.
    pub id: String,
    /// Transport and port, for example `udp53`.
    pub protocol: String,
    /// Bound address.
    pub bind: String,
    /// Runtime state, for example `running`.
    pub status: String,
}

/// TLS state reported by `get_status`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TlsStatus {
    /// Certificate mode, for example `acme` or `self_signed`.
    pub mode: String,
    /// Certificate expiry as an RFC 3339 timestamp, when known.
    pub cert_expiry: String,
    /// SHA-256 certificate fingerprint, when known.
    pub fingerprint: String,
}

/// Filtering state reported by `get_status`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FilteringStatus {
    /// Number of loaded filter lists.
    pub lists_loaded: u64,
    /// Number of active rules.
    pub rules_active: u64,
    /// Last successful list update as an RFC 3339 timestamp, when known.
    pub last_update: String,
}

/// Node status returned by `get_status`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeStatus {
    /// Node identifier.
    pub node_id: String,
    /// Build version.
    pub version: String,
    /// Process uptime in seconds.
    pub uptime_seconds: u64,
    /// Resolver state.
    pub resolver: ResolverStatus,
    /// Bound listeners.
    pub listeners: Vec<ListenerStatus>,
    /// TLS state.
    pub tls: TlsStatus,
    /// Filtering state.
    pub filtering: FilteringStatus,
}

/// Validated filters for [`McpBackend::search_query_log`](crate::backend::McpBackend::search_query_log).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueryLogSearch {
    /// Maximum number of entries to return (1..=500).
    pub limit: u32,
    /// Number of entries to skip.
    pub offset: u32,
    /// Inclusive lower time bound, RFC 3339.
    pub from: Option<String>,
    /// Exclusive upper time bound, RFC 3339.
    pub to: Option<String>,
    /// Exact client id.
    pub client_id: Option<String>,
    /// Case-insensitive substring of the client display name.
    pub client_name_substr: Option<String>,
    /// Exact canonical domain.
    pub domain: Option<String>,
    /// Case-insensitive substring of the domain.
    pub domain_substr: Option<String>,
    /// DNS protocol (`udp53`, `tcp53`, `dot`, `doh`, `doq`).
    pub protocol: Option<String>,
    /// Policy view id.
    pub view_id: Option<String>,
    /// Policy profile id.
    pub profile_id: Option<String>,
    /// Query outcome (`allowed`, `blocked`, `dnssec_bogus`, `servfail`).
    pub status: Option<String>,
    /// Return only blocked queries.
    pub only_blocked: bool,
    /// Sort key (`time`, `client`, `domain`, `rcode`).
    pub order_by: String,
    /// Sort direction (`asc`, `desc`).
    pub order: String,
}

/// Client attribution of one query-log row.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueryClient {
    /// Client id.
    pub id: String,
    /// Display name.
    pub display_name: String,
    /// Discovery source, for example `unifi`.
    pub source: String,
}

/// Queried name of one query-log row.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueryName {
    /// Canonical domain.
    pub name: String,
    /// Query type.
    pub qtype: QType,
}

/// Filter attribution of one query-log row.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueryLogFilter {
    /// Filtering reason, for example `adblock`.
    pub reason: String,
    /// Matching rule text, when any.
    pub rule_text: Option<String>,
    /// Source list id, when any.
    pub list_id: Option<String>,
}

/// Timings of one query-log row.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueryTimings {
    /// Total handling time in microseconds.
    pub total_us: u64,
}

/// One query-log row.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueryLogEntry {
    /// Canonical query id.
    pub id: String,
    /// RFC 3339 timestamp.
    pub time: String,
    /// Client attribution.
    pub client: QueryClient,
    /// Queried name.
    pub query: QueryName,
    /// Policy profile id.
    pub profile_id: String,
    /// Where the answer came from, for example `resolver`.
    pub answer_source: String,
    /// Filter attribution, when the query matched a rule.
    pub filter: Option<QueryLogFilter>,
    /// Response code, for example `NXDOMAIN`.
    pub rcode: String,
    /// Timings.
    pub timings: QueryTimings,
}

/// A page of query-log rows.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueryLogResult {
    /// The rows.
    pub queries: Vec<QueryLogEntry>,
    /// Whether more rows exist after this page.
    pub has_more: bool,
    /// Offset to request next, when `has_more`.
    pub next_offset: Option<u32>,
}

/// How the policy view was selected for a query.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Selection {
    /// Selection cause, for example `subnet` or `client_id`.
    pub cause: String,
    /// Matching source prefix, when the cause is a subnet.
    pub prefix: Option<String>,
    /// Matching client id, when the cause is a client.
    pub client_id: Option<String>,
}

/// One decision-pipeline step.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecisionStep {
    /// Pipeline stage, for example `filter_qname`.
    pub stage: String,
    /// Stage verdict, for example `blocked`.
    pub verdict: String,
    /// Matching rule text, when any.
    pub rule: Option<String>,
    /// Source list id, when any.
    pub list_id: Option<String>,
}

/// Filter attribution in a decision record.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecisionFilter {
    /// Filtering reason, for example `adblock`.
    pub reason: String,
    /// Block mode, for example `nxdomain`.
    pub block_mode: String,
    /// Matching rule text, when any.
    pub rule_text: Option<String>,
    /// Source list id, when any.
    pub list_id: Option<String>,
    /// Whether the rule is marked important.
    pub important: bool,
}

/// Timings of a decision record.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecisionTimings {
    /// View-selection time in microseconds.
    pub select_us: u64,
    /// Filtering time in microseconds.
    pub filter_us: u64,
    /// Total decision time in microseconds.
    pub total_us: u64,
}

/// Detail for one query (`get_query`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueryDetail {
    /// Canonical query id.
    pub id: String,
    /// Selected policy view id.
    pub view_id: String,
    /// Selected policy profile id.
    pub profile_id: String,
    /// View-selection result.
    pub selection: Selection,
    /// Decision-pipeline steps.
    pub steps: Vec<DecisionStep>,
    /// Filter attribution, when a rule matched.
    pub filter: Option<DecisionFilter>,
    /// DNSSEC status, when validated.
    pub dnssec: Option<String>,
    /// Where the answer came from.
    pub answer_source: String,
    /// Response code.
    pub rcode: String,
    /// Timings.
    pub timings: DecisionTimings,
}

/// Why a domain is blocked (`explain_block`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExplainReason {
    /// Matching rule text.
    pub rule_text: String,
    /// Rule source, for example `list:adguard-dns:line 1234`.
    pub source: String,
    /// Whether the rule is marked important.
    pub important: bool,
    /// Block mode.
    pub block_mode: String,
}

/// Result of `explain_block`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExplainBlockResult {
    /// Canonical domain.
    pub domain: String,
    /// Profile that was evaluated.
    pub profile_id: String,
    /// Filter set of the profile.
    pub filter_set_id: String,
    /// `blocked` or `allowed`.
    pub verdict: String,
    /// Matching rule, when blocked by a filter rule.
    pub reason: Option<ExplainReason>,
}

/// Validated input for `test_query`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TestQueryParams {
    /// Canonical domain.
    pub domain: String,
    /// Query type.
    pub qtype: QType,
    /// Client id to impersonate, when known.
    pub client_id: Option<String>,
    /// Source IP used for view selection when `client_id` is absent.
    pub source_ip: Option<String>,
    /// DNS protocol (`udp53`, `tcp53`, `dot`, `doh`, `doq`).
    pub protocol: String,
}

/// Filter attribution in a test-query result.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TestQueryFilter {
    /// Matching rule text.
    pub rule_text: String,
    /// Source list id, when any.
    pub list_id: Option<String>,
    /// Block mode.
    pub block_mode: String,
}

/// One synthesized answer record.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnswerRecord {
    /// Owner name.
    pub name: String,
    /// Record type.
    pub qtype: QType,
    /// TTL in seconds.
    pub ttl: u32,
    /// Presentation-format record data.
    pub data: String,
}

/// Synthesized answer of a dry-run query.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SynthesizedAnswer {
    /// Response code.
    pub rcode: String,
    /// Answer records.
    pub records: Vec<AnswerRecord>,
}

/// Result of `test_query`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TestQueryResult {
    /// Selected policy view id.
    pub view_id: String,
    /// Selected policy profile id.
    pub profile_id: String,
    /// View-selection result.
    pub selection: Selection,
    /// Filtering verdict.
    pub verdict: String,
    /// Filter attribution, when a rule matched.
    pub filter: Option<TestQueryFilter>,
    /// Synthesized answer.
    pub answer: SynthesizedAnswer,
    /// DNSSEC status, when validated.
    pub dnssec: Option<String>,
    /// Timings.
    pub timings: DecisionTimings,
}

/// Validated time filters for `get_stats`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatsParams {
    /// RFC 3339 lower bound, inclusive.
    pub from: Option<String>,
    /// RFC 3339 upper bound, exclusive.
    pub to: Option<String>,
    /// Restrict to one policy profile.
    pub profile_id: Option<String>,
}

/// Evaluated statistics period.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatsPeriod {
    /// Period start, RFC 3339.
    pub from: String,
    /// Period end, RFC 3339.
    pub to: String,
}

/// One entry of the top-blocked-domains list.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TopDomain {
    /// Canonical domain.
    pub domain: String,
    /// Number of blocked queries.
    pub count: u64,
}

/// One entry of the top-clients list.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TopClient {
    /// Client display name.
    pub client_name: String,
    /// Number of queries.
    pub queries: u64,
}

/// DNSSEC outcome counts.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnssecCounts {
    /// Securely validated answers.
    pub secure: u64,
    /// Insecure answers.
    pub insecure: u64,
    /// Bogus answers.
    pub bogus: u64,
}

/// Aggregate statistics (`get_stats`).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct StatsResult {
    /// Evaluated period.
    pub period: StatsPeriod,
    /// Total queries in the window.
    pub total_queries: u64,
    /// Blocked queries.
    pub blocked_queries: u64,
    /// Allowed queries.
    pub allowed_queries: u64,
    /// Blocked fraction in `0.0..=1.0`.
    pub blocked_ratio: f64,
    /// Top blocked domains, newest aggregates first.
    pub top_blocked_domains: Vec<TopDomain>,
    /// Top clients by query count.
    pub top_clients: Vec<TopClient>,
    /// Fraction of queries answered from cache.
    pub cache_hit_ratio: f64,
    /// DNSSEC outcome counts.
    pub dnssec: DnssecCounts,
}

/// Validated filters and pagination for `list_clients`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientListParams {
    /// Maximum number of clients to return (1..=500).
    pub limit: u32,
    /// Number of clients to skip.
    pub offset: u32,
    /// Case-insensitive substring of the display name.
    pub name_substr: Option<String>,
    /// Discovery source (`unifi`, `manual`).
    pub source: Option<String>,
}

/// VLAN attribution of a client.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct VlanInfo {
    /// VLAN id.
    pub id: u32,
    /// VLAN name.
    pub name: String,
}

/// One known client.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientInfo {
    /// Client id.
    pub id: String,
    /// Display name.
    pub display_name: String,
    /// Discovery source (`unifi`, `manual`).
    pub source: String,
    /// Known addresses.
    pub addresses: Vec<String>,
    /// Known MAC addresses.
    pub macs: Vec<String>,
    /// VLAN, when known.
    pub vlan: Option<VlanInfo>,
    /// Local domain, when known.
    pub local_domain: Option<String>,
}

/// A page of clients.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientListResult {
    /// The clients.
    pub clients: Vec<ClientInfo>,
    /// Whether more clients exist after this page.
    pub has_more: bool,
    /// Offset to request next, when `has_more`.
    pub next_offset: Option<u32>,
}

/// Validated selection and pagination for `list_mcp_rules`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListRulesParams {
    /// `rules`, `temporary_allows` or `pauses`.
    pub kind: String,
    /// Filter set to inspect; the backend resolves the default when `None`.
    pub filter_set_id: Option<String>,
    /// Maximum number of rows to return (1..=500).
    pub limit: u32,
    /// Number of rows to skip.
    pub offset: u32,
}

/// One active MCP-created block rule.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct McpRuleInfo {
    /// Rule id.
    pub id: String,
    /// Canonical domain.
    pub domain: String,
    /// Whether subdomains are covered.
    pub include_subdomains: bool,
    /// Canonical rule text.
    pub rule_text: String,
    /// RFC 3339 creation timestamp.
    pub created_at: String,
    /// RFC 3339 expiry timestamp.
    pub expires_at: String,
    /// Filter set the rule belongs to.
    pub filter_set_id: String,
}

/// One active temporary allow.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TempAllowInfo {
    /// Canonical domain.
    pub domain: String,
    /// Whether subdomains are covered.
    pub include_subdomains: bool,
    /// RFC 3339 creation timestamp.
    pub created_at: String,
    /// RFC 3339 expiry timestamp.
    pub expires_at: String,
    /// Filter set the allow belongs to.
    pub filter_set_id: String,
}

/// One active filter-set pause.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PauseInfo {
    /// Paused filter set.
    pub filter_set_id: String,
    /// RFC 3339 timestamp when filtering resumes.
    pub paused_until: String,
}

/// A page of MCP-managed entries; only the vector selected by `kind` is used.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListRulesResult {
    /// Filter set that was inspected (resolved by the backend).
    pub filter_set_id: String,
    /// `rules`, `temporary_allows` or `pauses`.
    pub kind: String,
    /// Active MCP-created block rules.
    pub rules: Vec<McpRuleInfo>,
    /// Active temporary allows.
    pub temporary_allows: Vec<TempAllowInfo>,
    /// Active pauses.
    pub pauses: Vec<PauseInfo>,
    /// Whether more entries exist after this page.
    pub has_more: bool,
    /// Offset to request next, when `has_more`.
    pub next_offset: Option<u32>,
}

/// Input for `allow_temporarily`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TempAllowParams {
    /// Canonical domain.
    pub domain: String,
    /// Whether subdomains are covered.
    pub include_subdomains: bool,
    /// Mandatory fixed-set duration.
    pub duration: PauseDuration,
    /// Filter set that receives the allow; the backend resolves the default.
    pub filter_set_id: Option<String>,
    /// Assistant-supplied reason, sanitized before audit.
    pub reason: String,
}

/// Result of `allow_temporarily`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TempAllowResult {
    /// RFC 3339 creation timestamp.
    pub created_at: String,
    /// RFC 3339 expiry timestamp.
    pub expires_at: String,
    /// Filter set that received the allow.
    pub filter_set_id: String,
}

/// Input for `add_rule`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AddRuleParams {
    /// Canonical domain.
    pub domain: String,
    /// Whether subdomains are covered.
    pub include_subdomains: bool,
    /// Filter set that receives the rule; the backend resolves the default.
    pub filter_set_id: Option<String>,
    /// Server-assigned lifetime in seconds (`max_block_rule_lifetime`).
    pub lifetime_seconds: u64,
}

/// Result of `add_rule`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AddRuleResult {
    /// Server-assigned rule id.
    pub rule_id: String,
    /// Generated rule text.
    pub rule_text: String,
    /// Filter set that received the rule.
    pub filter_set_id: String,
    /// Server-set RFC 3339 creation timestamp.
    pub created_at: String,
    /// Server-set RFC 3339 expiry timestamp.
    pub expires_at: String,
    /// Configuration version produced by the mutation, when any.
    pub config_version: Option<u64>,
}

/// Input for `remove_rule`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoveRuleParams {
    /// Canonical domain of the MCP-created rule.
    pub domain: String,
    /// Filter set that owns the rule; the backend resolves the default.
    pub filter_set_id: Option<String>,
}

/// Result of `remove_rule`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoveRuleResult {
    /// Whether a rule was removed.
    pub removed: bool,
    /// Filter set that was inspected (resolved by the backend).
    pub filter_set_id: String,
    /// Configuration version produced by the mutation, when any.
    pub config_version: Option<u64>,
}

/// Input for `pause_filter_set`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PauseParams {
    /// Filter set to pause; the backend resolves the default.
    pub filter_set_id: Option<String>,
    /// Mandatory fixed-set duration.
    pub duration: PauseDuration,
}

/// Result of `pause_filter_set`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PauseResult {
    /// Filter set that was paused (resolved by the backend).
    pub filter_set_id: String,
    /// RFC 3339 timestamp when filtering resumes.
    pub paused_until: String,
}

/// Result of `resume_filter_set`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResumeResult {
    /// Filter set that was resumed (resolved by the backend).
    pub filter_set_id: String,
    /// Whether the set is now running.
    pub resumed: bool,
    /// Expiry of the pause that was cleared, when one was active.
    pub was_paused_until: Option<String>,
}

/// Outcome recorded on an [`AuditEntry`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuditResult {
    /// The write succeeded.
    #[default]
    #[serde(rename = "success")]
    Success,
    /// The write was rejected or failed.
    #[serde(rename = "error")]
    Error,
}

/// One audit entry written by a write tool.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEntry {
    /// Action label, for example `mcp.add_rule`.
    pub action: String,
    /// Token id that performed the action.
    pub actor_id: String,
    /// Sanitized pre-state, when the tool has one.
    pub before: Option<Value>,
    /// Sanitized post-state.
    pub after: Value,
    /// Whether the write succeeded.
    pub result: AuditResult,
    /// Stable error code when `result` is [`AuditResult::Error`].
    pub error_code: Option<String>,
}
