//! Boundary DTOs for [`McpBackend`](crate::backend::McpBackend).
//!
//! Every type here is owned by this crate so that `control-api` can implement
//! the backend without `dnscraft-mcp` depending on it. Ids are `String`
//! values and domains are `String` in the canonical form described by
//! `SPEC-mcp.md`; no DNScraft module type crosses the boundary.
//!
//! These are the shapes the tools emit; most string fields are sanitized by
//! `sanitize::SafeText` before they reach tool output.

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

/// Filters for `search_query_log`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueryLogSearch {
    /// Maximum number of entries to return.
    pub limit: u32,
    /// Number of entries to skip.
    pub offset: u32,
    /// Restrict to a canonical domain, when set.
    pub domain: Option<String>,
    /// Restrict to a client id, when set.
    pub client_id: Option<String>,
}

/// One query-log row.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueryLogEntry {
    /// Canonical query id.
    pub id: String,
    /// RFC 3339 timestamp.
    pub timestamp: String,
    /// Client id.
    pub client_id: String,
    /// Client display name.
    pub client_name: String,
    /// Queried domain.
    pub domain: String,
    /// Query type.
    pub qtype: QType,
    /// Filtering verdict.
    pub verdict: String,
}

/// A page of query-log rows.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueryLogResult {
    /// The rows.
    pub entries: Vec<QueryLogEntry>,
    /// Whether more rows exist after this page.
    pub has_more: bool,
    /// Offset to request next, when `has_more`.
    pub next_offset: Option<u32>,
}

/// Detail for one query.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueryDetail {
    /// Canonical query id.
    pub id: String,
    /// RFC 3339 timestamp.
    pub timestamp: String,
    /// Client id.
    pub client_id: String,
    /// Client display name.
    pub client_name: String,
    /// Queried domain.
    pub domain: String,
    /// Query type.
    pub qtype: QType,
    /// Filtering verdict.
    pub verdict: String,
    /// Rule that produced the verdict, when any.
    pub rule: Option<String>,
}

/// Result of `explain_block`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExplainBlockResult {
    /// Canonical domain.
    pub domain: String,
    /// Whether the domain is currently blocked.
    pub blocked: bool,
    /// Matching rule text, when blocked.
    pub rule: Option<String>,
    /// Source list id, when known.
    pub list_id: Option<String>,
}

/// Input for `test_query`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TestQueryParams {
    /// Canonical domain.
    pub domain: String,
    /// Query type.
    pub qtype: QType,
    /// Filter profile to evaluate, when not the default.
    pub profile_id: Option<String>,
}

/// Result of `test_query`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TestQueryResult {
    /// Filtering verdict.
    pub verdict: String,
    /// Rule that produced the verdict, when any.
    pub rule: Option<String>,
}

/// Time filters for `get_stats`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatsParams {
    /// RFC 3339 lower bound, inclusive.
    pub since: Option<String>,
    /// RFC 3339 upper bound, exclusive.
    pub until: Option<String>,
}

/// Aggregate statistics.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatsResult {
    /// Total queries in the window.
    pub total_queries: u64,
    /// Blocked queries.
    pub blocked: u64,
    /// Allowed queries.
    pub allowed: u64,
}

/// Pagination for `list_clients`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientListParams {
    /// Maximum number of clients to return.
    pub limit: u32,
    /// Number of clients to skip.
    pub offset: u32,
}

/// One known client.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientInfo {
    /// Client id.
    pub id: String,
    /// Display name.
    pub display_name: String,
    /// Last seen as an RFC 3339 timestamp, when known.
    pub last_seen: Option<String>,
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

/// Selection for `list_mcp_rules`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListRulesParams {
    /// `rules`, `allows` or `pauses`.
    pub kind: String,
    /// Filter set to inspect, when required by `kind`.
    pub filter_set_id: Option<String>,
    /// Maximum number of rows to return.
    pub limit: u32,
    /// Number of rows to skip.
    pub offset: u32,
}

/// One MCP-managed rule, temporary allow or pause.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleInfo {
    /// Canonical domain, when applicable.
    pub domain: String,
    /// Whether subdomains are covered.
    pub include_subdomains: bool,
    /// RFC 3339 creation timestamp.
    pub created_at: String,
    /// RFC 3339 expiry timestamp, when applicable.
    pub expires_at: Option<String>,
    /// Filter set the entry belongs to, when applicable.
    pub filter_set_id: Option<String>,
}

/// A page of MCP-managed entries.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListRulesResult {
    /// The entries.
    pub rules: Vec<RuleInfo>,
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
    /// Assistant-supplied reason, sanitized before audit.
    pub reason: String,
}

/// Result of `allow_temporarily`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TempAllowResult {
    /// Canonical domain.
    pub domain: String,
    /// RFC 3339 expiry timestamp.
    pub expires_at: String,
}

/// Input for `add_rule`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AddRuleParams {
    /// Canonical domain.
    pub domain: String,
    /// Whether subdomains are covered.
    pub include_subdomains: bool,
    /// Filter set that receives the rule.
    pub filter_set_id: String,
}

/// Result of `add_rule`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AddRuleResult {
    /// Server-assigned rule id.
    pub rule_id: String,
    /// Server-set RFC 3339 expiry timestamp.
    pub expires_at: String,
    /// Configuration version produced by the mutation.
    pub config_version: u64,
}

/// Input for `remove_rule`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoveRuleParams {
    /// Rule id to remove.
    pub rule_id: String,
    /// Filter set that owns the rule.
    pub filter_set_id: String,
}

/// Result of `remove_rule`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoveRuleResult {
    /// Whether a rule was removed.
    pub removed: bool,
    /// Configuration version produced by the mutation.
    pub config_version: u64,
}

/// Result of `pause_filter_set`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PauseResult {
    /// Filter set that was paused.
    pub filter_set_id: String,
    /// RFC 3339 expiry timestamp.
    pub expires_at: String,
}

/// Result of `resume_filter_set`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResumeResult {
    /// Filter set that was resumed.
    pub filter_set_id: String,
    /// Whether the set is now running.
    pub resumed: bool,
}

/// One audit entry written by a write tool.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct AuditEntry {
    /// Action label, for example `mcp.add_rule`.
    pub action: String,
    /// Token id that performed the action.
    pub actor_id: String,
    /// Sanitized post-state.
    pub after: Value,
}
