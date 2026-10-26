//! Read-only tools.
//!
//! Every input is validated here before it reaches the backend, so a schema or
//! value failure is a tool result (`mcp.invalid_input`), never a JSON-RPC
//! error. Every string from the backend is untrusted and leaves through
//! [`SafeText`].
//!
//! The tools are dispatched manually (rather than with rmcp's typed
//! `Parameters` extractor) because that extractor reports deserialization
//! failures as JSON-RPC `-32602`, which SPEC-mcp.md forbids for tool input
//! errors.

use std::net::IpAddr;

use rmcp::RoleServer;
use rmcp::model::{CallToolResult, JsonObject, Tool, ToolAnnotations};
use rmcp::service::RequestContext;
use rmcp::{tool, tool_router};
use serde::Deserialize;
use serde_json::{Value, json};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use super::{McpServer, backend_call, invalid_input, parse_arguments, schema};
use crate::dto::{
    ClientInfo, ClientListParams, DecisionFilter, DecisionStep, DecisionTimings, DnssecCounts,
    ExplainBlockResult, ExplainReason, ListRulesParams, ListRulesResult, McpRuleInfo, PauseInfo,
    QType, QueryClient, QueryDetail, QueryLogEntry, QueryLogFilter, QueryLogResult, QueryLogSearch,
    QueryName, Selection, StatsParams, StatsPeriod, StatsResult, TempAllowInfo, TestQueryFilter,
    TestQueryParams, TestQueryResult, TopClient, TopDomain,
};
use crate::error::McpError;
use crate::result::{tool_error, tool_ok};
use crate::sanitize::{CAP_CLIENT_NAME, CAP_DOMAIN, CAP_LIST_ID, CAP_RULE_TEXT, SafeText};

/// Maximum entries returned in each `get_stats` top list.
pub const TOP_LIST_LIMIT: usize = 10;

const SEARCH_QUERY_LOG_DESCRIPTION: &str = "Search the DNS query log with filters. Returns recent queries with client names, queried domains, filtering verdicts, and timestamps. Use this to answer 'what queries did device X make?' or 'when was Y blocked?'";
const GET_QUERY_DESCRIPTION: &str = "Retrieve a single query-log entry by ID with full decision record (why blocked, which rule, DNSSEC status, timings). Use this after searching to get details.";
const EXPLAIN_BLOCK_DESCRIPTION: &str = "Explain why a domain is currently blocked for a given profile. Returns the matching filter rule, its source list, and priority. Does not perform a live DNS query.";
const TEST_QUERY_DESCRIPTION: &str = "Dry-run a DNS query through the policy engine as if it came from a specific client. Returns what the answer would be and why, without polluting the query log or cache. Use this to verify 'what would device X get for domain Y?'";
const GET_STATS_DESCRIPTION: &str = "Retrieve DNS statistics: total queries, blocked ratio, top domains, top clients, cache hit ratio, DNSSEC outcomes. Specify a time range or use defaults (last 24 hours).";
const LIST_CLIENTS_DESCRIPTION: &str = "List known clients (devices) with their names, IPs, VLANs, and source (UniFi, manual). Use this to find a client_id for other queries.";
const LIST_MCP_RULES_DESCRIPTION: &str = "List MCP-managed block rules, active temporary allows, or active pauses for a filter set. Shows domain, subdomain flag, creation and expiry times. Use this to see what assistants changed and when it expires.";

const READ_TOOL_NAMES: [&str; 7] = [
    "search_query_log",
    "get_query",
    "explain_block",
    "test_query",
    "get_stats",
    "list_clients",
    "list_mcp_rules",
];

/// Whether `name` is one of the read tools defined in this module.
pub fn is_read_tool(name: &str) -> bool {
    READ_TOOL_NAMES.contains(&name)
}

/// Static tool definitions (`tools/list`), one per read tool.
pub fn tool_definitions() -> Vec<Tool> {
    vec![
        Tool::new(
            "search_query_log",
            SEARCH_QUERY_LOG_DESCRIPTION,
            schema(json!({
                "type": "object",
                "properties": {
                    "from": { "type": "string", "format": "date-time", "description": "Start time (RFC 3339 UTC)" },
                    "to": { "type": "string", "format": "date-time", "description": "End time (RFC 3339 UTC)" },
                    "client_id": { "type": "string", "description": "Exact client ID" },
                    "client_name_substr": { "type": "string", "description": "Substring match in client display name (case-insensitive)" },
                    "domain": { "type": "string", "description": "Exact normalized domain name (no trailing dot)" },
                    "domain_substr": { "type": "string", "description": "Substring match in domain (case-insensitive)" },
                    "protocol": { "type": "string", "enum": ["udp53", "tcp53", "dot", "doh", "doq"], "description": "DNS protocol" },
                    "view_id": { "type": "string", "description": "Policy view ID" },
                    "profile_id": { "type": "string", "description": "Policy profile ID" },
                    "status": { "type": "string", "enum": ["allowed", "blocked", "dnssec_bogus", "servfail"], "description": "Query outcome" },
                    "only_blocked": { "type": "boolean", "description": "Return only blocked queries" },
                    "order_by": { "type": "string", "enum": ["time", "client", "domain", "rcode"], "default": "time" },
                    "order": { "type": "string", "enum": ["asc", "desc"], "default": "desc" },
                    "limit": { "type": "integer", "minimum": 1, "maximum": 500, "default": 50 },
                    "offset": { "type": "integer", "minimum": 0, "default": 0 }
                }
            })),
        )
        .with_annotations(
            ToolAnnotations::new()
                .read_only(true)
                .idempotent(true)
                .open_world(false),
        ),
        Tool::new(
            "get_query",
            GET_QUERY_DESCRIPTION,
            schema(json!({
                "type": "object",
                "properties": {
                    "id": { "type": "string", "format": "uuid", "description": "Query log entry ID" }
                },
                "required": ["id"]
            })),
        )
        .with_annotations(ToolAnnotations::new().read_only(true).idempotent(true)),
        Tool::new(
            "explain_block",
            EXPLAIN_BLOCK_DESCRIPTION,
            schema(json!({
                "type": "object",
                "properties": {
                    "domain": { "type": "string", "description": "Domain name (normalized, no trailing dot)" },
                    "profile_id": { "type": "string", "description": "Policy profile ID (default profile if omitted)" },
                    "qtype": { "type": "string", "enum": ["A", "AAAA", "CNAME", "MX", "TXT", "SRV"], "default": "A" }
                },
                "required": ["domain"]
            })),
        )
        .with_annotations(ToolAnnotations::new().read_only(true).idempotent(true)),
        Tool::new(
            "test_query",
            TEST_QUERY_DESCRIPTION,
            schema(json!({
                "type": "object",
                "properties": {
                    "domain": { "type": "string", "description": "Domain name to query" },
                    "qtype": { "type": "string", "enum": ["A", "AAAA", "CNAME", "MX", "TXT", "SRV", "HTTPS"], "default": "A" },
                    "client_id": { "type": "string", "description": "Client ID (optional; uses source_ip if omitted)" },
                    "source_ip": { "type": "string", "format": "ipv4 or ipv6", "description": "Source IP (for view selection if no client_id)" },
                    "protocol": { "type": "string", "enum": ["udp53", "tcp53", "dot", "doh", "doq"], "default": "udp53" }
                },
                "required": ["domain"]
            })),
        )
        .with_annotations(
            ToolAnnotations::new()
                .read_only(true)
                .idempotent(false)
                .open_world(false),
        ),
        Tool::new(
            "get_stats",
            GET_STATS_DESCRIPTION,
            schema(json!({
                "type": "object",
                "properties": {
                    "from": { "type": "string", "format": "date-time", "description": "Start time (default: 24h ago)" },
                    "to": { "type": "string", "format": "date-time", "description": "End time (default: now)" },
                    "profile_id": { "type": "string", "description": "Filter by profile (optional)" }
                }
            })),
        )
        .with_annotations(ToolAnnotations::new().read_only(true).idempotent(true)),
        Tool::new(
            "list_clients",
            LIST_CLIENTS_DESCRIPTION,
            schema(json!({
                "type": "object",
                "properties": {
                    "name_substr": { "type": "string", "description": "Filter by display name substring (case-insensitive)" },
                    "source": { "type": "string", "enum": ["unifi", "manual"], "description": "Filter by source" },
                    "limit": { "type": "integer", "minimum": 1, "maximum": 500, "default": 100 },
                    "offset": { "type": "integer", "minimum": 0, "default": 0 }
                }
            })),
        )
        .with_annotations(ToolAnnotations::new().read_only(true).idempotent(true)),
        Tool::new(
            "list_mcp_rules",
            LIST_MCP_RULES_DESCRIPTION,
            schema(json!({
                "type": "object",
                "properties": {
                    "filter_set_id": { "type": "string", "description": "Filter set ID (default set if omitted)" },
                    "kind": { "type": "string", "enum": ["rules", "temporary_allows", "pauses"], "default": "rules", "description": "Which MCP-managed entries to list" },
                    "limit": { "type": "integer", "minimum": 1, "maximum": 500, "default": 100 },
                    "offset": { "type": "integer", "minimum": 0, "default": 0 }
                }
            })),
        )
        .with_annotations(
            ToolAnnotations::new()
                .read_only(true)
                .idempotent(true)
                .open_world(false),
        ),
    ]
}

/// Dispatch one implemented read tool.
pub(crate) async fn call(
    name: &str,
    arguments: Option<JsonObject>,
    server: &McpServer,
    context: RequestContext<RoleServer>,
) -> CallToolResult {
    match name {
        "search_query_log" => search_query_log(arguments, server, context).await,
        "get_query" => get_query(arguments, server, context).await,
        "explain_block" => explain_block(arguments, server, context).await,
        "test_query" => test_query(arguments, server, context).await,
        "get_stats" => get_stats(arguments, server, context).await,
        "list_clients" => list_clients(arguments, server, context).await,
        "list_mcp_rules" => list_mcp_rules(arguments, server, context).await,
        other => tool_error(
            McpError::ToolNotFound { tool: other.into() }.code(),
            json!({ "tool": other }),
        ),
    }
}

#[tool_router(vis = "pub(crate)")]
impl McpServer {
    /// Current node status.
    #[tool(
        description = "Get node status: resolver health, listener bindings, TLS certificate status, filter list update times, uptime.",
        annotations(
            title = "Get node status",
            read_only_hint = true,
            idempotent_hint = true
        )
    )]
    pub async fn get_status(&self, context: RequestContext<RoleServer>) -> CallToolResult {
        let result = match backend_call("get_status", &context, self.backend.get_status()).await {
            Ok(status) => status,
            Err(error) => return error,
        };
        tool_ok(status_json(&result))
    }
}

async fn search_query_log(
    arguments: Option<JsonObject>,
    server: &McpServer,
    context: RequestContext<RoleServer>,
) -> CallToolResult {
    let params = match parse_arguments::<SearchArgs>(arguments).and_then(SearchArgs::into_params) {
        Ok(params) => params,
        Err(error) => return error,
    };
    match backend_call(
        "search_query_log",
        &context,
        server.backend.search_query_log(params),
    )
    .await
    {
        Ok(result) => tool_ok(query_log_json(&result)),
        Err(error) => error,
    }
}

async fn get_query(
    arguments: Option<JsonObject>,
    server: &McpServer,
    context: RequestContext<RoleServer>,
) -> CallToolResult {
    let id = match parse_arguments::<GetQueryArgs>(arguments).and_then(GetQueryArgs::into_id) {
        Ok(id) => id,
        Err(error) => return error,
    };
    match backend_call("get_query", &context, server.backend.get_query(&id)).await {
        Ok(result) => tool_ok(query_detail_json(&result)),
        Err(error) => error,
    }
}

async fn explain_block(
    arguments: Option<JsonObject>,
    server: &McpServer,
    context: RequestContext<RoleServer>,
) -> CallToolResult {
    let args = match parse_arguments::<ExplainArgs>(arguments).and_then(ExplainArgs::validate) {
        Ok(args) => args,
        Err(error) => return error,
    };
    match backend_call(
        "explain_block",
        &context,
        server
            .backend
            .explain_block(&args.domain, args.profile_id.as_deref(), args.qtype),
    )
    .await
    {
        Ok(result) => tool_ok(explain_json(&result)),
        Err(error) => error,
    }
}

async fn test_query(
    arguments: Option<JsonObject>,
    server: &McpServer,
    context: RequestContext<RoleServer>,
) -> CallToolResult {
    let params = match parse_arguments::<TestQueryArgs>(arguments).and_then(TestQueryArgs::validate)
    {
        Ok(params) => params,
        Err(error) => return error,
    };
    match backend_call("test_query", &context, server.backend.test_query(params)).await {
        Ok(result) => tool_ok(test_query_json(&result)),
        Err(error) => error,
    }
}

async fn get_stats(
    arguments: Option<JsonObject>,
    server: &McpServer,
    context: RequestContext<RoleServer>,
) -> CallToolResult {
    let params = match parse_arguments::<StatsArgs>(arguments).and_then(StatsArgs::into_params) {
        Ok(params) => params,
        Err(error) => return error,
    };
    match backend_call("get_stats", &context, server.backend.get_stats(params)).await {
        Ok(result) => tool_ok(stats_json(&result)),
        Err(error) => error,
    }
}

async fn list_clients(
    arguments: Option<JsonObject>,
    server: &McpServer,
    context: RequestContext<RoleServer>,
) -> CallToolResult {
    let params = match parse_arguments::<ClientsArgs>(arguments).and_then(ClientsArgs::into_params)
    {
        Ok(params) => params,
        Err(error) => return error,
    };
    match backend_call(
        "list_clients",
        &context,
        server.backend.list_clients(params),
    )
    .await
    {
        Ok(result) => tool_ok(clients_json(&result)),
        Err(error) => error,
    }
}

async fn list_mcp_rules(
    arguments: Option<JsonObject>,
    server: &McpServer,
    context: RequestContext<RoleServer>,
) -> CallToolResult {
    let params = match parse_arguments::<RulesArgs>(arguments).and_then(RulesArgs::into_params) {
        Ok(params) => params,
        Err(error) => return error,
    };
    let kind = params.kind.clone();
    match backend_call(
        "list_mcp_rules",
        &context,
        server.backend.list_mcp_rules(params),
    )
    .await
    {
        Ok(result) => tool_ok(rules_json(&result, &kind)),
        Err(error) => error,
    }
}

fn page_limit(value: Option<u32>, default: u32) -> Result<u32, CallToolResult> {
    match value.unwrap_or(default) {
        limit @ 1..=500 => Ok(limit),
        _ => Err(invalid_input("limit must be an integer in 1..=500")),
    }
}

fn check_time_range(from: Option<&str>, to: Option<&str>) -> Result<(), CallToolResult> {
    let from = from.map(parse_time).transpose()?;
    let to = to.map(parse_time).transpose()?;
    if let (Some(from), Some(to)) = (from, to)
        && from > to
    {
        return Err(invalid_input("from must not be after to"));
    }
    Ok(())
}

fn parse_time(value: &str) -> Result<OffsetDateTime, CallToolResult> {
    OffsetDateTime::parse(value, &Rfc3339).map_err(|_| invalid_input("timestamps must be RFC 3339"))
}

/// Validate and canonicalise a DNS name (trimmed of one trailing dot,
/// lowercased, ASCII labels only).
fn canonical_domain(input: &str) -> Result<String, CallToolResult> {
    let name = input.strip_suffix('.').unwrap_or(input);
    let valid = !name.is_empty()
        && name.len() <= 253
        && name.is_ascii()
        && name.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        });
    if !valid {
        return Err(invalid_input("invalid domain"));
    }
    Ok(name.to_ascii_lowercase())
}

fn canonical_uuid(input: &str) -> Result<String, CallToolResult> {
    let bytes = input.as_bytes();
    let valid = bytes.len() == 36
        && bytes.iter().enumerate().all(|(index, byte)| match index {
            8 | 13 | 18 | 23 => *byte == b'-',
            _ => byte.is_ascii_hexdigit(),
        });
    if !valid {
        return Err(invalid_input("id must be a UUID"));
    }
    Ok(input.to_ascii_lowercase())
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SearchArgs {
    from: Option<String>,
    to: Option<String>,
    client_id: Option<String>,
    client_name_substr: Option<String>,
    domain: Option<String>,
    domain_substr: Option<String>,
    protocol: Option<Protocol>,
    view_id: Option<String>,
    profile_id: Option<String>,
    status: Option<Status>,
    only_blocked: Option<bool>,
    order_by: Option<OrderBy>,
    order: Option<Order>,
    limit: Option<u32>,
    offset: Option<u32>,
}

impl SearchArgs {
    fn into_params(self) -> Result<QueryLogSearch, CallToolResult> {
        check_time_range(self.from.as_deref(), self.to.as_deref())?;
        let domain = match self.domain {
            Some(domain) => Some(canonical_domain(&domain)?),
            None => None,
        };
        Ok(QueryLogSearch {
            limit: page_limit(self.limit, 50)?,
            offset: self.offset.unwrap_or(0),
            from: self.from,
            to: self.to,
            client_id: self.client_id,
            client_name_substr: self.client_name_substr,
            domain,
            domain_substr: self.domain_substr,
            protocol: self.protocol.map(Protocol::as_str).map(str::to_owned),
            view_id: self.view_id,
            profile_id: self.profile_id,
            status: self.status.map(Status::as_str).map(str::to_owned),
            only_blocked: self.only_blocked.unwrap_or(false),
            order_by: self.order_by.unwrap_or_default().as_str().to_owned(),
            order: self.order.unwrap_or_default().as_str().to_owned(),
        })
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct GetQueryArgs {
    id: String,
}

impl GetQueryArgs {
    fn into_id(self) -> Result<String, CallToolResult> {
        canonical_uuid(&self.id)
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExplainArgs {
    domain: String,
    profile_id: Option<String>,
    qtype: Option<QType>,
}

struct ExplainParams {
    domain: String,
    profile_id: Option<String>,
    qtype: QType,
}

impl ExplainArgs {
    fn validate(self) -> Result<ExplainParams, CallToolResult> {
        let qtype = self.qtype.unwrap_or_default();
        if qtype == QType::Https {
            return Err(invalid_input(
                "qtype HTTPS is not supported by explain_block",
            ));
        }
        Ok(ExplainParams {
            domain: canonical_domain(&self.domain)?,
            profile_id: self.profile_id,
            qtype,
        })
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TestQueryArgs {
    domain: String,
    qtype: Option<QType>,
    client_id: Option<String>,
    source_ip: Option<String>,
    protocol: Option<Protocol>,
}

impl TestQueryArgs {
    fn validate(self) -> Result<TestQueryParams, CallToolResult> {
        let domain = canonical_domain(&self.domain)?;
        let source_ip = match self.source_ip {
            Some(ref value) => Some(
                value
                    .parse::<IpAddr>()
                    .map_err(|_| invalid_input("source_ip must be an IPv4 or IPv6 address"))?
                    .to_string(),
            ),
            None => None,
        };
        Ok(TestQueryParams {
            domain,
            qtype: self.qtype.unwrap_or_default(),
            client_id: self.client_id,
            source_ip,
            protocol: self.protocol.unwrap_or_default().as_str().to_owned(),
        })
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct StatsArgs {
    from: Option<String>,
    to: Option<String>,
    profile_id: Option<String>,
}

impl StatsArgs {
    fn into_params(self) -> Result<StatsParams, CallToolResult> {
        check_time_range(self.from.as_deref(), self.to.as_deref())?;
        Ok(StatsParams {
            from: self.from,
            to: self.to,
            profile_id: self.profile_id,
        })
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ClientsArgs {
    name_substr: Option<String>,
    source: Option<Source>,
    limit: Option<u32>,
    offset: Option<u32>,
}

impl ClientsArgs {
    fn into_params(self) -> Result<ClientListParams, CallToolResult> {
        Ok(ClientListParams {
            limit: page_limit(self.limit, 100)?,
            offset: self.offset.unwrap_or(0),
            name_substr: self.name_substr,
            source: self.source.map(Source::as_str).map(str::to_owned),
        })
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RulesArgs {
    filter_set_id: Option<String>,
    kind: Option<Kind>,
    limit: Option<u32>,
    offset: Option<u32>,
}

impl RulesArgs {
    fn into_params(self) -> Result<ListRulesParams, CallToolResult> {
        Ok(ListRulesParams {
            kind: self.kind.unwrap_or_default().as_str().to_owned(),
            filter_set_id: self.filter_set_id,
            limit: page_limit(self.limit, 100)?,
            offset: self.offset.unwrap_or(0),
        })
    }
}

#[derive(Debug, Clone, Copy, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
enum Protocol {
    #[default]
    Udp53,
    Tcp53,
    Dot,
    Doh,
    Doq,
}

impl Protocol {
    fn as_str(self) -> &'static str {
        match self {
            Self::Udp53 => "udp53",
            Self::Tcp53 => "tcp53",
            Self::Dot => "dot",
            Self::Doh => "doh",
            Self::Doq => "doq",
        }
    }
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Status {
    Allowed,
    Blocked,
    DnssecBogus,
    Servfail,
}

impl Status {
    fn as_str(self) -> &'static str {
        match self {
            Self::Allowed => "allowed",
            Self::Blocked => "blocked",
            Self::DnssecBogus => "dnssec_bogus",
            Self::Servfail => "servfail",
        }
    }
}

#[derive(Debug, Clone, Copy, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
enum OrderBy {
    #[default]
    Time,
    Client,
    Domain,
    Rcode,
}

impl OrderBy {
    fn as_str(self) -> &'static str {
        match self {
            Self::Time => "time",
            Self::Client => "client",
            Self::Domain => "domain",
            Self::Rcode => "rcode",
        }
    }
}

#[derive(Debug, Clone, Copy, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
enum Order {
    Asc,
    #[default]
    Desc,
}

impl Order {
    fn as_str(self) -> &'static str {
        match self {
            Self::Asc => "asc",
            Self::Desc => "desc",
        }
    }
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "lowercase")]
enum Source {
    Unifi,
    Manual,
}

impl Source {
    fn as_str(self) -> &'static str {
        match self {
            Self::Unifi => "unifi",
            Self::Manual => "manual",
        }
    }
}

#[derive(Debug, Clone, Copy, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Kind {
    #[default]
    Rules,
    TemporaryAllows,
    Pauses,
}

impl Kind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Rules => "rules",
            Self::TemporaryAllows => "temporary_allows",
            Self::Pauses => "pauses",
        }
    }
}

fn status_json(status: &crate::dto::NodeStatus) -> Value {
    json!({
        "node_id": SafeText::new(&status.node_id, CAP_CLIENT_NAME),
        "version": SafeText::new(&status.version, CAP_CLIENT_NAME),
        "uptime_seconds": status.uptime_seconds,
        "resolver": {
            "primed": status.resolver.primed,
            "cache_size": status.resolver.cache_size,
        },
        "listeners": status.listeners.iter().map(|listener| json!({
            "id": SafeText::new(&listener.id, CAP_LIST_ID),
            "protocol": SafeText::new(&listener.protocol, CAP_CLIENT_NAME),
            "bind": SafeText::new(&listener.bind, CAP_DOMAIN),
            "status": SafeText::new(&listener.status, CAP_CLIENT_NAME),
        })).collect::<Vec<_>>(),
        "tls": {
            "mode": SafeText::new(&status.tls.mode, CAP_CLIENT_NAME),
            "cert_expiry": SafeText::new(&status.tls.cert_expiry, CAP_RULE_TEXT),
            "fingerprint": SafeText::new(&status.tls.fingerprint, CAP_RULE_TEXT),
        },
        "filtering": {
            "lists_loaded": status.filtering.lists_loaded,
            "rules_active": status.filtering.rules_active,
            "last_update": SafeText::new(&status.filtering.last_update, CAP_RULE_TEXT),
        },
    })
}

fn query_log_json(result: &QueryLogResult) -> Value {
    json!({
        "queries": result.queries.iter().map(query_entry_json).collect::<Vec<_>>(),
        "has_more": result.has_more,
        "next_offset": result.next_offset,
    })
}

fn query_entry_json(entry: &QueryLogEntry) -> Value {
    json!({
        "id": SafeText::new(&entry.id, CAP_LIST_ID),
        "time": SafeText::new(&entry.time, CAP_CLIENT_NAME),
        "client": query_client_json(&entry.client),
        "query": query_name_json(&entry.query),
        "profile_id": SafeText::new(&entry.profile_id, CAP_LIST_ID),
        "answer_source": SafeText::new(&entry.answer_source, CAP_CLIENT_NAME),
        "filter": entry.filter.as_ref().map(query_filter_json),
        "rcode": SafeText::new(&entry.rcode, CAP_CLIENT_NAME),
        "timings": {
            "total_us": entry.timings.total_us,
        },
    })
}

fn query_client_json(client: &QueryClient) -> Value {
    json!({
        "id": SafeText::new(&client.id, CAP_LIST_ID),
        "display_name": SafeText::new(&client.display_name, CAP_CLIENT_NAME),
        "source": SafeText::new(&client.source, CAP_CLIENT_NAME),
    })
}

fn query_name_json(name: &QueryName) -> Value {
    json!({
        "name": SafeText::new(&name.name, CAP_DOMAIN),
        "type": name.qtype.as_str(),
    })
}

fn query_filter_json(filter: &QueryLogFilter) -> Value {
    json!({
        "reason": SafeText::new(&filter.reason, CAP_CLIENT_NAME),
        "rule_text": filter.rule_text.as_deref().map(|text| SafeText::new(text, CAP_RULE_TEXT)),
        "list_id": filter.list_id.as_deref().map(|text| SafeText::new(text, CAP_LIST_ID)),
    })
}

fn query_detail_json(detail: &QueryDetail) -> Value {
    json!({
        "id": SafeText::new(&detail.id, CAP_LIST_ID),
        "view_id": SafeText::new(&detail.view_id, CAP_LIST_ID),
        "profile_id": SafeText::new(&detail.profile_id, CAP_LIST_ID),
        "selection": selection_json(&detail.selection),
        "steps": detail.steps.iter().map(step_json).collect::<Vec<_>>(),
        "filter": detail.filter.as_ref().map(decision_filter_json),
        "dnssec": detail.dnssec.as_deref().map(|text| SafeText::new(text, CAP_CLIENT_NAME)),
        "answer_source": SafeText::new(&detail.answer_source, CAP_CLIENT_NAME),
        "rcode": SafeText::new(&detail.rcode, CAP_CLIENT_NAME),
        "timings": timings_json(&detail.timings),
    })
}

fn selection_json(selection: &Selection) -> Value {
    json!({
        "cause": SafeText::new(&selection.cause, CAP_CLIENT_NAME),
        "prefix": selection.prefix.as_deref().map(|text| SafeText::new(text, CAP_DOMAIN)),
        "client_id": selection.client_id.as_deref().map(|text| SafeText::new(text, CAP_LIST_ID)),
    })
}

fn step_json(step: &DecisionStep) -> Value {
    json!({
        "stage": SafeText::new(&step.stage, CAP_CLIENT_NAME),
        "verdict": SafeText::new(&step.verdict, CAP_CLIENT_NAME),
        "rule": step.rule.as_deref().map(|text| SafeText::new(text, CAP_RULE_TEXT)),
        "list_id": step.list_id.as_deref().map(|text| SafeText::new(text, CAP_LIST_ID)),
    })
}

fn decision_filter_json(filter: &DecisionFilter) -> Value {
    json!({
        "reason": SafeText::new(&filter.reason, CAP_CLIENT_NAME),
        "block_mode": SafeText::new(&filter.block_mode, CAP_CLIENT_NAME),
        "rule_text": filter.rule_text.as_deref().map(|text| SafeText::new(text, CAP_RULE_TEXT)),
        "list_id": filter.list_id.as_deref().map(|text| SafeText::new(text, CAP_LIST_ID)),
        "important": filter.important,
    })
}

fn timings_json(timings: &DecisionTimings) -> Value {
    json!({
        "select_us": timings.select_us,
        "filter_us": timings.filter_us,
        "total_us": timings.total_us,
    })
}

fn explain_json(result: &ExplainBlockResult) -> Value {
    json!({
        "domain": SafeText::new(&result.domain, CAP_DOMAIN),
        "profile_id": SafeText::new(&result.profile_id, CAP_LIST_ID),
        "filter_set_id": SafeText::new(&result.filter_set_id, CAP_LIST_ID),
        "verdict": SafeText::new(&result.verdict, CAP_CLIENT_NAME),
        "reason": result.reason.as_ref().map(explain_reason_json),
    })
}

fn explain_reason_json(reason: &ExplainReason) -> Value {
    json!({
        "rule_text": SafeText::new(&reason.rule_text, CAP_RULE_TEXT),
        "source": SafeText::new(&reason.source, CAP_RULE_TEXT),
        "important": reason.important,
        "block_mode": SafeText::new(&reason.block_mode, CAP_CLIENT_NAME),
    })
}

fn test_query_json(result: &TestQueryResult) -> Value {
    json!({
        "view_id": SafeText::new(&result.view_id, CAP_LIST_ID),
        "profile_id": SafeText::new(&result.profile_id, CAP_LIST_ID),
        "selection": selection_json(&result.selection),
        "verdict": SafeText::new(&result.verdict, CAP_CLIENT_NAME),
        "filter": result.filter.as_ref().map(test_filter_json),
        "answer": {
            "rcode": SafeText::new(&result.answer.rcode, CAP_CLIENT_NAME),
            "records": result.answer.records.iter().map(|record| json!({
                "name": SafeText::new(&record.name, CAP_DOMAIN),
                "type": record.qtype.as_str(),
                "ttl": record.ttl,
                "data": SafeText::new(&record.data, CAP_RULE_TEXT),
            })).collect::<Vec<_>>(),
        },
        "dnssec": result.dnssec.as_deref().map(|text| SafeText::new(text, CAP_CLIENT_NAME)),
        "timings": timings_json(&result.timings),
    })
}

fn test_filter_json(filter: &TestQueryFilter) -> Value {
    json!({
        "rule_text": SafeText::new(&filter.rule_text, CAP_RULE_TEXT),
        "list_id": filter.list_id.as_deref().map(|text| SafeText::new(text, CAP_LIST_ID)),
        "block_mode": SafeText::new(&filter.block_mode, CAP_CLIENT_NAME),
    })
}

fn stats_json(result: &StatsResult) -> Value {
    json!({
        "period": stats_period_json(&result.period),
        "total_queries": result.total_queries,
        "blocked_queries": result.blocked_queries,
        "allowed_queries": result.allowed_queries,
        "blocked_ratio": result.blocked_ratio,
        "top_blocked_domains": result.top_blocked_domains.iter().take(TOP_LIST_LIMIT).map(top_domain_json).collect::<Vec<_>>(),
        "top_clients": result.top_clients.iter().take(TOP_LIST_LIMIT).map(top_client_json).collect::<Vec<_>>(),
        "cache_hit_ratio": result.cache_hit_ratio,
        "dnssec": dnssec_json(&result.dnssec),
    })
}

fn stats_period_json(period: &StatsPeriod) -> Value {
    json!({
        "from": SafeText::new(&period.from, CAP_CLIENT_NAME),
        "to": SafeText::new(&period.to, CAP_CLIENT_NAME),
    })
}

fn top_domain_json(domain: &TopDomain) -> Value {
    json!({
        "domain": SafeText::new(&domain.domain, CAP_DOMAIN),
        "count": domain.count,
    })
}

fn top_client_json(client: &TopClient) -> Value {
    json!({
        "client_name": SafeText::new(&client.client_name, CAP_CLIENT_NAME),
        "queries": client.queries,
    })
}

fn dnssec_json(dnssec: &DnssecCounts) -> Value {
    json!({
        "secure": dnssec.secure,
        "insecure": dnssec.insecure,
        "bogus": dnssec.bogus,
    })
}

fn clients_json(result: &crate::dto::ClientListResult) -> Value {
    json!({
        "clients": result.clients.iter().map(client_json).collect::<Vec<_>>(),
        "has_more": result.has_more,
        "next_offset": result.next_offset,
    })
}

fn client_json(client: &ClientInfo) -> Value {
    json!({
        "id": SafeText::new(&client.id, CAP_LIST_ID),
        "display_name": SafeText::new(&client.display_name, CAP_CLIENT_NAME),
        "source": SafeText::new(&client.source, CAP_CLIENT_NAME),
        "addresses": client.addresses.iter().map(|address| SafeText::new(address, CAP_CLIENT_NAME)).collect::<Vec<_>>(),
        "macs": client.macs.iter().map(|mac| SafeText::new(mac, CAP_CLIENT_NAME)).collect::<Vec<_>>(),
        "vlan": client.vlan.as_ref().map(|vlan| json!({
            "id": vlan.id,
            "name": SafeText::new(&vlan.name, CAP_CLIENT_NAME),
        })),
        "local_domain": client.local_domain.as_deref().map(|text| SafeText::new(text, CAP_DOMAIN)),
    })
}

fn rules_json(result: &ListRulesResult, kind: &str) -> Value {
    let filter_set_id = SafeText::new(&result.filter_set_id, CAP_LIST_ID);
    match kind {
        "temporary_allows" => json!({
            "filter_set_id": filter_set_id,
            "kind": kind,
            "temporary_allows": result.temporary_allows.iter().map(temp_allow_json).collect::<Vec<_>>(),
            "has_more": result.has_more,
            "next_offset": result.next_offset,
        }),
        "pauses" => json!({
            "filter_set_id": filter_set_id,
            "kind": kind,
            "pauses": result.pauses.iter().map(pause_json).collect::<Vec<_>>(),
            "has_more": result.has_more,
            "next_offset": result.next_offset,
        }),
        _ => json!({
            "filter_set_id": filter_set_id,
            "kind": kind,
            "rules": result.rules.iter().map(rule_json).collect::<Vec<_>>(),
            "has_more": result.has_more,
            "next_offset": result.next_offset,
        }),
    }
}

fn rule_json(rule: &McpRuleInfo) -> Value {
    json!({
        "id": SafeText::new(&rule.id, CAP_LIST_ID),
        "domain": SafeText::new(&rule.domain, CAP_DOMAIN),
        "include_subdomains": rule.include_subdomains,
        "rule_text": SafeText::new(&rule.rule_text, CAP_RULE_TEXT),
        "created_at": SafeText::new(&rule.created_at, CAP_CLIENT_NAME),
        "expires_at": SafeText::new(&rule.expires_at, CAP_CLIENT_NAME),
        "filter_set_id": SafeText::new(&rule.filter_set_id, CAP_LIST_ID),
    })
}

fn temp_allow_json(allow: &TempAllowInfo) -> Value {
    json!({
        "domain": SafeText::new(&allow.domain, CAP_DOMAIN),
        "include_subdomains": allow.include_subdomains,
        "created_at": SafeText::new(&allow.created_at, CAP_CLIENT_NAME),
        "expires_at": SafeText::new(&allow.expires_at, CAP_CLIENT_NAME),
        "filter_set_id": SafeText::new(&allow.filter_set_id, CAP_LIST_ID),
    })
}

fn pause_json(pause: &PauseInfo) -> Value {
    json!({
        "filter_set_id": SafeText::new(&pause.filter_set_id, CAP_LIST_ID),
        "paused_until": SafeText::new(&pause.paused_until, CAP_CLIENT_NAME),
    })
}
