//! Stateless MCP server for DNScraft.
//!
//! This crate is the protocol and tool layer for the Model Context Protocol
//! revision 2026-07-28 (Streamable HTTP, no sessions, no `initialize`
//! handshake). The control API owns the HTTP listener and mounts the service
//! returned by `service` under `/mcp/v1`.
//!
//! It depends on no other DNScraft crate. `control-api` implements
//! [`McpBackend`] and injects it at wiring time; every DTO that crosses that
//! boundary is defined here.
//!
//! See `SPEC-mcp.md` for the authoritative protocol, tool and security rules.

pub mod backend;
pub mod config;
pub mod dto;
pub mod error;
pub mod result;
pub mod sanitize;
pub mod tools;
pub mod transport;

mod auth;

use std::sync::Arc;

pub use backend::{BackendError, McpBackend};
pub use config::McpConfig;
pub use dto::{
    AddRuleParams, AddRuleResult, AnswerRecord, AuditEntry, ClientInfo, ClientListParams,
    ClientListResult, DecisionFilter, DecisionStep, DecisionTimings, DnssecCounts,
    ExplainBlockResult, ExplainReason, FilteringStatus, ListRulesParams, ListRulesResult,
    ListenerStatus, McpRuleInfo, NodeStatus, PauseDuration, PauseInfo, PauseResult, QType,
    QueryClient, QueryDetail, QueryLogEntry, QueryLogFilter, QueryLogResult, QueryLogSearch,
    QueryName, QueryTimings, RemoveRuleParams, RemoveRuleResult, ResolverStatus, ResumeResult,
    Selection, StatsParams, StatsPeriod, StatsResult, SynthesizedAnswer, TempAllowInfo,
    TempAllowParams, TempAllowResult, TestQueryFilter, TestQueryParams, TestQueryResult, TlsStatus,
    TokenInfo, TokenScope, TopClient, TopDomain, VlanInfo,
};
pub use error::McpError;
pub use result::{tool_error, tool_ok};
pub use sanitize::{
    CAP_CLIENT_NAME, CAP_DOMAIN, CAP_LIST_ID, CAP_REASON, CAP_RULE_TEXT, SafeText, sanitize,
};
pub use tools::McpServer;
pub use transport::McpTransport;

/// Build the stateless MCP service mounted by `control-api` under `/mcp/v1`.
///
/// The returned service is cloned per request; every instance shares `backend`
/// and `config`. It wraps rmcp's `StreamableHttpService` with the transport
/// conformance rules in [`transport`] (instead of returning rmcp's type
/// directly, as SPEC-mcp.md's sketch says).
pub fn service(backend: Arc<dyn McpBackend>, config: McpConfig) -> McpTransport {
    transport::build(backend, config)
}
