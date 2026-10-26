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

use std::sync::Arc;

use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;
use rmcp::transport::streamable_http_server::{StreamableHttpServerConfig, StreamableHttpService};

pub use backend::{BackendError, McpBackend};
pub use config::McpConfig;
pub use dto::{
    AddRuleParams, AddRuleResult, AuditEntry, ClientInfo, ClientListParams, ClientListResult,
    ExplainBlockResult, FilteringStatus, ListRulesParams, ListRulesResult, ListenerStatus,
    NodeStatus, PauseDuration, PauseResult, QType, QueryDetail, QueryLogEntry, QueryLogResult,
    QueryLogSearch, RemoveRuleParams, RemoveRuleResult, ResolverStatus, ResumeResult, RuleInfo,
    StatsParams, StatsResult, TempAllowParams, TempAllowResult, TestQueryParams, TestQueryResult,
    TlsStatus, TokenInfo, TokenScope,
};
pub use error::McpError;
pub use result::{tool_error, tool_ok};
pub use sanitize::{
    CAP_CLIENT_NAME, CAP_DOMAIN, CAP_LIST_ID, CAP_REASON, CAP_RULE_TEXT, SafeText, sanitize,
};
pub use tools::McpServer;

/// Build the stateless MCP service mounted by `control-api` under `/mcp/v1`.
///
/// The returned service is cloned per request; every instance shares `backend`
/// and `config`. The factory itself cannot fail, so malformed per-request state
/// is impossible to introduce here.
pub fn service(
    backend: Arc<dyn McpBackend>,
    config: McpConfig,
) -> StreamableHttpService<McpServer, LocalSessionManager> {
    let server_config = StreamableHttpServerConfig::default()
        .with_legacy_session_mode(config.legacy_session_mode)
        .with_json_response(true);
    StreamableHttpService::new(
        move || Ok(McpServer::new(backend.clone(), config.clone())),
        Arc::new(LocalSessionManager::default()),
        server_config,
    )
}
