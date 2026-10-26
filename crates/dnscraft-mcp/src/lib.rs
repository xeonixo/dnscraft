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
