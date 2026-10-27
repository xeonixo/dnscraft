//! The backend interface implemented by `control-api`.
//!
//! The trait inverts the dependency: `control-api` depends on this crate and
//! injects an [`McpBackend`]; no DNScraft module type appears here. Every call
//! is authorized and audited by the implementation (the same code paths as the
//! REST API), so the tool layer is only protocol, validation and shaping.
//!
//! [`BackendError::Internal`] carries a detail string for logs only; it is
//! never returned to a client. Implementations must not put tokens or other
//! secrets in any error variant.

use async_trait::async_trait;
use serde_json::Value;

use crate::dto::{
    AddRuleParams, AddRuleResult, AuditEntry, ClientListParams, ClientListResult,
    ExplainBlockResult, ListRulesParams, ListRulesResult, McpRuleInfo, NodeStatus, PauseParams,
    PauseResult, QType, QueryDetail, QueryLogResult, QueryLogSearch, RemoveRuleParams,
    RemoveRuleResult, ResumeResult, StatsParams, StatsResult, TempAllowParams, TempAllowResult,
    TestQueryParams, TestQueryResult, TokenInfo,
};

/// An error returned by an [`McpBackend`] implementation.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]

pub enum BackendError {
    /// Token is missing, malformed, unknown, revoked or expired.
    #[error("missing or invalid bearer token")]
    Unauthenticated,
    /// Token scope is valid for the API but not for MCP (`viewer`/`admin`).
    #[error("token scope is not valid for this endpoint")]
    InvalidScope,
    /// The addressed object does not exist.
    #[error("not found: {what}")]
    NotFound {
        /// What was looked up.
        what: String,
    },
    /// A module error with its own stable code (for example
    /// `policy.config.unknown_filter_set` or `filter_build.invalid_domain`).
    #[error("coded backend error: {code}")]
    Coded {
        /// Stable `area.reason` code from the owning module.
        code: String,
        /// Non-secret context for the tool-error `params` object.
        params: Option<Value>,
    },
    /// Unexpected backend failure. The message is for logs only.
    #[error("internal backend error")]
    Internal {
        /// Detail for logs; never sent to a client.
        message: String,
    },
}

impl BackendError {
    /// Stable code used in the control-api error envelope or tool result.
    pub fn code(&self) -> &str {
        match self {
            Self::Unauthenticated => "control_api.auth.unauthenticated",
            Self::InvalidScope => "control_api.auth.invalid_scope",
            Self::NotFound { .. } => "control_api.not_found",
            Self::Coded { code, .. } => code,
            Self::Internal { .. } => "control_api.internal",
        }
    }

    /// Non-secret context for the error's `params` object.
    pub fn params(&self) -> Option<Value> {
        match self {
            Self::NotFound { what } => Some(serde_json::json!({ "what": what })),
            Self::Coded { params, .. } => params.clone(),
            Self::Unauthenticated | Self::InvalidScope | Self::Internal { .. } => None,
        }
    }
}

/// Operations the MCP tools need from the control API.
#[async_trait]
pub trait McpBackend: Send + Sync {
    /// Validate an MCP bearer token and return its identity and scope.
    async fn validate_token(&self, token: &str) -> Result<TokenInfo, BackendError>;

    /// Search the query log.
    async fn search_query_log(
        &self,
        params: QueryLogSearch,
    ) -> Result<QueryLogResult, BackendError>;

    /// Fetch one query by canonical id.
    async fn get_query(&self, id: &str) -> Result<QueryDetail, BackendError>;

    /// Explain why a domain is or is not blocked.
    async fn explain_block(
        &self,
        domain: &str,
        profile_id: Option<&str>,
        qtype: QType,
    ) -> Result<ExplainBlockResult, BackendError>;

    /// Evaluate a query without writing the query log or the resolver cache.
    async fn test_query(&self, params: TestQueryParams) -> Result<TestQueryResult, BackendError>;

    /// Aggregate query statistics.
    async fn get_stats(&self, params: StatsParams) -> Result<StatsResult, BackendError>;

    /// List known clients.
    async fn list_clients(
        &self,
        params: ClientListParams,
    ) -> Result<ClientListResult, BackendError>;

    /// Current node status.
    async fn get_status(&self) -> Result<NodeStatus, BackendError>;

    /// List MCP-managed rules, temporary allows or pauses.
    async fn list_mcp_rules(
        &self,
        params: ListRulesParams,
    ) -> Result<ListRulesResult, BackendError>;

    /// Create a temporary allow with a mandatory fixed-set duration.
    async fn allow_temporarily(
        &self,
        params: TempAllowParams,
    ) -> Result<TempAllowResult, BackendError>;

    /// Create an MCP-managed block rule.
    async fn add_custom_rule(&self, params: AddRuleParams) -> Result<AddRuleResult, BackendError>;

    /// Look up one MCP-created rule by canonical domain and filter set.
    ///
    /// `remove_rule` needs the stored `include_subdomains` flag for the
    /// protected-domain check (SPEC-mcp.md § Protected domains).
    async fn find_mcp_rule(
        &self,
        domain: &str,
        filter_set_id: Option<&str>,
    ) -> Result<Option<McpRuleInfo>, BackendError>;

    /// Remove an MCP-created rule.
    async fn remove_custom_rule(
        &self,
        params: RemoveRuleParams,
    ) -> Result<RemoveRuleResult, BackendError>;

    /// Pause a filter set for a mandatory fixed-set duration.
    ///
    /// A filter set has at most one active pause; a newer pause replaces an
    /// older one and the returned `paused_until` is the new expiry.
    async fn pause_filter_set(&self, params: PauseParams) -> Result<PauseResult, BackendError>;

    /// Resume a paused filter set. Resuming a set that is not paused succeeds
    /// with `resumed: false`.
    async fn resume_filter_set(
        &self,
        filter_set_id: Option<&str>,
    ) -> Result<ResumeResult, BackendError>;

    /// Persist an audit entry for a completed write.
    async fn record_audit(&self, entry: AuditEntry) -> Result<(), BackendError>;
}
