//! Server handler and tool catalog.
//!
//! Each implemented tool lives in a submodule and is registered on
//! [`McpServer`] by the `#[tool_router]` macro. The per-request factory clones
//! the shared handle.
//!
//! Listing and dispatch are overridden here because the catalog is
//! gate-aware: `write_tools_enabled = false` hides the five write tools and a
//! dispatched write tool is denied before it can touch the backend. Tools not
//! implemented yet are listed with an empty object schema and answer with
//! `control_api.internal`/`not_implemented` until their task lands.

pub mod read;

use std::borrow::Cow;

use rmcp::model::{
    CacheScope, CallToolRequestParams, CallToolResponse, CallToolResult, JsonObject,
    ListToolsResult, PaginatedRequestParams, ProtocolVersion, ResultType, Tool,
};
use rmcp::service::RequestContext;
use rmcp::{ErrorData, RoleServer, ServerHandler, tool_handler};
use serde_json::json;

use crate::backend::McpBackend;
use crate::config::McpConfig;
use crate::dto::{TokenInfo, TokenScope};
use crate::error::McpError;
use crate::result::tool_error;

/// Read tools that are not implemented yet (all except `get_status`).
const READ_TOOLS: [(&str, &str); 7] = [
    ("search_query_log", "Search the DNS query log with filters."),
    ("get_query", "Get one query log entry by id."),
    (
        "explain_block",
        "Explain why a domain is or is not blocked.",
    ),
    (
        "test_query",
        "Evaluate a DNS query without logging it or caching the result.",
    ),
    ("get_stats", "Get aggregate query statistics."),
    ("list_clients", "List known DNS clients."),
    ("list_mcp_rules", "List MCP-created block rules."),
];

/// The five write tools (not implemented yet).
const WRITE_TOOLS: [(&str, &str); 5] = [
    (
        "allow_temporarily",
        "Temporarily allow a domain that is currently blocked.",
    ),
    ("add_rule", "Add a structured block rule."),
    ("remove_rule", "Remove an MCP-created block rule."),
    (
        "pause_filter_set",
        "Pause a filter set for a fixed duration.",
    ),
    ("resume_filter_set", "Resume a paused filter set."),
];

/// Shared state cloned into every per-request server instance.
#[derive(Clone)]
pub struct McpServer {
    pub(crate) backend: std::sync::Arc<dyn McpBackend>,
    pub(crate) config: McpConfig,
}

impl McpServer {
    /// A server handle over `backend` and `config`.
    pub fn new(backend: std::sync::Arc<dyn McpBackend>, config: McpConfig) -> Self {
        Self { backend, config }
    }

    /// All 13 tools: the macro-registered `get_status` plus placeholders.
    fn catalog(&self) -> Vec<Tool> {
        let mut tools = Self::tool_router().list_all();
        let placeholders = READ_TOOLS
            .iter()
            .chain(WRITE_TOOLS.iter())
            .map(|(name, description)| Tool::new(*name, *description, empty_schema()));
        tools.extend(placeholders);
        tools.sort_by(|a, b| a.name.cmp(&b.name));
        tools
    }

    fn listed_tools(&self) -> Vec<Tool> {
        self.catalog()
            .into_iter()
            .filter(|tool| self.config.write_tools_enabled || !is_write(&tool.name))
            .collect()
    }

    fn call_write_tool(&self, name: &str, context: &RequestContext<RoleServer>) -> CallToolResult {
        let Some(token) = token_from(context) else {
            return tool_error("control_api.auth.unauthenticated", json!({}));
        };
        // Scope is checked before the gate so a read token always sees the
        // scope error, even while write tools are globally disabled.
        if token.scope != TokenScope::McpWrite {
            return tool_error("control_api.auth.insufficient_scope", json!({}));
        }
        if !self.config.write_tools_enabled {
            return tool_error(McpError::WriteToolsDisabled.code(), json!({}));
        }
        tool_error(
            "control_api.internal",
            json!({ "reason": "not_implemented", "tool": name }),
        )
    }
}

fn empty_schema() -> JsonObject {
    let mut schema = JsonObject::new();
    schema.insert("type".into(), json!("object"));
    schema
}

fn is_write(name: &str) -> bool {
    WRITE_TOOLS.iter().any(|(tool, _)| *tool == name)
}

fn is_read(name: &str) -> bool {
    name == "get_status" || READ_TOOLS.iter().any(|(tool, _)| *tool == name)
}

/// The token `transport` validated and attached to the request.
fn token_from(context: &RequestContext<RoleServer>) -> Option<&TokenInfo> {
    context
        .extensions
        .get::<http::request::Parts>()?
        .extensions
        .get::<TokenInfo>()
}

#[tool_handler(name = "dnscraft-mcp")]
impl ServerHandler for McpServer {
    fn supported_protocol_versions(&self) -> Cow<'static, [ProtocolVersion]> {
        if self.config.legacy_session_mode {
            Cow::Borrowed(ProtocolVersion::KNOWN_VERSIONS)
        } else {
            Cow::Borrowed(&[ProtocolVersion::V_2026_07_28])
        }
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, ErrorData> {
        let supports_cache = context
            .protocol_version()
            .is_some_and(|version| version >= ProtocolVersion::V_2026_07_28);
        Ok(ListToolsResult {
            result_type: Some(ResultType::COMPLETE),
            tools: self.listed_tools(),
            meta: None,
            next_cursor: None,
            ttl_ms: supports_cache.then_some(0),
            // The list depends on server config and the caller's endpoint, not
            // on public data, so never let a shared cache serve it.
            cache_scope: supports_cache.then_some(CacheScope::Private),
        })
    }

    fn get_tool(&self, name: &str) -> Option<Tool> {
        self.catalog().into_iter().find(|tool| tool.name == name)
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, ErrorData> {
        let name = request.name.as_ref();
        let result = if name == "get_status" {
            self.get_status(context).await
        } else if is_write(name) {
            self.call_write_tool(name, &context)
        } else if is_read(name) {
            tool_error(
                "control_api.internal",
                json!({ "reason": "not_implemented", "tool": name }),
            )
        } else {
            tool_error(
                McpError::ToolNotFound { tool: name.into() }.code(),
                json!({ "tool": name }),
            )
        };
        Ok(result.into())
    }
}
