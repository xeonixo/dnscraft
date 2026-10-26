//! Server handler and tool catalog.
//!
//! Each implemented tool lives in a submodule and is registered on
//! [`McpServer`] by the `#[tool_router]` macro. The per-request factory clones
//! the shared handle.
//!
//! Listing and dispatch are overridden here because the catalog is
//! gate-aware: `write_tools_enabled = false` hides the five write tools and a
//! dispatched write tool is denied before it can touch the backend. All tools
//! are defined statically and dispatched manually so input failures stay tool
//! results rather than JSON-RPC errors.

pub mod read;
pub mod write;

use std::borrow::Cow;
use std::future::Future;

use rmcp::model::{
    CacheScope, CallToolRequestParams, CallToolResponse, CallToolResult, JsonObject,
    ListToolsResult, PaginatedRequestParams, ProtocolVersion, ResultType, Tool,
};
use rmcp::service::RequestContext;
use rmcp::{ErrorData, RoleServer, ServerHandler, tool_handler};
use serde::de::DeserializeOwned;
use serde_json::{Value, json};

use crate::backend::{BackendError, McpBackend};
use crate::config::McpConfig;
use crate::dto::TokenInfo;
use crate::error::McpError;
use crate::protected::ProtectedDomains;
use crate::result::tool_error;

/// Shared state cloned into every per-request server instance.
#[derive(Clone)]
pub struct McpServer {
    pub(crate) backend: std::sync::Arc<dyn McpBackend>,
    pub(crate) config: McpConfig,
    /// Built once per server handle. `Err` means the configured list is
    /// malformed; write tools fail closed with that config error.
    pub(crate) protected: Result<ProtectedDomains, McpError>,
}

impl McpServer {
    /// A server handle over `backend` and `config`.
    pub fn new(backend: std::sync::Arc<dyn McpBackend>, config: McpConfig) -> Self {
        let protected = ProtectedDomains::new(config.protected_domains.iter().cloned());
        Self {
            backend,
            config,
            protected,
        }
    }

    /// All 13 tools: the macro-registered `get_status`, the seven static read
    /// tools and the five write tools.
    fn catalog(&self) -> Vec<Tool> {
        let mut tools = Self::tool_router().list_all();
        tools.extend(read::tool_definitions());
        tools.extend(write::tool_definitions());
        tools.sort_by(|a, b| a.name.cmp(&b.name));
        tools
    }

    fn listed_tools(&self) -> Vec<Tool> {
        self.catalog()
            .into_iter()
            .filter(|tool| self.config.write_tools_enabled || !write::is_write_tool(&tool.name))
            .collect()
    }
}

/// Parse tool arguments, mapping a deserialization failure to a tool result.
pub(crate) fn parse_arguments<T: DeserializeOwned>(
    arguments: Option<JsonObject>,
) -> Result<T, CallToolResult> {
    serde_json::from_value(Value::Object(arguments.unwrap_or_default()))
        .map_err(|_| invalid_input("arguments do not match the input schema"))
}

/// A `mcp.invalid_input` tool result with a fixed reason.
pub(crate) fn invalid_input(reason: &'static str) -> CallToolResult {
    tool_error(
        McpError::InvalidInput {
            reason: reason.into(),
        }
        .code(),
        json!({ "reason": reason }),
    )
}

/// Convert a JSON object literal into a tool input schema.
pub(crate) fn schema(value: Value) -> JsonObject {
    match value {
        Value::Object(map) => map,
        _ => JsonObject::new(),
    }
}

/// Await a backend call, mapping cancellation and errors to the tool shape.
pub(crate) async fn backend_call<T, F>(
    tool: &'static str,
    context: &RequestContext<RoleServer>,
    future: F,
) -> Result<T, CallToolResult>
where
    F: Future<Output = Result<T, BackendError>>,
{
    let outcome = tokio::select! {
        result = future => Some(result),
        _ = context.ct.cancelled() => None,
    };
    let Some(result) = outcome else {
        return Err(tool_error(
            "control_api.internal",
            json!({ "reason": "cancelled" }),
        ));
    };
    result.map_err(|error| {
        tracing::warn!(tool, code = error.code(), "{} backend error", tool);
        tool_error(error.code(), error.params().unwrap_or_else(|| json!({})))
    })
}

/// The token `transport` validated and attached to the request.
pub(crate) fn token_from(context: &RequestContext<RoleServer>) -> Option<&TokenInfo> {
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
        } else if write::is_write_tool(name) {
            write::call(name, request.arguments, self, context).await
        } else if read::is_read_tool(name) {
            read::call(name, request.arguments, self, context).await
        } else {
            tool_error(
                McpError::ToolNotFound { tool: name.into() }.code(),
                json!({ "tool": name }),
            )
        };
        Ok(result.into())
    }
}
