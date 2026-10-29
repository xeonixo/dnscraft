//! Server handler and tool catalog.
//!
//! Each implemented tool lives in a submodule and is registered on
//! [`McpServer`] by the `#[tool_router]` macro. The per-request factory clones
//! the shared handle.
//!
//! Listing and dispatch are overridden here because the catalog is
//! gate-aware: `write_tools_enabled = false` hides the six write tools and a
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
///
/// Crate-private on purpose: `dnscraft_mcp::service` is the only supported
/// mounting path, so a caller cannot expose the tools by constructing a raw
/// server that bypasses [`crate::transport::McpTransport`]'s authentication.
#[derive(Clone)]
pub(crate) struct McpServer {
    pub(crate) backend: std::sync::Arc<dyn McpBackend>,
    pub(crate) config: McpConfig,
    /// Built once per server handle. `Err` means the configured list is
    /// malformed; write tools fail closed with that config error.
    pub(crate) protected: Result<ProtectedDomains, McpError>,
}

impl McpServer {
    /// A server handle over `backend` and `config`.
    pub(crate) fn new(backend: std::sync::Arc<dyn McpBackend>, config: McpConfig) -> Self {
        let protected = ProtectedDomains::new(config.protected_domains.iter().cloned());
        Self {
            backend,
            config,
            protected,
        }
    }

    /// All 14 tools: the macro-registered `get_status`, the seven static read
    /// tools and the six write tools.
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

/// Parse and validate one tool's raw JSON input without performing I/O.
///
/// This is the fuzzing entry point (M26). `tool` is one of the 14 catalog
/// names and `json` is the raw `arguments` object. It runs the same
/// `serde_json` decode with `deny_unknown_fields` and the same per-tool value
/// checks as dispatch. Backend, scope, write-gate and protected-domain checks
/// are not input parsing and are not covered here; config-dependent duration
/// maxima likewise stay in the handlers.
///
/// `get_status` takes no arguments, so any JSON object is accepted.
///
/// # Errors
///
/// Returns [`McpError::ToolNotFound`] for a name outside the catalog and
/// [`McpError::InvalidInput`] for malformed JSON, a non-object document or
/// arguments the tool's parser rejects. The detail is collapsed to a stable
/// reason because this entry point has no tool-result envelope.
#[doc(hidden)]
pub fn parse_mcp_tool_input(tool: &str, json: &[u8]) -> Result<(), McpError> {
    let value: Value =
        serde_json::from_slice(json).map_err(|_| invalid_arguments("malformed JSON"))?;
    let Value::Object(arguments) = value else {
        return Err(invalid_arguments("arguments must be a JSON object"));
    };
    let valid = match tool {
        "get_status" => true,
        name if read::is_read_tool(name) => read::validate_arguments(name, Some(arguments)),
        name if write::is_write_tool(name) => write::validate_arguments(name, Some(arguments)),
        _ => {
            return Err(McpError::ToolNotFound {
                tool: tool.to_owned(),
            });
        }
    };
    if valid {
        Ok(())
    } else {
        Err(invalid_arguments("arguments do not match the input schema"))
    }
}

fn invalid_arguments(reason: &'static str) -> McpError {
    McpError::InvalidInput {
        reason: reason.to_owned(),
    }
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

/// Reject a tool call that carries no validated [`TokenInfo`].
///
/// `transport` always inserts the token after authentication. This guard is
/// defence in depth so a read tool cannot run if a server were ever mounted
/// without that wrapper, mirroring the check in `write::call`.
pub(crate) fn require_token(token: Option<&TokenInfo>) -> Result<(), CallToolResult> {
    match token {
        Some(_) => Ok(()),
        None => Err(tool_error("control_api.auth.unauthenticated", json!({}))),
    }
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
        let token_id = token_from(&context).map(|token| token.token_id.clone());
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
        // Telemetry counter `mcp.tool_calls{tool_name, token_id, result}`. It is
        // a structured tracing event (no metrics exporter exists yet). Unknown
        // names collapse to one label so a client cannot grow the label set.
        let tool_name = if self.get_tool(name).is_some() {
            name
        } else {
            "unknown"
        };
        tracing::info!(
            target: "dnscraft_mcp::telemetry",
            counter = "mcp.tool_calls",
            tool_name,
            token_id = token_id.as_deref().unwrap_or(""),
            result = if result.is_error == Some(true) { "error" } else { "success" },
            "mcp tool call"
        );
        Ok(result.into())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_valid_input_for_every_tool() {
        let cases = [
            ("search_query_log", r#"{"domain":"example.com","limit":10}"#),
            (
                "get_query",
                r#"{"id":"123e4567-e89b-12d3-a456-426614174000"}"#,
            ),
            ("explain_block", r#"{"domain":"example.com","qtype":"A"}"#),
            (
                "test_query",
                r#"{"domain":"example.net","source_ip":"192.0.2.1"}"#,
            ),
            (
                "get_stats",
                r#"{"from":"2026-01-01T00:00:00Z","to":"2026-01-02T00:00:00Z"}"#,
            ),
            ("list_clients", r#"{"limit":10,"source":"unifi"}"#),
            ("list_mcp_rules", r#"{"kind":"pauses","limit":10}"#),
            ("get_status", "{}"),
            (
                "allow_temporarily",
                r#"{"domain":"example.com","duration":"PT15M"}"#,
            ),
            ("add_rule", r#"{"domain":"ads.example"}"#),
            ("remove_rule", r#"{"domain":"example.com"}"#),
            ("pause_filter_set", r#"{"duration":"PT1H"}"#),
            ("resume_filter_set", r#"{"filter_set_id":"default"}"#),
        ];
        for (tool, json) in cases {
            assert!(
                parse_mcp_tool_input(tool, json.as_bytes()).is_ok(),
                "{tool}: {json}"
            );
        }
    }

    #[test]
    fn rejects_malformed_unknown_and_hostile_input() {
        for json in [
            r#"{"domain":"#,
            "[1,2,3]",
            r#"{"domain":"example.com","bogus":1}"#,
            r#"{"domain":"example.com$dnsrewrite=127.0.0.1"}"#,
            r#"{"domain":"||ads.example^"}"#,
            r#"{"domain":"*.example.com"}"#,
            r#"{"domain":""}"#,
            r#"{"id":"not-a-uuid"}"#,
            r#"{"limit":"fifty"}"#,
        ] {
            assert!(
                parse_mcp_tool_input("add_rule", json.as_bytes()).is_err(),
                "{json}"
            );
        }
        assert!(parse_mcp_tool_input("nope", b"{}").is_err());
    }

    #[test]
    fn read_dispatch_rejects_a_missing_token() {
        // `read::call` and `get_status` apply this guard before any work.
        let error = require_token(None).unwrap_err();
        assert_eq!(error.is_error, Some(true));
        assert_eq!(
            error.structured_content.unwrap()["error"]["code"],
            "control_api.auth.unauthenticated"
        );
        let token = crate::dto::TokenInfo {
            token_id: "tok-read".into(),
            scope: crate::dto::TokenScope::McpRead,
            actor_id: "actor".into(),
        };
        assert!(require_token(Some(&token)).is_ok());
    }
}
