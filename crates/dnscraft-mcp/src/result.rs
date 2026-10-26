//! Tool-result constructors.
//!
//! Every tool returns structured JSON in a `text` content item. Failures use
//! the single tool-error shape from SPEC-mcp.md § Common patterns:
//! `isError: true`, a `text` item carrying only the stable code, and
//! `structuredContent.error.{code,params}`. These helpers always produce a
//! [`CallToolResult`], so a tool-level failure can never become an HTTP status
//! or a JSON-RPC error.

use rmcp::model::{CallToolResult, ContentBlock};
use serde_json::{Value, json};

/// A successful tool result carrying `value` as JSON in one `text` item.
pub fn tool_ok(value: Value) -> CallToolResult {
    CallToolResult::success(vec![ContentBlock::text(value.to_string())])
}

/// A tool-level failure with the single documented shape.
///
/// `params` must be a JSON object (`{}` when the error carries no context).
pub fn tool_error(code: &str, params: Value) -> CallToolResult {
    let mut result = CallToolResult::success(vec![ContentBlock::text(code)]);
    result.is_error = Some(true);
    result.structured_content = Some(json!({
        "error": { "code": code, "params": params }
    }));
    result
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::error::{McpError, sample_errors};

    fn text_of(result: &CallToolResult) -> &str {
        match result.content.first().unwrap() {
            ContentBlock::Text(text) => text.text.as_str(),
            other => panic!("expected a text content item, got {other:?}"),
        }
    }

    #[test]
    fn tool_ok_puts_the_json_in_one_text_item() {
        let value = json!({ "node_id": "node1", "uptime_seconds": 5 });
        let result = tool_ok(value.clone());
        assert_eq!(result.is_error, Some(false));
        assert_eq!(result.structured_content, None);
        assert_eq!(result.content.len(), 1);
        assert_eq!(
            serde_json::from_str::<Value>(text_of(&result)).unwrap(),
            value
        );
    }

    #[test]
    fn tool_error_shape_is_exact() {
        let result = tool_error("mcp.protected_domain", json!({ "domain": "example.net" }));
        assert_eq!(result.is_error, Some(true));
        assert_eq!(text_of(&result), "mcp.protected_domain");
        assert_eq!(
            result.structured_content,
            Some(json!({
                "error": {
                    "code": "mcp.protected_domain",
                    "params": { "domain": "example.net" }
                }
            }))
        );
    }

    #[test]
    fn every_mcp_error_maps_to_the_tool_error_shape() {
        for error in sample_errors() {
            let result = tool_error(error.code(), error.params().unwrap());
            assert_eq!(result.is_error, Some(true), "{}", error.code());
            assert_eq!(text_of(&result), error.code());
            let structured = result.structured_content.unwrap();
            assert_eq!(structured["error"]["code"], error.code());
        }
    }

    #[test]
    fn helpers_only_return_tool_results() {
        // Compile-time guarantee: both helpers return `CallToolResult`, which
        // the handler returns as a tool result, never as an error status.
        let ok: CallToolResult = tool_ok(json!({}));
        let err: CallToolResult = tool_error("mcp.invalid_input", json!({}));
        assert_eq!(ok.is_error, Some(false));
        assert_eq!(err.is_error, Some(true));
        let _ = McpError::WriteToolsDisabled;
    }
}
