//! Write tools.
//!
//! All five tools share one check order (gate, scope, schema, duration
//! maximum, protected domain, backend call, audit). Failures that know their
//! arguments are audited with `result: "error"` and the stable code; a failed
//! audit write is logged and never replaces the tool result.
//!
//! Strings from the assistant (`reason`) and from the backend are untrusted
//! and leave through [`SafeText`]. Tool descriptions are static.

use std::net::IpAddr;
use std::time::Duration;

use rmcp::RoleServer;
use rmcp::model::{CallToolResult, JsonObject, Tool, ToolAnnotations};
use rmcp::service::RequestContext;
use serde::Deserialize;
use serde_json::{Value, json};

use super::{McpServer, invalid_input, parse_arguments, schema, token_from};
use crate::dto::{
    AddRuleParams, AuditEntry, AuditResult, PauseDuration, RemoveRuleParams, TempAllowParams,
    TokenInfo, TokenScope,
};
use crate::error::McpError;
use crate::result::{tool_error, tool_ok};
use crate::sanitize::{
    CAP_CLIENT_NAME, CAP_DOMAIN, CAP_LIST_ID, CAP_REASON, CAP_RULE_TEXT, SafeText,
};

/// Static description for `allow_temporarily`.
const ALLOW_DESCRIPTION: &str = "Temporarily allow a domain that is currently blocked, for a specified duration. The allow expires automatically. Use this when a legitimate site is blocked by a list and needs immediate access. Requires mcp:write scope and write_tools_enabled. The client will ask you to confirm this action. This affects every client using this filter set.";

/// Static description for `add_rule`.
const ADD_RULE_DESCRIPTION: &str = "Add a custom block rule to a filter set. The rule is built from structured input; no raw AdGuard syntax is accepted via MCP. Requires mcp:write scope and write_tools_enabled. The client will ask you to confirm. This affects every client using this filter set.";

/// Static description for `remove_rule`.
const REMOVE_RULE_DESCRIPTION: &str = "Remove a custom block rule that was previously added via MCP. Only rules created via MCP can be removed; web UI rules and downloaded list rules cannot. Requires mcp:write scope.";

const PAUSE_SCOPE: &str = "Pause a filter set for a fixed duration.";
const RESUME_SCOPE: &str = "Resume a paused filter set.";

const WRITE_TOOL_NAMES: [&str; 5] = [
    "allow_temporarily",
    "add_rule",
    "remove_rule",
    "pause_filter_set",
    "resume_filter_set",
];

/// Whether `name` is one of the five write tools.
pub fn is_write_tool(name: &str) -> bool {
    WRITE_TOOL_NAMES.contains(&name)
}

/// Static tool definitions (`tools/list`) for the write tools.
pub fn tool_definitions() -> Vec<Tool> {
    vec![
        allow_definition(),
        add_rule_definition(),
        remove_rule_definition(),
        placeholder("pause_filter_set", PAUSE_SCOPE),
        placeholder("resume_filter_set", RESUME_SCOPE),
    ]
}

fn allow_definition() -> Tool {
    Tool::new(
        "allow_temporarily",
        ALLOW_DESCRIPTION,
        schema(json!({
            "type": "object",
            "properties": {
                "domain": {
                    "type": "string",
                    "description": "Domain name to allow (validated and canonicalised; no wildcards, IP addresses or single-label names)"
                },
                "include_subdomains": {
                    "type": "boolean",
                    "default": true,
                    "description": "Allow all subdomains"
                },
                "duration": {
                    "type": "string",
                    "enum": ["PT5M", "PT15M", "PT1H"],
                    "description": "ISO 8601 duration: 5 minutes, 15 minutes, or 1 hour"
                },
                "filter_set_id": {
                    "type": "string",
                    "description": "Filter set ID (default set if omitted)"
                },
                "reason": {
                    "type": "string",
                    "maxLength": 200,
                    "description": "Why this domain is being allowed (optional, for audit; sanitized before storage)"
                }
            },
            "required": ["domain", "duration"]
        })),
    )
    .with_annotations(ToolAnnotations::new().destructive(true).idempotent(false))
}

fn add_rule_definition() -> Tool {
    Tool::new(
        "add_rule",
        ADD_RULE_DESCRIPTION,
        schema(json!({
            "type": "object",
            "properties": {
                "domain": {
                    "type": "string",
                    "description": "Domain name to block (validated; no wildcards, no single-label names, no IP addresses)"
                },
                "include_subdomains": {
                    "type": "boolean",
                    "default": true,
                    "description": "Apply to all subdomains"
                },
                "filter_set_id": {
                    "type": "string",
                    "description": "Filter set ID (default set if omitted)"
                },
                "reason": {
                    "type": "string",
                    "maxLength": 200,
                    "description": "Why this rule is being added (optional, for audit; sanitized before storage)"
                }
            },
            "required": ["domain"]
        })),
    )
    .with_annotations(ToolAnnotations::new().destructive(true).idempotent(false))
}

fn remove_rule_definition() -> Tool {
    Tool::new(
        "remove_rule",
        REMOVE_RULE_DESCRIPTION,
        schema(json!({
            "type": "object",
            "properties": {
                "domain": {
                    "type": "string",
                    "description": "Domain of the MCP-created rule to remove (exact match)"
                },
                "filter_set_id": {
                    "type": "string",
                    "description": "Filter set ID (default set if omitted)"
                }
            },
            "required": ["domain"]
        })),
    )
    .with_annotations(ToolAnnotations::new().destructive(true).idempotent(true))
}

/// A not-yet-implemented write tool definition (until its task lands).
fn placeholder(name: &'static str, description: &'static str) -> Tool {
    let mut input_schema = JsonObject::new();
    input_schema.insert("type".into(), json!("object"));
    Tool::new(name, description, input_schema)
}

/// Dispatch one write tool after the gate and scope checks.
pub(crate) async fn call(
    name: &str,
    arguments: Option<JsonObject>,
    server: &McpServer,
    context: RequestContext<RoleServer>,
) -> CallToolResult {
    if !server.config.write_tools_enabled {
        return tool_error(McpError::WriteToolsDisabled.code(), json!({}));
    }
    let Some(token) = token_from(&context).cloned() else {
        return tool_error("control_api.auth.unauthenticated", json!({}));
    };
    if token.scope != TokenScope::McpWrite {
        return tool_error("control_api.auth.insufficient_scope", json!({}));
    }
    match name {
        "allow_temporarily" => allow_temporarily(arguments, server, &token).await,
        "add_rule" => add_rule(arguments, server, &token).await,
        "remove_rule" => remove_rule(arguments, server, &token).await,
        other => tool_error(
            "control_api.internal",
            json!({ "reason": "not_implemented", "tool": other }),
        ),
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AllowArgs {
    domain: String,
    include_subdomains: Option<bool>,
    duration: PauseDuration,
    filter_set_id: Option<String>,
    reason: Option<String>,
}

async fn allow_temporarily(
    arguments: Option<JsonObject>,
    server: &McpServer,
    token: &TokenInfo,
) -> CallToolResult {
    let args = match parse_arguments::<AllowArgs>(arguments) {
        Ok(args) => args,
        Err(error) => return error,
    };
    let domain = match validate_domain(&args.domain) {
        Ok(domain) => domain,
        Err(error) => return error,
    };
    let include_subdomains = args.include_subdomains.unwrap_or(true);
    let reason = sanitize_reason(args.reason.as_deref());
    let filter_set_id = args.filter_set_id.clone();

    if let Some(error) = duration_error(args.duration, server.config.max_temporary_allow_duration) {
        let after = allow_failure_after(
            &domain,
            include_subdomains,
            args.duration,
            filter_set_id.as_deref(),
            &reason,
        );
        record(
            server,
            token,
            "mcp.allow_temporarily",
            None,
            Some(after),
            AuditResult::Error,
            Some(error.code()),
        )
        .await;
        return tool_error(error.code(), error.params().unwrap_or_else(|| json!({})));
    }

    if let Err(error) = protected_violation(server, &domain, include_subdomains) {
        let after = allow_failure_after(
            &domain,
            include_subdomains,
            args.duration,
            filter_set_id.as_deref(),
            &reason,
        );
        record(
            server,
            token,
            "mcp.allow_temporarily",
            None,
            Some(after),
            AuditResult::Error,
            Some(error.code()),
        )
        .await;
        return tool_error(error.code(), error.params().unwrap_or_else(|| json!({})));
    }

    let params = TempAllowParams {
        domain: domain.clone(),
        include_subdomains,
        duration: args.duration,
        filter_set_id: filter_set_id.clone(),
        reason: reason.clone(),
    };
    match server.backend.allow_temporarily(params).await {
        Ok(result) => {
            let after = json!({
                "domain": SafeText::new(&domain, CAP_DOMAIN),
                "include_subdomains": include_subdomains,
                "created_at": SafeText::new(&result.created_at, CAP_CLIENT_NAME),
                "expires_at": SafeText::new(&result.expires_at, CAP_CLIENT_NAME),
                "filter_set_id": SafeText::new(&result.filter_set_id, CAP_LIST_ID),
                "reason": reason,
            });
            record(
                server,
                token,
                "mcp.allow_temporarily",
                None,
                Some(after),
                AuditResult::Success,
                None,
            )
            .await;
            tool_ok(json!({
                "domain": SafeText::new(&domain, CAP_DOMAIN),
                "include_subdomains": include_subdomains,
                "created_at": SafeText::new(&result.created_at, CAP_CLIENT_NAME),
                "expires_at": SafeText::new(&result.expires_at, CAP_CLIENT_NAME),
                "filter_set_id": SafeText::new(&result.filter_set_id, CAP_LIST_ID),
            }))
        }
        Err(error) => {
            let code = error.code().to_owned();
            let params = error.params().unwrap_or_else(|| json!({}));
            let after = allow_failure_after(
                &domain,
                include_subdomains,
                args.duration,
                filter_set_id.as_deref(),
                &reason,
            );
            record(
                server,
                token,
                "mcp.allow_temporarily",
                None,
                Some(after),
                AuditResult::Error,
                Some(&code),
            )
            .await;
            tool_error(&code, params)
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AddRuleArgs {
    domain: String,
    include_subdomains: Option<bool>,
    filter_set_id: Option<String>,
    reason: Option<String>,
}

async fn add_rule(
    arguments: Option<JsonObject>,
    server: &McpServer,
    token: &TokenInfo,
) -> CallToolResult {
    let args = match parse_arguments::<AddRuleArgs>(arguments) {
        Ok(args) => args,
        Err(error) => return error,
    };
    let domain = match validate_domain(&args.domain) {
        Ok(domain) => domain,
        Err(error) => return error,
    };
    let include_subdomains = args.include_subdomains.unwrap_or(true);
    let reason = sanitize_reason(args.reason.as_deref());
    let filter_set_id = args.filter_set_id.clone();

    if let Err(error) = protected_violation(server, &domain, include_subdomains) {
        let after = rule_failure_after(
            &domain,
            include_subdomains,
            filter_set_id.as_deref(),
            &reason,
        );
        record(
            server,
            token,
            "mcp.add_rule",
            None,
            Some(after),
            AuditResult::Error,
            Some(error.code()),
        )
        .await;
        return tool_error(error.code(), error.params().unwrap_or_else(|| json!({})));
    }

    let params = AddRuleParams {
        domain: domain.clone(),
        include_subdomains,
        filter_set_id: filter_set_id.clone(),
        lifetime_seconds: server.config.max_block_rule_lifetime.as_secs(),
    };
    match server.backend.add_custom_rule(params).await {
        Ok(result) => {
            let after = json!({
                "domain": SafeText::new(&domain, CAP_DOMAIN),
                "include_subdomains": include_subdomains,
                "filter_set_id": SafeText::new(&result.filter_set_id, CAP_LIST_ID),
                "reason": reason,
                "rule_text": SafeText::new(&result.rule_text, CAP_RULE_TEXT),
                "created_at": SafeText::new(&result.created_at, CAP_CLIENT_NAME),
                "expires_at": SafeText::new(&result.expires_at, CAP_CLIENT_NAME),
                "config_version": result.config_version,
            });
            record(
                server,
                token,
                "mcp.add_rule",
                None,
                Some(after),
                AuditResult::Success,
                None,
            )
            .await;
            tool_ok(json!({
                "rule_text": SafeText::new(&result.rule_text, CAP_RULE_TEXT),
                "filter_set_id": SafeText::new(&result.filter_set_id, CAP_LIST_ID),
                "domain": SafeText::new(&domain, CAP_DOMAIN),
                "include_subdomains": include_subdomains,
                "created_at": SafeText::new(&result.created_at, CAP_CLIENT_NAME),
                "expires_at": SafeText::new(&result.expires_at, CAP_CLIENT_NAME),
            }))
        }
        Err(error) => {
            let code = error.code().to_owned();
            let params = error.params().unwrap_or_else(|| json!({}));
            let after = rule_failure_after(
                &domain,
                include_subdomains,
                filter_set_id.as_deref(),
                &reason,
            );
            record(
                server,
                token,
                "mcp.add_rule",
                None,
                Some(after),
                AuditResult::Error,
                Some(&code),
            )
            .await;
            tool_error(&code, params)
        }
    }
}

fn rule_failure_after(
    domain: &str,
    include_subdomains: bool,
    filter_set_id: Option<&str>,
    reason: &str,
) -> Value {
    json!({
        "domain": SafeText::new(domain, CAP_DOMAIN),
        "include_subdomains": include_subdomains,
        "filter_set_id": filter_set_id.map(|id| SafeText::new(id, CAP_LIST_ID)),
        "reason": reason,
    })
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RemoveRuleArgs {
    domain: String,
    filter_set_id: Option<String>,
}

async fn remove_rule(
    arguments: Option<JsonObject>,
    server: &McpServer,
    token: &TokenInfo,
) -> CallToolResult {
    let args = match parse_arguments::<RemoveRuleArgs>(arguments) {
        Ok(args) => args,
        Err(error) => return error,
    };
    let domain = match validate_domain(&args.domain) {
        Ok(domain) => domain,
        Err(error) => return error,
    };
    let filter_set_id = args.filter_set_id.clone();
    let before = json!({
        "domain": SafeText::new(&domain, CAP_DOMAIN),
        "filter_set_id": filter_set_id.as_deref().map(|id| SafeText::new(id, CAP_LIST_ID)),
    });

    let found = match server
        .backend
        .find_mcp_rule(&domain, filter_set_id.as_deref())
        .await
    {
        Ok(found) => found,
        Err(error) => {
            let code = error.code().to_owned();
            let params = error.params().unwrap_or_else(|| json!({}));
            record(
                server,
                token,
                "mcp.remove_rule",
                Some(before),
                Some(json!({ "removed": false })),
                AuditResult::Error,
                Some(&code),
            )
            .await;
            return tool_error(&code, params);
        }
    };

    if let Some(rule) = &found
        && let Err(error) = protected_violation(server, &domain, rule.include_subdomains)
    {
        record(
            server,
            token,
            "mcp.remove_rule",
            Some(before),
            Some(json!({ "removed": false })),
            AuditResult::Error,
            Some(error.code()),
        )
        .await;
        return tool_error(error.code(), error.params().unwrap_or_else(|| json!({})));
    }

    let Some(rule) = found else {
        let after = json!({
            "domain": SafeText::new(&domain, CAP_DOMAIN),
            "filter_set_id": filter_set_id.as_deref().map(|id| SafeText::new(id, CAP_LIST_ID)),
            "removed": false,
            "config_version": Value::Null,
        });
        record(
            server,
            token,
            "mcp.remove_rule",
            Some(before),
            Some(after),
            AuditResult::Success,
            None,
        )
        .await;
        return tool_ok(json!({ "removed": false }));
    };

    let params = RemoveRuleParams {
        domain: domain.clone(),
        filter_set_id: filter_set_id.clone(),
    };
    match server.backend.remove_custom_rule(params).await {
        Ok(result) => {
            let after = json!({
                "domain": SafeText::new(&domain, CAP_DOMAIN),
                "filter_set_id": SafeText::new(&result.filter_set_id, CAP_LIST_ID),
                "removed": result.removed,
                "config_version": result.config_version,
                "rule_id": SafeText::new(&rule.id, CAP_LIST_ID),
            });
            record(
                server,
                token,
                "mcp.remove_rule",
                Some(before),
                Some(after),
                AuditResult::Success,
                None,
            )
            .await;
            if result.removed {
                tool_ok(json!({
                    "removed": true,
                    "domain": SafeText::new(&domain, CAP_DOMAIN),
                    "filter_set_id": SafeText::new(&result.filter_set_id, CAP_LIST_ID),
                }))
            } else {
                tool_ok(json!({ "removed": false }))
            }
        }
        Err(error) => {
            let code = error.code().to_owned();
            let params = error.params().unwrap_or_else(|| json!({}));
            record(
                server,
                token,
                "mcp.remove_rule",
                Some(before),
                Some(json!({ "removed": false })),
                AuditResult::Error,
                Some(&code),
            )
            .await;
            tool_error(&code, params)
        }
    }
}

fn allow_failure_after(
    domain: &str,
    include_subdomains: bool,
    duration: PauseDuration,
    filter_set_id: Option<&str>,
    reason: &str,
) -> Value {
    json!({
        "domain": SafeText::new(domain, CAP_DOMAIN),
        "include_subdomains": include_subdomains,
        "duration": duration.as_str(),
        "filter_set_id": filter_set_id.map(|id| SafeText::new(id, CAP_LIST_ID)),
        "reason": reason,
    })
}

/// Canonicalise a write-tool target and reject structurally unusable names.
///
/// Wildcards, regular expressions, paths, IP literals and single-label names
/// are rejected here, before the backend sees the request.
fn validate_domain(raw: &str) -> Result<String, CallToolResult> {
    if raw.chars().any(char::is_control) {
        return Err(invalid_input("domain contains control characters"));
    }
    let canonical =
        crate::protected::canonicalize(raw).map_err(|_| invalid_input("invalid domain"))?;
    if canonical.parse::<IpAddr>().is_ok() {
        return Err(invalid_input("IP addresses are not allowed"));
    }
    if !canonical.contains('.') {
        return Err(invalid_input("single-label domains are not allowed"));
    }
    Ok(canonical)
}

/// Neutralise control characters and cap an assistant-supplied reason.
fn sanitize_reason(reason: Option<&str>) -> String {
    reason.map_or_else(String::new, |reason| {
        SafeText::new(reason, CAP_REASON).into_inner()
    })
}

/// Reject a fixed-set duration above the configured maximum.
fn duration_error(requested: PauseDuration, maximum: Duration) -> Option<McpError> {
    (requested.seconds() > maximum.as_secs()).then(|| McpError::DurationExceedsMaximum {
        requested: requested.as_str().to_owned(),
        maximum: iso_duration(maximum),
    })
}

/// Render a configured duration for the error `params`.
fn iso_duration(duration: Duration) -> String {
    match duration.as_secs() {
        300 => "PT5M".to_owned(),
        900 => "PT15M".to_owned(),
        3600 => "PT1H".to_owned(),
        seconds => format!("PT{seconds}S"),
    }
}

/// Reject a target covered by the protected-domain list.
fn protected_violation(
    server: &McpServer,
    domain: &str,
    include_subdomains: bool,
) -> Result<(), McpError> {
    let list = server.protected.as_ref().map_err(Clone::clone)?;
    match list.check(domain, include_subdomains) {
        Some(matched) => Err(McpError::ProtectedDomain {
            domain: SafeText::new(&matched, CAP_DOMAIN).into_inner(),
        }),
        None => Ok(()),
    }
}

/// Best-effort audit write; a failure is logged and never replaces the result.
async fn record(
    server: &McpServer,
    token: &TokenInfo,
    action: &str,
    before: Option<Value>,
    after: Option<Value>,
    result: AuditResult,
    error_code: Option<&str>,
) {
    let entry = AuditEntry {
        action: action.to_owned(),
        actor_id: token.token_id.clone(),
        before,
        after: after.unwrap_or(Value::Null),
        result,
        error_code: error_code.map(str::to_owned),
    };
    if let Err(error) = server.backend.record_audit(entry).await {
        tracing::warn!(action, code = error.code(), "audit write failed");
    }
}
