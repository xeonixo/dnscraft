//! Tool-level and configuration errors with stable, locale-neutral codes.
//!
//! Every variant exposes a `mcp.*` code through [`McpError::code`]. Tool
//! handlers turn these into the single tool-error shape (`isError: true` plus
//! `structuredContent.error`) with `result::tool_error`; they never become an
//! HTTP status or a JSON-RPC error.
//!
//! | Variant | Code |
//! |---|---|
//! | [`McpError::ToolNotFound`] | `mcp.tool_not_found` |
//! | [`McpError::InvalidInput`] | `mcp.invalid_input` |
//! | [`McpError::DomainTooBroad`] | `mcp.domain_too_broad` |
//! | [`McpError::WriteToolsDisabled`] | `mcp.write_tools_disabled` |
//! | [`McpError::DurationExceedsMaximum`] | `mcp.duration_exceeds_maximum` |
//! | [`McpError::RuleLimitExceeded`] | `mcp.rule_limit_exceeded` |
//! | [`McpError::ProtectedDomain`] | `mcp.protected_domain` |
//! | [`McpError::ConfigInvalid`] | `mcp.config.invalid` |
//! | [`McpError::ConfigProtectedDomain`] | `mcp.config.protected_domain` |

use serde_json::{Value, json};

/// An MCP-owned error.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum McpError {
    /// The tool name in `tools/call` does not exist.
    #[error("unknown tool: {tool}")]
    ToolNotFound {
        /// The requested tool name.
        tool: String,
    },
    /// Tool input failed schema or value validation.
    #[error("invalid input: {reason}")]
    InvalidInput {
        /// Why the input was rejected.
        reason: String,
    },
    /// The target is a single-label (TLD-wide) name.
    #[error("domain is too broad: {domain}")]
    DomainTooBroad {
        /// The rejected target.
        domain: String,
    },
    /// A write tool was called while write tools are disabled.
    #[error("write tools are disabled")]
    WriteToolsDisabled,
    /// A fixed-set duration is above the configured maximum.
    #[error("duration {requested} exceeds the configured maximum {maximum}")]
    DurationExceedsMaximum {
        /// The requested ISO 8601 duration.
        requested: String,
        /// The configured maximum ISO 8601 duration.
        maximum: String,
    },
    /// The MCP-created rule cap for the filter set was reached.
    #[error("rule limit reached for filter set {filter_set_id} (max {max})")]
    RuleLimitExceeded {
        /// The filter set whose cap was reached.
        filter_set_id: String,
        /// The configured cap.
        max: u32,
    },
    /// The target, an ancestor or a descendant is protected.
    #[error("protected domain: {domain}")]
    ProtectedDomain {
        /// The rejected target.
        domain: String,
    },
    /// A configuration value is out of range or otherwise invalid.
    #[error("invalid mcp config {key}: {reason}")]
    ConfigInvalid {
        /// The configuration key.
        key: &'static str,
        /// Why it was rejected.
        reason: String,
    },
    /// A `protected_domains` entry is not a valid domain.
    #[error("invalid protected domain {domain}: {reason}")]
    ConfigProtectedDomain {
        /// The rejected entry as written in config.
        domain: String,
        /// Why it was rejected.
        reason: String,
    },
}

impl McpError {
    /// Stable, locale-neutral code exposed in `structuredContent.error.code`.
    pub fn code(&self) -> &'static str {
        match self {
            Self::ToolNotFound { .. } => "mcp.tool_not_found",
            Self::InvalidInput { .. } => "mcp.invalid_input",
            Self::DomainTooBroad { .. } => "mcp.domain_too_broad",
            Self::WriteToolsDisabled => "mcp.write_tools_disabled",
            Self::DurationExceedsMaximum { .. } => "mcp.duration_exceeds_maximum",
            Self::RuleLimitExceeded { .. } => "mcp.rule_limit_exceeded",
            Self::ProtectedDomain { .. } => "mcp.protected_domain",
            Self::ConfigInvalid { .. } => "mcp.config.invalid",
            Self::ConfigProtectedDomain { .. } => "mcp.config.protected_domain",
        }
    }

    /// Non-secret context for the error envelope's `params` object.
    pub fn params(&self) -> Option<Value> {
        match self {
            Self::ToolNotFound { tool } => Some(json!({ "tool": tool })),
            Self::InvalidInput { reason } => Some(json!({ "reason": reason })),
            Self::DomainTooBroad { domain } => Some(json!({ "domain": domain })),
            Self::WriteToolsDisabled => Some(json!({})),
            Self::DurationExceedsMaximum { requested, maximum } => {
                Some(json!({ "requested": requested, "maximum": maximum }))
            }
            Self::RuleLimitExceeded { filter_set_id, max } => {
                Some(json!({ "filter_set_id": filter_set_id, "max": max }))
            }
            Self::ProtectedDomain { domain } => Some(json!({ "domain": domain })),
            Self::ConfigInvalid { key, reason } => Some(json!({ "key": key, "reason": reason })),
            Self::ConfigProtectedDomain { domain, reason } => {
                Some(json!({ "domain": domain, "reason": reason }))
            }
        }
    }
}

#[cfg(test)]
pub(crate) fn sample_errors() -> Vec<McpError> {
    vec![
        McpError::ToolNotFound {
            tool: "nope".into(),
        },
        McpError::InvalidInput { reason: "x".into() },
        McpError::DomainTooBroad {
            domain: "com".into(),
        },
        McpError::WriteToolsDisabled,
        McpError::DurationExceedsMaximum {
            requested: "PT1H".into(),
            maximum: "PT15M".into(),
        },
        McpError::RuleLimitExceeded {
            filter_set_id: "fs".into(),
            max: 100,
        },
        McpError::ProtectedDomain {
            domain: "example.com".into(),
        },
        McpError::ConfigInvalid {
            key: "request_timeout",
            reason: "x".into(),
        },
        McpError::ConfigProtectedDomain {
            domain: "bad".into(),
            reason: "x".into(),
        },
    ]
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn all() -> Vec<McpError> {
        sample_errors()
    }

    #[test]
    fn codes_are_unique_well_formed_and_have_params() {
        let mut codes: Vec<&str> = all().iter().map(McpError::code).collect();
        for code in &codes {
            assert!(code.starts_with("mcp."), "code {code} must use mcp. prefix");
            assert!(
                code.chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '.' || c == '_'),
                "code {code} must be locale-neutral ascii"
            );
        }
        for error in all() {
            assert!(
                error.params().is_some(),
                "{} must carry params",
                error.code()
            );
        }
        codes.sort_unstable();
        codes.dedup();
        assert_eq!(codes.len(), all().len(), "duplicate error codes");
    }
}
