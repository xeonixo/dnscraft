//! MCP configuration keys, defaults and startup validation.
//!
//! Values and ranges come from `SPEC-mcp.md` § Limits and defaults and §
//! Configuration excerpt. Validation rejects out-of-range values with a
//! `mcp.config.*` code before the service is served.
//!
//! `allowed_origins` is runtime-only: control-api derives it from the browser
//! origins allowed to reach the API listener and never reads it from TOML.

use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::error::McpError;
use crate::protected::ProtectedDomains;

/// Default `max_concurrent_requests_per_token`.
pub const DEFAULT_MAX_CONCURRENT_REQUESTS_PER_TOKEN: u32 = 5;
/// Lower bound for `max_concurrent_requests_per_token`.
pub const MIN_CONCURRENT_REQUESTS_PER_TOKEN: u32 = 1;
/// Upper bound for `max_concurrent_requests_per_token`.
pub const MAX_CONCURRENT_REQUESTS_PER_TOKEN: u32 = 50;
/// Default `request_timeout`.
pub const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(60);
/// Lower bound for `request_timeout`.
pub const MIN_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
/// Upper bound for `request_timeout`.
pub const MAX_REQUEST_TIMEOUT: Duration = Duration::from_secs(300);
/// Default `max_request_body_size` (1 MiB, matching control-api).
pub const DEFAULT_MAX_REQUEST_BODY_SIZE: usize = 1024 * 1024;
/// Lower bound for both temporary-allow and pause durations.
pub const MIN_ACTION_DURATION: Duration = Duration::from_secs(5 * 60);
/// Upper bound for both temporary-allow and pause durations.
pub const MAX_ACTION_DURATION: Duration = Duration::from_secs(60 * 60);
/// Default `max_custom_rules_per_set`.
pub const DEFAULT_MAX_CUSTOM_RULES_PER_SET: u32 = 100;
/// Lower bound for `max_custom_rules_per_set`.
pub const MIN_CUSTOM_RULES_PER_SET: u32 = 10;
/// Upper bound for `max_custom_rules_per_set`.
pub const MAX_CUSTOM_RULES_PER_SET: u32 = 1000;
/// Default `max_block_rule_lifetime`.
pub const DEFAULT_MAX_BLOCK_RULE_LIFETIME: Duration = Duration::from_secs(30 * 24 * 60 * 60);
/// Lower bound for `max_block_rule_lifetime`.
pub const MIN_BLOCK_RULE_LIFETIME: Duration = Duration::from_secs(24 * 60 * 60);
/// Upper bound for `max_block_rule_lifetime`.
pub const MAX_BLOCK_RULE_LIFETIME: Duration = Duration::from_secs(365 * 24 * 60 * 60);
/// Default `read_per_second` (same as control-api).
pub const DEFAULT_READ_PER_SECOND: u32 = 100;
/// Default `write_per_second` (same as control-api).
pub const DEFAULT_WRITE_PER_SECOND: u32 = 20;
/// Default `auth_per_second` (same as control-api).
pub const DEFAULT_AUTH_PER_SECOND: u32 = 10;
/// Upper bound for each per-token rate (defence against absurd configs).
pub const MAX_PER_SECOND: u32 = 10_000;
/// Default `max_tracked_tokens`.
pub const DEFAULT_MAX_TRACKED_TOKENS: usize = 10_000;
/// Upper bound for `max_tracked_tokens`.
pub const MAX_TRACKED_TOKENS: usize = 1_000_000;

/// MCP server configuration (`control_api.mcp` in the bootstrap TOML).
///
/// The container-level `default` fills any key omitted from the TOML from
/// [`McpConfig::default`]; `protected_domains` and `allowed_origins` are
/// runtime-derived and default to empty (control-api populates them after
/// loading, never from TOML). The type holds no secrets, so it is safe to
/// serialize (needed by `ControlApiConfig`'s snapshot `Serialize`).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default)]
pub struct McpConfig {
    /// Whether the MCP endpoint is mounted. Off by default.
    pub enabled: bool,
    /// Independent gate for the five write tools.
    pub write_tools_enabled: bool,
    /// Serve legacy (pre-2026-07-28) handshake clients alongside stateless
    /// requests.
    ///
    /// Only the accepted `MCP-Protocol-Version` list is widened. The header is
    /// still required in every mode, so rmcp's SEP-2243 header/body binding is
    /// never disabled by omitting it.
    pub legacy_session_mode: bool,
    /// Maximum in-flight requests per token.
    pub max_concurrent_requests_per_token: u32,
    /// Per-request deadline.
    pub request_timeout: Duration,
    /// Maximum JSON request body size in bytes.
    pub max_request_body_size: usize,
    /// Read-tool rate limit for each token, in requests per second.
    pub read_per_second: u32,
    /// Write-tool rate limit for each token, in requests per second.
    pub write_per_second: u32,
    /// Failed-authentication rate limit per source, in attempts per second.
    pub auth_per_second: u32,
    /// Maximum number of token/source buckets tracked before LRU eviction.
    pub max_tracked_tokens: usize,
    /// Highest accepted `allow_temporarily` duration; only lowers the fixed
    /// `PT5M`/`PT15M`/`PT1H` set.
    pub max_temporary_allow_duration: Duration,
    /// Highest accepted `pause_filter_set` duration; only lowers the fixed
    /// `PT5M`/`PT15M`/`PT1H` set.
    pub max_pause_duration: Duration,
    /// Maximum number of non-expired MCP-created block rules per filter set.
    pub max_custom_rules_per_set: u32,
    /// Lifetime assigned to every MCP-created block rule.
    pub max_block_rule_lifetime: Duration,
    /// Additional protected domains beyond the auto-derived list.
    pub protected_domains: Vec<String>,
    /// Browser origins allowed to reach the endpoint (runtime-only, supplied by
    /// control-api).
    pub allowed_origins: Vec<String>,
}

impl Default for McpConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            write_tools_enabled: false,
            legacy_session_mode: false,
            max_concurrent_requests_per_token: DEFAULT_MAX_CONCURRENT_REQUESTS_PER_TOKEN,
            request_timeout: DEFAULT_REQUEST_TIMEOUT,
            max_request_body_size: DEFAULT_MAX_REQUEST_BODY_SIZE,
            read_per_second: DEFAULT_READ_PER_SECOND,
            write_per_second: DEFAULT_WRITE_PER_SECOND,
            auth_per_second: DEFAULT_AUTH_PER_SECOND,
            max_tracked_tokens: DEFAULT_MAX_TRACKED_TOKENS,
            max_temporary_allow_duration: MAX_ACTION_DURATION,
            max_pause_duration: MAX_ACTION_DURATION,
            max_custom_rules_per_set: DEFAULT_MAX_CUSTOM_RULES_PER_SET,
            max_block_rule_lifetime: DEFAULT_MAX_BLOCK_RULE_LIFETIME,
            protected_domains: Vec::new(),
            allowed_origins: Vec::new(),
        }
    }
}

impl McpConfig {
    /// Validate every key and range; call once at startup.
    ///
    /// # Errors
    ///
    /// Returns [`McpError::ConfigInvalid`] for an out-of-range value and
    /// [`McpError::ConfigProtectedDomain`] for a malformed protected domain.
    pub fn validate(&self) -> Result<(), McpError> {
        if self.max_request_body_size == 0 {
            return Err(invalid("max_request_body_size", "must be at least 1 byte"));
        }
        check_range("read_per_second", self.read_per_second, 1, MAX_PER_SECOND)?;
        check_range("write_per_second", self.write_per_second, 1, MAX_PER_SECOND)?;
        check_range("auth_per_second", self.auth_per_second, 1, MAX_PER_SECOND)?;
        if self.max_tracked_tokens == 0 || self.max_tracked_tokens > MAX_TRACKED_TOKENS {
            return Err(invalid(
                "max_tracked_tokens",
                format!("must be in the range 1..={MAX_TRACKED_TOKENS}"),
            ));
        }
        check_range(
            "max_concurrent_requests_per_token",
            self.max_concurrent_requests_per_token,
            MIN_CONCURRENT_REQUESTS_PER_TOKEN,
            MAX_CONCURRENT_REQUESTS_PER_TOKEN,
        )?;
        check_duration(
            "request_timeout",
            self.request_timeout,
            MIN_REQUEST_TIMEOUT,
            MAX_REQUEST_TIMEOUT,
        )?;
        check_duration(
            "max_temporary_allow_duration",
            self.max_temporary_allow_duration,
            MIN_ACTION_DURATION,
            MAX_ACTION_DURATION,
        )?;
        check_duration(
            "max_pause_duration",
            self.max_pause_duration,
            MIN_ACTION_DURATION,
            MAX_ACTION_DURATION,
        )?;
        check_range(
            "max_custom_rules_per_set",
            self.max_custom_rules_per_set,
            MIN_CUSTOM_RULES_PER_SET,
            MAX_CUSTOM_RULES_PER_SET,
        )?;
        check_duration(
            "max_block_rule_lifetime",
            self.max_block_rule_lifetime,
            MIN_BLOCK_RULE_LIFETIME,
            MAX_BLOCK_RULE_LIFETIME,
        )?;
        ProtectedDomains::new(self.protected_domains.iter().cloned())?;
        Ok(())
    }
}

fn invalid(key: &'static str, reason: impl Into<String>) -> McpError {
    McpError::ConfigInvalid {
        key,
        reason: reason.into(),
    }
}

fn check_range(key: &'static str, value: u32, min: u32, max: u32) -> Result<(), McpError> {
    if (min..=max).contains(&value) {
        Ok(())
    } else {
        Err(invalid(
            key,
            format!("{value} is outside the allowed range {min}..={max}"),
        ))
    }
}

fn check_duration(
    key: &'static str,
    value: Duration,
    min: Duration,
    max: Duration,
) -> Result<(), McpError> {
    if value < min {
        Err(invalid(
            key,
            format!(
                "{}s is below the {}-second minimum",
                value.as_secs(),
                min.as_secs()
            ),
        ))
    } else if value > max {
        Err(invalid(
            key,
            format!(
                "{}s is above the {}-second maximum",
                value.as_secs(),
                max.as_secs()
            ),
        ))
    } else {
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_valid() {
        McpConfig::default().validate().unwrap();
    }

    #[test]
    fn deserializes_partial_config_with_runtime_fields_defaulted() {
        // Only one key is supplied; every other key (including the
        // runtime-derived lists) comes from `Default`.
        let config: McpConfig =
            serde_json::from_str(r#"{"enabled": true, "protected_domains": ["example.com"]}"#)
                .unwrap();
        assert!(config.enabled);
        assert_eq!(config.protected_domains, ["example.com"]);
        assert!(config.allowed_origins.is_empty());
        assert_eq!(config.request_timeout, DEFAULT_REQUEST_TIMEOUT);
        assert_eq!(config.max_request_body_size, DEFAULT_MAX_REQUEST_BODY_SIZE);
    }

    #[test]
    fn protected_domains_accept_canonical_and_idna_forms() {
        for domain in ["example.com", "Example.COM.", "münchen.example"] {
            let config = McpConfig {
                protected_domains: vec![domain.into()],
                ..McpConfig::default()
            };
            config.validate().unwrap();
        }
    }

    #[test]
    fn protected_domains_reject_schemes_paths_wildcards_and_empty_labels() {
        for domain in [
            "",
            "https://example.com",
            "example.com/path",
            "*.example.com",
            "example..com",
            ".example.com",
            "exa mple.com",
            "-example.com",
        ] {
            let config = McpConfig {
                protected_domains: vec![domain.into()],
                ..McpConfig::default()
            };
            assert_eq!(
                config.validate().unwrap_err().code(),
                "mcp.config.protected_domain",
                "{domain}"
            );
        }
    }
}
