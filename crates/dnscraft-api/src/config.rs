//! Control-API configuration values (no TOML parsing — the binary does that later).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use dnscraft_mcp::McpConfig;

use crate::Secret;
use crate::error::ControlApiError;

/// Default bind address (loopback; the API is always internal-only).
pub const DEFAULT_BIND: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);
/// Default TCP listen port.
/// Default control-api port. Matches [`ControlApiConfig::default`] (`tls = true`).
pub const DEFAULT_PORT: u16 = 443;

/// Default query-log retention window in days.
pub const DEFAULT_RETENTION_DAYS: u32 = 30;
/// Default maximum rows per query-log request.
pub const DEFAULT_MAX_ROWS_PER_REQUEST: u32 = 10_000;

/// Default failed local-login attempts before lockout.
pub const DEFAULT_LOCAL_LOGIN_MAX_ATTEMPTS: u32 = 5;
/// Default local-login lock window.
pub const DEFAULT_LOCAL_LOGIN_LOCK_WINDOW: Duration = Duration::from_secs(15 * 60);
/// Default allowed clock skew for OIDC `iat`/`exp` validation.
pub const DEFAULT_OIDC_TOKEN_SKEW: Duration = Duration::from_secs(30);
/// Default maximum lifetime of a newly issued API token.
pub const DEFAULT_API_TOKEN_MAX_TTL: Duration = Duration::from_secs(365 * 24 * 3600);
/// Default browser-session idle timeout (spec "Decisions": 60 min).
pub const DEFAULT_SESSION_IDLE_TIMEOUT: Duration = Duration::from_secs(60 * 60);
/// Default browser-session absolute lifetime (spec "Decisions": 12 h).
pub const DEFAULT_SESSION_ABSOLUTE_TIMEOUT: Duration = Duration::from_secs(12 * 3600);

/// Default read-endpoint rate (tokens/second).
pub const DEFAULT_READ_PER_SECOND: u32 = 100;
/// Default write-endpoint rate (tokens/second).
pub const DEFAULT_WRITE_PER_SECOND: u32 = 20;
/// Default auth-endpoint rate (tokens/second).
pub const DEFAULT_AUTH_PER_SECOND: u32 = 10;
/// Default burst multiplier (burst = per_second * factor).
pub const DEFAULT_BURST_FACTOR: u32 = 2;

// Validation bounds (documented in SPEC-control-api.md "Limits/defaults").
const MIN_RETENTION_DAYS: u32 = 1;
const MAX_RETENTION_DAYS: u32 = 3650;
const MIN_MAX_ROWS_PER_REQUEST: u32 = 100;
const MAX_MAX_ROWS_PER_REQUEST: u32 = 100_000;
const MIN_LOCAL_LOGIN_MAX_ATTEMPTS: u32 = 1;
const MAX_LOCAL_LOGIN_MAX_ATTEMPTS: u32 = 20;
const MIN_LOCAL_LOGIN_LOCK_WINDOW: Duration = Duration::from_secs(60);
const MAX_LOCAL_LOGIN_LOCK_WINDOW: Duration = Duration::from_secs(24 * 3600);
const MIN_OIDC_TOKEN_SKEW: Duration = Duration::from_secs(5);
const MAX_OIDC_TOKEN_SKEW: Duration = Duration::from_secs(300);
const MIN_API_TOKEN_MAX_TTL: Duration = Duration::from_secs(24 * 3600);
const MAX_API_TOKEN_MAX_TTL: Duration = Duration::from_secs(3650 * 24 * 3600);
const MIN_SESSION_IDLE_TIMEOUT: Duration = Duration::from_secs(5 * 60);
const MAX_SESSION_IDLE_TIMEOUT: Duration = Duration::from_secs(24 * 3600);
const MIN_SESSION_ABSOLUTE_TIMEOUT: Duration = Duration::from_secs(3600);
const MAX_SESSION_ABSOLUTE_TIMEOUT: Duration = Duration::from_secs(7 * 24 * 3600);

/// IP truncation level for persisted query-log records.
///
/// The serde names match the wire/config names (`none`, `last_octet`,
/// `last_group`); `none` is the default for new installs. The level is
/// runtime-editable through `control_api_settings.query_log.ip_truncate`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IpTruncate {
    /// Keep the full source IP; default for new installs.
    #[default]
    None,
    /// IPv4: zero the last octet (`x.x.x.0`).
    LastOctet,
    /// IPv6: keep the first 48 bits.
    LastGroup,
}

impl IpTruncate {
    /// Wire / config name (`none`, `last_octet`, `last_group`).
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::LastOctet => "last_octet",
            Self::LastGroup => "last_group",
        }
    }

    /// Parses the wire/config name; unknown values are rejected with the config code.
    pub fn parse(s: &str) -> Result<Self, ControlApiError> {
        match s.trim() {
            "none" => Ok(Self::None),
            "last_octet" => Ok(Self::LastOctet),
            "last_group" => Ok(Self::LastGroup),
            other => Err(ControlApiError::config(format!(
                "ip_truncate must be `none`, `last_octet` or `last_group`, got `{other}`"
            ))),
        }
    }

    /// Renders `ip` with this truncation applied.
    pub fn truncate(self, ip: IpAddr) -> String {
        match (self, ip) {
            (Self::None, ip) => ip.to_string(),
            (Self::LastOctet, IpAddr::V4(v4)) => {
                let o = v4.octets();
                Ipv4Addr::new(o[0], o[1], o[2], 0).to_string()
            }
            (Self::LastGroup, IpAddr::V6(v6)) => {
                let s = v6.segments();
                Ipv6Addr::new(s[0], s[1], s[2], 0, 0, 0, 0, 0).to_string()
            }
            (_, ip) => ip.to_string(),
        }
    }
}

/// Authentication settings.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct AuthConfig {
    /// Whether OIDC login is enabled.
    pub oidc_enabled: bool,
    /// OIDC issuer URL (discovery base).
    pub oidc_issuer: String,
    /// OIDC client id.
    pub oidc_client_id: String,
    /// OIDC client secret (env-only in the binary; serializes as `"redacted"`).
    ///
    /// Never read from TOML: the value is re-supplied from
    /// `DNSCRAFT_OIDC_CLIENT_SECRET` at startup, so a config file cannot
    /// smuggle a plaintext secret (nor a `"redacted"` marker) into the binary.
    #[serde(default, skip_deserializing)]
    pub oidc_client_secret: Secret,
    /// Group name that maps to the `admin` role.
    pub oidc_admin_group: String,
    /// ID-token claim that lists the user's groups (default `groups`, GA12).
    pub oidc_groups_claim: String,
    /// Allowed clock skew when validating `iat`/`exp` (5–300 s).
    pub oidc_token_skew: Duration,
    /// Whether the local break-glass login is enabled.
    pub local_login_enabled: bool,
    /// Failed attempts before a local account locks (1–20).
    pub local_login_max_attempts: u32,
    /// Sliding window in which local-login failures accumulate (1 m–24 h).
    pub local_login_lock_window: Duration,
    /// Maximum lifetime of a newly issued API token (1–3650 d).
    pub api_token_max_ttl: Duration,
    /// Idle timeout for a browser session (5 m–24 h).
    pub session_idle_timeout: Duration,
    /// Absolute lifetime for a browser session (1 h–7 d).
    pub session_absolute_timeout: Duration,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            oidc_enabled: true,
            oidc_issuer: String::new(),
            oidc_client_id: String::new(),
            oidc_client_secret: Secret::default(),
            oidc_admin_group: "dnscraft-admin".into(),
            oidc_groups_claim: "groups".into(),
            oidc_token_skew: DEFAULT_OIDC_TOKEN_SKEW,
            local_login_enabled: true,
            local_login_max_attempts: DEFAULT_LOCAL_LOGIN_MAX_ATTEMPTS,
            local_login_lock_window: DEFAULT_LOCAL_LOGIN_LOCK_WINDOW,
            api_token_max_ttl: DEFAULT_API_TOKEN_MAX_TTL,
            session_idle_timeout: DEFAULT_SESSION_IDLE_TIMEOUT,
            session_absolute_timeout: DEFAULT_SESSION_ABSOLUTE_TIMEOUT,
        }
    }
}

/// Query-log storage settings.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct QueryLogConfig {
    /// Retention window in days (1–3650).
    pub retention_days: u32,
    /// Source-IP truncation for persisted records.
    pub ip_truncate: IpTruncate,
    /// Maximum rows any single query-log request may return (100–100000).
    pub max_rows_per_request: u32,
}

impl Default for QueryLogConfig {
    fn default() -> Self {
        Self {
            retention_days: DEFAULT_RETENTION_DAYS,
            ip_truncate: IpTruncate::default(),
            max_rows_per_request: DEFAULT_MAX_ROWS_PER_REQUEST,
        }
    }
}

/// Rate-limit settings for the internal API.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct RateLimitConfig {
    /// Read endpoints: tokens per second.
    pub read_per_second: u32,
    /// Write endpoints: tokens per second.
    pub write_per_second: u32,
    /// Auth endpoints: tokens per second.
    pub auth_per_second: u32,
    /// Burst multiplier (burst = per_second * factor).
    pub burst_factor: u32,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            read_per_second: DEFAULT_READ_PER_SECOND,
            write_per_second: DEFAULT_WRITE_PER_SECOND,
            auth_per_second: DEFAULT_AUTH_PER_SECOND,
            burst_factor: DEFAULT_BURST_FACTOR,
        }
    }
}

/// Full control-api bootstrap configuration.
///
/// The container-level `default` fills omitted TOML keys from
/// [`ControlApiConfig::default`]. `IpAddr`, `Duration`, `Vec` and `Option`
/// fields use serde's built-in representations; the binary's TOML loader must
/// turn human forms such as `"60s"` / `"1MiB"` into their serde forms before
/// deserializing (no custom `serde(with)` is used here).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ControlApiConfig {
    /// Bind address. Must be loopback/private/ULA (never `0.0.0.0`/`::`).
    pub bind: IpAddr,
    /// TCP listen port.
    pub port: u16,
    /// Serve direct TLS via the `tls` module `CertResolver` (with self-signed bootstrap).
    pub tls: bool,
    /// Id of a local DoH listener that also serves the web UI and API (non-`/dns-query` paths, private
    /// sources only), so both share its address and port (typically `:443`). When set, `bind`/`port`
    /// open no socket and the listener's TLS (the `tls` module certificate) terminates the connection.
    pub shared_doh_listener: Option<String>,
    /// Reverse-proxy addresses allowed to set forwarded headers (used when `tls == false`).
    pub trusted_proxies: Vec<IpAddr>,
    /// Authentication settings.
    pub auth: AuthConfig,
    /// Query-log settings.
    pub query_log: QueryLogConfig,
    /// Rate limits.
    pub rate_limit: RateLimitConfig,
    /// MCP server configuration (`control_api.mcp.*` in the bootstrap TOML).
    pub mcp: McpConfig,
}

impl Default for ControlApiConfig {
    fn default() -> Self {
        Self {
            bind: DEFAULT_BIND,
            port: DEFAULT_PORT,
            tls: true,
            shared_doh_listener: None,
            trusted_proxies: Vec::new(),
            auth: AuthConfig::default(),
            query_log: QueryLogConfig::default(),
            rate_limit: RateLimitConfig::default(),
            mcp: McpConfig::default(),
        }
    }
}

impl ControlApiConfig {
    /// Validates the bind address, port and each sub-section against the spec limits.
    pub fn validate(&self) -> Result<(), ControlApiError> {
        if !is_internal_bind(self.bind) {
            return Err(ControlApiError::config(format!(
                "bind address {} is not loopback/private/ULA",
                self.bind
            )));
        }
        if self.port == 0 {
            return Err(ControlApiError::config("port must be > 0"));
        }
        let auth = &self.auth;
        if auth.local_login_max_attempts < MIN_LOCAL_LOGIN_MAX_ATTEMPTS
            || auth.local_login_max_attempts > MAX_LOCAL_LOGIN_MAX_ATTEMPTS
        {
            return Err(ControlApiError::config(format!(
                "auth.local_login_max_attempts must be {MIN_LOCAL_LOGIN_MAX_ATTEMPTS}..={MAX_LOCAL_LOGIN_MAX_ATTEMPTS}, got {}",
                auth.local_login_max_attempts
            )));
        }
        check_duration_range(
            "auth.local_login_lock_window",
            auth.local_login_lock_window,
            MIN_LOCAL_LOGIN_LOCK_WINDOW,
            MAX_LOCAL_LOGIN_LOCK_WINDOW,
        )?;
        let claim = &auth.oidc_groups_claim;
        if claim.is_empty()
            || claim.len() > 64
            || !claim
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
        {
            return Err(ControlApiError::config(
                "auth.oidc_groups_claim must be 1..=64 letters, digits, '_' or '-'",
            ));
        }
        check_duration_range(
            "auth.oidc_token_skew",
            auth.oidc_token_skew,
            MIN_OIDC_TOKEN_SKEW,
            MAX_OIDC_TOKEN_SKEW,
        )?;
        check_duration_range(
            "auth.api_token_max_ttl",
            auth.api_token_max_ttl,
            MIN_API_TOKEN_MAX_TTL,
            MAX_API_TOKEN_MAX_TTL,
        )?;
        check_duration_range(
            "auth.session_idle_timeout",
            auth.session_idle_timeout,
            MIN_SESSION_IDLE_TIMEOUT,
            MAX_SESSION_IDLE_TIMEOUT,
        )?;
        check_duration_range(
            "auth.session_absolute_timeout",
            auth.session_absolute_timeout,
            MIN_SESSION_ABSOLUTE_TIMEOUT,
            MAX_SESSION_ABSOLUTE_TIMEOUT,
        )?;

        let query_log = &self.query_log;
        if query_log.retention_days < MIN_RETENTION_DAYS
            || query_log.retention_days > MAX_RETENTION_DAYS
        {
            return Err(ControlApiError::config(format!(
                "query_log.retention_days must be {MIN_RETENTION_DAYS}..={MAX_RETENTION_DAYS}, got {}",
                query_log.retention_days
            )));
        }
        if query_log.max_rows_per_request < MIN_MAX_ROWS_PER_REQUEST
            || query_log.max_rows_per_request > MAX_MAX_ROWS_PER_REQUEST
        {
            return Err(ControlApiError::config(format!(
                "query_log.max_rows_per_request must be {MIN_MAX_ROWS_PER_REQUEST}..={MAX_MAX_ROWS_PER_REQUEST}, got {}",
                query_log.max_rows_per_request
            )));
        }

        let rate_limit = &self.rate_limit;
        if rate_limit.read_per_second == 0 {
            return Err(ControlApiError::config(
                "rate_limit.read_per_second must be > 0",
            ));
        }
        if rate_limit.write_per_second == 0 {
            return Err(ControlApiError::config(
                "rate_limit.write_per_second must be > 0",
            ));
        }
        if rate_limit.auth_per_second == 0 {
            return Err(ControlApiError::config(
                "rate_limit.auth_per_second must be > 0",
            ));
        }
        if rate_limit.burst_factor == 0 {
            return Err(ControlApiError::config(
                "rate_limit.burst_factor must be > 0",
            ));
        }
        self.mcp.validate().map_err(|error| {
            ControlApiError::config(format!(
                "mcp config invalid: {}",
                error
                    .params()
                    .and_then(|p| p.get("reason").cloned())
                    .unwrap_or_else(|| serde_json::Value::String(error.code().to_owned()))
                    .as_str()
                    .unwrap_or(error.code())
            ))
        })?;
        Ok(())
    }
}

fn check_duration_range(
    name: &str,
    value: Duration,
    min: Duration,
    max: Duration,
) -> Result<(), ControlApiError> {
    if value < min || value > max {
        return Err(ControlApiError::config(format!(
            "{name} must be within {}..={} seconds, got {} seconds",
            min.as_secs(),
            max.as_secs(),
            value.as_secs()
        )));
    }
    Ok(())
}

/// Whether an address may host the internal-only API (loopback/private/ULA, never wildcard).
pub(crate) fn is_internal_bind(ip: IpAddr) -> bool {
    match ip.to_canonical() {
        // The shared helper also treats `0.0.0.0/8` and broadcast as private;
        // the API must never bind those. Loopback/private/ULA only.
        IpAddr::V4(v4) => {
            v4.octets()[0] != 0 && !v4.is_broadcast() && dnscraft_common::net::is_private_v4(v4)
        }
        IpAddr::V6(v6) => is_private_v6(v6),
    }
}

fn is_private_v6(v6: Ipv6Addr) -> bool {
    v6.is_loopback() || v6.is_unicast_link_local() || v6.is_unique_local()
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::field_reassign_with_default
)]
mod tests {
    use super::*;

    fn config_with_bind(addr: &str) -> ControlApiConfig {
        let mut c = ControlApiConfig::default();
        c.bind = addr.parse().unwrap();
        c
    }

    #[test]
    fn bind_accepts_loopback_private_and_ula() {
        for addr in [
            "127.0.0.1",
            "10.0.0.1",
            "192.168.1.10",
            "172.16.0.1",
            "100.64.0.1",
            "::1",
            "fd00::1",
            // IPv4-mapped loopback is still internal.
            "::ffff:127.0.0.1",
        ] {
            assert!(
                config_with_bind(addr).validate().is_ok(),
                "{addr} should be an allowed bind address"
            );
        }
    }

    #[test]
    fn bind_rejects_wildcard_and_public() {
        for addr in [
            "0.0.0.0",
            "::",
            "8.8.8.8",
            "1.1.1.1",
            "2606:4700:4700::1111",
            // IPv4-mapped public addresses are rejected too.
            "::ffff:8.8.8.8",
        ] {
            let err = config_with_bind(addr).validate().unwrap_err();
            assert_eq!(
                err.code(),
                "control_api.config.invalid",
                "{addr} must be rejected"
            );
        }
    }

    #[test]
    fn query_log_limits_return_config_code() {
        let mut c = ControlApiConfig::default();
        c.query_log.retention_days = 0;
        assert_eq!(
            c.validate().unwrap_err().code(),
            "control_api.config.invalid"
        );
        c.query_log.retention_days = MAX_RETENTION_DAYS + 1;
        assert_eq!(
            c.validate().unwrap_err().code(),
            "control_api.config.invalid"
        );

        let mut c = ControlApiConfig::default();
        c.query_log.max_rows_per_request = MIN_MAX_ROWS_PER_REQUEST - 1;
        assert_eq!(
            c.validate().unwrap_err().code(),
            "control_api.config.invalid"
        );
        c.query_log.max_rows_per_request = MAX_MAX_ROWS_PER_REQUEST + 1;
        assert_eq!(
            c.validate().unwrap_err().code(),
            "control_api.config.invalid"
        );
    }

    #[test]
    fn ip_truncate_parse_rejects_unknown() {
        assert_eq!(IpTruncate::parse("none").unwrap(), IpTruncate::None);
        assert_eq!(
            IpTruncate::parse("last_octet").unwrap(),
            IpTruncate::LastOctet
        );
        assert_eq!(
            IpTruncate::parse("last_group").unwrap(),
            IpTruncate::LastGroup
        );
        assert_eq!(
            IpTruncate::parse("everything").unwrap_err().code(),
            "control_api.config.invalid"
        );
    }

    #[test]
    fn rate_limit_values_return_config_code() {
        let mut c = ControlApiConfig::default();
        c.rate_limit.read_per_second = 0;
        assert_eq!(
            c.validate().unwrap_err().code(),
            "control_api.config.invalid"
        );

        let mut c = ControlApiConfig::default();
        c.rate_limit.burst_factor = 0;
        assert_eq!(
            c.validate().unwrap_err().code(),
            "control_api.config.invalid"
        );
    }

    #[test]
    fn ttl_values_return_config_code() {
        let mut c = ControlApiConfig::default();
        c.auth.local_login_lock_window = Duration::from_secs(30); // below 1 m
        assert_eq!(
            c.validate().unwrap_err().code(),
            "control_api.config.invalid"
        );

        let mut c = ControlApiConfig::default();
        c.auth.session_absolute_timeout = Duration::from_secs(30 * 60); // below 1 h
        assert_eq!(
            c.validate().unwrap_err().code(),
            "control_api.config.invalid"
        );

        let mut c = ControlApiConfig::default();
        c.auth.api_token_max_ttl = Duration::from_secs(4000 * 24 * 3600); // above 3650 d
        assert_eq!(
            c.validate().unwrap_err().code(),
            "control_api.config.invalid"
        );
    }

    #[test]
    fn default_config_is_valid() {
        assert!(ControlApiConfig::default().validate().is_ok());
    }

    /// Every field differs from its default (documentation ranges only), so
    /// the round-trip covers the full value space.
    fn non_default_config() -> ControlApiConfig {
        ControlApiConfig {
            bind: "127.0.0.1".parse().unwrap(),
            port: 8443,
            tls: false,
            shared_doh_listener: Some("local-doh".into()),
            trusted_proxies: vec![
                "192.0.2.10".parse().unwrap(),
                "2001:db8::1".parse().unwrap(),
            ],
            auth: AuthConfig {
                oidc_enabled: false,
                oidc_issuer: "https://auth.example.com/application/o/dnscraft".into(),
                oidc_client_id: "dnscraft".into(),
                oidc_client_secret: Secret::new("real-secret-value"),
                oidc_admin_group: "admins".into(),
                oidc_groups_claim: "groups".into(),
                oidc_token_skew: Duration::from_secs(60),
                local_login_enabled: true,
                local_login_max_attempts: 3,
                local_login_lock_window: Duration::from_secs(600),
                api_token_max_ttl: Duration::from_secs(30 * 24 * 3600),
                session_idle_timeout: Duration::from_secs(900),
                session_absolute_timeout: Duration::from_secs(4 * 3600),
            },
            query_log: QueryLogConfig {
                retention_days: 7,
                ip_truncate: IpTruncate::LastGroup,
                max_rows_per_request: 500,
            },
            rate_limit: RateLimitConfig {
                read_per_second: 10,
                write_per_second: 5,
                auth_per_second: 2,
                burst_factor: 3,
            },
            mcp: McpConfig {
                enabled: true,
                protected_domains: vec!["example.com".into()],
                ..McpConfig::default()
            },
        }
    }

    #[test]
    fn config_round_trips_through_json() {
        let original = non_default_config();
        let json = serde_json::to_string(&original).unwrap();
        let decoded: ControlApiConfig = serde_json::from_str(&json).unwrap();

        // The secret is env-only: it is skipped on deserialization and the
        // binary re-supplies it at startup. All other fields round-trip.
        assert_eq!(decoded.auth.oidc_client_secret.expose(), "");
        let mut decoded = decoded;
        decoded.auth.oidc_client_secret = original.auth.oidc_client_secret.clone();
        assert_eq!(decoded, original);
        // `[control_api.mcp]` is no longer skipped.
        assert!(json.contains(r#""mcp":{"#));
    }

    #[test]
    fn serialized_config_never_contains_plaintext_secret() {
        let config = non_default_config();
        assert_eq!(config.auth.oidc_client_secret.expose(), "real-secret-value");

        let json = serde_json::to_string(&config).unwrap();
        assert!(
            !json.contains("real-secret-value"),
            "plaintext secret leaked into serialized config: {json}"
        );
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(value["auth"]["oidc_client_secret"], "redacted");
    }
}
