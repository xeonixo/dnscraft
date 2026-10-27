//! Node-local `[cluster]` bootstrap configuration.
//!
//! These values are read from the node's own config file and are **never** part
//! of the replicated cluster snapshot: the master must not overwrite a
//! sub-node's role, identity, address, or timeouts. Secrets do not belong here
//! (they come from the environment or `*_FILE`).

use std::net::IpAddr;
use std::path::PathBuf;
use std::time::Duration;

use serde::Deserialize;

use dnscraft_common::config::check_https_url;
use dnscraft_common::net::is_private;

use crate::error::ClusterError;

/// Default one-time join-token lifetime (15 min).
pub const DEFAULT_TOKEN_TTL: Duration = Duration::from_secs(15 * 60);
/// Default issued node-certificate lifetime (90 days).
pub const DEFAULT_NODE_CERT_TTL: Duration = Duration::from_secs(90 * 24 * 3600);
/// Default cluster listener port when `[cluster.listen]` omits `port`.
pub const DEFAULT_CLUSTER_PORT: u16 = 8443;
/// Default heartbeat interval.
pub const DEFAULT_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(10);
/// Default timeout waiting for a master response.
pub const DEFAULT_MASTER_TIMEOUT: Duration = Duration::from_secs(5);
/// Default timeout for a sub-node to apply and ack a snapshot.
pub const DEFAULT_CONFIG_APPLY_TIMEOUT: Duration = Duration::from_secs(30);
/// Default reconnect backoff floor.
pub const DEFAULT_RECONNECT_BACKOFF: Duration = Duration::from_secs(1);
/// Default reconnect backoff ceiling.
pub const DEFAULT_RECONNECT_BACKOFF_MAX: Duration = Duration::from_secs(60);
/// Default offline-write queue capacity.
pub const DEFAULT_QUEUE_MAX_ENTRIES: u32 = 100;
/// Default maximum age of a buffered offline write.
pub const DEFAULT_OFFLINE_WRITE_MAX_AGE: Duration = Duration::from_secs(24 * 3600);
/// Default local log-buffer retention.
pub const DEFAULT_BUFFER_RETENTION: Duration = Duration::from_secs(24 * 3600);
/// Default records per log batch.
pub const DEFAULT_BATCH_MAX_RECORDS: u32 = 500;
/// Default log-batch flush interval.
pub const DEFAULT_BATCH_INTERVAL: Duration = Duration::from_secs(1);
/// Default maximum log-batch size in bytes (1 MiB).
pub const DEFAULT_MAX_BATCH_BYTES: u64 = 1024 * 1024;
/// Default maximum in-flight log batches.
pub const DEFAULT_MAX_INFLIGHT_BATCHES: u32 = 4;
/// Default per-node relay rate limit.
pub const DEFAULT_MAX_RELAY_REQUESTS_PER_SECOND: u32 = 50;
/// Default per-node log bandwidth limit in bytes per second (2 MiB/s).
pub const DEFAULT_MAX_LOG_BYTES_PER_SECOND: u64 = 2 * 1024 * 1024;
/// Default maximum queued offline writes on the master.
pub const DEFAULT_MAX_QUEUED_OFFLINE_WRITES: u32 = 100;
/// Default clock-skew warning threshold.
pub const DEFAULT_CLOCK_SKEW_WARNING: Duration = Duration::from_secs(5 * 60);

/// Node role in the cluster.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    /// No cluster; cluster code stays idle.
    #[default]
    Standalone,
    /// Sole writer, log/stats aggregator, CA and join-token owner.
    Master,
    /// Outbound-only member that answers DNS from the last applied snapshot.
    SubNode,
}

/// Node-local cluster bootstrap configuration (the `[cluster]` TOML table).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClusterConfig {
    /// Cluster role; defaults to `standalone`.
    #[serde(default)]
    pub role: Role,
    /// Required for `master` and `sub_node`: lowercase DNS label, 1–63 chars.
    #[serde(default)]
    pub node_id: String,
    /// Required for `sub_node`; forbidden otherwise. Must be `https://`.
    #[serde(default)]
    pub master_url: Option<String>,
    /// Master-only inbound cluster listener.
    #[serde(default)]
    pub listen: Option<ListenConfig>,
    /// Join-token and issued-node-certificate lifetimes (master only).
    #[serde(default)]
    pub join: JoinConfig,
    /// Heartbeat, timeout and reconnect timing.
    #[serde(default)]
    pub timing: TimingConfig,
    /// Offline write buffering (sub-node).
    #[serde(default)]
    pub offline_writes: OfflineWritesConfig,
    /// Query-log streaming and buffering (sub-node).
    #[serde(default)]
    pub log: LogConfig,
    /// Per-node quotas enforced on the master.
    #[serde(default)]
    pub quota: QuotaConfig,
    /// Cluster certificate and key paths.
    #[serde(default)]
    pub tls: TlsPaths,
}

impl ClusterConfig {
    /// Parses a TOML document and validates role consistency.
    ///
    /// The document must contain a `[cluster]` table; other top-level tables
    /// (for example `[listeners]`) are ignored.
    pub fn from_toml(text: &str) -> Result<Self, ClusterError> {
        #[derive(Deserialize)]
        struct Document {
            cluster: ClusterConfig,
        }

        let document: Document =
            toml::from_str(text).map_err(|error| ClusterError::RoleInvalid {
                reason: format!("invalid [cluster] config: {error}"),
            })?;
        document.cluster.validate()?;
        Ok(document.cluster)
    }

    /// Checks role ↔ config consistency and the field formats.
    ///
    /// - `standalone` forbids `listen` and `master_url`.
    /// - `master` requires `listen` + `node_id`; forbids `master_url`.
    /// - `sub_node` requires `master_url` + `node_id`; forbids `listen`.
    /// - the cluster bind must be loopback/private/ULA.
    /// - `node_id` must be a lowercase DNS label; `master_url` must be HTTPS.
    pub fn validate(&self) -> Result<(), ClusterError> {
        match self.role {
            Role::Standalone => {
                if self.listen.is_some() {
                    return Err(role_error("standalone must not configure cluster.listen"));
                }
                if self.master_url.is_some() {
                    return Err(role_error("standalone must not configure master_url"));
                }
            }
            Role::Master => {
                if self.master_url.is_some() {
                    return Err(role_error("master must not configure master_url"));
                }
                if self.listen.is_none() {
                    return Err(role_error("master requires cluster.listen"));
                }
                validate_node_id(&self.node_id)?;
            }
            Role::SubNode => {
                if self.listen.is_some() {
                    return Err(role_error(
                        "sub_node must not configure cluster.listen (outbound only)",
                    ));
                }
                validate_node_id(&self.node_id)?;
                let Some(master_url) = self.master_url.as_deref() else {
                    return Err(role_error("sub_node requires master_url"));
                };
                check_https_url(master_url, false, "cluster.master_url").map_err(role_error)?;
            }
        }

        if let Some(listen) = &self.listen {
            listen.validate()?;
        }
        Ok(())
    }
}

/// The master-only inbound cluster listener (`[cluster.listen]`).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListenConfig {
    /// Bind address; loopback, RFC 1918 private, CGNAT, link-local or ULA only.
    pub bind: IpAddr,
    /// Bind port.
    #[serde(default = "default_cluster_port")]
    pub port: u16,
}

impl ListenConfig {
    fn validate(&self) -> Result<(), ClusterError> {
        if self.bind.is_unspecified() {
            return Err(role_error("cluster.listen.bind must not be 0.0.0.0 or ::"));
        }
        if !is_private(self.bind) {
            return Err(role_error(
                "cluster.listen.bind must be a loopback or private/ULA address",
            ));
        }
        if self.port == 0 {
            return Err(role_error("cluster.listen.port must not be 0"));
        }
        Ok(())
    }
}

/// `[cluster.join]` (master only).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JoinConfig {
    /// One-time join-token lifetime.
    #[serde(default = "default_token_ttl", deserialize_with = "de_duration")]
    pub token_ttl: Duration,
    /// Issued node-certificate lifetime.
    #[serde(default = "default_node_cert_ttl", deserialize_with = "de_duration")]
    pub node_cert_ttl: Duration,
}

impl Default for JoinConfig {
    fn default() -> Self {
        Self {
            token_ttl: DEFAULT_TOKEN_TTL,
            node_cert_ttl: DEFAULT_NODE_CERT_TTL,
        }
    }
}

/// `[cluster.timing]`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TimingConfig {
    /// Heartbeat interval.
    #[serde(
        default = "default_heartbeat_interval",
        deserialize_with = "de_duration"
    )]
    pub heartbeat_interval: Duration,
    /// Timeout waiting for a master response.
    #[serde(default = "default_master_timeout", deserialize_with = "de_duration")]
    pub master_timeout: Duration,
    /// Deadline for a sub-node to apply and ack a snapshot.
    #[serde(
        default = "default_config_apply_timeout",
        deserialize_with = "de_duration"
    )]
    pub config_apply_timeout: Duration,
    /// Reconnect backoff floor.
    #[serde(
        default = "default_reconnect_backoff",
        deserialize_with = "de_duration"
    )]
    pub reconnect_backoff: Duration,
    /// Reconnect backoff ceiling.
    #[serde(
        default = "default_reconnect_backoff_max",
        deserialize_with = "de_duration"
    )]
    pub reconnect_backoff_max: Duration,
}

impl Default for TimingConfig {
    fn default() -> Self {
        Self {
            heartbeat_interval: DEFAULT_HEARTBEAT_INTERVAL,
            master_timeout: DEFAULT_MASTER_TIMEOUT,
            config_apply_timeout: DEFAULT_CONFIG_APPLY_TIMEOUT,
            reconnect_backoff: DEFAULT_RECONNECT_BACKOFF,
            reconnect_backoff_max: DEFAULT_RECONNECT_BACKOFF_MAX,
        }
    }
}

/// `[cluster.offline_writes]`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OfflineWritesConfig {
    /// Whether keyed config writes may be buffered while the master is down.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Queue capacity, 1–10000.
    #[serde(default = "default_queue_max_entries")]
    pub queue_max_entries: u32,
    /// Maximum age of a queued write; older rows are dropped.
    #[serde(
        default = "default_offline_write_max_age",
        deserialize_with = "de_duration"
    )]
    pub max_age: Duration,
}

impl Default for OfflineWritesConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            queue_max_entries: DEFAULT_QUEUE_MAX_ENTRIES,
            max_age: DEFAULT_OFFLINE_WRITE_MAX_AGE,
        }
    }
}

/// `[cluster.log]`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogConfig {
    /// Local buffer retention, 1 h–7 d.
    #[serde(default = "default_buffer_retention", deserialize_with = "de_duration")]
    pub buffer_retention: Duration,
    /// Records per batch, 50–5000.
    #[serde(default = "default_batch_max_records")]
    pub batch_max_records: u32,
    /// Batch flush interval, 100 ms–10 s.
    #[serde(default = "default_batch_interval", deserialize_with = "de_duration")]
    pub batch_interval: Duration,
    /// Maximum batch size in bytes, 64 KiB–16 MiB.
    #[serde(default = "default_max_batch_bytes", deserialize_with = "de_byte_size")]
    pub max_batch_bytes: u64,
    /// Maximum in-flight batches, 1–16.
    #[serde(default = "default_max_inflight_batches")]
    pub max_inflight_batches: u32,
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            buffer_retention: DEFAULT_BUFFER_RETENTION,
            batch_max_records: DEFAULT_BATCH_MAX_RECORDS,
            batch_interval: DEFAULT_BATCH_INTERVAL,
            max_batch_bytes: DEFAULT_MAX_BATCH_BYTES,
            max_inflight_batches: DEFAULT_MAX_INFLIGHT_BATCHES,
        }
    }
}

/// `[cluster.quota]` (per-node limits enforced on the master).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QuotaConfig {
    /// Relay requests per second, 1–1000.
    #[serde(default = "default_max_relay_requests_per_second")]
    pub max_relay_requests_per_second: u32,
    /// Log bytes per second, 64 KiB/s–64 MiB/s.
    #[serde(
        default = "default_max_log_bytes_per_second",
        deserialize_with = "de_byte_size"
    )]
    pub max_log_bytes_per_second: u64,
    /// Maximum queued offline writes; must not exceed `queue_max_entries`.
    #[serde(default = "default_max_queued_offline_writes")]
    pub max_queued_offline_writes: u32,
    /// Clock-skew warning threshold, 30 s–1 h.
    #[serde(
        default = "default_clock_skew_warning",
        deserialize_with = "de_duration"
    )]
    pub clock_skew_warning: Duration,
}

impl Default for QuotaConfig {
    fn default() -> Self {
        Self {
            max_relay_requests_per_second: DEFAULT_MAX_RELAY_REQUESTS_PER_SECOND,
            max_log_bytes_per_second: DEFAULT_MAX_LOG_BYTES_PER_SECOND,
            max_queued_offline_writes: DEFAULT_MAX_QUEUED_OFFLINE_WRITES,
            clock_skew_warning: DEFAULT_CLOCK_SKEW_WARNING,
        }
    }
}

/// `[cluster.tls]` — cluster certificate/key paths.
///
/// The CA private key path is derived from `ca_cert` (`ca.pem` → `ca.key`) and
/// is never configured separately.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlsPaths {
    /// Cluster CA certificate (PEM).
    #[serde(default = "default_ca_cert")]
    pub ca_cert: PathBuf,
    /// This node's certificate (PEM).
    #[serde(default = "default_node_cert")]
    pub node_cert: PathBuf,
    /// This node's private key (PEM); prefer environment/`*_FILE` when deployed.
    #[serde(default = "default_node_key")]
    pub node_key: PathBuf,
}

impl Default for TlsPaths {
    fn default() -> Self {
        Self {
            ca_cert: default_ca_cert(),
            node_cert: default_node_cert(),
            node_key: default_node_key(),
        }
    }
}

/// Validates a cluster `node_id`: a lowercase DNS label of 1–63 characters.
pub(crate) fn validate_node_id(node_id: &str) -> Result<(), ClusterError> {
    let bytes = node_id.as_bytes();
    if bytes.is_empty() || bytes.len() > 63 {
        return Err(role_error("node_id must be a DNS label of 1-63 characters"));
    }
    if !bytes[0].is_ascii_lowercase() && !bytes[0].is_ascii_digit() {
        return Err(role_error(
            "node_id must start with a lowercase letter or digit",
        ));
    }
    if !bytes.last().is_some_and(u8::is_ascii_alphanumeric) {
        return Err(role_error(
            "node_id must end with a lowercase letter or digit",
        ));
    }
    if !bytes
        .iter()
        .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
    {
        return Err(role_error(
            "node_id may only contain lowercase letters, digits and '-'",
        ));
    }
    Ok(())
}

fn role_error(reason: impl Into<String>) -> ClusterError {
    ClusterError::RoleInvalid {
        reason: reason.into(),
    }
}

const fn default_cluster_port() -> u16 {
    DEFAULT_CLUSTER_PORT
}
const fn default_token_ttl() -> Duration {
    DEFAULT_TOKEN_TTL
}
const fn default_node_cert_ttl() -> Duration {
    DEFAULT_NODE_CERT_TTL
}
const fn default_heartbeat_interval() -> Duration {
    DEFAULT_HEARTBEAT_INTERVAL
}
const fn default_master_timeout() -> Duration {
    DEFAULT_MASTER_TIMEOUT
}
const fn default_config_apply_timeout() -> Duration {
    DEFAULT_CONFIG_APPLY_TIMEOUT
}
const fn default_reconnect_backoff() -> Duration {
    DEFAULT_RECONNECT_BACKOFF
}
const fn default_reconnect_backoff_max() -> Duration {
    DEFAULT_RECONNECT_BACKOFF_MAX
}
const fn default_true() -> bool {
    true
}
const fn default_queue_max_entries() -> u32 {
    DEFAULT_QUEUE_MAX_ENTRIES
}
const fn default_offline_write_max_age() -> Duration {
    DEFAULT_OFFLINE_WRITE_MAX_AGE
}
const fn default_buffer_retention() -> Duration {
    DEFAULT_BUFFER_RETENTION
}
const fn default_batch_max_records() -> u32 {
    DEFAULT_BATCH_MAX_RECORDS
}
const fn default_batch_interval() -> Duration {
    DEFAULT_BATCH_INTERVAL
}
const fn default_max_batch_bytes() -> u64 {
    DEFAULT_MAX_BATCH_BYTES
}
const fn default_max_inflight_batches() -> u32 {
    DEFAULT_MAX_INFLIGHT_BATCHES
}
const fn default_max_relay_requests_per_second() -> u32 {
    DEFAULT_MAX_RELAY_REQUESTS_PER_SECOND
}
const fn default_max_log_bytes_per_second() -> u64 {
    DEFAULT_MAX_LOG_BYTES_PER_SECOND
}
const fn default_max_queued_offline_writes() -> u32 {
    DEFAULT_MAX_QUEUED_OFFLINE_WRITES
}
const fn default_clock_skew_warning() -> Duration {
    DEFAULT_CLOCK_SKEW_WARNING
}
fn default_ca_cert() -> PathBuf {
    PathBuf::from("data/cluster/ca.pem")
}
fn default_node_cert() -> PathBuf {
    PathBuf::from("data/cluster/node.pem")
}
fn default_node_key() -> PathBuf {
    PathBuf::from("data/cluster/node.key")
}

/// Deserializes a human duration (`30s`, `15m`, `24h`, `90d`, `100ms`).
fn de_duration<'de, D>(deserializer: D) -> Result<Duration, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;
    parse_duration(&value).map_err(serde::de::Error::custom)
}

/// Deserializes a human byte size (`64KiB`, `1MiB`, `2MiB`, `16MiB`).
fn de_byte_size<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;
    parse_byte_size(&value).map_err(serde::de::Error::custom)
}

fn parse_duration(value: &str) -> Result<Duration, String> {
    let value = value.trim();
    let (number, unit) = if let Some(number) = value.strip_suffix("ms") {
        (number, "ms")
    } else if let Some(number) = value.strip_suffix('s') {
        (number, "s")
    } else if let Some(number) = value.strip_suffix('m') {
        (number, "m")
    } else if let Some(number) = value.strip_suffix('h') {
        (number, "h")
    } else if let Some(number) = value.strip_suffix('d') {
        (number, "d")
    } else {
        return Err(format!("duration {value:?} needs a unit (s, m, h, d)"));
    };
    let number: u64 = number
        .trim()
        .parse()
        .map_err(|_| format!("invalid duration {value:?}"))?;
    if unit == "ms" {
        return Ok(Duration::from_millis(number));
    }
    let seconds = match unit {
        "s" => Some(number),
        "m" => number.checked_mul(60),
        "h" => number.checked_mul(60 * 60),
        "d" => number.checked_mul(24 * 60 * 60),
        _ => unreachable!("unit is one of ms/s/m/h/d"),
    };
    seconds
        .map(Duration::from_secs)
        .ok_or_else(|| format!("duration {value:?} is too large"))
}

fn parse_byte_size(value: &str) -> Result<u64, String> {
    let value = value.trim();
    let units = [
        ("GiB", 1024_u64 * 1024 * 1024),
        ("MiB", 1024_u64 * 1024),
        ("KiB", 1024_u64),
        ("B", 1_u64),
    ];
    for (suffix, multiplier) in units {
        if let Some(number) = value.strip_suffix(suffix) {
            let number: u64 = number
                .trim()
                .parse()
                .map_err(|_| format!("invalid byte size {value:?}"))?;
            return number
                .checked_mul(multiplier)
                .ok_or_else(|| format!("byte size {value:?} is too large"));
        }
    }
    Err(format!(
        "byte size {value:?} needs a unit (B, KiB, MiB, GiB)"
    ))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn parse(top: &str) -> Result<ClusterConfig, ClusterError> {
        ClusterConfig::from_toml(&format!("[cluster]\n{top}"))
    }

    const MASTER: &str = r#"
role = "master"
node_id = "node-a"

[cluster.listen]
bind = "10.0.0.5"
"#;

    const SUB_NODE: &str = r#"
role = "sub_node"
node_id = "node-a"
master_url = "https://master.example.com:8443"
"#;

    #[test]
    fn valid_roles_parse() {
        assert_eq!(
            parse("role = \"standalone\"").unwrap().role,
            Role::Standalone
        );
        assert_eq!(parse(MASTER).unwrap().role, Role::Master);
        assert_eq!(parse(SUB_NODE).unwrap().role, Role::SubNode);
        // `role` defaults to standalone.
        assert_eq!(parse("").unwrap().role, Role::Standalone);
    }

    #[test]
    fn standalone_forbids_listener_and_master_url() {
        let err = parse(
            r#"
role = "standalone"

[cluster.listen]
bind = "127.0.0.1"
"#,
        )
        .unwrap_err();
        assert_eq!(err.code(), "cluster.role.invalid");

        let err = parse(
            r#"
role = "standalone"
master_url = "https://master.example.com:8443"
"#,
        )
        .unwrap_err();
        assert_eq!(err.code(), "cluster.role.invalid");
    }

    #[test]
    fn sub_node_requires_master_url_and_node_id() {
        let err = parse(
            r#"
role = "sub_node"
node_id = "node-a"
"#,
        )
        .unwrap_err();
        assert_eq!(err.code(), "cluster.role.invalid");

        let err = parse(
            r#"
role = "sub_node"
master_url = "https://master.example.com:8443"
"#,
        )
        .unwrap_err();
        assert_eq!(err.code(), "cluster.role.invalid");
    }

    #[test]
    fn sub_node_forbids_listener() {
        let err = parse(
            r#"
role = "sub_node"
node_id = "node-a"
master_url = "https://master.example.com:8443"

[cluster.listen]
bind = "127.0.0.1"
"#,
        )
        .unwrap_err();
        assert_eq!(err.code(), "cluster.role.invalid");
    }

    #[test]
    fn master_requires_listener_and_node_id_and_forbids_master_url() {
        let err = parse(
            r#"
role = "master"
node_id = "node-a"
"#,
        )
        .unwrap_err();
        assert_eq!(err.code(), "cluster.role.invalid");

        let err = parse(
            r#"
role = "master"

[cluster.listen]
bind = "127.0.0.1"
"#,
        )
        .unwrap_err();
        assert_eq!(err.code(), "cluster.role.invalid");

        let err = parse(
            r#"
role = "master"
node_id = "node-a"
master_url = "https://master.example.com:8443"

[cluster.listen]
bind = "127.0.0.1"
"#,
        )
        .unwrap_err();
        assert_eq!(err.code(), "cluster.role.invalid");
    }

    #[test]
    fn node_id_must_be_a_lowercase_dns_label() {
        let valid = ["a", "node-a", "abc123", "0", &"a".repeat(63)];
        for node_id in valid {
            assert!(
                parse(&format!("role = \"master\"\nnode_id = \"{node_id}\"\n[cluster.listen]\nbind = \"127.0.0.1\"\n")).is_ok(),
                "{node_id} should be valid"
            );
        }

        let invalid = [
            "",
            "Node-A",
            "node_a",
            "-node",
            "node-",
            "node.a",
            &"a".repeat(64),
            "nöde",
        ];
        for node_id in invalid {
            let err = parse(&format!(
                "role = \"master\"\nnode_id = \"{node_id}\"\n[cluster.listen]\nbind = \"127.0.0.1\"\n"
            ))
            .unwrap_err();
            assert_eq!(err.code(), "cluster.role.invalid", "{node_id:?}");
        }
    }

    #[test]
    fn master_url_must_be_https() {
        let err = parse(
            r#"
role = "sub_node"
node_id = "node-a"
master_url = "http://master.example.com:8443"
"#,
        )
        .unwrap_err();
        assert_eq!(err.code(), "cluster.role.invalid");
    }

    #[test]
    fn bind_must_be_loopback_or_private() {
        for bind in ["127.0.0.1", "::1", "10.1.2.3", "192.168.1.10", "fd00::1"] {
            assert!(
                parse(&format!(
                    "role = \"master\"\nnode_id = \"node-a\"\n[cluster.listen]\nbind = \"{bind}\"\n"
                ))
                .is_ok(),
                "{bind} should be accepted"
            );
        }
        for bind in ["0.0.0.0", "::", "8.8.8.8", "2001:db8::1"] {
            let err = parse(&format!(
                "role = \"master\"\nnode_id = \"node-a\"\n[cluster.listen]\nbind = \"{bind}\"\n"
            ))
            .unwrap_err();
            assert_eq!(err.code(), "cluster.role.invalid", "{bind}");
        }
    }

    #[test]
    fn defaults_match_the_spec() {
        let config = parse(MASTER).unwrap();
        assert_eq!(config.join.token_ttl, Duration::from_secs(15 * 60));
        assert_eq!(
            config.join.node_cert_ttl,
            Duration::from_secs(90 * 24 * 3600)
        );
        assert_eq!(config.timing.heartbeat_interval, Duration::from_secs(10));
        assert_eq!(config.timing.reconnect_backoff_max, Duration::from_secs(60));
        assert!(config.offline_writes.enabled);
        assert_eq!(config.offline_writes.queue_max_entries, 100);
        assert_eq!(
            config.offline_writes.max_age,
            Duration::from_secs(24 * 3600)
        );
        assert_eq!(config.log.batch_max_records, 500);
        assert_eq!(config.log.max_batch_bytes, 1024 * 1024);
        assert_eq!(config.log.max_inflight_batches, 4);
        assert_eq!(config.quota.max_log_bytes_per_second, 2 * 1024 * 1024);
        assert_eq!(config.quota.clock_skew_warning, Duration::from_secs(300));
        assert_eq!(config.listen.unwrap().port, 8443);
    }

    #[test]
    fn full_excerpt_parses() {
        let text = r#"
[cluster]
role = "master"
node_id = "node-a"

[cluster.listen]
bind = "10.0.0.5"
port = 8443

[cluster.join]
token_ttl = "15m"
node_cert_ttl = "90d"

[cluster.timing]
heartbeat_interval = "10s"
master_timeout = "5s"
config_apply_timeout = "30s"
reconnect_backoff = "1s"
reconnect_backoff_max = "60s"

[cluster.offline_writes]
enabled = true
queue_max_entries = 100
max_age = "24h"

[cluster.log]
buffer_retention = "24h"
batch_max_records = 500
batch_interval = "1s"
max_batch_bytes = "1MiB"
max_inflight_batches = 4

[cluster.quota]
max_relay_requests_per_second = 50
max_log_bytes_per_second = "2MiB"
max_queued_offline_writes = 100
clock_skew_warning = "5m"

[cluster.tls]
ca_cert = "data/cluster/ca.pem"
node_cert = "data/cluster/node.pem"
node_key = "data/cluster/node.key"
"#;
        let config = ClusterConfig::from_toml(text).unwrap();
        assert_eq!(config.role, Role::Master);
        assert_eq!(config.node_id, "node-a");
        assert_eq!(config.join.token_ttl, DEFAULT_TOKEN_TTL);
        assert_eq!(config.log.max_batch_bytes, DEFAULT_MAX_BATCH_BYTES);
        assert_eq!(config.tls.ca_cert, PathBuf::from("data/cluster/ca.pem"));
    }

    #[test]
    fn durations_and_byte_sizes_parse() {
        assert_eq!(parse_duration("100ms").unwrap(), Duration::from_millis(100));
        assert_eq!(parse_duration("30s").unwrap(), Duration::from_secs(30));
        assert_eq!(parse_duration("15m").unwrap(), Duration::from_secs(900));
        assert_eq!(
            parse_duration("90d").unwrap(),
            Duration::from_secs(7_776_000)
        );
        assert!(parse_duration("5").is_err());
        assert!(parse_byte_size("1MiB").unwrap() == 1024 * 1024);
        assert!(parse_byte_size("64KiB").unwrap() == 64 * 1024);
        assert!(parse_byte_size("2GiB").unwrap() == 2 * 1024 * 1024 * 1024);
        assert!(parse_byte_size("12").is_err());
    }

    #[test]
    fn unknown_keys_are_rejected() {
        let err = parse(
            r#"
role = "standalone"
surprise = true
"#,
        )
        .unwrap_err();
        assert_eq!(err.code(), "cluster.role.invalid");
    }
}
