//! TOML bootstrap and environment secrets.

use std::env;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use dnscraft_api::ControlApiConfig;
pub use dnscraft_api::IpTruncate;
use dnscraft_clients::ClientsConfig;
use dnscraft_cluster::ClusterConfig;
use dnscraft_filtering::FilterConfig;
use dnscraft_listeners::{
    DdrConfig, Exposure, Limits, ListenerConfig, ListenersConfig, Protocol, PublicConfig, TlsPolicy,
};
use dnscraft_policy::{IdError, ListenerId, NodeId, PolicyConfig};
use dnscraft_resolver::ResolverConfig;
use dnscraft_tls::{Secret, TlsConfig};

use crate::Error;

/// TLS secret material loaded from the environment (never the TOML file).
///
/// The PEM fields are wrapped in [`Secret`] so they never appear in `Debug`
/// output and are zeroized on drop.
#[derive(Debug)]
pub struct TlsSecrets {
    /// PEM certificate chain.
    pub chain_pem: Secret,
    /// PEM private key.
    pub key_pem: Secret,
}

/// Environment variable holding the PEM certificate chain.
pub const TLS_CERT_ENV: &str = "DNSCRAFT_TLS_CERT";
/// Environment variable holding the path to a PEM certificate chain file.
pub const TLS_CERT_FILE_ENV: &str = "DNSCRAFT_TLS_CERT_FILE";
/// Environment variable holding the PEM private key.
pub const TLS_KEY_ENV: &str = "DNSCRAFT_TLS_KEY";
/// Environment variable holding the path to a PEM private key file.
pub const TLS_KEY_FILE_ENV: &str = "DNSCRAFT_TLS_KEY_FILE";

/// Reads the TLS PEM pair from the environment.
///
/// Each secret has exactly one source: the PEM-in-env variable or the
/// `*_FILE` path variable (both set → `dnscraft.config.tls_env_conflict`).
/// Returns `None` when neither secret is configured and
/// `dnscraft.config.tls_env_incomplete` when only one of the pair is.
pub fn tls_secrets_from_env() -> Result<Option<TlsSecrets>, Error> {
    tls_secrets_from_parts(
        env::var(TLS_CERT_ENV).ok().as_deref(),
        env::var(TLS_CERT_FILE_ENV).ok().as_deref(),
        env::var(TLS_KEY_ENV).ok().as_deref(),
        env::var(TLS_KEY_FILE_ENV).ok().as_deref(),
        |path| std::fs::read_to_string(path),
    )
}

/// Core secret resolution used by [`tls_secrets_from_env`] and tests (no
/// process-environment mutation — the workspace forbids `unsafe`, and
/// `set_var` is unsafe on current Rust).
pub(crate) fn tls_secrets_from_parts(
    cert_env: Option<&str>,
    cert_file: Option<&str>,
    key_env: Option<&str>,
    key_file: Option<&str>,
    read_file: impl Fn(&Path) -> std::io::Result<String>,
) -> Result<Option<TlsSecrets>, Error> {
    let chain = resolve_one(
        "certificate chain",
        TLS_CERT_ENV,
        TLS_CERT_FILE_ENV,
        cert_env,
        cert_file,
        &read_file,
    )?;
    let key = resolve_one(
        "private key",
        TLS_KEY_ENV,
        TLS_KEY_FILE_ENV,
        key_env,
        key_file,
        &read_file,
    )?;

    match (chain, key) {
        (None, None) => Ok(None),
        (Some(chain_pem), Some(key_pem)) => {
            if let Some(warning) = key_file
                .map(str::trim)
                .filter(|p| !p.is_empty())
                .and_then(key_file_permissions_warning)
            {
                tracing::warn!("{warning}");
            }
            Ok(Some(TlsSecrets { chain_pem, key_pem }))
        }
        _ => Err(Error::config(
            "dnscraft.config.tls_env_incomplete",
            format!(
                "set both {TLS_CERT_ENV}/{TLS_CERT_FILE_ENV} and {TLS_KEY_ENV}/{TLS_KEY_FILE_ENV}"
            ),
        )),
    }
}

fn resolve_one(
    name: &str,
    env_name: &str,
    file_name: &str,
    env_value: Option<&str>,
    file_value: Option<&str>,
    read_file: &impl Fn(&Path) -> std::io::Result<String>,
) -> Result<Option<Secret>, Error> {
    let env_value = env_value.map(str::trim).filter(|s| !s.is_empty());
    let file_value = file_value.map(str::trim).filter(|s| !s.is_empty());
    match (env_value, file_value) {
        (Some(_), Some(_)) => Err(Error::config(
            "dnscraft.config.tls_env_conflict",
            format!("set exactly one of {env_name} or {file_name} for the {name}"),
        )),
        (Some(value), None) => Ok(Some(Secret::new(value))),
        (None, Some(path)) => {
            let contents = read_file(Path::new(path)).map_err(|e| {
                Error::config(
                    "dnscraft.config.tls_env_incomplete",
                    format!("read {file_name} `{path}`: {e}"),
                )
            })?;
            let trimmed = contents.trim();
            if trimmed.is_empty() {
                return Err(Error::config(
                    "dnscraft.config.tls_env_incomplete",
                    format!("{file_name} `{path}` is empty"),
                ));
            }
            Ok(Some(Secret::new(trimmed)))
        }
        (None, None) => Ok(None),
    }
}

/// Environment variable holding the one-time join token for sub-node enrollment.
pub const CLUSTER_JOIN_TOKEN_ENV: &str = "DNSCRAFT_CLUSTER_JOIN_TOKEN";
/// Environment variable holding the path to a file with the join token.
pub const CLUSTER_JOIN_TOKEN_FILE_ENV: &str = "DNSCRAFT_CLUSTER_JOIN_TOKEN_FILE";
/// Environment variable holding the path to the master's pinned certificate (PEM).
pub const CLUSTER_MASTER_CERT_FILE_ENV: &str = "DNSCRAFT_CLUSTER_MASTER_CERT_FILE";

/// Sub-node enrollment material. Secrets come from the environment only, never
/// from the TOML file.
#[derive(Debug, Default)]
pub struct Enrollment {
    /// One-time join token minted on the master for this node's `node_id`.
    pub join_token: Option<Secret>,
    /// Pinned master certificate (PEM), used only for the first enrollment.
    pub master_cert_pem: Option<String>,
}

/// Reads the enrollment material from the environment.
///
/// The join token has one source: `DNSCRAFT_CLUSTER_JOIN_TOKEN` or the
/// `*_FILE` path (both set is an error). Unset variables yield `None`; a
/// sub-node that already has an identity on disk never needs them.
pub fn enrollment_from_env() -> Result<Enrollment, Error> {
    let env_value = |name: &str| env::var(name).ok().map(|v| v.trim().to_owned());
    let token = env_value(CLUSTER_JOIN_TOKEN_ENV).filter(|v| !v.is_empty());
    let token_file = env_value(CLUSTER_JOIN_TOKEN_FILE_ENV).filter(|v| !v.is_empty());
    let join_token = match (token, token_file) {
        (Some(_), Some(_)) => {
            return Err(Error::config(
                "dnscraft.config.cluster_env",
                format!(
                    "set only one of {CLUSTER_JOIN_TOKEN_ENV} or {CLUSTER_JOIN_TOKEN_FILE_ENV}"
                ),
            ));
        }
        (Some(token), None) => Some(Secret::new(token)),
        (None, Some(path)) => Some(Secret::new(
            read_env_file(CLUSTER_JOIN_TOKEN_FILE_ENV, &path)?
                .trim()
                .to_owned(),
        )),
        (None, None) => None,
    };
    let master_cert_pem = match env_value(CLUSTER_MASTER_CERT_FILE_ENV).filter(|v| !v.is_empty()) {
        Some(path) => Some(read_env_file(CLUSTER_MASTER_CERT_FILE_ENV, &path)?),
        None => None,
    };
    Ok(Enrollment {
        join_token,
        master_cert_pem,
    })
}

/// Reads one secret or certificate file named by an environment variable.
fn read_env_file(env_name: &str, path: &str) -> Result<String, Error> {
    std::fs::read_to_string(path).map_err(|e| {
        Error::config(
            "dnscraft.config.cluster_env",
            format!("read {env_name} `{path}`: {e}"),
        )
    })
}

/// Whether the key file's permissions are too open (group/other readable).
#[cfg(unix)]
fn key_file_permissions_warning(path: &str) -> Option<String> {
    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::metadata(path).ok()?.permissions().mode();
    (mode & 0o077 != 0).then(|| {
        format!("TLS key file `{path}` is group/other readable (mode {mode:o}); recommend 0600")
    })
}

#[cfg(not(unix))]
fn key_file_permissions_warning(_path: &str) -> Option<String> {
    None
}

/// Top-level configuration loaded from a TOML file.
///
/// Every module section is optional: an omitted section takes the module
/// config type's [`Default`]. Present sections are deserialized field for
/// field, so the module type governs which keys are required once its table
/// appears.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Cluster node identity of this process (`node_id`). Views with `nodes`
    /// match it. Omitted means a standalone install, which is `local`.
    #[serde(default)]
    pub node_id: Option<String>,
    /// Public DNS domain for SNI / DDR (`dns.<domain>`).
    pub public_domain: String,
    /// Directory for the SQLite store, TLS state and filter-list bodies.
    #[serde(default)]
    pub data_dir: Option<PathBuf>,
    /// Listeners to serve (at least one in practice).
    #[serde(default)]
    pub listeners: Vec<ListenerToml>,
    /// Keep the listener-set partial-bind behaviour (report bind failures in
    /// status and keep the other listeners). Default `false`: any bind failure
    /// is fatal (`dnscraft.startup.bind`).
    #[serde(default)]
    pub allow_partial_bind: bool,
    /// Query-log settings.
    #[serde(default)]
    pub log: LogConfig,
    /// Recursive resolver settings (`[resolver]`).
    #[serde(default)]
    pub resolver: ResolverConfig,
    /// Filter-list and filter-set settings (`[filtering]`).
    #[serde(default)]
    pub filtering: FilterConfig,
    /// Client directory settings (`[clients]`).
    #[serde(default)]
    pub clients: ClientsConfig,
    /// TLS management settings (`[tls]`).
    #[serde(default)]
    pub tls: TlsConfig,
    /// Policy (views, profiles, records) settings (`[policy]`).
    #[serde(default)]
    pub policy: PolicyConfig,
    /// Public-exposure gate and ban policy (`[listeners_public]`).
    #[serde(default)]
    pub listeners_public: PublicConfig,
    /// Shared listener limits (`[listeners_limits]`).
    #[serde(default)]
    pub listeners_limits: Limits,
    /// DDR discovery settings (`[listeners_ddr]`).
    #[serde(default)]
    pub listeners_ddr: DdrConfig,
    /// Control API settings (`[control_api]`).
    #[serde(default)]
    pub control_api: ControlApiConfig,
    /// Cluster role and node-local bootstrap settings (`[cluster]`). Absent or
    /// `role = "standalone"` keeps the cluster idle.
    #[serde(default)]
    pub cluster: Option<ClusterConfig>,
}

/// Query-log settings (`[log]`).
///
/// Persistence is controlled by `[control_api.query_log]`; this section only
/// covers the optional stdout debug writer.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogConfig {
    /// Also write one JSON object per answered query to stdout. Default `false`
    /// (the SQLite query log is the default sink; stdout is opt-in debug).
    #[serde(default)]
    pub queries: bool,
    /// Source-IP truncation: `none`, `last_octet` or `last_group`.
    /// Default `last_octet` (D6).
    #[serde(default = "default_ip_truncate")]
    pub ip_truncate: String,
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            queries: false,
            ip_truncate: default_ip_truncate(),
        }
    }
}

fn default_ip_truncate() -> String {
    "last_octet".to_owned()
}

/// Resolved query-log settings (validated values).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LogSettings {
    /// Whether the stdout JSON-lines debug writer is enabled.
    pub queries: bool,
    /// Source-IP truncation for the stdout lines.
    pub ip_truncate: IpTruncate,
}

/// One listener entry in the TOML file.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListenerToml {
    /// Unique listener id (`[a-z0-9-]{1,64}`).
    pub id: String,
    /// Transport: `udp53`, `tcp53`, `dot`, `doh`, `doq`.
    pub protocol: String,
    /// Bind address (`host:port`; port `0` picks an ephemeral port).
    pub address: SocketAddr,
    /// `local` (default) or `public` (encrypted transports only).
    #[serde(default = "default_exposure")]
    pub exposure: String,
    /// DoH only: also serve HTTP/3 on the same UDP port.
    #[serde(default)]
    pub h3: bool,
    /// Encrypted listeners only: TLS protocol / cipher policy.
    #[serde(default)]
    pub tls_policy: Option<TlsPolicyToml>,
}

/// `[listeners.tls_policy]` block (encrypted listeners only).
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlsPolicyToml {
    /// `"1.2"` (default) or `"1.3"`.
    #[serde(default = "default_min_tls_version")]
    pub min_version: String,
    /// Ring cipher suites by IANA name; absent = provider defaults.
    #[serde(default)]
    pub ciphersuites: Option<Vec<String>>,
    /// ALPN for DoH over TCP; absent = `["h2", "http/1.1"]`.
    #[serde(default)]
    pub alpn: Option<Vec<String>>,
}

fn default_exposure() -> String {
    "local".to_owned()
}

fn default_min_tls_version() -> String {
    dnscraft_listeners::DEFAULT_TLS_MIN_VERSION.to_owned()
}

impl TlsPolicyToml {
    fn into_policy(self) -> TlsPolicy {
        let defaults = TlsPolicy::default();
        TlsPolicy {
            min_version: self.min_version,
            ciphersuites: self.ciphersuites,
            alpn: self.alpn.unwrap_or(defaults.alpn),
        }
    }
}

impl Config {
    /// Directory for the SQLite store, TLS state and filter-list bodies.
    pub fn data_dir(&self) -> Option<&Path> {
        self.data_dir.as_deref()
    }

    /// The node id this process serves as: `node_id`, or `local` when unset.
    pub fn node_id(&self) -> Result<NodeId, IdError> {
        NodeId::new(self.node_id.as_deref().unwrap_or("local"))
    }

    /// Maps this TOML config onto a [`ListenersConfig`].
    ///
    /// `[listeners_limits]`, `[listeners_public]` and `[listeners_ddr]` are
    /// embedded as-is. Public exposure is gated only by
    /// `listeners_public.enabled` (GL2), never inferred from a listener's
    /// `exposure`; [`ListenersConfig::validate`] rejects a public listener
    /// when the gate is closed.
    pub fn listeners_config(&self) -> Result<ListenersConfig, Error> {
        let mut listeners = Vec::with_capacity(self.listeners.len());
        for listener in &self.listeners {
            let id = ListenerId::new(&listener.id).map_err(|_| {
                Error::config(
                    "dnscraft.config.invalid_listener",
                    format!("invalid listener id `{}`", listener.id),
                )
            })?;
            let protocol = parse_protocol(&listener.protocol).ok_or_else(|| {
                Error::config(
                    "dnscraft.config.invalid_listener",
                    format!(
                        "unknown protocol `{}` for listener `{}`",
                        listener.protocol, listener.id
                    ),
                )
            })?;
            let exposure = parse_exposure(&listener.exposure).ok_or_else(|| {
                Error::config(
                    "dnscraft.config.invalid_listener",
                    format!(
                        "unknown exposure `{}` for listener `{}`",
                        listener.exposure, listener.id
                    ),
                )
            })?;
            listeners.push(ListenerConfig {
                id,
                protocol,
                address: listener.address,
                exposure,
                h3: listener.h3,
                tls_policy: listener.tls_policy.clone().map(TlsPolicyToml::into_policy),
                node_id: None,
            });
        }
        let cfg = ListenersConfig {
            listeners,
            limits: self.listeners_limits.clone(),
            public: self.listeners_public.clone(),
            ddr: self.listeners_ddr.clone(),
        };
        cfg.validate()
            .map_err(|e| Error::config("dnscraft.config.invalid_listener", e.to_string()))?;
        Ok(cfg)
    }

    /// Validated query-log settings.
    pub fn log_settings(&self) -> Result<LogSettings, Error> {
        let ip_truncate = match self.log.ip_truncate.as_str() {
            "none" => IpTruncate::None,
            "last_octet" => IpTruncate::LastOctet,
            "last_group" => IpTruncate::LastGroup,
            other => {
                return Err(Error::config(
                    "dnscraft.config.invalid_log",
                    format!(
                        "ip_truncate must be `none`, `last_octet` or `last_group`, got `{other}`"
                    ),
                ));
            }
        };
        Ok(LogSettings {
            queries: self.log.queries,
            ip_truncate,
        })
    }
}

fn parse_protocol(s: &str) -> Option<Protocol> {
    match s {
        "udp53" => Some(Protocol::Udp53),
        "tcp53" => Some(Protocol::Tcp53),
        "dot" => Some(Protocol::Dot),
        "doh" => Some(Protocol::Doh),
        "doq" => Some(Protocol::Doq),
        _ => None,
    }
}

fn parse_exposure(s: &str) -> Option<Exposure> {
    match s {
        "local" => Some(Exposure::Local),
        "public" => Some(Exposure::Public),
        _ => None,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn tls_secrets_debug_is_redacted() {
        let secrets = TlsSecrets {
            chain_pem: Secret::new(
                "-----BEGIN CERTIFICATE-----\nchain-material\n-----END CERTIFICATE-----",
            ),
            key_pem: Secret::new(
                "-----BEGIN PRIVATE KEY-----\nsuper-secret-key\n-----END PRIVATE KEY-----",
            ),
        };
        let shown = format!("{secrets:?}");
        assert!(!shown.contains("super-secret-key"), "key leaked: {shown}");
        assert!(
            !shown.contains("BEGIN PRIVATE KEY"),
            "key PEM leaked: {shown}"
        );
        assert!(
            shown.contains("Secret([redacted])"),
            "missing marker: {shown}"
        );
    }

    #[test]
    fn half_configured_env_is_incomplete() {
        let err =
            tls_secrets_from_parts(Some("cert"), None, None, None, |_| unreachable!()).unwrap_err();
        assert_eq!(err.code(), "dnscraft.config.tls_env_incomplete");
    }

    #[test]
    fn both_sources_for_one_secret_is_a_conflict() {
        let err = tls_secrets_from_parts(
            Some("cert"),
            Some("/cert.pem"),
            None,
            None,
            |_| unreachable!(),
        )
        .unwrap_err();
        assert_eq!(err.code(), "dnscraft.config.tls_env_conflict");
    }

    #[test]
    fn file_sources_load_and_trim() {
        let dir = std::env::temp_dir().join("dnscraft-tls-secrets-test");
        let _ = std::fs::create_dir_all(&dir);
        let cert = dir.join("cert.pem");
        let key = dir.join("key.pem");
        std::fs::write(&cert, "-----BEGIN CERTIFICATE-----\nchain\n").unwrap();
        std::fs::write(&key, "-----BEGIN PRIVATE KEY-----\nkey\n").unwrap();

        let secrets = tls_secrets_from_parts(
            None,
            Some(cert.to_str().unwrap()),
            None,
            Some(key.to_str().unwrap()),
            |p| std::fs::read_to_string(p),
        )
        .unwrap()
        .expect("both file sources resolve");
        assert_eq!(
            secrets.chain_pem.expose(),
            "-----BEGIN CERTIFICATE-----\nchain"
        );
        assert_eq!(secrets.key_pem.expose(), "-----BEGIN PRIVATE KEY-----\nkey");

        let _ = std::fs::remove_file(&cert);
        let _ = std::fs::remove_file(&key);
    }

    #[cfg(unix)]
    #[test]
    fn key_file_permission_warning_detects_open_modes() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join("dnscraft-key-perm-test");
        let _ = std::fs::create_dir_all(&dir);
        let key = dir.join("key.pem");
        std::fs::write(&key, "k").unwrap();

        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(key_file_permissions_warning(key.to_str().unwrap()).is_none());

        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(key_file_permissions_warning(key.to_str().unwrap()).is_some());

        let _ = std::fs::remove_file(&key);
    }

    #[test]
    fn log_settings_rejects_unknown_ip_truncate() {
        let cfg = Config {
            public_domain: "example.com".into(),
            log: LogConfig {
                queries: true,
                ip_truncate: "everything".into(),
            },
            ..Config::default()
        };
        let err = cfg.log_settings().unwrap_err();
        assert_eq!(err.code(), "dnscraft.config.invalid_log");
    }

    #[test]
    fn ip_truncate_renders() {
        use std::net::IpAddr;
        assert_eq!(
            IpTruncate::None.truncate("192.0.2.10".parse::<IpAddr>().unwrap()),
            "192.0.2.10"
        );
        assert_eq!(
            IpTruncate::LastOctet.truncate("192.0.2.10".parse::<IpAddr>().unwrap()),
            "192.0.2.0"
        );
        assert_eq!(
            IpTruncate::LastGroup.truncate("2001:db8::1".parse::<IpAddr>().unwrap()),
            "2001:db8::"
        );
    }

    /// Every module section present, with documentation-range values and
    /// human-readable durations.
    const FULL_TOML: &str = r#"
public_domain = "example.com"
data_dir = "/var/lib/dnscraft"
allow_partial_bind = true

[[listeners]]
id = "lan"
protocol = "udp53"
address = "192.0.2.10:53"
exposure = "local"

[[listeners]]
id = "public-doh"
protocol = "doh"
address = "192.0.2.10:443"
exposure = "public"
h3 = true

[log]
queries = true
ip_truncate = "last_octet"

[resolver]
root_hints = ["192.0.2.53:53"]
query_timeout = "10s"
max_referral_depth = 16
max_queries_per_resolve = 64
max_nested_depth = 4
max_cname_chain = 16
qname_minimisation = true
negative_trust_anchors = ["example.com"]
cache_size_mb = 64
ttl_min = 0
ttl_max = 86400
serve_stale = "1d"
prefetch = true
ipv6_cooldown = "1m"
outgoing_ipv6 = true
forward_zones = []
max_concurrent_resolutions = 1024
allow_private_nameservers = false
root_reprime_interval = "1d"
resolve_deadline = "10s"

[resolver.trust_anchors]
anchors = []

[resolver.nameserver_addr_overrides]

[filtering]
lists = []
sets = []
update_interval = "1d"
max_list_size_mb = 64

[clients]
local_domain = "home.arpa"
local_domain_mode = "UnifiThenConfig"
offline_retain = "7d"
ipv6_address_ttl = "1d"
manual = []
allow_http_for_tests = false

[clients.unifi]
enabled = false
base_url = ""
poll_interval = "1m"
classic_clients = true
insecure_skip_verify = false

[tls]
public_domain = "example.com"
extra_sans = []
key_type = "EcdsaP256"
renew_before = "30d"
expiry_warn = "14d"

[tls.acme]
enabled = false
directory = "Production"
email = ""
propagation_timeout = "2m"
propagation_poll = "5s"

[tls.acme.account]
tos_agreed = false
auto_deactivate = false

[tls.dns_provider]
kind = "Cloudflare"
zones = []
manual_txt = []

[tls.dns_provider.cloudflare]

[tls.dyndns]
enabled = false
hostname = ""
public_entry = false
reserved_labels = []
interval = "5m"
echo_url = "https://example.com/"
ipv4 = true
ipv6 = true
proxied = false
interfaces = []
record_inventory = false

[tls.dyndns.ipv6_identifier]
mode = "Eui64"

[tls.notifications]
on_expiry = false
on_dyndns_failure = false

[policy]
default_rebind = true
ptr_prefixes = ["192.0.2.0/24", "2001:db8::/32"]
local_nxdomain_suffixes = ["example.com"]
rebind_check_forward_zones = []
views = []
profiles = []

[listeners_public]
enabled = true
ban_strikes = 5
ban_window = "10m"
ban_duration = "1h"
max_tracked_sources = 10000

[listeners_limits]
udp_payload_max = 1232
query_timeout = "5s"
tcp_idle_timeout = "10s"
tls_handshake_timeout = "5s"
max_inflight_per_listener = 1000
max_connections_per_listener = 1000
max_connections_per_source = 50
max_quic_streams_per_connection = 100
max_queries_per_connection = 100
rate_per_source = { per_second = 200, burst = 400 }
rate_per_client_id = { per_second = 50, burst = 100 }

[listeners_ddr]
enabled = true
target = "dns"

[control_api]
"#;

    #[test]
    fn full_toml_deserializes_all_sections() {
        let cfg: Config = toml::from_str(FULL_TOML).unwrap();

        assert_eq!(cfg.public_domain, "example.com");
        assert_eq!(cfg.data_dir(), Some(Path::new("/var/lib/dnscraft")));
        assert!(cfg.allow_partial_bind);
        assert_eq!(cfg.listeners.len(), 2);
        assert_eq!(cfg.listeners[0].protocol, "udp53");
        assert_eq!(cfg.listeners[1].exposure, "public");
        assert_eq!(cfg.log.ip_truncate, "last_octet");

        assert_eq!(
            cfg.resolver.query_timeout,
            std::time::Duration::from_secs(10)
        );
        assert_eq!(
            cfg.resolver.serve_stale,
            std::time::Duration::from_secs(86_400)
        );
        assert_eq!(
            cfg.filtering.update_interval,
            std::time::Duration::from_secs(86_400)
        );
        assert_eq!(cfg.clients.local_domain, "home.arpa");
        assert_eq!(
            cfg.clients.offline_retain,
            std::time::Duration::from_secs(7 * 24 * 3600)
        );
        assert_eq!(
            cfg.tls.renew_before,
            std::time::Duration::from_secs(30 * 24 * 3600)
        );
        assert_eq!(cfg.policy.ptr_prefixes.len(), 2);
        assert!(cfg.listeners_public.enabled);
        assert_eq!(
            cfg.listeners_limits.query_timeout,
            std::time::Duration::from_secs(5)
        );
        assert_eq!(cfg.listeners_ddr.target, "dns");
        assert_eq!(cfg.control_api, ControlApiConfig::default());

        // The embedded sections map straight onto the listener config.
        let listeners = cfg.listeners_config().unwrap();
        assert_eq!(listeners.listeners.len(), 2);
        assert!(listeners.public.enabled);
        assert_eq!(listeners.limits, cfg.listeners_limits);
    }

    #[test]
    fn minimal_toml_takes_module_defaults() {
        let cfg: Config = toml::from_str(r#"public_domain = "example.com""#).unwrap();

        assert_eq!(cfg.public_domain, "example.com");
        assert_eq!(cfg.data_dir(), None);
        assert!(cfg.listeners.is_empty());
        assert!(!cfg.allow_partial_bind);
        assert!(!cfg.log.queries);
        assert_eq!(cfg.log.ip_truncate, "last_octet");
        assert_eq!(cfg.resolver.cache_size_mb, 64);
        assert_eq!(
            cfg.resolver.query_timeout,
            std::time::Duration::from_millis(1500)
        );
        assert_eq!(cfg.filtering, FilterConfig::default());
        assert_eq!(cfg.clients, ClientsConfig::default());
        assert_eq!(cfg.tls, TlsConfig::default());
        assert_eq!(cfg.policy, PolicyConfig::default());
        assert_eq!(cfg.listeners_public, PublicConfig::default());
        assert_eq!(cfg.listeners_limits, Limits::default());
        assert_eq!(cfg.listeners_ddr, DdrConfig::default());
        assert_eq!(cfg.control_api, ControlApiConfig::default());
    }

    #[test]
    fn public_listener_requires_public_gate() {
        let cfg: Config = toml::from_str(
            r#"
public_domain = "example.com"

[[listeners]]
id = "public-doh"
protocol = "doh"
address = "192.0.2.10:443"
exposure = "public"
"#,
        )
        .unwrap();
        assert!(!cfg.listeners_public.enabled);
        let err = cfg.listeners_config().unwrap_err();
        assert_eq!(err.code(), "dnscraft.config.invalid_listener");
    }

    #[test]
    fn ip_truncate_defaults_to_last_octet() {
        assert_eq!(LogConfig::default().ip_truncate, "last_octet");
        let log: LogConfig = toml::from_str("").unwrap();
        assert_eq!(log.ip_truncate, "last_octet");
    }
}
