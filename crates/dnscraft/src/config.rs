//! TOML bootstrap and environment secrets.

use std::env;
use std::net::SocketAddr;
use std::path::Path;

use serde::Deserialize;

use dnscraft_listeners::{
    DdrConfig, Exposure, Limits, ListenerConfig, ListenersConfig, Protocol, PublicConfig,
};
use dnscraft_policy::ListenerId;
use dnscraft_tls::Secret;

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
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Public DNS domain for SNI / DDR (`dns.<domain>`).
    pub public_domain: String,
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
}

/// Query-log settings (`[log]`).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogConfig {
    /// Write one JSON object per answered query to stdout. Default `true`.
    #[serde(default = "default_true")]
    pub queries: bool,
    /// Source-IP truncation: `none`, `last_octet` or `last_group`.
    #[serde(default = "default_ip_truncate")]
    pub ip_truncate: String,
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            queries: true,
            ip_truncate: default_ip_truncate(),
        }
    }
}

fn default_true() -> bool {
    true
}

fn default_ip_truncate() -> String {
    "none".to_owned()
}

/// Source-IP truncation for query-log lines.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum IpTruncate {
    /// Keep the full source IP.
    #[default]
    None,
    /// IPv4: zero the last octet (`x.x.x.0`).
    LastOctet,
    /// IPv6: keep the first 48 bits (`a:b:c::`).
    LastGroup,
}

impl IpTruncate {
    /// Renders `ip` with this truncation applied.
    pub fn truncate(self, ip: std::net::IpAddr) -> String {
        use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
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

/// Resolved query-log settings (validated values).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LogSettings {
    /// Whether the query log is enabled.
    pub queries: bool,
    /// Source-IP truncation.
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
}

fn default_exposure() -> String {
    "local".to_owned()
}

impl Config {
    /// Maps this TOML config onto a [`ListenersConfig`] with security defaults
    /// (shared [`Limits::default`], public exposure enabled only when a
    /// listener explicitly opts in, DDR discovery on).
    pub fn listeners_config(&self) -> Result<ListenersConfig, Error> {
        let mut listeners = Vec::with_capacity(self.listeners.len());
        let mut public = false;
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
            if exposure == Exposure::Public {
                public = true;
            }
            listeners.push(ListenerConfig {
                id,
                protocol,
                address: listener.address,
                exposure,
                h3: listener.h3,
            });
        }
        let cfg = ListenersConfig {
            listeners,
            limits: Limits::default(),
            public: PublicConfig {
                enabled: public,
                ..PublicConfig::default()
            },
            ddr: DdrConfig::default(),
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
            listeners: vec![],
            allow_partial_bind: false,
            log: LogConfig {
                queries: true,
                ip_truncate: "everything".into(),
            },
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
}
