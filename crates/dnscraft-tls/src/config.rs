//! TLS module configuration as Rust values.
//!
//! Bootstrap settings may arrive from TOML; the UI edits the same shapes.
//! [`TlsConfig::validate`] normalises domains and enforces the v1 rules from
//! SPEC-tls.md (empty `extra_sans`, DNS-only DynDNS, hostname under
//! `dns.<domain>`, ACME email when enabled, HTTPS-only URLs).

use std::net::IpAddr;
use std::time::Duration;

use crate::error::TlsError;
use crate::secret::{CLOUDFLARE_API_TOKEN_ENV, Secret, read_secret};

/// Default renew-before window: 30 days.
pub const DEFAULT_RENEW_BEFORE: Duration = Duration::from_secs(30 * 24 * 3600);
/// Default expiry warning threshold: 14 days.
pub const DEFAULT_EXPIRY_WARN: Duration = Duration::from_secs(14 * 24 * 3600);
/// Default ACME DNS-01 propagation timeout: 2 minutes.
pub const DEFAULT_PROPAGATION_TIMEOUT: Duration = Duration::from_secs(120);
/// Default ACME DNS-01 poll interval: 5 seconds.
pub const DEFAULT_PROPAGATION_POLL: Duration = Duration::from_secs(5);
/// Default DynDNS check interval: 5 minutes.
pub const DEFAULT_DYNDNS_INTERVAL: Duration = Duration::from_secs(5 * 60);
/// Default public IP echo URL (Cloudflare `cdn-cgi/trace`).
pub const DEFAULT_ECHO_URL: &str = "https://cloudflare.com/cdn-cgi/trace";

/// ECDSA key type for issued certificates. RSA is not supported.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum KeyType {
    /// NIST P-256 (default).
    #[default]
    EcdsaP256,
    /// NIST P-384.
    EcdsaP384,
}

/// Which ACME directory to use.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum AcmeDirectoryKind {
    /// Let's Encrypt production (`https://acme-v02.api.letsencrypt.org/directory`).
    #[default]
    Production,
    /// Let's Encrypt staging (untrusted roots; separate accounts).
    Staging,
    /// A custom directory URL (must be HTTPS, unless the test hatch is on).
    Url(String),
}

impl AcmeDirectoryKind {
    /// Resolves the directory URL string.
    pub fn url(&self) -> &str {
        match self {
            Self::Production => "https://acme-v02.api.letsencrypt.org/directory",
            Self::Staging => "https://acme-staging-v02.api.letsencrypt.org/directory",
            Self::Url(u) => u.as_str(),
        }
    }
}

/// ACME issuance settings.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AcmeConfig {
    /// When false, this node never creates ACME orders (sub-node / import-only).
    pub enabled: bool,
    /// ACME directory endpoint.
    pub directory: AcmeDirectoryKind,
    /// Contact email required by the CA when [`Self::enabled`] is true.
    pub email: String,
    /// How long to wait for TXT visibility on authoritative nameservers.
    pub propagation_timeout: Duration,
    /// How often to poll those nameservers.
    pub propagation_poll: Duration,
}

impl Default for AcmeConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            directory: AcmeDirectoryKind::Production,
            email: String::new(),
            propagation_timeout: DEFAULT_PROPAGATION_TIMEOUT,
            propagation_poll: DEFAULT_PROPAGATION_POLL,
        }
    }
}

/// Cloudflare zone settings. The API token is never stored here — see
/// [`crate::secret::read_secret`].
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CloudflareConfig {
    /// Optional zone id; when empty it is resolved by `public_domain` name.
    pub zone_id: Option<String>,
}

/// DynDNS settings for this node's public hostname.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DynDnsConfig {
    /// When false, DynDNS tasks do not run.
    pub enabled: bool,
    /// This node's public hostname, e.g. `node1.dns.example.com`.
    pub hostname: String,
    /// When true, this node also maintains `*.dns.<domain>` and `dns.<domain>`.
    /// At most one node in the cluster may set this (see [`validate_public_entry`]).
    pub public_entry: bool,
    /// Reserved (non–Client-ID) labels for this deployment, usually node names.
    /// The hostname's leftmost label must be one of these.
    pub reserved_labels: Vec<String>,
    /// How often to check and update records (±10 % jitter applied later).
    pub interval: Duration,
    /// Public IP echo URL (HTTPS).
    pub echo_url: String,
    /// Discover and publish IPv4.
    pub ipv4: bool,
    /// Discover and publish IPv6.
    pub ipv6: bool,
    /// Must be `false` (DNS-only). Orange-cloud proxy would break DoT/DoQ.
    pub proxied: bool,
}

impl Default for DynDnsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            hostname: String::new(),
            public_entry: false,
            reserved_labels: Vec::new(),
            interval: DEFAULT_DYNDNS_INTERVAL,
            echo_url: DEFAULT_ECHO_URL.to_owned(),
            ipv4: true,
            ipv6: true,
            proxied: false,
        }
    }
}

/// Top-level TLS configuration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TlsConfig {
    /// Public registered domain (e.g. `example.com`). Cert SANs are
    /// `dns.<domain>` and `*.dns.<domain>`.
    pub public_domain: String,
    /// Extra SANs. Must be empty in v1.
    pub extra_sans: Vec<String>,
    /// Leaf key type.
    pub key_type: KeyType,
    /// Renew when `not_after - now` falls below this (unless ARI says sooner).
    pub renew_before: Duration,
    /// Status flag [`crate::TlsError::CertExpiring`] below this remaining time.
    pub expiry_warn: Duration,
    /// ACME settings.
    pub acme: AcmeConfig,
    /// Cloudflare zone settings.
    pub cloudflare: CloudflareConfig,
    /// DynDNS settings.
    pub dyndns: DynDnsConfig,
    /// Accept `http://` URLs for echo / custom ACME directory on loopback.
    /// Only for local mock servers in tests.
    #[doc(hidden)]
    pub allow_http_for_tests: bool,
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            public_domain: String::new(),
            extra_sans: Vec::new(),
            key_type: KeyType::EcdsaP256,
            renew_before: DEFAULT_RENEW_BEFORE,
            expiry_warn: DEFAULT_EXPIRY_WARN,
            acme: AcmeConfig::default(),
            cloudflare: CloudflareConfig::default(),
            dyndns: DynDnsConfig::default(),
            allow_http_for_tests: false,
        }
    }
}

impl TlsConfig {
    /// Validates and normalises this config in place.
    ///
    /// When ACME or DynDNS is enabled, also requires
    /// [`CLOUDFLARE_API_TOKEN_ENV`] (or its `_FILE` form).
    pub fn validate(&mut self) -> Result<(), TlsError> {
        self.validate_with_token(read_secret)
    }

    /// Like [`Self::validate`], but uses `lookup` for the Cloudflare token.
    ///
    /// Tests inject a fake lookup so they never mutate process environment
    /// (`set_var` is `unsafe` and forbidden in this workspace).
    pub fn validate_with_token(
        &mut self,
        lookup: impl FnOnce(&str) -> Result<Secret, TlsError>,
    ) -> Result<(), TlsError> {
        self.public_domain = normalise_domain(&self.public_domain)?;
        if self.public_domain.is_empty() {
            return Err(TlsError::config("public_domain is empty"));
        }
        if !self.extra_sans.is_empty() {
            return Err(TlsError::config(
                "extra_sans must be empty in v1 (only dns.<domain> and *.dns.<domain>)",
            ));
        }
        if self.renew_before.is_zero() {
            return Err(TlsError::config("renew_before must be positive"));
        }
        if self.expiry_warn.is_zero() {
            return Err(TlsError::config("expiry_warn must be positive"));
        }

        self.validate_acme()?;
        self.validate_dyndns()?;
        if self.acme.enabled || self.dyndns.enabled {
            let _ = lookup(CLOUDFLARE_API_TOKEN_ENV)?;
        }
        Ok(())
    }

    fn validate_acme(&mut self) -> Result<(), TlsError> {
        if !self.acme.enabled {
            return Ok(());
        }
        let email = self.acme.email.trim();
        if email.is_empty() {
            return Err(TlsError::config(
                "acme.email is required when ACME is enabled",
            ));
        }
        if !email.contains('@') || email.starts_with('@') || email.ends_with('@') {
            return Err(TlsError::config("acme.email is not a valid address"));
        }
        self.acme.email = email.to_owned();
        if self.acme.propagation_timeout.is_zero() {
            return Err(TlsError::config(
                "acme.propagation_timeout must be positive",
            ));
        }
        if self.acme.propagation_poll.is_zero() {
            return Err(TlsError::config("acme.propagation_poll must be positive"));
        }
        if let AcmeDirectoryKind::Url(url) = &self.acme.directory {
            check_https_url(url, self.allow_http_for_tests, "acme.directory")?;
        }
        Ok(())
    }

    fn validate_dyndns(&mut self) -> Result<(), TlsError> {
        if self.dyndns.proxied {
            return Err(TlsError::config(
                "dyndns.proxied must be false (DNS-only; orange-cloud breaks DoT/DoQ)",
            ));
        }
        if !self.dyndns.enabled {
            return Ok(());
        }
        if self.dyndns.interval.is_zero() {
            return Err(TlsError::config("dyndns.interval must be positive"));
        }
        if !self.dyndns.ipv4 && !self.dyndns.ipv6 {
            return Err(TlsError::config(
                "dyndns must enable at least one of ipv4 or ipv6",
            ));
        }
        check_https_url(
            &self.dyndns.echo_url,
            self.allow_http_for_tests,
            "dyndns.echo_url",
        )?;

        // Normalise reserved labels (lower-case, trim).
        for label in &mut self.dyndns.reserved_labels {
            *label = label.trim().to_ascii_lowercase();
            if label.is_empty() {
                return Err(TlsError::config(
                    "dyndns.reserved_labels contains an empty label",
                ));
            }
            if label.contains('.') {
                return Err(TlsError::config(
                    "dyndns.reserved_labels must be single labels, not FQDNs",
                ));
            }
        }

        self.dyndns.hostname = normalise_domain(&self.dyndns.hostname)?;
        let expected_suffix = format!("dns.{}", self.public_domain);
        let Some((label, rest)) = self.dyndns.hostname.split_once('.') else {
            return Err(TlsError::config(format!(
                "dyndns.hostname {:?} is not <label>.dns.<public_domain>",
                self.dyndns.hostname
            )));
        };
        if rest != expected_suffix {
            return Err(TlsError::config(format!(
                "dyndns.hostname {:?} must be <label>.dns.{}",
                self.dyndns.hostname, self.public_domain
            )));
        }
        if label.contains('.') {
            return Err(TlsError::config(
                "dyndns.hostname must have exactly one label below dns.<domain>",
            ));
        }
        let reserved_ok = self
            .dyndns
            .reserved_labels
            .iter()
            .any(|r| r.eq_ignore_ascii_case(label));
        if !reserved_ok {
            return Err(TlsError::config(format!(
                "dyndns.hostname label {label:?} is not in reserved_labels"
            )));
        }
        Ok(())
    }
}

/// Minimal description of a cluster node's DynDNS role.
///
/// Used by cluster / control-api to reject two public-entry nodes before
/// applying config. The TLS crate itself does not discover peers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodeEntry {
    /// Node name (diagnostics only).
    pub name: String,
    /// Whether this node maintains the wildcard and apex records.
    pub public_entry: bool,
}

/// Rejects configurations where more than one node claims `public_entry`.
pub fn validate_public_entry(nodes: &[NodeEntry]) -> Result<(), TlsError> {
    let count = nodes.iter().filter(|n| n.public_entry).count();
    if count > 1 {
        Err(TlsError::DyndnsEntryConflict)
    } else {
        Ok(())
    }
}

/// Normalises a domain: UTS 46 → ASCII, lower-case, no trailing dot.
fn normalise_domain(input: &str) -> Result<String, TlsError> {
    let trimmed = input.trim().trim_end_matches('.');
    if trimmed.is_empty() {
        return Ok(String::new());
    }
    let ascii = idna::domain_to_ascii_cow(trimmed.as_bytes(), idna::AsciiDenyList::URL)
        .map_err(|_| TlsError::config(format!("invalid domain {input:?}")))?;
    let s = ascii.into_owned().to_ascii_lowercase();
    if s.is_empty() || s.starts_with('.') || s.contains("..") || s.ends_with('.') {
        return Err(TlsError::config(format!("invalid domain {input:?}")));
    }
    for label in s.split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(TlsError::config(format!("invalid domain {input:?}")));
        }
    }
    if s.len() > 253 {
        return Err(TlsError::config(format!("domain too long ({})", s.len())));
    }
    Ok(s)
}

fn check_https_url(url: &str, allow_http_for_tests: bool, field: &str) -> Result<(), TlsError> {
    let lower = url.trim().to_ascii_lowercase();
    let rest = if let Some(r) = lower.strip_prefix("https://") {
        r
    } else if allow_http_for_tests {
        if let Some(r) = lower.strip_prefix("http://") {
            if !is_loopback_host_str(r) {
                return Err(TlsError::config(format!(
                    "{field} http:// is only allowed for loopback in tests"
                )));
            }
            r
        } else {
            return Err(TlsError::config(format!("{field} must be an https:// URL")));
        }
    } else {
        return Err(TlsError::config(format!("{field} must be an https:// URL")));
    };
    if rest.is_empty() || rest.starts_with('/') || rest.chars().any(char::is_whitespace) {
        return Err(TlsError::config(format!("{field} has no valid host")));
    }
    Ok(())
}

fn is_loopback_host_str(rest: &str) -> bool {
    // rest is "host/path…" or "host:port/…"
    let host_port = rest.split('/').next().unwrap_or(rest);
    let host = if host_port.starts_with('[') {
        host_port
            .trim_start_matches('[')
            .split(']')
            .next()
            .unwrap_or("")
    } else {
        host_port.split(':').next().unwrap_or(host_port)
    };
    host.eq_ignore_ascii_case("localhost")
        || host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn ok_token(_: &str) -> Result<Secret, TlsError> {
        Ok(Secret::new("test-token-not-real"))
    }

    fn missing_token(name: &str) -> Result<Secret, TlsError> {
        Err(TlsError::SecretMissing {
            name: name.to_owned(),
        })
    }

    fn example_config() -> TlsConfig {
        TlsConfig {
            public_domain: "Example.COM.".into(),
            extra_sans: Vec::new(),
            key_type: KeyType::EcdsaP256,
            renew_before: DEFAULT_RENEW_BEFORE,
            expiry_warn: DEFAULT_EXPIRY_WARN,
            acme: AcmeConfig {
                enabled: true,
                directory: AcmeDirectoryKind::Staging,
                email: "admin@example.com".into(),
                propagation_timeout: DEFAULT_PROPAGATION_TIMEOUT,
                propagation_poll: DEFAULT_PROPAGATION_POLL,
            },
            cloudflare: CloudflareConfig { zone_id: None },
            dyndns: DynDnsConfig {
                enabled: true,
                hostname: "Node1.DNS.Example.COM.".into(),
                public_entry: false,
                reserved_labels: vec!["node1".into(), "node2".into()],
                interval: DEFAULT_DYNDNS_INTERVAL,
                echo_url: DEFAULT_ECHO_URL.into(),
                ipv4: true,
                ipv6: true,
                proxied: false,
            },
            allow_http_for_tests: false,
        }
    }

    #[test]
    fn config_example_from_spec_validates_and_normalises() {
        let mut cfg = example_config();
        cfg.validate_with_token(ok_token).expect("valid");
        assert_eq!(cfg.public_domain, "example.com");
        assert_eq!(cfg.dyndns.hostname, "node1.dns.example.com");
        assert_eq!(
            cfg.acme.directory.url(),
            "https://acme-staging-v02.api.letsencrypt.org/directory"
        );
    }

    #[test]
    fn config_rejects_non_empty_extra_sans() {
        let mut cfg = example_config();
        cfg.extra_sans = vec!["vpn.example.com".into()];
        let err = cfg.validate_with_token(ok_token).expect_err("extra_sans");
        assert_eq!(err.code(), "tls.config.invalid");
        assert!(err.to_string().contains("extra_sans"));
    }

    #[test]
    fn config_rejects_proxied_true() {
        let mut cfg = example_config();
        cfg.dyndns.proxied = true;
        let err = cfg.validate_with_token(ok_token).expect_err("proxied");
        assert_eq!(err.code(), "tls.config.invalid");
        assert!(err.to_string().contains("proxied"));
    }

    #[test]
    fn config_rejects_hostname_outside_dns_domain() {
        let mut cfg = example_config();
        cfg.dyndns.hostname = "node1.example.com".into();
        let err = cfg.validate_with_token(ok_token).expect_err("hostname");
        assert_eq!(err.code(), "tls.config.invalid");
    }

    #[test]
    fn config_rejects_hostname_label_not_reserved() {
        let mut cfg = example_config();
        cfg.dyndns.hostname = "phone.dns.example.com".into();
        let err = cfg.validate_with_token(ok_token).expect_err("not reserved");
        assert_eq!(err.code(), "tls.config.invalid");
        assert!(err.to_string().contains("reserved_labels"));
    }

    #[test]
    fn config_rejects_missing_email_when_acme_enabled() {
        let mut cfg = example_config();
        cfg.acme.email.clear();
        let err = cfg.validate_with_token(ok_token).expect_err("email");
        assert_eq!(err.code(), "tls.config.invalid");
        assert!(err.to_string().contains("email"));
    }

    #[test]
    fn config_allows_empty_email_when_acme_disabled() {
        let mut cfg = example_config();
        cfg.acme.enabled = false;
        cfg.acme.email.clear();
        cfg.validate_with_token(ok_token).expect("acme off");
    }

    #[test]
    fn config_missing_token_with_acme_enabled() {
        let mut cfg = example_config();
        let err = cfg.validate_with_token(missing_token).expect_err("token");
        assert_eq!(err.code(), "tls.secret.missing");
        assert!(!format!("{err:?}").contains("test-token"));
    }

    #[test]
    fn config_missing_token_with_dyndns_enabled() {
        let mut cfg = example_config();
        cfg.acme.enabled = false;
        cfg.acme.email.clear();
        cfg.dyndns.enabled = true;
        let err = cfg.validate_with_token(missing_token).expect_err("token");
        assert_eq!(err.code(), "tls.secret.missing");
    }

    #[test]
    fn config_no_token_needed_when_both_disabled() {
        let mut cfg = example_config();
        cfg.acme.enabled = false;
        cfg.acme.email.clear();
        cfg.dyndns.enabled = false;
        // lookup must not be called; panic if it is
        cfg.validate_with_token(|_| panic!("token lookup must not run"))
            .expect("no secret needed");
    }

    #[test]
    fn config_rejects_http_echo_url_without_hatch() {
        let mut cfg = example_config();
        cfg.dyndns.echo_url = "http://127.0.0.1:9/trace".into();
        let err = cfg.validate_with_token(ok_token).expect_err("http");
        assert_eq!(err.code(), "tls.config.invalid");
    }

    #[test]
    fn config_allows_loopback_http_with_test_hatch() {
        let mut cfg = example_config();
        cfg.allow_http_for_tests = true;
        cfg.dyndns.echo_url = "http://127.0.0.1:9/trace".into();
        cfg.validate_with_token(ok_token).expect("loopback hatch");
    }

    #[test]
    fn config_validate_public_entry_rejects_two_nodes() {
        let nodes = [
            NodeEntry {
                name: "a".into(),
                public_entry: true,
            },
            NodeEntry {
                name: "b".into(),
                public_entry: true,
            },
        ];
        let err = validate_public_entry(&nodes).expect_err("conflict");
        assert_eq!(err.code(), "tls.dyndns.entry_conflict");
    }

    #[test]
    fn config_validate_public_entry_allows_one() {
        let nodes = [
            NodeEntry {
                name: "a".into(),
                public_entry: true,
            },
            NodeEntry {
                name: "b".into(),
                public_entry: false,
            },
        ];
        validate_public_entry(&nodes).expect("one entry ok");
        validate_public_entry(&[]).expect("empty ok");
    }

    #[test]
    fn config_token_absent_from_debug_of_validated_config() {
        let mut cfg = example_config();
        cfg.validate_with_token(ok_token).unwrap();
        let shown = format!("{cfg:?}");
        assert!(!shown.contains("test-token-not-real"));
        assert!(!shown.contains("BEGIN"));
    }
}
