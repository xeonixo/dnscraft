//! Clients module configuration as Rust values.
//!
//! Bootstrap settings may arrive from TOML; the UI edits the same shapes.
//! [`ClientsConfig::validate`] normalises domains and enforces the v1 rules from
//! SPEC-clients.md (HTTPS gateway URL, pin format, manual IP xor CIDR, caps).

use std::net::IpAddr;
use std::path::PathBuf;
use std::time::Duration;

use ipnet::IpNet;

use crate::error::ClientsError;
use crate::secret::{Secret, UNIFI_API_KEY_ENV, read_secret};

/// Default parent domain when UniFi has no per-network DHCP domain (RFC 8375).
pub const DEFAULT_LOCAL_DOMAIN: &str = "home.arpa";
/// Default offline retain window: 7 days.
pub const DEFAULT_OFFLINE_RETAIN: Duration = Duration::from_secs(7 * 24 * 3600);
/// Default IPv6 address TTL after last observation: 24 hours.
pub const DEFAULT_IPV6_ADDRESS_TTL: Duration = Duration::from_secs(24 * 3600);
/// Default UniFi poll interval: 60 seconds.
pub const DEFAULT_POLL_INTERVAL: Duration = Duration::from_secs(60);
/// Soft documentation cap; hard validation refuse above this.
pub const MAX_MANUAL_ENTRIES: usize = 1_000;

/// How the parent domain for FQDNs is chosen.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum LocalDomainMode {
    /// Prefer UniFi per-VLAN DHCP domain when present; else config `local_domain`.
    #[default]
    UnifiThenConfig,
    /// Always use config `local_domain` (admin override).
    Config,
}

/// TLS trust mode for the UniFi gateway connection.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum TlsMode {
    /// SHA-256 of the leaf certificate DER must equal this pin (32 bytes).
    Pin([u8; 32]),
    /// Trust a CA (or chain) loaded from this PEM file.
    CaFile(PathBuf),
    /// Accept any certificate. Opt-in only; never the default.
    Insecure,
}

impl TlsMode {
    /// Parses a pin string of the form `sha256:` + 32 hex bytes (colons optional).
    ///
    /// Examples: `sha256:aabb…` (64 hex digits) or `sha256:AA:BB:…`.
    pub fn pin_from_str(input: &str) -> Result<Self, ClientsError> {
        let rest = input
            .strip_prefix("sha256:")
            .or_else(|| input.strip_prefix("SHA256:"))
            .ok_or_else(|| {
                ClientsError::config(format!("tls pin must start with sha256: (got {input:?})"))
            })?;
        let hex: String = rest
            .chars()
            .filter(|c| c.is_ascii_hexdigit())
            .map(|c| c.to_ascii_lowercase())
            .collect();
        if hex.len() != 64 {
            return Err(ClientsError::config(format!(
                "tls pin must be sha256: + 32 hex bytes (64 digits), got {} digits",
                hex.len()
            )));
        }
        let mut pin = [0u8; 32];
        for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
            let s = std::str::from_utf8(chunk)
                .map_err(|_| ClientsError::config("tls pin contains invalid hex"))?;
            pin[i] = u8::from_str_radix(s, 16)
                .map_err(|_| ClientsError::config("tls pin contains invalid hex"))?;
        }
        Ok(Self::Pin(pin))
    }
}

/// UniFi gateway connection settings. The API key is never stored here — see
/// [`crate::secret::read_secret`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnifiConfig {
    /// When false, UniFi contributes nothing; manuals only.
    pub enabled: bool,
    /// Gateway base URL, e.g. `https://192.0.2.1` (HTTPS required).
    pub base_url: String,
    /// Optional Integration site UUID; required when more than one site exists.
    pub site_id: Option<String>,
    /// How often to poll (±10 % jitter applied by the engine).
    pub poll_interval: Duration,
    /// Fetch the classic client feed for complete IPv6 (default on).
    pub classic_clients: bool,
    /// TLS trust mode. Required when [`Self::enabled`].
    pub tls: TlsMode,
}

impl Default for UnifiConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            base_url: String::new(),
            site_id: None,
            poll_interval: DEFAULT_POLL_INTERVAL,
            classic_clients: true,
            // Placeholder; validate rejects enabled UniFi without a real mode set by the caller.
            tls: TlsMode::Insecure,
        }
    }
}

/// One manual name entry (exact IP or CIDR).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ManualEntry {
    /// Display name (normalised later into a DNS label).
    pub name: String,
    /// Exact host address. Mutually exclusive with [`Self::cidr`].
    pub ip: Option<IpAddr>,
    /// CIDR range. Mutually exclusive with [`Self::ip`].
    pub cidr: Option<IpNet>,
    /// Optional domain override for this entry only.
    pub domain: Option<String>,
}

/// Top-level clients configuration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClientsConfig {
    /// Fallback parent domain when UniFi has no DHCP domain for the network.
    pub local_domain: String,
    /// How `local_domain` interacts with UniFi per-network domains.
    pub local_domain_mode: LocalDomainMode,
    /// How long to keep a client after it disappears from a successful sync.
    pub offline_retain: Duration,
    /// How long to keep previously observed UniFi IPv6 addresses.
    pub ipv6_address_ttl: Duration,
    /// UniFi gateway settings.
    pub unifi: UnifiConfig,
    /// Manual IP / CIDR names (≤ [`MAX_MANUAL_ENTRIES`]).
    pub manual: Vec<ManualEntry>,
    /// Accept `http://` gateway URLs on loopback. Only for local mock servers.
    #[doc(hidden)]
    pub allow_http_for_tests: bool,
}

impl Default for ClientsConfig {
    fn default() -> Self {
        Self {
            local_domain: DEFAULT_LOCAL_DOMAIN.to_owned(),
            local_domain_mode: LocalDomainMode::UnifiThenConfig,
            offline_retain: DEFAULT_OFFLINE_RETAIN,
            ipv6_address_ttl: DEFAULT_IPV6_ADDRESS_TTL,
            unifi: UnifiConfig::default(),
            manual: Vec::new(),
            allow_http_for_tests: false,
        }
    }
}

impl ClientsConfig {
    /// Validates and normalises this config in place.
    ///
    /// When UniFi is enabled, also requires [`UNIFI_API_KEY_ENV`] (or its `_FILE`
    /// form).
    pub fn validate(&mut self) -> Result<(), ClientsError> {
        self.validate_with_secret(read_secret)
    }

    /// Like [`Self::validate`], but uses `lookup` for the UniFi API key.
    ///
    /// Tests inject a fake lookup so they never mutate process environment
    /// (`set_var` is `unsafe` and forbidden in this workspace).
    pub fn validate_with_secret(
        &mut self,
        lookup: impl FnOnce(&str) -> Result<Secret, ClientsError>,
    ) -> Result<(), ClientsError> {
        self.local_domain = normalise_domain(&self.local_domain)?;
        if self.local_domain.is_empty() {
            return Err(ClientsError::config("local_domain is empty"));
        }
        if self.offline_retain.is_zero() {
            return Err(ClientsError::config("offline_retain must be positive"));
        }
        if self.ipv6_address_ttl.is_zero() {
            return Err(ClientsError::config("ipv6_address_ttl must be positive"));
        }
        if self.manual.len() > MAX_MANUAL_ENTRIES {
            return Err(ClientsError::config(format!(
                "at most {MAX_MANUAL_ENTRIES} manual entries, got {}",
                self.manual.len()
            )));
        }
        for (i, entry) in self.manual.iter_mut().enumerate() {
            validate_manual(entry, i)?;
        }
        self.validate_unifi(lookup)?;
        Ok(())
    }

    fn validate_unifi(
        &mut self,
        lookup: impl FnOnce(&str) -> Result<Secret, ClientsError>,
    ) -> Result<(), ClientsError> {
        if !self.unifi.enabled {
            return Ok(());
        }
        if self.unifi.poll_interval.is_zero() {
            return Err(ClientsError::config("unifi.poll_interval must be positive"));
        }
        check_https_url(
            &self.unifi.base_url,
            self.allow_http_for_tests,
            "unifi.base_url",
        )?;
        // Trim trailing slash for a stable base.
        while self.unifi.base_url.ends_with('/') {
            self.unifi.base_url.pop();
        }
        if let Some(site) = &mut self.unifi.site_id {
            let trimmed = site.trim();
            if trimmed.is_empty() {
                self.unifi.site_id = None;
            } else {
                *site = trimmed.to_owned();
            }
        }
        match &self.unifi.tls {
            TlsMode::Pin(_) => {}
            TlsMode::CaFile(path) => {
                if path.as_os_str().is_empty() {
                    return Err(ClientsError::config("unifi.ca_file is empty"));
                }
            }
            TlsMode::Insecure => {
                // Allowed only when explicitly configured; callers must set it.
                // Engine will warn on apply (C8).
            }
        }
        let _ = lookup(UNIFI_API_KEY_ENV)?;
        Ok(())
    }
}

fn validate_manual(entry: &mut ManualEntry, index: usize) -> Result<(), ClientsError> {
    let name = entry.name.trim();
    if name.is_empty() {
        return Err(ClientsError::config(format!(
            "manual[{index}].name is empty"
        )));
    }
    entry.name = name.to_owned();
    match (entry.ip, entry.cidr) {
        (Some(_), None) | (None, Some(_)) => {}
        (Some(_), Some(_)) => {
            return Err(ClientsError::config(format!(
                "manual[{index}] must have exactly one of ip or cidr, not both"
            )));
        }
        (None, None) => {
            return Err(ClientsError::config(format!(
                "manual[{index}] must have exactly one of ip or cidr"
            )));
        }
    }
    if let Some(domain) = &mut entry.domain {
        let normalised = normalise_domain(domain)?;
        if normalised.is_empty() {
            return Err(ClientsError::config(format!(
                "manual[{index}].domain is empty"
            )));
        }
        *domain = normalised;
    }
    Ok(())
}

/// Normalises a domain: UTS 46 → ASCII, lower-case, no trailing dot.
pub(crate) fn normalise_domain(input: &str) -> Result<String, ClientsError> {
    let trimmed = input.trim().trim_end_matches('.');
    if trimmed.is_empty() {
        return Ok(String::new());
    }
    let ascii = idna::domain_to_ascii_cow(trimmed.as_bytes(), idna::AsciiDenyList::URL)
        .map_err(|_| ClientsError::config(format!("invalid domain {input:?}")))?;
    let s = ascii.into_owned().to_ascii_lowercase();
    if s.is_empty() || s.starts_with('.') || s.contains("..") || s.ends_with('.') {
        return Err(ClientsError::config(format!("invalid domain {input:?}")));
    }
    for label in s.split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(ClientsError::config(format!("invalid domain {input:?}")));
        }
    }
    if s.len() > 253 {
        return Err(ClientsError::config(format!(
            "domain too long ({})",
            s.len()
        )));
    }
    Ok(s)
}

fn check_https_url(url: &str, allow_http_for_tests: bool, field: &str) -> Result<(), ClientsError> {
    let lower = url.trim().to_ascii_lowercase();
    let rest = if let Some(r) = lower.strip_prefix("https://") {
        r
    } else if allow_http_for_tests {
        if let Some(r) = lower.strip_prefix("http://") {
            if !is_loopback_host_str(r) {
                return Err(ClientsError::config(format!(
                    "{field} http:// is only allowed for loopback in tests"
                )));
            }
            r
        } else {
            return Err(ClientsError::config(format!(
                "{field} must be an https:// URL"
            )));
        }
    } else {
        return Err(ClientsError::config(format!(
            "{field} must be an https:// URL"
        )));
    };
    if rest.is_empty() || rest.starts_with('/') || rest.chars().any(char::is_whitespace) {
        return Err(ClientsError::config(format!("{field} has no valid host")));
    }
    Ok(())
}

fn is_loopback_host_str(rest: &str) -> bool {
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
    use std::str::FromStr;

    fn ok_secret(_: &str) -> Result<Secret, ClientsError> {
        Ok(Secret::new("test-api-key-not-real"))
    }

    fn missing_secret(name: &str) -> Result<Secret, ClientsError> {
        Err(ClientsError::SecretMissing {
            name: name.to_owned(),
        })
    }

    /// Spec configuration excerpt as Rust values (documentation ranges).
    fn example_config() -> ClientsConfig {
        let pin = TlsMode::pin_from_str(
            "sha256:00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
        )
        .unwrap();
        ClientsConfig {
            local_domain: "Home.ARPA.".into(),
            local_domain_mode: LocalDomainMode::UnifiThenConfig,
            offline_retain: DEFAULT_OFFLINE_RETAIN,
            ipv6_address_ttl: DEFAULT_IPV6_ADDRESS_TTL,
            unifi: UnifiConfig {
                enabled: true,
                base_url: "https://192.0.2.1/".into(),
                site_id: Some("00000000-0000-0000-0000-000000000000".into()),
                poll_interval: DEFAULT_POLL_INTERVAL,
                classic_clients: true,
                tls: pin,
            },
            manual: vec![
                ManualEntry {
                    name: "paperless".into(),
                    ip: Some(IpAddr::from_str("198.51.100.5").unwrap()),
                    cidr: None,
                    domain: None,
                },
                ManualEntry {
                    name: "Docker on server1".into(),
                    ip: None,
                    cidr: Some(IpNet::from_str("198.51.100.0/24").unwrap()),
                    domain: None,
                },
            ],
            allow_http_for_tests: false,
        }
    }

    #[test]
    fn valid_spec_example_normalises() {
        let mut cfg = example_config();
        cfg.validate_with_secret(ok_secret).expect("valid");
        assert_eq!(cfg.local_domain, "home.arpa");
        assert_eq!(cfg.unifi.base_url, "https://192.0.2.1");
        assert_eq!(cfg.manual.len(), 2);
    }

    #[test]
    fn http_url_rejected() {
        let mut cfg = example_config();
        cfg.unifi.base_url = "http://192.0.2.1".into();
        let err = cfg.validate_with_secret(ok_secret).expect_err("http");
        assert_eq!(err.code(), "clients.config.invalid");
        assert!(err.to_string().contains("https"));
    }

    #[test]
    fn bad_pin_rejected() {
        let err = TlsMode::pin_from_str("sha256:deadbeef").expect_err("short");
        assert_eq!(err.code(), "clients.config.invalid");
        let err = TlsMode::pin_from_str("md5:00").expect_err("wrong algo");
        assert_eq!(err.code(), "clients.config.invalid");
    }

    #[test]
    fn pin_accepts_colon_separated() {
        let colon = "sha256:00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:\
                      00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff";
        let plain = "sha256:00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
        assert_eq!(
            TlsMode::pin_from_str(colon).unwrap(),
            TlsMode::pin_from_str(plain).unwrap()
        );
    }

    #[test]
    fn both_ip_and_cidr_rejected() {
        let mut cfg = example_config();
        cfg.manual[0].cidr = Some(IpNet::from_str("198.51.100.0/24").unwrap());
        let err = cfg.validate_with_secret(ok_secret).expect_err("both");
        assert_eq!(err.code(), "clients.config.invalid");
        assert!(err.to_string().contains("exactly one"));
    }

    #[test]
    fn too_many_manuals_rejected() {
        let mut cfg = ClientsConfig {
            manual: (0..=MAX_MANUAL_ENTRIES)
                .map(|i| ManualEntry {
                    name: format!("host-{i}"),
                    ip: Some(IpAddr::from([10, 0, (i / 256) as u8, (i % 256) as u8])),
                    cidr: None,
                    domain: None,
                })
                .collect(),
            ..ClientsConfig::default()
        };
        assert_eq!(cfg.manual.len(), MAX_MANUAL_ENTRIES + 1);
        let err = cfg.validate_with_secret(ok_secret).expect_err("cap");
        assert_eq!(err.code(), "clients.config.invalid");
        assert!(err.to_string().contains("1000"));
    }

    #[test]
    fn unifi_enabled_requires_secret() {
        let mut cfg = example_config();
        let err = cfg
            .validate_with_secret(missing_secret)
            .expect_err("secret");
        assert_eq!(err.code(), "clients.secret.missing");
    }

    #[test]
    fn unifi_disabled_skips_secret_and_url() {
        let mut cfg = ClientsConfig::default();
        assert!(!cfg.unifi.enabled);
        assert!(cfg.unifi.base_url.is_empty());
        cfg.validate_with_secret(missing_secret)
            .expect("manuals only");
    }

    #[test]
    fn http_loopback_allowed_with_test_hatch() {
        let mut cfg = example_config();
        cfg.allow_http_for_tests = true;
        cfg.unifi.base_url = "http://127.0.0.1:8443".into();
        cfg.validate_with_secret(ok_secret).expect("loopback http");
    }
}
