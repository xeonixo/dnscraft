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
use crate::{Secret, UNIFI_API_KEY_ENV, read_secret};
use dnscraft_common::config::normalise_domain;
use dnscraft_common::net::is_loopback_host_str;

/// serde adapter for an optional [`IpNet`], which has no serde implementation
/// used by this crate. Uses the CIDR presentation form (`192.0.2.0/24`).
pub(crate) mod optional_ipnet_serde {
    use std::str::FromStr;

    use ipnet::IpNet;
    use serde::de::Error as _;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(net: &Option<IpNet>, serializer: S) -> Result<S::Ok, S::Error> {
        match net {
            Some(net) => serializer.serialize_some(&net.to_string()),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<IpNet>, D::Error> {
        Option::<String>::deserialize(deserializer)?
            .map(|text| IpNet::from_str(&text))
            .transpose()
            .map_err(D::Error::custom)
    }
}

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
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
pub enum LocalDomainMode {
    /// Prefer UniFi per-VLAN DHCP domain when present; else config `local_domain`.
    #[default]
    UnifiThenConfig,
    /// Always use config `local_domain` (admin override).
    Config,
}

/// TLS trust mode for the UniFi gateway connection.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum TlsMode {
    /// SHA-256 of the leaf certificate DER must equal this pin (32 bytes).
    Pin([u8; 32]),
    /// Trust a CA (or chain) loaded from this PEM file.
    CaFile(PathBuf),
    /// Verify against the operating system's CA bundle (the default).
    Secure,
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
/// [`crate::read_secret`].
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct UnifiConfig {
    /// When false, UniFi contributes nothing; manuals only.
    pub enabled: bool,
    /// Gateway base URL, e.g. `https://192.0.2.1` (HTTPS required).
    pub base_url: String,
    /// Optional Integration site UUID; required when more than one site exists.
    pub site_id: Option<String>,
    /// How often to poll (±10 % jitter applied by the engine).
    #[serde(with = "dnscraft_common::duration::serde")]
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
            // Verify against the system CA bundle. Insecure is opt-in only.
            tls: TlsMode::Secure,
        }
    }
}

/// One manual name entry (exact IP or CIDR).
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ManualEntry {
    /// Display name (normalised later into a DNS label).
    pub name: String,
    /// Exact host address. Mutually exclusive with [`Self::cidr`].
    pub ip: Option<IpAddr>,
    /// CIDR range. Mutually exclusive with [`Self::ip`].
    #[serde(with = "optional_ipnet_serde")]
    pub cidr: Option<IpNet>,
    /// Optional domain override for this entry only.
    pub domain: Option<String>,
}

/// Top-level clients configuration.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ClientsConfig {
    /// Fallback parent domain when UniFi has no DHCP domain for the network.
    pub local_domain: String,
    /// How `local_domain` interacts with UniFi per-network domains.
    pub local_domain_mode: LocalDomainMode,
    /// How long to keep a client after it disappears from a successful sync.
    #[serde(with = "dnscraft_common::duration::serde")]
    pub offline_retain: Duration,
    /// How long to keep previously observed UniFi IPv6 addresses.
    #[serde(with = "dnscraft_common::duration::serde")]
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
        self.local_domain = normalise_domain(&self.local_domain).map_err(ClientsError::config)?;
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
            TlsMode::Pin(_) | TlsMode::Secure => {}
            TlsMode::CaFile(path) => {
                if path.as_os_str().is_empty() {
                    return Err(ClientsError::config("unifi.ca_file is empty"));
                }
            }
            TlsMode::Insecure => {
                // Allowed only when explicitly configured. The default is
                // `Secure`, so reaching this arm means the caller opted in.
                // Engine warns when the TLS client is built.
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
        let normalised = normalise_domain(domain).map_err(ClientsError::config)?;
        if normalised.is_empty() {
            return Err(ClientsError::config(format!(
                "manual[{index}].domain is empty"
            )));
        }
        *domain = normalised;
    }
    Ok(())
}

fn check_https_url(url: &str, allow_http_for_tests: bool, field: &str) -> Result<(), ClientsError> {
    let trimmed = url.trim();
    let parsed = reqwest::Url::parse(trimmed)
        .map_err(|e| ClientsError::config(format!("{field} is not a valid URL: {e}")))?;
    let loopback_http = allow_http_for_tests
        && parsed.scheme() == "http"
        && parsed.host_str().is_some_and(is_loopback_host_str);
    if parsed.scheme() != "https" && !loopback_http {
        return Err(ClientsError::config(format!(
            "{field} must be an https:// URL"
        )));
    }
    let Some(host) = parsed.host_str() else {
        return Err(ClientsError::config(format!("{field} has no valid host")));
    };
    if host.is_empty() {
        return Err(ClientsError::config(format!("{field} has no valid host")));
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(ClientsError::config(format!(
            "{field} must not include credentials"
        )));
    }
    if parsed.port() == Some(0) {
        return Err(ClientsError::config(format!("{field} has an invalid port")));
    }
    if parsed.query().is_some() || parsed.fragment().is_some() {
        return Err(ClientsError::config(format!(
            "{field} must not include a query or fragment"
        )));
    }
    if parsed.path() != "/" {
        return Err(ClientsError::config(format!(
            "{field} must be an origin URL without a path"
        )));
    }
    Ok(())
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

    #[test]
    fn default_tls_is_secure_not_insecure() {
        let cfg = UnifiConfig::default();
        assert_eq!(cfg.tls, TlsMode::Secure);
        assert!(!matches!(cfg.tls, TlsMode::Insecure));
    }

    #[test]
    fn enabled_config_with_defaults_does_not_use_insecure_tls() {
        // `..Default::default()` must never opt into skip-verify.
        let mut cfg = ClientsConfig {
            unifi: UnifiConfig {
                enabled: true,
                base_url: "https://192.0.2.1".into(),
                ..UnifiConfig::default()
            },
            ..ClientsConfig::default()
        };
        assert_eq!(cfg.unifi.tls, TlsMode::Secure);
        cfg.validate_with_secret(ok_secret)
            .expect("secure default is valid");
    }

    #[test]
    fn explicit_insecure_tls_is_accepted() {
        let mut cfg = example_config();
        cfg.unifi.tls = TlsMode::Insecure;
        cfg.validate_with_secret(ok_secret)
            .expect("insecure is an explicit opt-in");
    }

    #[test]
    fn malformed_or_unsafe_urls_rejected() {
        for bad in [
            "https://192.0.2.1/path",
            "https://192.0.2.1?query=1",
            "https://192.0.2.1#frag",
            "https://user:pass@192.0.2.1",
            "https://192.0.2.1:0",
            "https://192.0.2.1:99999",
            "https://",
            "https://exa mple.example.com",
        ] {
            let mut cfg = example_config();
            cfg.unifi.base_url = bad.into();
            let err = cfg
                .validate_with_secret(ok_secret)
                .expect_err("malformed URL must be rejected");
            assert_eq!(err.code(), "clients.config.invalid", "{bad:?}");
        }
    }

    #[test]
    fn ipv6_origin_url_accepted() {
        let mut cfg = example_config();
        cfg.unifi.base_url = "https://[2001:db8::1]:8443".into();
        cfg.validate_with_secret(ok_secret).expect("ipv6 origin");
    }

    #[test]
    fn config_round_trips_through_json() {
        let config = ClientsConfig {
            local_domain: "example.com".into(),
            local_domain_mode: LocalDomainMode::Config,
            offline_retain: Duration::from_secs(7 * 24 * 3600),
            ipv6_address_ttl: Duration::from_secs(24 * 3600),
            unifi: UnifiConfig {
                enabled: true,
                base_url: "https://192.0.2.1".into(),
                site_id: Some("site-1".into()),
                poll_interval: Duration::from_secs(60),
                classic_clients: false,
                tls: TlsMode::pin_from_str(
                    "sha256:00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
                )
                .unwrap(),
            },
            manual: vec![
                ManualEntry {
                    name: "printer".into(),
                    ip: Some("192.0.2.10".parse().unwrap()),
                    cidr: None,
                    domain: Some("example.com".into()),
                },
                ManualEntry {
                    name: "lab".into(),
                    ip: None,
                    cidr: Some("2001:db8::/32".parse().unwrap()),
                    domain: None,
                },
            ],
            allow_http_for_tests: false,
        };

        let json = serde_json::to_string(&config).unwrap();
        assert!(json.contains("\"offline_retain\":\"1w\""), "{json}");
        assert!(json.contains("\"ipv6_address_ttl\":\"1d\""), "{json}");
        assert!(json.contains("\"poll_interval\":\"1m\""), "{json}");
        let back: ClientsConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back, config);
    }

    #[test]
    fn duration_fields_parse_human_strings() {
        let mut value = serde_json::to_value(ClientsConfig::default()).unwrap();
        value["offline_retain"] = "1d".into();
        value["ipv6_address_ttl"] = "90s".into();
        value["unifi"]["poll_interval"] = "1m".into();
        let config: ClientsConfig = serde_json::from_value(value.clone()).unwrap();
        assert_eq!(config.offline_retain, Duration::from_secs(86_400));
        assert_eq!(config.ipv6_address_ttl, Duration::from_secs(90));
        assert_eq!(config.unifi.poll_interval, Duration::from_secs(60));

        value["offline_retain"] = "1x".into();
        assert!(serde_json::from_value::<ClientsConfig>(value).is_err());
    }

    #[test]
    fn all_tls_modes_round_trip() {
        for tls in [
            TlsMode::Pin([7; 32]),
            TlsMode::CaFile(PathBuf::from("/etc/dnscraft/ca.pem")),
            TlsMode::Secure,
            TlsMode::Insecure,
        ] {
            let json = serde_json::to_string(&tls).unwrap();
            let back: TlsMode = serde_json::from_str(&json).unwrap();
            assert_eq!(back, tls);
        }
    }
}
