//! Clients module configuration as Rust values.
//!
//! Bootstrap settings may arrive from TOML; the UI edits the same shapes.
//! [`ClientsConfig::validate`] normalises domains and enforces the v1 rules from
//! SPEC-clients.md (HTTPS gateway URL, pin format, manual IP xor CIDR, caps).

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::path::PathBuf;
use std::time::Duration;

use ipnet::IpNet;

use crate::error::ClientsError;
use crate::{Secret, UNIFI_API_KEY_ENV, read_secret};
use dnscraft_common::config::normalise_domain;
use dnscraft_common::net::is_loopback_host_str;

/// Profile id used when migrating a legacy flat `[clients.unifi]` block.
pub const DEFAULT_UNIFI_PROFILE_ID: &str = "default";
/// Solo / non-cluster `sync_owner` and binding key after legacy migration.
pub const LOCAL_NODE_ID: &str = "local";

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
#[serde(rename_all = "snake_case")]
pub enum LocalDomainMode {
    /// Prefer UniFi per-VLAN DHCP domain when present; else config `local_domain`.
    #[default]
    #[serde(alias = "UnifiThenConfig")]
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
///
/// Serialised as the flat `[clients.unifi]` keys of SPEC-clients.md (see [`UnifiWire`]).
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(try_from = "UnifiWire", into = "UnifiWire")]
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

/// Flat wire form of [`UnifiConfig`]. At most one of `tls_pin_sha256`, `ca_file`,
/// `insecure_skip_verify` may be set; none of them means the system CA bundle.
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct UnifiWire {
    enabled: bool,
    base_url: String,
    #[serde(default)]
    site_id: Option<String>,
    #[serde(with = "dnscraft_common::duration::serde")]
    poll_interval: Duration,
    classic_clients: bool,
    #[serde(default)]
    tls_pin_sha256: Option<String>,
    #[serde(default)]
    ca_file: Option<PathBuf>,
    #[serde(default)]
    insecure_skip_verify: bool,
}

impl From<UnifiConfig> for UnifiWire {
    fn from(c: UnifiConfig) -> Self {
        let (tls_pin_sha256, ca_file, insecure_skip_verify) = match c.tls {
            TlsMode::Pin(pin) => (
                Some(format!(
                    "sha256:{}",
                    pin.iter().map(|b| format!("{b:02x}")).collect::<String>()
                )),
                None,
                false,
            ),
            TlsMode::CaFile(path) => (None, Some(path), false),
            TlsMode::Secure => (None, None, false),
            TlsMode::Insecure => (None, None, true),
        };
        Self {
            enabled: c.enabled,
            base_url: c.base_url,
            site_id: c.site_id,
            poll_interval: c.poll_interval,
            classic_clients: c.classic_clients,
            tls_pin_sha256,
            ca_file,
            insecure_skip_verify,
        }
    }
}

impl TryFrom<UnifiWire> for UnifiConfig {
    type Error = String;

    fn try_from(w: UnifiWire) -> Result<Self, Self::Error> {
        let modes = [
            w.tls_pin_sha256.is_some(),
            w.ca_file.is_some(),
            w.insecure_skip_verify,
        ];
        if modes.iter().filter(|set| **set).count() > 1 {
            return Err(
                "set at most one of tls_pin_sha256, ca_file, insecure_skip_verify".to_owned(),
            );
        }
        let tls = if let Some(pin) = &w.tls_pin_sha256 {
            TlsMode::pin_from_str(pin).map_err(|e| e.to_string())?
        } else if let Some(path) = w.ca_file {
            TlsMode::CaFile(path)
        } else if w.insecure_skip_verify {
            TlsMode::Insecure
        } else {
            TlsMode::Secure
        };
        Ok(Self {
            enabled: w.enabled,
            base_url: w.base_url,
            site_id: w.site_id,
            poll_interval: w.poll_interval,
            classic_clients: w.classic_clients,
            tls,
        })
    }
}

/// One named UniFi gateway profile (shared by one or more nodes).
///
/// The API key is never stored here — see control-api kv `unifi.api_key.{id}`.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct UnifiProfile {
    /// Stable profile id (e.g. `home`).
    pub id: String,
    /// `node_id` of the only node allowed to poll this gateway.
    pub sync_owner: String,
    /// Connection settings (enabled, URL, TLS, …).
    #[serde(flatten)]
    pub connection: UnifiConfig,
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
    /// Named UniFi profiles (preferred). Empty until migrate or UI creates one.
    #[serde(default)]
    pub unifi_profiles: Vec<UnifiProfile>,
    /// `node_id` → profile id. Missing node → UniFi off on that node.
    #[serde(default)]
    pub unifi_bindings: BTreeMap<String, String>,
    /// Effective UniFi settings for **this process** after
    /// [`Self::resolve_for_node`]. Also accepts legacy flat `[clients.unifi]`
    /// on deserialize (migrated into [`Self::unifi_profiles`] on validate).
    #[serde(default)]
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
            unifi_profiles: Vec::new(),
            unifi_bindings: BTreeMap::new(),
            unifi: UnifiConfig::default(),
            manual: Vec::new(),
            allow_http_for_tests: false,
        }
    }
}

impl ClientsConfig {
    /// Kv / env lookup name for a profile's API key.
    ///
    /// Profile [`DEFAULT_UNIFI_PROFILE_ID`] uses [`UNIFI_API_KEY_ENV`]; others use
    /// the opaque kv key `unifi.api_key.{id}` (control-api) or a namespaced env.
    pub fn api_key_lookup_name(profile_id: &str) -> String {
        if profile_id == DEFAULT_UNIFI_PROFILE_ID {
            UNIFI_API_KEY_ENV.to_owned()
        } else {
            format!("unifi.api_key.{profile_id}")
        }
    }

    /// Moves a legacy flat [`Self::unifi`] block into [`Self::unifi_profiles`]
    /// when no profiles exist yet.
    pub fn migrate_legacy_unifi(&mut self) {
        if !self.unifi_profiles.is_empty() {
            return;
        }
        if !self.unifi.enabled && self.unifi.base_url.is_empty() {
            return;
        }
        let id = DEFAULT_UNIFI_PROFILE_ID.to_owned();
        self.unifi_profiles.push(UnifiProfile {
            id: id.clone(),
            sync_owner: LOCAL_NODE_ID.to_owned(),
            connection: self.unifi.clone(),
        });
        if self.unifi.enabled {
            self.unifi_bindings
                .entry(LOCAL_NODE_ID.to_owned())
                .or_insert(id);
        }
    }

    /// Profile bound to `node_id`, if any.
    pub fn bound_profile(&self, node_id: &str) -> Option<&UnifiProfile> {
        let profile_id = self.unifi_bindings.get(node_id)?;
        self.unifi_profiles.iter().find(|p| p.id == *profile_id)
    }

    /// True when this node may poll UniFi for its bound profile.
    pub fn is_sync_owner(&self, node_id: &str) -> bool {
        self.bound_profile(node_id)
            .is_some_and(|p| p.connection.enabled && p.sync_owner == node_id)
    }

    /// Sets [`Self::unifi`] to the connection this process should use for polling.
    ///
    /// Non-owners and unbound nodes get `enabled = false` (directory arrives via
    /// cluster push). Call after [`Self::migrate_legacy_unifi`].
    pub fn resolve_for_node(&mut self, node_id: &str) {
        self.unifi = if self.is_sync_owner(node_id) {
            self.bound_profile(node_id)
                .map(|p| p.connection.clone())
                .unwrap_or_default()
        } else {
            UnifiConfig::default()
        };
    }

    /// Validates and normalises this config in place.
    ///
    /// When a UniFi profile is enabled, also requires its API key via
    /// [`Self::api_key_lookup_name`].
    pub fn validate(&mut self) -> Result<(), ClientsError> {
        self.validate_with_secret(read_secret)
    }

    /// Like [`Self::validate`], but uses `lookup` for UniFi API keys.
    ///
    /// Tests inject a fake lookup so they never mutate process environment
    /// (`set_var` is `unsafe` and forbidden in this workspace).
    pub fn validate_with_secret(
        &mut self,
        mut lookup: impl FnMut(&str) -> Result<Secret, ClientsError>,
    ) -> Result<(), ClientsError> {
        self.migrate_legacy_unifi();
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
        self.validate_profiles(&mut lookup)?;
        Ok(())
    }

    fn validate_profiles(
        &mut self,
        lookup: &mut impl FnMut(&str) -> Result<Secret, ClientsError>,
    ) -> Result<(), ClientsError> {
        let mut seen = BTreeMap::<String, usize>::new();
        for (i, profile) in self.unifi_profiles.iter_mut().enumerate() {
            let id = profile.id.trim();
            if id.is_empty() {
                return Err(ClientsError::config(format!(
                    "unifi_profiles[{i}].id is empty"
                )));
            }
            profile.id = id.to_owned();
            let owner = profile.sync_owner.trim();
            if owner.is_empty() {
                return Err(ClientsError::config(format!(
                    "unifi_profiles[{i}].sync_owner is empty"
                )));
            }
            profile.sync_owner = owner.to_owned();
            if seen.insert(profile.id.clone(), i).is_some() {
                return Err(ClientsError::config(format!(
                    "duplicate unifi profile id `{}`",
                    profile.id
                )));
            }
            normalise_unifi_connection(
                &mut profile.connection,
                self.allow_http_for_tests,
                &format!("unifi_profiles[{i}]"),
            )?;
            if profile.connection.enabled {
                let bound = self.unifi_bindings.get(&profile.sync_owner);
                if bound.map(String::as_str) != Some(profile.id.as_str()) {
                    return Err(ClientsError::config(format!(
                        "unifi_profiles[{i}].sync_owner `{}` must be bound to profile `{}`",
                        profile.sync_owner, profile.id
                    )));
                }
                let _ = lookup(&Self::api_key_lookup_name(&profile.id))?;
            }
        }
        for (node, profile_id) in &self.unifi_bindings {
            if node.trim().is_empty() || profile_id.trim().is_empty() {
                return Err(ClientsError::config(
                    "unifi_bindings entries must have non-empty node and profile id",
                ));
            }
            if !self.unifi_profiles.iter().any(|p| p.id == *profile_id) {
                return Err(ClientsError::config(format!(
                    "unifi_bindings[`{node}`] references unknown profile `{profile_id}`"
                )));
            }
        }
        // Keep legacy `unifi` aligned with profile `default` when present so
        // older readers of the struct still see connection settings.
        if let Some(default) = self
            .unifi_profiles
            .iter()
            .find(|p| p.id == DEFAULT_UNIFI_PROFILE_ID)
        {
            self.unifi = default.connection.clone();
        }
        Ok(())
    }
}

fn normalise_unifi_connection(
    unifi: &mut UnifiConfig,
    allow_http_for_tests: bool,
    field_prefix: &str,
) -> Result<(), ClientsError> {
    if !unifi.enabled {
        return Ok(());
    }
    if unifi.poll_interval.is_zero() {
        return Err(ClientsError::config(format!(
            "{field_prefix}.poll_interval must be positive"
        )));
    }
    check_https_url(
        &unifi.base_url,
        allow_http_for_tests,
        &format!("{field_prefix}.base_url"),
    )?;
    while unifi.base_url.ends_with('/') {
        unifi.base_url.pop();
    }
    if let Some(site) = &mut unifi.site_id {
        let trimmed = site.trim();
        if trimmed.is_empty() {
            unifi.site_id = None;
        } else {
            *site = trimmed.to_owned();
        }
    }
    match &unifi.tls {
        TlsMode::Pin(_) | TlsMode::Secure => {}
        TlsMode::CaFile(path) => {
            if path.as_os_str().is_empty() {
                return Err(ClientsError::config(format!(
                    "{field_prefix}.ca_file is empty"
                )));
            }
        }
        TlsMode::Insecure => {}
    }
    Ok(())
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
            ..ClientsConfig::default()
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
            ..ClientsConfig::default()
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
    #[test]
    fn unifi_uses_flat_spec_keys_and_round_trips_every_tls_mode() {
        for tls in [
            TlsMode::Pin([7; 32]),
            TlsMode::CaFile(PathBuf::from("/etc/dnscraft/ca.pem")),
            TlsMode::Secure,
            TlsMode::Insecure,
        ] {
            let unifi = UnifiConfig {
                enabled: true,
                base_url: "https://192.0.2.1".into(),
                tls: tls.clone(),
                ..UnifiConfig::default()
            };
            let json = serde_json::to_value(&unifi).unwrap();
            assert!(json.get("tls").is_none(), "{json}");
            let back: UnifiConfig = serde_json::from_value(json).unwrap();
            assert_eq!(back.tls, tls);
        }
    }

    #[test]
    fn unifi_tls_keys_are_flat_and_mutually_exclusive() {
        let base = |extra: serde_json::Value| {
            let mut v = serde_json::json!({
                "enabled": true,
                "base_url": "https://192.0.2.1",
                "poll_interval": "60s",
                "classic_clients": true,
            });
            v.as_object_mut()
                .unwrap()
                .extend(extra.as_object().unwrap().clone());
            serde_json::from_value::<UnifiConfig>(v)
        };
        let pin = format!("sha256:{}", "ab".repeat(32));
        assert_eq!(base(serde_json::json!({})).unwrap().tls, TlsMode::Secure);
        assert_eq!(
            base(serde_json::json!({"tls_pin_sha256": pin}))
                .unwrap()
                .tls,
            TlsMode::Pin([0xab; 32])
        );
        assert_eq!(
            base(serde_json::json!({"ca_file": "/etc/ca.pem"}))
                .unwrap()
                .tls,
            TlsMode::CaFile(PathBuf::from("/etc/ca.pem"))
        );
        assert_eq!(
            base(serde_json::json!({"insecure_skip_verify": true}))
                .unwrap()
                .tls,
            TlsMode::Insecure
        );
        assert!(
            base(serde_json::json!({"tls_pin_sha256": pin, "insecure_skip_verify": true})).is_err()
        );
        assert!(base(serde_json::json!({"tls_pin_sha256": "sha256:12"})).is_err());
        assert!(base(serde_json::json!({"tls": "Secure"})).is_err());
    }

    #[test]
    fn local_domain_mode_uses_snake_case_with_legacy_alias() {
        let mode: LocalDomainMode = serde_json::from_str("\"unifi_then_config\"").unwrap();
        assert_eq!(mode, LocalDomainMode::UnifiThenConfig);
        let legacy: LocalDomainMode = serde_json::from_str("\"UnifiThenConfig\"").unwrap();
        assert_eq!(legacy, LocalDomainMode::UnifiThenConfig);
        assert_eq!(
            serde_json::to_string(&LocalDomainMode::Config).unwrap(),
            "\"config\""
        );
    }

    #[test]
    fn legacy_unifi_migrates_to_default_profile() {
        let mut cfg = example_config();
        cfg.validate_with_secret(ok_secret).unwrap();
        assert_eq!(cfg.unifi_profiles.len(), 1);
        assert_eq!(cfg.unifi_profiles[0].id, DEFAULT_UNIFI_PROFILE_ID);
        assert_eq!(cfg.unifi_profiles[0].sync_owner, LOCAL_NODE_ID);
        assert_eq!(
            cfg.unifi_bindings.get(LOCAL_NODE_ID).map(String::as_str),
            Some(DEFAULT_UNIFI_PROFILE_ID)
        );
        assert!(cfg.is_sync_owner(LOCAL_NODE_ID));
    }

    #[test]
    fn shared_profile_bindings_validate_and_resolve() {
        let pin = TlsMode::pin_from_str(
            "sha256:00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
        )
        .unwrap();
        let mut cfg = ClientsConfig {
            unifi_profiles: vec![UnifiProfile {
                id: "home".into(),
                sync_owner: "master".into(),
                connection: UnifiConfig {
                    enabled: true,
                    base_url: "https://192.0.2.1".into(),
                    tls: pin,
                    ..UnifiConfig::default()
                },
            }],
            unifi_bindings: BTreeMap::from([
                ("master".into(), "home".into()),
                ("garage".into(), "home".into()),
            ]),
            ..ClientsConfig::default()
        };
        cfg.validate_with_secret(ok_secret).unwrap();
        assert!(cfg.is_sync_owner("master"));
        assert!(!cfg.is_sync_owner("garage"));
        cfg.resolve_for_node("master");
        assert!(cfg.unifi.enabled);
        cfg.resolve_for_node("garage");
        assert!(!cfg.unifi.enabled);
    }

    #[test]
    fn sync_owner_must_be_bound_to_same_profile() {
        let mut cfg = ClientsConfig {
            unifi_profiles: vec![UnifiProfile {
                id: "home".into(),
                sync_owner: "master".into(),
                connection: UnifiConfig {
                    enabled: true,
                    base_url: "https://192.0.2.1".into(),
                    ..UnifiConfig::default()
                },
            }],
            unifi_bindings: BTreeMap::from([("garage".into(), "home".into())]),
            ..ClientsConfig::default()
        };
        let err = cfg.validate_with_secret(ok_secret).expect_err("owner unbound");
        assert_eq!(err.code(), "clients.config.invalid");
        assert!(err.to_string().contains("sync_owner"));
    }
}
