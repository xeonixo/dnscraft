//! TLS module configuration as Rust values.
//!
//! Bootstrap settings may arrive from TOML; the UI edits the same shapes.
//! [`TlsConfig::validate`] normalises domains and enforces the v1 rules from
//! SPEC-tls.md (empty `extra_sans`, DNS-only DynDNS, hostname under
//! `dns.<domain>`, ACME email when enabled, HTTPS-only URLs).

use std::net::Ipv6Addr;
use std::time::{Duration, SystemTime};

use serde::{Deserialize, Serialize};

use crate::error::TlsError;
use crate::pem_util::certified_key_from_pem;
use crate::{CLOUDFLARE_API_TOKEN_ENV, Secret, read_secret};
use dnscraft_common::config::{check_https_url, normalise_domain};

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
///
/// Wire / TOML form is snake_case (`ecdsa_p256`). PascalCase (`EcdsaP256`) and
/// short (`p256`) aliases are accepted so older snapshots keep loading.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyType {
    /// NIST P-256 (default).
    #[default]
    #[serde(alias = "EcdsaP256", alias = "p256")]
    EcdsaP256,
    /// NIST P-384.
    #[serde(alias = "EcdsaP384", alias = "p384")]
    EcdsaP384,
}

/// Which ACME directory to use.
#[derive(Clone, Debug, PartialEq, Eq, Default, Serialize, Deserialize)]
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

/// Serializes a secret as the bracket marker persisted in TLS config snapshots.
fn serialize_redacted<S: serde::Serializer>(_: &Secret, serializer: S) -> Result<S::Ok, S::Error> {
    serializer.serialize_str("[redacted]")
}

/// External Account Binding (RFC 8555 §7.3.4).
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Eab {
    /// Key identifier issued by the CA.
    pub kid: String,
    /// Raw HMAC key value (not base64-decoded); redacted in [`Debug`].
    #[serde(serialize_with = "serialize_redacted")]
    pub hmac_key: Secret,
}

impl std::fmt::Debug for Eab {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Eab")
            .field("kid", &self.kid)
            .field("hmac_key", &self.hmac_key)
            .finish()
    }
}

/// ACME account policy (EAB, ToS, deactivation).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AcmeAccountConfig {
    /// External Account Binding, when the CA requires one.
    pub eab: Option<Eab>,
    /// Operator accepted the CA's terms of service (required to create an account).
    pub tos_agreed: bool,
    /// Deactivate the ACME account when ACME is disabled by config apply.
    pub auto_deactivate: bool,
}

/// ACME issuance settings.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AcmeConfig {
    /// When false, this node never creates ACME orders (sub-node / import-only).
    pub enabled: bool,
    /// ACME directory endpoint.
    pub directory: AcmeDirectoryKind,
    /// Contact email required by the CA when [`Self::enabled`] is true.
    pub email: String,
    /// How long to wait for TXT visibility on authoritative nameservers.
    #[serde(with = "dnscraft_common::duration::serde")]
    pub propagation_timeout: Duration,
    /// How often to poll those nameservers.
    #[serde(with = "dnscraft_common::duration::serde")]
    pub propagation_poll: Duration,
    /// Account policy (EAB / ToS / auto-deactivate).
    pub account: AcmeAccountConfig,
}

impl Default for AcmeConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            directory: AcmeDirectoryKind::Production,
            email: String::new(),
            propagation_timeout: DEFAULT_PROPAGATION_TIMEOUT,
            propagation_poll: DEFAULT_PROPAGATION_POLL,
            account: AcmeAccountConfig::default(),
        }
    }
}

/// Manually supplied certificate material (`tls_mode = manual`).
///
/// The key is persisted to `key.pem` (mode 0o600) by the store and is
/// redacted in [`Debug`].
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManualCertConfig {
    /// Leaf certificate PEM.
    pub cert_pem: String,
    /// Intermediate chain PEM (may be empty).
    pub chain_pem: String,
    /// Private key PEM (redacted).
    #[serde(serialize_with = "serialize_redacted")]
    pub key_pem: Secret,
}

impl std::fmt::Debug for ManualCertConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ManualCertConfig")
            .field("cert_pem_len", &self.cert_pem.len())
            .field("chain_pem_len", &self.chain_pem.len())
            .field("key_pem", &self.key_pem)
            .finish()
    }
}

impl ManualCertConfig {
    /// Leaf + chain as one PEM bundle, leaf first.
    pub fn fullchain_pem(&self) -> String {
        let mut out = self.cert_pem.trim().to_owned();
        let chain = self.chain_pem.trim();
        if !chain.is_empty() {
            out.push('\n');
            out.push_str(chain);
        }
        out.push('\n');
        out
    }
}

/// Pinned leaf SHA-256 fingerprint (trust pinning).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustPin {
    /// Lower-case hex SHA-256 of the leaf DER.
    pub sha256: String,
    /// When the pin was recorded.
    pub pinned_at: SystemTime,
}

/// Cloudflare zone settings. The API token is never stored here — see
/// [`crate::read_secret`].
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareConfig {
    /// Optional zone id; when empty it is resolved by `public_domain` name.
    pub zone_id: Option<String>,
}

/// One additionally configured zone (multi-zone DNS provider).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZoneConfig {
    /// Zone apex name (e.g. `example.com`).
    pub name: String,
    /// Optional Cloudflare zone id; resolved by name when empty.
    pub zone_id: Option<String>,
}

/// Which DNS provider publishes ACME DNS-01 TXT records.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DnsProviderKind {
    /// Cloudflare API (the only provider that can publish automatically).
    #[default]
    Cloudflare,
    /// Operator publishes the challenge TXT manually; issuance reports it.
    Manual,
    /// No DNS provider; ACME DNS-01 cannot run.
    None,
}

/// Operator-published `_acme-challenge` TXT record.
///
/// One certificate order needs two distinct values at the same owner
/// (`dns.<domain>` and `*.dns.<domain>`); configure one entry per value.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManualDns01Config {
    /// TXT owner name (e.g. `_acme-challenge.dns.example.com`).
    pub name: String,
    /// TXT value the operator published.
    pub value: String,
}

/// DNS provider selection for ACME DNS-01.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsProvider {
    /// Provider implementation.
    pub kind: DnsProviderKind,
    /// Cloudflare credentials/zone settings (used when `kind = cloudflare`).
    pub cloudflare: CloudflareConfig,
    /// Additional zones resolved by longest suffix match.
    pub zones: Vec<ZoneConfig>,
    /// Pre-published TXT records (used when `kind = manual`). One entry per
    /// DNS-01 challenge value; two share the same owner for apex + wildcard.
    pub manual_txt: Vec<ManualDns01Config>,
}

impl DnsProvider {
    /// `true` when this provider can publish records via the Cloudflare API.
    pub fn uses_cloudflare(&self) -> bool {
        self.kind == DnsProviderKind::Cloudflare
    }
}

/// How the stable IPv6 address is chosen.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Ipv6IdentifierMode {
    /// EUI-64 derived address (OS default): dynamic prefix, stable interface id.
    #[default]
    Eui64,
    /// Stable-privacy address (OS default).
    StablePrivacy,
    /// Use [`Ipv6Identifier::static_address`] verbatim.
    Static,
}

/// IPv6 stable-identifier selection for DynDNS.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ipv6Identifier {
    /// Selection mode.
    pub mode: Ipv6IdentifierMode,
    /// Fixed address, required when `mode = static`.
    pub static_address: Option<String>,
}

/// Webhook notification settings (SMTP is deferred).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NotificationsConfig {
    /// HTTPS webhook URL; `None` disables delivery.
    pub webhook_url: Option<String>,
    /// Notify when the certificate is expiring/expired.
    pub on_expiry: bool,
    /// Notify when a DynDNS pass fails.
    pub on_dyndns_failure: bool,
}

fn default_true() -> bool {
    true
}

/// Per-node DynDNS profile inside a cluster-wide config snapshot.
///
/// Each cluster member picks the entry whose [`Self::node_id`] matches its
/// local id (`DNSCRAFT_NODE_ID`). Standalone deployments leave
/// [`DynDnsConfig::nodes`] empty and use the flat hostname fields.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DynDnsNodeProfile {
    /// Cluster node id (e.g. `node1`).
    pub node_id: String,
    /// This node's public hostname, e.g. `ns1.dns.example.com`.
    pub hostname: String,
    /// When false, this node does not run DynDNS (per-node opt-out).
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Publish A for this node when DynDNS runs.
    #[serde(default = "default_true")]
    pub ipv4: bool,
    /// Publish AAAA for this node when DynDNS runs.
    #[serde(default = "default_true")]
    pub ipv6: bool,
    /// When true, this node maintains apex/wildcard **CNAME** → its hostname.
    /// At most one profile may set this; requires [`Self::enabled`].
    #[serde(default)]
    pub public_entry: bool,
    /// How this node selects its IPv6 address (EUI-64 / stable-privacy / static).
    #[serde(default)]
    pub ipv6_identifier: Ipv6Identifier,
    /// Local interfaces for IPv6 discovery on this node. Empty = public-IP echo.
    #[serde(default)]
    pub interfaces: Vec<String>,
}

impl Default for DynDnsNodeProfile {
    fn default() -> Self {
        Self {
            node_id: String::new(),
            hostname: String::new(),
            enabled: true,
            ipv4: true,
            ipv6: true,
            public_entry: false,
            ipv6_identifier: Ipv6Identifier::default(),
            interfaces: Vec::new(),
        }
    }
}

/// DynDNS settings for public hostnames at the DNS provider.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DynDnsConfig {
    /// When false, DynDNS tasks do not run on this process.
    pub enabled: bool,
    /// This node's public hostname, e.g. `ns1.dns.example.com`.
    ///
    /// Used when [`Self::nodes`] is empty (standalone). With a non-empty
    /// `nodes` list, prefer [`Self::resolve_for_node`].
    pub hostname: String,
    /// When true, this node also maintains `*.dns.<domain>` and `dns.<domain>`
    /// as **CNAME** records targeting [`Self::hostname`].
    pub public_entry: bool,
    /// Per-node hostnames / opt-in flags for a cluster snapshot.
    ///
    /// Empty = use flat [`Self::hostname`] / [`Self::public_entry`] /
    /// [`Self::enabled`] / [`Self::ipv4`] / [`Self::ipv6`].
    #[serde(default)]
    pub nodes: Vec<DynDnsNodeProfile>,
    /// Reserved (non–Client-ID) labels for this deployment, usually node names.
    /// The hostname's leftmost label must be one of these.
    pub reserved_labels: Vec<String>,
    /// How often to check and update records (±10 % jitter applied later).
    #[serde(with = "dnscraft_common::duration::serde")]
    pub interval: Duration,
    /// Public IP echo URL (HTTPS).
    pub echo_url: String,
    /// Discover and publish IPv4.
    pub ipv4: bool,
    /// Discover and publish IPv6.
    pub ipv6: bool,
    /// Must be `false` (DNS-only). Orange-cloud proxy would break DoT/DoQ.
    pub proxied: bool,
    /// How the stable IPv6 address is selected.
    pub ipv6_identifier: Ipv6Identifier,
    /// Local interfaces to read IPv6 addresses from. Empty = public-IP echo.
    pub interfaces: Vec<String>,
    /// List/inspect managed records from the status API.
    pub record_inventory: bool,
}

impl Default for DynDnsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            hostname: String::new(),
            public_entry: false,
            nodes: Vec::new(),
            reserved_labels: Vec::new(),
            interval: DEFAULT_DYNDNS_INTERVAL,
            echo_url: DEFAULT_ECHO_URL.to_owned(),
            ipv4: true,
            ipv6: true,
            proxied: false,
            ipv6_identifier: Ipv6Identifier::default(),
            interfaces: Vec::new(),
            record_inventory: false,
        }
    }
}

impl DynDnsConfig {
    /// Apply the cluster profile for `node_id` onto a copy of this config.
    ///
    /// Prefers a matching [`Self::nodes`] entry for hostname, public-entry,
    /// enabled, address-family flags, and IPv6 discovery; otherwise keeps the
    /// flat fields.
    pub fn resolve_for_node(&self, node_id: Option<&str>) -> Self {
        let mut out = self.clone();
        if let Some(id) = node_id
            && let Some(profile) = self.nodes.iter().find(|p| p.node_id == id)
        {
            out.hostname = profile.hostname.clone();
            out.public_entry = profile.public_entry && profile.enabled;
            out.enabled = self.enabled && profile.enabled;
            out.ipv4 = profile.ipv4;
            out.ipv6 = profile.ipv6;
            out.ipv6_identifier = profile.ipv6_identifier.clone();
            out.interfaces = profile.interfaces.clone();
        }
        out
    }
}

/// Top-level TLS configuration.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TlsConfig {
    /// Public registered domain (e.g. `example.com`). Cert SANs are
    /// `dns.<domain>` and `*.dns.<domain>`.
    pub public_domain: String,
    /// Extra SANs. Must be empty in v1.
    pub extra_sans: Vec<String>,
    /// Leaf key type.
    pub key_type: KeyType,
    /// Renew when `not_after - now` falls below this (unless ARI says sooner).
    #[serde(with = "dnscraft_common::duration::serde")]
    pub renew_before: Duration,
    /// Status flag [`crate::TlsError::CertExpiring`] below this remaining time.
    #[serde(with = "dnscraft_common::duration::serde")]
    pub expiry_warn: Duration,
    /// ACME settings.
    pub acme: AcmeConfig,
    /// Manual certificate material (bootstrap / `tls_mode = manual`).
    pub manual: Option<ManualCertConfig>,
    /// Pinned leaf fingerprint (trust pinning).
    pub trust_pin: Option<TrustPin>,
    /// DNS provider for ACME DNS-01.
    pub dns_provider: DnsProvider,
    /// DynDNS settings.
    pub dyndns: DynDnsConfig,
    /// Webhook notification settings (delivery is control-api's job).
    pub notifications: NotificationsConfig,
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
            manual: None,
            trust_pin: None,
            dns_provider: DnsProvider::default(),
            dyndns: DynDnsConfig::default(),
            notifications: NotificationsConfig::default(),
        }
    }
}

impl TlsConfig {
    /// Validates and normalises this config in place.
    ///
    /// When ACME or DynDNS needs Cloudflare, probes
    /// [`CLOUDFLARE_API_TOKEN_ENV`] (or its `_FILE` form). An empty or
    /// deferred token is allowed here — the control-api / UI may supply it
    /// separately; Cloudflare calls fail later with `tls.secret.missing`.
    pub fn validate(&mut self) -> Result<(), TlsError> {
        self.validate_with_token_impl(read_secret, false)
    }

    /// Like [`Self::validate`], but uses `lookup` for the Cloudflare token.
    ///
    /// Tests inject a fake lookup so they never mutate process environment
    /// (`set_var` is `unsafe` and forbidden in this workspace).
    pub fn validate_with_token(
        &mut self,
        lookup: impl FnOnce(&str) -> Result<Secret, TlsError>,
    ) -> Result<(), TlsError> {
        self.validate_with_token_impl(lookup, false)
    }

    /// Shared validation; `allow_http` lets tests accept loopback `http://` URLs.
    pub(crate) fn validate_with_token_impl(
        &mut self,
        lookup: impl FnOnce(&str) -> Result<Secret, TlsError>,
        allow_http: bool,
    ) -> Result<(), TlsError> {
        self.public_domain = normalise_domain(&self.public_domain).map_err(TlsError::config)?;
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

        self.validate_acme(allow_http)?;
        self.validate_dns_provider()?;
        self.validate_dyndns(allow_http)?;
        self.validate_manual()?;
        self.validate_trust_pin()?;
        self.validate_notifications(allow_http)?;
        if self.dns_provider.uses_cloudflare() && (self.acme.enabled || self.dyndns.enabled) {
            // Probe only: `Err` means the lookup itself failed in a hard way.
            // Missing / empty tokens are deferred to runtime (UI/kv/env).
            match lookup(CLOUDFLARE_API_TOKEN_ENV) {
                Ok(_) => {}
                Err(TlsError::SecretMissing { .. }) => {}
                Err(other) => return Err(other),
            }
        }
        Ok(())
    }

    fn validate_acme(&mut self, allow_http: bool) -> Result<(), TlsError> {
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
            check_https_url(url, allow_http, "acme.directory").map_err(TlsError::config)?;
        }
        if let Some(eab) = &mut self.acme.account.eab {
            eab.kid = eab.kid.trim().to_owned();
            if eab.kid.is_empty() || eab.hmac_key.expose().trim().is_empty() {
                return Err(TlsError::AcmeAccountEab {
                    message: "eab.kid and eab.hmac_key are required".into(),
                });
            }
        }
        Ok(())
    }

    fn validate_dns_provider(&mut self) -> Result<(), TlsError> {
        for zone in &mut self.dns_provider.zones {
            zone.name = normalise_domain(&zone.name).map_err(TlsError::config)?;
            if zone.name.is_empty() {
                return Err(TlsError::config("dns_provider.zones has an empty name"));
            }
        }
        self.dns_provider.zones.sort_by(|a, b| a.name.cmp(&b.name));
        self.dns_provider.zones.dedup_by(|a, b| a.name == b.name);
        for txt in &mut self.dns_provider.manual_txt {
            txt.name = normalise_domain(&txt.name).map_err(TlsError::config)?;
            txt.value = txt.value.trim().to_owned();
            if txt.name.is_empty() || txt.value.is_empty() {
                return Err(TlsError::DnsManual {
                    message: "manual_txt requires a non-empty name and value".into(),
                });
            }
        }
        match self.dns_provider.kind {
            DnsProviderKind::None if self.acme.enabled => {
                return Err(TlsError::DnsProviderAuth {
                    message: "acme requires dns_provider.kind = cloudflare or manual".into(),
                });
            }
            DnsProviderKind::None | DnsProviderKind::Manual if self.dyndns.enabled => {
                return Err(TlsError::config(
                    "dyndns requires dns_provider.kind = cloudflare",
                ));
            }
            _ => {}
        }
        Ok(())
    }

    fn validate_manual(&mut self) -> Result<(), TlsError> {
        let Some(manual) = &self.manual else {
            return Ok(());
        };
        let fullchain = manual.fullchain_pem();
        certified_key_from_pem(fullchain.as_bytes(), manual.key_pem.expose().as_bytes()).map_err(
            |message| TlsError::CertManualInvalid {
                message: format!("manual certificate: {message}"),
            },
        )?;
        Ok(())
    }

    fn validate_trust_pin(&mut self) -> Result<(), TlsError> {
        let Some(pin) = &mut self.trust_pin else {
            return Ok(());
        };
        let normalised: String = pin
            .sha256
            .chars()
            .filter(|c| *c != ':' && !c.is_ascii_whitespace())
            .map(|c| c.to_ascii_lowercase())
            .collect();
        if normalised.len() != 64 || !normalised.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(TlsError::config(
                "trust_pin.sha256 must be a SHA-256 hex fingerprint (64 hex chars)",
            ));
        }
        pin.sha256 = normalised;
        Ok(())
    }

    fn validate_notifications(&mut self, allow_http: bool) -> Result<(), TlsError> {
        if let Some(url) = &self.notifications.webhook_url {
            let url = url.trim().to_owned();
            if url.is_empty() {
                self.notifications.webhook_url = None;
            } else {
                check_https_url(&url, allow_http, "notifications.webhook_url")
                    .map_err(TlsError::config)?;
                self.notifications.webhook_url = Some(url);
            }
        }
        Ok(())
    }

    fn validate_dyndns(&mut self, allow_http: bool) -> Result<(), TlsError> {
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
        check_https_url(&self.dyndns.echo_url, allow_http, "dyndns.echo_url")
            .map_err(TlsError::config)?;

        Self::normalise_ipv6_identifier(&mut self.dyndns.ipv6_identifier)?;
        self.dyndns.interfaces = Self::normalise_interfaces(&self.dyndns.interfaces)?;

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

        let expected_suffix = format!("dns.{}", self.public_domain);

        for profile in &mut self.dyndns.nodes {
            profile.node_id = profile.node_id.trim().to_owned();
            if profile.node_id.is_empty() {
                return Err(TlsError::config("dyndns.nodes[].node_id is empty"));
            }
            profile.hostname = normalise_domain(&profile.hostname).map_err(TlsError::config)?;
            Self::validate_dyndns_hostname(
                &profile.hostname,
                &expected_suffix,
                &self.public_domain,
                &self.dyndns.reserved_labels,
            )?;
            if profile.public_entry && !profile.enabled {
                return Err(TlsError::config(
                    "dyndns.nodes[] public_entry requires enabled=true",
                ));
            }
            if profile.enabled && !profile.ipv4 && !profile.ipv6 {
                return Err(TlsError::config(format!(
                    "dyndns.nodes[{}] must enable at least one of ipv4 or ipv6",
                    profile.node_id
                )));
            }
            if profile.enabled && profile.ipv6 {
                Self::normalise_ipv6_identifier(&mut profile.ipv6_identifier)?;
            }
            profile.interfaces = Self::normalise_interfaces(&profile.interfaces)?;
        }
        if self.dyndns.nodes.iter().filter(|p| p.public_entry).count() > 1 {
            return Err(TlsError::DyndnsEntryConflict);
        }

        self.dyndns.hostname = normalise_domain(&self.dyndns.hostname).map_err(TlsError::config)?;
        if self.dyndns.nodes.is_empty() || !self.dyndns.hostname.is_empty() {
            Self::validate_dyndns_hostname(
                &self.dyndns.hostname,
                &expected_suffix,
                &self.public_domain,
                &self.dyndns.reserved_labels,
            )?;
        }
        Ok(())
    }

    fn normalise_ipv6_identifier(ident: &mut Ipv6Identifier) -> Result<(), TlsError> {
        let static_addr = ident.static_address.as_deref();
        match ident.mode {
            Ipv6IdentifierMode::Static => {
                let Some(addr) = static_addr else {
                    return Err(TlsError::DyndnsIpv6 {
                        message:
                            "dyndns.ipv6_identifier.static_address is required for mode=static"
                                .into(),
                    });
                };
                addr.trim()
                    .parse::<Ipv6Addr>()
                    .map_err(|_| TlsError::DyndnsIpv6 {
                        message: format!(
                            "dyndns.ipv6_identifier.static_address {addr:?} is not IPv6"
                        ),
                    })?;
            }
            Ipv6IdentifierMode::Eui64 | Ipv6IdentifierMode::StablePrivacy => {
                if static_addr.is_some() {
                    return Err(TlsError::DyndnsIpv6 {
                        message: "static_address is only valid with mode=static".into(),
                    });
                }
            }
        }
        if let Some(addr) = &mut ident.static_address {
            *addr = addr.trim().to_owned();
        }
        Ok(())
    }

    fn normalise_interfaces(raw: &[String]) -> Result<Vec<String>, TlsError> {
        let mut interfaces = Vec::with_capacity(raw.len());
        for name in raw {
            let name = name.trim().to_owned();
            if name.is_empty() {
                return Err(TlsError::config(
                    "dyndns.interfaces contains an empty interface name",
                ));
            }
            if !interfaces.contains(&name) {
                interfaces.push(name);
            }
        }
        Ok(interfaces)
    }

    fn validate_dyndns_hostname(
        hostname: &str,
        expected_suffix: &str,
        public_domain: &str,
        reserved_labels: &[String],
    ) -> Result<(), TlsError> {
        let Some((label, rest)) = hostname.split_once('.') else {
            return Err(TlsError::config(format!(
                "dyndns.hostname {hostname:?} is not <label>.dns.<public_domain>"
            )));
        };
        if rest != expected_suffix {
            return Err(TlsError::config(format!(
                "dyndns.hostname {hostname:?} must be <label>.dns.{public_domain}"
            )));
        }
        if label.contains('.') {
            return Err(TlsError::config(
                "dyndns.hostname must have exactly one label below dns.<domain>",
            ));
        }
        let reserved_ok = reserved_labels
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
                account: AcmeAccountConfig {
                    tos_agreed: true,
                    ..AcmeAccountConfig::default()
                },
            },
            manual: None,
            trust_pin: None,
            dns_provider: DnsProvider::default(),
            dyndns: DynDnsConfig {
                enabled: true,
                hostname: "Node1.DNS.Example.COM.".into(),
                public_entry: false,
                nodes: Vec::new(),
                reserved_labels: vec!["node1".into(), "node2".into()],
                interval: DEFAULT_DYNDNS_INTERVAL,
                echo_url: DEFAULT_ECHO_URL.into(),
                ipv4: true,
                ipv6: true,
                proxied: false,
                ipv6_identifier: Ipv6Identifier::default(),
                interfaces: Vec::new(),
                record_inventory: false,
            },
            notifications: NotificationsConfig::default(),
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
    fn config_missing_token_with_acme_enabled_is_deferred() {
        // Token may arrive later via UI/kv; config validation must not block.
        let mut cfg = example_config();
        cfg.validate_with_token(missing_token)
            .expect("deferred token ok at config time");
    }

    #[test]
    fn config_missing_token_with_dyndns_enabled_is_deferred() {
        let mut cfg = example_config();
        cfg.acme.enabled = false;
        cfg.acme.email.clear();
        cfg.dyndns.enabled = true;
        cfg.validate_with_token(missing_token)
            .expect("deferred token ok at config time");
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
        cfg.dyndns.echo_url = "http://127.0.0.1:9/trace".into();
        cfg.validate_with_token_impl(ok_token, true)
            .expect("loopback hatch");
    }

    #[test]
    fn config_validate_public_entry_rejects_two_nodes() {
        let nodes = [
            NodeEntry { public_entry: true },
            NodeEntry { public_entry: true },
        ];
        let err = validate_public_entry(&nodes).expect_err("conflict");
        assert_eq!(err.code(), "tls.dyndns.entry_conflict");
    }

    #[test]
    fn config_validate_public_entry_allows_one() {
        let nodes = [
            NodeEntry { public_entry: true },
            NodeEntry {
                public_entry: false,
            },
        ];
        validate_public_entry(&nodes).expect("one entry ok");
        validate_public_entry(&[]).expect("empty ok");
    }

    #[test]
    fn resolve_for_node_applies_opt_in_and_families() {
        let cfg = DynDnsConfig {
            hostname: "ns1.dns.example.com".into(),
            public_entry: true,
            enabled: true,
            ipv4: true,
            ipv6: true,
            nodes: vec![
                DynDnsNodeProfile {
                    node_id: "node1".into(),
                    hostname: "ns1.dns.example.com".into(),
                    enabled: true,
                    ipv4: true,
                    ipv6: true,
                    public_entry: true,
                    interfaces: vec!["eth0".into()],
                    ipv6_identifier: Ipv6Identifier {
                        mode: Ipv6IdentifierMode::Eui64,
                        static_address: None,
                    },
                },
                DynDnsNodeProfile {
                    node_id: "node2".into(),
                    hostname: "ns2.dns.example.com".into(),
                    enabled: false,
                    ipv4: true,
                    ipv6: true,
                    public_entry: false,
                    interfaces: vec!["enp1s0".into()],
                    ..Default::default()
                },
            ],
            ..DynDnsConfig::default()
        };
        let n1 = cfg.resolve_for_node(Some("node1"));
        assert!(n1.enabled);
        assert!(n1.public_entry);
        assert!(n1.ipv4);
        assert!(n1.ipv6);
        assert_eq!(n1.interfaces, vec!["eth0".to_owned()]);
        let n2 = cfg.resolve_for_node(Some("node2"));
        assert!(!n2.enabled);
        assert!(!n2.public_entry);
        assert_eq!(n2.hostname, "ns2.dns.example.com");
        assert_eq!(n2.interfaces, vec!["enp1s0".to_owned()]);
    }

    #[test]
    fn config_rejects_public_entry_on_disabled_profile() {
        let mut cfg = example_config();
        cfg.dyndns.nodes = vec![DynDnsNodeProfile {
            node_id: "node1".into(),
            hostname: "node1.dns.example.com".into(),
            enabled: false,
            ipv4: true,
            ipv6: true,
            public_entry: true,
            ..Default::default()
        }];
        let err = cfg
            .validate_with_token(ok_token)
            .expect_err("entry needs enabled");
        assert_eq!(err.code(), "tls.config.invalid");
    }

    #[test]
    fn ipv6_mode_serialises_snake_case() {
        let json = serde_json::to_value(Ipv6IdentifierMode::StablePrivacy).unwrap();
        assert_eq!(json, "stable_privacy");
        let back: Ipv6IdentifierMode = serde_json::from_value(serde_json::json!("eui64")).unwrap();
        assert_eq!(back, Ipv6IdentifierMode::Eui64);
    }

    #[test]
    fn config_token_absent_from_debug_of_validated_config() {
        let mut cfg = example_config();
        cfg.validate_with_token(ok_token).unwrap();
        let shown = format!("{cfg:?}");
        assert!(!shown.contains("test-token-not-real"));
        assert!(!shown.contains("BEGIN"));
    }

    fn self_signed_pem() -> (String, String) {
        let certified = rcgen::generate_simple_self_signed(vec!["dns.example.com".into()]).unwrap();
        (certified.cert.pem(), certified.signing_key.serialize_pem())
    }

    #[test]
    fn config_manual_cert_validates_and_redacts_key() {
        let (cert, key) = self_signed_pem();
        let mut cfg = example_config();
        cfg.dns_provider.kind = DnsProviderKind::Cloudflare;
        cfg.manual = Some(ManualCertConfig {
            cert_pem: cert,
            chain_pem: String::new(),
            key_pem: Secret::new(key),
        });
        cfg.validate_with_token(ok_token).expect("manual valid");
        assert!(!format!("{cfg:?}").contains("PRIVATE KEY"));

        cfg.manual.as_mut().unwrap().key_pem = Secret::new("not a key");
        let err = cfg.validate_with_token(ok_token).expect_err("bad key");
        assert_eq!(err.code(), "tls.cert.manual.invalid");
    }

    #[test]
    fn config_manual_provider_needs_no_cloudflare_token() {
        let mut cfg = example_config();
        cfg.dns_provider.kind = DnsProviderKind::Manual;
        cfg.dyndns.enabled = false;
        cfg.validate_with_token(|_| panic!("manual provider must not need a token"))
            .expect("manual provider ok");
    }

    #[test]
    fn config_none_provider_conflicts_with_acme() {
        let mut cfg = example_config();
        cfg.dns_provider.kind = DnsProviderKind::None;
        let err = cfg.validate_with_token(ok_token).expect_err("none + acme");
        assert_eq!(err.code(), "tls.dns.provider.auth");
    }

    #[test]
    fn config_dyndns_requires_cloudflare_provider() {
        let mut cfg = example_config();
        cfg.dns_provider.kind = DnsProviderKind::Manual;
        let err = cfg
            .validate_with_token(ok_token)
            .expect_err("manual + dyndns");
        assert_eq!(err.code(), "tls.config.invalid");
    }

    #[test]
    fn config_zones_are_normalised_and_deduplicated() {
        let mut cfg = example_config();
        cfg.dns_provider.zones = vec![
            ZoneConfig {
                name: "B.Example.COM.".into(),
                zone_id: None,
            },
            ZoneConfig {
                name: "b.example.com".into(),
                zone_id: Some("z2".into()),
            },
            ZoneConfig {
                name: "a.example.com".into(),
                zone_id: None,
            },
        ];
        cfg.validate_with_token(ok_token).expect("zones");
        let names: Vec<_> = cfg
            .dns_provider
            .zones
            .iter()
            .map(|z| z.name.as_str())
            .collect();
        assert_eq!(names, vec!["a.example.com", "b.example.com"]);
    }

    #[test]
    fn config_ipv6_static_requires_valid_address_and_interfaces_normalise() {
        let mut cfg = example_config();
        cfg.dyndns.ipv6_identifier = Ipv6Identifier {
            mode: Ipv6IdentifierMode::Static,
            static_address: Some("not-an-ip".into()),
        };
        let err = cfg.validate_with_token(ok_token).expect_err("bad static");
        assert_eq!(err.code(), "tls.dyndns.ipv6");

        cfg.dyndns.ipv6_identifier.static_address = Some("2001:db8::10".into());
        cfg.dyndns.interfaces = vec![" eth0 ".into(), "eth0".into(), "eth1".into()];
        cfg.validate_with_token(ok_token).expect("valid static");
        assert_eq!(cfg.dyndns.interfaces, vec!["eth0", "eth1"]);
        assert_eq!(
            cfg.dyndns.ipv6_identifier.static_address.as_deref(),
            Some("2001:db8::10")
        );

        cfg.dyndns.ipv6_identifier.mode = Ipv6IdentifierMode::Eui64;
        let err = cfg
            .validate_with_token(ok_token)
            .expect_err("static addr with eui64");
        assert_eq!(err.code(), "tls.dyndns.ipv6");
    }

    #[test]
    fn config_trust_pin_normalises_and_rejects_bad_length() {
        let mut cfg = example_config();
        cfg.trust_pin = Some(TrustPin {
            sha256: "AB:CD".into(),
            pinned_at: std::time::UNIX_EPOCH,
        });
        let err = cfg.validate_with_token(ok_token).expect_err("short pin");
        assert_eq!(err.code(), "tls.config.invalid");

        let fp = "ab".repeat(32);
        cfg.trust_pin = Some(TrustPin {
            sha256: fp.to_ascii_uppercase(),
            pinned_at: std::time::UNIX_EPOCH,
        });
        cfg.validate_with_token(ok_token).expect("pin");
        assert_eq!(cfg.trust_pin.as_ref().unwrap().sha256, fp);
    }

    #[test]
    fn config_notifications_require_https() {
        let mut cfg = example_config();
        cfg.notifications.webhook_url = Some("http://127.0.0.1/hook".into());
        let err = cfg.validate_with_token(ok_token).expect_err("http hook");
        assert_eq!(err.code(), "tls.config.invalid");

        cfg.notifications.webhook_url = Some("http://127.0.0.1/hook".into());
        cfg.validate_with_token_impl(ok_token, true)
            .expect("loopback hook");
    }

    /// Representative config carrying both `Secret`-typed fields.
    fn serde_config() -> TlsConfig {
        let mut cfg = example_config();
        cfg.public_domain = "example.com".into();
        cfg.acme.account.eab = Some(Eab {
            kid: "kid-example".into(),
            hmac_key: Secret::new("eab-hmac-key-plaintext"),
        });
        cfg.manual = Some(ManualCertConfig {
            cert_pem: "-----BEGIN CERTIFICATE-----\nMIIBexample\n-----END CERTIFICATE-----\n"
                .into(),
            chain_pem: String::new(),
            key_pem: Secret::new(
                "-----BEGIN PRIVATE KEY-----\nMIIEkeyplaintext\n-----END PRIVATE KEY-----\n",
            ),
        });
        cfg
    }

    #[test]
    fn key_type_serializes_snake_case_and_accepts_legacy_aliases() {
        assert_eq!(
            serde_json::to_value(KeyType::EcdsaP256).unwrap(),
            serde_json::json!("ecdsa_p256")
        );
        assert_eq!(
            serde_json::to_value(KeyType::EcdsaP384).unwrap(),
            serde_json::json!("ecdsa_p384")
        );
        for wire in ["ecdsa_p256", "EcdsaP256", "p256"] {
            let parsed: KeyType = serde_json::from_value(serde_json::json!(wire)).unwrap();
            assert_eq!(parsed, KeyType::EcdsaP256, "{wire}");
        }
        for wire in ["ecdsa_p384", "EcdsaP384", "p384"] {
            let parsed: KeyType = serde_json::from_value(serde_json::json!(wire)).unwrap();
            assert_eq!(parsed, KeyType::EcdsaP384, "{wire}");
        }
    }

    #[test]
    fn config_serde_round_trip_preserves_non_secret_fields() {
        let cfg = serde_config();
        let json = serde_json::to_string(&cfg).expect("serialize");
        assert!(json.contains("\"ecdsa_p256\""), "{json}");
        let back: TlsConfig = serde_json::from_str(&json).expect("deserialize");

        assert_eq!(back.public_domain, cfg.public_domain);
        assert_eq!(back.key_type, cfg.key_type);
        assert_eq!(back.renew_before, cfg.renew_before);
        assert_eq!(back.expiry_warn, cfg.expiry_warn);
        assert_eq!(back.acme.directory, cfg.acme.directory);
        assert_eq!(back.acme.email, cfg.acme.email);
        assert_eq!(back.acme.propagation_poll, cfg.acme.propagation_poll);
        assert_eq!(back.dns_provider, cfg.dns_provider);
        assert_eq!(back.dyndns, cfg.dyndns);
        assert_eq!(back.notifications, cfg.notifications);
        assert_eq!(back.trust_pin, cfg.trust_pin);

        let eab = back.acme.account.eab.expect("eab");
        assert_eq!(eab.kid, "kid-example");
        assert_eq!(eab.hmac_key, Secret::new("[redacted]"));
        let manual = back.manual.expect("manual");
        assert_eq!(
            manual.cert_pem,
            cfg.manual.as_ref().expect("manual").cert_pem
        );
        assert_eq!(manual.key_pem, Secret::new("[redacted]"));
    }

    #[test]
    fn duration_fields_parse_human_strings() {
        let mut value = serde_json::to_value(serde_config()).expect("serialize");
        value["renew_before"] = "90s".into();
        value["expiry_warn"] = "1d".into();
        value["acme"]["propagation_timeout"] = "1d".into();
        value["acme"]["propagation_poll"] = "500ms".into();
        value["dyndns"]["interval"] = "5m".into();
        let cfg: TlsConfig = serde_json::from_value(value.clone()).expect("deserialize");
        assert_eq!(cfg.renew_before, Duration::from_secs(90));
        assert_eq!(cfg.expiry_warn, Duration::from_secs(86_400));
        assert_eq!(cfg.acme.propagation_timeout, Duration::from_secs(86_400));
        assert_eq!(cfg.acme.propagation_poll, Duration::from_millis(500));
        assert_eq!(cfg.dyndns.interval, Duration::from_secs(300));

        let json = serde_json::to_value(&cfg).expect("serialize");
        assert_eq!(json["renew_before"], "90s");
        assert_eq!(json["expiry_warn"], "1d");
        assert_eq!(json["acme"]["propagation_poll"], "500ms");
        assert_eq!(json["dyndns"]["interval"], "5m");

        value["renew_before"] = "1x".into();
        assert!(serde_json::from_value::<TlsConfig>(value).is_err());
    }

    #[test]
    fn config_serde_never_contains_secret_plaintext() {
        const HMAC: &str = "eab-hmac-key-plaintext";
        const KEY: &str = "MIIEkeyplaintext";
        let mut cfg = serde_config();
        cfg.acme.account.eab = Some(Eab {
            kid: "kid-example".into(),
            hmac_key: Secret::new(HMAC),
        });
        cfg.manual = Some(ManualCertConfig {
            cert_pem: "-----BEGIN CERTIFICATE-----\nMIIBexample\n-----END CERTIFICATE-----\n"
                .into(),
            chain_pem: String::new(),
            key_pem: Secret::new(format!(
                "-----BEGIN PRIVATE KEY-----\n{KEY}\n-----END PRIVATE KEY-----\n"
            )),
        });

        let json = serde_json::to_string(&cfg).expect("serialize");

        assert!(!json.contains(HMAC), "EAB HMAC key leaked: {json}");
        assert!(!json.contains(KEY), "manual private key leaked: {json}");
        // Only the marker appears, once per secret field.
        assert_eq!(json.matches("[redacted]").count(), 2, "{json}");
        assert!(json.contains("example.com"));
    }
}
