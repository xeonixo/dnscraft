//! TLS module configuration as Rust values.
//!
//! Bootstrap settings may arrive from TOML; the UI edits the same shapes.
//! [`TlsConfig::validate`] normalises domains and enforces the v1 rules from
//! SPEC-tls.md (empty `extra_sans`, DNS-only DynDNS, hostname under
//! `dns.<domain>`, ACME email when enabled, HTTPS-only URLs).

use std::net::{IpAddr, Ipv6Addr};
use std::time::{Duration, SystemTime};

use crate::error::TlsError;
use crate::pem_util::certified_key_from_pem;
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

pub enum KeyType {
    /// NIST P-256 (default).
    #[default]
    EcdsaP256,
    /// NIST P-384.
    EcdsaP384,
}

/// Which ACME directory to use.
#[derive(Clone, Debug, PartialEq, Eq, Default)]

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

/// External Account Binding (RFC 8555 §7.3.4).
#[derive(Clone, PartialEq, Eq)]
pub struct Eab {
    /// Key identifier issued by the CA.
    pub kid: String,
    /// Raw HMAC key value (not base64-decoded); redacted in [`Debug`].
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
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AcmeAccountConfig {
    /// External Account Binding, when the CA requires one.
    pub eab: Option<Eab>,
    /// Operator accepted the CA's terms of service (required to create an account).
    pub tos_agreed: bool,
    /// Deactivate the ACME account when ACME is disabled by config apply.
    pub auto_deactivate: bool,
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
#[derive(Clone, PartialEq, Eq)]
pub struct ManualCertConfig {
    /// Leaf certificate PEM.
    pub cert_pem: String,
    /// Intermediate chain PEM (may be empty).
    pub chain_pem: String,
    /// Private key PEM (redacted).
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
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrustPin {
    /// Lower-case hex SHA-256 of the leaf DER.
    pub sha256: String,
    /// When the pin was recorded.
    pub pinned_at: SystemTime,
}

/// Cloudflare zone settings. The API token is never stored here — see
/// [`crate::secret::read_secret`].
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CloudflareConfig {
    /// Optional zone id; when empty it is resolved by `public_domain` name.
    pub zone_id: Option<String>,
}

/// One additionally configured zone (multi-zone DNS provider).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ZoneConfig {
    /// Zone apex name (e.g. `example.com`).
    pub name: String,
    /// Optional Cloudflare zone id; resolved by name when empty.
    pub zone_id: Option<String>,
}

/// Which DNS provider publishes ACME DNS-01 TXT records.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
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
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ManualDns01Config {
    /// TXT owner name (e.g. `_acme-challenge.dns.example.com`).
    pub name: String,
    /// TXT value the operator published.
    pub value: String,
}

/// DNS provider selection for ACME DNS-01.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DnsProvider {
    /// Provider implementation.
    pub kind: DnsProviderKind,
    /// Cloudflare credentials/zone settings (used when `kind = cloudflare`).
    pub cloudflare: CloudflareConfig,
    /// Additional zones resolved by longest suffix match.
    pub zones: Vec<ZoneConfig>,
    /// Pre-published TXT value (used when `kind = manual`).
    pub manual_txt: Option<ManualDns01Config>,
}

impl DnsProvider {
    /// `true` when this provider can publish records via the Cloudflare API.
    pub fn uses_cloudflare(&self) -> bool {
        self.kind == DnsProviderKind::Cloudflare
    }
}

/// How the stable IPv6 address is chosen.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Ipv6IdentifierMode {
    /// EUI-64 derived address (OS default).
    #[default]
    Eui64,
    /// Stable-privacy address (OS default).
    StablePrivacy,
    /// Use [`Ipv6Identifier::static_address`] verbatim.
    Static,
}

/// IPv6 stable-identifier selection for DynDNS.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Ipv6Identifier {
    /// Selection mode.
    pub mode: Ipv6IdentifierMode,
    /// Fixed address, required when `mode = static`.
    pub static_address: Option<String>,
}

/// Webhook notification settings (SMTP is deferred).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NotificationsConfig {
    /// HTTPS webhook URL; `None` disables delivery.
    pub webhook_url: Option<String>,
    /// Notify when the certificate is expiring/expired.
    pub on_expiry: bool,
    /// Notify when a DynDNS pass fails.
    pub on_dyndns_failure: bool,
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
            manual: None,
            trust_pin: None,
            dns_provider: DnsProvider::default(),
            dyndns: DynDnsConfig::default(),
            notifications: NotificationsConfig::default(),
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
        self.validate_dns_provider()?;
        self.validate_dyndns()?;
        self.validate_manual()?;
        self.validate_trust_pin()?;
        self.validate_notifications()?;
        if self.dns_provider.uses_cloudflare() && (self.acme.enabled || self.dyndns.enabled) {
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
            zone.name = normalise_domain(&zone.name)?;
            if zone.name.is_empty() {
                return Err(TlsError::config("dns_provider.zones has an empty name"));
            }
        }
        self.dns_provider.zones.sort_by(|a, b| a.name.cmp(&b.name));
        self.dns_provider.zones.dedup_by(|a, b| a.name == b.name);
        if let Some(txt) = &mut self.dns_provider.manual_txt {
            txt.name = normalise_domain(&txt.name)?;
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

    fn validate_notifications(&mut self) -> Result<(), TlsError> {
        if let Some(url) = &self.notifications.webhook_url {
            let url = url.trim().to_owned();
            if url.is_empty() {
                self.notifications.webhook_url = None;
            } else {
                check_https_url(&url, self.allow_http_for_tests, "notifications.webhook_url")?;
                self.notifications.webhook_url = Some(url);
            }
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

        // IPv6 stable identifier: static mode needs a valid fixed address.
        let static_addr = self.dyndns.ipv6_identifier.static_address.as_deref();
        match self.dyndns.ipv6_identifier.mode {
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
        if let Some(addr) = &mut self.dyndns.ipv6_identifier.static_address {
            *addr = addr.trim().to_owned();
        }

        // Normalise interface names (trim, drop empties, keep order).
        let mut interfaces = Vec::with_capacity(self.dyndns.interfaces.len());
        for name in &self.dyndns.interfaces {
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
        self.dyndns.interfaces = interfaces;

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

        cfg.allow_http_for_tests = true;
        cfg.notifications.webhook_url = Some("http://127.0.0.1/hook".into());
        cfg.validate_with_token(ok_token).expect("loopback hook");
    }
}
