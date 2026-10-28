//! TLS certificates, ACME DNS-01, and DynDNS for DNScraft.
//!
//! This crate obtains and renews the shared certificate for encrypted DNS
//! listeners (`dns.<domain>` and `*.dns.<domain>`), exposes a hot-reloadable
//! cert resolver, and keeps the node's public A/AAAA records current via
//! Cloudflare.
//!
//! It does **not** bind sockets (that is `listeners`) and does **not** own the
//! Client-ID registry (that is `policy` / `control-api`).
//!
//! So far: [`TlsConfig`], [`TlsError`], [`Clock`] / [`ManualClock`],
//! [`read_secret`], SNI helpers, [`CertStore`], [`CertResolver`], ACME
//! ([`InstantAcme`], [`AcmeDirectory`], [`AcmeOrder`]), [`CloudflareClient`],
//! DNS-01 [`wait_for_txt`], [`issue`], renewal scheduling ([`next_renewal`]),
//! DynDNS ([`dyndns_once`]), and [`TlsEngine`].

#![deny(missing_docs)]

mod acme;
mod acme_http;
mod clock;
mod cloudflare;
mod config;
mod dyndns;
mod engine;
mod error;
mod http_tls;
mod issue;
mod pem_util;
mod propagation;
mod renew;
mod resolver;
mod sni;
mod status;
mod store;

pub use acme::{
    AcmeAccountStatus, AcmeBackend, AcmeDirectory, AcmeOrder, AcmeOrderStatus, ChallengeProgress,
    Dns01Txt, FakeAcmeDirectory, FakeAcmeFail, InstantAcme, RevocationReason, account_status,
    ari_certificate_id, challenge_txt_name, default_identifiers,
};
pub use acme_http::ReqwestHttpClient;
pub use clock::{Clock, ManualClock, SystemClock, wait_until};
pub use cloudflare::{
    CLOUDFLARE_API_BASE, CloudflareClient, DnsRecord, TTL_ACME_TXT, TTL_AUTO, ZoneInfo,
};
pub use config::{
    AcmeAccountConfig, AcmeConfig, AcmeDirectoryKind, CloudflareConfig, DEFAULT_DYNDNS_INTERVAL,
    DEFAULT_ECHO_URL, DEFAULT_EXPIRY_WARN, DEFAULT_PROPAGATION_POLL, DEFAULT_PROPAGATION_TIMEOUT,
    DEFAULT_RENEW_BEFORE, DnsProvider, DnsProviderKind, DynDnsConfig, Eab, Ipv6Identifier,
    Ipv6IdentifierMode, KeyType, ManualCertConfig, ManualDns01Config, NodeEntry,
    NotificationsConfig, TlsConfig, TrustPin, ZoneConfig, validate_public_entry,
};
pub use dnscraft_common::secret::Secret;
pub use dyndns::{
    DynDnsResult, EchoClient, InventoryRecord, dyndns_interval, dyndns_interval_with_rng,
    dyndns_names, dyndns_once, parse_trace_ip, record_inventory,
};
pub use engine::{EngineDeps, EngineInner, TlsEngine};
pub use error::{TlsError, parse_retry_after_header};
pub use issue::issue;
pub use pem_util::{KeyPem, fingerprint_sha256};
pub use propagation::{resolve_nameservers, wait_for_txt, wait_for_txt_with_query_timeout};
pub use renew::{
    AriWindow, BACKOFF_BASE, BACKOFF_CAP, RenewFn, RenewFut, RenewScheduler, ScheduleFn, StatusFn,
    backoff_delay, backoff_delay_with_rng, current_ari_window, is_transient_renew_error,
    next_renewal, next_renewal_with_rng,
};
pub use resolver::CertResolver;

/// Environment variable holding the Cloudflare API token (Zone → DNS → Edit).
pub const CLOUDFLARE_API_TOKEN_ENV: &str = "DNSCRAFT_CLOUDFLARE_API_TOKEN";

/// Reads a secret from `name` or `{name}_FILE`.
///
/// A missing or empty value maps to [`TlsError::SecretMissing`].
pub fn read_secret(name: &str) -> Result<Secret, TlsError> {
    dnscraft_common::secret::read_secret(name).map_err(|name| TlsError::SecretMissing { name })
}
pub use sni::{
    ClientIdRegistry, FIXED_RESERVED_LABELS, ReservedLabels, SniKind, accept_public_sni,
    parse_client_id_sni,
};
pub use status::{
    AriStatus, CertDetail, CertSource, DynDnsAuditEntry, IssueOutcome, IssueRecord, PreflightCheck,
    PreflightReport, RateLimitStatus, StoreHealth, TlsMetrics, TlsStatus, cert_flags,
};
pub use store::{
    CertMeta, CertStore, DYNDNS_AUDIT_LIMIT, HISTORY_LIMIT, IssueState, LoadedCert, TLS_DIR_NAME,
    push_dyndns_audit, push_history,
};
