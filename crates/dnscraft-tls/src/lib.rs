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
//! DNS-01 [`wait_for_txt`], [`issue`], and renewal scheduling ([`next_renewal`]).

#![deny(missing_docs)]

mod acme;
mod acme_http;
mod clock;
mod cloudflare;
mod config;
mod error;
mod issue;
mod pem_util;
mod propagation;
mod renew;
mod resolver;
mod secret;
mod sni;
mod status;
mod store;

pub use acme::{
    AcmeDirectory, AcmeOrder, Dns01Txt, FakeAcmeDirectory, FakeAcmeFail, InstantAcme,
    challenge_txt_name, default_identifiers,
};
pub use acme_http::ReqwestHttpClient;
pub use clock::{Clock, ManualClock, SystemClock, wait_until};
pub use cloudflare::{
    CLOUDFLARE_API_BASE, CloudflareClient, DnsRecord, TTL_ACME_TXT, TTL_AUTO, ZoneInfo,
};
pub use config::{
    AcmeConfig, AcmeDirectoryKind, CloudflareConfig, DEFAULT_DYNDNS_INTERVAL, DEFAULT_ECHO_URL,
    DEFAULT_EXPIRY_WARN, DEFAULT_PROPAGATION_POLL, DEFAULT_PROPAGATION_TIMEOUT,
    DEFAULT_RENEW_BEFORE, DynDnsConfig, KeyType, NodeEntry, TlsConfig, validate_public_entry,
};
pub use error::TlsError;
pub use issue::issue;
pub use pem_util::KeyPem;
pub use propagation::{resolve_nameservers, wait_for_txt};
pub use renew::{
    AriWindow, BACKOFF_BASE, BACKOFF_CAP, RenewFn, RenewFut, RenewScheduler, ScheduleFn, StatusFn,
    apply_cert_flags, backoff_delay, backoff_delay_with_rng, is_transient_renew_error,
    next_renewal, next_renewal_with_rng, parse_retry_after, retry_after_from_error,
};
pub use resolver::CertResolver;
pub use secret::{CLOUDFLARE_API_TOKEN_ENV, Secret, read_secret};
pub use sni::{
    ClientIdRegistry, FIXED_RESERVED_LABELS, ReservedLabels, SniKind, accept_public_sni,
    parse_client_id_sni,
};
pub use status::{TlsStatus, cert_flags};
pub use store::{CertMeta, CertStore, LoadedCert, TLS_DIR_NAME};
