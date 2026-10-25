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
//! [`read_secret`], SNI helpers, [`CertStore`], and [`CertResolver`].

#![deny(missing_docs)]

mod clock;
mod config;
mod error;
mod pem_util;
mod resolver;
mod secret;
mod sni;
mod store;

pub use clock::{Clock, ManualClock, SystemClock};
pub use config::{
    AcmeConfig, AcmeDirectoryKind, CloudflareConfig, DEFAULT_DYNDNS_INTERVAL, DEFAULT_ECHO_URL,
    DEFAULT_EXPIRY_WARN, DEFAULT_PROPAGATION_POLL, DEFAULT_PROPAGATION_TIMEOUT,
    DEFAULT_RENEW_BEFORE, DynDnsConfig, KeyType, NodeEntry, TlsConfig, validate_public_entry,
};
pub use error::TlsError;
pub use pem_util::KeyPem;
pub use resolver::CertResolver;
pub use secret::{CLOUDFLARE_API_TOKEN_ENV, Secret, read_secret};
pub use sni::{
    ClientIdRegistry, FIXED_RESERVED_LABELS, ReservedLabels, SniKind, accept_public_sni,
    parse_client_id_sni,
};
pub use store::{CertMeta, CertStore, LoadedCert, TLS_DIR_NAME};
