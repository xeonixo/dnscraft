//! TLS certificates, ACME DNS-01, and DynDNS for DNScraft.
//!
//! This crate obtains and renews the shared certificate for encrypted DNS
//! listeners (`dns.<domain>` and `*.dns.<domain>`), exposes a hot-reloadable
//! cert resolver (later tasks), and keeps the node's public A/AAAA records
//! current via Cloudflare.
//!
//! It does **not** bind sockets (that is `listeners`) and does **not** own the
//! Client-ID registry (that is `policy` / `control-api`).
//!
//! Phase-1 foundation (this crate so far): [`TlsConfig`], [`TlsError`],
//! [`Clock`] / [`ManualClock`], and [`read_secret`].

#![deny(missing_docs)]

mod clock;
mod config;
mod error;
mod secret;

pub use clock::{Clock, ManualClock, SystemClock};
pub use config::{
    AcmeConfig, AcmeDirectoryKind, CloudflareConfig, DEFAULT_DYNDNS_INTERVAL, DEFAULT_ECHO_URL,
    DEFAULT_EXPIRY_WARN, DEFAULT_PROPAGATION_POLL, DEFAULT_PROPAGATION_TIMEOUT,
    DEFAULT_RENEW_BEFORE, DynDnsConfig, KeyType, NodeEntry, TlsConfig, validate_public_entry,
};
pub use error::TlsError;
pub use secret::{CLOUDFLARE_API_TOKEN_ENV, Secret, read_secret};
