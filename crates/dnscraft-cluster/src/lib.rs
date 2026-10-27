//! Cluster identity and bootstrap state for DNScraft.
//!
//! A DNScraft cluster is one `master` plus zero or more `sub_node`s, connected
//! hub-and-spoke with mutual TLS under a dedicated cluster CA. This crate owns
//! the node-local pieces that exist before any connection is opened:
//!
//! - [`ClusterConfig`] — node-local `[cluster]` bootstrap configuration and
//!   role-consistency validation ([`Role`]).
//! - [`ClusterError`] — stable `cluster.<area>.<reason>` error codes.
//! - [`ClusterCa`] — the master's dedicated cluster CA (key mode `0600`).
//! - [`ClusterStore`] — the durable master registry for nodes and one-time
//!   join tokens (SQLite in the data directory).
//!
//! The mTLS transport, enrollment endpoint, and log/write streaming are later
//! slices; nothing here opens a socket.

#![deny(missing_docs)]

mod ca;
mod config;
mod error;
mod store;

pub use ca::{ClusterCa, cert_fingerprint};
pub use config::{
    ClusterConfig, JoinConfig, ListenConfig, LogConfig, OfflineWritesConfig, QuotaConfig, Role,
    TimingConfig, TlsPaths,
};
pub use error::ClusterError;
pub use store::{ClusterNode, ClusterStore, MintedJoinToken};

use ring::digest::{SHA256, digest};

/// Lowercase hex SHA-256 of `bytes` (used for fingerprints and token hashes).
pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    hex(digest(&SHA256, bytes).as_ref())
}

/// Lowercase hex encoding.
fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[usize::from(byte >> 4)] as char);
        out.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    out
}
