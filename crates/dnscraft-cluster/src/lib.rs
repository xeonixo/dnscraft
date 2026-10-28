//! Cluster identity and transport for DNScraft.
//!
//! A DNScraft cluster is one `master` plus zero or more `sub_node`s, connected
//! hub-and-spoke with mutual TLS under a dedicated cluster CA. This crate owns:
//!
//! - [`ClusterConfig`] — node-local `[cluster]` bootstrap configuration and
//!   role-consistency validation ([`Role`]).
//! - [`ClusterError`] — stable `cluster.<area>.<reason>` error codes.
//! - [`ClusterCa`] — the master's dedicated cluster CA (key mode `0600`).
//! - [`ClusterStore`] — the durable master registry for nodes and one-time
//!   join tokens (SQLite in the data directory).
//! - [`enroll`] / [`EnrollRequest`] / [`EnrollResponse`] — the in-process
//!   master-side enrollment protocol and its wire shape.
//! - [`PendingNodeIdentity`] / [`NodeIdentity`] — sub-node key + CSR
//!   generation and durable certificate/key storage.
//! - [`ClusterServer`] — the master's separate mTLS HTTP/2 listener with
//!   enroll, stream and heartbeat routes.
//! - [`ClusterClient`] — the sub-node's outbound mTLS client (the master never
//!   dials a sub-node).
//! - [`StreamRecord`] / [`Hello`] / [`ConfigPush`] / [`ConfigAck`] — the NDJSON
//!   stream records, plus [`ConfigApplier`] and [`ConfigSync`] for full-snapshot
//!   configuration push, digest verification, acknowledgement, lag, and retry.
//! - [`CertPush`] / [`CertInstaller`] and [`AuthSnapshotPush`] /
//!   [`AuthSnapshotApplier`] — master pushes for TLS certificate hot-reload and
//!   encrypted auth-state replication.
//! - [`WriteRelay`] / [`WriteExecutor`] / [`RelayResponse`] — live write relay
//!   from a sub-node to the master (the caller re-checks RBAC and executes the
//!   canonical handler).
//! - [`OfflineWriteQueue`] — the durable FIFO of keyed config writes buffered
//!   while the master is unreachable, with replay conflict/expiry semantics.
//! - [`RuntimeCommand`] / [`RuntimeCommandApplier`] — volatile runtime-command
//!   broadcast to every connected node (never persisted or queued).
//! - [`LogOutbox`] / [`LogIngest`] — caller-supplied query-log hooks;
//!   [`LogStreamer`] batches contiguous unacked rows into a [`LogBatch`] and
//!   [`ClusterServer`] acknowledges the highest contiguous [`LogAck`]. Records
//!   are opaque, and [`Backfill`] resumes after an outage with `cluster.log_gap`
//!   when the local buffer overran.

#![deny(missing_docs)]

mod ca;
mod client;
mod config;
mod enroll;
mod error;
mod identity;
mod log;
mod offline;
mod quota;
mod relay;
mod server;
mod store;
mod sync;

pub use ca::{ClusterCa, cert_fingerprint};
pub use client::{ClusterClient, ClusterStream};
pub use config::{
    ClusterConfig, JoinConfig, ListenConfig, LogConfig, OfflineWritesConfig, QuotaConfig, Role,
    TimingConfig, TlsPaths,
};
pub use enroll::{EnrollRequest, EnrollResponse, PROTOCOL_VERSION, RenewRequest, enroll};
pub use error::ClusterError;
pub use identity::{NodeIdentity, PendingNodeIdentity};
pub use log::{
    Backfill, FlushOutcome, LogAck, LogBatch, LogIngest, LogOutbox, LogRecord, LogStreamer,
};
pub use offline::{
    ActorValidator, EnqueueOutcome, OfflineQueueStatus, OfflineWriteEntry, OfflineWriteQueue,
    OfflineWriteState, QueuedWrite, ReplayOutcome,
};
pub use relay::{
    RelayResponse, RelayedActor, RuntimeCommand, RuntimeCommandApplier, WriteExecutor, WriteRelay,
};
pub use server::{
    AuthSnapshotSource, ClusterBroadcast, ClusterServer, ClusterServerConfig, HeartbeatRequest,
    HeartbeatResponse, StatusWarning,
};
pub use store::{ClusterNode, ClusterStore, MintedJoinToken};
pub use sync::{
    AuthSnapshotApplier, AuthSnapshotPush, CertInstaller, CertPush, ConfigAck, ConfigApplier,
    ConfigPush, ConfigSync, Hello, NodeLag, StreamError, StreamRecord, canonical_snapshot_bytes,
    snapshot_digest,
};

/// Lowercase hex SHA-256 of `bytes` (used for fingerprints and token hashes).
pub(crate) use dnscraft_common::hash::sha256_hex;

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
