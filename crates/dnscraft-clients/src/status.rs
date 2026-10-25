//! Runtime status surfaced to control-api / UI.

use std::time::{Duration, SystemTime};

/// Snapshot of sync health and inventory counts.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ClientsStatus {
    /// Wall time of the last sync attempt (success or failure).
    pub last_attempt: Option<SystemTime>,
    /// Wall time of the last successful sync that produced a usable snapshot.
    pub last_success: Option<SystemTime>,
    /// True when the last attempt failed (or never succeeded) while serving
    /// a previous / manuals-only snapshot.
    pub stale: bool,
    /// Clients in the current lookup (manual + UniFi).
    pub client_count: usize,
    /// Manual entries in the active config.
    pub manual_count: usize,
    /// UniFi-sourced clients in the current lookup.
    pub unifi_count: usize,
    /// Indexed addresses across all clients.
    pub address_count: usize,
    /// Stable `code()` of the last error, if any.
    pub last_error: Option<&'static str>,
    /// Configured poll interval (without jitter).
    pub poll_interval: Duration,
    /// Lookup generation; increments only when the snapshot is rebuilt.
    pub generation: u64,
}
