//! Per-listener and aggregate runtime status.

use std::net::SocketAddr;

use dnscraft_policy::ListenerId;

use crate::config::Protocol;
use crate::error::ListenersError;

/// Snapshot of one listener's bind state and counters.
#[derive(Clone, Debug)]
pub struct ListenerStatus {
    /// Configured listener id.
    pub id: ListenerId,
    /// Transport protocol.
    pub protocol: Protocol,
    /// Address from config (may use port 0).
    pub configured_address: SocketAddr,
    /// Actual bound address when bind succeeded.
    pub bound: Option<SocketAddr>,
    /// Bind / startup error (`listeners.bind`, `listeners.tls.no_cert`, …).
    pub error: Option<ListenersError>,
    /// Active connections (TCP / DoT / DoH / DoQ); UDP always 0.
    pub connections: u64,
    /// Queries admitted into handling.
    pub queries: u64,
    /// Answers successfully written.
    pub answered: u64,
    /// Dropped / rejected before an answer (admission, caps, silent, …).
    pub dropped: u64,
    /// Rate-limit refusals / drops attributed to rate.
    pub rate_limited: u64,
    /// Admission drops because the source was banned.
    pub banned_sources: u64,
    /// TLS: no certificate installed (handshake attempts).
    pub tls_no_cert: u64,
    /// TLS: handshake failures + timeouts.
    pub tls_handshake_failures: u64,
}

/// Aggregate status for a [`crate::ListenerSet`].
#[derive(Clone, Debug, Default)]
pub struct ListenersStatus {
    /// One entry per configured listener (including bind failures).
    pub listeners: Vec<ListenerStatus>,
    /// Events dropped by a full [`crate::ChannelSink`].
    pub events_dropped: u64,
    /// Ban / strike table entries in the shared admission state.
    pub ban_entries: u64,
}
