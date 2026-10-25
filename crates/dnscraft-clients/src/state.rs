//! Persistent merge state (labels, offline retain, IPv6 observations).
//!
//! Survives restarts via the last-good disk cache (C9). Treat loaded values as
//! untrusted input and re-validate caps on use.

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::SystemTime;

use crate::types::{ClientId, MacAddr};

/// Label + retain + IPv6 TTL state carried across syncs.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct State {
    /// First-seen DNS label per client id (survives renames / id-order churn).
    pub labels: HashMap<ClientId, String>,
    /// UniFi clients missing from the last successful sync, still within retain.
    pub retained: HashMap<ClientId, RetainedClient>,
    /// Last time each non–link-local IPv6 address was observed for a client.
    pub ipv6_last_seen: HashMap<ClientId, HashMap<IpAddr, SystemTime>>,
    /// Full UniFi inventory from the previous successful merge (online + retained).
    ///
    /// Used to detect disappearances, including IPv4-only clients that have no
    /// IPv6 TTL map entries.
    pub last_unifi: HashMap<ClientId, RetainedClient>,
}

/// A UniFi client snapshot used for retain / inventory.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RetainedClient {
    /// Raw display name.
    pub display_name: String,
    /// MACs last known.
    pub macs: Vec<MacAddr>,
    /// Addresses last indexed (no link-local).
    pub addresses: Vec<IpAddr>,
    /// UniFi network id when known.
    pub network_id: Option<String>,
    /// Last `connectedAt` / seen time.
    pub last_seen: Option<SystemTime>,
    /// When the client first went missing from a successful sync (`None` while online).
    pub missing_since: Option<SystemTime>,
}
