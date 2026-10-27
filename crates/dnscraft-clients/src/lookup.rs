//! Snapshot index for client identity lookups.
//!
//! [`ClientLookup`] is an immutable `Arc`-friendly snapshot. Lookups never
//! allocate beyond cloning an `Arc` and never await.
//!
//! [`by_ip`](ClientLookup::by_ip) precedence: manual exact IP → longest manual
//! CIDR → UniFi exact IP.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::SystemTime;

use ipnet::IpNet;

use crate::config::{ClientsConfig, ManualEntry};
use crate::error::ClientsError;
use crate::merge::{self, MergeOutput};
use crate::state::State;
use crate::types::ClientInfo;
use dnscraft_common::config::normalise_domain;

/// Immutable client identity snapshot.
#[derive(Clone, Debug)]
pub struct ClientLookup {
    clients: Arc<[Arc<ClientInfo>]>,
    /// Manual single-IP entries.
    by_manual_ip: HashMap<IpAddr, u32>,
    /// Manual CIDRs, longest prefix first.
    cidrs: Vec<(IpNet, u32)>,
    /// UniFi addresses (after IP-conflict resolution).
    by_unifi_ip: HashMap<IpAddr, u32>,
    /// Lower-cased FQDN → client index.
    by_fqdn: HashMap<String, u32>,
    /// Bare label → unique client index, or absent when ambiguous / unused.
    by_bare: HashMap<String, u32>,
    /// Parent domains currently in use (sorted, unique).
    local_domains: Arc<[String]>,
}

impl ClientLookup {
    /// Assembles a snapshot from pre-built indexes (used by [`merge::build`]).
    pub(crate) fn from_parts(
        clients: Arc<[Arc<ClientInfo>]>,
        by_manual_ip: HashMap<IpAddr, u32>,
        cidrs: Vec<(IpNet, u32)>,
        by_unifi_ip: HashMap<IpAddr, u32>,
        by_fqdn: HashMap<String, u32>,
        by_bare: HashMap<String, u32>,
        local_domains: Arc<[String]>,
    ) -> Self {
        Self {
            clients,
            by_manual_ip,
            cidrs,
            by_unifi_ip,
            by_fqdn,
            by_bare,
            local_domains,
        }
    }

    /// Builds a snapshot from manual entries only (no UniFi).
    pub fn build_manual(
        manuals: &[ManualEntry],
        default_domain: &str,
    ) -> Result<Self, ClientsError> {
        let cfg = ClientsConfig {
            local_domain: default_domain.to_owned(),
            ..ClientsConfig::default()
        };
        let MergeOutput { lookup, .. } = merge::build(
            manuals,
            &[],
            &[],
            &State::default(),
            &cfg,
            SystemTime::UNIX_EPOCH,
        )?;
        Ok(lookup)
    }

    /// Empty snapshot (UniFi disabled, no manuals).
    pub fn empty() -> Self {
        Self {
            clients: Arc::from([]),
            by_manual_ip: HashMap::new(),
            cidrs: Vec::new(),
            by_unifi_ip: HashMap::new(),
            by_fqdn: HashMap::new(),
            by_bare: HashMap::new(),
            local_domains: Arc::from([]),
        }
    }

    /// Number of clients in the snapshot.
    pub fn len(&self) -> usize {
        self.clients.len()
    }

    /// Whether the snapshot has no clients.
    pub fn is_empty(&self) -> bool {
        self.clients.is_empty()
    }

    /// Hot-path enrichment: manual IP → longest manual CIDR → UniFi IP.
    ///
    /// Returns an `Arc` clone (no deep copy of [`ClientInfo`]).
    pub fn by_ip(&self, ip: IpAddr) -> Option<Arc<ClientInfo>> {
        if let Some(&idx) = self.by_manual_ip.get(&ip) {
            return self.clients.get(idx as usize).cloned();
        }
        for (net, idx) in &self.cidrs {
            if net.contains(&ip) {
                return self.clients.get(*idx as usize).cloned();
            }
        }
        if let Some(&idx) = self.by_unifi_ip.get(&ip) {
            return self.clients.get(idx as usize).cloned();
        }
        None
    }

    /// Forward local name: FQDN (case-insensitive, trailing dot ok), or a bare
    /// label when it is unambiguous across all local domains.
    pub fn by_name(&self, name: &str) -> Option<Arc<ClientInfo>> {
        let trimmed = name.trim().trim_end_matches('.');
        if trimmed.is_empty() {
            return None;
        }
        if let Some((lab, rest)) = trimmed.split_once('.') {
            let lab = lab.to_ascii_lowercase();
            let domain = normalise_domain(rest).ok()?;
            if domain.is_empty() {
                return None;
            }
            let key = format!("{lab}.{domain}");
            let idx = *self.by_fqdn.get(&key)?;
            self.clients.get(idx as usize).cloned()
        } else {
            let lab = trimmed.to_ascii_lowercase();
            let idx = *self.by_bare.get(&lab)?;
            self.clients.get(idx as usize).cloned()
        }
    }

    /// PTR: IP → FQDN, same winner as [`Self::by_ip`].
    pub fn reverse(&self, ip: IpAddr) -> Option<String> {
        let client = self.by_ip(ip)?;
        Some(format!("{}.{}", client.dns_label, client.local_domain))
    }

    /// Domains currently treated as local (cheap `Arc` clone).
    pub fn local_domains(&self) -> Arc<[String]> {
        Arc::clone(&self.local_domains)
    }

    /// All clients in snapshot order (manuals first, then UniFi).
    pub fn clients(&self) -> &[Arc<ClientInfo>] {
        &self.clients
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn empty_lookup() {
        let l = ClientLookup::empty();
        assert!(l.is_empty());
        assert!(l.by_ip(IpAddr::from_str("192.0.2.1").unwrap()).is_none());
        assert!(l.local_domains().is_empty());
    }
}
