//! Pure snapshot builder: manuals + UniFi observations → [`ClientLookup`] + [`State`].

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use ipnet::IpNet;
use ring::digest::{Context, SHA256};
use tracing::warn;

use crate::config::{ClientsConfig, LocalDomainMode, ManualEntry};
use crate::error::ClientsError;
use crate::label::{fqdn, normalise_label, suffixed};
use crate::lookup::ClientLookup;
use crate::state::{RetainedClient, State};
use crate::types::{ClientId, ClientInfo, ClientSource, MacAddr, VlanInfo};
use dnscraft_common::config::normalise_domain;

/// Soft warn threshold (SPEC-clients.md): clients + indexed addresses.
pub const WARN_CLIENT_COUNT: usize = 2_000;
/// Hard refuse threshold: clients + indexed addresses.
pub const MAX_CLIENT_COUNT: usize = 10_000;

/// Normalised UniFi client row (Integration + classic merged upstream).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnifiObservation {
    /// Stable UniFi client id (UUID).
    pub id: ClientId,
    /// Display name from UniFi.
    pub display_name: String,
    /// Zero or more MACs.
    pub macs: Vec<MacAddr>,
    /// All reported addresses (link-local may be present; stripped when indexing).
    pub addresses: Vec<IpAddr>,
    /// Classic/Integration network id when known.
    pub network_id: Option<String>,
    /// `connectedAt` or equivalent.
    pub last_seen: Option<SystemTime>,
    /// Currently connected (vs known-offline from `rest/user`).
    pub online: bool,
}

/// UniFi network / VLAN metadata.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NetworkInfo {
    /// UniFi network id.
    pub id: String,
    /// Network name (e.g. `"IoT"`).
    pub name: String,
    /// 802.1Q VLAN id when known.
    pub vlan_id: Option<u16>,
    /// IPv4 prefix from gateway-managed details.
    pub ipv4_prefix: Option<IpNet>,
    /// IPv6 prefix from gateway-managed details.
    pub ipv6_prefix: Option<IpNet>,
    /// Per-network DHCP domain (source unverified until O1).
    pub domain_name: Option<String>,
}

/// Counters and flags from one merge.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MergeStats {
    /// UniFi↔UniFi IP claims resolved by dropping the loser from the index.
    pub ip_conflicts: u64,
    /// True when the soft 2 000-client warn fired.
    pub warned_too_many: bool,
}

/// Result of [`build`].
#[derive(Clone, Debug)]
pub struct MergeOutput {
    /// Ready-to-serve snapshot.
    pub lookup: ClientLookup,
    /// State to persist for the next sync / restart.
    pub state: State,
    /// Informational counters.
    pub stats: MergeStats,
}

/// Builds a snapshot from manuals and UniFi observations.
///
/// `prev` supplies first-seen labels, retained offline clients, and IPv6 TTLs.
/// `now` is the merge clock (injectable via [`crate::ManualClock`]).
pub fn build(
    manuals: &[ManualEntry],
    observations: &[UnifiObservation],
    networks: &[NetworkInfo],
    prev: &State,
    cfg: &ClientsConfig,
    now: SystemTime,
) -> Result<MergeOutput, ClientsError> {
    let default_domain = normalise_domain(&cfg.local_domain).map_err(ClientsError::config)?;
    if default_domain.is_empty() {
        return Err(ClientsError::config("local_domain is empty"));
    }

    let net_by_id: HashMap<&str, &NetworkInfo> =
        networks.iter().map(|n| (n.id.as_str(), n)).collect();

    let mut unifi_draft: HashMap<ClientId, DraftUnifi> = HashMap::new();
    let mut seen_now: HashMap<ClientId, ()> = HashMap::new();

    for obs in observations {
        seen_now.insert(obs.id.clone(), ());
        let (addrs, v6_ts) = merge_addresses(
            &obs.addresses,
            prev.ipv6_last_seen.get(&obs.id),
            cfg.ipv6_address_ttl,
            now,
            /*refresh_observed=*/ true,
        );
        unifi_draft.insert(
            obs.id.clone(),
            DraftUnifi {
                id: obs.id.clone(),
                display_name: obs.display_name.clone(),
                macs: obs.macs.clone(),
                addresses: addrs,
                v6_timestamps: v6_ts,
                network_id: obs.network_id.clone(),
                last_seen: obs.last_seen,
                online: obs.online,
                missing_since: None,
            },
        );
    }

    // Disappeared UniFi clients from the previous inventory → retain or evict.
    for (id, snap) in &prev.last_unifi {
        if seen_now.contains_key(id) {
            continue;
        }
        let missing_since = snap.missing_since.unwrap_or(now);
        let age = now.duration_since(missing_since).unwrap_or_default();
        if age > cfg.offline_retain {
            continue;
        }
        let (addrs, v6_ts) = merge_addresses(
            &snap.addresses,
            prev.ipv6_last_seen.get(id),
            cfg.ipv6_address_ttl,
            now,
            /*refresh_observed=*/ false,
        );
        unifi_draft.insert(
            id.clone(),
            DraftUnifi {
                id: id.clone(),
                display_name: snap.display_name.clone(),
                macs: snap.macs.clone(),
                addresses: addrs,
                v6_timestamps: v6_ts,
                network_id: snap.network_id.clone(),
                last_seen: snap.last_seen,
                online: false,
                missing_since: Some(missing_since),
            },
        );
    }

    // The cap covers client rows *and* addresses held in the lookup indexes.
    let client_total = manuals.len() + unifi_draft.len();
    let address_total = manuals
        .iter()
        .filter(|m| m.ip.is_some_and(|ip| !is_link_local(ip)))
        .count()
        + unifi_draft
            .values()
            .map(|d| d.addresses.len())
            .sum::<usize>();
    let total = client_total + address_total;
    if total > MAX_CLIENT_COUNT {
        return Err(ClientsError::TooMany {
            message: format!(
                "{client_total} clients / {address_total} addresses exceeds hard cap \
                 {MAX_CLIENT_COUNT}"
            ),
        });
    }
    let mut stats = MergeStats::default();
    if total > WARN_CLIENT_COUNT {
        stats.warned_too_many = true;
        warn!(
            code = "clients.too_many",
            clients = client_total,
            addresses = address_total,
            "client/address count above soft warn threshold"
        );
    }

    let mut clients: Vec<Arc<ClientInfo>> = Vec::with_capacity(total);
    let mut by_manual_ip: HashMap<IpAddr, u32> = HashMap::new();
    let mut cidrs: Vec<(IpNet, u32)> = Vec::new();
    let mut by_fqdn: HashMap<String, u32> = HashMap::new();
    let mut label_owners: HashMap<String, Vec<u32>> = HashMap::new();
    let mut taken_in_domain: HashMap<(String, String), ClientId> = HashMap::new();
    let mut domains_used: HashMap<String, ()> = HashMap::new();

    let mut next_state = State::default();

    for (i, entry) in manuals.iter().enumerate() {
        let idx = clients.len() as u32;
        let id = manual_client_id(entry)?;
        let domain = match &entry.domain {
            Some(d) => {
                let n = normalise_domain(d).map_err(ClientsError::config)?;
                if n.is_empty() {
                    return Err(ClientsError::config(format!("manual[{i}].domain is empty")));
                }
                n
            }
            None => default_domain.clone(),
        };
        domains_used.insert(domain.clone(), ());

        let dns_label = assign_label(&id, &entry.name, &domain, prev, &mut taken_in_domain);
        let name_key = fqdn(&dns_label, &domain)?;
        by_fqdn.entry(name_key).or_insert(idx);
        label_owners.entry(dns_label.clone()).or_default().push(idx);
        next_state.labels.insert(id.clone(), dns_label.clone());

        let addresses: Arc<[IpAddr]> = match (entry.ip, entry.cidr) {
            (Some(ip), None) => {
                if is_link_local(ip) {
                    // Spec: link-local IPv6 must not be indexed, manuals included.
                    Arc::from(Vec::new())
                } else {
                    by_manual_ip.entry(ip).or_insert(idx);
                    Arc::from([ip].as_slice())
                }
            }
            (None, Some(net)) => {
                cidrs.push((net, idx));
                Arc::from([])
            }
            _ => {
                return Err(ClientsError::config(format!(
                    "manual[{i}] must have exactly one of ip or cidr"
                )));
            }
        };

        clients.push(Arc::new(ClientInfo {
            id,
            display_name: entry.name.clone(),
            dns_label,
            local_domain: domain,
            source: ClientSource::Manual,
            macs: Vec::new(),
            addresses,
            vlan: None,
            last_seen: None,
            online: true,
        }));
    }

    let mut unifi_list: Vec<DraftUnifi> = unifi_draft.into_values().collect();
    // Existing labels first so newcomers never steal a first-seen name;
    // then online before offline; then id for stability.
    unifi_list.sort_by(|a, b| {
        let a_known = prev.labels.contains_key(&a.id);
        let b_known = prev.labels.contains_key(&b.id);
        b_known
            .cmp(&a_known)
            .then_with(|| b.online.cmp(&a.online))
            .then_with(|| a.id.as_str().cmp(b.id.as_str()))
    });

    let mut unifi_meta: Vec<UnifiMeta> = Vec::with_capacity(unifi_list.len());

    for draft in unifi_list {
        let idx = clients.len() as u32;
        let network = resolve_network(&draft, &net_by_id, networks);
        let vlan = network.and_then(vlan_info);
        let domain = resolve_domain(cfg, &default_domain, network);

        domains_used.insert(domain.clone(), ());

        let mut dns_label = assign_label(
            &draft.id,
            &draft.display_name,
            &domain,
            prev,
            &mut taken_in_domain,
        );

        // Manual (or earlier) FQDN wins: suffix this UniFi client if needed.
        let name_key = fqdn(&dns_label, &domain)?;
        if by_fqdn
            .get(&name_key)
            .and_then(|&i| clients.get(i as usize))
            .is_some_and(|c| c.id != draft.id)
        {
            dns_label = suffixed(&dns_label, &draft.id);
            taken_in_domain.insert((domain.clone(), dns_label.clone()), draft.id.clone());
        }
        let name_key = fqdn(&dns_label, &domain)?;
        by_fqdn.entry(name_key).or_insert(idx);
        label_owners.entry(dns_label.clone()).or_default().push(idx);
        next_state
            .labels
            .insert(draft.id.clone(), dns_label.clone());

        if !draft.v6_timestamps.is_empty() {
            next_state
                .ipv6_last_seen
                .insert(draft.id.clone(), draft.v6_timestamps.clone());
        }

        let inventory = RetainedClient {
            display_name: draft.display_name.clone(),
            macs: draft.macs.clone(),
            addresses: draft.addresses.clone(),
            network_id: draft.network_id.clone(),
            last_seen: draft.last_seen,
            missing_since: if draft.online {
                None
            } else {
                Some(draft.missing_since.unwrap_or(now))
            },
        };
        if !draft.online {
            next_state
                .retained
                .insert(draft.id.clone(), inventory.clone());
        }
        next_state.last_unifi.insert(draft.id.clone(), inventory);

        unifi_meta.push(UnifiMeta {
            idx,
            online: draft.online,
            last_seen: draft.last_seen,
            addresses: draft.addresses.clone(),
        });

        clients.push(Arc::new(ClientInfo {
            id: draft.id,
            display_name: draft.display_name,
            dns_label,
            local_domain: domain,
            source: ClientSource::Unifi,
            macs: draft.macs,
            addresses: Arc::from(draft.addresses),
            vlan,
            last_seen: draft.last_seen,
            online: draft.online,
        }));
    }

    let mut claimants: HashMap<IpAddr, Vec<usize>> = HashMap::new();
    for (i, meta) in unifi_meta.iter().enumerate() {
        for &ip in &meta.addresses {
            claimants.entry(ip).or_default().push(i);
        }
    }

    let mut by_unifi_ip: HashMap<IpAddr, u32> = HashMap::new();
    for (ip, idxs) in claimants {
        if idxs.len() > 1 {
            stats.ip_conflicts += (idxs.len() - 1) as u64;
        }
        let Some(&first) = idxs.first() else {
            continue;
        };
        let winner = idxs.iter().copied().fold(first, |best, cur| {
            let ma = &unifi_meta[best];
            let mb = &unifi_meta[cur];
            match ma
                .online
                .cmp(&mb.online)
                .then_with(|| ma.last_seen.cmp(&mb.last_seen))
                .then_with(|| best.cmp(&cur))
            {
                std::cmp::Ordering::Less => cur,
                _ => best,
            }
        });
        by_unifi_ip.insert(ip, unifi_meta[winner].idx);
    }

    let by_bare: HashMap<String, u32> = label_owners
        .into_iter()
        .filter_map(|(label, owners)| {
            if owners.len() == 1 {
                Some((label, owners[0]))
            } else {
                None
            }
        })
        .collect();

    let mut domain_list: Vec<String> = domains_used.into_keys().collect();
    domain_list.sort();

    let lookup = ClientLookup::from_parts(
        Arc::from(clients),
        by_manual_ip,
        cidrs,
        by_unifi_ip,
        by_fqdn,
        by_bare,
        Arc::from(domain_list),
    );

    Ok(MergeOutput {
        lookup,
        state: next_state,
        stats,
    })
}

struct DraftUnifi {
    id: ClientId,
    display_name: String,
    macs: Vec<MacAddr>,
    addresses: Vec<IpAddr>,
    v6_timestamps: HashMap<IpAddr, SystemTime>,
    network_id: Option<String>,
    last_seen: Option<SystemTime>,
    online: bool,
    missing_since: Option<SystemTime>,
}

struct UnifiMeta {
    idx: u32,
    online: bool,
    last_seen: Option<SystemTime>,
    addresses: Vec<IpAddr>,
}

/// Stable manual client id derived from config data, so inserting, removing or
/// reordering entries does not shift identities (and persisted labels).
fn manual_client_id(entry: &ManualEntry) -> Result<ClientId, ClientsError> {
    let mut ctx = Context::new(&SHA256);
    ctx.update(entry.name.as_bytes());
    ctx.update(b"\0");
    if let Some(domain) = &entry.domain {
        ctx.update(domain.as_bytes());
    }
    ctx.update(b"\0");
    match (entry.ip, entry.cidr) {
        (Some(ip), _) => ctx.update(ip.to_string().as_bytes()),
        (None, Some(net)) => ctx.update(net.to_string().as_bytes()),
        (None, None) => {
            return Err(ClientsError::config(
                "manual entry must have exactly one of ip or cidr",
            ));
        }
    }
    let digest = ctx.finish();
    let hex: String = digest.as_ref()[..8]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    ClientId::new(format!("manual-{hex}"))
}

fn assign_label(
    id: &ClientId,
    display: &str,
    domain: &str,
    prev: &State,
    taken: &mut HashMap<(String, String), ClientId>,
) -> String {
    if let Some(existing) = prev.labels.get(id) {
        let key = (domain.to_owned(), existing.clone());
        if !taken.contains_key(&key) || taken.get(&key) == Some(id) {
            taken.insert(key, id.clone());
            return existing.clone();
        }
        let s = suffixed(existing, id);
        taken.insert((domain.to_owned(), s.clone()), id.clone());
        return s;
    }
    let base = normalise_label(display, id);
    let key = (domain.to_owned(), base.clone());
    if taken.contains_key(&key) {
        let s = suffixed(&base, id);
        taken.insert((domain.to_owned(), s.clone()), id.clone());
        s
    } else {
        taken.insert(key, id.clone());
        base
    }
}

/// Resolves the network a UniFi client belongs to: id join, then longest
/// matching gateway-managed prefix.
fn resolve_network<'a>(
    draft: &DraftUnifi,
    by_id: &HashMap<&str, &'a NetworkInfo>,
    networks: &'a [NetworkInfo],
) -> Option<&'a NetworkInfo> {
    if let Some(nid) = &draft.network_id
        && let Some(&n) = by_id.get(nid.as_str())
    {
        return Some(n);
    }
    let mut best: Option<(&NetworkInfo, u8)> = None;
    for addr in &draft.addresses {
        for n in networks {
            for prefix in [n.ipv4_prefix, n.ipv6_prefix].into_iter().flatten() {
                if prefix.contains(addr) {
                    let len = prefix.prefix_len();
                    if best.is_none_or(|(_, bl)| len > bl) {
                        best = Some((n, len));
                    }
                }
            }
        }
    }
    best.map(|(n, _)| n)
}

/// `None` when the matched network has no 802.1Q id: an unknown VLAN is not id 0.
fn vlan_info(network: &NetworkInfo) -> Option<VlanInfo> {
    Some(VlanInfo {
        id: network.vlan_id?,
        name: network.name.clone(),
        domain_name: network.domain_name.clone(),
    })
}

fn resolve_domain(
    cfg: &ClientsConfig,
    default_domain: &str,
    network: Option<&NetworkInfo>,
) -> String {
    if cfg.local_domain_mode == LocalDomainMode::Config {
        return default_domain.to_owned();
    }
    if let Some(n) = network
        && let Some(d) = &n.domain_name
        && let Ok(norm) = normalise_domain(d)
        && !norm.is_empty()
    {
        return norm;
    }
    default_domain.to_owned()
}

/// Combines current addresses with TTL-retained IPv6; strips link-local.
fn merge_addresses(
    current: &[IpAddr],
    prev: Option<&HashMap<IpAddr, SystemTime>>,
    ttl: Duration,
    now: SystemTime,
    refresh_observed: bool,
) -> (Vec<IpAddr>, HashMap<IpAddr, SystemTime>) {
    let mut out: Vec<IpAddr> = Vec::new();
    let mut ts: HashMap<IpAddr, SystemTime> = HashMap::new();
    let mut seen: HashMap<IpAddr, ()> = HashMap::new();

    for &ip in current {
        if is_link_local(ip) {
            continue;
        }
        if seen.insert(ip, ()).is_none() {
            out.push(ip);
        }
        if ip.is_ipv6() {
            let when = if refresh_observed {
                now
            } else {
                prev.and_then(|p| p.get(&ip).copied()).unwrap_or(now)
            };
            ts.insert(ip, when);
        }
    }

    if let Some(prev_map) = prev {
        for (&ip, &when) in prev_map {
            if !ip.is_ipv6() || is_link_local(ip) || seen.contains_key(&ip) {
                continue;
            }
            let age = now.duration_since(when).unwrap_or_default();
            if age <= ttl {
                seen.insert(ip, ());
                out.push(ip);
                ts.insert(ip, when);
            }
        }
    }

    (out, ts)
}

/// Whether an address is IPv6 link-local (`fe80::/10`) and must not be indexed.
pub fn is_link_local(ip: IpAddr) -> bool {
    matches!(ip, IpAddr::V6(v6) if v6.is_unicast_link_local())
}
