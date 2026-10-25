//! One-shot UniFi sync: Integration + optional classic → merge snapshot.
//!
//! Classic failures are non-fatal when Integration succeeded: the snapshot is
//! built from Integration rows alone and [`SyncResult::classic_error`] records
//! the classic failure code for status.

use std::collections::HashMap;
use std::time::SystemTime;

use crate::classic::{self, ClassicFetch};
use crate::config::{ClientsConfig, UnifiConfig};
use crate::error::ClientsError;
use crate::gateway::GatewayClient;
use crate::integration::{self, IntegrationFetch};
use crate::merge::{self, MergeOutput, NetworkInfo, UnifiObservation};
use crate::state::State;
use crate::types::{ClientId, MacAddr};

/// Outcome of [`sync_once`].
#[derive(Clone, Debug)]
pub struct SyncResult {
    /// Merged lookup + state from [`merge::build`].
    pub merge: MergeOutput,
    /// Normalised observations that fed the merge (for engine cache / apply_config).
    pub observations: Vec<UnifiObservation>,
    /// Networks that fed the merge.
    pub networks: Vec<NetworkInfo>,
    /// Integration site UUID that was synced.
    pub site_id: String,
    /// Classic site key when classic ran successfully.
    pub classic_site_key: Option<String>,
    /// Rows skipped across Integration + classic parsers.
    pub skipped_rows: u64,
    /// Classic fetch/mapping error when Integration still produced a snapshot.
    pub classic_error: Option<ClientsError>,
}

/// Runs one UniFi sync against `gw` and builds a snapshot.
///
/// When `unifi.classic_clients` is false, no classic HTTP requests are made.
/// When classic fails after a successful Integration fetch, Integration-only
/// observations are used and the classic error is returned in
/// [`SyncResult::classic_error`] (not as `Err`).
pub async fn sync_once(
    gw: &GatewayClient,
    cfg: &ClientsConfig,
    unifi: &UnifiConfig,
    prev: &State,
    now: SystemTime,
) -> Result<SyncResult, ClientsError> {
    let integ: IntegrationFetch = integration::fetch(gw, unifi.site_id.as_deref()).await?;

    let mut skipped = integ.skipped_rows;
    let mut classic_error = None;
    let mut classic_site_key = None;
    let mut classic_nets: Vec<NetworkInfo> = Vec::new();
    let mut classic_obs: Vec<UnifiObservation> = Vec::new();

    if unifi.classic_clients {
        match fetch_classic(gw, &integ.site_id).await {
            Ok(c) => {
                skipped = skipped.saturating_add(c.skipped_rows);
                classic_site_key = Some(c.site_key);
                classic_nets = c.networks;
                classic_obs = c.observations;
            }
            Err(e) => {
                classic_error = Some(e);
            }
        }
    }

    let observations = merge_observations(integ.observations, classic_obs);
    let networks = merge_networks(integ.networks, classic_nets);

    let merge = merge::build(&cfg.manual, &observations, &networks, prev, cfg, now)?;

    Ok(SyncResult {
        merge,
        observations,
        networks,
        site_id: integ.site_id,
        classic_site_key,
        skipped_rows: skipped,
        classic_error,
    })
}

async fn fetch_classic(
    gw: &GatewayClient,
    integration_site_id: &str,
) -> Result<ClassicFetch, ClientsError> {
    let site_key = classic::resolve_site_key(gw, integration_site_id).await?;
    classic::fetch(gw, &site_key).await
}

/// Merges Integration + classic rows by MAC (preferred) or client id.
///
/// When a classic row matches an Integration client, the Integration id is kept
/// (stable UUID) and addresses / `network_id` are enriched from classic.
pub(crate) fn merge_observations(
    integration: Vec<UnifiObservation>,
    classic: Vec<UnifiObservation>,
) -> Vec<UnifiObservation> {
    let mut by_id: HashMap<ClientId, UnifiObservation> = HashMap::new();
    let mut mac_index: HashMap<MacAddr, ClientId> = HashMap::new();

    for obs in integration {
        for m in &obs.macs {
            mac_index.insert(*m, obs.id.clone());
        }
        by_id.insert(obs.id.clone(), obs);
    }

    for c in classic {
        let match_id = c
            .macs
            .iter()
            .find_map(|m| mac_index.get(m).cloned())
            .or_else(|| {
                if by_id.contains_key(&c.id) {
                    Some(c.id.clone())
                } else {
                    None
                }
            });

        if let Some(id) = match_id {
            if let Some(entry) = by_id.get_mut(&id) {
                enrich_from_classic(entry, &c);
            }
            for m in &c.macs {
                mac_index.insert(*m, id.clone());
            }
        } else {
            for m in &c.macs {
                mac_index.insert(*m, c.id.clone());
            }
            by_id.insert(c.id.clone(), c);
        }
    }

    let mut out: Vec<_> = by_id.into_values().collect();
    // Stable order so content hashes / change detection do not flap on HashMap
    // iteration (would rebuild every poll once ≥ 2 clients exist).
    out.sort_by(|a, b| a.id.as_str().cmp(b.id.as_str()));
    out
}

fn enrich_from_classic(dst: &mut UnifiObservation, classic: &UnifiObservation) {
    for a in &classic.addresses {
        if !dst.addresses.contains(a) {
            dst.addresses.push(*a);
        }
    }
    for m in &classic.macs {
        if !dst.macs.contains(m) {
            dst.macs.push(*m);
        }
    }
    if classic.network_id.is_some() {
        dst.network_id = classic.network_id.clone();
    }
    match (dst.last_seen, classic.last_seen) {
        (Some(a), Some(b)) if b > a => dst.last_seen = Some(b),
        (None, Some(b)) => dst.last_seen = Some(b),
        _ => {}
    }
    dst.online = dst.online || classic.online;
    // Prefer classic hostname when Integration only had a placeholder id-ish name.
    if !classic.display_name.is_empty()
        && (dst.display_name.is_empty() || dst.display_name == dst.id.as_str())
    {
        dst.display_name = classic.display_name.clone();
    }
}

/// Combines Integration networks (prefixes) with classic `networkconf` (domain / classic ids).
///
/// Classic rows are kept under their `_id` so `network_id` joins work. Prefixes
/// from a same-named Integration network are copied onto classic rows.
pub(crate) fn merge_networks(
    integration: Vec<NetworkInfo>,
    classic: Vec<NetworkInfo>,
) -> Vec<NetworkInfo> {
    if classic.is_empty() {
        return integration;
    }

    let integ_by_name: HashMap<&str, &NetworkInfo> =
        integration.iter().map(|n| (n.name.as_str(), n)).collect();

    let mut out: Vec<NetworkInfo> = classic
        .into_iter()
        .map(|mut c| {
            if let Some(i) = integ_by_name.get(c.name.as_str()) {
                if c.ipv4_prefix.is_none() {
                    c.ipv4_prefix = i.ipv4_prefix;
                }
                if c.ipv6_prefix.is_none() {
                    c.ipv6_prefix = i.ipv6_prefix;
                }
                if c.vlan_id.is_none() {
                    c.vlan_id = i.vlan_id;
                }
                if c.domain_name.is_none() {
                    c.domain_name = i.domain_name.clone();
                }
            }
            c
        })
        .collect();

    // Keep Integration-only networks (different names) for LPM fallback.
    let classic_names: HashMap<String, ()> = out.iter().map(|n| (n.name.clone(), ())).collect();
    for i in integration {
        if !classic_names.contains_key(&i.name) {
            out.push(i);
        }
    }
    out
}
