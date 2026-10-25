//! Classic UniFi controller API (`/proxy/network/api/s/{site}/…`).
//!
//! Defensive `serde_json::Value` parsing: unknown fields ignored; bad rows
//! skipped and counted. Field names confirmed by O1 (`ip`, `ipv6_addresses`,
//! `network_id`, `domain_name`) plus common fallbacks.

use std::collections::HashSet;
use std::net::IpAddr;
use std::str::FromStr;
use std::time::{Duration, SystemTime};

use ipnet::IpNet;
use serde_json::Value;

use crate::error::ClientsError;
use crate::gateway::GatewayClient;
use crate::integration::INTEGRATION_PREFIX;
use crate::merge::{NetworkInfo, UnifiObservation};
use crate::types::{ClientId, MacAddr};

/// Classic API path prefix on UniFi OS.
pub const CLASSIC_PREFIX: &str = "/proxy/network/api";

/// Result of one classic fetch for a site key.
#[derive(Clone, Debug)]
pub struct ClassicFetch {
    /// Classic site key used in URLs (e.g. `"default"`).
    pub site_key: String,
    /// Networks from `rest/networkconf` (ids are classic `_id` values).
    pub networks: Vec<NetworkInfo>,
    /// Clients from `stat/sta` (online) merged with `rest/user` (known/offline).
    pub observations: Vec<UnifiObservation>,
    /// Rows skipped due to missing id / unparseable required fields.
    pub skipped_rows: u64,
}

/// Maps an Integration site UUID to the classic site key (`default`, …).
///
/// Uses Integration `internalReference` (fallback: `name`), then verifies the
/// key exists in `/api/self/sites`. Mapping failure → [`ClientsError::ConfigInvalid`].
pub async fn resolve_site_key(
    gw: &GatewayClient,
    integration_site_id: &str,
) -> Result<String, ClientsError> {
    let body = gw.get(&format!("{INTEGRATION_PREFIX}/sites")).await?;
    let sites = parse_data_array(&body, "integration sites")?;
    let want = integration_site_id;
    let integ = sites
        .iter()
        .find(|s| s.get("id").and_then(|v| v.as_str()) == Some(want));
    let Some(integ) = integ else {
        return Err(ClientsError::config(format!(
            "integration site {want} not found for classic mapping"
        )));
    };
    let candidate = integ
        .get("internalReference")
        .and_then(|v| v.as_str())
        .or_else(|| integ.get("name").and_then(|v| v.as_str()))
        .ok_or_else(|| ClientsError::config("integration site missing internalReference/name"))?
        .to_owned();

    let body = gw.get(&format!("{CLASSIC_PREFIX}/self/sites")).await?;
    let classic_sites = parse_data_array(&body, "classic self/sites")?;
    let names: Vec<&str> = classic_sites
        .iter()
        .filter_map(|s| s.get("name").and_then(|v| v.as_str()))
        .collect();

    if names.iter().any(|n| *n == candidate) {
        return Ok(candidate);
    }
    match names.as_slice() {
        [only] => Ok((*only).to_owned()),
        [] => Err(ClientsError::config("classic self/sites returned no sites")),
        _ => Err(ClientsError::config(format!(
            "classic site key {candidate:?} not in self/sites"
        ))),
    }
}

/// Defensively parses a classic `{"meta":…,"data":[…]}` client feed body.
///
/// Never panics on malformed JSON shapes beyond a fatal outer parse
/// ([`ClientsError::HttpBody`]). Individual bad rows are skipped and counted
/// in the returned `skipped` value. Intended for tests / fuzzing as well as
/// the live fetch path.
pub fn parse_clients_json(body: &[u8]) -> Result<(Vec<UnifiObservation>, u64), ClientsError> {
    let rows = parse_data_array(body, "classic clients")?;
    let mut out = Vec::new();
    let mut skipped = 0u64;
    for row in &rows {
        // Treat as online (stat/sta); offline merging is the fetch() caller's job.
        match parse_client_row(row, true) {
            Some(obs) => out.push(obs),
            None => skipped += 1,
        }
    }
    Ok((out, skipped))
}

/// Classic site keys used in URL path segments (`/api/s/{key}/…`).
///
/// Rejects anything outside `[A-Za-z0-9_-]{1,64}` so a hostile/misconfigured
/// gateway cannot inject path separators into the request URL.
pub(crate) fn validate_site_key(site_key: &str) -> Result<(), ClientsError> {
    let ok = !site_key.is_empty()
        && site_key.len() <= 64
        && site_key
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-');
    if ok {
        Ok(())
    } else {
        Err(ClientsError::HttpBody {
            message: "classic site key rejected (expected [A-Za-z0-9_-]{1,64})".into(),
        })
    }
}

/// Fetches `stat/sta`, `rest/user`, and `rest/networkconf` for `site_key`.
pub async fn fetch(gw: &GatewayClient, site_key: &str) -> Result<ClassicFetch, ClientsError> {
    validate_site_key(site_key)?;
    let sta_path = format!("{CLASSIC_PREFIX}/s/{site_key}/stat/sta");
    let user_path = format!("{CLASSIC_PREFIX}/s/{site_key}/rest/user");
    let net_path = format!("{CLASSIC_PREFIX}/s/{site_key}/rest/networkconf");

    let sta_body = gw.get(&sta_path).await?;
    let user_body = gw.get(&user_path).await?;
    let net_body = gw.get(&net_path).await?;

    let mut skipped = 0u64;
    let mut by_id: std::collections::HashMap<ClientId, UnifiObservation> =
        std::collections::HashMap::new();

    let sta_rows = parse_data_array(&sta_body, "stat/sta")?;
    for row in &sta_rows {
        match parse_client_row(row, true) {
            Some(obs) => {
                by_id.insert(obs.id.clone(), obs);
            }
            None => skipped += 1,
        }
    }

    let user_rows = parse_data_array(&user_body, "rest/user")?;
    for row in &user_rows {
        match parse_client_row(row, false) {
            Some(obs) => {
                by_id
                    .entry(obs.id.clone())
                    .and_modify(|existing| {
                        // sta (online) wins; enrich addresses / network from user if missing.
                        merge_into(existing, &obs);
                    })
                    .or_insert(obs);
            }
            None => skipped += 1,
        }
    }

    let net_rows = parse_data_array(&net_body, "networkconf")?;
    let mut networks = Vec::with_capacity(net_rows.len());
    for row in &net_rows {
        if let Some(n) = parse_network_row(row) {
            networks.push(n);
        } else {
            skipped += 1;
        }
    }

    Ok(ClassicFetch {
        site_key: site_key.to_owned(),
        networks,
        observations: by_id.into_values().collect(),
        skipped_rows: skipped,
    })
}

fn parse_data_array(bytes: &[u8], what: &str) -> Result<Vec<Value>, ClientsError> {
    let v: Value = serde_json::from_slice(bytes).map_err(|e| ClientsError::HttpBody {
        message: format!("{what} JSON: {e}"),
    })?;
    match v.get("data") {
        Some(Value::Array(a)) => Ok(a.clone()),
        Some(_) => Err(ClientsError::HttpBody {
            message: format!("{what}: data is not an array"),
        }),
        None => Err(ClientsError::HttpBody {
            message: format!("{what}: missing data"),
        }),
    }
}

fn parse_client_row(row: &Value, online: bool) -> Option<UnifiObservation> {
    let id_str = row
        .get("_id")
        .or_else(|| row.get("user_id"))
        .or_else(|| row.get("id"))
        .and_then(|v| v.as_str())?;
    let id = ClientId::new(id_str).ok()?;

    let display_name = row
        .get("hostname")
        .or_else(|| row.get("name"))
        .and_then(|v| v.as_str())
        .unwrap_or(id_str)
        .to_owned();

    let mut macs = Vec::new();
    if let Some(m) = row.get("mac").and_then(|v| v.as_str())
        && let Ok(mac) = MacAddr::parse(m)
    {
        macs.push(mac);
    }

    let addresses = collect_addresses(row);
    let network_id = row
        .get("network_id")
        .and_then(|v| v.as_str())
        .map(str::to_owned);
    let last_seen = row.get("last_seen").and_then(parse_last_seen);

    Some(UnifiObservation {
        id,
        display_name,
        macs,
        addresses,
        network_id,
        last_seen,
        online,
    })
}

fn collect_addresses(row: &Value) -> Vec<IpAddr> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();

    for key in ["ip", "last_ip", "fixed_ip"] {
        if let Some(s) = row.get(key).and_then(|v| v.as_str()) {
            push_addr(s, &mut out, &mut seen);
        }
    }

    for key in ["ipv6_addresses", "ipv6"] {
        match row.get(key) {
            Some(Value::Array(arr)) => {
                for v in arr {
                    if let Some(s) = v.as_str() {
                        push_addr(s, &mut out, &mut seen);
                    }
                }
            }
            Some(Value::String(s)) => push_addr(s, &mut out, &mut seen),
            _ => {}
        }
    }

    out
}

fn push_addr(s: &str, out: &mut Vec<IpAddr>, seen: &mut HashSet<IpAddr>) {
    if let Ok(addr) = IpAddr::from_str(s)
        && seen.insert(addr)
    {
        out.push(addr);
    }
}

fn parse_last_seen(v: &Value) -> Option<SystemTime> {
    let secs = if let Some(n) = v.as_u64() {
        if n > 1_000_000_000_000 { n / 1000 } else { n }
    } else if let Some(n) = v.as_i64() {
        if n < 0 {
            return None;
        }
        let n = n as u64;
        if n > 1_000_000_000_000 { n / 1000 } else { n }
    } else {
        v.as_str()?.parse::<u64>().ok()?
    };
    Some(SystemTime::UNIX_EPOCH + Duration::from_secs(secs))
}

fn parse_network_row(row: &Value) -> Option<NetworkInfo> {
    let id = row
        .get("_id")
        .or_else(|| row.get("id"))
        .and_then(|v| v.as_str())?;
    let name = row
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or(id)
        .to_owned();
    let vlan_id = row
        .get("vlan")
        .and_then(|v| v.as_u64().or_else(|| v.as_str()?.parse().ok()))
        .map(|n| n as u16);
    let domain_name = row
        .get("domain_name")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(str::to_owned);
    let ipv4_prefix = row
        .get("ip_subnet")
        .and_then(|v| v.as_str())
        .and_then(|s| IpNet::from_str(s).ok())
        .filter(|n| matches!(n, IpNet::V4(_)));
    let ipv6_prefix = None;

    Some(NetworkInfo {
        id: id.to_owned(),
        name,
        vlan_id,
        ipv4_prefix,
        ipv6_prefix,
        domain_name,
    })
}

fn merge_into(dst: &mut UnifiObservation, src: &UnifiObservation) {
    for a in &src.addresses {
        if !dst.addresses.contains(a) {
            dst.addresses.push(*a);
        }
    }
    for m in &src.macs {
        if !dst.macs.contains(m) {
            dst.macs.push(*m);
        }
    }
    if dst.network_id.is_none() {
        dst.network_id = src.network_id.clone();
    }
    if dst.last_seen.is_none() {
        dst.last_seen = src.last_seen;
    }
    // Keep online=true if either side is online (sta already set true).
    dst.online = dst.online || src.online;
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn site_key_charset() {
        assert!(validate_site_key("default").is_ok());
        assert!(validate_site_key("site_1-A").is_ok());
        assert_eq!(
            validate_site_key("../evil").unwrap_err().code(),
            "clients.http.body"
        );
        assert_eq!(
            validate_site_key("bad key").unwrap_err().code(),
            "clients.http.body"
        );
        assert_eq!(
            validate_site_key(&"a".repeat(65)).unwrap_err().code(),
            "clients.http.body"
        );
        assert_eq!(
            validate_site_key("").unwrap_err().code(),
            "clients.http.body"
        );
    }
}
