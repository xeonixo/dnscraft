//! UniFi Network Integration API (`/proxy/network/integration/v1/…`).
//!
//! Fetches sites, networks (with optional details), and paged connected clients.
//! Defensive parsing: unknown fields ignored; bad rows skipped and counted.

use std::net::IpAddr;
use std::str::FromStr;
use std::time::SystemTime;

use ipnet::IpNet;
use serde::Deserialize;
use serde_json::Value;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::error::ClientsError;
use crate::gateway::GatewayClient;
use crate::merge::{MAX_CLIENT_COUNT, NetworkInfo, UnifiObservation};
use crate::types::{ClientId, MacAddr};

/// Integration API path prefix on the gateway.
pub const INTEGRATION_PREFIX: &str = "/proxy/network/integration/v1";

const PAGE_LIMIT: usize = 200;
/// Hard page bound: enough for [`MAX_CLIENT_COUNT`] at `PAGE_LIMIT`, plus one.
const MAX_PAGES: usize = MAX_CLIENT_COUNT / PAGE_LIMIT + 1;

/// Result of one Integration fetch.
#[derive(Clone, Debug)]
pub struct IntegrationFetch {
    /// Resolved site UUID.
    pub site_id: String,
    /// Networks (details merged when available).
    pub networks: Vec<NetworkInfo>,
    /// Connected clients as normalised observations (singular `ipAddress`).
    pub observations: Vec<UnifiObservation>,
    /// Rows skipped due to missing id / unparseable fields.
    pub skipped_rows: u64,
}

/// Defensively parses one Integration clients page (`{"data":[…],…}`).
///
/// Never panics on odd row shapes: unknown fields are ignored, bad rows are
/// skipped and counted. A completely unusable body yields
/// [`ClientsError::HttpBody`].
pub fn parse_clients_page_json(body: &[u8]) -> Result<(Vec<UnifiObservation>, u64), ClientsError> {
    let page: ListPage<Value> =
        serde_json::from_slice(body).map_err(|e| ClientsError::HttpBody {
            message: format!("clients JSON: {e}"),
        })?;
    let mut out = Vec::new();
    let mut skipped = 0u64;
    for row in &page.data {
        match parse_client_row(row) {
            Some(obs) => out.push(obs),
            None => skipped += 1,
        }
    }
    Ok((out, skipped))
}

/// Fetches sites → networks → paged clients for one site.
///
/// When `configured_site` is `None`, the sole site is auto-picked; two or more
/// sites without a configured id → [`ClientsError::ConfigInvalid`].
pub async fn fetch(
    gw: &GatewayClient,
    configured_site: Option<&str>,
) -> Result<IntegrationFetch, ClientsError> {
    let site_id = resolve_site(gw, configured_site).await?;
    let networks = fetch_networks(gw, &site_id).await?;
    let (observations, skipped_rows) = fetch_clients(gw, &site_id).await?;
    Ok(IntegrationFetch {
        site_id,
        networks,
        observations,
        skipped_rows,
    })
}

async fn resolve_site(
    gw: &GatewayClient,
    configured: Option<&str>,
) -> Result<String, ClientsError> {
    let body = gw.get(&format!("{INTEGRATION_PREFIX}/sites")).await?;
    let page: ListPage<SiteRow> =
        serde_json::from_slice(&body).map_err(|e| ClientsError::HttpBody {
            message: format!("sites JSON: {e}"),
        })?;
    let sites = page.data;
    match configured {
        Some(want) => Ok(want.to_owned()),
        None => match sites.as_slice() {
            [] => Err(ClientsError::config("no UniFi sites returned")),
            [one] => Ok(one.id.clone()),
            _ => Err(ClientsError::config(
                "multiple UniFi sites; set unifi.site_id",
            )),
        },
    }
}

async fn fetch_networks(
    gw: &GatewayClient,
    site_id: &str,
) -> Result<Vec<NetworkInfo>, ClientsError> {
    let path = format!("{INTEGRATION_PREFIX}/sites/{site_id}/networks");
    let body = gw.get(&path).await?;
    let page: ListPage<Value> =
        serde_json::from_slice(&body).map_err(|e| ClientsError::HttpBody {
            message: format!("networks JSON: {e}"),
        })?;

    let mut out = Vec::with_capacity(page.data.len());
    for row in page.data {
        let Some(id) = row.get("id").and_then(|v| v.as_str()) else {
            continue;
        };
        let name = row
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or(id)
            .to_owned();
        let vlan_id = row.get("vlanId").and_then(|v| v.as_u64()).map(|n| n as u16);

        // Try details endpoint; missing/failure → overview-only.
        let details_path = format!("{INTEGRATION_PREFIX}/sites/{site_id}/networks/{id}");
        let (ipv4_prefix, ipv6_prefix, domain_name) = match gw.get(&details_path).await {
            Ok(bytes) => parse_network_details(&bytes),
            Err(_) => (None, None, None),
        };

        out.push(NetworkInfo {
            id: id.to_owned(),
            name,
            vlan_id,
            ipv4_prefix,
            ipv6_prefix,
            domain_name,
        });
    }
    Ok(out)
}

fn parse_network_details(bytes: &[u8]) -> (Option<IpNet>, Option<IpNet>, Option<String>) {
    let Ok(v) = serde_json::from_slice::<Value>(bytes) else {
        return (None, None, None);
    };
    // Details may be wrapped in `{ "data": { … } }` or be the object itself.
    let obj = v.get("data").unwrap_or(&v);

    let ipv4 = obj
        .pointer("/ipv4Configuration/hostIpAddress")
        .and_then(|x| x.as_str())
        .zip(
            obj.pointer("/ipv4Configuration/prefixLength")
                .and_then(|x| x.as_u64()),
        )
        .and_then(|(host, len)| {
            let addr = IpAddr::from_str(host).ok()?;
            IpNet::new(addr, len as u8).ok()
        });

    let ipv6 = obj
        .pointer("/ipv6Configuration/hostIpAddress")
        .and_then(|x| x.as_str())
        .zip(
            obj.pointer("/ipv6Configuration/prefixLength")
                .and_then(|x| x.as_u64()),
        )
        .and_then(|(host, len)| {
            let addr = IpAddr::from_str(host).ok()?;
            IpNet::new(addr, len as u8).ok()
        });

    // DHCP domain is not on Integration schemas (unverified); accept if present.
    let domain = obj
        .pointer("/dhcpConfiguration/domainName")
        .or_else(|| obj.get("domainName"))
        .and_then(|x| x.as_str())
        .map(str::to_owned);

    (ipv4, ipv6, domain)
}

async fn fetch_clients(
    gw: &GatewayClient,
    site_id: &str,
) -> Result<(Vec<UnifiObservation>, u64), ClientsError> {
    let mut observations = Vec::new();
    let mut skipped = 0u64;
    let mut offset = 0usize;

    for page_idx in 0..MAX_PAGES {
        let path = format!(
            "{INTEGRATION_PREFIX}/sites/{site_id}/clients?offset={offset}&limit={PAGE_LIMIT}"
        );
        let body = match gw.get(&path).await {
            Ok(b) => b,
            Err(e) if page_idx > 0 => {
                return Err(ClientsError::SyncPartial {
                    message: format!("clients page offset={offset}: {}", e.code()),
                });
            }
            Err(e) => return Err(e),
        };

        let page: ListPage<Value> = serde_json::from_slice(&body).map_err(|e| {
            if page_idx > 0 {
                ClientsError::SyncPartial {
                    message: format!("clients page offset={offset} JSON: {e}"),
                }
            } else {
                ClientsError::HttpBody {
                    message: format!("clients JSON: {e}"),
                }
            }
        })?;

        let count = page.data.len();
        for row in page.data {
            match parse_client_row(&row) {
                Some(obs) => observations.push(obs),
                None => skipped += 1,
            }
        }

        if count < PAGE_LIMIT {
            break;
        }
        offset = offset.saturating_add(PAGE_LIMIT);
        if page_idx + 1 == MAX_PAGES {
            return Err(ClientsError::SyncPartial {
                message: format!("clients pagination exceeded {MAX_PAGES} pages"),
            });
        }
    }

    Ok((observations, skipped))
}

fn parse_client_row(row: &Value) -> Option<UnifiObservation> {
    let id_str = row.get("id")?.as_str()?;
    let id = ClientId::new(id_str).ok()?;
    let display_name = row
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or(id_str)
        .to_owned();

    let mut addresses = Vec::new();
    if let Some(ip) = row.get("ipAddress").and_then(|v| v.as_str())
        && let Ok(addr) = IpAddr::from_str(ip)
    {
        addresses.push(addr);
    }

    let mut macs = Vec::new();
    if let Some(m) = row.get("macAddress").and_then(|v| v.as_str())
        && let Ok(mac) = MacAddr::parse(m)
    {
        macs.push(mac);
    }

    let last_seen = row
        .get("connectedAt")
        .and_then(|v| v.as_str())
        .and_then(parse_connected_at);

    Some(UnifiObservation {
        id,
        display_name,
        macs,
        addresses,
        network_id: None, // not on Integration client schemas
        last_seen,
        online: true,
    })
}

fn parse_connected_at(s: &str) -> Option<SystemTime> {
    let odt = OffsetDateTime::parse(s, &Rfc3339).ok()?;
    let secs = odt.unix_timestamp();
    if secs < 0 {
        return None;
    }
    Some(SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(secs as u64))
}

#[derive(Debug, Deserialize)]
#[serde(bound(deserialize = "T: Deserialize<'de>"))]
struct ListPage<T> {
    #[serde(default)]
    data: Vec<T>,
}

#[derive(Debug, Deserialize)]
struct SiteRow {
    id: String,
}
