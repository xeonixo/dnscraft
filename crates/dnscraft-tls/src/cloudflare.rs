//! Cloudflare DNS API client (zones + DNS records).
//!
//! Writers for ACME TXT and DynDNS A/AAAA share [`CloudflareClient::write_lock`]
//! so DynDNS never mutates records while a challenge is in flight (L7 / L9).

use std::sync::Arc;
use std::time::Duration;

use reqwest::Client;
use reqwest::header::{CONTENT_TYPE, HeaderValue};
use serde::Deserialize;
use serde_json::json;
use tokio::sync::{Mutex, MutexGuard};

const JSON: HeaderValue = HeaderValue::from_static("application/json");

use crate::Secret;
use crate::config::{CloudflareConfig, ZoneConfig};
use crate::error::TlsError;

/// Production Cloudflare API root (v4).
pub const CLOUDFLARE_API_BASE: &str = "https://api.cloudflare.com/client/v4";

/// Cloudflare "automatic" TTL.
pub const TTL_AUTO: u32 = 1;

/// Short TTL used for ACME DNS-01 TXT records.
pub const TTL_ACME_TXT: u32 = 120;

const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_BODY_BYTES: usize = 1024 * 1024;

/// Zone id and authoritative nameservers from Cloudflare.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ZoneInfo {
    /// Zone identifier.
    pub id: String,
    /// Apex name (e.g. `example.com`).
    pub name: String,
    /// Zone lifecycle status (`active`, `pending`, …).
    pub status: String,
    /// Cloudflare-assigned authoritative nameserver hostnames.
    pub name_servers: Vec<String>,
}

/// One DNS record as returned by the API.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DnsRecord {
    /// Cloudflare record id.
    pub id: String,
    /// Fully-qualified owner name.
    pub name: String,
    /// Record type (`A`, `AAAA`, `TXT`, …).
    pub record_type: String,
    /// RDATA (IP or TXT string).
    pub content: String,
    /// TTL in seconds (`1` = automatic).
    pub ttl: u32,
    /// Orange-cloud flag; must be `false` for DoT/DoQ.
    pub proxied: bool,
}

/// Query parameters for [`CloudflareClient::list_zone_records`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ListZoneRecordsQuery {
    /// 1-based page index (Cloudflare pagination).
    pub page: u32,
    /// Page size (`per_page` query parameter).
    pub per_page: u32,
    /// Optional case-insensitive substring filter on the record owner name.
    pub name_substr: Option<String>,
}

/// One page of DNS records from [`CloudflareClient::list_zone_records`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ZoneRecordsPage {
    /// Records on this page.
    pub records: Vec<DnsRecord>,
    /// Echo of the requested page.
    pub page: u32,
    /// Echo of the requested page size.
    pub per_page: u32,
    /// Total matching records across all pages.
    pub total_count: u32,
    /// Total pages available (`0` when unknown / empty).
    pub total_pages: u32,
}

/// Cloudflare DNS client with a shared writer mutex.
#[derive(Clone, Debug)]
pub struct CloudflareClient {
    http: Client,
    token: Secret,
    base_url: String,
    configured_zone_id: Option<String>,
    public_domain: String,
    zones: Vec<ZoneConfig>,
    write_lock: Arc<Mutex<()>>,
    cached_zone: Arc<Mutex<Option<ZoneInfo>>>,
    cached_zones: Arc<Mutex<Vec<ZoneInfo>>>,
}

impl CloudflareClient {
    /// Builds a client against the production API base.
    pub fn new(
        token: Secret,
        public_domain: impl Into<String>,
        cfg: &CloudflareConfig,
    ) -> Result<Self, TlsError> {
        Self::with_base_url(token, public_domain, cfg, CLOUDFLARE_API_BASE)
    }

    /// Builds a client against an alternate base URL (mock / tests).
    ///
    /// `base_url` should look like `https://api.cloudflare.com/client/v4` or
    /// `http://127.0.0.1:PORT/client/v4`.
    pub fn with_base_url(
        token: Secret,
        public_domain: impl Into<String>,
        cfg: &CloudflareConfig,
        base_url: impl Into<String>,
    ) -> Result<Self, TlsError> {
        let tls = crate::http_tls::client_config(&[])
            .map_err(|e| TlsError::cloudflare_http(format!("build TLS config: {e}")))?;
        let http = Client::builder()
            .use_preconfigured_tls(tls)
            .timeout(REQUEST_TIMEOUT)
            .connect_timeout(CONNECT_TIMEOUT)
            .build()
            .map_err(|e| TlsError::cloudflare_http(format!("build HTTP client: {e}")))?;
        Ok(Self {
            http,
            token,
            base_url: base_url.into().trim_end_matches('/').to_owned(),
            configured_zone_id: cfg.zone_id.clone(),
            public_domain: public_domain.into(),
            zones: Vec::new(),
            write_lock: Arc::new(Mutex::new(())),
            cached_zone: Arc::new(Mutex::new(None)),
            cached_zones: Arc::new(Mutex::new(Vec::new())),
        })
    }

    /// Adds additional zones, resolved by longest suffix match.
    pub fn with_zones(mut self, zones: Vec<ZoneConfig>) -> Self {
        self.zones = zones;
        self
    }

    /// Shared mutex for record writers (issuance + DynDNS).
    ///
    /// Callers that perform a multi-step mutation (e.g. create two TXT values)
    /// must hold this lock across the whole sequence. Individual methods do
    /// **not** take it themselves, to avoid deadlocks with a non-reentrant mutex.
    pub fn write_lock(&self) -> &Arc<Mutex<()>> {
        &self.write_lock
    }

    /// Convenience: lock the writer mutex.
    pub async fn write_guard(&self) -> MutexGuard<'_, ()> {
        self.write_lock.lock().await
    }

    /// Resolves (and caches) the zone id + nameservers.
    ///
    /// Uses `cfg.zone_id` when set; otherwise `GET /zones?name=<public_domain>`.
    /// Empty / missing zone → [`TlsError::CloudflareZone`].
    pub async fn zone(&self) -> Result<ZoneInfo, TlsError> {
        {
            let guard = self.cached_zone.lock().await;
            if let Some(z) = guard.as_ref() {
                return Ok(z.clone());
            }
        }
        let info = if let Some(id) = &self.configured_zone_id {
            self.fetch_zone_by_id(id).await?
        } else {
            self.fetch_zone_by_name(&self.public_domain).await?
        };
        *self.cached_zone.lock().await = Some(info.clone());
        Ok(info)
    }

    /// Resolves the zone that owns `name`.
    ///
    /// Uses the longest configured zone suffix match, falling back to
    /// [`Self::zone`] (public domain / `cloudflare.zone_id`). A name owned by
    /// neither is [`TlsError::DnsProviderZone`].
    pub async fn zone_for_name(&self, name: &str) -> Result<ZoneInfo, TlsError> {
        let Some(index) = pick_zone(&self.zones, name) else {
            let fallback = self.zone().await?;
            if zone_contains(&fallback.name, name) {
                return Ok(fallback);
            }
            return Err(TlsError::DnsProviderZone {
                message: format!("no configured zone matches {name}"),
            });
        };
        let zone_name = self.zones[index].name.clone();
        {
            let cached = self.cached_zones.lock().await;
            if let Some(info) = cached.iter().find(|z| z.name == zone_name) {
                return Ok(info.clone());
            }
        }
        let zone_id = self.zones[index].zone_id.clone();
        let info = match zone_id {
            Some(id) => self.fetch_zone_by_id(&id).await?,
            None => self.fetch_zone_by_name(&zone_name).await?,
        };
        self.cached_zones.lock().await.push(info.clone());
        Ok(info)
    }

    /// Lists every zone visible to the API token (all pages).
    ///
    /// Read-only inventory helper for Domain-Zonen; does not use or alter the
    /// writer mutex.
    pub async fn list_zones(&self) -> Result<Vec<ZoneInfo>, TlsError> {
        let mut page = 1u32;
        let per_page = 50u32;
        let mut out = Vec::new();
        loop {
            let url = format!("{}/zones", self.base_url);
            let page_s = page.to_string();
            let per_page_s = per_page.to_string();
            let url = url_with_query(&url, &[("page", &page_s), ("per_page", &per_page_s)])?;
            let envelope: Envelope<Vec<ApiZone>> = self.request(self.http.get(url)).await?;
            let batch = envelope.result.unwrap_or_default();
            let batch_len = batch.len();
            out.extend(batch.into_iter().map(ZoneInfo::from));
            let total_pages = envelope
                .result_info
                .as_ref()
                .map(ResultInfo::total_pages_or_computed)
                .unwrap_or(1);
            if page >= total_pages || batch_len == 0 {
                break;
            }
            page += 1;
        }
        Ok(out)
    }

    /// Lists DNS records in `zone_id` with Cloudflare pagination.
    ///
    /// Optional [`ListZoneRecordsQuery::name_substr`] is a case-insensitive
    /// substring match on the owner name (applied by the API mock / filtered
    /// server-side when supported). Does not take the writer mutex.
    pub async fn list_zone_records(
        &self,
        zone_id: &str,
        query: &ListZoneRecordsQuery,
    ) -> Result<ZoneRecordsPage, TlsError> {
        let page = query.page.max(1);
        let per_page = query.per_page.max(1);
        let url = format!("{}/zones/{zone_id}/dns_records", self.base_url);
        let page_s = page.to_string();
        let per_page_s = per_page.to_string();
        let mut params: Vec<(&str, &str)> = vec![("page", &page_s), ("per_page", &per_page_s)];
        if let Some(substr) = query.name_substr.as_deref() {
            params.push(("name_substr", substr));
        }
        let url = url_with_query(&url, &params)?;
        let envelope: Envelope<Vec<ApiRecord>> = self.request(self.http.get(url)).await?;
        let records: Vec<DnsRecord> = envelope
            .result
            .unwrap_or_default()
            .into_iter()
            .map(DnsRecord::from)
            .collect();
        let (total_count, total_pages) = match envelope.result_info.as_ref() {
            Some(info) => (info.total_count, info.total_pages_or_computed()),
            None => {
                let n = records.len() as u32;
                (n, if n == 0 { 0 } else { 1 })
            }
        };
        Ok(ZoneRecordsPage {
            records,
            page,
            per_page,
            total_count,
            total_pages,
        })
    }

    /// Lists records filtered by owner name and type.
    pub async fn list_records(
        &self,
        name: &str,
        record_type: &str,
    ) -> Result<Vec<DnsRecord>, TlsError> {
        let zone = self.zone_for_name(name).await?;
        let url = format!("{}/zones/{}/dns_records", self.base_url, zone.id);
        let url = url_with_query(&url, &[("name", name), ("type", record_type)])?;
        let envelope: Envelope<Vec<ApiRecord>> = self.request(self.http.get(url)).await?;
        Ok(envelope
            .result
            .unwrap_or_default()
            .into_iter()
            .map(DnsRecord::from)
            .collect())
    }

    /// Creates a TXT record (**add**, never upsert) so multiple values can
    /// coexist at one name.
    pub async fn create_txt(
        &self,
        name: &str,
        content: &str,
        ttl: u32,
    ) -> Result<DnsRecord, TlsError> {
        let zone = self.zone_for_name(name).await?;
        let url = format!("{}/zones/{}/dns_records", self.base_url, zone.id);
        let body = json!({
            "type": "TXT",
            "name": name,
            "content": content,
            "ttl": ttl,
        });
        let envelope: Envelope<ApiRecord> = self
            .request(
                self.http
                    .post(&url)
                    .header(CONTENT_TYPE, JSON)
                    .body(body.to_string()),
            )
            .await?;
        envelope
            .result
            .map(DnsRecord::from)
            .ok_or_else(|| TlsError::cloudflare_http("create TXT: empty result"))
    }

    /// Deletes a record by id in the default (public-domain) zone.
    pub async fn delete_record(&self, record_id: &str) -> Result<(), TlsError> {
        let zone = self.zone().await?;
        self.delete_record_in(&zone.id, record_id).await
    }

    /// Deletes a record by id in an explicit zone.
    pub async fn delete_record_in(&self, zone_id: &str, record_id: &str) -> Result<(), TlsError> {
        let url = format!("{}/zones/{zone_id}/dns_records/{record_id}", self.base_url);
        let _: Envelope<serde_json::Value> = self.request(self.http.delete(&url)).await?;
        Ok(())
    }

    /// Upserts an A or AAAA record with `proxied: false` and automatic TTL.
    ///
    /// If a record of that type already exists at `name`, it is updated (PUT);
    /// otherwise a new one is created.
    pub async fn upsert_address(
        &self,
        name: &str,
        record_type: &str,
        content: &str,
    ) -> Result<DnsRecord, TlsError> {
        if record_type != "A" && record_type != "AAAA" {
            return Err(TlsError::cloudflare_http(format!(
                "upsert_address: unsupported type {record_type}"
            )));
        }
        self.upsert_record(name, record_type, content, false).await
    }

    /// Upserts a DNS-only CNAME (`proxied: false`) at `name` → `target`.
    ///
    /// Removes conflicting A/AAAA at the same owner first (a name cannot hold
    /// both address records and a CNAME). Used by DynDNS public-entry to point
    /// `dns.<domain>` / `*.dns.<domain>` at the entry node's hostname.
    pub async fn upsert_cname(&self, name: &str, target: &str) -> Result<DnsRecord, TlsError> {
        // CNAME cannot coexist with A/AAAA at the same owner.
        self.delete_records_of_types(name, &["A", "AAAA"]).await?;
        self.upsert_record(name, "CNAME", target, false).await
    }

    /// Deletes every record of the given types at `name`.
    pub async fn delete_records_of_types(
        &self,
        name: &str,
        types: &[&str],
    ) -> Result<(), TlsError> {
        let zone = self.zone_for_name(name).await?;
        for record_type in types {
            for record in self.list_records(name, record_type).await? {
                self.delete_record_in(&zone.id, &record.id).await?;
            }
        }
        Ok(())
    }

    async fn upsert_record(
        &self,
        name: &str,
        record_type: &str,
        content: &str,
        proxied: bool,
    ) -> Result<DnsRecord, TlsError> {
        let existing = self.list_records(name, record_type).await?;
        let zone = self.zone_for_name(name).await?;
        if let Some(prev) = existing.into_iter().next() {
            if prev.content.eq_ignore_ascii_case(content) && prev.proxied == proxied {
                return Ok(prev);
            }
            let url = format!(
                "{}/zones/{}/dns_records/{}",
                self.base_url, zone.id, prev.id
            );
            let body = json!({
                "type": record_type,
                "name": name,
                "content": content,
                "ttl": TTL_AUTO,
                "proxied": proxied,
            });
            let envelope: Envelope<ApiRecord> = self
                .request(
                    self.http
                        .put(&url)
                        .header(CONTENT_TYPE, JSON)
                        .body(body.to_string()),
                )
                .await?;
            envelope
                .result
                .map(DnsRecord::from)
                .ok_or_else(|| TlsError::cloudflare_http("upsert: empty result"))
        } else {
            let url = format!("{}/zones/{}/dns_records", self.base_url, zone.id);
            let body = json!({
                "type": record_type,
                "name": name,
                "content": content,
                "ttl": TTL_AUTO,
                "proxied": proxied,
            });
            let envelope: Envelope<ApiRecord> = self
                .request(
                    self.http
                        .post(&url)
                        .header(CONTENT_TYPE, JSON)
                        .body(body.to_string()),
                )
                .await?;
            envelope
                .result
                .map(DnsRecord::from)
                .ok_or_else(|| TlsError::cloudflare_http("create record: empty result"))
        }
    }

    async fn fetch_zone_by_name(&self, name: &str) -> Result<ZoneInfo, TlsError> {
        let url = format!("{}/zones", self.base_url);
        let url = url_with_query(&url, &[("name", name)])?;
        let envelope: Envelope<Vec<ApiZone>> = self.request(self.http.get(url)).await?;
        let list = envelope.result.unwrap_or_default();
        match list.as_slice() {
            [] => Err(TlsError::CloudflareZone {
                message: format!("no zone named {name}"),
            }),
            [z, ..] => Ok(ZoneInfo::from(z.clone())),
        }
    }

    async fn fetch_zone_by_id(&self, id: &str) -> Result<ZoneInfo, TlsError> {
        let url = format!("{}/zones/{id}", self.base_url);
        match self.request::<ApiZone>(self.http.get(&url)).await {
            Ok(envelope) => {
                let z = envelope.result.ok_or_else(|| TlsError::CloudflareZone {
                    message: format!("zone id {id} not found"),
                })?;
                Ok(ZoneInfo::from(z))
            }
            Err(TlsError::CloudflareHttp {
                status: Some(404),
                message,
                ..
            }) => Err(TlsError::CloudflareZone {
                message: format!("zone id {id} not found ({message})"),
            }),
            Err(e) => Err(e),
        }
    }

    async fn request<T: for<'de> Deserialize<'de>>(
        &self,
        builder: reqwest::RequestBuilder,
    ) -> Result<Envelope<T>, TlsError> {
        let token = self.token.expose();
        let response = builder
            .header("Authorization", format!("Bearer {token}"))
            .send()
            .await
            .map_err(|e| {
                TlsError::cloudflare_http(redact_token(&format!("transport: {e}"), token))
            })?;

        let status = response.status();
        let status_code = status.as_u16();
        let retry_after = response
            .headers()
            .get(reqwest::header::RETRY_AFTER)
            .and_then(|v| v.to_str().ok())
            .and_then(crate::error::parse_retry_after_header);

        let bytes = read_capped(response, MAX_BODY_BYTES)
            .await
            .map_err(|m| TlsError::cloudflare_http(redact_token(&m, token)))?;

        let envelope: Envelope<T> = serde_json::from_slice(&bytes).map_err(|e| {
            TlsError::cloudflare_http_status(
                redact_token(&format!("HTTP {status}: unparseable body ({e})"), token),
                status_code,
                retry_after,
            )
        })?;

        if !envelope.success || !status.is_success() {
            let detail = envelope
                .errors
                .iter()
                .map(|e| format!("{}: {}", e.code, e.message))
                .collect::<Vec<_>>()
                .join("; ");
            let message = if detail.is_empty() {
                format!("HTTP {status}")
            } else {
                format!("HTTP {status}: {detail}")
            };
            return Err(TlsError::CloudflareHttp {
                message: redact_token(&message, token),
                retry_after,
                status: Some(status_code),
            });
        }

        Ok(envelope)
    }
}

/// Whether `name` is `zone` or a subdomain of it (case-insensitive).
fn zone_contains(zone: &str, name: &str) -> bool {
    let name = name.trim_end_matches('.').to_ascii_lowercase();
    let zone = zone.trim_end_matches('.').to_ascii_lowercase();
    !zone.is_empty() && (name == zone || name.ends_with(&format!(".{zone}")))
}

/// Index of the configured zone that owns `name` (longest suffix wins).
fn pick_zone(zones: &[ZoneConfig], name: &str) -> Option<usize> {
    let name = name.trim_end_matches('.').to_ascii_lowercase();
    zones
        .iter()
        .enumerate()
        .filter(|(_, z)| {
            let zone = z.name.trim_end_matches('.').to_ascii_lowercase();
            name == zone || name.ends_with(&format!(".{zone}"))
        })
        .max_by_key(|(_, z)| z.name.len())
        .map(|(i, _)| i)
}

/// Appends percent-encoded query parameters (reqwest 0.13 gates
/// `RequestBuilder::query` behind the `query` feature, which we do not enable).
fn url_with_query(url: &str, params: &[(&str, &str)]) -> Result<reqwest::Url, TlsError> {
    reqwest::Url::parse_with_params(url, params)
        .map_err(|e| TlsError::cloudflare_http(format!("build request URL: {e}")))
}

/// Reads an HTTP body while enforcing `max`: rejects early on an oversized
/// `Content-Length` and aborts as soon as streamed chunks exceed the cap.
pub(crate) async fn read_capped(
    mut response: reqwest::Response,
    max: usize,
) -> Result<Vec<u8>, String> {
    if let Some(len) = response.content_length()
        && len > max as u64
    {
        return Err(format!("body {len} bytes exceeds {max} cap"));
    }
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|e| format!("read body: {e}"))?
    {
        if body.len() + chunk.len() > max {
            return Err(format!(
                "body over {} bytes exceeds {max} cap",
                body.len() + chunk.len()
            ));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

fn redact_token(text: &str, token: &str) -> String {
    if token.is_empty() {
        return text.to_owned();
    }
    text.replace(token, "[redacted]")
}

#[derive(Debug, Deserialize)]
#[serde(bound(deserialize = "T: Deserialize<'de>"))]
struct Envelope<T> {
    success: bool,
    #[serde(default)]
    errors: Vec<ApiError>,
    #[serde(default)]
    result: Option<T>,
    #[serde(default)]
    result_info: Option<ResultInfo>,
}

#[derive(Debug, Deserialize)]
struct ResultInfo {
    #[serde(default)]
    per_page: u32,
    #[serde(default)]
    total_count: u32,
    #[serde(default)]
    total_pages: u32,
}

impl ResultInfo {
    fn total_pages_or_computed(&self) -> u32 {
        if self.total_pages > 0 {
            return self.total_pages;
        }
        if self.per_page == 0 || self.total_count == 0 {
            return 0;
        }
        self.total_count.div_ceil(self.per_page)
    }
}

#[derive(Debug, Deserialize)]
struct ApiError {
    code: u32,
    message: String,
}

#[derive(Clone, Debug, Deserialize)]
struct ApiZone {
    id: String,
    name: String,
    #[serde(default)]
    status: String,
    #[serde(default)]
    name_servers: Vec<String>,
}

impl From<ApiZone> for ZoneInfo {
    fn from(z: ApiZone) -> Self {
        Self {
            id: z.id,
            name: z.name,
            status: z.status,
            name_servers: z.name_servers,
        }
    }
}

#[derive(Debug, Deserialize)]
struct ApiRecord {
    id: String,
    name: String,
    #[serde(rename = "type")]
    record_type: String,
    content: String,
    #[serde(default)]
    ttl: u32,
    #[serde(default)]
    proxied: bool,
}

impl From<ApiRecord> for DnsRecord {
    fn from(r: ApiRecord) -> Self {
        Self {
            id: r.id,
            name: r.name,
            record_type: r.record_type,
            content: r.content,
            ttl: r.ttl,
            proxied: r.proxied,
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn zones() -> Vec<ZoneConfig> {
        vec![
            ZoneConfig {
                name: "example.com".into(),
                zone_id: None,
            },
            ZoneConfig {
                name: "sub.example.com".into(),
                zone_id: Some("z-sub".into()),
            },
        ]
    }

    #[test]
    fn pick_zone_uses_longest_suffix() {
        let zones = zones();
        assert_eq!(
            pick_zone(&zones, "_acme-challenge.dns.sub.example.com."),
            Some(1)
        );
        assert_eq!(pick_zone(&zones, "dns.example.com"), Some(0));
        assert_eq!(pick_zone(&zones, "example.com"), Some(0));
        assert_eq!(pick_zone(&zones, "other.net"), None);
        // A label that merely ends with the zone text is not a suffix match.
        assert_eq!(pick_zone(&zones, "notexample.com"), None);
    }
}
