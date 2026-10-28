//! Webhook notification channels (WX7): section validation, the egress guard,
//! one pinned HTTPS delivery and the payload. Routes are in
//! `api/notifications_routes.rs`.
//!
//! Egress rules (SPEC-control-api.md, WX7): HTTPS only; the host must match
//! `notifications.allowed_hosts` (exact or suffix), and an empty list rejects
//! every host; every resolved address is checked against the private, loopback,
//! link-local, multicast and CGNAT ranges unless `allow_private_destinations`
//! is set; the connection is pinned to the checked address; redirects are not
//! followed; connect and total timeouts are 5 s and 10 s. Secrets live in the
//! `kv` store, never in the config snapshot, and are never logged or returned.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

use ring::rand::{SecureRandom, SystemRandom};
use serde_json::{Value, json};
use url::Url;

use crate::api::config_routes::valid_id;
use crate::error::ControlApiError;
use crate::notifications::ring_client_builder;
use crate::storage::Db;

/// Config snapshot section for notification channels.
pub(crate) const SECTION: &str = "notifications";
/// Event codes a channel may subscribe to.
pub(crate) const EVENT_CATALOG: [&str; 4] = [
    "tls.cert.expiring",
    "tls.dyndns.failure",
    "cluster.node.offline",
    "filtering.list.update_failed",
];
/// Longest accepted webhook secret.
pub(crate) const MAX_SECRET_BYTES: usize = 256;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const TOTAL_TIMEOUT: Duration = Duration::from_secs(10);

/// Errors of the notification routes, carrying their stable code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NotificationError {
    /// Stable code, for example `control_api.notifications.egress_denied`.
    pub code: &'static str,
    /// Non-secret detail for the client.
    pub reason: String,
}

impl NotificationError {
    pub(crate) fn new(code: &'static str, reason: impl Into<String>) -> Self {
        Self {
            code,
            reason: reason.into(),
        }
    }
}

/// `kv` key holding the webhook secret of one channel.
pub(crate) fn secret_key(channel_id: &str) -> String {
    format!("notifications.secret.{channel_id}")
}

/// Whether `host` is an allowed hostname (`allowed_hosts` entry or a subdomain).
pub(crate) fn host_allowed(host: &str, allowed_hosts: &[String]) -> bool {
    let host = host.to_ascii_lowercase();
    allowed_hosts
        .iter()
        .any(|entry| host == *entry || host.ends_with(&format!(".{entry}")))
}

/// Validates a plain hostname used in `allowed_hosts`.
fn valid_host(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= 253
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
                && !label.starts_with('-')
                && !label.ends_with('-')
        })
}

/// Parses a channel URL: HTTPS, a host, no userinfo and no fragment.
pub(crate) fn parse_channel_url(raw: &str) -> Result<Url, NotificationError> {
    let invalid =
        |reason: &str| NotificationError::new("control_api.notifications.invalid", reason);
    let url = Url::parse(raw).map_err(|_| invalid("url is not a valid URL"))?;
    if url.scheme() != "https" {
        return Err(invalid("url must use https"));
    }
    if url.host_str().is_none() {
        return Err(invalid("url has no host"));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(invalid("url must not contain credentials"));
    }
    if url.fragment().is_some() {
        return Err(invalid("url must not contain a fragment"));
    }
    Ok(url)
}

/// The URL as returned by the API: scheme, host, port and path only. The query
/// and userinfo are never returned.
pub(crate) fn redacted_url(raw: &str) -> Option<String> {
    let url = Url::parse(raw).ok()?;
    let host = url.host_str()?;
    let port = url.port().map(|p| format!(":{p}")).unwrap_or_default();
    Some(format!("{}://{host}{port}{}", url.scheme(), url.path()))
}

/// Validates the stored `notifications` section (shape only). Host allowlist
/// and egress checks happen at write time and at delivery time.
pub(crate) fn validate_section(section: &Value) -> Result<(), NotificationError> {
    let invalid =
        |reason: &str| NotificationError::new("control_api.notifications.invalid", reason);
    let map = section
        .as_object()
        .ok_or_else(|| invalid("notifications must be an object"))?;
    for key in map.keys() {
        if !matches!(
            key.as_str(),
            "channels" | "allowed_hosts" | "allow_private_destinations"
        ) {
            return Err(invalid(&format!("unknown field `notifications.{key}`")));
        }
    }
    if let Some(hosts) = map.get("allowed_hosts") {
        let hosts = hosts
            .as_array()
            .ok_or_else(|| invalid("allowed_hosts must be a list"))?;
        for host in hosts {
            match host.as_str() {
                Some(host) if valid_host(host) => {}
                _ => return Err(invalid("allowed_hosts entries must be plain hostnames")),
            }
        }
    }
    if let Some(flag) = map.get("allow_private_destinations")
        && !flag.is_boolean()
    {
        return Err(invalid("allow_private_destinations must be a boolean"));
    }
    let channels = match map.get("channels") {
        None => return Ok(()),
        Some(channels) => channels
            .as_array()
            .ok_or_else(|| invalid("channels must be a list"))?,
    };
    let mut seen = std::collections::BTreeSet::new();
    for channel in channels {
        let object = channel
            .as_object()
            .ok_or_else(|| invalid("each channel must be an object"))?;
        for key in object.keys() {
            if !matches!(key.as_str(), "id" | "type" | "enabled" | "url" | "events") {
                return Err(invalid(&format!("unknown channel field `{key}`")));
            }
        }
        let id = object
            .get("id")
            .and_then(Value::as_str)
            .filter(|id| valid_id(id))
            .ok_or_else(|| invalid("channel id must be a lowercase label"))?;
        if !seen.insert(id.to_owned()) {
            return Err(invalid("channel ids must be unique"));
        }
        if object.get("type").and_then(Value::as_str) != Some("webhook") {
            return Err(invalid("channel type must be webhook"));
        }
        if object.get("enabled").is_some_and(|v| !v.is_boolean()) {
            return Err(invalid("channel enabled must be a boolean"));
        }
        let url = object
            .get("url")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid("channel url is required"))?;
        parse_channel_url(url)?;
        let events = object
            .get("events")
            .and_then(Value::as_array)
            .ok_or_else(|| invalid("channel events must be a list"))?;
        for event in events {
            match event.as_str() {
                Some(name) if EVENT_CATALOG.contains(&name) => {}
                _ => return Err(invalid("channel events must come from the event catalog")),
            }
        }
    }
    Ok(())
}

/// Whether an address is private, loopback, link-local, multicast, unspecified
/// or CGNAT, or an IPv4-mapped form of one of those.
pub(crate) fn is_private_address(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_private_v4(v4),
        IpAddr::V6(v6) => {
            if let Some(mapped) = v6.to_ipv4_mapped() {
                return is_private_v4(mapped);
            }
            let segments = v6.segments();
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || segments[0] & 0xffc0 == 0xfe80
                || segments[0] & 0xfe00 == 0xfc00
        }
    }
}

fn is_private_v4(v4: Ipv4Addr) -> bool {
    let [a, b, _, _] = v4.octets();
    v4.is_private()
        || v4.is_loopback()
        || v4.is_link_local()
        || v4.is_multicast()
        || v4.is_broadcast()
        || v4.is_unspecified()
        || (a == 100 && (b & 0xc0) == 64)
}

/// Resolves the URL host and returns the address to pin to. Every resolved
/// address is checked; one private address denies the whole destination.
pub(crate) async fn check_egress(
    url: &Url,
    allow_private: bool,
) -> Result<SocketAddr, NotificationError> {
    let host = url.host_str().ok_or_else(|| {
        NotificationError::new("control_api.notifications.invalid", "url has no host")
    })?;
    let port = url.port_or_known_default().unwrap_or(443);
    let addresses: Vec<SocketAddr> = tokio::net::lookup_host((host, port))
        .await
        .map_err(|_| {
            NotificationError::new("control_api.notifications.delivery", "host did not resolve")
        })?
        .collect();
    if addresses.is_empty() {
        return Err(NotificationError::new(
            "control_api.notifications.delivery",
            "host did not resolve",
        ));
    }
    if !allow_private && addresses.iter().any(|addr| is_private_address(addr.ip())) {
        return Err(NotificationError::new(
            "control_api.notifications.egress_denied",
            "destination resolves to a private address",
        ));
    }
    Ok(addresses[0])
}

/// Random hex event id for the payload.
fn event_id() -> String {
    let mut bytes = [0u8; 16];
    // A failed system RNG yields an all-zero id; it is only a correlation key.
    let _ = SystemRandom::new().fill(&mut bytes);
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// The webhook body. It carries the event code, severity, module, time and the
/// caller's raw params. No client or domain names are added (default off).
pub(crate) fn payload(
    event: &str,
    severity: &str,
    module: &str,
    params: Value,
    created_at: i64,
) -> Value {
    json!({
        "id": event_id(),
        "severity": severity,
        "module": module,
        "created_at": created_at,
        "code": event,
        "params": params,
    })
}

impl From<NotificationError> for ControlApiError {
    fn from(error: NotificationError) -> Self {
        ControlApiError::Notification {
            code: error.code,
            reason: error.reason,
        }
    }
}

/// Result of one successful delivery.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Delivery {
    /// HTTP status returned by the receiver.
    pub status: u16,
    /// Wall time of the request.
    pub latency_ms: u64,
}

/// Sends one payload to a channel URL. Transport and non-2xx failures map to
/// `control_api.notifications.delivery`; no URL or secret appears in the error.
pub(crate) async fn deliver(
    url: &Url,
    allowed_hosts: &[String],
    allow_private: bool,
    secret: Option<&str>,
    body: &Value,
) -> Result<Delivery, NotificationError> {
    let host = url.host_str().ok_or_else(|| {
        NotificationError::new("control_api.notifications.invalid", "url has no host")
    })?;
    if !host_allowed(host, allowed_hosts) {
        return Err(NotificationError::new(
            "control_api.notifications.host_not_allowed",
            "host is not in notifications.allowed_hosts",
        ));
    }
    let addr = check_egress(url, allow_private).await?;
    let client = ring_client_builder()
        .and_then(|builder| {
            builder
                .resolve(host, addr)
                .redirect(reqwest::redirect::Policy::none())
                .connect_timeout(CONNECT_TIMEOUT)
                .timeout(TOTAL_TIMEOUT)
                .build()
                .ok()
        })
        .ok_or_else(|| {
            NotificationError::new("control_api.notifications.delivery", "client unavailable")
        })?;
    let mut request = client
        .post(url.as_str())
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(body.to_string());
    if let Some(secret) = secret {
        request = request.bearer_auth(secret);
    }
    let started = Instant::now();
    let response = request.send().await.map_err(|error| {
        let reason = if error.is_timeout() {
            "request timed out"
        } else {
            "request failed"
        };
        NotificationError::new("control_api.notifications.delivery", reason)
    })?;
    let status = response.status();
    let latency_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    if !status.is_success() {
        return Err(NotificationError::new(
            "control_api.notifications.delivery",
            format!("receiver answered {}", status.as_u16()),
        ));
    }
    Ok(Delivery {
        status: status.as_u16(),
        latency_ms,
    })
}

/// Reads the stored secret of a channel, if any.
pub(crate) async fn channel_secret(
    db: &Db,
    channel_id: &str,
) -> Result<Option<String>, ControlApiError> {
    db.kv_get(&secret_key(channel_id)).await
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn private_ranges_are_denied() {
        for ip in [
            "127.0.0.1",
            "10.1.2.3",
            "172.16.0.9",
            "192.168.1.1",
            "169.254.1.1",
            "100.64.0.1",
            "224.0.0.1",
            "0.0.0.0",
            "::1",
            "fe80::1",
            "fd00::1",
            "::ffff:10.0.0.1",
        ] {
            assert!(is_private_address(ip.parse().unwrap()), "{ip}");
        }
        for ip in ["203.0.113.5", "1.1.1.1", "2606:4700::1111"] {
            assert!(!is_private_address(ip.parse().unwrap()), "{ip}");
        }
    }

    #[test]
    fn allowlist_matches_exact_and_subdomains_only() {
        let allowed = vec!["example.com".to_owned()];
        assert!(host_allowed("example.com", &allowed));
        assert!(host_allowed("hooks.example.com", &allowed));
        assert!(!host_allowed("evilexample.com", &allowed));
        assert!(!host_allowed("example.com.evil.net", &allowed));
        assert!(!host_allowed("example.com", &[]), "empty list rejects all");
    }

    #[test]
    fn urls_must_be_https_without_credentials() {
        assert!(parse_channel_url("http://example.com/h").is_err());
        assert!(parse_channel_url("https://user:pw@example.com/h").is_err());
        assert!(parse_channel_url("https://example.com/h#frag").is_err());
        assert!(parse_channel_url("https://example.com/h?token=x").is_ok());
    }

    #[test]
    fn returned_url_drops_query_and_userinfo() {
        assert_eq!(
            redacted_url("https://hooks.example.com:8443/in/abc?token=secret").as_deref(),
            Some("https://hooks.example.com:8443/in/abc")
        );
    }

    #[test]
    fn payload_has_no_client_or_domain_names_by_default() {
        let body = payload(
            "tls.cert.expiring",
            "warning",
            "tls",
            json!({"days": 3}),
            10,
        );
        let keys: Vec<&str> = body
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(
            keys,
            ["code", "created_at", "id", "module", "params", "severity"]
        );
        assert_eq!(body["id"].as_str().unwrap().len(), 32);
    }
}
