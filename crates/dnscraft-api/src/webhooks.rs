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

use crate::api::alerts_routes::collect_alerts;
use crate::api::config_routes::valid_id;
use crate::error::ControlApiError;
use crate::notifications::ring_client_builder_with;
use crate::server::AppState;
use crate::storage::Db;

/// Config snapshot section for notification channels.
pub(crate) const SECTION: &str = "notifications";
/// Event codes a channel may subscribe to: the alert ids of `GET /api/v1/alerts`.
pub(crate) const EVENT_CATALOG: [&str; 7] = [
    "tls.cert.revoked",
    "tls.cert.expired",
    "tls.cert.expiring",
    "tls.dyndns.stale",
    "filtering.list.update_failed",
    "cluster.master.unreachable",
    "cluster.node.offline",
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

/// `kv` key holding the webhook secret (sent as a bearer token) of one channel.
pub(crate) fn secret_key(channel_id: &str) -> String {
    format!("notifications.secret.{channel_id}")
}

/// `kv` key holding the full webhook URL of one channel. The URL may embed a
/// token, so it is a secret: write-only, never returned, never audited.
pub(crate) fn url_key(channel_id: &str) -> String {
    format!("notifications.url.{channel_id}")
}

/// The stored full URL of a channel, if any.
pub(crate) async fn channel_url(
    db: &Db,
    channel_id: &str,
) -> Result<Option<String>, ControlApiError> {
    db.kv_get(&url_key(channel_id)).await
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
            if !matches!(key.as_str(), "id" | "type" | "enabled" | "host" | "events") {
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
        let host = object
            .get("host")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid("channel host is required"))?;
        if !valid_host(host) {
            return Err(invalid("channel host must be a plain hostname"));
        }
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
    trust: &[Vec<u8>],
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
    let client = ring_client_builder_with(trust)
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

/// Alert-to-webhook cooldown: one attempt per channel and alert per hour.
const DISPATCH_COOLDOWN_SECS: i64 = 3600;
/// `kv` key of the dispatch ledger: `"<channel>:<alert>" -> last attempt (unix s)`.
const DISPATCH_LEDGER_KEY: &str = "notifications.dispatch";

/// Sends every active alert to each enabled channel subscribed to it, at most
/// once per channel and alert per cooldown. A cleared alert leaves the ledger, so
/// its recurrence is sent again. Failures are logged and count as an attempt.
/// Meant to be called periodically by the binary (WX7). Returns the number of
/// successful deliveries.
pub async fn dispatch_alerts(state: &AppState) -> Result<usize, ControlApiError> {
    let (Some(db), Some(service)) = (state.db(), state.config_service()) else {
        return Ok(0);
    };
    let snapshot = service.current().await?.1.unwrap_or(Value::Null);
    let section = snapshot.get(SECTION).cloned().unwrap_or(Value::Null);
    let channels: Vec<Value> = section
        .get("channels")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    if channels.is_empty() {
        return Ok(0);
    }
    let alerts = collect_alerts(state).await;
    let now = crate::system::unix_now(state);
    let mut ledger: serde_json::Map<String, Value> = db
        .kv_get(DISPATCH_LEDGER_KEY)
        .await?
        .and_then(|raw| serde_json::from_str(&raw).ok())
        .unwrap_or_default();
    let active: std::collections::BTreeSet<&str> = alerts
        .iter()
        .filter_map(|alert| alert["id"].as_str())
        .collect();
    ledger.retain(|key, _| {
        key.split_once(':')
            .is_some_and(|(_, alert)| active.contains(alert))
    });
    let allowed: Vec<String> = section
        .get("allowed_hosts")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|host| host.as_str().map(str::to_owned))
        .collect();
    let allow_private = section
        .get("allow_private_destinations")
        .and_then(Value::as_bool)
        .unwrap_or(false);

    let mut delivered = 0;
    for alert in &alerts {
        let Some(id) = alert["id"].as_str() else {
            continue;
        };
        for channel in &channels {
            let Some(channel_id) = channel["id"].as_str() else {
                continue;
            };
            if channel.get("enabled").and_then(Value::as_bool) == Some(false) {
                continue;
            }
            let subscribed = channel["events"]
                .as_array()
                .is_some_and(|events| events.iter().any(|event| event.as_str() == Some(id)));
            if !subscribed {
                continue;
            }
            let key = format!("{channel_id}:{id}");
            let cooling = ledger
                .get(&key)
                .and_then(Value::as_i64)
                .is_some_and(|last| now.saturating_sub(last) < DISPATCH_COOLDOWN_SECS);
            if cooling {
                continue;
            }
            ledger.insert(key, json!(now));
            let Some(raw_url) = channel_url(db, channel_id).await? else {
                tracing::warn!(channel = channel_id, "webhook has no stored url");
                continue;
            };
            let url = match parse_channel_url(&raw_url) {
                Ok(url) => url,
                Err(error) => {
                    tracing::warn!(
                        channel = channel_id,
                        code = error.code,
                        "stored webhook url is invalid"
                    );
                    continue;
                }
            };
            let secret = channel_secret(db, channel_id).await?;
            let body = payload(
                id,
                alert["severity"].as_str().unwrap_or("warning"),
                alert["module"].as_str().unwrap_or("system"),
                alert["params"].clone(),
                now,
            );
            match deliver(
                &url,
                &allowed,
                allow_private,
                secret.as_deref(),
                &body,
                state.webhook_trust_roots(),
            )
            .await
            {
                Ok(_) => delivered += 1,
                Err(error) => tracing::warn!(
                    channel = channel_id,
                    alert = id,
                    code = error.code,
                    "alert webhook delivery failed"
                ),
            }
        }
    }
    db.kv_set(DISPATCH_LEDGER_KEY, &Value::Object(ledger).to_string())
        .await?;
    Ok(delivered)
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
