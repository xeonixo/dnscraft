//! DynDNS: discover public IPs and upsert Cloudflare A/AAAA only on change.
//!
//! Failures return [`TlsError::DyndnsEcho`] / [`TlsError::DyndnsUpdate`] and
//! never touch the certificate store.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::{Duration, SystemTime};

use rand::{Rng, RngExt};
use reqwest::Client;
use tracing::debug;

use crate::cloudflare::CloudflareClient;
use crate::config::DynDnsConfig;
use crate::error::TlsError;

const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_ECHO_BYTES: usize = 64 * 1024;

/// Outcome of one [`dyndns_once`] pass.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DynDnsResult {
    /// Discovered IPv4, when requested and available.
    pub ipv4: Option<Ipv4Addr>,
    /// Discovered IPv6, when requested and available.
    pub ipv6: Option<Ipv6Addr>,
    /// Families that had no usable route (not an error).
    pub skipped_no_route: Vec<&'static str>,
    /// `true` when at least one Cloudflare write (POST/PUT) ran.
    pub changed: bool,
    /// Wall time of the last successful content change, if any this pass.
    pub last_change: Option<SystemTime>,
}

/// HTTP client pair for per-family public IP discovery.
///
/// Production uses sockets bound to `0.0.0.0` / `::` so each request forces
/// that family. Tests use [`EchoClient::unbound`] against a loopback mock.
#[derive(Clone, Debug)]
pub struct EchoClient {
    v4: Client,
    v6: Client,
}

impl EchoClient {
    /// Bound clients for production (IPv4 → `0.0.0.0`, IPv6 → `::`).
    pub fn new() -> Result<Self, TlsError> {
        Ok(Self {
            v4: build_client(Some(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))))?,
            v6: build_client(Some(SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0))))?,
        })
    }

    /// Unbound clients for loopback mocks (both families share one stack).
    pub fn unbound() -> Result<Self, TlsError> {
        let c = build_client(None)?;
        Ok(Self {
            v4: c.clone(),
            v6: c,
        })
    }

    /// Fetches `url` with the family-specific client and parses the `ip=` line.
    ///
    /// Returns `Ok(None)` when the family has no route (transport failure).
    /// Garbage body or wrong address family → [`TlsError::DyndnsEcho`].
    pub async fn discover(&self, url: &str, want_v4: bool) -> Result<Option<IpAddr>, TlsError> {
        let client = if want_v4 { &self.v4 } else { &self.v6 };
        let family = if want_v4 { "ipv4" } else { "ipv6" };

        let response = match client.get(url).send().await {
            Ok(r) => r,
            Err(e) => {
                debug!(family, error = %e, "DynDNS echo: no route / transport");
                return Ok(None);
            }
        };

        if !response.status().is_success() {
            return Err(TlsError::DyndnsEcho {
                message: format!("HTTP {} from echo ({family})", response.status()),
            });
        }

        let bytes = read_echo_body(response).await?;
        let body = String::from_utf8_lossy(&bytes);
        let ip = parse_trace_ip(&body).ok_or_else(|| TlsError::DyndnsEcho {
            message: format!("no ip= line in echo body ({family})"),
        })?;

        match (want_v4, ip) {
            (true, IpAddr::V4(v4)) => Ok(Some(IpAddr::V4(v4))),
            (false, IpAddr::V6(v6)) => Ok(Some(IpAddr::V6(v6))),
            (true, IpAddr::V6(_)) => Err(TlsError::DyndnsEcho {
                message: "echo returned IPv6 on IPv4 fetch".into(),
            }),
            (false, IpAddr::V4(_)) => Err(TlsError::DyndnsEcho {
                message: "echo returned IPv4 on IPv6 fetch".into(),
            }),
        }
    }
}

fn build_client(local: Option<SocketAddr>) -> Result<Client, TlsError> {
    let tls = crate::http_tls::client_config(&[]).map_err(|e| TlsError::DyndnsEcho {
        message: format!("build TLS config: {e}"),
    })?;
    let mut b = Client::builder()
        .use_preconfigured_tls(tls)
        .timeout(REQUEST_TIMEOUT)
        .connect_timeout(CONNECT_TIMEOUT);
    if let Some(addr) = local {
        b = b.local_address(addr.ip());
    }
    b.build().map_err(|e| TlsError::DyndnsEcho {
        message: format!("build HTTP client: {e}"),
    })
}

async fn read_echo_body(mut response: reqwest::Response) -> Result<Vec<u8>, TlsError> {
    if let Some(len) = response.content_length()
        && len > MAX_ECHO_BYTES as u64
    {
        return Err(TlsError::DyndnsEcho {
            message: format!("echo body {len} bytes exceeds {MAX_ECHO_BYTES} cap"),
        });
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|e| TlsError::DyndnsEcho {
        message: format!("read echo body: {e}"),
    })? {
        if body.len() + chunk.len() > MAX_ECHO_BYTES {
            return Err(TlsError::DyndnsEcho {
                message: format!("echo body exceeds {MAX_ECHO_BYTES} bytes"),
            });
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

/// Parses the `ip=` line from a Cloudflare `cdn-cgi/trace` body.
pub fn parse_trace_ip(body: &str) -> Option<IpAddr> {
    for line in body.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("ip=") {
            return rest.trim().parse().ok();
        }
    }
    None
}

/// Next DynDNS interval with ±10 % jitter (minimum 1 s).
pub fn dyndns_interval(base: Duration) -> Duration {
    dyndns_interval_with_rng(base, &mut rand::rng())
}

/// Like [`dyndns_interval`] with an injectable RNG.
pub fn dyndns_interval_with_rng(base: Duration, rng: &mut impl Rng) -> Duration {
    let secs = base.as_secs_f64().max(1.0);
    let jitter = secs * 0.1;
    let delta: f64 = rng.random_range(-jitter..=jitter);
    Duration::from_secs_f64((secs + delta).max(1.0))
}

/// Owner names this node maintains for DynDNS.
///
/// Always includes the node hostname. When `public_entry`, also
/// `*.dns.<public_domain>` and `dns.<public_domain>`.
pub fn dyndns_names(cfg: &DynDnsConfig, public_domain: &str) -> Vec<String> {
    let mut names = vec![cfg.hostname.clone()];
    if cfg.public_entry {
        names.push(format!("*.dns.{public_domain}"));
        names.push(format!("dns.{public_domain}"));
    }
    names
}

/// One DynDNS pass: echo → compare → upsert under the Cloudflare writer mutex.
///
/// Does not touch certificates. When `cfg.enabled` is false, returns
/// [`DynDnsResult::default`] without network I/O.
pub async fn dyndns_once(
    cfg: &DynDnsConfig,
    public_domain: &str,
    echo: &EchoClient,
    cloudflare: &CloudflareClient,
) -> Result<DynDnsResult, TlsError> {
    if !cfg.enabled {
        return Ok(DynDnsResult::default());
    }

    let mut result = DynDnsResult::default();

    if cfg.ipv4 {
        match echo.discover(&cfg.echo_url, true).await? {
            Some(IpAddr::V4(v4)) => result.ipv4 = Some(v4),
            Some(IpAddr::V6(_)) => unreachable!("discover validates family"),
            None => result.skipped_no_route.push("ipv4"),
        }
    }
    if cfg.ipv6 {
        match echo.discover(&cfg.echo_url, false).await? {
            Some(IpAddr::V6(v6)) => result.ipv6 = Some(v6),
            Some(IpAddr::V4(_)) => unreachable!("discover validates family"),
            None => result.skipped_no_route.push("ipv6"),
        }
    }

    if result.ipv4.is_none() && result.ipv6.is_none() {
        // All enabled families skipped (no route) — not an error.
        return Ok(result);
    }

    let names = dyndns_names(cfg, public_domain);
    let _guard = cloudflare.write_guard().await;

    for name in &names {
        if let Some(v4) = result.ipv4 {
            ensure_address(cloudflare, name, "A", &v4.to_string(), &mut result).await?;
        }
        if let Some(v6) = result.ipv6 {
            ensure_address(cloudflare, name, "AAAA", &v6.to_string(), &mut result).await?;
        }
    }

    Ok(result)
}

async fn ensure_address(
    cloudflare: &CloudflareClient,
    name: &str,
    record_type: &str,
    content: &str,
    result: &mut DynDnsResult,
) -> Result<(), TlsError> {
    let existing = cloudflare
        .list_records(name, record_type)
        .await
        .map_err(map_update_err)?;
    if existing.iter().any(|r| r.content == content) {
        return Ok(());
    }
    cloudflare
        .upsert_address(name, record_type, content)
        .await
        .map_err(map_update_err)?;
    result.changed = true;
    result.last_change = Some(SystemTime::now());
    Ok(())
}

fn map_update_err(err: TlsError) -> TlsError {
    match err {
        TlsError::CloudflareHttp { message, .. } | TlsError::CloudflareZone { message } => {
            TlsError::DyndnsUpdate { message }
        }
        other => other,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod unit {
    use super::*;
    use rand::SeedableRng;
    use rand::rngs::StdRng;

    #[test]
    fn parse_trace_ip_happy_and_garbage() {
        let body = "fl=1\nh=cloudflare.com\nip=203.0.113.10\nts=1\n";
        assert_eq!(
            parse_trace_ip(body),
            Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)))
        );
        let v6 = "ip=2001:db8::1\n";
        assert_eq!(
            parse_trace_ip(v6),
            Some(IpAddr::V6("2001:db8::1".parse().unwrap()))
        );
        assert_eq!(parse_trace_ip("nope\n"), None);
        assert_eq!(parse_trace_ip("ip=not-an-ip\n"), None);
    }

    #[test]
    fn names_respect_public_entry() {
        let mut cfg = DynDnsConfig {
            hostname: "node1.dns.example.com".into(),
            public_entry: false,
            ..DynDnsConfig::default()
        };
        assert_eq!(
            dyndns_names(&cfg, "example.com"),
            vec!["node1.dns.example.com".to_owned()]
        );
        cfg.public_entry = true;
        assert_eq!(
            dyndns_names(&cfg, "example.com"),
            vec![
                "node1.dns.example.com".to_owned(),
                "*.dns.example.com".to_owned(),
                "dns.example.com".to_owned(),
            ]
        );
    }

    #[test]
    fn interval_jitter_within_ten_percent() {
        let base = Duration::from_secs(300);
        let mut rng = StdRng::seed_from_u64(42);
        for _ in 0..50 {
            let d = dyndns_interval_with_rng(base, &mut rng);
            assert!(d.as_secs() >= 270 && d.as_secs() <= 330, "{d:?}");
        }
    }
}
