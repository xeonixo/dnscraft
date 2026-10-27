//! Listener configuration values (no TOML parsing — the binary does that later).

use std::collections::HashSet;
use std::net::SocketAddr;
use std::time::Duration;

use dnscraft_policy::ListenerId;
use serde::{Deserialize, Serialize};

use crate::error::ListenersError;

/// Default EDNS UDP payload size (DNS Flag Day 2020).
pub const DEFAULT_UDP_PAYLOAD_MAX: u16 = 1232;
/// Default per-query deadline.
pub const DEFAULT_QUERY_TIMEOUT: Duration = Duration::from_secs(10);
/// Default TCP/DoT idle timeout.
pub const DEFAULT_TCP_IDLE_TIMEOUT: Duration = Duration::from_secs(10);
/// Default TLS handshake timeout.
pub const DEFAULT_TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
/// Default in-flight queries per listener.
pub const DEFAULT_MAX_INFLIGHT: u32 = 4096;
/// Default concurrent connections per listener.
pub const DEFAULT_MAX_CONNECTIONS: u32 = 1024;
/// Default concurrent connections per source IP.
pub const DEFAULT_MAX_CONNECTIONS_PER_SOURCE: u32 = 32;
/// Default QUIC bidirectional streams per connection.
pub const DEFAULT_MAX_QUIC_STREAMS: u32 = 64;
/// Default max concurrent in-flight queries per TCP/DoT connection.
pub const DEFAULT_MAX_QUERIES_PER_CONNECTION: u32 = 64;
/// Default ban strikes before a temporary ban.
pub const DEFAULT_BAN_STRIKES: u32 = 5;
/// Default window in which ban strikes accumulate.
pub const DEFAULT_BAN_WINDOW: Duration = Duration::from_secs(60);
/// Default ban duration after the strike threshold.
pub const DEFAULT_BAN_DURATION: Duration = Duration::from_secs(15 * 60);
/// Default LRU cap for rate/ban tables.
pub const DEFAULT_MAX_TRACKED_SOURCES: u32 = 100_000;

/// Transport protocol of one listener.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]

pub enum Protocol {
    /// Plain DNS over UDP (port 53 by convention).
    Udp53,
    /// Plain DNS over TCP (port 53 by convention).
    Tcp53,
    /// DNS over TLS.
    Dot,
    /// DNS over HTTPS (HTTP/2 + HTTP/1.1; HTTP/3 when [`ListenerConfig::h3`]).
    Doh,
    /// DNS over QUIC.
    Doq,
}

impl Protocol {
    /// Wire / config name (`udp53`, `tcp53`, `dot`, `doh`, `doq`).
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Udp53 => "udp53",
            Self::Tcp53 => "tcp53",
            Self::Dot => "dot",
            Self::Doh => "doh",
            Self::Doq => "doq",
        }
    }

    /// Whether this protocol may be exposed as [`Exposure::Public`].
    pub fn allows_public(self) -> bool {
        matches!(self, Self::Dot | Self::Doh | Self::Doq)
    }
}

/// Who may use the listener.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]

pub enum Exposure {
    /// Private / local sources only (default).
    #[default]
    Local,
    /// Also reachable from public sources (encrypted protocols only).
    Public,
}

/// TLS protocol / cipher policy for an encrypted listener.
///
/// Applied when building the rustls `ServerConfig`. `alpn` configures DoH over
/// TCP only; DoT and DoQ keep their protocol-mandated ALPN (`dot`, `doq`, `h3`).
/// Ring is the only provider (no aws-lc).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TlsPolicy {
    /// Minimum TLS version: `"1.2"` (default) or `"1.3"`.
    pub min_version: String,
    /// Allowed rustls/ring cipher suites (IANA names); `None` = provider defaults.
    pub ciphersuites: Option<Vec<String>>,
    /// ALPN for DoH over TCP; default `["h2", "http/1.1"]`.
    pub alpn: Vec<String>,
}

/// Default minimum TLS version for TCP listeners.
pub const DEFAULT_TLS_MIN_VERSION: &str = "1.2";
/// Default ALPN for DoH over TCP.
pub const DEFAULT_TLS_ALPN: [&str; 2] = ["h2", "http/1.1"];

impl Default for TlsPolicy {
    fn default() -> Self {
        Self {
            min_version: DEFAULT_TLS_MIN_VERSION.to_owned(),
            ciphersuites: None,
            alpn: DEFAULT_TLS_ALPN.iter().map(|s| (*s).to_owned()).collect(),
        }
    }
}

/// One listener entry.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListenerConfig {
    /// Unique id (`[a-z0-9-]{1,64}`), passed to policy as `listener_id`.
    pub id: ListenerId,
    /// Transport protocol.
    pub protocol: Protocol,
    /// Bind address (concrete or wildcard).
    pub address: SocketAddr,
    /// Local vs public exposure.
    pub exposure: Exposure,
    /// When `protocol == Doh`, also serve HTTP/3 on UDP of the same port.
    pub h3: bool,
    /// Optional TLS policy; absent = defaults. Rejected on plaintext protocols.
    pub tls_policy: Option<TlsPolicy>,
}

/// Token-bucket rate: `N` tokens per second, burst capacity `2N` when parsed from `N/s`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenRate {
    /// Tokens replenished per second.
    pub per_second: u32,
    /// Maximum burst size.
    pub burst: u32,
}

impl TokenRate {
    /// Parses `"N/s"` (N > 0). Burst defaults to `2 * N`.
    pub fn parse(s: &str) -> Result<Self, ListenersError> {
        let s = s.trim();
        let Some(num) = s.strip_suffix("/s") else {
            return Err(ListenersError::config(format!(
                "rate must look like `N/s`, got `{s}`"
            )));
        };
        let per_second: u32 = num
            .parse()
            .map_err(|_| ListenersError::config(format!("rate numerator is not a u32: `{num}`")))?;
        if per_second == 0 {
            return Err(ListenersError::config("rate must be > 0"));
        }
        Ok(Self {
            per_second,
            burst: per_second.saturating_mul(2),
        })
    }
}

/// Resource and timing limits shared by all listeners.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Limits {
    /// EDNS UDP payload maximum advertised and enforced.
    pub udp_payload_max: u16,
    /// Per-query deadline.
    #[serde(with = "dnscraft_common::duration::serde")]
    pub query_timeout: Duration,
    /// TCP / DoT idle timeout.
    #[serde(with = "dnscraft_common::duration::serde")]
    pub tcp_idle_timeout: Duration,
    /// TLS handshake timeout.
    #[serde(with = "dnscraft_common::duration::serde")]
    pub tls_handshake_timeout: Duration,
    /// Max concurrent in-flight queries per listener.
    pub max_inflight_per_listener: u32,
    /// Max concurrent connections per listener.
    pub max_connections_per_listener: u32,
    /// Max concurrent connections per source IP.
    pub max_connections_per_source: u32,
    /// Max QUIC bidirectional streams per connection.
    pub max_quic_streams_per_connection: u32,
    /// Max concurrent in-flight queries per TCP/DoT connection (backpressure).
    pub max_queries_per_connection: u32,
    /// Token bucket per source IP (all sources).
    pub rate_per_source: TokenRate,
    /// Token bucket per Client ID (public sources).
    pub rate_per_client_id: TokenRate,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            udp_payload_max: DEFAULT_UDP_PAYLOAD_MAX,
            query_timeout: DEFAULT_QUERY_TIMEOUT,
            tcp_idle_timeout: DEFAULT_TCP_IDLE_TIMEOUT,
            tls_handshake_timeout: DEFAULT_TLS_HANDSHAKE_TIMEOUT,
            max_inflight_per_listener: DEFAULT_MAX_INFLIGHT,
            max_connections_per_listener: DEFAULT_MAX_CONNECTIONS,
            max_connections_per_source: DEFAULT_MAX_CONNECTIONS_PER_SOURCE,
            max_quic_streams_per_connection: DEFAULT_MAX_QUIC_STREAMS,
            max_queries_per_connection: DEFAULT_MAX_QUERIES_PER_CONNECTION,
            rate_per_source: TokenRate {
                per_second: 200,
                burst: 400,
            },
            rate_per_client_id: TokenRate {
                per_second: 50,
                burst: 100,
            },
        }
    }
}

impl Limits {
    /// True when any field that a running listener's transport/limits read changed.
    ///
    /// Destructures [`Limits`] exhaustively (no `..`): adding a field fails to
    /// compile until it is classified here as listener-affecting or, in
    /// [`Self::admission_limits_changed`], as admission-only. The two admission
    /// rate limits are deliberately ignored here — they only feed
    /// [`crate::admission::Admission`], so changing them must not restart listeners.
    pub fn listener_limits_changed(&self, old: &Limits) -> bool {
        let Limits {
            udp_payload_max,
            query_timeout,
            tcp_idle_timeout,
            tls_handshake_timeout,
            max_inflight_per_listener,
            max_connections_per_listener,
            max_connections_per_source,
            max_quic_streams_per_connection,
            max_queries_per_connection,
            rate_per_source: _,
            rate_per_client_id: _,
        } = self;
        let Limits {
            udp_payload_max: old_udp_payload_max,
            query_timeout: old_query_timeout,
            tcp_idle_timeout: old_tcp_idle_timeout,
            tls_handshake_timeout: old_tls_handshake_timeout,
            max_inflight_per_listener: old_max_inflight_per_listener,
            max_connections_per_listener: old_max_connections_per_listener,
            max_connections_per_source: old_max_connections_per_source,
            max_quic_streams_per_connection: old_max_quic_streams_per_connection,
            max_queries_per_connection: old_max_queries_per_connection,
            rate_per_source: _,
            rate_per_client_id: _,
        } = old;
        udp_payload_max != old_udp_payload_max
            || query_timeout != old_query_timeout
            || tcp_idle_timeout != old_tcp_idle_timeout
            || tls_handshake_timeout != old_tls_handshake_timeout
            || max_inflight_per_listener != old_max_inflight_per_listener
            || max_connections_per_listener != old_max_connections_per_listener
            || max_connections_per_source != old_max_connections_per_source
            || max_quic_streams_per_connection != old_max_quic_streams_per_connection
            || max_queries_per_connection != old_max_queries_per_connection
    }

    /// True when either admission rate limit changed.
    ///
    /// Mirrors [`Self::listener_limits_changed`]'s exhaustive destructure so a
    /// new [`Limits`] field is unclassified (fails to compile) until listed here.
    pub fn admission_limits_changed(&self, old: &Limits) -> bool {
        let Limits {
            rate_per_source,
            rate_per_client_id,
            udp_payload_max: _,
            query_timeout: _,
            tcp_idle_timeout: _,
            tls_handshake_timeout: _,
            max_inflight_per_listener: _,
            max_connections_per_listener: _,
            max_connections_per_source: _,
            max_quic_streams_per_connection: _,
            max_queries_per_connection: _,
        } = self;
        let Limits {
            rate_per_source: old_rate_per_source,
            rate_per_client_id: old_rate_per_client_id,
            udp_payload_max: _,
            query_timeout: _,
            tcp_idle_timeout: _,
            tls_handshake_timeout: _,
            max_inflight_per_listener: _,
            max_connections_per_listener: _,
            max_connections_per_source: _,
            max_quic_streams_per_connection: _,
            max_queries_per_connection: _,
        } = old;
        rate_per_source != old_rate_per_source || rate_per_client_id != old_rate_per_client_id
    }
}

/// Per-node public DoH/DoT/DoQ settings (off by default).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicConfig {
    /// When false, no listener may use [`Exposure::Public`].
    pub enabled: bool,
    /// Strikes within [`Self::ban_window`] before a ban.
    pub ban_strikes: u32,
    /// Sliding window for ban strikes.
    #[serde(with = "dnscraft_common::duration::serde")]
    pub ban_window: Duration,
    /// How long a ban lasts.
    #[serde(with = "dnscraft_common::duration::serde")]
    pub ban_duration: Duration,
    /// LRU cap for rate buckets and the ban table.
    pub max_tracked_sources: u32,
}

impl Default for PublicConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            ban_strikes: DEFAULT_BAN_STRIKES,
            ban_window: DEFAULT_BAN_WINDOW,
            ban_duration: DEFAULT_BAN_DURATION,
            max_tracked_sources: DEFAULT_MAX_TRACKED_SOURCES,
        }
    }
}

/// DDR (`_dns.resolver.arpa`) settings.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DdrConfig {
    /// When false, DDR queries fall through to policy.
    pub enabled: bool,
    /// Target label (`dns` → `dns.<public_domain>`, or a node hostname label).
    pub target: String,
}

impl Default for DdrConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            target: "dns".into(),
        }
    }
}

/// Full listeners configuration.
#[derive(Clone, Debug, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ListenersConfig {
    /// Configured listeners.
    pub listeners: Vec<ListenerConfig>,
    /// Shared limits.
    pub limits: Limits,
    /// Public exposure settings.
    pub public: PublicConfig,
    /// DDR discovery.
    pub ddr: DdrConfig,
}

/// Underlying socket kind used for bind-conflict detection.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum SocketKind {
    Udp,
    Tcp,
}

fn socket_kinds(protocol: Protocol, h3: bool) -> &'static [SocketKind] {
    match protocol {
        Protocol::Udp53 | Protocol::Doq => &[SocketKind::Udp],
        Protocol::Tcp53 | Protocol::Dot => &[SocketKind::Tcp],
        Protocol::Doh if h3 => &[SocketKind::Tcp, SocketKind::Udp],
        Protocol::Doh => &[SocketKind::Tcp],
    }
}

impl ListenersConfig {
    /// Validates ids, exposure rules, bind conflicts, limits and rates.
    pub fn validate(&self) -> Result<(), ListenersError> {
        let mut ids = HashSet::new();
        let mut binds: HashSet<(SocketKind, SocketAddr)> = HashSet::new();

        for listener in &self.listeners {
            let id = listener.id.as_str();
            if !ids.insert(id.to_owned()) {
                return Err(ListenersError::ConfigDuplicateId { id: id.to_owned() });
            }

            if listener.exposure == Exposure::Public {
                if !listener.protocol.allows_public() {
                    return Err(ListenersError::ConfigPublicPlaintext {
                        protocol: listener.protocol.as_str().to_owned(),
                    });
                }
                if !self.public.enabled {
                    return Err(ListenersError::config(
                        "public listeners require listeners_public.enabled = true",
                    ));
                }
            }

            if listener.h3 && listener.protocol != Protocol::Doh {
                return Err(ListenersError::config(
                    "h3 = true is only allowed on protocol = doh",
                ));
            }

            if let Some(policy) = &listener.tls_policy {
                if !matches!(
                    listener.protocol,
                    Protocol::Dot | Protocol::Doh | Protocol::Doq
                ) {
                    return Err(ListenersError::TlsPolicy {
                        reason: format!(
                            "tls_policy is only allowed on dot, doh or doq, got {}",
                            listener.protocol.as_str()
                        ),
                    });
                }
                crate::tls::validate_tls_policy(policy, listener.protocol, listener.h3)?;
            }

            for &kind in socket_kinds(listener.protocol, listener.h3) {
                if !binds.insert((kind, listener.address)) {
                    return Err(ListenersError::config(format!(
                        "duplicate bind: {:?} {} ({})",
                        kind,
                        listener.address,
                        listener.protocol.as_str()
                    )));
                }
            }
        }

        validate_limits(&self.limits)?;
        validate_public(&self.public)?;

        if self.ddr.target.is_empty() {
            return Err(ListenersError::config("ddr.target must not be empty"));
        }

        Ok(())
    }
}

fn validate_limits(limits: &Limits) -> Result<(), ListenersError> {
    if limits.udp_payload_max == 0 {
        return Err(ListenersError::config("udp_payload_max must be > 0"));
    }
    if limits.query_timeout.is_zero() {
        return Err(ListenersError::config("query_timeout must be > 0"));
    }
    if limits.tcp_idle_timeout.is_zero() {
        return Err(ListenersError::config("tcp_idle_timeout must be > 0"));
    }
    if limits.tls_handshake_timeout.is_zero() {
        return Err(ListenersError::config("tls_handshake_timeout must be > 0"));
    }
    if limits.max_inflight_per_listener == 0 {
        return Err(ListenersError::config(
            "max_inflight_per_listener must be > 0",
        ));
    }
    if limits.max_connections_per_listener == 0 {
        return Err(ListenersError::config(
            "max_connections_per_listener must be > 0",
        ));
    }
    if limits.max_connections_per_source == 0 {
        return Err(ListenersError::config(
            "max_connections_per_source must be > 0",
        ));
    }
    if limits.max_quic_streams_per_connection == 0 {
        return Err(ListenersError::config(
            "max_quic_streams_per_connection must be > 0",
        ));
    }
    if limits.max_queries_per_connection == 0 {
        return Err(ListenersError::config(
            "max_queries_per_connection must be > 0",
        ));
    }
    if limits.rate_per_source.per_second == 0 || limits.rate_per_source.burst == 0 {
        return Err(ListenersError::config("rate_per_source must be > 0"));
    }
    if limits.rate_per_client_id.per_second == 0 || limits.rate_per_client_id.burst == 0 {
        return Err(ListenersError::config("rate_per_client_id must be > 0"));
    }
    Ok(())
}

fn validate_public(public: &PublicConfig) -> Result<(), ListenersError> {
    if public.ban_strikes == 0 {
        return Err(ListenersError::config("ban_strikes must be > 0"));
    }
    if public.ban_window.is_zero() {
        return Err(ListenersError::config("ban_window must be > 0"));
    }
    if public.ban_duration.is_zero() {
        return Err(ListenersError::config("ban_duration must be > 0"));
    }
    if public.max_tracked_sources == 0 {
        return Err(ListenersError::config("max_tracked_sources must be > 0"));
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use super::*;

    #[test]
    fn config_round_trips_through_json() {
        let cfg = ListenersConfig {
            listeners: vec![
                ListenerConfig {
                    id: ListenerId::new("lan-udp").unwrap(),
                    protocol: Protocol::Udp53,
                    address: SocketAddr::from((Ipv4Addr::UNSPECIFIED, 53)),
                    exposure: Exposure::Local,
                    h3: false,
                    tls_policy: None,
                },
                ListenerConfig {
                    id: ListenerId::new("public-doh").unwrap(),
                    protocol: Protocol::Doh,
                    address: SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), 443),
                    exposure: Exposure::Public,
                    h3: true,
                    tls_policy: Some(TlsPolicy {
                        min_version: "1.3".to_owned(),
                        ciphersuites: Some(vec!["TLS_AES_128_GCM_SHA256".to_owned()]),
                        alpn: vec!["h2".to_owned(), "http/1.1".to_owned()],
                    }),
                },
            ],
            limits: Limits {
                query_timeout: Duration::from_secs(5),
                rate_per_source: TokenRate {
                    per_second: 100,
                    burst: 200,
                },
                ..Limits::default()
            },
            public: PublicConfig {
                enabled: true,
                ban_strikes: 3,
                ban_window: Duration::from_secs(30),
                ban_duration: Duration::from_secs(600),
                max_tracked_sources: 10_000,
            },
            ddr: DdrConfig {
                enabled: true,
                target: "dns".to_owned(),
            },
        };

        let json = serde_json::to_string(&cfg).unwrap();
        assert!(json.contains("\"query_timeout\":\"5s\""), "{json}");
        assert!(json.contains("\"ban_window\":\"30s\""), "{json}");
        assert!(json.contains("\"ban_duration\":\"10m\""), "{json}");
        let decoded: ListenersConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, cfg);
    }

    #[test]
    fn duration_fields_parse_human_strings() {
        let mut value = serde_json::to_value(Limits::default()).unwrap();
        value["query_timeout"] = "1d".into();
        value["tls_handshake_timeout"] = "90s".into();
        let limits: Limits = serde_json::from_value(value.clone()).unwrap();
        assert_eq!(limits.query_timeout, Duration::from_secs(86_400));
        assert_eq!(limits.tls_handshake_timeout, Duration::from_secs(90));
        value["query_timeout"] = "1x".into();
        assert!(serde_json::from_value::<Limits>(value).is_err());

        let mut value = serde_json::to_value(PublicConfig::default()).unwrap();
        value["ban_window"] = "1d".into();
        value["ban_duration"] = "90s".into();
        let public: PublicConfig = serde_json::from_value(value.clone()).unwrap();
        assert_eq!(public.ban_window, Duration::from_secs(86_400));
        assert_eq!(public.ban_duration, Duration::from_secs(90));
        value["ban_window"] = "1x".into();
        assert!(serde_json::from_value::<PublicConfig>(value).is_err());
    }
}
