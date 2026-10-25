//! Resolver configuration.

use std::collections::HashMap;
use std::fmt;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use dnscraft_proto::Name;

use crate::clock::{Clock, SystemClock};
use crate::dnssec::TrustAnchors;
use crate::error::ForwardZoneIdError;
use crate::hints::default_root_hints;

const MAX_FORWARD_ZONE_ID: usize = 64;

/// Identifier of a [`ForwardZone`].
///
/// Matches `[a-z0-9-]{1,64}`. [`Resolver::new`](crate::Resolver::new) rejects
/// two zones that share an id.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub struct ForwardZoneId(Arc<str>);

impl ForwardZoneId {
    /// Validates `s` (`[a-z0-9-]{1,64}`) and wraps it.
    pub fn new(s: &str) -> Result<Self, ForwardZoneIdError> {
        if s.is_empty() {
            return Err(ForwardZoneIdError::Empty);
        }
        if s.len() > MAX_FORWARD_ZONE_ID {
            return Err(ForwardZoneIdError::TooLong { len: s.len() });
        }
        if let Some(ch) = s
            .chars()
            .find(|c| !(c.is_ascii_lowercase() || c.is_ascii_digit() || *c == '-'))
        {
            return Err(ForwardZoneIdError::InvalidChar { ch });
        }
        Ok(Self(Arc::from(s)))
    }

    /// The id as text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ForwardZoneId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for ForwardZoneId {
    type Err = ForwardZoneIdError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s)
    }
}

/// Configuration of a [`Resolver`](crate::Resolver).
#[derive(Clone, Debug)]
pub struct ResolverConfig {
    /// Root server addresses used for priming and as fallback.
    pub root_hints: Vec<SocketAddr>,
    /// How long to wait for one answer from one server.
    pub query_timeout: Duration,
    /// Maximum number of referrals followed for one lookup.
    pub max_referral_depth: u8,
    /// Maximum number of outgoing queries for one incoming question,
    /// including nested name server address lookups.
    pub max_queries_per_resolve: u32,
    /// Maximum nesting of name server address lookups.
    pub max_nested_depth: u8,
    /// Maximum number of CNAME/DNAME links followed for one question.
    pub max_cname_chain: u8,
    /// QNAME minimisation (RFC 9156): send each server only the labels it
    /// needs. Default on; when off the full QNAME/QTYPE goes to every server.
    pub qname_minimisation: bool,
    /// DNSSEC trust anchors. An empty set switches validation off: every
    /// answer is then `Indeterminate`.
    pub trust_anchors: TrustAnchors,
    /// Negative trust anchors (RFC 7646): names at or below one of these
    /// domains are resolved without DNSSEC validation (status `Insecure`,
    /// no AD bit, no SERVFAIL for bogus data). Default empty.
    pub negative_trust_anchors: Vec<Name>,
    /// Time source.
    pub clock: Arc<dyn Clock>,
    /// Answer-cache limit in mebibytes (1024×1024 bytes). `0` stores nothing.
    /// Default: 64.
    pub cache_size_mb: u64,
    /// Lowest TTL kept in the cache, in seconds. Shorter TTLs are raised to
    /// this before the entry is stored. Default: 0.
    pub ttl_min: u32,
    /// Highest TTL kept in the cache, in seconds. Longer TTLs are lowered to
    /// this. Default: 86400 (one day).
    pub ttl_max: u32,
    /// How long after an entry expires it may still be served when no
    /// authoritative server can be reached (RFC 8767). [`Duration::ZERO`]
    /// disables serve-stale. Default: one day.
    pub serve_stale: Duration,
    /// Refresh popular cache entries shortly before they expire, without
    /// making the client wait. Default on.
    pub prefetch: bool,
    /// Test hook: when a nameserver host name is in this map, its address is
    /// taken from here instead of glue/A lookups; exists because the testkit
    /// runs every server on 127.0.0.1 with distinct ports.
    ///
    /// For a glueless delegation the nested address lookup is still performed
    /// (so the glueless path is exercised); only its result is replaced by the
    /// mapped address.
    #[doc(hidden)]
    pub nameserver_addr_overrides: HashMap<Name, SocketAddr>,
    /// Test hook: exact cache budget in bytes. When set, replaces
    /// [`Self::cache_size_mb`].
    #[doc(hidden)]
    pub cache_capacity_bytes: Option<u64>,
    /// How long IPv6 name servers are deprioritised after an IPv6 send failed
    /// with network-unreachable.
    pub ipv6_cooldown: Duration,
    /// Zones answered by stub forwarders instead of iterative resolution.
    ///
    /// Empty by default. A name is forwarded to the most specific zone that
    /// covers it. See [`ForwardZone`].
    pub forward_zones: Vec<ForwardZone>,
    /// Upper bound on upstream resolutions running at the same time.
    /// Cache hits do not count and never wait. A miss that cannot get a slot
    /// within [`Self::query_timeout`] fails with
    /// [`ResolveError::Overloaded`](crate::ResolveError::Overloaded)
    /// (`resolver.overloaded`). Prefetch only runs when a slot is free.
    /// Must be at least 1. Default: 1024.
    pub max_concurrent_resolutions: usize,
    /// Accept private-use addresses (RFC 1918, carrier-grade NAT
    /// 100.64.0.0/10, unique local fc00::/7) for name servers learned from the
    /// network (glue and address lookups of NS hosts). Default `false`: such
    /// an address in a public delegation is an attempt to make the resolver
    /// query internal hosts. Loopback, unspecified, link-local, multicast,
    /// broadcast/reserved and IPv4-mapped/compatible addresses are never
    /// accepted. Operator-configured addresses (root hints, forward targets)
    /// are not filtered.
    pub allow_private_nameservers: bool,
    /// How often the root server set is refreshed by priming again
    /// (RFC 8109), checked when a resolution starts. [`Duration::ZERO`]
    /// primes only once at start-up. Default: 24 hours.
    pub root_reprime_interval: Duration,
    /// Upper bound on the time of one upstream resolution (everything from
    /// the first query to the final answer, including nested lookups and
    /// validation). On expiry the question fails like an unreachable zone
    /// (SERVFAIL; serve-stale may apply). Must be greater than zero.
    /// Default: 10 seconds.
    pub resolve_deadline: Duration,
}

/// A zone whose queries are sent to recursive targets (stub forwarding).
///
/// Queries for [`Self::zone`] and names below it go to [`Self::targets`] with
/// the recursion-desired bit set, in smoothed-RTT order. A target that does
/// not answer is skipped and the next one is tried.
///
/// [`Self::validate`] should stay `false` unless the zone is signed and a
/// trust anchor for it is configured: `false` is an implicit negative trust
/// anchor (status `Insecure`, no AD bit, records not checked). `true`
/// validates positive RRsets against that zone's DNSKEY, fetched from the
/// same targets.
///
/// A target that answers SERVFAIL, REFUSED, FORMERR or NOTIMP counts as
/// failed like one that does not answer, and the next target is tried. Only
/// NOERROR and NXDOMAIN are accepted from the first target that gives them.
/// If every target fails with an error rcode, the last such response is
/// passed on.
///
/// Loop protection needs [`RequestFlags::client`](crate::RequestFlags::client)
/// to be the real peer address of the client. A loop that crosses NAT (the
/// peer address seen here is not a configured target) is not detected by
/// address; it ends at `query_timeout`, so it is bounded but slow.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ForwardZone {
    /// Stable id (`[a-z0-9-]{1,64}`). Unique among the configured zones.
    ///
    /// Profiles name this id in [`RequestFlags::forward_zones`](crate::RequestFlags::forward_zones).
    /// The cache and in-flight keys use it as the forward route.
    pub id: ForwardZoneId,
    /// Apex of the forwarded zone.
    pub zone: Name,
    /// Recursive servers that answer this zone.
    pub targets: Vec<SocketAddr>,
    /// When `false`, do not validate (implicit negative trust anchor).
    /// When `true`, validate against a trust anchor for [`Self::zone`].
    pub validate: bool,
}

impl Default for ResolverConfig {
    fn default() -> Self {
        Self {
            root_hints: default_root_hints(),
            query_timeout: Duration::from_millis(1500),
            max_referral_depth: 16,
            max_queries_per_resolve: 64,
            max_nested_depth: 4,
            max_cname_chain: 16,
            qname_minimisation: true,
            trust_anchors: TrustAnchors::iana_root(),
            negative_trust_anchors: Vec::new(),
            clock: Arc::new(SystemClock),
            cache_size_mb: 64,
            ttl_min: 0,
            ttl_max: 86_400,
            serve_stale: Duration::from_secs(86_400),
            prefetch: true,
            nameserver_addr_overrides: HashMap::new(),
            cache_capacity_bytes: None,
            ipv6_cooldown: Duration::from_secs(60),
            forward_zones: Vec::new(),
            max_concurrent_resolutions: 1024,
            allow_private_nameservers: false,
            root_reprime_interval: Duration::from_secs(24 * 3600),
            resolve_deadline: Duration::from_secs(10),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn cache_defaults_match_the_spec() {
        let config = ResolverConfig::default();
        assert_eq!(config.cache_size_mb, 64);
        assert_eq!(config.ttl_min, 0);
        assert_eq!(config.ttl_max, 86_400);
        assert_eq!(config.serve_stale, Duration::from_secs(86_400));
        assert!(config.prefetch);
        assert_eq!(config.cache_capacity_bytes, None);
        assert_eq!(config.max_concurrent_resolutions, 1024);
        assert!(!config.allow_private_nameservers);
        assert_eq!(config.root_reprime_interval, Duration::from_secs(86_400));
        assert_eq!(config.resolve_deadline, Duration::from_secs(10));
    }

    #[test]
    fn forward_zone_id_accepts_the_list_charset() {
        assert_eq!(
            ForwardZoneId::new("vpn-site-1").unwrap().as_str(),
            "vpn-site-1"
        );
        assert_eq!("x".parse::<ForwardZoneId>().unwrap().to_string(), "x");
        assert!(ForwardZoneId::new(&"a".repeat(64)).is_ok());
    }

    #[test]
    fn forward_zone_id_rejects_empty_long_and_other_characters() {
        assert_eq!(
            ForwardZoneId::new("").unwrap_err().code(),
            "resolver.forward_zone.empty"
        );
        assert_eq!(
            ForwardZoneId::new(&"a".repeat(65)).unwrap_err().code(),
            "resolver.forward_zone.too_long"
        );
        for bad in ["Upper", "under_score", "sp ace", "dot.ted", "ü"] {
            assert_eq!(
                ForwardZoneId::new(bad).unwrap_err().code(),
                "resolver.forward_zone.invalid_char",
                "{bad}"
            );
        }
    }
}
