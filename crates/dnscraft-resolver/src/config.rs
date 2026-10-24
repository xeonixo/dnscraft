//! Resolver configuration.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use dnscraft_proto::Name;

use crate::clock::{Clock, SystemClock};
use crate::dnssec::TrustAnchors;
use crate::hints::default_root_hints;

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
    /// Zones answered by forward targets — full forwarding arrives in Task 14;
    /// for now only used to exempt them from locally served zones.
    pub forward_zones: Vec<Name>,
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
            prefetch: true,
            nameserver_addr_overrides: HashMap::new(),
            cache_capacity_bytes: None,
            ipv6_cooldown: Duration::from_secs(60),
            forward_zones: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cache_defaults_match_the_spec() {
        let config = ResolverConfig::default();
        assert_eq!(config.cache_size_mb, 64);
        assert_eq!(config.ttl_min, 0);
        assert_eq!(config.ttl_max, 86_400);
        assert!(config.prefetch);
        assert_eq!(config.cache_capacity_bytes, None);
    }
}
