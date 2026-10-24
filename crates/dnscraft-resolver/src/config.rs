//! Resolver configuration.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use dnscraft_proto::Name;

use crate::clock::{Clock, SystemClock};
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
    /// Time source.
    pub clock: Arc<dyn Clock>,
    /// Test hook: when a nameserver host name is in this map, its address is
    /// taken from here instead of glue/A lookups; exists because the testkit
    /// runs every server on 127.0.0.1 with distinct ports.
    ///
    /// For a glueless delegation the nested address lookup is still performed
    /// (so the glueless path is exercised); only its result is replaced by the
    /// mapped address.
    #[doc(hidden)]
    pub nameserver_addr_overrides: HashMap<Name, SocketAddr>,
    /// How long IPv6 name servers are deprioritised after an IPv6 send failed
    /// with network-unreachable.
    pub ipv6_cooldown: Duration,
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
            clock: Arc::new(SystemClock),
            nameserver_addr_overrides: HashMap::new(),
            ipv6_cooldown: Duration::from_secs(60),
        }
    }
}
