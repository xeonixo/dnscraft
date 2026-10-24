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
    /// Maximum number of referrals followed for one lookup (Task 5 moves the
    /// limits into `limits.rs`).
    pub max_referral_depth: u8,
    /// Maximum number of outgoing queries for one incoming question,
    /// including nested name server address lookups.
    pub max_queries_per_resolve: u32,
    /// Maximum nesting of name server address lookups.
    pub max_nested_depth: u8,
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
}

impl Default for ResolverConfig {
    fn default() -> Self {
        Self {
            root_hints: default_root_hints(),
            query_timeout: Duration::from_millis(1500),
            max_referral_depth: 16,
            max_queries_per_resolve: 64,
            max_nested_depth: 4,
            clock: Arc::new(SystemClock),
            nameserver_addr_overrides: HashMap::new(),
        }
    }
}
