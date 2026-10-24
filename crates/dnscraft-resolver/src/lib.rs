//! Recursive, DNSSEC-validating DNS resolver with cache for DNScraft.
//!
//! Module layout (later tasks plug in here):
//! - `iterate`: iterative resolution and referral following (Tasks 5, 7 extend it:
//!   CNAME chains, limits, QNAME minimisation).
//! - `transport`: single UDP exchange with response matching (Task 6: TCP, retries,
//!   server selection).
//! - `priming`: root priming (RFC 8109).
//! - `clock`: injectable time for the cache and DNSSEC (Tasks 9, 11).

mod clock;
mod config;
pub mod dnssec;
mod error;
mod hints;
mod iterate;
mod limits;
mod priming;
mod server_selection;
mod transport;
mod types;

use std::net::SocketAddr;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

pub use clock::{Clock, ManualClock, SystemClock};
pub use config::ResolverConfig;
pub use error::{ResolveError, ResolverError};
pub use hints::default_root_hints;
pub use types::{
    Answer, AnswerSource, DnssecStatus, ExtendedError, FlushScope, PrimingStatus, Query,
    RequestFlags, ResolverStats,
};

/// A recursive resolver.
#[derive(Debug)]
pub struct Resolver {
    config: ResolverConfig,
    roots: Mutex<Vec<SocketAddr>>,
    priming: Mutex<PrimingStatus>,
    resolutions: AtomicU64,
    outgoing: AtomicU64,
}

impl Resolver {
    /// Creates a resolver and primes the root server set (RFC 8109).
    ///
    /// Priming failure is not an error: the built-in hints are used instead
    /// (see [`Resolver::priming_status`]).
    pub async fn new(config: ResolverConfig) -> Result<Self, ResolverError> {
        if config.root_hints.is_empty() {
            return Err(ResolverError::NoRootHints);
        }
        if config.query_timeout.is_zero() {
            return Err(ResolverError::InvalidConfig {
                reason: "query_timeout must be greater than zero",
            });
        }
        let outgoing = AtomicU64::new(0);
        let (roots, status) = {
            let ctx = iterate::Context::new(&config, &config.root_hints, &outgoing);
            priming::prime(&ctx).await
        };
        Ok(Self {
            config,
            roots: Mutex::new(roots),
            priming: Mutex::new(status),
            resolutions: AtomicU64::new(0),
            outgoing,
        })
    }

    /// Resolves `query` by iterating from the root servers.
    pub async fn resolve(
        &self,
        query: &Query,
        flags: RequestFlags,
    ) -> Result<Answer, ResolveError> {
        self.resolutions.fetch_add(1, Ordering::Relaxed);
        let roots = lock(&self.roots).clone();
        let ctx = iterate::Context::new(&self.config, &roots, &self.outgoing);
        tracing::debug!(
            qname = %query.name,
            qtype = %query.qtype,
            cd = flags.checking_disabled,
            do_bit = flags.dnssec_ok,
            "resolving"
        );
        let outcome =
            iterate::resolve_iterative(&ctx, &query.name, query.qtype, 0, Vec::new()).await?;
        tracing::debug!(qname = %query.name, zone = %outcome.zone, "resolved");
        let mut message = outcome.message;
        message.header.aa = false;
        message.header.ra = true;
        message.edns = None;
        Ok(Answer {
            message,
            dnssec: DnssecStatus::Indeterminate,
            source: AnswerSource::Recursion,
            ede: None,
        })
    }

    /// Removes cached data. Implemented in Task 11 (there is no cache yet).
    pub fn flush(&self, scope: FlushScope) {
        tracing::debug!(?scope, "flush requested; no cache yet");
    }

    /// Counters. Extended in Task 16.
    pub fn stats(&self) -> ResolverStats {
        ResolverStats {
            resolutions: self.resolutions.load(Ordering::Relaxed),
            outgoing_queries: self.outgoing.load(Ordering::Relaxed),
        }
    }

    /// Outcome of the priming done in [`Resolver::new`].
    pub fn priming_status(&self) -> PrimingStatus {
        lock(&self.priming).clone()
    }
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}
