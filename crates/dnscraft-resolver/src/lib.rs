//! Recursive, DNSSEC-validating DNS resolver with cache for DNScraft.
//!
//! Module layout (later tasks plug in here):
//! - `cache`: positive and negative answer cache (RFC 2308, Task 11).
//! - `iterate`: iterative resolution and referral following (Tasks 5, 7 extend it:
//!   CNAME chains, limits, QNAME minimisation).
//! - `transport`: single UDP exchange with response matching (Task 6: TCP, retries,
//!   server selection).
//! - `priming`: root priming (RFC 8109).
//! - `clock`: injectable time for the cache and DNSSEC (Tasks 9, 11).

mod cache;
mod clock;
mod config;
pub mod dnssec;
mod error;
mod hints;
mod iterate;
mod limits;
#[doc(hidden)]
pub mod local_zones;
mod priming;
#[doc(hidden)]
pub mod server_selection;
#[doc(hidden)]
pub mod transport;
mod types;

use std::net::SocketAddr;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use dnscraft_proto::{Message, Rcode, Record, RecordType};
use dnssec::status::Status;
use local_zones::LocalZones;
use server_selection::ServerStats;

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
    local_zones: LocalZones,
    cache: cache::Cache,
    roots: Mutex<Vec<SocketAddr>>,
    priming: Mutex<PrimingStatus>,
    resolutions: AtomicU64,
    outgoing: AtomicU64,
    stats: ServerStats,
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
        let stats = ServerStats::new(config.ipv6_cooldown);
        let (roots, status) = {
            let ctx = iterate::Context::new(&config, &config.root_hints, &outgoing, stats.clone());
            priming::prime(&ctx).await
        };
        let cache = cache::Cache::new(cache::budget_bytes(&config));
        Ok(Self {
            config,
            local_zones: LocalZones::rfc6303(),
            cache,
            roots: Mutex::new(roots),
            priming: Mutex::new(status),
            resolutions: AtomicU64::new(0),
            outgoing,
            stats,
        })
    }

    /// Resolves `query` by iterating from the root servers.
    pub async fn resolve(
        &self,
        query: &Query,
        flags: RequestFlags,
    ) -> Result<Answer, ResolveError> {
        if let Some(answer) = self.local_zones.answer(query, &self.config.forward_zones) {
            return Ok(answer);
        }
        self.resolutions.fetch_add(1, Ordering::Relaxed);
        let now = self.config.clock.instant();
        if let Some(mut answer) = self.cache.lookup(query, now) {
            tracing::debug!(qname = %query.name, qtype = %query.qtype, "cache hit");
            if !flags.dnssec_ok {
                strip_dnssec_records(&mut answer.message, query.qtype);
            }
            return Ok(answer);
        }
        let roots = lock(&self.roots).clone();
        let mut ctx =
            iterate::Context::new(&self.config, &roots, &self.outgoing, self.stats.clone());
        ctx.validate = !flags.checking_disabled && !self.config.trust_anchors.anchors().is_empty();
        tracing::debug!(
            qname = %query.name,
            qtype = %query.qtype,
            cd = flags.checking_disabled,
            do_bit = flags.dnssec_ok,
            "resolving"
        );
        let (outcome, status) =
            iterate::resolve_iterative(&ctx, &query.name, query.qtype, 0, Vec::new()).await?;
        tracing::debug!(qname = %query.name, zone = %outcome.zone, "resolved");
        let mut message = outcome.message;
        message.header.aa = false;
        message.header.ra = true;
        // Never pass on an AD bit set by a server; only our own validation counts.
        message.header.ad = false;
        message.edns = None;
        let ede = status.ede().map(|(code, text)| ExtendedError {
            code,
            text: Some(text.to_owned()),
        });
        let dnssec = status.public();
        // CD skips validation, and Bogus is rewritten to SERVFAIL below. Neither
        // is cached: an unvalidated or bogus answer must not be replayed later.
        let cacheable = !flags.checking_disabled && !matches!(status, Status::Bogus(_));
        match status {
            Status::Secure => message.header.ad = true,
            Status::Bogus(_) => {
                message.answers.clear();
                message.authorities.clear();
                message.additionals.clear();
                message.set_rcode(Rcode::SERVFAIL)?;
            }
            Status::Insecure | Status::InsecureNsec3Iterations | Status::Indeterminate => {}
        }
        // Store before DO stripping so a later client with DO still gets the
        // DNSSEC records. The TTL window starts when the answer is stored.
        let stored_at = self.config.clock.instant();
        let published_ttl = if cacheable {
            self.cache.store(
                query,
                &message,
                dnssec,
                ede.clone(),
                stored_at,
                cache::TtlClamp {
                    min: self.config.ttl_min,
                    max: self.config.ttl_max,
                },
            )
        } else {
            None
        };
        if let Some(ttl) = published_ttl {
            cache::set_ttls(&mut message, ttl);
        }
        if !flags.dnssec_ok {
            strip_dnssec_records(&mut message, query.qtype);
        }
        Ok(Answer {
            message,
            dnssec,
            source: AnswerSource::Recursion,
            ede,
        })
    }

    /// Removes cached answers.
    ///
    /// [`FlushScope::Domain`] drops that name and every name below it. Locally
    /// served zones are not cached.
    pub fn flush(&self, scope: FlushScope) {
        tracing::debug!(?scope, "flushing cache");
        self.cache.flush(&scope);
    }

    /// Bytes currently charged to the answer cache. For tests.
    #[doc(hidden)]
    pub fn cached_bytes(&self) -> usize {
        self.cache.bytes_used()
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

/// Removes RRSIG, NSEC and NSEC3 records from a response for a client that did
/// not set DO (RFC 4035 section 3.2.1); records of the queried type stay.
fn strip_dnssec_records(message: &mut Message, qtype: RecordType) {
    let drop = |r: &Record| {
        matches!(
            r.rtype,
            RecordType::RRSIG | RecordType::NSEC | RecordType::NSEC3
        ) && r.rtype != qtype
    };
    message.answers.retain(|r| !drop(r));
    message.authorities.retain(|r| !drop(r));
    message.additionals.retain(|r| !drop(r));
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}
