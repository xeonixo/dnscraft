//! Recursive, DNSSEC-validating DNS resolver with cache for DNScraft.
//!
//! Module layout (later tasks plug in here):
//! - `cache`: positive and negative answer cache (RFC 2308), including
//!   serve-stale when authoritative servers are unreachable (RFC 8767).
//! - `inflight`: coalescing of identical concurrent misses.
//! - `prefetch`: background refresh of popular entries shortly before expiry.
//! - `iterate`: iterative resolution and referral following (Tasks 5, 7 extend it:
//!   CNAME chains, limits, QNAME minimisation).
//! - `forward`: stub forwarding of configured zones, with failover and loop
//!   protection.
//! - `transport`: single UDP exchange with response matching (Task 6: TCP, retries,
//!   server selection).
//! - `priming`: root priming (RFC 8109).
//! - `stats`: counters for cache hits, latencies, and DNSSEC outcomes.
//! - `clock`: injectable time for the cache and DNSSEC (Tasks 9, 11).

mod cache;
mod clock;
mod config;
pub mod dnssec;
mod error;
mod forward;
mod hints;
mod inflight;
mod iterate;
mod limits;
#[doc(hidden)]
pub mod local_zones;
mod prefetch;
mod priming;
#[doc(hidden)]
pub mod server_selection;
mod stats;
#[doc(hidden)]
pub mod transport;
mod types;

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use dnscraft_proto::{Class, Message, Name, Rcode, Record, RecordType};
use dnssec::status::{BogusReason, Status, rrsets};
use dnssec::{ChainFailure, DelegationTrust, KeysOutcome, validate_dnskey_rrset, validate_rrset};
use local_zones::LocalZones;
use server_selection::ServerStats;
use stats::Counters;

pub use clock::{Clock, ManualClock, SystemClock};
pub use config::{ForwardZone, ResolverConfig};
pub use error::{ResolveError, ResolverError};
pub use hints::default_root_hints;
pub use stats::ResolverStats;
pub use types::{
    Answer, AnswerSource, DnssecStatus, ExtendedError, FlushScope, PrimingStatus, Query,
    RequestFlags,
};

/// In-memory answer cache, exposed only for the criterion microbench.
#[doc(hidden)]
pub use cache::{Cache as __BenchCache, TtlClamp as __BenchTtlClamp};

/// State shared with background prefetch tasks. Those tasks must not borrow
/// the `Resolver`, which the caller is free to drop while a refresh runs.
#[derive(Debug)]
struct Shared {
    config: ResolverConfig,
    local_zones: LocalZones,
    cache: cache::Cache,
    roots: Mutex<Vec<SocketAddr>>,
    priming: Mutex<PrimingStatus>,
    counters: Counters,
    stats: ServerStats,
    inflight: inflight::Inflight,
}

/// A recursive resolver.
#[derive(Debug)]
pub struct Resolver {
    shared: Arc<Shared>,
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
        let counters = Counters::new();
        let stats = ServerStats::new(config.ipv6_cooldown);
        let (roots, status) = {
            let ctx = iterate::Context::new(
                &config,
                &config.root_hints,
                counters.outgoing(),
                stats.clone(),
            );
            priming::prime(&ctx).await
        };
        let cache = cache::Cache::new(cache::budget_bytes(&config));
        Ok(Self {
            shared: Arc::new(Shared {
                config,
                local_zones: LocalZones::rfc6303(),
                cache,
                roots: Mutex::new(roots),
                priming: Mutex::new(status),
                counters,
                stats,
                inflight: inflight::Inflight::new(),
            }),
        })
    }

    /// Resolves `query`.
    ///
    /// Names covered by a configured forward zone are sent to that zone's
    /// targets. Every other name is resolved iteratively from the root
    /// servers.
    pub async fn resolve(
        &self,
        query: &Query,
        flags: RequestFlags,
    ) -> Result<Answer, ResolveError> {
        if let Some(answer) = self.shared.local_zones.answer(
            query,
            self.shared
                .config
                .forward_zones
                .iter()
                .map(|zone| &zone.zone),
        ) {
            return Ok(answer);
        }
        self.shared.counters.begin_resolve();
        let started = Instant::now();
        let result = self.resolve_counted(query, flags).await;
        self.shared.counters.add_resolve_latency(started.elapsed());
        if let Ok(answer) = &result {
            self.shared.counters.record_dnssec(answer.dnssec);
            if answer.source == AnswerSource::Stale {
                self.shared.counters.record_stale();
            }
        }
        result
    }

    async fn resolve_counted(
        &self,
        query: &Query,
        flags: RequestFlags,
    ) -> Result<Answer, ResolveError> {
        let now = self.shared.config.clock.instant();
        let hit_started = Instant::now();
        if let Some(answer) = self.shared.cache.lookup(query, now) {
            tracing::debug!(qname = %query.name, qtype = %query.qtype, "cache hit");
            self.shared.counters.record_cache_hit(hit_started.elapsed());
            self.maybe_prefetch(query, flags, now);
            return Ok(present(answer, flags, query.qtype));
        }
        // Forward loop: peer is a configured target of the matching zone.
        // Checked before dedup so we do not join a flight that is waiting on
        // that same peer (deadlock). Ordinary clients are not targets, so
        // they still coalesce on the in-flight forward.
        if query.qclass == Class::IN
            && let Some(client) = flags.client
            && let Some(zone) = forward::covering(&self.shared.config.forward_zones, &query.name)
            && zone.targets.contains(&client)
        {
            tracing::debug!(qname = %query.name, zone = %zone.zone, peer = %client, "forward loop");
            return Err(ResolveError::ForwardLoop {
                zone: zone.zone.clone(),
            });
        }
        // Misses for the same question share one upstream resolution. DO is
        // applied per waiter afterwards, because it is not part of the key.
        let key = inflight::Key::new(query, flags.checking_disabled);
        let shared = Arc::clone(&self.shared);
        let owned = query.clone();
        let upstream = self
            .shared
            .inflight
            .dedup(
                key,
                async move { shared.resolve_upstream(&owned, flags).await },
            )
            .await;
        match upstream {
            Ok(answer) => Ok(present(answer, flags, query.qtype)),
            // RFC 8767: serve an expired entry only when the authoritative
            // servers could not be reached. A timeout of every server of a
            // zone is reported as `Unreachable`. The stale answer is not
            // stored (that would refresh its TTL) and does not start prefetch,
            // which runs only for a fresh hit. Past the serve-stale window the
            // original error is returned; it is not rewritten to SERVFAIL.
            Err(err @ ResolveError::Unreachable { .. }) => {
                let now = self.shared.config.clock.instant();
                if let Some(answer) =
                    self.shared
                        .cache
                        .lookup_stale(query, now, self.shared.config.serve_stale)
                {
                    tracing::debug!(
                        qname = %query.name,
                        qtype = %query.qtype,
                        "serving stale answer"
                    );
                    Ok(present(answer, flags, query.qtype))
                } else {
                    Err(err)
                }
            }
            Err(err) => Err(err),
        }
    }

    /// Starts a background refresh when the cached answer is popular and
    /// close to expiry. The caller already has that answer and does not wait.
    fn maybe_prefetch(&self, query: &Query, flags: RequestFlags, now: Instant) {
        // CD would store an unvalidated replacement, which is the same reason
        // CD answers are not cached. Bogus entries are never stored, so a hit
        // is already something prefetch is allowed to refresh.
        if !self.shared.config.prefetch || flags.checking_disabled {
            return;
        }
        let Some(stats) = self.shared.cache.fresh_stats(query, now) else {
            return;
        };
        if !prefetch::should_refresh(stats) {
            return;
        }
        // CD is clear on the refresh itself, so it coalesces with validating
        // misses and the result stays cacheable. A second hit finds this
        // flight and does not start another.
        let Some(leader) = self
            .shared
            .inflight
            .try_lead(inflight::Key::new(query, false))
        else {
            return;
        };
        tracing::debug!(
            qname = %query.name,
            qtype = %query.qtype,
            hits = stats.hits,
            "prefetching"
        );
        let shared = Arc::clone(&self.shared);
        let query = query.clone();
        let task = tokio::spawn(async move {
            let result = shared
                .resolve_upstream(&query, RequestFlags::default())
                .await;
            if let Err(err) = &result {
                // The client already received the cached answer. A failed
                // refresh leaves that entry in place.
                tracing::debug!(qname = %query.name, error = %err, "prefetch failed");
            }
            leader.complete(result);
        });
        drop(task);
    }

    /// Removes cached answers.
    ///
    /// [`FlushScope::Domain`] drops that name and every name below it. Locally
    /// served zones are not cached.
    pub fn flush(&self, scope: FlushScope) {
        tracing::debug!(?scope, "flushing cache");
        self.shared.cache.flush(&scope);
    }

    /// Waits until every resolution and prefetch has finished. For tests.
    #[doc(hidden)]
    pub async fn wait_idle(&self) {
        self.shared.inflight.wait_idle().await;
    }

    /// Bytes currently charged to the answer cache. For tests.
    #[doc(hidden)]
    pub fn cached_bytes(&self) -> usize {
        self.shared.cache.bytes_used()
    }

    /// Counters: cache hits, latencies, DNSSEC outcomes, and traffic.
    pub fn stats(&self) -> ResolverStats {
        self.shared.counters.snapshot()
    }

    /// Outcome of the priming done in [`Resolver::new`].
    pub fn priming_status(&self) -> PrimingStatus {
        lock(&self.shared.priming).clone()
    }
}

impl Shared {
    /// One upstream resolution, stored when the answer is cacheable.
    ///
    /// A name covered by a forward zone is stub-forwarded. Everything else
    /// is resolved iteratively from the roots. DNSSEC records are left in
    /// place. Each caller strips them according to its own DO bit, including
    /// waiters that shared this flight.
    async fn resolve_upstream(
        &self,
        query: &Query,
        flags: RequestFlags,
    ) -> Result<Answer, ResolveError> {
        if query.qclass == Class::IN
            && let Some(zone) = forward::covering(&self.config.forward_zones, &query.name)
        {
            let zone = zone.clone();
            return self.forward_zone(zone, query, flags).await;
        }
        let roots = lock(&self.roots).clone();
        let mut ctx = iterate::Context::new(
            &self.config,
            &roots,
            self.counters.outgoing(),
            self.stats.clone(),
        );
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
        self.finish_answer(query, flags, outcome.message, status)
    }

    /// Sends `query` to `zone`'s targets and caches the answer like a
    /// recursive one.
    async fn forward_zone(
        &self,
        zone: ForwardZone,
        query: &Query,
        flags: RequestFlags,
    ) -> Result<Answer, ResolveError> {
        tracing::debug!(
            qname = %query.name,
            qtype = %query.qtype,
            zone = %zone.zone,
            "forwarding"
        );
        let message = self
            .exchange_forward(&zone.targets, &zone.zone, &query.name, query.qtype)
            .await?;
        let status = self.forwarded_status(&zone, flags, &message).await?;
        self.finish_answer(query, flags, message, status)
    }

    /// One stub query to `targets`. An empty list or no usable answer is
    /// [`ResolveError::Unreachable`] for `zone`.
    async fn exchange_forward(
        &self,
        targets: &[SocketAddr],
        zone: &Name,
        name: &Name,
        qtype: RecordType,
    ) -> Result<Message, ResolveError> {
        if targets.is_empty() {
            return Err(ResolveError::Unreachable { zone: zone.clone() });
        }
        self.counters
            .outgoing()
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let query = transport::build_forward_query(name, qtype);
        match transport::query_servers(targets, &query, self.config.query_timeout, &self.stats)
            .await
        {
            Ok(resp) => Ok(resp.message),
            Err(transport::TransportError::Encode(err)) => Err(ResolveError::Encode(err)),
            Err(err) => {
                tracing::debug!(qname = %name, qtype = %qtype, zone = %zone, error = %err, "forward failed");
                Err(ResolveError::Unreachable { zone: zone.clone() })
            }
        }
    }

    /// DNSSEC status of a stub answer.
    ///
    /// `validate == false` is always `Insecure`. Otherwise CD, or no trust
    /// anchors at all, yields `Indeterminate` (validation is off), matching
    /// a recursive answer. With validation on, the zone apex must have a
    /// trust anchor; DNSKEY is fetched from the same targets and positive
    /// in-zone RRsets are checked against it. A response with nothing to
    /// check stays `Indeterminate` — a stub answer does not carry a denial
    /// proof this resolver rebuilds.
    async fn forwarded_status(
        &self,
        zone: &ForwardZone,
        flags: RequestFlags,
        message: &Message,
    ) -> Result<Status, ResolveError> {
        if !zone.validate {
            return Ok(Status::Insecure);
        }
        let validating =
            !flags.checking_disabled && !self.config.trust_anchors.anchors().is_empty();
        if !validating {
            return Ok(Status::Indeterminate);
        }
        if !self.config.trust_anchors.has_zone(&zone.zone) {
            return Ok(Status::Bogus(BogusReason::Chain(
                ChainFailure::NoTrustAnchor,
            )));
        }
        tracing::debug!(zone = %zone.zone, "validating forwarded answer");
        let keys_msg = match self
            .exchange_forward(&zone.targets, &zone.zone, &zone.zone, RecordType::DNSKEY)
            .await
        {
            Ok(message) => message,
            Err(ResolveError::Unreachable { .. }) => {
                return Ok(Status::Bogus(BogusReason::DnskeyUnavailable));
            }
            Err(err) => return Err(err),
        };
        let keys = match validate_dnskey_rrset(
            &zone.zone,
            &keys_msg.answers,
            &keys_msg.answers,
            DelegationTrust::Anchors(&self.config.trust_anchors),
            self.config.clock.now(),
        ) {
            Ok(KeysOutcome::Secure(keys)) => keys,
            Ok(KeysOutcome::Insecure(_)) => return Ok(Status::Insecure),
            Err(err) => return Ok(Status::Bogus(BogusReason::Chain(err))),
        };
        let now = self.config.clock.now();
        let mut saw = false;
        for set in rrsets(&message.answers, &zone.zone, |_| true) {
            let owned: Vec<Record> = set.into_iter().cloned().collect();
            if let Err(err) = validate_rrset(&owned, &message.answers, &keys, now) {
                return Ok(Status::Bogus(BogusReason::Verify(err)));
            }
            saw = true;
        }
        if saw {
            Ok(Status::Secure)
        } else {
            Ok(Status::Indeterminate)
        }
    }

    /// Applies AA/RA/AD, rewrites Bogus to SERVFAIL, and stores a cacheable
    /// answer. Shared by iterative and forwarded resolutions.
    fn finish_answer(
        &self,
        query: &Query,
        flags: RequestFlags,
        mut message: Message,
        status: Status,
    ) -> Result<Answer, ResolveError> {
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
        Ok(Answer {
            message,
            dnssec,
            source: AnswerSource::Recursion,
            ede,
        })
    }
}

/// Applies the caller's DO bit. Shared by a cache hit and every in-flight waiter.
fn present(mut answer: Answer, flags: RequestFlags, qtype: RecordType) -> Answer {
    if !flags.dnssec_ok {
        strip_dnssec_records(&mut answer.message, qtype);
    }
    answer
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
