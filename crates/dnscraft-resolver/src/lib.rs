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

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use dnscraft_proto::{Class, Message, Name, Rcode, Record, RecordType};
use dnssec::status::Status;
use local_zones::LocalZones;
use server_selection::ServerStats;
use stats::Counters;
use tokio::sync::Semaphore;

pub use config::{ForwardZone, ForwardZoneId, ResolverConfig};
pub use dnscraft_common::clock::{Clock, ManualClock, SystemClock};
pub use error::{ForwardZoneIdError, ResolveError, ResolverError};
pub use hints::default_root_hints;
pub use stats::ResolverStats;
pub use types::{
    Answer, AnswerSource, DnssecStatus, ExtendedError, FlushScope, PrimingStatus, Query,
    RequestFlags, Route,
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
    /// When the root set is primed again (see `root_reprime_interval`).
    next_prime: Mutex<Instant>,
    counters: Counters,
    stats: ServerStats,
    inflight: inflight::Inflight,
    /// One permit per upstream resolution (`max_concurrent_resolutions`).
    permits: Arc<Semaphore>,
    /// Keys whose last prefetch failed, with the time of that failure.
    prefetch_failed: Mutex<HashMap<inflight::Key, Instant>>,
}

/// After a failed priming (start-up or refresh) the next attempt waits this
/// long, or the refresh interval when that is shorter.
const REPRIME_RETRY: Duration = Duration::from_secs(300);

fn status_ok(status: &PrimingStatus) -> bool {
    matches!(status, PrimingStatus::Primed { .. })
}

/// When the root set is due for priming again, counted from now.
fn next_prime_after(config: &ResolverConfig, primed: bool) -> Instant {
    let now = config.clock.instant();
    let wait = if config.root_reprime_interval.is_zero() {
        // Never again: far in the future, but representable.
        Duration::from_secs(100 * 365 * 24 * 3600)
    } else if primed {
        config.root_reprime_interval
    } else {
        config.root_reprime_interval.min(REPRIME_RETRY)
    };
    now.checked_add(wait).unwrap_or(now)
}

/// After a failed prefetch of a key, the next attempt for it waits this long.
const PREFETCH_BACKOFF: Duration = Duration::from_secs(30);

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
        if config.resolve_deadline.is_zero() {
            return Err(ResolverError::InvalidConfig {
                reason: "resolve_deadline must be greater than zero",
            });
        }
        if config.max_concurrent_resolutions == 0 {
            return Err(ResolverError::InvalidConfig {
                reason: "max_concurrent_resolutions must be at least 1",
            });
        }
        reject_duplicate_forward_zones(&config.forward_zones)?;
        let permits = Arc::new(Semaphore::new(
            config
                .max_concurrent_resolutions
                .min(Semaphore::MAX_PERMITS),
        ));
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
        let next_prime = Mutex::new(next_prime_after(&config, status_ok(&status)));
        Ok(Self {
            shared: Arc::new(Shared {
                config,
                local_zones: LocalZones::rfc6303(),
                cache,
                roots: Mutex::new(roots),
                priming: Mutex::new(status),
                next_prime,
                counters,
                stats,
                inflight: inflight::Inflight::new(),
                permits,
                prefetch_failed: Mutex::new(HashMap::new()),
            }),
        })
    }

    /// Ids of every configured forward zone, in config order.
    ///
    /// Used by policy to validate profile allow-lists. Pure lookup; no I/O.
    pub fn forward_zone_ids(&self) -> Vec<ForwardZoneId> {
        self.shared
            .config
            .forward_zones
            .iter()
            .map(|z| z.id.clone())
            .collect()
    }

    /// Most specific configured forward zone that covers `name`, if allowed.
    ///
    /// `allow` is the same filter as [`RequestFlags::forward_zones`]: `None`
    /// considers every configured zone, `Some` only the listed ids. Pure
    /// lookup; no I/O. Used by policy for special-use NXDOMAIN (a covering
    /// forward zone wins over synthesised NXDOMAIN).
    pub fn forward_zone_for(
        &self,
        name: &Name,
        allow: Option<&[ForwardZoneId]>,
    ) -> Option<ForwardZoneId> {
        forward::covering(&self.shared.config.forward_zones, name, allow).map(|z| z.id.clone())
    }

    /// Resolves `query`.
    ///
    /// Names covered by an allowed forward zone are sent to that zone's
    /// targets. [`RequestFlags::forward_zones`] chooses the zones that may
    /// forward: `None` allows every configured zone, and `Some` allows only
    /// the listed ids. Every other name is resolved iteratively from the root
    /// servers. A forward zone the query may not use does not suppress a
    /// local answer.
    pub async fn resolve(
        &self,
        query: &Query,
        flags: RequestFlags,
    ) -> Result<Answer, ResolveError> {
        if let Some(answer) = self.shared.local_zones.answer(
            query,
            forward::allowed_names(
                &self.shared.config.forward_zones,
                flags.forward_zones.as_deref(),
            ),
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
        let route = forward::route_for(
            &self.shared.config.forward_zones,
            query,
            flags.forward_zones.as_deref(),
        );
        let now = self.shared.config.clock.instant();
        let hit_started = Instant::now();
        if let Some(answer) = self.shared.cache.lookup(query, &route, now) {
            tracing::debug!(qname = %query.name, qtype = %query.qtype, "cache hit");
            self.shared.counters.record_cache_hit(hit_started.elapsed());
            self.maybe_prefetch(query, &flags, &route, now);
            return Ok(present(answer, flags, query.qtype));
        }
        // Forward loop: peer is a configured target of the matching zone.
        // Only the IP is compared: a forwarder that queries us back uses an
        // ephemeral source port, and policy passes port 0.
        // Checked before dedup so we do not join a flight that is waiting on
        // that same peer (deadlock). Ordinary clients are not targets, so
        // they still coalesce on the in-flight forward. A zone the query is
        // not allowed to use is not a forward, so it is not a loop either.
        if let types::Route::Forward(id) = &route
            && let Some(client) = flags.client
            && let Some(zone) = self
                .shared
                .config
                .forward_zones
                .iter()
                .find(|zone| &zone.id == id)
            && zone
                .targets
                .iter()
                .any(|target| target.ip().to_canonical() == client.ip().to_canonical())
        {
            tracing::debug!(qname = %query.name, zone = %zone.zone, peer = %client, "forward loop");
            return Err(ResolveError::ForwardLoop {
                zone: zone.zone.clone(),
            });
        }
        // Misses for the same question and route share one upstream
        // resolution. DO is applied per waiter afterwards, because it is not
        // part of the key.
        let key = inflight::Key::new(query, flags.checking_disabled, route.clone());
        let shared = Arc::clone(&self.shared);
        let owned = query.clone();
        let task_flags = flags.clone();
        let upstream = self
            .shared
            .inflight
            .dedup(key, async move {
                shared.resolve_limited(&owned, task_flags).await
            })
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
                if let Some(answer) = self.shared.cache.lookup_stale(
                    query,
                    &route,
                    now,
                    self.shared.config.serve_stale,
                ) {
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
    fn maybe_prefetch(
        &self,
        query: &Query,
        flags: &RequestFlags,
        route: &types::Route,
        now: Instant,
    ) {
        // CD would store an unvalidated replacement, which is the same reason
        // CD answers are not cached. Bogus entries are never stored, so a hit
        // is already something prefetch is allowed to refresh.
        if !self.shared.config.prefetch || flags.checking_disabled || flags.no_cache_write {
            return;
        }
        let Some(stats) = self.shared.cache.fresh_stats(query, route, now) else {
            return;
        };
        if !prefetch::should_refresh(stats) {
            return;
        }
        let key = inflight::Key::new(query, false, route.clone());
        if self.shared.prefetch_backed_off(&key, now) {
            return;
        }
        // Prefetch is best effort: with no free slot it is skipped rather than
        // queued behind (or in front of) client resolutions. The permit is
        // taken before the flight so a skipped prefetch leaves no trace.
        let Ok(permit) = Arc::clone(&self.shared.permits).try_acquire_owned() else {
            tracing::debug!(qname = %query.name, "prefetch skipped: no free resolution slot");
            return;
        };
        // CD is clear on the refresh itself, so it coalesces with validating
        // misses and the result stays cacheable. The allow-list is the one
        // from the hit, so the refresh follows the same route. A second hit
        // finds this flight and does not start another.
        let Some(leader) = self.shared.inflight.try_lead(key.clone()) else {
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
        let refresh_flags = RequestFlags {
            checking_disabled: false,
            dnssec_ok: flags.dnssec_ok,
            client: None,
            forward_zones: flags.forward_zones.clone(),
            no_cache_write: false,
        };
        let task = tokio::spawn(async move {
            let result = shared.resolve_upstream(&query, refresh_flags).await;
            drop(permit);
            // The refresh only counts when it produced a cacheable outcome. A
            // forwarded SERVFAIL or REFUSED arrives as `Ok` but left the old
            // entry in place, so it is a failure too.
            let refreshed = result.as_ref().is_ok_and(|answer| {
                matches!(answer.message.rcode(), Rcode::NOERROR | Rcode::NXDOMAIN)
            });
            if refreshed {
                shared.clear_prefetch_failure(&key);
            } else {
                // The client already received the cached answer. A failed
                // refresh leaves that entry in place, and the key is not
                // retried for a while.
                tracing::debug!(qname = %query.name, "prefetch failed");
                shared.note_prefetch_failure(key);
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
        let mut stats = self.shared.counters.snapshot();
        stats.cache_entries = self.shared.cache.entries();
        stats
    }

    /// Outcome of the priming done in [`Resolver::new`].
    pub fn priming_status(&self) -> PrimingStatus {
        lock(&self.shared.priming).clone()
    }
}

impl Shared {
    /// True while `key` is inside the backoff window of a failed prefetch.
    fn prefetch_backed_off(&self, key: &inflight::Key, now: Instant) -> bool {
        lock(&self.prefetch_failed)
            .get(key)
            .is_some_and(|failed_at| now.saturating_duration_since(*failed_at) < PREFETCH_BACKOFF)
    }

    fn note_prefetch_failure(&self, key: inflight::Key) {
        let now = self.config.clock.instant();
        let mut failed = lock(&self.prefetch_failed);
        // Entries past their window carry no information; dropping them here
        // keeps the map small.
        failed.retain(|_, at| now.saturating_duration_since(*at) < PREFETCH_BACKOFF);
        failed.insert(key, now);
    }

    fn clear_prefetch_failure(&self, key: &inflight::Key) {
        lock(&self.prefetch_failed).remove(key);
    }

    /// [`Shared::resolve_upstream`] under the concurrency cap.
    ///
    /// Waits up to `query_timeout` for a slot. The permit is held for the
    /// whole resolution.
    async fn resolve_limited(
        &self,
        query: &Query,
        flags: RequestFlags,
    ) -> Result<Answer, ResolveError> {
        let permit = match tokio::time::timeout(
            self.config.query_timeout,
            Arc::clone(&self.permits).acquire_owned(),
        )
        .await
        {
            Ok(Ok(permit)) => permit,
            Ok(Err(_)) | Err(_) => {
                tracing::debug!(qname = %query.name, "resolution refused: too many in flight");
                return Err(ResolveError::Overloaded);
            }
        };
        let result = self.resolve_upstream(query, flags).await;
        drop(permit);
        result
    }

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
        // Per-query and per-resolution budgets bound the work, but not the
        // time: a server that dribbles answers can keep a resolution (and its
        // concurrency permit) alive for a long time. The deadline ends it.
        match tokio::time::timeout(
            self.config.resolve_deadline,
            self.resolve_upstream_inner(query, flags),
        )
        .await
        {
            Ok(result) => result,
            Err(_) => {
                tracing::debug!(qname = %query.name, "resolution deadline exceeded");
                Err(ResolveError::Unreachable {
                    zone: query.name.clone(),
                })
            }
        }
    }

    async fn resolve_upstream_inner(
        &self,
        query: &Query,
        flags: RequestFlags,
    ) -> Result<Answer, ResolveError> {
        // A flush while this resolution runs must not be undone by storing
        // its (older) result.
        let epoch = self.cache.epoch();
        if query.qclass == Class::IN
            && let Some(zone) = forward::covering(
                &self.config.forward_zones,
                &query.name,
                flags.forward_zones.as_deref(),
            )
        {
            let zone = zone.clone();
            return self.forward_zone(zone, query, flags, epoch).await;
        }
        self.reprime_if_due().await;
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
        self.finish_answer(
            query,
            flags,
            outcome.message,
            status,
            epoch,
            outcome.sig_cap,
            &types::Route::Recursive,
        )
    }

    /// Primes the root set again when `root_reprime_interval` has passed.
    ///
    /// The caller that finds the refresh due claims it (later callers go on
    /// with the current set) and runs it inline. A priming that falls back
    /// to the hints keeps the set in use and is retried after a short wait,
    /// so a flaky network does not replace a good set by the built-in hints.
    async fn reprime_if_due(&self) {
        if self.config.root_reprime_interval.is_zero() {
            return;
        }
        let now = self.config.clock.instant();
        {
            let mut next = lock(&self.next_prime);
            if now < *next {
                return;
            }
            *next = next_prime_after(&self.config, false);
        }
        tracing::debug!("priming the root servers again");
        let (roots, status) = {
            let ctx = iterate::Context::new(
                &self.config,
                &self.config.root_hints,
                self.counters.outgoing(),
                self.stats.clone(),
            );
            priming::prime(&ctx).await
        };
        if status_ok(&status) {
            *lock(&self.roots) = roots;
            *lock(&self.priming) = status;
            *lock(&self.next_prime) = next_prime_after(&self.config, true);
        }
    }

    /// Sends `query` to `zone`'s targets and caches the answer like a
    /// recursive one.
    async fn forward_zone(
        &self,
        zone: ForwardZone,
        query: &Query,
        flags: RequestFlags,
        epoch: u64,
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
        let message = forward::scrub(message, &query.name, query.qtype, &zone.zone);
        // One validation budget for the whole forwarded resolution.
        let budget = dnssec::ValidationBudget::default();
        let mut caps = Vec::new();
        let status = self
            .forwarded_status(
                &zone,
                &flags,
                &query.name,
                query.qtype,
                &message,
                &budget,
                &mut caps,
            )
            .await?;
        let mut message = message;
        let mut sig_cap = None;
        for section in [&mut message.answers, &mut message.authorities] {
            dnssec::walk::apply_caps(section, &caps, &mut sig_cap);
        }
        let route = types::Route::Forward(zone.id.clone());
        self.finish_answer(query, flags, message, status, epoch, sig_cap, &route)
    }

    /// Applies AA/RA/AD, rewrites Bogus to SERVFAIL, and stores a cacheable
    /// answer. Shared by iterative and forwarded resolutions.
    #[allow(clippy::too_many_arguments)]
    fn finish_answer(
        &self,
        query: &Query,
        flags: RequestFlags,
        mut message: Message,
        status: Status,
        epoch: u64,
        sig_cap: Option<u32>,
        route: &types::Route,
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
        // Dry-run queries read the cache but never write it.
        let cacheable = !flags.checking_disabled
            && !flags.no_cache_write
            && !matches!(status, Status::Bogus(_));
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
            self.cache.store_in_epoch(
                query,
                route,
                &message,
                dnssec,
                ede.clone(),
                stored_at,
                cache::TtlClamp {
                    min: self.config.ttl_min,
                    max: self.config.ttl_max,
                },
                Some(epoch),
                sig_cap,
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
            forward_zone: route.forward_zone(),
        })
    }
}

/// Two forward zones with the same id cannot be told apart on a query.
fn reject_duplicate_forward_zones(zones: &[config::ForwardZone]) -> Result<(), ResolverError> {
    let mut seen = HashSet::with_capacity(zones.len());
    for zone in zones {
        if !seen.insert(&zone.id) {
            return Err(ResolverError::DuplicateForwardZone {
                id: zone.id.clone(),
            });
        }
    }
    Ok(())
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
            r.rtype(),
            RecordType::RRSIG | RecordType::NSEC | RecordType::NSEC3
        ) && r.rtype() != qtype
    };
    message.answers.retain(|r| !drop(r));
    message.authorities.retain(|r| !drop(r));
    message.additionals.retain(|r| !drop(r));
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}
