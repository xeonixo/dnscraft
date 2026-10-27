//! Resolver counters exposed through [`Resolver::stats`](crate::Resolver::stats).

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use crate::types::DnssecStatus;

/// Snapshot of resolver counters.
///
/// Latencies are wall-clock sums in nanoseconds. Means are
/// `resolve_latency_ns / resolutions` and `cache_hit_latency_ns / cache_hits`
/// when the denominator is non-zero. Percentiles are measured by the criterion
/// cache-hit benchmark, not by these counters.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ResolverStats {
    /// Questions passed to `resolve` (local RFC 6303 answers are excluded).
    pub resolutions: u64,
    /// Queries sent to authoritative or forward-target servers.
    pub outgoing_queries: u64,
    /// Fresh cache hits (expired entries served stale are not hits).
    pub cache_hits: u64,
    /// Answers served from an expired entry under serve-stale (RFC 8767).
    pub stale_answers: u64,
    /// Successful answers whose DNSSEC status was [`DnssecStatus::Secure`].
    pub dnssec_secure: u64,
    /// Successful answers whose DNSSEC status was [`DnssecStatus::Insecure`].
    pub dnssec_insecure: u64,
    /// Successful answers whose DNSSEC status was [`DnssecStatus::Bogus`].
    pub dnssec_bogus: u64,
    /// Successful answers whose DNSSEC status was [`DnssecStatus::Indeterminate`].
    pub dnssec_indeterminate: u64,
    /// Sum of wall-clock nanoseconds spent in counted `resolve` calls.
    pub resolve_latency_ns: u64,
    /// Sum of wall-clock nanoseconds spent on the fresh cache-hit path.
    pub cache_hit_latency_ns: u64,
    /// Entries currently held in the answer cache.
    pub cache_entries: u64,
}

/// Atomic counters behind [`ResolverStats`].
#[derive(Debug, Default)]
pub(crate) struct Counters {
    resolutions: AtomicU64,
    outgoing: AtomicU64,
    cache_hits: AtomicU64,
    stale_answers: AtomicU64,
    dnssec_secure: AtomicU64,
    dnssec_insecure: AtomicU64,
    dnssec_bogus: AtomicU64,
    dnssec_indeterminate: AtomicU64,
    resolve_latency_ns: AtomicU64,
    cache_hit_latency_ns: AtomicU64,
}

impl Counters {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn outgoing(&self) -> &AtomicU64 {
        &self.outgoing
    }

    pub(crate) fn begin_resolve(&self) {
        self.resolutions.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn add_resolve_latency(&self, elapsed: Duration) {
        self.resolve_latency_ns
            .fetch_add(nanos(elapsed), Ordering::Relaxed);
    }

    pub(crate) fn record_cache_hit(&self, elapsed: Duration) {
        self.cache_hits.fetch_add(1, Ordering::Relaxed);
        self.cache_hit_latency_ns
            .fetch_add(nanos(elapsed), Ordering::Relaxed);
    }

    pub(crate) fn record_stale(&self) {
        self.stale_answers.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn record_dnssec(&self, status: DnssecStatus) {
        let counter = match status {
            DnssecStatus::Secure => &self.dnssec_secure,
            DnssecStatus::Insecure => &self.dnssec_insecure,
            DnssecStatus::Bogus => &self.dnssec_bogus,
            DnssecStatus::Indeterminate => &self.dnssec_indeterminate,
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn snapshot(&self) -> ResolverStats {
        ResolverStats {
            resolutions: self.resolutions.load(Ordering::Relaxed),
            outgoing_queries: self.outgoing.load(Ordering::Relaxed),
            cache_hits: self.cache_hits.load(Ordering::Relaxed),
            stale_answers: self.stale_answers.load(Ordering::Relaxed),
            dnssec_secure: self.dnssec_secure.load(Ordering::Relaxed),
            dnssec_insecure: self.dnssec_insecure.load(Ordering::Relaxed),
            dnssec_bogus: self.dnssec_bogus.load(Ordering::Relaxed),
            dnssec_indeterminate: self.dnssec_indeterminate.load(Ordering::Relaxed),
            resolve_latency_ns: self.resolve_latency_ns.load(Ordering::Relaxed),
            cache_hit_latency_ns: self.cache_hit_latency_ns.load(Ordering::Relaxed),
            // Filled in by `Resolver::stats`, which can see the cache.
            cache_entries: 0,
        }
    }
}

fn nanos(elapsed: Duration) -> u64 {
    u64::try_from(elapsed.as_nanos()).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_reflects_recorded_events() {
        let c = Counters::new();
        c.begin_resolve();
        c.record_cache_hit(Duration::from_nanos(100));
        c.add_resolve_latency(Duration::from_nanos(100));
        c.record_dnssec(DnssecStatus::Secure);
        c.begin_resolve();
        c.record_stale();
        c.add_resolve_latency(Duration::from_nanos(50));
        c.record_dnssec(DnssecStatus::Insecure);
        c.outgoing().fetch_add(3, Ordering::Relaxed);

        let s = c.snapshot();
        assert_eq!(s.resolutions, 2);
        assert_eq!(s.outgoing_queries, 3);
        assert_eq!(s.cache_hits, 1);
        assert_eq!(s.stale_answers, 1);
        assert_eq!(s.dnssec_secure, 1);
        assert_eq!(s.dnssec_insecure, 1);
        assert_eq!(s.dnssec_bogus, 0);
        assert_eq!(s.dnssec_indeterminate, 0);
        assert_eq!(s.resolve_latency_ns, 150);
        assert_eq!(s.cache_hit_latency_ns, 100);
    }
}
