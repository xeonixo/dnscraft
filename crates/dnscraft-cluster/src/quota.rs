//! Master-side per-node quotas.
//!
//! Token buckets (one per node and class) are refilled from a caller-supplied
//! [`SystemTime`] — the handler passes the injected [`Clock`] value, so there
//! are no wall-clock sleeps. A fresh node starts with one second's worth of
//! tokens, so it may burst up to its per-second limit immediately.
//!
//! [`Clock`]: dnscraft_common::clock::Clock

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::SystemTime;

use crate::config::QuotaConfig;

/// One token bucket: continuous refill up to a fixed capacity.
#[derive(Debug)]
struct TokenBucket {
    tokens: f64,
    last: SystemTime,
}

impl TokenBucket {
    fn full(now: SystemTime, capacity: f64) -> Self {
        Self {
            tokens: capacity,
            last: now,
        }
    }

    /// Refills for the elapsed clock time, then charges `cost` when it fits.
    ///
    /// A backwards clock step refills nothing. A cost above the bucket
    /// capacity can never fit and is rejected without draining the bucket.
    fn try_consume(&mut self, now: SystemTime, rate: f64, capacity: f64, cost: f64) -> bool {
        if let Ok(elapsed) = now.duration_since(self.last) {
            self.tokens = (self.tokens + elapsed.as_secs_f64() * rate).min(capacity);
            self.last = now;
        }
        if cost > capacity || self.tokens < cost {
            return false;
        }
        self.tokens -= cost;
        true
    }
}

impl NodeBuckets {
    fn new(now: SystemTime, limits: &QuotaConfig) -> Self {
        Self {
            relay: TokenBucket::full(now, relay_rate(limits)),
            log: TokenBucket::full(now, log_rate(limits)),
            heartbeat: TokenBucket::full(now, HEARTBEAT_BURST),
        }
    }
}

#[derive(Debug)]
struct NodeBuckets {
    relay: TokenBucket,
    log: TokenBucket,
    heartbeat: TokenBucket,
}

/// Heartbeats per second per node. Nodes send one per `heartbeat_interval`
/// (5 s to 60 s), so this only stops a flood.
// ponytail: fixed rate, not a `[cluster.quota]` key; add one if an operator needs it.
const HEARTBEAT_RATE: f64 = 1.0;
/// Heartbeats a node may send at once after a quiet period.
const HEARTBEAT_BURST: f64 = 10.0;
/// Unauthenticated enroll attempts per second, master-wide. Enrollment is
/// rare (one per node) and each attempt needs a 256-bit one-time token.
const ENROLL_RATE: f64 = 1.0;
/// Enroll attempts allowed at once.
const ENROLL_BURST: f64 = 10.0;

fn relay_rate(limits: &QuotaConfig) -> f64 {
    f64::from(limits.max_relay_requests_per_second.max(1))
}

fn log_rate(limits: &QuotaConfig) -> f64 {
    limits.max_log_bytes_per_second as f64
}

/// Per-node relay/log rate limits shared by the master's handlers.
///
/// Keys are authenticated `node_id`s, so the map is bounded by the registry
/// rather than by untrusted input.
#[derive(Debug)]
pub(crate) struct QuotaLimiter {
    limits: QuotaConfig,
    nodes: Mutex<HashMap<String, NodeBuckets>>,
    enroll: Mutex<TokenBucket>,
}

impl QuotaLimiter {
    pub(crate) fn new(limits: QuotaConfig) -> Self {
        Self {
            limits,
            nodes: Mutex::new(HashMap::new()),
            enroll: Mutex::new(TokenBucket::full(SystemTime::UNIX_EPOCH, ENROLL_BURST)),
        }
    }

    /// Charges one heartbeat to `node_id`.
    pub(crate) fn allow_heartbeat(&self, node_id: &str, now: SystemTime) -> bool {
        let mut nodes = self
            .nodes
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let buckets = nodes
            .entry(node_id.to_owned())
            .or_insert_with(|| NodeBuckets::new(now, &self.limits));
        buckets
            .heartbeat
            .try_consume(now, HEARTBEAT_RATE, HEARTBEAT_BURST, 1.0)
    }

    /// Charges one enroll attempt. Enrollment is unauthenticated, so the
    /// bucket is shared by the whole listener rather than kept per node.
    pub(crate) fn allow_enroll(&self, now: SystemTime) -> bool {
        self.enroll
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .try_consume(now, ENROLL_RATE, ENROLL_BURST, 1.0)
    }

    /// The configured limits (queue cap, clock-skew threshold).
    pub(crate) fn limits(&self) -> &QuotaConfig {
        &self.limits
    }

    /// Charges one `/cluster/v1/writes` request to `node_id`.
    pub(crate) fn allow_relay(&self, node_id: &str, now: SystemTime) -> bool {
        let rate = relay_rate(&self.limits);
        let mut nodes = self
            .nodes
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let buckets = nodes
            .entry(node_id.to_owned())
            .or_insert_with(|| NodeBuckets::new(now, &self.limits));
        buckets.relay.try_consume(now, rate, rate, 1.0)
    }

    /// Charges `bytes` of `/cluster/v1/logs` payload to `node_id`.
    pub(crate) fn allow_log_bytes(&self, node_id: &str, bytes: u64, now: SystemTime) -> bool {
        let rate = log_rate(&self.limits);
        let mut nodes = self
            .nodes
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let buckets = nodes
            .entry(node_id.to_owned())
            .or_insert_with(|| NodeBuckets::new(now, &self.limits));
        buckets.log.try_consume(now, rate, rate, bytes as f64)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::time::{Duration, UNIX_EPOCH};

    use super::*;

    fn limiter() -> QuotaLimiter {
        QuotaLimiter::new(QuotaConfig {
            max_relay_requests_per_second: 2,
            max_log_bytes_per_second: 100,
            ..QuotaConfig::default()
        })
    }

    #[test]
    fn relay_bucket_refills_from_the_supplied_clock() {
        let limiter = limiter();
        let start = UNIX_EPOCH;
        assert!(limiter.allow_relay("node-a", start));
        assert!(limiter.allow_relay("node-a", start));
        assert!(!limiter.allow_relay("node-a", start));
        // Another node has its own bucket.
        assert!(limiter.allow_relay("node-b", start));
        // One second of clock time restores the full allowance, no sleep.
        assert!(limiter.allow_relay("node-a", start + Duration::from_secs(1)));
    }

    #[test]
    fn log_bucket_charges_payload_bytes() {
        let limiter = limiter();
        let start = UNIX_EPOCH;
        assert!(limiter.allow_log_bytes("node-a", 60, start));
        assert!(!limiter.allow_log_bytes("node-a", 60, start));
        assert!(limiter.allow_log_bytes("node-a", 40, start));
        // A single batch larger than the per-second budget never fits.
        assert!(!limiter.allow_log_bytes("node-a", 101, start));
        assert!(limiter.allow_log_bytes("node-a", 100, start + Duration::from_secs(1)));
    }
}
