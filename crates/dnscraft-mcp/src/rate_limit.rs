//! Per-token token-bucket rate limiting for MCP tool calls.
//!
//! Mirrors the semantics of the control-api limiter (`RateLimiter`): one
//! read/write/auth bucket per tracked key, continuous refill driven by the
//! injectable [`Clock`] and a bounded LRU map so a flood of distinct keys
//! cannot grow memory without bound. It is deliberately self-contained because
//! this crate depends on no other DNScraft crate.
//!
//! Keys are the validated `token_id` for read and write tools and the source
//! (peer address, or a shared fallback when no peer is available) for
//! failed-authentication attempts. A bucket starts full with one second's
//! tokens (`burst = rate`).

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex, PoisonError};

use crate::clock::{Clock, unix_seconds};
use crate::config::McpConfig;

/// Which rate-limit bucket a call falls into.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum BucketClass {
    /// Read tools and non-tool JSON-RPC methods.
    Read,
    /// Write tools.
    Write,
    /// Failed authentication attempts, keyed by source.
    Auth,
}

/// One token bucket: refills continuously up to a burst ceiling.
#[derive(Clone, Copy, Debug)]
struct TokenBucket {
    /// Current token balance (never exceeds `burst`).
    tokens: f64,
    /// Unix seconds of the last refill.
    last: i64,
}

impl TokenBucket {
    /// A bucket that starts full (a fresh key may burst immediately).
    fn full(now: i64, burst: f64) -> Self {
        Self {
            tokens: burst,
            last: now,
        }
    }

    /// Consumes one token. `Ok(())` on success, `Err(seconds)` until a token
    /// is available again when the bucket is empty.
    fn try_consume(&mut self, now: i64, rate: f64, burst: f64) -> Result<(), u64> {
        let elapsed = (now - self.last).max(0) as f64;
        self.tokens = (self.tokens + elapsed * rate).min(burst);
        self.last = now;
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            Ok(())
        } else {
            let deficit = 1.0 - self.tokens;
            Err((deficit / rate).ceil().max(1.0) as u64)
        }
    }
}

/// The three buckets held for one tracked key.
struct Buckets {
    read: TokenBucket,
    write: TokenBucket,
    auth: TokenBucket,
}

impl Buckets {
    fn new(now: i64, rates: &Rates) -> Self {
        Self {
            read: TokenBucket::full(now, rates.read),
            write: TokenBucket::full(now, rates.write),
            auth: TokenBucket::full(now, rates.auth),
        }
    }

    fn bucket_mut(&mut self, class: BucketClass) -> &mut TokenBucket {
        match class {
            BucketClass::Read => &mut self.read,
            BucketClass::Write => &mut self.write,
            BucketClass::Auth => &mut self.auth,
        }
    }
}

/// The three steady-state rates (tokens per second).
#[derive(Clone, Copy, Debug)]
struct Rates {
    read: f64,
    write: f64,
    auth: f64,
}

impl Rates {
    fn for_class(self, class: BucketClass) -> f64 {
        match class {
            BucketClass::Read => self.read,
            BucketClass::Write => self.write,
            BucketClass::Auth => self.auth,
        }
    }
}

/// One tracked key's buckets plus the generation of its last access.
struct Entry {
    buckets: Buckets,
    /// Generation at the last access, for LRU staleness detection.
    touched: u64,
}

/// Mutable limiter state: the bucket map and its recency order.
struct LimiterState {
    map: HashMap<String, Entry>,
    /// Recency order; front = least recently used. Each entry records the
    /// generation at which it was pushed, so a stale entry (superseded by a
    /// later touch of the same key) is skipped lazily on eviction.
    order: VecDeque<(String, u64)>,
    seq: u64,
    max_keys: usize,
}

impl LimiterState {
    fn check(&mut self, key: &str, class: BucketClass, now: i64, rates: Rates) -> Result<(), u64> {
        self.seq += 1;
        let seq = self.seq;
        let entry = self.map.entry(key.to_owned()).or_insert_with(|| Entry {
            buckets: Buckets::new(now, &rates),
            touched: seq,
        });
        entry.touched = seq;
        self.order.push_back((key.to_owned(), seq));

        // Config validation enforces a positive rate; `.max(1.0)` is defence
        // in depth against an unvalidated config reaching the limiter.
        let rate = rates.for_class(class).max(1.0);
        let result = entry.buckets.bucket_mut(class).try_consume(now, rate, rate);

        self.evict();
        result
    }

    /// Evicts least-recently-used entries until the map is within its cap, and
    /// compacts the recency order when it grows far past the cap.
    fn evict(&mut self) {
        while self.map.len() > self.max_keys {
            let Some((key, seq)) = self.order.pop_front() else {
                break;
            };
            if self.map.get(&key).map(|entry| entry.touched) == Some(seq) {
                self.map.remove(&key);
            }
            // else: a stale order entry superseded by a later touch — skip.
        }
        if self.order.len() > self.max_keys * 2 {
            self.order = self
                .map
                .iter()
                .map(|(key, entry)| (key.clone(), entry.touched))
                .collect();
        }
    }
}

/// In-memory token-bucket rate limiter keyed by token id or source.
///
/// Cloning shares the bucket map, so every per-request clone of the transport
/// consults the same limiter.
#[derive(Clone)]
pub(crate) struct TokenRateLimiter {
    rates: Rates,
    clock: Arc<dyn Clock>,
    state: Arc<Mutex<LimiterState>>,
}

impl TokenRateLimiter {
    /// Creates a limiter from the validated MCP rate-limit configuration.
    pub(crate) fn new(config: &McpConfig, clock: Arc<dyn Clock>) -> Self {
        Self {
            rates: Rates {
                read: config.read_per_second as f64,
                write: config.write_per_second as f64,
                auth: config.auth_per_second as f64,
            },
            clock,
            state: Arc::new(Mutex::new(LimiterState {
                map: HashMap::new(),
                order: VecDeque::new(),
                seq: 0,
                max_keys: config.max_tracked_tokens.max(1),
            })),
        }
    }

    /// Consumes one token for `key` in `class`; `Err(seconds)` until retry on
    /// excess. Refill is clock-driven — this never sleeps.
    pub(crate) fn check(&self, key: &str, class: BucketClass) -> Result<(), u64> {
        let now = unix_seconds(self.clock.now());
        self.state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .check(key, class, now, self.rates)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::time::{Duration, SystemTime};

    use super::*;
    use crate::clock::ManualClock;

    fn config(read: u32, write: u32, auth: u32, max_tracked_tokens: usize) -> McpConfig {
        McpConfig {
            read_per_second: read,
            write_per_second: write,
            auth_per_second: auth,
            max_tracked_tokens,
            ..McpConfig::default()
        }
    }

    fn limiter(read: u32, write: u32, auth: u32) -> (TokenRateLimiter, Arc<ManualClock>) {
        let clock = Arc::new(ManualClock::new(SystemTime::UNIX_EPOCH));
        (
            TokenRateLimiter::new(&config(read, write, auth, 8), clock.clone()),
            clock,
        )
    }

    fn tracked(limiter: &TokenRateLimiter) -> usize {
        limiter
            .state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .map
            .len()
    }

    #[test]
    fn burst_then_clock_refills_without_sleeping() {
        let (limiter, clock) = limiter(2, 2, 2);
        // A fresh bucket starts with one second of tokens (burst = 2).
        assert!(limiter.check("a", BucketClass::Read).is_ok());
        assert!(limiter.check("a", BucketClass::Read).is_ok());
        assert_eq!(limiter.check("a", BucketClass::Read), Err(1));
        // One clock second refills two tokens — no wall-clock wait.
        clock.advance(Duration::from_secs(1));
        assert!(limiter.check("a", BucketClass::Read).is_ok());
        assert!(limiter.check("a", BucketClass::Read).is_ok());
        assert!(limiter.check("a", BucketClass::Read).is_err());
    }

    #[test]
    fn buckets_are_independent() {
        let (limiter, _) = limiter(2, 2, 2);
        for _ in 0..2 {
            limiter.check("a", BucketClass::Read).unwrap();
        }
        assert!(limiter.check("a", BucketClass::Read).is_err());
        // The write and auth buckets for the same key are untouched.
        assert!(limiter.check("a", BucketClass::Write).is_ok());
        assert!(limiter.check("a", BucketClass::Auth).is_ok());
    }

    #[test]
    fn tokens_are_isolated_per_key() {
        let (limiter, _) = limiter(1, 1, 1);
        assert!(limiter.check("token-a", BucketClass::Read).is_ok());
        assert!(limiter.check("token-a", BucketClass::Read).is_err());
        // A second token has its own full bucket.
        assert!(limiter.check("token-b", BucketClass::Read).is_ok());
        assert!(limiter.check("token-b", BucketClass::Read).is_err());
    }

    #[test]
    fn lru_cap_bounds_tracked_keys() {
        let clock = Arc::new(ManualClock::new(SystemTime::UNIX_EPOCH));
        let limiter = TokenRateLimiter::new(&config(1, 1, 1, 3), clock);
        for key in ["a", "b", "c", "d", "e"] {
            limiter.check(key, BucketClass::Read).unwrap();
            assert!(tracked(&limiter) <= 3, "cap must hold");
        }
        assert_eq!(tracked(&limiter), 3);
    }
}
