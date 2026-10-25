//! Token buckets and an LRU-capped map for per-source / per-Client-ID rates.

use std::collections::HashMap;
use std::hash::Hash;
use std::time::{Duration, SystemTime};

use crate::config::TokenRate;

/// One token bucket (rate + burst from config).
#[derive(Clone, Debug)]
pub struct TokenBucket {
    tokens: f64,
    last: SystemTime,
    rate_per_sec: f64,
    burst: f64,
}

impl TokenBucket {
    /// Full bucket at `now`.
    pub fn new(rate: TokenRate, now: SystemTime) -> Self {
        let burst = f64::from(rate.burst);
        Self {
            tokens: burst,
            last: now,
            rate_per_sec: f64::from(rate.per_second),
            burst,
        }
    }

    /// Refills from `last` to `now`, then tries to consume one token.
    ///
    /// Returns `true` if the token was taken.
    pub fn try_take(&mut self, now: SystemTime) -> bool {
        self.refill(now);
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    fn refill(&mut self, now: SystemTime) {
        let elapsed = now
            .duration_since(self.last)
            .unwrap_or(Duration::ZERO)
            .as_secs_f64();
        if elapsed > 0.0 {
            self.tokens = (self.tokens + elapsed * self.rate_per_sec).min(self.burst);
            self.last = now;
        }
    }
}

/// LRU-bounded map: at most `cap` entries; insert/get refreshes recency;
/// when over capacity the least-recently-used entry is evicted.
#[derive(Debug)]
pub struct LruMap<K, V> {
    map: HashMap<K, (V, u64)>,
    cap: usize,
    tick: u64,
}

impl<K: Eq + Hash + Clone, V> LruMap<K, V> {
    /// Creates an empty map with the given capacity (at least 1).
    pub fn new(cap: usize) -> Self {
        Self {
            map: HashMap::new(),
            cap: cap.max(1),
            tick: 0,
        }
    }

    /// Current number of entries.
    pub fn len(&self) -> usize {
        self.map.len()
    }

    fn touch(&mut self) -> u64 {
        self.tick = self.tick.wrapping_add(1);
        self.tick
    }

    fn evict_lru(&mut self) {
        while self.map.len() > self.cap {
            let victim = self
                .map
                .iter()
                .min_by_key(|(_, (_, stamp))| *stamp)
                .map(|(k, _)| k.clone());
            if let Some(k) = victim {
                self.map.remove(&k);
            } else {
                break;
            }
        }
    }

    /// Inserts or replaces `key`, marking it most-recent; may evict another key.
    pub fn insert(&mut self, key: K, value: V) {
        let stamp = self.touch();
        self.map.insert(key, (value, stamp));
        self.evict_lru();
    }

    /// Takes the value for `key`, or `None` if absent.
    ///
    /// The entry is removed; the caller should [`insert`] it again after mutation
    /// so capacity accounting stays correct.
    pub fn take(&mut self, key: &K) -> Option<V> {
        self.map.remove(key).map(|(v, _)| v)
    }

    /// Returns a mutable reference, refreshing LRU order. `None` if absent.
    pub fn get_mut(&mut self, key: &K) -> Option<&mut V> {
        let stamp = self.touch();
        let entry = self.map.get_mut(key)?;
        entry.1 = stamp;
        Some(&mut entry.0)
    }
}
