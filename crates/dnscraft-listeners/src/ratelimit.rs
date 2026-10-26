//! Token buckets and an LRU-capped map for per-source / per-Client-ID rates.

use std::collections::{HashMap, VecDeque};
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
///
/// Eviction is **O(1) amortised**: a [`VecDeque`] records `(key, stamp)` on
/// every touch. The front of the queue is the oldest candidate; stale stamps
/// (a key was touched again) are skipped lazily. When the queue grows past
/// `2 × cap` it is compacted to live stamps only, so total work across `n`
/// operations stays linear.
#[derive(Debug)]
pub struct LruMap<K, V> {
    map: HashMap<K, (V, u64)>,
    /// Recency queue: front = oldest touch. Stale stamps are skipped on pop.
    order: VecDeque<(K, u64)>,
    cap: usize,
    tick: u64,
}

impl<K: Eq + Hash + Clone, V> LruMap<K, V> {
    /// Creates an empty map with the given capacity (at least 1).
    pub fn new(cap: usize) -> Self {
        Self {
            map: HashMap::new(),
            order: VecDeque::new(),
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

    fn record_touch(&mut self, key: &K, stamp: u64) {
        self.order.push_back((key.clone(), stamp));
        if self.order.len() > self.cap.saturating_mul(2) {
            self.compact_order();
        }
    }

    fn compact_order(&mut self) {
        let mut live = VecDeque::with_capacity(self.map.len());
        for (k, stamp) in self.order.drain(..) {
            if self.map.get(&k).is_some_and(|(_, s)| *s == stamp) {
                live.push_back((k, stamp));
            }
        }
        self.order = live;
    }

    fn evict_lru(&mut self) {
        while self.map.len() > self.cap {
            let Some((k, stamp)) = self.order.pop_front() else {
                break;
            };
            match self.map.get(&k) {
                Some((_, s)) if *s == stamp => {
                    self.map.remove(&k);
                }
                _ => {
                    // Stale stamp — key was re-touched or removed; skip.
                }
            }
        }
    }

    /// Inserts or replaces `key`, marking it most-recent; may evict another key.
    pub fn insert(&mut self, key: K, value: V) {
        let stamp = self.touch();
        self.map.insert(key.clone(), (value, stamp));
        self.record_touch(&key, stamp);
        self.evict_lru();
    }

    /// Takes the value for `key`, or `None` if absent.
    ///
    /// The entry is removed; the caller should [`insert`] it again after mutation
    /// so capacity accounting stays correct. Queue stamps for `key` become stale
    /// and are skipped on later eviction.
    pub fn take(&mut self, key: &K) -> Option<V> {
        self.map.remove(key).map(|(v, _)| v)
    }

    /// Returns a mutable reference, refreshing LRU order. `None` if absent.
    pub fn get_mut(&mut self, key: &K) -> Option<&mut V> {
        if !self.map.contains_key(key) {
            return None;
        }
        let stamp = self.touch();
        if let Some((_, s)) = self.map.get_mut(key) {
            *s = stamp;
        }
        self.record_touch(key, stamp);
        self.map.get_mut(key).map(|(v, _)| v)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn insert_evicts_oldest_at_cap() {
        let mut m = LruMap::new(2);
        m.insert(1, "a");
        m.insert(2, "b");
        m.insert(3, "c");
        assert_eq!(m.len(), 2);
        assert!(m.take(&1).is_none());
        assert_eq!(m.take(&2), Some("b"));
        assert_eq!(m.take(&3), Some("c"));
    }

    #[test]
    fn get_mut_refreshes_recency() {
        let mut m = LruMap::new(2);
        m.insert(1, 10);
        m.insert(2, 20);
        assert_eq!(m.get_mut(&1).copied(), Some(10));
        m.insert(3, 30);
        // 2 is oldest after touching 1.
        assert!(m.take(&2).is_none());
        assert_eq!(m.take(&1), Some(10));
        assert_eq!(m.take(&3), Some(30));
    }

    #[test]
    fn large_cap_insert_batch_stays_bounded() {
        const CAP: usize = 100_000;
        let mut m = LruMap::new(CAP);
        for i in 0..10_000u32 {
            m.insert(i, i);
        }
        assert_eq!(m.len(), 10_000);
        assert!(m.order.len() <= CAP * 2);
        // Fill past cap and ensure we never exceed it.
        for i in 10_000..CAP as u32 + 5_000 {
            m.insert(i, i);
            assert!(m.len() <= CAP);
        }
        assert_eq!(m.len(), CAP);
    }
}
