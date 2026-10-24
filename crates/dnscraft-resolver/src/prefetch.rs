//! Prefetch: refresh a popular cache entry shortly before it expires.
//!
//! An entry is popular once it has been served from the cache at least
//! [`POPULAR_HITS`] times since it was stored. The insert itself does not
//! count; the hit that observes the near-expiry window does.
//!
//! It is near expiry when the time remaining is at most the larger of one
//! tenth of the stored TTL and [`MIN_WINDOW`]. The floor keeps a short TTL
//! from opening a window too small to hide the refresh round trip. A longer
//! TTL uses the fraction, so a one-day entry is not refreshed minutes after
//! it was stored.
//!
//! The decision is pure. The resolver starts at most one background refresh
//! per key and still returns the cached answer to the client.

use std::time::Duration;

use crate::cache::FreshStats;

/// Fresh cache hits required before a near-expiry entry is refreshed.
pub(crate) const POPULAR_HITS: u64 = 3;

/// Smallest prefetch window.
pub(crate) const MIN_WINDOW: Duration = Duration::from_secs(2);

/// Whether `stats` should be refreshed in the background.
pub(crate) fn should_refresh(stats: FreshStats) -> bool {
    if stats.hits < POPULAR_HITS {
        return false;
    }
    let window = (stats.ttl / 10).max(MIN_WINDOW);
    stats.remaining <= window
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stats(hits: u64, ttl: u64, remaining_secs: u64) -> FreshStats {
        FreshStats {
            hits,
            ttl: Duration::from_secs(ttl),
            remaining: Duration::from_secs(remaining_secs),
        }
    }

    #[test]
    fn popular_entry_at_the_fractional_window_is_due() {
        // 10% of 100s is 10s, above the 2s floor. The edge is included.
        assert!(should_refresh(stats(POPULAR_HITS, 100, 10)));
        assert!(!should_refresh(FreshStats {
            hits: POPULAR_HITS,
            ttl: Duration::from_secs(100),
            remaining: Duration::from_secs(10) + Duration::from_nanos(1),
        }));
    }

    #[test]
    fn unpopular_and_fresh_entries_are_not_due() {
        assert!(!should_refresh(stats(POPULAR_HITS - 1, 100, 0)));
        assert!(!should_refresh(stats(POPULAR_HITS, 100, 11)));
    }

    #[test]
    fn short_ttls_use_the_minimum_window() {
        // 10% of 5s truncates to zero, so the floor of 2s applies.
        assert!(should_refresh(stats(POPULAR_HITS, 5, 2)));
        assert!(!should_refresh(stats(POPULAR_HITS, 5, 3)));
    }
}
