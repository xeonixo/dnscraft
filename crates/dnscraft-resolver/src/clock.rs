//! Injectable time source so TTL, cache, and RRSIG validity logic can be tested
//! without sleeping.

use std::fmt;
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime};

/// Source of wall-clock and monotonic time.
pub trait Clock: Send + Sync + fmt::Debug {
    /// Wall-clock time (used for RRSIG validity windows).
    fn now(&self) -> SystemTime;
    /// Monotonic time (used for TTL expiry and RTT measurements).
    fn instant(&self) -> Instant;
}

/// The real system clock.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> SystemTime {
        SystemTime::now()
    }

    fn instant(&self) -> Instant {
        Instant::now()
    }
}

/// A clock that only moves when told to; for tests.
#[doc(hidden)]
#[derive(Debug)]
pub struct ManualClock {
    base_system: SystemTime,
    base_instant: Instant,
    offset: Mutex<Duration>,
}

impl ManualClock {
    /// Creates a clock frozen at `start` (wall-clock) and "now" (monotonic).
    pub fn new(start: SystemTime) -> Self {
        Self {
            base_system: start,
            base_instant: Instant::now(),
            offset: Mutex::new(Duration::ZERO),
        }
    }

    /// Moves both clocks forward by `by`.
    pub fn advance(&self, by: Duration) {
        let mut offset = self
            .offset
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *offset += by;
    }

    fn offset(&self) -> Duration {
        *self
            .offset
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

impl Clock for ManualClock {
    fn now(&self) -> SystemTime {
        self.base_system + self.offset()
    }

    fn instant(&self) -> Instant {
        self.base_instant + self.offset()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manual_clock_advances() {
        let start = SystemTime::UNIX_EPOCH + Duration::from_secs(1000);
        let clock = ManualClock::new(start);
        let i0 = clock.instant();
        clock.advance(Duration::from_secs(5));
        assert_eq!(clock.now(), start + Duration::from_secs(5));
        assert_eq!(clock.instant() - i0, Duration::from_secs(5));
    }
}
