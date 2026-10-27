//! Injectable time source (ADR-0005).
//!
//! The rate limiter refills token buckets from [`Clock`] rather than calling
//! `SystemTime::now()` directly, so tests can advance time without sleeping.
//! Per ADR-0005 every crate carries its own small clock copy; this crate has no
//! shared workspace clock dependency.

use std::fmt;
use std::time::SystemTime;

#[cfg(test)]
use std::sync::Mutex;
#[cfg(test)]
use std::time::Duration;

/// Source of wall-clock time.
pub(crate) trait Clock: Send + Sync + fmt::Debug {
    /// Current wall-clock time.
    fn now(&self) -> SystemTime;
}

/// The real system clock.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> SystemTime {
        SystemTime::now()
    }
}

/// A clock that only moves when told to; for tests.
#[cfg(test)]
#[derive(Debug)]
pub(crate) struct ManualClock {
    now: Mutex<SystemTime>,
}

#[cfg(test)]
impl ManualClock {
    /// Creates a clock frozen at `start`.
    pub(crate) fn new(start: SystemTime) -> Self {
        Self {
            now: Mutex::new(start),
        }
    }

    /// Moves the clock forward by `by`.
    pub(crate) fn advance(&self, by: Duration) {
        let mut now = self
            .now
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *now += by;
    }
}

#[cfg(test)]
impl Clock for ManualClock {
    fn now(&self) -> SystemTime {
        *self
            .now
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn manual_clock_advances() {
        let start = SystemTime::UNIX_EPOCH + Duration::from_secs(1000);
        let clock = ManualClock::new(start);
        assert_eq!(clock.now(), start);
        clock.advance(Duration::from_secs(5));
        assert_eq!(clock.now(), start + Duration::from_secs(5));
    }
}
