//! Injectable time source (ADR-0005) so storage timestamps can be tested without
//! wall-clock time.
//!
//! The control-api crate carries its own small [`Clock`] copy, as every crate
//! does per [ADR-0005](../../docs/adr/0005-injectable-clock.md) — there is no
//! shared workspace clock crate.

use std::fmt;
use std::sync::Mutex;
use std::time::{Duration, SystemTime};

/// Source of wall-clock time.
pub trait Clock: Send + Sync + fmt::Debug {
    /// Current wall-clock time.
    fn now(&self) -> SystemTime;
}

/// The real system clock.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> SystemTime {
        SystemTime::now()
    }
}

/// A clock that only moves when told to; for tests.
#[derive(Debug)]
pub struct ManualClock {
    now: Mutex<SystemTime>,
}

impl ManualClock {
    /// Creates a clock frozen at `start`.
    pub fn new(start: SystemTime) -> Self {
        Self {
            now: Mutex::new(start),
        }
    }

    /// Moves the clock forward by `by`.
    pub fn advance(&self, by: Duration) {
        let mut now = self
            .now
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *now += by;
    }

    /// Sets the clock to an absolute time.
    pub fn set(&self, to: SystemTime) {
        *self
            .now
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = to;
    }
}

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
    fn manual_clock_advances_and_sets() {
        let start = SystemTime::UNIX_EPOCH + Duration::from_secs(1000);
        let clock = ManualClock::new(start);
        assert_eq!(clock.now(), start);
        clock.advance(Duration::from_secs(5));
        assert_eq!(clock.now(), start + Duration::from_secs(5));
        clock.set(SystemTime::UNIX_EPOCH);
        assert_eq!(clock.now(), SystemTime::UNIX_EPOCH);
    }

    #[test]
    fn system_clock_is_after_epoch() {
        assert!(SystemClock.now() > SystemTime::UNIX_EPOCH);
    }
}
