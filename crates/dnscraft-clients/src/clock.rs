//! Injectable time source so sync, retain and TTL logic can be tested
//! without sleeping.

use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use tokio::sync::Notify;

/// Source of wall-clock time.
pub trait Clock: Send + Sync + fmt::Debug {
    /// Current wall-clock time.
    fn now(&self) -> SystemTime;

    /// Optional wake signal fired when time jumps (see [`ManualClock`]).
    ///
    /// Schedulers wait on this instead of a real sleep so tests can drive the
    /// clock without blocking. [`SystemClock`] returns `None`.
    fn tick_notify(&self) -> Option<Arc<Notify>> {
        None
    }
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
    tick: Arc<Notify>,
}

impl ManualClock {
    /// Creates a clock frozen at `start`.
    pub fn new(start: SystemTime) -> Self {
        Self {
            now: Mutex::new(start),
            tick: Arc::new(Notify::new()),
        }
    }

    /// Moves the clock forward by `by` and wakes waiters.
    pub fn advance(&self, by: Duration) {
        let mut now = self
            .now
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *now += by;
        self.tick.notify_waiters();
    }

    /// Sets the clock to an absolute time and wakes waiters.
    pub fn set(&self, to: SystemTime) {
        *self
            .now
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = to;
        self.tick.notify_waiters();
    }
}

impl Clock for ManualClock {
    fn now(&self) -> SystemTime {
        *self
            .now
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn tick_notify(&self) -> Option<Arc<Notify>> {
        Some(Arc::clone(&self.tick))
    }
}

/// Waits until `clock.now() >= deadline`.
///
/// Uses [`Clock::tick_notify`] when present (manual clocks). Otherwise sleeps
/// for the remaining real time, also waking early when `extra` is notified
/// (`sync_now`, config changes).
pub async fn wait_until(clock: &dyn Clock, deadline: SystemTime, extra: &Notify) {
    let tick = clock.tick_notify();
    loop {
        // Register interest *before* reading the clock: a tick that lands
        // between the `now()` check and the wait would otherwise be lost.
        let extra_n = extra.notified();
        tokio::pin!(extra_n);
        extra_n.as_mut().enable();
        if let Some(tick) = tick.as_ref() {
            let tick_n = tick.notified();
            tokio::pin!(tick_n);
            tick_n.as_mut().enable();
            if clock.now() >= deadline {
                return;
            }
            tokio::select! {
                () = tick_n => {}
                () = extra_n => {}
            }
        } else {
            let now = clock.now();
            if now >= deadline {
                return;
            }
            let remaining = deadline.duration_since(now).unwrap_or(Duration::ZERO);
            tokio::select! {
                () = tokio::time::sleep(remaining) => {}
                () = extra_n => {}
            }
        }
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

    /// A clock that advances itself the first time it is read.
    #[derive(Debug)]
    struct RacyClock {
        inner: ManualClock,
        fired: std::sync::atomic::AtomicBool,
    }

    impl Clock for RacyClock {
        fn now(&self) -> SystemTime {
            let v = self.inner.now();
            if !self.fired.swap(true, std::sync::atomic::Ordering::SeqCst) {
                self.inner.advance(Duration::from_secs(10));
            }
            v
        }

        fn tick_notify(&self) -> Option<Arc<Notify>> {
            self.inner.tick_notify()
        }
    }

    #[tokio::test]
    async fn wait_until_does_not_miss_a_tick_between_check_and_wait() {
        let start = SystemTime::UNIX_EPOCH + Duration::from_secs(1000);
        let clock = RacyClock {
            inner: ManualClock::new(start),
            fired: std::sync::atomic::AtomicBool::new(false),
        };
        let extra = Notify::new();
        tokio::time::timeout(
            Duration::from_secs(5),
            wait_until(&clock, start + Duration::from_secs(5), &extra),
        )
        .await
        .expect("wait_until missed the tick");
    }
}
