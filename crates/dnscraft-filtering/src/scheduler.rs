//! Periodic list-update loop driven by an injectable [`Clock`].
//!
//! The interval comes from [`FilterConfig::update_interval`](crate::FilterConfig)
//! (default 24 h) with ±10 % jitter. Tests advance a [`ManualClock`] and never
//! sleep wall time; production uses [`SystemClock`](crate::SystemClock) sleeps
//! interrupted by [`UpdateScheduler::kick`] for "update now".

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Weak};
use std::time::Duration;

use tokio::sync::Notify;
use tokio::task::JoinHandle;

use crate::clock::{self, Clock};
use crate::engine::{FilterEngine, ListSelection, ListStatus};
use crate::set::DEFAULT_UPDATE_INTERVAL;
use dnscraft_common::config::jittered;

/// Delay before the first retry after a failed update round. Each further
/// consecutive failure doubles it, up to the regular update interval.
pub(crate) const RETRY_BASE: Duration = Duration::from_secs(5 * 60);

/// Delay before the next round, given the number of consecutive failed rounds
/// (`0` means the last round was clean and the regular `interval` applies).
pub(crate) fn next_round_delay(interval: Duration, failures: u32) -> Duration {
    if failures == 0 {
        return interval;
    }
    let factor = 2u32.saturating_pow((failures - 1).min(16));
    RETRY_BASE.saturating_mul(factor).min(interval)
}

/// A round failed when any list reported an error or the services catalog
/// is currently in error (fetch, validation or cache).
fn round_failed(engine: &FilterEngine, statuses: &[ListStatus]) -> bool {
    statuses.iter().any(|s| s.error_code.is_some()) || engine.services_last_error().is_some()
}

/// Runs `update_lists(All)` on a jittered interval until [`UpdateScheduler::stop`],
/// the scheduler is dropped, or the engine is gone.
#[derive(Debug)]
pub struct UpdateScheduler {
    tick: Arc<Notify>,
    stop: Arc<AtomicBool>,
    handle: std::sync::Mutex<Option<JoinHandle<()>>>,
}

impl Drop for UpdateScheduler {
    fn drop(&mut self) {
        let handle = self
            .handle
            .get_mut()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        if let Some(h) = handle {
            h.abort();
        }
    }
}

impl UpdateScheduler {
    /// Starts the loop on the current Tokio runtime.
    ///
    /// The task holds only a weak reference to `engine`, so storing the
    /// scheduler inside the engine creates no reference cycle. Dropping the
    /// scheduler aborts the task.
    pub fn start(engine: &Arc<FilterEngine>, clock: Arc<dyn Clock>) -> Self {
        let engine = Arc::downgrade(engine);
        let tick = Arc::new(Notify::new());
        let stop = Arc::new(AtomicBool::new(false));
        let tick_loop = Arc::clone(&tick);
        let stop_loop = Arc::clone(&stop);
        let handle = tokio::spawn(async move {
            run_loop(engine, clock, tick_loop, stop_loop).await;
        });
        Self {
            tick,
            stop,
            handle: std::sync::Mutex::new(Some(handle)),
        }
    }

    /// Wakes the loop early. A kick that arrives while the loop is busy is
    /// remembered (one permit) instead of being dropped.
    pub fn kick(&self) {
        self.tick.notify_one();
    }

    /// Asks the loop to exit and waits for it (best-effort).
    pub async fn stop(&self) {
        self.stop.store(true, Ordering::SeqCst);
        self.tick.notify_waiters();
        let handle = self
            .handle
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        if let Some(h) = handle {
            let _ = h.await;
        }
    }
}

/// The loop only holds a [`Weak`] handle while it waits, so it never keeps the
/// engine alive; it exits as soon as the engine is gone.
async fn run_loop(
    engine: Weak<FilterEngine>,
    clock: Arc<dyn Clock>,
    tick: Arc<Notify>,
    stop: Arc<AtomicBool>,
) {
    // First scheduled wait happens after one interval; callers that need an
    // immediate refresh use `update_lists` / `update_now` themselves.
    let mut failures: u32 = 0;
    loop {
        if stop.load(Ordering::SeqCst) {
            return;
        }
        let Some(interval) = engine.upgrade().map(|e| e.update_interval()) else {
            return;
        };
        let base = if interval.is_zero() {
            DEFAULT_UPDATE_INTERVAL
        } else {
            interval
        };
        let wait =
            jittered(next_round_delay(base, failures), clock.now()).max(Duration::from_secs(1));
        let deadline = clock.now() + wait;
        clock::wait_until(clock.as_ref(), deadline, tick.as_ref()).await;
        if stop.load(Ordering::SeqCst) {
            return;
        }
        let Some(eng) = engine.upgrade() else {
            return;
        };
        let statuses = eng.update_lists(ListSelection::All).await;
        eng.update_trackers().await;
        failures = if round_failed(&eng, &statuses) {
            failures.saturating_add(1)
        } else {
            0
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retry_delay_doubles_and_is_capped_by_the_interval() {
        let day = Duration::from_secs(24 * 3600);
        assert_eq!(next_round_delay(day, 0), day);
        assert_eq!(next_round_delay(day, 1), Duration::from_secs(300));
        assert_eq!(next_round_delay(day, 2), Duration::from_secs(600));
        assert_eq!(next_round_delay(day, 3), Duration::from_secs(1200));
        assert_eq!(next_round_delay(day, 200), day);
        let hour = Duration::from_secs(3600);
        assert_eq!(next_round_delay(hour, 2), Duration::from_secs(600));
        assert_eq!(next_round_delay(hour, 9), hour);
    }
}
