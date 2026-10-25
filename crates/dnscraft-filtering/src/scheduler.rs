//! Periodic list-update loop driven by an injectable [`Clock`].
//!
//! The interval comes from [`FilterConfig::update_interval`](crate::FilterConfig)
//! (default 24 h) with ±10 % jitter. Tests advance a [`ManualClock`] and never
//! sleep wall time; production uses [`SystemClock`](crate::SystemClock) sleeps
//! interrupted by [`UpdateScheduler::kick`] for "update now".

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use tokio::sync::Notify;
use tokio::task::JoinHandle;

use crate::clock::{self, Clock};
use crate::engine::{FilterEngine, ListSelection};
use crate::set::DEFAULT_UPDATE_INTERVAL;

/// Runs `update_lists(All)` on a jittered interval until [`UpdateScheduler::stop`].
#[derive(Debug)]
pub struct UpdateScheduler {
    tick: Arc<Notify>,
    stop: Arc<AtomicBool>,
    handle: std::sync::Mutex<Option<JoinHandle<()>>>,
}

impl UpdateScheduler {
    /// Starts the loop on the current Tokio runtime.
    pub fn start(engine: Arc<FilterEngine>, clock: Arc<dyn Clock>) -> Self {
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

    /// Wakes the loop early (manual "update now" or config change).
    pub fn kick(&self) {
        self.tick.notify_waiters();
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

async fn run_loop(
    engine: Arc<FilterEngine>,
    clock: Arc<dyn Clock>,
    tick: Arc<Notify>,
    stop: Arc<AtomicBool>,
) {
    // First scheduled wait happens after one interval; callers that need an
    // immediate refresh use `update_lists` / `kick` themselves.
    loop {
        if stop.load(Ordering::SeqCst) {
            return;
        }
        let interval = engine.update_interval();
        let wait = jittered(interval, clock.now());
        let deadline = clock.now() + wait;
        clock::wait_until(clock.as_ref(), deadline, tick.as_ref()).await;
        if stop.load(Ordering::SeqCst) {
            return;
        }
        let _ = engine.update_lists(ListSelection::All).await;
    }
}

/// Interval ±10 %, never below one second.
pub(crate) fn jittered(base: Duration, salt: std::time::SystemTime) -> Duration {
    let base = if base.is_zero() {
        DEFAULT_UPDATE_INTERVAL
    } else {
        base
    };
    let nanos = base.as_nanos().min(u128::from(u64::MAX)) as u64;
    let span = nanos / 10;
    let mix = salt
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
        .wrapping_mul(0x9E37_79B9_7F4A_7C15);
    // Map high bits to [-span, +span].
    let signed = (mix as i64) >> 32;
    let max = span as i64;
    let delta = if max == 0 {
        0
    } else {
        signed.rem_euclid(max.saturating_mul(2).saturating_add(1)) - max
    };
    let adjusted = nanos.saturating_add_signed(delta).max(1_000_000_000);
    Duration::from_nanos(adjusted)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use std::time::{Duration, SystemTime};

    #[test]
    fn jitter_stays_within_ten_percent() {
        let base = Duration::from_secs(1000);
        for i in 0..50 {
            let salt = SystemTime::UNIX_EPOCH + Duration::from_secs(i * 17);
            let j = jittered(base, salt);
            assert!(j >= Duration::from_secs(900), "{j:?}");
            assert!(j <= Duration::from_secs(1100), "{j:?}");
        }
    }
}
