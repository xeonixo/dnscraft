//! Certificate renewal scheduling (ARI / renew_before) and backoff.
//!
//! Pure planners are unit-tested with [`crate::ManualClock`]. The async
//! [`RenewScheduler`] loop calls an injected renew callback so tests never
//! hit ACME or Cloudflare.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, SystemTime};

use rand::{Rng, RngExt};
use tokio::sync::Notify;
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

use crate::acme::AcmeOrder;
use crate::clock::Clock;
use crate::config::{AcmeConfig, TlsConfig};
use crate::error::TlsError;
use crate::status::{TlsStatus, cert_flags};
use crate::store::CertStore;

/// Cap for exponential renew backoff (6 hours).
pub const BACKOFF_CAP: Duration = Duration::from_secs(6 * 3600);
/// Initial backoff before the first retry.
pub const BACKOFF_BASE: Duration = Duration::from_secs(30);

/// Suggested ARI renewal window (RFC 9773).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AriWindow {
    /// Inclusive start of the suggested window.
    pub start: SystemTime,
    /// End of the window; the picked instant is in `[start, end]`.
    pub end: SystemTime,
}

/// When the next renew/issue should run.
///
/// - No certificate → `now` (issue immediately).
/// - ARI window present → uniform random instant in `[start, end]` (clamped so
///   it is not before `now` when the window is still open; if the whole window
///   is in the past → `now`).
/// - Otherwise → `not_after - renew_before`, or `now` if that instant has passed.
pub fn next_renewal(
    not_after: Option<SystemTime>,
    renew_before: Duration,
    ari: Option<AriWindow>,
    now: SystemTime,
) -> SystemTime {
    next_renewal_with_rng(not_after, renew_before, ari, now, &mut rand::rng())
}

/// Like [`next_renewal`] but with an injectable RNG (table tests).
pub fn next_renewal_with_rng(
    not_after: Option<SystemTime>,
    renew_before: Duration,
    ari: Option<AriWindow>,
    now: SystemTime,
    rng: &mut impl Rng,
) -> SystemTime {
    let Some(not_after) = not_after else {
        return now;
    };

    if let Some(window) = ari {
        return pick_ari(window, now, rng);
    }

    let target = not_after
        .checked_sub(renew_before)
        .unwrap_or(SystemTime::UNIX_EPOCH);
    if target <= now { now } else { target }
}

fn pick_ari(window: AriWindow, now: SystemTime, rng: &mut impl Rng) -> SystemTime {
    let start = window.start.max(now);
    if window.end <= start {
        return now;
    }
    let span = window
        .end
        .duration_since(start)
        .unwrap_or(Duration::ZERO)
        .as_secs();
    if span == 0 {
        return start;
    }
    let offset = rng.random_range(0..=span);
    start + Duration::from_secs(offset)
}

/// Fetches the CA's ARI window for the certificate currently in `store`.
///
/// `None` when there is no (readable) certificate, the CA has no ARI, or the
/// request fails — ARI never fails renewal.
pub async fn current_ari_window<A>(
    acme: &A,
    store: &CertStore,
    cfg: &AcmeConfig,
) -> Option<AriWindow>
where
    A: AcmeOrder + ?Sized,
{
    let loaded = store.load().ok().flatten()?;
    acme.renewal_window(store, cfg, &loaded.chain_pem).await
}

/// Computes when the stored certificate should next be renewed, consulting ARI.
///
/// This is the async half of the schedule input: [`ScheduleFn`] is synchronous,
/// so L10 should call this after startup and after every successful renewal
/// (and periodically, since the CA may move the window), cache the returned
/// instant or the window from [`current_ari_window`], and have its `ScheduleFn`
/// return `next_renewal(not_after, cfg.renew_before, cached_window, now)`.
/// No certificate → `now`.
pub async fn plan_renewal<A>(
    acme: &A,
    store: &CertStore,
    cfg: &TlsConfig,
    now: SystemTime,
) -> SystemTime
where
    A: AcmeOrder + ?Sized,
{
    let Some(loaded) = store.load().ok().flatten() else {
        return now;
    };
    let ari = acme
        .renewal_window(store, &cfg.acme, &loaded.chain_pem)
        .await;
    next_renewal(Some(loaded.not_after), cfg.renew_before, ari, now)
}

/// Delay before the next renew attempt after a transient failure.
///
/// Exponential from [`BACKOFF_BASE`] with ±25 % jitter, capped at
/// [`BACKOFF_CAP`]. When `retry_after` is set (from `Retry-After`), the delay
/// is at least that long.
pub fn backoff_delay(attempt: u32, retry_after: Option<Duration>) -> Duration {
    backoff_delay_with_rng(attempt, retry_after, &mut rand::rng())
}

/// Like [`backoff_delay`] with injectable RNG.
pub fn backoff_delay_with_rng(
    attempt: u32,
    retry_after: Option<Duration>,
    rng: &mut impl Rng,
) -> Duration {
    let exp = attempt.min(20);
    let base_secs = BACKOFF_BASE.as_secs().saturating_mul(1u64 << exp);
    let capped = base_secs.min(BACKOFF_CAP.as_secs());
    let jitter_span = (capped / 4).max(1);
    let low = capped.saturating_sub(jitter_span);
    let high = capped
        .saturating_add(jitter_span)
        .min(BACKOFF_CAP.as_secs());
    let mut secs = if low >= high {
        capped
    } else {
        rng.random_range(low..=high)
    };
    if let Some(ra) = retry_after {
        secs = secs.max(ra.as_secs());
    }
    Duration::from_secs(secs.min(BACKOFF_CAP.as_secs()))
}

/// Whether a renew failure should be retried with backoff.
pub fn is_transient_renew_error(err: &TlsError) -> bool {
    matches!(
        err,
        TlsError::AcmePropagation
            | TlsError::AcmeRateLimited { .. }
            | TlsError::CloudflareHttp { .. }
            | TlsError::AcmeOrder { .. }
            | TlsError::AcmeChallenge { .. }
            | TlsError::AcmeAccount { .. }
    )
}

/// Boxed renew future returned by [`RenewFn`].
pub type RenewFut = Pin<Box<dyn Future<Output = Result<(), TlsError>> + Send>>;
/// Callback that performs one renew/issue attempt.
pub type RenewFn = Arc<dyn Fn() -> RenewFut + Send + Sync>;
/// Callback that builds a status snapshot.
pub type StatusFn = Arc<dyn Fn() -> TlsStatus + Send + Sync>;
/// Maps `now` → next renew instant.
pub type ScheduleFn = Arc<dyn Fn(SystemTime) -> SystemTime + Send + Sync>;

/// Background renew loop driven by [`Clock`].
///
/// When ACME is disabled the loop only refreshes status and never invokes the
/// renew callback. `kick` forces an immediate attempt (if ACME is enabled).
pub struct RenewScheduler {
    tick: Arc<Notify>,
    stop: Arc<AtomicBool>,
    handle: std::sync::Mutex<Option<JoinHandle<()>>>,
}

impl Drop for RenewScheduler {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        self.tick.notify_waiters();
        if let Some(h) = self
            .handle
            .get_mut()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
        {
            h.abort();
        }
    }
}

impl RenewScheduler {
    /// Starts the renew loop on the current Tokio runtime.
    pub fn start(
        clock: Arc<dyn Clock>,
        acme_enabled: Arc<AtomicBool>,
        schedule: ScheduleFn,
        renew: RenewFn,
        on_status: StatusFn,
    ) -> Self {
        let tick = Arc::new(Notify::new());
        let stop = Arc::new(AtomicBool::new(false));
        let tick_loop = Arc::clone(&tick);
        let stop_loop = Arc::clone(&stop);
        let handle = tokio::spawn(async move {
            run_loop(
                clock,
                acme_enabled,
                schedule,
                renew,
                on_status,
                tick_loop,
                stop_loop,
            )
            .await;
        });
        Self {
            tick,
            stop,
            handle: std::sync::Mutex::new(Some(handle)),
        }
    }

    /// Wakes the loop early (renew-now / config change).
    pub fn kick(&self) {
        self.tick.notify_one();
    }

    /// Asks the loop to exit and waits for it.
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
    clock: Arc<dyn Clock>,
    acme_enabled: Arc<AtomicBool>,
    schedule: ScheduleFn,
    renew: RenewFn,
    on_status: StatusFn,
    tick: Arc<Notify>,
    stop: Arc<AtomicBool>,
) {
    let mut attempt: u32 = 0;
    loop {
        if stop.load(Ordering::SeqCst) {
            return;
        }
        let _ = on_status();

        if !acme_enabled.load(Ordering::SeqCst) {
            let deadline = clock.now() + Duration::from_secs(24 * 3600);
            wait_or_kick(clock.as_ref(), deadline, &tick, &stop).await;
            continue;
        }

        let now = clock.now();
        let due = schedule(now);
        if due > now {
            wait_or_kick(clock.as_ref(), due, &tick, &stop).await;
            if stop.load(Ordering::SeqCst) {
                return;
            }
        }

        if !acme_enabled.load(Ordering::SeqCst) {
            continue;
        }

        info!("renewal attempt starting");
        match renew().await {
            Ok(()) => {
                attempt = 0;
                debug!("renewal succeeded");
                let _ = on_status();
                let next = schedule(clock.now());
                let wake = if next > clock.now() {
                    next
                } else {
                    // Avoid busy-loop when schedule still says "due now".
                    clock.now() + BACKOFF_CAP
                };
                wait_or_kick(clock.as_ref(), wake, &tick, &stop).await;
            }
            Err(err) => {
                warn!(code = err.code(), "renewal failed: {err}");
                let _ = on_status();
                if !is_transient_renew_error(&err) {
                    attempt = 0;
                    let next = schedule(clock.now());
                    wait_or_kick(
                        clock.as_ref(),
                        next.max(clock.now() + BACKOFF_BASE),
                        &tick,
                        &stop,
                    )
                    .await;
                    continue;
                }
                let delay = backoff_delay(attempt, err.retry_after());
                attempt = attempt.saturating_add(1);
                let wake = clock.now() + delay;
                wait_or_kick(clock.as_ref(), wake, &tick, &stop).await;
            }
        }
    }
}

async fn wait_or_kick(clock: &dyn Clock, deadline: SystemTime, tick: &Notify, stop: &AtomicBool) {
    loop {
        if stop.load(Ordering::SeqCst) || clock.now() >= deadline {
            return;
        }
        let kick = tick.notified();
        tokio::pin!(kick);
        kick.as_mut().enable();
        if let Some(clock_tick) = clock.tick_notify() {
            let t = clock_tick.notified();
            tokio::pin!(t);
            t.as_mut().enable();
            if clock.now() >= deadline {
                return;
            }
            tokio::select! {
                () = t => {}
                () = kick => return,
            }
        } else {
            let now = clock.now();
            if now >= deadline {
                return;
            }
            let remaining = deadline.duration_since(now).unwrap_or(Duration::ZERO);
            tokio::select! {
                () = tokio::time::sleep(remaining) => return,
                () = kick => return,
            }
        }
    }
}

/// Convenience: refresh expiring/expired flags on a status value in place.
pub fn apply_cert_flags(status: &mut TlsStatus, now: SystemTime, expiry_warn: Duration) {
    if let Some(not_after) = status.not_after {
        let (expiring, expired) = cert_flags(not_after, now, expiry_warn);
        status.cert_expiring = expiring;
        status.cert_expired = expired;
        status.days_to_expiry = Some(match not_after.duration_since(now) {
            Ok(d) => (d.as_secs() / 86_400) as i64,
            Err(e) => -((e.duration().as_secs() / 86_400) as i64),
        });
    } else {
        status.cert_expiring = false;
        status.cert_expired = false;
        status.days_to_expiry = None;
    }
}
