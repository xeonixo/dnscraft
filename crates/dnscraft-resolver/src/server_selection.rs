//! Server selection: smoothed RTT per address, exploration and IPv6
//! availability tracking.

use std::collections::HashMap;
use std::io::ErrorKind;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use rand::Rng;

/// Smoothing: `srtt = KEEP * old + (1 - KEEP) * sample`.
const KEEP: f64 = 0.7;
/// Penalty floor in ms, so that doubling a tiny srtt still matters.
const PENALTY_FLOOR_MS: f64 = 50.0;
/// Upper bound of any srtt in ms.
const SRTT_CAP_MS: f64 = 8000.0;
/// Unknown servers start with a random srtt in this range (ms); small, so
/// every server gets tried early.
const INITIAL_RANGE_MS: std::ops::Range<f64> = 1.0..10.0;
/// Default probability of putting a random candidate first.
const DEFAULT_EXPLORATION: f64 = 0.05;
/// Default time IPv6 stays disabled after a network-unreachable error.
pub const DEFAULT_IPV6_COOLDOWN: Duration = Duration::from_secs(60);

#[derive(Debug)]
struct Inner {
    srtt_ms: HashMap<SocketAddr, f64>,
    ipv6_down_until: Option<Instant>,
}

/// Shared per-server statistics. Cheap to clone (handles share state).
#[derive(Clone, Debug)]
pub struct ServerStats {
    inner: Arc<Mutex<Inner>>,
    exploration: f64,
    ipv6_cooldown: Duration,
}

impl Default for ServerStats {
    fn default() -> Self {
        Self::new(DEFAULT_IPV6_COOLDOWN)
    }
}

impl ServerStats {
    pub fn new(ipv6_cooldown: Duration) -> Self {
        Self {
            inner: Arc::new(Mutex::new(Inner {
                srtt_ms: HashMap::new(),
                ipv6_down_until: None,
            })),
            exploration: DEFAULT_EXPLORATION,
            ipv6_cooldown,
        }
    }

    /// Sets the probability (0.0..=1.0) that [`ServerStats::order`] moves a
    /// random candidate to the front. Tests use 0.0 for determinism.
    pub fn with_exploration(mut self, probability: f64) -> Self {
        self.exploration = probability.clamp(0.0, 1.0);
        self
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Current smoothed RTT of `server`, `None` if it was never seen.
    pub fn srtt(&self, server: SocketAddr) -> Option<Duration> {
        self.lock()
            .srtt_ms
            .get(&server)
            .map(|ms| Duration::from_secs_f64(ms / 1000.0))
    }

    /// Whether IPv6 is currently considered usable.
    pub fn ipv6_available(&self) -> bool {
        self.lock()
            .ipv6_down_until
            .is_none_or(|until| Instant::now() >= until)
    }

    /// Marks IPv6 unusable for the cool-down period.
    pub fn mark_ipv6_unavailable(&self) {
        self.lock().ipv6_down_until = Some(Instant::now() + self.ipv6_cooldown);
    }

    /// Records a successful exchange.
    pub fn record_success(&self, server: SocketAddr, rtt: Duration) {
        let sample = (rtt.as_secs_f64() * 1000.0).min(SRTT_CAP_MS);
        let mut inner = self.lock();
        let old = *inner
            .srtt_ms
            .entry(server)
            .or_insert_with(|| rand::rng().random_range(INITIAL_RANGE_MS));
        inner
            .srtt_ms
            .insert(server, KEEP * old + (1.0 - KEEP) * sample);
    }

    /// Records a timeout or other failure: doubles the srtt (capped).
    pub fn record_failure(&self, server: SocketAddr) {
        let mut inner = self.lock();
        let old = *inner
            .srtt_ms
            .entry(server)
            .or_insert_with(|| rand::rng().random_range(INITIAL_RANGE_MS));
        inner
            .srtt_ms
            .insert(server, (old.max(PENALTY_FLOOR_MS) * 2.0).min(SRTT_CAP_MS));
    }

    /// Records a socket error: penalises the server and, for IPv6 servers
    /// with a network-unreachable style error, disables IPv6 for a while.
    pub fn record_io_error(&self, server: SocketAddr, err: &std::io::Error) {
        if server.is_ipv6() && is_unreachable(err) {
            self.mark_ipv6_unavailable();
        }
        self.record_failure(server);
    }

    /// Orders `candidates` best first: ascending srtt (unknown servers get a
    /// small random initial value). While IPv6 is marked unavailable, IPv6
    /// addresses go last (they stay in the list as a last resort). With the
    /// exploration probability a random candidate is moved to the front.
    pub fn order(&self, candidates: &[SocketAddr]) -> Vec<SocketAddr> {
        let v6_ok = self.ipv6_available();
        let mut keyed: Vec<(bool, f64, SocketAddr)> = {
            let mut inner = self.lock();
            candidates
                .iter()
                .map(|&c| {
                    let srtt = *inner
                        .srtt_ms
                        .entry(c)
                        .or_insert_with(|| rand::rng().random_range(INITIAL_RANGE_MS));
                    (c.is_ipv6() && !v6_ok, srtt, c)
                })
                .collect()
        };
        keyed.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.total_cmp(&b.1)));
        let mut out: Vec<SocketAddr> = keyed.into_iter().map(|(_, _, c)| c).collect();
        if out.len() > 1 && rand::rng().random_bool(self.exploration) {
            let usable = out.iter().filter(|c| !(c.is_ipv6() && !v6_ok)).count();
            if usable > 1 {
                let pick = rand::rng().random_range(1..usable);
                let chosen = out.remove(pick);
                out.insert(0, chosen);
            }
        }
        out
    }
}

fn is_unreachable(err: &std::io::Error) -> bool {
    matches!(
        err.kind(),
        ErrorKind::NetworkUnreachable | ErrorKind::HostUnreachable | ErrorKind::AddrNotAvailable
    ) || err.raw_os_error() == Some(97) // EAFNOSUPPORT on Linux: IPv6 disabled
}
