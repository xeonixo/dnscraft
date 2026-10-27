//! Passive upstream health (WX3). Samples come from real exchanges; no probe
//! query is ever sent for health.

use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::time::{Duration, Instant, SystemTime};

use dnscraft_proto::Name;
use serde::Serialize;

/// Samples older than this are not counted.
const WINDOW: Duration = Duration::from_secs(300);
/// Most samples kept per target.
const RING: usize = 256;
/// Fewer samples than this is `unknown`.
const MIN_SAMPLES: usize = 3;
/// `down` needs at least this many samples.
const DOWN_MIN_SAMPLES: usize = 10;
/// Success below this share of samples is `down` (with enough samples).
const DOWN_BELOW: f64 = 0.5;
/// Success below this share of samples is `degraded`.
const DEGRADED_BELOW: f64 = 0.95;
/// A p95 RTT above this (ms) is `degraded`.
const SLOW_P95_MS: f64 = 1000.0;

/// Whose exchanges a sample belongs to.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) enum Target {
    /// A configured target of a forward zone.
    Forward { zone: Name, addr: SocketAddr },
    /// Every exchange made by iterative (root-hint) resolution.
    Recursion,
}

/// One exchange: its time, and its RTT or the stable code of its failure.
#[derive(Clone, Debug)]
pub(crate) struct Sample {
    /// Monotonic time, for the window.
    pub at: Instant,
    /// Wall-clock time, for `last_checked`.
    pub wall: SystemTime,
    pub outcome: Result<Duration, &'static str>,
}

/// Bounded sample rings, one per target.
pub(crate) type Rings = HashMap<Target, VecDeque<Sample>>;

pub(crate) fn push(rings: &mut Rings, target: Target, sample: Sample) {
    let ring = rings
        .entry(target)
        .or_insert_with(|| VecDeque::with_capacity(RING));
    if ring.len() == RING {
        ring.pop_front();
    }
    ring.push_back(sample);
}

/// Health of one upstream, as reported by [`Resolver::upstreams`](crate::Resolver::upstreams).
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct UpstreamHealth {
    /// `addr` for a forward target, `recursion` for the aggregate row.
    pub name: String,
    /// `forward_target` or `recursion`.
    pub kind: &'static str,
    /// Apex of the forward zone; `None` for recursion.
    pub zone: Option<String>,
    /// Transport the samples were taken over. Plain DNS (UDP, TCP on truncation).
    pub protocol: &'static str,
    pub state: UpstreamState,
    /// Exchanges inside the window.
    pub samples: usize,
    /// Median RTT of successful exchanges in the window, in ms.
    pub rtt_p50_ms: Option<f64>,
    /// 95th-percentile RTT of successful exchanges in the window, in ms.
    pub rtt_p95_ms: Option<f64>,
    /// Successful share of the exchanges in the window, 0.0 to 1.0.
    pub success_rate: Option<f64>,
    /// Stable code of the most recent failure in the window.
    pub last_error: Option<&'static str>,
    /// Time of the most recent exchange in the window.
    pub last_checked: Option<SystemTime>,
}

/// Health state of an upstream.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum UpstreamState {
    /// Enough samples, nearly all successful and fast.
    Up,
    /// Some failures, or a slow p95.
    Degraded,
    /// Most exchanges fail.
    Down,
    /// Too few samples to judge.
    Unknown,
}

/// Summarises the samples of one target at `now`.
pub(crate) fn summarise(
    name: String,
    kind: &'static str,
    zone: Option<String>,
    ring: Option<&VecDeque<Sample>>,
    now: Instant,
) -> UpstreamHealth {
    let live: Vec<&Sample> = ring
        .into_iter()
        .flatten()
        .filter(|s| now.saturating_duration_since(s.at) <= WINDOW)
        .collect();
    let mut rtts: Vec<f64> = live
        .iter()
        .filter_map(|s| s.outcome.ok())
        .map(|rtt| rtt.as_secs_f64() * 1000.0)
        .collect();
    rtts.sort_by(f64::total_cmp);
    let samples = live.len();
    let success_rate = (samples > 0).then(|| rtts.len() as f64 / samples as f64);
    let p95 = percentile(&rtts, 0.95);
    let state = match success_rate {
        _ if samples < MIN_SAMPLES => UpstreamState::Unknown,
        Some(rate) if samples >= DOWN_MIN_SAMPLES && rate < DOWN_BELOW => UpstreamState::Down,
        Some(rate) if rate < DEGRADED_BELOW || p95.is_some_and(|p| p > SLOW_P95_MS) => {
            UpstreamState::Degraded
        }
        _ => UpstreamState::Up,
    };
    UpstreamHealth {
        name,
        kind,
        zone,
        protocol: "dns",
        state,
        samples,
        rtt_p50_ms: percentile(&rtts, 0.5),
        rtt_p95_ms: p95,
        success_rate,
        last_error: live.iter().rev().find_map(|s| s.outcome.err()),
        last_checked: live.last().map(|s| s.wall),
    }
}

/// Nearest-rank percentile of a sorted slice.
fn percentile(sorted: &[f64], p: f64) -> Option<f64> {
    if sorted.is_empty() {
        return None;
    }
    let rank = (p * sorted.len() as f64).ceil() as usize;
    Some(sorted[rank.clamp(1, sorted.len()) - 1])
}
