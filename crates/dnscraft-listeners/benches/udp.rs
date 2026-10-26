//! Do53 UDP benchmark: single-flight round-trip latency and saturation throughput.
//!
//! Spawns a real [`serve_udp`] listener (with a [`FakeHandler`] answering
//! NOERROR) on a multi-thread tokio runtime, then drives it two ways:
//!
//! * **single-flight round trip** — one blocking client sends one query and
//!   waits for the answer before sending the next; criterion reports the
//!   loopback latency distribution (p50 / p99). This is a *latency* figure:
//!   its reciprocal is not a server throughput ceiling.
//! * **saturation** — N blocking client threads (N = 4 and 8), each on its own
//!   socket, keep N queries in flight for a fixed wall window; reported qps is
//!   `completed / wall_seconds` with warm-up iterations discarded.
//!
//! Reported: machine class (arch + logical cores), single-flight p50 / p99, and
//! saturated qps for N = 4 and 8. Run with `cargo bench -p dnscraft-listeners`.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::Arc;
use std::time::{Duration, Instant};

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use dnscraft_filtering::SetId;
use dnscraft_listeners::{
    Admission, Exposure, FakeHandler, Limits, ListenerConfig, Protocol, PublicConfig, SystemClock,
    TokenRate, UdpServeParams, UdpStats, serve_udp,
};
use dnscraft_policy::{
    AnswerOrigin, DecisionRecord, DecisionTimings, ListenerId, PolicyAnswer, ProfileId,
    SelectionCause, ViewId,
};
use dnscraft_proto::{Message, Name, Rcode, RecordType};
use tokio::sync::{oneshot, watch};

/// A minimal NOERROR answer so `handle_wire` runs the full encode/send path.
fn answer() -> PolicyAnswer {
    let q = Message::query(1, Name::from_ascii("example.com.").unwrap(), RecordType::A);
    PolicyAnswer {
        message: Message::response_to(&q),
        ede: None,
        record: DecisionRecord {
            view_id: ViewId::new("default").unwrap(),
            profile_id: ProfileId::new("default").unwrap(),
            selection: SelectionCause::Default,
            client_id: None,
            filter_set: SetId::new("default").unwrap(),
            steps: Vec::new(),
            filter: None,
            forward_zone: None,
            dnssec: None,
            answer_source: AnswerOrigin::LocalView,
            timings: DecisionTimings::default(),
            rcode: Rcode::NOERROR,
        },
        loggable: false,
    }
}

/// One saturation window: completed/wall qps plus the merged latency spread.
struct SaturationSample {
    qps: f64,
    p50: f64,
    p99: f64,
    samples: usize,
}

/// Runs `threads` blocking clients for `window`; returns `completed / window`
/// qps and the merged latency distribution. Warm-up iterations are discarded.
fn saturation_run(
    addr: SocketAddr,
    query: &[u8],
    threads: usize,
    window: Duration,
) -> SaturationSample {
    let barrier = Arc::new(std::sync::Barrier::new(threads + 1));
    let mut handles = Vec::with_capacity(threads);
    for _ in 0..threads {
        let barrier = Arc::clone(&barrier);
        let query = query.to_vec();
        handles.push(std::thread::spawn(move || {
            let client = UdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
            client
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut buf = [0u8; 65535];
            // Warm-up (discarded): prime the listener and drop any cold-start tail.
            for _ in 0..500 {
                client.send_to(&query, addr).unwrap();
                let _ = client.recv(&mut buf).unwrap();
            }
            barrier.wait();

            let mut latencies = Vec::with_capacity(1 << 20);
            let start = Instant::now();
            while start.elapsed() < window {
                let t0 = Instant::now();
                client.send_to(&query, addr).unwrap();
                let _ = client.recv(&mut buf).unwrap();
                latencies.push(t0.elapsed().as_nanos() as u64);
            }
            latencies
        }));
    }
    barrier.wait();

    let mut merged: Vec<u64> = Vec::new();
    let mut total = 0usize;
    for handle in handles {
        let latencies = handle.join().unwrap();
        total += latencies.len();
        merged.extend(latencies);
    }
    merged.sort_unstable();
    let n = merged.len();
    let pct = |p: f64| {
        if n == 0 {
            return 0.0;
        }
        merged[((n - 1) as f64 * p).round() as usize] as f64 / 1_000.0
    };
    SaturationSample {
        qps: total as f64 / window.as_secs_f64(),
        p50: pct(0.50),
        p99: pct(0.99),
        samples: n,
    }
}

fn bench_udp(c: &mut Criterion) {
    let cores = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);
    eprintln!(
        "[dnscraft-listeners udp bench] machine: arch = {}, cores = {cores}",
        std::env::consts::ARCH
    );

    // Rate limits must not throttle the load: this is a throughput benchmark.
    let fast = TokenRate {
        per_second: 2_000_000,
        burst: 4_000_000,
    };
    let limits = Limits {
        rate_per_source: fast,
        rate_per_client_id: fast,
        ..Limits::default()
    };

    // A multi-thread runtime drives the listener on worker threads while the
    // benchmark loops below run on this thread (single-flight) or on their own
    // blocking threads (saturation).
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    let (bound_tx, bound_rx) = oneshot::channel();
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    let public = PublicConfig::default();
    let admission = Arc::new(std::sync::Mutex::new(Admission::new(&limits, &public)));
    let handler = Arc::new(FakeHandler::new(answer()));
    let listener = ListenerConfig {
        id: ListenerId::new("bench-udp").unwrap(),
        protocol: Protocol::Udp53,
        address: SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
        exposure: Exposure::Local,
        h3: false,
    };
    rt.spawn(serve_udp(UdpServeParams {
        listener,
        limits,
        admission,
        handler,
        clock: Arc::new(SystemClock),
        stats: Arc::new(UdpStats::default()),
        ddr: None,
        event_sink: None,
        bound: bound_tx,
        shutdown: shutdown_rx,
    }));

    let addr = rt.block_on(async { bound_rx.await.unwrap() });

    let query = Message::query(1, Name::from_ascii("example.com.").unwrap(), RecordType::A)
        .encode()
        .unwrap();

    // Warm up the listener / code paths before measuring.
    {
        let client = UdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
        let mut buf = [0u8; 65535];
        for _ in 0..1_000 {
            client.send_to(&query, addr).unwrap();
            let _ = client.recv(&mut buf).unwrap();
        }
    }

    // Single-flight round-trip latency (one query in flight at a time).
    let mut latencies: Vec<u64> = Vec::with_capacity(1 << 20);
    {
        let client = UdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut buf = [0u8; 65535];
        let mut group = c.benchmark_group("udp");
        group.throughput(Throughput::Elements(1));
        group.warm_up_time(Duration::from_secs(1));
        group.measurement_time(Duration::from_secs(3));
        group.sample_size(20);
        group.bench_function("single_flight_roundtrip", |b| {
            b.iter_custom(|iters| {
                let start = Instant::now();
                for _ in 0..iters {
                    let t0 = Instant::now();
                    client.send_to(&query, addr).unwrap();
                    let _ = client.recv(&mut buf).unwrap();
                    latencies.push(t0.elapsed().as_nanos() as u64);
                }
                start.elapsed()
            });
        });
        group.finish();
    }

    latencies.sort_unstable();
    let n = latencies.len();
    let pct = |p: f64| {
        if n == 0 {
            return 0.0;
        }
        latencies[((n - 1) as f64 * p).round() as usize] as f64 / 1_000.0
    };
    eprintln!(
        "[dnscraft-listeners udp bench] single-flight round trip: p50 = {:.1} µs, p99 = {:.1} µs, samples = {n}",
        pct(0.50),
        pct(0.99),
    );

    // Saturation throughput: N concurrent clients over a fixed wall window.
    for threads in [4usize, 8] {
        let s = saturation_run(addr, &query, threads, Duration::from_secs(5));
        eprintln!(
            "[dnscraft-listeners udp bench] saturated N={threads}: qps = {:.0}, p50 = {:.1} µs, p99 = {:.1} µs, samples = {}",
            s.qps, s.p50, s.p99, s.samples
        );
    }

    // Tear the listener down so the runtime can drop cleanly.
    let _ = shutdown_tx.send(true);
    rt.shutdown_timeout(Duration::from_secs(2));
}

criterion_group!(benches, bench_udp);
criterion_main!(benches);
