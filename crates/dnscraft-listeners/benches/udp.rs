//! Do53 UDP benchmark: end-to-end query throughput and per-query latency.
//!
//! Spawns a real [`serve_udp`] listener (with a [`FakeHandler`] answering
//! NOERROR) on a multi-thread tokio runtime, then drives it from a blocking
//! `std::net::UdpSocket` so the timing loop has no async machinery in it.
//!
//! Reported: queries/sec (criterion throughput) plus p50 / p99 round-trip
//! latency collected per query. Run with `cargo bench -p dnscraft-listeners`.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::Arc;
use std::time::Duration;

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

fn bench_udp(c: &mut Criterion) {
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
    // benchmark loop below stays on this thread with a blocking socket.
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

    // Blocking client so latency is the raw loopback round-trip.
    let client = UdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let query = Message::query(1, Name::from_ascii("example.com.").unwrap(), RecordType::A)
        .encode()
        .unwrap();

    // Warm up the listener / code paths before measuring.
    let mut buf = [0u8; 65535];
    for _ in 0..1_000 {
        client.send_to(&query, addr).unwrap();
        let _ = client.recv(&mut buf).unwrap();
    }

    let mut latencies: Vec<u64> = Vec::with_capacity(1 << 20);
    {
        let mut group = c.benchmark_group("udp");
        group.throughput(Throughput::Elements(1));
        group.warm_up_time(Duration::from_secs(1));
        group.measurement_time(Duration::from_secs(3));
        group.sample_size(20);
        group.bench_function("roundtrip", |b| {
            b.iter_custom(|iters| {
                let start = std::time::Instant::now();
                for _ in 0..iters {
                    let t0 = std::time::Instant::now();
                    client.send_to(&query, addr).unwrap();
                    let _ = client.recv(&mut buf).unwrap();
                    latencies.push(t0.elapsed().as_nanos() as u64);
                }
                start.elapsed()
            });
        });
        group.finish();
    }

    // Report p50 / p99 and an explicit queries/sec figure for the evidence log.
    latencies.sort_unstable();
    let n = latencies.len();
    if n > 0 {
        let pct = |p: f64| {
            let idx = ((n - 1) as f64 * p).round() as usize;
            latencies[idx] as f64 / 1_000.0
        };
        let mean_ns = latencies.iter().sum::<u64>() as f64 / n as f64;
        let qps = 1_000_000_000.0 / mean_ns;
        eprintln!(
            "[dnscraft-listeners udp bench] qps = {qps:.0}, p50 = {:.1} µs, p99 = {:.1} µs, samples = {n}",
            pct(0.50),
            pct(0.99),
        );
    }

    // Tear the listener down so the runtime can drop cleanly.
    let _ = shutdown_tx.send(true);
    rt.shutdown_timeout(Duration::from_secs(2));
}

criterion_group!(benches, bench_udp);
criterion_main!(benches);
