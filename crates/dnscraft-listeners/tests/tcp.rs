//! Do53 TCP listener tests (N5 + Checkpoint B re-review).

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod support;

use std::io::ErrorKind;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, SystemTime};

use dnscraft_listeners::{
    Exposure, FakeHandler, Limits, ListenerConfig, ManualClock, OPTION_TCP_KEEPALIVE, Protocol,
    PublicConfig, SystemClock, TcpServeParams, TcpStats, TokenRate, duration_to_keepalive_units,
    read_frame, serve_tcp, write_frame,
};
use dnscraft_policy::{ListenerId, PolicyAnswer, RequestContext};
use dnscraft_proto::{Edns, EdnsOption, Message, Name, Rcode, RecordType};
use socket2::{Domain, Protocol as SockProtocol, Socket, Type};
use support::{encode_a_query, fake_a_answer, fake_large_answer, poll_until};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{Notify, oneshot, watch};

/// Connect with a tiny receive window so the server writer blocks quickly.
async fn connect_small_window(addr: SocketAddr) -> TcpStream {
    let domain = if addr.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let sock = Socket::new(domain, Type::STREAM, Some(SockProtocol::TCP)).unwrap();
    sock.set_recv_buffer_size(256).unwrap();
    sock.set_nonblocking(true).unwrap();
    match sock.connect(&addr.into()) {
        Ok(()) => {}
        Err(e) if e.kind() == ErrorKind::WouldBlock || e.raw_os_error() == Some(115) => {}
        Err(e) => panic!("connect: {e}"),
    }
    let stream = TcpStream::from_std(sock.into()).unwrap();
    stream.writable().await.unwrap();
    // Complete non-blocking connect.
    let _ = stream.peer_addr().unwrap();
    stream
}

fn listener_cfg(addr: SocketAddr) -> ListenerConfig {
    ListenerConfig {
        node_id: None,
        id: ListenerId::new("test-tcp").unwrap(),
        protocol: Protocol::Tcp53,
        address: addr,
        exposure: Exposure::Local,
        h3: false,
        tls_policy: None,
    }
}

struct TcpHarness {
    addr: SocketAddr,
    stats: Arc<TcpStats>,
    shutdown: watch::Sender<bool>,
    join: tokio::task::JoinHandle<Result<(), dnscraft_listeners::ListenersError>>,
}

impl TcpHarness {
    async fn spawn<H: dnscraft_listeners::QueryHandler + 'static>(
        bind: SocketAddr,
        handler: Arc<H>,
        limits: Limits,
        clock: Arc<dyn dnscraft_listeners::Clock>,
    ) -> Self {
        let stats = Arc::new(TcpStats::default());
        let (bound_tx, bound_rx) = oneshot::channel();
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let admission = Arc::new(std::sync::Mutex::new(dnscraft_listeners::Admission::new(
            &limits,
            &PublicConfig::default(),
        )));
        let join = tokio::spawn(serve_tcp(TcpServeParams {
            listener: listener_cfg(bind),
            limits,
            admission,
            handler,
            clock,
            stats: Arc::clone(&stats),
            ddr: None,
            event_sink: None,
            bound: bound_tx,
            shutdown: shutdown_rx,
        }));
        let addr = tokio::time::timeout(Duration::from_secs(2), bound_rx)
            .await
            .unwrap()
            .unwrap();
        Self {
            addr,
            stats,
            shutdown: shutdown_tx,
            join,
        }
    }

    async fn stop(self) {
        let _ = self.shutdown.send(true);
        let _ = tokio::time::timeout(Duration::from_secs(2), self.join).await;
    }
}

struct GatedHandler {
    first_gate: Arc<Notify>,
    second_seen: Arc<Notify>,
    answer: PolicyAnswer,
}

impl dnscraft_listeners::QueryHandler for GatedHandler {
    async fn handle(
        &self,
        ctx: RequestContext,
    ) -> Result<PolicyAnswer, dnscraft_policy::PolicyError> {
        let name = ctx.query.name.to_string();
        if name.starts_with("one.") {
            self.first_gate.notified().await;
        } else {
            self.second_seen.notify_waiters();
        }
        Ok(self.answer.clone())
    }
}

struct HangHandler;

impl dnscraft_listeners::QueryHandler for HangHandler {
    async fn handle(
        &self,
        _ctx: RequestContext,
    ) -> Result<PolicyAnswer, dnscraft_policy::PolicyError> {
        std::future::pending().await
    }
}

/// Answers only after `gate` is notified (for EOF-drain regression).
struct ReleaseHandler {
    gate: Arc<Notify>,
    answer: PolicyAnswer,
}

impl dnscraft_listeners::QueryHandler for ReleaseHandler {
    async fn handle(
        &self,
        _ctx: RequestContext,
    ) -> Result<PolicyAnswer, dnscraft_policy::PolicyError> {
        self.gate.notified().await;
        Ok(self.answer.clone())
    }
}

#[tokio::test]
async fn pipelined_out_of_order() {
    let first_gate = Arc::new(Notify::new());
    let second_seen = Arc::new(Notify::new());
    let handler = Arc::new(GatedHandler {
        first_gate: Arc::clone(&first_gate),
        second_seen: Arc::clone(&second_seen),
        answer: fake_a_answer(Ipv4Addr::new(192, 0, 2, 55)),
    });

    let h = TcpHarness::spawn(
        SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
        handler,
        Limits::default(),
        Arc::new(SystemClock),
    )
    .await;

    let mut client = TcpStream::connect(h.addr).await.unwrap();
    write_frame(&mut client, &encode_a_query(100, "one.example.com."))
        .await
        .unwrap();
    write_frame(&mut client, &encode_a_query(200, "two.example.com."))
        .await
        .unwrap();

    tokio::time::timeout(Duration::from_secs(2), second_seen.notified())
        .await
        .expect("second query");
    first_gate.notify_waiters();

    let a = read_frame(&mut client).await.unwrap();
    let b = read_frame(&mut client).await.unwrap();
    assert_eq!(Message::decode(&a).unwrap().header.id, 200);
    assert_eq!(Message::decode(&b).unwrap().header.id, 100);

    h.stop().await;
}

/// GL3: `max_inflight_per_listener` caps queries across a TCP connection (and
/// listener), in addition to `max_queries_per_connection`.
struct InflightCapHandler {
    entered: Arc<AtomicUsize>,
    release: Arc<Notify>,
    answer: PolicyAnswer,
}

impl dnscraft_listeners::QueryHandler for InflightCapHandler {
    async fn handle(
        &self,
        _ctx: RequestContext,
    ) -> Result<PolicyAnswer, dnscraft_policy::PolicyError> {
        let n = self.entered.fetch_add(1, Ordering::SeqCst) + 1;
        if n == 1 {
            self.release.notified().await;
        }
        Ok(self.answer.clone())
    }
}

#[tokio::test]
async fn listener_inflight_cap_applies_to_tcp() {
    let entered = Arc::new(AtomicUsize::new(0));
    let release = Arc::new(Notify::new());
    let handler = Arc::new(InflightCapHandler {
        entered: Arc::clone(&entered),
        release: Arc::clone(&release),
        answer: fake_a_answer(Ipv4Addr::new(192, 0, 2, 66)),
    });
    let limits = Limits {
        max_inflight_per_listener: 1,
        ..Limits::default()
    };
    let h = TcpHarness::spawn(
        SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
        handler,
        limits,
        Arc::new(SystemClock),
    )
    .await;

    let mut client = TcpStream::connect(h.addr).await.unwrap();
    write_frame(&mut client, &encode_a_query(1, "one.example.com."))
        .await
        .unwrap();
    write_frame(&mut client, &encode_a_query(2, "two.example.com."))
        .await
        .unwrap();

    poll_until(
        || entered.load(Ordering::SeqCst) >= 1,
        Duration::from_secs(2),
    )
    .await;
    // The second query must be held by the listener-wide cap.
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(
        entered.load(Ordering::SeqCst),
        1,
        "second query must wait for the listener in-flight cap"
    );

    release.notify_waiters();
    let a = read_frame(&mut client).await.unwrap();
    let b = read_frame(&mut client).await.unwrap();
    assert_eq!(Message::decode(&a).unwrap().header.id, 1);
    assert_eq!(Message::decode(&b).unwrap().header.id, 2);
    assert_eq!(entered.load(Ordering::SeqCst), 2);

    h.stop().await;
}

#[tokio::test]
async fn idle_timeout_closes() {
    let clock = Arc::new(ManualClock::new(
        SystemTime::UNIX_EPOCH + Duration::from_secs(1_000),
    ));
    let limits = Limits {
        tcp_idle_timeout: Duration::from_secs(2),
        ..Limits::default()
    };
    let h = TcpHarness::spawn(
        SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
        Arc::new(FakeHandler::new(fake_a_answer(Ipv4Addr::new(192, 0, 2, 1)))),
        limits,
        Arc::clone(&clock) as Arc<dyn dnscraft_listeners::Clock>,
    )
    .await;

    let client = TcpStream::connect(h.addr).await.unwrap();
    let stats = Arc::clone(&h.stats);
    poll_until(
        || stats.accepted.load(Ordering::Relaxed) >= 1,
        Duration::from_secs(2),
    )
    .await;

    clock.advance(Duration::from_secs(3));
    poll_until(
        || stats.idle_timeouts.load(Ordering::Relaxed) >= 1,
        Duration::from_secs(2),
    )
    .await;
    drop(client);
    h.stop().await;
}

#[tokio::test]
async fn connection_caps() {
    let handler = Arc::new(FakeHandler::new(fake_a_answer(Ipv4Addr::new(192, 0, 2, 1))));
    let limits = Limits {
        max_connections_per_listener: 1,
        max_connections_per_source: 32,
        ..Limits::default()
    };
    let h = TcpHarness::spawn(
        SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
        Arc::clone(&handler),
        limits,
        Arc::new(SystemClock),
    )
    .await;

    let _c1 = TcpStream::connect(h.addr).await.unwrap();
    let stats = Arc::clone(&h.stats);
    poll_until(
        || stats.accepted.load(Ordering::Relaxed) >= 1,
        Duration::from_secs(2),
    )
    .await;
    let _c2 = TcpStream::connect(h.addr).await.unwrap();
    poll_until(
        || stats.rejected_conn_cap.load(Ordering::Relaxed) >= 1,
        Duration::from_secs(2),
    )
    .await;
    h.stop().await;

    let limits = Limits {
        max_connections_per_listener: 32,
        max_connections_per_source: 1,
        ..Limits::default()
    };
    let h = TcpHarness::spawn(
        SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
        handler,
        limits,
        Arc::new(SystemClock),
    )
    .await;
    let _c1 = TcpStream::connect(h.addr).await.unwrap();
    let stats = Arc::clone(&h.stats);
    poll_until(
        || stats.accepted.load(Ordering::Relaxed) >= 1,
        Duration::from_secs(2),
    )
    .await;
    let _c2 = TcpStream::connect(h.addr).await.unwrap();
    poll_until(
        || stats.rejected_per_source.load(Ordering::Relaxed) >= 1,
        Duration::from_secs(2),
    )
    .await;
    h.stop().await;
}

#[tokio::test]
async fn framing_errors_close_and_count() {
    let h = TcpHarness::spawn(
        SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
        Arc::new(FakeHandler::new(fake_a_answer(Ipv4Addr::new(192, 0, 2, 1)))),
        Limits::default(),
        Arc::new(SystemClock),
    )
    .await;

    {
        let mut c = TcpStream::connect(h.addr).await.unwrap();
        c.write_all(&[0x00]).await.unwrap();
        c.flush().await.unwrap();
        drop(c);
    }
    let stats = Arc::clone(&h.stats);
    poll_until(
        || stats.framing_errors.load(Ordering::Relaxed) >= 1,
        Duration::from_secs(2),
    )
    .await;

    {
        let mut c = TcpStream::connect(h.addr).await.unwrap();
        c.write_all(&0u16.to_be_bytes()).await.unwrap();
        c.flush().await.unwrap();
        let mut buf = [0u8; 8];
        let _ = tokio::time::timeout(Duration::from_millis(200), c.read(&mut buf)).await;
    }
    poll_until(
        || stats.framing_errors.load(Ordering::Relaxed) >= 2,
        Duration::from_secs(2),
    )
    .await;
    h.stop().await;
}

#[tokio::test]
async fn keepalive_echoed_in_response() {
    let h = TcpHarness::spawn(
        SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
        Arc::new(FakeHandler::new(fake_a_answer(Ipv4Addr::new(192, 0, 2, 9)))),
        Limits {
            tcp_idle_timeout: Duration::from_secs(10),
            ..Limits::default()
        },
        Arc::new(SystemClock),
    )
    .await;

    let mut q = Message::query(5, Name::from_ascii("example.com.").unwrap(), RecordType::A);
    let mut edns = Edns::new(1232);
    edns.options.push(EdnsOption::Unknown {
        code: OPTION_TCP_KEEPALIVE,
        data: Box::from([]),
    });
    q.edns = Some(edns);

    let mut client = TcpStream::connect(h.addr).await.unwrap();
    write_frame(&mut client, &q.encode().unwrap())
        .await
        .unwrap();
    let resp = read_frame(&mut client).await.unwrap();
    let msg = Message::decode(&resp).unwrap();
    assert_eq!(msg.rcode(), Rcode::NOERROR);
    let ka = msg
        .edns
        .as_ref()
        .unwrap()
        .options
        .iter()
        .find(|o| matches!(o, EdnsOption::Unknown { code, .. } if *code == OPTION_TCP_KEEPALIVE))
        .unwrap();
    if let EdnsOption::Unknown { data, .. } = ka {
        assert_eq!(
            u16::from_be_bytes([data[0], data[1]]),
            duration_to_keepalive_units(Duration::from_secs(10))
        );
    }
    h.stop().await;
}

/// Client pipelines past the query cap and never reads; write deadline aborts and frees the slot.
async fn non_reading_client_write_timeout_once(
    clock: &ManualClock,
    h: &TcpHarness,
    start_accepted: u64,
    start_closed: u64,
) {
    let mut client = connect_small_window(h.addr).await;
    let stats = Arc::clone(&h.stats);
    poll_until(
        || stats.accepted.load(Ordering::Relaxed) > start_accepted,
        Duration::from_secs(2),
    )
    .await;

    // Large answers + tiny client window fill the server send buffer so write blocks.
    for i in 0..128u16 {
        write_frame(
            &mut client,
            &encode_a_query(i, &format!("q{i}.example.com.")),
        )
        .await
        .unwrap();
    }
    // Do not read answers — wait until the writer stalls (send buffer / window full).
    poll_until(
        || stats.answered.load(Ordering::Relaxed) >= 1,
        Duration::from_secs(2),
    )
    .await;
    let mut last = stats.answered.load(Ordering::Relaxed);
    let mut stable_rounds = 0u32;
    let stall_deadline = std::time::Instant::now() + Duration::from_secs(2);
    while stable_rounds < 10 {
        if std::time::Instant::now() >= stall_deadline {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
        let now = stats.answered.load(Ordering::Relaxed);
        if now == last {
            stable_rounds += 1;
        } else {
            last = now;
            stable_rounds = 0;
        }
    }
    assert!(
        last >= 1,
        "expected some answers before write stall, got {last}"
    );

    // Writer is blocked inside write_frame; advancing past tcp_idle_timeout trips the deadline.
    clock.advance(Duration::from_secs(3));
    poll_until(
        || stats.closed.load(Ordering::Relaxed) > start_closed,
        Duration::from_secs(2),
    )
    .await;
    assert_eq!(stats.closed.load(Ordering::Relaxed), start_closed + 1);
    assert!(stats.write_timeouts.load(Ordering::Relaxed) >= 1);
    drop(client);
}

#[tokio::test]
async fn query_cap_write_timeout_frees_per_source_slot() {
    let clock = Arc::new(ManualClock::new(
        SystemTime::UNIX_EPOCH + Duration::from_secs(5_000),
    ));
    let limits = Limits {
        max_queries_per_connection: 2,
        max_connections_per_source: 1,
        max_connections_per_listener: 32,
        tcp_idle_timeout: Duration::from_secs(2),
        query_timeout: Duration::from_secs(60),
        rate_per_source: TokenRate {
            per_second: 10_000,
            burst: 10_000,
        },
        ..Limits::default()
    };
    let h = TcpHarness::spawn(
        SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
        Arc::new(FakeHandler::new(fake_large_answer(40))),
        limits,
        Arc::clone(&clock) as Arc<dyn dnscraft_listeners::Clock>,
    )
    .await;

    let stats = Arc::clone(&h.stats);
    non_reading_client_write_timeout_once(clock.as_ref(), &h, 0, 0).await;

    // Per-source slot free: a new connection from the same source is accepted.
    let c2 = TcpStream::connect(h.addr).await.unwrap();
    poll_until(
        || stats.accepted.load(Ordering::Relaxed) >= 2,
        Duration::from_secs(2),
    )
    .await;
    assert_eq!(stats.rejected_per_source.load(Ordering::Relaxed), 0);
    drop(c2);
    h.stop().await;
}

#[tokio::test]
async fn query_cap_write_timeout_stable_over_repeats() {
    let clock = Arc::new(ManualClock::new(
        SystemTime::UNIX_EPOCH + Duration::from_secs(9_000),
    ));
    let limits = Limits {
        max_queries_per_connection: 2,
        max_connections_per_source: 1,
        max_connections_per_listener: 32,
        tcp_idle_timeout: Duration::from_secs(2),
        query_timeout: Duration::from_secs(60),
        rate_per_source: TokenRate {
            per_second: 10_000,
            burst: 10_000,
        },
        ..Limits::default()
    };
    let h = TcpHarness::spawn(
        SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
        Arc::new(FakeHandler::new(fake_large_answer(40))),
        limits,
        Arc::clone(&clock) as Arc<dyn dnscraft_listeners::Clock>,
    )
    .await;

    let stats = Arc::clone(&h.stats);
    for i in 0..20u64 {
        non_reading_client_write_timeout_once(clock.as_ref(), &h, i, i).await;
        assert_eq!(
            stats.closed.load(Ordering::Relaxed),
            stats.accepted.load(Ordering::Relaxed)
        );
    }
    h.stop().await;
}

#[tokio::test]
async fn peer_eof_drains_in_flight_answer() {
    let gate = Arc::new(Notify::new());
    let handler = Arc::new(ReleaseHandler {
        gate: Arc::clone(&gate),
        answer: fake_a_answer(Ipv4Addr::new(192, 0, 2, 77)),
    });
    let h = TcpHarness::spawn(
        SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
        handler,
        Limits::default(),
        Arc::new(SystemClock),
    )
    .await;

    let mut client = TcpStream::connect(h.addr).await.unwrap();
    write_frame(&mut client, &encode_a_query(7, "drain.example.com."))
        .await
        .unwrap();
    let stats = Arc::clone(&h.stats);
    poll_until(
        || stats.queries.load(Ordering::Relaxed) >= 1,
        Duration::from_secs(2),
    )
    .await;

    client.shutdown().await.unwrap();
    // Answer after half-close; server must still flush it, then EOF.
    gate.notify_waiters();
    let resp = tokio::time::timeout(Duration::from_secs(2), read_frame(&mut client))
        .await
        .expect("drained answer")
        .unwrap();
    assert_eq!(Message::decode(&resp).unwrap().header.id, 7);
    let mut buf = [0u8; 4];
    let n = tokio::time::timeout(Duration::from_secs(2), client.read(&mut buf))
        .await
        .expect("eof")
        .unwrap();
    assert_eq!(n, 0);
    h.stop().await;
}

/// Idle must re-arm after a slow answer completes (must fail on b6c2757).
#[tokio::test]
async fn idle_rearms_after_slow_answer() {
    let clock = Arc::new(ManualClock::new(
        SystemTime::UNIX_EPOCH + Duration::from_secs(6_000),
    ));
    let gate = Arc::new(Notify::new());
    let handler = Arc::new(ReleaseHandler {
        gate: Arc::clone(&gate),
        answer: fake_a_answer(Ipv4Addr::new(192, 0, 2, 33)),
    });
    let limits = Limits {
        tcp_idle_timeout: Duration::from_secs(2),
        query_timeout: Duration::from_secs(5),
        ..Limits::default()
    };
    let h = TcpHarness::spawn(
        SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
        handler,
        limits,
        Arc::clone(&clock) as Arc<dyn dnscraft_listeners::Clock>,
    )
    .await;

    let mut client = TcpStream::connect(h.addr).await.unwrap();
    write_frame(&mut client, &encode_a_query(11, "slow.example.com."))
        .await
        .unwrap();
    let stats = Arc::clone(&h.stats);
    poll_until(
        || stats.queries.load(Ordering::Relaxed) >= 1,
        Duration::from_secs(2),
    )
    .await;

    // Loop is waiting for the next frame while the query is outstanding; then answer.
    gate.notify_waiters();
    let resp = tokio::time::timeout(Duration::from_secs(2), read_frame(&mut client))
        .await
        .expect("slow answer")
        .unwrap();
    assert_eq!(Message::decode(&resp).unwrap().header.id, 11);
    // Client stays silent; idle must re-arm from the drain moment.
    for _ in 0..5 {
        clock.advance(Duration::from_secs(2));
        tokio::task::yield_now().await;
    }
    poll_until(
        || stats.idle_timeouts.load(Ordering::Relaxed) >= 1,
        Duration::from_secs(2),
    )
    .await;
    assert_eq!(stats.idle_timeouts.load(Ordering::Relaxed), 1);
    assert_eq!(stats.closed.load(Ordering::Relaxed), 1);
    h.stop().await;
}

#[tokio::test]
async fn idle_waits_for_outstanding_then_query_timeout_servfail() {
    let clock = Arc::new(ManualClock::new(
        SystemTime::UNIX_EPOCH + Duration::from_secs(7_000),
    ));
    let limits = Limits {
        tcp_idle_timeout: Duration::from_secs(2),
        query_timeout: Duration::from_secs(5),
        ..Limits::default()
    };
    let h = TcpHarness::spawn(
        SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
        Arc::new(HangHandler),
        limits,
        Arc::clone(&clock) as Arc<dyn dnscraft_listeners::Clock>,
    )
    .await;

    let mut client = TcpStream::connect(h.addr).await.unwrap();
    write_frame(&mut client, &encode_a_query(99, "hang.example.com."))
        .await
        .unwrap();
    let stats = Arc::clone(&h.stats);
    poll_until(
        || stats.queries.load(Ordering::Relaxed) >= 1,
        Duration::from_secs(2),
    )
    .await;

    clock.advance(Duration::from_secs(3));
    tokio::task::yield_now().await;
    assert_eq!(stats.closed.load(Ordering::Relaxed), 0);
    assert_eq!(stats.idle_timeouts.load(Ordering::Relaxed), 0);

    clock.advance(Duration::from_secs(3));
    let resp = tokio::time::timeout(Duration::from_secs(2), read_frame(&mut client))
        .await
        .expect("servfail")
        .unwrap();
    assert_eq!(Message::decode(&resp).unwrap().rcode(), Rcode::SERVFAIL);
    assert_eq!(stats.idle_timeouts.load(Ordering::Relaxed), 0);

    // Peer close (not idle): outstanding work drained via query_timeout, idle never fired.
    drop(client);
    poll_until(
        || stats.closed.load(Ordering::Relaxed) >= 1,
        Duration::from_secs(2),
    )
    .await;
    assert_eq!(stats.idle_timeouts.load(Ordering::Relaxed), 0);
    h.stop().await;
}

#[tokio::test]
async fn per_query_rate_limit_refused() {
    let limits = Limits {
        rate_per_source: TokenRate {
            per_second: 1,
            burst: 1,
        },
        ..Limits::default()
    };
    let h = TcpHarness::spawn(
        SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
        Arc::new(FakeHandler::new(fake_a_answer(Ipv4Addr::new(192, 0, 2, 7)))),
        limits,
        Arc::new(SystemClock),
    )
    .await;

    let mut client = TcpStream::connect(h.addr).await.unwrap();
    for i in 0..5u16 {
        write_frame(
            &mut client,
            &encode_a_query(i + 1, &format!("r{i}.example.com.")),
        )
        .await
        .unwrap();
    }

    let mut noerror = 0;
    let mut refused = 0;
    for _ in 0..5 {
        let resp = read_frame(&mut client).await.unwrap();
        match Message::decode(&resp).unwrap().rcode() {
            Rcode::NOERROR => noerror += 1,
            Rcode::REFUSED => refused += 1,
            other => panic!("unexpected rcode {other:?}"),
        }
    }
    assert_eq!(noerror, 1);
    assert_eq!(refused, 4);
    poll_until(
        || h.stats.refused.load(Ordering::Relaxed) >= 4,
        Duration::from_secs(2),
    )
    .await;
    h.stop().await;
}

#[tokio::test]
async fn query_timeout_servfail() {
    let clock = Arc::new(ManualClock::new(
        SystemTime::UNIX_EPOCH + Duration::from_secs(8_000),
    ));
    let limits = Limits {
        query_timeout: Duration::from_secs(2),
        tcp_idle_timeout: Duration::from_secs(60),
        ..Limits::default()
    };
    let h = TcpHarness::spawn(
        SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
        Arc::new(HangHandler),
        limits,
        Arc::clone(&clock) as Arc<dyn dnscraft_listeners::Clock>,
    )
    .await;

    let mut client = TcpStream::connect(h.addr).await.unwrap();
    write_frame(&mut client, &encode_a_query(42, "hang.example.com."))
        .await
        .unwrap();
    let stats = Arc::clone(&h.stats);
    poll_until(
        || stats.queries.load(Ordering::Relaxed) >= 1,
        Duration::from_secs(2),
    )
    .await;

    clock.advance(Duration::from_secs(3));
    let resp = tokio::time::timeout(Duration::from_secs(2), read_frame(&mut client))
        .await
        .expect("servfail answer")
        .unwrap();
    let msg = Message::decode(&resp).unwrap();
    assert_eq!(msg.header.id, 42);
    assert_eq!(msg.rcode(), Rcode::SERVFAIL);
    h.stop().await;
}

#[test]
fn keepalive_units() {
    assert_eq!(duration_to_keepalive_units(Duration::from_secs(10)), 100);
}
