//! Do53 TCP listener tests (N5).

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod support;

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use dnscraft_listeners::{
    Exposure, FakeHandler, Limits, ListenerConfig, ManualClock, OPTION_TCP_KEEPALIVE, Protocol,
    PublicConfig, SystemClock, TcpServeParams, TcpStats, duration_to_keepalive_units, read_frame,
    serve_tcp, write_frame,
};
use dnscraft_policy::{ListenerId, PolicyAnswer, RequestContext};
use dnscraft_proto::{Edns, EdnsOption, Message, Name, Rcode, RecordType};
use support::{encode_a_query, fake_a_answer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{Notify, oneshot, watch};

fn listener_cfg(addr: SocketAddr) -> ListenerConfig {
    ListenerConfig {
        id: ListenerId::new("test-tcp").unwrap(),
        protocol: Protocol::Tcp53,
        address: addr,
        exposure: Exposure::Local,
        h3: false,
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
        let join = tokio::spawn(serve_tcp(TcpServeParams {
            listener: listener_cfg(bind),
            limits,
            public: PublicConfig::default(),
            handler,
            clock,
            stats: Arc::clone(&stats),
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
    /// Released when the slow (`one.*`) query may answer.
    first_gate: Arc<Notify>,
    /// Signalled when the fast (`two.*`) query is in the handler.
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
    let q1 = encode_a_query(100, "one.example.com.");
    let q2 = encode_a_query(200, "two.example.com.");
    write_frame(&mut client, &q1).await.unwrap();
    write_frame(&mut client, &q2).await.unwrap();

    // Wait until the second query is in the handler, then release the first.
    tokio::time::timeout(Duration::from_secs(2), second_seen.notified())
        .await
        .expect("second query");
    first_gate.notify_waiters();

    let a = read_frame(&mut client).await.unwrap();
    let b = read_frame(&mut client).await.unwrap();
    let id_a = Message::decode(&a).unwrap().header.id;
    let id_b = Message::decode(&b).unwrap().header.id;
    // Second query (id 200) must arrive first.
    assert_eq!(id_a, 200, "fast second answer should come first");
    assert_eq!(id_b, 100, "slow first answer should come second");

    h.stop().await;
}

#[tokio::test]
async fn idle_timeout_closes() {
    let clock = Arc::new(ManualClock::new(
        std::time::SystemTime::UNIX_EPOCH + Duration::from_secs(1_000),
    ));
    let limits = Limits {
        tcp_idle_timeout: Duration::from_secs(2),
        ..Limits::default()
    };
    let h = TcpHarness::spawn(
        SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
        Arc::new(FakeHandler::new(fake_a_answer(Ipv4Addr::new(192, 0, 2, 1)))),
        limits,
        clock.clone() as Arc<dyn dnscraft_listeners::Clock>,
    )
    .await;

    let client = TcpStream::connect(h.addr).await.unwrap();
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert_eq!(h.stats.accepted.load(Ordering::Relaxed), 1);

    clock.advance(Duration::from_secs(3));
    // Give the server task a turn to observe the clock.
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(
        h.stats.idle_timeouts.load(Ordering::Relaxed) >= 1,
        "idle timeout should close the connection"
    );
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
    tokio::time::sleep(Duration::from_millis(30)).await;
    let _c2 = TcpStream::connect(h.addr).await.unwrap();
    tokio::time::sleep(Duration::from_millis(30)).await;
    assert!(
        h.stats.rejected_conn_cap.load(Ordering::Relaxed) >= 1,
        "second connection must hit listener cap"
    );
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
    tokio::time::sleep(Duration::from_millis(30)).await;
    let _c2 = TcpStream::connect(h.addr).await.unwrap();
    tokio::time::sleep(Duration::from_millis(30)).await;
    assert!(h.stats.rejected_per_source.load(Ordering::Relaxed) >= 1);
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

    // Half length prefix then close → framing error
    {
        let mut c = TcpStream::connect(h.addr).await.unwrap();
        c.write_all(&[0x00]).await.unwrap();
        c.flush().await.unwrap();
        drop(c);
    }
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(
        h.stats.framing_errors.load(Ordering::Relaxed) >= 1,
        "half length prefix must count as framing error"
    );

    // length 0 is invalid
    {
        let mut c = TcpStream::connect(h.addr).await.unwrap();
        c.write_all(&0u16.to_be_bytes()).await.unwrap();
        c.flush().await.unwrap();
        let mut buf = [0u8; 8];
        let _ = tokio::time::timeout(Duration::from_millis(200), c.read(&mut buf)).await;
    }
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(h.stats.framing_errors.load(Ordering::Relaxed) >= 2);
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
    let wire = q.encode().unwrap();

    let mut client = TcpStream::connect(h.addr).await.unwrap();
    write_frame(&mut client, &wire).await.unwrap();
    let resp = read_frame(&mut client).await.unwrap();
    let msg = Message::decode(&resp).unwrap();
    assert_eq!(msg.rcode(), Rcode::NOERROR);
    let opt = msg.edns.as_ref().expect("OPT");
    let ka = opt
        .options
        .iter()
        .find(|o| matches!(o, EdnsOption::Unknown { code, .. } if *code == OPTION_TCP_KEEPALIVE))
        .expect("keepalive option");
    if let EdnsOption::Unknown { data, .. } = ka {
        assert_eq!(data.len(), 2);
        let units = u16::from_be_bytes([data[0], data[1]]);
        assert_eq!(units, duration_to_keepalive_units(Duration::from_secs(10)));
    }
    h.stop().await;
}

#[test]
fn keepalive_units() {
    assert_eq!(duration_to_keepalive_units(Duration::from_secs(10)), 100);
}
