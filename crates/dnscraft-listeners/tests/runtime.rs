//! ListenerSet runtime: partial bind, reload, events, shutdown drain (N11).

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod support;

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use dnscraft_listeners::{
    ChannelSink, EmptyClientIds, Exposure, FakeHandler, Limits, ListenerConfig, ListenerSet,
    ListenerSetParams, ListenersConfig, Protocol, SystemClock, bind_udp, emit_event, read_frame,
    write_frame,
};
use dnscraft_policy::{ListenerId, PolicyAnswer, RequestContext};
use dnscraft_proto::{Message, Name, RecordType};
use support::{encode_a_query, fake_a_answer, poll_until, query_udp};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::Notify;

fn udp_cfg(id: &str, addr: SocketAddr) -> ListenerConfig {
    ListenerConfig {
        id: ListenerId::new(id).unwrap(),
        protocol: Protocol::Udp53,
        address: addr,
        exposure: Exposure::Local,
        h3: false,
    }
}

fn tcp_cfg(id: &str, addr: SocketAddr) -> ListenerConfig {
    ListenerConfig {
        id: ListenerId::new(id).unwrap(),
        protocol: Protocol::Tcp53,
        address: addr,
        exposure: Exposure::Local,
        h3: false,
    }
}

fn base_cfg(listeners: Vec<ListenerConfig>) -> ListenersConfig {
    ListenersConfig {
        listeners,
        limits: Limits::default(),
        ..ListenersConfig::default()
    }
}

async fn start_set(
    cfg: ListenersConfig,
    handler: Arc<FakeHandler>,
    sink: Arc<dyn dnscraft_listeners::QueryEventSink>,
) -> ListenerSet<FakeHandler> {
    ListenerSet::start_with(ListenerSetParams {
        config: cfg,
        handler,
        certs: None,
        sink,
        clock: Arc::new(SystemClock),
        public_domain: "example.com".into(),
        client_ids: Arc::new(EmptyClientIds),
    })
    .await
    .unwrap()
}

#[tokio::test]
async fn runtime_partial_bind_failure_others_serve() {
    let held = bind_udp(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
    let busy = held.local_addr().unwrap();

    let free_bind = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
    let cfg = base_cfg(vec![
        udp_cfg("ok-udp", free_bind),
        udp_cfg("busy-udp", busy),
    ]);
    let (sink, _rx) = ChannelSink::new(64);
    let handler = Arc::new(FakeHandler::new(fake_a_answer(Ipv4Addr::new(192, 0, 2, 1))));
    let set = start_set(cfg, handler, sink).await;

    let status = set.status();
    let ok = status
        .listeners
        .iter()
        .find(|l| l.id.as_str() == "ok-udp")
        .unwrap();
    let bad = status
        .listeners
        .iter()
        .find(|l| l.id.as_str() == "busy-udp")
        .unwrap();
    assert!(ok.bound.is_some(), "ok listener should bind");
    assert!(bad.bound.is_none());
    assert_eq!(bad.error.as_ref().map(|e| e.code()), Some("listeners.bind"));

    let addr = ok.bound.unwrap();
    let (wire, _) = query_udp(addr, &encode_a_query(1, "example.com.")).await;
    let msg = Message::decode(&wire).unwrap();
    assert_eq!(msg.answers.len(), 1);

    drop(held);
    set.shutdown(Duration::from_secs(2)).await;
}

#[tokio::test]
async fn runtime_reload_keeps_tcp_connection() {
    let cfg = base_cfg(vec![tcp_cfg(
        "lan-tcp",
        SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
    )]);
    let (sink, _rx) = ChannelSink::new(64);
    let handler = Arc::new(FakeHandler::new(fake_a_answer(Ipv4Addr::new(192, 0, 2, 2))));
    let set = start_set(cfg.clone(), handler, sink).await;

    let tcp_addr = set
        .status()
        .listeners
        .iter()
        .find(|l| l.id.as_str() == "lan-tcp")
        .unwrap()
        .bound
        .unwrap();

    let mut stream = TcpStream::connect(tcp_addr).await.unwrap();
    write_frame(&mut stream, &encode_a_query(7, "example.com."))
        .await
        .unwrap();
    let first = read_frame(&mut stream).await.unwrap();
    assert!(!first.is_empty());

    // Add UDP listener; TCP config unchanged → open connection survives.
    let mut next = cfg;
    next.listeners.push(udp_cfg(
        "lan-udp",
        SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
    ));
    set.apply_config(next.clone()).await.unwrap();

    write_frame(&mut stream, &encode_a_query(8, "example.com."))
        .await
        .unwrap();
    let second = tokio::time::timeout(Duration::from_secs(2), read_frame(&mut stream))
        .await
        .expect("tcp still alive after reload")
        .unwrap();
    assert!(!second.is_empty());

    // Change TCP to a concrete free port (config still has :0 until now) → rebind.
    let probe = tokio::net::TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .await
        .unwrap();
    let free = probe.local_addr().unwrap();
    drop(probe);

    let mut moved = next;
    let old_id = ListenerId::new("lan-tcp").unwrap();
    if let Some(l) = moved.listeners.iter_mut().find(|l| l.id == old_id) {
        l.address = free;
    }
    set.apply_config(moved).await.unwrap();

    let write_after = write_frame(&mut stream, &encode_a_query(9, "example.com.")).await;
    assert!(
        write_after.is_err()
            || tokio::time::timeout(Duration::from_millis(500), read_frame(&mut stream))
                .await
                .is_err(),
        "rebound tcp should close old connection"
    );

    let new_tcp = set
        .status()
        .listeners
        .iter()
        .find(|l| l.id.as_str() == "lan-tcp")
        .unwrap()
        .bound
        .unwrap();
    assert_eq!(new_tcp, free);
    assert_ne!(new_tcp, tcp_addr);

    // Remove UDP → only TCP remains.
    let only_tcp = base_cfg(vec![tcp_cfg("lan-tcp", free)]);
    set.apply_config(only_tcp).await.unwrap();
    assert_eq!(set.status().listeners.len(), 1);
    assert!(
        set.status()
            .listeners
            .iter()
            .all(|l| l.id.as_str() != "lan-udp")
    );

    set.shutdown(Duration::from_secs(2)).await;
}

#[tokio::test]
async fn runtime_full_sink_never_blocks_and_test_query_silent() {
    let cfg = base_cfg(vec![udp_cfg(
        "lan-udp",
        SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
    )]);
    let (sink, mut rx) = ChannelSink::new(1);
    // Stall the consumer: fill the single slot, leave receiver unread for further drops.
    let handler = Arc::new(FakeHandler::new(fake_a_answer(Ipv4Addr::new(192, 0, 2, 3))));
    let set = start_set(cfg, Arc::clone(&handler), Arc::clone(&sink) as _).await;
    let addr = set.status().listeners[0].bound.unwrap();

    // First answer fills the sink.
    let _ = query_udp(addr, &encode_a_query(1, "example.com.")).await;
    poll_until(
        || sink.events_dropped() > 0 || rx.try_recv().is_ok(),
        Duration::from_secs(2),
    )
    .await;

    // Drain one so we know the channel mechanics, then leave it full.
    let _ = rx.try_recv();
    // Fill again and keep consumer stalled.
    let _ = query_udp(addr, &encode_a_query(2, "example.com.")).await;
    poll_until(
        || rx.try_recv().is_ok() || sink.events_dropped() > 0,
        Duration::from_secs(2),
    )
    .await;
    // Leave event in channel (do not recv) and send more — must still answer.
    for i in 3u16..8 {
        let (wire, _) = query_udp(addr, &encode_a_query(i, "example.com.")).await;
        assert!(!wire.is_empty(), "full sink must not block answering");
    }
    assert!(sink.events_dropped() > 0 || set.status().events_dropped > 0);

    // loggable=false (test_query) → no event.
    let mut silent = fake_a_answer(Ipv4Addr::new(192, 0, 2, 9));
    silent.loggable = false;
    handler.set_answer(silent);
    let before = sink.events_dropped();
    // Clear channel so a wrongly-emitted event would be receivable.
    while rx.try_recv().is_ok() {}
    let _ = query_udp(addr, &encode_a_query(99, "example.com.")).await;
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(
        rx.try_recv().is_err(),
        "test_query / non-loggable must not emit"
    );
    assert_eq!(sink.events_dropped(), before);

    // Direct emit_event unit path for loggable=false (belt and braces).
    let clock = SystemClock;
    let mut ev = {
        // Build via a loggable answer path then flip — use emit_event API.
        use dnscraft_filtering::SetId;
        use dnscraft_policy::{
            AnswerOrigin, DecisionRecord, DecisionTimings, DnsProtocol, ProfileId, SelectionCause,
            ViewId,
        };
        use dnscraft_proto::{Class, Rcode};
        use dnscraft_resolver::Query;
        use std::time::SystemTime;
        dnscraft_listeners::QueryEvent {
            time: SystemTime::UNIX_EPOCH,
            protocol: DnsProtocol::Udp53,
            listener_id: ListenerId::new("lan-udp").unwrap(),
            source: Ipv4Addr::LOCALHOST.into(),
            client_id: None,
            query: Query {
                name: Name::from_ascii("example.com.").unwrap(),
                qtype: RecordType::A,
                qclass: Class::IN,
            },
            rcode: Rcode::NOERROR,
            answer_size: 1,
            duration: Duration::from_millis(1),
            decision: DecisionRecord {
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
    };
    ev.loggable = false;
    emit_event(sink.as_ref(), &clock, ev);
    assert!(rx.try_recv().is_err());

    set.shutdown(Duration::from_secs(2)).await;
}

#[tokio::test]
async fn runtime_apply_limits_change_enforces_new_per_source_cap() {
    let mut cfg = base_cfg(vec![tcp_cfg(
        "lan-tcp",
        SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
    )]);
    cfg.limits.max_connections_per_source = 1;
    let (sink, _rx) = ChannelSink::new(64);
    let handler = Arc::new(FakeHandler::new(fake_a_answer(Ipv4Addr::new(192, 0, 2, 5))));
    let set = start_set(cfg.clone(), handler, sink).await;
    let addr = set.status().listeners[0].bound.unwrap();

    // Cap 1: the first connection is accepted, the second is rejected.
    let _c1 = TcpStream::connect(addr).await.unwrap();
    poll_until(
        || set.status().listeners[0].connections >= 1,
        Duration::from_secs(2),
    )
    .await;
    let _c2 = TcpStream::connect(addr).await.unwrap();
    poll_until(
        || set.status().listeners[0].dropped >= 1,
        Duration::from_secs(2),
    )
    .await;

    // Raise the cap: limits changed, so the listener restarts with the new value.
    let mut next = cfg;
    next.limits.max_connections_per_source = 2;
    set.apply_config(next).await.unwrap();
    let addr2 = set.status().listeners[0].bound.unwrap();

    // Cap 2: two connections from the same source are both accepted.
    let _c3 = TcpStream::connect(addr2).await.unwrap();
    let _c4 = TcpStream::connect(addr2).await.unwrap();
    poll_until(
        || set.status().listeners[0].connections >= 2,
        Duration::from_secs(2),
    )
    .await;
    assert_eq!(
        set.status().listeners[0].dropped,
        0,
        "cap 2 must accept both connections"
    );

    set.shutdown(Duration::from_secs(2)).await;
}

#[tokio::test]
async fn runtime_rate_only_change_keeps_tcp_connection() {
    let cfg = base_cfg(vec![tcp_cfg(
        "lan-tcp",
        SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
    )]);
    let (sink, _rx) = ChannelSink::new(64);
    let handler = Arc::new(FakeHandler::new(fake_a_answer(Ipv4Addr::new(192, 0, 2, 7))));
    let set = start_set(cfg.clone(), handler, sink).await;

    let tcp_addr = set.status().listeners[0].bound.unwrap();
    let mut stream = TcpStream::connect(tcp_addr).await.unwrap();
    write_frame(&mut stream, &encode_a_query(7, "example.com."))
        .await
        .unwrap();
    let first = read_frame(&mut stream).await.unwrap();
    assert!(!first.is_empty());

    // Change only admission rate limits; no listener should restart.
    let mut next = cfg;
    next.limits.rate_per_source.per_second = 9999;
    next.limits.rate_per_source.burst = 19998;
    next.limits.rate_per_client_id.per_second = 42;
    next.limits.rate_per_client_id.burst = 84;
    set.apply_config(next).await.unwrap();

    let addr_after = set.status().listeners[0].bound.unwrap();
    assert_eq!(
        addr_after, tcp_addr,
        "rate-only change must keep the listener socket"
    );

    write_frame(&mut stream, &encode_a_query(8, "example.com."))
        .await
        .unwrap();
    let second = tokio::time::timeout(Duration::from_secs(2), read_frame(&mut stream))
        .await
        .expect("tcp still alive after rate-only reload")
        .unwrap();
    assert!(!second.is_empty());

    set.shutdown(Duration::from_secs(2)).await;
}

#[tokio::test]
async fn runtime_concurrent_apply_config_ends_consistent() {
    let base = base_cfg(vec![udp_cfg(
        "lan-udp",
        SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
    )]);
    let (sink, _rx) = ChannelSink::new(64);
    let handler = Arc::new(FakeHandler::new(fake_a_answer(Ipv4Addr::new(192, 0, 2, 6))));
    let set = start_set(base.clone(), handler, sink).await;

    let mut a = base.clone();
    a.listeners.push(udp_cfg(
        "udp-a",
        SocketAddr::from((Ipv4Addr::new(127, 0, 0, 2), 0)),
    ));
    let mut b = base;
    b.listeners.push(udp_cfg(
        "udp-b",
        SocketAddr::from((Ipv4Addr::new(127, 0, 0, 3), 0)),
    ));

    let (ra, rb) = tokio::join!(set.apply_config(a), set.apply_config(b));
    ra.unwrap();
    rb.unwrap();

    let status = set.status();
    let ids: Vec<&str> = status.listeners.iter().map(|l| l.id.as_str()).collect();
    assert!(
        ids == ["lan-udp", "udp-a"] || ids == ["lan-udp", "udp-b"],
        "final listeners must match exactly one config, got {ids:?}"
    );

    set.shutdown(Duration::from_secs(2)).await;
}

struct GateHandler {
    entered: Arc<Notify>,
    release: Arc<Notify>,
    done: Arc<AtomicBool>,
    answer: PolicyAnswer,
}

impl dnscraft_listeners::QueryHandler for GateHandler {
    async fn handle(
        &self,
        _ctx: RequestContext,
    ) -> Result<PolicyAnswer, dnscraft_policy::PolicyError> {
        self.entered.notify_one();
        self.release.notified().await;
        self.done.store(true, Ordering::SeqCst);
        Ok(self.answer.clone())
    }
}

#[tokio::test]
async fn runtime_shutdown_drains_inflight_within_grace() {
    let entered = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let done = Arc::new(AtomicBool::new(false));
    let handler = Arc::new(GateHandler {
        entered: Arc::clone(&entered),
        release: Arc::clone(&release),
        done: Arc::clone(&done),
        answer: fake_a_answer(Ipv4Addr::new(192, 0, 2, 4)),
    });

    let cfg = base_cfg(vec![udp_cfg(
        "lan-udp",
        SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
    )]);
    let (sink, _rx) = ChannelSink::new(16);
    let set = ListenerSet::start_with(ListenerSetParams {
        config: cfg,
        handler,
        certs: None,
        sink,
        clock: Arc::new(SystemClock),
        public_domain: "example.com".into(),
        client_ids: Arc::new(EmptyClientIds),
    })
    .await
    .unwrap();

    let addr = set.status().listeners[0].bound.unwrap();
    let client = UdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .await
        .unwrap();
    client
        .send_to(&encode_a_query(1, "example.com."), addr)
        .await
        .unwrap();

    tokio::time::timeout(Duration::from_secs(2), entered.notified())
        .await
        .expect("handler should start");

    let shutdown = tokio::spawn(async move {
        set.shutdown(Duration::from_secs(3)).await;
    });

    // Let shutdown begin (stop accepting + wait for inflight), then release the query.
    tokio::time::sleep(Duration::from_millis(50)).await;
    release.notify_one();

    tokio::time::timeout(Duration::from_secs(3), shutdown)
        .await
        .expect("shutdown within grace")
        .unwrap();
    assert!(done.load(Ordering::SeqCst), "in-flight query must finish");
}
