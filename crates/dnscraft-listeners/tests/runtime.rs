//! ListenerSet runtime: partial bind, reload, events, shutdown drain (N11).

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod support;

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use dnscraft_listeners::{
    ChannelSink, EmptyClientIds, Exposure, FakeHandler, Limits, ListenerConfig, ListenerSet,
    ListenerSetParams, ListenersConfig, Protocol, PublicConfig, SystemClock, bind_tcp, bind_udp,
    default_classifier, emit_event, read_frame, write_frame,
};
use dnscraft_policy::{ListenerId, PolicyAnswer, RequestContext};
use dnscraft_proto::{Message, Name, RecordType};
use dnscraft_tls::CertResolver;
use support::{encode_a_query, fake_a_answer, poll_until, query_udp};
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::Notify;

fn udp_cfg(id: &str, addr: SocketAddr) -> ListenerConfig {
    ListenerConfig {
        node_id: None,
        id: ListenerId::new(id).unwrap(),
        protocol: Protocol::Udp53,
        address: addr,
        exposure: Exposure::Local,
        h3: false,
        tls_policy: None,
    }
}

fn tcp_cfg(id: &str, addr: SocketAddr) -> ListenerConfig {
    ListenerConfig {
        node_id: None,
        id: ListenerId::new(id).unwrap(),
        protocol: Protocol::Tcp53,
        address: addr,
        exposure: Exposure::Local,
        h3: false,
        tls_policy: None,
    }
}

fn doh_cfg(id: &str, addr: SocketAddr, h3: bool) -> ListenerConfig {
    ListenerConfig {
        node_id: None,
        id: ListenerId::new(id).unwrap(),
        protocol: Protocol::Doh,
        address: addr,
        exposure: Exposure::Local,
        h3,
        tls_policy: None,
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
        node_id: None,
        config: cfg,
        handler,
        certs: None,
        sink,
        clock: Arc::new(SystemClock),
        public_domain: "example.com".into(),
        client_ids: Arc::new(EmptyClientIds),
        classify: default_classifier(),
    })
    .await
    .unwrap()
}

async fn one_query(set: &ListenerSet<FakeHandler>) {
    let addr = set.status().listeners[0].bound.unwrap();
    let _ = query_udp(addr, &encode_a_query(1, "example.com.")).await;
    poll_until(
        || set.status().listeners[0].queries >= 1,
        Duration::from_secs(2),
    )
    .await;
}

/// S1: every `Limits` field is classified as listener-affecting (restart) or
/// admission-only (no restart), exercised end-to-end through `apply_config`.
/// A restart rebinds the UDP socket and resets its `queries` counter, so the
/// counter is the restart signal.
#[tokio::test]
async fn runtime_limits_fields_restart_vs_no_restart() {
    let cfg = base_cfg(vec![udp_cfg(
        "lan-udp",
        SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
    )]);
    let (sink, _rx) = ChannelSink::new(64);
    let handler = Arc::new(FakeHandler::new(fake_a_answer(Ipv4Addr::new(
        192, 0, 2, 10,
    ))));
    let set = start_set(cfg.clone(), handler, sink).await;

    type LimitsCase = (&'static str, fn(&mut Limits));
    let listener_cases: &[LimitsCase] = &[
        ("udp_payload_max", |l| l.udp_payload_max = 4096),
        ("query_timeout", |l| {
            l.query_timeout = Duration::from_secs(30)
        }),
        ("tcp_idle_timeout", |l| {
            l.tcp_idle_timeout = Duration::from_secs(30)
        }),
        ("tls_handshake_timeout", |l| {
            l.tls_handshake_timeout = Duration::from_secs(30)
        }),
        ("max_inflight_per_listener", |l| {
            l.max_inflight_per_listener = 8
        }),
        ("max_connections_per_listener", |l| {
            l.max_connections_per_listener = 8
        }),
        ("max_connections_per_source", |l| {
            l.max_connections_per_source = 8
        }),
        ("max_quic_streams_per_connection", |l| {
            l.max_quic_streams_per_connection = 8
        }),
        ("max_queries_per_connection", |l| {
            l.max_queries_per_connection = 8
        }),
    ];
    // Accumulate each change so every apply_config mutates exactly one field
    // relative to the running config (otherwise later cases would also revert
    // the earlier listener-affecting edits and spuriously restart).
    let mut current = cfg.clone();
    for (name, apply) in listener_cases {
        one_query(&set).await;
        apply(&mut current.limits);
        set.apply_config(current.clone()).await.unwrap();
        assert_eq!(
            set.status().listeners[0].queries,
            0,
            "{name} change must restart the listener (queries counter reset)"
        );
    }

    let admission_cases: &[LimitsCase] = &[
        ("rate_per_source", |l| l.rate_per_source.per_second = 9999),
        ("rate_per_client_id", |l| {
            l.rate_per_client_id.per_second = 9999
        }),
    ];
    for (name, apply) in admission_cases {
        one_query(&set).await;
        apply(&mut current.limits);
        set.apply_config(current.clone()).await.unwrap();
        assert!(
            set.status().listeners[0].queries >= 1,
            "{name} change must not restart the listener (queries counter kept)"
        );
    }

    set.shutdown(Duration::from_secs(2)).await;
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

/// GL1: a DoH `h3 = true` listener whose UDP/QUIC half fails to bind must be
/// reported as failed (never as bound) and must not hang startup.
#[tokio::test]
async fn runtime_doh_h3_udp_bind_failure_reported_without_hang() {
    // Reserve a port for TCP, then hold the same port with UDP so the h3 half
    // fails while the TCP half binds.
    let probe = bind_tcp(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
    let addr = probe.local_addr().unwrap();
    drop(probe);
    let held_udp = bind_udp(addr).unwrap();

    let cfg = base_cfg(vec![doh_cfg("doh-h3", addr, true)]);
    let (sink, _rx) = ChannelSink::new(64);
    let handler = Arc::new(FakeHandler::new(fake_a_answer(Ipv4Addr::new(
        192, 0, 2, 31,
    ))));
    let params = ListenerSetParams {
        node_id: None,
        config: cfg,
        handler,
        certs: None,
        sink,
        clock: Arc::new(SystemClock),
        public_domain: "example.com".into(),
        client_ids: Arc::new(EmptyClientIds),
        classify: default_classifier(),
    };
    let set = tokio::time::timeout(Duration::from_secs(3), ListenerSet::start_with(params))
        .await
        .expect("start must not hang on a partial DoH h3 bind")
        .unwrap();

    let status = set.status();
    let listener = &status.listeners[0];
    assert!(
        listener.bound.is_none(),
        "a DoH listener whose h3 half failed must not be reported as bound"
    );
    assert_eq!(
        listener.error.as_ref().map(|e| e.code()),
        Some("listeners.bind")
    );

    drop(held_udp);
    set.shutdown(Duration::from_secs(2)).await;
}

/// GL1 (reverse): TCP half fails, UDP/QUIC half binds — same reporting and no
/// hang (the still-running QUIC listener must not block the bind report).
#[tokio::test]
async fn runtime_doh_h3_tcp_bind_failure_reported_without_hang() {
    let held_tcp = bind_tcp(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
    let addr = held_tcp.local_addr().unwrap();

    let cfg = base_cfg(vec![doh_cfg("doh-h3", addr, true)]);
    let (sink, _rx) = ChannelSink::new(64);
    let handler = Arc::new(FakeHandler::new(fake_a_answer(Ipv4Addr::new(
        192, 0, 2, 32,
    ))));
    let params = ListenerSetParams {
        node_id: None,
        config: cfg,
        handler,
        certs: None,
        sink,
        clock: Arc::new(SystemClock),
        public_domain: "example.com".into(),
        client_ids: Arc::new(EmptyClientIds),
        classify: default_classifier(),
    };
    let set = tokio::time::timeout(Duration::from_secs(3), ListenerSet::start_with(params))
        .await
        .expect("start must not hang when the DoH TCP half fails to bind")
        .unwrap();

    let status = set.status();
    let listener = &status.listeners[0];
    assert!(listener.bound.is_none());
    assert_eq!(
        listener.error.as_ref().map(|e| e.code()),
        Some("listeners.bind")
    );

    drop(held_tcp);
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
async fn runtime_reload_keeps_bans_across_rate_and_public_changes() {
    // Public DoT listener with loopback classified public; one strike bans.
    let (pem, key, _der) = support::certs::example_dns_cert();
    let certs = Arc::new(CertResolver::new());
    certs.install(&pem, &key).unwrap();

    let cfg = ListenersConfig {
        listeners: vec![ListenerConfig {
            node_id: None,
            id: ListenerId::new("pub-dot").unwrap(),
            protocol: Protocol::Dot,
            address: SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
            exposure: Exposure::Public,
            h3: false,
            tls_policy: None,
        }],
        limits: Limits {
            tls_handshake_timeout: Duration::from_millis(500),
            ..Limits::default()
        },
        public: PublicConfig {
            enabled: true,
            ban_strikes: 1,
            ..PublicConfig::default()
        },
        ..ListenersConfig::default()
    };
    let (sink, _rx) = ChannelSink::new(64);
    let handler = Arc::new(FakeHandler::new(fake_a_answer(Ipv4Addr::new(192, 0, 2, 8))));
    let set = ListenerSet::start_with(ListenerSetParams {
        node_id: None,
        config: cfg.clone(),
        handler,
        certs: Some(certs),
        sink,
        clock: Arc::new(SystemClock),
        public_domain: "example.com".into(),
        client_ids: Arc::new(EmptyClientIds),
        classify: support::loopback_as_public(),
    })
    .await
    .unwrap();

    let addr = set.status().listeners[0].bound.unwrap();

    // A non-TLS client on a public DoT listener fails the handshake → one strike
    // (ban_strikes = 1) bans the loopback source through the real admission path.
    {
        let mut tcp = TcpStream::connect(addr).await.unwrap();
        let _ = tcp.write_all(b"not-a-tls-client-hello").await;
    }
    poll_until(|| set.status().ban_entries >= 1, Duration::from_secs(2)).await;

    // Banned source is now dropped before any TLS work.
    let dropped_before = set.status().listeners[0].dropped;
    let _ = TcpStream::connect(addr).await.unwrap();
    poll_until(
        || set.status().listeners[0].dropped > dropped_before,
        Duration::from_secs(2),
    )
    .await;

    // Reload that changes only admission rates must keep the ban.
    let mut rate_only = cfg.clone();
    rate_only.limits.rate_per_source.per_second = 9999;
    rate_only.limits.rate_per_source.burst = 19998;
    rate_only.limits.rate_per_client_id.per_second = 42;
    rate_only.limits.rate_per_client_id.burst = 84;
    set.apply_config(rate_only).await.unwrap();
    assert_eq!(
        set.status().ban_entries,
        1,
        "ban must survive a rate-only reload"
    );

    // A new connection from the banned source is still dropped pre-handshake.
    let dropped_after_rate = set.status().listeners[0].dropped;
    let _ = TcpStream::connect(addr).await.unwrap();
    poll_until(
        || set.status().listeners[0].dropped > dropped_after_rate,
        Duration::from_secs(2),
    )
    .await;

    // Reload that changes public ban params must keep the ban too.
    let mut public_change = cfg;
    public_change.public.ban_duration = Duration::from_secs(3600);
    set.apply_config(public_change).await.unwrap();
    assert_eq!(
        set.status().ban_entries,
        1,
        "ban must survive a public-params reload"
    );

    // Still dropped pre-handshake after the public-params reload too.
    let dropped_after_public = set.status().listeners[0].dropped;
    let _ = TcpStream::connect(addr).await.unwrap();
    poll_until(
        || set.status().listeners[0].dropped > dropped_after_public,
        Duration::from_secs(2),
    )
    .await;

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
        node_id: None,
        config: cfg,
        handler,
        certs: None,
        sink,
        clock: Arc::new(SystemClock),
        public_domain: "example.com".into(),
        client_ids: Arc::new(EmptyClientIds),
        classify: default_classifier(),
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

/// GL4: shutdown drains in-flight queries on TCP too (previously the
/// connection loop aborted them on the listener-shutdown signal).
#[tokio::test]
async fn runtime_shutdown_drains_tcp_inflight_within_grace() {
    let entered = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let done = Arc::new(AtomicBool::new(false));
    let handler = Arc::new(GateHandler {
        entered: Arc::clone(&entered),
        release: Arc::clone(&release),
        done: Arc::clone(&done),
        answer: fake_a_answer(Ipv4Addr::new(192, 0, 2, 33)),
    });

    let cfg = base_cfg(vec![tcp_cfg(
        "lan-tcp",
        SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
    )]);
    let (sink, _rx) = ChannelSink::new(16);
    let set = ListenerSet::start_with(ListenerSetParams {
        node_id: None,
        config: cfg,
        handler,
        certs: None,
        sink,
        clock: Arc::new(SystemClock),
        public_domain: "example.com".into(),
        client_ids: Arc::new(EmptyClientIds),
        classify: default_classifier(),
    })
    .await
    .unwrap();

    let addr = set.status().listeners[0].bound.unwrap();
    let mut client = TcpStream::connect(addr).await.unwrap();
    write_frame(&mut client, &encode_a_query(1, "example.com."))
        .await
        .unwrap();

    tokio::time::timeout(Duration::from_secs(2), entered.notified())
        .await
        .expect("handler should start");

    let shutdown = tokio::spawn(async move {
        set.shutdown(Duration::from_secs(3)).await;
    });

    tokio::time::sleep(Duration::from_millis(50)).await;
    release.notify_one();

    tokio::time::timeout(Duration::from_secs(3), shutdown)
        .await
        .expect("shutdown within grace")
        .unwrap();
    assert!(
        done.load(Ordering::SeqCst),
        "in-flight TCP query must finish during drain"
    );

    // The answer is still written before the connection closes.
    let resp = tokio::time::timeout(Duration::from_secs(2), read_frame(&mut client))
        .await
        .expect("drained TCP answer")
        .unwrap();
    assert_eq!(Message::decode(&resp).unwrap().header.id, 1);
}

/// S2: a listener that fails to rebind during `apply_config` records the bind
/// error in its status instead of failing the whole reload; unchanged
/// listeners keep serving.
#[tokio::test]
async fn runtime_apply_config_bind_failure_keeps_others() {
    let held = bind_udp(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
    let busy = held.local_addr().unwrap();

    let cfg = base_cfg(vec![
        udp_cfg("ok-udp", SocketAddr::from((Ipv4Addr::LOCALHOST, 0))),
        udp_cfg(
            "rebind-udp",
            SocketAddr::from((Ipv4Addr::new(127, 0, 0, 2), 0)),
        ),
    ]);
    let (sink, _rx) = ChannelSink::new(64);
    let handler = Arc::new(FakeHandler::new(fake_a_answer(Ipv4Addr::new(
        192, 0, 2, 12,
    ))));
    let set = start_set(cfg.clone(), handler, sink).await;

    // Re-point "rebind-udp" at the held port; "ok-udp" stays put.
    let mut next = cfg;
    if let Some(l) = next
        .listeners
        .iter_mut()
        .find(|l| l.id.as_str() == "rebind-udp")
    {
        l.address = busy;
    }
    set.apply_config(next).await.unwrap();

    let status = set.status();
    let ok = status
        .listeners
        .iter()
        .find(|l| l.id.as_str() == "ok-udp")
        .unwrap();
    let rebind = status
        .listeners
        .iter()
        .find(|l| l.id.as_str() == "rebind-udp")
        .unwrap();
    assert!(
        ok.bound.is_some(),
        "unchanged listener must keep its socket"
    );
    assert!(rebind.bound.is_none(), "rebound listener must fail to bind");
    assert_eq!(
        rebind.error.as_ref().map(|e| e.code()),
        Some("listeners.bind")
    );

    // The unchanged listener still answers.
    let addr = ok.bound.unwrap();
    let (wire, _) = query_udp(addr, &encode_a_query(1, "example.com.")).await;
    assert!(!wire.is_empty());

    drop(held);
    set.shutdown(Duration::from_secs(2)).await;
}

/// S2: toggling `h3` on a DoH listener changes `ListenerConfig`, so the
/// listener restarts (fresh stats → `connections` resets to 0).
#[tokio::test]
async fn runtime_h3_toggle_restarts_doh_listener() {
    let cfg = base_cfg(vec![doh_cfg(
        "doh",
        SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
        false,
    )]);
    let (sink, _rx) = ChannelSink::new(64);
    let handler = Arc::new(FakeHandler::new(fake_a_answer(Ipv4Addr::new(
        192, 0, 2, 13,
    ))));
    let (pem, key, _der) = support::certs::example_dns_cert();
    let certs = Arc::new(CertResolver::new());
    certs.install(&pem, &key).unwrap();
    let set = ListenerSet::start_with(ListenerSetParams {
        node_id: None,
        config: cfg.clone(),
        handler,
        certs: Some(certs),
        sink,
        clock: Arc::new(SystemClock),
        public_domain: "example.com".into(),
        client_ids: Arc::new(EmptyClientIds),
        classify: default_classifier(),
    })
    .await
    .unwrap();

    // A raw TCP connect bumps the DoH `connections` counter (accepted pre-TLS;
    // with a cert installed the handshake waits instead of closing, so
    // `accepted - closed` stays 1).
    let addr = set.status().listeners[0].bound.unwrap();
    let _conn = TcpStream::connect(addr).await.unwrap();
    poll_until(
        || set.status().listeners[0].connections >= 1,
        Duration::from_secs(2),
    )
    .await;

    let mut h3_on = cfg.clone();
    h3_on.listeners[0].h3 = true;
    set.apply_config(h3_on).await.unwrap();
    assert_eq!(
        set.status().listeners[0].connections,
        0,
        "h3 false -> true must restart the DoH listener"
    );

    let addr2 = set.status().listeners[0].bound.unwrap();
    let _conn2 = TcpStream::connect(addr2).await.unwrap();
    poll_until(
        || set.status().listeners[0].connections >= 1,
        Duration::from_secs(2),
    )
    .await;

    let mut h3_off = cfg;
    h3_off.listeners[0].h3 = false;
    set.apply_config(h3_off).await.unwrap();
    assert_eq!(
        set.status().listeners[0].connections,
        0,
        "h3 true -> false must restart the DoH listener"
    );

    set.shutdown(Duration::from_secs(2)).await;
}

/// S2: `status()` must not panic or deadlock while `apply_config` rebinds
/// listeners concurrently.
#[tokio::test]
async fn runtime_status_reads_during_apply_config() {
    let mut listeners = Vec::new();
    for i in 0..20 {
        listeners.push(udp_cfg(
            &format!("udp-{i}"),
            SocketAddr::from((Ipv4Addr::new(127, 0, 0, (i + 1) as u8), 0)),
        ));
    }
    let cfg = base_cfg(listeners);
    let (sink, _rx) = ChannelSink::new(64);
    let handler = Arc::new(FakeHandler::new(fake_a_answer(Ipv4Addr::new(
        192, 0, 2, 14,
    ))));
    let set = Arc::new(start_set(cfg.clone(), handler, sink).await);

    // A limits change restarts every listener (stop + start all 20), giving the
    // concurrent status() reader a real reload to observe.
    let mut next = cfg;
    next.limits.udp_payload_max = 4096;
    let apply = {
        let set = Arc::clone(&set);
        tokio::spawn(async move { set.apply_config(next).await })
    };

    for _ in 0..1000 {
        let _ = set.status();
        tokio::task::yield_now().await;
    }

    apply
        .await
        .expect("apply_config task must not panic")
        .unwrap();
    assert_eq!(set.status().listeners.len(), 20, "all listeners rebound");
    let set = Arc::try_unwrap(set).unwrap_or_else(|_| panic!("only one Arc ref remains"));
    set.shutdown(Duration::from_secs(2)).await;
}

/// S2: `shutdown(grace)` returns within grace even when a client has opened a
/// connection and gone quiet (the accept loop stops; the connection task is
/// detached, so it cannot block shutdown).
#[tokio::test]
async fn runtime_shutdown_returns_with_stuck_connection() {
    let cfg = base_cfg(vec![tcp_cfg(
        "lan-tcp",
        SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
    )]);
    let (sink, _rx) = ChannelSink::new(64);
    let handler = Arc::new(FakeHandler::new(fake_a_answer(Ipv4Addr::new(
        192, 0, 2, 15,
    ))));
    let set = start_set(cfg, handler, sink).await;

    let addr = set.status().listeners[0].bound.unwrap();
    let _stuck = TcpStream::connect(addr).await.unwrap();
    poll_until(
        || set.status().listeners[0].connections >= 1,
        Duration::from_secs(2),
    )
    .await;

    tokio::time::timeout(Duration::from_secs(5), set.shutdown(Duration::from_secs(2)))
        .await
        .expect("shutdown must not hang on a stuck connection");
}
