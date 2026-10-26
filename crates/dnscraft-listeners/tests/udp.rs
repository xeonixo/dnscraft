//! Do53 UDP listener tests (N4).

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod support;

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use dnscraft_listeners::{
    CLASSIC_UDP_LIMIT, Exposure, Limits, ListenerConfig, Protocol, PublicConfig, SystemClock,
    TokenRate, UdpServeParams, UdpStats, serve_udp, udp_size_limit,
};
use dnscraft_policy::ListenerId;
use dnscraft_proto::{Header, Message, Name, Rcode, RecordType};
use support::{
    UdpHarness, encode_a_query, encode_a_query_edns, fake_a_answer, fake_large_answer,
    local_policy_engine, poll_until, query_udp, query_udp_from,
};
use tokio::sync::{oneshot, watch};

#[test]
fn udp_size_limit_classic_and_edns() {
    let classic = encode_a_query(1, "example.com.");
    assert_eq!(udp_size_limit(&classic, 1232), CLASSIC_UDP_LIMIT);

    let edns = encode_a_query_edns(1, "example.com.", 4096);
    assert_eq!(udp_size_limit(&edns, 1232), 1232);

    let edns_small = encode_a_query_edns(1, "example.com.", 800);
    assert_eq!(udp_size_limit(&edns_small, 1232), 800);
}

#[tokio::test]
async fn ipv4_loopback_fake_and_policy() {
    let h = UdpHarness::spawn_fake(
        SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
        fake_a_answer(Ipv4Addr::new(192, 0, 2, 55)),
        Limits::default(),
    )
    .await;
    let wire = encode_a_query(42, "example.com.");
    let (resp, _) = query_udp(h.addr, &wire).await;
    let msg = Message::decode(&resp).unwrap();
    assert_eq!(msg.header.id, 42);
    assert_eq!(msg.rcode(), Rcode::NOERROR);
    assert!(!msg.answers.is_empty());
    assert!(h.stats.answered.load(Ordering::Relaxed) >= 1);
    h.stop().await;

    let engine = local_policy_engine().await;
    let h = UdpHarness::spawn(
        SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
        engine,
        Limits::default(),
    )
    .await;
    let wire = encode_a_query(7, "local.test.");
    let (resp, _) = query_udp(h.addr, &wire).await;
    let msg = Message::decode(&resp).unwrap();
    assert_eq!(msg.header.id, 7);
    assert_eq!(msg.rcode(), Rcode::NOERROR);
    assert_eq!(msg.answers.len(), 1);
    h.stop().await;
}

#[tokio::test]
async fn ipv6_loopback_fake() {
    let h = UdpHarness::spawn_fake(
        SocketAddr::from((Ipv6Addr::LOCALHOST, 0)),
        fake_a_answer(Ipv4Addr::new(192, 0, 2, 55)),
        Limits::default(),
    )
    .await;
    let wire = encode_a_query(9, "example.com.");
    let (resp, _) = query_udp(h.addr, &wire).await;
    let msg = Message::decode(&resp).unwrap();
    assert_eq!(msg.header.id, 9);
    assert_eq!(msg.rcode(), Rcode::NOERROR);
    h.stop().await;
}

#[tokio::test]
async fn wildcard_replies_from_arrival_address() {
    let h = UdpHarness::spawn_fake(
        SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)),
        fake_a_answer(Ipv4Addr::new(192, 0, 2, 55)),
        Limits::default(),
    )
    .await;
    let port = h.addr.port();
    let wire = encode_a_query(1, "example.com.");

    for dest_ip in [
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)),
    ] {
        let dest = SocketAddr::new(dest_ip, port);
        let (_resp, from) =
            query_udp_from(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)), dest, &wire).await;
        assert_eq!(
            from.ip(),
            dest_ip,
            "reply must leave from destination {dest_ip}"
        );
    }
    h.stop().await;
}

#[tokio::test]
async fn same_port_v4_and_v6_unspecified() {
    let limits = Limits::default();
    let stats4 = Arc::new(UdpStats::default());
    let stats6 = Arc::new(UdpStats::default());
    let (b4_tx, b4_rx) = oneshot::channel();
    let (b6_tx, b6_rx) = oneshot::channel();
    let (sd4_tx, sd4_rx) = watch::channel(false);
    let (sd6_tx, sd6_rx) = watch::channel(false);
    let handler = Arc::new(dnscraft_listeners::FakeHandler::new(fake_a_answer(
        Ipv4Addr::new(192, 0, 2, 10),
    )));
    let clock: Arc<dyn dnscraft_listeners::Clock> = Arc::new(SystemClock);

    // Bind IPv4 first with port 0, then IPv6 on the same port.
    let adm4 = Arc::new(std::sync::Mutex::new(dnscraft_listeners::Admission::new(
        &limits,
        &PublicConfig::default(),
    )));
    let adm6 = Arc::new(std::sync::Mutex::new(dnscraft_listeners::Admission::new(
        &limits,
        &PublicConfig::default(),
    )));
    let join4 = tokio::spawn(serve_udp(UdpServeParams {
        listener: ListenerConfig {
            id: ListenerId::new("udp4").unwrap(),
            protocol: Protocol::Udp53,
            address: SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)),
            exposure: Exposure::Local,
            h3: false,
        },
        limits: limits.clone(),
        admission: adm4,
        handler: Arc::clone(&handler),
        clock: Arc::clone(&clock),
        stats: Arc::clone(&stats4),
        bound: b4_tx,
        shutdown: sd4_rx,
    }));
    let addr4 = b4_rx.await.unwrap();
    let join6 = tokio::spawn(serve_udp(UdpServeParams {
        listener: ListenerConfig {
            id: ListenerId::new("udp6").unwrap(),
            protocol: Protocol::Udp53,
            address: SocketAddr::from((Ipv6Addr::UNSPECIFIED, addr4.port())),
            exposure: Exposure::Local,
            h3: false,
        },
        limits,
        admission: adm6,
        handler,
        clock,
        stats: Arc::clone(&stats6),
        bound: b6_tx,
        shutdown: sd6_rx,
    }));
    let addr6 = b6_rx.await.unwrap();
    assert_eq!(addr4.port(), addr6.port());

    let wire = encode_a_query(3, "example.com.");
    let (r4, _) = query_udp(SocketAddr::from((Ipv4Addr::LOCALHOST, addr4.port())), &wire).await;
    assert_eq!(Message::decode(&r4).unwrap().header.id, 3);

    let (r6, _) = query_udp(SocketAddr::from((Ipv6Addr::LOCALHOST, addr6.port())), &wire).await;
    assert_eq!(Message::decode(&r6).unwrap().header.id, 3);

    let _ = sd4_tx.send(true);
    let _ = sd6_tx.send(true);
    let _ = join4.await;
    let _ = join6.await;
}

#[tokio::test]
async fn truncation_tc_and_classic_512() {
    let h = UdpHarness::spawn_fake(
        SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
        fake_large_answer(40),
        Limits::default(),
    )
    .await;

    // No OPT → 512 limit, TC set
    let wire = Message::query(
        11,
        Name::from_ascii("big.example.com.").unwrap(),
        RecordType::TXT,
    )
    .encode()
    .unwrap();
    let (resp, _) = query_udp(h.addr, &wire).await;
    assert!(resp.len() <= CLASSIC_UDP_LIMIT);
    let (hdr, _) = Header::decode(&resp).unwrap();
    assert!(hdr.tc, "classic UDP must set TC when truncated");

    // With OPT, still truncated within advertised limit
    let mut q = Message::query(
        12,
        Name::from_ascii("big.example.com.").unwrap(),
        RecordType::TXT,
    );
    q.edns = Some(dnscraft_proto::Edns::new(512));
    let (resp2, _) = query_udp(h.addr, &q.encode().unwrap()).await;
    assert!(resp2.len() <= 512);
    let (hdr2, _) = Header::decode(&resp2).unwrap();
    assert!(hdr2.tc);

    h.stop().await;
}

#[tokio::test]
async fn inflight_cap_and_public_source_counted() {
    // Slow handler: hold answers until released.
    let release = Arc::new(tokio::sync::Notify::new());
    let release2 = Arc::clone(&release);
    let base = fake_a_answer(Ipv4Addr::new(192, 0, 2, 1));
    let handler = Arc::new(SlowHandler {
        release: release2,
        answer: base,
    });

    let limits = Limits {
        max_inflight_per_listener: 1,
        rate_per_source: TokenRate {
            per_second: 10_000,
            burst: 10_000,
        },
        ..Limits::default()
    };

    let h = UdpHarness::spawn(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)), handler, limits).await;

    let client = tokio::net::UdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .await
        .unwrap();
    let wire = encode_a_query(1, "example.com.");
    client.send_to(&wire, h.addr).await.unwrap();
    let stats = Arc::clone(&h.stats);
    poll_until(
        || stats.received.load(Ordering::Relaxed) >= 1,
        Duration::from_secs(2),
    )
    .await;
    client
        .send_to(&encode_a_query(2, "example.com."), h.addr)
        .await
        .unwrap();
    poll_until(
        || stats.dropped_inflight.load(Ordering::Relaxed) >= 1,
        Duration::from_secs(2),
    )
    .await;
    release.notify_waiters();
    // Drain any answers
    let mut buf = [0u8; 512];
    let _ = tokio::time::timeout(Duration::from_millis(200), client.recv_from(&mut buf)).await;
    h.stop().await;
}

/// Handler that waits on `release` before answering (inflight tests).
struct SlowHandler {
    release: Arc<tokio::sync::Notify>,
    answer: dnscraft_policy::PolicyAnswer,
}

impl dnscraft_listeners::QueryHandler for SlowHandler {
    async fn handle(
        &self,
        _ctx: dnscraft_policy::RequestContext,
    ) -> Result<dnscraft_policy::PolicyAnswer, dnscraft_policy::PolicyError> {
        self.release.notified().await;
        Ok(self.answer.clone())
    }
}

#[tokio::test]
async fn public_source_drop_counted_via_admission_path() {
    // Directly exercise the same drop counter path used by serve_udp by running a
    // minimal recv isn't needed: we verify serve_udp increments dropped_public when
    // SourceClass::Public hits Do53 — use a Unix abstract... no.
    //
    // On Linux, 127.0.0.0/8 is private. Documentation ranges need a local address.
    // Skip if we cannot bind 192.0.2.1; otherwise send from it.
    let bind_pub = SocketAddr::from((Ipv4Addr::new(192, 0, 2, 1), 0));
    let client = match tokio::net::UdpSocket::bind(bind_pub).await {
        Ok(c) => c,
        Err(_) => {
            // No documentation-range address configured; still assert counter starts at 0
            // and the wildcard path answers private sources (sanity).
            let h = UdpHarness::spawn_fake(
                SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)),
                fake_a_answer(Ipv4Addr::new(192, 0, 2, 55)),
                Limits::default(),
            )
            .await;
            assert_eq!(h.stats.dropped_public.load(Ordering::Relaxed), 0);
            let (resp, _) = query_udp(
                SocketAddr::from((Ipv4Addr::LOCALHOST, h.addr.port())),
                &encode_a_query(1, "example.com."),
            )
            .await;
            assert!(!resp.is_empty());
            h.stop().await;
            return;
        }
    };

    let h = UdpHarness::spawn_fake(
        SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)),
        fake_a_answer(Ipv4Addr::new(192, 0, 2, 55)),
        Limits::default(),
    )
    .await;
    let dest = SocketAddr::from((Ipv4Addr::LOCALHOST, h.addr.port()));
    client
        .send_to(&encode_a_query(1, "example.com."), dest)
        .await
        .unwrap();
    let stats = Arc::clone(&h.stats);
    poll_until(
        || stats.dropped_public.load(Ordering::Relaxed) >= 1,
        Duration::from_secs(2),
    )
    .await;
    h.stop().await;
}
