//! Checkpoint B: Do53 UDP + TCP through PolicyEngine on the testkit hierarchy.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod support;

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use dnscraft_filtering::{
    FilterConfig, FilterEngine, FilterSetConfig, ListBodies, ListId, ManualClock, SetId,
    SnapshotBuilder,
};
use dnscraft_listeners::{
    Exposure, Limits, ListenerConfig, Protocol, PublicConfig, SystemClock, TcpServeParams,
    TcpStats, UdpServeParams, UdpStats, read_frame, serve_tcp, serve_udp, write_frame,
};
use dnscraft_policy::{
    ListenerId, NoClients, PolicyConfig, PolicyEngine, ProfileConfig, ProfileId, SafeSearchConfig,
    ViewConfig, ViewId, ViewRecordConfig,
};
use dnscraft_proto::{Message, Name, RData, Rcode};
use dnscraft_resolver::dnssec::TrustAnchors;
use dnscraft_resolver::{Resolver, ResolverConfig};
use dnscraft_testkit::Hierarchy;
use support::encode_a_query;
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::{oneshot, watch};

#[derive(Debug, Default)]
struct EmptyBodies;

impl ListBodies for EmptyBodies {
    fn body(&self, _id: &ListId) -> Option<Arc<str>> {
        None
    }
}

fn filter_with_block() -> Arc<FilterEngine> {
    let mut sc = FilterSetConfig::new(SetId::new("default").unwrap(), "default");
    sc.custom_rules = "blocked.example.test\n".into();
    let cfg = FilterConfig {
        lists: Vec::new(),
        sets: vec![sc],
        ..FilterConfig::default()
    };
    Arc::new(FilterEngine::from_snapshot(
        SnapshotBuilder::new(Arc::new(EmptyBodies) as Arc<dyn ListBodies>)
            .build(&cfg)
            .unwrap(),
    ))
}

fn config_for(h: &Hierarchy) -> ResolverConfig {
    let overrides = h
        .nameserver_addrs()
        .iter()
        .map(|(n, a)| (Name::from_ascii(&n.to_string()).unwrap(), *a))
        .collect::<HashMap<_, _>>();
    ResolverConfig {
        root_hints: h.root_hints(),
        query_timeout: Duration::from_millis(500),
        nameserver_addr_overrides: overrides,
        trust_anchors: TrustAnchors::empty(),
        prefetch: false,
        ..ResolverConfig::default()
    }
}

async fn policy_engine() -> (Hierarchy, Arc<PolicyEngine>) {
    let h = Hierarchy::start().await.unwrap();
    let resolver = Arc::new(Resolver::new(config_for(&h)).await.unwrap());
    let profile = ProfileConfig {
        id: ProfileId::new("default").unwrap(),
        filter_set: SetId::new("default").unwrap(),
        suppress_aaaa: false,
        firefox_canary: false,
        icloud_private_relay: false,
        rebind: Some(false),
        rebind_exceptions: Vec::new(),
        forward_zones: None,
        safesearch: SafeSearchConfig::default(),
        schedules: Vec::new(),
    };
    let view = ViewConfig {
        id: ViewId::new("default").unwrap(),
        is_default: true,
        subnets: Vec::new(),
        client_ids: Vec::new(),
        records: vec![ViewRecordConfig {
            name: Name::from_ascii("lan.example.test.").unwrap(),
            ttl: 60,
            rdata: RData::A(Ipv4Addr::new(192, 0, 2, 99)),
        }],
        profile: ProfileId::new("default").unwrap(),
    };
    let cfg = PolicyConfig {
        views: vec![view],
        profiles: vec![profile],
        ..PolicyConfig::default()
    };
    let clock = Arc::new(ManualClock::new(
        SystemTime::UNIX_EPOCH + Duration::from_secs(1_000),
    ));
    let engine = Arc::new(
        PolicyEngine::new(
            cfg,
            filter_with_block(),
            resolver,
            Arc::new(NoClients),
            clock,
        )
        .unwrap(),
    );
    (h, engine)
}

async fn spawn_udp(
    bind: SocketAddr,
    engine: Arc<PolicyEngine>,
) -> (
    SocketAddr,
    watch::Sender<bool>,
    tokio::task::JoinHandle<Result<(), dnscraft_listeners::ListenersError>>,
) {
    let (bound_tx, bound_rx) = oneshot::channel();
    let (sd_tx, sd_rx) = watch::channel(false);
    let admission = Arc::new(std::sync::Mutex::new(dnscraft_listeners::Admission::new(
        &Limits::default(),
        &PublicConfig::default(),
    )));
    let join = tokio::spawn(serve_udp(UdpServeParams {
        listener: ListenerConfig {
            id: ListenerId::new("e2e-udp").unwrap(),
            protocol: Protocol::Udp53,
            address: bind,
            exposure: Exposure::Local,
            h3: false,
        },
        limits: Limits::default(),
        admission,
        handler: engine,
        clock: Arc::new(SystemClock),
        stats: Arc::new(UdpStats::default()),
        ddr: None,
        event_sink: None,
        bound: bound_tx,
        shutdown: sd_rx,
    }));
    let addr = bound_rx.await.unwrap();
    (addr, sd_tx, join)
}

async fn spawn_tcp(
    bind: SocketAddr,
    engine: Arc<PolicyEngine>,
) -> (
    SocketAddr,
    watch::Sender<bool>,
    tokio::task::JoinHandle<Result<(), dnscraft_listeners::ListenersError>>,
) {
    let (bound_tx, bound_rx) = oneshot::channel();
    let (sd_tx, sd_rx) = watch::channel(false);
    let admission = Arc::new(std::sync::Mutex::new(dnscraft_listeners::Admission::new(
        &Limits::default(),
        &PublicConfig::default(),
    )));
    let join = tokio::spawn(serve_tcp(TcpServeParams {
        listener: ListenerConfig {
            id: ListenerId::new("e2e-tcp").unwrap(),
            protocol: Protocol::Tcp53,
            address: bind,
            exposure: Exposure::Local,
            h3: false,
        },
        limits: Limits::default(),
        admission,
        handler: engine,
        clock: Arc::new(SystemClock),
        stats: Arc::new(TcpStats::default()),
        ddr: None,
        event_sink: None,
        bound: bound_tx,
        shutdown: sd_rx,
    }));
    let addr = bound_rx.await.unwrap();
    (addr, sd_tx, join)
}

async fn udp_query(dest: SocketAddr, name: &str) -> Message {
    let client = if dest.is_ipv4() {
        UdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .await
            .unwrap()
    } else {
        UdpSocket::bind("[::1]:0").await.unwrap()
    };
    let wire = encode_a_query(1, name);
    client.send_to(&wire, dest).await.unwrap();
    let mut buf = [0u8; 4096];
    let (n, _) = tokio::time::timeout(Duration::from_secs(3), client.recv_from(&mut buf))
        .await
        .expect("udp timeout")
        .unwrap();
    Message::decode(&buf[..n]).unwrap()
}

async fn tcp_query(dest: SocketAddr, name: &str) -> Message {
    let mut client = TcpStream::connect(dest).await.unwrap();
    write_frame(&mut client, &encode_a_query(1, name))
        .await
        .unwrap();
    let resp = tokio::time::timeout(Duration::from_secs(3), read_frame(&mut client))
        .await
        .expect("tcp timeout")
        .unwrap();
    Message::decode(&resp).unwrap()
}

fn assert_matrix(msg: &Message, name: &str, expect: Expect) {
    match expect {
        Expect::LocalA(ip) => {
            assert_eq!(msg.rcode(), Rcode::NOERROR, "{name}");
            assert!(
                msg.answers.iter().any(|r| matches!(
                    &r.rdata,
                    RData::A(a) if *a == ip
                )),
                "{name}: {:?}",
                msg.answers
            );
        }
        Expect::RecursedA => {
            assert_eq!(msg.rcode(), Rcode::NOERROR, "{name}");
            assert!(
                msg.answers.iter().any(|r| matches!(&r.rdata, RData::A(_))),
                "{name} should recurse to an A"
            );
        }
        Expect::Blocked => {
            // Default filter block_mode is REFUSED.
            assert_eq!(
                msg.rcode(),
                Rcode::REFUSED,
                "{name}: expected REFUSED, got {:?} answers={:?}",
                msg.rcode(),
                msg.answers
            );
        }
    }
}

#[derive(Clone, Copy)]
enum Expect {
    LocalA(Ipv4Addr),
    RecursedA,
    Blocked,
}

async fn run_family(v4: bool) {
    let (_h, engine) = policy_engine().await;
    let bind_ip: IpAddr = if v4 {
        Ipv4Addr::LOCALHOST.into()
    } else {
        Ipv6Addr::LOCALHOST.into()
    };

    let (udp_addr, udp_sd, udp_join) =
        spawn_udp(SocketAddr::new(bind_ip, 0), Arc::clone(&engine)).await;
    let (tcp_addr, tcp_sd, tcp_join) = spawn_tcp(SocketAddr::new(bind_ip, 0), engine).await;

    let cases = [
        (
            "lan.example.test.",
            Expect::LocalA(Ipv4Addr::new(192, 0, 2, 99)),
        ),
        ("www.example.test.", Expect::RecursedA),
        ("blocked.example.test.", Expect::Blocked),
    ];

    for (name, expect) in cases {
        let u = udp_query(udp_addr, name).await;
        assert_matrix(&u, &format!("udp/{name}"), expect);
        let t = tcp_query(tcp_addr, name).await;
        assert_matrix(&t, &format!("tcp/{name}"), expect);
    }

    let _ = udp_sd.send(true);
    let _ = tcp_sd.send(true);
    let _ = udp_join.await;
    let _ = tcp_join.await;
}

#[tokio::test]
async fn checkpoint_b_ipv4() {
    run_family(true).await;
}

#[tokio::test]
async fn checkpoint_b_ipv6() {
    run_family(false).await;
}
