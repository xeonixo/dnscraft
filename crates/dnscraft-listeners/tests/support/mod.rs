//! Shared helpers for listener integration tests.

#![allow(clippy::unwrap_used, clippy::expect_used, dead_code)]

pub mod certs;

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use dnscraft_filtering::{
    FilterConfig, FilterEngine, FilterSetConfig, ListBodies, ListId, SetId, SnapshotBuilder,
};
use dnscraft_listeners::{
    Admission, Exposure, FakeHandler, Limits, ListenerConfig, Protocol, PublicConfig, SourceClass,
    SourceClassifier, SystemClock, UdpServeParams, UdpStats, serve_udp,
};
use dnscraft_policy::{
    AnswerOrigin, ClientId, DecisionRecord, DecisionTimings, ListenerId, NoClients, PolicyAnswer,
    PolicyConfig, PolicyEngine, ProfileConfig, ProfileId, SafeSearchConfig, SelectionCause,
    ViewConfig, ViewId, ViewRecordConfig,
};
use dnscraft_proto::{Class, Message, Name, RData, Rcode, Record, RecordType};
use dnscraft_resolver::dnssec::TrustAnchors;
use dnscraft_resolver::{Resolver, ResolverConfig};
use tokio::net::UdpSocket;
use tokio::sync::{oneshot, watch};

/// Polls `ready` until true or `timeout` elapses (then panics).
///
/// Prefer this over fixed `sleep` when waiting for background listener work.
pub async fn poll_until(mut ready: impl FnMut() -> bool, timeout: Duration) {
    let start = Instant::now();
    loop {
        if ready() {
            return;
        }
        if start.elapsed() >= timeout {
            panic!("poll_until timed out after {timeout:?}");
        }
        tokio::task::yield_now().await;
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
}

#[derive(Debug, Default)]
struct EmptyBodies;

impl ListBodies for EmptyBodies {
    fn body(&self, _id: &ListId) -> Option<Arc<str>> {
        None
    }
}

pub fn empty_filter() -> Arc<FilterEngine> {
    let sc = FilterSetConfig::new(SetId::new("default").unwrap(), "default");
    let cfg = FilterConfig {
        lists: Vec::new(),
        sets: vec![sc],
        ..FilterConfig::default()
    };
    let snap = SnapshotBuilder::new(Arc::new(EmptyBodies) as Arc<dyn ListBodies>)
        .build(&cfg)
        .unwrap();
    Arc::new(FilterEngine::from_snapshot(snap))
}

pub fn decision() -> DecisionRecord {
    DecisionRecord {
        view_id: ViewId::new("default").unwrap(),
        profile_id: ProfileId::new("default").unwrap(),
        selection: SelectionCause::Default,
        client_id: None,
        client_label: None,
        client_device: None,
        filter_set: SetId::new("default").unwrap(),
        steps: Vec::new(),
        filter: None,
        forward_zone: None,
        dnssec: None,
        answer_source: AnswerOrigin::LocalView,
        timings: DecisionTimings::default(),
        rcode: Rcode::NOERROR,
    }
}

pub fn fake_a_answer(ip: Ipv4Addr) -> PolicyAnswer {
    let q = Message::query(1, Name::from_ascii("example.com.").unwrap(), RecordType::A);
    let mut resp = Message::response_to(&q);
    resp.answers.push(Record::new(
        Name::from_ascii("example.com.").unwrap(),
        Class::IN,
        60,
        RData::A(ip),
    ));
    PolicyAnswer {
        message: resp,
        ede: None,
        record: decision(),
        loggable: true,
    }
}

pub fn fake_large_answer(rr_count: usize) -> PolicyAnswer {
    let name = Name::from_ascii("big.example.com.").unwrap();
    let q = Message::query(1, name.clone(), RecordType::TXT);
    let mut resp = Message::response_to(&q);
    for i in 0..rr_count {
        let txt = format!("pad-{i:04}-{}", "x".repeat(200));
        resp.answers.push(Record::new(
            name.clone(),
            Class::IN,
            60,
            RData::TXT(vec![txt.into_bytes().into()]),
        ));
    }
    PolicyAnswer {
        message: resp,
        ede: None,
        record: decision(),
        loggable: true,
    }
}

pub fn encode_a_query(id: u16, name: &str) -> Vec<u8> {
    Message::query(id, Name::from_ascii(name).unwrap(), RecordType::A)
        .encode()
        .unwrap()
}

pub fn encode_a_query_edns(id: u16, name: &str, udp_payload: u16) -> Vec<u8> {
    let mut q = Message::query(id, Name::from_ascii(name).unwrap(), RecordType::A);
    q.edns = Some(dnscraft_proto::Edns::new(udp_payload));
    q.encode().unwrap()
}

pub fn listener(protocol: Protocol, address: SocketAddr) -> ListenerConfig {
    ListenerConfig {
        node_id: None,
        nodes: Vec::new(),
        id: ListenerId::new("test-udp").unwrap(),
        protocol,
        address,
        exposure: Exposure::Local,
        h3: false,
        tls_policy: None,
    }
}

pub fn public_default() -> PublicConfig {
    PublicConfig::default()
}

/// Fresh shared admission for a listener harness (default limits / public config).
pub fn fresh_admission() -> Arc<Mutex<Admission>> {
    Arc::new(Mutex::new(Admission::new(
        &Limits::default(),
        &PublicConfig::default(),
    )))
}

/// Shared admission built from the given limits and public settings.
pub fn admission_for(limits: &Limits, public: &PublicConfig) -> Arc<Mutex<Admission>> {
    Arc::new(Mutex::new(Admission::new(limits, public)))
}

/// Classifies loopback as [`SourceClass::Public`] so public-listener admission
/// can be exercised from `127.0.0.1` / `::1` without real public peers.
pub fn loopback_as_public() -> SourceClassifier {
    Arc::new(|ip: IpAddr| {
        let ip = ip.to_canonical();
        match ip {
            IpAddr::V4(v4) if v4.is_loopback() => SourceClass::Public,
            IpAddr::V6(v6) if v6.is_loopback() => SourceClass::Public,
            _ => SourceClass::of(ip),
        }
    })
}

/// Admission for public-listener tests (loopback peers count as public).
pub fn public_test_admission(limits: &Limits, public: &PublicConfig) -> Arc<Mutex<Admission>> {
    Arc::new(Mutex::new(Admission::with_classifier(
        limits,
        public,
        loopback_as_public(),
    )))
}

pub struct UdpHarness {
    pub addr: SocketAddr,
    pub stats: Arc<UdpStats>,
    shutdown: watch::Sender<bool>,
    join: tokio::task::JoinHandle<Result<(), dnscraft_listeners::ListenersError>>,
}

impl UdpHarness {
    pub async fn spawn_fake(bind: SocketAddr, answer: PolicyAnswer, limits: Limits) -> Self {
        let handler = Arc::new(FakeHandler::new(answer));
        Self::spawn(bind, handler, limits).await
    }

    pub async fn spawn<H: dnscraft_listeners::QueryHandler + 'static>(
        bind: SocketAddr,
        handler: Arc<H>,
        limits: Limits,
    ) -> Self {
        let stats = Arc::new(UdpStats::default());
        let (bound_tx, bound_rx) = oneshot::channel();
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let clock: Arc<dyn dnscraft_listeners::Clock> = Arc::new(SystemClock);
        let admission = admission_for(&limits, &public_default());
        let join = tokio::spawn(serve_udp(UdpServeParams {
            listener: listener(Protocol::Udp53, bind),
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
            .expect("bound timeout")
            .expect("bound closed");
        Self {
            addr,
            stats,
            shutdown: shutdown_tx,
            join,
        }
    }

    pub async fn stop(self) {
        let _ = self.shutdown.send(true);
        let _ = tokio::time::timeout(Duration::from_secs(2), self.join).await;
    }
}

pub async fn query_udp(dest: SocketAddr, wire: &[u8]) -> (Vec<u8>, SocketAddr) {
    let client = if dest.is_ipv4() {
        UdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .await
            .unwrap()
    } else {
        UdpSocket::bind("[::1]:0").await.unwrap()
    };
    client.send_to(wire, dest).await.unwrap();
    let mut buf = [0u8; 65535];
    let (n, from) = tokio::time::timeout(Duration::from_secs(2), client.recv_from(&mut buf))
        .await
        .expect("recv timeout")
        .unwrap();
    (buf[..n].to_vec(), from)
}

pub async fn query_udp_from(
    bind: SocketAddr,
    dest: SocketAddr,
    wire: &[u8],
) -> (Vec<u8>, SocketAddr) {
    let client = UdpSocket::bind(bind).await.unwrap();
    client.send_to(wire, dest).await.unwrap();
    let mut buf = [0u8; 65535];
    let (n, from) = tokio::time::timeout(Duration::from_secs(2), client.recv_from(&mut buf))
        .await
        .expect("recv timeout")
        .unwrap();
    (buf[..n].to_vec(), from)
}

/// PolicyEngine that answers `local.test.` from a view record (no recursion needed).
pub async fn local_policy_engine() -> Arc<PolicyEngine> {
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
        nodes: Vec::new(),
        profile: ProfileId::new("default").unwrap(),
    };
    let cfg = PolicyConfig {
        client_ids: Vec::new(),
        records: vec![ViewRecordConfig {
            name: Name::from_ascii("local.test.").unwrap(),
            ttl: 60,
            rdata: RData::A(Ipv4Addr::new(192, 0, 2, 77)),
            overrides: Default::default(),
        }],
        views: vec![view],
        profiles: vec![profile],
        ..PolicyConfig::default()
    };
    let resolver = Arc::new(
        Resolver::new(ResolverConfig {
            trust_anchors: TrustAnchors::empty(),
            query_timeout: Duration::from_millis(50),
            ..ResolverConfig::default()
        })
        .await
        .unwrap(),
    );
    let clock = Arc::new(dnscraft_filtering::ManualClock::new(
        SystemTime::UNIX_EPOCH + Duration::from_secs(1_000),
    ));
    Arc::new(PolicyEngine::new(cfg, empty_filter(), resolver, Arc::new(NoClients), clock).unwrap())
}

/// PolicyEngine with the given Client IDs registered on the default view.
pub async fn policy_engine_with_client_ids(ids: &[&str]) -> Arc<PolicyEngine> {
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
        nodes: Vec::new(),
        profile: ProfileId::new("default").unwrap(),
    };
    let cfg = PolicyConfig {
        client_ids: ids
            .iter()
            .map(|id| ClientId::new(id).unwrap().into())
            .collect(),
        records: Vec::new(),
        views: vec![view],
        profiles: vec![profile],
        ..PolicyConfig::default()
    };
    let resolver = Arc::new(
        Resolver::new(ResolverConfig {
            trust_anchors: TrustAnchors::empty(),
            query_timeout: Duration::from_millis(50),
            ..ResolverConfig::default()
        })
        .await
        .unwrap(),
    );
    let clock = Arc::new(dnscraft_filtering::ManualClock::new(
        SystemTime::UNIX_EPOCH + Duration::from_secs(1_000),
    ));
    Arc::new(PolicyEngine::new(cfg, empty_filter(), resolver, Arc::new(NoClients), clock).unwrap())
}
