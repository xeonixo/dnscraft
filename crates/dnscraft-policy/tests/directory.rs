//! Step 2: ClientDirectory names / PTR and special-use NXDOMAIN.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, SystemTime};

use dnscraft_filtering::{
    FilterConfig, FilterEngine, FilterSetConfig, ListBodies, ListId, ManualClock, SetId,
    SnapshotBuilder,
};
use dnscraft_policy::{
    AnswerOrigin, ClientDirectory, ClientFlags, DecisionStep, DnsProtocol, ListenerId,
    PolicyConfig, PolicyEngine, ProfileConfig, ProfileId, RequestContext, SafeSearchConfig,
    ViewConfig, ViewId,
};
use dnscraft_proto::{Class, Name, RData, Rcode, RecordType};
use dnscraft_resolver::dnssec::TrustAnchors;
use dnscraft_resolver::{ForwardZone, ForwardZoneId, Query, Resolver, ResolverConfig};
use dnscraft_testkit::Hierarchy;
use ipnet::IpNet;
use tokio::net::UdpSocket;

fn clock() -> Arc<ManualClock> {
    Arc::new(ManualClock::new(
        SystemTime::UNIX_EPOCH + Duration::from_secs(1_000),
    ))
}

#[derive(Debug, Default)]
struct EmptyBodies;

impl ListBodies for EmptyBodies {
    fn body(&self, _id: &ListId) -> Option<Arc<str>> {
        None
    }
}

fn set(id: &str) -> SetId {
    SetId::new(id).unwrap()
}

fn empty_filter() -> Arc<FilterEngine> {
    let sc = FilterSetConfig::new(set("default"), "default");
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

fn profile(id: &str, forward_zones: Option<Vec<ForwardZoneId>>) -> ProfileConfig {
    ProfileConfig {
        id: ProfileId::new(id).unwrap(),
        filter_set: set("default"),
        suppress_aaaa: false,
        firefox_canary: false,
        icloud_private_relay: false,
        rebind: None,
        rebind_exceptions: Vec::new(),
        forward_zones,
        safesearch: SafeSearchConfig::default(),
        schedules: Vec::new(),
    }
}

fn default_view(profile_id: &str) -> ViewConfig {
    ViewConfig {
        id: ViewId::new("default").unwrap(),
        is_default: true,
        subnets: Vec::new(),
        nodes: Vec::new(),
        profile: ProfileId::new(profile_id).unwrap(),
    }
}

fn config_for(h: &Hierarchy) -> ResolverConfig {
    let overrides = h
        .nameserver_addrs()
        .iter()
        .map(|(n, a)| (Name::from_ascii(&n.to_string()).unwrap(), *a))
        .collect::<HashMap<_, _>>();
    ResolverConfig {
        root_hints: h.root_hints(),
        query_timeout: Duration::from_millis(300),
        nameserver_addr_overrides: overrides,
        trust_anchors: TrustAnchors::empty(),
        prefetch: false,
        ..ResolverConfig::default()
    }
}

fn ctx(name: &str, qtype: RecordType) -> RequestContext {
    RequestContext {
        source_ip: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
        protocol: DnsProtocol::Udp53,
        listener_id: ListenerId::new("udp-53").unwrap(),
        node_id: None,
        client_id: None,
        query: Query {
            name: Name::from_ascii(name).unwrap(),
            qtype,
            qclass: Class::IN,
        },
        flags: ClientFlags::default(),
        test_query: false,
    }
}

fn root_query_count(h: &Hierarchy) -> usize {
    h.server(".").unwrap().queries().len()
}

/// Mock directory with fixed forward and reverse entries.
#[derive(Clone, Default)]
struct MockDir {
    addresses: HashMap<Name, Arc<[IpAddr]>>,
    reverse: HashMap<IpAddr, Arc<str>>,
    local_domains: Arc<[String]>,
}

impl ClientDirectory for MockDir {
    fn addresses(&self, fqdn: &Name) -> Option<Arc<[IpAddr]>> {
        self.addresses.get(fqdn).cloned()
    }

    fn reverse(&self, ip: IpAddr) -> Option<Arc<str>> {
        self.reverse.get(&ip).cloned()
    }

    fn local_domains(&self) -> Arc<[String]> {
        Arc::clone(&self.local_domains)
    }
}

impl MockDir {
    fn with_host(mut self, fqdn: &str, addrs: Vec<IpAddr>) -> Self {
        self.addresses
            .insert(Name::from_ascii(fqdn).unwrap(), Arc::from(addrs.as_slice()));
        self
    }

    fn with_reverse(mut self, ip: IpAddr, name: &str) -> Self {
        self.reverse.insert(ip, Arc::from(name));
        self
    }

    fn with_local_domains(mut self, domains: &[&str]) -> Self {
        self.local_domains = Arc::from(domains.iter().map(|d| (*d).to_owned()).collect::<Vec<_>>());
        self
    }
}

struct CountingTarget {
    addr: SocketAddr,
    hits: Arc<AtomicUsize>,
    task: tokio::task::JoinHandle<()>,
}

impl CountingTarget {
    async fn spawn() -> Self {
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let addr = socket.local_addr().unwrap();
        let hits = Arc::new(AtomicUsize::new(0));
        let hits_task = Arc::clone(&hits);
        let task = tokio::spawn(async move {
            let mut buf = vec![0u8; 2048];
            loop {
                let Ok((len, peer)) = socket.recv_from(&mut buf).await else {
                    return;
                };
                hits_task.fetch_add(1, Ordering::Relaxed);
                let Ok(req) = dnscraft_proto::Message::decode(&buf[..len]) else {
                    continue;
                };
                let mut resp = dnscraft_proto::Message::response_to(&req);
                resp.header.ra = true;
                if let Some(q) = req.questions.first() {
                    resp.answers.push(dnscraft_proto::Record::new(
                        q.name.clone(),
                        Class::IN,
                        60,
                        RData::A(Ipv4Addr::new(192, 0, 2, 55)),
                    ));
                }
                let Ok(out) = resp.encode() else {
                    continue;
                };
                let _ = socket.send_to(&out, peer).await;
            }
        });
        Self { addr, hits, task }
    }

    fn hits(&self) -> usize {
        self.hits.load(Ordering::Relaxed)
    }
}

impl Drop for CountingTarget {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn engine_with(
    policy: PolicyConfig,
    clients: Arc<dyn ClientDirectory>,
    resolver_cfg: ResolverConfig,
) -> PolicyEngine {
    let resolver = Arc::new(Resolver::new(resolver_cfg).await.unwrap());
    PolicyEngine::new(policy, empty_filter(), resolver, clients, clock()).unwrap()
}

#[tokio::test]
async fn directory_known_a_only_aaaa_nodata_unknown_reaches_resolver() {
    let h = Hierarchy::start().await.unwrap();
    let dir = Arc::new(
        MockDir::default()
            .with_host(
                "nas.example.com",
                vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 20))],
            )
            .with_local_domains(&["example.com"]),
    );
    let engine = engine_with(
        PolicyConfig {
            client_ids: Vec::new(),
            records: Vec::new(),
            default_rebind: true,
            ptr_prefixes: Vec::new(),
            local_nxdomain_suffixes: Vec::new(),
            rebind_check_forward_zones: Vec::new(),
            views: vec![default_view("default")],
            profiles: vec![profile("default", None)],
        },
        dir,
        config_for(&h),
    )
    .await;

    let before = root_query_count(&h);
    let a = engine
        .handle(ctx("nas.example.com", RecordType::A))
        .await
        .unwrap();
    assert_eq!(a.message.rcode(), Rcode::NOERROR);
    assert_eq!(a.record.answer_source, AnswerOrigin::LocalClient);
    assert!(a.record.steps.contains(&DecisionStep::LocalClient));
    assert_eq!(a.message.answers.len(), 1);
    assert_eq!(
        a.message.answers[0].rdata,
        RData::A(Ipv4Addr::new(192, 0, 2, 20))
    );
    assert!(!a.message.header.ad);
    assert!(a.message.header.aa);
    assert_eq!(root_query_count(&h), before);

    let aaaa = engine
        .handle(ctx("nas.example.com", RecordType::AAAA))
        .await
        .unwrap();
    assert_eq!(aaaa.message.rcode(), Rcode::NOERROR);
    assert!(aaaa.message.answers.is_empty());
    assert_eq!(aaaa.record.answer_source, AnswerOrigin::LocalClient);
    assert_eq!(root_query_count(&h), before);

    let txt = engine
        .handle(ctx("nas.example.com", RecordType::TXT))
        .await
        .unwrap();
    assert_eq!(txt.message.rcode(), Rcode::NOERROR);
    assert!(txt.message.answers.is_empty());
    assert_eq!(root_query_count(&h), before);

    // Unknown name under the same local domain → resolver (not synthesised).
    let unknown = engine
        .handle(ctx("other.example.com", RecordType::A))
        .await
        .unwrap();
    assert_eq!(unknown.record.answer_source, AnswerOrigin::Resolver);
    assert!(root_query_count(&h) > before);
}

#[tokio::test]
async fn directory_ptr_private_and_ptr_prefixes_public_goes_to_resolver() {
    let h = Hierarchy::start().await.unwrap();
    let dir = Arc::new(
        MockDir::default()
            .with_reverse(
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)),
                "host.lan.example.com.",
            )
            .with_reverse(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7)), "doc.example.com.")
            .with_reverse(
                IpAddr::V4(Ipv4Addr::new(198, 51, 100, 9)),
                "public-but-listed.example.com.",
            ),
    );
    let engine = engine_with(
        PolicyConfig {
            client_ids: Vec::new(),
            records: Vec::new(),
            default_rebind: true,
            ptr_prefixes: vec!["192.0.2.0/24".parse::<IpNet>().unwrap()],
            local_nxdomain_suffixes: Vec::new(),
            rebind_check_forward_zones: Vec::new(),
            views: vec![default_view("default")],
            profiles: vec![profile("default", None)],
        },
        dir,
        config_for(&h),
    )
    .await;

    let before = root_query_count(&h);

    let priv_ptr = engine
        .handle(ctx("5.0.0.10.in-addr.arpa", RecordType::PTR))
        .await
        .unwrap();
    assert_eq!(priv_ptr.message.rcode(), Rcode::NOERROR);
    assert_eq!(priv_ptr.record.answer_source, AnswerOrigin::LocalClient);
    assert_eq!(priv_ptr.message.answers.len(), 1);
    assert_eq!(
        priv_ptr.message.answers[0].rdata,
        RData::PTR(Name::from_ascii("host.lan.example.com.").unwrap())
    );
    assert_eq!(root_query_count(&h), before);

    let doc_ptr = engine
        .handle(ctx("7.2.0.192.in-addr.arpa", RecordType::PTR))
        .await
        .unwrap();
    assert_eq!(doc_ptr.record.answer_source, AnswerOrigin::LocalClient);
    assert_eq!(
        doc_ptr.message.answers[0].rdata,
        RData::PTR(Name::from_ascii("doc.example.com.").unwrap())
    );
    assert_eq!(root_query_count(&h), before);

    // Public documentation range not in ptr_prefixes → resolver (directory
    // knows a reverse entry, but the prefix is not eligible).
    let public = engine
        .handle(ctx("9.100.51.198.in-addr.arpa", RecordType::PTR))
        .await
        .unwrap();
    assert_ne!(public.record.answer_source, AnswerOrigin::LocalClient);
    assert!(
        !public
            .record
            .steps
            .iter()
            .any(|s| matches!(s, DecisionStep::LocalClient))
    );
}

#[tokio::test]
async fn special_use_nxdomain_unless_forward_zone_allowed() {
    let h = Hierarchy::start().await.unwrap();
    let target = CountingTarget::spawn().await;
    let zone_id = ForwardZoneId::new("lan-fwd").unwrap();
    let mut resolver_cfg = config_for(&h);
    resolver_cfg.forward_zones = vec![ForwardZone {
        id: zone_id.clone(),
        zone: Name::from_ascii("lan.").unwrap(),
        targets: vec![target.addr],
        validate: false,
    }];

    let dir = Arc::new(MockDir::default());

    // No forward zone in profile allow-list (empty Some) and no covering
    // zone usable → NXDOMAIN, zero resolver / forward traffic.
    let engine_deny = engine_with(
        PolicyConfig {
            client_ids: Vec::new(),
            records: Vec::new(),
            default_rebind: true,
            ptr_prefixes: Vec::new(),
            local_nxdomain_suffixes: vec![Arc::from("lan")],
            rebind_check_forward_zones: Vec::new(),
            views: vec![default_view("default")],
            profiles: vec![profile("default", Some(vec![]))],
        },
        Arc::clone(&dir) as Arc<dyn ClientDirectory>,
        resolver_cfg.clone(),
    )
    .await;

    let before_root = root_query_count(&h);
    let nx = engine_deny
        .handle(ctx("printer.lan", RecordType::A))
        .await
        .unwrap();
    assert_eq!(nx.message.rcode(), Rcode::NXDOMAIN);
    assert_eq!(nx.record.answer_source, AnswerOrigin::LocalClient);
    assert!(nx.record.steps.contains(&DecisionStep::SpecialUseNxdomain));
    assert!(nx.ede.is_none());
    assert_eq!(nx.message.authorities.len(), 1);
    assert_eq!(nx.message.authorities[0].rtype(), RecordType::SOA);
    assert_eq!(root_query_count(&h), before_root);
    assert_eq!(target.hits(), 0);

    // Zone allowed → fall through and forward.
    let engine_allow = engine_with(
        PolicyConfig {
            client_ids: Vec::new(),
            records: Vec::new(),
            default_rebind: true,
            ptr_prefixes: Vec::new(),
            local_nxdomain_suffixes: vec![Arc::from("lan")],
            rebind_check_forward_zones: Vec::new(),
            views: vec![default_view("default")],
            profiles: vec![profile("default", Some(vec![zone_id]))],
        },
        dir,
        resolver_cfg,
    )
    .await;

    let fwd = engine_allow
        .handle(ctx("printer.lan", RecordType::A))
        .await
        .unwrap();
    assert_eq!(fwd.message.rcode(), Rcode::NOERROR);
    assert_eq!(fwd.record.answer_source, AnswerOrigin::Resolver);
    assert!(fwd.record.forward_zone.is_some());
    assert_eq!(target.hits(), 1);
    assert!(
        !fwd.record
            .steps
            .iter()
            .any(|s| matches!(s, DecisionStep::SpecialUseNxdomain))
    );
}
