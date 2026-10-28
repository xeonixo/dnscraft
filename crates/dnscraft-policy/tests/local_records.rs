//! Step 1: view local records (exact name, CNAME follow, split-horizon).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use dnscraft_filtering::{
    FilterConfig, FilterEngine, FilterSetConfig, ListBodies, ListId, ManualClock, SetId,
    SnapshotBuilder,
};
use dnscraft_policy::{
    AnswerOrigin, ClientFlags, DecisionStep, DnsProtocol, ListenerId, NoClients, PolicyConfig,
    PolicyEngine, ProfileConfig, ProfileId, RequestContext, SafeSearchConfig, ViewConfig, ViewId,
    ViewRecordConfig,
};
use dnscraft_proto::{Class, Name, RData, Rcode, RecordType};
use dnscraft_resolver::dnssec::TrustAnchors;
use dnscraft_resolver::{Query, Resolver, ResolverConfig};
use dnscraft_testkit::Hierarchy;
use ipnet::IpNet;

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

fn profile(id: &str) -> ProfileConfig {
    ProfileConfig {
        id: ProfileId::new(id).unwrap(),
        filter_set: set("default"),
        suppress_aaaa: false,
        firefox_canary: false,
        icloud_private_relay: false,
        rebind: None,
        rebind_exceptions: Vec::new(),
        forward_zones: None,
        safesearch: SafeSearchConfig::default(),
        schedules: Vec::new(),
    }
}

fn rec(name: &str, rdata: RData) -> ViewRecordConfig {
    ViewRecordConfig {
        name: Name::from_ascii(name).unwrap(),
        ttl: 60,
        rdata,
        overrides: Default::default(),
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

fn ctx(source: IpAddr, name: &str, qtype: RecordType) -> RequestContext {
    RequestContext {
        source_ip: source,
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

async fn engine_with(
    views: Vec<ViewConfig>,
    records: Vec<ViewRecordConfig>,
) -> (Hierarchy, PolicyEngine) {
    let h = Hierarchy::start().await.unwrap();
    let resolver = Arc::new(Resolver::new(config_for(&h)).await.unwrap());
    let cfg = PolicyConfig {
        client_ids: Vec::new(),
        records,
        default_rebind: true,
        ptr_prefixes: Vec::new(),
        local_nxdomain_suffixes: Vec::new(),
        rebind_check_forward_zones: Vec::new(),
        views,
        profiles: vec![profile("default")],
    };
    let engine =
        PolicyEngine::new(cfg, empty_filter(), resolver, Arc::new(NoClients), clock()).unwrap();
    (h, engine)
}

#[tokio::test]
async fn local_records_all_types_without_resolver_traffic() {
    let lan = IpNet::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 0)), 24).unwrap();
    let records = vec![
        rec("a.lan.example.com", RData::A(Ipv4Addr::new(192, 0, 2, 10))),
        rec(
            "aaaa.lan.example.com",
            RData::AAAA(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
        ),
        rec(
            "txt.lan.example.com",
            RData::TXT(vec![Box::from(b"hello".as_slice())]),
        ),
        rec(
            "srv.lan.example.com",
            RData::SRV {
                priority: 10,
                weight: 5,
                port: 5060,
                target: Name::from_ascii("sip.lan.example.com").unwrap(),
            },
        ),
        rec(
            "mx.lan.example.com",
            RData::MX {
                preference: 10,
                exchange: Name::from_ascii("mail.lan.example.com").unwrap(),
            },
        ),
        rec(
            "10.2.0.192.in-addr.arpa",
            RData::PTR(Name::from_ascii("nas.lan.example.com").unwrap()),
        ),
    ];
    let views = vec![
        ViewConfig {
            id: ViewId::new("lan").unwrap(),
            is_default: false,
            subnets: vec![lan],
            nodes: Vec::new(),
            profile: ProfileId::new("default").unwrap(),
        },
        ViewConfig {
            id: ViewId::new("default").unwrap(),
            is_default: true,
            subnets: Vec::new(),
            nodes: Vec::new(),
            profile: ProfileId::new("default").unwrap(),
        },
    ];
    let (h, engine) = engine_with(views, records).await;
    let src = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 50));
    h.server(".").unwrap().clear_queries();

    let cases: &[(&str, RecordType)] = &[
        ("a.lan.example.com", RecordType::A),
        ("aaaa.lan.example.com", RecordType::AAAA),
        ("txt.lan.example.com", RecordType::TXT),
        ("srv.lan.example.com", RecordType::SRV),
        ("mx.lan.example.com", RecordType::MX),
        ("10.2.0.192.in-addr.arpa", RecordType::PTR),
    ];
    for &(name, qtype) in cases {
        let before = root_query_count(&h);
        let answer = engine.handle(ctx(src, name, qtype)).await.unwrap();
        assert_eq!(root_query_count(&h), before, "{name} {qtype} hit resolver");
        assert_eq!(answer.record.answer_source, AnswerOrigin::LocalView);
        assert!(answer.message.header.aa);
        assert!(!answer.message.header.ad);
        assert_eq!(answer.message.rcode(), Rcode::NOERROR);
        assert!(!answer.message.answers.is_empty());
        assert_eq!(answer.message.answers[0].rtype(), qtype);
        assert!(
            answer
                .record
                .steps
                .iter()
                .any(|s| matches!(s, DecisionStep::LocalView))
        );
    }
}

#[tokio::test]
async fn local_records_cname_local_a_and_external() {
    let records = vec![
        rec(
            "alias.example.com",
            RData::CNAME(Name::from_ascii("nas.example.com").unwrap()),
        ),
        rec("nas.example.com", RData::A(Ipv4Addr::new(192, 0, 2, 10))),
        rec(
            "ext.example.com",
            RData::CNAME(Name::from_ascii("cdn.example.net").unwrap()),
        ),
    ];
    let views = vec![ViewConfig {
        id: ViewId::new("default").unwrap(),
        is_default: true,
        subnets: Vec::new(),
        nodes: Vec::new(),
        profile: ProfileId::new("default").unwrap(),
    }];
    let (h, engine) = engine_with(views, records).await;
    let src = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1));
    h.server(".").unwrap().clear_queries();

    let local = engine
        .handle(ctx(src, "alias.example.com", RecordType::A))
        .await
        .unwrap();
    assert_eq!(root_query_count(&h), 0);
    assert_eq!(local.message.answers.len(), 2);
    assert_eq!(local.message.answers[0].rtype(), RecordType::CNAME);
    assert_eq!(local.message.answers[1].rtype(), RecordType::A);
    assert_eq!(
        local.message.answers[1].rdata,
        RData::A(Ipv4Addr::new(192, 0, 2, 10))
    );

    let external = engine
        .handle(ctx(src, "ext.example.com", RecordType::A))
        .await
        .unwrap();
    assert_eq!(root_query_count(&h), 0);
    assert_eq!(external.message.answers.len(), 1);
    assert_eq!(external.message.answers[0].rtype(), RecordType::CNAME);
}

#[tokio::test]
async fn local_records_cname_loop_stops_at_eight() {
    let mut records = Vec::new();
    for i in 0..8 {
        let name = format!("n{i}.example.com");
        let next = format!("n{}.example.com", (i + 1) % 8);
        records.push(rec(&name, RData::CNAME(Name::from_ascii(&next).unwrap())));
    }
    let views = vec![ViewConfig {
        id: ViewId::new("default").unwrap(),
        is_default: true,
        subnets: Vec::new(),
        nodes: Vec::new(),
        profile: ProfileId::new("default").unwrap(),
    }];
    let (h, engine) = engine_with(views, records).await;
    h.server(".").unwrap().clear_queries();
    let answer = engine
        .handle(ctx(
            IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)),
            "n0.example.com",
            RecordType::A,
        ))
        .await
        .unwrap();
    assert_eq!(root_query_count(&h), 0);
    assert_eq!(answer.message.answers.len(), 8);
    assert!(
        answer
            .message
            .answers
            .iter()
            .all(|r| r.rtype() == RecordType::CNAME)
    );
}

#[tokio::test]
async fn local_records_split_horizon_per_view() {
    let lan = IpNet::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 0)), 24).unwrap();
    let guest = IpNet::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 0)), 24).unwrap();
    let name = "app.example.com";
    let mut app = rec(name, RData::A(Ipv4Addr::new(192, 0, 2, 10)));
    app.overrides.insert(
        ViewId::new("guest").unwrap(),
        RData::A(Ipv4Addr::new(198, 51, 100, 10)),
    );
    let records = vec![app];
    let views = vec![
        ViewConfig {
            id: ViewId::new("lan").unwrap(),
            is_default: false,
            subnets: vec![lan],
            nodes: Vec::new(),
            profile: ProfileId::new("default").unwrap(),
        },
        ViewConfig {
            id: ViewId::new("guest").unwrap(),
            is_default: false,
            subnets: vec![guest],
            nodes: Vec::new(),
            profile: ProfileId::new("default").unwrap(),
        },
        ViewConfig {
            id: ViewId::new("default").unwrap(),
            is_default: true,
            subnets: Vec::new(),
            nodes: Vec::new(),
            profile: ProfileId::new("default").unwrap(),
        },
    ];
    let (_h, engine) = engine_with(views, records).await;

    let from_lan = engine
        .handle(ctx(
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 50)),
            name,
            RecordType::A,
        ))
        .await
        .unwrap();
    assert_eq!(from_lan.record.view_id.as_str(), "lan");
    assert_eq!(
        from_lan.message.answers[0].rdata,
        RData::A(Ipv4Addr::new(192, 0, 2, 10))
    );

    let from_guest = engine
        .handle(ctx(
            IpAddr::V4(Ipv4Addr::new(198, 51, 100, 50)),
            name,
            RecordType::A,
        ))
        .await
        .unwrap();
    assert_eq!(from_guest.record.view_id.as_str(), "guest");
    assert_eq!(
        from_guest.message.answers[0].rdata,
        RData::A(Ipv4Addr::new(198, 51, 100, 10))
    );
}

#[tokio::test]
async fn local_records_nodata_when_type_missing() {
    let records = vec![rec(
        "only-a.example.com",
        RData::A(Ipv4Addr::new(192, 0, 2, 10)),
    )];
    let views = vec![ViewConfig {
        id: ViewId::new("default").unwrap(),
        is_default: true,
        subnets: Vec::new(),
        nodes: Vec::new(),
        profile: ProfileId::new("default").unwrap(),
    }];
    let (h, engine) = engine_with(views, records).await;
    h.server(".").unwrap().clear_queries();
    let answer = engine
        .handle(ctx(
            IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)),
            "only-a.example.com",
            RecordType::AAAA,
        ))
        .await
        .unwrap();
    assert_eq!(root_query_count(&h), 0);
    assert_eq!(answer.record.answer_source, AnswerOrigin::LocalView);
    assert!(answer.message.header.aa);
    assert!(answer.message.answers.is_empty());
    assert_eq!(answer.message.rcode(), Rcode::NOERROR);
}

fn default_view_with_a() -> (Vec<ViewConfig>, Vec<ViewRecordConfig>) {
    let views = vec![ViewConfig {
        id: ViewId::new("default").unwrap(),
        is_default: true,
        subnets: Vec::new(),
        nodes: Vec::new(),
        profile: ProfileId::new("default").unwrap(),
    }];
    let records = vec![rec(
        "nas.example.com",
        RData::A(Ipv4Addr::new(192, 0, 2, 10)),
    )];
    (views, records)
}

#[tokio::test]
async fn synthetic_answers_mirror_client_rd() {
    let (views, records) = default_view_with_a();
    let (_h, engine) = engine_with(views, records).await;
    let src = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1));
    for rd in [true, false] {
        for (qtype, origin) in [
            (RecordType::A, AnswerOrigin::LocalView),
            (RecordType::ANY, AnswerOrigin::SynthAny),
        ] {
            let mut c = ctx(src, "nas.example.com", qtype);
            c.flags.recursion_desired = rd;
            let answer = engine.handle(c).await.unwrap();
            assert_eq!(answer.record.answer_source, origin);
            assert_eq!(answer.message.header.rd, rd, "{qtype:?} rd={rd}");
        }
    }
}

#[tokio::test]
async fn local_records_ignore_non_in_class() {
    let (views, records) = default_view_with_a();
    let (_h, engine) = engine_with(views, records).await;
    let mut c = ctx(
        IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)),
        "nas.example.com",
        RecordType::A,
    );
    c.query.qclass = Class::CH;
    let answer = engine.handle(c).await.unwrap();
    assert_ne!(answer.record.answer_source, AnswerOrigin::LocalView);
    assert!(
        !answer
            .record
            .steps
            .iter()
            .any(|s| matches!(s, DecisionStep::LocalView))
    );
}
