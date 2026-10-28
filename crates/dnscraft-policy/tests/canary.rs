//! Step 3: bypass canaries (Firefox DoH, iCloud Private Relay).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use dnscraft_filtering::{
    FilterConfig, FilterEngine, FilterSetConfig, ListBodies, ListId, ManualClock, SetId,
    SnapshotBuilder,
};
use dnscraft_policy::{
    AnswerOrigin, ClientFlags, DecisionStep, DnsProtocol, ListenerId, NoClients, PolicyConfig,
    PolicyEngine, ProfileConfig, ProfileId, RequestContext, SafeSearchConfig, ViewConfig, ViewId,
};
use dnscraft_proto::{Class, Name, Rcode, RecordType};
use dnscraft_resolver::dnssec::TrustAnchors;
use dnscraft_resolver::{Query, Resolver, ResolverConfig};
use dnscraft_testkit::Hierarchy;

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

fn profile(firefox: bool, icloud: bool) -> ProfileConfig {
    ProfileConfig {
        id: ProfileId::new("default").unwrap(),
        filter_set: set("default"),
        suppress_aaaa: false,
        firefox_canary: firefox,
        icloud_private_relay: icloud,
        rebind: None,
        rebind_exceptions: Vec::new(),
        forward_zones: None,
        safesearch: SafeSearchConfig::default(),
        schedules: Vec::new(),
    }
}

fn default_view() -> ViewConfig {
    ViewConfig {
        id: ViewId::new("default").unwrap(),
        is_default: true,
        subnets: Vec::new(),
        nodes: Vec::new(),
        profile: ProfileId::new("default").unwrap(),
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

async fn engine(firefox: bool, icloud: bool) -> (Hierarchy, PolicyEngine) {
    let h = Hierarchy::start().await.unwrap();
    let resolver = Arc::new(Resolver::new(config_for(&h)).await.unwrap());
    let cfg = PolicyConfig {
        client_ids: Vec::new(),
        records: Vec::new(),
        default_rebind: true,
        ptr_prefixes: Vec::new(),
        local_nxdomain_suffixes: Vec::new(),
        rebind_check_forward_zones: Vec::new(),
        views: vec![default_view()],
        profiles: vec![profile(firefox, icloud)],
    };
    let engine =
        PolicyEngine::new(cfg, empty_filter(), resolver, Arc::new(NoClients), clock()).unwrap();
    (h, engine)
}

#[tokio::test]
async fn canary_firefox_nxdomain_when_enabled_resolves_when_disabled() {
    let (h, on) = engine(true, false).await;
    let before = root_query_count(&h);
    let ans = on
        .handle(ctx("use-application-dns.net", RecordType::A))
        .await
        .unwrap();
    assert_eq!(ans.message.rcode(), Rcode::NXDOMAIN);
    assert_eq!(ans.record.answer_source, AnswerOrigin::Bypass);
    assert!(ans.record.steps.contains(&DecisionStep::Bypass));
    assert!(ans.ede.is_none());
    assert!(!ans.message.header.ad);
    assert_eq!(root_query_count(&h), before);

    let aaaa = on
        .handle(ctx("use-application-dns.net", RecordType::AAAA))
        .await
        .unwrap();
    assert_eq!(aaaa.message.rcode(), Rcode::NXDOMAIN);
    assert_eq!(aaaa.record.answer_source, AnswerOrigin::Bypass);
    assert_eq!(root_query_count(&h), before);

    let (h2, off) = engine(false, false).await;
    let before2 = root_query_count(&h2);
    let passthrough = off
        .handle(ctx("use-application-dns.net", RecordType::A))
        .await
        .unwrap();
    assert_ne!(passthrough.record.answer_source, AnswerOrigin::Bypass);
    assert!(
        !passthrough
            .record
            .steps
            .iter()
            .any(|s| matches!(s, DecisionStep::Bypass))
    );
    assert!(root_query_count(&h2) > before2);
}

#[tokio::test]
async fn canary_icloud_mask_names_when_enabled() {
    let (h, on) = engine(false, true).await;
    let before = root_query_count(&h);
    for name in ["mask.icloud.com", "mask-h2.icloud.com"] {
        let ans = on.handle(ctx(name, RecordType::A)).await.unwrap();
        assert_eq!(ans.message.rcode(), Rcode::NXDOMAIN, "{name}");
        assert_eq!(ans.record.answer_source, AnswerOrigin::Bypass, "{name}");
        assert!(ans.ede.is_none(), "{name}");
    }
    assert_eq!(root_query_count(&h), before);
    // Sibling used by Apple but not a canary — must not be synthesised.
    let other = on
        .handle(ctx("mask-api.icloud.com", RecordType::A))
        .await
        .unwrap();
    assert_ne!(other.record.answer_source, AnswerOrigin::Bypass);

    let (h2, off) = engine(false, false).await;
    let before2 = root_query_count(&h2);
    let passthrough = off
        .handle(ctx("mask.icloud.com", RecordType::A))
        .await
        .unwrap();
    assert_ne!(passthrough.record.answer_source, AnswerOrigin::Bypass);
    assert!(root_query_count(&h2) > before2);
}
