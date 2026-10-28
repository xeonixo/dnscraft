//! Task M5: dry-run (`test_query`) requests are side-effect free.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use dnscraft_filtering::{
    BlockMode, FilterConfig, FilterEngine, FilterSetConfig, ListBodies, ListId, ManualClock, SetId,
    SnapshotBuilder,
};
use dnscraft_policy::{
    ClientFlags, DecisionStep, DnsProtocol, ListenerId, NoClients, PolicyConfig, PolicyEngine,
    ProfileConfig, ProfileId, RequestContext, SafeSearchConfig, ViewConfig, ViewId,
};
use dnscraft_proto::{Class, Name, Rcode, RecordType};
use dnscraft_resolver::dnssec::TrustAnchors;
use dnscraft_resolver::{AnswerSource, Query, Resolver, ResolverConfig};
use dnscraft_testkit::{Hierarchy, ServerHandle};

#[derive(Debug, Default)]
struct EmptyBodies;

impl ListBodies for EmptyBodies {
    fn body(&self, _id: &ListId) -> Option<Arc<str>> {
        None
    }
}

fn sid(s: &str) -> SetId {
    SetId::new(s).unwrap()
}

fn filter_with(custom: &str) -> Arc<FilterEngine> {
    let mut set = FilterSetConfig::new(sid("default"), "default");
    set.custom_rules = custom.to_owned();
    set.block_mode = BlockMode::NxDomain;
    Arc::new(FilterEngine::from_snapshot(
        SnapshotBuilder::new(Arc::new(EmptyBodies) as Arc<dyn ListBodies>)
            .build(&FilterConfig {
                lists: Vec::new(),
                sets: vec![set],
                ..FilterConfig::default()
            })
            .unwrap(),
    ))
}

fn profile() -> ProfileConfig {
    ProfileConfig {
        id: ProfileId::new("default").unwrap(),
        filter_set: sid("default"),
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

fn ctx(name: &str, qtype: RecordType, test_query: bool) -> RequestContext {
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
        test_query,
    }
}

async fn engine_with(filter: Arc<FilterEngine>) -> (Hierarchy, Arc<Resolver>, PolicyEngine) {
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
        profiles: vec![profile()],
    };
    let clock = Arc::new(ManualClock::new(
        SystemTime::UNIX_EPOCH + Duration::from_secs(1_000),
    ));
    let eng = PolicyEngine::new(
        cfg,
        filter,
        Arc::clone(&resolver),
        Arc::new(NoClients),
        clock,
    )
    .unwrap();
    (h, resolver, eng)
}

fn zones(h: &Hierarchy) -> Vec<&ServerHandle> {
    [".", "test.", "example.test."]
        .iter()
        .map(|z| h.server(z).unwrap())
        .collect()
}

fn clear(h: &Hierarchy) {
    for server in zones(h) {
        server.clear_queries();
    }
}

fn traffic(h: &Hierarchy) -> usize {
    zones(h).iter().map(|s| s.queries().len()).sum()
}

fn resolved_from(answer: &dnscraft_policy::PolicyAnswer) -> Option<AnswerSource> {
    answer.record.steps.iter().find_map(|step| match step {
        DecisionStep::Resolve { source, .. } => Some(*source),
        _ => None,
    })
}

#[tokio::test]
async fn test_query_does_not_write_the_cache_or_policy_stats() {
    let (h, resolver, eng) = engine_with(filter_with("")).await;
    let stats_before = eng.stats();
    assert_eq!(resolver.stats().cache_entries, 0);

    clear(&h);
    let first = eng
        .handle(ctx("www.example.test.", RecordType::A, true))
        .await
        .unwrap();
    assert!(!first.loggable);
    assert_eq!(resolved_from(&first), Some(AnswerSource::Recursion));
    assert!(traffic(&h) > 0, "a test query still resolves upstream");
    assert_eq!(resolver.stats().cache_entries, 0);
    assert_eq!(eng.stats(), stats_before);

    clear(&h);
    let second = eng
        .handle(ctx("www.example.test.", RecordType::A, true))
        .await
        .unwrap();
    assert_eq!(
        resolved_from(&second),
        Some(AnswerSource::Recursion),
        "a test query must not become a cache hit"
    );
    assert!(traffic(&h) > 0, "the second test query must go upstream");
    assert_eq!(resolver.stats().cache_entries, 0);
    assert_eq!(eng.stats(), stats_before);
}

#[tokio::test]
async fn test_query_still_returns_the_full_decision_record() {
    let (_h, resolver, eng) = engine_with(filter_with("||ads.example.test^\n")).await;
    let stats_before = eng.stats();

    let answer = eng
        .handle(ctx("ads.example.test.", RecordType::A, true))
        .await
        .unwrap();

    assert!(!answer.loggable);
    assert_eq!(answer.record.view_id, ViewId::new("default").unwrap());
    assert_eq!(answer.record.profile_id, ProfileId::new("default").unwrap());
    assert_eq!(answer.record.filter_set, sid("default"));
    assert_eq!(answer.record.rcode, Rcode::NXDOMAIN);
    assert_eq!(
        answer
            .record
            .filter
            .as_ref()
            .map(|f| f.reason.rule.as_ref()),
        Some("||ads.example.test^")
    );
    assert!(
        answer
            .record
            .steps
            .iter()
            .any(|step| matches!(step, DecisionStep::FilterBlocked))
    );
    assert_eq!(resolver.stats().cache_entries, 0);
    assert_eq!(eng.stats(), stats_before);
}

#[tokio::test]
async fn test_query_rewrite_follow_does_not_write_the_cache() {
    let (h, resolver, eng) = engine_with(filter_with(
        "||rewrite.example.test^$dnsrewrite=www.example.test\n",
    ))
    .await;

    let test = eng
        .handle(ctx("rewrite.example.test.", RecordType::A, true))
        .await
        .unwrap();
    assert!(!test.loggable);
    assert!(
        test.record
            .steps
            .iter()
            .any(|step| matches!(step, DecisionStep::FilterRewrite))
    );
    assert_eq!(resolver.stats().cache_entries, 0, "test query wrote cache");

    // The same query as normal traffic does cache the followed target.
    let normal = eng
        .handle(ctx("rewrite.example.test.", RecordType::A, false))
        .await
        .unwrap();
    assert!(normal.loggable);
    assert!(resolver.stats().cache_entries > 0);
    assert!(traffic(&h) > 0);
}

#[tokio::test]
async fn test_query_reads_a_cache_entry_warmed_by_normal_traffic() {
    let (h, resolver, eng) = engine_with(filter_with("")).await;

    let warm = eng
        .handle(ctx("www.example.test.", RecordType::A, false))
        .await
        .unwrap();
    assert!(warm.loggable);
    assert_eq!(resolved_from(&warm), Some(AnswerSource::Recursion));
    let entries = resolver.stats().cache_entries;
    assert!(entries > 0);
    let stats_after_warm = eng.stats();

    clear(&h);
    let dry = eng
        .handle(ctx("www.example.test.", RecordType::A, true))
        .await
        .unwrap();
    assert!(!dry.loggable);
    assert_eq!(
        resolved_from(&dry),
        Some(AnswerSource::Cache),
        "a test query must read the cache"
    );
    assert_eq!(traffic(&h), 0, "a warm cache hit must not go upstream");
    assert_eq!(resolver.stats().cache_entries, entries);
    assert_eq!(eng.stats(), stats_after_warm);
}

#[tokio::test]
async fn normal_query_updates_policy_stats_and_cache() {
    let (_h, resolver, eng) = engine_with(filter_with("")).await;
    let before = eng.stats();
    assert_eq!(resolver.stats().cache_entries, 0);

    let answer = eng
        .handle(ctx("www.example.test.", RecordType::A, false))
        .await
        .unwrap();
    assert!(answer.loggable);
    assert_ne!(eng.stats(), before);
    assert!(resolver.stats().cache_entries > 0);
}
