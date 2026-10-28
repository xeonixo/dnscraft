//! Hot reload: apply_config keeps last-good snapshot; counters survive by id.

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
    ClientFlags, DecisionStep, DnsProtocol, ListenerId, NoClients, PauseScope, PauseUntil,
    PolicyConfig, PolicyEngine, ProfileConfig, ProfileId, RequestContext, SafeSearchConfig,
    ViewConfig, ViewId, ViewRecordConfig,
};
use dnscraft_proto::{Class, Name, RData, Rcode, RecordType};
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

fn sid(s: &str) -> SetId {
    SetId::new(s).unwrap()
}

fn blocking_filter() -> Arc<FilterEngine> {
    let mut set = FilterSetConfig::new(sid("default"), "default");
    set.custom_rules = "||ads.example^\n".to_owned();
    set.block_mode = BlockMode::NxDomain;
    let cfg = FilterConfig {
        lists: Vec::new(),
        sets: vec![set],
        ..FilterConfig::default()
    };
    Arc::new(FilterEngine::from_snapshot(
        SnapshotBuilder::new(Arc::new(EmptyBodies) as Arc<dyn ListBodies>)
            .build(&cfg)
            .unwrap(),
    ))
}

fn profile(id: &str) -> ProfileConfig {
    ProfileConfig {
        id: ProfileId::new(id).unwrap(),
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

fn default_view(profile: &str) -> ViewConfig {
    ViewConfig {
        id: ViewId::new("default").unwrap(),
        is_default: true,
        subnets: Vec::new(),
        nodes: Vec::new(),
        profile: ProfileId::new(profile).unwrap(),
    }
}

fn base_cfg() -> PolicyConfig {
    PolicyConfig {
        client_ids: Vec::new(),
        records: Vec::new(),
        default_rebind: true,
        ptr_prefixes: Vec::new(),
        local_nxdomain_suffixes: Vec::new(),
        rebind_check_forward_zones: Vec::new(),
        views: vec![default_view("default")],
        profiles: vec![profile("default")],
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

async fn engine() -> PolicyEngine {
    let h = Hierarchy::start().await.unwrap();
    let resolver = Arc::new(Resolver::new(config_for(&h)).await.unwrap());
    PolicyEngine::new(
        base_cfg(),
        blocking_filter(),
        resolver,
        Arc::new(NoClients),
        clock(),
    )
    .unwrap()
}

#[tokio::test]
async fn apply_config_invalid_keeps_old_snapshot() {
    let eng = engine().await;

    // Baseline: blocked name → NXDOMAIN from filter.
    let before = eng.handle(ctx("ads.example", RecordType::A)).await.unwrap();
    assert!(before.record.steps.contains(&DecisionStep::FilterBlocked));

    // Invalid: no default view.
    let mut bad = base_cfg();
    bad.views[0].is_default = false;
    let err = eng.apply_config(bad).await.unwrap_err();
    assert_eq!(err.code(), "policy.config.invalid");

    // Still the old snapshot.
    let after = eng.handle(ctx("ads.example", RecordType::A)).await.unwrap();
    assert!(after.record.steps.contains(&DecisionStep::FilterBlocked));
}

#[tokio::test]
async fn apply_config_valid_takes_effect_next_query() {
    let eng = engine().await;

    let mut next = base_cfg();
    next.records.push(ViewRecordConfig {
        name: Name::from_ascii("local.test.").unwrap(),
        ttl: 60,
        rdata: RData::A(Ipv4Addr::new(192, 0, 2, 50)),
        overrides: Default::default(),
    });
    eng.apply_config(next).await.unwrap();

    let ans = eng.handle(ctx("local.test.", RecordType::A)).await.unwrap();
    assert_eq!(ans.message.rcode(), Rcode::NOERROR);
    assert!(ans.record.steps.contains(&DecisionStep::LocalView));
    assert!(!ans.message.answers.is_empty());
}

#[tokio::test]
async fn counters_increment_and_survive_reload() {
    let eng = engine().await;

    eng.handle(ctx("ads.example", RecordType::A)).await.unwrap();
    eng.handle(ctx("ads.example", RecordType::A)).await.unwrap();

    let stats = eng.stats();
    let view = stats
        .views
        .iter()
        .find(|v| v.view.as_str() == "default")
        .unwrap();
    assert_eq!(view.queries, 2);
    assert_eq!(view.blocked, 2);
    assert_eq!(view.local_hits, 0);
    let profile = stats
        .profiles
        .iter()
        .find(|p| p.profile.as_str() == "default")
        .unwrap();
    assert_eq!(profile.queries, 2);
    assert_eq!(profile.blocked, 2);

    // Local view hit.
    let mut with_local = base_cfg();
    with_local.records.push(ViewRecordConfig {
        name: Name::from_ascii("lan.test.").unwrap(),
        ttl: 60,
        rdata: RData::A(Ipv4Addr::new(192, 0, 2, 7)),
        overrides: Default::default(),
    });
    eng.apply_config(with_local).await.unwrap();
    eng.handle(ctx("lan.test.", RecordType::A)).await.unwrap();

    let mid = eng.stats();
    let view = mid
        .views
        .iter()
        .find(|v| v.view.as_str() == "default")
        .unwrap();
    assert_eq!(view.queries, 3);
    assert_eq!(view.blocked, 2);
    assert_eq!(view.local_hits, 1);

    // Valid reload (same ids) must keep counters.
    eng.apply_config(base_cfg()).await.unwrap();
    let after = eng.stats();
    let view = after
        .views
        .iter()
        .find(|v| v.view.as_str() == "default")
        .unwrap();
    assert_eq!(view.queries, 3);
    assert_eq!(view.blocked, 2);
    assert_eq!(view.local_hits, 1);

    eng.handle(ctx("ads.example", RecordType::A)).await.unwrap();
    assert_eq!(
        eng.stats()
            .views
            .iter()
            .find(|v| v.view.as_str() == "default")
            .unwrap()
            .queries,
        4
    );
}

#[tokio::test]
async fn test_query_does_not_inflate_stats() {
    let eng = engine().await;
    let before = eng.stats();

    let mut tq = ctx("ads.example", RecordType::A);
    tq.test_query = true;
    let ans = eng.handle(tq).await.unwrap();
    assert!(!ans.loggable);
    assert!(ans.record.steps.contains(&DecisionStep::FilterBlocked));
    assert_eq!(eng.stats(), before, "test_query must not bump counters");

    eng.handle(ctx("ads.example", RecordType::A)).await.unwrap();
    let after = eng.stats();
    let view = after
        .views
        .iter()
        .find(|v| v.view.as_str() == "default")
        .unwrap();
    assert_eq!(view.queries, 1);
    assert_eq!(view.blocked, 1);
}

#[tokio::test]
async fn apply_config_adds_new_ids_and_drops_removed_counters() {
    let eng = engine().await;
    eng.handle(ctx("ads.example", RecordType::A)).await.unwrap();
    assert_eq!(
        eng.stats()
            .views
            .iter()
            .find(|v| v.view.as_str() == "default")
            .unwrap()
            .queries,
        1
    );

    // Add a new view + profile (mutant that skips ensure/sync for new ids fails).
    let mut next = base_cfg();
    next.profiles.push(profile("kids"));
    next.views.push(ViewConfig {
        id: ViewId::new("kids").unwrap(),
        is_default: false,
        subnets: vec!["192.0.2.10/32".parse().unwrap()],
        nodes: Vec::new(),
        profile: ProfileId::new("kids").unwrap(),
    });
    eng.apply_config(next).await.unwrap();

    eng.handle(ctx("ads.example", RecordType::A)).await.unwrap();

    let stats = eng.stats();
    let kids_view = stats
        .views
        .iter()
        .find(|v| v.view.as_str() == "kids")
        .expect("new view must appear in stats");
    assert_eq!(kids_view.queries, 1);
    assert_eq!(kids_view.blocked, 1);
    let kids_profile = stats
        .profiles
        .iter()
        .find(|p| p.profile.as_str() == "kids")
        .expect("new profile must appear in stats");
    assert_eq!(kids_profile.queries, 1);
    assert_eq!(
        stats
            .views
            .iter()
            .find(|v| v.view.as_str() == "default")
            .unwrap()
            .queries,
        1,
        "existing counters survive"
    );

    // Drop kids → counters for removed ids must leave stats().
    eng.apply_config(base_cfg()).await.unwrap();
    let pruned = eng.stats();
    assert!(
        pruned.views.iter().all(|v| v.view.as_str() != "kids"),
        "removed view counters must be dropped"
    );
    assert!(
        pruned.profiles.iter().all(|p| p.profile.as_str() != "kids"),
        "removed profile counters must be dropped"
    );
    assert_eq!(
        pruned
            .views
            .iter()
            .find(|v| v.view.as_str() == "default")
            .unwrap()
            .queries,
        1
    );
}

#[tokio::test]
async fn apply_config_drops_pause_for_removed_profile() {
    let h = Hierarchy::start().await.unwrap();
    let resolver = Arc::new(Resolver::new(config_for(&h)).await.unwrap());
    let mut cfg = base_cfg();
    cfg.profiles.push(profile("kids"));
    cfg.views.push(ViewConfig {
        id: ViewId::new("kids").unwrap(),
        is_default: false,
        subnets: Vec::new(),
        nodes: Vec::new(),
        profile: ProfileId::new("kids").unwrap(),
    });
    let eng = PolicyEngine::new(
        cfg,
        blocking_filter(),
        resolver,
        Arc::new(NoClients),
        clock(),
    )
    .unwrap();

    eng.pause(
        PauseScope::Profile(ProfileId::new("kids").unwrap()),
        PauseUntil::UntilResumed,
    )
    .unwrap();

    // Drop kids profile + view.
    eng.apply_config(base_cfg()).await.unwrap();

    // Re-adding kids must not inherit the old pause (pause was dropped).
    let mut again = base_cfg();
    again.profiles.push(profile("kids"));
    again.views.push(ViewConfig {
        id: ViewId::new("kids").unwrap(),
        is_default: false,
        subnets: vec!["192.0.2.10/32".parse().unwrap()],
        nodes: Vec::new(),
        profile: ProfileId::new("kids").unwrap(),
    });
    eng.apply_config(again).await.unwrap();

    let ans = eng.handle(ctx("ads.example", RecordType::A)).await.unwrap();
    assert!(
        ans.record.steps.contains(&DecisionStep::FilterBlocked),
        "pause for removed profile must not survive reload"
    );
}
