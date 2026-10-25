//! P11: SafeSearch + schedules config surface (stubs, status flags).

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
    ClientFlags, DecisionStep, DnsProtocol, ListenerId, NoClients, NotAppliedStep, PolicyConfig,
    PolicyEngine, ProfileConfig, ProfileId, RequestContext, SafeSearchConfig, ScheduleConfig,
    ViewConfig, ViewId,
};
use dnscraft_proto::{Class, Name, RecordType};
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

fn empty_filter() -> Arc<FilterEngine> {
    let mut sets = vec![FilterSetConfig::new(sid("default"), "default")];
    sets.push(FilterSetConfig::new(sid("evening"), "evening"));
    let cfg = FilterConfig {
        lists: Vec::new(),
        sets,
        ..FilterConfig::default()
    };
    Arc::new(FilterEngine::from_snapshot(
        SnapshotBuilder::new(Arc::new(EmptyBodies) as Arc<dyn ListBodies>)
            .build(&cfg)
            .unwrap(),
    ))
}

fn profile_base() -> ProfileConfig {
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
        client_ids: Vec::new(),
        records: Vec::new(),
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

fn ctx(name: &str) -> RequestContext {
    RequestContext {
        source_ip: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
        protocol: DnsProtocol::Udp53,
        listener_id: ListenerId::new("udp-53").unwrap(),
        client_id: None,
        query: Query {
            name: Name::from_ascii(name).unwrap(),
            qtype: RecordType::A,
            qclass: Class::IN,
        },
        flags: ClientFlags::default(),
        test_query: false,
    }
}

async fn engine_with(profile: ProfileConfig) -> PolicyEngine {
    let h = Hierarchy::start().await.unwrap();
    let resolver = Arc::new(Resolver::new(config_for(&h)).await.unwrap());
    let cfg = PolicyConfig {
        default_rebind: true,
        ptr_prefixes: Vec::new(),
        local_nxdomain_suffixes: Vec::new(),
        rebind_check_forward_zones: Vec::new(),
        views: vec![default_view()],
        profiles: vec![profile],
    };
    PolicyEngine::new(cfg, empty_filter(), resolver, Arc::new(NoClients), clock()).unwrap()
}

#[tokio::test]
async fn safesearch_enabled_records_not_applied_and_status_false() {
    let mut profile = profile_base();
    profile.safesearch = SafeSearchConfig {
        enabled: true,
        providers: vec![Arc::from("google")],
    };
    let eng = engine_with(profile).await;

    let status = eng.status();
    assert!(!status.safesearch_applied);
    assert!(!status.schedules_applied);

    let ans = eng.handle(ctx("www.example.test.")).await.unwrap();
    assert!(
        ans.record.steps.contains(&DecisionStep::NotApplied {
            step: NotAppliedStep::SafeSearch,
        }),
        "step 5 stub missing: {:?}",
        ans.record.steps
    );
    assert!(
        ans.record.steps.contains(&DecisionStep::NotApplied {
            step: NotAppliedStep::SafeSearchFilter,
        }),
        "step 6 stub missing: {:?}",
        ans.record.steps
    );
}

#[tokio::test]
async fn schedules_config_validates_and_records_not_applied() {
    let mut profile = profile_base();
    profile.schedules = vec![ScheduleConfig {
        id: Arc::from("evening"),
        filter_set: sid("evening"),
        start: Duration::from_secs(18 * 3600),
        end: Duration::from_secs(22 * 3600),
    }];
    let eng = engine_with(profile).await;
    assert!(!eng.status().schedules_applied);

    let ans = eng.handle(ctx("www.example.test.")).await.unwrap();
    assert!(ans.record.steps.contains(&DecisionStep::NotApplied {
        step: NotAppliedStep::Schedules,
    }));
}

#[tokio::test]
async fn safesearch_disabled_no_not_applied_steps() {
    let eng = engine_with(profile_base()).await;
    let ans = eng.handle(ctx("www.example.test.")).await.unwrap();
    assert!(
        !ans.record
            .steps
            .iter()
            .any(|s| matches!(s, DecisionStep::NotApplied { .. }))
    );
}

#[test]
fn schedule_unknown_filter_set_rejected() {
    let mut profile = profile_base();
    profile.schedules = vec![ScheduleConfig {
        id: Arc::from("bad"),
        filter_set: sid("missing"),
        start: Duration::ZERO,
        end: Duration::from_secs(1),
    }];
    let cfg = PolicyConfig {
        default_rebind: true,
        ptr_prefixes: Vec::new(),
        local_nxdomain_suffixes: Vec::new(),
        rebind_check_forward_zones: Vec::new(),
        views: vec![default_view()],
        profiles: vec![profile],
    };
    // Filter engine only knows default + evening — not "missing".
    let filter = empty_filter();
    let err = dnscraft_policy::PolicySnapshot::build(
        cfg,
        &filter.snapshot().set_ids().cloned().collect::<Vec<_>>(),
        &[],
    )
    .unwrap_err();
    assert_eq!(err.code(), "policy.config.unknown_filter_set");
}
