//! P14: schedule evaluation (active filter set by week offset).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::{Duration, UNIX_EPOCH};

use dnscraft_filtering::{
    BlockMode, FilterConfig, FilterEngine, FilterSetConfig, ListBodies, ListId, ManualClock, SetId,
    SnapshotBuilder,
};
use dnscraft_policy::{
    ClientFlags, DecisionStep, DnsProtocol, ListenerId, NoClients, PauseScope, PauseUntil,
    PolicyConfig, PolicyEngine, ProfileConfig, ProfileId, RequestContext, SCHEDULE_WEEK,
    SafeSearchConfig, ScheduleConfig, ViewConfig, ViewId, YoutubeMode, active_schedule,
    offset_in_week,
};
use dnscraft_proto::{Class, Name, Rcode, RecordType};
use dnscraft_resolver::dnssec::TrustAnchors;
use dnscraft_resolver::{Query, Resolver, ResolverConfig};
use dnscraft_testkit::{Hierarchy, ServerSpec, Zone, default_servers};
use hickory_proto::rr::rdata::CNAME;
use hickory_proto::rr::{Name as HName, RData as HRData, Record as HRecord};

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

/// Monday 00:00 UTC + `offset` on the ManualClock.
fn clock_at_week_offset(offset: Duration) -> Arc<ManualClock> {
    // 1970-01-05 was Monday (epoch Thursday + 4 days).
    let monday = UNIX_EPOCH + Duration::from_secs(4 * 24 * 3600);
    Arc::new(ManualClock::new(monday + offset))
}

fn filter_sets(default_rules: &str, evening_rules: &str) -> Arc<FilterEngine> {
    let mut default = FilterSetConfig::new(sid("default"), "default");
    default.custom_rules = default_rules.to_owned();
    default.block_mode = BlockMode::NxDomain;
    let mut evening = FilterSetConfig::new(sid("evening"), "evening");
    evening.custom_rules = evening_rules.to_owned();
    evening.block_mode = BlockMode::NxDomain;
    Arc::new(FilterEngine::from_snapshot(
        SnapshotBuilder::new(Arc::new(EmptyBodies) as Arc<dyn ListBodies>)
            .build(&FilterConfig {
                lists: Vec::new(),
                sets: vec![default, evening],
                ..FilterConfig::default()
            })
            .unwrap(),
    ))
}

fn profile_with(schedules: Vec<ScheduleConfig>) -> ProfileConfig {
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
        schedules,
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

fn evening_window() -> ScheduleConfig {
    ScheduleConfig {
        id: Arc::from("evening"),
        filter_set: sid("evening"),
        start: Duration::from_secs(18 * 3600),
        end: Duration::from_secs(22 * 3600),
    }
}

async fn engine_at(
    schedules: Vec<ScheduleConfig>,
    default_rules: &str,
    evening_rules: &str,
    offset: Duration,
) -> (Hierarchy, PolicyEngine) {
    let h = Hierarchy::start().await.unwrap();
    let resolver = Arc::new(Resolver::new(config_for(&h)).await.unwrap());
    let cfg = PolicyConfig {
        default_rebind: true,
        ptr_prefixes: Vec::new(),
        local_nxdomain_suffixes: Vec::new(),
        rebind_check_forward_zones: Vec::new(),
        views: vec![default_view()],
        profiles: vec![profile_with(schedules)],
    };
    let eng = PolicyEngine::new(
        cfg,
        filter_sets(default_rules, evening_rules),
        resolver,
        Arc::new(NoClients),
        clock_at_week_offset(offset),
    )
    .unwrap();
    (h, eng)
}

const NAME: &str = "www.example.test.";
const BLOCK: &str = "||www.example.test^\n";

#[tokio::test]
async fn before_inside_after_window() {
    // default set blocks; evening set is empty (allows).
    let schedules = vec![evening_window()];

    let (_h, before) =
        engine_at(schedules.clone(), BLOCK, "", Duration::from_secs(17 * 3600)).await;
    let ans = before.handle(ctx(NAME)).await.unwrap();
    assert_eq!(ans.message.rcode(), Rcode::NXDOMAIN);
    assert!(
        !ans.record
            .steps
            .iter()
            .any(|s| matches!(s, DecisionStep::ScheduleActive { .. }))
    );
    assert_eq!(ans.record.filter_set, sid("default"));

    let (_h, inside) =
        engine_at(schedules.clone(), BLOCK, "", Duration::from_secs(19 * 3600)).await;
    let ans = inside.handle(ctx(NAME)).await.unwrap();
    assert_eq!(ans.message.rcode(), Rcode::NOERROR);
    assert!(!ans.record.steps.contains(&DecisionStep::FilterBlocked));
    assert!(ans.record.steps.contains(&DecisionStep::ScheduleActive {
        id: Arc::from("evening"),
        filter_set: sid("evening"),
    }));
    assert_eq!(ans.record.filter_set, sid("evening"));
    assert!(inside.status().schedules_applied);
    assert_eq!(
        inside.status().active_schedules[0]
            .active_schedule_id
            .as_deref(),
        Some("evening")
    );

    let (_h, after) = engine_at(schedules, BLOCK, "", Duration::from_secs(22 * 3600)).await;
    let ans = after.handle(ctx(NAME)).await.unwrap();
    assert_eq!(ans.message.rcode(), Rcode::NXDOMAIN);
    assert_eq!(ans.record.filter_set, sid("default"));
    assert!(
        after.status().active_schedules[0]
            .active_schedule_id
            .is_none()
    );
}

#[tokio::test]
async fn window_boundaries_inclusive_start_exclusive_end() {
    let schedules = vec![evening_window()];
    let (_h, at_start) =
        engine_at(schedules.clone(), BLOCK, "", Duration::from_secs(18 * 3600)).await;
    assert_eq!(
        at_start.handle(ctx(NAME)).await.unwrap().record.filter_set,
        sid("evening")
    );

    let (_h, at_end) = engine_at(schedules, BLOCK, "", Duration::from_secs(22 * 3600)).await;
    assert_eq!(
        at_end.handle(ctx(NAME)).await.unwrap().record.filter_set,
        sid("default")
    );
}

#[tokio::test]
async fn sunday_to_monday_split_windows() {
    let sun_start = 6 * 24 * 3600 + 22 * 3600;
    let schedules = vec![
        ScheduleConfig {
            id: Arc::from("sun-late"),
            filter_set: sid("evening"),
            start: Duration::from_secs(sun_start),
            end: SCHEDULE_WEEK,
        },
        ScheduleConfig {
            id: Arc::from("mon-early"),
            filter_set: sid("evening"),
            start: Duration::ZERO,
            end: Duration::from_secs(2 * 3600),
        },
    ];

    let (_h, sun) = engine_at(
        schedules.clone(),
        BLOCK,
        "",
        Duration::from_secs(sun_start + 60),
    )
    .await;
    let ans = sun.handle(ctx(NAME)).await.unwrap();
    assert_eq!(ans.record.filter_set, sid("evening"));
    assert!(ans.record.steps.iter().any(|s| matches!(
        s,
        DecisionStep::ScheduleActive { id, .. } if id.as_ref() == "sun-late"
    )));

    let (_h, mon) = engine_at(schedules, BLOCK, "", Duration::from_secs(3600)).await;
    let ans = mon.handle(ctx(NAME)).await.unwrap();
    assert_eq!(ans.record.filter_set, sid("evening"));
    assert!(ans.record.steps.iter().any(|s| matches!(
        s,
        DecisionStep::ScheduleActive { id, .. } if id.as_ref() == "mon-early"
    )));
}

#[tokio::test]
async fn schedule_set_blocks_name_default_allows_and_vice_versa() {
    // default empty (allows); evening blocks.
    let schedules = vec![evening_window()];
    let (_h, outside) =
        engine_at(schedules.clone(), "", BLOCK, Duration::from_secs(12 * 3600)).await;
    assert_eq!(
        outside.handle(ctx(NAME)).await.unwrap().message.rcode(),
        Rcode::NOERROR
    );

    let (_h, inside) = engine_at(schedules, "", BLOCK, Duration::from_secs(19 * 3600)).await;
    assert_eq!(
        inside.handle(ctx(NAME)).await.unwrap().message.rcode(),
        Rcode::NXDOMAIN
    );
}

#[tokio::test]
async fn pause_wins_over_schedule() {
    let schedules = vec![evening_window()];
    let (_h, eng) = engine_at(schedules, "", BLOCK, Duration::from_secs(19 * 3600)).await;
    eng.pause(PauseScope::Global, PauseUntil::UntilResumed)
        .unwrap();
    let ans = eng.handle(ctx(NAME)).await.unwrap();
    assert!(
        ans.record
            .steps
            .iter()
            .any(|s| matches!(s, DecisionStep::ProtectionPaused { .. }))
    );
    assert!(ans.record.steps.contains(&DecisionStep::ScheduleActive {
        id: Arc::from("evening"),
        filter_set: sid("evening"),
    }));
    // Filtering Passes while paused despite evening blocking the name.
    assert_eq!(ans.message.rcode(), Rcode::NOERROR);
}

#[tokio::test]
async fn reload_swaps_windows() {
    let (_h, eng) = engine_at(
        vec![evening_window()],
        BLOCK,
        "",
        Duration::from_secs(19 * 3600),
    )
    .await;
    assert_eq!(
        eng.handle(ctx(NAME)).await.unwrap().record.filter_set,
        sid("evening")
    );

    let mut cfg = PolicyConfig {
        default_rebind: true,
        ptr_prefixes: Vec::new(),
        local_nxdomain_suffixes: Vec::new(),
        rebind_check_forward_zones: Vec::new(),
        views: vec![default_view()],
        profiles: vec![profile_with(vec![ScheduleConfig {
            id: Arc::from("night"),
            filter_set: sid("evening"),
            start: Duration::from_secs(22 * 3600),
            end: Duration::from_secs(23 * 3600),
        }])],
    };
    // Window no longer covers 19:00 → default set.
    eng.apply_config(cfg.clone()).await.unwrap();
    assert_eq!(
        eng.handle(ctx(NAME)).await.unwrap().record.filter_set,
        sid("default")
    );

    cfg.profiles[0].schedules = vec![ScheduleConfig {
        id: Arc::from("afternoon"),
        filter_set: sid("evening"),
        start: Duration::from_secs(12 * 3600),
        end: Duration::from_secs(20 * 3600),
    }];
    eng.apply_config(cfg).await.unwrap();
    let ans = eng.handle(ctx(NAME)).await.unwrap();
    assert_eq!(ans.record.filter_set, sid("evening"));
    assert!(ans.record.steps.iter().any(|s| matches!(
        s,
        DecisionStep::ScheduleActive { id, .. } if id.as_ref() == "afternoon"
    )));
}

#[test]
fn active_schedule_api_takes_offset_in_week() {
    let windows = [evening_window()];
    assert!(active_schedule(&windows, Duration::from_secs(17 * 3600)).is_none());
    assert_eq!(
        active_schedule(&windows, Duration::from_secs(18 * 3600))
            .unwrap()
            .id
            .as_ref(),
        "evening"
    );
    let monday = UNIX_EPOCH + Duration::from_secs(4 * 24 * 3600);
    assert_eq!(offset_in_week(monday), Duration::ZERO);
    assert_eq!(
        offset_in_week(monday + Duration::from_secs(18 * 3600)),
        Duration::from_secs(18 * 3600)
    );
}
