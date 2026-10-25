//! Pause protection: global / per-profile scopes; filter skipped, other steps still run.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use dnscraft_filtering::{
    BlockMode, FilterConfig, FilterEngine, FilterSetConfig, ListBodies, ListId, ManualClock, SetId,
    SnapshotBuilder,
};
use dnscraft_policy::{
    AnswerOrigin, ClientFlags, ClientId, DecisionStep, DnsProtocol, ListenerId, NoClients,
    PauseScope, PauseUntil, PolicyConfig, PolicyEngine, ProfileConfig, ProfileId, RequestContext,
    SafeSearchConfig, ViewConfig, ViewId,
};
use dnscraft_proto::{Class, Name, Rcode, RecordType};
use dnscraft_resolver::dnssec::TrustAnchors;
use dnscraft_resolver::{Query, Resolver, ResolverConfig};
use dnscraft_testkit::{Hierarchy, default_servers};

fn clock_at(secs: u64) -> Arc<ManualClock> {
    Arc::new(ManualClock::new(
        SystemTime::UNIX_EPOCH + Duration::from_secs(secs),
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

fn view(id: &str, is_default: bool, profile: &str, client_ids: &[&str]) -> ViewConfig {
    ViewConfig {
        id: ViewId::new(id).unwrap(),
        is_default,
        subnets: Vec::new(),
        client_ids: client_ids
            .iter()
            .map(|c| ClientId::new(c).unwrap())
            .collect(),
        records: Vec::new(),
        profile: ProfileId::new(profile).unwrap(),
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

fn ctx(name: &str, qtype: RecordType, client_id: Option<&str>) -> RequestContext {
    RequestContext {
        source_ip: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
        protocol: DnsProtocol::Udp53,
        listener_id: ListenerId::new("udp-53").unwrap(),
        client_id: client_id.map(|c| ClientId::new(c).unwrap()),
        query: Query {
            name: Name::from_ascii(name).unwrap(),
            qtype,
            qclass: Class::IN,
        },
        flags: ClientFlags::default(),
        test_query: false,
    }
}

fn policy_cfg(profiles: Vec<ProfileConfig>, views: Vec<ViewConfig>) -> PolicyConfig {
    PolicyConfig {
        default_rebind: true,
        ptr_prefixes: Vec::new(),
        local_nxdomain_suffixes: Vec::new(),
        rebind_check_forward_zones: Vec::new(),
        views,
        profiles,
    }
}

async fn engine_blocking(clock: Arc<ManualClock>) -> (Hierarchy, PolicyEngine) {
    let h = Hierarchy::start().await.unwrap();
    let resolver = Arc::new(Resolver::new(config_for(&h)).await.unwrap());
    let eng = PolicyEngine::new(
        policy_cfg(
            vec![profile("default")],
            vec![view("default", true, "default", &[])],
        ),
        blocking_filter(),
        resolver,
        Arc::new(NoClients),
        clock,
    )
    .unwrap();
    (h, eng)
}

#[tokio::test]
async fn pause_global_five_minutes_expires_on_manual_clock() {
    let clock = clock_at(1_000);
    let (_h, eng) = engine_blocking(Arc::clone(&clock)).await;

    let blocked = eng
        .handle(ctx("ads.example", RecordType::A, None))
        .await
        .unwrap();
    assert_eq!(blocked.message.rcode(), Rcode::NXDOMAIN);
    assert!(blocked.record.steps.contains(&DecisionStep::FilterBlocked));

    eng.pause(
        PauseScope::Global,
        PauseUntil::For(Duration::from_secs(5 * 60)),
    )
    .unwrap();

    let passed = eng
        .handle(ctx("ads.example", RecordType::A, None))
        .await
        .unwrap();
    assert!(
        !passed.record.steps.contains(&DecisionStep::FilterBlocked),
        "paused filter must Pass"
    );
    assert_ne!(passed.record.answer_source, AnswerOrigin::Filter);

    clock.advance(Duration::from_secs(5 * 60));
    let again = eng
        .handle(ctx("ads.example", RecordType::A, None))
        .await
        .unwrap();
    assert!(
        again.record.steps.contains(&DecisionStep::FilterBlocked),
        "after expiry filter blocks again"
    );
}

#[tokio::test]
async fn pause_per_profile_only_affects_that_profile() {
    let clock = clock_at(1_000);
    let h = Hierarchy::start().await.unwrap();
    let resolver = Arc::new(Resolver::new(config_for(&h)).await.unwrap());
    let eng = PolicyEngine::new(
        policy_cfg(
            vec![profile("kids"), profile("default")],
            vec![
                view("kids", false, "kids", &["kids"]),
                view("default", true, "default", &[]),
            ],
        ),
        blocking_filter(),
        resolver,
        Arc::new(NoClients),
        clock,
    )
    .unwrap();

    eng.pause(
        PauseScope::Profile(ProfileId::new("kids").unwrap()),
        PauseUntil::UntilResumed,
    )
    .unwrap();

    let kids = eng
        .handle(ctx("ads.example", RecordType::A, Some("kids")))
        .await
        .unwrap();
    assert!(
        !kids.record.steps.contains(&DecisionStep::FilterBlocked),
        "kids profile paused"
    );

    let other = eng
        .handle(ctx("ads.example", RecordType::A, None))
        .await
        .unwrap();
    assert!(
        other.record.steps.contains(&DecisionStep::FilterBlocked),
        "default profile still filters"
    );
}

#[tokio::test]
async fn pause_until_resumed_stays_until_resume() {
    let clock = clock_at(1_000);
    let (_h, eng) = engine_blocking(Arc::clone(&clock)).await;

    eng.pause(PauseScope::Global, PauseUntil::UntilResumed)
        .unwrap();
    clock.advance(Duration::from_secs(3600));
    let still = eng
        .handle(ctx("ads.example", RecordType::A, None))
        .await
        .unwrap();
    assert!(!still.record.steps.contains(&DecisionStep::FilterBlocked));

    eng.resume(PauseScope::Global).unwrap();
    let after = eng
        .handle(ctx("ads.example", RecordType::A, None))
        .await
        .unwrap();
    assert!(after.record.steps.contains(&DecisionStep::FilterBlocked));
}

#[tokio::test]
async fn pause_skips_filter_but_keeps_canary_rebind_aaaa() {
    let clock = clock_at(1_000);
    let mut specs = default_servers().unwrap();
    for spec in &mut specs {
        if spec.zone.origin().to_string() == "example.test." {
            spec.zone = spec
                .zone
                .clone()
                .with_a("private.example.test.", Ipv4Addr::new(10, 0, 0, 1))
                .unwrap()
                .with_aaaa(
                    "www.example.test.",
                    Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
                )
                .unwrap();
        }
    }
    let h = Hierarchy::start_with(specs).await.unwrap();
    let resolver = Arc::new(Resolver::new(config_for(&h)).await.unwrap());

    let mut set = FilterSetConfig::new(sid("default"), "default");
    set.custom_rules = "||ads.example^\n||private.example.test^\n".to_owned();
    set.block_mode = BlockMode::NxDomain;
    let filter = Arc::new(FilterEngine::from_snapshot(
        SnapshotBuilder::new(Arc::new(EmptyBodies) as Arc<dyn ListBodies>)
            .build(&FilterConfig {
                lists: Vec::new(),
                sets: vec![set],
                ..FilterConfig::default()
            })
            .unwrap(),
    ));

    let mut p = profile("default");
    p.firefox_canary = true;
    p.suppress_aaaa = true;
    p.rebind = Some(true);

    let eng = PolicyEngine::new(
        policy_cfg(vec![p], vec![view("default", true, "default", &[])]),
        filter,
        resolver,
        Arc::new(NoClients),
        clock,
    )
    .unwrap();

    eng.pause(PauseScope::Global, PauseUntil::UntilResumed)
        .unwrap();

    // Canary still runs.
    let canary = eng
        .handle(ctx("use-application-dns.net", RecordType::A, None))
        .await
        .unwrap();
    assert_eq!(canary.message.rcode(), Rcode::NXDOMAIN);
    assert_eq!(canary.record.answer_source, AnswerOrigin::Bypass);

    // Blocked name would have been NXDOMAIN from filter; pause lets it resolve
    // (or NXDOMAIN from auth) — must not be FilterBlocked.
    let ads = eng
        .handle(ctx("ads.example", RecordType::A, None))
        .await
        .unwrap();
    assert!(!ads.record.steps.contains(&DecisionStep::FilterBlocked));

    // Rebind still strips private addresses.
    let rebind = eng
        .handle(ctx("private.example.test.", RecordType::A, None))
        .await
        .unwrap();
    assert!(
        rebind
            .record
            .steps
            .contains(&DecisionStep::RebindStripped { count: 1 }),
        "rebind must still run while paused"
    );
    assert!(rebind.message.answers.is_empty());
    assert_eq!(rebind.message.authorities[0].rtype(), RecordType::SOA);

    // AAAA suppression still runs.
    let aaaa = eng
        .handle(ctx("www.example.test.", RecordType::AAAA, None))
        .await
        .unwrap();
    assert!(aaaa.record.steps.contains(&DecisionStep::AaaaSuppressed));
    assert!(aaaa.message.answers.is_empty());
}

#[tokio::test]
async fn pause_unknown_profile_errors() {
    let (_h, eng) = engine_blocking(clock_at(1_000)).await;
    let err = eng
        .pause(
            PauseScope::Profile(ProfileId::new("missing").unwrap()),
            PauseUntil::UntilResumed,
        )
        .unwrap_err();
    assert_eq!(err.code(), "policy.config.invalid");
}
