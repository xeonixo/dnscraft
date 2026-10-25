//! P13: SafeSearch evaluation (steps 5–6).

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
    ClientFlags, DecisionStep, DnsProtocol, ListenerId, NoClients, NotAppliedStep, PauseScope,
    PauseUntil, PolicyConfig, PolicyEngine, ProfileConfig, ProfileId, RequestContext,
    SafeSearchConfig, ScheduleConfig, ViewConfig, ViewId, YoutubeMode,
};
use dnscraft_proto::{Class, Name, RData, Rcode, RecordType};
use dnscraft_resolver::dnssec::TrustAnchors;
use dnscraft_resolver::{Query, Resolver, ResolverConfig};
use dnscraft_testkit::{Hierarchy, ServerSpec, Zone, default_servers};

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

fn filter_with(custom: &str) -> Arc<FilterEngine> {
    let mut set = FilterSetConfig::new(sid("default"), "default");
    set.custom_rules = custom.to_owned();
    set.block_mode = BlockMode::NxDomain;
    let mut evening = FilterSetConfig::new(sid("evening"), "evening");
    evening.block_mode = BlockMode::NxDomain;
    Arc::new(FilterEngine::from_snapshot(
        SnapshotBuilder::new(Arc::new(EmptyBodies) as Arc<dyn ListBodies>)
            .build(&FilterConfig {
                lists: Vec::new(),
                sets: vec![set, evening],
                ..FilterConfig::default()
            })
            .unwrap(),
    ))
}

fn empty_filter() -> Arc<FilterEngine> {
    filter_with("")
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

fn ctx(name: &str, qtype: RecordType) -> RequestContext {
    RequestContext {
        source_ip: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
        protocol: DnsProtocol::Udp53,
        listener_id: ListenerId::new("udp-53").unwrap(),
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

/// Hierarchy with safe-host zones so SafeSearch CNAME follow can resolve.
fn safesearch_specs() -> Vec<ServerSpec> {
    let lo = Ipv4Addr::LOCALHOST;
    let mut specs = default_servers().unwrap();
    // Extend root with delegations.
    for spec in &mut specs {
        if spec.zone.origin().to_string() == "." {
            spec.zone = spec
                .zone
                .clone()
                .with_ns("google.com.", "ns1.google.com.")
                .unwrap()
                .with_a("ns1.google.com.", lo)
                .unwrap()
                .with_ns("google.co.uk.", "ns1.google.co.uk.")
                .unwrap()
                .with_a("ns1.google.co.uk.", lo)
                .unwrap()
                .with_ns("youtube.com.", "ns1.youtube.com.")
                .unwrap()
                .with_a("ns1.youtube.com.", lo)
                .unwrap()
                .with_ns("googleapis.com.", "ns1.googleapis.com.")
                .unwrap()
                .with_a("ns1.googleapis.com.", lo)
                .unwrap()
                .with_ns("bing.com.", "ns1.bing.com.")
                .unwrap()
                .with_a("ns1.bing.com.", lo)
                .unwrap()
                .with_ns("duckduckgo.com.", "ns1.duckduckgo.com.")
                .unwrap()
                .with_a("ns1.duckduckgo.com.", lo)
                .unwrap();
        }
    }
    let google = Zone::new("google.com.")
        .unwrap()
        .with_soa("ns1.google.com.", "hostmaster.google.com.")
        .unwrap()
        .with_ns("google.com.", "ns1.google.com.")
        .unwrap()
        .with_a("ns1.google.com.", lo)
        .unwrap()
        .with_a("forcesafesearch.google.com.", Ipv4Addr::new(192, 0, 2, 100))
        .unwrap()
        .with_a("www.google.com.", Ipv4Addr::new(192, 0, 2, 101))
        .unwrap();
    let google_uk = Zone::new("google.co.uk.")
        .unwrap()
        .with_soa("ns1.google.co.uk.", "hostmaster.google.co.uk.")
        .unwrap()
        .with_ns("google.co.uk.", "ns1.google.co.uk.")
        .unwrap()
        .with_a("ns1.google.co.uk.", lo)
        .unwrap()
        .with_a("www.google.co.uk.", Ipv4Addr::new(192, 0, 2, 102))
        .unwrap();
    let youtube = Zone::new("youtube.com.")
        .unwrap()
        .with_soa("ns1.youtube.com.", "hostmaster.youtube.com.")
        .unwrap()
        .with_ns("youtube.com.", "ns1.youtube.com.")
        .unwrap()
        .with_a("ns1.youtube.com.", lo)
        .unwrap()
        .with_a("restrict.youtube.com.", Ipv4Addr::new(192, 0, 2, 110))
        .unwrap()
        .with_a(
            "restrictmoderate.youtube.com.",
            Ipv4Addr::new(192, 0, 2, 111),
        )
        .unwrap()
        .with_a("www.youtube.com.", Ipv4Addr::new(192, 0, 2, 112))
        .unwrap();
    let googleapis = Zone::new("googleapis.com.")
        .unwrap()
        .with_soa("ns1.googleapis.com.", "hostmaster.googleapis.com.")
        .unwrap()
        .with_ns("googleapis.com.", "ns1.googleapis.com.")
        .unwrap()
        .with_a("ns1.googleapis.com.", lo)
        .unwrap();
    let bing = Zone::new("bing.com.")
        .unwrap()
        .with_soa("ns1.bing.com.", "hostmaster.bing.com.")
        .unwrap()
        .with_ns("bing.com.", "ns1.bing.com.")
        .unwrap()
        .with_a("ns1.bing.com.", lo)
        .unwrap()
        .with_a("strict.bing.com.", Ipv4Addr::new(192, 0, 2, 120))
        .unwrap()
        .with_a("www.bing.com.", Ipv4Addr::new(192, 0, 2, 121))
        .unwrap();
    let ddg = Zone::new("duckduckgo.com.")
        .unwrap()
        .with_soa("ns1.duckduckgo.com.", "hostmaster.duckduckgo.com.")
        .unwrap()
        .with_ns("duckduckgo.com.", "ns1.duckduckgo.com.")
        .unwrap()
        .with_a("ns1.duckduckgo.com.", lo)
        .unwrap()
        .with_a("safe.duckduckgo.com.", Ipv4Addr::new(192, 0, 2, 130))
        .unwrap()
        .with_a("duckduckgo.com.", Ipv4Addr::new(192, 0, 2, 131))
        .unwrap();
    specs.push(ServerSpec::new("ns1.google.com.", google).unwrap());
    specs.push(ServerSpec::new("ns1.google.co.uk.", google_uk).unwrap());
    specs.push(ServerSpec::new("ns1.youtube.com.", youtube).unwrap());
    specs.push(ServerSpec::new("ns1.googleapis.com.", googleapis).unwrap());
    specs.push(ServerSpec::new("ns1.bing.com.", bing).unwrap());
    specs.push(ServerSpec::new("ns1.duckduckgo.com.", ddg).unwrap());
    specs
}

async fn engine_with(
    profile: ProfileConfig,
    filter: Arc<FilterEngine>,
    clock: Arc<ManualClock>,
) -> (Hierarchy, PolicyEngine) {
    let h = Hierarchy::start_with(safesearch_specs()).await.unwrap();
    let resolver = Arc::new(Resolver::new(config_for(&h)).await.unwrap());
    let cfg = PolicyConfig {
        default_rebind: true,
        ptr_prefixes: Vec::new(),
        local_nxdomain_suffixes: Vec::new(),
        rebind_check_forward_zones: Vec::new(),
        views: vec![default_view()],
        profiles: vec![profile],
    };
    let eng = PolicyEngine::new(cfg, filter, resolver, Arc::new(NoClients), clock).unwrap();
    (h, eng)
}

fn ss(providers: &[&str], mode: YoutubeMode) -> SafeSearchConfig {
    SafeSearchConfig {
        enabled: true,
        providers: providers.iter().map(|p| Arc::<str>::from(*p)).collect(),
        youtube_mode: mode,
    }
}

fn cname_target(ans: &dnscraft_policy::PolicyAnswer) -> String {
    match &ans.message.answers[0].rdata {
        RData::CNAME(n) => n.to_string().trim_end_matches('.').to_owned(),
        other => panic!("expected CNAME, got {other:?}"),
    }
}

fn has_rewrite(ans: &dnscraft_policy::PolicyAnswer, provider: &str, target: &str) -> bool {
    ans.record.steps.iter().any(|s| match s {
        DecisionStep::SafeSearchRewrite {
            provider: p,
            target: t,
        } => p.as_ref() == provider && t.as_ref() == target,
        _ => false,
    })
}

#[tokio::test]
async fn each_provider_rewrites_and_country_domain() {
    let mut profile = profile_base();
    profile.safesearch = ss(
        &["google", "bing", "youtube", "duckduckgo"],
        YoutubeMode::Strict,
    );
    let (_h, eng) = engine_with(profile, empty_filter(), clock_at(1_000)).await;
    assert!(eng.status().safesearch_applied);
    assert!(!eng.status().schedules_applied);

    let cases = [
        (
            "www.google.com.",
            "google",
            "forcesafesearch.google.com",
            192,
            0,
            2,
            100,
        ),
        (
            "www.google.co.uk.",
            "google",
            "forcesafesearch.google.com",
            192,
            0,
            2,
            100,
        ),
        (
            "www.youtube.com.",
            "youtube",
            "restrict.youtube.com",
            192,
            0,
            2,
            110,
        ),
        ("www.bing.com.", "bing", "strict.bing.com", 192, 0, 2, 120),
        (
            "duckduckgo.com.",
            "duckduckgo",
            "safe.duckduckgo.com",
            192,
            0,
            2,
            130,
        ),
    ];
    for (qname, provider, target, a, b, c, d) in cases {
        let ans = eng.handle(ctx(qname, RecordType::A)).await.unwrap();
        assert!(
            has_rewrite(&ans, provider, target),
            "{qname}: {:?}",
            ans.record.steps
        );
        assert_eq!(cname_target(&ans), target, "{qname}");
        assert!(
            ans.message
                .answers
                .iter()
                .any(|r| r.rdata == RData::A(Ipv4Addr::new(a, b, c, d))),
            "{qname} answers={:?}",
            ans.message.answers
        );
        assert!(!ans.message.header.ad, "{qname}");
        assert!(ans.ede.is_none(), "{qname}");
    }
}

#[tokio::test]
async fn youtube_moderate_vs_strict() {
    let mut strict = profile_base();
    strict.safesearch = ss(&["youtube"], YoutubeMode::Strict);
    let (_h, eng) = engine_with(strict, empty_filter(), clock_at(1_000)).await;
    let ans = eng
        .handle(ctx("m.youtube.com.", RecordType::A))
        .await
        .unwrap();
    assert!(has_rewrite(&ans, "youtube", "restrict.youtube.com"));
    assert_eq!(cname_target(&ans), "restrict.youtube.com");

    let mut moderate = profile_base();
    moderate.safesearch = ss(&["youtube"], YoutubeMode::Moderate);
    let (_h, eng) = engine_with(moderate, empty_filter(), clock_at(1_000)).await;
    let ans = eng
        .handle(ctx("www.youtube.com.", RecordType::A))
        .await
        .unwrap();
    assert!(has_rewrite(&ans, "youtube", "restrictmoderate.youtube.com"));
    assert_eq!(cname_target(&ans), "restrictmoderate.youtube.com");
}

#[tokio::test]
async fn provider_or_safesearch_disabled_passthrough() {
    // SafeSearch enabled but google not in providers → no rewrite.
    let mut profile = profile_base();
    profile.safesearch = ss(&["bing"], YoutubeMode::Strict);
    let (_h, eng) = engine_with(profile, empty_filter(), clock_at(1_000)).await;
    let ans = eng
        .handle(ctx("www.google.com.", RecordType::A))
        .await
        .unwrap();
    assert!(
        !ans.record
            .steps
            .iter()
            .any(|s| matches!(s, DecisionStep::SafeSearchRewrite { .. }))
    );
    // Resolved original (not CNAME to forcesafesearch).
    assert!(
        ans.message
            .answers
            .iter()
            .any(|r| r.rdata == RData::A(Ipv4Addr::new(192, 0, 2, 101)))
    );

    // SafeSearch disabled entirely.
    let (_h, eng) = engine_with(profile_base(), empty_filter(), clock_at(1_000)).await;
    let ans = eng
        .handle(ctx("www.google.com.", RecordType::A))
        .await
        .unwrap();
    assert!(
        !ans.record
            .steps
            .iter()
            .any(|s| matches!(s, DecisionStep::SafeSearchRewrite { .. }))
    );
}

#[tokio::test]
async fn safe_host_blocked_in_step_6() {
    let mut profile = profile_base();
    profile.safesearch = ss(&["google"], YoutubeMode::Strict);
    let filter = filter_with("||forcesafesearch.google.com^\n");
    let (_h, eng) = engine_with(profile, filter, clock_at(1_000)).await;
    let ans = eng
        .handle(ctx("www.google.com.", RecordType::A))
        .await
        .unwrap();
    assert!(has_rewrite(&ans, "google", "forcesafesearch.google.com"));
    assert!(ans.record.steps.contains(&DecisionStep::FilterBlocked));
    assert_eq!(ans.message.rcode(), Rcode::NXDOMAIN);
    assert_eq!(ans.ede.as_ref().map(|e| e.code), Some(15));
}

#[tokio::test]
async fn original_name_blocked_wins_over_safesearch() {
    let mut profile = profile_base();
    profile.safesearch = ss(&["youtube"], YoutubeMode::Strict);
    let filter = filter_with("||www.youtube.com^\n");
    let (_h, eng) = engine_with(profile, filter, clock_at(1_000)).await;
    let ans = eng
        .handle(ctx("www.youtube.com.", RecordType::A))
        .await
        .unwrap();
    assert!(ans.record.steps.contains(&DecisionStep::FilterBlocked));
    assert!(
        !ans.record
            .steps
            .iter()
            .any(|s| matches!(s, DecisionStep::SafeSearchRewrite { .. })),
        "blocked original must not reach SafeSearch: {:?}",
        ans.record.steps
    );
    assert_eq!(ans.message.rcode(), Rcode::NXDOMAIN);
    assert!(!ans.message.answers.iter().any(|r| matches!(
        &r.rdata,
        RData::CNAME(n) if n.to_string().contains("restrict.youtube.com")
    )));
}

#[tokio::test]
async fn mx_qtype_passthrough() {
    let mut profile = profile_base();
    profile.safesearch = ss(&["google"], YoutubeMode::Strict);
    let (_h, eng) = engine_with(profile, empty_filter(), clock_at(1_000)).await;
    let ans = eng
        .handle(ctx("www.google.com.", RecordType::MX))
        .await
        .unwrap();
    assert!(
        !ans.record
            .steps
            .iter()
            .any(|s| matches!(s, DecisionStep::SafeSearchRewrite { .. }))
    );
}

#[tokio::test]
async fn pause_keeps_safesearch_running() {
    let mut profile = profile_base();
    profile.safesearch = ss(&["google"], YoutubeMode::Strict);
    // Safe host would be blocked if step 6 ran.
    let filter = filter_with("||forcesafesearch.google.com^\n");
    let (_h, eng) = engine_with(profile, filter, clock_at(1_000)).await;
    eng.pause(PauseScope::Global, PauseUntil::UntilResumed)
        .unwrap();

    let ans = eng
        .handle(ctx("www.google.com.", RecordType::A))
        .await
        .unwrap();
    assert!(
        ans.record
            .steps
            .iter()
            .any(|s| matches!(s, DecisionStep::ProtectionPaused { .. }))
    );
    // SafeSearch still rewrites; step 6 skipped while paused → resolve succeeds.
    assert!(has_rewrite(&ans, "google", "forcesafesearch.google.com"));
    assert!(!ans.record.steps.contains(&DecisionStep::FilterBlocked));
    assert_eq!(cname_target(&ans), "forcesafesearch.google.com");
}

#[tokio::test]
async fn schedules_still_not_applied_breadcrumb() {
    let mut profile = profile_base();
    profile.schedules = vec![ScheduleConfig {
        id: Arc::from("evening"),
        filter_set: sid("evening"),
        start: Duration::from_secs(18 * 3600),
        end: Duration::from_secs(22 * 3600),
    }];
    let (_h, eng) = engine_with(profile, empty_filter(), clock_at(1_000)).await;
    assert!(!eng.status().schedules_applied);
    let ans = eng
        .handle(ctx("www.example.test.", RecordType::A))
        .await
        .unwrap();
    assert!(ans.record.steps.contains(&DecisionStep::NotApplied {
        step: NotAppliedStep::Schedules,
    }));
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
    let filter = empty_filter();
    let err = dnscraft_policy::PolicySnapshot::build(
        cfg,
        &filter.snapshot().set_ids().cloned().collect::<Vec<_>>(),
        &[],
    )
    .unwrap_err();
    assert_eq!(err.code(), "policy.config.unknown_filter_set");
}
