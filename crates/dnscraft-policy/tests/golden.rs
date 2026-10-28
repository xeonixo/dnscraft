//! Golden pipeline tests for SPEC-policy.md success criteria 2 / 3 / 3a (todo P12).
//!
//! Criterion 1 (selection) lives in `tests/select.rs`; criterion 4 (AD/EDE) in
//! `tests/ad_ede.rs`; criterion 5 (p50 bench) in `benches/pipeline.rs`.

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
    AnswerOrigin, ClientDirectory, ClientFlags, DecisionStep, DnsProtocol, ListenerId, NoClients,
    PolicyConfig, PolicyEngine, ProfileConfig, ProfileId, RebindSkipReason, RequestContext,
    SafeSearchConfig, ViewConfig, ViewId, ViewRecordConfig, YoutubeMode,
};
use dnscraft_proto::{Class, Name, RData, Rcode, RecordType};
use dnscraft_resolver::dnssec::TrustAnchors;
use dnscraft_resolver::{Query, Resolver, ResolverConfig};
use dnscraft_testkit::{Hierarchy, ServerSpec, default_servers};
use hickory_proto::rr::rdata::svcb::{IpHint, SvcParamKey, SvcParamValue};
use hickory_proto::rr::rdata::{A as HA, CNAME, HTTPS, SVCB};
use hickory_proto::rr::{Name as HName, RData as HRData, Record as HRecord};

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
        rebind: Some(true),
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

fn with_records(mut cfg: PolicyConfig, records: Vec<ViewRecordConfig>) -> PolicyConfig {
    cfg.records = records;
    cfg
}

fn policy_cfg(profile: ProfileConfig, views: Vec<ViewConfig>) -> PolicyConfig {
    PolicyConfig {
        client_ids: Vec::new(),
        records: Vec::new(),
        default_rebind: true,
        ptr_prefixes: Vec::new(),
        local_nxdomain_suffixes: vec![Arc::from("local"), Arc::from("lan"), Arc::from("internal")],
        rebind_check_forward_zones: Vec::new(),
        views,
        profiles: vec![profile],
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

fn root_queries(h: &Hierarchy) -> usize {
    h.server(".").unwrap().queries().len()
}

#[derive(Debug)]
struct MockDir {
    addresses: HashMap<Name, Arc<[IpAddr]>>,
}

impl ClientDirectory for MockDir {
    fn addresses(&self, fqdn: &Name) -> Option<Arc<[IpAddr]>> {
        self.addresses.get(fqdn).cloned()
    }

    fn reverse(&self, _ip: IpAddr) -> Option<Arc<str>> {
        None
    }

    fn local_domains(&self) -> Arc<[String]> {
        Arc::from(vec!["lan".to_owned()])
    }
}

fn specs_golden() -> Vec<ServerSpec> {
    let mut specs = default_servers().unwrap();
    for spec in &mut specs {
        if spec.zone.origin().to_string() == "example.test." {
            let cname = HRecord::from_rdata(
                HName::from_ascii("a.example.test.").unwrap(),
                300,
                HRData::CNAME(CNAME(HName::from_ascii("tracker.example.test.").unwrap())),
            );
            let cname2 = HRecord::from_rdata(
                HName::from_ascii("tracker.example.test.").unwrap(),
                300,
                HRData::CNAME(CNAME(HName::from_ascii("www.example.test.").unwrap())),
            );
            let https = HRecord::from_rdata(
                HName::from_ascii("hints.example.test.").unwrap(),
                300,
                HRData::HTTPS(HTTPS(SVCB::new(
                    1,
                    HName::from_ascii(".").unwrap(),
                    vec![(
                        SvcParamKey::Ipv4Hint,
                        SvcParamValue::Ipv4Hint(IpHint(vec![
                            HA::new(10, 0, 0, 1),
                            HA::new(192, 0, 2, 1),
                        ])),
                    )],
                ))),
            );
            spec.zone = spec
                .zone
                .clone()
                .with_a("private.example.test.", Ipv4Addr::new(10, 0, 0, 1))
                .unwrap()
                .with_a("www.example.test.", Ipv4Addr::new(192, 0, 2, 1))
                .unwrap()
                .with_aaaa(
                    "www.example.test.",
                    Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
                )
                .unwrap()
                .with_record(cname)
                .with_record(cname2)
                .with_record(https);
        }
    }
    specs
}

/// Criterion 2: view local + ClientDirectory answers never query the root.
#[tokio::test]
async fn golden_view_and_directory_never_hit_resolver() {
    let h = Hierarchy::start_with(specs_golden()).await.unwrap();
    let dir = Arc::new(MockDir {
        addresses: HashMap::from([(
            Name::from_ascii("phone.lan.").unwrap(),
            Arc::from([IpAddr::V4(Ipv4Addr::new(10, 0, 0, 42))] as [IpAddr; 1]),
        )]),
    });

    let resolver = Arc::new(Resolver::new(config_for(&h)).await.unwrap());
    let eng = PolicyEngine::new(
        with_records(
            policy_cfg(profile_base(), vec![default_view()]),
            vec![ViewRecordConfig {
                name: Name::from_ascii("nas.lan.").unwrap(),
                ttl: 60,
                rdata: RData::A(Ipv4Addr::new(10, 0, 0, 1)),
                overrides: Default::default(),
            }],
        ),
        empty_filter(),
        resolver,
        dir,
        clock(),
    )
    .unwrap();
    // Measure after resolver priming so we only count policy-driven traffic.
    let before = root_queries(&h);

    let view = eng.handle(ctx("nas.lan.", RecordType::A)).await.unwrap();
    assert_eq!(view.record.answer_source, AnswerOrigin::LocalView);
    assert_eq!(root_queries(&h), before);

    let client = eng.handle(ctx("phone.lan.", RecordType::A)).await.unwrap();
    assert_eq!(client.record.answer_source, AnswerOrigin::LocalClient);
    assert_eq!(root_queries(&h), before);
}

/// Criterion 2: blocked qname never hits the resolver.
#[tokio::test]
async fn golden_blocked_qname_never_hits_resolver() {
    let h = Hierarchy::start_with(specs_golden()).await.unwrap();
    let resolver = Arc::new(Resolver::new(config_for(&h)).await.unwrap());
    let eng = PolicyEngine::new(
        policy_cfg(profile_base(), vec![default_view()]),
        filter_with("||ads.example^\n"),
        resolver,
        Arc::new(NoClients),
        clock(),
    )
    .unwrap();
    let before = root_queries(&h);

    let ans = eng.handle(ctx("ads.example", RecordType::A)).await.unwrap();
    assert_eq!(ans.message.rcode(), Rcode::NXDOMAIN);
    assert!(ans.record.steps.contains(&DecisionStep::FilterBlocked));
    assert_eq!(root_queries(&h), before);
}

/// Criterion 2: CNAME chain uncloaking blocks a mid-chain name.
#[tokio::test]
async fn golden_cname_chain_block() {
    let h = Hierarchy::start_with(specs_golden()).await.unwrap();
    let resolver = Arc::new(Resolver::new(config_for(&h)).await.unwrap());
    let eng = PolicyEngine::new(
        policy_cfg(profile_base(), vec![default_view()]),
        filter_with("||tracker.example.test^\n"),
        resolver,
        Arc::new(NoClients),
        clock(),
    )
    .unwrap();

    let ans = eng
        .handle(ctx("a.example.test.", RecordType::A))
        .await
        .unwrap();
    assert!(ans.record.steps.contains(&DecisionStep::AnswerChainBlocked));
    assert_eq!(ans.record.answer_source, AnswerOrigin::Filter);
}

/// Criterion 3: rebind strips private A and HTTPS ipv4hint; exception skips.
#[tokio::test]
async fn golden_rebind_matrix_a_and_svcb_hints() {
    let h = Hierarchy::start_with(specs_golden()).await.unwrap();
    let resolver = Arc::new(Resolver::new(config_for(&h)).await.unwrap());
    let eng = PolicyEngine::new(
        policy_cfg(profile_base(), vec![default_view()]),
        empty_filter(),
        resolver,
        Arc::new(NoClients),
        clock(),
    )
    .unwrap();

    let nodata = eng
        .handle(ctx("private.example.test.", RecordType::A))
        .await
        .unwrap();
    assert!(nodata.message.answers.is_empty());
    assert_eq!(nodata.message.authorities[0].rtype(), RecordType::SOA);
    assert!(
        nodata
            .record
            .steps
            .contains(&DecisionStep::RebindStripped { count: 1 })
    );

    let hints = eng
        .handle(ctx("hints.example.test.", RecordType::HTTPS))
        .await
        .unwrap();
    assert!(
        hints
            .record
            .steps
            .contains(&DecisionStep::RebindStripped { count: 1 })
    );

    // Additional-section stripping is covered by `rebind::unit::run_strips_private_additional_and_clears_ad`
    // because the recursive resolver clears `additionals` before policy sees the answer.

    let mut profile = profile_base();
    profile.rebind_exceptions = vec![Arc::from("*.example.test")];
    let resolver2 = Arc::new(Resolver::new(config_for(&h)).await.unwrap());
    let eng_ex = PolicyEngine::new(
        policy_cfg(profile, vec![default_view()]),
        empty_filter(),
        resolver2,
        Arc::new(NoClients),
        clock(),
    )
    .unwrap();
    let allowed = eng_ex
        .handle(ctx("private.example.test.", RecordType::A))
        .await
        .unwrap();
    assert!(allowed.record.steps.contains(&DecisionStep::RebindSkipped {
        reason: RebindSkipReason::Exception,
    }));
    assert!(!allowed.message.answers.is_empty());
}

/// Criterion 3a: a blocked service is not bypassed by SafeSearch.
#[tokio::test]
async fn golden_blocked_service_not_bypassed_by_safesearch() {
    let h = Hierarchy::start_with(specs_golden()).await.unwrap();
    let resolver = Arc::new(Resolver::new(config_for(&h)).await.unwrap());
    let mut profile = profile_base();
    profile.safesearch = SafeSearchConfig {
        enabled: true,
        providers: vec![Arc::from("youtube")],
        youtube_mode: YoutubeMode::Strict,
    };
    let eng = PolicyEngine::new(
        policy_cfg(profile, vec![default_view()]),
        filter_with("||www.youtube.com^\n"),
        resolver,
        Arc::new(NoClients),
        clock(),
    )
    .unwrap();

    let ans = eng
        .handle(ctx("www.youtube.com.", RecordType::A))
        .await
        .unwrap();
    assert_eq!(ans.message.rcode(), Rcode::NXDOMAIN);
    assert!(ans.record.steps.contains(&DecisionStep::FilterBlocked));
    assert!(
        !ans.record
            .steps
            .iter()
            .any(|s| matches!(s, DecisionStep::SafeSearchRewrite { .. })),
        "SafeSearch must not run after an original-name block: {:?}",
        ans.record.steps
    );
    assert!(
        !ans.message.answers.iter().any(|r| matches!(
            &r.rdata,
            RData::CNAME(n) if n.to_string().contains("restrict.youtube.com")
        )),
        "must never answer restrict.youtube.com for a blocked youtube host"
    );
}

/// Criterion 3a: unknown name under a local-looking domain reaches the resolver;
/// special-use unknown never does.
#[tokio::test]
async fn golden_local_domain_fallthrough_vs_special_use_nxdomain() {
    let h = Hierarchy::start_with(specs_golden()).await.unwrap();
    let resolver = Arc::new(Resolver::new(config_for(&h)).await.unwrap());
    let eng = PolicyEngine::new(
        policy_cfg(profile_base(), vec![default_view()]),
        empty_filter(),
        resolver,
        Arc::new(NoClients),
        clock(),
    )
    .unwrap();
    let before = root_queries(&h);

    // Special-use: NXDOMAIN, no additional root traffic.
    let special = eng
        .handle(ctx("unknown.lan.", RecordType::A))
        .await
        .unwrap();
    assert_eq!(special.message.rcode(), Rcode::NXDOMAIN);
    assert!(
        special
            .record
            .steps
            .contains(&DecisionStep::SpecialUseNxdomain)
    );
    assert_eq!(root_queries(&h), before);

    // Public-looking name under example.test reaches recursion (root queried).
    let public = eng
        .handle(ctx("www.example.test.", RecordType::A))
        .await
        .unwrap();
    assert_eq!(public.message.rcode(), Rcode::NOERROR);
    assert!(root_queries(&h) > before);
}

/// RFC 8375: `home.arpa` is the resolver's local zone, so policy falls
/// through step 2 and the resolver answers NXDOMAIN without root traffic.
#[tokio::test]
async fn golden_home_arpa_falls_through_to_resolver_local_zone() {
    let h = Hierarchy::start_with(specs_golden()).await.unwrap();
    let resolver = Arc::new(Resolver::new(config_for(&h)).await.unwrap());
    let eng = PolicyEngine::new(
        policy_cfg(profile_base(), vec![default_view()]),
        empty_filter(),
        resolver,
        Arc::new(NoClients),
        clock(),
    )
    .unwrap();
    let before = root_queries(&h);

    let answer = eng
        .handle(ctx("unknown.home.arpa.", RecordType::A))
        .await
        .unwrap();
    assert_eq!(answer.message.rcode(), Rcode::NXDOMAIN);
    assert_eq!(answer.record.answer_source, AnswerOrigin::Resolver);
    assert!(
        !answer
            .record
            .steps
            .contains(&DecisionStep::SpecialUseNxdomain),
        "home.arpa must be answered by the resolver local zone"
    );
    assert_eq!(root_queries(&h), before, "home.arpa leaked to the root");
}
