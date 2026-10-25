//! Step 4: filter qname block / rewrite synthesis.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use dnscraft_filtering::{
    BlockMode, FilterConfig, FilterEngine, FilterSetConfig, ListBodies, ListConfig, ListId,
    ListSourceSpec, ManualClock, SetId, SnapshotBuilder, TempAllow,
};
use dnscraft_policy::{
    AnswerOrigin, ClientFlags, DecisionStep, DnsProtocol, ListenerId, NoClients, PolicyConfig,
    PolicyEngine, ProfileConfig, ProfileId, RequestContext, SafeSearchConfig, ViewConfig, ViewId,
};
use dnscraft_proto::{Class, Name, RData, Rcode, RecordType};
use dnscraft_resolver::dnssec::TrustAnchors;
use dnscraft_resolver::{Query, Resolver, ResolverConfig};
use dnscraft_testkit::Hierarchy;

fn clock_at(secs: u64) -> Arc<ManualClock> {
    Arc::new(ManualClock::new(
        SystemTime::UNIX_EPOCH + Duration::from_secs(secs),
    ))
}

#[derive(Debug, Default)]
struct MapBodies {
    map: HashMap<ListId, Arc<str>>,
}

impl ListBodies for MapBodies {
    fn body(&self, id: &ListId) -> Option<Arc<str>> {
        self.map.get(id).cloned()
    }
}

fn sid(s: &str) -> SetId {
    SetId::new(s).unwrap()
}
fn lid(s: &str) -> ListId {
    ListId::new(s).unwrap()
}

fn filter_engine(
    lists: &[(&str, &str)],
    custom: &str,
    block_mode: BlockMode,
    paused_until: Option<SystemTime>,
) -> Arc<FilterEngine> {
    let bodies = Arc::new(MapBodies {
        map: lists
            .iter()
            .map(|(id, body)| (lid(id), Arc::from(*body)))
            .collect(),
    });
    let mut set = FilterSetConfig::new(sid("default"), "default");
    set.lists = lists.iter().map(|(id, _)| lid(id)).collect();
    set.custom_rules = custom.to_owned();
    set.block_mode = block_mode;
    set.paused_until = paused_until;
    let cfg = FilterConfig {
        lists: lists
            .iter()
            .map(|(id, _)| ListConfig {
                id: lid(id),
                name: (*id).to_owned(),
                source: ListSourceSpec::Url(format!("https://example.invalid/{id}.txt")),
                enabled: true,
            })
            .collect(),
        sets: vec![set],
        ..FilterConfig::default()
    };
    Arc::new(FilterEngine::from_snapshot(
        SnapshotBuilder::new(bodies).build(&cfg).unwrap(),
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

fn root_query_count(h: &Hierarchy) -> usize {
    h.server(".").unwrap().queries().len()
}

async fn engine_with(
    filter: Arc<FilterEngine>,
    clock: Arc<ManualClock>,
) -> (Hierarchy, PolicyEngine) {
    let h = Hierarchy::start().await.unwrap();
    let resolver = Arc::new(Resolver::new(config_for(&h)).await.unwrap());
    let cfg = PolicyConfig {
        default_rebind: true,
        ptr_prefixes: Vec::new(),
        local_nxdomain_suffixes: Vec::new(),
        rebind_check_forward_zones: Vec::new(),
        views: vec![default_view()],
        profiles: vec![profile()],
    };
    let engine = PolicyEngine::new(cfg, filter, resolver, Arc::new(NoClients), clock).unwrap();
    (h, engine)
}

#[tokio::test]
async fn filter_each_block_mode_and_zero_resolver_traffic() {
    let modes = [
        (
            BlockMode::Refused,
            Rcode::REFUSED,
            Some(15u16),
            false,
            false,
        ),
        (BlockMode::NxDomain, Rcode::NXDOMAIN, Some(15), true, false),
        (BlockMode::NullIp, Rcode::NOERROR, Some(4), false, true),
        (
            BlockMode::CustomIp {
                v4: Some(Ipv4Addr::new(192, 0, 2, 99)),
                v6: None,
            },
            Rcode::NOERROR,
            Some(4),
            false,
            true,
        ),
    ];

    for (mode, rcode, ede_code, expect_soa, expect_answer) in modes {
        let filter = filter_engine(&[("ads", "||ads.example^\n")], "", mode, None);
        let (h, engine) = engine_with(filter, clock_at(1_000)).await;
        let before = root_query_count(&h);
        let ans = engine
            .handle(ctx("ads.example", RecordType::A))
            .await
            .unwrap();
        assert_eq!(ans.message.rcode(), rcode, "{mode:?}");
        assert_eq!(ans.record.answer_source, AnswerOrigin::Filter, "{mode:?}");
        assert!(
            ans.record.steps.contains(&DecisionStep::FilterBlocked),
            "{mode:?}"
        );
        assert!(!ans.message.header.ad, "{mode:?}");
        assert_eq!(ans.ede.as_ref().map(|e| e.code), ede_code, "{mode:?}");
        if expect_soa {
            assert!(
                ans.message
                    .authorities
                    .iter()
                    .any(|r| r.rtype() == RecordType::SOA),
                "{mode:?}"
            );
        }
        if expect_answer {
            assert!(!ans.message.answers.is_empty(), "{mode:?}");
        }
        assert_eq!(root_query_count(&h), before, "{mode:?} must not resolve");
    }

    // CustomIp missing AAAA family → NODATA + EDE 4.
    let filter = filter_engine(
        &[("ads", "||ads.example^\n")],
        "",
        BlockMode::CustomIp {
            v4: Some(Ipv4Addr::new(192, 0, 2, 1)),
            v6: None,
        },
        None,
    );
    let (h, engine) = engine_with(filter, clock_at(1_000)).await;
    let before = root_query_count(&h);
    let aaaa = engine
        .handle(ctx("ads.example", RecordType::AAAA))
        .await
        .unwrap();
    assert_eq!(aaaa.message.rcode(), Rcode::NOERROR);
    assert!(aaaa.message.answers.is_empty());
    assert_eq!(aaaa.ede.as_ref().map(|e| e.code), Some(4));
    assert_eq!(root_query_count(&h), before);

    // NullIp other qtype → NODATA.
    let filter = filter_engine(&[("ads", "||ads.example^\n")], "", BlockMode::NullIp, None);
    let (h, engine) = engine_with(filter, clock_at(1_000)).await;
    let before = root_query_count(&h);
    let txt = engine
        .handle(ctx("ads.example", RecordType::TXT))
        .await
        .unwrap();
    assert_eq!(txt.message.rcode(), Rcode::NOERROR);
    assert!(txt.message.answers.is_empty());
    assert_eq!(txt.ede.as_ref().map(|e| e.code), Some(4));
    assert_eq!(root_query_count(&h), before);
}

#[tokio::test]
async fn filter_rewrite_a_nxdomain_and_cname() {
    // Rewrite to A.
    let filter = filter_engine(
        &[],
        "||rw.example^$dnsrewrite=192.0.2.50\n",
        BlockMode::Refused,
        None,
    );
    let (h, engine) = engine_with(filter, clock_at(1_000)).await;
    let before = root_query_count(&h);
    let a = engine
        .handle(ctx("rw.example", RecordType::A))
        .await
        .unwrap();
    assert_eq!(a.message.rcode(), Rcode::NOERROR);
    assert_eq!(a.record.answer_source, AnswerOrigin::Filter);
    assert!(a.record.steps.contains(&DecisionStep::FilterRewrite));
    assert_eq!(
        a.message.answers[0].rdata,
        RData::A(Ipv4Addr::new(192, 0, 2, 50))
    );
    assert!(a.ede.is_none());
    assert_eq!(root_query_count(&h), before);

    // Rewrite to NXDOMAIN.
    let filter = filter_engine(
        &[],
        "||gone.example^$dnsrewrite=NXDOMAIN\n",
        BlockMode::Refused,
        None,
    );
    let (_h, engine) = engine_with(filter, clock_at(1_000)).await;
    let nx = engine
        .handle(ctx("gone.example", RecordType::A))
        .await
        .unwrap();
    assert_eq!(nx.message.rcode(), Rcode::NXDOMAIN);
    assert_eq!(nx.record.answer_source, AnswerOrigin::Filter);
    assert!(nx.ede.is_none());

    // CNAME rewrite: target resolved via testkit (public name under hierarchy).
    let filter = filter_engine(
        &[],
        "||alias.example^$dnsrewrite=NOERROR;CNAME;example.com\n",
        BlockMode::Refused,
        None,
    );
    let (h, engine) = engine_with(filter, clock_at(1_000)).await;
    let cname = engine
        .handle(ctx("alias.example", RecordType::A))
        .await
        .unwrap();
    assert_eq!(cname.record.answer_source, AnswerOrigin::Filter);
    assert!(cname.record.steps.contains(&DecisionStep::FilterRewrite));
    assert_eq!(cname.message.answers[0].rtype(), RecordType::CNAME);
    assert!(
        !cname.message.answers.is_empty(),
        "CNAME present; target follow may add more"
    );
    // Root saw the follow for example.com.
    assert!(root_query_count(&h) > 0);

    // CNAME rewrite to a blocked target → block synthesis, no (extra) resolve needed
    // after the target filter hit.
    let filter = filter_engine(
        &[("ads", "||tracker.example^\n")],
        "||via.example^$dnsrewrite=NOERROR;CNAME;tracker.example\n",
        BlockMode::NxDomain,
        None,
    );
    let (h, engine) = engine_with(filter, clock_at(1_000)).await;
    let before = root_query_count(&h);
    let blocked = engine
        .handle(ctx("via.example", RecordType::A))
        .await
        .unwrap();
    assert_eq!(blocked.message.rcode(), Rcode::NXDOMAIN);
    assert!(blocked.record.steps.contains(&DecisionStep::FilterBlocked));
    assert_eq!(blocked.ede.as_ref().map(|e| e.code), Some(15));
    assert_eq!(root_query_count(&h), before);
}

#[tokio::test]
async fn filter_temporary_allow_and_set_pause_pass_through() {
    let filter = filter_engine(&[("ads", "||ads.example^\n")], "", BlockMode::Refused, None);
    filter
        .allow_temporarily(
            &sid("default"),
            TempAllow {
                domain: "ads.example".parse().unwrap(),
                include_subdomains: false,
                until: SystemTime::UNIX_EPOCH + Duration::from_secs(5_000),
            },
        )
        .unwrap();
    let (h, engine) = engine_with(Arc::clone(&filter), clock_at(1_000)).await;
    let before = root_query_count(&h);
    let allowed = engine
        .handle(ctx("ads.example", RecordType::A))
        .await
        .unwrap();
    assert_ne!(allowed.record.answer_source, AnswerOrigin::Filter);
    assert!(
        !allowed
            .record
            .steps
            .iter()
            .any(|s| matches!(s, DecisionStep::FilterBlocked | DecisionStep::FilterRewrite))
    );
    assert!(root_query_count(&h) > before);

    // Set pause → Pass.
    let paused = filter_engine(
        &[("ads", "||ads.example^\n")],
        "",
        BlockMode::Refused,
        Some(SystemTime::UNIX_EPOCH + Duration::from_secs(9_000)),
    );
    let (h2, engine2) = engine_with(paused, clock_at(1_000)).await;
    let before2 = root_query_count(&h2);
    let pass = engine2
        .handle(ctx("ads.example", RecordType::A))
        .await
        .unwrap();
    assert_ne!(pass.record.answer_source, AnswerOrigin::Filter);
    assert!(root_query_count(&h2) > before2);
}

#[tokio::test]
async fn filter_custom_ip_aaaa_only_and_ipv6_null() {
    let filter = filter_engine(&[("ads", "||ads.example^\n")], "", BlockMode::NullIp, None);
    let (_h, engine) = engine_with(filter, clock_at(1_000)).await;
    let aaaa = engine
        .handle(ctx("ads.example", RecordType::AAAA))
        .await
        .unwrap();
    assert_eq!(aaaa.message.rcode(), Rcode::NOERROR);
    assert_eq!(
        aaaa.message.answers[0].rdata,
        RData::AAAA(Ipv6Addr::UNSPECIFIED)
    );
    assert_eq!(aaaa.ede.as_ref().map(|e| e.code), Some(4));
}
