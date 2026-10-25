//! Steps 8–9: CNAME uncloaking and answer-IP filtering.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use dnscraft_filtering::{
    BlockMode, FilterConfig, FilterEngine, FilterSetConfig, ListBodies, ListConfig, ListId,
    ListSourceSpec, ManualClock, SetId, SnapshotBuilder,
};
use dnscraft_policy::{
    AnswerOrigin, ClientFlags, DecisionStep, DnsProtocol, ListenerId, NoClients, PolicyConfig,
    PolicyEngine, ProfileConfig, ProfileId, RequestContext, SafeSearchConfig, ViewConfig, ViewId,
};
use dnscraft_proto::{Class, Name, Rcode, RecordType};
use dnscraft_resolver::dnssec::TrustAnchors;
use dnscraft_resolver::{DnssecStatus, Query, Resolver, ResolverConfig};
use dnscraft_testkit::{ChildVariant, Hierarchy, ServerSpec, default_servers};
use hickory_proto::rr::rdata::CNAME;
use hickory_proto::rr::{Name as HName, RData as HRData, Record as HRecord};

fn clock() -> Arc<ManualClock> {
    Arc::new(ManualClock::new(
        SystemTime::UNIX_EPOCH + Duration::from_secs(1_000),
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

fn filter_engine(lists: &[(&str, &str)], custom: &str) -> Arc<FilterEngine> {
    let bodies = Arc::new(MapBodies {
        map: lists
            .iter()
            .map(|(id, body)| (lid(id), Arc::from(*body)))
            .collect(),
    });
    let mut set = FilterSetConfig::new(sid("default"), "default");
    set.lists = lists.iter().map(|(id, _)| lid(id)).collect();
    set.custom_rules = custom.to_owned();
    set.block_mode = BlockMode::NxDomain;
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

fn policy_cfg() -> PolicyConfig {
    PolicyConfig {
        default_rebind: true,
        ptr_prefixes: Vec::new(),
        local_nxdomain_suffixes: Vec::new(),
        rebind_check_forward_zones: Vec::new(),
        views: vec![default_view()],
        profiles: vec![profile()],
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

fn cname_rec(owner: &str, target: &str) -> HRecord {
    HRecord::from_rdata(
        HName::from_ascii(owner).unwrap(),
        300,
        HRData::CNAME(CNAME(HName::from_ascii(target).unwrap())),
    )
}

fn specs_with_cname_chain() -> Vec<ServerSpec> {
    let mut specs = default_servers().unwrap();
    for spec in &mut specs {
        if spec.zone.origin().to_string() == "example.test." {
            // a.example.test → tracker.example.test → www.example.test (A 192.0.2.1)
            spec.zone = spec
                .zone
                .clone()
                .with_record(cname_rec("a.example.test.", "tracker.example.test."))
                .with_record(cname_rec("tracker.example.test.", "www.example.test."));
        }
    }
    specs
}

async fn engine_on(h: &Hierarchy, filter: Arc<FilterEngine>, trust: TrustAnchors) -> PolicyEngine {
    let mut rcfg = config_for(h);
    rcfg.trust_anchors = trust;
    let resolver = Arc::new(Resolver::new(rcfg).await.unwrap());
    PolicyEngine::new(policy_cfg(), filter, resolver, Arc::new(NoClients), clock()).unwrap()
}

#[tokio::test]
async fn answer_side_cname_chain_blocked_target() {
    let h = Hierarchy::start_with(specs_with_cname_chain())
        .await
        .unwrap();
    let filter = filter_engine(&[("ads", "||tracker.example.test^\n")], "");
    let engine = engine_on(&h, filter, TrustAnchors::empty()).await;

    let ans = engine
        .handle(ctx("a.example.test.", RecordType::A))
        .await
        .unwrap();
    assert_eq!(ans.message.rcode(), Rcode::NXDOMAIN);
    assert_eq!(ans.record.answer_source, AnswerOrigin::Filter);
    assert!(ans.record.steps.contains(&DecisionStep::AnswerChainBlocked));
    assert!(
        ans.record
            .steps
            .iter()
            .any(|s| matches!(s, DecisionStep::Resolve { .. }))
    );
    assert!(!ans.message.header.ad);
    assert_eq!(ans.ede.as_ref().map(|e| e.code), Some(15));
}

#[tokio::test]
async fn answer_side_important_allow_on_qname_overrides_chain_block() {
    let h = Hierarchy::start_with(specs_with_cname_chain())
        .await
        .unwrap();
    let filter = filter_engine(
        &[("ads", "||tracker.example.test^\n")],
        "@@||a.example.test^$important\n",
    );
    let engine = engine_on(&h, filter, TrustAnchors::empty()).await;

    let ans = engine
        .handle(ctx("a.example.test.", RecordType::A))
        .await
        .unwrap();
    assert_eq!(ans.record.answer_source, AnswerOrigin::Resolver);
    assert!(
        !ans.record
            .steps
            .iter()
            .any(|s| matches!(s, DecisionStep::AnswerChainBlocked))
    );
    assert_eq!(ans.message.rcode(), Rcode::NOERROR);
    assert!(!ans.message.answers.is_empty());
}

#[tokio::test]
async fn answer_side_ip_rule_blocks_address() {
    let h = Hierarchy::start().await.unwrap();
    // www.example.test → 192.0.2.1
    let filter = filter_engine(&[("ads", "||192.0.2.1^\n")], "");
    let engine = engine_on(&h, filter, TrustAnchors::empty()).await;

    let ans = engine
        .handle(ctx("www.example.test.", RecordType::A))
        .await
        .unwrap();
    assert_eq!(ans.message.rcode(), Rcode::NXDOMAIN);
    assert_eq!(ans.record.answer_source, AnswerOrigin::Filter);
    assert!(ans.record.steps.contains(&DecisionStep::AnswerIpBlocked));
    assert_eq!(ans.ede.as_ref().map(|e| e.code), Some(15));
}

#[tokio::test]
async fn answer_side_unblocked_secure_keeps_ad() {
    let h = Hierarchy::start_signed(&[ChildVariant::Secure])
        .await
        .unwrap();
    let anchor = h.trust_anchor().unwrap();
    let bytes = {
        use hickory_proto::serialize::binary::BinEncodable;
        anchor.ds.to_bytes().unwrap()
    };
    let ds = dnscraft_proto::Record {
        name: Name::root(),
        class: Class::IN,
        ttl: 3600,
        rdata: dnscraft_proto::RData::decode(&bytes, RecordType::DS, 0, bytes.len()).unwrap(),
    };
    let trust = TrustAnchors::from_records(&[ds]).unwrap();
    let filter = filter_engine(&[], "");
    let engine = engine_on(&h, filter, trust).await;

    let ans = engine
        .handle(ctx("www.secure.test.", RecordType::A))
        .await
        .unwrap();
    assert_eq!(ans.record.answer_source, AnswerOrigin::Resolver);
    assert_eq!(ans.record.dnssec, Some(DnssecStatus::Secure));
    assert!(ans.message.header.ad);
    assert!(!ans.record.steps.iter().any(|s| matches!(
        s,
        DecisionStep::AnswerChainBlocked | DecisionStep::AnswerIpBlocked
    )));
}
