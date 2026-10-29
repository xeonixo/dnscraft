//! Policy engine: resolver passthrough, ANY, AD, forward-zone allow-list.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, SystemTime};

use dnscraft_filtering::{
    FilterConfig, FilterEngine, FilterSetConfig, ListBodies, ListId, ManualClock, SetId,
    SnapshotBuilder,
};
use dnscraft_policy::{
    AnswerOrigin, ClientFlags, DecisionStep, DnsProtocol, ListenerId, NoClients, PolicyConfig,
    PolicyEngine, ProfileConfig, ProfileId, RequestContext, SafeSearchConfig, SelectionCause,
    ViewConfig, ViewId,
};
use dnscraft_proto::{Class, Name, RData, Rcode, Record, RecordType};
use dnscraft_resolver::dnssec::TrustAnchors;
use dnscraft_resolver::{
    DnssecStatus, ForwardZone, ForwardZoneId, Query, Resolver, ResolverConfig,
};
use dnscraft_testkit::{ChildVariant, DnssecScenario, Hierarchy};
use hickory_proto::serialize::binary::BinEncodable;
use tokio::net::UdpSocket;

fn clock() -> Arc<ManualClock> {
    Arc::new(ManualClock::new(
        SystemTime::UNIX_EPOCH + Duration::from_secs(1_000),
    ))
}

fn anchors_of(h: &Hierarchy) -> TrustAnchors {
    let anchor = h.trust_anchor().unwrap();
    let bytes = anchor.ds.to_bytes().unwrap();
    let ds = Record {
        name: Name::root(),
        class: Class::IN,
        ttl: 3600,
        rdata: RData::decode(&bytes, RecordType::DS, 0, bytes.len()).unwrap(),
    };
    TrustAnchors::from_records(&[ds]).unwrap()
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
    let mut sc = FilterSetConfig::new(set("default"), "default");
    sc.lists = Vec::new();
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

fn profile(id: &str, forward_zones: Option<Vec<ForwardZoneId>>) -> ProfileConfig {
    ProfileConfig {
        id: ProfileId::new(id).unwrap(),
        filter_set: set("default"),
        suppress_aaaa: false,
        firefox_canary: false,
        icloud_private_relay: false,
        rebind: None,
        rebind_exceptions: Vec::new(),
        forward_zones,
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

fn policy_config(profiles: Vec<ProfileConfig>) -> PolicyConfig {
    PolicyConfig {
        client_ids: Vec::new(),
        records: Vec::new(),
        default_rebind: true,
        ptr_prefixes: Vec::new(),
        local_nxdomain_suffixes: Vec::new(),
        rebind_check_forward_zones: Vec::new(),
        views: vec![default_view(profiles[0].id.as_str())],
        profiles,
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

struct CountingTarget {
    addr: SocketAddr,
    hits: Arc<AtomicUsize>,
    task: tokio::task::JoinHandle<()>,
}

impl CountingTarget {
    async fn spawn() -> Self {
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let addr = socket.local_addr().unwrap();
        let hits = Arc::new(AtomicUsize::new(0));
        let hits_task = Arc::clone(&hits);
        let task = tokio::spawn(async move {
            let mut buf = vec![0u8; 2048];
            loop {
                let Ok((len, peer)) = socket.recv_from(&mut buf).await else {
                    return;
                };
                hits_task.fetch_add(1, Ordering::Relaxed);
                let Ok(req) = dnscraft_proto::Message::decode(&buf[..len]) else {
                    continue;
                };
                let mut resp = dnscraft_proto::Message::response_to(&req);
                resp.header.ra = true;
                if let Some(q) = req.questions.first() {
                    resp.answers.push(dnscraft_proto::Record::new(
                        q.name.clone(),
                        Class::IN,
                        60,
                        RData::A(Ipv4Addr::new(192, 0, 2, 55)),
                    ));
                }
                let Ok(out) = resp.encode() else {
                    continue;
                };
                let _ = socket.send_to(&out, peer).await;
            }
        });
        Self { addr, hits, task }
    }

    fn hits(&self) -> usize {
        self.hits.load(Ordering::Relaxed)
    }
}

impl Drop for CountingTarget {
    fn drop(&mut self) {
        self.task.abort();
    }
}

#[tokio::test]
async fn engine_resolves_a_through_testkit() {
    let h = Hierarchy::start().await.unwrap();
    let resolver = Arc::new(Resolver::new(config_for(&h)).await.unwrap());
    let engine = PolicyEngine::new(
        policy_config(vec![profile("default", None)]),
        empty_filter(),
        resolver,
        Arc::new(NoClients),
        clock(),
    )
    .unwrap();

    let answer = engine
        .handle(ctx("www.example.test.", RecordType::A, false))
        .await
        .unwrap();

    assert_eq!(answer.message.header.id, 0, "listener owns the message id");
    assert_eq!(answer.message.rcode(), Rcode::NOERROR);
    assert!(!answer.message.answers.is_empty());
    assert!(answer.loggable);
    assert_eq!(answer.record.answer_source, AnswerOrigin::Resolver);
    assert_eq!(answer.record.view_id.as_str(), "default");
    assert_eq!(answer.record.selection, SelectionCause::Default);
    assert!(
        answer
            .record
            .steps
            .iter()
            .any(|s| matches!(s, DecisionStep::Selected { .. }))
    );
    assert!(
        answer
            .record
            .steps
            .iter()
            .any(|s| matches!(s, DecisionStep::Resolve { .. }))
    );
}

#[tokio::test]
async fn engine_forward_zones_allow_list_skips_disallowed_zone() {
    let h = Hierarchy::start().await.unwrap();
    let target = CountingTarget::spawn().await;
    let zone_id = ForwardZoneId::new("corp-internal").unwrap();
    let mut rcfg = config_for(&h);
    rcfg.forward_zones = vec![ForwardZone {
        id: zone_id.clone(),
        zone: Name::from_ascii("corp.internal.").unwrap(),
        targets: vec![target.addr],
        validate: false,
    }];
    let resolver = Arc::new(Resolver::new(rcfg).await.unwrap());
    assert_eq!(resolver.forward_zone_ids(), vec![zone_id.clone()]);

    // Profile allow-list is empty → name under the zone must recurse, not forward.
    let engine = PolicyEngine::new(
        policy_config(vec![profile("default", Some(Vec::new()))]),
        empty_filter(),
        resolver,
        Arc::new(NoClients),
        clock(),
    )
    .unwrap();

    h.server(".").unwrap().clear_queries();
    let _ = engine
        .handle(ctx("www.corp.internal.", RecordType::A, false))
        .await
        .unwrap();

    assert_eq!(
        target.hits(),
        0,
        "disallowed forward zone must not see the query"
    );
}

#[tokio::test]
async fn engine_any_never_reaches_resolver() {
    let h = Hierarchy::start().await.unwrap();
    let resolver = Arc::new(Resolver::new(config_for(&h)).await.unwrap());
    let engine = PolicyEngine::new(
        policy_config(vec![profile("default", None)]),
        empty_filter(),
        resolver,
        Arc::new(NoClients),
        clock(),
    )
    .unwrap();

    h.server(".").unwrap().clear_queries();
    let before = h.server(".").unwrap().queries().len();
    let answer = engine
        .handle(ctx("www.example.test.", RecordType::ANY, false))
        .await
        .unwrap();
    let after = h.server(".").unwrap().queries().len();

    assert_eq!(after, before, "ANY must not query the hierarchy");
    assert_eq!(answer.record.answer_source, AnswerOrigin::SynthAny);
    assert_eq!(answer.message.rcode(), Rcode::NOERROR);
    assert!(!answer.message.header.ad);
    assert!(
        answer
            .record
            .steps
            .iter()
            .any(|s| matches!(s, DecisionStep::AnySynth))
    );
}

#[tokio::test]
async fn engine_test_query_not_loggable() {
    let h = Hierarchy::start().await.unwrap();
    let resolver = Arc::new(Resolver::new(config_for(&h)).await.unwrap());
    let engine = PolicyEngine::new(
        policy_config(vec![profile("default", None)]),
        empty_filter(),
        resolver,
        Arc::new(NoClients),
        clock(),
    )
    .unwrap();

    let answer = engine
        .handle(ctx("www.example.test.", RecordType::A, true))
        .await
        .unwrap();
    assert!(!answer.loggable);
}

#[tokio::test]
async fn engine_secure_keeps_ad_insecure_clears() {
    let h = Hierarchy::start_signed(&[ChildVariant::Secure, ChildVariant::Insecure])
        .await
        .unwrap();
    let mut rcfg = config_for(&h);
    rcfg.trust_anchors = anchors_of(&h);
    let resolver = Arc::new(Resolver::new(rcfg).await.unwrap());
    let engine = PolicyEngine::new(
        policy_config(vec![profile("default", None)]),
        empty_filter(),
        resolver,
        Arc::new(NoClients),
        clock(),
    )
    .unwrap();

    let secure = engine
        .handle(ctx("www.secure.test.", RecordType::A, false))
        .await
        .unwrap();
    assert_eq!(secure.record.dnssec, Some(DnssecStatus::Secure));
    assert!(secure.message.header.ad);

    let insecure = engine
        .handle(ctx("www.insecure.test.", RecordType::A, false))
        .await
        .unwrap();
    assert_eq!(insecure.record.dnssec, Some(DnssecStatus::Insecure));
    assert!(!insecure.message.header.ad);
}

async fn signed_engine(variants: &[ChildVariant]) -> (Hierarchy, PolicyEngine) {
    let h = Hierarchy::start_scenario(&DnssecScenario::new(variants))
        .await
        .unwrap();
    let mut rcfg = config_for(&h);
    rcfg.trust_anchors = anchors_of(&h);
    let resolver = Arc::new(Resolver::new(rcfg).await.unwrap());
    let engine = PolicyEngine::new(
        policy_config(vec![profile("default", None)]),
        empty_filter(),
        resolver,
        Arc::new(NoClients),
        clock(),
    )
    .unwrap();
    (h, engine)
}

#[tokio::test]
async fn engine_forwards_client_cd_to_resolver() {
    let (_h, engine) = signed_engine(&[ChildVariant::BogusSig]).await;

    let strict = engine
        .handle(ctx("www.bogus-sig.test.", RecordType::A, false))
        .await
        .unwrap();
    assert_eq!(strict.message.rcode(), Rcode::SERVFAIL);
    assert_eq!(strict.record.dnssec, Some(DnssecStatus::Bogus));

    let mut cd = ctx("www.bogus-sig.test.", RecordType::A, false);
    cd.flags.checking_disabled = true;
    let answer = engine.handle(cd).await.unwrap();
    assert_eq!(answer.message.rcode(), Rcode::NOERROR);
    assert!(!answer.message.answers.is_empty());
    assert!(!answer.message.header.ad);
}

#[tokio::test]
async fn engine_forwards_client_do_to_resolver() {
    let (_h, engine) = signed_engine(&[ChildVariant::Secure]).await;
    let has_rrsig = |a: &dnscraft_policy::PolicyAnswer| {
        a.message
            .answers
            .iter()
            .any(|r| r.rtype() == RecordType::RRSIG)
    };

    let plain = engine
        .handle(ctx("www.secure.test.", RecordType::A, false))
        .await
        .unwrap();
    assert!(!plain.message.answers.is_empty());
    assert!(!has_rrsig(&plain), "DO clear must strip RRSIG");

    let mut with_do = ctx("www.secure.test.", RecordType::A, false);
    with_do.flags.dnssec_ok = true;
    let signed = engine.handle(with_do).await.unwrap();
    assert!(has_rrsig(&signed), "DO set must keep RRSIG");
}

#[tokio::test]
async fn engine_forward_loop_yields_servfail_with_cause() {
    let h = Hierarchy::start().await.unwrap();
    let target = CountingTarget::spawn().await;
    let mut rcfg = config_for(&h);
    rcfg.forward_zones = vec![ForwardZone {
        id: ForwardZoneId::new("corp-internal").unwrap(),
        zone: Name::from_ascii("corp.internal.").unwrap(),
        targets: vec![target.addr],
        validate: false,
    }];
    let resolver = Arc::new(Resolver::new(rcfg).await.unwrap());
    let engine = PolicyEngine::new(
        policy_config(vec![profile("default", None)]),
        empty_filter(),
        resolver,
        Arc::new(NoClients),
        clock(),
    )
    .unwrap();

    // The query comes from the forward target's own IP (it forwarded back).
    let mut looped = ctx("www.corp.internal.", RecordType::A, false);
    looped.source_ip = target.addr.ip();
    let answer = engine.handle(looped).await.unwrap();

    assert_eq!(answer.message.rcode(), Rcode::SERVFAIL);
    assert_eq!(answer.record.answer_source, AnswerOrigin::ResolveError);
    assert!(answer.record.steps.iter().any(|s| matches!(
        s,
        DecisionStep::ResolveFailed {
            cause_code: Some("resolver.forward_loop")
        }
    )));
    assert_eq!(target.hits(), 0, "a loop must not be forwarded");
}

#[tokio::test]
async fn client_id_registry_lists_configured_ids_and_follows_apply() {
    let h = Hierarchy::start().await.unwrap();
    let resolver = Arc::new(Resolver::new(config_for(&h)).await.unwrap());
    let mut cfg = policy_config(vec![profile("default", None)]);
    cfg.client_ids.push(
        dnscraft_policy::ClientId::new("iphone-k7q2x9")
            .unwrap()
            .into(),
    );
    let engine =
        PolicyEngine::new(cfg, empty_filter(), resolver, Arc::new(NoClients), clock()).unwrap();

    let registered = engine.registered_client_ids();
    assert_eq!(registered.len(), 1);
    assert_eq!(registered[0].as_str(), "iphone-k7q2x9");

    engine
        .apply_config(policy_config(vec![profile("default", None)]))
        .await
        .unwrap();
    assert!(engine.registered_client_ids().is_empty());
}

#[tokio::test]
async fn client_id_entries_accept_strings_and_objects_and_expose_labels() {
    let h = Hierarchy::start().await.unwrap();
    let resolver = Arc::new(Resolver::new(config_for(&h)).await.unwrap());
    let mut cfg = policy_config(vec![profile("default", None)]);
    cfg.client_ids = serde_json::from_value(serde_json::json!([
        "phone",
        { "id": "tablet", "label": "  Anna's iPad  " },
        { "id": "laptop", "device": "lan-laptop-1" }
    ]))
    .unwrap();
    let engine =
        PolicyEngine::new(cfg, empty_filter(), resolver, Arc::new(NoClients), clock()).unwrap();

    let registered = engine.registered_client_ids();
    let ids: Vec<&str> = registered.iter().map(|id| id.as_str()).collect();
    assert_eq!(ids, ["phone", "tablet", "laptop"]);
    let labels = engine.client_id_labels();
    assert_eq!(labels.len(), 1);
    assert_eq!(labels.get("tablet").map(|l| &**l), Some("Anna's iPad"));
}

#[tokio::test]
async fn decision_record_carries_the_label_of_a_registered_client_id() {
    let h = Hierarchy::start().await.unwrap();
    let resolver = Arc::new(Resolver::new(config_for(&h)).await.unwrap());
    let mut cfg = policy_config(vec![profile("default", None)]);
    cfg.client_ids = serde_json::from_value(serde_json::json!([
        { "id": "tablet", "label": "Anna's iPad" },
        "phone"
    ]))
    .unwrap();
    let engine =
        PolicyEngine::new(cfg, empty_filter(), resolver, Arc::new(NoClients), clock()).unwrap();

    // ANY is answered without an upstream query.
    let cases = [
        (Some("tablet"), Some("Anna's iPad")),
        (Some("phone"), None),
        (Some("ghost"), None),
        (None, None),
    ];
    for (client, expected) in cases {
        let mut query = ctx("example.com.", RecordType::ANY, true);
        query.client_id = client.map(|id| dnscraft_policy::ClientId::new(id).unwrap());
        let answer = engine.handle(query).await.unwrap();
        assert_eq!(
            answer.record.client_label.as_deref(),
            expected,
            "{client:?}"
        );
    }
}

#[tokio::test]
async fn decision_record_carries_the_device_of_a_registered_client_id() {
    let h = Hierarchy::start().await.unwrap();
    let resolver = Arc::new(Resolver::new(config_for(&h)).await.unwrap());
    let mut cfg = policy_config(vec![profile("default", None)]);
    cfg.client_ids = serde_json::from_value(serde_json::json!([
        { "id": "tablet", "label": "Anna's iPad", "device": "lan-tablet-1" },
        { "id": "phone" }
    ]))
    .unwrap();
    let engine =
        PolicyEngine::new(cfg, empty_filter(), resolver, Arc::new(NoClients), clock()).unwrap();

    // ANY is answered without an upstream query.
    let cases = [
        (Some("tablet"), Some("lan-tablet-1")),
        (Some("phone"), None),
        (Some("ghost"), None),
        (None, None),
    ];
    for (client, expected) in cases {
        let mut query = ctx("example.com.", RecordType::ANY, true);
        query.client_id = client.map(|id| dnscraft_policy::ClientId::new(id).unwrap());
        let answer = engine.handle(query).await.unwrap();
        assert_eq!(
            answer.record.client_device.as_deref(),
            expected,
            "{client:?}"
        );
    }
}

#[tokio::test]
async fn decision_record_reports_client_id_selection_cause() {
    let h = Hierarchy::start().await.unwrap();
    let resolver = Arc::new(Resolver::new(config_for(&h)).await.unwrap());
    let mut cfg = policy_config(vec![profile("default", None)]);
    cfg.client_ids = serde_json::from_value(serde_json::json!([
        { "id": "tablet", "view": "unterwegs" },
        "phone"
    ]))
    .unwrap();
    cfg.views.push(ViewConfig {
        id: ViewId::new("unterwegs").unwrap(),
        is_default: false,
        subnets: Vec::new(),
        nodes: Vec::new(),
        profile: ProfileId::new("default").unwrap(),
    });
    let engine =
        PolicyEngine::new(cfg, empty_filter(), resolver, Arc::new(NoClients), clock()).unwrap();

    // ANY is answered without an upstream query. The source matches no subnet.
    for (client, expected, view) in [
        (Some("tablet"), SelectionCause::ClientId, "unterwegs"),
        (Some("phone"), SelectionCause::Default, "default"),
        (None, SelectionCause::Default, "default"),
    ] {
        let mut query = ctx("example.com.", RecordType::ANY, true);
        query.client_id = client.map(|id| dnscraft_policy::ClientId::new(id).unwrap());
        let answer = engine.handle(query).await.unwrap();
        assert_eq!(answer.record.selection, expected, "{client:?}");
        assert_eq!(answer.record.view_id.as_str(), view, "{client:?}");
    }
}
