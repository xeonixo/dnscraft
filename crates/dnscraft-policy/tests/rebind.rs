//! Step 10–11: rebind protection and AAAA suppression.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, SystemTime};

use dnscraft_filtering::{
    BlockMode, FilterConfig, FilterEngine, FilterSetConfig, ListBodies, ListId, ManualClock, SetId,
    SnapshotBuilder,
};
use dnscraft_policy::{
    AnswerOrigin, ClientFlags, DecisionStep, DnsProtocol, ListenerId, NoClients, PolicyConfig,
    PolicyEngine, ProfileConfig, ProfileId, RebindSkipReason, RequestContext, SafeSearchConfig,
    ViewConfig, ViewId, ViewRecordConfig,
};
use dnscraft_proto::{Class, Name, RData, Rcode, RecordType};
use dnscraft_resolver::dnssec::TrustAnchors;
use dnscraft_resolver::{ForwardZone, ForwardZoneId, Query, Resolver, ResolverConfig};
use dnscraft_testkit::{Hierarchy, ServerSpec, default_servers};
use tokio::net::UdpSocket;

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
    let sc = FilterSetConfig::new(sid("default"), "default");
    let cfg = FilterConfig {
        lists: Vec::new(),
        sets: vec![sc],
        ..FilterConfig::default()
    };
    Arc::new(FilterEngine::from_snapshot(
        SnapshotBuilder::new(Arc::new(EmptyBodies) as Arc<dyn ListBodies>)
            .build(&cfg)
            .unwrap(),
    ))
}

fn filter_with_custom(custom: &str) -> Arc<FilterEngine> {
    let mut set = FilterSetConfig::new(sid("default"), "default");
    set.custom_rules = custom.to_owned();
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
        nodes: Vec::new(),
        profile: ProfileId::new("default").unwrap(),
    }
}

fn policy_cfg(profile: ProfileConfig, check_zones: Vec<ForwardZoneId>) -> PolicyConfig {
    PolicyConfig {
        client_ids: Vec::new(),
        records: Vec::new(),
        default_rebind: true,
        ptr_prefixes: Vec::new(),
        local_nxdomain_suffixes: Vec::new(),
        rebind_check_forward_zones: check_zones,
        views: vec![default_view()],
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

fn specs_with_rebind_names() -> Vec<ServerSpec> {
    use hickory_proto::rr::rdata::svcb::{IpHint, SvcParamKey, SvcParamValue};
    use hickory_proto::rr::rdata::{A as HA, AAAA as HAAAA, CNAME, HTTPS, SVCB};
    use hickory_proto::rr::{Name as HName, RData as HRData, Record as HRecord};

    let mut specs = default_servers().unwrap();
    for spec in &mut specs {
        if spec.zone.origin().to_string() == "example.test." {
            let cname = HRecord::from_rdata(
                HName::from_ascii("alias.example.test.").unwrap(),
                300,
                HRData::CNAME(CNAME(HName::from_ascii("private.example.test.").unwrap())),
            );
            let https_mixed = HRecord::from_rdata(
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
            let https_all_private = HRecord::from_rdata(
                HName::from_ascii("privhints.example.test.").unwrap(),
                300,
                HRData::HTTPS(HTTPS(SVCB::new(
                    1,
                    HName::from_ascii(".").unwrap(),
                    vec![(
                        SvcParamKey::Ipv4Hint,
                        SvcParamValue::Ipv4Hint(IpHint(vec![
                            HA::new(10, 0, 0, 1),
                            HA::new(192, 168, 1, 1),
                        ])),
                    )],
                ))),
            );
            let https_v6 = HRecord::from_rdata(
                HName::from_ascii("v6hints.example.test.").unwrap(),
                300,
                HRData::HTTPS(HTTPS(SVCB::new(
                    1,
                    HName::from_ascii(".").unwrap(),
                    vec![(
                        SvcParamKey::Ipv6Hint,
                        SvcParamValue::Ipv6Hint(IpHint(vec![
                            HAAAA::new(0xfd12, 0, 0, 0, 0, 0, 0, 1),
                            HAAAA::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
                        ])),
                    )],
                ))),
            );
            spec.zone = spec
                .zone
                .clone()
                .with_a("private.example.test.", Ipv4Addr::new(10, 0, 0, 1))
                .unwrap()
                .with_a("mixed.example.test.", Ipv4Addr::new(10, 0, 0, 1))
                .unwrap()
                .with_a("mixed.example.test.", Ipv4Addr::new(192, 0, 2, 99))
                .unwrap()
                .with_a("cdn.example.test.", Ipv4Addr::new(10, 1, 2, 3))
                .unwrap()
                .with_aaaa(
                    "www.example.test.",
                    Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
                )
                .unwrap()
                .with_record(cname)
                .with_record(https_mixed)
                .with_record(https_all_private)
                .with_record(https_v6);
        }
    }
    specs
}

struct PrivateTarget {
    addr: SocketAddr,
    hits: Arc<AtomicUsize>,
    task: tokio::task::JoinHandle<()>,
}

impl PrivateTarget {
    async fn spawn(ip: Ipv4Addr) -> Self {
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
                        RData::A(ip),
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

impl Drop for PrivateTarget {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn engine_on(
    _h: &Hierarchy,
    policy: PolicyConfig,
    filter: Arc<FilterEngine>,
    resolver_cfg: ResolverConfig,
) -> PolicyEngine {
    let resolver = Arc::new(Resolver::new(resolver_cfg).await.unwrap());
    PolicyEngine::new(policy, filter, resolver, Arc::new(NoClients), clock()).unwrap()
}

#[tokio::test]
async fn rebind_strips_private_to_nodata_keeps_public_exception_passes() {
    let h = Hierarchy::start_with(specs_with_rebind_names())
        .await
        .unwrap();
    let engine = engine_on(
        &h,
        policy_cfg(profile_base(), Vec::new()),
        empty_filter(),
        config_for(&h),
    )
    .await;

    // Public name → only 10.0.0.1 → NODATA.
    let nodata = engine
        .handle(ctx("private.example.test.", RecordType::A))
        .await
        .unwrap();
    assert_eq!(nodata.message.rcode(), Rcode::NOERROR);
    assert!(nodata.message.answers.is_empty());
    assert_eq!(
        nodata.message.authorities.len(),
        1,
        "empty rebind NODATA needs SOA for negative caching"
    );
    assert_eq!(nodata.message.authorities[0].rtype(), RecordType::SOA);
    assert!(nodata.ede.is_none());
    assert!(!nodata.message.header.ad);
    assert!(
        nodata
            .record
            .steps
            .contains(&DecisionStep::RebindStripped { count: 1 })
    );
    assert_eq!(nodata.record.answer_source, AnswerOrigin::Resolver);

    // Mixed: private + public → keep public only.
    let mixed = engine
        .handle(ctx("mixed.example.test.", RecordType::A))
        .await
        .unwrap();
    assert_eq!(mixed.message.rcode(), Rcode::NOERROR);
    assert_eq!(mixed.message.answers.len(), 1);
    assert_eq!(
        mixed.message.answers[0].rdata,
        RData::A(Ipv4Addr::new(192, 0, 2, 99))
    );
    assert!(
        mixed
            .record
            .steps
            .contains(&DecisionStep::RebindStripped { count: 1 })
    );
    assert!(!mixed.message.header.ad);

    // Exception suffix: private address passes.
    let mut profile = profile_base();
    profile.rebind_exceptions = vec![Arc::from("*.example.test")];
    let engine_ex = engine_on(
        &h,
        policy_cfg(profile, Vec::new()),
        empty_filter(),
        config_for(&h),
    )
    .await;
    let allowed = engine_ex
        .handle(ctx("cdn.example.test.", RecordType::A))
        .await
        .unwrap();
    assert_eq!(allowed.message.rcode(), Rcode::NOERROR);
    assert_eq!(allowed.message.answers.len(), 1);
    assert_eq!(
        allowed.message.answers[0].rdata,
        RData::A(Ipv4Addr::new(10, 1, 2, 3))
    );
    assert!(allowed.record.steps.contains(&DecisionStep::RebindSkipped {
        reason: RebindSkipReason::Exception,
    }));
}

#[tokio::test]
async fn rebind_forward_zone_exempt_by_default_checked_when_listed() {
    let h = Hierarchy::start().await.unwrap();
    let target = PrivateTarget::spawn(Ipv4Addr::new(10, 50, 0, 1)).await;
    let zone_id = ForwardZoneId::new("lan-fwd").unwrap();
    let mut resolver_cfg = config_for(&h);
    resolver_cfg.forward_zones = vec![ForwardZone {
        id: zone_id.clone(),
        zone: Name::from_ascii("lan.").unwrap(),
        targets: vec![target.addr],
        validate: false,
    }];

    // Default: forward-zone answers exempt → private A kept.
    let engine_exempt = engine_on(
        &h,
        policy_cfg(profile_base(), Vec::new()),
        empty_filter(),
        resolver_cfg.clone(),
    )
    .await;
    let pass = engine_exempt
        .handle(ctx("nas.lan.", RecordType::A))
        .await
        .unwrap();
    assert_eq!(pass.message.rcode(), Rcode::NOERROR);
    assert_eq!(
        pass.message.answers[0].rdata,
        RData::A(Ipv4Addr::new(10, 50, 0, 1))
    );
    assert!(pass.record.forward_zone.as_ref() == Some(&zone_id));
    assert!(pass.record.steps.contains(&DecisionStep::RebindSkipped {
        reason: RebindSkipReason::ForwardZoneExempt,
    }));
    assert_eq!(target.hits(), 1);

    // Listed in rebind_check_forward_zones → stripped to NODATA.
    let engine_check = engine_on(
        &h,
        policy_cfg(profile_base(), vec![zone_id.clone()]),
        empty_filter(),
        resolver_cfg,
    )
    .await;
    let stripped = engine_check
        .handle(ctx("nas.lan.", RecordType::A))
        .await
        .unwrap();
    assert_eq!(stripped.message.rcode(), Rcode::NOERROR);
    assert!(stripped.message.answers.is_empty());
    assert_eq!(stripped.message.authorities[0].rtype(), RecordType::SOA);
    assert!(
        stripped
            .record
            .steps
            .contains(&DecisionStep::RebindStripped { count: 1 })
    );
    assert!(stripped.ede.is_none());
}

#[tokio::test]
async fn synthetic_private_passes_and_aaaa_suppression_is_qtype_only() {
    let h = Hierarchy::start_with(specs_with_rebind_names())
        .await
        .unwrap();

    // View record pointing at a private IP skips rebind (synthetic).
    let view_cfg = PolicyConfig {
        client_ids: Vec::new(),
        records: vec![ViewRecordConfig {
            name: Name::from_ascii("nas.lan.").unwrap(),
            ttl: 60,
            rdata: RData::A(Ipv4Addr::new(192, 168, 1, 10)),
            overrides: Default::default(),
        }],
        default_rebind: true,
        ptr_prefixes: Vec::new(),
        local_nxdomain_suffixes: Vec::new(),
        rebind_check_forward_zones: Vec::new(),
        views: vec![default_view()],
        profiles: vec![profile_base()],
    };
    let engine_view = engine_on(&h, view_cfg, empty_filter(), config_for(&h)).await;
    let view = engine_view
        .handle(ctx("nas.lan.", RecordType::A))
        .await
        .unwrap();
    assert_eq!(view.record.answer_source, AnswerOrigin::LocalView);
    assert_eq!(
        view.message.answers[0].rdata,
        RData::A(Ipv4Addr::new(192, 168, 1, 10))
    );
    assert!(!view.record.steps.iter().any(|s| matches!(
        s,
        DecisionStep::RebindStripped { .. } | DecisionStep::RebindSkipped { .. }
    )));

    // Filter rewrite to a private IP also skips rebind.
    let engine_rw = engine_on(
        &h,
        policy_cfg(profile_base(), Vec::new()),
        filter_with_custom("||rw.example^$dnsrewrite=192.168.0.5\n"),
        config_for(&h),
    )
    .await;
    let rw = engine_rw
        .handle(ctx("rw.example", RecordType::A))
        .await
        .unwrap();
    assert_eq!(rw.record.answer_source, AnswerOrigin::Filter);
    assert!(rw.record.steps.contains(&DecisionStep::FilterRewrite));
    assert_eq!(
        rw.message.answers[0].rdata,
        RData::A(Ipv4Addr::new(192, 168, 0, 5))
    );
    assert!(
        !rw.record
            .steps
            .iter()
            .any(|s| matches!(s, DecisionStep::RebindStripped { .. }))
    );

    // AAAA suppression: AAAA → NODATA; A and HTTPS unchanged.
    let mut profile = profile_base();
    profile.suppress_aaaa = true;
    let engine_aaaa = engine_on(
        &h,
        policy_cfg(profile, Vec::new()),
        empty_filter(),
        config_for(&h),
    )
    .await;

    let aaaa = engine_aaaa
        .handle(ctx("www.example.test.", RecordType::AAAA))
        .await
        .unwrap();
    assert_eq!(aaaa.message.rcode(), Rcode::NOERROR);
    assert!(aaaa.message.answers.is_empty());
    assert!(aaaa.record.steps.contains(&DecisionStep::AaaaSuppressed));
    assert!(aaaa.ede.is_none());
    assert!(!aaaa.message.header.ad);

    let a = engine_aaaa
        .handle(ctx("www.example.test.", RecordType::A))
        .await
        .unwrap();
    assert_eq!(a.message.rcode(), Rcode::NOERROR);
    assert!(
        !a.message.answers.is_empty(),
        "A answers must not be suppressed"
    );
    assert!(
        !a.record
            .steps
            .iter()
            .any(|s| matches!(s, DecisionStep::AaaaSuppressed))
    );

    // HTTPS/SVCB: no records in the hierarchy → NODATA from recursion, but
    // must not record AaaaSuppressed (qtype is not AAAA).
    let https = engine_aaaa
        .handle(ctx("www.example.test.", RecordType::HTTPS))
        .await
        .unwrap();
    assert!(
        !https
            .record
            .steps
            .iter()
            .any(|s| matches!(s, DecisionStep::AaaaSuppressed)),
        "HTTPS must not trigger AAAA suppression"
    );
    let svcb = engine_aaaa
        .handle(ctx("www.example.test.", RecordType::SVCB))
        .await
        .unwrap();
    assert!(
        !svcb
            .record
            .steps
            .iter()
            .any(|s| matches!(s, DecisionStep::AaaaSuppressed)),
        "SVCB must not trigger AAAA suppression"
    );
}

#[tokio::test]
async fn rebind_off_skips_and_records_disabled() {
    let h = Hierarchy::start_with(specs_with_rebind_names())
        .await
        .unwrap();
    let mut profile = profile_base();
    profile.rebind = Some(false);
    let engine = engine_on(
        &h,
        policy_cfg(profile, Vec::new()),
        empty_filter(),
        config_for(&h),
    )
    .await;
    let ans = engine
        .handle(ctx("private.example.test.", RecordType::A))
        .await
        .unwrap();
    assert_eq!(
        ans.message.answers[0].rdata,
        RData::A(Ipv4Addr::new(10, 0, 0, 1))
    );
    assert!(ans.record.steps.contains(&DecisionStep::RebindSkipped {
        reason: RebindSkipReason::Disabled,
    }));
}

#[tokio::test]
async fn rebind_cname_to_private_keeps_cname_chain() {
    let h = Hierarchy::start_with(specs_with_rebind_names())
        .await
        .unwrap();
    let engine = engine_on(
        &h,
        policy_cfg(profile_base(), Vec::new()),
        empty_filter(),
        config_for(&h),
    )
    .await;

    let ans = engine
        .handle(ctx("alias.example.test.", RecordType::A))
        .await
        .unwrap();
    assert_eq!(ans.message.rcode(), Rcode::NOERROR);
    assert!(
        ans.record
            .steps
            .contains(&DecisionStep::RebindStripped { count: 1 })
    );
    assert!(!ans.message.header.ad);
    assert!(ans.ede.is_none());
    assert_eq!(ans.message.answers.len(), 1);
    assert_eq!(ans.message.answers[0].rtype(), RecordType::CNAME);
    assert!(
        !ans.message
            .answers
            .iter()
            .any(|r| matches!(&r.rdata, RData::A(_) | RData::AAAA(_))),
        "private A must be stripped; CNAME kept"
    );
}

#[tokio::test]
async fn rebind_strips_https_hints_and_honours_exception() {
    use dnscraft_proto::SvcbData;

    let h = Hierarchy::start_with(specs_with_rebind_names())
        .await
        .unwrap();
    let engine = engine_on(
        &h,
        policy_cfg(profile_base(), Vec::new()),
        empty_filter(),
        config_for(&h),
    )
    .await;

    // Mixed ipv4hint: strip private, keep public (RFC 9460 §7.3).
    let mixed = engine
        .handle(ctx("hints.example.test.", RecordType::HTTPS))
        .await
        .unwrap();
    assert!(
        mixed
            .record
            .steps
            .contains(&DecisionStep::RebindStripped { count: 1 })
    );
    assert!(!mixed.message.header.ad);
    assert!(mixed.ede.is_none());
    let RData::HTTPS(SvcbData { params, .. }) = &mixed.message.answers[0].rdata else {
        panic!("expected HTTPS answer");
    };
    let hint = params.iter().find(|(k, _)| *k == 4).expect("ipv4hint kept");
    assert_eq!(hint.1.as_ref(), &Ipv4Addr::new(192, 0, 2, 1).octets()[..]);

    // All-private hint → param dropped, record kept.
    let all_priv = engine
        .handle(ctx("privhints.example.test.", RecordType::HTTPS))
        .await
        .unwrap();
    assert!(
        all_priv
            .record
            .steps
            .contains(&DecisionStep::RebindStripped { count: 2 })
    );
    let RData::HTTPS(SvcbData { params: p2, .. }) = &all_priv.message.answers[0].rdata else {
        panic!("expected HTTPS");
    };
    assert!(p2.iter().all(|(k, _)| *k != 4), "empty ipv4hint dropped");

    // ULA in ipv6hint stripped.
    let v6 = engine
        .handle(ctx("v6hints.example.test.", RecordType::HTTPS))
        .await
        .unwrap();
    assert!(
        v6.record
            .steps
            .contains(&DecisionStep::RebindStripped { count: 1 })
    );
    let RData::HTTPS(SvcbData { params: p6, .. }) = &v6.message.answers[0].rdata else {
        panic!("expected HTTPS");
    };
    let v6hint = p6.iter().find(|(k, _)| *k == 6).expect("ipv6hint kept");
    assert_eq!(
        v6hint.1.as_ref(),
        &Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1).octets()[..]
    );

    // Exception skips hint stripping entirely.
    let mut profile = profile_base();
    profile.rebind_exceptions = vec![Arc::from("*.example.test")];
    let engine_ex = engine_on(
        &h,
        policy_cfg(profile, Vec::new()),
        empty_filter(),
        config_for(&h),
    )
    .await;
    let allowed = engine_ex
        .handle(ctx("hints.example.test.", RecordType::HTTPS))
        .await
        .unwrap();
    assert!(allowed.record.steps.contains(&DecisionStep::RebindSkipped {
        reason: RebindSkipReason::Exception,
    }));
    let RData::HTTPS(SvcbData { params: raw, .. }) = &allowed.message.answers[0].rdata else {
        panic!("expected HTTPS");
    };
    let raw_hint = raw.iter().find(|(k, _)| *k == 4).unwrap();
    assert_eq!(raw_hint.1.len(), 8, "both addresses kept under exception");
}

#[tokio::test]
async fn aaaa_suppress_leaves_nxdomain_untouched() {
    let h = Hierarchy::start_with(specs_with_rebind_names())
        .await
        .unwrap();
    let mut profile = profile_base();
    profile.suppress_aaaa = true;
    let engine = engine_on(
        &h,
        policy_cfg(profile, Vec::new()),
        empty_filter(),
        config_for(&h),
    )
    .await;

    let nx = engine
        .handle(ctx("no-such.example.test.", RecordType::AAAA))
        .await
        .unwrap();
    assert_eq!(nx.message.rcode(), Rcode::NXDOMAIN);
    assert!(
        !nx.record
            .steps
            .iter()
            .any(|s| matches!(s, DecisionStep::AaaaSuppressed)),
        "AAAA suppression must not rewrite NXDOMAIN"
    );
}
