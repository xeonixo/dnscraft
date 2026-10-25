//! AD/EDE matrix coverage for Checkpoint B (Secure clear_ad, EDE drop, Bogus).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use dnscraft_filtering::{
    FilterConfig, FilterEngine, FilterSetConfig, ListBodies, ListId, ManualClock, SetId,
    SnapshotBuilder,
};
use dnscraft_policy::{
    ClientFlags, DecisionStep, DnsProtocol, ListenerId, NoClients, PolicyConfig, PolicyEngine,
    ProfileConfig, ProfileId, RequestContext, SafeSearchConfig, ViewConfig, ViewId,
};
use dnscraft_proto::{Class, Name, RData, Rcode, Record, RecordType};
use dnscraft_resolver::dnssec::TrustAnchors;
use dnscraft_resolver::{
    DnssecStatus, ManualClock as ResolverClock, Query, Resolver, ResolverConfig,
};
use dnscraft_testkit::{
    ChildVariant, DnssecScenario, Hierarchy, ServerSpec, SigningOptions, TrustAnchor, Zone,
    ZoneKey, default_servers, parse_name, sign_zone, unix_now,
};
use hickory_proto::serialize::binary::BinEncodable;

fn policy_clock() -> Arc<ManualClock> {
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

fn policy_cfg(profile: ProfileConfig) -> PolicyConfig {
    PolicyConfig {
        default_rebind: true,
        ptr_prefixes: Vec::new(),
        local_nxdomain_suffixes: Vec::new(),
        rebind_check_forward_zones: Vec::new(),
        views: vec![ViewConfig {
            id: ViewId::new("default").unwrap(),
            is_default: true,
            subnets: Vec::new(),
            client_ids: Vec::new(),
            records: Vec::new(),
            profile: ProfileId::new("default").unwrap(),
        }],
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

fn trust_from_anchor(anchor: &TrustAnchor) -> TrustAnchors {
    let bytes = anchor.ds.to_bytes().unwrap();
    let ds = Record {
        name: Name::root(),
        class: Class::IN,
        ttl: 3600,
        rdata: RData::decode(&bytes, RecordType::DS, 0, bytes.len()).unwrap(),
    };
    TrustAnchors::from_records(&[ds]).unwrap()
}

fn anchors_of(h: &Hierarchy) -> TrustAnchors {
    trust_from_anchor(h.trust_anchor().unwrap())
}

/// Signed hierarchy where `www.secure.test.` is `10.0.0.1` (private) so rebind
/// can strip a Secure answer and clear AD.
fn signed_private_secure() -> (Vec<ServerSpec>, TrustAnchor) {
    let lo = Ipv4Addr::LOCALHOST;
    let alg = Default::default();
    let now = unix_now();
    let options = SigningOptions::at(now);
    let root_key = ZoneKey::generate(alg).unwrap();
    let test_key = ZoneKey::generate(alg).unwrap();
    let child_key = ZoneKey::generate(alg).unwrap();
    let secure_name = parse_name("secure.test.").unwrap();

    let test = Zone::new("test.")
        .unwrap()
        .with_soa("ns1.test.", "hostmaster.test.")
        .unwrap()
        .with_ns("test.", "ns1.test.")
        .unwrap()
        .with_a("ns1.test.", lo)
        .unwrap()
        .with_ns("secure.test.", "ns1.secure.test.")
        .unwrap()
        .with_a("ns1.secure.test.", lo)
        .unwrap()
        .with_record(child_key.ds_record(&secure_name).unwrap());
    let test = sign_zone(test, &test_key, &options).unwrap();

    let secure = Zone::new("secure.test.")
        .unwrap()
        .with_soa("ns1.secure.test.", "hostmaster.secure.test.")
        .unwrap()
        .with_ns("secure.test.", "ns1.secure.test.")
        .unwrap()
        .with_a("ns1.secure.test.", lo)
        .unwrap()
        .with_a("www.secure.test.", Ipv4Addr::new(10, 0, 0, 1))
        .unwrap()
        .with_aaaa(
            "www.secure.test.",
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
        )
        .unwrap();
    let secure = sign_zone(secure, &child_key, &options).unwrap();

    let root = Zone::new(".")
        .unwrap()
        .with_soa("a.root-servers.net.", "hostmaster.root-servers.net.")
        .unwrap()
        .with_ns(".", "a.root-servers.net.")
        .unwrap()
        .with_a("a.root-servers.net.", lo)
        .unwrap()
        .with_ns("test.", "ns1.test.")
        .unwrap()
        .with_a("ns1.test.", lo)
        .unwrap()
        .with_record(test_key.ds_record(&parse_name("test.").unwrap()).unwrap());
    let root = sign_zone(root, &root_key, &options).unwrap();

    let anchor = TrustAnchor {
        owner: hickory_proto::rr::Name::root(),
        dnskey: root_key.dnskey().clone(),
        ds: root_key.ds(&hickory_proto::rr::Name::root()).unwrap(),
    };
    let specs = vec![
        ServerSpec::new("a.root-servers.net.", root).unwrap(),
        ServerSpec::new("ns1.test.", test).unwrap(),
        ServerSpec::new("ns1.secure.test.", secure).unwrap(),
    ];
    (specs, anchor)
}

async fn engine(
    _h: &Hierarchy,
    profile: ProfileConfig,
    trust: TrustAnchors,
    mut rcfg: ResolverConfig,
) -> PolicyEngine {
    rcfg.trust_anchors = trust;
    let resolver = Arc::new(Resolver::new(rcfg).await.unwrap());
    PolicyEngine::new(
        policy_cfg(profile),
        empty_filter(),
        resolver,
        Arc::new(NoClients),
        policy_clock(),
    )
    .unwrap()
}

#[tokio::test]
async fn secure_rebind_strip_clears_ad() {
    let (specs, anchor) = signed_private_secure();
    let h = Hierarchy::start_with(specs).await.unwrap();
    let eng = engine(
        &h,
        profile_base(),
        trust_from_anchor(&anchor),
        config_for(&h),
    )
    .await;

    let ans = eng
        .handle(ctx("www.secure.test.", RecordType::A))
        .await
        .unwrap();
    assert_eq!(ans.record.dnssec, Some(DnssecStatus::Secure));
    assert!(
        ans.record
            .steps
            .contains(&DecisionStep::RebindStripped { count: 1 })
    );
    assert!(
        !ans.message.header.ad,
        "rebind modification must clear AD on a Secure answer"
    );
    assert!(ans.message.answers.is_empty());
    assert_eq!(ans.message.authorities[0].rtype(), RecordType::SOA);
    assert_eq!(ans.message.rcode(), Rcode::NOERROR);
}

#[tokio::test]
async fn secure_aaaa_suppress_clears_ad() {
    let h = Hierarchy::start_signed(&[ChildVariant::Secure])
        .await
        .unwrap();

    // Baseline: Secure NODATA for AAAA has AD set.
    let baseline = engine(&h, profile_base(), anchors_of(&h), config_for(&h)).await;
    let bare = baseline
        .handle(ctx("www.secure.test.", RecordType::AAAA))
        .await
        .unwrap();
    assert_eq!(bare.record.dnssec, Some(DnssecStatus::Secure));
    assert!(bare.message.header.ad, "baseline Secure NODATA must set AD");
    assert_eq!(bare.message.rcode(), Rcode::NOERROR);

    let mut profile = profile_base();
    profile.suppress_aaaa = true;
    let eng = engine(&h, profile, anchors_of(&h), config_for(&h)).await;
    let ans = eng
        .handle(ctx("www.secure.test.", RecordType::AAAA))
        .await
        .unwrap();
    assert!(ans.record.steps.contains(&DecisionStep::AaaaSuppressed));
    assert!(
        !ans.message.header.ad,
        "AAAA suppression must clear AD on a Secure answer"
    );
    assert_eq!(ans.message.rcode(), Rcode::NOERROR);
    assert!(ans.message.answers.is_empty());
}

#[tokio::test]
async fn rebind_strip_drops_stale_ede() {
    let rclock = Arc::new(ResolverClock::new(SystemTime::now()));
    let mut specs = default_servers().unwrap();
    for spec in &mut specs {
        if spec.zone.origin().to_string() == "example.test." {
            spec.zone = spec
                .zone
                .clone()
                .with_a("private.example.test.", Ipv4Addr::new(10, 0, 0, 1))
                .unwrap();
        }
    }
    let h = Hierarchy::start_with(specs).await.unwrap();
    let mut rcfg = config_for(&h);
    rcfg.clock = Arc::clone(&rclock) as _;
    rcfg.ttl_max = 30;
    rcfg.serve_stale = Duration::from_secs(86_400);
    rcfg.prefetch = false;
    rcfg.query_timeout = Duration::from_millis(200);

    let resolver = Arc::new(Resolver::new(rcfg).await.unwrap());
    let eng = PolicyEngine::new(
        policy_cfg(profile_base()),
        empty_filter(),
        Arc::clone(&resolver),
        Arc::new(NoClients),
        policy_clock(),
    )
    .unwrap();

    let _warm = eng
        .handle(ctx("private.example.test.", RecordType::A))
        .await
        .unwrap();

    rclock.advance(Duration::from_secs(30));
    for zone in [".", "test.", "example.test."] {
        h.server(zone).unwrap().stop().await;
    }

    let stale = eng
        .handle(ctx("private.example.test.", RecordType::A))
        .await
        .unwrap();
    assert!(
        stale
            .record
            .steps
            .contains(&DecisionStep::RebindStripped { count: 1 })
    );
    assert!(
        stale.ede.is_none(),
        "rebind strip must drop resolver EDE (stale code 3)"
    );
    assert!(stale.message.answers.is_empty());
    assert_eq!(stale.message.authorities[0].rtype(), RecordType::SOA);
}

#[tokio::test]
async fn aaaa_suppress_drops_stale_ede() {
    let rclock = Arc::new(ResolverClock::new(SystemTime::now()));
    let h = Hierarchy::start().await.unwrap();
    let mut rcfg = config_for(&h);
    rcfg.clock = Arc::clone(&rclock) as _;
    rcfg.ttl_max = 30;
    rcfg.serve_stale = Duration::from_secs(86_400);
    rcfg.prefetch = false;
    rcfg.query_timeout = Duration::from_millis(200);

    let mut profile = profile_base();
    profile.suppress_aaaa = true;
    let resolver = Arc::new(Resolver::new(rcfg).await.unwrap());
    let eng = PolicyEngine::new(
        policy_cfg(profile),
        empty_filter(),
        resolver,
        Arc::new(NoClients),
        policy_clock(),
    )
    .unwrap();

    let _warm = eng
        .handle(ctx("www.example.test.", RecordType::AAAA))
        .await
        .unwrap();

    rclock.advance(Duration::from_secs(30));
    for zone in [".", "test.", "example.test."] {
        h.server(zone).unwrap().stop().await;
    }

    let stale = eng
        .handle(ctx("www.example.test.", RecordType::AAAA))
        .await
        .unwrap();
    assert!(stale.record.steps.contains(&DecisionStep::AaaaSuppressed));
    assert!(
        stale.ede.is_none(),
        "AAAA suppression must drop resolver EDE (stale code 3)"
    );
}

#[tokio::test]
async fn bogus_keeps_servfail_ad_clear_and_dnssec_ede() {
    let h = Hierarchy::start_scenario(&DnssecScenario::new(&[ChildVariant::BogusSig]))
        .await
        .unwrap();
    let eng = engine(&h, profile_base(), anchors_of(&h), config_for(&h)).await;

    let ans = eng
        .handle(ctx("www.bogus-sig.test.", RecordType::A))
        .await
        .unwrap();
    assert_eq!(ans.message.rcode(), Rcode::SERVFAIL);
    assert_eq!(ans.record.dnssec, Some(DnssecStatus::Bogus));
    assert!(!ans.message.header.ad);
    let ede = ans.ede.expect("Bogus must keep resolver DNSSEC EDE");
    assert_eq!(ede.code, 6);
}

#[tokio::test]
async fn unmodified_stale_passes_ede_through() {
    // The resolver's serve-stale path always sets DnssecStatus::Indeterminate
    // and clears AD, so a "stale Secure + EDE" answer never exists. Closest
    // cover for unmodified EDE pass-through: stale answer with no rebind /
    // AAAA change keeps EDE 3.
    let rclock = Arc::new(ResolverClock::new(SystemTime::now()));
    let h = Hierarchy::start().await.unwrap();
    let mut rcfg = config_for(&h);
    rcfg.clock = Arc::clone(&rclock) as _;
    rcfg.ttl_max = 30;
    rcfg.serve_stale = Duration::from_secs(86_400);
    rcfg.prefetch = false;
    rcfg.query_timeout = Duration::from_millis(200);

    let mut profile = profile_base();
    profile.rebind = Some(false);
    let resolver = Arc::new(Resolver::new(rcfg).await.unwrap());
    let eng = PolicyEngine::new(
        policy_cfg(profile),
        empty_filter(),
        resolver,
        Arc::new(NoClients),
        policy_clock(),
    )
    .unwrap();

    let _warm = eng
        .handle(ctx("www.example.test.", RecordType::A))
        .await
        .unwrap();
    rclock.advance(Duration::from_secs(30));
    for zone in [".", "test.", "example.test."] {
        h.server(zone).unwrap().stop().await;
    }

    let stale = eng
        .handle(ctx("www.example.test.", RecordType::A))
        .await
        .unwrap();
    assert_eq!(stale.message.rcode(), Rcode::NOERROR);
    assert!(!stale.message.answers.is_empty());
    let ede = stale.ede.expect("unmodified stale must pass EDE through");
    assert_eq!(ede.code, 3);
}

#[tokio::test]
async fn aaaa_suppress_leaves_bogus_servfail_with_ede() {
    // BogusExpired makes every RRSIG invalid, so AAAA is also Bogus SERVFAIL.
    let h = Hierarchy::start_scenario(&DnssecScenario::new(&[ChildVariant::BogusExpired]))
        .await
        .unwrap();
    let mut profile = profile_base();
    profile.suppress_aaaa = true;
    let eng = engine(&h, profile, anchors_of(&h), config_for(&h)).await;

    let ans = eng
        .handle(ctx("www.bogus-expired.test.", RecordType::AAAA))
        .await
        .unwrap();
    assert_eq!(ans.message.rcode(), Rcode::SERVFAIL);
    assert_eq!(ans.record.dnssec, Some(DnssecStatus::Bogus));
    assert!(
        !ans.record
            .steps
            .iter()
            .any(|s| matches!(s, DecisionStep::AaaaSuppressed)),
        "AAAA suppression must not rewrite Bogus SERVFAIL"
    );
    let ede = ans.ede.expect("DNSSEC EDE must be kept");
    // BogusExpired → INFO-CODE 7 (Signature Expired per RFC 8914).
    assert_eq!(ede.code, 7);
    assert!(!ans.message.header.ad);
}
