//! Positive and negative cache (Task 11).
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use dnscraft_proto::{Class, Name, RData, Rcode, Record, RecordType};
use dnscraft_resolver::dnssec::TrustAnchors;
use dnscraft_resolver::{
    Answer, AnswerSource, DnssecStatus, FlushScope, ManualClock, Query, RequestFlags, Resolver,
    ResolverConfig,
};
use dnscraft_testkit::{ChildVariant, DnssecScenario, Hierarchy, default_servers};
use hickory_proto::serialize::binary::BinEncodable;

const ZONES: &[&str] = &[".", "test.", "example.test."];

fn config_for(h: &Hierarchy) -> ResolverConfig {
    let overrides = h
        .nameserver_addrs()
        .iter()
        .map(|(n, a)| (Name::from_ascii(&n.to_string()).unwrap(), *a))
        .collect();
    ResolverConfig {
        root_hints: h.root_hints(),
        query_timeout: Duration::from_millis(500),
        nameserver_addr_overrides: overrides,
        trust_anchors: TrustAnchors::empty(),
        ..ResolverConfig::default()
    }
}

fn query(name: &str, qtype: RecordType) -> Query {
    Query {
        name: Name::from_ascii(name).unwrap(),
        qtype,
        qclass: Class::IN,
    }
}

async fn resolve(r: &Resolver, name: &str, qtype: RecordType, flags: RequestFlags) -> Answer {
    r.resolve(&query(name, qtype), flags).await.unwrap()
}

fn clear(h: &Hierarchy, zones: &[&str]) {
    for zone in zones {
        h.server(zone).unwrap().clear_queries();
    }
}

fn traffic(h: &Hierarchy, zones: &[&str]) -> usize {
    zones
        .iter()
        .map(|zone| h.server(zone).unwrap().queries().len())
        .sum()
}

fn soa(answer: &Answer) -> &Record {
    answer
        .message
        .authorities
        .iter()
        .find(|record| record.rtype == RecordType::SOA)
        .unwrap()
}

fn anchors_of(h: &Hierarchy) -> TrustAnchors {
    let anchor = h.trust_anchor().unwrap();
    let bytes = anchor.ds.to_bytes().unwrap();
    let ds = Record {
        name: Name::root(),
        rtype: RecordType::DS,
        class: Class::IN,
        ttl: 3600,
        rdata: RData::decode(&bytes, RecordType::DS, 0, bytes.len()).unwrap(),
    };
    TrustAnchors::from_records(&[ds]).unwrap()
}

fn has_rrsig(answer: &Answer) -> bool {
    answer
        .message
        .answers
        .iter()
        .chain(answer.message.authorities.iter())
        .any(|record| record.rtype == RecordType::RRSIG)
}

async fn hierarchy_with(extra: &[(&str, Ipv4Addr)]) -> Hierarchy {
    let mut specs = default_servers().unwrap();
    for spec in &mut specs {
        if spec.zone.origin().to_string() == "example.test." {
            for &(name, addr) in extra {
                spec.zone = spec.zone.clone().with_a(name, addr).unwrap();
            }
        }
    }
    Hierarchy::start_with(specs).await.unwrap()
}

fn clock() -> Arc<ManualClock> {
    Arc::new(ManualClock::new(
        SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000),
    ))
}

#[tokio::test]
async fn second_identical_query_hits_the_cache_without_upstream_traffic() {
    let h = Hierarchy::start().await.unwrap();
    let r = Resolver::new(config_for(&h)).await.unwrap();
    let first = resolve(
        &r,
        "www.example.test.",
        RecordType::A,
        RequestFlags::default(),
    )
    .await;
    assert_eq!(first.source, AnswerSource::Recursion);
    assert_eq!(
        first.message.answers[0].rdata,
        RData::A(Ipv4Addr::new(192, 0, 2, 1))
    );

    clear(&h, ZONES);
    let second = resolve(
        &r,
        "www.example.test.",
        RecordType::A,
        RequestFlags::default(),
    )
    .await;
    assert_eq!(second.source, AnswerSource::Cache);
    assert_eq!(second.dnssec, first.dnssec);
    assert_eq!(
        second.message.answers[0].rdata,
        first.message.answers[0].rdata
    );
    assert_eq!(traffic(&h, ZONES), 0);
}

#[tokio::test]
async fn qtype_is_part_of_the_cache_key() {
    let h = Hierarchy::start().await.unwrap();
    let r = Resolver::new(config_for(&h)).await.unwrap();
    let _ = resolve(
        &r,
        "www.example.test.",
        RecordType::A,
        RequestFlags::default(),
    )
    .await;

    clear(&h, ZONES);
    let aaaa = resolve(
        &r,
        "www.example.test.",
        RecordType::AAAA,
        RequestFlags::default(),
    )
    .await;
    assert_eq!(aaaa.source, AnswerSource::Recursion);
    assert!(traffic(&h, ZONES) > 0);

    clear(&h, ZONES);
    let again = resolve(
        &r,
        "www.example.test.",
        RecordType::A,
        RequestFlags::default(),
    )
    .await;
    assert_eq!(again.source, AnswerSource::Cache);
    assert_eq!(traffic(&h, ZONES), 0);
}

#[tokio::test]
async fn positive_ttl_is_clamped_to_ttl_max() {
    let clock = clock();
    let h = Hierarchy::start().await.unwrap();
    let mut config = config_for(&h);
    config.clock = clock.clone();
    config.ttl_max = 30;
    let r = Resolver::new(config).await.unwrap();

    let first = resolve(
        &r,
        "www.example.test.",
        RecordType::A,
        RequestFlags::default(),
    )
    .await;
    assert_eq!(first.source, AnswerSource::Recursion);
    // The zone TTL is 300s; the clamp is what we cache and serve.
    assert_eq!(first.message.answers[0].ttl, 30);

    clear(&h, ZONES);
    clock.advance(Duration::from_secs(29));
    let hit = resolve(
        &r,
        "www.example.test.",
        RecordType::A,
        RequestFlags::default(),
    )
    .await;
    assert_eq!(hit.source, AnswerSource::Cache);
    assert_eq!(hit.message.answers[0].ttl, 1);
    assert_eq!(traffic(&h, ZONES), 0);

    clock.advance(Duration::from_secs(1));
    clear(&h, ZONES);
    let miss = resolve(
        &r,
        "www.example.test.",
        RecordType::A,
        RequestFlags::default(),
    )
    .await;
    assert_eq!(miss.source, AnswerSource::Recursion);
    assert!(traffic(&h, ZONES) > 0);
}

#[tokio::test]
async fn negative_answers_expire_after_the_soa_minimum() {
    let clock = clock();
    let h = Hierarchy::start().await.unwrap();
    let mut config = config_for(&h);
    config.clock = clock.clone();
    let r = Resolver::new(config).await.unwrap();

    let nx = resolve(
        &r,
        "nope.example.test.",
        RecordType::A,
        RequestFlags::default(),
    )
    .await;
    let nodata = resolve(
        &r,
        "www.example.test.",
        RecordType::MX,
        RequestFlags::default(),
    )
    .await;
    assert_eq!(nx.source, AnswerSource::Recursion);
    assert_eq!(nx.message.rcode(), Rcode::NXDOMAIN);
    assert_eq!(nodata.source, AnswerSource::Recursion);
    assert_eq!(nodata.message.rcode(), Rcode::NOERROR);
    assert!(nodata.message.answers.is_empty());

    let nx_min = match &soa(&nx).rdata {
        RData::SOA { minimum, .. } => *minimum,
        _ => panic!("nxdomain authority is not an SOA"),
    };
    let nd_min = match &soa(&nodata).rdata {
        RData::SOA { minimum, .. } => *minimum,
        _ => panic!("nodata authority is not an SOA"),
    };
    // Served TTL is min(SOA TTL, SOA MINIMUM), which is the MINIMUM in the
    // testkit zones (the SOA record itself is 300s).
    assert_eq!(soa(&nx).ttl, nx_min);
    assert_eq!(soa(&nodata).ttl, nd_min);
    assert_eq!(nx_min, nd_min);
    assert!(nx_min > 1);

    clear(&h, ZONES);
    clock.advance(Duration::from_secs(u64::from(nx_min) - 1));
    let nx_hit = resolve(
        &r,
        "nope.example.test.",
        RecordType::A,
        RequestFlags::default(),
    )
    .await;
    let nd_hit = resolve(
        &r,
        "www.example.test.",
        RecordType::MX,
        RequestFlags::default(),
    )
    .await;
    assert_eq!(nx_hit.source, AnswerSource::Cache);
    assert_eq!(nd_hit.source, AnswerSource::Cache);
    assert_eq!(soa(&nx_hit).ttl, 1);
    assert_eq!(traffic(&h, ZONES), 0);

    clock.advance(Duration::from_secs(1));
    clear(&h, ZONES);
    let nx_miss = resolve(
        &r,
        "nope.example.test.",
        RecordType::A,
        RequestFlags::default(),
    )
    .await;
    assert_eq!(nx_miss.source, AnswerSource::Recursion);
    assert!(traffic(&h, ZONES) > 0);
}

#[tokio::test]
async fn ttl_min_raises_a_short_negative_ttl() {
    // The testkit SOA minimum is 60s and the SOA record TTL is 300s, so a
    // floor of 90s is above the negative TTL and below the record TTL.
    let clock = clock();
    let h = Hierarchy::start().await.unwrap();
    let mut config = config_for(&h);
    config.clock = clock.clone();
    config.ttl_min = 90;
    let r = Resolver::new(config).await.unwrap();

    let nx = resolve(
        &r,
        "nope.example.test.",
        RecordType::A,
        RequestFlags::default(),
    )
    .await;
    assert_eq!(soa(&nx).ttl, 90);

    clear(&h, ZONES);
    clock.advance(Duration::from_secs(61));
    let hit = resolve(
        &r,
        "nope.example.test.",
        RecordType::A,
        RequestFlags::default(),
    )
    .await;
    assert_eq!(hit.source, AnswerSource::Cache);
    assert_eq!(traffic(&h, ZONES), 0);

    clock.advance(Duration::from_secs(29));
    clear(&h, ZONES);
    let miss = resolve(
        &r,
        "nope.example.test.",
        RecordType::A,
        RequestFlags::default(),
    )
    .await;
    assert_eq!(miss.source, AnswerSource::Recursion);
    assert!(traffic(&h, ZONES) > 0);
}

#[tokio::test]
async fn byte_budget_evicts_the_least_recently_used() {
    let names = [
        "n00.example.test.",
        "n01.example.test.",
        "n02.example.test.",
        "n03.example.test.",
    ];
    let extra: Vec<(&str, Ipv4Addr)> = names
        .iter()
        .enumerate()
        .map(|(i, name)| {
            let octet = u8::try_from(i).unwrap();
            (*name, Ipv4Addr::new(192, 0, 2, octet))
        })
        .collect();
    let h = hierarchy_with(&extra).await;
    let probe = Resolver::new(config_for(&h)).await.unwrap();
    let _ = resolve(&probe, names[0], RecordType::A, RequestFlags::default()).await;
    let one = probe.cached_bytes();
    assert!(one > 0);

    let mut config = config_for(&h);
    config.cache_capacity_bytes = Some(u64::try_from(one.saturating_mul(2)).unwrap());
    let r = Resolver::new(config).await.unwrap();
    for name in names {
        let answer = resolve(&r, name, RecordType::A, RequestFlags::default()).await;
        assert_eq!(answer.source, AnswerSource::Recursion);
    }
    assert_eq!(
        r.cached_bytes(),
        one * 2,
        "two equal entries of {one} bytes should remain"
    );

    clear(&h, ZONES);
    let newest = resolve(&r, names[3], RecordType::A, RequestFlags::default()).await;
    assert_eq!(newest.source, AnswerSource::Cache);
    assert_eq!(traffic(&h, ZONES), 0);

    clear(&h, ZONES);
    let oldest = resolve(&r, names[0], RecordType::A, RequestFlags::default()).await;
    assert_eq!(oldest.source, AnswerSource::Recursion);
    assert!(traffic(&h, ZONES) > 0);
    assert!(r.cached_bytes() <= one * 2);
}

#[tokio::test]
async fn flush_all_drops_every_entry() {
    let h = Hierarchy::start().await.unwrap();
    let r = Resolver::new(config_for(&h)).await.unwrap();
    let _ = resolve(
        &r,
        "www.example.test.",
        RecordType::A,
        RequestFlags::default(),
    )
    .await;
    let _ = resolve(
        &r,
        "www.example.test.",
        RecordType::AAAA,
        RequestFlags::default(),
    )
    .await;
    assert!(r.cached_bytes() > 0);

    r.flush(FlushScope::All);
    assert_eq!(r.cached_bytes(), 0);
    clear(&h, ZONES);
    let again = resolve(
        &r,
        "www.example.test.",
        RecordType::A,
        RequestFlags::default(),
    )
    .await;
    assert_eq!(again.source, AnswerSource::Recursion);
    assert!(traffic(&h, ZONES) > 0);
}

#[tokio::test]
async fn flush_domain_removes_that_name_and_names_below_it() {
    let h = hierarchy_with(&[
        ("mail.example.test.", Ipv4Addr::new(192, 0, 2, 10)),
        ("sub.www.example.test.", Ipv4Addr::new(192, 0, 2, 11)),
    ])
    .await;
    let r = Resolver::new(config_for(&h)).await.unwrap();
    for name in [
        "www.example.test.",
        "sub.www.example.test.",
        "mail.example.test.",
    ] {
        let answer = resolve(&r, name, RecordType::A, RequestFlags::default()).await;
        assert_eq!(answer.source, AnswerSource::Recursion);
    }

    r.flush(FlushScope::Domain(
        Name::from_ascii("www.example.test.").unwrap(),
    ));
    clear(&h, ZONES);
    let www = resolve(
        &r,
        "www.example.test.",
        RecordType::A,
        RequestFlags::default(),
    )
    .await;
    assert_eq!(www.source, AnswerSource::Recursion);
    assert!(traffic(&h, ZONES) > 0);

    clear(&h, ZONES);
    let sub = resolve(
        &r,
        "sub.www.example.test.",
        RecordType::A,
        RequestFlags::default(),
    )
    .await;
    assert_eq!(sub.source, AnswerSource::Recursion);
    assert!(traffic(&h, ZONES) > 0);

    clear(&h, ZONES);
    let mail = resolve(
        &r,
        "mail.example.test.",
        RecordType::A,
        RequestFlags::default(),
    )
    .await;
    assert_eq!(mail.source, AnswerSource::Cache);
    assert_eq!(traffic(&h, ZONES), 0);
}

#[tokio::test]
async fn cached_secure_answer_keeps_dnssec_status_and_records() {
    let zones = [".", "test.", "secure.test."];
    let h = Hierarchy::start_scenario(&DnssecScenario::new(&[ChildVariant::Secure]))
        .await
        .unwrap();
    let mut config = config_for(&h);
    config.trust_anchors = anchors_of(&h);
    let r = Resolver::new(config).await.unwrap();

    let first = resolve(
        &r,
        "www.secure.test.",
        RecordType::A,
        RequestFlags::default(),
    )
    .await;
    assert_eq!(first.source, AnswerSource::Recursion);
    assert_eq!(first.dnssec, DnssecStatus::Secure);
    assert!(first.message.header.ad);
    assert!(!has_rrsig(&first));

    clear(&h, &zones);
    let with_do = resolve(
        &r,
        "www.secure.test.",
        RecordType::A,
        RequestFlags {
            checking_disabled: false,
            dnssec_ok: true,
        },
    )
    .await;
    assert_eq!(with_do.source, AnswerSource::Cache);
    assert_eq!(with_do.dnssec, DnssecStatus::Secure);
    assert!(with_do.message.header.ad);
    assert!(has_rrsig(&with_do));
    assert_eq!(traffic(&h, &zones), 0);

    clear(&h, &zones);
    let stripped = resolve(
        &r,
        "www.secure.test.",
        RecordType::A,
        RequestFlags::default(),
    )
    .await;
    assert_eq!(stripped.source, AnswerSource::Cache);
    assert!(!has_rrsig(&stripped));
    assert!(stripped.message.header.ad);
    assert_eq!(traffic(&h, &zones), 0);

    // Stripping the previous answer must not have removed the stored RRSIGs.
    clear(&h, &zones);
    let again = resolve(
        &r,
        "www.secure.test.",
        RecordType::A,
        RequestFlags {
            checking_disabled: false,
            dnssec_ok: true,
        },
    )
    .await;
    assert_eq!(again.source, AnswerSource::Cache);
    assert!(has_rrsig(&again));
    assert_eq!(traffic(&h, &zones), 0);
}

#[tokio::test]
async fn bogus_servfail_is_not_cached() {
    let zones = [".", "test.", "bogus-sig.test."];
    let h = Hierarchy::start_scenario(&DnssecScenario::new(&[ChildVariant::BogusSig]))
        .await
        .unwrap();
    let mut config = config_for(&h);
    config.trust_anchors = anchors_of(&h);
    let r = Resolver::new(config).await.unwrap();

    let first = resolve(
        &r,
        "www.bogus-sig.test.",
        RecordType::A,
        RequestFlags::default(),
    )
    .await;
    assert_eq!(first.dnssec, DnssecStatus::Bogus);
    assert_eq!(first.message.rcode(), Rcode::SERVFAIL);
    assert_eq!(first.source, AnswerSource::Recursion);

    clear(&h, &zones);
    let second = resolve(
        &r,
        "www.bogus-sig.test.",
        RecordType::A,
        RequestFlags::default(),
    )
    .await;
    assert_eq!(second.source, AnswerSource::Recursion);
    assert_eq!(second.dnssec, DnssecStatus::Bogus);
    assert!(traffic(&h, &zones) > 0);
}

#[tokio::test]
async fn checking_disabled_answers_are_not_stored() {
    let h = Hierarchy::start().await.unwrap();
    let r = Resolver::new(config_for(&h)).await.unwrap();
    let cd = RequestFlags {
        checking_disabled: true,
        dnssec_ok: false,
    };
    let first = resolve(&r, "www.example.test.", RecordType::A, cd).await;
    assert_eq!(first.source, AnswerSource::Recursion);

    clear(&h, ZONES);
    let second = resolve(&r, "www.example.test.", RecordType::A, cd).await;
    assert_eq!(second.source, AnswerSource::Recursion);
    assert!(traffic(&h, ZONES) > 0);
}

#[tokio::test]
async fn validated_cache_entry_is_served_to_a_cd_query() {
    let h = Hierarchy::start().await.unwrap();
    let r = Resolver::new(config_for(&h)).await.unwrap();
    let _ = resolve(
        &r,
        "www.example.test.",
        RecordType::A,
        RequestFlags::default(),
    )
    .await;

    clear(&h, ZONES);
    let cd = resolve(
        &r,
        "www.example.test.",
        RecordType::A,
        RequestFlags {
            checking_disabled: true,
            dnssec_ok: false,
        },
    )
    .await;
    assert_eq!(cd.source, AnswerSource::Cache);
    assert_eq!(traffic(&h, ZONES), 0);
}

#[tokio::test]
async fn local_answers_are_not_cached() {
    let h = Hierarchy::start().await.unwrap();
    let r = Resolver::new(config_for(&h)).await.unwrap();
    let before = r.stats().outgoing_queries;
    let first = resolve(
        &r,
        "1.0.0.10.in-addr.arpa.",
        RecordType::PTR,
        RequestFlags::default(),
    )
    .await;
    let second = resolve(
        &r,
        "1.0.0.10.in-addr.arpa.",
        RecordType::PTR,
        RequestFlags::default(),
    )
    .await;
    assert_eq!(first.source, AnswerSource::Recursion);
    assert_eq!(second.source, AnswerSource::Recursion);
    assert_eq!(first.message.rcode(), Rcode::NXDOMAIN);
    assert_eq!(r.stats().outgoing_queries, before);
    assert_eq!(r.cached_bytes(), 0);
}
