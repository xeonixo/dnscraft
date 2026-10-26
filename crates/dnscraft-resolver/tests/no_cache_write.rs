//! Task M4: `RequestFlags::no_cache_write` (dry-run queries).
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::time::Duration;

use dnscraft_proto::{Class, Name, RData, Record, RecordType};
use dnscraft_resolver::dnssec::TrustAnchors;
use dnscraft_resolver::{
    Answer, AnswerSource, DnssecStatus, Query, RequestFlags, Resolver, ResolverConfig,
};
use dnscraft_testkit::{ChildVariant, Hierarchy};
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

fn dry_run() -> RequestFlags {
    RequestFlags {
        no_cache_write: true,
        ..RequestFlags::default()
    }
}

fn clear(h: &Hierarchy) {
    for zone in ZONES {
        h.server(zone).unwrap().clear_queries();
    }
}

fn traffic(h: &Hierarchy) -> usize {
    ZONES
        .iter()
        .map(|zone| h.server(zone).unwrap().queries().len())
        .sum()
}

#[tokio::test]
async fn no_cache_write_query_goes_upstream_both_times_and_stores_nothing() {
    let h = Hierarchy::start().await.unwrap();
    let r = Resolver::new(config_for(&h)).await.unwrap();
    let before = r.stats().cache_entries;
    assert_eq!(before, 0);

    clear(&h);
    let first = resolve(&r, "www.example.test.", RecordType::A, dry_run()).await;
    assert_eq!(first.source, AnswerSource::Recursion);
    assert!(traffic(&h) > 0);

    clear(&h);
    let second = resolve(&r, "www.example.test.", RecordType::A, dry_run()).await;
    assert_eq!(
        second.source,
        AnswerSource::Recursion,
        "a dry run must not become a cache hit"
    );
    assert!(traffic(&h) > 0, "the second dry run must go upstream");
    assert_eq!(r.stats().cache_entries, before);
    assert_eq!(r.cached_bytes(), 0);
}

#[tokio::test]
async fn no_cache_write_negative_answer_is_not_stored() {
    let h = Hierarchy::start().await.unwrap();
    let r = Resolver::new(config_for(&h)).await.unwrap();

    clear(&h);
    let first = resolve(&r, "missing.example.test.", RecordType::A, dry_run()).await;
    assert_eq!(first.source, AnswerSource::Recursion);
    clear(&h);
    let second = resolve(&r, "missing.example.test.", RecordType::A, dry_run()).await;
    assert_eq!(second.source, AnswerSource::Recursion);
    assert!(traffic(&h) > 0);
    assert_eq!(r.stats().cache_entries, 0);
}

#[tokio::test]
async fn control_normal_query_is_cached_without_no_cache_write() {
    let h = Hierarchy::start().await.unwrap();
    let r = Resolver::new(config_for(&h)).await.unwrap();

    clear(&h);
    let first = resolve(
        &r,
        "www.example.test.",
        RecordType::A,
        RequestFlags::default(),
    )
    .await;
    assert_eq!(first.source, AnswerSource::Recursion);
    let after_first = r.stats().cache_entries;
    assert!(after_first > 0);

    clear(&h);
    let second = resolve(
        &r,
        "www.example.test.",
        RecordType::A,
        RequestFlags::default(),
    )
    .await;
    assert_eq!(second.source, AnswerSource::Cache);
    assert_eq!(traffic(&h), 0, "a normal cache hit must not go upstream");
    assert_eq!(r.stats().cache_entries, after_first);
}

#[tokio::test]
async fn no_cache_write_still_reads_an_entry_from_earlier_normal_traffic() {
    let h = Hierarchy::start().await.unwrap();
    let r = Resolver::new(config_for(&h)).await.unwrap();

    clear(&h);
    let warm = resolve(
        &r,
        "www.example.test.",
        RecordType::A,
        RequestFlags::default(),
    )
    .await;
    assert_eq!(warm.source, AnswerSource::Recursion);
    let entries = r.stats().cache_entries;
    assert!(entries > 0);

    clear(&h);
    let dry = resolve(&r, "www.example.test.", RecordType::A, dry_run()).await;
    assert_eq!(
        dry.source,
        AnswerSource::Cache,
        "dry run must see the cache"
    );
    assert_eq!(traffic(&h), 0);
    assert_eq!(r.stats().cache_entries, entries);
}

#[tokio::test]
async fn no_cache_write_dnssec_validation_still_works() {
    let h = Hierarchy::start_signed(&[ChildVariant::Secure])
        .await
        .unwrap();
    let mut config = config_for(&h);
    config.trust_anchors = anchors_of(&h);
    let r = Resolver::new(config).await.unwrap();

    let flags = RequestFlags {
        dnssec_ok: true,
        no_cache_write: true,
        ..RequestFlags::default()
    };
    let answer = resolve(&r, "www.secure.test.", RecordType::A, flags).await;
    assert_eq!(answer.dnssec, DnssecStatus::Secure);
    assert!(answer.message.header.ad);
    assert_eq!(answer.source, AnswerSource::Recursion);
    assert_eq!(r.stats().cache_entries, 0);
}
