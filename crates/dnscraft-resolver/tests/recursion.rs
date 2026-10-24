#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::{Duration, Instant};

use dnscraft_proto::{Class, Name, RData, RecordType};
use dnscraft_resolver::{
    AnswerSource, DnssecStatus, PrimingStatus, Query, RequestFlags, Resolver, ResolverConfig,
};
use dnscraft_testkit::{Hierarchy, ServerSpec, Zone, default_servers};

fn config_for(h: &Hierarchy) -> ResolverConfig {
    let overrides = h
        .nameserver_addrs()
        .iter()
        .map(|(n, a)| (Name::from_ascii(&n.to_string()).unwrap(), *a))
        .collect();
    ResolverConfig {
        root_hints: h.root_hints(),
        query_timeout: Duration::from_millis(300),
        nameserver_addr_overrides: overrides,
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

fn names(h: &Hierarchy, zone: &str) -> Vec<(String, RecordType)> {
    h.server(zone)
        .unwrap()
        .queries()
        .iter()
        .map(|q| (q.name.to_string(), RecordType(u16::from(q.query_type))))
        .collect()
}

#[tokio::test]
async fn resolves_a_through_hierarchy() {
    let h = Hierarchy::start().await.unwrap();
    let r = Resolver::new(config_for(&h)).await.unwrap();
    h.server(".").unwrap().clear_queries();
    let ans = r
        .resolve(
            &query("www.example.test.", RecordType::A),
            RequestFlags::default(),
        )
        .await
        .unwrap();
    assert_eq!(ans.source, AnswerSource::Recursion);
    assert_eq!(ans.dnssec, DnssecStatus::Indeterminate);
    assert_eq!(ans.message.answers.len(), 1);
    assert_eq!(
        ans.message.answers[0].rdata,
        RData::A(Ipv4Addr::new(192, 0, 2, 1))
    );

    let want = ("www.example.test.".to_owned(), RecordType::A);
    assert_eq!(names(&h, "."), vec![want.clone()]);
    assert_eq!(names(&h, "test."), vec![want.clone()]);
    assert_eq!(names(&h, "example.test."), vec![want]);
    let q = &h.server("test.").unwrap().queries()[0];
    assert!(q.edns_present && q.dnssec_ok && q.edns_options.is_empty());
}

#[tokio::test]
async fn resolves_aaaa() {
    let h = Hierarchy::start().await.unwrap();
    let r = Resolver::new(config_for(&h)).await.unwrap();
    let ans = r
        .resolve(
            &query("www.example.test.", RecordType::AAAA),
            RequestFlags::default(),
        )
        .await
        .unwrap();
    assert_eq!(
        ans.message.answers[0].rdata,
        RData::AAAA(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1))
    );
}

#[tokio::test]
async fn priming_queries_root_ns() {
    let h = Hierarchy::start().await.unwrap();
    let r = Resolver::new(config_for(&h)).await.unwrap();
    assert!(matches!(
        r.priming_status(),
        PrimingStatus::Primed { servers: 1, .. }
    ));
    let log = names(&h, ".");
    assert_eq!(log, vec![(".".to_owned(), RecordType::NS)]);
    let ans = r
        .resolve(
            &query("www.example.test.", RecordType::A),
            RequestFlags::default(),
        )
        .await
        .unwrap();
    assert_eq!(ans.message.answers.len(), 1);
}

#[tokio::test]
async fn priming_falls_back_to_hints() {
    let h = Hierarchy::start().await.unwrap();
    h.server(".").unwrap().stop().await;
    let r = Resolver::new(config_for(&h)).await.unwrap();
    assert_eq!(r.priming_status(), PrimingStatus::FellBack);
}

#[tokio::test]
async fn resolves_glueless_out_of_bailiwick_nameserver() {
    let lo = Ipv4Addr::LOCALHOST;
    let mut specs = default_servers().unwrap();
    for spec in &mut specs {
        if spec.zone.origin().to_string() == "test." {
            spec.zone = spec
                .zone
                .clone()
                .with_ns("other.test.", "ns.example.test.")
                .unwrap();
        }
        if spec.zone.origin().to_string() == "example.test." {
            spec.zone = spec.zone.clone().with_a("ns.example.test.", lo).unwrap();
        }
    }
    let other = Zone::new("other.test.")
        .unwrap()
        .with_soa("ns.example.test.", "hostmaster.other.test.")
        .unwrap()
        .with_ns("other.test.", "ns.example.test.")
        .unwrap()
        .with_a("www.other.test.", Ipv4Addr::new(192, 0, 2, 77))
        .unwrap();
    specs.push(ServerSpec::new("ns.example.test.", other).unwrap());
    let h = Hierarchy::start_with(specs).await.unwrap();
    let r = Resolver::new(config_for(&h)).await.unwrap();

    let ans = r
        .resolve(
            &query("www.other.test.", RecordType::A),
            RequestFlags::default(),
        )
        .await
        .unwrap();
    assert_eq!(
        ans.message.answers[0].rdata,
        RData::A(Ipv4Addr::new(192, 0, 2, 77))
    );
    // The nameserver address was looked up through example.test.
    assert!(names(&h, "example.test.").contains(&("ns.example.test.".to_owned(), RecordType::A)));
}

#[tokio::test]
async fn unreachable_zone_errors_in_bounded_time() {
    let h = Hierarchy::start().await.unwrap();
    let r = Resolver::new(config_for(&h)).await.unwrap();
    h.server("example.test.").unwrap().stop().await;
    let start = Instant::now();
    let err = r
        .resolve(
            &query("www.example.test.", RecordType::A),
            RequestFlags::default(),
        )
        .await
        .unwrap_err();
    assert_eq!(err.code(), "resolver.unreachable");
    assert!(start.elapsed() < Duration::from_secs(3));
}
