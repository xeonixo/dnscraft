//! Locally served RFC 6303 zones and ECS stripping.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::time::Duration;

use dnscraft_proto::{Class, Edns, EdnsOption, Message, Name, RData, Rcode, RecordType};
use dnscraft_resolver::dnssec::TrustAnchors;
use dnscraft_resolver::local_zones::{LocalZones, strip_client_subnet};
use dnscraft_resolver::{
    AnswerSource, DnssecStatus, ForwardZone, ForwardZoneId, Query, RequestFlags, Resolver,
    ResolverConfig,
};
use dnscraft_testkit::Hierarchy;

fn name(text: &str) -> Name {
    Name::from_ascii(text).unwrap()
}

fn query(text: &str, qtype: RecordType) -> Query {
    Query {
        name: name(text),
        qtype,
        qclass: Class::IN,
    }
}

#[test]
fn built_in_list_has_rfc6303_zones_and_home_arpa() {
    let zones = LocalZones::rfc6303();
    // 10, 168.192, 0, 127, 254.169, 2.0.192, 100.51.198, 113.0.203,
    // 255.255.255.255, 16..31.172 (16), d.f, 8.e.f, 9.e.f, a.e.f, b.e.f,
    // 8.b.d.0.1.0.0.2, ::, ::1, home.arpa.
    assert_eq!(zones.zones().len(), 34);
    assert!(zones.zones().contains(&name("31.172.in-addr.arpa.")));
    assert!(
        zones
            .zones()
            .contains(&name(&format!("1.{}ip6.arpa.", "0.".repeat(31))))
    );
    assert!(zones.zones().contains(&name("home.arpa.")));
}

#[test]
fn ptr_in_private_space_is_local_nxdomain_with_soa() {
    let zones = LocalZones::rfc6303();
    let answer = zones
        .answer(&query("1.0.0.10.in-addr.arpa.", RecordType::PTR), &[])
        .unwrap();
    assert_eq!(answer.message.rcode(), Rcode::NXDOMAIN);
    assert!(answer.message.header.aa);
    assert!(answer.message.answers.is_empty());
    assert_eq!(answer.message.authorities.len(), 1);
    let soa = &answer.message.authorities[0];
    assert_eq!(soa.name, name("10.in-addr.arpa."));
    assert_eq!(soa.rtype(), RecordType::SOA);
    assert_eq!(
        soa.rdata,
        RData::SOA {
            mname: name("10.in-addr.arpa."),
            rname: name("nobody.invalid."),
            serial: 1,
            refresh: 604_800,
            retry: 86_400,
            expire: 2_419_200,
            minimum: 10_800,
        }
    );
    assert_eq!(answer.dnssec, DnssecStatus::Insecure);
    assert_eq!(answer.source, AnswerSource::Recursion);
}

#[test]
fn soa_at_apex_is_answered() {
    let zones = LocalZones::rfc6303();
    let answer = zones
        .answer(&query("10.in-addr.arpa.", RecordType::SOA), &[])
        .unwrap();
    assert_eq!(answer.message.rcode(), Rcode::NOERROR);
    assert_eq!(answer.message.answers.len(), 1);
    assert_eq!(answer.message.answers[0].rtype(), RecordType::SOA);
    assert!(answer.message.authorities.is_empty());
}

#[test]
fn ns_at_apex_points_to_localhost() {
    let zones = LocalZones::rfc6303();
    let answer = zones
        .answer(&query("10.in-addr.arpa.", RecordType::NS), &[])
        .unwrap();
    assert_eq!(answer.message.rcode(), Rcode::NOERROR);
    assert_eq!(answer.message.answers.len(), 1);
    assert_eq!(
        answer.message.answers[0].rdata,
        RData::NS(name("localhost."))
    );
}

#[test]
fn other_type_at_apex_is_nodata_with_soa() {
    let zones = LocalZones::rfc6303();
    let answer = zones
        .answer(&query("10.in-addr.arpa.", RecordType::A), &[])
        .unwrap();
    assert_eq!(answer.message.rcode(), Rcode::NOERROR);
    assert!(answer.message.answers.is_empty());
    assert_eq!(answer.message.authorities.len(), 1);
    assert_eq!(answer.message.authorities[0].rtype(), RecordType::SOA);
}

#[test]
fn public_reverse_name_is_not_local() {
    let zones = LocalZones::rfc6303();
    assert!(
        zones
            .answer(&query("8.8.8.8.in-addr.arpa.", RecordType::PTR), &[])
            .is_none()
    );
}

#[test]
fn ula_reverse_name_is_local_nxdomain() {
    let zones = LocalZones::rfc6303();
    let answer = zones
        .answer(&query("1.0.0.0.d.f.ip6.arpa.", RecordType::PTR), &[])
        .unwrap();
    assert_eq!(answer.message.rcode(), Rcode::NXDOMAIN);
}

#[test]
fn other_class_is_not_answered_locally() {
    let zones = LocalZones::rfc6303();
    let mut q = query("1.0.0.10.in-addr.arpa.", RecordType::PTR);
    q.qclass = Class::CH;
    assert!(zones.answer(&q, &[]).is_none());
}

#[test]
fn forward_zone_equal_to_local_zone_overrides_it() {
    let zones = LocalZones::rfc6303();
    let forward = [name("20.172.in-addr.arpa.")];
    assert!(
        zones
            .answer(&query("20.172.in-addr.arpa.", RecordType::SOA), &forward)
            .is_none()
    );
    assert!(
        zones
            .answer(&query("5.20.172.in-addr.arpa.", RecordType::PTR), &forward)
            .is_none()
    );
    // The neighbouring zone stays local.
    let answer = zones
        .answer(&query("21.172.in-addr.arpa.", RecordType::SOA), &forward)
        .unwrap();
    assert_eq!(answer.message.rcode(), Rcode::NOERROR);
}

#[test]
fn forward_zone_inside_local_zone_only_overrides_its_own_subtree() {
    let zones = LocalZones::rfc6303();
    let forward = [name("corp.10.in-addr.arpa.")];
    // Inside the forward zone: forwarded.
    assert!(
        zones
            .answer(
                &query("1.0.corp.10.in-addr.arpa.", RecordType::PTR),
                &forward
            )
            .is_none()
    );
    assert!(
        zones
            .answer(&query("corp.10.in-addr.arpa.", RecordType::PTR), &forward)
            .is_none()
    );
    // Sibling under the same local zone but outside the forward zone: local.
    let answer = zones
        .answer(&query("1.0.0.10.in-addr.arpa.", RecordType::PTR), &forward)
        .unwrap();
    assert_eq!(answer.message.rcode(), Rcode::NXDOMAIN);
    assert!(answer.message.header.aa);
    // The apex of the local zone is outside the forward zone as well.
    assert!(
        zones
            .answer(&query("10.in-addr.arpa.", RecordType::SOA), &forward)
            .is_some()
    );
}

#[test]
fn covering_forward_zone_overrides_all_contained_local_zones() {
    let zones = LocalZones::rfc6303();
    let forward = [name("172.in-addr.arpa.")];
    for second in 16..=31 {
        let text = format!("{second}.172.in-addr.arpa.");
        assert!(
            zones
                .answer(&query(&text, RecordType::SOA), &forward)
                .is_none(),
            "{text} should be overridden"
        );
    }
    // Zones outside the covering forward zone stay local.
    assert!(
        zones
            .answer(&query("10.in-addr.arpa.", RecordType::SOA), &forward)
            .is_some()
    );
}

#[test]
fn without_removes_equal_above_and_below_zones() {
    let mut zones = LocalZones::rfc6303();
    zones.without(&name("172.in-addr.arpa."));
    assert!(!zones.zones().contains(&name("16.172.in-addr.arpa.")));
    assert!(!zones.zones().contains(&name("31.172.in-addr.arpa.")));
    assert!(zones.zones().contains(&name("10.in-addr.arpa.")));
    assert_eq!(zones.zones().len(), 34 - 16);
}

#[test]
fn strip_client_subnet_keeps_other_options() {
    let mut msg = Message::query(7, name("1.0.0.10.in-addr.arpa."), RecordType::PTR);
    let mut edns = Edns::new(1232);
    edns.options.push(EdnsOption::ClientSubnet {
        family: 1,
        source_prefix: 24,
        scope_prefix: 0,
        address: Box::new([192, 0, 2]),
    });
    edns.options.push(EdnsOption::Padding(4));
    msg.edns = Some(edns);

    strip_client_subnet(&mut msg);

    let options = &msg.edns.as_ref().unwrap().options;
    assert_eq!(options, &[EdnsOption::Padding(4)]);
}

#[test]
fn strip_client_subnet_without_edns_is_noop() {
    let mut msg = Message::query(7, name("example.com."), RecordType::A);
    let before = msg.clone();
    strip_client_subnet(&mut msg);
    assert_eq!(msg, before);
}

// ---- Resolver integration ----

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
        trust_anchors: TrustAnchors::empty(),
        ..ResolverConfig::default()
    }
}

/// Names and types received by the fake root (the query log of `.`).
fn root_queries(h: &Hierarchy) -> Vec<(String, RecordType)> {
    h.server(".")
        .unwrap()
        .queries()
        .iter()
        .map(|q| (q.name.to_string(), RecordType(u16::from(q.query_type))))
        .collect()
}

#[tokio::test]
async fn local_zone_answer_never_leaves_the_host() {
    let h = Hierarchy::start().await.unwrap();
    let r = Resolver::new(config_for(&h)).await.unwrap();
    h.server(".").unwrap().clear_queries();
    let before = r.stats().outgoing_queries;

    let ans = r
        .resolve(
            &query("1.0.0.10.in-addr.arpa.", RecordType::PTR),
            RequestFlags::default(),
        )
        .await
        .unwrap();
    assert_eq!(ans.message.rcode(), Rcode::NXDOMAIN);
    assert!(ans.message.header.aa);
    assert_eq!(ans.dnssec, DnssecStatus::Insecure);
    assert_eq!(ans.source, AnswerSource::Recursion);
    // Local answers are not outgoing queries and reach no server at all.
    assert!(root_queries(&h).is_empty());
    assert_eq!(r.stats().outgoing_queries, before);
}

#[tokio::test]
async fn forward_zone_disables_local_answer_for_its_subtree() {
    let h = Hierarchy::start().await.unwrap();
    let mut config = config_for(&h);
    // The fake root is the forward target, so the query leaves the host as a
    // stub query instead of being synthesized locally.
    config.forward_zones = vec![ForwardZone {
        id: ForwardZoneId::new("rfc1918-10").unwrap(),
        zone: name("10.in-addr.arpa."),
        targets: h.root_hints(),
        validate: false,
    }];
    let r = Resolver::new(config).await.unwrap();
    h.server(".").unwrap().clear_queries();

    let ans = r
        .resolve(
            &query("1.0.0.10.in-addr.arpa.", RecordType::PTR),
            RequestFlags::default(),
        )
        .await
        .unwrap();
    // Local answers are authoritative and do not set RA. A forwarded answer
    // clears AA, sets RA, and is Insecure because the zone does not validate.
    assert!(!ans.message.header.aa);
    assert!(ans.message.header.ra);
    assert_eq!(ans.dnssec, DnssecStatus::Insecure);
    assert_eq!(ans.message.rcode(), Rcode::NXDOMAIN);
    assert_eq!(
        root_queries(&h),
        vec![("1.0.0.10.in-addr.arpa.".to_owned(), RecordType::PTR)]
    );
}

#[tokio::test]
async fn sibling_of_an_inner_forward_zone_stays_local_and_never_reaches_the_root() {
    let h = Hierarchy::start().await.unwrap();
    let mut config = config_for(&h);
    config.forward_zones = vec![ForwardZone {
        id: ForwardZoneId::new("corp-10").unwrap(),
        zone: name("corp.10.in-addr.arpa."),
        targets: h.root_hints(),
        validate: false,
    }];
    let r = Resolver::new(config).await.unwrap();
    h.server(".").unwrap().clear_queries();

    let ans = r
        .resolve(
            &query("1.0.0.10.in-addr.arpa.", RecordType::PTR),
            RequestFlags::default(),
        )
        .await
        .unwrap();
    assert_eq!(ans.message.rcode(), Rcode::NXDOMAIN);
    assert!(ans.message.header.aa);
    assert!(
        root_queries(&h).is_empty(),
        "private PTR leaked: {:?}",
        root_queries(&h)
    );

    // The forward zone itself still forwards.
    let fwd = r
        .resolve(
            &query("1.0.corp.10.in-addr.arpa.", RecordType::PTR),
            RequestFlags::default(),
        )
        .await
        .unwrap();
    assert!(!fwd.message.header.aa);
    assert_eq!(
        root_queries(&h),
        vec![("1.0.corp.10.in-addr.arpa.".to_owned(), RecordType::PTR)]
    );
}
