#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::{Duration, Instant};

use dnscraft_proto::{Class, Message, Name, RData, Rcode, Record, RecordType};
use dnscraft_resolver::{
    AnswerSource, DnssecStatus, PrimingStatus, Query, RequestFlags, Resolver, ResolverConfig,
};
use dnscraft_testkit::{Hierarchy, ServerSpec, Zone, default_servers};
use hickory_proto::rr::rdata::CNAME;
use hickory_proto::rr::{Name as HName, RData as HRData, Record as HRecord};
use tokio::net::UdpSocket;

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

#[tokio::test]
async fn resolves_when_first_nameserver_of_zone_is_stopped() {
    let lo = Ipv4Addr::LOCALHOST;
    let zone = simple_zone("two.test.")
        .with_ns("two.test.", "ns1.two.test.")
        .unwrap()
        .with_ns("two.test.", "ns2.two.test.")
        .unwrap()
        .with_a("www.two.test.", Ipv4Addr::new(192, 0, 2, 55))
        .unwrap();
    let mut specs = default_servers().unwrap();
    for spec in &mut specs {
        if origin(spec) == "test." {
            spec.zone = spec
                .zone
                .clone()
                .with_ns("two.test.", "ns1.two.test.")
                .unwrap()
                .with_a("ns1.two.test.", lo)
                .unwrap()
                .with_ns("two.test.", "ns2.two.test.")
                .unwrap()
                .with_a("ns2.two.test.", lo)
                .unwrap();
        }
    }
    specs.push(ServerSpec::new("ns1.two.test.", zone.clone()).unwrap());
    specs.push(ServerSpec::new("ns2.two.test.", zone).unwrap());
    let h = Hierarchy::start_with(specs).await.unwrap();
    // `server` returns the first server of the zone, i.e. ns1.
    h.server("two.test.").unwrap().stop().await;
    let r = Resolver::new(config_for(&h)).await.unwrap();

    let ans = r
        .resolve(
            &query("www.two.test.", RecordType::A),
            RequestFlags::default(),
        )
        .await
        .unwrap();
    assert_eq!(
        ans.message.answers[0].rdata,
        RData::A(Ipv4Addr::new(192, 0, 2, 55))
    );
}

// ---- Task 5: CNAME chains, NXDOMAIN/NODATA, limits ----

const LO: Ipv4Addr = Ipv4Addr::LOCALHOST;

fn cname(owner: &str, target: &str) -> HRecord {
    HRecord::from_rdata(
        HName::from_ascii(owner).unwrap(),
        300,
        HRData::CNAME(CNAME(HName::from_ascii(target).unwrap())),
    )
}

fn origin(spec: &ServerSpec) -> String {
    spec.zone.origin().to_string()
}

/// Default servers with `extra` records added to `example.test.`.
fn specs_with_example(extra: Vec<HRecord>) -> Vec<ServerSpec> {
    let mut specs = default_servers().unwrap();
    for spec in &mut specs {
        if origin(spec) == "example.test." {
            for r in &extra {
                spec.zone = spec.zone.clone().with_record(r.clone());
            }
        }
    }
    specs
}

/// Adds a delegation `zone` -> `ns_host` (glue 127.0.0.1) to `test.` and a
/// server for `zone` hosted under `ns_host`.
fn add_zone(specs: &mut Vec<ServerSpec>, zone: Zone, ns_host: &str) {
    let apex = zone.origin().to_string();
    for spec in specs.iter_mut() {
        if origin(spec) == "test." {
            spec.zone = spec
                .zone
                .clone()
                .with_ns(&apex, ns_host)
                .unwrap()
                .with_a(ns_host, LO)
                .unwrap();
        }
    }
    specs.push(ServerSpec::new(ns_host, zone).unwrap());
}

fn simple_zone(apex: &str) -> Zone {
    Zone::new(apex)
        .unwrap()
        .with_soa("ns.example.test.", &format!("hostmaster.{apex}"))
        .unwrap()
}

fn has_soa(records: &[Record]) -> bool {
    records.iter().any(|r| matches!(r.rdata, RData::SOA { .. }))
}

fn rdatas(ans: &dnscraft_resolver::Answer) -> Vec<RData> {
    ans.message
        .answers
        .iter()
        .map(|r| r.rdata.clone())
        .collect()
}

fn n(text: &str) -> Name {
    Name::from_ascii(text).unwrap()
}

#[tokio::test]
async fn follows_same_zone_cname() {
    let specs = specs_with_example(vec![cname("alias.example.test.", "www.example.test.")]);
    let h = Hierarchy::start_with(specs).await.unwrap();
    let r = Resolver::new(config_for(&h)).await.unwrap();
    let ans = r
        .resolve(
            &query("alias.example.test.", RecordType::A),
            RequestFlags::default(),
        )
        .await
        .unwrap();
    assert_eq!(ans.message.rcode(), Rcode::NOERROR);
    assert_eq!(
        rdatas(&ans),
        vec![
            RData::CNAME(n("www.example.test.")),
            RData::A(Ipv4Addr::new(192, 0, 2, 1))
        ]
    );
    assert_eq!(ans.message.answers[0].name, n("alias.example.test."));
    assert_eq!(ans.message.answers[1].name, n("www.example.test."));
}

#[tokio::test]
async fn cname_query_is_not_followed() {
    let specs = specs_with_example(vec![cname("alias.example.test.", "www.example.test.")]);
    let h = Hierarchy::start_with(specs).await.unwrap();
    let r = Resolver::new(config_for(&h)).await.unwrap();
    let ans = r
        .resolve(
            &query("alias.example.test.", RecordType::CNAME),
            RequestFlags::default(),
        )
        .await
        .unwrap();
    assert_eq!(rdatas(&ans), vec![RData::CNAME(n("www.example.test."))]);
}

#[tokio::test]
async fn follows_cross_zone_cname() {
    let mut specs = specs_with_example(vec![cname("x.example.test.", "www.other.test.")]);
    let other = simple_zone("other.test.")
        .with_ns("other.test.", "ns.other.test.")
        .unwrap()
        .with_a("ns.other.test.", LO)
        .unwrap()
        .with_a("www.other.test.", Ipv4Addr::new(192, 0, 2, 88))
        .unwrap();
    add_zone(&mut specs, other, "ns.other.test.");
    let h = Hierarchy::start_with(specs).await.unwrap();
    let r = Resolver::new(config_for(&h)).await.unwrap();
    let ans = r
        .resolve(
            &query("x.example.test.", RecordType::A),
            RequestFlags::default(),
        )
        .await
        .unwrap();
    assert_eq!(
        rdatas(&ans),
        vec![
            RData::CNAME(n("www.other.test.")),
            RData::A(Ipv4Addr::new(192, 0, 2, 88))
        ]
    );
    // The target was resolved by a new resolution reaching other.test.
    assert!(names(&h, "other.test.").contains(&("www.other.test.".to_owned(), RecordType::A)));
}

#[tokio::test]
async fn nxdomain_and_nodata_carry_soa() {
    let specs = specs_with_example(vec![
        cname("dead.example.test.", "nope.example.test."),
        cname("ok.example.test.", "www.example.test."),
    ]);
    let h = Hierarchy::start_with(specs).await.unwrap();
    let r = Resolver::new(config_for(&h)).await.unwrap();

    let nx = r
        .resolve(
            &query("nope.example.test.", RecordType::A),
            RequestFlags::default(),
        )
        .await
        .unwrap();
    assert_eq!(nx.message.rcode(), Rcode::NXDOMAIN);
    assert!(nx.message.answers.is_empty());
    assert!(has_soa(&nx.message.authorities));

    let nodata = r
        .resolve(
            &query("www.example.test.", RecordType::MX),
            RequestFlags::default(),
        )
        .await
        .unwrap();
    assert_eq!(nodata.message.rcode(), Rcode::NOERROR);
    assert!(nodata.message.answers.is_empty());
    assert!(has_soa(&nodata.message.authorities));

    // NXDOMAIN at the end of a chain: chain kept, rcode of the final target.
    let chained = r
        .resolve(
            &query("dead.example.test.", RecordType::A),
            RequestFlags::default(),
        )
        .await
        .unwrap();
    assert_eq!(chained.message.rcode(), Rcode::NXDOMAIN);
    assert_eq!(
        rdatas(&chained),
        vec![RData::CNAME(n("nope.example.test."))]
    );
    assert!(has_soa(&chained.message.authorities));

    // NODATA at the end of a chain.
    let chained = r
        .resolve(
            &query("ok.example.test.", RecordType::MX),
            RequestFlags::default(),
        )
        .await
        .unwrap();
    assert_eq!(chained.message.rcode(), Rcode::NOERROR);
    assert_eq!(rdatas(&chained), vec![RData::CNAME(n("www.example.test."))]);
    assert!(has_soa(&chained.message.authorities));
}

#[tokio::test]
async fn cname_loop_and_long_chain_hit_limit() {
    let mut extra = vec![
        cname("a.example.test.", "b.example.test."),
        cname("b.example.test.", "a.example.test."),
        cname("self.example.test.", "self.example.test."),
    ];
    // c0 -> c1 -> ... -> c17 -> www: 17 links.
    for i in 0..17 {
        extra.push(cname(
            &format!("c{i}.example.test."),
            &format!("c{}.example.test.", i + 1),
        ));
    }
    extra.push(cname("c17.example.test.", "www.example.test."));
    let h = Hierarchy::start_with(specs_with_example(extra))
        .await
        .unwrap();
    let mut config = config_for(&h);
    config.max_queries_per_resolve = 500;
    let r = Resolver::new(config).await.unwrap();

    for name in ["a.example.test.", "self.example.test."] {
        let err = r
            .resolve(&query(name, RecordType::A), RequestFlags::default())
            .await
            .unwrap_err();
        assert_eq!(err.code(), "resolver.cname_limit", "{name}");
    }
    let err = r
        .resolve(
            &query("c0.example.test.", RecordType::A),
            RequestFlags::default(),
        )
        .await
        .unwrap_err();
    assert_eq!(err.code(), "resolver.cname_limit");

    // Exactly sixteen links (c2 .. c17, then www) are still allowed.
    let ans = r
        .resolve(
            &query("c2.example.test.", RecordType::A),
            RequestFlags::default(),
        )
        .await
        .unwrap();
    assert_eq!(ans.message.answers.len(), 17);
    assert_eq!(
        ans.message.answers.last().unwrap().rdata,
        RData::A(Ipv4Addr::new(192, 0, 2, 1))
    );
}

/// Minimal authoritative server for `dn.test.` that only answers with a
/// DNAME (`dn.test. DNAME example.test.`), never with the synthesized CNAME.
async fn spawn_dname_server() -> std::net::SocketAddr {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 1500];
        loop {
            let Ok((len, peer)) = socket.recv_from(&mut buf).await else {
                return;
            };
            let Ok(req) = Message::decode(&buf[..len]) else {
                continue;
            };
            let mut resp = Message::response_to(&req);
            resp.header.aa = true;
            resp.answers.push(Record {
                name: n("dn.test."),
                rtype: RecordType::DNAME,
                class: Class::IN,
                ttl: 300,
                rdata: RData::DNAME(n("example.test.")),
            });
            if let Ok(bytes) = resp.encode() {
                let _ = socket.send_to(&bytes, peer).await;
            }
        }
    });
    addr
}

#[tokio::test]
async fn synthesizes_cname_from_dname() {
    let mut specs = default_servers().unwrap();
    for spec in &mut specs {
        if origin(spec) == "test." {
            spec.zone = spec
                .zone
                .clone()
                .with_ns("dn.test.", "ns.dn.test.")
                .unwrap()
                .with_a("ns.dn.test.", LO)
                .unwrap();
        }
    }
    let h = Hierarchy::start_with(specs).await.unwrap();
    let dname_addr = spawn_dname_server().await;
    let mut config = config_for(&h);
    config
        .nameserver_addr_overrides
        .insert(n("ns.dn.test."), dname_addr);
    let r = Resolver::new(config).await.unwrap();
    let ans = r
        .resolve(
            &query("www.dn.test.", RecordType::A),
            RequestFlags::default(),
        )
        .await
        .unwrap();
    assert_eq!(ans.message.rcode(), Rcode::NOERROR);
    assert_eq!(
        rdatas(&ans),
        vec![
            RData::DNAME(n("example.test.")),
            RData::CNAME(n("www.example.test.")),
            RData::A(Ipv4Addr::new(192, 0, 2, 1))
        ]
    );
    assert_eq!(ans.message.answers[1].name, n("www.dn.test."));
}

#[tokio::test]
async fn query_explosion_is_cut_off_by_budget() {
    let mut specs = default_servers().unwrap();
    let mut big = simple_zone("big.test.");
    // Dozens of glueless name servers that do not exist: each needs nested lookups.
    let mut test_zone_ns = Vec::new();
    for i in 0..40 {
        test_zone_ns.push(format!("ns{i}.gone.test."));
        big = big
            .with_ns("big.test.", &format!("ns{i}.gone.test."))
            .unwrap();
    }
    for spec in &mut specs {
        if origin(spec) == "test." {
            for ns in &test_zone_ns {
                spec.zone = spec.zone.clone().with_ns("big.test.", ns).unwrap();
            }
        }
    }
    specs.push(ServerSpec::new("ns.big.test.", big).unwrap());
    let h = Hierarchy::start_with(specs).await.unwrap();
    let mut config = config_for(&h);
    config.max_queries_per_resolve = 20;
    let r = Resolver::new(config).await.unwrap();
    let before = r.stats().outgoing_queries;
    let start = Instant::now();
    let err = r
        .resolve(
            &query("www.big.test.", RecordType::A),
            RequestFlags::default(),
        )
        .await
        .unwrap_err();
    assert_eq!(err.code(), "resolver.query_budget");
    assert!(start.elapsed() < Duration::from_secs(5));
    assert!(r.stats().outgoing_queries - before <= 20);
}
