//! Regression tests for the security-review findings of batch A2: what a
//! hostile authority can get into the client answer and the cache, rcode
//! forgery, synthesized CNAMEs below a DNAME, signature-bound TTLs, name
//! server address filtering, root priming, the resolution deadline.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use dnscraft_proto::{Class, Message, Name, RData, Rcode, Record, RecordType};
use dnscraft_resolver::dnssec::TrustAnchors;
use dnscraft_resolver::{
    Answer, AnswerSource, DnssecStatus, ForwardZone, ManualClock, PrimingStatus, Query,
    RequestFlags, ResolveError, Resolver, ResolverConfig,
};
use dnscraft_testkit::{
    ChildVariant, DnssecScenario, Hierarchy, ServerSpec, SigningOptions, Zone, ZoneKey,
    default_servers, parse_name, sign_zone, unix_now,
};
use hickory_proto::serialize::binary::BinEncodable;
use tokio::net::UdpSocket;
use tokio::time::timeout;

const LO: Ipv4Addr = Ipv4Addr::LOCALHOST;
const EVIL_IP: Ipv4Addr = Ipv4Addr::new(6, 6, 6, 6);

const DO: RequestFlags = RequestFlags {
    checking_disabled: false,
    dnssec_ok: true,
    client: None,
};

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

fn overrides(h: &Hierarchy) -> std::collections::HashMap<Name, SocketAddr> {
    h.nameserver_addrs()
        .iter()
        .map(|(n, a)| (name(&n.to_string()), *a))
        .collect()
}

/// Validation off (no trust anchors).
fn plain_config(h: &Hierarchy) -> ResolverConfig {
    ResolverConfig {
        root_hints: h.root_hints(),
        query_timeout: Duration::from_millis(400),
        nameserver_addr_overrides: overrides(h),
        trust_anchors: TrustAnchors::empty(),
        prefetch: false,
        ..ResolverConfig::default()
    }
}

fn anchors_from(ds: &hickory_proto::dnssec::rdata::DS, owner: &Name) -> TrustAnchors {
    let bytes = ds.to_bytes().unwrap();
    let rdata = RData::decode(&bytes, RecordType::DS, 0, bytes.len()).unwrap();
    TrustAnchors::from_records(&[Record {
        name: owner.clone(),
        rtype: RecordType::DS,
        class: Class::IN,
        ttl: 3600,
        rdata,
    }])
    .unwrap()
}

/// Validation on, with the testkit root as the trust anchor.
fn signed_config(h: &Hierarchy) -> ResolverConfig {
    ResolverConfig {
        trust_anchors: anchors_from(&h.trust_anchor().unwrap().ds, &Name::root()),
        ..plain_config(h)
    }
}

async fn ask(r: &Resolver, qname: &str, qtype: RecordType, flags: RequestFlags) -> Answer {
    r.resolve(&query(qname, qtype), flags).await.unwrap()
}

/// Edits a response of a server in flight.
type Mutate = Arc<dyn Fn(&Name, RecordType, &mut Message) + Send + Sync>;

/// A UDP proxy in front of `upstream` that lets `mutate` forge each response.
async fn forge_proxy(upstream: SocketAddr, mutate: Mutate) -> SocketAddr {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 8192];
        loop {
            let Ok((len, from)) = socket.recv_from(&mut buf).await else {
                return;
            };
            let q = Message::decode(&buf[..len]).unwrap();
            let up = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            up.send_to(&buf[..len], upstream).await.unwrap();
            let mut rbuf = vec![0u8; 8192];
            let Ok(Ok((rlen, _))) = timeout(Duration::from_secs(2), up.recv_from(&mut rbuf)).await
            else {
                continue;
            };
            let mut m = Message::decode(&rbuf[..rlen]).unwrap();
            mutate(&q.questions[0].name, q.questions[0].qtype, &mut m);
            socket.send_to(&m.encode().unwrap(), from).await.unwrap();
        }
    });
    addr
}

async fn raw_query(server: SocketAddr, qname: &str, qtype: RecordType) -> Message {
    let mut q = Message::query(7, name(qname), qtype);
    q.header.rd = false;
    let mut edns = dnscraft_proto::Edns::new(4096);
    edns.dnssec_ok = true;
    q.edns = Some(edns);
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    socket.send_to(&q.encode().unwrap(), server).await.unwrap();
    let mut buf = vec![0u8; 8192];
    let (len, _) = timeout(Duration::from_secs(2), socket.recv_from(&mut buf))
        .await
        .unwrap()
        .unwrap();
    Message::decode(&buf[..len]).unwrap()
}

fn a_record(owner: &str, ip: Ipv4Addr) -> Record {
    Record {
        name: name(owner),
        rtype: RecordType::A,
        class: Class::IN,
        ttl: 300,
        rdata: RData::A(ip),
    }
}

fn all_records(ans: &Answer) -> impl Iterator<Item = &Record> {
    let m = &ans.message;
    m.answers.iter().chain(&m.authorities).chain(&m.additionals)
}

// ===========================================================================
// 1. Records the resolver did not accept never reach the client or the cache
// ===========================================================================

/// The attack: a response for `qname` that also carries `www.bank.test. A
/// 6.6.6.6` in the answer, authority and additional sections, plus an
/// in-zone name nobody asked for in the additional section.
fn inject_foreign(zone: &'static str) -> Mutate {
    Arc::new(move |_, qtype, m: &mut Message| {
        if qtype != RecordType::A || !m.header.aa {
            return;
        }
        m.answers.push(a_record("www.bank.test.", EVIL_IP));
        m.authorities.push(a_record("www.bank.test.", EVIL_IP));
        m.additionals.push(a_record("www.bank.test.", EVIL_IP));
        m.additionals
            .push(a_record(&format!("junk.{zone}"), EVIL_IP));
    })
}

fn assert_no_foreign(ans: &Answer, qname: &str) {
    assert!(
        all_records(ans).all(|r| r.rdata != RData::A(EVIL_IP) && r.name != name("www.bank.test.")),
        "foreign record reached the client: {:?}",
        ans.message
    );
    assert!(ans.message.additionals.is_empty(), "{:?}", ans.message);
    assert!(
        ans.message.answers.iter().all(|r| r.name == name(qname)),
        "{:?}",
        ans.message.answers
    );
}

/// Asks twice (fresh, then from the cache), with and without DO.
async fn assert_clean_fresh_and_cached(
    r: &Resolver,
    qname: &str,
    status: DnssecStatus,
) -> (Answer, Answer) {
    let fresh = ask(r, qname, RecordType::A, DO).await;
    assert_eq!(fresh.source, AnswerSource::Recursion);
    assert_eq!(fresh.dnssec, status);
    assert_eq!(fresh.message.header.ad, status == DnssecStatus::Secure);
    assert_no_foreign(&fresh, qname);
    assert!(!fresh.message.answers.is_empty());
    let cached = ask(r, qname, RecordType::A, RequestFlags::default()).await;
    assert_eq!(cached.source, AnswerSource::Cache);
    assert_eq!(cached.dnssec, status);
    assert_eq!(cached.message.header.ad, status == DnssecStatus::Secure);
    assert_no_foreign(&cached, qname);
    assert!(!cached.message.answers.is_empty());
    (fresh, cached)
}

#[tokio::test]
async fn injected_records_are_dropped_from_a_signed_zone() {
    let h = Hierarchy::start_signed(&[ChildVariant::Secure])
        .await
        .unwrap();
    let upstream = h.server("secure.test.").unwrap().addr();
    let proxy = forge_proxy(upstream, inject_foreign("secure.test.")).await;
    let mut config = signed_config(&h);
    config
        .nameserver_addr_overrides
        .insert(name("ns1.secure.test."), proxy);
    let r = Resolver::new(config).await.unwrap();
    assert_clean_fresh_and_cached(&r, "www.secure.test.", DnssecStatus::Secure).await;
}

#[tokio::test]
async fn injected_records_are_dropped_from_an_unsigned_zone() {
    let h = Hierarchy::start_signed(&[ChildVariant::Insecure])
        .await
        .unwrap();
    let upstream = h.server("insecure.test.").unwrap().addr();
    let proxy = forge_proxy(upstream, inject_foreign("insecure.test.")).await;
    let mut config = signed_config(&h);
    config
        .nameserver_addr_overrides
        .insert(name("ns1.insecure.test."), proxy);
    let r = Resolver::new(config).await.unwrap();
    // Insecure: never AD, but bailiwick scrubbing applies all the same.
    assert_clean_fresh_and_cached(&r, "www.insecure.test.", DnssecStatus::Insecure).await;
}

#[tokio::test]
async fn injected_records_are_dropped_with_validation_off() {
    let h = Hierarchy::start().await.unwrap();
    let upstream = h.server("example.test.").unwrap().addr();
    let proxy = forge_proxy(upstream, inject_foreign("example.test.")).await;
    let mut config = plain_config(&h);
    config
        .nameserver_addr_overrides
        .insert(name("ns1.example.test."), proxy);
    let r = Resolver::new(config).await.unwrap();
    assert_clean_fresh_and_cached(&r, "www.example.test.", DnssecStatus::Indeterminate).await;
}

#[tokio::test]
async fn injected_records_are_dropped_from_a_negative_answer() {
    let h = Hierarchy::start_signed(&[ChildVariant::Secure])
        .await
        .unwrap();
    let upstream = h.server("secure.test.").unwrap().addr();
    let inject: Mutate = Arc::new(|_, qtype, m: &mut Message| {
        if qtype == RecordType::A && m.rcode() == Rcode::NXDOMAIN {
            m.answers.push(a_record("www.bank.test.", EVIL_IP));
            m.authorities.push(a_record("www.bank.test.", EVIL_IP));
            m.additionals.push(a_record("www.bank.test.", EVIL_IP));
        }
    });
    let proxy = forge_proxy(upstream, inject).await;
    let mut config = signed_config(&h);
    config
        .nameserver_addr_overrides
        .insert(name("ns1.secure.test."), proxy);
    let r = Resolver::new(config).await.unwrap();
    for pass in 0..2 {
        let ans = ask(&r, "nope.secure.test.", RecordType::A, DO).await;
        assert_eq!(ans.source == AnswerSource::Cache, pass == 1);
        assert_eq!(ans.message.rcode(), Rcode::NXDOMAIN);
        assert_eq!(ans.dnssec, DnssecStatus::Secure);
        assert!(ans.message.header.ad);
        assert!(ans.message.answers.is_empty(), "{:?}", ans.message);
        assert!(ans.message.additionals.is_empty());
        assert!(
            ans.message.authorities.iter().all(|r| {
                name("secure.test.").zone_of(&r.name)
                    && matches!(
                        r.rtype,
                        RecordType::SOA | RecordType::NSEC | RecordType::RRSIG
                    )
            }),
            "{:?}",
            ans.message.authorities
        );
        assert!(
            ans.message
                .authorities
                .iter()
                .any(|r| r.rtype == RecordType::SOA)
        );
    }
}

/// A forward target that answers `qname A` and adds foreign records.
async fn injecting_target() -> SocketAddr {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        loop {
            let Ok((len, from)) = socket.recv_from(&mut buf).await else {
                return;
            };
            let q = Message::decode(&buf[..len]).unwrap();
            let mut m = Message::response_to(&q);
            m.header.ra = true;
            m.answers
                .push(a_record(&q.questions[0].name.to_string(), LO));
            m.answers.push(a_record("www.bank.test.", EVIL_IP));
            m.authorities.push(a_record("www.bank.test.", EVIL_IP));
            m.additionals.push(a_record("www.bank.test.", EVIL_IP));
            socket.send_to(&m.encode().unwrap(), from).await.unwrap();
        }
    });
    addr
}

#[tokio::test]
async fn forwarded_answers_are_scrubbed() {
    let target = injecting_target().await;
    let config = ResolverConfig {
        forward_zones: vec![ForwardZone {
            zone: name("corp.test."),
            targets: vec![target],
            validate: false,
        }],
        ..ResolverConfig::default()
    };
    let r = Resolver::new(ResolverConfig {
        root_hints: vec![target],
        query_timeout: Duration::from_millis(200),
        ..config
    })
    .await
    .unwrap();
    for pass in 0..2 {
        let ans = ask(&r, "host.corp.test.", RecordType::A, DO).await;
        assert_eq!(ans.source == AnswerSource::Cache, pass == 1);
        assert_no_foreign(&ans, "host.corp.test.");
        assert_eq!(ans.message.answers.len(), 1);
        assert!(ans.message.authorities.is_empty());
        assert!(!ans.message.header.ad);
    }
}

// ===========================================================================
// 2. The rcode is not signed
// ===========================================================================

fn flip_to_nxdomain() -> Mutate {
    Arc::new(|_, qtype, m: &mut Message| {
        if qtype == RecordType::A && m.header.aa && m.rcode() == Rcode::NOERROR {
            m.set_rcode(Rcode::NXDOMAIN).unwrap();
        }
    })
}

#[tokio::test]
async fn rcode_flipped_on_a_validated_answer_is_bogus() {
    for (variant, zone) in [
        (ChildVariant::Secure, "secure.test."),
        (ChildVariant::Nsec3, "nsec3.test."),
    ] {
        let h = Hierarchy::start_signed(&[variant]).await.unwrap();
        let upstream = h.server(zone).unwrap().addr();
        let proxy = forge_proxy(upstream, flip_to_nxdomain()).await;
        let mut config = signed_config(&h);
        config
            .nameserver_addr_overrides
            .insert(name(&format!("ns1.{zone}")), proxy);
        let r = Resolver::new(config).await.unwrap();
        let ans = ask(&r, &format!("www.{zone}"), RecordType::A, DO).await;
        assert_eq!(ans.dnssec, DnssecStatus::Bogus, "{zone}");
        assert_eq!(ans.message.rcode(), Rcode::SERVFAIL);
        assert!(!ans.message.header.ad);
        let ede = ans.ede.unwrap();
        assert_eq!(ede.code, 6);
        assert_eq!(ede.text.as_deref(), Some("dnssec.rcode_mismatch"));
    }
}

#[tokio::test]
async fn rcode_flipped_by_every_server_of_an_insecure_zone_is_a_failure() {
    let h = Hierarchy::start_signed(&[ChildVariant::Insecure])
        .await
        .unwrap();
    let upstream = h.server("insecure.test.").unwrap().addr();
    let proxy = forge_proxy(upstream, flip_to_nxdomain()).await;
    let mut config = signed_config(&h);
    config
        .nameserver_addr_overrides
        .insert(name("ns1.insecure.test."), proxy);
    let r = Resolver::new(config).await.unwrap();
    // The only server is treated as broken: no NXDOMAIN reaches the client.
    let err = r
        .resolve(&query("www.insecure.test.", RecordType::A), DO)
        .await
        .unwrap_err();
    assert!(matches!(err, ResolveError::Unreachable { .. }), "{err:?}");
}

#[tokio::test]
async fn rcode_flipping_server_is_skipped_for_the_next_one() {
    let mut specs = default_servers().unwrap();
    let mut example = None;
    for spec in &mut specs {
        match spec.zone.origin().to_string().as_str() {
            "test." => {
                spec.zone = spec
                    .zone
                    .clone()
                    .with_ns("example.test.", "ns2.example.test.")
                    .unwrap()
                    .with_a("ns2.example.test.", LO)
                    .unwrap();
            }
            "example.test." => example = Some(spec.zone.clone()),
            _ => {}
        }
    }
    specs.push(ServerSpec::new("ns2.example.test.", example.unwrap()).unwrap());
    let h = Hierarchy::start_with(specs).await.unwrap();
    let real1 = overrides(&h)[&name("ns1.example.test.")];
    let proxy = forge_proxy(real1, flip_to_nxdomain()).await;
    let mut config = plain_config(&h);
    config
        .nameserver_addr_overrides
        .insert(name("ns1.example.test."), proxy);
    let r = Resolver::new(config).await.unwrap();
    for _ in 0..5 {
        r.flush(dnscraft_resolver::FlushScope::All);
        let ans = ask(&r, "www.example.test.", RecordType::A, DO).await;
        assert_eq!(ans.message.rcode(), Rcode::NOERROR);
        assert_eq!(ans.message.answers.len(), 1);
    }
}

// ===========================================================================
// 3. Synthesized CNAME below a DNAME
// ===========================================================================

/// Root and `test.` signed; `test.` holds `alias.test. DNAME target.test.`
/// and `host.target.test. A`. Returns the hierarchy and its trust anchors.
async fn dname_hierarchy() -> (Hierarchy, TrustAnchors) {
    let alg = dnscraft_testkit::SigAlgorithm::default();
    let root_key = ZoneKey::generate(alg).unwrap();
    let test_key = ZoneKey::generate(alg).unwrap();
    let target = name("target.test.").as_wire().to_vec();
    let dname = hickory_proto::rr::Record::from_rdata(
        parse_name("alias.test.").unwrap(),
        3600,
        hickory_proto::rr::RData::Unknown {
            code: hickory_proto::rr::RecordType::from(39u16),
            rdata: hickory_proto::rr::rdata::NULL::with(target),
        },
    );
    let test = Zone::new("test.")
        .unwrap()
        .with_soa("ns1.test.", "hostmaster.test.")
        .unwrap()
        .with_ns("test.", "ns1.test.")
        .unwrap()
        .with_a("ns1.test.", LO)
        .unwrap()
        .with_record(dname)
        .with_a("host.target.test.", Ipv4Addr::new(192, 0, 2, 50))
        .unwrap();
    let test = sign_zone(test, &test_key, &SigningOptions::now()).unwrap();
    let root = Zone::new(".")
        .unwrap()
        .with_soa("a.root-servers.net.", "hostmaster.root-servers.net.")
        .unwrap()
        .with_ns(".", "a.root-servers.net.")
        .unwrap()
        .with_a("a.root-servers.net.", LO)
        .unwrap()
        .with_ns("test.", "ns1.test.")
        .unwrap()
        .with_a("ns1.test.", LO)
        .unwrap()
        .with_record(test_key.ds_record(&parse_name("test.").unwrap()).unwrap());
    let root = sign_zone(root, &root_key, &SigningOptions::now()).unwrap();
    let anchors = anchors_from(
        &root_key.ds(&parse_name(".").unwrap()).unwrap(),
        &Name::root(),
    );
    let h = Hierarchy::start_with(vec![
        ServerSpec::new("a.root-servers.net.", root).unwrap(),
        ServerSpec::new("ns1.test.", test).unwrap(),
    ])
    .await
    .unwrap();
    (h, anchors)
}

/// A proxy in front of the `test.` server that answers every name below
/// `alias.test.` like a server doing DNAME synthesis, except that the
/// synthesized CNAME points at `host.evil.test.` instead of
/// `<label>.target.test.`.
async fn forged_dname_proxy(upstream: SocketAddr) -> SocketAddr {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();
    let genuine = raw_query(upstream, "alias.test.", RecordType::from(39u16))
        .await
        .answers;
    assert!(genuine.len() >= 2, "DNAME and its RRSIG expected");
    tokio::spawn(async move {
        let mut buf = vec![0u8; 8192];
        loop {
            let Ok((len, from)) = socket.recv_from(&mut buf).await else {
                return;
            };
            let q = Message::decode(&buf[..len]).unwrap();
            let qname = q.questions[0].name.clone();
            let below = name("alias.test.").zone_of(&qname) && qname != name("alias.test.");
            let response = if below {
                let mut m = Message::response_to(&q);
                m.header.aa = true;
                m.answers = genuine.clone();
                m.answers.push(Record {
                    name: qname,
                    rtype: RecordType::CNAME,
                    class: Class::IN,
                    ttl: 3600,
                    rdata: RData::CNAME(name("host.evil.test.")),
                });
                m
            } else {
                let up = UdpSocket::bind("127.0.0.1:0").await.unwrap();
                up.send_to(&buf[..len], upstream).await.unwrap();
                let mut rbuf = vec![0u8; 8192];
                let Ok(Ok((rlen, _))) =
                    timeout(Duration::from_secs(2), up.recv_from(&mut rbuf)).await
                else {
                    continue;
                };
                Message::decode(&rbuf[..rlen]).unwrap()
            };
            socket
                .send_to(&response.encode().unwrap(), from)
                .await
                .unwrap();
        }
    });
    addr
}

async fn dname_resolver() -> (Hierarchy, Resolver) {
    let (h, anchors) = dname_hierarchy().await;
    let proxy = forged_dname_proxy(h.server("test.").unwrap().addr()).await;
    let mut config = plain_config(&h);
    config.trust_anchors = anchors;
    config
        .nameserver_addr_overrides
        .insert(name("ns1.test."), proxy);
    let r = Resolver::new(config).await.unwrap();
    (h, r)
}

fn cname_targets(ans: &Answer) -> Vec<Name> {
    ans.message
        .answers
        .iter()
        .filter_map(|r| match &r.rdata {
            RData::CNAME(t) => Some(t.clone()),
            _ => None,
        })
        .collect()
}

#[tokio::test]
async fn forged_synthesized_cname_is_replaced_for_qtype_a() {
    let (_h, r) = dname_resolver().await;
    let ans = ask(&r, "host.alias.test.", RecordType::A, DO).await;
    assert_eq!(ans.dnssec, DnssecStatus::Secure, "{:?}", ans.ede);
    assert_eq!(cname_targets(&ans), vec![name("host.target.test.")]);
    assert!(
        ans.message
            .answers
            .iter()
            .any(|r| r.rdata == RData::A(Ipv4Addr::new(192, 0, 2, 50)))
    );
    assert!(all_records(&ans).all(|r| r.name != name("host.evil.test.")));
}

#[tokio::test]
async fn forged_synthesized_cname_is_replaced_for_qtype_cname() {
    let (_h, r) = dname_resolver().await;
    let ans = ask(&r, "host.alias.test.", RecordType::CNAME, DO).await;
    assert_eq!(ans.dnssec, DnssecStatus::Secure, "{:?}", ans.ede);
    // The DNAME and the resolver's own synthesis; nothing the server made up.
    assert_eq!(cname_targets(&ans), vec![name("host.target.test.")]);
    assert!(
        ans.message
            .answers
            .iter()
            .any(|r| r.rtype == RecordType::from(39u16)),
        "{:?}",
        ans.message.answers
    );
    assert_eq!(ans.message.answers.len(), 3, "DNAME, RRSIG, CNAME");
}

// ===========================================================================
// 4. TTLs are bound to the signatures
// ===========================================================================

/// A signed hierarchy whose signatures are valid from `now - 1h` until
/// `now + lifetime` (shorter than the 300 s record TTL of the testkit zones), and a resolver driven by a manual clock at `now`.
async fn short_signature_resolver(
    lifetime: u32,
    ttl_min: u32,
) -> (Hierarchy, Resolver, Arc<ManualClock>) {
    let now = unix_now();
    let scenario = DnssecScenario::new(&[ChildVariant::Secure])
        .with_now(now)
        .with_validity(now - 3600, now + lifetime);
    let h = Hierarchy::start_scenario(&scenario).await.unwrap();
    let clock = Arc::new(ManualClock::new(
        UNIX_EPOCH + Duration::from_secs(u64::from(now)),
    ));
    let mut config = signed_config(&h);
    config.clock = clock.clone();
    config.ttl_min = ttl_min;
    let r = Resolver::new(config).await.unwrap();
    (h, r, clock)
}

fn ttl_of(ans: &Answer, rtype: RecordType) -> u32 {
    ans.message
        .answers
        .iter()
        .chain(&ans.message.authorities)
        .find(|r| r.rtype == rtype)
        .unwrap()
        .ttl
}

async fn assert_cache_follows_signature(ttl_min: u32) {
    let (_h, r, clock) = short_signature_resolver(60, ttl_min).await;
    let pos = ask(&r, "www.secure.test.", RecordType::A, DO).await;
    assert_eq!(pos.dnssec, DnssecStatus::Secure);
    assert!(ttl_of(&pos, RecordType::A) <= 60, "{:?}", pos.message);
    assert!(ttl_of(&pos, RecordType::A) > 0);
    let neg = ask(&r, "nope.secure.test.", RecordType::A, DO).await;
    assert_eq!(neg.message.rcode(), Rcode::NXDOMAIN);
    assert_eq!(neg.dnssec, DnssecStatus::Secure);
    assert!(ttl_of(&neg, RecordType::SOA) <= 60, "{:?}", neg.message);

    clock.advance(Duration::from_secs(50));
    assert_eq!(
        ask(&r, "www.secure.test.", RecordType::A, DO).await.source,
        AnswerSource::Cache
    );
    clock.advance(Duration::from_secs(11));
    // 61 s: the signatures have expired and so must the cache entries.
    // Asking again goes upstream, where the expired signatures fail.
    let again = ask(&r, "www.secure.test.", RecordType::A, DO).await;
    assert_eq!(again.dnssec, DnssecStatus::Bogus, "{again:?}");
    let again = ask(&r, "nope.secure.test.", RecordType::A, DO).await;
    assert_eq!(again.dnssec, DnssecStatus::Bogus, "{again:?}");
}

#[tokio::test]
async fn ttl_and_cache_entry_do_not_outlive_the_signature() {
    assert_cache_follows_signature(0).await;
}

#[tokio::test]
async fn ttl_min_cannot_keep_an_entry_past_the_signature() {
    assert_cache_follows_signature(3600).await;
}

#[tokio::test]
async fn ttl_raised_by_a_forger_is_capped_to_the_original_ttl() {
    let h = Hierarchy::start_signed(&[ChildVariant::Secure])
        .await
        .unwrap();
    let upstream = h.server("secure.test.").unwrap().addr();
    let raise: Mutate = Arc::new(|_, qtype, m: &mut Message| {
        if qtype == RecordType::A {
            // The RRSIG's own TTL is raised too; its original-TTL field is signed.
            for r in &mut m.answers {
                r.ttl = 86_400;
            }
        }
    });
    let proxy = forge_proxy(upstream, raise).await;
    let now = unix_now();
    let clock = Arc::new(ManualClock::new(
        UNIX_EPOCH + Duration::from_secs(u64::from(now)),
    ));
    let mut config = signed_config(&h);
    config.clock = clock.clone();
    config
        .nameserver_addr_overrides
        .insert(name("ns1.secure.test."), proxy);
    let r = Resolver::new(config).await.unwrap();
    let ans = ask(&r, "www.secure.test.", RecordType::A, DO).await;
    assert_eq!(ans.dnssec, DnssecStatus::Secure);
    let original = ans
        .message
        .answers
        .iter()
        .find_map(|r| match &r.rdata {
            RData::RRSIG { original_ttl, .. } if r.rtype == RecordType::RRSIG => {
                Some(*original_ttl)
            }
            _ => None,
        })
        .unwrap();
    assert!(original < 86_400);
    assert!(ttl_of(&ans, RecordType::A) <= original, "{:?}", ans.message);
    clock.advance(Duration::from_secs(u64::from(original) + 1));
    assert_eq!(
        ask(&r, "www.secure.test.", RecordType::A, DO).await.source,
        AnswerSource::Recursion
    );
}

// ===========================================================================
// 5. Name server addresses learned from the network
// ===========================================================================

/// The default hierarchy with `ns1.test.` glue (and the in-zone address of
/// `ns1.test.`) replaced by `glue_ip` in the root zone.
async fn hierarchy_with_root_glue(glue_ip: Ipv4Addr) -> Hierarchy {
    let mut specs = default_servers().unwrap();
    for spec in &mut specs {
        if spec.zone.origin().is_root() {
            spec.zone = Zone::new(".")
                .unwrap()
                .with_soa("a.root-servers.net.", "hostmaster.root-servers.net.")
                .unwrap()
                .with_ns(".", "a.root-servers.net.")
                .unwrap()
                .with_a("a.root-servers.net.", LO)
                .unwrap()
                .with_ns("test.", "ns1.test.")
                .unwrap()
                .with_a("ns1.test.", glue_ip)
                .unwrap();
        }
    }
    Hierarchy::start_with(specs).await.unwrap()
}

/// Config whose overrides cover only the root server, so the glue for
/// `ns1.test.` is subject to the address filter.
fn root_only_config(h: &Hierarchy) -> ResolverConfig {
    let mut config = plain_config(h);
    config
        .nameserver_addr_overrides
        .retain(|n, _| *n == name("a.root-servers.net."));
    config
}

async fn queries_sent_for(config: ResolverConfig) -> (u64, Result<Answer, ResolveError>) {
    let r = Resolver::new(config).await.unwrap();
    let before = r.stats().outgoing_queries;
    let result = r
        .resolve(
            &query("www.example.test.", RecordType::A),
            RequestFlags::default(),
        )
        .await;
    (r.stats().outgoing_queries - before, result)
}

#[tokio::test]
async fn loopback_and_private_glue_from_the_network_is_not_queried() {
    for ip in [
        Ipv4Addr::new(127, 0, 0, 1),
        Ipv4Addr::new(10, 0, 0, 1),
        Ipv4Addr::new(192, 168, 1, 1),
        Ipv4Addr::new(100, 64, 0, 1),
        Ipv4Addr::new(169, 254, 1, 1),
    ] {
        let h = hierarchy_with_root_glue(ip).await;
        let (sent, result) = queries_sent_for(root_only_config(&h)).await;
        // Only the question to the root: the referral names no usable server.
        assert_eq!(sent, 1, "{ip}: queried the glue address");
        assert!(
            matches!(result, Err(ResolveError::Unreachable { .. })),
            "{ip}: {result:?}"
        );
        assert!(h.server("test.").unwrap().queries().is_empty());
    }
}

#[tokio::test]
async fn allow_private_nameservers_re_enables_private_glue_only() {
    let private = hierarchy_with_root_glue(Ipv4Addr::new(10, 0, 0, 1)).await;
    let mut config = root_only_config(&private);
    config.allow_private_nameservers = true;
    config.query_timeout = Duration::from_millis(100);
    let (sent, _) = queries_sent_for(config).await;
    assert!(sent >= 2, "the private address was not tried: {sent}");

    // Loopback stays refused even with the flag.
    let loopback = hierarchy_with_root_glue(Ipv4Addr::new(127, 0, 0, 1)).await;
    let mut config = root_only_config(&loopback);
    config.allow_private_nameservers = true;
    let (sent, _) = queries_sent_for(config).await;
    assert_eq!(sent, 1);
}

#[tokio::test]
async fn resolution_uses_the_usable_servers_of_a_referral() {
    let mut specs = default_servers().unwrap();
    for spec in &mut specs {
        if spec.zone.origin().is_root() {
            spec.zone = Zone::new(".")
                .unwrap()
                .with_soa("a.root-servers.net.", "hostmaster.root-servers.net.")
                .unwrap()
                .with_ns(".", "a.root-servers.net.")
                .unwrap()
                .with_a("a.root-servers.net.", LO)
                .unwrap()
                .with_ns("test.", "ns1.test.")
                .unwrap()
                .with_a("ns1.test.", Ipv4Addr::new(10, 0, 0, 1))
                .unwrap()
                .with_ns("test.", "ns2.test.")
                .unwrap()
                .with_a("ns2.test.", LO)
                .unwrap();
        }
        if spec.zone.origin().to_string() == "test." {
            spec.ns_name = parse_name("ns2.test.").unwrap();
        }
    }
    let h = Hierarchy::start_with(specs).await.unwrap();
    let config = plain_config(&h);
    let (_, result) = queries_sent_for(config).await;
    assert_eq!(result.unwrap().message.answers.len(), 1);
}

// ===========================================================================
// 6. Root priming
// ===========================================================================

/// A proxy in front of the root server that edits the `. NS` answer.
async fn priming_forger(
    h: &Hierarchy,
    edit: impl Fn(&mut Message) + Send + Sync + 'static,
) -> SocketAddr {
    let mutate: Mutate = Arc::new(move |_, qtype, m: &mut Message| {
        if qtype == RecordType::NS {
            edit(m);
        }
    });
    forge_proxy(h.root_hints()[0], mutate).await
}

fn rogue_root(m: &mut Message) {
    for r in &mut m.answers {
        if r.rtype == RecordType::NS {
            r.rdata = RData::NS(name("b.root-servers.net."));
        }
    }
    m.additionals = vec![a_record(
        "b.root-servers.net.",
        Ipv4Addr::new(203, 0, 113, 9),
    )];
}

#[tokio::test]
async fn forged_priming_response_is_rejected_when_validating() {
    let h = Hierarchy::start_signed(&[ChildVariant::Secure])
        .await
        .unwrap();
    // The RRSIG stays but no longer matches the replaced NS RRset.
    let forged = priming_forger(&h, rogue_root).await;
    let mut config = signed_config(&h);
    config.root_hints = vec![forged];
    let r = Resolver::new(config).await.unwrap();
    assert_eq!(r.priming_status(), PrimingStatus::FellBack);

    // An unsigned reply (RRSIG removed) is no better.
    let unsigned = priming_forger(&h, |m| {
        m.answers.retain(|r| r.rtype != RecordType::RRSIG);
    })
    .await;
    let mut config = signed_config(&h);
    config.root_hints = vec![unsigned];
    let r = Resolver::new(config).await.unwrap();
    assert_eq!(r.priming_status(), PrimingStatus::FellBack);
}

#[tokio::test]
async fn genuine_signed_priming_response_is_accepted() {
    let h = Hierarchy::start_signed(&[ChildVariant::Secure])
        .await
        .unwrap();
    let r = Resolver::new(signed_config(&h)).await.unwrap();
    assert!(matches!(
        r.priming_status(),
        PrimingStatus::Primed { servers: 1, .. }
    ));
    let ans = ask(&r, "www.secure.test.", RecordType::A, DO).await;
    assert_eq!(ans.dnssec, DnssecStatus::Secure);
}

#[tokio::test]
async fn priming_takes_root_addresses_only_for_root_servers_net() {
    let h = Hierarchy::start().await.unwrap();
    let forged = priming_forger(&h, |m| {
        let mut extra = m.answers[0].clone();
        extra.rdata = RData::NS(name("ns.evil.example."));
        m.answers.push(extra);
        m.additionals
            .push(a_record("ns.evil.example.", Ipv4Addr::new(203, 0, 113, 9)));
    })
    .await;
    let mut config = plain_config(&h);
    config.root_hints = vec![forged];
    let r = Resolver::new(config).await.unwrap();
    assert!(matches!(
        r.priming_status(),
        PrimingStatus::Primed { servers: 1, .. }
    ));
}

#[tokio::test]
async fn root_set_is_primed_again_after_the_interval() {
    let h = Hierarchy::start().await.unwrap();
    let clock = Arc::new(ManualClock::new(SystemTime::now()));
    let mut config = plain_config(&h);
    config.clock = clock.clone();
    config.root_reprime_interval = Duration::from_secs(3600);
    let r = Resolver::new(config).await.unwrap();
    let ns_queries = || {
        h.server(".")
            .unwrap()
            .queries()
            .iter()
            .filter(|q| RecordType(u16::from(q.query_type)) == RecordType::NS && q.name.is_root())
            .count()
    };
    assert_eq!(ns_queries(), 1);
    ask(
        &r,
        "www.example.test.",
        RecordType::A,
        RequestFlags::default(),
    )
    .await;
    assert_eq!(ns_queries(), 1, "primed again too early");
    clock.advance(Duration::from_secs(3601));
    ask(
        &r,
        "www.example.test.",
        RecordType::AAAA,
        RequestFlags::default(),
    )
    .await;
    assert_eq!(ns_queries(), 2);
    assert!(matches!(r.priming_status(), PrimingStatus::Primed { .. }));
    // Not again until the next interval has passed.
    ask(&r, "ns1.test.", RecordType::A, RequestFlags::default()).await;
    assert_eq!(ns_queries(), 2);
}

// ===========================================================================
// 7. Overall deadline
// ===========================================================================

#[tokio::test]
async fn a_silent_server_ends_at_the_resolution_deadline() {
    let h = Hierarchy::start().await.unwrap();
    // The root hint is a proxy that goes silent after priming.
    let silent = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&silent);
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let front = socket.local_addr().unwrap();
    let upstream = h.root_hints()[0];
    tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        loop {
            let Ok((len, from)) = socket.recv_from(&mut buf).await else {
                return;
            };
            if flag.load(Ordering::SeqCst) {
                continue;
            }
            let up = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            up.send_to(&buf[..len], upstream).await.unwrap();
            let mut rbuf = vec![0u8; 4096];
            if let Ok(Ok((rlen, _))) =
                timeout(Duration::from_secs(1), up.recv_from(&mut rbuf)).await
            {
                socket.send_to(&rbuf[..rlen], from).await.unwrap();
            }
        }
    });
    let mut config = plain_config(&h);
    // No override for the root server: priming then keeps the hint (the
    // proxy) instead of switching to the real root address.
    config.nameserver_addr_overrides.clear();
    config.root_hints = vec![front];
    config.query_timeout = Duration::from_secs(5);
    config.resolve_deadline = Duration::from_millis(300);
    let r = Resolver::new(config).await.unwrap();
    silent.store(true, Ordering::SeqCst);
    let started = std::time::Instant::now();
    let err = r
        .resolve(
            &query("www.example.test.", RecordType::A),
            RequestFlags::default(),
        )
        .await
        .unwrap_err();
    let elapsed = started.elapsed();
    assert!(matches!(err, ResolveError::Unreachable { .. }), "{err:?}");
    assert_eq!(err.code(), "resolver.unreachable");
    assert!(elapsed < Duration::from_secs(2), "took {elapsed:?}");
}

#[tokio::test]
async fn zero_deadline_is_rejected() {
    let h = Hierarchy::start().await.unwrap();
    let mut config = plain_config(&h);
    config.resolve_deadline = Duration::ZERO;
    assert!(Resolver::new(config).await.is_err());
}
