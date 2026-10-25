//! DNSSEC validator tests (Task 9a): chain of trust against the testkit's signed
//! hierarchy and the real root DNSKEY RRset.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::net::SocketAddr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use dnscraft_proto::dnssec::key_tag;
use dnscraft_proto::{Class, Edns, Message, Name, RData, Record, RecordType};
use dnscraft_resolver::dnssec::{
    ChainFailure, DelegationTrust, DsStatus, InsecureReason, KeysOutcome, MAX_KEYS_PER_TAG,
    MAX_SIGS_PER_RRSET, TrustAnchors, ValidatedKeys, ValidationBudget, VerifyFailure, ds_status,
    validate_dnskey_rrset, validate_dnskey_rrset_budgeted, validate_rrset, validate_rrset_budgeted,
    verify_rrsig,
};
use dnscraft_resolver::{DnssecStatus, ManualClock, Query, RequestFlags, Resolver, ResolverConfig};
use dnscraft_testkit::{ChildVariant, DnssecScenario, Hierarchy, SigAlgorithm};
use hickory_proto::serialize::binary::BinEncodable;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::time::timeout;

// Real root DNSKEY RRset fixture (see crates/dnscraft-proto/tests/dnssec_vectors.rs).
const KSK_20326: &str = "AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3+/4RgWOq7HrxRixHlFlExOLAJr5emLvN7SWXgnLh4+B5xQlNVz8Og8kvArMtNROxVQuCaSnIDdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF0jLHwVN8efS3rCj/EWgvIWgb9tarpVUDK/b58Da+sqqls3eNbuv7pr+eoZG+SrDK6nWeL3c6H5Apxz7LjVc1uTIdsIXxuOLYA4/ilBmSVIzuDWfdRUfhHdY6+cn8HFRm+2hM8AnXGXws9555KrUB5qihylGa8subX2Nn6UwNR1AkUTV74bU=";
const KSK_38696: &str = "AwEAAa96jeuknZlaeSrvyAJj6ZHv28hhOKkx3rLGXVaC6rXTsDc449/cidltpkyGwCJNnOAlFNKF2jBosZBU5eeHspaQWOmOElZsjICMQMC3aeHbGiShvZsx4wMYSjH8e7Vrhbu6irwCzVBApESjbUdpWWmEnhathWu1jo+siFUiRAAxm9qyJNg/wOZqqzL/dL/q8PkcRU5oUKEpUge71M3ej2/7CPqpdVwuMoTvoB+ZOT4YeGyxMvHmbrxlFzGOHOijtzN+u1TQNatX2XBuzZNQ1K+s2CXkPIZo7s6JgZyvaBevYtxPvYLw4z9mR7K2vaF18UYH9Z9GNUUeayffKC73PYc=";
const ZSK_8763: &str = "AwEAAcorNxNc9t0ue1ZenPjVMRujlQ2YLBJ0pR/4XMjHby9vr03cRxFSKnWpxeg5PL384D9VeqdS1bjrGyTsHtoagzI3NiXFd8sjHMOnZxu5pp/+UBIg7tasYgVMMdUiM1Yu/c+t30d1Qw/v6NYLNnOnywTu6HuUh7Y1sZRq/GZcrxLENXHQoyKpOrOr8R3+qd6wK69IKB80ZBZtkX9rdEqKJk+yYXjEZzZ0zkAFthmNgCreAoU9PVlU66dyOsaLjf3wKUlUm9SNOKs+tK6LuSmRbK6+1T/tPaRaMBSEuv2G6vXfnJ1uyMbGvtpRn/YDcvTjrp6DzE6XyF44QdwJ3oKx4ek=";
const RRSIG_38696: &str = "VHYFWQzxvfICyEMAwDCqNJCoASexi9RUJqXLc8rsaEpX4x2J2YkgxJzMHN1HsXXmnLC7eqbdERKWI5wm/KzoFhDzY4F4TZB91tzN3gTDdDlIWvJi2GeUxfWj5MK/FalRoE9QX8EMjkVJPjqbxoeJ7yog7Yy+3z5vo4e+OeqcPHniyc90+cxo6fE6nLeFIQxicSrEBLkPMX7jA2ipXynVxJepQT/Qkzos7HL0N1xeHR3z3nfeH2JyFKz9moc6fSb4x0gDf9cbnFNJ5vbIttuxCEMcC4oWa/HNHPYeYHKKaLJ040QmaQGBJG59X77u0+FznsPxHLOdUjTQ9Ab4UvTYIA==";

fn b64(s: &str) -> Vec<u8> {
    let mut out = Vec::new();
    let (mut acc, mut bits) = (0u32, 0u32);
    for c in s.bytes().filter(|&c| c != b'=') {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => panic!("bad base64"),
        };
        acc = acc << 6 | u32::from(v);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((acc >> bits) & 0xFF) as u8);
        }
    }
    out
}

fn name(s: &str) -> Name {
    Name::from_ascii(s).unwrap()
}

fn root_dnskey(flags: u16, key: &str) -> Record {
    Record {
        name: Name::root(),
        class: Class::IN,
        ttl: 2567,
        rdata: RData::DNSKEY {
            flags,
            protocol: 3,
            algorithm: 8,
            public_key: b64(key).into(),
        },
    }
}

fn real_root() -> (Vec<Record>, Record) {
    let set = vec![
        root_dnskey(256, ZSK_8763),
        root_dnskey(257, KSK_20326),
        root_dnskey(257, KSK_38696),
    ];
    let sig = Record {
        name: Name::root(),
        class: Class::IN,
        ttl: 2567,
        rdata: RData::RRSIG {
            type_covered: RecordType::DNSKEY,
            algorithm: 8,
            labels: 0,
            original_ttl: 172_800,
            expiration: 1_794_355_200,
            inception: 1_792_540_800,
            key_tag: 38696,
            signer_name: Name::root(),
            signature: b64(RRSIG_38696).into(),
        },
    };
    (set, sig)
}

fn at(secs: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(secs)
}

/// Sends a DO query and returns (answer RRset of `qtype`, all RRSIGs of the answer).
async fn fetch(server: SocketAddr, qname: &str, qtype: RecordType) -> (Vec<Record>, Vec<Record>) {
    let mut q = Message::query(7, name(qname), qtype);
    q.header.rd = false;
    let mut edns = Edns::new(4096);
    edns.dnssec_ok = true;
    q.edns = Some(edns);
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    socket.send_to(&q.encode().unwrap(), server).await.unwrap();
    let mut buf = vec![0u8; 8192];
    let (len, _) = timeout(Duration::from_secs(2), socket.recv_from(&mut buf))
        .await
        .unwrap()
        .unwrap();
    let m = Message::decode(&buf[..len]).unwrap();
    let rrset = m
        .answers
        .iter()
        .filter(|r| r.rtype() == qtype)
        .cloned()
        .collect();
    let sigs = m
        .answers
        .iter()
        .filter(|r| r.rtype() == RecordType::RRSIG)
        .cloned()
        .collect();
    (rrset, sigs)
}

fn anchors_of(h: &Hierarchy) -> TrustAnchors {
    let a = h.trust_anchor().unwrap();
    let rdata = |rtype, bytes: Vec<u8>| RData::decode(&bytes, rtype, 0, bytes.len()).unwrap();
    let ds = Record {
        name: Name::root(),
        class: Class::IN,
        ttl: 3600,
        rdata: rdata(RecordType::DS, a.ds.to_bytes().unwrap()),
    };
    TrustAnchors::from_records(&[ds]).unwrap()
}

fn secure(o: KeysOutcome) -> ValidatedKeys {
    match o {
        KeysOutcome::Secure(k) => k,
        other => panic!("not secure: {other:?}"),
    }
}

struct Chain {
    h: Hierarchy,
    now: SystemTime,
}

impl Chain {
    async fn start(variants: &[ChildVariant], alg: Option<SigAlgorithm>) -> Self {
        let mut s = DnssecScenario::new(variants);
        if let Some(a) = alg {
            s = s.with_algorithm(a);
        }
        Self {
            h: Hierarchy::start_scenario(&s).await.unwrap(),
            now: SystemTime::now(),
        }
    }

    fn addr(&self, zone: &str) -> SocketAddr {
        if zone == "." {
            self.h.root_hints()[0]
        } else {
            self.h.server(zone).unwrap().addr()
        }
    }

    /// Validated keys for `zone` ("." or "test." ...), walking down from the root anchor.
    async fn keys(&self, zone: &str) -> Result<KeysOutcome, ChainFailure> {
        let anchors = anchors_of(&self.h);
        let (dk, ds) = fetch(self.addr("."), ".", RecordType::DNSKEY).await;
        let root = secure(
            validate_dnskey_rrset(
                &Name::root(),
                &dk,
                &ds,
                DelegationTrust::Anchors(&anchors),
                self.now,
            )
            .unwrap(),
        );
        let mut parent = root;
        let mut parent_name = ".".to_owned();
        let mut path = vec![];
        let mut cur = name(zone);
        while !cur.is_root() {
            path.push(cur.clone());
            cur = cur.parent().unwrap();
        }
        path.reverse();
        let mut last = KeysOutcome::Secure(parent.clone());
        for z in path {
            let zs = z.to_string();
            let (ds_set, ds_sigs) = fetch(self.addr(&parent_name), &zs, RecordType::DS).await;
            validate_rrset(&ds_set, &ds_sigs, &parent, self.now).expect("DS validates");
            let (dk, sigs) = fetch(self.addr(&zs), &zs, RecordType::DNSKEY).await;
            last = validate_dnskey_rrset(&z, &dk, &sigs, DelegationTrust::Ds(&ds_set), self.now)?;
            match &last {
                KeysOutcome::Secure(k) => parent = k.clone(),
                KeysOutcome::Insecure(_) => return Ok(last),
            }
            parent_name = zs;
        }
        Ok(last)
    }
}

async fn full_chain(alg: Option<SigAlgorithm>) {
    let c = Chain::start(&[ChildVariant::Secure], alg).await;
    let keys = secure(c.keys("secure.test.").await.unwrap());
    let (a, sigs) = fetch(c.addr("secure.test."), "www.secure.test.", RecordType::A).await;
    assert!(!a.is_empty() && !sigs.is_empty());
    let v = validate_rrset(&a, &sigs, &keys, c.now).unwrap();
    assert_eq!(v.signer, name("secure.test."));
    assert_eq!(v.wildcard, None);
}

#[tokio::test]
async fn chain_secure_ecdsa() {
    full_chain(None).await;
}

#[tokio::test]
async fn chain_secure_rsa() {
    full_chain(Some(SigAlgorithm::RsaSha256)).await;
}

#[tokio::test]
async fn chain_secure_ed25519() {
    full_chain(Some(SigAlgorithm::Ed25519)).await;
}

#[tokio::test]
async fn chain_wildcard_expansion_reported() {
    let c = Chain::start(&[ChildVariant::Secure], None).await;
    let keys = secure(c.keys("secure.test.").await.unwrap());
    let (a, sigs) = fetch(c.addr("secure.test."), "x.wild.secure.test.", RecordType::A).await;
    assert!(!a.is_empty());
    let v = validate_rrset(&a, &sigs, &keys, c.now).unwrap();
    assert_eq!(v.wildcard, Some(name("*.wild.secure.test.")));
}

#[tokio::test]
async fn chain_rejects_tampered_rrset_and_wrong_time() {
    let c = Chain::start(&[ChildVariant::Secure], None).await;
    let keys = secure(c.keys("secure.test.").await.unwrap());
    let (mut a, sigs) = fetch(c.addr("secure.test."), "www.secure.test.", RecordType::A).await;
    let day = 86_400;
    let now = c.now.duration_since(UNIX_EPOCH).unwrap().as_secs();
    assert_eq!(
        validate_rrset(&a, &sigs, &keys, at(now + 60 * day)).unwrap_err(),
        VerifyFailure::Expired
    );
    assert_eq!(
        validate_rrset(&a, &sigs, &keys, at(now - 2 * day)).unwrap_err(),
        VerifyFailure::NotYetValid
    );
    a[0].rdata = RData::A("192.0.2.200".parse().unwrap());
    assert_eq!(
        validate_rrset(&a, &sigs, &keys, c.now).unwrap_err(),
        VerifyFailure::BadSignature
    );
    assert_eq!(
        validate_rrset(&a, &[], &keys, c.now).unwrap_err(),
        VerifyFailure::NoSignatures
    );
}

#[tokio::test]
async fn chain_bogus_sig() {
    let c = Chain::start(&[ChildVariant::BogusSig], None).await;
    let keys = secure(c.keys("bogus-sig.test.").await.unwrap());
    let (a, sigs) = fetch(
        c.addr("bogus-sig.test."),
        "www.bogus-sig.test.",
        RecordType::A,
    )
    .await;
    let e = validate_rrset(&a, &sigs, &keys, c.now).unwrap_err();
    assert_eq!(e, VerifyFailure::BadSignature);
    assert_eq!(e.ede_code(), 6);
}

#[tokio::test]
async fn chain_bogus_expired() {
    let c = Chain::start(&[ChildVariant::BogusExpired], None).await;
    // The DNSKEY RRset itself is expired, so the chain breaks at the zone apex.
    let e = c.keys("bogus-expired.test.").await.unwrap_err();
    assert_eq!(e, ChainFailure::Verify(VerifyFailure::Expired));
    assert_eq!(e.ede_code(), 7);
}

#[tokio::test]
async fn chain_bogus_nokey() {
    let c = Chain::start(&[ChildVariant::BogusNoKey], None).await;
    let e = c.keys("bogus-nokey.test.").await.unwrap_err();
    assert_eq!(e, ChainFailure::DsNoMatch);
    assert_eq!(e.ede_code(), 9);
}

#[tokio::test]
async fn chain_insecure_delegation_has_no_ds() {
    let c = Chain::start(&[ChildVariant::Insecure, ChildVariant::Secure], None).await;
    let (ds, _) = fetch(c.addr("test."), "insecure.test.", RecordType::DS).await;
    assert!(ds.is_empty());
    assert_eq!(ds_status(&ds), DsStatus::Absent);
    let (ds, _) = fetch(c.addr("test."), "secure.test.", RecordType::DS).await;
    assert_eq!(ds_status(&ds), DsStatus::Usable);
}

fn dnskey_rec(owner: &str, alg: u8, key: Vec<u8>) -> Record {
    Record {
        name: name(owner),
        class: Class::IN,
        ttl: 300,
        rdata: RData::DNSKEY {
            flags: 257,
            protocol: 3,
            algorithm: alg,
            public_key: key.into(),
        },
    }
}

#[test]
fn chain_unsupported_algorithm_is_insecure_not_bogus() {
    // Algorithm 5 (RSASHA1): DS and DNSKEY crafted by hand.
    let key = vec![1, 3, 0xAA, 0xBB, 0xCC, 0xDD];
    let dk = dnskey_rec("old.test.", 5, key.clone());
    let tag = key_tag(257, 3, 5, &key);
    let ds = Record {
        name: name("old.test."),
        class: Class::IN,
        ttl: 300,
        rdata: RData::DS {
            key_tag: tag,
            algorithm: 5,
            digest_type: 1,
            digest: vec![0; 20].into(),
        },
    };
    assert_eq!(
        ds_status(std::slice::from_ref(&ds)),
        DsStatus::Unsupported(InsecureReason::UnsupportedAlgorithm(5))
    );
    let out = validate_dnskey_rrset(
        &name("old.test."),
        std::slice::from_ref(&dk),
        &[],
        DelegationTrust::Ds(std::slice::from_ref(&ds)),
        SystemTime::now(),
    )
    .unwrap();
    assert_eq!(
        out,
        KeysOutcome::Insecure(InsecureReason::UnsupportedAlgorithm(5))
    );
    assert_eq!(InsecureReason::UnsupportedAlgorithm(5).ede_code(), 1);

    // Unsupported digest type (3 = GOST) with a supported algorithm.
    let ds3 = Record {
        rdata: RData::DS {
            key_tag: 1,
            algorithm: 13,
            digest_type: 3,
            digest: vec![0; 32].into(),
        },
        ..ds.clone()
    };
    assert_eq!(
        ds_status(&[ds3]),
        DsStatus::Unsupported(InsecureReason::UnsupportedDigest(3))
    );

    // A direct RRSIG check reports UnsupportedAlgorithm, not BadSignature.
    let a = Record {
        name: name("www.old.test."),
        class: Class::IN,
        ttl: 300,
        rdata: RData::A("192.0.2.1".parse().unwrap()),
    };
    let sig = Record {
        name: a.name.clone(),
        class: Class::IN,
        ttl: 300,
        rdata: RData::RRSIG {
            type_covered: RecordType::A,
            algorithm: 5,
            labels: 3,
            original_ttl: 300,
            expiration: u32::MAX,
            inception: 0,
            key_tag: tag,
            signer_name: name("old.test."),
            signature: vec![0; 128].into(),
        },
    };
    let e = verify_rrsig(&[a], &sig, &dk, SystemTime::now()).unwrap_err();
    assert_eq!(e, VerifyFailure::UnsupportedAlgorithm(5));
    assert_eq!(e.ede_code(), 1);
}

#[test]
fn chain_root_anchors_validate_real_root_dnskey_set() {
    let (set, sig) = real_root();
    let anchors = TrustAnchors::iana_root();
    // One day after inception.
    let now = at(1_792_540_800 + 86_400);
    let out = validate_dnskey_rrset(
        &Name::root(),
        &set,
        std::slice::from_ref(&sig),
        DelegationTrust::Anchors(&anchors),
        now,
    )
    .unwrap();
    let keys = secure(out);
    assert_eq!(keys.keys().len(), 3);

    // Outside the window it fails with the matching reason.
    let e = validate_dnskey_rrset(
        &Name::root(),
        &set,
        std::slice::from_ref(&sig),
        DelegationTrust::Anchors(&anchors),
        at(1_794_355_200 + 10),
    )
    .unwrap_err();
    assert_eq!(e, ChainFailure::Verify(VerifyFailure::Expired));

    // Tampering with a key breaks the signature (the KSK still matches its DS
    // only if untouched, so tamper with the ZSK).
    let mut bad = set.clone();
    if let RData::DNSKEY { public_key, .. } = &mut bad[0].rdata {
        let mut k = public_key.to_vec();
        k[10] ^= 1;
        *public_key = k.into();
    }
    let e = validate_dnskey_rrset(
        &Name::root(),
        &bad,
        std::slice::from_ref(&sig),
        DelegationTrust::Anchors(&anchors),
        now,
    )
    .unwrap_err();
    assert_eq!(e, ChainFailure::Verify(VerifyFailure::BadSignature));

    // No anchor for another zone.
    assert_eq!(
        validate_dnskey_rrset(
            &name("com."),
            &set,
            &[],
            DelegationTrust::Anchors(&anchors),
            now
        )
        .unwrap_err(),
        ChainFailure::NoTrustAnchor
    );
}

#[test]
fn chain_dnskey_style_anchor_works() {
    let (set, sig) = real_root();
    let anchors = TrustAnchors::from_records(&[set[2].clone()]).unwrap();
    let out = validate_dnskey_rrset(
        &Name::root(),
        &set,
        std::slice::from_ref(&sig),
        DelegationTrust::Anchors(&anchors),
        at(1_792_540_800 + 86_400),
    )
    .unwrap();
    assert!(matches!(out, KeysOutcome::Secure(_)));
}

// ---------------------------------------------------------------------------
// Task 9b: validation status, AD, SERVFAIL + EDE, CD
// ---------------------------------------------------------------------------

fn status_config(h: &Hierarchy) -> ResolverConfig {
    let overrides = h
        .nameserver_addrs()
        .iter()
        .map(|(n, a)| (Name::from_ascii(&n.to_string()).unwrap(), *a))
        .collect();
    ResolverConfig {
        root_hints: h.root_hints(),
        query_timeout: Duration::from_millis(500),
        nameserver_addr_overrides: overrides,
        trust_anchors: anchors_of(h),
        ..ResolverConfig::default()
    }
}

async fn status_resolver(h: &Hierarchy) -> Resolver {
    Resolver::new(status_config(h)).await.unwrap()
}

async fn status_ask(r: &Resolver, qname: &str, flags: RequestFlags) -> dnscraft_resolver::Answer {
    let q = Query {
        name: name(qname),
        qtype: RecordType::A,
        qclass: Class::IN,
    };
    r.resolve(&q, flags).await.unwrap()
}

const DO: RequestFlags = RequestFlags {
    checking_disabled: false,
    dnssec_ok: true,
    client: None,
};

async fn status_secure(alg: Option<SigAlgorithm>) {
    let mut s = DnssecScenario::new(&[ChildVariant::Secure]);
    if let Some(a) = alg {
        s = s.with_algorithm(a);
    }
    let h = Hierarchy::start_scenario(&s).await.unwrap();
    let r = status_resolver(&h).await;
    let ans = status_ask(&r, "www.secure.test.", DO).await;
    assert_eq!(ans.dnssec, DnssecStatus::Secure);
    assert!(ans.message.header.ad);
    assert_eq!(ans.message.rcode(), dnscraft_proto::Rcode::NOERROR);
    assert!(ans.ede.is_none());
    assert_eq!(
        ans.message
            .answers
            .iter()
            .filter(|r| r.rtype() == RecordType::A)
            .count(),
        1
    );
}

#[tokio::test]
async fn status_secure_ecdsa() {
    status_secure(None).await;
}

#[tokio::test]
async fn status_secure_rsa() {
    status_secure(Some(SigAlgorithm::RsaSha256)).await;
}

#[tokio::test]
async fn status_secure_ed25519() {
    status_secure(Some(SigAlgorithm::Ed25519)).await;
}

#[tokio::test]
async fn status_insecure_child_has_no_ad() {
    let h = Hierarchy::start_signed(&[ChildVariant::Insecure])
        .await
        .unwrap();
    let r = status_resolver(&h).await;
    let ans = status_ask(&r, "www.insecure.test.", DO).await;
    assert_eq!(ans.dnssec, DnssecStatus::Insecure);
    assert!(!ans.message.header.ad);
    assert_eq!(ans.message.rcode(), dnscraft_proto::Rcode::NOERROR);
    assert_eq!(
        ans.message
            .answers
            .iter()
            .filter(|r| r.rtype() == RecordType::A)
            .count(),
        1
    );
    assert!(ans.ede.is_none());
}

#[tokio::test]
async fn status_insecure_stops_dnskey_fetches() {
    let h = Hierarchy::start_signed(&[ChildVariant::Insecure])
        .await
        .unwrap();
    let r = status_resolver(&h).await;
    // Priming validates the root NS set and so fetches the root DNSKEY once;
    // only the fetches of the resolution itself are counted.
    h.server(".").unwrap().clear_queries();
    status_ask(&r, "www.insecure.test.", DO).await;
    let asked_dnskey = |zone: &str| {
        h.server(zone)
            .unwrap()
            .queries()
            .iter()
            .filter(|q| RecordType(u16::from(q.query_type)) == RecordType::DNSKEY)
            .count()
    };
    assert_eq!(asked_dnskey("."), 1);
    assert_eq!(asked_dnskey("test."), 1);
    assert_eq!(asked_dnskey("insecure.test."), 0);
}

/// A UDP proxy that routes each query to the server of the longest matching
/// zone in `routes` (a DS query at a zone apex goes to the next shorter match,
/// like a server hosting parent and child), and optionally removes the
/// DS/NSEC/NSEC3/RRSIG records from referrals and DS responses (an attacker
/// trying to downgrade a signed child to insecure).
async fn proxy(routes: Vec<(Name, SocketAddr)>, strip: bool) -> SocketAddr {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 8192];
        loop {
            let Ok((len, from)) = socket.recv_from(&mut buf).await else {
                return;
            };
            let q = Message::decode(&buf[..len]).unwrap();
            let (qname, qtype) = (q.questions[0].name.clone(), q.questions[0].qtype);
            let upstream = routes
                .iter()
                .filter(|(zone, _)| zone.zone_of(&qname))
                .filter(|(zone, _)| !(qtype == RecordType::DS && *zone == qname))
                .max_by_key(|(zone, _)| zone.label_count())
                .map(|(_, a)| *a)
                .unwrap();
            let up = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            up.send_to(&buf[..len], upstream).await.unwrap();
            let mut rbuf = vec![0u8; 8192];
            let Ok(Ok((rlen, _))) = timeout(Duration::from_secs(2), up.recv_from(&mut rbuf)).await
            else {
                continue;
            };
            let mut m = Message::decode(&rbuf[..rlen]).unwrap();
            let is_ds_query = qtype == RecordType::DS;
            let is_referral =
                m.authorities.iter().any(|r| r.rtype() == RecordType::NS) && m.answers.is_empty();
            if strip && (is_referral || is_ds_query) {
                let strip = |r: &Record| {
                    matches!(
                        r.rtype(),
                        RecordType::DS | RecordType::NSEC | RecordType::NSEC3 | RecordType::RRSIG
                    )
                };
                m.authorities.retain(|r| !strip(r));
                if is_ds_query {
                    m.answers.retain(|r| !strip(r));
                }
            }
            socket.send_to(&m.encode().unwrap(), from).await.unwrap();
        }
    });
    addr
}

async fn strip_proxy(upstream: SocketAddr) -> SocketAddr {
    proxy(vec![(Name::root(), upstream)], true).await
}

async fn status_downgraded(variant: ChildVariant, qname: &str) -> dnscraft_resolver::Answer {
    let h = Hierarchy::start_signed(&[variant]).await.unwrap();
    let proxy = strip_proxy(h.server("test.").unwrap().addr()).await;
    let mut config = status_config(&h);
    config
        .nameserver_addr_overrides
        .insert(name("ns1.test."), proxy);
    let r = Resolver::new(config).await.unwrap();
    status_ask(&r, qname, DO).await
}

#[tokio::test]
async fn status_missing_ds_and_no_nsec_proof_is_bogus_not_insecure() {
    // Stripping the NSEC proof of an unsigned delegation must not be accepted as insecure.
    let ans = status_downgraded(ChildVariant::Insecure, "www.insecure.test.").await;
    assert_eq!(ans.dnssec, DnssecStatus::Bogus);
    assert_eq!(ans.message.rcode(), dnscraft_proto::Rcode::SERVFAIL);
    assert_eq!(ans.ede.unwrap().code, 12);
}

#[tokio::test]
async fn status_stripped_ds_of_signed_child_is_bogus_not_insecure() {
    let ans = status_downgraded(ChildVariant::Secure, "www.secure.test.").await;
    assert_eq!(ans.dnssec, DnssecStatus::Bogus);
    assert_eq!(ans.message.rcode(), dnscraft_proto::Rcode::SERVFAIL);
    assert!(ans.message.answers.is_empty());
}

#[tokio::test]
async fn status_insecure_sibling_does_not_taint_secure() {
    // The testkit has no signed zone below an unsigned one; the "once insecure,
    // always insecure" descent is covered by status_insecure_stops_dnskey_fetches.
    let h = Hierarchy::start_signed(&[ChildVariant::Insecure, ChildVariant::Secure])
        .await
        .unwrap();
    let r = status_resolver(&h).await;
    let ans = status_ask(&r, "www.insecure.test.", DO).await;
    assert_eq!(ans.dnssec, DnssecStatus::Insecure);
    let ans = status_ask(&r, "www.secure.test.", DO).await;
    assert_eq!(ans.dnssec, DnssecStatus::Secure);
}

async fn status_bogus(variant: ChildVariant, qname: &str, ede: u16, text: &str) {
    let h = Hierarchy::start_signed(&[variant]).await.unwrap();
    let r = status_resolver(&h).await;
    let ans = status_ask(&r, qname, DO).await;
    assert_eq!(ans.dnssec, DnssecStatus::Bogus);
    assert_eq!(ans.message.rcode(), dnscraft_proto::Rcode::SERVFAIL);
    assert!(ans.message.answers.is_empty());
    assert!(ans.message.authorities.is_empty());
    assert!(!ans.message.header.ad);
    let e = ans.ede.expect("EDE");
    assert_eq!(e.code, ede);
    assert_eq!(e.text.as_deref(), Some(text));
}

#[tokio::test]
async fn status_bogus_sig() {
    status_bogus(
        ChildVariant::BogusSig,
        "www.bogus-sig.test.",
        VerifyFailure::BadSignature.ede_code(),
        VerifyFailure::BadSignature.code(),
    )
    .await;
}

#[tokio::test]
async fn status_bogus_expired() {
    status_bogus(
        ChildVariant::BogusExpired,
        "www.bogus-expired.test.",
        7,
        VerifyFailure::Expired.code(),
    )
    .await;
}

#[tokio::test]
async fn status_bogus_nokey() {
    status_bogus(
        ChildVariant::BogusNoKey,
        "www.bogus-nokey.test.",
        ChainFailure::DsNoMatch.ede_code(),
        ChainFailure::DsNoMatch.code(),
    )
    .await;
}

#[tokio::test]
async fn status_cd_returns_bogus_answer_unvalidated() {
    let h = Hierarchy::start_signed(&[ChildVariant::BogusSig, ChildVariant::BogusNoKey])
        .await
        .unwrap();
    let r = status_resolver(&h).await;
    let cd = RequestFlags {
        checking_disabled: true,
        dnssec_ok: true,
        client: None,
    };
    for qname in ["www.bogus-sig.test.", "www.bogus-nokey.test."] {
        let ans = status_ask(&r, qname, cd).await;
        assert_eq!(ans.dnssec, DnssecStatus::Indeterminate);
        assert_eq!(ans.message.rcode(), dnscraft_proto::Rcode::NOERROR);
        assert!(!ans.message.header.ad);
        assert!(ans.ede.is_none());
        assert_eq!(
            ans.message
                .answers
                .iter()
                .filter(|r| r.rtype() == RecordType::A)
                .count(),
            1
        );
    }
    // No DNSKEY was fetched for a CD query.
    assert!(
        h.server("test.")
            .unwrap()
            .queries()
            .iter()
            .all(|q| RecordType(u16::from(q.query_type)) != RecordType::DNSKEY)
    );
}

#[tokio::test]
async fn status_empty_anchors_is_indeterminate() {
    let h = Hierarchy::start_signed(&[ChildVariant::Secure, ChildVariant::BogusSig])
        .await
        .unwrap();
    let mut config = status_config(&h);
    config.trust_anchors = TrustAnchors::empty();
    let r = Resolver::new(config).await.unwrap();
    for qname in ["www.secure.test.", "www.bogus-sig.test."] {
        let ans = status_ask(&r, qname, DO).await;
        assert_eq!(ans.dnssec, DnssecStatus::Indeterminate);
        assert!(!ans.message.header.ad);
        assert_eq!(ans.message.rcode(), dnscraft_proto::Rcode::NOERROR);
    }
}

#[tokio::test]
async fn status_do_controls_dnssec_records() {
    let h = Hierarchy::start_signed(&[ChildVariant::Secure])
        .await
        .unwrap();
    let r = status_resolver(&h).await;
    let with = status_ask(&r, "www.secure.test.", DO).await;
    assert!(
        with.message
            .answers
            .iter()
            .any(|r| r.rtype() == RecordType::RRSIG)
    );
    let without = status_ask(&r, "www.secure.test.", RequestFlags::default()).await;
    assert_eq!(without.dnssec, DnssecStatus::Secure);
    assert!(without.message.header.ad);
    assert!(
        without
            .message
            .answers
            .iter()
            .all(|r| r.rtype() == RecordType::A)
    );
    assert_eq!(without.message.answers.len(), 1);
}

#[tokio::test]
async fn status_expired_signatures_after_time_travel_are_bogus() {
    let h = Hierarchy::start_signed(&[ChildVariant::Secure])
        .await
        .unwrap();
    let clock = Arc::new(ManualClock::new(SystemTime::now()));
    let mut config = status_config(&h);
    config.clock = clock.clone();
    let r = Resolver::new(config).await.unwrap();
    let ans = status_ask(&r, "www.secure.test.", DO).await;
    assert_eq!(ans.dnssec, DnssecStatus::Secure);
    clock.advance(Duration::from_secs(60 * 86_400));
    let ans = status_ask(&r, "www.secure.test.", DO).await;
    assert_eq!(ans.dnssec, DnssecStatus::Bogus);
    assert_eq!(ans.message.rcode(), dnscraft_proto::Rcode::SERVFAIL);
    assert_eq!(ans.ede.unwrap().code, 7);
}

// ---------------------------------------------------------------------------
// Authenticated denial (Task 10)
// ---------------------------------------------------------------------------

async fn ask_type(
    r: &Resolver,
    qname: &str,
    qtype: RecordType,
    flags: RequestFlags,
) -> dnscraft_resolver::Answer {
    let q = Query {
        name: name(qname),
        qtype,
        qclass: Class::IN,
    };
    r.resolve(&q, flags).await.unwrap()
}

fn count_type(ans: &dnscraft_resolver::Answer, t: RecordType) -> usize {
    ans.message
        .answers
        .iter()
        .filter(|r| r.rtype() == t)
        .count()
}

fn assert_secure(ans: &dnscraft_resolver::Answer, rcode: dnscraft_proto::Rcode) {
    assert_eq!(ans.dnssec, DnssecStatus::Secure, "ede {:?}", ans.ede);
    assert!(ans.message.header.ad);
    assert_eq!(ans.message.rcode(), rcode);
    assert!(ans.ede.is_none());
}

/// The set of denial answers every signed zone `zone` (NSEC or NSEC3) must
/// get right.
async fn denial_suite(variant: ChildVariant) {
    use dnscraft_proto::Rcode;
    let zone = variant.zone_name();
    let h = Hierarchy::start_signed(&[variant]).await.unwrap();
    let r = status_resolver(&h).await;
    // NXDOMAIN.
    let ans = ask_type(&r, &format!("nope.{zone}"), RecordType::A, DO).await;
    assert_secure(&ans, Rcode::NXDOMAIN);
    assert!(ans.message.answers.is_empty());
    // NODATA at an existing name.
    let ans = ask_type(&r, &format!("www.{zone}"), RecordType::AAAA, DO).await;
    assert_secure(&ans, Rcode::NOERROR);
    assert!(ans.message.answers.is_empty());
    // NODATA for a type below the apex (apex has SOA/NS/NSEC...).
    let ans = ask_type(&r, zone, RecordType::MX, DO).await;
    assert_secure(&ans, Rcode::NOERROR);
    // Wildcard expansion.
    let ans = ask_type(&r, &format!("x.wild.{zone}"), RecordType::A, DO).await;
    assert_secure(&ans, Rcode::NOERROR);
    assert_eq!(count_type(&ans, RecordType::A), 1);
    // Wildcard NODATA.
    let ans = ask_type(&r, &format!("x.wild.{zone}"), RecordType::AAAA, DO).await;
    assert_secure(&ans, Rcode::NOERROR);
    assert!(ans.message.answers.is_empty());
    // Deeper NXDOMAIN (closest encloser is not the apex).
    let ans = ask_type(&r, &format!("a.b.www.{zone}"), RecordType::A, DO).await;
    assert_secure(&ans, Rcode::NXDOMAIN);
    // The signed zone's own NXDOMAIN did not break positive answers.
    let ans = ask_type(&r, &format!("www.{zone}"), RecordType::A, DO).await;
    assert_secure(&ans, Rcode::NOERROR);
}

#[tokio::test]
async fn denial_nsec_zone_is_secure() {
    denial_suite(ChildVariant::Secure).await;
}

#[tokio::test]
async fn denial_nsec3_zone_is_secure() {
    denial_suite(ChildVariant::Nsec3).await;
}

#[tokio::test]
async fn denial_nsec3_empty_non_terminal_nodata_is_secure() {
    let h = Hierarchy::start_signed(&[ChildVariant::Nsec3])
        .await
        .unwrap();
    let r = status_resolver(&h).await;
    let ans = ask_type(&r, "wild.nsec3.test.", RecordType::A, DO).await;
    assert_secure(&ans, dnscraft_proto::Rcode::NOERROR);
}

#[tokio::test]
async fn denial_nsec3_optout_nxdomain_needs_the_wildcard_proof_for_secure() {
    let h = Hierarchy::start_signed(&[ChildVariant::Nsec3OptOut])
        .await
        .unwrap();
    let r = status_resolver(&h).await;
    // The complete closest-encloser proof validates even with the opt-out
    // flag (like delv for .de and .com).
    let ans = ask_type(&r, "nope.nsec3-optout.test.", RecordType::A, DO).await;
    assert_secure(&ans, dnscraft_proto::Rcode::NXDOMAIN);
    // Names that exist keep their secure answers and denials.
    let ans = ask_type(&r, "www.nsec3-optout.test.", RecordType::A, DO).await;
    assert_secure(&ans, dnscraft_proto::Rcode::NOERROR);
    let ans = ask_type(&r, "www.nsec3-optout.test.", RecordType::AAAA, DO).await;
    assert_secure(&ans, dnscraft_proto::Rcode::NOERROR);

    // Dropping any record of the proof must never leave it Secure (the
    // Insecure outcome without the wildcard proof is a unit test).
    let upstream = h.server("nsec3-optout.test.").unwrap().addr();
    let genuine = raw_query(upstream, "nope.nsec3-optout.test.", RecordType::A).await;
    let mut owners: Vec<Name> = genuine
        .authorities
        .iter()
        .filter(|r| r.rtype() == RecordType::NSEC3)
        .map(|r| r.name.clone())
        .collect();
    owners.dedup();
    let mut outcomes = Vec::new();
    for victim in owners {
        let proxy = forge_proxy(
            upstream,
            Arc::new(move |_, t, m: &mut Message| {
                if t == RecordType::A {
                    m.authorities
                        .retain(|r| !(r.name == victim && is_denial(r)));
                }
            }),
        )
        .await;
        let mut config = status_config(&h);
        config
            .nameserver_addr_overrides
            .insert(name("ns1.nsec3-optout.test."), proxy);
        let r = Resolver::new(config).await.unwrap();
        let ans = ask_type(&r, "nope.nsec3-optout.test.", RecordType::A, DO).await;
        assert!(!ans.message.header.ad);
        outcomes.push(ans.dnssec);
    }
    assert!(outcomes.iter().all(|s| *s != DnssecStatus::Secure));
}

#[tokio::test]
async fn denial_nsec3_optout_unsigned_delegation_is_insecure() {
    let h = Hierarchy::start_signed(&[ChildVariant::Nsec3OptOut])
        .await
        .unwrap();
    let r = status_resolver(&h).await;
    // DS NODATA at the delegation inside the opt-out span (RFC 5155 section 8.6).
    let ans = ask_type(&r, "unsigned.nsec3-optout.test.", RecordType::DS, DO).await;
    assert_eq!(ans.dnssec, DnssecStatus::Insecure);
    assert!(!ans.message.header.ad);
    assert_eq!(ans.message.rcode(), dnscraft_proto::Rcode::NOERROR);
}

/// A server that answers every query with `192.0.2.77` (authoritative).
async fn stub_server() -> SocketAddr {
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
            m.header.aa = true;
            if q.questions[0].qtype == RecordType::A {
                m.answers.push(Record {
                    name: q.questions[0].name.clone(),
                    class: Class::IN,
                    ttl: 60,
                    rdata: RData::A("192.0.2.77".parse().unwrap()),
                });
            }
            socket.send_to(&m.encode().unwrap(), from).await.unwrap();
        }
    });
    addr
}

#[tokio::test]
async fn denial_nsec3_optout_referral_to_unsigned_child_is_insecure() {
    let h = Hierarchy::start_signed(&[ChildVariant::Nsec3OptOut])
        .await
        .unwrap();
    let stub = stub_server().await;
    let mut config = status_config(&h);
    config
        .nameserver_addr_overrides
        .insert(name("ns1.unsigned.nsec3-optout.test."), stub);
    let r = Resolver::new(config).await.unwrap();
    let ans = ask_type(&r, "www.unsigned.nsec3-optout.test.", RecordType::A, DO).await;
    assert_eq!(ans.dnssec, DnssecStatus::Insecure);
    assert!(!ans.message.header.ad);
    assert_eq!(count_type(&ans, RecordType::A), 1);
}

/// Edits a response of the zone server in flight.
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

/// Status of `qname`/`qtype` in the zone of `variant` when its server's
/// answers pass through `mutate` (built from a closure that gets the zone
/// server's address, to fetch genuine records from it).
async fn forged(
    variant: ChildVariant,
    qname: &str,
    qtype: RecordType,
    mutate: impl FnOnce(SocketAddr) -> Mutate,
) -> dnscraft_resolver::Answer {
    let h = Hierarchy::start_signed(&[variant]).await.unwrap();
    let upstream = h.server(variant.zone_name()).unwrap().addr();
    let proxy = forge_proxy(upstream, mutate(upstream)).await;
    let mut config = status_config(&h);
    config
        .nameserver_addr_overrides
        .insert(name(&format!("ns1.{}", variant.zone_name())), proxy);
    let r = Resolver::new(config).await.unwrap();
    ask_type(&r, qname, qtype, DO).await
}

fn is_denial(r: &Record) -> bool {
    matches!(r.rtype(), RecordType::NSEC | RecordType::NSEC3)
        || matches!(&r.rdata, RData::RRSIG { type_covered, .. }
            if matches!(*type_covered, RecordType::NSEC | RecordType::NSEC3))
}

fn assert_bogus(ans: &dnscraft_resolver::Answer, ede: u16) {
    assert_eq!(ans.dnssec, DnssecStatus::Bogus);
    assert_eq!(ans.message.rcode(), dnscraft_proto::Rcode::SERVFAIL);
    assert!(!ans.message.header.ad);
    assert_eq!(ans.ede.as_ref().unwrap().code, ede, "{:?}", ans.ede);
}

fn strip_denial() -> impl FnOnce(SocketAddr) -> Mutate {
    |_| {
        Arc::new(|_, _, m: &mut Message| {
            m.authorities.retain(|r| !is_denial(r));
        })
    }
}

#[tokio::test]
async fn denial_stripped_proof_is_bogus_nsec_missing() {
    for (variant, zone) in [
        (ChildVariant::Secure, "secure.test."),
        (ChildVariant::Nsec3, "nsec3.test."),
    ] {
        for qname in [format!("nope.{zone}"), format!("www.{zone}")] {
            // NXDOMAIN and NODATA (www has no AAAA).
            let qtype = if qname.starts_with("nope") {
                RecordType::A
            } else {
                RecordType::AAAA
            };
            let ans = forged(variant, &qname, qtype, strip_denial()).await;
            assert_bogus(&ans, 12);
            assert!(ans.message.answers.is_empty());
        }
    }
}

#[tokio::test]
async fn denial_wildcard_answer_without_proof_is_bogus() {
    for (variant, zone) in [
        (ChildVariant::Secure, "secure.test."),
        (ChildVariant::Nsec3, "nsec3.test."),
    ] {
        let ans = forged(
            variant,
            &format!("x.wild.{zone}"),
            RecordType::A,
            strip_denial(),
        )
        .await;
        assert_bogus(&ans, 12);
        assert!(ans.message.answers.is_empty());
    }
}

#[tokio::test]
async fn denial_wildcard_with_wrong_closest_encloser_is_bogus() {
    // Replay a valid *.wild expansion under a covering NSEC whose implied
    // closest encloser is the apex (not wild): must not become Secure.
    let h = Hierarchy::start_signed(&[ChildVariant::Secure])
        .await
        .unwrap();
    let upstream = h.server("secure.test.").unwrap().addr();
    let donor = raw_query(upstream, "ns1.secure.test.", RecordType::AAAA).await;
    let proof: Vec<Record> = donor
        .authorities
        .iter()
        .filter(|r| is_denial(r))
        .cloned()
        .collect();
    assert!(
        proof.iter().any(|r| r.rtype() == RecordType::NSEC),
        "expected an NSEC at ns1: {:?}",
        proof
            .iter()
            .map(|r| (&r.name, r.rtype()))
            .collect::<Vec<_>>()
    );
    let proxy = forge_proxy(
        upstream,
        Arc::new(move |_, t, m: &mut Message| {
            if t == RecordType::A {
                m.authorities.retain(|r| !is_denial(r));
                m.authorities.extend(proof.clone());
            }
        }),
    )
    .await;
    let mut config = status_config(&h);
    config
        .nameserver_addr_overrides
        .insert(name("ns1.secure.test."), proxy);
    let r = Resolver::new(config).await.unwrap();
    let ans = ask_type(&r, "x.wild.secure.test.", RecordType::A, DO).await;
    assert_bogus(&ans, 6);
}

#[tokio::test]
async fn denial_dropping_any_single_proof_record_is_bogus() {
    // Every record of an NXDOMAIN proof is needed (closest encloser, next
    // closer, wildcard): dropping any one of them must not validate.
    for (variant, zone) in [
        (ChildVariant::Secure, "secure.test."),
        (ChildVariant::Nsec3, "nsec3.test."),
    ] {
        let qname = format!("nope.{zone}");
        let h = Hierarchy::start_signed(&[variant]).await.unwrap();
        let upstream = h.server(zone).unwrap().addr();
        let genuine = raw_query(upstream, &qname, RecordType::A).await;
        let mut owners: Vec<Name> = genuine
            .authorities
            .iter()
            .filter(|r| matches!(r.rtype(), RecordType::NSEC | RecordType::NSEC3))
            .map(|r| r.name.clone())
            .collect();
        owners.dedup();
        assert!(!owners.is_empty());
        for victim in owners {
            let proxy = forge_proxy(
                upstream,
                Arc::new(move |_, t, m: &mut Message| {
                    if t == RecordType::A {
                        m.authorities
                            .retain(|r| !(r.name == victim && is_denial(r)));
                    }
                }),
            )
            .await;
            let mut config = status_config(&h);
            config
                .nameserver_addr_overrides
                .insert(name(&format!("ns1.{zone}")), proxy);
            let r = Resolver::new(config).await.unwrap();
            let ans = ask_type(&r, &qname, RecordType::A, DO).await;
            assert_eq!(ans.dnssec, DnssecStatus::Bogus, "{zone}: {:?}", ans.ede);
        }
    }
}

async fn raw_query(server: SocketAddr, qname: &str, qtype: RecordType) -> Message {
    let mut q = Message::query(9, name(qname), qtype);
    q.header.rd = false;
    let mut edns = Edns::new(4096);
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

#[tokio::test]
async fn denial_valid_but_irrelevant_proof_is_bogus() {
    // Swap the proof of `nope` for the (validly signed) records that prove
    // something about `www`: it does not prove that `nope` is absent.
    for (variant, zone) in [
        (ChildVariant::Secure, "secure.test."),
        (ChildVariant::Nsec3, "nsec3.test."),
    ] {
        let h = Hierarchy::start_signed(&[variant]).await.unwrap();
        let upstream = h.server(zone).unwrap().addr();
        let other = raw_query(upstream, &format!("www.{zone}"), RecordType::AAAA).await;
        let other_proof: Vec<Record> = other
            .authorities
            .iter()
            .filter(|r| is_denial(r))
            .cloned()
            .collect();
        assert!(!other_proof.is_empty());
        let proxy = forge_proxy(
            upstream,
            Arc::new(move |_, t, m: &mut Message| {
                if t == RecordType::A {
                    m.authorities.retain(|r| !is_denial(r));
                    m.authorities.extend(other_proof.clone());
                }
            }),
        )
        .await;
        let mut config = status_config(&h);
        config
            .nameserver_addr_overrides
            .insert(name(&format!("ns1.{zone}")), proxy);
        let r = Resolver::new(config).await.unwrap();
        let ans = ask_type(&r, &format!("nope.{zone}"), RecordType::A, DO).await;
        assert_bogus(&ans, 6);
    }
}

#[tokio::test]
async fn denial_nxdomain_rewritten_to_noerror_is_bogus() {
    // An attacker turns the NXDOMAIN into NODATA: the NXDOMAIN proof does not
    // show that the name exists.
    for (variant, zone) in [
        (ChildVariant::Secure, "secure.test."),
        (ChildVariant::Nsec3, "nsec3.test."),
    ] {
        let ans = forged(variant, &format!("nope.{zone}"), RecordType::A, |_| {
            Arc::new(|_, t, m: &mut Message| {
                if t == RecordType::A {
                    m.set_rcode(dnscraft_proto::Rcode::NOERROR).unwrap();
                }
            })
        })
        .await;
        assert_bogus(&ans, 6);
    }
}

#[tokio::test]
async fn denial_nodata_rewritten_to_nxdomain_is_bogus() {
    for (variant, zone) in [
        (ChildVariant::Secure, "secure.test."),
        (ChildVariant::Nsec3, "nsec3.test."),
    ] {
        let ans = forged(variant, &format!("www.{zone}"), RecordType::AAAA, |_| {
            Arc::new(|_, t, m: &mut Message| {
                if t == RecordType::AAAA {
                    m.set_rcode(dnscraft_proto::Rcode::NXDOMAIN).unwrap();
                }
            })
        })
        .await;
        assert_bogus(&ans, 6);
    }
}

#[tokio::test]
async fn denial_positive_answer_turned_into_nodata_is_bogus() {
    // The A answer of www is removed and the NODATA proof of AAAA is attached.
    let h = Hierarchy::start_signed(&[ChildVariant::Secure])
        .await
        .unwrap();
    let upstream = h.server("secure.test.").unwrap().addr();
    let proof = raw_query(upstream, "www.secure.test.", RecordType::AAAA)
        .await
        .authorities;
    let proxy = forge_proxy(
        upstream,
        Arc::new(move |_, t, m: &mut Message| {
            if t == RecordType::A {
                m.answers.clear();
                m.authorities = proof.clone();
            }
        }),
    )
    .await;
    let mut config = status_config(&h);
    config
        .nameserver_addr_overrides
        .insert(name("ns1.secure.test."), proxy);
    let r = Resolver::new(config).await.unwrap();
    let ans = ask_type(&r, "www.secure.test.", RecordType::A, DO).await;
    // The NSEC at www lists A: the NODATA claim for A is contradicted.
    assert_bogus(&ans, 6);
}

// ---------------------------------------------------------------------------
// Negative trust anchors (Task 10)
// ---------------------------------------------------------------------------

async fn nta_resolver(h: &Hierarchy, ntas: &[&str]) -> Resolver {
    let mut config = status_config(h);
    config.negative_trust_anchors = ntas.iter().map(|n| name(n)).collect();
    Resolver::new(config).await.unwrap()
}

#[tokio::test]
async fn nta_makes_bogus_zone_insecure() {
    let h = Hierarchy::start_signed(&[
        ChildVariant::BogusSig,
        ChildVariant::BogusNoKey,
        ChildVariant::BogusExpired,
        ChildVariant::Secure,
    ])
    .await
    .unwrap();
    // Without the NTA the zones are bogus.
    let plain = status_resolver(&h).await;
    let ans = status_ask(&plain, "www.bogus-sig.test.", DO).await;
    assert_eq!(ans.dnssec, DnssecStatus::Bogus);

    let r = nta_resolver(
        &h,
        &[
            "bogus-sig.test.",
            "bogus-nokey.test.",
            "bogus-expired.test.",
        ],
    )
    .await;
    for qname in [
        "www.bogus-sig.test.",
        "www.bogus-nokey.test.",
        "www.bogus-expired.test.",
    ] {
        let ans = status_ask(&r, qname, DO).await;
        assert_eq!(ans.dnssec, DnssecStatus::Insecure, "{qname}");
        assert!(!ans.message.header.ad);
        assert_eq!(ans.message.rcode(), dnscraft_proto::Rcode::NOERROR);
        assert_eq!(count_type(&ans, RecordType::A), 1, "{qname}");
        assert!(ans.ede.is_none());
    }
    // A denial below the NTA is insecure too.
    let ans = ask_type(&r, "nope.bogus-sig.test.", RecordType::A, DO).await;
    assert_eq!(ans.dnssec, DnssecStatus::Insecure);
    assert_eq!(ans.message.rcode(), dnscraft_proto::Rcode::NXDOMAIN);
    // The sibling outside the NTA still validates.
    let ans = status_ask(&r, "www.secure.test.", DO).await;
    assert_secure(&ans, dnscraft_proto::Rcode::NOERROR);
    let ans = ask_type(&r, "nope.secure.test.", RecordType::A, DO).await;
    assert_secure(&ans, dnscraft_proto::Rcode::NXDOMAIN);
}

#[tokio::test]
async fn nta_on_parent_covers_children() {
    let h = Hierarchy::start_signed(&[ChildVariant::BogusSig, ChildVariant::Secure])
        .await
        .unwrap();
    let r = nta_resolver(&h, &["test."]).await;
    for qname in ["www.bogus-sig.test.", "www.secure.test."] {
        let ans = status_ask(&r, qname, DO).await;
        assert_eq!(ans.dnssec, DnssecStatus::Insecure, "{qname}");
        assert!(!ans.message.header.ad);
        assert_eq!(count_type(&ans, RecordType::A), 1);
    }
}

#[tokio::test]
async fn nta_does_not_cover_its_parent_or_siblings() {
    let h = Hierarchy::start_signed(&[ChildVariant::BogusSig, ChildVariant::Secure])
        .await
        .unwrap();
    let r = nta_resolver(&h, &["www.bogus-sig.test."]).await;
    // BogusSig only corrupts www's A; ns1 stays Secure. The NTA covers only www.
    let ans = ask_type(&r, "ns1.bogus-sig.test.", RecordType::A, DO).await;
    assert_eq!(ans.dnssec, DnssecStatus::Secure);
    let ans = status_ask(&r, "www.bogus-sig.test.", DO).await;
    assert_eq!(ans.dnssec, DnssecStatus::Insecure);
    let ans = status_ask(&r, "www.secure.test.", DO).await;
    assert_secure(&ans, dnscraft_proto::Rcode::NOERROR);
}

// ---------------------------------------------------------------------------
// Hidden zone cuts: parent and child served by the same servers, so the
// resolver never sees a referral for the child (like uk, co.uk and bbc.co.uk).
// The testkit serves one zone per server, so a routing proxy plays the part of
// the shared server.
// ---------------------------------------------------------------------------

struct Cohost {
    h: Hierarchy,
    anchors: TrustAnchors,
    proxy: SocketAddr,
}

/// Builds root, `test.` and the nested zones of `chain` (each a child of the
/// previous one, the first a child of `test.`). A zone is `(origin, signed,
/// hidden)`: hidden zones are served through the shared proxy together with
/// `test.`; a visible one is reached through the referral of its parent.
async fn cohost(chain: &[(&str, bool, bool)], strip: bool) -> Cohost {
    use dnscraft_testkit::{ServerSpec, SigningOptions, Zone, ZoneKey, parse_name, sign_zone};
    use std::net::Ipv4Addr;
    let lo = Ipv4Addr::LOCALHOST;
    let alg = SigAlgorithm::default();
    let root_key = ZoneKey::generate(alg).unwrap();
    let test_key = ZoneKey::generate(alg).unwrap();
    let keys: Vec<Option<ZoneKey>> = chain
        .iter()
        .map(|(_, signed, _)| signed.then(|| ZoneKey::generate(alg).unwrap()))
        .collect();
    let delegate = |zone: Zone, child: usize| {
        let (origin, _, _) = chain[child];
        let mut zone = zone
            .with_ns(origin, &format!("ns1.{origin}"))
            .unwrap()
            .with_a(&format!("ns1.{origin}"), lo)
            .unwrap();
        if let Some(k) = &keys[child] {
            zone = zone.with_record(k.ds_record(&parse_name(origin).unwrap()).unwrap());
        }
        zone
    };
    let mut specs = Vec::new();
    let mut test = Zone::new("test.")
        .unwrap()
        .with_soa("ns1.test.", "hostmaster.test.")
        .unwrap()
        .with_ns("test.", "ns1.test.")
        .unwrap()
        .with_a("ns1.test.", lo)
        .unwrap();
    test = delegate(test, 0);
    for (i, (origin, _, _)) in chain.iter().enumerate() {
        let mut zone = Zone::new(origin)
            .unwrap()
            .with_soa(&format!("ns1.{origin}"), &format!("hostmaster.{origin}"))
            .unwrap()
            .with_ns(origin, &format!("ns1.{origin}"))
            .unwrap()
            .with_a(&format!("ns1.{origin}"), lo)
            .unwrap()
            .with_a(&format!("www.{origin}"), Ipv4Addr::new(192, 0, 2, 50))
            .unwrap();
        if i + 1 < chain.len() {
            zone = delegate(zone, i + 1);
        }
        if let Some(k) = &keys[i] {
            zone = sign_zone(zone, k, &SigningOptions::now()).unwrap();
        }
        specs.push(ServerSpec::new(&format!("ns1.{origin}"), zone).unwrap());
    }
    let test = sign_zone(test, &test_key, &SigningOptions::now()).unwrap();
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
    let root = sign_zone(root, &root_key, &SigningOptions::now()).unwrap();
    let mut all = vec![
        ServerSpec::new("a.root-servers.net.", root).unwrap(),
        ServerSpec::new("ns1.test.", test).unwrap(),
    ];
    all.extend(specs);
    let h = Hierarchy::start_with(all).await.unwrap();

    let mut routes = vec![(name("test."), h.server("test.").unwrap().addr())];
    for (origin, _, hidden) in chain {
        if *hidden {
            routes.push((name(origin), h.server(origin).unwrap().addr()));
        }
    }
    let proxy = proxy(routes, strip).await;

    let ds = root_key
        .ds(&Name::root().to_string().parse().unwrap())
        .unwrap();
    let bytes = ds.to_bytes().unwrap();
    let anchor_ds = Record {
        name: Name::root(),
        class: Class::IN,
        ttl: 3600,
        rdata: RData::decode(&bytes, RecordType::DS, 0, bytes.len()).unwrap(),
    };
    Cohost {
        h,
        anchors: TrustAnchors::from_records(&[anchor_ds]).unwrap(),
        proxy,
    }
}

impl Cohost {
    async fn resolver(&self, minimisation: bool) -> Resolver {
        let mut config = status_config_with(&self.h, self.anchors.clone());
        config
            .nameserver_addr_overrides
            .insert(name("ns1.test."), self.proxy);
        config.qname_minimisation = minimisation;
        Resolver::new(config).await.unwrap()
    }
}

fn status_config_with(h: &Hierarchy, anchors: TrustAnchors) -> ResolverConfig {
    ResolverConfig {
        trust_anchors: anchors,
        ..status_config_base(h)
    }
}

fn status_config_base(h: &Hierarchy) -> ResolverConfig {
    let overrides = h
        .nameserver_addrs()
        .iter()
        .map(|(n, a)| (Name::from_ascii(&n.to_string()).unwrap(), *a))
        .collect();
    ResolverConfig {
        root_hints: h.root_hints(),
        query_timeout: Duration::from_millis(500),
        nameserver_addr_overrides: overrides,
        ..ResolverConfig::default()
    }
}

async fn cohost_status(
    chain: &[(&str, bool, bool)],
    strip: bool,
    qname: &str,
) -> Vec<(DnssecStatus, bool)> {
    let c = cohost(chain, strip).await;
    let mut out = Vec::new();
    for minimisation in [true, false] {
        let r = c.resolver(minimisation).await;
        let ans = status_ask(&r, qname, DO).await;
        if ans.dnssec != DnssecStatus::Bogus {
            assert_eq!(
                ans.message.rcode(),
                dnscraft_proto::Rcode::NOERROR,
                "{qname}"
            );
            assert_eq!(
                ans.message
                    .answers
                    .iter()
                    .filter(|r| r.rtype() == RecordType::A)
                    .count(),
                1
            );
        } else {
            assert_eq!(ans.message.rcode(), dnscraft_proto::Rcode::SERVFAIL);
            assert!(ans.message.answers.is_empty());
        }
        out.push((ans.dnssec, ans.message.header.ad));
    }
    out
}

fn both(status: DnssecStatus, ad: bool) -> Vec<(DnssecStatus, bool)> {
    vec![(status, ad), (status, ad)]
}

#[tokio::test]
async fn status_hidden_signed_child_is_secure() {
    let r = cohost_status(&[("i.test.", true, true)], false, "www.i.test.").await;
    assert_eq!(r, both(DnssecStatus::Secure, true));
}

#[tokio::test]
async fn status_hidden_unsigned_child_with_proof_is_insecure() {
    let r = cohost_status(&[("i.test.", false, true)], false, "www.i.test.").await;
    assert_eq!(r, both(DnssecStatus::Insecure, false));
}

#[tokio::test]
async fn status_hidden_children_with_stripped_proofs_are_bogus() {
    for signed in [true, false] {
        let r = cohost_status(&[("i.test.", signed, true)], true, "www.i.test.").await;
        assert_eq!(r, both(DnssecStatus::Bogus, false), "signed={signed}");
    }
}

#[tokio::test]
async fn status_hidden_intermediate_zone_between_parent_and_signer() {
    let r = cohost_status(
        &[("i.test.", true, true), ("s.i.test.", true, true)],
        false,
        "www.s.i.test.",
    )
    .await;
    assert_eq!(r, both(DnssecStatus::Secure, true));
    let r = cohost_status(
        &[("i.test.", true, true), ("s.i.test.", false, true)],
        false,
        "www.s.i.test.",
    )
    .await;
    assert_eq!(r, both(DnssecStatus::Insecure, false));
    let r = cohost_status(
        &[("i.test.", true, true), ("s.i.test.", true, true)],
        true,
        "www.s.i.test.",
    )
    .await;
    assert_eq!(r, both(DnssecStatus::Bogus, false));
}

#[tokio::test]
async fn status_referral_signed_by_hidden_zone() {
    // Like bbc.co.uk below uk/co.uk: the referral for c.s.i.test. comes from
    // the shared server, but its DS is signed by the hidden zone s.i.test.
    let chain = |c_signed| {
        vec![
            ("i.test.", true, true),
            ("s.i.test.", true, true),
            ("c.s.i.test.", c_signed, false),
        ]
    };
    let r = cohost_status(&chain(true), false, "www.c.s.i.test.").await;
    assert_eq!(r, both(DnssecStatus::Secure, true));
    let r = cohost_status(&chain(false), false, "www.c.s.i.test.").await;
    assert_eq!(r, both(DnssecStatus::Insecure, false));
    let r = cohost_status(&chain(true), true, "www.c.s.i.test.").await;
    assert_eq!(r, both(DnssecStatus::Bogus, false));
}

// ---------------------------------------------------------------------------
// CPU-exhaustion hardening: KeyTrap, NSEC3 hashing, inception skew
// ---------------------------------------------------------------------------

mod keytrap {
    use super::*;
    use dnscraft_proto::dnssec::{key_tag, rrsig_signing_input};
    use ring::signature::{Ed25519KeyPair, KeyPair};

    const ALG_ED25519: u8 = 15;
    const ZONE: &str = "kt.test.";

    fn pair() -> Ed25519KeyPair {
        Ed25519KeyPair::from_seed_unchecked(&[7u8; 32]).unwrap()
    }

    /// `n` distinct 32-byte public keys with the same key tag as `base`:
    /// the tag is a 16-bit word sum, so shifting value between two aligned
    /// words keeps it. Only the tag matters for the attempt count; the extra
    /// keys are not valid points.
    fn colliding_keys(base: &[u8], n: usize) -> Vec<Vec<u8>> {
        let w = |k: &[u8], i: usize| u32::from(u16::from_be_bytes([k[i], k[i + 1]]));
        let sum = w(base, 0) + w(base, 2);
        let lo = sum.saturating_sub(0xFFFF);
        let mut out = vec![base.to_vec()];
        for i in 1..=n as u32 {
            let a = lo + i;
            let b = sum - a;
            let mut k = base.to_vec();
            k[0..2].copy_from_slice(&(a as u16).to_be_bytes());
            k[2..4].copy_from_slice(&(b as u16).to_be_bytes());
            if !out.contains(&k) {
                out.push(k);
            }
        }
        let tag = key_tag(257, 3, ALG_ED25519, base);
        for k in &out {
            assert_eq!(key_tag(257, 3, ALG_ED25519, k), tag, "tag collision setup");
        }
        out
    }

    fn secs(t: SystemTime) -> u32 {
        t.duration_since(UNIX_EPOCH).unwrap().as_secs() as u32
    }

    fn rrsig(
        rrset: &[Record],
        kp: &Ed25519KeyPair,
        tag: u16,
        now: SystemTime,
        sign: bool,
    ) -> Record {
        let first = &rrset[0];
        let mut rdata = RData::RRSIG {
            type_covered: first.rtype(),
            algorithm: ALG_ED25519,
            labels: first.name.label_count() as u8,
            original_ttl: 300,
            expiration: secs(now) + 86_400,
            inception: secs(now) - 3600,
            key_tag: tag,
            signer_name: name(ZONE),
            signature: Vec::new().into(),
        };
        let sig = if sign {
            kp.sign(&rrsig_signing_input(&rdata, rrset).unwrap())
                .as_ref()
                .to_vec()
        } else {
            vec![0x5a; 64]
        };
        if let RData::RRSIG { signature, .. } = &mut rdata {
            *signature = sig.into();
        }
        Record {
            name: first.name.clone(),
            class: Class::IN,
            ttl: 300,
            rdata,
        }
    }

    fn anchors(keys: &[Vec<u8>]) -> TrustAnchors {
        let recs: Vec<Record> = keys
            .iter()
            .map(|k| dnskey_rec(ZONE, ALG_ED25519, k.clone()))
            .collect();
        TrustAnchors::from_records(&recs).unwrap()
    }

    #[test]
    fn dnskey_validation_attempts_are_bounded() {
        let kp = pair();
        let keys = colliding_keys(kp.public_key().as_ref(), 50);
        let tag = key_tag(257, 3, ALG_ED25519, &keys[0]);
        let dnskeys: Vec<Record> = keys
            .iter()
            .map(|k| dnskey_rec(ZONE, ALG_ED25519, k.clone()))
            .collect();
        // 200 bogus RRSIGs, all naming the colliding tag; 51 anchored keys.
        let junk: Vec<Record> = (0..200)
            .map(|_| rrsig(&dnskeys, &kp, tag, SystemTime::now(), false))
            .collect();
        let anchors = anchors(&keys);
        let budget = ValidationBudget::unlimited();
        let t = std::time::Instant::now();
        let e = validate_dnskey_rrset_budgeted(
            &name(ZONE),
            &dnskeys,
            &junk,
            DelegationTrust::Anchors(&anchors),
            SystemTime::now(),
            &budget,
        )
        .unwrap_err();
        assert_eq!(e, ChainFailure::Verify(VerifyFailure::BadSignature));
        // Before the fix: 200 sigs x 51 keys = 10200 verifications.
        assert!(
            budget.verifications_used() as usize <= MAX_SIGS_PER_RRSET * MAX_KEYS_PER_TAG,
            "{} verifications",
            budget.verifications_used()
        );
        assert!(t.elapsed() < Duration::from_secs(1));

        // A tight per-resolution budget fails closed with its own reason.
        let tight = ValidationBudget::with_limits(5, 128);
        let e = validate_dnskey_rrset_budgeted(
            &name(ZONE),
            &dnskeys,
            &junk,
            DelegationTrust::Anchors(&anchors),
            SystemTime::now(),
            &tight,
        )
        .unwrap_err();
        assert_eq!(e, ChainFailure::Verify(VerifyFailure::BudgetExhausted));
        assert_eq!(e.code(), "dnssec.validation_budget");
        assert_eq!(e.ede_code(), 6);
        assert_eq!(tight.verifications_used(), 5);
    }

    /// DNSKEY RRset (signer first, then colliding decoys) validated through a
    /// single anchored key.
    fn validated_keys(kp: &Ed25519KeyPair, decoys: usize, now: SystemTime) -> ValidatedKeys {
        let keys = colliding_keys(kp.public_key().as_ref(), decoys);
        let tag = key_tag(257, 3, ALG_ED25519, &keys[0]);
        let dnskeys: Vec<Record> = keys
            .iter()
            .map(|k| dnskey_rec(ZONE, ALG_ED25519, k.clone()))
            .collect();
        let sig = rrsig(&dnskeys, kp, tag, now, true);
        let anchors = anchors(&keys[..1]);
        secure(
            validate_dnskey_rrset(
                &name(ZONE),
                &dnskeys,
                &[sig],
                DelegationTrust::Anchors(&anchors),
                now,
            )
            .unwrap(),
        )
    }

    fn a_record() -> Record {
        Record {
            name: name("www.kt.test."),
            class: Class::IN,
            ttl: 300,
            rdata: RData::A("192.0.2.7".parse().unwrap()),
        }
    }

    #[test]
    fn rrset_validation_attempts_are_bounded_and_valid_sig_still_works() {
        let now = SystemTime::now();
        let kp = pair();
        let vk = validated_keys(&kp, 50, now);
        assert_eq!(vk.keys().len(), 51);
        let tag = key_tag(257, 3, ALG_ED25519, kp.public_key().as_ref());
        let a = [a_record()];

        // Control: one valid RRSIG validates with a single verification.
        let good = rrsig(&a, &kp, tag, now, true);
        let budget = ValidationBudget::default();
        validate_rrset_budgeted(&a, std::slice::from_ref(&good), &vk, now, &budget).unwrap();
        assert_eq!(budget.verifications_used(), 1);

        // 200 bogus RRSIGs against 51 same-tag keys.
        let junk: Vec<Record> = (0..200).map(|_| rrsig(&a, &kp, tag, now, false)).collect();
        let budget = ValidationBudget::unlimited();
        let t = std::time::Instant::now();
        let e = validate_rrset_budgeted(&a, &junk, &vk, now, &budget).unwrap_err();
        assert_eq!(e, VerifyFailure::BadSignature);
        // Before the fix: 200 x 51 = 10200 verifications.
        assert!(
            budget.verifications_used() as usize <= MAX_SIGS_PER_RRSET * MAX_KEYS_PER_TAG,
            "{} verifications",
            budget.verifications_used()
        );
        assert!(t.elapsed() < Duration::from_secs(1));

        // The per-resolution budget is shared across calls.
        let shared = ValidationBudget::with_limits(40, 128);
        let mut seen_exhausted = false;
        for _ in 0..4 {
            match validate_rrset_budgeted(&a, &junk, &vk, now, &shared) {
                Err(VerifyFailure::BudgetExhausted) => seen_exhausted = true,
                Err(VerifyFailure::BadSignature) => {}
                other => panic!("unexpected {other:?}"),
            }
        }
        assert!(seen_exhausted);
        assert_eq!(shared.verifications_used(), 40);
        // Once spent, even a genuine signature is refused (fail closed).
        let e = validate_rrset_budgeted(&a, std::slice::from_ref(&good), &vk, now, &shared)
            .unwrap_err();
        assert_eq!(e, VerifyFailure::BudgetExhausted);
        assert_eq!(e.code(), "dnssec.validation_budget");
    }
}

#[tokio::test]
async fn inception_skew_is_tolerated_up_to_300_seconds() {
    const SIGNED_AT: u32 = 1_900_000_000;
    let inception = u64::from(SIGNED_AT) - 3600;
    for (early, bogus) in [(60, false), (600, true)] {
        let h = Hierarchy::start_scenario(
            &DnssecScenario::new(&[ChildVariant::Secure]).with_now(SIGNED_AT),
        )
        .await
        .unwrap();
        let clock = Arc::new(ManualClock::new(at(inception - early)));
        let mut config = status_config(&h);
        config.clock = clock.clone();
        let r = Resolver::new(config).await.unwrap();
        let ans = status_ask(&r, "www.secure.test.", DO).await;
        if bogus {
            assert_eq!(ans.dnssec, DnssecStatus::Bogus, "{early}s early");
            assert_eq!(ans.ede.unwrap().code, 8);
        } else {
            assert_eq!(
                ans.dnssec,
                DnssecStatus::Secure,
                "{early}s early: {:?}",
                ans.ede
            );
        }
    }
}

#[tokio::test]
async fn nsec3_nxdomain_for_a_100_label_name_completes_within_budget() {
    let h = Hierarchy::start_signed(&[ChildVariant::Nsec3])
        .await
        .unwrap();
    let r = status_resolver(&h).await;
    let qname = format!("{}nsec3.test.", "a.".repeat(100));
    let t = std::time::Instant::now();
    let ans = ask_type(&r, &qname, RecordType::A, DO).await;
    assert!(t.elapsed() < Duration::from_secs(5));
    // 100 labels need about 100 hashes, within the per-resolution budget.
    assert_secure(&ans, dnscraft_proto::Rcode::NXDOMAIN);
}
