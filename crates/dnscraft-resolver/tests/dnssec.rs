//! DNSSEC validator tests (Task 9a): chain of trust against the testkit's signed
//! hierarchy and the real root DNSKEY RRset.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::net::SocketAddr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use dnscraft_proto::dnssec::key_tag;
use dnscraft_proto::{Class, Edns, Message, Name, RData, Record, RecordType};
use dnscraft_resolver::dnssec::{
    ChainFailure, DelegationTrust, DsStatus, InsecureReason, KeysOutcome, TrustAnchors,
    ValidatedKeys, VerifyFailure, ds_status, validate_dnskey_rrset, validate_rrset, verify_rrsig,
};
use dnscraft_testkit::{ChildVariant, DnssecScenario, Hierarchy, SigAlgorithm};
use hickory_proto::serialize::binary::BinEncodable;
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
        rtype: RecordType::DNSKEY,
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
        rtype: RecordType::RRSIG,
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
        .filter(|r| r.rtype == qtype)
        .cloned()
        .collect();
    let sigs = m
        .answers
        .iter()
        .filter(|r| r.rtype == RecordType::RRSIG)
        .cloned()
        .collect();
    (rrset, sigs)
}

fn anchors_of(h: &Hierarchy) -> TrustAnchors {
    let a = h.trust_anchor().unwrap();
    let rdata = |rtype, bytes: Vec<u8>| RData::decode(&bytes, rtype, 0, bytes.len()).unwrap();
    let ds = Record {
        name: Name::root(),
        rtype: RecordType::DS,
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
        rtype: RecordType::DNSKEY,
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
        rtype: RecordType::DS,
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
        rtype: RecordType::A,
        class: Class::IN,
        ttl: 300,
        rdata: RData::A("192.0.2.1".parse().unwrap()),
    };
    let sig = Record {
        name: a.name.clone(),
        rtype: RecordType::RRSIG,
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
