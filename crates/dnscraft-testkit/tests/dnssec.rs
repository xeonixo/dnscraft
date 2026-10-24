#![allow(clippy::unwrap_used, clippy::expect_used)]

//! DNSSEC testkit zones, checked with hickory-proto's own verification.

use std::time::Duration;

use dnscraft_testkit::{
    ChildVariant, DnssecScenario, Hierarchy, SigAlgorithm, parse_name, unix_now,
};
use hickory_proto::dnssec::rdata::{DNSKEY, DNSSECRData, DS, NSEC, NSEC3, RRSIG};
use hickory_proto::dnssec::{Nsec3HashAlgorithm, Verifier};
use hickory_proto::op::{Edns, Message, Query, ResponseCode};
use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType};
use tokio::net::UdpSocket;
use tokio::time::timeout;

async fn ask_with(
    h: &Hierarchy,
    zone: &str,
    name: &str,
    rtype: RecordType,
    dnssec_ok: bool,
) -> Message {
    let server = h.server(zone).unwrap().addr();
    let mut msg = Message::query();
    msg.metadata.recursion_desired = false;
    msg.add_query(Query::query(parse_name(name).unwrap(), rtype));
    let mut edns = Edns::new();
    edns.set_max_payload(4096);
    edns.set_dnssec_ok(dnssec_ok);
    msg.edns = Some(edns);
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    socket
        .send_to(&msg.to_vec().unwrap(), server)
        .await
        .unwrap();
    let mut buf = vec![0u8; 8192];
    let (len, _) = timeout(Duration::from_secs(2), socket.recv_from(&mut buf))
        .await
        .unwrap()
        .unwrap();
    Message::from_vec(&buf[..len]).unwrap()
}

async fn ask(h: &Hierarchy, zone: &str, name: &str, rtype: RecordType) -> Message {
    ask_with(h, zone, name, rtype, true).await
}

fn sigs(records: &[Record]) -> Vec<(&Record, &RRSIG)> {
    records
        .iter()
        .filter_map(|r| match &r.data {
            RData::DNSSEC(DNSSECRData::RRSIG(s)) => Some((r, s)),
            _ => None,
        })
        .collect()
}

fn rrset(records: &[Record], name: &Name, rtype: RecordType) -> Vec<Record> {
    records
        .iter()
        .filter(|r| r.name == *name && r.record_type() == rtype)
        .cloned()
        .collect()
}

/// Verifies the RRSIG(s) covering `(name, rtype)` among `records` with `key`.
fn verify(key: &DNSKEY, records: &[Record], name: &Name, rtype: RecordType) -> Result<(), String> {
    let set = rrset(records, name, rtype);
    assert!(!set.is_empty(), "no {rtype} RRset at {name}");
    let covering: Vec<_> = sigs(records)
        .into_iter()
        .filter(|(r, s)| r.name == *name && s.input().type_covered == rtype)
        .collect();
    if covering.is_empty() {
        return Err(format!("no RRSIG for {rtype} at {name}"));
    }
    for (_, sig) in covering {
        key.verify_rrsig(name, DNSClass::IN, sig, set.iter())
            .map_err(|e| e.to_string())?;
    }
    Ok(())
}

fn dnskey_of(records: &[Record], name: &Name) -> DNSKEY {
    records
        .iter()
        .find_map(|r| match &r.data {
            RData::DNSSEC(DNSSECRData::DNSKEY(k)) if r.name == *name => Some(k.clone()),
            _ => None,
        })
        .expect("DNSKEY present")
}

fn ds_of(records: &[Record], name: &Name) -> Option<DS> {
    records.iter().find_map(|r| match &r.data {
        RData::DNSSEC(DNSSECRData::DS(d)) if r.name == *name => Some(d.clone()),
        _ => None,
    })
}

async fn child_key(h: &Hierarchy, zone: &str) -> DNSKEY {
    let resp = ask(h, zone, zone, RecordType::DNSKEY).await;
    let key = dnskey_of(&resp.answers, &parse_name(zone).unwrap());
    verify(
        &key,
        &resp.answers,
        &parse_name(zone).unwrap(),
        RecordType::DNSKEY,
    )
    .unwrap();
    key
}

fn nsec_of(records: &[Record]) -> Vec<(&Record, &NSEC)> {
    records
        .iter()
        .filter_map(|r| match &r.data {
            RData::DNSSEC(DNSSECRData::NSEC(n)) => Some((r, n)),
            _ => None,
        })
        .collect()
}

fn nsec3_of(records: &[Record]) -> Vec<(&Record, &NSEC3)> {
    records
        .iter()
        .filter_map(|r| match &r.data {
            RData::DNSSEC(DNSSECRData::NSEC3(n)) => Some((r, n)),
            _ => None,
        })
        .collect()
}

fn base32hex_decode(text: &str) -> Vec<u8> {
    let mut out = Vec::new();
    let (mut acc, mut bits) = (0u32, 0u32);
    for c in text.to_ascii_lowercase().bytes() {
        let v = match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'v' => c - b'a' + 10,
            _ => panic!("bad base32hex"),
        };
        acc = (acc << 5) | u32::from(v);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(((acc >> bits) & 0xff) as u8);
        }
    }
    out
}

fn owner_hash(record: &Record) -> Vec<u8> {
    let label = record.name.iter().next().unwrap();
    base32hex_decode(std::str::from_utf8(label).unwrap())
}

fn nsec3_hash(name: &str, salt: &[u8], iterations: u16) -> Vec<u8> {
    Nsec3HashAlgorithm::SHA1
        .hash(salt, &parse_name(name).unwrap(), iterations)
        .unwrap()
        .as_ref()
        .to_vec()
}

fn covers(owner: &[u8], next: &[u8], hash: &[u8]) -> bool {
    if owner < next {
        owner < hash && hash < next
    } else {
        hash > owner || hash < next
    }
}

async fn all() -> Hierarchy {
    Hierarchy::start_signed(&ChildVariant::ALL).await.unwrap()
}

#[test]
fn variants_are_selectable_by_name() {
    for v in ChildVariant::ALL {
        assert_eq!(ChildVariant::from_zone_name(v.zone_name()), Some(v));
    }
    assert_eq!(
        ChildVariant::from_zone_name("secure.test"),
        Some(ChildVariant::Secure)
    );
    assert_eq!(ChildVariant::from_zone_name("nope.test."), None);
}

#[tokio::test]
async fn trust_anchor_matches_root_dnskey() {
    let h = all().await;
    let anchor = h.trust_anchor().unwrap();
    let resp = ask(&h, ".", ".", RecordType::DNSKEY).await;
    let key = dnskey_of(&resp.answers, &Name::root());
    assert_eq!(key, anchor.dnskey);
    assert_eq!(
        anchor.dnskey_record().data,
        RData::DNSSEC(DNSSECRData::DNSKEY(key.clone()))
    );
    assert!(anchor.ds.covers(&Name::root(), &key).unwrap());
    verify(&key, &resp.answers, &Name::root(), RecordType::DNSKEY).unwrap();
    assert_eq!(u8::from(anchor.ds.algorithm()), 13);
    assert!(Hierarchy::start().await.unwrap().trust_anchor().is_none());
}

#[tokio::test]
async fn secure_chain_verifies_from_root_to_answer() {
    let h = all().await;
    let root_key = h.trust_anchor().unwrap().dnskey.clone();

    // root -> test.: DS signed by the root key, covers test.'s DNSKEY.
    let test = parse_name("test.").unwrap();
    let ds_resp = ask(&h, ".", "test.", RecordType::DS).await;
    assert!(ds_resp.metadata.authoritative);
    verify(&root_key, &ds_resp.answers, &test, RecordType::DS).unwrap();
    let test_key = child_key(&h, "test.").await;
    assert!(
        ds_of(&ds_resp.answers, &test)
            .unwrap()
            .covers(&test, &test_key)
            .unwrap()
    );

    // test. -> secure.test.
    let secure = parse_name("secure.test.").unwrap();
    let ds_resp = ask(&h, "test.", "secure.test.", RecordType::DS).await;
    verify(&test_key, &ds_resp.answers, &secure, RecordType::DS).unwrap();
    let secure_key = child_key(&h, "secure.test.").await;
    assert!(
        ds_of(&ds_resp.answers, &secure)
            .unwrap()
            .covers(&secure, &secure_key)
            .unwrap()
    );

    // The answer itself.
    let www = parse_name("www.secure.test.").unwrap();
    let resp = ask(&h, "secure.test.", "www.secure.test.", RecordType::A).await;
    assert_eq!(resp.metadata.response_code, ResponseCode::NoError);
    verify(&secure_key, &resp.answers, &www, RecordType::A).unwrap();
    let now = unix_now();
    for (_, sig) in sigs(&resp.answers) {
        assert!(sig.input().sig_inception.get() <= now);
        assert!(sig.input().sig_expiration.get() > now + 29 * 86400);
        assert_eq!(sig.input().signer_name, secure);
        assert_eq!(sig.input().num_labels, www.num_labels());
    }
}

#[tokio::test]
async fn no_dnssec_records_without_do_bit() {
    let h = all().await;
    let resp = ask_with(&h, "secure.test.", "www.secure.test.", RecordType::A, false).await;
    assert_eq!(resp.answers.len(), 1);
    let resp = ask_with(
        &h,
        "secure.test.",
        "nope.secure.test.",
        RecordType::A,
        false,
    )
    .await;
    assert_eq!(resp.metadata.response_code, ResponseCode::NXDomain);
    assert!(
        resp.authorities
            .iter()
            .all(|r| r.record_type() == RecordType::SOA)
    );
}

#[tokio::test]
async fn ds_at_zone_cut_is_answered_by_parent() {
    let h = all().await;
    let parent = h.server("test.").unwrap();
    parent.clear_queries();
    let resp = ask(&h, "test.", "secure.test.", RecordType::DS).await;
    assert!(resp.metadata.authoritative, "DS must not be a referral");
    assert_eq!(
        rrset(
            &resp.answers,
            &parse_name("secure.test.").unwrap(),
            RecordType::DS
        )
        .len(),
        1
    );
    assert!(h.server("secure.test.").unwrap().queries().is_empty());

    // Insecure child: authoritative NODATA with SOA and an NSEC proving no DS.
    let insecure = parse_name("insecure.test.").unwrap();
    let resp = ask(&h, "test.", "insecure.test.", RecordType::DS).await;
    assert!(resp.metadata.authoritative);
    assert_eq!(resp.metadata.response_code, ResponseCode::NoError);
    assert!(resp.answers.is_empty());
    assert!(
        resp.authorities
            .iter()
            .any(|r| r.record_type() == RecordType::SOA)
    );
    let nsec = nsec_of(&resp.authorities);
    let (record, data) = nsec.first().expect("NSEC proof");
    assert_eq!(record.name, insecure);
    let types: Vec<_> = data.type_bit_maps().collect();
    assert!(types.contains(&RecordType::NS) && !types.contains(&RecordType::DS));
    let test_key = child_key(&h, "test.").await;
    verify(&test_key, &resp.authorities, &insecure, RecordType::NSEC).unwrap();
    verify(
        &test_key,
        &resp.authorities,
        &parse_name("test.").unwrap(),
        RecordType::SOA,
    )
    .unwrap();

    // Referrals carry DS (secure) or the NSEC proof (insecure).
    let resp = ask(&h, "test.", "www.secure.test.", RecordType::A).await;
    assert!(!resp.metadata.authoritative);
    assert!(ds_of(&resp.authorities, &parse_name("secure.test.").unwrap()).is_some());
    assert!(!sigs(&resp.authorities).is_empty());
    let resp = ask(&h, "test.", "www.insecure.test.", RecordType::A).await;
    assert!(ds_of(&resp.authorities, &insecure).is_none());
    assert_eq!(nsec_of(&resp.authorities).len(), 1);
}

#[tokio::test]
async fn nxdomain_in_secure_zone_carries_nsec_proof() {
    let h = all().await;
    let key = child_key(&h, "secure.test.").await;
    let resp = ask(&h, "secure.test.", "nope.secure.test.", RecordType::A).await;
    assert_eq!(resp.metadata.response_code, ResponseCode::NXDomain);
    let qname = parse_name("nope.secure.test.").unwrap();
    let nsec = nsec_of(&resp.authorities);
    assert!(nsec.iter().any(|(r, n)| {
        r.name < qname && (qname < *n.next_domain_name() || n.next_domain_name() <= &r.name)
    }));
    let wildcard = parse_name("*.secure.test.").unwrap();
    assert!(nsec.iter().any(|(r, n)| {
        r.name < wildcard && (wildcard < *n.next_domain_name() || n.next_domain_name() <= &r.name)
    }));
    for (record, _) in &nsec {
        verify(&key, &resp.authorities, &record.name, RecordType::NSEC).unwrap();
    }
    verify(
        &key,
        &resp.authorities,
        &parse_name("secure.test.").unwrap(),
        RecordType::SOA,
    )
    .unwrap();

    // NODATA: matching NSEC without the queried type.
    let resp = ask(&h, "secure.test.", "www.secure.test.", RecordType::AAAA).await;
    assert_eq!(resp.metadata.response_code, ResponseCode::NoError);
    let www = parse_name("www.secure.test.").unwrap();
    let nsec = nsec_of(&resp.authorities);
    let (record, data) = nsec
        .iter()
        .find(|(r, _)| r.name == www)
        .expect("matching NSEC");
    assert!(data.type_bit_maps().all(|t| t != RecordType::AAAA));
    verify(&key, &resp.authorities, &record.name, RecordType::NSEC).unwrap();
}

#[tokio::test]
async fn nsec3_zone_carries_nsec3_proof_with_correct_hashes() {
    let h = all().await;
    let key = child_key(&h, "nsec3.test.").await;
    let salt = [0xaa, 0xbb, 0xcc, 0xdd];

    let param = ask(&h, "nsec3.test.", "nsec3.test.", RecordType::NSEC3PARAM).await;
    assert_eq!(param.answers.len() - sigs(&param.answers).len(), 1);

    let resp = ask(&h, "nsec3.test.", "nope.nsec3.test.", RecordType::A).await;
    assert_eq!(resp.metadata.response_code, ResponseCode::NXDomain);
    let proofs = nsec3_of(&resp.authorities);
    assert!(proofs.len() >= 2);
    for (record, n) in &proofs {
        assert_eq!(n.salt(), salt);
        assert_eq!(n.iterations(), 0);
        assert!(!n.opt_out());
        verify(&key, &resp.authorities, &record.name, RecordType::NSEC3).unwrap();
    }
    // Closest encloser matches exactly; next closer and wildcard are covered.
    let encloser = nsec3_hash("nsec3.test.", &salt, 0);
    assert!(proofs.iter().any(|(r, _)| owner_hash(r) == encloser));
    for name in ["nope.nsec3.test.", "*.nsec3.test."] {
        let hash = nsec3_hash(name, &salt, 0);
        assert!(
            proofs
                .iter()
                .any(|(r, n)| covers(&owner_hash(r), n.next_hashed_owner_name(), &hash)),
            "{name} not covered"
        );
    }

    // NODATA at an existing name: the matching NSEC3.
    let resp = ask(&h, "nsec3.test.", "www.nsec3.test.", RecordType::AAAA).await;
    let proofs = nsec3_of(&resp.authorities);
    let hash = nsec3_hash("www.nsec3.test.", &salt, 0);
    let (record, n) = proofs
        .iter()
        .find(|(r, _)| owner_hash(r) == hash)
        .expect("match");
    assert!(n.type_bit_maps().all(|t| t != RecordType::AAAA));
    verify(&key, &resp.authorities, &record.name, RecordType::NSEC3).unwrap();
}

#[tokio::test]
async fn nsec3_opt_out_leaves_insecure_delegation_out_of_chain() {
    let h = all().await;
    let salt = [0xaa, 0xbb, 0xcc, 0xdd];
    let resp = ask(
        &h,
        "nsec3-optout.test.",
        "unsigned.nsec3-optout.test.",
        RecordType::DS,
    )
    .await;
    assert!(resp.metadata.authoritative);
    assert!(resp.answers.is_empty());
    let proofs = nsec3_of(&resp.authorities);
    assert!(!proofs.is_empty());
    assert!(proofs.iter().all(|(_, n)| n.opt_out()));
    let hash = nsec3_hash("unsigned.nsec3-optout.test.", &salt, 0);
    assert!(proofs.iter().all(|(r, _)| owner_hash(r) != hash));
    assert!(
        proofs
            .iter()
            .any(|(r, n)| covers(&owner_hash(r), n.next_hashed_owner_name(), &hash))
    );
}

#[tokio::test]
async fn wildcard_answers_are_synthesized_with_original_labels() {
    let h = all().await;
    for (zone, expect_nsec3) in [("secure.test.", false), ("nsec3.test.", true)] {
        let key = child_key(&h, zone).await;
        let qname = format!("anything.wild.{zone}");
        let name = parse_name(&qname).unwrap();
        let resp = ask(&h, zone, &qname, RecordType::A).await;
        assert_eq!(resp.metadata.response_code, ResponseCode::NoError);
        let answers = rrset(&resp.answers, &name, RecordType::A);
        assert_eq!(answers.len(), 1);
        let (_, sig) = sigs(&resp.answers).into_iter().next().expect("RRSIG");
        assert!(sig.input().num_labels < name.num_labels());
        assert_eq!(sig.input().num_labels, name.num_labels() - 1);
        verify(&key, &resp.answers, &name, RecordType::A).unwrap();
        // The proof that the exact name does not exist accompanies the answer.
        if expect_nsec3 {
            assert_eq!(nsec3_of(&resp.authorities).len(), 1);
        } else {
            assert_eq!(nsec_of(&resp.authorities).len(), 1);
        }
        // Wildcard NODATA and a name outside the wildcard.
        let resp = ask(&h, zone, &qname, RecordType::AAAA).await;
        assert_eq!(resp.metadata.response_code, ResponseCode::NoError);
        assert!(resp.answers.is_empty());
        let resp = ask(&h, zone, &format!("x.other.{zone}"), RecordType::A).await;
        assert_eq!(resp.metadata.response_code, ResponseCode::NXDomain);
    }
}

#[tokio::test]
async fn bogus_signature_fails_verification() {
    let h = all().await;
    let key = child_key(&h, "bogus-sig.test.").await;
    let www = parse_name("www.bogus-sig.test.").unwrap();
    let resp = ask(&h, "bogus-sig.test.", "www.bogus-sig.test.", RecordType::A).await;
    assert!(verify(&key, &resp.answers, &www, RecordType::A).is_err());
    // Everything else in the zone is still valid.
    let soa = ask(&h, "bogus-sig.test.", "bogus-sig.test.", RecordType::SOA).await;
    verify(
        &key,
        &soa.answers,
        &parse_name("bogus-sig.test.").unwrap(),
        RecordType::SOA,
    )
    .unwrap();
}

#[tokio::test]
async fn expired_signatures_are_valid_but_outside_their_window() {
    let h = all().await;
    let key = child_key(&h, "bogus-expired.test.").await;
    let www = parse_name("www.bogus-expired.test.").unwrap();
    let resp = ask(
        &h,
        "bogus-expired.test.",
        "www.bogus-expired.test.",
        RecordType::A,
    )
    .await;
    verify(&key, &resp.answers, &www, RecordType::A).unwrap();
    let now = unix_now();
    let (_, sig) = sigs(&resp.answers).into_iter().next().unwrap();
    assert!(sig.input().sig_expiration.get() < now);
    assert!(sig.input().sig_inception.get() < sig.input().sig_expiration.get());
}

#[tokio::test]
async fn bogus_nokey_ds_does_not_match_published_key() {
    let h = all().await;
    let name = parse_name("bogus-nokey.test.").unwrap();
    let key = child_key(&h, "bogus-nokey.test.").await;
    let ds = ask(&h, "test.", "bogus-nokey.test.", RecordType::DS).await;
    let ds = ds_of(&ds.answers, &name).expect("DS in parent");
    assert!(!ds.covers(&name, &key).unwrap());
    // Control: the secure zone's DS does match.
    let name = parse_name("secure.test.").unwrap();
    let key = child_key(&h, "secure.test.").await;
    let ds = ask(&h, "test.", "secure.test.", RecordType::DS).await;
    assert!(
        ds_of(&ds.answers, &name)
            .unwrap()
            .covers(&name, &key)
            .unwrap()
    );
}

#[tokio::test]
async fn insecure_zone_is_unsigned() {
    let h = all().await;
    let resp = ask(&h, "insecure.test.", "www.insecure.test.", RecordType::A).await;
    assert_eq!(resp.answers.len(), 1);
    let resp = ask(&h, "insecure.test.", "insecure.test.", RecordType::DNSKEY).await;
    assert!(resp.answers.is_empty());
}

#[tokio::test]
async fn other_algorithms_sign_and_verify() {
    for (alg, number) in [(SigAlgorithm::RsaSha256, 8u8), (SigAlgorithm::Ed25519, 15)] {
        let h = Hierarchy::start_scenario(
            &DnssecScenario::new(&[ChildVariant::Secure]).with_algorithm(alg),
        )
        .await
        .unwrap();
        let key = child_key(&h, "secure.test.").await;
        assert_eq!(u8::from(key.algorithm()), number);
        let www = parse_name("www.secure.test.").unwrap();
        let resp = ask(&h, "secure.test.", "www.secure.test.", RecordType::A).await;
        verify(&key, &resp.answers, &www, RecordType::A).unwrap();
    }
}

#[tokio::test]
async fn explicit_time_controls_validity_window() {
    let h = Hierarchy::start_scenario(
        &DnssecScenario::new(&[ChildVariant::Secure]).with_validity(1_000_000, 2_000_000),
    )
    .await
    .unwrap();
    let resp = ask(&h, "secure.test.", "www.secure.test.", RecordType::A).await;
    let (_, sig) = sigs(&resp.answers).into_iter().next().unwrap();
    assert_eq!(sig.input().sig_inception.get(), 1_000_000);
    assert_eq!(sig.input().sig_expiration.get(), 2_000_000);
}
