//! Oracle tests: DNSSEC RDATA, key tags, DS digests, NSEC3 hashes and the
//! RRset signing input against hickory-proto's DNSSEC implementation.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::net::Ipv4Addr;

use dnscraft_proto::dnssec::{
    MAX_ITERATIONS_DEFAULT, NSEC3_HASH_SHA1, ds_digest, key_tag, nsec3_hash, rrsig_signing_input,
};
use dnscraft_proto::{Class, Name, RData, Record, RecordType, TypeBitmap};
use hickory_proto::dnssec::rdata::{DNSKEY, DNSSECRData};
use hickory_proto::dnssec::{
    Algorithm, DigestType, Nsec3HashAlgorithm, PublicKey, PublicKeyBuf, TBS,
};
use hickory_proto::rr::{Name as HName, RData as HRData, Record as HRecord};
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable, BinEncoder, NameEncoding};

fn n(s: &str) -> Name {
    Name::from_ascii(s).expect("our name")
}

fn rec(owner: &str, rdata: RData) -> Record {
    Record {
        name: n(owner),
        rtype: rdata.record_type(),
        class: Class::IN,
        ttl: 300,
        rdata,
    }
}

fn our_bytes(r: &Record) -> Vec<u8> {
    let mut buf = Vec::new();
    r.encode(&mut buf, None).expect("encode");
    buf
}

fn hickory_of(r: &Record) -> HRecord {
    HRecord::from_bytes(&our_bytes(r)).expect("hickory decodes our bytes")
}

fn hickory_bytes(r: &HRecord) -> Vec<u8> {
    let mut buf = Vec::new();
    let mut enc = BinEncoder::new(&mut buf);
    enc.set_name_encoding(NameEncoding::Uncompressed);
    r.emit(&mut enc).expect("hickory encodes");
    buf
}

fn types(list: &[RecordType]) -> TypeBitmap {
    TypeBitmap::new(list.iter().copied())
}

fn rrsig(covered: RecordType, labels: u8, signer: &str, expiration: u32, inception: u32) -> RData {
    RData::RRSIG {
        type_covered: covered,
        algorithm: 13,
        labels,
        original_ttl: 3600,
        expiration,
        inception,
        key_tag: 4242,
        signer_name: n(signer),
        signature: vec![0xAB; 64].into(),
    }
}

fn corpus() -> Vec<Record> {
    vec![
        rec(
            "example.com.",
            RData::DNSKEY {
                flags: 257,
                protocol: 3,
                algorithm: 13,
                public_key: vec![5; 64].into(),
            },
        ),
        rec(
            "example.com.",
            RData::DS {
                key_tag: 20326,
                algorithm: 8,
                digest_type: 2,
                digest: vec![0x11; 32].into(),
            },
        ),
        rec(
            "www.example.com.",
            rrsig(
                RecordType::A,
                3,
                "example.com.",
                2_000_000_000,
                1_900_000_000,
            ),
        ),
        rec(
            "a.example.com.",
            RData::NSEC {
                next_domain: n("b.example.com."),
                types: types(&[
                    RecordType::A,
                    RecordType::MX,
                    RecordType::RRSIG,
                    RecordType::NSEC,
                    RecordType(1234),
                ]),
            },
        ),
        rec(
            "0p9mhaveqvm6t7vbl5lop2u3t2rp3tom.example.",
            RData::NSEC3 {
                hash_algorithm: 1,
                flags: 1,
                iterations: 12,
                salt: vec![0xAA, 0xBB, 0xCC, 0xDD].into(),
                next_hashed_owner: vec![0x42; 20].into(),
                types: types(&[RecordType::NS, RecordType::DS, RecordType::RRSIG]),
            },
        ),
        rec(
            "example.",
            RData::NSEC3PARAM {
                hash_algorithm: 1,
                flags: 0,
                iterations: 12,
                salt: vec![0xAA, 0xBB].into(),
            },
        ),
    ]
}

#[test]
fn round_trip_all_six_types() {
    for ours in corpus() {
        let theirs = hickory_of(&ours);
        // Hickory re-emits exactly the octets we produced...
        assert_eq!(hickory_bytes(&theirs), our_bytes(&ours), "{}", ours.rtype);
        // ...and we decode hickory's output back to the same record.
        let (back, end) = Record::decode(&hickory_bytes(&theirs), 0).expect("ours decodes");
        assert_eq!(back, ours);
        assert_eq!(end, our_bytes(&ours).len());
    }
}

#[test]
fn decoded_fields_agree() {
    for ours in corpus() {
        let theirs = hickory_of(&ours);
        let HRData::DNSSEC(d) = theirs.data else {
            panic!("not a DNSSEC rdata");
        };
        match (&ours.rdata, d) {
            (
                RData::DNSKEY {
                    flags, public_key, ..
                },
                DNSSECRData::DNSKEY(k),
            ) => {
                assert_eq!(k.flags(), *flags);
                assert_eq!(k.public_key().public_bytes(), &public_key[..]);
            }
            (
                RData::DS {
                    key_tag, digest, ..
                },
                DNSSECRData::DS(ds),
            ) => {
                assert_eq!(ds.key_tag(), *key_tag);
                assert_eq!(ds.digest(), &digest[..]);
            }
            (
                RData::RRSIG {
                    key_tag, signature, ..
                },
                DNSSECRData::RRSIG(s),
            ) => {
                assert_eq!(s.input().key_tag, *key_tag);
                assert_eq!(s.sig(), &signature[..]);
            }
            (RData::NSEC { types, .. }, DNSSECRData::NSEC(nsec)) => {
                let theirs: Vec<u16> = nsec.type_bit_maps().map(u16::from).collect();
                let mine: Vec<u16> = types.iter().map(RecordType::value).collect();
                assert_eq!(theirs, mine);
            }
            (
                RData::NSEC3 {
                    iterations,
                    salt,
                    next_hashed_owner,
                    types,
                    flags,
                    ..
                },
                DNSSECRData::NSEC3(nsec3),
            ) => {
                assert_eq!(nsec3.iterations(), *iterations);
                assert_eq!(nsec3.salt(), &salt[..]);
                assert_eq!(nsec3.next_hashed_owner_name(), &next_hashed_owner[..]);
                assert_eq!(nsec3.flags(), *flags);
                let theirs: Vec<u16> = nsec3.type_bit_maps().map(u16::from).collect();
                let mine: Vec<u16> = types.iter().map(RecordType::value).collect();
                assert_eq!(theirs, mine);
            }
            (
                RData::NSEC3PARAM {
                    iterations, salt, ..
                },
                DNSSECRData::NSEC3PARAM(p),
            ) => {
                assert_eq!(p.iterations(), *iterations);
                assert_eq!(p.salt(), &salt[..]);
            }
            (a, b) => panic!("mismatched variants {a:?} / {b:?}"),
        }
    }
}

#[test]
fn key_tag_ds_digest_and_nsec3_hash_match_hickory() {
    let owner = n("Example.COM.");
    let howner = HName::from_ascii("Example.COM.").expect("name");
    for (flags, algorithm, key) in [
        (257u16, 8u8, vec![3u8, 1, 0, 1, 9, 9, 9, 9, 9, 8, 7]),
        (256, 13, vec![0x55; 64]),
        (257, 15, (0..32).collect::<Vec<u8>>()),
        (256, 8, vec![1, 2, 3]),
    ] {
        let ours = RData::DNSKEY {
            flags,
            protocol: 3,
            algorithm,
            public_key: key.clone().into(),
        };
        let theirs = DNSKEY::with_flags(
            flags,
            PublicKeyBuf::new(key.clone(), Algorithm::from_u8(algorithm)),
        );
        assert_eq!(
            Some(theirs.calculate_key_tag().expect("tag")),
            Some(key_tag(flags, 3, algorithm, &key)),
        );
        for (ours_type, theirs_type) in [
            (1u8, DigestType::SHA1),
            (2, DigestType::SHA256),
            (4, DigestType::SHA384),
        ] {
            let want = theirs.to_digest(&howner, theirs_type).expect("digest");
            assert_eq!(
                ds_digest(&owner, &ours, ours_type).expect("ours"),
                want.as_ref()
            );
        }
    }

    let salt = [0xAAu8, 0xBB, 0xCC, 0xDD];
    for (name, iterations) in [("example.", 12u16), ("A.B.Example.", 0), ("x.", 150)] {
        let want = Nsec3HashAlgorithm::SHA1
            .hash(&salt, &HName::from_ascii(name).expect("name"), iterations)
            .expect("hash");
        let got = nsec3_hash(
            NSEC3_HASH_SHA1,
            &n(name),
            &salt,
            iterations,
            MAX_ITERATIONS_DEFAULT,
        )
        .expect("ours");
        assert_eq!(&got[..], want.as_ref(), "{name}");
    }
}

/// Our signing input against hickory's `TBS` for the same RRset and RRSIG.
fn assert_tbs_matches(rrsig_rdata: &RData, rrset: &[Record]) {
    let ours = rrsig_signing_input(rrsig_rdata, rrset).expect("ours");

    let sig_record = Record {
        name: rrset.first().expect("non-empty").name.clone(),
        rtype: RecordType::RRSIG,
        class: Class::IN,
        ttl: 300,
        rdata: rrsig_rdata.clone(),
    };
    let HRData::DNSSEC(DNSSECRData::RRSIG(hsig)) = hickory_of(&sig_record).data else {
        panic!("not an RRSIG");
    };
    let hrecords: Vec<HRecord> = rrset.iter().map(hickory_of).collect();
    let owner = hrecords.first().expect("non-empty").name.clone();
    let tbs = TBS::from_input(
        &owner,
        hickory_proto::rr::DNSClass::IN,
        hsig.input(),
        hrecords.iter(),
    )
    .expect("hickory tbs");
    assert_eq!(ours, tbs.as_ref());
}

#[test]
fn signing_input_mixed_case_a_rrset() {
    let rrset = [
        rec("WwW.ExAmPlE.CoM.", RData::A(Ipv4Addr::new(192, 0, 2, 9))),
        rec("www.example.com.", RData::A(Ipv4Addr::new(192, 0, 2, 1))),
        rec("WWW.example.com.", RData::A(Ipv4Addr::new(192, 0, 2, 5))),
    ];
    let sig = rrsig(
        RecordType::A,
        3,
        "ExAmPlE.CoM.",
        2_000_000_000,
        1_900_000_000,
    );
    assert_tbs_matches(&sig, &rrset);
}

#[test]
fn signing_input_names_in_rdata() {
    let mx = [
        rec(
            "example.com.",
            RData::MX {
                preference: 20,
                exchange: n("MAIL2.Example.COM."),
            },
        ),
        rec(
            "example.com.",
            RData::MX {
                preference: 10,
                exchange: n("Mail1.EXAMPLE.com."),
            },
        ),
    ];
    assert_tbs_matches(
        &rrsig(
            RecordType::MX,
            2,
            "example.com.",
            2_000_000_000,
            1_900_000_000,
        ),
        &mx,
    );
    // Hickory sorts by the raw, not the lowercased, RDATA octets (an RFC 4034
    // section 6.3 deviation: with "NS2" and "ns1" it puts "NS2" first), so the
    // names here are chosen to sort the same way in both forms.
    let ns = [
        rec("example.com.", RData::NS(n("ns2.EXAMPLE.com."))),
        rec("example.com.", RData::NS(n("NS1.Example.com."))),
    ];
    assert_tbs_matches(
        &rrsig(
            RecordType::NS,
            2,
            "example.com.",
            2_000_000_000,
            1_900_000_000,
        ),
        &ns,
    );
    let soa = [rec(
        "example.com.",
        RData::SOA {
            mname: n("NS.Example.com."),
            rname: n("Host.Example.com."),
            serial: 1,
            refresh: 2,
            retry: 3,
            expire: 4,
            minimum: 5,
        },
    )];
    assert_tbs_matches(
        &rrsig(
            RecordType::SOA,
            2,
            "example.com.",
            2_000_000_000,
            1_900_000_000,
        ),
        &soa,
    );
    let srv = [rec(
        "_sip._tcp.example.com.",
        RData::SRV {
            priority: 1,
            weight: 2,
            port: 5060,
            target: n("SIP.Example.com."),
        },
    )];
    assert_tbs_matches(
        &rrsig(
            RecordType::SRV,
            4,
            "example.com.",
            2_000_000_000,
            1_900_000_000,
        ),
        &srv,
    );
}

#[test]
fn signing_input_wildcard_expansion() {
    // Owner a.b.example.com. answered from *.example.com.: RRSIG labels = 2.
    let rrset = [rec(
        "A.B.example.com.",
        RData::A(Ipv4Addr::new(198, 51, 100, 7)),
    )];
    let sig = rrsig(
        RecordType::A,
        2,
        "example.com.",
        2_000_000_000,
        1_900_000_000,
    );
    assert_tbs_matches(&sig, &rrset);
    let input = rrsig_signing_input(&sig, &rrset).expect("ours");
    // The owner in the signing input is the wildcard name.
    let needle = b"\x01*\x07example\x03com\x00";
    assert!(input.windows(needle.len()).any(|w| w == needle));
    assert!(!input.windows(3).any(|w| w == b"\x01a\x01"));
}

#[test]
fn signing_input_wildcard_owner_itself_and_root_labels() {
    // The wildcard record as stored in the zone: labels excludes the "*".
    let rrset = [rec("*.Example.com.", RData::A(Ipv4Addr::new(192, 0, 2, 1)))];
    assert_tbs_matches(
        &rrsig(
            RecordType::A,
            2,
            "example.com.",
            2_000_000_000,
            1_900_000_000,
        ),
        &rrset,
    );
    // Labels 0: the expansion is "*." under the root.
    let rrset = [rec("x.y.", RData::A(Ipv4Addr::new(192, 0, 2, 1)))];
    assert_tbs_matches(&rrsig(RecordType::A, 0, ".", 2, 1), &rrset);
}

#[test]
fn signing_input_sorts_by_lowercased_rdata() {
    // RFC 4034 section 6.3: canonical RDATA octets decide, so "ns1" sorts
    // before "NS2" even though 'N' < 'n' in the raw octets.
    let rrset = [
        rec("example.com.", RData::NS(n("NS2.example.com."))),
        rec("example.com.", RData::NS(n("ns1.example.com."))),
    ];
    let sig = rrsig(RecordType::NS, 2, "example.com.", 2, 1);
    let input = rrsig_signing_input(&sig, &rrset).expect("ours");
    let pos = |needle: &[u8]| input.windows(needle.len()).position(|w| w == needle);
    assert!(pos(b"\x03ns1").expect("ns1") < pos(b"\x03ns2").expect("ns2"));
}
