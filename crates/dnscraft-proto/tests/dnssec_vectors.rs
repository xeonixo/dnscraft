//! Real-world DNSSEC vectors: the IANA root trust anchors and the live root
//! DNSKEY RRset with its RRSIG, used to check key tags, DS digests and the
//! RRset signing input end to end (the signature is verified with `ring`).
//!
//! Source: https://data.iana.org/root-anchors/root-anchors.xml and
//! `dig . DNSKEY +dnssec @1.1.1.1`, both fetched on 2026-10-24.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use dnscraft_proto::dnssec::{
    DIGEST_SHA256, dnskey_key_tag, ds_digest, ds_digest_from_wire, key_tag_from_rdata,
    rrsig_signing_input,
};
use dnscraft_proto::{Class, Name, RData, Record, RecordType};
use ring::signature::{RSA_PKCS1_2048_8192_SHA256, RsaPublicKeyComponents};

const KSK_20326: &str = "AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3+/4RgWOq7HrxRixHlFlExOLAJr5emLvN7SWXgnLh4+B5xQlNVz8Og8kvArMtNROxVQuCaSnIDdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF0jLHwVN8efS3rCj/EWgvIWgb9tarpVUDK/b58Da+sqqls3eNbuv7pr+eoZG+SrDK6nWeL3c6H5Apxz7LjVc1uTIdsIXxuOLYA4/ilBmSVIzuDWfdRUfhHdY6+cn8HFRm+2hM8AnXGXws9555KrUB5qihylGa8subX2Nn6UwNR1AkUTV74bU=";
const KSK_38696: &str = "AwEAAa96jeuknZlaeSrvyAJj6ZHv28hhOKkx3rLGXVaC6rXTsDc449/cidltpkyGwCJNnOAlFNKF2jBosZBU5eeHspaQWOmOElZsjICMQMC3aeHbGiShvZsx4wMYSjH8e7Vrhbu6irwCzVBApESjbUdpWWmEnhathWu1jo+siFUiRAAxm9qyJNg/wOZqqzL/dL/q8PkcRU5oUKEpUge71M3ej2/7CPqpdVwuMoTvoB+ZOT4YeGyxMvHmbrxlFzGOHOijtzN+u1TQNatX2XBuzZNQ1K+s2CXkPIZo7s6JgZyvaBevYtxPvYLw4z9mR7K2vaF18UYH9Z9GNUUeayffKC73PYc=";
const ZSK_8763: &str = "AwEAAcorNxNc9t0ue1ZenPjVMRujlQ2YLBJ0pR/4XMjHby9vr03cRxFSKnWpxeg5PL384D9VeqdS1bjrGyTsHtoagzI3NiXFd8sjHMOnZxu5pp/+UBIg7tasYgVMMdUiM1Yu/c+t30d1Qw/v6NYLNnOnywTu6HuUh7Y1sZRq/GZcrxLENXHQoyKpOrOr8R3+qd6wK69IKB80ZBZtkX9rdEqKJk+yYXjEZzZ0zkAFthmNgCreAoU9PVlU66dyOsaLjf3wKUlUm9SNOKs+tK6LuSmRbK6+1T/tPaRaMBSEuv2G6vXfnJ1uyMbGvtpRn/YDcvTjrp6DzE6XyF44QdwJ3oKx4ek=";
const DIGEST_20326: &str = "E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D";
const DIGEST_38696: &str = "683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16";
/// RRSIG over the root DNSKEY RRset: inception 2026-10-21, expiration 2026-11-11.
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

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02X}")).collect()
}

fn dnskey(flags: u16, key: &str) -> RData {
    RData::DNSKEY {
        flags,
        protocol: 3,
        algorithm: 8,
        public_key: b64(key).into(),
    }
}

#[test]
fn root_key_tags() {
    assert_eq!(dnskey_key_tag(&dnskey(257, KSK_20326)), Some(20326));
    assert_eq!(dnskey_key_tag(&dnskey(257, KSK_38696)), Some(38696));
    assert_eq!(dnskey_key_tag(&dnskey(256, ZSK_8763)), Some(8763));
    let mut wire = Vec::new();
    dnskey(257, KSK_20326).encode(&mut wire, None).unwrap();
    assert_eq!(key_tag_from_rdata(&wire, 8), 20326);
}

#[test]
fn root_ds_digests() {
    let root = Name::root();
    for (key, want) in [(KSK_20326, DIGEST_20326), (KSK_38696, DIGEST_38696)] {
        let got = ds_digest(&root, &dnskey(257, key), DIGEST_SHA256).unwrap();
        assert_eq!(hex(&got), want);
    }
    // The digest of the wire form is the same, and other digest types differ
    // in length but not in determinism.
    let mut wire = Vec::new();
    dnskey(257, KSK_20326).encode(&mut wire, None).unwrap();
    assert_eq!(
        hex(&ds_digest_from_wire(&root, &wire, 2).unwrap()),
        DIGEST_20326
    );
    assert_eq!(ds_digest_from_wire(&root, &wire, 1).unwrap().len(), 20);
    assert_eq!(ds_digest_from_wire(&root, &wire, 4).unwrap().len(), 48);
}

/// Splits RFC 3110 RSA key material into (exponent, modulus).
fn rsa_parts(key: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let (first, rest) = key.split_first().unwrap();
    assert_ne!(*first, 0, "long exponent form not used by the root");
    let (e, n) = rest.split_at(usize::from(*first));
    (e.to_vec(), n.to_vec())
}

#[test]
fn root_dnskey_rrset_signing_input_verifies() {
    let rrset: Vec<Record> = [
        dnskey(256, ZSK_8763),
        dnskey(257, KSK_20326),
        dnskey(257, KSK_38696),
    ]
    .into_iter()
    .map(|rdata| Record {
        name: Name::root(),
        rtype: RecordType::DNSKEY,
        class: Class::IN,
        ttl: 2567,
        rdata,
    })
    .collect();
    let rrsig = RData::RRSIG {
        type_covered: RecordType::DNSKEY,
        algorithm: 8,
        labels: 0,
        original_ttl: 172_800,
        // 20261111000000 and 20261021000000 UTC.
        expiration: 1_794_355_200,
        inception: 1_792_540_800,
        key_tag: 38696,
        signer_name: Name::root(),
        signature: b64(RRSIG_38696).into(),
    };
    let RData::RRSIG { signature, .. } = &rrsig else {
        unreachable!()
    };
    let input = rrsig_signing_input(&rrsig, &rrset).unwrap();

    let RData::DNSKEY { public_key, .. } = dnskey(257, KSK_38696) else {
        unreachable!()
    };
    let (e, n) = rsa_parts(&public_key);
    RsaPublicKeyComponents { n, e }
        .verify(&RSA_PKCS1_2048_8192_SHA256, &input, signature)
        .expect("the real root signature verifies over our signing input");

    // Any change to the input must break the signature.
    let mut tampered = input;
    *tampered.last_mut().unwrap() ^= 1;
    let (e, n) = rsa_parts(&public_key);
    assert!(
        RsaPublicKeyComponents { n, e }
            .verify(&RSA_PKCS1_2048_8192_SHA256, &tampered, signature)
            .is_err()
    );
}
