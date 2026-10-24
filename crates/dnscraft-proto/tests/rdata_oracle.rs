//! Oracle tests: compare `Record`/`RData` against hickory-proto.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::net::{Ipv4Addr, Ipv6Addr};

use dnscraft_proto::{Class, CompressionMap, Name, RData, Record, RecordType, SvcbData};
use hickory_proto::dnssec::rdata::{DNSSECRData, DS};
use hickory_proto::dnssec::{Algorithm, DigestType};
use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::rdata::caa::KeyValue;
use hickory_proto::rr::rdata::null::NULL;
use hickory_proto::rr::rdata::svcb::{Alpn, SVCB, SvcParamKey, SvcParamValue};
use hickory_proto::rr::rdata::{A, AAAA, CAA, CNAME, HTTPS, MX, NS, PTR, SOA, SRV, TXT};
use hickory_proto::rr::{Name as HName, RData as HRData, Record as HRecord, RecordType as HType};
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable, BinEncoder, NameEncoding};

fn hn(s: &str) -> HName {
    HName::from_ascii(s).expect("hickory name")
}

fn n(s: &str) -> Name {
    Name::from_ascii(s).expect("our name")
}

fn ours(name: &str, rtype: RecordType, ttl: u32, rdata: RData) -> Record {
    Record {
        name: n(name),
        rtype,
        class: Class::IN,
        ttl,
        rdata,
    }
}

/// Pairs of the hickory record and the record we expect to decode from it.
fn corpus() -> Vec<(HRecord, Record)> {
    let h = |name: &str, ttl: u32, data: HRData| HRecord::from_rdata(hn(name), ttl, data);
    let svcb_params = vec![
        (
            SvcParamKey::Alpn,
            SvcParamValue::Alpn(Alpn(vec!["h2".into(), "h3".into()])),
        ),
        (SvcParamKey::NoDefaultAlpn, SvcParamValue::NoDefaultAlpn),
        (SvcParamKey::Port, SvcParamValue::Port(8443)),
    ];
    let our_params: Vec<(u16, Box<[u8]>)> = vec![
        (1, b"\x02h2\x02h3".to_vec().into()),
        (2, Box::new([])),
        (3, vec![0x20, 0xFB].into()),
    ];
    vec![
        (
            h(
                "www.example.com.",
                300,
                HRData::A(A(Ipv4Addr::new(192, 0, 2, 1))),
            ),
            ours(
                "www.example.com.",
                RecordType::A,
                300,
                RData::A(Ipv4Addr::new(192, 0, 2, 1)),
            ),
        ),
        (
            h(
                "www.example.com.",
                300,
                HRData::AAAA(AAAA(Ipv6Addr::LOCALHOST)),
            ),
            ours(
                "www.example.com.",
                RecordType::AAAA,
                300,
                RData::AAAA(Ipv6Addr::LOCALHOST),
            ),
        ),
        (
            h("example.com.", 3600, HRData::NS(NS(hn("ns1.example.com.")))),
            ours(
                "example.com.",
                RecordType::NS,
                3600,
                RData::NS(n("ns1.example.com.")),
            ),
        ),
        (
            h(
                "www.example.com.",
                60,
                HRData::CNAME(CNAME(hn("web.example.com."))),
            ),
            ours(
                "www.example.com.",
                RecordType::CNAME,
                60,
                RData::CNAME(n("web.example.com.")),
            ),
        ),
        (
            h(
                "1.2.0.192.in-addr.arpa.",
                60,
                HRData::PTR(PTR(hn("host.example.com."))),
            ),
            ours(
                "1.2.0.192.in-addr.arpa.",
                RecordType::PTR,
                60,
                RData::PTR(n("host.example.com.")),
            ),
        ),
        (
            h(
                "example.com.",
                3600,
                HRData::SOA(SOA::new(
                    hn("ns1.example.com."),
                    hn("hostmaster.example.com."),
                    2024010101,
                    7200,
                    3600,
                    1209600,
                    300,
                )),
            ),
            ours(
                "example.com.",
                RecordType::SOA,
                3600,
                RData::SOA {
                    mname: n("ns1.example.com."),
                    rname: n("hostmaster.example.com."),
                    serial: 2024010101,
                    refresh: 7200,
                    retry: 3600,
                    expire: 1209600,
                    minimum: 300,
                },
            ),
        ),
        (
            h(
                "example.com.",
                300,
                HRData::MX(MX::new(10, hn("mail.example.com."))),
            ),
            ours(
                "example.com.",
                RecordType::MX,
                300,
                RData::MX {
                    preference: 10,
                    exchange: n("mail.example.com."),
                },
            ),
        ),
        (
            h(
                "example.com.",
                300,
                HRData::TXT(TXT::new(vec![
                    "v=spf1 -all".into(),
                    "second".into(),
                    String::new(),
                ])),
            ),
            ours(
                "example.com.",
                RecordType::TXT,
                300,
                RData::TXT(vec![
                    b"v=spf1 -all".to_vec().into(),
                    b"second".to_vec().into(),
                    Vec::new().into(),
                ]),
            ),
        ),
        (
            h(
                "_sip._tcp.example.com.",
                300,
                HRData::SRV(SRV::new(1, 2, 5060, hn("sip.example.com."))),
            ),
            ours(
                "_sip._tcp.example.com.",
                RecordType::SRV,
                300,
                RData::SRV {
                    priority: 1,
                    weight: 2,
                    port: 5060,
                    target: n("sip.example.com."),
                },
            ),
        ),
        (
            h(
                "example.com.",
                300,
                HRData::CAA(CAA::new_issue(
                    true,
                    Some(hn("ca.example.net.")),
                    vec![KeyValue::new("account", "123")],
                )),
            ),
            ours(
                "example.com.",
                RecordType::CAA,
                300,
                RData::CAA {
                    flags: 128,
                    tag: "issue".into(),
                    value: b"ca.example.net.; account=123".to_vec().into(),
                },
            ),
        ),
        (
            h(
                "_dns.resolver.example.",
                300,
                HRData::SVCB(SVCB::new(1, hn("dot.example."), svcb_params.clone())),
            ),
            ours(
                "_dns.resolver.example.",
                RecordType::SVCB,
                300,
                RData::SVCB(SvcbData {
                    priority: 1,
                    target: n("dot.example."),
                    params: our_params.clone(),
                }),
            ),
        ),
        (
            h(
                "example.com.",
                300,
                HRData::HTTPS(HTTPS(SVCB::new(0, hn("."), Vec::new()))),
            ),
            ours(
                "example.com.",
                RecordType::HTTPS,
                300,
                RData::HTTPS(SvcbData {
                    priority: 0,
                    target: Name::root(),
                    params: Vec::new(),
                }),
            ),
        ),
        (
            h(
                "example.com.",
                300,
                HRData::HTTPS(HTTPS(SVCB::new(1, hn("."), svcb_params))),
            ),
            ours(
                "example.com.",
                RecordType::HTTPS,
                300,
                RData::HTTPS(SvcbData {
                    priority: 1,
                    target: Name::root(),
                    params: our_params,
                }),
            ),
        ),
        (
            h(
                "example.com.",
                300,
                HRData::Unknown {
                    code: HType::Unknown(65280),
                    rdata: NULL::with(vec![0xDE, 0xAD, 0xBE, 0xEF]),
                },
            ),
            ours(
                "example.com.",
                RecordType(65280),
                300,
                RData::Unknown {
                    rtype: RecordType(65280),
                    data: vec![0xDE, 0xAD, 0xBE, 0xEF].into(),
                },
            ),
        ),
        // DS is a typed record since W4.
        (
            h(
                "example.com.",
                300,
                HRData::DNSSEC(DNSSECRData::DS(DS::new(
                    0x4E20,
                    Algorithm::RSASHA256,
                    DigestType::SHA256,
                    vec![1, 2, 3, 4, 5, 6, 7, 8],
                ))),
            ),
            ours(
                "example.com.",
                RecordType::DS,
                300,
                RData::DS {
                    key_tag: 0x4E20,
                    algorithm: 8,
                    digest_type: 2,
                    digest: vec![1, 2, 3, 4, 5, 6, 7, 8].into(),
                },
            ),
        ),
    ]
}

fn hickory_bytes(rec: &HRecord, encoding: NameEncoding) -> Vec<u8> {
    let mut buf = Vec::new();
    let mut enc = BinEncoder::new(&mut buf);
    enc.set_name_encoding(encoding);
    rec.emit(&mut enc).expect("hickory encodes");
    buf
}

fn hickory_decode(bytes: &[u8]) -> HRecord {
    HRecord::from_bytes(bytes).expect("hickory decodes")
}

#[test]
fn decode_hickory_bytes_with_and_without_compression() {
    for (theirs, expected) in corpus() {
        for encoding in [NameEncoding::Compressed, NameEncoding::Uncompressed] {
            let bytes = hickory_bytes(&theirs, encoding);
            let (decoded, end) = Record::decode(&bytes, 0).expect("ours decodes");
            assert_eq!(end, bytes.len(), "{}", expected.rtype);
            assert_eq!(decoded, expected, "{}", expected.rtype);
        }
    }
}

#[test]
fn our_reencoding_decodes_in_hickory() {
    for (theirs, expected) in corpus() {
        let bytes = hickory_bytes(&theirs, NameEncoding::Compressed);
        let (decoded, _) = Record::decode(&bytes, 0).expect("ours decodes");

        let mut plain = Vec::new();
        decoded.encode(&mut plain, None).expect("encode");
        assert_eq!(hickory_decode(&plain), theirs, "plain {}", expected.rtype);

        let mut compressed = Vec::new();
        let mut map = CompressionMap::new();
        decoded
            .encode(&mut compressed, Some(&mut map))
            .expect("encode");
        assert_eq!(
            hickory_decode(&compressed),
            theirs,
            "compressed {}",
            expected.rtype
        );
        // And we read our own output back identically.
        assert_eq!(Record::decode(&compressed, 0).expect("own").0, expected);
    }
}

#[test]
fn uncompressed_bytes_match_hickory() {
    for (theirs, expected) in corpus() {
        let want = hickory_bytes(&theirs, NameEncoding::Uncompressed);
        let mut got = Vec::new();
        expected.encode(&mut got, None).expect("encode");
        assert_eq!(got, want, "{}", expected.rtype);
    }
}

#[test]
fn compressed_bytes_match_hickory_for_legacy_types() {
    // Hickory compresses exactly the RFC 3597 set (plus owner names); where
    // both sides compress, the bytes agree.
    for (theirs, expected) in corpus() {
        if !matches!(
            expected.rtype,
            RecordType::NS
                | RecordType::CNAME
                | RecordType::SOA
                | RecordType::PTR
                | RecordType::MX
                | RecordType::A
                | RecordType::AAAA
                | RecordType::TXT
        ) {
            continue;
        }
        let want = hickory_bytes(&theirs, NameEncoding::Compressed);
        let mut got = Vec::new();
        let mut map = CompressionMap::new();
        expected.encode(&mut got, Some(&mut map)).expect("encode");
        assert_eq!(got, want, "{}", expected.rtype);
    }
}

/// Offset just after the 12-byte header and the question section.
fn skip_question(msg: &[u8], count: usize) -> usize {
    let mut pos = 12;
    for _ in 0..count {
        let (_, next) = Name::decode(msg, pos).expect("question name");
        pos = next + 4;
    }
    pos
}

#[test]
fn walk_hickory_message_with_shared_suffixes() {
    let mut msg = Message::new(7, MessageType::Response, OpCode::Query);
    msg.add_query(Query::query(hn("www.example.com."), HType::A));
    let records: Vec<(HRecord, Record)> = corpus()
        .into_iter()
        .filter(|(_, o)| !matches!(o.rtype, RecordType::SVCB | RecordType::HTTPS))
        .collect();
    for (theirs, _) in &records {
        msg.add_answer(theirs.clone());
    }
    let extra = HRecord::from_rdata(
        hn("mail.example.com."),
        10,
        HRData::CNAME(CNAME(hn("www.example.com."))),
    );
    msg.add_additional(extra.clone());
    let bytes = msg.to_vec().expect("hickory encodes message");

    let mut pos = skip_question(&bytes, 1);
    for (_, expected) in &records {
        let (rec, next) = Record::decode(&bytes, pos).expect("walk");
        assert_eq!(&rec, expected);
        pos = next;
    }
    let (rec, next) = Record::decode(&bytes, pos).expect("additional");
    assert_eq!(rec.name, n("mail.example.com."));
    assert_eq!(rec.rdata, RData::CNAME(n("www.example.com.")));
    assert_eq!(next, bytes.len());
    // Shared suffixes were really compressed on the wire.
    assert!(bytes.windows(2).any(|w| w[0] & 0xC0 == 0xC0));
}

#[test]
fn our_message_body_decodes_in_hickory() {
    let records = corpus();
    let mut buf = vec![0u8; 12];
    let mut map = CompressionMap::new();
    for (_, expected) in &records {
        expected.encode(&mut buf, Some(&mut map)).expect("encode");
    }
    // Header: id 1, response, no question, answers = records.len().
    buf[2] = 0x80;
    buf[7] = u8::try_from(records.len()).expect("count");
    let msg = Message::from_vec(&buf).expect("hickory decodes our message");
    assert_eq!(msg.answers.len(), records.len());
    for (got, (theirs, _)) in msg.answers.iter().zip(&records) {
        assert_eq!(got, theirs);
    }
}
