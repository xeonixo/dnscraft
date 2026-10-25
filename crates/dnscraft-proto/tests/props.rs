//! Property-based round-trip tests for names, records and messages.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use dnscraft_proto::{
    Class, Edns, EdnsOption, Header, Message, Name, Opcode, ProtoError, Question, RData, Record,
    RecordType,
};
use proptest::collection::vec;
use proptest::prelude::*;
use std::net::{Ipv4Addr, Ipv6Addr};

/// Builds a name from labels via the wire decoder (labels already valid).
fn name_from_labels(labels: &[Vec<u8>]) -> Name {
    let mut wire = Vec::new();
    for l in labels {
        wire.push(l.len() as u8);
        wire.extend_from_slice(l);
    }
    wire.push(0);
    Name::decode(&wire, 0).expect("valid wire name").0
}

fn labels_strategy() -> impl Strategy<Value = Vec<Vec<u8>>> {
    vec(vec(any::<u8>(), 1..=63), 0..=8).prop_filter("name too long", |ls| {
        ls.iter().map(|l| l.len() + 1).sum::<usize>() < 255
    })
}

fn name() -> impl Strategy<Value = Name> {
    // A small alphabet makes repeated suffixes (compression) likely.
    let small = vec(
        vec(prop::sample::select(vec![b'a', b'b', b'C', b'.']), 1..=3),
        0..=4,
    );
    prop_oneof![
        labels_strategy().prop_map(|ls| name_from_labels(&ls)),
        small.prop_map(|ls| name_from_labels(&ls)),
    ]
}

fn rdata() -> impl Strategy<Value = RData> {
    prop_oneof![
        any::<u32>().prop_map(|v| RData::A(Ipv4Addr::from(v))),
        any::<u128>().prop_map(|v| RData::AAAA(Ipv6Addr::from(v))),
        name().prop_map(RData::NS),
        name().prop_map(RData::CNAME),
        (any::<u16>(), name()).prop_map(|(preference, exchange)| RData::MX {
            preference,
            exchange
        }),
        vec(vec(any::<u8>(), 0..=255), 1..=4)
            .prop_map(|v| RData::TXT(v.into_iter().map(Vec::into_boxed_slice).collect())),
        (name(), name(), any::<[u32; 5]>()).prop_map(|(mname, rname, n)| RData::SOA {
            mname,
            rname,
            serial: n[0],
            refresh: n[1],
            retry: n[2],
            expire: n[3],
            minimum: n[4],
        }),
        (any::<u16>(), any::<u16>(), any::<u16>(), name()).prop_map(
            |(priority, weight, port, target)| RData::SRV {
                priority,
                weight,
                port,
                target
            }
        ),
        (100u16..=200, vec(any::<u8>(), 0..=64)).prop_map(|(t, data)| RData::Unknown {
            rtype: RecordType(t),
            data: data.into_boxed_slice()
        }),
    ]
}

fn record() -> impl Strategy<Value = Record> {
    (name(), any::<u16>(), any::<u32>(), rdata()).prop_map(|(name, class, ttl, rdata)| Record {
        name,
        class: Class(class),
        ttl,
        rdata,
    })
}

fn edns() -> impl Strategy<Value = Edns> {
    let opt = prop_oneof![
        (0u16..=512).prop_map(EdnsOption::Padding),
        (
            any::<u16>().prop_filter("known code", |c| ![8, 10, 12, 15].contains(c)),
            vec(any::<u8>(), 0..=32)
        )
            .prop_map(|(code, d)| EdnsOption::Unknown {
                code,
                data: d.into_boxed_slice()
            }),
    ];
    (any::<u16>(), any::<bool>(), vec(opt, 0..=2)).prop_map(|(p, d, options)| {
        let mut e = Edns::new(p);
        e.dnssec_ok = d;
        e.options = options;
        e
    })
}

fn question() -> impl Strategy<Value = Question> {
    (name(), any::<u16>(), any::<u16>()).prop_map(|(name, t, c)| Question {
        name,
        qtype: RecordType(t),
        qclass: Class(c),
    })
}

fn rr_vec() -> impl Strategy<Value = Vec<Record>> {
    vec(record(), 0..=5)
}

fn message() -> impl Strategy<Value = Message> {
    let header =
        (any::<u16>(), any::<[bool; 7]>(), 0u8..=15, 0u8..=15).prop_map(|(id, f, op, rc)| Header {
            id,
            qr: f[0],
            opcode: Opcode(op),
            aa: f[1],
            tc: f[2],
            rd: f[3],
            ra: f[4],
            z: f[5],
            ad: f[6],
            cd: f[0] ^ f[1],
            rcode_low: rc,
        });
    (
        header,
        vec(question(), 0..=2),
        rr_vec(),
        rr_vec(),
        rr_vec(),
        prop::option::of(edns()),
    )
        .prop_map(
            |(header, questions, answers, authorities, additionals, edns)| Message {
                header,
                questions,
                answers,
                authorities,
                additionals,
                edns,
            },
        )
}

fn flip_case(n: &Name, mask: &[bool]) -> Name {
    let mut wire = n.as_wire().to_vec();
    let mut i = 0;
    let mut k = 0;
    while i < wire.len() {
        let len = usize::from(wire[i]);
        for b in &mut wire[i + 1..i + 1 + len] {
            if mask.get(k % mask.len().max(1)).copied().unwrap_or(false) {
                *b = if b.is_ascii_lowercase() {
                    b.to_ascii_uppercase()
                } else {
                    b.to_ascii_lowercase()
                };
            }
            k += 1;
        }
        i += len + 1;
    }
    Name::decode(&wire, 0).expect("case-flipped name").0
}

proptest! {
    #[test]
    fn name_roundtrip(n in name()) {
        let mut buf = Vec::new();
        n.encode(&mut buf, None);
        let (d, end) = Name::decode(&buf, 0).unwrap();
        prop_assert_eq!(&d, &n);
        prop_assert_eq!(end, buf.len());
        prop_assert_eq!(d.as_wire(), n.as_wire());
        // Presentation format round-trips too.
        let text = n.to_string();
        prop_assert_eq!(Name::from_ascii(&text).unwrap(), n);
    }

    #[test]
    fn name_case_insensitive(n in name(), mask in vec(any::<bool>(), 1..=16)) {
        let m = flip_case(&n, &mask);
        prop_assert_eq!(&m, &n);
        prop_assert_eq!(m.cmp(&n), std::cmp::Ordering::Equal);
        use std::hash::{BuildHasher, RandomState};
        let s = RandomState::new();
        prop_assert_eq!(s.hash_one(&m), s.hash_one(&n));
        let (lm, ln) = (m.to_lowercase(), n.to_lowercase());
        prop_assert_eq!(lm.as_wire(), ln.as_wire());
    }

    #[test]
    fn record_roundtrip(r in record(), compressed in any::<bool>()) {
        // Minimal message buffer: a 12 octet header, then the record.
        let mut buf = vec![0u8; 12];
        let mut map = dnscraft_proto::CompressionMap::new();
        r.encode(&mut buf, if compressed { Some(&mut map) } else { None }).unwrap();
        let (d, end) = Record::decode(&buf, 12).unwrap();
        prop_assert_eq!(end, buf.len());
        prop_assert_eq!(d, r);
    }

    #[test]
    fn message_roundtrip(m in message()) {
        let bytes = m.encode().unwrap();
        let d = Message::decode(&bytes).unwrap();
        prop_assert_eq!(&d, &m);
        prop_assert_eq!(d.encode().unwrap(), bytes);
    }

    #[test]
    fn message_limit(m in message(), limit in 12usize..=4096) {
        match m.encode_with_limit(limit) {
            Ok(bytes) => {
                prop_assert!(bytes.len() <= limit);
                prop_assert!(Message::decode(&bytes).is_ok());
            }
            Err(ProtoError::LimitTooSmall { .. }) => {}
            Err(e) => prop_assert!(false, "unexpected error {e:?}"),
        }
    }
}
