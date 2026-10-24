//! Oracle tests: compare `Message`/`Edns` against hickory-proto.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::net::{IpAddr, Ipv4Addr};

use dnscraft_proto::{
    Class, Edns, EdnsOption, Message, Name, Question, RData, Rcode, Record, RecordType,
};
use hickory_proto::op::{Edns as HEdns, Message as HMessage, MessageType, Query, ResponseCode};
use hickory_proto::rr::rdata::opt::{ClientSubnet, EdnsOption as HOpt};
use hickory_proto::rr::rdata::{A, NS, SOA};
use hickory_proto::rr::{Name as HName, RData as HRData, Record as HRecord, RecordType as HType};

fn hn(s: &str) -> HName {
    HName::from_ascii(s).unwrap()
}

fn n(s: &str) -> Name {
    Name::from_ascii(s).unwrap()
}

fn hickory_response() -> HMessage {
    let mut m = HMessage::query();
    m.metadata.id = 0x4242;
    m.metadata.message_type = MessageType::Response;
    m.metadata.authoritative = true;
    m.metadata.recursion_desired = true;
    m.metadata.recursion_available = true;
    m.metadata.authentic_data = true;
    m.metadata.response_code = ResponseCode::NoError;
    m.add_query(Query::query(hn("www.example.com."), HType::A));
    m.add_answer(HRecord::from_rdata(
        hn("www.example.com."),
        300,
        HRData::A(A(Ipv4Addr::new(192, 0, 2, 1))),
    ));
    m.add_answer(HRecord::from_rdata(
        hn("www.example.com."),
        300,
        HRData::A(A(Ipv4Addr::new(192, 0, 2, 2))),
    ));
    m.add_authority(HRecord::from_rdata(
        hn("example.com."),
        3600,
        HRData::NS(NS(hn("ns1.example.com."))),
    ));
    m.add_authority(HRecord::from_rdata(
        hn("example.com."),
        3600,
        HRData::SOA(SOA::new(
            hn("ns1.example.com."),
            hn("hostmaster.example.com."),
            7,
            1,
            2,
            3,
            4,
        )),
    ));
    m.add_additional(HRecord::from_rdata(
        hn("ns1.example.com."),
        3600,
        HRData::A(A(Ipv4Addr::new(192, 0, 2, 53))),
    ));
    let mut edns = HEdns::new();
    edns.set_max_payload(1232).set_dnssec_ok(true);
    m.set_edns(edns);
    m
}

#[test]
fn hickory_query_decodes() {
    let mut q = HMessage::query();
    q.metadata.id = 77;
    q.metadata.recursion_desired = true;
    q.metadata.checking_disabled = true;
    q.add_query(Query::query(hn("example.org."), HType::AAAA));
    let m = Message::decode(&q.to_vec().unwrap()).unwrap();
    assert_eq!(m.header.id, 77);
    assert!(!m.header.qr && m.header.rd && m.header.cd && !m.header.ad);
    assert_eq!(
        m.questions,
        vec![Question {
            name: n("example.org."),
            qtype: RecordType::AAAA,
            qclass: Class::IN
        }]
    );
    assert!(m.edns.is_none());
}

#[test]
fn hickory_full_response_decodes() {
    let h = hickory_response();
    let m = Message::decode(&h.to_vec().unwrap()).unwrap();
    assert_eq!(m.header.id, 0x4242);
    assert!(m.header.qr && m.header.aa && m.header.rd && m.header.ra && m.header.ad);
    assert_eq!(m.rcode(), Rcode::NOERROR);
    assert_eq!(m.answers.len(), 2);
    assert_eq!(m.answers[1].rdata, RData::A(Ipv4Addr::new(192, 0, 2, 2)));
    assert_eq!(m.authorities.len(), 2);
    assert_eq!(m.authorities[1].rtype, RecordType::SOA);
    assert_eq!(m.additionals.len(), 1);
    let e = m.edns.as_ref().unwrap();
    assert_eq!(e.udp_payload, 1232);
    assert!(e.dnssec_ok);
}

#[test]
fn our_encoding_decodes_equal_in_hickory() {
    let h = hickory_response();
    let m = Message::decode(&h.to_vec().unwrap()).unwrap();
    let back = HMessage::from_vec(&m.encode().unwrap()).unwrap();
    assert_eq!(back.metadata.id, h.metadata.id);
    assert_eq!(back.metadata.message_type, h.metadata.message_type);
    assert_eq!(back.metadata.authoritative, h.metadata.authoritative);
    assert_eq!(back.metadata.authentic_data, h.metadata.authentic_data);
    assert_eq!(back.queries, h.queries);
    assert_eq!(back.answers, h.answers);
    assert_eq!(back.authorities, h.authorities);
    assert_eq!(back.additionals, h.additionals);
    let e = back.edns.unwrap();
    assert_eq!(e.max_payload(), 1232);
    assert!(e.flags().dnssec_ok);
}

#[test]
fn rcodes_agree_with_hickory() {
    for (rc, code) in [
        (ResponseCode::NXDomain, Rcode::NXDOMAIN),
        (ResponseCode::Refused, Rcode::REFUSED),
        (ResponseCode::BADVERS, Rcode::BADVERS),
        (ResponseCode::BADCOOKIE, Rcode::BADCOOKIE),
    ] {
        let mut h = hickory_response();
        h.metadata.response_code = rc;
        let mut m = Message::decode(&h.to_vec().unwrap()).unwrap();
        assert_eq!(m.rcode(), code, "{rc:?}");
        let back = HMessage::from_vec(&m.encode().unwrap()).unwrap();
        // Hickory decodes 16 as BADSIG, so compare numeric values.
        assert_eq!(u16::from(back.metadata.response_code), code.value());
        m.set_rcode(code).unwrap();
        assert_eq!(m.rcode(), code);
    }
}

#[test]
fn ecs_and_raw_options_agree_with_hickory() {
    let mut h = hickory_response();
    let mut edns = HEdns::new();
    edns.set_max_payload(1232);
    edns.options_mut().insert(HOpt::Subnet(ClientSubnet::new(
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 0)),
        24,
        0,
    )));
    // Hickory has no typed cookie, padding or EDE options; they travel as
    // unknown options and our typed decoding is checked against them.
    let mut cookie = vec![1, 2, 3, 4, 5, 6, 7, 8];
    cookie.extend_from_slice(&[9; 16]);
    edns.options_mut().insert(HOpt::Unknown(10, cookie.clone()));
    edns.options_mut().insert(HOpt::Unknown(12, vec![0; 5]));
    edns.options_mut()
        .insert(HOpt::Unknown(15, [&[0, 18][..], b"blocked"].concat()));
    h.set_edns(edns);

    let m = Message::decode(&h.to_vec().unwrap()).unwrap();
    let opts = &m.edns.as_ref().unwrap().options;
    assert_eq!(
        opts[0],
        EdnsOption::ClientSubnet {
            family: 1,
            source_prefix: 24,
            scope_prefix: 0,
            address: vec![192, 0, 2].into()
        }
    );
    assert_eq!(
        opts[1],
        EdnsOption::Cookie {
            client: [1, 2, 3, 4, 5, 6, 7, 8],
            server: Some(vec![9; 16].into())
        }
    );
    assert_eq!(opts[2], EdnsOption::Padding(5));
    assert_eq!(
        opts[3],
        EdnsOption::ExtendedError {
            info_code: 18,
            extra_text: "blocked".into()
        }
    );

    let back = HMessage::from_vec(&m.encode().unwrap()).unwrap();
    let be = back.edns.unwrap();
    let he = h.edns.unwrap();
    assert_eq!(be.options(), he.options());
}

#[test]
fn our_query_is_valid_for_hickory() {
    let mut q = Message::query(5, n("example.com."), RecordType::MX);
    let mut e = Edns::new(1232);
    e.dnssec_ok = true;
    q.edns = Some(e);
    let h = HMessage::from_vec(&q.encode().unwrap()).unwrap();
    assert_eq!(h.metadata.id, 5);
    assert!(h.metadata.recursion_desired);
    assert_eq!(h.queries[0].query_type(), HType::MX);
    assert_eq!(h.edns.unwrap().max_payload(), 1232);
}

#[test]
fn truncated_encoding_decodes_in_hickory_with_tc() {
    let q = Message::query(5, n("big.example.com."), RecordType::A);
    let mut m = Message::response_to(&q);
    for i in 0..200u8 {
        m.answers.push(Record {
            name: n("big.example.com."),
            rtype: RecordType::A,
            class: Class::IN,
            ttl: 1,
            rdata: RData::A(Ipv4Addr::new(10, 0, 0, i)),
        });
    }
    let bytes = m.encode_with_limit(512).unwrap();
    assert!(bytes.len() <= 512);
    let h = HMessage::from_vec(&bytes).unwrap();
    assert!(h.metadata.truncation);
    assert!(h.answers.is_empty());
}
