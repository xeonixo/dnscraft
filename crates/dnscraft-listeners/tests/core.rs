//! Message core (`handle_wire`) table tests, padding property, proptest.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use dnscraft_filtering::SetId;
use dnscraft_listeners::{DEFAULT_UDP_PAYLOAD_MAX, FakeHandler, PAD_BLOCK, QueryMeta, handle_wire};
use dnscraft_policy::{
    AnswerOrigin, DecisionRecord, DecisionTimings, DnsProtocol, ListenerId, PolicyAnswer,
    ProfileId, SelectionCause, ViewId,
};
use dnscraft_proto::{
    Class, Edns, EdnsOption, Header, Message, Name, Opcode, RData, Rcode, Record, RecordType,
};
use dnscraft_resolver::ExtendedError;
use proptest::prelude::*;

fn lid() -> ListenerId {
    ListenerId::new("lan-udp").unwrap()
}

fn meta(protocol: DnsProtocol, size_limit: usize, pad: bool) -> QueryMeta {
    QueryMeta {
        protocol,
        listener_id: lid(),
        source: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
        client_id: None,
        size_limit,
        pad,
        udp_payload_max: DEFAULT_UDP_PAYLOAD_MAX,
    }
}

fn decision() -> DecisionRecord {
    DecisionRecord {
        view_id: ViewId::new("default").unwrap(),
        profile_id: ProfileId::new("default").unwrap(),
        selection: SelectionCause::Default,
        client_id: None,
        filter_set: SetId::new("default").unwrap(),
        steps: Vec::new(),
        filter: None,
        forward_zone: None,
        dnssec: None,
        answer_source: AnswerOrigin::LocalView,
        timings: DecisionTimings::default(),
        rcode: Rcode::NOERROR,
    }
}

fn answer_for(query: &Message) -> PolicyAnswer {
    let mut resp = Message::response_to(query);
    if let Some(q) = query.questions.first() {
        resp.answers.push(Record::new(
            q.name.clone(),
            Class::IN,
            60,
            RData::A(Ipv4Addr::new(192, 0, 2, 55)),
        ));
    }
    PolicyAnswer {
        message: resp,
        ede: None,
        record: decision(),
        loggable: true,
    }
}

fn encode_query(msg: Message) -> Vec<u8> {
    msg.encode().unwrap()
}

fn a_query(id: u16) -> Message {
    Message::query(id, Name::from_ascii("example.com.").unwrap(), RecordType::A)
}

#[tokio::test]
async fn core_drops_without_header() {
    let fake = FakeHandler::new(answer_for(&a_query(1)));
    assert!(
        handle_wire(&[0u8; 8], meta(DnsProtocol::Udp53, 512, false), &fake)
            .await
            .is_none()
    );
}

#[tokio::test]
async fn core_drops_qr1() {
    let mut q = a_query(7);
    q.header.qr = true;
    let fake = FakeHandler::new(answer_for(&q));
    assert!(
        handle_wire(
            &encode_query(q),
            meta(DnsProtocol::Udp53, 512, false),
            &fake
        )
        .await
        .is_none()
    );
}

#[tokio::test]
async fn core_notimp_on_non_query_opcode() {
    let mut q = a_query(1);
    q.header.opcode = Opcode::NOTIFY;
    let fake = FakeHandler::new(answer_for(&q));
    let out = handle_wire(
        &encode_query(q),
        meta(DnsProtocol::Udp53, 512, false),
        &fake,
    )
    .await
    .unwrap();
    let resp = Message::decode(&out.bytes).unwrap();
    assert_eq!(resp.rcode(), Rcode::NOTIMP);
    assert!(out.event.is_none());
}

#[tokio::test]
async fn core_formerr_on_qdcount_not_one() {
    let mut q = a_query(1);
    q.questions.push(q.questions[0].clone());
    let fake = FakeHandler::new(answer_for(&q));
    let out = handle_wire(
        &encode_query(q),
        meta(DnsProtocol::Udp53, 512, false),
        &fake,
    )
    .await
    .unwrap();
    assert_eq!(Message::decode(&out.bytes).unwrap().rcode(), Rcode::FORMERR);
}

#[tokio::test]
async fn core_formerr_when_header_ok_but_body_corrupt() {
    // Valid 12-byte header, truncated question → decode fails → FORMERR.
    let hdr = Header {
        id: 0xABCD,
        rd: true,
        ..Header::default()
    };
    let mut buf = Vec::new();
    hdr.encode(
        &mut buf,
        dnscraft_proto::Counts {
            qd: 1,
            an: 0,
            ns: 0,
            ar: 0,
        },
    );
    assert_eq!(buf.len(), 12);
    let fake = FakeHandler::new(answer_for(&a_query(1)));
    let out = handle_wire(&buf, meta(DnsProtocol::Udp53, 512, false), &fake)
        .await
        .unwrap();
    let resp = Message::decode(&out.bytes).unwrap();
    assert_eq!(resp.header.id, 0xABCD);
    assert_eq!(resp.rcode(), Rcode::FORMERR);
}

#[tokio::test]
async fn core_refused_unknown_class() {
    let mut q = a_query(1);
    q.questions[0].qclass = Class(99);
    let fake = FakeHandler::new(answer_for(&q));
    let out = handle_wire(
        &encode_query(q),
        meta(DnsProtocol::Udp53, 512, false),
        &fake,
    )
    .await
    .unwrap();
    assert_eq!(Message::decode(&out.bytes).unwrap().rcode(), Rcode::REFUSED);
}

#[tokio::test]
async fn core_refused_chaos() {
    let mut q = Message::query(
        1,
        Name::from_ascii("version.bind.").unwrap(),
        RecordType::TXT,
    );
    q.questions[0].qclass = Class::CH;
    let fake = FakeHandler::new(answer_for(&q));
    let out = handle_wire(
        &encode_query(q),
        meta(DnsProtocol::Udp53, 512, false),
        &fake,
    )
    .await
    .unwrap();
    assert_eq!(Message::decode(&out.bytes).unwrap().rcode(), Rcode::REFUSED);
    assert!(fake.recorded().is_empty());
}

#[tokio::test]
async fn core_badvers_on_edns_version() {
    let mut q = a_query(1);
    let mut edns = Edns::new(1232);
    edns.version = 1;
    q.edns = Some(edns);
    let fake = FakeHandler::new(answer_for(&q));
    let out = handle_wire(
        &encode_query(q),
        meta(DnsProtocol::Udp53, 1232, false),
        &fake,
    )
    .await
    .unwrap();
    let resp = Message::decode(&out.bytes).unwrap();
    assert_eq!(resp.rcode(), Rcode::BADVERS);
    assert!(resp.edns.is_some());
    assert_eq!(resp.edns.as_ref().unwrap().version, 0);
}

#[tokio::test]
async fn core_strips_ecs_and_does_not_echo_it() {
    let mut q = a_query(9);
    let mut edns = Edns::new(1232);
    edns.options.push(EdnsOption::ClientSubnet {
        family: 1,
        source_prefix: 24,
        scope_prefix: 0,
        address: vec![192, 0, 2].into(),
    });
    q.edns = Some(edns);
    let fake = FakeHandler::new(answer_for(&q));
    let out = handle_wire(
        &encode_query(q),
        meta(DnsProtocol::Udp53, 1232, false),
        &fake,
    )
    .await
    .unwrap();
    let resp = Message::decode(&out.bytes).unwrap();
    let edns = resp.edns.unwrap();
    assert!(
        edns.options
            .iter()
            .all(|o| !matches!(o, EdnsOption::ClientSubnet { .. }))
    );
}

#[tokio::test]
async fn core_attaches_ede_only_when_client_sent_opt() {
    let mut q = a_query(1);
    q.edns = Some(Edns::new(1232));
    let mut ans = answer_for(&q);
    ans.ede = Some(ExtendedError {
        code: 15,
        text: Some("blocked".into()),
    });
    let fake = FakeHandler::new(ans);
    let out = handle_wire(
        &encode_query(q),
        meta(DnsProtocol::Udp53, 1232, false),
        &fake,
    )
    .await
    .unwrap();
    let resp = Message::decode(&out.bytes).unwrap();
    assert!(
        resp.edns
            .as_ref()
            .unwrap()
            .options
            .iter()
            .any(|o| matches!(o, EdnsOption::ExtendedError { info_code: 15, .. }))
    );

    // Without OPT: no EDE.
    let q2 = a_query(2);
    let mut ans2 = answer_for(&q2);
    ans2.ede = Some(ExtendedError {
        code: 15,
        text: None,
    });
    let fake2 = FakeHandler::new(ans2);
    let out2 = handle_wire(
        &encode_query(q2),
        meta(DnsProtocol::Udp53, 512, false),
        &fake2,
    )
    .await
    .unwrap();
    assert!(Message::decode(&out2.bytes).unwrap().edns.is_none());
}

#[tokio::test]
async fn core_sets_ra_copies_rd_and_id_by_protocol() {
    let mut q = a_query(0x1234);
    q.header.rd = true;
    let fake = FakeHandler::new(answer_for(&q));
    let out = handle_wire(
        &encode_query(q.clone()),
        meta(DnsProtocol::Udp53, 512, false),
        &fake,
    )
    .await
    .unwrap();
    let resp = Message::decode(&out.bytes).unwrap();
    assert!(resp.header.ra);
    assert!(resp.header.rd);
    assert_eq!(resp.header.id, 0x1234);

    let out_doh = handle_wire(
        &encode_query(q.clone()),
        meta(DnsProtocol::DoH, 65535, false),
        &fake,
    )
    .await
    .unwrap();
    assert_eq!(Message::decode(&out_doh.bytes).unwrap().header.id, 0);

    let out_doq = handle_wire(
        &encode_query(q),
        meta(DnsProtocol::DoQ, 65535, false),
        &fake,
    )
    .await
    .unwrap();
    assert_eq!(Message::decode(&out_doq.bytes).unwrap().header.id, 0);
}

#[tokio::test]
async fn core_opt_echo_min_payload() {
    // Client 4096, configured max 1232 → response OPT 1232.
    let mut q = a_query(1);
    q.edns = Some(Edns::new(4096));
    let fake = FakeHandler::new(answer_for(&q));
    let mut m = meta(DnsProtocol::Udp53, 4096, false);
    m.udp_payload_max = 1232;
    let out = handle_wire(&encode_query(q), m, &fake).await.unwrap();
    assert_eq!(
        Message::decode(&out.bytes)
            .unwrap()
            .edns
            .unwrap()
            .udp_payload,
        1232
    );

    // Client 512, max 1232 → response OPT 512.
    let mut q2 = a_query(2);
    q2.edns = Some(Edns::new(512));
    let fake2 = FakeHandler::new(answer_for(&q2));
    let mut m2 = meta(DnsProtocol::Udp53, 512, false);
    m2.udp_payload_max = 1232;
    let out2 = handle_wire(&encode_query(q2), m2, &fake2).await.unwrap();
    assert_eq!(
        Message::decode(&out2.bytes)
            .unwrap()
            .edns
            .unwrap()
            .udp_payload,
        512
    );
}

#[tokio::test]
async fn core_truncation_sets_tc() {
    let q = a_query(1);
    let mut resp = Message::response_to(&q);
    // Many answers so encoding exceeds a tiny limit.
    for i in 0..40 {
        resp.answers.push(Record::new(
            Name::from_ascii(&format!("x{i}.example.com.")).unwrap(),
            Class::IN,
            60,
            RData::A(Ipv4Addr::new(192, 0, 2, i as u8)),
        ));
    }
    let fake = FakeHandler::new(PolicyAnswer {
        message: resp,
        ede: None,
        record: decision(),
        loggable: true,
    });
    let out = handle_wire(
        &encode_query(q),
        meta(DnsProtocol::Udp53, 200, false),
        &fake,
    )
    .await
    .unwrap();
    let decoded = Message::decode(&out.bytes).unwrap();
    assert!(decoded.header.tc, "TC must be set when answer RRsets drop");
    assert!(out.bytes.len() <= 200);
}

#[tokio::test]
async fn core_canonicalises_ipv4_mapped_source() {
    let q = a_query(1);
    let fake = FakeHandler::new(answer_for(&q));
    let mut m = meta(DnsProtocol::Udp53, 512, false);
    m.source = IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0xc000, 0x0201)); // ::ffff:192.0.2.1
    let out = handle_wire(&encode_query(q), m, &fake).await.unwrap();
    let ctx = &fake.recorded()[0];
    assert_eq!(ctx.source_ip, IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)));
    assert_eq!(
        out.event.as_ref().unwrap().source,
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))
    );
}

#[tokio::test]
async fn core_padding_multiple_of_468_within_limit() {
    let mut q = a_query(1);
    q.edns = Some(Edns::new(1232));
    let fake = FakeHandler::new(answer_for(&q));
    let out = handle_wire(&encode_query(q), meta(DnsProtocol::DoT, 4096, true), &fake)
        .await
        .unwrap();
    assert_eq!(out.bytes.len() % PAD_BLOCK, 0);
    assert!(out.bytes.len() <= 4096);
    let resp = Message::decode(&out.bytes).unwrap();
    assert!(
        resp.edns
            .unwrap()
            .options
            .iter()
            .any(|o| matches!(o, EdnsOption::Padding(_)))
            || out.bytes.len() % PAD_BLOCK == 0
    );
}

#[tokio::test]
async fn core_happy_path_calls_handler_and_emits_event() {
    let q = a_query(42);
    let fake = FakeHandler::new(answer_for(&q));
    let out = handle_wire(
        &encode_query(q),
        meta(DnsProtocol::Udp53, 512, false),
        &fake,
    )
    .await
    .unwrap();
    assert_eq!(fake.recorded().len(), 1);
    let ev = out.event.unwrap();
    assert!(ev.loggable);
    assert_eq!(ev.rcode, Rcode::NOERROR);
    assert_eq!(ev.answer_size, out.bytes.len());
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1024))]

    #[test]
    fn core_never_panics_on_arbitrary_input(
        bytes in prop::collection::vec(any::<u8>(), 0..512),
        pad in any::<bool>(),
    ) {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let q = Message::query(1, Name::root(), RecordType::A);
            let fake = FakeHandler::new(answer_for(&q));
            let _ = handle_wire(
                &bytes,
                meta(DnsProtocol::Udp53, 1232, pad),
                &fake,
            )
            .await;
        });
    }
}
