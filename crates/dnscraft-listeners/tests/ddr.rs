//! N10: DDR `_dns.resolver.arpa` SVCB answers on local Do53.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod support;

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::sync::RwLock;
use std::time::Duration;

use dnscraft_listeners::{
    DDR_QNAME, DDR_TTL, DEFAULT_UDP_PAYLOAD_MAX, DOH_PATH, DdrEndpoint, DdrEndpoints, Exposure,
    FakeHandler, Limits, ListenerConfig, Protocol, PublicConfig, QueryMeta, SystemClock,
    UdpServeParams, UdpStats, handle_wire, serve_udp,
};
use dnscraft_policy::{AnswerOrigin, DnsProtocol, ListenerId};
use dnscraft_proto::{Message, Name, RData, Rcode, RecordType, SvcbData};
use hickory_proto::op::Message as HMessage;
use hickory_proto::op::ResponseCode;
use hickory_proto::rr::RData as HRData;
use hickory_proto::rr::RecordType as HRecordType;
use hickory_proto::rr::rdata::svcb::{SvcParamKey, SvcParamValue};
use support::fake_a_answer;
use tokio::net::UdpSocket;
use tokio::sync::{oneshot, watch};

const DOMAIN: &str = "example.com";

fn ddr_state(endpoints: Vec<DdrEndpoint>, enabled: bool) -> Arc<RwLock<DdrEndpoints>> {
    Arc::new(RwLock::new(DdrEndpoints {
        enabled,
        target: "dns".into(),
        public_domain: DOMAIN.into(),
        endpoints,
    }))
}

fn endpoints_v4(dot: u16, doh: u16, doq: u16) -> Vec<DdrEndpoint> {
    vec![
        DdrEndpoint {
            protocol: Protocol::Dot,
            address: SocketAddr::from((Ipv4Addr::new(192, 0, 2, 1), dot)),
            h3: false,
        },
        DdrEndpoint {
            protocol: Protocol::Doh,
            address: SocketAddr::from((Ipv4Addr::new(192, 0, 2, 1), doh)),
            h3: false,
        },
        DdrEndpoint {
            protocol: Protocol::Doq,
            address: SocketAddr::from((Ipv4Addr::new(192, 0, 2, 1), doq)),
            h3: false,
        },
    ]
}

fn svcb_query() -> Message {
    Message::query(7, Name::from_ascii(DDR_QNAME).unwrap(), RecordType::SVCB)
}

fn meta_udp(ddr: Option<Arc<RwLock<DdrEndpoints>>>, arrival: IpAddr) -> QueryMeta {
    QueryMeta {
        protocol: DnsProtocol::Udp53,
        listener_id: ListenerId::new("lan-udp").unwrap(),
        exposure: Exposure::Local,
        source: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
        arrival,
        client_id: None,
        size_limit: 1232,
        pad: false,
        udp_payload_max: DEFAULT_UDP_PAYLOAD_MAX,
        ddr,
    }
}

fn falling_handler() -> FakeHandler {
    // Distinct A answer so tests can tell policy ran.
    FakeHandler::new(fake_a_answer(Ipv4Addr::new(203, 0, 113, 9)))
}

fn parse_our_svcbs(bytes: &[u8]) -> Vec<SvcbData> {
    let msg = Message::decode(bytes).unwrap();
    assert_eq!(msg.rcode(), Rcode::NOERROR);
    msg.answers
        .iter()
        .filter_map(|rr| match &rr.rdata {
            RData::SVCB(d) => Some(d.clone()),
            _ => None,
        })
        .collect()
}

type HickorySvcb = (u16, String, Vec<(SvcParamKey, SvcParamValue)>);

fn hickory_oracle_svcbs(bytes: &[u8]) -> Vec<HickorySvcb> {
    let h = HMessage::from_vec(bytes).expect("hickory decode");
    assert_eq!(h.response_code, ResponseCode::NoError);
    h.answers
        .iter()
        .filter(|rr| rr.record_type() == HRecordType::SVCB)
        .map(|rr| {
            let HRData::SVCB(svcb) = &rr.data else {
                panic!("expected SVCB");
            };
            (
                svcb.svc_priority,
                svcb.target_name.to_string(),
                svcb.svc_params.clone(),
            )
        })
        .collect()
}

#[tokio::test]
async fn ddr_svcb_lists_endpoints_hickory_oracle() {
    let ddr = ddr_state(endpoints_v4(853, 443, 853), true);
    let fake = falling_handler();
    let out = handle_wire(
        &svcb_query().encode().unwrap(),
        meta_udp(
            Some(Arc::clone(&ddr)),
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
        ),
        &fake,
    )
    .await
    .unwrap();

    let event = out.event.as_ref().unwrap();
    assert_eq!(event.decision.answer_source, AnswerOrigin::ListenerDdr);
    assert!(event.loggable);

    let ours = parse_our_svcbs(&out.bytes);
    assert_eq!(ours.len(), 3);
    assert_eq!(ours[0].priority, 1);
    assert_eq!(ours[0].target.to_string(), "dns.example.com.");
    assert_eq!(ours[1].priority, 2);
    assert_eq!(ours[2].priority, 3);

    // alpn / port / hint / dohpath
    assert_eq!(ours[0].params[0].0, 1); // alpn
    assert_eq!(&ours[0].params[0].1[..], b"\x03dot");
    assert_eq!(ours[0].params[1].0, 3); // port
    assert_eq!(&ours[0].params[1].1[..], &853u16.to_be_bytes());
    assert_eq!(ours[0].params[2].0, 4); // ipv4hint
    assert_eq!(
        &ours[0].params[2].1[..],
        &Ipv4Addr::new(192, 0, 2, 1).octets()
    );

    assert_eq!(ours[1].params[0].1.as_ref(), b"\x02h2");
    assert!(
        ours[1]
            .params
            .iter()
            .any(|(k, v)| *k == 7 && v.as_ref() == DOH_PATH.as_bytes())
    );
    assert_eq!(ours[2].params[0].1.as_ref(), b"\x03doq");

    let hickory = hickory_oracle_svcbs(&out.bytes);
    assert_eq!(hickory.len(), 3);
    assert_eq!(hickory[0].0, 1);
    assert!(hickory[0].1.eq_ignore_ascii_case("dns.example.com."));
    let alpns: Vec<_> = hickory
        .iter()
        .filter_map(|(_, _, params)| {
            params.iter().find_map(|(k, v)| match (k, v) {
                (SvcParamKey::Alpn, SvcParamValue::Alpn(a)) => Some(a.0.clone()),
                _ => None,
            })
        })
        .collect();
    assert_eq!(
        alpns,
        vec![
            vec!["dot".to_string()],
            vec!["h2".to_string()],
            vec!["doq".to_string()]
        ]
    );
}

#[tokio::test]
async fn ddr_family_split_and_wildcard_arrival() {
    let endpoints = vec![
        DdrEndpoint {
            protocol: Protocol::Dot,
            address: SocketAddr::from((Ipv4Addr::UNSPECIFIED, 853)),
            h3: false,
        },
        DdrEndpoint {
            protocol: Protocol::Dot,
            address: SocketAddr::from((Ipv6Addr::UNSPECIFIED, 853)),
            h3: false,
        },
        DdrEndpoint {
            protocol: Protocol::Doh,
            address: SocketAddr::from((Ipv4Addr::new(198, 51, 100, 1), 443)),
            h3: false,
        },
    ];
    let ddr = ddr_state(endpoints, true);
    let fake = falling_handler();

    let v4 = handle_wire(
        &svcb_query().encode().unwrap(),
        meta_udp(
            Some(Arc::clone(&ddr)),
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 55)),
        ),
        &fake,
    )
    .await
    .unwrap();
    let v4_svcbs = parse_our_svcbs(&v4.bytes);
    assert_eq!(v4_svcbs.len(), 2);
    // Wildcard → arrival; concrete → bound.
    let hints: Vec<_> = v4_svcbs
        .iter()
        .map(|s| {
            s.params
                .iter()
                .find(|(k, _)| *k == 4)
                .map(|(_, v)| Ipv4Addr::new(v[0], v[1], v[2], v[3]))
                .unwrap()
        })
        .collect();
    assert!(hints.contains(&Ipv4Addr::new(192, 0, 2, 55)));
    assert!(hints.contains(&Ipv4Addr::new(198, 51, 100, 1)));

    let v6 = handle_wire(
        &svcb_query().encode().unwrap(),
        meta_udp(
            Some(Arc::clone(&ddr)),
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
        ),
        &fake,
    )
    .await
    .unwrap();
    let v6_svcbs = parse_our_svcbs(&v6.bytes);
    assert_eq!(v6_svcbs.len(), 1);
    let hint6 = &v6_svcbs[0].params.iter().find(|(k, _)| *k == 6).unwrap().1;
    assert_eq!(
        hint6.as_ref(),
        &Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1).octets()[..]
    );
}

#[tokio::test]
async fn ddr_nodata_soa_without_encrypted_listeners() {
    let ddr = ddr_state(Vec::new(), true);
    let fake = falling_handler();
    let out = handle_wire(
        &svcb_query().encode().unwrap(),
        meta_udp(Some(ddr), IpAddr::V4(Ipv4Addr::LOCALHOST)),
        &fake,
    )
    .await
    .unwrap();
    let msg = Message::decode(&out.bytes).unwrap();
    assert_eq!(msg.rcode(), Rcode::NOERROR);
    assert!(msg.answers.is_empty());
    assert_eq!(msg.authorities.len(), 1);
    assert_eq!(msg.authorities[0].rtype(), RecordType::SOA);
    assert_eq!(msg.authorities[0].name.to_string(), "resolver.arpa.");
    assert_eq!(msg.authorities[0].ttl, DDR_TTL);
    assert_eq!(
        out.event.as_ref().unwrap().decision.answer_source,
        AnswerOrigin::ListenerDdr
    );
}

#[tokio::test]
async fn ddr_disabled_and_nonsvcb_go_to_policy() {
    let ddr = ddr_state(endpoints_v4(853, 443, 853), false);
    let fake = falling_handler();
    let out = handle_wire(
        &svcb_query().encode().unwrap(),
        meta_udp(Some(ddr), IpAddr::V4(Ipv4Addr::LOCALHOST)),
        &fake,
    )
    .await
    .unwrap();
    let msg = Message::decode(&out.bytes).unwrap();
    // Policy FakeHandler A answer, not SVCB.
    assert!(msg.answers.iter().any(|rr| matches!(rr.rdata, RData::A(_))));
    assert_ne!(
        out.event.as_ref().unwrap().decision.answer_source,
        AnswerOrigin::ListenerDdr
    );

    let ddr_on = ddr_state(endpoints_v4(853, 443, 853), true);
    let a_q = Message::query(1, Name::from_ascii(DDR_QNAME).unwrap(), RecordType::A);
    let out = handle_wire(
        &a_q.encode().unwrap(),
        meta_udp(Some(ddr_on), IpAddr::V4(Ipv4Addr::LOCALHOST)),
        &fake,
    )
    .await
    .unwrap();
    let msg = Message::decode(&out.bytes).unwrap();
    assert!(msg.answers.iter().any(|rr| matches!(rr.rdata, RData::A(_))));
}

#[tokio::test]
async fn ddr_not_intercepted_on_encrypted() {
    let ddr = ddr_state(endpoints_v4(853, 443, 853), true);
    let fake = falling_handler();
    for protocol in [DnsProtocol::DoT, DnsProtocol::DoH, DnsProtocol::DoQ] {
        let mut meta = meta_udp(Some(Arc::clone(&ddr)), IpAddr::V4(Ipv4Addr::LOCALHOST));
        meta.protocol = protocol;
        // Encrypted transports leave ddr: None in production; even with Some, protocol gate skips.
        let out = handle_wire(&svcb_query().encode().unwrap(), meta, &fake)
            .await
            .unwrap();
        assert_ne!(
            out.event.as_ref().unwrap().decision.answer_source,
            AnswerOrigin::ListenerDdr,
            "{protocol:?}"
        );
    }
}

#[tokio::test]
async fn ddr_udp_serve_end_to_end() {
    let endpoints = endpoints_v4(853, 443, 853);
    let ddr = ddr_state(endpoints, true);
    let stats = Arc::new(UdpStats::default());
    let (bound_tx, bound_rx) = oneshot::channel();
    let (sd_tx, sd_rx) = watch::channel(false);
    let join = tokio::spawn(serve_udp(UdpServeParams {
        listener: ListenerConfig {
            id: ListenerId::new("ddr-udp").unwrap(),
            protocol: Protocol::Udp53,
            address: SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
            exposure: Exposure::Local,
            h3: false,
            tls_policy: None,
        },
        limits: Limits::default(),
        admission: support::admission_for(&Limits::default(), &PublicConfig::default()),
        handler: Arc::new(falling_handler()),
        clock: Arc::new(SystemClock),
        stats: Arc::clone(&stats),
        ddr: Some(ddr),
        event_sink: None,
        bound: bound_tx,
        shutdown: sd_rx,
    }));
    let addr = bound_rx.await.unwrap();
    let sock = UdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .await
        .unwrap();
    sock.send_to(&svcb_query().encode().unwrap(), addr)
        .await
        .unwrap();
    let mut buf = [0u8; 4096];
    let (n, _) = tokio::time::timeout(Duration::from_secs(2), sock.recv_from(&mut buf))
        .await
        .unwrap()
        .unwrap();
    let svcbs = parse_our_svcbs(&buf[..n]);
    assert_eq!(svcbs.len(), 3);
    let _ = sd_tx.send(true);
    let _ = join.await;
}
