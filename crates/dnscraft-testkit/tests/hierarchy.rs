#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use dnscraft_testkit::{Hierarchy, Transport, parse_name};
use hickory_proto::op::{Edns, Message, Query, ResponseCode};
use hickory_proto::rr::{RData, RecordType};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::timeout;

fn build_query(name: &str, rtype: RecordType) -> Message {
    let mut msg = Message::query();
    msg.metadata.recursion_desired = false;
    msg.add_query(Query::query(parse_name(name).unwrap(), rtype));
    msg.edns = Some(Edns::new());
    msg
}

async fn udp_query(server: SocketAddr, name: &str, rtype: RecordType) -> Option<Message> {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    socket
        .send_to(&build_query(name, rtype).to_vec().unwrap(), server)
        .await
        .unwrap();
    let mut buf = vec![0u8; 4096];
    let (len, _) = timeout(Duration::from_millis(500), socket.recv_from(&mut buf))
        .await
        .ok()?
        .ok()?;
    Some(Message::from_vec(&buf[..len]).unwrap())
}

async fn tcp_query(server: SocketAddr, name: &str, rtype: RecordType) -> Message {
    let mut stream = TcpStream::connect(server).await.unwrap();
    let bytes = build_query(name, rtype).to_vec().unwrap();
    stream.write_u16(bytes.len() as u16).await.unwrap();
    stream.write_all(&bytes).await.unwrap();
    let len = stream.read_u16().await.unwrap();
    let mut buf = vec![0u8; usize::from(len)];
    stream.read_exact(&mut buf).await.unwrap();
    Message::from_vec(&buf).unwrap()
}

#[tokio::test]
async fn root_returns_referral_with_glue() {
    let h = Hierarchy::start().await.unwrap();
    let root = h.root_hints()[0];
    let resp = udp_query(root, "www.example.test.", RecordType::A)
        .await
        .unwrap();
    assert_eq!(resp.metadata.response_code, ResponseCode::NoError);
    assert!(!resp.metadata.authoritative);
    assert!(resp.answers.is_empty());
    assert_eq!(resp.authorities.len(), 1);
    assert_eq!(resp.authorities[0].record_type(), RecordType::NS);
    assert_eq!(resp.authorities[0].name, parse_name("test.").unwrap());
    assert_eq!(resp.additionals.len(), 1);
    assert_eq!(
        resp.additionals[0].data,
        RData::A(hickory_proto::rr::rdata::A(Ipv4Addr::LOCALHOST))
    );
    let ns = parse_name("ns1.test.").unwrap();
    assert_eq!(resp.additionals[0].name, ns);
    assert_eq!(
        h.nameserver_addrs().get(&ns),
        Some(&h.server("test.").unwrap().addr())
    );
}

#[tokio::test]
async fn leaf_server_answers_authoritatively() {
    let h = Hierarchy::start().await.unwrap();
    let addr = h.server("example.test.").unwrap().addr();
    let resp = udp_query(addr, "www.example.test.", RecordType::A)
        .await
        .unwrap();
    assert!(resp.metadata.authoritative);
    assert_eq!(resp.answers.len(), 1);
    assert_eq!(
        resp.answers[0].data,
        RData::A(hickory_proto::rr::rdata::A(Ipv4Addr::new(192, 0, 2, 1)))
    );
    let resp = udp_query(addr, "www.example.test.", RecordType::AAAA)
        .await
        .unwrap();
    assert_eq!(resp.answers.len(), 1);
    assert_eq!(resp.answers[0].record_type(), RecordType::AAAA);
}

#[tokio::test]
async fn nxdomain_and_nodata_carry_soa() {
    let h = Hierarchy::start().await.unwrap();
    let addr = h.server("example.test.").unwrap().addr();

    let nx = udp_query(addr, "missing.example.test.", RecordType::A)
        .await
        .unwrap();
    assert_eq!(nx.metadata.response_code, ResponseCode::NXDomain);
    assert!(nx.metadata.authoritative);
    assert!(nx.answers.is_empty());
    assert_eq!(nx.authorities.len(), 1);
    assert_eq!(nx.authorities[0].record_type(), RecordType::SOA);

    let nodata = udp_query(addr, "www.example.test.", RecordType::TXT)
        .await
        .unwrap();
    assert_eq!(nodata.metadata.response_code, ResponseCode::NoError);
    assert!(nodata.metadata.authoritative);
    assert!(nodata.answers.is_empty());
    assert_eq!(nodata.authorities.len(), 1);
    assert_eq!(nodata.authorities[0].record_type(), RecordType::SOA);
}

#[tokio::test]
async fn tcp_works_on_same_port() {
    let h = Hierarchy::start().await.unwrap();
    let addr = h.server("example.test.").unwrap().addr();
    let resp = tcp_query(addr, "www.example.test.", RecordType::A).await;
    assert!(resp.metadata.authoritative);
    assert_eq!(resp.answers.len(), 1);
    let log = h.server("example.test.").unwrap().queries();
    assert_eq!(log.len(), 1);
    assert_eq!(log[0].transport, Transport::Tcp);
}

#[tokio::test]
async fn stop_start_and_query_log() {
    let h = Hierarchy::start().await.unwrap();
    let server = h.server("test.").unwrap().clone();
    let addr = server.addr();
    assert_eq!(addr.ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));

    assert!(
        udp_query(addr, "www.example.test.", RecordType::A)
            .await
            .is_some()
    );
    server.stop().await;
    assert!(
        udp_query(addr, "www.example.test.", RecordType::A)
            .await
            .is_none()
    );
    assert!(TcpStream::connect(addr).await.is_err());

    server.start().await.unwrap();
    assert_eq!(server.addr(), addr);
    assert!(
        udp_query(addr, "www.example.test.", RecordType::A)
            .await
            .is_some()
    );

    let log = server.queries();
    assert_eq!(log.len(), 2);
    assert_eq!(log[0].name, parse_name("www.example.test.").unwrap());
    assert_eq!(log[0].query_type, RecordType::A);
    assert_eq!(log[0].transport, Transport::Udp);
    assert!(log[0].edns_present);
    assert!(log[0].edns_options.is_empty());
    server.clear_queries();
    assert!(server.queries().is_empty());
}
