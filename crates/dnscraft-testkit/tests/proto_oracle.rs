//! Oracle: queries built by `dnscraft-proto` against the hickory-based
//! testkit servers; the hickory-encoded responses must decode with ours and
//! survive a re-encode.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::net::SocketAddr;
use std::time::Duration;

use dnscraft_proto::{Edns, Message, Name, Rcode, RecordType};
use dnscraft_testkit::Hierarchy;
use hickory_proto::op::Message as HMessage;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::timeout;

fn request(name: &str, qtype: RecordType, id: u16) -> Vec<u8> {
    let mut q = Message::query(id, Name::from_ascii(name).unwrap(), qtype);
    q.header.rd = false;
    q.edns = Some(Edns::new(1232));
    q.encode().unwrap()
}

async fn udp(server: SocketAddr, name: &str, qtype: RecordType, id: u16) -> Vec<u8> {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    socket
        .send_to(&request(name, qtype, id), server)
        .await
        .unwrap();
    let mut buf = vec![0u8; 4096];
    let (len, _) = timeout(Duration::from_secs(2), socket.recv_from(&mut buf))
        .await
        .unwrap()
        .unwrap();
    buf.truncate(len);
    buf
}

async fn tcp(server: SocketAddr, name: &str, qtype: RecordType, id: u16) -> Vec<u8> {
    let mut stream = TcpStream::connect(server).await.unwrap();
    let bytes = request(name, qtype, id);
    stream
        .write_u16(u16::try_from(bytes.len()).unwrap())
        .await
        .unwrap();
    stream.write_all(&bytes).await.unwrap();
    let len = stream.read_u16().await.unwrap();
    let mut buf = vec![0u8; usize::from(len)];
    stream.read_exact(&mut buf).await.unwrap();
    buf
}

/// Decodes with ours, re-encodes with ours, decodes with hickory and compares
/// the section sizes and the records against the original hickory decode.
fn check_equivalent(raw: &[u8]) -> Message {
    let ours = Message::decode(raw).expect("our decode of hickory bytes");
    let again = ours.encode().expect("our encode");
    assert_eq!(Message::decode(&again).unwrap(), ours);

    let orig = HMessage::from_vec(raw).unwrap();
    let back = HMessage::from_vec(&again).expect("hickory decode of our bytes");
    assert_eq!(back.metadata.id, orig.metadata.id);
    assert_eq!(back.metadata.response_code, orig.metadata.response_code);
    assert_eq!(back.metadata.authoritative, orig.metadata.authoritative);
    assert_eq!(back.queries, orig.queries);
    assert_eq!(back.answers, orig.answers);
    assert_eq!(back.authorities, orig.authorities);
    assert_eq!(back.additionals, orig.additionals);
    assert_eq!(back.edns.is_some(), orig.edns.is_some());
    assert_eq!(ours.answers.len(), orig.answers.len());
    assert_eq!(ours.authorities.len(), orig.authorities.len());
    assert_eq!(ours.additionals.len(), orig.additionals.len());
    ours
}

#[tokio::test]
async fn referral_from_root() {
    let h = Hierarchy::start().await.unwrap();
    let raw = udp(h.root_hints()[0], "www.example.test.", RecordType::A, 1).await;
    let m = check_equivalent(&raw);
    assert_eq!(m.header.id, 1);
    assert!(m.header.qr && !m.header.aa);
    assert_eq!(m.rcode(), Rcode::NOERROR);
    assert!(m.answers.is_empty());
    assert_eq!(m.authorities.len(), 1);
    assert_eq!(m.authorities[0].rtype, RecordType::NS);
    assert_eq!(m.additionals.len(), 1);
}

#[tokio::test]
async fn authoritative_answers_a_and_aaaa() {
    let h = Hierarchy::start().await.unwrap();
    let addr = h.server("example.test.").unwrap().addr();
    let raw = udp(addr, "www.example.test.", RecordType::A, 2).await;
    let m = check_equivalent(&raw);
    assert!(m.header.aa);
    assert_eq!(m.rcode(), Rcode::NOERROR);
    assert_eq!(m.answers.len(), 1);
    assert_eq!(m.answers[0].rtype, RecordType::A);

    let raw = udp(addr, "www.example.test.", RecordType::AAAA, 3).await;
    let m = check_equivalent(&raw);
    assert_eq!(m.answers.len(), 1);
    assert_eq!(m.answers[0].rtype, RecordType::AAAA);
}

#[tokio::test]
async fn nxdomain_and_nodata() {
    let h = Hierarchy::start().await.unwrap();
    let addr = h.server("example.test.").unwrap().addr();
    let raw = udp(addr, "missing.example.test.", RecordType::A, 4).await;
    let m = check_equivalent(&raw);
    assert!(m.header.aa);
    assert_eq!(m.rcode(), Rcode::NXDOMAIN);
    assert!(m.answers.is_empty());
    assert_eq!(m.authorities.len(), 1);
    assert_eq!(m.authorities[0].rtype, RecordType::SOA);

    let raw = udp(addr, "www.example.test.", RecordType::TXT, 5).await;
    let m = check_equivalent(&raw);
    assert_eq!(m.rcode(), Rcode::NOERROR);
    assert!(m.answers.is_empty());
    assert_eq!(m.authorities.len(), 1);
    assert_eq!(m.authorities[0].rtype, RecordType::SOA);
}

#[tokio::test]
async fn tcp_response_decodes() {
    let h = Hierarchy::start().await.unwrap();
    let addr = h.server("example.test.").unwrap().addr();
    let raw = tcp(addr, "www.example.test.", RecordType::A, 6).await;
    let m = check_equivalent(&raw);
    assert!(m.header.aa);
    assert_eq!(m.answers.len(), 1);
    assert_eq!(m.header.id, 6);
}
