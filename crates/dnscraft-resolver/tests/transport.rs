//! Transport tests. The modules under test are crate-private, so their
//! sources are compiled into this test crate directly.
#![allow(clippy::unwrap_used, clippy::expect_used, dead_code)]

#[path = "../src/server_selection.rs"]
mod server_selection;
#[path = "../src/transport.rs"]
mod transport;

use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use dnscraft_proto::{Class, Message, Name, RData, Rcode, Record, RecordType};
use server_selection::ServerStats;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use transport::{TransportError, build_query, exchange, query_servers, query_servers_with};

const TIMEOUT: Duration = Duration::from_millis(500);

fn qname() -> Name {
    Name::from_ascii("www.example.test.").unwrap()
}

fn answer_for(query: &Message, ip: Ipv4Addr) -> Message {
    let mut resp = Message::response_to(query);
    resp.header.aa = true;
    resp.answers.push(Record {
        name: query.questions[0].name.clone(),
        rtype: RecordType::A,
        class: Class::IN,
        ttl: 60,
        rdata: RData::A(ip),
    });
    resp
}

fn first_ip(msg: &Message) -> Ipv4Addr {
    match &msg.answers[0].rdata {
        RData::A(a) => *a,
        other => panic!("unexpected rdata {other:?}"),
    }
}

#[derive(Clone, Copy)]
enum Behavior {
    /// Answers 192.0.2.1 after `delay_ms`.
    Answer { delay_ms: u64 },
    /// Always sets TC on UDP; answers over TCP.
    Truncate,
    /// Wrong id, wrong question, response-flag-less echo, then the answer.
    Spoof,
    /// Garbage datagrams, then (if `then_answer`) the answer.
    Garbage { then_answer: bool },
}

/// Fake server on 127.0.0.1 (same port for UDP and TCP); returns its address.
async fn send(udp: &UdpSocket, peer: SocketAddr, m: &Message) -> std::io::Result<usize> {
    udp.send_to(&m.encode().unwrap(), peer).await
}

async fn fake(behavior: Behavior) -> SocketAddr {
    let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = tcp.local_addr().unwrap();
    let udp = UdpSocket::bind(addr).await.unwrap();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        loop {
            let (len, peer) = udp.recv_from(&mut buf).await.unwrap();
            let Ok(q) = Message::decode(&buf[..len]) else {
                continue;
            };
            let good = answer_for(&q, Ipv4Addr::new(192, 0, 2, 1));
            match behavior {
                Behavior::Answer { delay_ms } => {
                    tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                    send(&udp, peer, &good).await.unwrap();
                }
                Behavior::Truncate => {
                    let mut tc = Message::response_to(&q);
                    tc.header.tc = true;
                    send(&udp, peer, &tc).await.unwrap();
                }
                Behavior::Spoof => {
                    let mut wrong_id = answer_for(&q, Ipv4Addr::new(6, 6, 6, 6));
                    wrong_id.header.id = q.header.id.wrapping_add(1);
                    send(&udp, peer, &wrong_id).await.unwrap();
                    let mut wrong_q = answer_for(&q, Ipv4Addr::new(6, 6, 6, 6));
                    wrong_q.questions[0].name = Name::from_ascii("evil.example.test.").unwrap();
                    send(&udp, peer, &wrong_q).await.unwrap();
                    let mut wrong_type = answer_for(&q, Ipv4Addr::new(6, 6, 6, 6));
                    wrong_type.questions[0].qtype = RecordType::AAAA;
                    send(&udp, peer, &wrong_type).await.unwrap();
                    let mut not_response = answer_for(&q, Ipv4Addr::new(6, 6, 6, 6));
                    not_response.header.qr = false;
                    send(&udp, peer, &not_response).await.unwrap();
                    send(&udp, peer, &good).await.unwrap();
                }
                Behavior::Garbage { then_answer } => {
                    udp.send_to(&[0xde, 0xad, 0xbe, 0xef], peer).await.unwrap();
                    udp.send_to(&[], peer).await.unwrap();
                    let mut junk = good.encode().unwrap();
                    junk.truncate(20);
                    udp.send_to(&junk, peer).await.unwrap();
                    if then_answer {
                        send(&udp, peer, &good).await.unwrap();
                    }
                }
            }
        }
    });
    if matches!(behavior, Behavior::Truncate) {
        tokio::spawn(async move {
            loop {
                let (mut s, _) = tcp.accept().await.unwrap();
                tokio::spawn(async move {
                    let mut len = [0u8; 2];
                    s.read_exact(&mut len).await.unwrap();
                    let mut buf = vec![0u8; usize::from(u16::from_be_bytes(len))];
                    s.read_exact(&mut buf).await.unwrap();
                    let q = Message::decode(&buf).unwrap();
                    let wire = answer_for(&q, Ipv4Addr::new(192, 0, 2, 7))
                        .encode()
                        .unwrap();
                    s.write_all(&(wire.len() as u16).to_be_bytes())
                        .await
                        .unwrap();
                    s.write_all(&wire).await.unwrap();
                });
            }
        });
    }
    addr
}

/// An address on which nothing listens (UDP gets ICMP port unreachable).
async fn dead_addr() -> SocketAddr {
    let s = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    s.local_addr().unwrap()
}

#[tokio::test]
async fn truncated_udp_is_retried_over_tcp() {
    let server = fake(Behavior::Truncate).await;
    let q = build_query(&qname(), RecordType::A);
    let resp = exchange(server, &q, TIMEOUT).await.unwrap();
    assert!(!resp.header.tc);
    assert_eq!(first_ip(&resp), Ipv4Addr::new(192, 0, 2, 7), "TCP answer");
}

#[tokio::test]
async fn stopped_server_is_skipped_and_penalised() {
    let dead = dead_addr().await;
    let good = fake(Behavior::Answer { delay_ms: 0 }).await;
    let stats = ServerStats::default().with_exploration(0.0);
    // Make the dead server the preferred one so it is tried first.
    stats.record_success(good, Duration::from_millis(200));
    stats.record_success(dead, Duration::from_millis(1));
    assert_eq!(stats.order(&[good, dead])[0], dead);

    let q = build_query(&qname(), RecordType::A);
    let r = query_servers(&[dead, good], &q, TIMEOUT, &stats)
        .await
        .unwrap();
    assert_eq!(r.server, good);
    assert!(!r.lame);
    assert!(stats.srtt(dead).unwrap() > stats.srtt(good).unwrap());
    assert_eq!(stats.order(&[dead, good])[0], good);
}

#[tokio::test]
async fn silent_server_times_out_then_next_answers() {
    // Bound but never answering.
    let silent = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let silent_addr = silent.local_addr().unwrap();
    let good = fake(Behavior::Answer { delay_ms: 0 }).await;
    let stats = ServerStats::default().with_exploration(0.0);
    stats.record_success(good, Duration::from_millis(200));
    stats.record_success(silent_addr, Duration::from_millis(1));
    let q = build_query(&qname(), RecordType::A);
    let r = query_servers(&[silent_addr, good], &q, Duration::from_millis(150), &stats)
        .await
        .unwrap();
    assert_eq!(r.server, good);
    assert!(stats.srtt(silent_addr).unwrap() >= Duration::from_millis(100));
}

#[tokio::test]
async fn lame_response_moves_to_next_server() {
    let lame = fake(Behavior::Answer { delay_ms: 0 }).await;
    let good = fake(Behavior::Answer { delay_ms: 0 }).await;
    let stats = ServerStats::default().with_exploration(0.0);
    stats.record_success(lame, Duration::from_millis(1));
    stats.record_success(good, Duration::from_millis(100));
    let q = build_query(&qname(), RecordType::A);
    // Reject answers from the first server by source, via a stateful predicate.
    let calls = std::cell::Cell::new(0);
    let r = query_servers_with(&[lame, good], &q, TIMEOUT, &stats, |_| {
        calls.set(calls.get() + 1);
        calls.get() > 1
    })
    .await
    .unwrap();
    assert_eq!(r.server, good);
    assert!(!r.lame);

    // All lame: the last lame response is returned, flagged.
    let r = query_servers_with(&[lame, good], &q, TIMEOUT, &stats, |m| {
        m.header.rcode_low == Rcode::REFUSED.value() as u8
    })
    .await
    .unwrap();
    assert!(r.lame);
}

#[tokio::test]
async fn spoofed_datagrams_are_ignored() {
    let server = fake(Behavior::Spoof).await;
    let q = build_query(&qname(), RecordType::A);
    let resp = exchange(server, &q, TIMEOUT).await.unwrap();
    assert_eq!(first_ip(&resp), Ipv4Addr::new(192, 0, 2, 1));
}

#[tokio::test]
async fn case_insensitive_question_is_accepted() {
    let server = fake(Behavior::Answer { delay_ms: 0 }).await;
    let q = build_query(
        &Name::from_ascii("WWW.Example.TEST.").unwrap(),
        RecordType::A,
    );
    assert!(exchange(server, &q, TIMEOUT).await.is_ok());
}

#[tokio::test]
async fn ordering_prefers_the_faster_server() {
    let slow = fake(Behavior::Answer { delay_ms: 80 }).await;
    let fast = fake(Behavior::Answer { delay_ms: 0 }).await;
    let stats = ServerStats::default().with_exploration(0.0);
    for _ in 0..4 {
        for s in [slow, fast] {
            let q = build_query(&qname(), RecordType::A);
            query_servers(&[s], &q, TIMEOUT, &stats).await.unwrap();
        }
    }
    assert!(stats.srtt(fast).unwrap() < stats.srtt(slow).unwrap());
    assert_eq!(stats.order(&[slow, fast]), vec![fast, slow]);
    assert_eq!(stats.order(&[fast, slow]), vec![fast, slow]);
    let q = build_query(&qname(), RecordType::A);
    let r = query_servers(&[slow, fast], &q, TIMEOUT, &stats)
        .await
        .unwrap();
    assert_eq!(r.server, fast);
}

#[tokio::test]
async fn garbage_is_ignored_until_valid_answer() {
    let server = fake(Behavior::Garbage { then_answer: true }).await;
    let q = build_query(&qname(), RecordType::A);
    let resp = exchange(server, &q, TIMEOUT).await.unwrap();
    assert_eq!(first_ip(&resp), Ipv4Addr::new(192, 0, 2, 1));
}

#[tokio::test]
async fn only_garbage_times_out() {
    let server = fake(Behavior::Garbage { then_answer: false }).await;
    let q = build_query(&qname(), RecordType::A);
    let err = exchange(server, &q, Duration::from_millis(200))
        .await
        .unwrap_err();
    assert!(matches!(err, TransportError::Timeout), "{err:?}");
}

#[tokio::test]
async fn empty_candidates_is_an_error() {
    let stats = ServerStats::default();
    let q = build_query(&qname(), RecordType::A);
    let err = query_servers(&[], &q, TIMEOUT, &stats).await.unwrap_err();
    assert!(matches!(err, TransportError::NoServers));
}

#[test]
fn ipv6_is_deprioritised_while_marked_unavailable() {
    let stats = ServerStats::new(Duration::from_secs(60)).with_exploration(0.0);
    let v6: SocketAddr = "[2001:db8::1]:53".parse().unwrap();
    let v4: SocketAddr = "192.0.2.1:53".parse().unwrap();
    stats.record_success(v6, Duration::from_millis(1));
    stats.record_success(v4, Duration::from_millis(100));
    assert_eq!(stats.order(&[v4, v6]), vec![v6, v4]);
    let err = std::io::Error::from(std::io::ErrorKind::NetworkUnreachable);
    stats.record_io_error(v6, &err);
    assert!(!stats.ipv6_available());
    assert_eq!(stats.order(&[v6, v4]), vec![v4, v6]);
}
