//! ACME DNS-01 propagation check against a tiny loopback UDP TXT responder.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use dnscraft_proto::{Class, Message, RData, Record};
use dnscraft_tls::{
    ManualClock, TlsError, resolve_nameservers, wait_for_txt, wait_for_txt_with_query_timeout,
};
use tokio::net::UdpSocket;

const NAME: &str = "_acme-challenge.dns.example.com";
const V1: &str = "challenge-value-one";
const V2: &str = "challenge-value-two";

#[derive(Clone, Copy, Debug)]
enum Behaviour {
    /// Answer with the current TXT set and matching query id.
    Normal,
    /// Echo a wrong query id.
    WrongId,
    /// Send fewer than 12 bytes (truncated header).
    TruncatedWire,
    /// Answer correctly, but from a different socket than the one queried.
    OtherSource,
}

struct Responder {
    addr: SocketAddr,
    values: Arc<Mutex<Vec<String>>>,
    behaviour: Arc<Mutex<Behaviour>>,
}

impl Responder {
    async fn start() -> Self {
        Self::start_on("127.0.0.1:0").await
    }

    async fn start_on(bind: &str) -> Self {
        let sock = UdpSocket::bind(bind).await.unwrap();
        let spoof_bind = if sock.local_addr().unwrap().is_ipv6() {
            "[::1]:0"
        } else {
            "127.0.0.1:0"
        };
        let spoof = UdpSocket::bind(spoof_bind).await.unwrap();
        let addr = sock.local_addr().unwrap();
        let values: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let behaviour = Arc::new(Mutex::new(Behaviour::Normal));
        let (v, b) = (values.clone(), behaviour.clone());
        tokio::spawn(async move {
            let mut buf = vec![0u8; 2048];
            loop {
                let Ok((n, peer)) = sock.recv_from(&mut buf).await else {
                    return;
                };
                let behaviour = *b.lock().unwrap();
                match behaviour {
                    Behaviour::TruncatedWire => {
                        let _ = sock.send_to(&[0u8; 8], peer).await;
                        continue;
                    }
                    Behaviour::WrongId | Behaviour::Normal | Behaviour::OtherSource => {}
                }
                let Ok(req) = Message::decode(&buf[..n]) else {
                    continue;
                };
                let mut resp = Message::response_to(&req);
                resp.header.aa = true;
                if matches!(behaviour, Behaviour::WrongId) {
                    resp.header.id = req.header.id.wrapping_add(1);
                }
                let vals = v.lock().unwrap().clone();
                let qname = req.questions.first().map(|q| q.name.clone());
                if let Some(owner) = qname {
                    for content in vals {
                        resp.answers.push(Record::new(
                            owner.clone(),
                            Class::IN,
                            120,
                            RData::TXT(vec![content.into_bytes().into()]),
                        ));
                    }
                }
                let Ok(wire) = resp.encode() else {
                    continue;
                };
                if matches!(behaviour, Behaviour::OtherSource) {
                    let _ = spoof.send_to(&wire, peer).await;
                } else {
                    let _ = sock.send_to(&wire, peer).await;
                }
            }
        });
        Self {
            addr,
            values,
            behaviour,
        }
    }

    fn set_values(&self, vals: &[&str]) {
        *self.values.lock().unwrap() = vals.iter().map(|s| (*s).to_owned()).collect();
    }

    fn set_behaviour(&self, b: Behaviour) {
        *self.behaviour.lock().unwrap() = b;
    }
}

fn clock() -> Arc<ManualClock> {
    Arc::new(ManualClock::new(
        SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000),
    ))
}

async fn drive_polls(clock: &ManualClock, poll: Duration, n: u32) {
    for _ in 0..n {
        // Let the waiter register on tick_notify, then advance.
        tokio::task::yield_now().await;
        tokio::time::sleep(Duration::from_millis(20)).await;
        clock.advance(poll);
    }
}

#[tokio::test]
async fn values_appear_after_two_polls() {
    let srv = Responder::start().await;
    let clock = clock();
    let poll = Duration::from_secs(5);
    let timeout = Duration::from_secs(60);
    let ns = vec![vec![srv.addr]];

    let clock2 = clock.clone();
    let task = tokio::spawn(async move {
        wait_for_txt(
            NAME,
            &[V1.into(), V2.into()],
            &ns,
            poll,
            timeout,
            clock2.as_ref(),
        )
        .await
    });

    // Round 0: empty → wait
    tokio::time::sleep(Duration::from_millis(50)).await;
    srv.set_values(&[V1]); // still missing V2
    drive_polls(&clock, poll, 1).await;

    tokio::time::sleep(Duration::from_millis(50)).await;
    srv.set_values(&[V1, V2]);
    drive_polls(&clock, poll, 1).await;

    let result = tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .expect("join timeout")
        .unwrap();
    assert!(result.is_ok(), "{result:?}");
}

#[tokio::test]
async fn only_one_of_two_keeps_waiting_then_times_out() {
    let srv = Responder::start().await;
    srv.set_values(&[V1]);
    let clock = clock();
    let poll = Duration::from_secs(5);
    let timeout = Duration::from_secs(15);
    let ns = vec![vec![srv.addr]];

    let clock2 = clock.clone();
    let task = tokio::spawn(async move {
        wait_for_txt(
            NAME,
            &[V1.into(), V2.into()],
            &ns,
            poll,
            timeout,
            clock2.as_ref(),
        )
        .await
    });

    // Advance past the timeout while only one value is present.
    drive_polls(&clock, poll, 4).await;

    let result = tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .expect("join timeout")
        .unwrap();
    let err = result.expect_err("must time out");
    assert_eq!(err.code(), "tls.acme.propagation");
    assert!(matches!(err, TlsError::AcmePropagation));
}

#[tokio::test]
async fn mismatched_query_id_ignored_no_panic() {
    let srv = Responder::start().await;
    srv.set_values(&[V1, V2]);
    srv.set_behaviour(Behaviour::WrongId);
    let clock = clock();
    let poll = Duration::from_secs(5);
    let timeout = Duration::from_secs(10);
    let ns = vec![vec![srv.addr]];

    let clock2 = clock.clone();
    let task = tokio::spawn(async move {
        wait_for_txt(
            NAME,
            &[V1.into(), V2.into()],
            &ns,
            poll,
            timeout,
            clock2.as_ref(),
        )
        .await
    });

    drive_polls(&clock, poll, 3).await;
    let result = tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .expect("join timeout")
        .unwrap();
    assert_eq!(result.unwrap_err().code(), "tls.acme.propagation");
}

#[tokio::test]
async fn truncated_response_ignored_no_panic() {
    let srv = Responder::start().await;
    srv.set_values(&[V1, V2]);
    srv.set_behaviour(Behaviour::TruncatedWire);
    let clock = clock();
    let poll = Duration::from_secs(5);
    let timeout = Duration::from_secs(10);
    let ns = vec![vec![srv.addr]];

    let clock2 = clock.clone();
    let task = tokio::spawn(async move {
        wait_for_txt(
            NAME,
            &[V1.into(), V2.into()],
            &ns,
            poll,
            timeout,
            clock2.as_ref(),
        )
        .await
    });

    drive_polls(&clock, poll, 3).await;
    let result = tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .expect("join timeout")
        .unwrap();
    assert_eq!(result.unwrap_err().code(), "tls.acme.propagation");
}

#[tokio::test]
async fn every_nameserver_must_have_all_values() {
    let a = Responder::start().await;
    let b = Responder::start().await;
    a.set_values(&[V1, V2]);
    b.set_values(&[V1]); // missing V2

    let clk = clock();
    let poll = Duration::from_secs(5);
    let timeout = Duration::from_secs(12);
    let ns = vec![vec![a.addr], vec![b.addr]];

    let clk2 = clk.clone();
    let task = tokio::spawn(async move {
        wait_for_txt(
            NAME,
            &[V1.into(), V2.into()],
            &ns,
            poll,
            timeout,
            clk2.as_ref(),
        )
        .await
    });

    drive_polls(&clk, poll, 3).await;
    let err = tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap_err();
    assert_eq!(err.code(), "tls.acme.propagation");

    // Fix second NS and succeed on a fresh wait.
    b.set_values(&[V1, V2]);
    let clk_ok = clock();
    let ok = wait_for_txt(
        NAME,
        &[V1.into(), V2.into()],
        &[vec![a.addr], vec![b.addr]],
        poll,
        timeout,
        clk_ok.as_ref(),
    )
    .await;
    assert!(ok.is_ok());
}

const SHORT_QUERY: Duration = Duration::from_millis(200);

fn expected() -> Vec<String> {
    vec![V1.into(), V2.into()]
}

#[tokio::test]
async fn ipv6_loopback_nameserver_is_queried_over_v6() {
    // Skip (not fail) on hosts without IPv6 loopback.
    if UdpSocket::bind("[::1]:0").await.is_err() {
        eprintln!("no IPv6 loopback; skipping");
        return;
    }
    let srv = Responder::start_on("[::1]:0").await;
    srv.set_values(&[V1, V2]);
    assert!(srv.addr.is_ipv6());

    let clk = clock();
    // The clock is never advanced: success must come from the first round.
    let result = tokio::time::timeout(
        Duration::from_secs(5),
        wait_for_txt(
            NAME,
            &expected(),
            &[vec![srv.addr]],
            Duration::from_secs(5),
            Duration::from_secs(10),
            clk.as_ref(),
        ),
    )
    .await
    .expect("first round must succeed over IPv6");
    assert!(result.is_ok(), "{result:?}");
}

#[tokio::test]
async fn nameserver_passes_when_one_address_answers() {
    // First address is bound but silent (like an unreachable AAAA); the second answers.
    let silent = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let silent_addr = silent.local_addr().unwrap();
    let good = Responder::start().await;
    good.set_values(&[V1, V2]);

    let clk = clock();
    // The clock is never advanced: success must come from the first round.
    let result = tokio::time::timeout(
        Duration::from_secs(5),
        wait_for_txt_with_query_timeout(
            NAME,
            &expected(),
            &[vec![silent_addr, good.addr]],
            Duration::from_secs(5),
            Duration::from_secs(10),
            SHORT_QUERY,
            clk.as_ref(),
        ),
    )
    .await
    .expect("first round must succeed via the answering address");
    assert!(result.is_ok(), "{result:?}");
    drop(silent);
}

#[tokio::test]
async fn nameserver_with_only_silent_addresses_times_out() {
    let silent = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let silent_addr = silent.local_addr().unwrap();
    let good = Responder::start().await;
    good.set_values(&[V1, V2]);

    let clk = clock();
    let clk2 = clk.clone();
    // Group 1 (silent) can never pass, even though group 2 is fine.
    let ns = vec![vec![silent_addr], vec![good.addr]];
    let task = tokio::spawn(async move {
        wait_for_txt_with_query_timeout(
            NAME,
            &[V1.into(), V2.into()],
            &ns,
            Duration::from_secs(5),
            Duration::from_secs(10),
            SHORT_QUERY,
            clk2.as_ref(),
        )
        .await
    });
    drive_polls(&clk, Duration::from_secs(5), 4).await;
    let err = tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap_err();
    assert_eq!(err.code(), "tls.acme.propagation");
}

#[tokio::test]
async fn response_from_unexpected_source_is_ignored() {
    let srv = Responder::start().await;
    srv.set_values(&[V1, V2]);
    srv.set_behaviour(Behaviour::OtherSource);

    let clk = clock();
    let clk2 = clk.clone();
    let ns = vec![vec![srv.addr]];
    let task = tokio::spawn(async move {
        wait_for_txt_with_query_timeout(
            NAME,
            &[V1.into(), V2.into()],
            &ns,
            Duration::from_secs(5),
            Duration::from_secs(10),
            SHORT_QUERY,
            clk2.as_ref(),
        )
        .await
    });
    drive_polls(&clk, Duration::from_secs(5), 4).await;
    let err = tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap_err();
    assert_eq!(err.code(), "tls.acme.propagation");
}

#[tokio::test]
async fn resolve_nameservers_groups_literals_and_fails_closed() {
    let groups = resolve_nameservers(&["127.0.0.1:5353".into(), "[::1]:5354".into()])
        .await
        .unwrap();
    assert_eq!(groups.len(), 2);
    assert!(groups.iter().all(|g| g.len() == 1));

    let err = resolve_nameservers(&[]).await.unwrap_err();
    assert_eq!(err.code(), "tls.acme.propagation");
}
