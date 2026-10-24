//! Stub forwarding: targets only, failover, and forwarding loops.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use dnscraft_proto::{Class, Message, Name, RData, Rcode, Record, RecordType};
use dnscraft_resolver::dnssec::TrustAnchors;
use dnscraft_resolver::{
    AnswerSource, DnssecStatus, ForwardZone, Query, RequestFlags, Resolver, ResolverConfig,
};
use dnscraft_testkit::Hierarchy;
use tokio::net::UdpSocket;
use tokio::sync::oneshot;

fn name(text: &str) -> Name {
    Name::from_ascii(text).unwrap()
}

fn query(text: &str, qtype: RecordType) -> Query {
    Query {
        name: name(text),
        qtype,
        qclass: Class::IN,
    }
}

fn config_for(h: &Hierarchy) -> ResolverConfig {
    let overrides = h
        .nameserver_addrs()
        .iter()
        .map(|(n, a)| (Name::from_ascii(&n.to_string()).unwrap(), *a))
        .collect();
    ResolverConfig {
        root_hints: h.root_hints(),
        query_timeout: Duration::from_millis(300),
        nameserver_addr_overrides: overrides,
        trust_anchors: TrustAnchors::empty(),
        prefetch: false,
        ..ResolverConfig::default()
    }
}

fn root_queries(h: &Hierarchy) -> Vec<(String, RecordType)> {
    h.server(".")
        .unwrap()
        .queries()
        .iter()
        .map(|q| (q.name.to_string(), RecordType(u16::from(q.query_type))))
        .collect()
}

/// UDP target that answers every query with one A record.
struct Target {
    addr: SocketAddr,
    hits: Arc<AtomicUsize>,
    rd: Arc<AtomicBool>,
    dnssec_ok: Arc<AtomicBool>,
    task: tokio::task::JoinHandle<()>,
}

impl Target {
    async fn spawn(ip: Ipv4Addr) -> Self {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();
        let hits = Arc::new(AtomicUsize::new(0));
        let rd = Arc::new(AtomicBool::new(false));
        let dnssec_ok = Arc::new(AtomicBool::new(false));
        let hits_task = Arc::clone(&hits);
        let rd_task = Arc::clone(&rd);
        let do_task = Arc::clone(&dnssec_ok);
        let task = tokio::spawn(async move {
            let mut buf = vec![0u8; 2048];
            loop {
                let Ok((len, peer)) = socket.recv_from(&mut buf).await else {
                    return;
                };
                let Ok(req) = Message::decode(&buf[..len]) else {
                    continue;
                };
                hits_task.fetch_add(1, Ordering::Relaxed);
                rd_task.store(req.header.rd, Ordering::Relaxed);
                do_task.store(
                    req.edns.as_ref().is_some_and(|edns| edns.dnssec_ok),
                    Ordering::Relaxed,
                );
                let qname = req
                    .questions
                    .first()
                    .map(|q| q.name.clone())
                    .unwrap_or_else(Name::root);
                let mut resp = Message::response_to(&req);
                resp.header.aa = true;
                resp.header.ra = true;
                resp.answers.push(Record {
                    name: qname,
                    rtype: RecordType::A,
                    class: Class::IN,
                    ttl: 120,
                    rdata: RData::A(ip),
                });
                if let Ok(bytes) = resp.encode() {
                    let _ = socket.send_to(&bytes, peer).await;
                }
            }
        });
        Self {
            addr,
            hits,
            rd,
            dnssec_ok,
            task,
        }
    }

    fn hits(&self) -> usize {
        self.hits.load(Ordering::Relaxed)
    }
}

impl Drop for Target {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn forward(zone: &str, targets: Vec<SocketAddr>) -> ForwardZone {
    ForwardZone {
        zone: name(zone),
        targets,
        validate: false,
    }
}

#[tokio::test]
async fn forward_zone_is_answered_by_targets_not_the_root() {
    let h = Hierarchy::start().await.unwrap();
    let target = Target::spawn(Ipv4Addr::new(192, 0, 2, 10)).await;
    let mut config = config_for(&h);
    config.forward_zones = vec![forward("corp.internal.", vec![target.addr])];
    let resolver = Resolver::new(config).await.unwrap();
    h.server(".").unwrap().clear_queries();

    let q = query("www.corp.internal.", RecordType::A);
    let answer = resolver.resolve(&q, RequestFlags::default()).await.unwrap();
    assert_eq!(answer.source, AnswerSource::Recursion);
    assert_eq!(answer.dnssec, DnssecStatus::Insecure);
    assert!(!answer.message.header.aa);
    assert!(answer.message.header.ra);
    assert!(!answer.message.header.ad);
    assert_eq!(answer.message.rcode(), Rcode::NOERROR);
    assert_eq!(
        answer.message.answers[0].rdata,
        RData::A(Ipv4Addr::new(192, 0, 2, 10))
    );
    assert_eq!(target.hits(), 1);
    assert!(target.rd.load(Ordering::Relaxed));
    assert!(target.dnssec_ok.load(Ordering::Relaxed));
    // The fake root was primed, then cleared. The forwarded name never
    // reaches it; a name outside the zone still does.
    assert!(root_queries(&h).is_empty());

    let outside = resolver
        .resolve(
            &query("www.example.test.", RecordType::A),
            RequestFlags::default(),
        )
        .await
        .unwrap();
    assert_eq!(
        outside.message.answers[0].rdata,
        RData::A(Ipv4Addr::new(192, 0, 2, 1))
    );
    assert!(
        root_queries(&h)
            .iter()
            .any(|(n, t)| n == "test." && *t == RecordType::A)
    );
    assert!(
        root_queries(&h)
            .iter()
            .all(|(n, _)| !n.contains("corp.internal"))
    );
    assert_eq!(target.hits(), 1);

    let before = resolver.stats().outgoing_queries;
    let cached = resolver.resolve(&q, RequestFlags::default()).await.unwrap();
    assert_eq!(cached.source, AnswerSource::Cache);
    assert_eq!(cached.dnssec, DnssecStatus::Insecure);
    assert_eq!(
        cached.message.answers[0].rdata,
        RData::A(Ipv4Addr::new(192, 0, 2, 10))
    );
    assert_eq!(target.hits(), 1);
    assert_eq!(resolver.stats().outgoing_queries, before);
}

#[tokio::test]
async fn forward_fails_over_when_the_first_target_is_down() {
    let h = Hierarchy::start().await.unwrap();
    let live = Target::spawn(Ipv4Addr::new(192, 0, 2, 20)).await;
    let dead = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let dead_addr = dead.local_addr().unwrap();
    drop(dead);

    let mut config = config_for(&h);
    config.forward_zones = vec![forward("corp.internal.", vec![dead_addr, live.addr])];
    let resolver = Resolver::new(config).await.unwrap();
    h.server(".").unwrap().clear_queries();

    let answer = resolver
        .resolve(
            &query("www.corp.internal.", RecordType::A),
            RequestFlags::default(),
        )
        .await
        .unwrap();
    assert_eq!(
        answer.message.answers[0].rdata,
        RData::A(Ipv4Addr::new(192, 0, 2, 20))
    );
    assert!(answer.message.header.ra);
    assert!(!answer.message.header.aa);
    assert_eq!(answer.dnssec, DnssecStatus::Insecure);
    assert!(live.hits() >= 1);
    assert!(root_queries(&h).is_empty());
}

#[tokio::test]
async fn forward_loop_returns_servfail_without_hanging() {
    let h = Hierarchy::start().await.unwrap();
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();
    let mut config = config_for(&h);
    config.forward_zones = vec![forward("corp.internal.", vec![addr])];
    let resolver = Arc::new(Resolver::new(config).await.unwrap());
    h.server(".").unwrap().clear_queries();

    // Simulate the remote target forwarding the question back: the peer on
    // the re-entrant resolve is the forward target itself.
    let inner = Arc::clone(&resolver);
    let (tx, rx) = oneshot::channel();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 2048];
        let Ok((len, peer)) = socket.recv_from(&mut buf).await else {
            return;
        };
        let Ok(req) = Message::decode(&buf[..len]) else {
            return;
        };
        let question = &req.questions[0];
        let q = Query {
            name: question.name.clone(),
            qtype: question.qtype,
            qclass: question.qclass,
        };
        let flags = RequestFlags {
            client: Some(addr),
            ..RequestFlags::default()
        };
        let code = match inner.resolve(&q, flags).await {
            Err(err) => err.code().to_owned(),
            Ok(_) => "ok".to_owned(),
        };
        let _ = tx.send(code);
        let mut resp = Message::response_to(&req);
        resp.set_rcode(Rcode::SERVFAIL).unwrap();
        if let Ok(bytes) = resp.encode() {
            let _ = socket.send_to(&bytes, peer).await;
        }
    });

    let q = query("www.corp.internal.", RecordType::A);
    let finished = tokio::time::timeout(
        Duration::from_secs(2),
        resolver.resolve(&q, RequestFlags::default()),
    )
    .await
    .expect("forward loop hung");
    let answer = finished.expect("outer forward failed");
    assert_eq!(answer.message.rcode(), Rcode::SERVFAIL);
    let code = tokio::time::timeout(Duration::from_secs(1), rx)
        .await
        .expect("re-entrant resolve hung")
        .unwrap();
    assert_eq!(code, "resolver.forward_loop");
    assert!(root_queries(&h).is_empty());
}

#[tokio::test]
async fn concurrent_forwards_coalesce_on_one_target_query() {
    let h = Hierarchy::start().await.unwrap();
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();
    let hits = Arc::new(AtomicUsize::new(0));
    let hits_task = Arc::clone(&hits);
    // Delay the answer so every concurrent resolve is in flight together.
    tokio::spawn(async move {
        let mut buf = vec![0u8; 2048];
        let Ok((len, peer)) = socket.recv_from(&mut buf).await else {
            return;
        };
        hits_task.fetch_add(1, Ordering::Relaxed);
        let Ok(req) = Message::decode(&buf[..len]) else {
            return;
        };
        tokio::time::sleep(Duration::from_millis(50)).await;
        let qname = req
            .questions
            .first()
            .map(|q| q.name.clone())
            .unwrap_or_else(Name::root);
        let mut resp = Message::response_to(&req);
        resp.header.aa = true;
        resp.header.ra = true;
        resp.answers.push(Record {
            name: qname,
            rtype: RecordType::A,
            class: Class::IN,
            ttl: 60,
            rdata: RData::A(Ipv4Addr::new(192, 0, 2, 30)),
        });
        if let Ok(bytes) = resp.encode() {
            let _ = socket.send_to(&bytes, peer).await;
        }
    });

    let mut config = config_for(&h);
    config.forward_zones = vec![forward("corp.internal.", vec![addr])];
    let resolver = Arc::new(Resolver::new(config).await.unwrap());
    let q = query("www.corp.internal.", RecordType::A);

    let mut tasks = Vec::new();
    for _ in 0..20 {
        let r = Arc::clone(&resolver);
        let q = q.clone();
        tasks.push(tokio::spawn(async move {
            r.resolve(&q, RequestFlags::default()).await.unwrap()
        }));
    }
    let mut answers = Vec::new();
    for task in tasks {
        answers.push(task.await.unwrap());
    }
    assert_eq!(hits.load(Ordering::Relaxed), 1);
    for answer in answers {
        assert_eq!(
            answer.message.answers[0].rdata,
            RData::A(Ipv4Addr::new(192, 0, 2, 30))
        );
    }
}
