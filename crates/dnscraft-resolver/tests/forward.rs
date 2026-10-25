//! Stub forwarding: targets only, failover, and forwarding loops.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use dnscraft_proto::{Class, Message, Name, RData, Rcode, Record, RecordType};
use dnscraft_resolver::dnssec::TrustAnchors;
use dnscraft_resolver::{
    AnswerSource, DnssecStatus, ForwardZone, ManualClock, Query, RequestFlags, ResolveError,
    Resolver, ResolverConfig,
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

/// UDP target that answers every query with one A record (or with `rcode`
/// and no records when that is not NOERROR), after an optional delay.
struct Target {
    addr: SocketAddr,
    hits: Arc<AtomicUsize>,
    rd: Arc<AtomicBool>,
    dnssec_ok: Arc<AtomicBool>,
    rcode: Arc<Mutex<Rcode>>,
    task: tokio::task::JoinHandle<()>,
}

impl Target {
    async fn spawn(ip: Ipv4Addr) -> Self {
        Self::spawn_with(ip, 120, Duration::ZERO, Rcode::NOERROR).await
    }

    async fn spawn_with(ip: Ipv4Addr, ttl: u32, delay: Duration, rcode: Rcode) -> Self {
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let addr = socket.local_addr().unwrap();
        let hits = Arc::new(AtomicUsize::new(0));
        let rd = Arc::new(AtomicBool::new(false));
        let dnssec_ok = Arc::new(AtomicBool::new(false));
        let rcode = Arc::new(Mutex::new(rcode));
        let hits_task = Arc::clone(&hits);
        let rd_task = Arc::clone(&rd);
        let do_task = Arc::clone(&dnssec_ok);
        let rcode_task = Arc::clone(&rcode);
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
                let code = *rcode_task.lock().unwrap();
                let mut resp = Message::response_to(&req);
                resp.header.aa = true;
                resp.header.ra = true;
                if code == Rcode::NOERROR {
                    resp.answers.push(Record {
                        name: qname,
                        rtype: RecordType::A,
                        class: Class::IN,
                        ttl,
                        rdata: RData::A(ip),
                    });
                } else {
                    resp.set_rcode(code).unwrap();
                }
                let socket = Arc::clone(&socket);
                tokio::spawn(async move {
                    tokio::time::sleep(delay).await;
                    if let Ok(bytes) = resp.encode() {
                        let _ = socket.send_to(&bytes, peer).await;
                    }
                });
            }
        });
        Self {
            addr,
            hits,
            rd,
            dnssec_ok,
            rcode,
            task,
        }
    }

    fn set_rcode(&self, code: Rcode) {
        *self.rcode.lock().unwrap() = code;
    }

    fn hits(&self) -> usize {
        self.hits.load(Ordering::Relaxed)
    }
}

/// Socket that receives queries and never answers.
async fn silent_addr() -> (SocketAddr, UdpSocket) {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    (socket.local_addr().unwrap(), socket)
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

fn a_rdata(answer: &dnscraft_resolver::Answer) -> RData {
    answer.message.answers[0].rdata.clone()
}

/// Target order is randomised per resolver (server selection), so each
/// round uses a fresh resolver; across the rounds the failing target is
/// asked first with overwhelming probability.
async fn assert_fails_over(code: Rcode) {
    let h = Hierarchy::start().await.unwrap();
    let bad = Target::spawn_with(Ipv4Addr::new(192, 0, 2, 40), 120, Duration::ZERO, code).await;
    let live = Target::spawn(Ipv4Addr::new(192, 0, 2, 41)).await;
    for round in 0..16 {
        let mut config = config_for(&h);
        config.forward_zones = vec![forward("corp.internal.", vec![bad.addr, live.addr])];
        let resolver = Resolver::new(config).await.unwrap();
        let answer = resolver
            .resolve(
                &query("www.corp.internal.", RecordType::A),
                RequestFlags::default(),
            )
            .await
            .unwrap();
        assert_eq!(answer.message.rcode(), Rcode::NOERROR, "round {round}");
        assert_eq!(a_rdata(&answer), RData::A(Ipv4Addr::new(192, 0, 2, 41)));
    }
    assert!(bad.hits() > 0, "the failing target was never asked first");
    assert_eq!(live.hits(), 16);
}

#[tokio::test]
async fn forward_fails_over_when_the_first_target_answers_servfail() {
    assert_fails_over(Rcode::SERVFAIL).await;
}

#[tokio::test]
async fn forward_fails_over_on_refused_formerr_and_notimp() {
    for code in [Rcode::REFUSED, Rcode::FORMERR, Rcode::NOTIMP] {
        assert_fails_over(code).await;
    }
}

#[tokio::test]
async fn forward_passes_on_the_error_when_every_target_fails() {
    let h = Hierarchy::start().await.unwrap();
    let first = Target::spawn_with(
        Ipv4Addr::new(192, 0, 2, 40),
        120,
        Duration::ZERO,
        Rcode::SERVFAIL,
    )
    .await;
    let second = Target::spawn_with(
        Ipv4Addr::new(192, 0, 2, 41),
        120,
        Duration::ZERO,
        Rcode::REFUSED,
    )
    .await;
    let mut config = config_for(&h);
    config.forward_zones = vec![forward("corp.internal.", vec![first.addr, second.addr])];
    let resolver = Resolver::new(config).await.unwrap();
    let answer = resolver
        .resolve(
            &query("www.corp.internal.", RecordType::A),
            RequestFlags::default(),
        )
        .await
        .unwrap();
    assert_eq!(first.hits(), 1);
    assert_eq!(second.hits(), 1);
    assert_ne!(answer.message.rcode(), Rcode::NOERROR);
    assert!(answer.message.answers.is_empty());
}

#[tokio::test]
async fn cancelling_the_first_caller_does_not_fail_the_others() {
    let h = Hierarchy::start().await.unwrap();
    let slow = Target::spawn_with(
        Ipv4Addr::new(192, 0, 2, 50),
        120,
        Duration::from_millis(400),
        Rcode::NOERROR,
    )
    .await;
    let mut config = config_for(&h);
    config.query_timeout = Duration::from_secs(3);
    config.serve_stale = Duration::from_secs(86_400);
    config.forward_zones = vec![forward("corp.internal.", vec![slow.addr])];
    let resolver = Arc::new(Resolver::new(config).await.unwrap());
    let q = query("www.corp.internal.", RecordType::A);

    let first = {
        let r = Arc::clone(&resolver);
        let q = q.clone();
        tokio::spawn(async move { r.resolve(&q, RequestFlags::default()).await })
    };
    tokio::time::sleep(Duration::from_millis(100)).await;
    let mut followers = Vec::new();
    for _ in 0..4 {
        let r = Arc::clone(&resolver);
        let q = q.clone();
        followers.push(tokio::spawn(async move {
            r.resolve(&q, RequestFlags::default()).await
        }));
    }
    tokio::time::sleep(Duration::from_millis(100)).await;
    first.abort();
    let _ = first.await;

    for follower in followers {
        let answer = tokio::time::timeout(Duration::from_secs(5), follower)
            .await
            .unwrap()
            .unwrap()
            .expect("followers must get the real answer");
        assert_eq!(answer.source, AnswerSource::Recursion);
        assert_eq!(a_rdata(&answer), RData::A(Ipv4Addr::new(192, 0, 2, 50)));
    }
    assert_eq!(slow.hits(), 1);
    // The result was published and cached by the task that owned it.
    let cached = resolver.resolve(&q, RequestFlags::default()).await.unwrap();
    assert_eq!(cached.source, AnswerSource::Cache);
}

#[tokio::test]
async fn flush_during_a_resolution_keeps_its_result_out_of_the_cache() {
    let h = Hierarchy::start().await.unwrap();
    let slow = Target::spawn_with(
        Ipv4Addr::new(192, 0, 2, 60),
        120,
        Duration::from_millis(400),
        Rcode::NOERROR,
    )
    .await;
    let mut config = config_for(&h);
    config.query_timeout = Duration::from_secs(3);
    config.forward_zones = vec![forward("corp.internal.", vec![slow.addr])];
    let resolver = Arc::new(Resolver::new(config).await.unwrap());
    let q = query("www.corp.internal.", RecordType::A);

    let running = {
        let r = Arc::clone(&resolver);
        let q = q.clone();
        tokio::spawn(async move { r.resolve(&q, RequestFlags::default()).await })
    };
    tokio::time::sleep(Duration::from_millis(100)).await;
    resolver.flush(dnscraft_resolver::FlushScope::All);
    let answer = running.await.unwrap().unwrap();
    // The caller still gets its answer, with the TTL it would have been cached with.
    assert_eq!(a_rdata(&answer), RData::A(Ipv4Addr::new(192, 0, 2, 60)));
    assert_eq!(answer.message.answers[0].ttl, 120);
    resolver.wait_idle().await;
    assert_eq!(resolver.cached_bytes(), 0, "pre-flush result was stored");

    let again = resolver.resolve(&q, RequestFlags::default()).await.unwrap();
    assert_eq!(again.source, AnswerSource::Recursion);
    assert_eq!(slow.hits(), 2);
    assert!(resolver.cached_bytes() > 0);
}

#[tokio::test]
async fn concurrency_cap_returns_overloaded_after_query_timeout_and_recovers() {
    let h = Hierarchy::start().await.unwrap();
    let (silent_a, _keep_a) = silent_addr().await;
    let (silent_b, _keep_b) = silent_addr().await;
    let live = Target::spawn(Ipv4Addr::new(192, 0, 2, 70)).await;
    let mut config = config_for(&h);
    config.query_timeout = Duration::from_millis(300);
    config.max_concurrent_resolutions = 1;
    config.forward_zones = vec![
        // Two silent targets keep the single slot busy for two timeouts.
        forward("slow.internal.", vec![silent_a, silent_b]),
        forward("fast.internal.", vec![live.addr]),
    ];
    let resolver = Arc::new(Resolver::new(config).await.unwrap());

    let busy = {
        let r = Arc::clone(&resolver);
        tokio::spawn(async move {
            r.resolve(
                &query("x.slow.internal.", RecordType::A),
                RequestFlags::default(),
            )
            .await
        })
    };
    tokio::time::sleep(Duration::from_millis(50)).await;

    let started = std::time::Instant::now();
    let err = resolver
        .resolve(
            &query("www.fast.internal.", RecordType::A),
            RequestFlags::default(),
        )
        .await
        .unwrap_err();
    assert!(matches!(err, ResolveError::Overloaded), "{err:?}");
    assert_eq!(err.code(), "resolver.overloaded");
    assert!(started.elapsed() >= Duration::from_millis(250));
    assert_eq!(live.hits(), 0, "an overloaded miss must not reach upstream");

    // Cache hits and local answers never wait for a slot: prime one first.
    let _ = busy.await.unwrap();
    let ok = resolver
        .resolve(
            &query("www.fast.internal.", RecordType::A),
            RequestFlags::default(),
        )
        .await
        .unwrap();
    assert_eq!(ok.source, AnswerSource::Recursion);
    assert_eq!(live.hits(), 1);
}

#[tokio::test]
async fn cache_hits_do_not_wait_for_a_resolution_slot() {
    let h = Hierarchy::start().await.unwrap();
    let (silent_a, _keep_a) = silent_addr().await;
    let (silent_b, _keep_b) = silent_addr().await;
    let live = Target::spawn(Ipv4Addr::new(192, 0, 2, 70)).await;
    let mut config = config_for(&h);
    config.query_timeout = Duration::from_millis(300);
    config.max_concurrent_resolutions = 1;
    config.prefetch = false;
    config.forward_zones = vec![
        forward("slow.internal.", vec![silent_a, silent_b]),
        forward("fast.internal.", vec![live.addr]),
    ];
    let resolver = Arc::new(Resolver::new(config).await.unwrap());
    let q = query("www.fast.internal.", RecordType::A);
    resolver.resolve(&q, RequestFlags::default()).await.unwrap();

    let busy = {
        let r = Arc::clone(&resolver);
        tokio::spawn(async move {
            r.resolve(
                &query("x.slow.internal.", RecordType::A),
                RequestFlags::default(),
            )
            .await
        })
    };
    tokio::time::sleep(Duration::from_millis(50)).await;
    let started = std::time::Instant::now();
    let hit = resolver.resolve(&q, RequestFlags::default()).await.unwrap();
    assert_eq!(hit.source, AnswerSource::Cache);
    assert!(started.elapsed() < Duration::from_millis(150));
    let _ = busy.await;
}

#[tokio::test]
async fn zero_concurrency_cap_is_rejected() {
    let h = Hierarchy::start().await.unwrap();
    let mut config = config_for(&h);
    config.max_concurrent_resolutions = 0;
    let err = Resolver::new(config).await.unwrap_err();
    assert_eq!(err.code(), "resolver.invalid_config");
}

fn prefetch_config(h: &Hierarchy, clock: &Arc<ManualClock>) -> ResolverConfig {
    let mut config = config_for(h);
    config.clock = clock.clone();
    config.prefetch = true;
    config.query_timeout = Duration::from_millis(300);
    config
}

fn manual_clock() -> Arc<ManualClock> {
    Arc::new(ManualClock::new(std::time::SystemTime::now()))
}

/// Resolves `q` until it is popular, then moves the clock into the prefetch
/// window of an entry stored with a 600 s TTL (window: 60 s).
async fn make_popular(resolver: &Resolver, clock: &ManualClock, q: &Query) {
    resolver.resolve(q, RequestFlags::default()).await.unwrap();
    for _ in 0..3 {
        let hit = resolver.resolve(q, RequestFlags::default()).await.unwrap();
        assert_eq!(hit.source, AnswerSource::Cache);
    }
    resolver.wait_idle().await;
    clock.advance(Duration::from_secs(545));
}

#[tokio::test]
async fn prefetch_is_skipped_when_no_resolution_slot_is_free() {
    let h = Hierarchy::start().await.unwrap();
    let (silent_a, _keep_a) = silent_addr().await;
    let (silent_b, _keep_b) = silent_addr().await;
    let pop = Target::spawn_with(
        Ipv4Addr::new(192, 0, 2, 80),
        600,
        Duration::ZERO,
        Rcode::NOERROR,
    )
    .await;
    let clock = manual_clock();
    let mut config = prefetch_config(&h, &clock);
    config.max_concurrent_resolutions = 1;
    config.forward_zones = vec![
        forward("slow.internal.", vec![silent_a, silent_b]),
        forward("pop.internal.", vec![pop.addr]),
    ];
    let resolver = Arc::new(Resolver::new(config).await.unwrap());
    let q = query("www.pop.internal.", RecordType::A);
    make_popular(&resolver, &clock, &q).await;
    assert_eq!(pop.hits(), 1);

    // Occupy the only slot, then hit the popular entry inside its window.
    let busy = {
        let r = Arc::clone(&resolver);
        tokio::spawn(async move {
            r.resolve(
                &query("x.slow.internal.", RecordType::A),
                RequestFlags::default(),
            )
            .await
        })
    };
    tokio::time::sleep(Duration::from_millis(50)).await;
    let hit = resolver.resolve(&q, RequestFlags::default()).await.unwrap();
    assert_eq!(hit.source, AnswerSource::Cache);
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(pop.hits(), 1, "prefetch must not run without a free slot");
    let _ = busy.await;

    // With the slot free again the next hit prefetches.
    let hit = resolver.resolve(&q, RequestFlags::default()).await.unwrap();
    assert_eq!(hit.source, AnswerSource::Cache);
    resolver.wait_idle().await;
    assert_eq!(pop.hits(), 2);
}

#[tokio::test]
async fn failed_prefetch_is_not_retried_for_thirty_seconds() {
    let h = Hierarchy::start().await.unwrap();
    let pop = Target::spawn_with(
        Ipv4Addr::new(192, 0, 2, 80),
        600,
        Duration::ZERO,
        Rcode::NOERROR,
    )
    .await;
    let clock = manual_clock();
    let mut config = prefetch_config(&h, &clock);
    config.forward_zones = vec![forward("pop.internal.", vec![pop.addr])];
    let resolver = Arc::new(Resolver::new(config).await.unwrap());
    let q = query("www.pop.internal.", RecordType::A);
    make_popular(&resolver, &clock, &q).await;
    assert_eq!(pop.hits(), 1);

    // The upstream breaks. The first hit in the window tries and fails.
    pop.set_rcode(Rcode::SERVFAIL);
    resolver.resolve(&q, RequestFlags::default()).await.unwrap();
    resolver.wait_idle().await;
    assert_eq!(pop.hits(), 2);

    // Further hits inside the backoff do not query the upstream again.
    for _ in 0..3 {
        let hit = resolver.resolve(&q, RequestFlags::default()).await.unwrap();
        assert_eq!(hit.source, AnswerSource::Cache);
        resolver.wait_idle().await;
    }
    assert_eq!(pop.hits(), 2, "retried inside the backoff window");
    clock.advance(Duration::from_secs(29));
    resolver.resolve(&q, RequestFlags::default()).await.unwrap();
    resolver.wait_idle().await;
    assert_eq!(pop.hits(), 2);

    // After 30 s the key may be tried again, and a success clears the backoff.
    pop.set_rcode(Rcode::NOERROR);
    clock.advance(Duration::from_secs(2));
    resolver.resolve(&q, RequestFlags::default()).await.unwrap();
    resolver.wait_idle().await;
    assert_eq!(pop.hits(), 3);
}
