//! Checkpoint C: encrypted e2e, public admission matrix, cert hot reload.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod support;

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, SystemTime};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use bytes::Bytes;
use dnscraft_filtering::{
    FilterConfig, FilterEngine, FilterSetConfig, ListBodies, ListId, ManualClock, SetId,
    SnapshotBuilder,
};
use dnscraft_listeners::{
    ALPN_DOT, ALPN_H2, ALPN_HTTP_1_1, Admission, DohServeParams, DohStats, DoqServeParams,
    DoqStats, DotServeParams, DotStats, Exposure, Limits, ListenerConfig, PolicyClientIds,
    Protocol, PublicConfig, SniGate, SourceClass, SourceClassifier, SystemClock, TcpServeParams,
    TcpStats, TlsStats, UdpServeParams, UdpStats, cache_max_age, read_frame, serve_doh, serve_doq,
    serve_dot, serve_tcp, serve_udp, write_frame,
};
use dnscraft_policy::{
    ClientId, ListenerId, NoClients, PolicyConfig, PolicyEngine, ProfileConfig, ProfileId,
    SafeSearchConfig, ViewConfig, ViewId, ViewRecordConfig,
};
use dnscraft_proto::{Class, Message, Name, RData, Rcode, Record, RecordType};
use dnscraft_resolver::dnssec::TrustAnchors;
use dnscraft_resolver::{Resolver, ResolverConfig};
use dnscraft_testkit::Hierarchy;
use dnscraft_tls::{CertResolver, ReservedLabels};
use http::{Method, Request, StatusCode, header};
use http_body_util::{BodyExt, Full};
use hyper_util::rt::{TokioExecutor, TokioIo};
use quinn::crypto::rustls::QuicClientConfig;
use quinn::{ClientConfig, Endpoint};
use rustls::ClientConfig as RustlsClientConfig;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::ring::default_provider;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, Error as RustlsError, SignatureScheme};
use support::certs::{example_dns_cert, example_dns_cert_b};
use support::{encode_a_query, encode_a_query_edns, poll_until};
use tokio::net::{TcpSocket, TcpStream, UdpSocket};
use tokio::sync::{oneshot, watch};
use tokio_rustls::TlsConnector;

const DOMAIN: &str = "example.com";
const PUBLIC_PEER: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 2);
const LOCAL_A: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 99);

fn install_ring() {
    let _ = default_provider().install_default();
}

#[derive(Debug, Default)]
struct EmptyBodies;

impl ListBodies for EmptyBodies {
    fn body(&self, _id: &ListId) -> Option<Arc<str>> {
        None
    }
}

fn filter_with_block() -> Arc<FilterEngine> {
    let mut sc = FilterSetConfig::new(SetId::new("default").unwrap(), "default");
    sc.custom_rules = "blocked.example.test\n".into();
    let cfg = FilterConfig {
        lists: Vec::new(),
        sets: vec![sc],
        ..FilterConfig::default()
    };
    Arc::new(FilterEngine::from_snapshot(
        SnapshotBuilder::new(Arc::new(EmptyBodies) as Arc<dyn ListBodies>)
            .build(&cfg)
            .unwrap(),
    ))
}

fn config_for(h: &Hierarchy) -> ResolverConfig {
    let overrides = h
        .nameserver_addrs()
        .iter()
        .map(|(n, a)| (Name::from_ascii(&n.to_string()).unwrap(), *a))
        .collect::<HashMap<_, _>>();
    ResolverConfig {
        root_hints: h.root_hints(),
        query_timeout: Duration::from_millis(500),
        nameserver_addr_overrides: overrides,
        trust_anchors: TrustAnchors::empty(),
        prefetch: false,
        ..ResolverConfig::default()
    }
}

async fn policy_engine(client_ids: &[&str]) -> (Hierarchy, Arc<PolicyEngine>) {
    let h = Hierarchy::start().await.unwrap();
    let resolver = Arc::new(Resolver::new(config_for(&h)).await.unwrap());
    let profile = ProfileConfig {
        id: ProfileId::new("default").unwrap(),
        filter_set: SetId::new("default").unwrap(),
        suppress_aaaa: false,
        firefox_canary: false,
        icloud_private_relay: false,
        rebind: Some(false),
        rebind_exceptions: Vec::new(),
        forward_zones: None,
        safesearch: SafeSearchConfig::default(),
        schedules: Vec::new(),
    };
    let view = ViewConfig {
        id: ViewId::new("default").unwrap(),
        is_default: true,
        subnets: Vec::new(),
        client_ids: client_ids
            .iter()
            .map(|id| ClientId::new(id).unwrap())
            .collect(),
        records: vec![ViewRecordConfig {
            name: Name::from_ascii("lan.example.test.").unwrap(),
            ttl: 60,
            rdata: RData::A(LOCAL_A),
        }],
        profile: ProfileId::new("default").unwrap(),
    };
    let cfg = PolicyConfig {
        views: vec![view],
        profiles: vec![profile],
        ..PolicyConfig::default()
    };
    let clock = Arc::new(ManualClock::new(
        SystemTime::UNIX_EPOCH + Duration::from_secs(1_000),
    ));
    let engine = Arc::new(
        PolicyEngine::new(
            cfg,
            filter_with_block(),
            resolver,
            Arc::new(NoClients),
            clock,
        )
        .unwrap(),
    );
    (h, engine)
}

fn classify_127_0_0_2_public() -> SourceClassifier {
    Arc::new(|ip: IpAddr| {
        let ip = ip.to_canonical();
        if ip == IpAddr::V4(PUBLIC_PEER) {
            SourceClass::Public
        } else {
            SourceClass::of(ip)
        }
    })
}

fn sni_gate(engine: Arc<PolicyEngine>) -> Arc<SniGate> {
    Arc::new(SniGate {
        public_domain: DOMAIN.into(),
        reserved: ReservedLabels::new(["node1".into()]),
        registry: Arc::new(PolicyClientIds(engine)),
    })
}

/// Compare DNS answers ignoring message id and OPT/padding additionals.
fn answers_equivalent(a: &Message, b: &Message) {
    assert_eq!(a.rcode(), b.rcode(), "rcode");
    assert_eq!(a.questions, b.questions, "questions");
    assert_eq!(a.answers, b.answers, "answers");
    assert_eq!(a.authorities, b.authorities, "authorities");
}

#[derive(Debug)]
struct AcceptAll {
    leaves: Option<Arc<Vec<Vec<u8>>>>,
    seen: Option<Arc<AtomicUsize>>,
}

impl AcceptAll {
    fn plain() -> Self {
        Self {
            leaves: None,
            seen: None,
        }
    }

    fn tracking(leaves: Arc<Vec<Vec<u8>>>, seen: Arc<AtomicUsize>) -> Self {
        Self {
            leaves: Some(leaves),
            seen: Some(seen),
        }
    }
}

impl ServerCertVerifier for AcceptAll {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        if let (Some(leaves), Some(seen)) = (&self.leaves, &self.seen) {
            let der = end_entity.as_ref();
            if let Some(idx) = leaves.iter().position(|l| l.as_slice() == der) {
                seen.store(idx + 1, Ordering::SeqCst);
            } else {
                seen.store(99, Ordering::SeqCst);
            }
        }
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

fn tls_connector(alpn: &[&[u8]], verifier: Arc<dyn ServerCertVerifier>) -> TlsConnector {
    let mut cfg = RustlsClientConfig::builder_with_provider(Arc::new(default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    cfg.alpn_protocols = alpn.iter().map(|a| a.to_vec()).collect();
    cfg.resumption = rustls::client::Resumption::disabled();
    TlsConnector::from(Arc::new(cfg))
}

fn doq_client_config(verifier: Arc<dyn ServerCertVerifier>) -> ClientConfig {
    let mut tls = RustlsClientConfig::builder_with_provider(Arc::new(default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    tls.alpn_protocols = vec![b"doq".to_vec()];
    tls.enable_early_data = false;
    tls.resumption = rustls::client::Resumption::disabled();
    ClientConfig::new(Arc::new(QuicClientConfig::try_from(tls).unwrap()))
}

async fn bind_tcp_from(src: Ipv4Addr, dest: SocketAddr) -> TcpStream {
    let socket = TcpSocket::new_v4().unwrap();
    socket.bind(SocketAddr::from((src, 0))).unwrap();
    socket.connect(dest).await.unwrap()
}

async fn udp_query(dest: SocketAddr, name: &str) -> Message {
    let client = UdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .await
        .unwrap();
    client
        .send_to(&encode_a_query(1, name), dest)
        .await
        .unwrap();
    let mut buf = [0u8; 4096];
    let (n, _) = tokio::time::timeout(Duration::from_secs(3), client.recv_from(&mut buf))
        .await
        .expect("udp")
        .unwrap();
    Message::decode(&buf[..n]).unwrap()
}

async fn tcp_query(dest: SocketAddr, name: &str) -> Message {
    let mut client = TcpStream::connect(dest).await.unwrap();
    write_frame(&mut client, &encode_a_query(1, name))
        .await
        .unwrap();
    let resp = tokio::time::timeout(Duration::from_secs(3), read_frame(&mut client))
        .await
        .expect("tcp")
        .unwrap();
    Message::decode(&resp).unwrap()
}

async fn dot_query(dest: SocketAddr, sni: &str, name: &str, from: Ipv4Addr) -> Message {
    let connector = tls_connector(&[ALPN_DOT], Arc::new(AcceptAll::plain()));
    let tcp = bind_tcp_from(from, dest).await;
    let mut tls = connector
        .connect(ServerName::try_from(sni.to_owned()).unwrap(), tcp)
        .await
        .unwrap();
    write_frame(&mut tls, &encode_a_query_edns(1, name, 1232))
        .await
        .unwrap();
    let resp = read_frame(&mut tls).await.unwrap();
    Message::decode(&resp).unwrap()
}

async fn doh_query(
    dest: SocketAddr,
    path: &str,
    name: &str,
    alpn: &[&[u8]],
    from: Ipv4Addr,
) -> (StatusCode, http::HeaderMap, Message) {
    let connector = tls_connector(alpn, Arc::new(AcceptAll::plain()));
    let tcp = bind_tcp_from(from, dest).await;
    let tls = connector
        .connect(ServerName::try_from("dns.example.com").unwrap(), tcp)
        .await
        .unwrap();
    let io = TokioIo::new(tls);
    let q = encode_a_query(1, name);
    let enc = URL_SAFE_NO_PAD.encode(&q);
    let req = Request::builder()
        .method(Method::GET)
        .uri(format!("https://dns.example.com{path}?dns={enc}"))
        .body(Full::new(Bytes::new()))
        .unwrap();

    let (status, headers, body) = if alpn.iter().any(|a| *a == b"h2") {
        let (mut sender, conn) = hyper::client::conn::http2::Builder::new(TokioExecutor::new())
            .handshake(io)
            .await
            .unwrap();
        tokio::spawn(conn);
        let resp = sender.send_request(req).await.unwrap();
        let status = resp.status();
        let headers = resp.headers().clone();
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        (status, headers, body)
    } else {
        let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await.unwrap();
        tokio::spawn(conn);
        let resp = sender.send_request(req).await.unwrap();
        let status = resp.status();
        let headers = resp.headers().clone();
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        (status, headers, body)
    };
    let msg = Message::decode(&body).unwrap_or_else(|_| {
        // Empty body on error statuses.
        Message::query(0, Name::from_ascii(".").unwrap(), RecordType::A)
    });
    (status, headers, msg)
}

async fn doq_query(dest: SocketAddr, sni: &str, name: &str, from: Ipv4Addr) -> Message {
    let mut endpoint = Endpoint::client(SocketAddr::from((from, 0))).unwrap();
    endpoint.set_default_client_config(doq_client_config(Arc::new(AcceptAll::plain())));
    let conn = endpoint
        .connect(dest, sni)
        .unwrap()
        .await
        .expect("doq connect");
    let (mut send, mut recv) = conn.open_bi().await.unwrap();
    write_frame(&mut send, &encode_a_query(0, name))
        .await
        .unwrap();
    send.finish().unwrap();
    let data = recv.read_to_end(65_535 + 2).await.unwrap();
    let len = u16::from_be_bytes([data[0], data[1]]) as usize;
    Message::decode(&data[2..2 + len]).unwrap()
}

struct EncryptedSet {
    admission: Arc<Mutex<Admission>>,
    #[allow(dead_code)]
    gate: Arc<SniGate>,
    #[allow(dead_code)]
    certs: Arc<CertResolver>,
    dot: SocketAddr,
    doh: SocketAddr,
    doq: SocketAddr,
    dot_stats: Arc<DotStats>,
    doh_stats: Arc<DohStats>,
    doq_stats: Arc<DoqStats>,
    tls_dot: Arc<TlsStats>,
    #[allow(dead_code)]
    tls_doh: Arc<TlsStats>,
    #[allow(dead_code)]
    tls_doq: Arc<TlsStats>,
    shutdowns: Vec<watch::Sender<bool>>,
    joins: Vec<tokio::task::JoinHandle<Result<(), dnscraft_listeners::ListenersError>>>,
}

impl EncryptedSet {
    async fn spawn(
        engine: Arc<PolicyEngine>,
        exposure: Exposure,
        public: PublicConfig,
        classify: SourceClassifier,
        certs: Arc<CertResolver>,
    ) -> Self {
        let limits = Limits::default();
        let admission = Arc::new(Mutex::new(Admission::with_classifier(
            &limits, &public, classify,
        )));
        let gate = sni_gate(Arc::clone(&engine));
        let mut shutdowns = Vec::new();
        let mut joins = Vec::new();

        let (dot_tx, dot_rx) = oneshot::channel();
        let (dot_sd_tx, dot_sd_rx) = watch::channel(false);
        let dot_stats = Arc::new(DotStats::default());
        let tls_dot = Arc::new(TlsStats::default());
        joins.push(tokio::spawn(serve_dot(DotServeParams {
            listener: ListenerConfig {
                id: ListenerId::new("c-dot").unwrap(),
                protocol: Protocol::Dot,
                address: SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
                exposure,
                h3: false,
            },
            limits: limits.clone(),
            admission: Arc::clone(&admission),
            handler: Arc::clone(&engine),
            clock: Arc::new(SystemClock),
            stats: Arc::clone(&dot_stats),
            tls_stats: Arc::clone(&tls_dot),
            certs: Arc::clone(&certs),
            sni_gate: Arc::clone(&gate),
            bound: dot_tx,
            shutdown: dot_sd_rx,
        })));
        shutdowns.push(dot_sd_tx);
        let dot = dot_rx.await.unwrap();

        let (doh_tx, doh_rx) = oneshot::channel();
        let (doh_sd_tx, doh_sd_rx) = watch::channel(false);
        let doh_stats = Arc::new(DohStats::default());
        let tls_doh = Arc::new(TlsStats::default());
        joins.push(tokio::spawn(serve_doh(DohServeParams {
            listener: ListenerConfig {
                id: ListenerId::new("c-doh").unwrap(),
                protocol: Protocol::Doh,
                address: SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
                exposure,
                h3: false,
            },
            limits: limits.clone(),
            admission: Arc::clone(&admission),
            handler: Arc::clone(&engine),
            clock: Arc::new(SystemClock),
            stats: Arc::clone(&doh_stats),
            tls_stats: Arc::clone(&tls_doh),
            certs: Arc::clone(&certs),
            sni_gate: Arc::clone(&gate),
            bound: doh_tx,
            shutdown: doh_sd_rx,
        })));
        shutdowns.push(doh_sd_tx);
        let doh = doh_rx.await.unwrap();

        let (doq_tx, doq_rx) = oneshot::channel();
        let (doq_sd_tx, doq_sd_rx) = watch::channel(false);
        let doq_stats = Arc::new(DoqStats::default());
        let tls_doq = Arc::new(TlsStats::default());
        joins.push(tokio::spawn(serve_doq(DoqServeParams {
            listener: ListenerConfig {
                id: ListenerId::new("c-doq").unwrap(),
                protocol: Protocol::Doq,
                address: SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
                exposure,
                h3: false,
            },
            limits,
            admission: Arc::clone(&admission),
            handler: engine,
            clock: Arc::new(SystemClock),
            stats: Arc::clone(&doq_stats),
            tls_stats: Arc::clone(&tls_doq),
            certs: Arc::clone(&certs),
            sni_gate: Arc::clone(&gate),
            bound: doq_tx,
            shutdown: doq_sd_rx,
        })));
        shutdowns.push(doq_sd_tx);
        let doq = doq_rx.await.unwrap();

        Self {
            admission,
            gate,
            certs,
            dot,
            doh,
            doq,
            dot_stats,
            doh_stats,
            doq_stats,
            tls_dot,
            tls_doh,
            tls_doq,
            shutdowns,
            joins,
        }
    }

    async fn stop(self) {
        for sd in &self.shutdowns {
            let _ = sd.send(true);
        }
        for j in self.joins {
            let _ = tokio::time::timeout(Duration::from_secs(2), j).await;
        }
    }
}

#[tokio::test]
async fn checkpoint_c_same_question_all_transports() {
    install_ring();
    let (_h, engine) = policy_engine(&["phone"]).await;
    let (pem, key, _) = example_dns_cert();
    let certs = Arc::new(CertResolver::new());
    certs.install(&pem, &key).unwrap();

    let admission = Arc::new(Mutex::new(Admission::new(
        &Limits::default(),
        &PublicConfig::default(),
    )));

    // Do53 UDP + TCP
    let (udp_tx, udp_rx) = oneshot::channel();
    let (udp_sd_tx, udp_sd_rx) = watch::channel(false);
    let udp_join = tokio::spawn(serve_udp(UdpServeParams {
        listener: ListenerConfig {
            id: ListenerId::new("c-udp").unwrap(),
            protocol: Protocol::Udp53,
            address: SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
            exposure: Exposure::Local,
            h3: false,
        },
        limits: Limits::default(),
        admission: Arc::clone(&admission),
        handler: Arc::clone(&engine),
        clock: Arc::new(SystemClock),
        stats: Arc::new(UdpStats::default()),
        bound: udp_tx,
        shutdown: udp_sd_rx,
    }));
    let udp = udp_rx.await.unwrap();

    let (tcp_tx, tcp_rx) = oneshot::channel();
    let (tcp_sd_tx, tcp_sd_rx) = watch::channel(false);
    let tcp_join = tokio::spawn(serve_tcp(TcpServeParams {
        listener: ListenerConfig {
            id: ListenerId::new("c-tcp").unwrap(),
            protocol: Protocol::Tcp53,
            address: SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
            exposure: Exposure::Local,
            h3: false,
        },
        limits: Limits::default(),
        admission: Arc::clone(&admission),
        handler: Arc::clone(&engine),
        clock: Arc::new(SystemClock),
        stats: Arc::new(TcpStats::default()),
        bound: tcp_tx,
        shutdown: tcp_sd_rx,
    }));
    let tcp = tcp_rx.await.unwrap();

    let set = EncryptedSet::spawn(
        Arc::clone(&engine),
        Exposure::Local,
        PublicConfig::default(),
        Arc::new(SourceClass::of),
        certs,
    )
    .await;

    let name = "lan.example.test.";
    let udp_msg = udp_query(udp, name).await;
    let tcp_msg = tcp_query(tcp, name).await;
    let dot_msg = dot_query(set.dot, "localhost", name, Ipv4Addr::LOCALHOST).await;
    let (s_h2, _, doh_h2) =
        doh_query(set.doh, "/dns-query", name, &[ALPN_H2], Ipv4Addr::LOCALHOST).await;
    let (s_h1, _, doh_h1) = doh_query(
        set.doh,
        "/dns-query",
        name,
        &[ALPN_HTTP_1_1],
        Ipv4Addr::LOCALHOST,
    )
    .await;
    let doq_msg = doq_query(set.doq, "localhost", name, Ipv4Addr::LOCALHOST).await;

    assert_eq!(s_h2, StatusCode::OK);
    assert_eq!(s_h1, StatusCode::OK);
    for (label, msg) in [
        ("udp", &udp_msg),
        ("tcp", &tcp_msg),
        ("dot", &dot_msg),
        ("doh-h2", &doh_h2),
        ("doh-h1", &doh_h1),
        ("doq", &doq_msg),
    ] {
        assert_eq!(msg.rcode(), Rcode::NOERROR, "{label}");
        assert!(
            msg.answers
                .iter()
                .any(|r| matches!(&r.rdata, RData::A(a) if *a == LOCAL_A)),
            "{label}: {:?}",
            msg.answers
        );
    }
    answers_equivalent(&udp_msg, &tcp_msg);
    answers_equivalent(&udp_msg, &dot_msg);
    answers_equivalent(&udp_msg, &doh_h2);
    answers_equivalent(&udp_msg, &doh_h1);
    answers_equivalent(&udp_msg, &doq_msg);

    let _ = udp_sd_tx.send(true);
    let _ = tcp_sd_tx.send(true);
    let _ = udp_join.await;
    let _ = tcp_join.await;
    set.stop().await;
}

#[tokio::test]
async fn checkpoint_c_public_admission_matrix_and_shared_ban() {
    install_ring();
    let (_h, engine) = policy_engine(&["phone"]).await;
    let (pem, key, _) = example_dns_cert();
    let certs = Arc::new(CertResolver::new());
    certs.install(&pem, &key).unwrap();

    let public = PublicConfig {
        ban_strikes: 2,
        ..PublicConfig::default()
    };
    let set = EncryptedSet::spawn(
        Arc::clone(&engine),
        Exposure::Public,
        public,
        classify_127_0_0_2_public(),
        certs,
    )
    .await;

    let name = "lan.example.test.";

    // Registered Client ID → answered on all three.
    let (s, _, m) = doh_query(set.doh, "/dns-query/phone", name, &[ALPN_H2], PUBLIC_PEER).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(m.rcode(), Rcode::NOERROR);
    let ok = dot_query(set.dot, "phone.dns.example.com", name, PUBLIC_PEER).await;
    assert_eq!(ok.rcode(), Rcode::NOERROR);
    let ok = doq_query(set.doq, "phone.dns.example.com", name, PUBLIC_PEER).await;
    assert_eq!(ok.rcode(), Rcode::NOERROR);

    // Missing Client ID / bare path → DoH 404 (no strike).
    let (s, _, _) = doh_query(set.doh, "/dns-query", name, &[ALPN_H2], PUBLIC_PEER).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    let connector = tls_connector(&[ALPN_DOT], Arc::new(AcceptAll::plain()));

    // Unknown id → strike (DoT).
    let tcp = bind_tcp_from(PUBLIC_PEER, set.dot).await;
    assert!(
        connector
            .connect(
                ServerName::try_from("unknown.dns.example.com").unwrap(),
                tcp
            )
            .await
            .is_err()
    );
    poll_until(
        || set.tls_dot.sni_reject_strike.load(Ordering::Relaxed) >= 1,
        Duration::from_secs(2),
    )
    .await;

    // Node → reject no strike.
    let before = set.tls_dot.sni_reject_no_strike.load(Ordering::Relaxed);
    let tcp = bind_tcp_from(PUBLIC_PEER, set.dot).await;
    assert!(
        connector
            .connect(ServerName::try_from("node1.dns.example.com").unwrap(), tcp)
            .await
            .is_err()
    );
    poll_until(
        || set.tls_dot.sni_reject_no_strike.load(Ordering::Relaxed) > before,
        Duration::from_secs(2),
    )
    .await;

    // Apex → reject no strike.
    let before = set.tls_dot.sni_reject_no_strike.load(Ordering::Relaxed);
    let tcp = bind_tcp_from(PUBLIC_PEER, set.dot).await;
    assert!(
        connector
            .connect(ServerName::try_from("dns.example.com").unwrap(), tcp)
            .await
            .is_err()
    );
    poll_until(
        || set.tls_dot.sni_reject_no_strike.load(Ordering::Relaxed) > before,
        Duration::from_secs(2),
    )
    .await;

    // Second unknown strike → ban (DoH path).
    let (s, _, _) = doh_query(set.doh, "/dns-query/unknown", name, &[ALPN_H2], PUBLIC_PEER).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    poll_until(
        || {
            set.admission
                .lock()
                .unwrap()
                .is_banned(IpAddr::V4(PUBLIC_PEER), SystemTime::now())
        },
        Duration::from_secs(2),
    )
    .await;

    // Ban on shared admission blocks DoT/DoH/DoQ before handshake.
    let before_dot = set.dot_stats.dropped_admission.load(Ordering::Relaxed);
    let before_doh = set.doh_stats.dropped_banned.load(Ordering::Relaxed);
    let before_doq = set.doq_stats.dropped_banned.load(Ordering::Relaxed);

    let tcp = bind_tcp_from(PUBLIC_PEER, set.dot).await;
    let _ = connector
        .connect(ServerName::try_from("phone.dns.example.com").unwrap(), tcp)
        .await;
    poll_until(
        || set.dot_stats.dropped_admission.load(Ordering::Relaxed) > before_dot,
        Duration::from_secs(2),
    )
    .await;

    // TCP accept drop → TLS connect fails / resets (no HTTP exchange).
    let tcp = bind_tcp_from(PUBLIC_PEER, set.doh).await;
    let connector_h2 = tls_connector(&[ALPN_H2], Arc::new(AcceptAll::plain()));
    let _ = connector_h2
        .connect(ServerName::try_from("dns.example.com").unwrap(), tcp)
        .await;
    poll_until(
        || set.doh_stats.dropped_banned.load(Ordering::Relaxed) > before_doh,
        Duration::from_secs(2),
    )
    .await;

    let mut ep = Endpoint::client(SocketAddr::from((PUBLIC_PEER, 0))).unwrap();
    ep.set_default_client_config(doq_client_config(Arc::new(AcceptAll::plain())));
    let _ = ep.connect(set.doq, "phone.dns.example.com").unwrap().await;
    poll_until(
        || set.doq_stats.dropped_banned.load(Ordering::Relaxed) > before_doq,
        Duration::from_secs(2),
    )
    .await;

    // Private source on a public listener without id is answered.
    let priv_ok = dot_query(set.dot, "localhost", name, Ipv4Addr::LOCALHOST).await;
    assert_eq!(priv_ok.rcode(), Rcode::NOERROR);
    let (s, _, m) = doh_query(set.doh, "/dns-query", name, &[ALPN_H2], Ipv4Addr::LOCALHOST).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(m.rcode(), Rcode::NOERROR);

    set.stop().await;
}

#[tokio::test]
async fn checkpoint_c_cert_hot_reload_dot_doh_doq() {
    install_ring();
    let (_h, engine) = policy_engine(&["phone"]).await;
    let (pem_a, key_a, der_a) = example_dns_cert();
    let (pem_b, key_b, der_b) = example_dns_cert_b();
    assert_ne!(der_a, der_b);
    let certs = Arc::new(CertResolver::new());
    certs.install(&pem_a, &key_a).unwrap();

    let set = EncryptedSet::spawn(
        engine,
        Exposure::Local,
        PublicConfig::default(),
        Arc::new(SourceClass::of),
        Arc::clone(&certs),
    )
    .await;

    let leaves = Arc::new(vec![der_a, der_b]);
    let seen = Arc::new(AtomicUsize::new(0));
    let verifier = Arc::new(AcceptAll::tracking(Arc::clone(&leaves), Arc::clone(&seen)));

    // Open DoT connection on cert A; keep it alive across reload.
    let connector = tls_connector(
        &[ALPN_DOT],
        Arc::clone(&verifier) as Arc<dyn ServerCertVerifier>,
    );
    let tcp = TcpStream::connect(set.dot).await.unwrap();
    let mut open = connector
        .connect(ServerName::try_from("localhost").unwrap(), tcp)
        .await
        .unwrap();
    assert_eq!(seen.load(Ordering::SeqCst), 1);
    write_frame(
        &mut open,
        &encode_a_query_edns(1, "lan.example.test.", 1232),
    )
    .await
    .unwrap();
    let _ = read_frame(&mut open).await.unwrap();

    certs.install(&pem_b, &key_b).unwrap();
    seen.store(0, Ordering::SeqCst);

    // New DoT handshake sees B.
    let tcp = TcpStream::connect(set.dot).await.unwrap();
    let mut fresh = connector
        .connect(ServerName::try_from("localhost").unwrap(), tcp)
        .await
        .unwrap();
    assert_eq!(seen.load(Ordering::SeqCst), 2);
    write_frame(
        &mut fresh,
        &encode_a_query_edns(2, "lan.example.test.", 1232),
    )
    .await
    .unwrap();
    assert_eq!(
        Message::decode(&read_frame(&mut fresh).await.unwrap())
            .unwrap()
            .rcode(),
        Rcode::NOERROR
    );

    // Open connection still works on A.
    write_frame(
        &mut open,
        &encode_a_query_edns(3, "lan.example.test.", 1232),
    )
    .await
    .unwrap();
    assert_eq!(
        Message::decode(&read_frame(&mut open).await.unwrap())
            .unwrap()
            .rcode(),
        Rcode::NOERROR
    );

    // DoH new handshake sees B.
    seen.store(0, Ordering::SeqCst);
    let connector_h2 = tls_connector(
        &[ALPN_H2],
        Arc::clone(&verifier) as Arc<dyn ServerCertVerifier>,
    );
    let tcp = TcpStream::connect(set.doh).await.unwrap();
    let _ = connector_h2
        .connect(ServerName::try_from("dns.example.com").unwrap(), tcp)
        .await
        .unwrap();
    assert_eq!(seen.load(Ordering::SeqCst), 2);

    // DoQ new handshake sees B.
    seen.store(0, Ordering::SeqCst);
    let mut ep = Endpoint::client(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
    ep.set_default_client_config(doq_client_config(
        Arc::clone(&verifier) as Arc<dyn ServerCertVerifier>
    ));
    let _ = ep.connect(set.doq, "localhost").unwrap().await.unwrap();
    assert_eq!(seen.load(Ordering::SeqCst), 2);

    set.stop().await;
}

#[tokio::test]
async fn checkpoint_c_cache_control_absent_for_errors() {
    install_ring();
    let (_h, engine) = policy_engine(&["phone"]).await;
    let (pem, key, _) = example_dns_cert();
    let certs = Arc::new(CertResolver::new());
    certs.install(&pem, &key).unwrap();

    let set = EncryptedSet::spawn(
        engine,
        Exposure::Local,
        PublicConfig::default(),
        Arc::new(SourceClass::of),
        certs,
    )
    .await;

    // Policy REFUSED (blocked) → HTTP 200 DNS body, no Cache-Control.
    let (s, headers, msg) = doh_query(
        set.doh,
        "/dns-query",
        "blocked.example.test.",
        &[ALPN_H2],
        Ipv4Addr::LOCALHOST,
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(msg.rcode(), Rcode::REFUSED);
    assert!(
        !headers.contains_key(header::CACHE_CONTROL),
        "REFUSED must not carry Cache-Control: {headers:?}"
    );
    assert!(cache_max_age(&msg.encode().unwrap()).is_none());

    // SERVFAIL wire (synthetic) → helper returns None.
    let q = Message::query(1, Name::from_ascii("example.com.").unwrap(), RecordType::A);
    let mut resp = Message::response_to(&q);
    resp.set_rcode(Rcode::SERVFAIL).unwrap();
    resp.answers.push(Record::new(
        Name::from_ascii("example.com.").unwrap(),
        Class::IN,
        60,
        RData::A(Ipv4Addr::new(192, 0, 2, 1)),
    ));
    assert!(cache_max_age(&resp.encode().unwrap()).is_none());

    set.stop().await;
}
