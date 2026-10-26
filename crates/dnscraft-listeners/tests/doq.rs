//! N9: DNS over QUIC listener tests.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod support;

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, SystemTime};

use dnscraft_listeners::{
    Clock, DOQ_NO_ERROR, DOQ_PROTOCOL_ERROR, DoqServeParams, DoqStats, Exposure, FakeHandler,
    Limits, ListenerConfig, ManualClock, PAD_BLOCK, PolicyClientIds, Protocol, PublicConfig,
    SniGate, SystemClock, TcpServeParams, TcpStats, TlsStats, read_frame, serve_doq, serve_tcp,
    write_frame,
};
use dnscraft_policy::ListenerId;
use dnscraft_proto::{Message, Rcode};
use dnscraft_tls::{CertResolver, ReservedLabels};
use quinn::crypto::rustls::QuicClientConfig;
use quinn::{ClientConfig, Connection, Endpoint, RecvStream, TransportConfig};
use rustls::ClientConfig as RustlsClientConfig;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::ring::default_provider;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, Error as RustlsError, SignatureScheme};
use support::certs::example_dns_cert;
use support::{
    encode_a_query, encode_a_query_edns, fake_a_answer, policy_engine_with_client_ids, poll_until,
};
use tokio::net::TcpStream;
use tokio::sync::{oneshot, watch};

const DOMAIN: &str = "example.com";

fn install_ring() {
    let _ = default_provider().install_default();
}

fn listener_doq(addr: SocketAddr, exposure: Exposure) -> ListenerConfig {
    ListenerConfig {
        id: ListenerId::new("test-doq").unwrap(),
        protocol: Protocol::Doq,
        address: addr,
        exposure,
        h3: false,
    }
}

fn listener_tcp(addr: SocketAddr) -> ListenerConfig {
    ListenerConfig {
        id: ListenerId::new("test-tcp").unwrap(),
        protocol: Protocol::Tcp53,
        address: addr,
        exposure: Exposure::Local,
        h3: false,
    }
}

#[derive(Debug)]
struct AcceptAll;

impl ServerCertVerifier for AcceptAll {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, RustlsError> {
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

fn doq_client_config() -> ClientConfig {
    doq_client_config_with_keepalive(None)
}

fn doq_client_config_with_keepalive(keep_alive: Option<Duration>) -> ClientConfig {
    let mut tls = RustlsClientConfig::builder_with_provider(Arc::new(default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAll))
        .with_no_client_auth();
    tls.alpn_protocols = vec![b"doq".to_vec()];
    tls.enable_early_data = false;
    tls.resumption = rustls::client::Resumption::disabled();
    let quic = QuicClientConfig::try_from(tls).unwrap();
    let mut cfg = ClientConfig::new(Arc::new(quic));
    if let Some(interval) = keep_alive {
        let mut transport = TransportConfig::default();
        transport.keep_alive_interval(Some(interval));
        // Transport idle longer than application idle under test.
        transport.max_idle_timeout(Some(
            Duration::from_secs(60).try_into().expect("idle timeout"),
        ));
        cfg.transport_config(Arc::new(transport));
    }
    cfg
}

async fn connect_doq(addr: SocketAddr, sni: &str) -> Connection {
    connect_doq_with(addr, sni, doq_client_config()).await
}

async fn connect_doq_with(addr: SocketAddr, sni: &str, client: ClientConfig) -> Connection {
    let mut endpoint = Endpoint::client(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
    endpoint.set_default_client_config(client);
    endpoint
        .connect(addr, sni)
        .unwrap()
        .await
        .expect("DoQ connect")
}

async fn query_on_stream(conn: &Connection, wire: &[u8]) -> Vec<u8> {
    let (mut send, mut recv) = conn.open_bi().await.unwrap();
    write_frame(&mut send, wire).await.unwrap();
    send.finish().unwrap();
    read_doq_response(&mut recv).await
}

async fn read_doq_response(recv: &mut RecvStream) -> Vec<u8> {
    let data = recv.read_to_end(65_535 + 2).await.unwrap();
    assert!(data.len() >= 2, "empty DoQ response");
    let len = u16::from_be_bytes([data[0], data[1]]) as usize;
    assert_eq!(data.len(), 2 + len, "trailing bytes on DoQ response");
    data[2..].to_vec()
}

struct DoqHarness {
    addr: SocketAddr,
    stats: Arc<DoqStats>,
    tls_stats: Arc<TlsStats>,
    shutdown: watch::Sender<bool>,
    join: tokio::task::JoinHandle<Result<(), dnscraft_listeners::ListenersError>>,
}

impl DoqHarness {
    async fn spawn(
        exposure: Exposure,
        limits: Limits,
        gate: SniGate,
        certs: Arc<CertResolver>,
        answer: Ipv4Addr,
    ) -> Self {
        Self::spawn_with(
            exposure,
            limits,
            gate,
            certs,
            Arc::new(FakeHandler::new(fake_a_answer(answer))),
            Arc::new(SystemClock),
        )
        .await
    }

    async fn spawn_with<H: dnscraft_listeners::QueryHandler + 'static>(
        exposure: Exposure,
        limits: Limits,
        gate: SniGate,
        certs: Arc<CertResolver>,
        handler: Arc<H>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        let stats = Arc::new(DoqStats::default());
        let tls_stats = Arc::new(TlsStats::default());
        let (bound_tx, bound_rx) = oneshot::channel();
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let public = PublicConfig {
            ban_strikes: 2,
            ..PublicConfig::default()
        };
        let admission = if exposure == Exposure::Public {
            support::public_test_admission(&limits, &public)
        } else {
            support::admission_for(&limits, &public)
        };
        let join = tokio::spawn(serve_doq(DoqServeParams {
            listener: listener_doq(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)), exposure),
            limits,
            admission,
            handler,
            clock,
            stats: Arc::clone(&stats),
            tls_stats: Arc::clone(&tls_stats),
            certs,
            sni_gate: Arc::new(gate),
            event_sink: None,
            bound: bound_tx,
            shutdown: shutdown_rx,
        }));
        let addr = tokio::time::timeout(Duration::from_secs(2), bound_rx)
            .await
            .unwrap()
            .unwrap();
        Self {
            addr,
            stats,
            tls_stats,
            shutdown: shutdown_tx,
            join,
        }
    }

    async fn stop(self) {
        let _ = self.shutdown.send(true);
        let _ = tokio::time::timeout(Duration::from_secs(2), self.join).await;
    }
}

#[tokio::test]
async fn doq_matches_do53_except_padding_and_id() {
    install_ring();
    let engine = policy_engine_with_client_ids(&["phone"]).await;
    let gate = SniGate {
        public_domain: DOMAIN.into(),
        reserved: Arc::new(std::sync::RwLock::new(ReservedLabels::new(
            ["node1".into()],
        ))),
        registry: Arc::new(PolicyClientIds(engine)),
    };
    let (pem, key, _) = example_dns_cert();
    let certs = Arc::new(CertResolver::new());
    certs.install(&pem, &key).unwrap();
    let answer_ip = Ipv4Addr::new(192, 0, 2, 9);
    let handler = Arc::new(FakeHandler::new(fake_a_answer(answer_ip)));

    let tcp_stats = Arc::new(TcpStats::default());
    let (tcp_bound_tx, tcp_bound_rx) = oneshot::channel();
    let (tcp_shutdown_tx, tcp_shutdown_rx) = watch::channel(false);
    let tcp_join = tokio::spawn(serve_tcp(TcpServeParams {
        listener: listener_tcp(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))),
        limits: Limits::default(),
        admission: support::fresh_admission(),
        handler: Arc::clone(&handler),
        clock: Arc::new(SystemClock),
        stats: Arc::clone(&tcp_stats),
        ddr: None,
        event_sink: None,
        bound: tcp_bound_tx,
        shutdown: tcp_shutdown_rx,
    }));
    let tcp_addr = tokio::time::timeout(Duration::from_secs(2), tcp_bound_rx)
        .await
        .unwrap()
        .unwrap();

    // Client query id is non-zero on Do53; DoQ requires id 0 on the wire.
    let q_tcp = encode_a_query_edns(7, "example.com.", 1232);
    let mut tcp_client = TcpStream::connect(tcp_addr).await.unwrap();
    write_frame(&mut tcp_client, &q_tcp).await.unwrap();
    let tcp_resp = read_frame(&mut tcp_client).await.unwrap();
    let _ = tcp_shutdown_tx.send(true);
    let _ = tcp_join.await;

    let doq = DoqHarness::spawn(Exposure::Local, Limits::default(), gate, certs, answer_ip).await;
    let conn = connect_doq(doq.addr, "phone.dns.example.com").await;
    let q_doq = encode_a_query_edns(0, "example.com.", 1232);
    let doq_resp = query_on_stream(&conn, &q_doq).await;
    doq.stop().await;

    let tcp_msg = Message::decode(&tcp_resp).unwrap();
    let doq_msg = Message::decode(&doq_resp).unwrap();
    assert_eq!(tcp_msg.rcode(), Rcode::NOERROR);
    assert_eq!(doq_msg.rcode(), Rcode::NOERROR);
    assert_eq!(tcp_msg.header.id, 7);
    assert_eq!(doq_msg.header.id, 0);
    assert_eq!(tcp_msg.answers.len(), doq_msg.answers.len());
    assert_eq!(tcp_msg.answers[0].rdata, doq_msg.answers[0].rdata);
    assert_eq!(doq_resp.len() % PAD_BLOCK, 0);
    assert!(doq_resp.len() > tcp_resp.len());
}

#[tokio::test]
async fn concurrent_streams_on_one_connection() {
    install_ring();
    let engine = policy_engine_with_client_ids(&["phone"]).await;
    let gate = SniGate {
        public_domain: DOMAIN.into(),
        reserved: Arc::new(std::sync::RwLock::new(ReservedLabels::new(
            ["node1".into()],
        ))),
        registry: Arc::new(PolicyClientIds(engine)),
    };
    let (pem, key, _) = example_dns_cert();
    let certs = Arc::new(CertResolver::new());
    certs.install(&pem, &key).unwrap();
    let doq = DoqHarness::spawn(
        Exposure::Local,
        Limits::default(),
        gate,
        certs,
        Ipv4Addr::new(192, 0, 2, 11),
    )
    .await;

    let conn = connect_doq(doq.addr, "localhost").await;
    let q = encode_a_query(0, "example.com.");
    let mut handles = Vec::new();
    for _ in 0..4 {
        let c = conn.clone();
        let wire = q.clone();
        handles.push(tokio::spawn(
            async move { query_on_stream(&c, &wire).await },
        ));
    }
    for h in handles {
        let resp = h.await.unwrap();
        assert_eq!(Message::decode(&resp).unwrap().rcode(), Rcode::NOERROR);
        assert_eq!(Message::decode(&resp).unwrap().header.id, 0);
    }
    poll_until(
        || doq.stats.answered.load(Ordering::Relaxed) >= 4,
        Duration::from_secs(2),
    )
    .await;
    doq.stop().await;
}

#[tokio::test]
async fn nonzero_id_closes_with_protocol_error() {
    install_ring();
    let engine = policy_engine_with_client_ids(&["phone"]).await;
    let gate = SniGate {
        public_domain: DOMAIN.into(),
        reserved: Arc::new(std::sync::RwLock::new(ReservedLabels::new(
            ["node1".into()],
        ))),
        registry: Arc::new(PolicyClientIds(engine)),
    };
    let (pem, key, _) = example_dns_cert();
    let certs = Arc::new(CertResolver::new());
    certs.install(&pem, &key).unwrap();
    let doq = DoqHarness::spawn(
        Exposure::Local,
        Limits::default(),
        gate,
        certs,
        Ipv4Addr::new(192, 0, 2, 9),
    )
    .await;

    let conn = connect_doq(doq.addr, "localhost").await;
    let bad = encode_a_query(42, "example.com.");
    let (mut send, mut recv) = conn.open_bi().await.unwrap();
    write_frame(&mut send, &bad).await.unwrap();
    send.finish().unwrap();
    let read_err = recv.read_to_end(64).await;
    assert!(read_err.is_err(), "server must abort after non-zero id");

    poll_until(
        || doq.stats.protocol_errors.load(Ordering::Relaxed) >= 1,
        Duration::from_secs(2),
    )
    .await;

    // Connection should be application-closed with DOQ_PROTOCOL_ERROR.
    let closed = tokio::time::timeout(Duration::from_secs(2), conn.closed())
        .await
        .expect("wait closed");
    match closed {
        quinn::ConnectionError::ApplicationClosed(ac) => {
            assert_eq!(ac.error_code, DOQ_PROTOCOL_ERROR);
        }
        other => panic!("expected ApplicationClosed, got {other:?}"),
    }
    doq.stop().await;
}

#[tokio::test]
async fn stream_cap_blocks_extra_stream() {
    install_ring();
    let engine = policy_engine_with_client_ids(&["phone"]).await;
    let gate = SniGate {
        public_domain: DOMAIN.into(),
        reserved: Arc::new(std::sync::RwLock::new(ReservedLabels::new(
            ["node1".into()],
        ))),
        registry: Arc::new(PolicyClientIds(engine)),
    };
    let (pem, key, _) = example_dns_cert();
    let certs = Arc::new(CertResolver::new());
    certs.install(&pem, &key).unwrap();
    let limits = Limits {
        max_quic_streams_per_connection: 2,
        ..Limits::default()
    };
    let doq = DoqHarness::spawn(
        Exposure::Local,
        limits,
        gate,
        certs,
        Ipv4Addr::new(192, 0, 2, 9),
    )
    .await;

    let conn = connect_doq(doq.addr, "localhost").await;
    // Open two streams and leave them unfinished so credits stay consumed.
    let (_s1, _r1) = conn.open_bi().await.unwrap();
    let (_s2, _r2) = conn.open_bi().await.unwrap();
    let third = tokio::time::timeout(Duration::from_millis(400), conn.open_bi()).await;
    assert!(
        third.is_err(),
        "third concurrent stream must wait on stream credit"
    );
    doq.stop().await;
}

#[tokio::test]
async fn idle_timeout_closes_connection() {
    install_ring();
    let engine = policy_engine_with_client_ids(&["phone"]).await;
    let gate = SniGate {
        public_domain: DOMAIN.into(),
        reserved: Arc::new(std::sync::RwLock::new(ReservedLabels::new(
            ["node1".into()],
        ))),
        registry: Arc::new(PolicyClientIds(engine)),
    };
    let (pem, key, _) = example_dns_cert();
    let certs = Arc::new(CertResolver::new());
    certs.install(&pem, &key).unwrap();
    let limits = Limits {
        tcp_idle_timeout: Duration::from_millis(300),
        ..Limits::default()
    };
    let doq = DoqHarness::spawn(
        Exposure::Local,
        limits,
        gate,
        certs,
        Ipv4Addr::new(192, 0, 2, 9),
    )
    .await;

    let conn = connect_doq(doq.addr, "localhost").await;
    let closed = tokio::time::timeout(Duration::from_secs(3), conn.closed())
        .await
        .expect("idle close");
    assert!(
        matches!(
            closed,
            quinn::ConnectionError::TimedOut
                | quinn::ConnectionError::ApplicationClosed(_)
                | quinn::ConnectionError::LocallyClosed
        ),
        "got {closed:?}"
    );
    poll_until(
        || doq.stats.idle_timeouts.load(Ordering::Relaxed) >= 1,
        Duration::from_secs(2),
    )
    .await;
    doq.stop().await;
}

#[tokio::test]
async fn app_idle_closes_despite_quic_keepalive() {
    install_ring();
    let engine = policy_engine_with_client_ids(&["phone"]).await;
    let gate = SniGate {
        public_domain: DOMAIN.into(),
        reserved: Arc::new(std::sync::RwLock::new(ReservedLabels::new(
            ["node1".into()],
        ))),
        registry: Arc::new(PolicyClientIds(engine)),
    };
    let (pem, key, _) = example_dns_cert();
    let certs = Arc::new(CertResolver::new());
    certs.install(&pem, &key).unwrap();

    let idle = Duration::from_secs(2);
    let clock = Arc::new(ManualClock::new(
        SystemTime::UNIX_EPOCH + Duration::from_secs(40_000),
    ));
    let limits = Limits {
        tcp_idle_timeout: idle,
        ..Limits::default()
    };
    let doq = DoqHarness::spawn_with(
        Exposure::Local,
        limits,
        gate,
        certs,
        Arc::new(FakeHandler::new(fake_a_answer(Ipv4Addr::new(192, 0, 2, 9)))),
        Arc::clone(&clock) as Arc<dyn Clock>,
    )
    .await;

    let conn = connect_doq_with(
        doq.addr,
        "localhost",
        doq_client_config_with_keepalive(Some(Duration::from_millis(100))),
    )
    .await;
    // No streams — only QUIC keep-alives.
    tokio::time::sleep(Duration::from_millis(50)).await;
    clock.advance(idle + Duration::from_millis(100));
    let closed = tokio::time::timeout(Duration::from_secs(2), conn.closed())
        .await
        .expect("app idle must close despite keep-alive");
    match closed {
        quinn::ConnectionError::ApplicationClosed(c) => {
            assert_eq!(c.error_code, DOQ_NO_ERROR);
        }
        other => panic!("expected ApplicationClosed(DOQ_NO_ERROR), got {other:?}"),
    }
    poll_until(
        || doq.stats.idle_timeouts.load(Ordering::Relaxed) >= 1,
        Duration::from_secs(2),
    )
    .await;
    doq.stop().await;
}

#[tokio::test]
async fn app_idle_closes_incomplete_streams_with_keepalive_releases_slot() {
    install_ring();
    let engine = policy_engine_with_client_ids(&["phone"]).await;
    let gate = SniGate {
        public_domain: DOMAIN.into(),
        reserved: Arc::new(std::sync::RwLock::new(ReservedLabels::new(
            ["node1".into()],
        ))),
        registry: Arc::new(PolicyClientIds(engine)),
    };
    let (pem, key, _) = example_dns_cert();
    let certs = Arc::new(CertResolver::new());
    certs.install(&pem, &key).unwrap();

    let idle = Duration::from_secs(2);
    let clock = Arc::new(ManualClock::new(
        SystemTime::UNIX_EPOCH + Duration::from_secs(50_000),
    ));
    let limits = Limits {
        tcp_idle_timeout: idle,
        max_quic_streams_per_connection: 2,
        max_connections_per_source: 1,
        query_timeout: Duration::from_secs(60),
        ..Limits::default()
    };
    let doq = DoqHarness::spawn_with(
        Exposure::Local,
        limits,
        gate,
        certs,
        Arc::new(FakeHandler::new(fake_a_answer(Ipv4Addr::new(192, 0, 2, 9)))),
        Arc::clone(&clock) as Arc<dyn Clock>,
    )
    .await;

    let client = doq_client_config_with_keepalive(Some(Duration::from_millis(100)));
    let conn = connect_doq_with(doq.addr, "localhost", client.clone()).await;
    // Cap filled with incomplete streams; client keeps handles (ignores STOP_SENDING).
    let (_s1, _r1) = conn.open_bi().await.unwrap();
    let (_s2, _r2) = conn.open_bi().await.unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;

    clock.advance(idle + Duration::from_millis(100));
    let closed = tokio::time::timeout(Duration::from_secs(2), conn.closed())
        .await
        .expect("app idle must close with incomplete streams + keep-alive");
    assert!(
        matches!(
            closed,
            quinn::ConnectionError::ApplicationClosed(ref c) if c.error_code == DOQ_NO_ERROR
        ),
        "got {closed:?}"
    );
    poll_until(
        || doq.stats.idle_timeouts.load(Ordering::Relaxed) >= 1,
        Duration::from_secs(2),
    )
    .await;
    poll_until(
        || doq.stats.closed.load(Ordering::Relaxed) >= 1,
        Duration::from_secs(2),
    )
    .await;

    // Per-source slot released — another connection from the same source is admitted.
    let again = tokio::time::timeout(
        Duration::from_secs(2),
        connect_doq_with(doq.addr, "localhost", client),
    )
    .await
    .expect("slot released after idle close");
    drop(again);
    doq.stop().await;
}

#[tokio::test]
async fn public_sni_matrix() {
    install_ring();
    let engine = policy_engine_with_client_ids(&["phone"]).await;
    let gate = SniGate {
        public_domain: DOMAIN.into(),
        reserved: Arc::new(std::sync::RwLock::new(ReservedLabels::new(
            ["node1".into()],
        ))),
        registry: Arc::new(PolicyClientIds(engine)),
    };
    let (pem, key, _) = example_dns_cert();
    let certs = Arc::new(CertResolver::new());
    certs.install(&pem, &key).unwrap();
    let doq = DoqHarness::spawn(
        Exposure::Public,
        Limits::default(),
        gate,
        certs,
        Ipv4Addr::new(192, 0, 2, 9),
    )
    .await;

    // Registered Client ID → answer.
    let conn = connect_doq(doq.addr, "phone.dns.example.com").await;
    let q = encode_a_query(0, "example.com.");
    let ok = query_on_stream(&conn, &q).await;
    assert_eq!(Message::decode(&ok).unwrap().rcode(), Rcode::NOERROR);
    drop(conn);

    // Unknown id → post-handshake SNI reject + strike (QUIC handshake itself may
    // complete; the server then closes before serving streams).
    let mut endpoint = Endpoint::client(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
    endpoint.set_default_client_config(doq_client_config());
    let bad_conn = endpoint
        .connect(doq.addr, "unknown.dns.example.com")
        .unwrap()
        .await
        .expect("QUIC handshake completes before SNI gate");
    poll_until(
        || doq.tls_stats.sni_reject_strike.load(Ordering::Relaxed) >= 1,
        Duration::from_secs(2),
    )
    .await;
    assert!(
        bad_conn.open_bi().await.is_err(),
        "unknown SNI connection must not serve streams"
    );
    drop(bad_conn);

    // Node hostname → reject without strike.
    let node_conn = endpoint
        .connect(doq.addr, "node1.dns.example.com")
        .unwrap()
        .await
        .expect("QUIC handshake completes before SNI gate");
    poll_until(
        || doq.tls_stats.sni_reject_no_strike.load(Ordering::Relaxed) >= 1,
        Duration::from_secs(2),
    )
    .await;
    assert!(node_conn.open_bi().await.is_err());
    drop(node_conn);

    doq.stop().await;
}

#[tokio::test]
async fn stream_query_timeout_frees_cap_for_third() {
    install_ring();
    let engine = policy_engine_with_client_ids(&["phone"]).await;
    let gate = SniGate {
        public_domain: DOMAIN.into(),
        reserved: Arc::new(std::sync::RwLock::new(ReservedLabels::new(
            ["node1".into()],
        ))),
        registry: Arc::new(PolicyClientIds(engine)),
    };
    let (pem, key, _) = example_dns_cert();
    let certs = Arc::new(CertResolver::new());
    certs.install(&pem, &key).unwrap();

    let clock = Arc::new(ManualClock::new(
        SystemTime::UNIX_EPOCH + Duration::from_secs(30_000),
    ));
    let limits = Limits {
        max_quic_streams_per_connection: 2,
        query_timeout: Duration::from_secs(2),
        tcp_idle_timeout: Duration::from_secs(60),
        ..Limits::default()
    };
    let doq = DoqHarness::spawn_with(
        Exposure::Local,
        limits,
        gate,
        certs,
        Arc::new(FakeHandler::new(fake_a_answer(Ipv4Addr::new(192, 0, 2, 9)))),
        Arc::clone(&clock) as Arc<dyn Clock>,
    )
    .await;

    let conn = connect_doq(doq.addr, "localhost").await;
    // Two streams without FIN: consume the stream cap until the per-stream deadline.
    let (mut s1, r1) = conn.open_bi().await.unwrap();
    let (mut s2, r2) = conn.open_bi().await.unwrap();
    // Prefix of a length-framed query, no FIN — read_to_end stays pending.
    s1.write_all(&[0, 12]).await.unwrap();
    s2.write_all(&[0, 12]).await.unwrap();

    // Let the server accept both streams and enter read_to_end + wait_until.
    tokio::time::sleep(Duration::from_millis(100)).await;

    clock.advance(Duration::from_secs(3));
    // Drop client handles so QUIC stream credits return after server stop/reset.
    drop(s1);
    drop(s2);
    drop(r1);
    drop(r2);

    let q = encode_a_query(0, "example.com.");
    let third = tokio::time::timeout(Duration::from_secs(2), async {
        query_on_stream(&conn, &q).await
    })
    .await
    .expect("third query should open after stalled streams timed out");
    assert_eq!(Message::decode(&third).unwrap().rcode(), Rcode::NOERROR);

    doq.stop().await;
}
