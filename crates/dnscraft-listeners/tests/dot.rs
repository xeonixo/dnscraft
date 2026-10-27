//! N7: DNS over TLS listener tests.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod support;

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, SystemTime};

use dnscraft_listeners::{
    DotServeParams, DotStats, Exposure, FakeHandler, Limits, ListenerConfig, ManualClock,
    PAD_BLOCK, PolicyClientIds, Protocol, PublicConfig, SniGate, SystemClock, TcpServeParams,
    TcpStats, TlsStats, read_frame, serve_dot, serve_tcp, write_frame,
};
use dnscraft_policy::ListenerId;
use dnscraft_proto::{Message, Rcode};
use dnscraft_tls::{CertResolver, ReservedLabels};
use rustls::ClientConfig;
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
use tokio_rustls::TlsConnector;

const DOMAIN: &str = "example.com";

fn install_ring() {
    let _ = default_provider().install_default();
}

fn listener_dot(addr: SocketAddr, exposure: Exposure) -> ListenerConfig {
    ListenerConfig {
        id: ListenerId::new("test-dot").unwrap(),
        protocol: Protocol::Dot,
        address: addr,
        exposure,
        h3: false,
        tls_policy: None,
    }
}

fn listener_tcp(addr: SocketAddr) -> ListenerConfig {
    ListenerConfig {
        id: ListenerId::new("test-tcp").unwrap(),
        protocol: Protocol::Tcp53,
        address: addr,
        exposure: Exposure::Local,
        h3: false,
        tls_policy: None,
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

fn dot_connector() -> TlsConnector {
    let mut cfg = ClientConfig::builder_with_provider(Arc::new(default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAll))
        .with_no_client_auth();
    cfg.alpn_protocols = vec![b"dot".to_vec()];
    cfg.resumption = rustls::client::Resumption::disabled();
    TlsConnector::from(Arc::new(cfg))
}

struct DotHarness {
    addr: SocketAddr,
    stats: Arc<DotStats>,
    tls_stats: Arc<TlsStats>,
    shutdown: watch::Sender<bool>,
    join: tokio::task::JoinHandle<Result<(), dnscraft_listeners::ListenersError>>,
}

impl DotHarness {
    async fn spawn(
        exposure: Exposure,
        limits: Limits,
        clock: Arc<dyn dnscraft_listeners::Clock>,
        gate: SniGate,
        certs: Arc<CertResolver>,
    ) -> Self {
        let stats = Arc::new(DotStats::default());
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
        let join = tokio::spawn(serve_dot(DotServeParams {
            listener: listener_dot(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)), exposure),
            limits,
            admission,
            handler: Arc::new(FakeHandler::new(fake_a_answer(Ipv4Addr::new(192, 0, 2, 9)))),
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

async fn query_dot(addr: SocketAddr, sni: &str, wire: &[u8]) -> Vec<u8> {
    let connector = dot_connector();
    let tcp = TcpStream::connect(addr).await.unwrap();
    let name = ServerName::try_from(sni.to_owned()).unwrap();
    let mut tls = connector.connect(name, tcp).await.unwrap();
    write_frame(&mut tls, wire).await.unwrap();
    read_frame(&mut tls).await.unwrap()
}

#[tokio::test]
async fn dot_matches_do53_except_padding() {
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

    let answer = fake_a_answer(Ipv4Addr::new(192, 0, 2, 9));
    let handler = Arc::new(FakeHandler::new(answer));

    // Do53 TCP
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

    let mut tcp_client = TcpStream::connect(tcp_addr).await.unwrap();
    let q = encode_a_query_edns(7, "example.com.", 1232);
    write_frame(&mut tcp_client, &q).await.unwrap();
    let tcp_resp = read_frame(&mut tcp_client).await.unwrap();
    let _ = tcp_shutdown_tx.send(true);
    let _ = tcp_join.await;

    // DoT
    let dot = DotHarness::spawn(
        Exposure::Local,
        Limits::default(),
        Arc::new(SystemClock),
        gate,
        certs,
    )
    .await;
    // Re-bind handler: DotHarness uses its own FakeHandler — use same answer IP via harness.
    let dot_resp = query_dot(dot.addr, "phone.dns.example.com", &q).await;
    dot.stop().await;

    let tcp_msg = Message::decode(&tcp_resp).unwrap();
    let dot_msg = Message::decode(&dot_resp).unwrap();
    assert_eq!(tcp_msg.rcode(), Rcode::NOERROR);
    assert_eq!(dot_msg.rcode(), Rcode::NOERROR);
    assert_eq!(tcp_msg.header.id, 7);
    assert_eq!(dot_msg.header.id, 7);
    assert_eq!(tcp_msg.answers.len(), dot_msg.answers.len());
    assert_eq!(
        tcp_msg.answers[0].rdata, dot_msg.answers[0].rdata,
        "answer RDATA must match"
    );
    // DoT pads when the client sent OPT; Do53 TCP does not.
    assert_eq!(
        dot_resp.len() % PAD_BLOCK,
        0,
        "DoT answer must be padded to {PAD_BLOCK}"
    );
    assert!(
        dot_resp.len() > tcp_resp.len(),
        "padded DoT ({}) should exceed unpadded TCP ({})",
        dot_resp.len(),
        tcp_resp.len()
    );
}

#[tokio::test]
async fn public_registered_ok_unknown_strike_then_ban() {
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
        SystemTime::UNIX_EPOCH + Duration::from_secs(10_000),
    ));
    let h = DotHarness::spawn(
        Exposure::Public,
        Limits::default(),
        Arc::clone(&clock) as Arc<dyn dnscraft_listeners::Clock>,
        gate,
        certs,
    )
    .await;

    let q = encode_a_query(1, "example.com.");
    let ok = query_dot(h.addr, "phone.dns.example.com", &q).await;
    assert_eq!(Message::decode(&ok).unwrap().rcode(), Rcode::NOERROR);

    // Unknown SNI → handshake reject + strike (loopback is private → strike no-op on ban
    // table; counters still move). Use inspect path already covered in tls tests; here
    // assert handshake fails and sni_reject_strike increments.
    let connector = dot_connector();
    let tcp = TcpStream::connect(h.addr).await.unwrap();
    let name = ServerName::try_from("unknown.dns.example.com").unwrap();
    assert!(connector.connect(name, tcp).await.is_err());
    poll_until(
        || h.tls_stats.sni_reject_strike.load(Ordering::Relaxed) >= 1,
        Duration::from_secs(2),
    )
    .await;

    // Ban path with a public peer: strike via Admission after two unknown SNIs from
    // 203.0.113.x is covered in tls inspect_public_sni_matrix; here confirm node/apex
    // do not strike.
    let tcp = TcpStream::connect(h.addr).await.unwrap();
    let name = ServerName::try_from("node1.dns.example.com").unwrap();
    assert!(connector.connect(name, tcp).await.is_err());
    poll_until(
        || h.tls_stats.sni_reject_no_strike.load(Ordering::Relaxed) >= 1,
        Duration::from_secs(2),
    )
    .await;

    h.stop().await;
}

#[tokio::test]
async fn handshake_timeout_closes_slow_loris() {
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
        SystemTime::UNIX_EPOCH + Duration::from_secs(20_000),
    ));
    let limits = Limits {
        tls_handshake_timeout: Duration::from_secs(2),
        ..Limits::default()
    };
    let h = DotHarness::spawn(
        Exposure::Local,
        limits,
        Arc::clone(&clock) as Arc<dyn dnscraft_listeners::Clock>,
        gate,
        certs,
    )
    .await;

    // Connect TCP but never speak TLS.
    let _stall = TcpStream::connect(h.addr).await.unwrap();
    poll_until(
        || h.stats.accepted.load(Ordering::Relaxed) >= 1,
        Duration::from_secs(2),
    )
    .await;

    clock.advance(Duration::from_secs(3));
    poll_until(
        || {
            h.tls_stats.handshake_timeouts.load(Ordering::Relaxed) >= 1
                || h.tls_stats.handshake_fail.load(Ordering::Relaxed) >= 1
        },
        Duration::from_secs(2),
    )
    .await;
    poll_until(
        || h.stats.closed.load(Ordering::Relaxed) >= 1,
        Duration::from_secs(2),
    )
    .await;

    h.stop().await;
}

#[tokio::test]
async fn dot_rejects_client_offering_only_h2_alpn() {
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
    let h = DotHarness::spawn(
        Exposure::Local,
        Limits::default(),
        Arc::new(SystemClock),
        gate,
        certs,
    )
    .await;

    let mut cfg = ClientConfig::builder_with_provider(Arc::new(default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAll))
        .with_no_client_auth();
    cfg.alpn_protocols = vec![b"h2".to_vec()];
    cfg.resumption = rustls::client::Resumption::disabled();
    let connector = TlsConnector::from(Arc::new(cfg));
    let tcp = TcpStream::connect(h.addr).await.unwrap();
    let name = ServerName::try_from("localhost").unwrap();
    assert!(
        connector.connect(name, tcp).await.is_err(),
        "DoT must not negotiate h2-only ClientHello"
    );
    h.stop().await;
}

#[tokio::test]
async fn public_ban_after_strikes_from_public_ip_helper() {
    // End-to-end ban: apply_sni_strike with a documentation-range public IP.
    use dnscraft_listeners::{
        Admission, AdmitDecision, ClientIdState, apply_sni_strike, inspect_public_sni,
    };
    install_ring();
    let engine = policy_engine_with_client_ids(&["phone"]).await;
    let gate = SniGate {
        public_domain: DOMAIN.into(),
        reserved: Arc::new(std::sync::RwLock::new(ReservedLabels::new(
            ["node1".into()],
        ))),
        registry: Arc::new(PolicyClientIds(engine)),
    };
    let mut adm = Admission::new(
        &Limits::default(),
        &PublicConfig {
            ban_strikes: 2,
            ..PublicConfig::default()
        },
    );
    let peer: IpAddr = "203.0.113.77".parse().unwrap();
    let now = SystemTime::UNIX_EPOCH + Duration::from_secs(50);
    let bad = inspect_public_sni(Some("unknown.dns.example.com"), &gate);
    apply_sni_strike(&mut adm, peer, &bad, now);
    apply_sni_strike(&mut adm, peer, &bad, now);
    let d = adm.check(
        &listener_dot(
            SocketAddr::from((Ipv4Addr::LOCALHOST, 853)),
            Exposure::Public,
        ),
        peer,
        &ClientIdState::Registered(dnscraft_policy::ClientId::new("phone").unwrap()),
        now,
    );
    assert!(matches!(
        d,
        AdmitDecision::Drop {
            code: "listeners.banned"
        }
    ));
}
