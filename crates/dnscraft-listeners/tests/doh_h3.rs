//! DoH over HTTP/3 (N12): GET/POST parity, Alt-Svc, stream caps.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod support;

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use bytes::{Buf, Bytes};
use dnscraft_listeners::{
    ALT_SVC_MAX_AGE, DNS_MESSAGE_TYPE, DohH3ServeParams, DohServeParams, DohStats, Exposure,
    FakeHandler, Limits, ListenerConfig, MAX_DOH_HEADER_LIST_SIZE, PAD_BLOCK, PolicyClientIds,
    Protocol, PublicConfig, QueryHandler, SniGate, SystemClock, TcpServeParams, TcpStats, TlsStats,
    read_frame, serve_doh, serve_doh_h3, serve_tcp, write_frame,
};
use dnscraft_policy::{ListenerId, PolicyAnswer, RequestContext};
use dnscraft_proto::{Message, Rcode};
use dnscraft_tls::{CertResolver, ReservedLabels};
use http::{Method, Request, StatusCode, header};
use quinn::crypto::rustls::QuicClientConfig;
use quinn::{ClientConfig, Endpoint};
use rustls::ClientConfig as RustlsClientConfig;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::ring::default_provider;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, Error as TlsError, SignatureScheme};
use support::certs::example_dns_cert;
use support::{encode_a_query_edns, fake_a_answer, policy_engine_with_client_ids};
use tokio::net::TcpStream;
use tokio::sync::{Notify, oneshot, watch};

const DOMAIN: &str = "example.com";

fn install_ring() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

fn listener_doh(addr: SocketAddr, exposure: Exposure, h3: bool) -> ListenerConfig {
    ListenerConfig {
        node_id: None,
        nodes: Vec::new(),
        id: ListenerId::new("test-doh").unwrap(),
        protocol: Protocol::Doh,
        address: addr,
        exposure,
        h3,
        tls_policy: None,
    }
}

struct DohH3Harness {
    tcp_addr: SocketAddr,
    udp_addr: SocketAddr,
    shutdown: watch::Sender<bool>,
    joins: Vec<tokio::task::JoinHandle<Result<(), dnscraft_listeners::ListenersError>>>,
}

impl DohH3Harness {
    async fn spawn_with<H: QueryHandler + 'static>(
        exposure: Exposure,
        limits: Limits,
        gate: SniGate,
        certs: Arc<CertResolver>,
        handler: Arc<H>,
        h3: bool,
    ) -> Self {
        let stats = Arc::new(DohStats::default());
        let tls_stats = Arc::new(TlsStats::default());
        let alt_svc_port = Arc::new(AtomicU16::new(0));
        let (tcp_tx, tcp_rx) = oneshot::channel();
        let (udp_tx, udp_rx) = oneshot::channel();
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let public = PublicConfig {
            ban_strikes: 5,
            ..PublicConfig::default()
        };
        let admission = if exposure == Exposure::Public {
            support::public_test_admission(&limits, &public)
        } else {
            support::admission_for(&limits, &public)
        };
        let gate = Arc::new(gate);

        let mut joins = Vec::new();
        joins.push(tokio::spawn(serve_doh(DohServeParams {
            listener: listener_doh(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)), exposure, h3),
            limits: limits.clone(),
            admission: Arc::clone(&admission),
            handler: Arc::clone(&handler),
            clock: Arc::new(SystemClock),
            stats: Arc::clone(&stats),
            tls_stats: Arc::clone(&tls_stats),
            certs: Arc::clone(&certs),
            sni_gate: Arc::clone(&gate),
            event_sink: None,
            alt_svc_port: Arc::clone(&alt_svc_port),
            bound: tcp_tx,
            shutdown: shutdown_rx.clone(),
        })));

        let udp_addr = if h3 {
            joins.push(tokio::spawn(serve_doh_h3(DohH3ServeParams {
                listener: listener_doh(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)), exposure, true),
                limits,
                admission,
                handler,
                clock: Arc::new(SystemClock),
                stats: Arc::clone(&stats),
                tls_stats,
                certs,
                sni_gate: gate,
                event_sink: None,
                alt_svc_port: Arc::clone(&alt_svc_port),
                bound: udp_tx,
                shutdown: shutdown_rx,
            })));
            tokio::time::timeout(Duration::from_secs(2), udp_rx)
                .await
                .unwrap()
                .unwrap()
        } else {
            drop(udp_tx);
            SocketAddr::from((Ipv4Addr::LOCALHOST, 0))
        };

        let tcp_addr = tokio::time::timeout(Duration::from_secs(2), tcp_rx)
            .await
            .unwrap()
            .unwrap();
        if h3 {
            assert_ne!(alt_svc_port.load(Ordering::Relaxed), 0);
        }

        let _ = stats;
        Self {
            tcp_addr,
            udp_addr,
            shutdown: shutdown_tx,
            joins,
        }
    }

    async fn stop(self) {
        let _ = self.shutdown.send(true);
        for j in self.joins {
            let _ = tokio::time::timeout(Duration::from_secs(2), j).await;
        }
    }
}

async fn doh_exchange_h3(
    addr: SocketAddr,
    method: Method,
    path_and_query: &str,
    body: Bytes,
    content_type: Option<&str>,
) -> (StatusCode, http::HeaderMap, Bytes) {
    let mut client_tls = RustlsClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(TrustAny))
        .with_no_client_auth();
    client_tls.alpn_protocols = vec![b"h3".to_vec()];

    let mut client = Endpoint::client(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
    client.set_default_client_config(ClientConfig::new(Arc::new(
        QuicClientConfig::try_from(client_tls).unwrap(),
    )));

    let conn = client
        .connect(addr, "dns.example.com")
        .unwrap()
        .await
        .unwrap();
    let quinn_conn = h3_quinn::Connection::new(conn);
    let (mut driver, mut send_request) = h3::client::new(quinn_conn).await.unwrap();
    let drive = tokio::spawn(async move { std::future::poll_fn(|cx| driver.poll_close(cx)).await });

    let uri = format!("https://dns.example.com{path_and_query}");
    let mut b = Request::builder().method(method).uri(uri);
    if let Some(ct) = content_type {
        b = b.header(header::CONTENT_TYPE, ct);
    }
    let req = b.body(()).unwrap();
    let mut stream = send_request.send_request(req).await.unwrap();
    if !body.is_empty() {
        stream.send_data(body).await.unwrap();
    }
    stream.finish().await.unwrap();
    let resp = stream.recv_response().await.unwrap();
    let status = resp.status();
    let headers = resp.headers().clone();
    let mut out = Vec::new();
    while let Some(mut chunk) = stream.recv_data().await.unwrap() {
        out.extend_from_slice(chunk.chunk());
        chunk.advance(chunk.remaining());
    }
    drop(send_request);
    drop(stream);
    let _ = drive.await;
    (status, headers, Bytes::from(out))
}

async fn doh_exchange_h2(
    addr: SocketAddr,
    req: Request<http_body_util::Full<Bytes>>,
) -> (StatusCode, http::HeaderMap, Bytes) {
    use http_body_util::BodyExt;
    use hyper_util::rt::{TokioExecutor, TokioIo};
    use rustls_pki_types::ServerName as PkiName;
    use tokio_rustls::TlsConnector;

    let mut cfg = RustlsClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(TrustAny))
        .with_no_client_auth();
    cfg.alpn_protocols = vec![b"h2".to_vec()];
    let connector = TlsConnector::from(Arc::new(cfg));
    let tcp = TcpStream::connect(addr).await.unwrap();
    let name = PkiName::try_from("dns.example.com").unwrap();
    let tls = connector.connect(name, tcp).await.unwrap();
    let io = TokioIo::new(tls);
    let (mut sender, conn) = hyper::client::conn::http2::Builder::new(TokioExecutor::new())
        .handshake(io)
        .await
        .unwrap();
    tokio::spawn(async move {
        let _ = conn.await;
    });
    let resp = sender.send_request(req).await.unwrap();
    let status = resp.status();
    let headers = resp.headers().clone();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    (status, headers, body)
}

#[derive(Debug)]
struct TrustAny;

impl ServerCertVerifier for TrustAny {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[tokio::test]
async fn h3_get_post_match_do53() {
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

    let mut answer = fake_a_answer(Ipv4Addr::new(192, 0, 2, 44));
    if let Some(rr) = answer.message.answers.first_mut() {
        rr.ttl = 60;
    }
    let handler = Arc::new(FakeHandler::new(answer));

    let tcp_stats = Arc::new(TcpStats::default());
    let (tcp_tx, tcp_rx) = oneshot::channel();
    let (tcp_sd_tx, tcp_sd_rx) = watch::channel(false);
    let tcp_join = tokio::spawn(serve_tcp(TcpServeParams {
        listener: ListenerConfig {
            node_id: None,
            nodes: Vec::new(),
            id: ListenerId::new("tcp-base").unwrap(),
            protocol: Protocol::Tcp53,
            address: SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
            exposure: Exposure::Local,
            h3: false,
            tls_policy: None,
        },
        limits: Limits::default(),
        admission: support::fresh_admission(),
        handler: Arc::clone(&handler),
        clock: Arc::new(SystemClock),
        stats: tcp_stats,
        ddr: None,
        event_sink: None,
        bound: tcp_tx,
        shutdown: tcp_sd_rx,
    }));
    let tcp_addr = tokio::time::timeout(Duration::from_secs(2), tcp_rx)
        .await
        .unwrap()
        .unwrap();
    let q = encode_a_query_edns(99, "example.com.", 1232);
    let mut tcp_c = TcpStream::connect(tcp_addr).await.unwrap();
    write_frame(&mut tcp_c, &q).await.unwrap();
    let tcp_resp = read_frame(&mut tcp_c).await.unwrap();
    let _ = tcp_sd_tx.send(true);
    let _ = tcp_join.await;
    let tcp_rdata = Message::decode(&tcp_resp).unwrap().answers[0].rdata.clone();

    let h = DohH3Harness::spawn_with(
        Exposure::Local,
        Limits::default(),
        gate,
        certs,
        handler,
        true,
    )
    .await;
    let enc = URL_SAFE_NO_PAD.encode(&q);

    let check = |label: &str, status: StatusCode, headers: &http::HeaderMap, body: &Bytes| {
        assert_eq!(status, StatusCode::OK, "{label}");
        assert_eq!(
            headers.get(header::CONTENT_TYPE).unwrap(),
            DNS_MESSAGE_TYPE,
            "{label}"
        );
        assert!(
            headers.get(header::ALT_SVC).is_none(),
            "{label}: h3 response must not carry Alt-Svc"
        );
        let msg = Message::decode(body).unwrap();
        assert_eq!(msg.header.id, 0, "{label}");
        assert_eq!(msg.rcode(), Rcode::NOERROR, "{label}");
        assert_eq!(msg.answers[0].rdata, tcp_rdata, "{label}");
        assert_eq!(body.len() % PAD_BLOCK, 0, "{label}");
    };

    let (s, hdr, body) = doh_exchange_h3(
        h.udp_addr,
        Method::GET,
        &format!("/dns-query?dns={enc}"),
        Bytes::new(),
        None,
    )
    .await;
    check("h3-get", s, &hdr, &body);

    let (s, hdr, body) = doh_exchange_h3(
        h.udp_addr,
        Method::POST,
        "/dns-query",
        Bytes::from(q),
        Some(DNS_MESSAGE_TYPE),
    )
    .await;
    check("h3-post", s, &hdr, &body);

    h.stop().await;
}

#[tokio::test]
async fn alt_svc_only_when_h3_enabled() {
    install_ring();
    let engine = policy_engine_with_client_ids(&["phone"]).await;
    let gate = SniGate {
        public_domain: DOMAIN.into(),
        reserved: Arc::new(std::sync::RwLock::new(ReservedLabels::new(
            ["node1".into()],
        ))),
        registry: Arc::new(PolicyClientIds(Arc::clone(&engine))),
    };
    let (pem, key, _) = example_dns_cert();
    let certs = Arc::new(CertResolver::new());
    certs.install(&pem, &key).unwrap();
    let answer = fake_a_answer(Ipv4Addr::new(192, 0, 2, 44));
    let handler = Arc::new(FakeHandler::new(answer));
    let q = encode_a_query_edns(1, "example.com.", 1232);
    let enc = URL_SAFE_NO_PAD.encode(&q);
    let req = Request::builder()
        .method(Method::GET)
        .uri(format!("https://dns.example.com/dns-query?dns={enc}"))
        .body(http_body_util::Full::new(Bytes::new()))
        .unwrap();

    let gate_h3 = SniGate {
        public_domain: DOMAIN.into(),
        reserved: Arc::new(std::sync::RwLock::new(ReservedLabels::new(
            ["node1".into()],
        ))),
        registry: Arc::new(PolicyClientIds(Arc::clone(&engine))),
    };
    let with_h3 = DohH3Harness::spawn_with(
        Exposure::Local,
        Limits::default(),
        gate_h3,
        Arc::clone(&certs),
        Arc::clone(&handler),
        true,
    )
    .await;
    let (_s, hdr, _b) = doh_exchange_h2(with_h3.tcp_addr, req.clone()).await;
    let alt = hdr
        .get(header::ALT_SVC)
        .expect("Alt-Svc when h3=true")
        .to_str()
        .unwrap();
    assert!(
        alt.contains(&format!("h3=\":{}\"", with_h3.udp_addr.port())),
        "alt={alt}"
    );
    assert!(alt.contains(&format!("ma={ALT_SVC_MAX_AGE}")), "alt={alt}");
    with_h3.stop().await;

    let without = DohH3Harness::spawn_with(
        Exposure::Local,
        Limits::default(),
        gate,
        certs,
        handler,
        false,
    )
    .await;
    let (_s, hdr, _b) = doh_exchange_h2(without.tcp_addr, req).await;
    assert!(hdr.get(header::ALT_SVC).is_none());
    without.stop().await;
}

struct HangHandler {
    entered: Arc<Notify>,
    release: Arc<Notify>,
    answer: PolicyAnswer,
}

impl QueryHandler for HangHandler {
    async fn handle(
        &self,
        _ctx: RequestContext,
    ) -> Result<PolicyAnswer, dnscraft_policy::PolicyError> {
        self.entered.notify_one();
        self.release.notified().await;
        Ok(self.answer.clone())
    }
}

#[tokio::test]
async fn h3_stream_cap_like_doq() {
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

    let entered = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let handler = Arc::new(HangHandler {
        entered: Arc::clone(&entered),
        release: Arc::clone(&release),
        answer: fake_a_answer(Ipv4Addr::new(192, 0, 2, 7)),
    });
    let limits = Limits {
        max_quic_streams_per_connection: 2,
        ..Limits::default()
    };

    let h = DohH3Harness::spawn_with(Exposure::Local, limits, gate, certs, handler, true).await;
    let q = encode_a_query_edns(1, "example.com.", 1232);
    let enc = URL_SAFE_NO_PAD.encode(&q);
    let path = format!("/dns-query?dns={enc}");

    // Open one h3 connection and start two hanging requests (fill stream cap).
    let mut client_tls = RustlsClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(TrustAny))
        .with_no_client_auth();
    client_tls.alpn_protocols = vec![b"h3".to_vec()];
    let mut client = Endpoint::client(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
    client.set_default_client_config(ClientConfig::new(Arc::new(
        QuicClientConfig::try_from(client_tls).unwrap(),
    )));
    let conn = client
        .connect(h.udp_addr, "dns.example.com")
        .unwrap()
        .await
        .unwrap();
    let quinn_conn = h3_quinn::Connection::new(conn.clone());
    let (mut driver, mut send_request) = h3::client::new(quinn_conn).await.unwrap();
    let drive = tokio::spawn(async move { std::future::poll_fn(|cx| driver.poll_close(cx)).await });

    let mut streams = Vec::new();
    for _ in 0..2 {
        let req = Request::builder()
            .method(Method::GET)
            .uri(format!("https://dns.example.com{path}"))
            .body(())
            .unwrap();
        let mut stream = send_request.send_request(req).await.unwrap();
        stream.finish().await.unwrap();
        streams.push(stream);
        tokio::time::timeout(Duration::from_secs(2), entered.notified())
            .await
            .expect("handler entered");
    }

    // Third request: server should close for excessive load (stream cap).
    let req = Request::builder()
        .method(Method::GET)
        .uri(format!("https://dns.example.com{path}"))
        .body(())
        .unwrap();
    let third = send_request.send_request(req).await;
    // Either send fails or connection closes while waiting.
    let closed = match third {
        Err(_) => true,
        Ok(mut stream) => {
            let _ = stream.finish().await;
            tokio::time::timeout(Duration::from_millis(500), stream.recv_response())
                .await
                .is_err()
                || conn.close_reason().is_some()
        }
    };
    assert!(
        closed || conn.close_reason().is_some(),
        "stream cap must trip"
    );

    release.notify_waiters();
    drop(streams);
    drop(send_request);
    let _ = drive.await;
    h.stop().await;
}

/// QUIC client endpoint whose transport sends PING keep-alives every 100 ms so
/// the connection never idles out at the transport layer. Only the server's
/// application idle / request deadline can close it.
fn h3_endpoint_with_keepalive() -> quinn::Endpoint {
    let mut client_tls = RustlsClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(TrustAny))
        .with_no_client_auth();
    client_tls.alpn_protocols = vec![b"h3".to_vec()];
    let mut client = Endpoint::client(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
    let mut transport = quinn::TransportConfig::default();
    transport.keep_alive_interval(Some(Duration::from_millis(100)));
    let mut cfg = ClientConfig::new(Arc::new(QuicClientConfig::try_from(client_tls).unwrap()));
    cfg.transport_config(Arc::new(transport));
    client.set_default_client_config(cfg);
    client
}

async fn h3_stall_harness(limits: Limits) -> DohH3Harness {
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
    let handler = Arc::new(FakeHandler::new(fake_a_answer(Ipv4Addr::new(
        192, 0, 2, 44,
    ))));
    DohH3Harness::spawn_with(Exposure::Local, limits, gate, certs, handler, true).await
}

#[tokio::test]
async fn h3_stalled_request_closes_connection() {
    install_ring();
    let limits = Limits {
        tcp_idle_timeout: Duration::from_millis(500),
        ..Limits::default()
    };
    let h = h3_stall_harness(limits).await;

    let client = h3_endpoint_with_keepalive();
    let conn = client
        .connect(h.udp_addr, "dns.example.com")
        .unwrap()
        .await
        .unwrap();
    let quinn_conn = h3_quinn::Connection::new(conn.clone());
    let (mut driver, mut send_request) = h3::client::new(quinn_conn).await.unwrap();
    tokio::spawn(async move { std::future::poll_fn(|cx| driver.poll_close(cx)).await });

    // HEADERS only: never send a body and never finish the request stream.
    let req = Request::builder()
        .method(Method::POST)
        .uri("https://dns.example.com/dns-query")
        .header(header::CONTENT_TYPE, DNS_MESSAGE_TYPE)
        .body(())
        .unwrap();
    let _stream = send_request.send_request(req).await.unwrap();

    // The server's per-request deadline must close the connection despite the
    // client PING keep-alive and the in-flight (stalled) request.
    let closed = tokio::time::timeout(Duration::from_secs(3), conn.closed()).await;
    assert!(
        closed.is_ok(),
        "stalled request must not hold the connection open"
    );

    drop(send_request);
    h.stop().await;
}

#[tokio::test]
async fn h3_concurrent_request_completes_while_stalled() {
    install_ring();
    let limits = Limits {
        tcp_idle_timeout: Duration::from_millis(500),
        ..Limits::default()
    };
    let h = h3_stall_harness(limits).await;
    let q = encode_a_query_edns(2, "example.com.", 1232);
    let enc = URL_SAFE_NO_PAD.encode(&q);

    let client = h3_endpoint_with_keepalive();
    let conn = client
        .connect(h.udp_addr, "dns.example.com")
        .unwrap()
        .await
        .unwrap();
    let quinn_conn = h3_quinn::Connection::new(conn.clone());
    let (mut driver, mut send_request) = h3::client::new(quinn_conn).await.unwrap();
    tokio::spawn(async move { std::future::poll_fn(|cx| driver.poll_close(cx)).await });

    // Stall one stream with HEADERS only.
    let stalled = Request::builder()
        .method(Method::POST)
        .uri("https://dns.example.com/dns-query")
        .header(header::CONTENT_TYPE, DNS_MESSAGE_TYPE)
        .body(())
        .unwrap();
    let _stalled_stream = send_request.send_request(stalled).await.unwrap();

    // A well-behaved GET on a second stream still completes.
    let get = Request::builder()
        .method(Method::GET)
        .uri(format!("https://dns.example.com/dns-query?dns={enc}"))
        .body(())
        .unwrap();
    let mut stream = send_request.send_request(get).await.unwrap();
    stream.finish().await.unwrap();
    let resp = stream.recv_response().await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let mut out = Vec::new();
    while let Some(mut chunk) = stream.recv_data().await.unwrap() {
        out.extend_from_slice(chunk.chunk());
        chunk.advance(chunk.remaining());
    }
    assert!(!out.is_empty(), "concurrent request must yield an answer");

    drop(send_request);
    h.stop().await;
}

#[tokio::test]
async fn h3_slow_progress_killed_at_total_deadline() {
    install_ring();
    // The request read budget (headers + body) is a single tcp_idle_timeout
    // window, not a per-chunk idle timer: progress below the budget is allowed,
    // but a request that never finishes is killed once the total budget elapses.
    let limits = Limits {
        tcp_idle_timeout: Duration::from_millis(500),
        ..Limits::default()
    };
    let h = h3_stall_harness(limits).await;

    let client = h3_endpoint_with_keepalive();
    let conn = client
        .connect(h.udp_addr, "dns.example.com")
        .unwrap()
        .await
        .unwrap();
    let quinn_conn = h3_quinn::Connection::new(conn.clone());
    let (mut driver, mut send_request) = h3::client::new(quinn_conn).await.unwrap();
    tokio::spawn(async move { std::future::poll_fn(|cx| driver.poll_close(cx)).await });

    let req = Request::builder()
        .method(Method::POST)
        .uri("https://dns.example.com/dns-query")
        .header(header::CONTENT_TYPE, DNS_MESSAGE_TYPE)
        .body(())
        .unwrap();
    let mut stream = send_request.send_request(req).await.unwrap();
    // Trickle one byte every 150 ms (< 500 ms deadline) and never finish.
    for _ in 0..3 {
        stream.send_data(Bytes::from_static(&[0u8])).await.unwrap();
        tokio::time::sleep(Duration::from_millis(150)).await;
    }

    // Total time has passed the budget; the request must be killed.
    let closed = tokio::time::timeout(Duration::from_secs(3), conn.closed()).await;
    assert!(
        closed.is_ok(),
        "slow request beyond the total deadline must be killed"
    );

    drop(send_request);
    h.stop().await;
}

#[tokio::test]
async fn h3_oversized_headers_rejected_server_stays_healthy() {
    install_ring();
    let h = h3_stall_harness(Limits::default()).await;

    let client = h3_endpoint_with_keepalive();
    let conn = client
        .connect(h.udp_addr, "dns.example.com")
        .unwrap()
        .await
        .unwrap();
    let quinn_conn = h3_quinn::Connection::new(conn.clone());
    let (mut driver, mut send_request) = h3::client::new(quinn_conn).await.unwrap();
    tokio::spawn(async move { std::future::poll_fn(|cx| driver.poll_close(cx)).await });

    // A field section just over the shared 16 KiB bound (one past the limit).
    let big = "x".repeat(MAX_DOH_HEADER_LIST_SIZE as usize + 1);
    let req = Request::builder()
        .method(Method::GET)
        .uri("https://dns.example.com/dns-query")
        .header("x-pad", big)
        .body(())
        .unwrap();
    let mut stream = send_request.send_request(req).await.unwrap();
    stream.finish().await.unwrap();

    // The server must reject the oversized header section: 431 or a stream reset
    // is fine, but never 200 OK.
    let rejected = match stream.recv_response().await {
        Ok(resp) => resp.status() == StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE,
        Err(_) => true,
    };
    assert!(rejected, "oversized headers must be rejected");

    drop(stream);
    drop(send_request);

    // The listener stays healthy: a normal query still succeeds.
    let q = encode_a_query_edns(3, "example.com.", 1232);
    let enc = URL_SAFE_NO_PAD.encode(&q);
    let (status, _hdr, body) = doh_exchange_h3(
        h.udp_addr,
        Method::GET,
        &format!("/dns-query?dns={enc}"),
        Bytes::new(),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "listener must stay healthy");
    assert!(!body.is_empty(), "healthy request must yield an answer");

    h.stop().await;
}

#[tokio::test]
async fn h2_oversized_headers_rejected_at_shared_bound() {
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
    let handler = Arc::new(FakeHandler::new(fake_a_answer(Ipv4Addr::new(
        192, 0, 2, 45,
    ))));

    let h = DohH3Harness::spawn_with(
        Exposure::Local,
        Limits::default(),
        gate,
        certs,
        handler,
        false,
    )
    .await;

    use http_body_util::Full;
    use hyper_util::rt::{TokioExecutor, TokioIo};
    use rustls_pki_types::ServerName as PkiName;
    use tokio_rustls::TlsConnector;

    let mut cfg = RustlsClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(TrustAny))
        .with_no_client_auth();
    cfg.alpn_protocols = vec![b"h2".to_vec()];
    let connector = TlsConnector::from(Arc::new(cfg));
    let tcp = TcpStream::connect(h.tcp_addr).await.unwrap();
    let name = PkiName::try_from("dns.example.com").unwrap();
    let tls = connector.connect(name, tcp).await.unwrap();
    let io = TokioIo::new(tls);
    let (mut sender, conn) = hyper::client::conn::http2::Builder::new(TokioExecutor::new())
        .handshake(io)
        .await
        .unwrap();
    tokio::spawn(async move {
        let _ = conn.await;
    });

    // One past the shared 16 KiB bound: the server must reject the stream, so
    // the client never receives a response.
    let big = "x".repeat(MAX_DOH_HEADER_LIST_SIZE as usize + 1);
    let req = Request::builder()
        .method(Method::POST)
        .uri("https://dns.example.com/dns-query")
        .header(header::CONTENT_TYPE, DNS_MESSAGE_TYPE)
        .header("x-pad", big)
        .body(Full::new(Bytes::from_static(b"\x00\x01")))
        .unwrap();
    let res = sender.send_request(req).await;
    let rejected = match res {
        Ok(resp) => resp.status() == StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE,
        Err(_) => true,
    };
    assert!(
        rejected,
        "h2 oversized headers must be rejected with 431 (or a stream reset)"
    );

    h.stop().await;
}
