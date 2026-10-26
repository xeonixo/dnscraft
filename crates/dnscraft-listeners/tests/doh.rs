//! N8: DoH HTTP/2 + HTTP/1.1 tests.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod support;

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use bytes::Bytes;
use dnscraft_listeners::{
    DNS_MESSAGE_TYPE, DohPath, DohServeParams, DohStats, DohWireError, Exposure, FakeHandler,
    Limits, ListenerConfig, MAX_DOH_PAYLOAD, PAD_BLOCK, PolicyClientIds, Protocol, PublicConfig,
    QueryHandler, SniGate, SystemClock, TcpServeParams, TcpStats, TlsStats, cache_max_age,
    extract_wire, parse_doh_path, read_frame, serve_doh, serve_tcp, write_frame,
};
use dnscraft_policy::ListenerId;
use dnscraft_policy::{PolicyAnswer, PolicyError, RequestContext};
use dnscraft_proto::{Class, Message, Name, RData, Rcode, Record, RecordType};
use dnscraft_tls::{CertResolver, ReservedLabels};
use http::{Method, Request, StatusCode, Uri, header};
use http_body_util::{BodyExt, Full};
use hyper_util::rt::{TokioExecutor, TokioIo};
use rustls::ClientConfig;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::ring::default_provider;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, Error as RustlsError, SignatureScheme};
use support::certs::example_dns_cert;
use support::{
    encode_a_query, encode_a_query_edns, fake_a_answer, policy_engine_with_client_ids, poll_until,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{Notify, oneshot, watch};
use tokio_rustls::TlsConnector;

const DOMAIN: &str = "example.com";

fn install_ring() {
    let _ = default_provider().install_default();
}

fn listener_doh(addr: SocketAddr, exposure: Exposure) -> ListenerConfig {
    ListenerConfig {
        id: ListenerId::new("test-doh").unwrap(),
        protocol: Protocol::Doh,
        address: addr,
        exposure,
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

fn connector(alpn: &[&[u8]]) -> TlsConnector {
    let mut cfg = ClientConfig::builder_with_provider(Arc::new(default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAll))
        .with_no_client_auth();
    cfg.alpn_protocols = alpn.iter().map(|a| a.to_vec()).collect();
    cfg.resumption = rustls::client::Resumption::disabled();
    TlsConnector::from(Arc::new(cfg))
}

struct DohHarness {
    addr: SocketAddr,
    stats: Arc<DohStats>,
    shutdown: watch::Sender<bool>,
    join: tokio::task::JoinHandle<Result<(), dnscraft_listeners::ListenersError>>,
}

impl DohHarness {
    async fn spawn(
        exposure: Exposure,
        limits: Limits,
        gate: SniGate,
        certs: Arc<CertResolver>,
        answer_ttl: u32,
    ) -> Self {
        let mut answer = fake_a_answer(Ipv4Addr::new(192, 0, 2, 44));
        if let Some(rr) = answer.message.answers.first_mut() {
            rr.ttl = answer_ttl;
        }
        Self::spawn_with(
            exposure,
            limits,
            gate,
            certs,
            Arc::new(FakeHandler::new(answer)),
        )
        .await
    }

    async fn spawn_with<H: QueryHandler + 'static>(
        exposure: Exposure,
        limits: Limits,
        gate: SniGate,
        certs: Arc<CertResolver>,
        handler: Arc<H>,
    ) -> Self {
        let stats = Arc::new(DohStats::default());
        let tls_stats = Arc::new(TlsStats::default());
        let (bound_tx, bound_rx) = oneshot::channel();
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
        let join = tokio::spawn(serve_doh(DohServeParams {
            listener: listener_doh(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)), exposure),
            limits,
            admission,
            handler,
            clock: Arc::new(SystemClock),
            stats: Arc::clone(&stats),
            tls_stats,
            certs,
            sni_gate: Arc::new(gate),
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
            shutdown: shutdown_tx,
            join,
        }
    }

    async fn stop(self) {
        let _ = self.shutdown.send(true);
        let _ = tokio::time::timeout(Duration::from_secs(2), self.join).await;
    }
}

async fn doh_exchange_h1(
    addr: SocketAddr,
    req: Request<Full<Bytes>>,
) -> (StatusCode, http::HeaderMap, Bytes) {
    let connector = connector(&[b"http/1.1"]);
    let tcp = TcpStream::connect(addr).await.unwrap();
    let name = ServerName::try_from("dns.example.com").unwrap();
    let tls = connector.connect(name, tcp).await.unwrap();
    let io = TokioIo::new(tls);
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await.unwrap();
    tokio::spawn(async move {
        let _ = conn.await;
    });
    let resp = sender.send_request(req).await.unwrap();
    let status = resp.status();
    let headers = resp.headers().clone();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    (status, headers, body)
}

async fn doh_exchange_h2(
    addr: SocketAddr,
    req: Request<Full<Bytes>>,
) -> (StatusCode, http::HeaderMap, Bytes) {
    let connector = connector(&[b"h2"]);
    let tcp = TcpStream::connect(addr).await.unwrap();
    let name = ServerName::try_from("dns.example.com").unwrap();
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

fn get_req(path_and_query: &str) -> Request<Full<Bytes>> {
    Request::builder()
        .method(Method::GET)
        .uri(format!("https://dns.example.com{path_and_query}"))
        .body(Full::new(Bytes::new()))
        .unwrap()
}

fn post_req(path: &str, body: Bytes, content_type: Option<&str>) -> Request<Full<Bytes>> {
    let mut b = Request::builder()
        .method(Method::POST)
        .uri(format!("https://dns.example.com{path}"));
    if let Some(ct) = content_type {
        b = b.header(header::CONTENT_TYPE, ct);
    }
    b.body(Full::new(body)).unwrap()
}

#[test]
fn path_and_wire_helpers() {
    assert_eq!(
        parse_doh_path("/dns-query/PHONE"),
        DohPath::ClientId("phone".into())
    );
    assert_eq!(
        extract_wire(
            &Method::DELETE,
            &"/dns-query".parse::<Uri>().unwrap(),
            None,
            b""
        ),
        Err(DohWireError::MethodNotAllowed)
    );
}

#[tokio::test]
async fn get_post_match_do53_h2_and_h1() {
    install_ring();
    let engine = policy_engine_with_client_ids(&["phone"]).await;
    let gate = SniGate {
        public_domain: DOMAIN.into(),
        reserved: ReservedLabels::new(["node1".into()]),
        registry: Arc::new(PolicyClientIds(engine)),
    };
    let (pem, key, _) = example_dns_cert();
    let certs = Arc::new(CertResolver::new());
    certs.install(&pem, &key).unwrap();

    let answer = fake_a_answer(Ipv4Addr::new(192, 0, 2, 44));
    let handler = Arc::new(FakeHandler::new(answer.clone()));

    // Do53 TCP baseline (no pad).
    let tcp_stats = Arc::new(TcpStats::default());
    let (tcp_tx, tcp_rx) = oneshot::channel();
    let (tcp_sd_tx, tcp_sd_rx) = watch::channel(false);
    let tcp_join = tokio::spawn(serve_tcp(TcpServeParams {
        listener: ListenerConfig {
            id: ListenerId::new("tcp-base").unwrap(),
            protocol: Protocol::Tcp53,
            address: SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
            exposure: Exposure::Local,
            h3: false,
        },
        limits: Limits::default(),
        admission: support::fresh_admission(),
        handler,
        clock: Arc::new(SystemClock),
        stats: tcp_stats,
        ddr: None,
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

    let h = DohHarness::spawn(Exposure::Local, Limits::default(), gate, certs, 60).await;
    let enc = URL_SAFE_NO_PAD.encode(&q);
    let tcp_rdata = Message::decode(&tcp_resp).unwrap().answers[0].rdata.clone();

    let check = |label: &str, status: StatusCode, headers: &http::HeaderMap, body: &Bytes| {
        assert_eq!(status, StatusCode::OK, "{label}");
        assert_eq!(
            headers.get(header::CONTENT_TYPE).unwrap(),
            DNS_MESSAGE_TYPE,
            "{label}"
        );
        let msg = Message::decode(body).unwrap();
        assert_eq!(msg.header.id, 0, "{label} id must be 0");
        assert_eq!(msg.rcode(), Rcode::NOERROR, "{label}");
        assert_eq!(msg.answers[0].rdata, tcp_rdata, "{label}");
        assert_eq!(body.len() % PAD_BLOCK, 0, "{label} padding");
        assert_eq!(
            headers.get(header::CACHE_CONTROL).unwrap(),
            "max-age=60",
            "{label}"
        );
    };

    let (s, hdr, body) = doh_exchange_h2(h.addr, get_req(&format!("/dns-query?dns={enc}"))).await;
    check("h2-get", s, &hdr, &body);
    let (s, hdr, body) = doh_exchange_h2(
        h.addr,
        post_req("/dns-query", Bytes::from(q.clone()), Some(DNS_MESSAGE_TYPE)),
    )
    .await;
    check("h2-post", s, &hdr, &body);
    let (s, hdr, body) = doh_exchange_h1(h.addr, get_req(&format!("/dns-query?dns={enc}"))).await;
    check("h1-get", s, &hdr, &body);
    let (s, hdr, body) = doh_exchange_h1(
        h.addr,
        post_req("/dns-query", Bytes::from(q), Some(DNS_MESSAGE_TYPE)),
    )
    .await;
    check("h1-post", s, &hdr, &body);

    h.stop().await;
}

#[tokio::test]
async fn error_status_table() {
    install_ring();
    let engine = policy_engine_with_client_ids(&["phone"]).await;
    let gate = SniGate {
        public_domain: DOMAIN.into(),
        reserved: ReservedLabels::new(["node1".into()]),
        registry: Arc::new(PolicyClientIds(Arc::clone(&engine))),
    };
    let (pem, key, _) = example_dns_cert();
    let certs = Arc::new(CertResolver::new());
    certs.install(&pem, &key).unwrap();

    // Local: bare path OK for errors that don't need DNS.
    let local = DohHarness::spawn(
        Exposure::Local,
        Limits::default(),
        gate.clone(),
        Arc::clone(&certs),
        30,
    )
    .await;

    let q = encode_a_query(1, "example.com.");
    let enc = URL_SAFE_NO_PAD.encode(&q);

    // 405
    let put = Request::builder()
        .method(Method::PUT)
        .uri("https://dns.example.com/dns-query")
        .body(Full::new(Bytes::new()))
        .unwrap();
    let (s, _, _) = doh_exchange_h2(local.addr, put).await;
    assert_eq!(s, StatusCode::METHOD_NOT_ALLOWED);

    // 415
    let (s, _, _) = doh_exchange_h2(
        local.addr,
        post_req("/dns-query", Bytes::from(q.clone()), Some("text/plain")),
    )
    .await;
    assert_eq!(s, StatusCode::UNSUPPORTED_MEDIA_TYPE);

    // 400 padded base64
    let (s, _, _) = doh_exchange_h2(local.addr, get_req(&format!("/dns-query?dns={enc}="))).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);

    // 413
    let big = vec![0u8; MAX_DOH_PAYLOAD + 1];
    let (s, _, _) = doh_exchange_h2(
        local.addr,
        post_req("/dns-query", Bytes::from(big), Some(DNS_MESSAGE_TYPE)),
    )
    .await;
    assert_eq!(s, StatusCode::PAYLOAD_TOO_LARGE);

    // 404 other path
    let (s, _, _) = doh_exchange_h2(local.addr, get_req(&format!("/nope?dns={enc}"))).await;
    assert_eq!(s, StatusCode::NOT_FOUND);

    local.stop().await;

    // Public path rules
    let public = DohHarness::spawn(
        Exposure::Public,
        Limits {
            rate_per_source: dnscraft_listeners::TokenRate {
                per_second: 1,
                burst: 1,
            },
            ..Limits::default()
        },
        gate,
        certs,
        30,
    )
    .await;

    // bare path on public → 404 no strike
    let (s, _, _) = doh_exchange_h2(public.addr, get_req(&format!("/dns-query?dns={enc}"))).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    assert_eq!(public.stats.path_strikes.load(Ordering::Relaxed), 0);

    // unknown id → 404 + strike
    let (s, _, _) = doh_exchange_h2(
        public.addr,
        get_req(&format!("/dns-query/unknown?dns={enc}")),
    )
    .await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    poll_until(
        || public.stats.path_strikes.load(Ordering::Relaxed) >= 1,
        Duration::from_secs(2),
    )
    .await;

    // registered + rate limit → 429 (burst 1: first OK, second 429)
    let (s1, _, _) =
        doh_exchange_h2(public.addr, get_req(&format!("/dns-query/phone?dns={enc}"))).await;
    assert_eq!(s1, StatusCode::OK);
    let (s2, _, _) =
        doh_exchange_h2(public.addr, get_req(&format!("/dns-query/phone?dns={enc}"))).await;
    assert_eq!(s2, StatusCode::TOO_MANY_REQUESTS);

    public.stop().await;
}

#[test]
fn cache_max_age_min_ttl() {
    let q = Message::query(1, Name::from_ascii("example.com.").unwrap(), RecordType::A);
    let mut resp = Message::response_to(&q);
    resp.answers.push(Record::new(
        Name::from_ascii("example.com.").unwrap(),
        Class::IN,
        120,
        RData::A(Ipv4Addr::new(192, 0, 2, 1)),
    ));
    resp.answers.push(Record::new(
        Name::from_ascii("example.com.").unwrap(),
        Class::IN,
        45,
        RData::A(Ipv4Addr::new(192, 0, 2, 2)),
    ));
    let wire = resp.encode().unwrap();
    assert_eq!(cache_max_age(&wire), Some(45));
}

struct HangHandler {
    release: Arc<Notify>,
    answer: PolicyAnswer,
}

impl QueryHandler for HangHandler {
    async fn handle(&self, _ctx: RequestContext) -> Result<PolicyAnswer, PolicyError> {
        self.release.notified().await;
        Ok(self.answer.clone())
    }
}

#[tokio::test(start_paused = true)]
async fn doh_partial_headers_closed() {
    install_ring();
    let engine = policy_engine_with_client_ids(&["phone"]).await;
    let gate = SniGate {
        public_domain: DOMAIN.into(),
        reserved: ReservedLabels::new(["node1".into()]),
        registry: Arc::new(PolicyClientIds(engine)),
    };
    let (pem, key, _) = example_dns_cert();
    let certs = Arc::new(CertResolver::new());
    certs.install(&pem, &key).unwrap();
    let idle = Duration::from_secs(5);
    let h = DohHarness::spawn(
        Exposure::Local,
        Limits {
            tcp_idle_timeout: idle,
            ..Limits::default()
        },
        gate,
        certs,
        60,
    )
    .await;

    let connector = connector(&[b"http/1.1"]);
    let tcp = TcpStream::connect(h.addr).await.unwrap();
    let name = ServerName::try_from("dns.example.com").unwrap();
    let mut tls = connector.connect(name, tcp).await.unwrap();
    // Incomplete request-line / headers — header_read_timeout should close.
    tls.write_all(b"GET /dns-query HTTP/1.1\r\nHost: dns.example.com\r\n")
        .await
        .unwrap();
    tokio::time::advance(idle + Duration::from_secs(1)).await;
    let mut buf = [0u8; 8];
    let closed = tokio::time::timeout(Duration::from_secs(1), tls.read(&mut buf)).await;
    assert!(
        matches!(closed, Ok(Ok(0)) | Ok(Err(_)) | Err(_)),
        "partial headers must close the connection: {closed:?}"
    );
    h.stop().await;
}

#[tokio::test]
async fn doh_idle_h1_keepalive_closed() {
    install_ring();
    let engine = policy_engine_with_client_ids(&["phone"]).await;
    let gate = SniGate {
        public_domain: DOMAIN.into(),
        reserved: ReservedLabels::new(["node1".into()]),
        registry: Arc::new(PolicyClientIds(engine)),
    };
    let (pem, key, _) = example_dns_cert();
    let certs = Arc::new(CertResolver::new());
    certs.install(&pem, &key).unwrap();
    // Real time (not start_paused): paused auto-advance races header_read_timeout.
    let idle = Duration::from_millis(300);
    let h = DohHarness::spawn(
        Exposure::Local,
        Limits {
            tcp_idle_timeout: idle,
            ..Limits::default()
        },
        gate,
        certs,
        60,
    )
    .await;

    let connector = connector(&[b"http/1.1"]);
    let tcp = TcpStream::connect(h.addr).await.unwrap();
    let name = ServerName::try_from("dns.example.com").unwrap();
    let tls = connector.connect(name, tcp).await.unwrap();
    let io = TokioIo::new(tls);
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await.unwrap();
    let conn_task = tokio::spawn(conn);

    let q = encode_a_query(1, "example.com.");
    let enc = URL_SAFE_NO_PAD.encode(&q);
    let resp = sender
        .send_request(get_req(&format!("/dns-query?dns={enc}")))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let _ = resp.into_body().collect().await.unwrap();

    poll_until(
        || h.stats.closed.load(Ordering::Relaxed) >= 1,
        Duration::from_secs(3),
    )
    .await;
    assert_eq!(h.stats.closed.load(Ordering::Relaxed), 1);
    let next = sender
        .send_request(get_req(&format!("/dns-query?dns={enc}")))
        .await;
    assert!(next.is_err(), "idle h1 keep-alive must close: {next:?}");
    let _ = conn_task.await;
    h.stop().await;
}

#[tokio::test]
async fn doh_idle_h2_ping_keepalive_closed() {
    install_ring();
    let engine = policy_engine_with_client_ids(&["phone"]).await;
    let gate = SniGate {
        public_domain: DOMAIN.into(),
        reserved: ReservedLabels::new(["node1".into()]),
        registry: Arc::new(PolicyClientIds(engine)),
    };
    let (pem, key, _) = example_dns_cert();
    let certs = Arc::new(CertResolver::new());
    certs.install(&pem, &key).unwrap();
    let idle = Duration::from_millis(400);
    let h = DohHarness::spawn(
        Exposure::Local,
        Limits {
            tcp_idle_timeout: idle,
            ..Limits::default()
        },
        gate,
        certs,
        60,
    )
    .await;

    let connector = connector(&[b"h2"]);
    let tcp = TcpStream::connect(h.addr).await.unwrap();
    let name = ServerName::try_from("dns.example.com").unwrap();
    let tls = connector.connect(name, tcp).await.unwrap();
    let io = TokioIo::new(tls);
    // Client sends PINGs while idle — must not count as application activity.
    let (mut sender, conn) = hyper::client::conn::http2::Builder::new(TokioExecutor::new())
        .timer(hyper_util::rt::TokioTimer::new())
        .keep_alive_interval(Duration::from_millis(50))
        .keep_alive_while_idle(true)
        .handshake(io)
        .await
        .unwrap();
    let conn_task = tokio::spawn(conn);

    let q = encode_a_query(1, "example.com.");
    let enc = URL_SAFE_NO_PAD.encode(&q);
    let resp = sender
        .send_request(get_req(&format!("/dns-query?dns={enc}")))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let _ = resp.into_body().collect().await.unwrap();

    poll_until(
        || h.stats.closed.load(Ordering::Relaxed) >= 1,
        Duration::from_secs(3),
    )
    .await;
    assert_eq!(
        h.stats.closed.load(Ordering::Relaxed),
        1,
        "h2 PING keep-alive must not prevent application idle close"
    );
    let _ = conn_task.await;
    h.stop().await;
}

#[tokio::test]
async fn doh_h2_stream_cap() {
    install_ring();
    let engine = policy_engine_with_client_ids(&["phone"]).await;
    let gate = SniGate {
        public_domain: DOMAIN.into(),
        reserved: ReservedLabels::new(["node1".into()]),
        registry: Arc::new(PolicyClientIds(engine)),
    };
    let (pem, key, _) = example_dns_cert();
    let certs = Arc::new(CertResolver::new());
    certs.install(&pem, &key).unwrap();
    let release = Arc::new(Notify::new());
    let h = DohHarness::spawn_with(
        Exposure::Local,
        Limits {
            max_queries_per_connection: 2,
            ..Limits::default()
        },
        gate,
        certs,
        Arc::new(HangHandler {
            release: Arc::clone(&release),
            answer: fake_a_answer(Ipv4Addr::new(192, 0, 2, 44)),
        }),
    )
    .await;

    let connector = connector(&[b"h2"]);
    let tcp = TcpStream::connect(h.addr).await.unwrap();
    let name = ServerName::try_from("dns.example.com").unwrap();
    let tls = connector.connect(name, tcp).await.unwrap();
    let io = TokioIo::new(tls);
    let (mut sender, conn) = hyper::client::conn::http2::Builder::new(TokioExecutor::new())
        .handshake(io)
        .await
        .unwrap();
    tokio::spawn(async move {
        let _ = conn.await;
    });

    let q = encode_a_query(1, "example.com.");
    let enc = URL_SAFE_NO_PAD.encode(&q);
    let r1 = sender.send_request(get_req(&format!("/dns-query?dns={enc}")));
    let r2 = sender.send_request(get_req(&format!("/dns-query?dns={enc}")));
    tokio::pin!(r1);
    tokio::pin!(r2);
    // Drive the two hanging streams far enough to occupy the cap.
    let _ = tokio::time::timeout(Duration::from_millis(100), async {
        tokio::select! {
            biased;
            _ = &mut r1 => {}
            _ = &mut r2 => {}
            () = tokio::task::yield_now() => {}
        }
    })
    .await;

    let third = tokio::time::timeout(
        Duration::from_millis(300),
        sender.send_request(get_req(&format!("/dns-query?dns={enc}"))),
    )
    .await;
    assert!(
        third.is_err() || third.as_ref().ok().is_some_and(|r| r.is_err()),
        "third concurrent h2 stream must be blocked by max_concurrent_streams"
    );

    release.notify_waiters();
    h.stop().await;
}
