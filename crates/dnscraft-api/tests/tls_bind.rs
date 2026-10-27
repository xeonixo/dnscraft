//! A4 integration tests: TLS bootstrap persistence, status reporting, and a
//! real TLS bind + handshake against `serve`.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use axum::body::Body;
use axum::extract::connect_info::MockConnectInfo;
use axum::http::{Request, StatusCode};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::ring::default_provider;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tower::ServiceExt as _;

use dnscraft_api::{
    AppState, ControlApiConfig, ControlApiTls, SystemClock, TlsMode, TlsStatus, TlsStatusProvider,
    serve,
};

/// A unique, self-cleaning temporary directory.
struct TempDir(PathBuf);

impl TempDir {
    fn new(name: &str) -> Self {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let id = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("dnscraft-api-{name}-{}-{id}", std::process::id()));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).unwrap();
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// A client cert verifier that accepts anything (the peer's trust is irrelevant
/// to these tests).
#[derive(Debug)]
struct NoVerify;

impl ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// A TLS connector that skips peer verification.
fn tls_connector() -> tokio_rustls::TlsConnector {
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerify))
        .with_no_client_auth();
    tokio_rustls::TlsConnector::from(Arc::new(config))
}

/// An ephemeral loopback port for `serve` to bind (the probe listener is
/// dropped; `serve` rebinds the same port a moment later).
async fn ephemeral_port() -> u16 {
    let probe = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    probe.local_addr().unwrap().port()
}

fn bootstrap(hostname: &str, dir: &Path) -> ControlApiTls {
    ControlApiTls::bootstrap(
        hostname,
        dir,
        &SystemClock,
        Arc::new(dnscraft_tls::CertResolver::new()),
    )
    .unwrap()
}

#[test]
fn bootstrap_creates_persisted_self_signed_cert() {
    let dir = TempDir::new("bootstrap");
    let tls = bootstrap("node.example.com", dir.path());

    let status = tls.status();
    assert_eq!(status.mode, TlsMode::SelfSigned);
    assert_eq!(status.fingerprint.len(), 64);

    let control_dir = dir.path().join("control-api");
    assert!(control_dir.join("tls-cert.pem").is_file());
    assert!(control_dir.join("tls-key.pem").is_file());
    assert!(control_dir.join("tls-meta.json").is_file());

    // The fingerprint is stable across a second bootstrap of the same dir.
    let again = bootstrap("node.example.com", dir.path());
    assert_eq!(again.status().fingerprint, status.fingerprint);
}

/// A TLS status source that reports a fixed status (no cert machinery needed).
struct FakeTls(TlsStatus);

impl TlsStatusProvider for FakeTls {
    fn status(&self) -> TlsStatus {
        self.0.clone()
    }
}

#[tokio::test]
async fn status_reports_tls_mode_fingerprint_and_self_signed_warning() {
    let state = AppState::new().with_tls(Arc::new(FakeTls(TlsStatus::new(
        TlsMode::SelfSigned,
        "ab".repeat(32),
    ))));
    let res = state
        .router()
        .layer(MockConnectInfo(SocketAddr::from(([127, 0, 0, 1], 40_000))))
        .oneshot(
            Request::builder()
                .uri("/api/v1/status")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .unwrap();
    let body: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(body["data"]["tls_mode"], "self_signed");
    assert_eq!(body["data"]["tls_fingerprint"], "ab".repeat(32));
    assert_eq!(
        body["data"]["warnings"],
        serde_json::json!(["control_api.tls.self_signed"])
    );
}

#[tokio::test]
async fn status_omits_tls_fields_without_a_provider() {
    let res = AppState::new()
        .router()
        .layer(MockConnectInfo(SocketAddr::from(([127, 0, 0, 1], 40_000))))
        .oneshot(
            Request::builder()
                .uri("/api/v1/status")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .unwrap();
    let body: Value = serde_json::from_slice(&bytes).unwrap();
    assert!(body["data"].is_object());
    assert!(body["data"].get("tls_mode").is_none());
    assert!(body["data"].get("tls_fingerprint").is_none());
    assert!(body["data"].get("warnings").is_none());
}

#[tokio::test]
async fn serve_tls_round_trip_reports_self_signed_status() {
    let dir = TempDir::new("serve-tls");
    let tls = bootstrap("localhost", dir.path());
    let state = AppState::new().with_tls(tls.status_provider());
    let port = ephemeral_port().await;
    let config = ControlApiConfig {
        bind: "127.0.0.1".parse().unwrap(),
        port,
        ..ControlApiConfig::default()
    };
    let server_config = tls.server_config();

    let handle = tokio::spawn(async move {
        let _ = serve(config, state, Some(server_config)).await;
    });

    // Wait for the listener to come up, then open a TLS connection.
    let addr = format!("127.0.0.1:{port}");
    let mut tcp = None;
    for _ in 0..200 {
        if let Ok(stream) = tokio::net::TcpStream::connect(&addr).await {
            tcp = Some(stream);
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let tcp = tcp.expect("server should accept connections");
    let mut tls_stream = tls_connector()
        .connect(ServerName::try_from("localhost").unwrap(), tcp)
        .await
        .unwrap();

    tls_stream
        .write_all(b"GET /api/v1/status HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut raw = Vec::new();
    tls_stream.read_to_end(&mut raw).await.unwrap();
    let text = String::from_utf8(raw).unwrap();

    assert!(text.starts_with("HTTP/1.1 200 OK"), "response: {text}");
    assert!(text.contains("\"tls_mode\":\"self_signed\""), "{text}");
    assert!(text.contains("\"tls_fingerprint\""), "{text}");
    assert!(text.contains("control_api.tls.self_signed"), "{text}");

    handle.abort();
}
