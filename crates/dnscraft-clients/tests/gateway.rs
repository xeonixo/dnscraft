//! Gateway HTTPS client against the hand-written mock (C4).

#![allow(clippy::unwrap_used, clippy::expect_used)]

#[path = "support/mock_gateway.rs"]
mod mock_gateway;

use std::path::PathBuf;
use std::sync::Mutex;
use std::time::Duration;

use dnscraft_clients::{
    DEFAULT_POLL_INTERVAL, GatewayClient, Secret, TlsMode, UnifiConfig, leaf_sha256,
};
use mock_gateway::{CertKind, MockGateway, OversizeBody};

const API_KEY: &str = "test-unifi-api-key-do-not-leak";

fn unifi(base_url: String, tls: TlsMode) -> UnifiConfig {
    UnifiConfig {
        enabled: true,
        base_url,
        site_id: None,
        poll_interval: DEFAULT_POLL_INTERVAL,
        classic_clients: true,
        tls,
    }
}

fn pin_mode(der: &[u8]) -> TlsMode {
    TlsMode::Pin(leaf_sha256(der))
}

#[tokio::test]
async fn right_pin_ok() {
    let mock = MockGateway::start(API_KEY, CertKind::SelfSigned).await;
    let client = GatewayClient::new(
        &unifi(mock.base_url(), pin_mode(&mock.leaf_der)),
        Secret::new(API_KEY),
    )
    .unwrap();
    let body = client.get("/v1/ping").await.unwrap();
    assert_eq!(body, br#"{"ok":true}"#);

    let log = mock.take_log().await;
    assert_eq!(log.len(), 1);
    assert_eq!(
        log[0].headers.get("x-api-key").map(String::as_str),
        Some(API_KEY)
    );
}

#[tokio::test]
async fn wrong_pin_untrusted() {
    let mock = MockGateway::start(API_KEY, CertKind::SelfSigned).await;
    let mut bad = leaf_sha256(&mock.leaf_der);
    bad[0] ^= 0xff;
    let client = GatewayClient::new(
        &unifi(mock.base_url(), TlsMode::Pin(bad)),
        Secret::new(API_KEY),
    )
    .unwrap();
    let err = client.get("/v1/ping").await.expect_err("pin mismatch");
    assert_eq!(err.code(), "clients.tls.untrusted");
    assert!(!format!("{err:?}").contains(API_KEY));
    assert!(!err.to_string().contains(API_KEY));
}

#[tokio::test]
async fn ca_mode_with_mock_ca_ok() {
    let mock = MockGateway::start(API_KEY, CertKind::CaSigned).await;
    let dir = std::env::temp_dir().join("dnscraft-clients-ca-ok");
    let _ = std::fs::create_dir_all(&dir);
    let ca_path = dir.join("ca.pem");
    std::fs::write(&ca_path, &mock.ca_pem).unwrap();

    let client = GatewayClient::new(
        &unifi(mock.base_url(), TlsMode::CaFile(ca_path)),
        Secret::new(API_KEY),
    )
    .unwrap();
    let body = client.get("/v1/ping").await.unwrap();
    assert_eq!(body, br#"{"ok":true}"#);
}

#[tokio::test]
async fn ca_mode_with_other_ca_untrusted() {
    let mock = MockGateway::start(API_KEY, CertKind::CaSigned).await;
    // A different self-signed cert used as "CA" — does not issue the mock leaf.
    let other = MockGateway::start("other", CertKind::SelfSigned).await;
    let dir = std::env::temp_dir().join("dnscraft-clients-ca-bad");
    let _ = std::fs::create_dir_all(&dir);
    let ca_path = dir.join("other.pem");
    std::fs::write(&ca_path, &other.leaf_pem).unwrap();

    let client = GatewayClient::new(
        &unifi(mock.base_url(), TlsMode::CaFile(ca_path)),
        Secret::new(API_KEY),
    )
    .unwrap();
    let err = client.get("/v1/ping").await.expect_err("wrong ca");
    assert_eq!(err.code(), "clients.tls.untrusted");
}

#[tokio::test]
async fn insecure_connects_and_warns() {
    let mock = MockGateway::start(API_KEY, CertKind::SelfSigned).await;

    // Capture tracing warnings that carry our stable insecure code.
    // `with_default` (not `set_default`) keeps the subscriber on the same
    // thread as `GatewayClient::new` so a multi-thread runtime cannot miss it.
    static WARNED: Mutex<bool> = Mutex::new(false);
    *WARNED.lock().unwrap() = false;

    struct WarnCapture;
    impl std::io::Write for WarnCapture {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            let s = String::from_utf8_lossy(buf);
            if s.contains("clients.tls.insecure") {
                *WARNED.lock().unwrap() = true;
            }
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::WARN)
        .with_writer(|| WarnCapture)
        .finish();
    let client = tracing::subscriber::with_default(subscriber, || {
        GatewayClient::new(
            &unifi(mock.base_url(), TlsMode::Insecure),
            Secret::new(API_KEY),
        )
        .unwrap()
    });
    assert!(
        *WARNED.lock().unwrap(),
        "insecure mode must emit clients.tls.insecure warning"
    );
    let body = client.get("/v1/ping").await.unwrap();
    assert_eq!(body, br#"{"ok":true}"#);
}

#[tokio::test]
async fn http_401_and_429() {
    let mock = MockGateway::start(API_KEY, CertKind::SelfSigned).await;
    let client = GatewayClient::new(
        &unifi(mock.base_url(), pin_mode(&mock.leaf_der)),
        Secret::new(API_KEY),
    )
    .unwrap();

    mock.force_status(401).await;
    let err = client.get("/v1/ping").await.expect_err("401");
    assert_eq!(err.code(), "clients.http.status");
    match &err {
        dnscraft_clients::ClientsError::HttpStatus { status, message } => {
            assert_eq!(*status, 401);
            assert!(!message.contains(API_KEY));
        }
        other => panic!("expected HttpStatus, got {other:?}"),
    }

    mock.force_status(429).await;
    let err = client.get("/v1/ping").await.expect_err("429");
    assert_eq!(err.code(), "clients.http.status");
    match err {
        dnscraft_clients::ClientsError::HttpStatus { status, .. } => assert_eq!(status, 429),
        other => panic!("expected HttpStatus, got {other:?}"),
    }
}

#[tokio::test]
async fn body_over_8mib_rejected() {
    let mock = MockGateway::start(API_KEY, CertKind::SelfSigned).await;
    let client = GatewayClient::new(
        &unifi(mock.base_url(), pin_mode(&mock.leaf_der)),
        Secret::new(API_KEY),
    )
    .unwrap();

    mock.force_oversize(OversizeBody::DeclaredOnly).await;
    let err = client.get("/v1/ping").await.expect_err("declared");
    assert_eq!(err.code(), "clients.http.body");

    mock.force_oversize(OversizeBody::Streamed).await;
    let err = client.get("/v1/ping").await.expect_err("streamed");
    assert_eq!(err.code(), "clients.http.body");
}

#[tokio::test]
async fn refused_port_is_connect() {
    // Port 1 is almost never listening on loopback.
    let cfg = unifi("https://127.0.0.1:1".into(), TlsMode::Insecure);
    let client = GatewayClient::new(&cfg, Secret::new(API_KEY)).unwrap();
    let err = tokio::time::timeout(Duration::from_secs(5), client.get("/"))
        .await
        .expect("should finish")
        .expect_err("refused");
    assert_eq!(err.code(), "clients.connect");
    assert!(!format!("{err:?}").contains(API_KEY));
}

#[tokio::test]
async fn gateway_debug_redacts_key() {
    let mock = MockGateway::start(API_KEY, CertKind::SelfSigned).await;
    let client = GatewayClient::new(
        &unifi(mock.base_url(), pin_mode(&mock.leaf_der)),
        Secret::new(API_KEY),
    )
    .unwrap();
    let shown = format!("{client:?}");
    assert!(!shown.contains(API_KEY));
    assert!(shown.contains("Secret([redacted])"));
}

#[test]
fn insecure_is_not_enabled_by_default() {
    // Default UnifiConfig uses Insecure only as a placeholder while disabled;
    // enabling UniFi without an explicit pin/CA is a deliberate admin choice.
    let cfg = UnifiConfig::default();
    assert!(!cfg.enabled);
    let _ = PathBuf::new();
}
