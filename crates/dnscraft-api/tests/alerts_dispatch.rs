//! WX7 automatic dispatch: active alerts reach a configured webhook once per
//! cooldown, a cleared alert can fire again, and the egress guard still applies.
//!
//! The receiver is a loopback HTTPS server with a self-signed certificate. Only
//! this test configuration sets `allow_private_destinations` and trusts that
//! certificate; nothing leaves the machine.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::convert::Infallible;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, UNIX_EPOCH};

use axum::body::Body;
use axum::extract::connect_info::MockConnectInfo;
use axum::http::{Method, Request, StatusCode, header};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use serde_json::{Value, json};
use tokio::net::TcpListener;
use tower::ServiceExt as _;

use dnscraft_api::{
    AppState, Audit, ConfigService, ConfigStore, Db, ManualClock, ModuleAppliers, TlsMode,
    TlsStatus, TlsStatusProvider, dispatch_alerts,
};

/// Authorization headers seen by the receiver, one entry per delivery.
type Received = Arc<Mutex<Vec<Option<String>>>>;

/// Starts a loopback HTTPS receiver. Returns its address, the DER certificate
/// to trust, and what it received.
async fn start_receiver() -> (SocketAddr, Vec<u8>, Received) {
    let certified = rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_owned()]).unwrap();
    let cert_der = certified.cert.der().to_vec();
    let key_der = certified.signing_key.serialize_der();
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        vec![CertificateDer::from(cert_der.clone())],
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_der)),
    )
    .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let address = listener.local_addr().unwrap();
    let received: Received = Arc::new(Mutex::new(Vec::new()));
    let sink = received.clone();
    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                break;
            };
            let acceptor = acceptor.clone();
            let sink = sink.clone();
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(tcp).await else {
                    return;
                };
                let service = service_fn(move |request: hyper::Request<Incoming>| {
                    let sink = sink.clone();
                    async move {
                        let auth = request
                            .headers()
                            .get(header::AUTHORIZATION)
                            .and_then(|value| value.to_str().ok())
                            .map(str::to_owned);
                        sink.lock().unwrap().push(auth);
                        Ok::<_, Infallible>(hyper::Response::new(Body::empty()))
                    }
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(tls), service)
                    .await;
            });
        }
    });
    (address, cert_der, received)
}

/// A TLS provider whose certificate-expiring flag the test flips.
struct Expiring(Mutex<bool>);

impl TlsStatusProvider for Expiring {
    fn status(&self) -> TlsStatus {
        let mut status = TlsStatus::new(TlsMode::Acme, "00".repeat(32));
        status.cert_expiring = *self.0.lock().unwrap();
        status
    }
}

async fn call(
    state: &AppState,
    method: Method,
    uri: &str,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let router = state
        .clone()
        .router()
        .layer(MockConnectInfo(SocketAddr::from(([127, 0, 0, 1], 40_000))));
    let request = match body {
        Some(body) => Request::builder()
            .method(method)
            .uri(uri)
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap(),
        None => Request::builder()
            .method(method)
            .uri(uri)
            .body(Body::empty())
            .unwrap(),
    };
    let response = router.oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

#[tokio::test]
async fn expiring_certificate_reaches_the_webhook_once_until_it_clears() {
    let (address, cert_der, received) = start_receiver().await;
    let expiring = Arc::new(Expiring(Mutex::new(true)));
    let clock = Arc::new(ManualClock::new(
        UNIX_EPOCH + Duration::from_secs(1_700_000_000),
    ));
    let db = Db::open_in_memory(clock.clone()).await.unwrap();
    let service = ConfigService::new(
        ConfigStore::new(db.clone()),
        Audit::new(db.clone()),
        ModuleAppliers::default(),
        "node-a",
    );
    let state = AppState::new()
        .with_clock(clock)
        .with_db(db)
        .with_config_service(Arc::new(service))
        .with_tls(expiring.clone())
        .with_webhook_trust_root(cert_der);

    // Test configuration only: the loopback receiver is a private destination.
    let (status, body) = call(
        &state,
        Method::PUT,
        "/api/v1/notifications",
        Some(json!({
            "allowed_hosts": ["127.0.0.1"],
            "allow_private_destinations": true,
            "channels": [{
                "id": "ops",
                "type": "webhook",
                "enabled": true,
                "url": format!("https://127.0.0.1:{}/hook", address.port()),
                "events": ["tls.cert.expiring"],
                "secret": "tok"
            }]
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    assert_eq!(dispatch_alerts(&state).await.unwrap(), 1);
    assert_eq!(
        received.lock().unwrap().as_slice(),
        [Some("Bearer tok".to_owned())]
    );

    // Still active and inside the cooldown: nothing new is sent.
    assert_eq!(dispatch_alerts(&state).await.unwrap(), 0);
    assert_eq!(received.lock().unwrap().len(), 1);

    // The alert clears: its ledger entry is dropped, so a recurrence is sent again.
    *expiring.0.lock().unwrap() = false;
    assert_eq!(dispatch_alerts(&state).await.unwrap(), 0);
    *expiring.0.lock().unwrap() = true;
    assert_eq!(dispatch_alerts(&state).await.unwrap(), 1);
    assert_eq!(received.lock().unwrap().len(), 2);
}
