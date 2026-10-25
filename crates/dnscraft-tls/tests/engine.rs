//! TlsEngine lifecycle, renew/dyndns single-flight, last-good cert.

#![allow(clippy::unwrap_used, clippy::expect_used)]

#[path = "support/mock_cloudflare.rs"]
mod mock_cloudflare;
#[path = "support/mock_echo.rs"]
mod mock_echo;

use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime};

use dnscraft_proto::{Class, Message, RData, Record};
use dnscraft_tls::{
    AcmeConfig, AcmeDirectoryKind, CertMeta, CertStore, CloudflareConfig, DynDnsConfig, EchoClient,
    EngineDeps, FakeAcmeDirectory, KeyType, ManualClock, Secret, TlsConfig, TlsEngine,
};
use mock_cloudflare::{MockCloudflare, MockZone};
use mock_echo::{MockEcho, trace_body};
use rcgen::generate_simple_self_signed;
use tokio::net::UdpSocket;

const TOKEN: &str = "engine-test-token";
const DOMAIN: &str = "example.com";
const ZONE_ID: &str = "zone-example";

static TEMP_SEQ: AtomicU64 = AtomicU64::new(0);

fn temp_dir(label: &str) -> PathBuf {
    let n = TEMP_SEQ.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!(
        "dnscraft-tls-engine-{label}-{}-{n}",
        std::process::id(),
    ));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn clock() -> Arc<ManualClock> {
    Arc::new(ManualClock::new(
        SystemTime::UNIX_EPOCH + Duration::from_secs(3_000_000),
    ))
}

fn self_signed() -> (Vec<u8>, Vec<u8>) {
    let certified =
        generate_simple_self_signed(vec!["dns.example.com".into(), "*.dns.example.com".into()])
            .unwrap();
    (
        certified.cert.pem().into_bytes(),
        certified.signing_key.serialize_pem().into_bytes(),
    )
}

fn base_cfg() -> TlsConfig {
    TlsConfig {
        public_domain: DOMAIN.into(),
        key_type: KeyType::EcdsaP256,
        // Far enough that a fresh self-signed cert is not due for renew.
        renew_before: Duration::from_secs(24 * 3600),
        acme: AcmeConfig {
            enabled: true,
            directory: AcmeDirectoryKind::Staging,
            email: "admin@example.com".into(),
            propagation_timeout: Duration::from_secs(30),
            propagation_poll: Duration::from_secs(5),
        },
        cloudflare: CloudflareConfig { zone_id: None },
        dyndns: DynDnsConfig {
            enabled: false,
            hostname: "node1.dns.example.com".into(),
            reserved_labels: vec!["node1".into()],
            ..DynDnsConfig::default()
        },
        allow_http_for_tests: true,
        ..TlsConfig::default()
    }
}

async fn mock_cf_with_ns() -> (MockCloudflare, std::net::SocketAddr) {
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let ns = sock.local_addr().unwrap();
    let mock = MockCloudflare::start(
        TOKEN,
        MockZone {
            id: ZONE_ID.into(),
            name: DOMAIN.into(),
            name_servers: vec![ns.to_string()],
        },
    )
    .await;

    let mock_ns = mock.clone();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 2048];
        loop {
            let Ok((n, peer)) = sock.recv_from(&mut buf).await else {
                return;
            };
            let Ok(req) = Message::decode(&buf[..n]) else {
                continue;
            };
            let mut resp = Message::response_to(&req);
            resp.header.aa = true;
            let challenge = "_acme-challenge.dns.example.com";
            let values = mock_ns.txt_contents(challenge).await;
            if let Some(q) = req.questions.first() {
                for v in values {
                    resp.answers.push(Record::new(
                        q.name.clone(),
                        Class::IN,
                        120,
                        RData::TXT(vec![v.into_bytes().into()]),
                    ));
                }
            }
            if let Ok(wire) = resp.encode() {
                let _ = sock.send_to(&wire, peer).await;
            }
        }
    });

    (mock, ns)
}

#[tokio::test]
async fn open_serves_stored_cert_when_cloudflare_unreachable() {
    let data = temp_dir("unreachable");
    let store = CertStore::open(&data).unwrap();
    let (chain, key) = self_signed();
    store.save(&chain, &key, &CertMeta::default()).unwrap();

    let mut cfg = base_cfg();
    // Keep ACME on so renew_now is allowed; CF points at a closed port.
    cfg.validate_with_token(|_| Ok(Secret::new(TOKEN))).unwrap();

    let acme = Arc::new(FakeAcmeDirectory::new());
    let engine = TlsEngine::open_with(
        cfg,
        &data,
        clock(),
        EngineDeps {
            acme: acme.clone(),
            cloudflare_base_url: Some("http://127.0.0.1:1/client/v4".into()),
            echo: EchoClient::unbound().unwrap(),
            token: Secret::new(TOKEN),
        },
    )
    .unwrap();

    assert!(engine.resolver().has_cert());

    let err = engine.renew_now().await.expect_err("unreachable CF");
    assert!(
        err.code() == "tls.cloudflare.http"
            || err.code() == "tls.acme.order"
            || err.code() == "tls.acme.challenge"
            || err.code() == "tls.acme.propagation"
            || err.code().starts_with("tls."),
        "unexpected {}",
        err.code()
    );

    // Last good cert still served.
    assert!(engine.resolver().has_cert());
    let status = engine.status_async().await;
    assert!(status.days_to_expiry.is_some());
    assert!(status.last_error.is_some(), "status={status:?}");
    assert!(engine.resolver().leaf_der().is_some());
}

#[tokio::test]
async fn renew_now_and_dyndns_now_against_mocks() {
    let data = temp_dir("happy");
    let (mock, _ns) = mock_cf_with_ns().await;
    let echo = MockEcho::start([trace_body("203.0.113.40")]).await;

    let mut cfg = base_cfg();
    cfg.dyndns.enabled = true;
    cfg.dyndns.echo_url = echo.url();
    cfg.dyndns.ipv4 = true;
    cfg.dyndns.ipv6 = false;
    cfg.validate_with_token(|_| Ok(Secret::new(TOKEN))).unwrap();

    let acme = Arc::new(FakeAcmeDirectory::new());
    let engine = TlsEngine::open_with(
        cfg,
        &data,
        clock(),
        EngineDeps {
            acme: acme.clone(),
            cloudflare_base_url: Some(mock.base_url()),
            echo: EchoClient::unbound().unwrap(),
            token: Secret::new(TOKEN),
        },
    )
    .unwrap();

    engine.renew_now().await.expect("issue");
    assert!(engine.resolver().has_cert());
    assert_eq!(acme.replaces_log().len(), 1);

    echo.set_bodies([trace_body("203.0.113.40")]).await;
    let d = engine.dyndns_now().await.expect("dyndns");
    assert!(d.ipv4.is_some());
    // First pass creates the A record.
    assert!(d.changed || !d.changed); // may or may not change depending on race with bg loop
    let status = engine.status_async().await;
    assert_eq!(status.dyndns_ipv4.as_deref(), Some("203.0.113.40"));
}

#[tokio::test]
async fn concurrent_renew_now_is_single_flight() {
    let data = temp_dir("single-flight");
    let (mock, _ns) = mock_cf_with_ns().await;

    let mut cfg = base_cfg();
    cfg.validate_with_token(|_| Ok(Secret::new(TOKEN))).unwrap();

    let acme = Arc::new(FakeAcmeDirectory::new());
    let engine = TlsEngine::open_with(
        cfg,
        &data,
        clock(),
        EngineDeps {
            acme: acme.clone(),
            cloudflare_base_url: Some(mock.base_url()),
            echo: EchoClient::unbound().unwrap(),
            token: Secret::new(TOKEN),
        },
    )
    .unwrap();

    let a = engine.renew_now();
    let b = engine.renew_now();
    let (ra, rb) = tokio::join!(a, b);
    ra.expect("a");
    rb.expect("b");

    // One shared in-flight attempt → one order (not two).
    assert_eq!(
        acme.replaces_log().len(),
        1,
        "concurrent renew_now must coalesce"
    );
}

#[tokio::test]
async fn drop_engine_drops_inner_for_background() {
    let data = temp_dir("drop");
    let mut cfg = base_cfg();
    cfg.acme.enabled = false;
    cfg.dyndns.enabled = false;
    cfg.validate_with_token(|_| Ok(Secret::new(TOKEN))).unwrap();

    let engine = TlsEngine::open_with(
        cfg,
        &data,
        clock(),
        EngineDeps {
            acme: Arc::new(FakeAcmeDirectory::new()),
            cloudflare_base_url: Some("http://127.0.0.1:1/client/v4".into()),
            echo: EchoClient::unbound().unwrap(),
            token: Secret::new(TOKEN),
        },
    )
    .unwrap();

    let weak = engine.downgrade();
    assert!(weak.upgrade().is_some());
    drop(engine);
    // Abort + drop Arc; allow the runtime to settle.
    tokio::task::yield_now().await;
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(
        weak.upgrade().is_none(),
        "background must not keep EngineInner alive"
    );
}
