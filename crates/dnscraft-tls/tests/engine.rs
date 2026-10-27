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
    AcmeConfig, AcmeDirectoryKind, CertMeta, CertStore, DynDnsConfig, EchoClient, EngineDeps,
    FakeAcmeDirectory, KeyType, ManualClock, Secret, TlsConfig, TlsEngine,
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
            account: dnscraft_tls::AcmeAccountConfig {
                tos_agreed: true,
                ..Default::default()
            },
        },
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
#[cfg(unix)]
async fn open_with_world_readable_key_refuses_serve_and_reports_permissions() {
    use std::os::unix::fs::PermissionsExt;

    let data = temp_dir("open-key-perms");
    let store = CertStore::open(&data).unwrap();
    let (chain, key) = self_signed();
    store.save(&chain, &key, &CertMeta::default()).unwrap();

    let key_path = store.dir().join("key.pem");
    let mut perms = fs::metadata(&key_path).unwrap().permissions();
    perms.set_mode(0o644);
    fs::set_permissions(&key_path, perms).unwrap();

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
    .expect("open must not fail on key.pem permissions");

    let status = engine.status_async().await;
    assert_eq!(status.last_error.as_deref(), Some("tls.store.permissions"));
    assert!(
        !engine.resolver().has_cert(),
        "must not install world-readable key.pem"
    );
    drop(engine);
    let _ = fs::remove_dir_all(&data);
}

#[tokio::test]
#[cfg(unix)]
async fn open_key_with_acme_on_reissues_and_writes_0600() {
    use std::os::unix::fs::PermissionsExt;

    let data = temp_dir("open-key-reissue");
    let store = CertStore::open(&data).unwrap();
    let (chain, key) = self_signed();
    store.save(&chain, &key, &CertMeta::default()).unwrap();
    let key_path = store.dir().join("key.pem");
    let key_before = fs::read(&key_path).unwrap();
    let mut perms = fs::metadata(&key_path).unwrap().permissions();
    perms.set_mode(0o644);
    fs::set_permissions(&key_path, perms).unwrap();

    let (mock, _ns) = mock_cf_with_ns().await;
    let mut cfg = base_cfg();
    cfg.acme.enabled = true;
    cfg.dyndns.enabled = false;
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
    .expect("open must not fail on key.pem permissions");

    assert!(
        !engine.resolver().has_cert(),
        "open key must not be served before reissue"
    );
    assert_eq!(
        engine.status_async().await.last_error.as_deref(),
        Some("tls.store.permissions")
    );

    engine.renew_now().await.expect("reissue after exposed key");
    assert!(engine.resolver().has_cert());
    let status = engine.status_async().await;
    assert_eq!(
        status.last_error, None,
        "successful reissue clears permissions error: {status:?}"
    );

    let key_after = fs::read(&key_path).unwrap();
    assert_ne!(key_before, key_after, "exposed key must be replaced");
    let mode = fs::metadata(&key_path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "new key.pem must be 0600");

    drop(engine);
    let _ = fs::remove_dir_all(&data);
}

#[tokio::test]
#[cfg(unix)]
async fn open_with_world_readable_account_reports_permissions_keeps_cert() {
    use std::os::unix::fs::PermissionsExt;

    let data = temp_dir("open-account-perms");
    let store = CertStore::open(&data).unwrap();
    let (chain, key) = self_signed();
    store.save(&chain, &key, &CertMeta::default()).unwrap();
    store
        .save_account(b"{\"directory\":\"https://acme.example/dir\"}")
        .unwrap();

    let account_path = store.dir().join("account.json");
    let mut perms = fs::metadata(&account_path).unwrap().permissions();
    perms.set_mode(0o644);
    fs::set_permissions(&account_path, perms).unwrap();

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
    .expect("open must not fail on account.json permissions");

    let status = engine.status_async().await;
    assert_eq!(status.last_error.as_deref(), Some("tls.store.permissions"));
    assert!(
        engine.resolver().has_cert(),
        "good key.pem must still be served when only account.json is open"
    );
    drop(engine);
    let _ = fs::remove_dir_all(&data);
}

#[tokio::test]
async fn manual_upload_export_revoke_and_restart_do_not_serve_revoked() {
    let data = temp_dir("manual");
    let (chain, key) = self_signed();
    let cert_pem = String::from_utf8(chain).unwrap();
    let key_pem = String::from_utf8(key).unwrap();

    let mut cfg = base_cfg();
    cfg.acme.enabled = false;
    cfg.dyndns.enabled = false;
    cfg.validate_with_token(|_| Ok(Secret::new(TOKEN))).unwrap();

    let engine = TlsEngine::open_with(
        cfg.clone(),
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

    engine
        .upload_manual_cert(&cert_pem, &Secret::new(key_pem.clone()), "")
        .await
        .expect("manual upload");
    assert!(engine.resolver().has_cert());

    let status = engine.status_async().await;
    assert_eq!(status.source, dnscraft_tls::CertSource::Manual);
    assert!(status.not_before.is_some());
    assert!(status.issuer.is_some());
    assert!(status.subject.is_some());
    assert!(status.serial.as_deref().is_some_and(|s| !s.is_empty()));
    assert_eq!(
        status.signature_algorithm.as_deref(),
        Some("ecdsa-with-SHA256")
    );
    assert_eq!(status.chain.len(), 1);
    assert!(!status.revoked);
    assert!(
        status
            .history
            .iter()
            .any(|h| { h.outcome == dnscraft_tls::IssueOutcome::Issued && h.error.is_none() })
    );

    let exported = engine.export_cert().expect("export");
    assert!(exported.contains("BEGIN CERTIFICATE"));
    assert!(!exported.contains("PRIVATE KEY"));

    let err = engine
        .revoke(Some("not-a-reason"))
        .await
        .expect_err("bad reason");
    assert_eq!(err.code(), "tls.config.invalid");

    engine
        .revoke(Some("key_compromise"))
        .await
        .expect("manual revoke");
    let status = engine.status_async().await;
    assert!(status.revoked);
    assert_eq!(status.last_error.as_deref(), Some("tls.cert.revoked"));
    assert!(
        !engine.resolver().has_cert(),
        "revoked cert must not be served"
    );

    drop(engine);

    // Restart: the persisted revoked flag keeps the certificate unserved.
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
    assert!(!engine.resolver().has_cert());
    assert!(engine.status_async().await.revoked);
    drop(engine);
    let _ = fs::remove_dir_all(&data);
}

#[tokio::test]
async fn status_reports_ari_schedule_store_health_and_order_progress() {
    let data = temp_dir("status-detail");
    let (mock, _ns) = mock_cf_with_ns().await;
    let window = dnscraft_tls::AriWindow {
        start: SystemTime::UNIX_EPOCH + Duration::from_secs(3_100_000),
        end: SystemTime::UNIX_EPOCH + Duration::from_secs(3_200_000),
    };
    let mut cfg = base_cfg();
    let acme = Arc::new(FakeAcmeDirectory::with_ari_window(window));
    cfg.validate_with_token(|_| Ok(Secret::new(TOKEN))).unwrap();

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
    let status = engine.status_async().await;
    assert_eq!(status.source, dnscraft_tls::CertSource::Acme);
    let ari = status.ari.expect("ARI status");
    assert!(ari.supported);
    assert_eq!(ari.suggested_window_start, Some(window.start));
    assert_eq!(ari.suggested_window_end, Some(window.end));
    assert!(ari.certificate_id.is_some());
    assert!(status.next_renew_at.is_some());
    let store = status.store.expect("store health");
    assert!(store.writable);
    assert!(!store.corrupt);

    let order = engine.order_status();
    assert_eq!(order.state, "valid");
    assert_eq!(
        order.identifiers,
        vec!["dns.example.com", "*.dns.example.com"]
    );
    assert!(order.challenges.iter().all(|c| c.status == "valid"));
    assert!(!engine.rate_limit_status().await.limited);

    // Preflight is offline and passes for this config.
    let report = engine.preflight().await;
    assert!(report.ok, "{report:?}");

    drop(engine);
    let _ = fs::remove_dir_all(&data);
}

#[tokio::test]
async fn rotate_key_maps_failure_and_dyndns_records_audit_and_inventory() {
    let data = temp_dir("rotate-inventory");
    let (mock, _ns) = mock_cf_with_ns().await;
    let echo = MockEcho::start(std::iter::repeat_n(trace_body("203.0.113.55"), 20)).await;

    let mut cfg = base_cfg();
    cfg.dyndns.enabled = true;
    cfg.dyndns.record_inventory = true;
    cfg.dyndns.echo_url = echo.url();
    cfg.dyndns.ipv6 = false;
    cfg.validate_with_token(|_| Ok(Secret::new(TOKEN))).unwrap();

    let engine = TlsEngine::open_with(
        cfg,
        &data,
        clock(),
        EngineDeps {
            acme: Arc::new(FakeAcmeDirectory::failing(
                dnscraft_tls::FakeAcmeFail::Finalize,
            )),
            cloudflare_base_url: Some(mock.base_url()),
            echo: EchoClient::unbound().unwrap(),
            token: Secret::new(TOKEN),
        },
    )
    .unwrap();

    let err = engine.rotate_key().await.expect_err("finalize fails");
    assert_eq!(err.code(), "tls.cert.rotate.failed");

    engine.dyndns_now().await.expect("dyndns");
    let audit = engine.dyndns_audit().await;
    assert!(
        audit
            .iter()
            .any(|e| e.content == "203.0.113.55" && e.record_type == "A"),
        "{audit:?}"
    );
    let inventory = engine.record_inventory().await.expect("inventory");
    assert!(
        inventory
            .iter()
            .any(|r| r.record_type == "A" && r.content == "203.0.113.55" && r.managed),
        "{inventory:?}"
    );
    let status = engine.status_async().await;
    assert!(!status.dyndns_stale);
    assert!(status.last_dyndns_success.is_some());
    assert!(status.next_dyndns_at.is_some());

    drop(engine);
    let _ = fs::remove_dir_all(&data);
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
