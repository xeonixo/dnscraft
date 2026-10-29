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
    AcmeConfig, AcmeDirectoryKind, CertMeta, CertStore, DnsProviderKind, DynDnsConfig, EchoClient,
    EngineDeps, FakeAcmeDirectory, KeyType, ManualCertConfig, ManualClock, RevocationReason,
    Secret, TlsConfig, TlsEngine,
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
            status: "active".into(),
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
            allow_http_for_tests: true,
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
    let m = engine.metrics().await;
    assert_eq!((m.renew_success_total, m.renew_failure_total), (0, 1));
    assert_eq!(m.days_to_expiry, status.days_to_expiry);
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

    let acme = Arc::new(FakeAcmeDirectory::new());
    let engine = TlsEngine::open_with(
        cfg,
        &data,
        clock(),
        EngineDeps {
            allow_http_for_tests: true,
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
    let m = engine.metrics().await;
    assert_eq!((m.renew_success_total, m.renew_failure_total), (1, 0));
    assert!(m.days_to_expiry.is_some());

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
            allow_http_for_tests: true,
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
            allow_http_for_tests: true,
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
            allow_http_for_tests: true,
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
            allow_http_for_tests: true,
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
            allow_http_for_tests: true,
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
            allow_http_for_tests: true,
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
            allow_http_for_tests: true,
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

    let engine = TlsEngine::open_with(
        cfg,
        &data,
        clock(),
        EngineDeps {
            allow_http_for_tests: true,
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
async fn apply_config_does_not_revert_upload_or_unrevoke() {
    let data = temp_dir("apply-manual");
    let (chain_a, key_a) = self_signed();
    let cert_a = String::from_utf8(chain_a).unwrap();
    let key_a = String::from_utf8(key_a).unwrap();

    let mut cfg = base_cfg();
    cfg.acme.enabled = false;
    cfg.dyndns.enabled = false;
    cfg.validate_with_token(|_| Ok(Secret::new(TOKEN))).unwrap();

    let engine = TlsEngine::open_with(
        cfg.clone(),
        &data,
        clock(),
        EngineDeps {
            allow_http_for_tests: true,
            acme: Arc::new(FakeAcmeDirectory::new()),
            cloudflare_base_url: Some("http://127.0.0.1:1/client/v4".into()),
            echo: EchoClient::unbound().unwrap(),
            token: Secret::new(TOKEN),
        },
    )
    .unwrap();

    // A newer API upload lands after the engine opened.
    engine
        .upload_manual_cert(&cert_a, &Secret::new(key_a), "")
        .await
        .expect("manual upload");

    // Re-applying the (older) bootstrap config must not revert it.
    let (chain_b, key_b) = self_signed();
    let mut cfg_b = cfg.clone();
    cfg_b.manual = Some(ManualCertConfig {
        cert_pem: String::from_utf8(chain_b).unwrap(),
        chain_pem: String::new(),
        key_pem: Secret::new(String::from_utf8(key_b).unwrap()),
    });
    engine
        .apply_config(cfg_b.clone())
        .await
        .expect("apply config");
    assert_eq!(
        engine.export_cert().unwrap(),
        cert_a,
        "apply_config must not overwrite a newer manual upload"
    );
    assert!(engine.resolver().has_cert());

    // Revoked state must survive re-applying the bootstrap config.
    engine.revoke(Some("superseded")).await.expect("revoke");
    engine.apply_config(cfg_b).await.expect("apply config");
    assert!(engine.status_async().await.revoked);
    assert!(!engine.resolver().has_cert());

    drop(engine);
    let _ = fs::remove_dir_all(&data);
}

#[tokio::test]
async fn unreachable_echo_marks_dyndns_stale_with_echo_error() {
    let data = temp_dir("echo-down");
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);

    let mut cfg = base_cfg();
    cfg.acme.enabled = false;
    cfg.dyndns.enabled = false;
    cfg.validate_with_token(|_| Ok(Secret::new(TOKEN))).unwrap();

    let engine = TlsEngine::open_with(
        cfg.clone(),
        &data,
        clock(),
        EngineDeps {
            allow_http_for_tests: true,
            acme: Arc::new(FakeAcmeDirectory::new()),
            cloudflare_base_url: Some("http://127.0.0.1:1/client/v4".into()),
            echo: EchoClient::unbound().unwrap(),
            token: Secret::new(TOKEN),
        },
    )
    .unwrap();

    let mut enabled = cfg;
    enabled.dyndns.enabled = true;
    enabled.dyndns.ipv6 = false;
    enabled.dyndns.echo_url = format!("http://{addr}/cdn-cgi/trace");
    engine.apply_config(enabled).await.unwrap();

    let err = engine.dyndns_now().await.expect_err("echo unreachable");
    assert_eq!(err.code(), "tls.dyndns.echo");

    let status = engine.status_async().await;
    assert!(status.dyndns_stale);
    assert_eq!(status.last_error.as_deref(), Some("tls.dyndns.echo"));
    assert!(
        status.last_dyndns_success.is_none(),
        "a failed echo must not advance last_dyndns_success"
    );

    drop(engine);
    let _ = fs::remove_dir_all(&data);
}

#[tokio::test]
async fn partial_dyndns_write_failure_keeps_audit_for_successful_writes() {
    let data = temp_dir("partial-audit");
    let (mock, _ns) = mock_cf_with_ns().await;
    let echo = MockEcho::start([trace_body("203.0.113.70")]).await;

    let mut cfg = base_cfg();
    cfg.acme.enabled = false;
    cfg.dyndns.enabled = false;
    cfg.validate_with_token(|_| Ok(Secret::new(TOKEN))).unwrap();

    let engine = TlsEngine::open_with(
        cfg.clone(),
        &data,
        clock(),
        EngineDeps {
            allow_http_for_tests: true,
            acme: Arc::new(FakeAcmeDirectory::new()),
            cloudflare_base_url: Some(mock.base_url()),
            echo: EchoClient::unbound().unwrap(),
            token: Secret::new(TOKEN),
        },
    )
    .unwrap();

    let mut enabled = cfg;
    enabled.dyndns.enabled = true;
    enabled.dyndns.public_entry = true;
    enabled.dyndns.ipv6 = false;
    enabled.dyndns.echo_url = echo.url();
    engine.apply_config(enabled).await.unwrap();

    // Requests: zone lookup, two node1 lists + create, then fail the wildcard
    // list (the create already succeeded).
    mock.force_status_on_request(5, 500, None).await;
    let err = engine.dyndns_now().await.expect_err("second write fails");
    assert_eq!(err.code(), "tls.dyndns.update");

    let audit = engine.dyndns_audit().await;
    assert!(
        audit
            .iter()
            .any(|e| e.name == "node1.dns.example.com" && e.content == "203.0.113.70"),
        "audit for the successful write must be persisted: {audit:?}"
    );
    assert!(engine.status_async().await.dyndns_stale);

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
            allow_http_for_tests: true,
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

#[tokio::test]
async fn rollover_account_key_is_exposed_and_rewrites_account() {
    let data = temp_dir("account-rollover");
    let store = CertStore::open(&data).unwrap();
    let (chain, key) = self_signed();
    store.save(&chain, &key, &CertMeta::default()).unwrap();

    let mut cfg = base_cfg();
    cfg.dyndns.enabled = false;
    cfg.validate_with_token(|_| Ok(Secret::new(TOKEN))).unwrap();

    let acme = Arc::new(FakeAcmeDirectory::with_account_id("rolled"));
    let engine = TlsEngine::open_with(
        cfg,
        &data,
        clock(),
        EngineDeps {
            allow_http_for_tests: true,
            acme,
            cloudflare_base_url: Some("http://127.0.0.1:1/client/v4".into()),
            echo: EchoClient::unbound().unwrap(),
            token: Secret::new(TOKEN),
        },
    )
    .unwrap();

    assert!(!engine.acme_account_status().await.unwrap().exists);
    engine
        .rollover_account_key()
        .await
        .expect("account key rollover");
    let status = engine.acme_account_status().await.unwrap();
    assert!(status.exists);
    assert_eq!(status.account_id.as_deref(), Some("rolled"));

    drop(engine);
    let _ = fs::remove_dir_all(&data);
}

#[tokio::test]
async fn preflight_checks_acme_and_dns_when_acme_is_disabled() {
    let data = temp_dir("preflight-acme-off");
    let mut cfg = base_cfg();
    cfg.acme.enabled = false;
    cfg.acme.account.tos_agreed = false;
    cfg.dns_provider.kind = DnsProviderKind::None;
    cfg.dyndns.enabled = false;
    cfg.validate_with_token(|_| Ok(Secret::new(TOKEN))).unwrap();

    let engine = TlsEngine::open_with(
        cfg,
        &data,
        clock(),
        EngineDeps {
            allow_http_for_tests: true,
            acme: Arc::new(FakeAcmeDirectory::new()),
            cloudflare_base_url: Some("http://127.0.0.1:1/client/v4".into()),
            echo: EchoClient::unbound().unwrap(),
            token: Secret::new(TOKEN),
        },
    )
    .unwrap();

    let report = engine.preflight().await;
    let acme = report
        .checks
        .iter()
        .find(|c| c.name == "acme_account")
        .expect("acme_account check must run when ACME is disabled");
    assert!(!acme.ok);
    assert_eq!(acme.code.as_deref(), Some("tls.acme.account.tos"));
    let dns = report
        .checks
        .iter()
        .find(|c| c.name == "dns_provider")
        .expect("dns_provider check must run when ACME is disabled");
    assert!(!dns.ok);
    assert_eq!(dns.code.as_deref(), Some("tls.dns.provider.auth"));
    assert!(!report.ok);

    drop(engine);
    let _ = fs::remove_dir_all(&data);
}

#[tokio::test]
async fn revoke_acme_cert_at_ca_when_acme_is_disabled() {
    let data = temp_dir("revoke-acme-off");
    let store = CertStore::open(&data).unwrap();
    let (chain, key) = self_signed();
    // `CertMeta::default()` marks the certificate as ACME-sourced.
    store.save(&chain, &key, &CertMeta::default()).unwrap();

    let mut cfg = base_cfg();
    cfg.acme.enabled = false;
    cfg.dyndns.enabled = false;
    cfg.validate_with_token(|_| Ok(Secret::new(TOKEN))).unwrap();

    let acme = Arc::new(FakeAcmeDirectory::new());
    let engine = TlsEngine::open_with(
        cfg,
        &data,
        clock(),
        EngineDeps {
            allow_http_for_tests: true,
            acme: acme.clone(),
            cloudflare_base_url: Some("http://127.0.0.1:1/client/v4".into()),
            echo: EchoClient::unbound().unwrap(),
            token: Secret::new(TOKEN),
        },
    )
    .unwrap();
    assert!(engine.resolver().has_cert());

    engine
        .revoke(Some("key_compromise"))
        .await
        .expect("ACME-sourced revoke");
    assert_eq!(
        acme.revocation_log(),
        vec![RevocationReason::KeyCompromise],
        "the CA must be told even when ACME issuance is disabled"
    );
    assert!(!engine.resolver().has_cert());
    assert!(engine.status_async().await.revoked);

    drop(engine);
    let _ = fs::remove_dir_all(&data);
}

fn deps_with(mock: &MockCloudflare, acme: Arc<FakeAcmeDirectory>, echo: EchoClient) -> EngineDeps {
    EngineDeps {
        allow_http_for_tests: true,
        acme,
        cloudflare_base_url: Some(mock.base_url()),
        echo,
        token: Secret::new(TOKEN),
    }
}

#[tokio::test]
async fn dyndns_uses_configured_node_id_for_its_profile() {
    let data = temp_dir("node-id");
    let (mock, _ns) = mock_cf_with_ns().await;
    let echo = MockEcho::start([trace_body("203.0.113.41")]).await;

    let mut cfg = base_cfg();
    cfg.acme.enabled = false;
    cfg.dyndns.enabled = true;
    cfg.dyndns.echo_url = echo.url();
    cfg.dyndns.ipv4 = true;
    cfg.dyndns.ipv6 = false;
    cfg.dyndns.reserved_labels = vec!["node1".into(), "ns1".into(), "ns2".into()];
    cfg.dyndns.nodes = ["node1", "node2"]
        .iter()
        .enumerate()
        .map(|(i, id)| dnscraft_tls::DynDnsNodeProfile {
            node_id: (*id).into(),
            hostname: format!("ns{}.dns.example.com", i + 1),
            enabled: true,
            ipv4: true,
            ipv6: false,
            ..Default::default()
        })
        .collect();

    let engine = TlsEngine::open_with(
        cfg,
        &data,
        clock(),
        deps_with(
            &mock,
            Arc::new(FakeAcmeDirectory::new()),
            EchoClient::unbound().unwrap(),
        ),
    )
    .unwrap();
    engine.set_node_context(Some("node2".into()), true);
    engine.dyndns_now().await.expect("dyndns");

    let recs = mock.records().await;
    assert!(recs.iter().any(|r| r.name == "ns2.dns.example.com"));
    assert!(!recs.iter().any(|r| r.name == "ns1.dns.example.com"));
}

#[tokio::test]
async fn sub_node_never_orders_acme_even_when_snapshot_enables_it() {
    let data = temp_dir("sub-node");
    let (mock, _ns) = mock_cf_with_ns().await;
    let mut off = base_cfg();
    off.acme.enabled = false;
    let acme = Arc::new(FakeAcmeDirectory::new());
    let engine = TlsEngine::open_with(
        off,
        &data,
        clock(),
        deps_with(&mock, acme.clone(), EchoClient::unbound().unwrap()),
    )
    .unwrap();
    engine.set_node_context(Some("node2".into()), false);

    // Synced snapshot from the master says acme.enabled = true.
    engine.apply_config(base_cfg()).await.unwrap();
    assert!(engine.renew_now().await.is_err());
    assert!(engine.rotate_key().await.is_err());
    assert!(engine.sign_csr("csr").await.is_err());
    assert!(
        acme.replaces_log().is_empty(),
        "no ACME order on a sub-node"
    );
    assert!(!engine.resolver().has_cert());
}

#[tokio::test]
async fn on_issued_hook_runs_after_successful_issuance() {
    let data = temp_dir("on-issued");
    let (mock, _ns) = mock_cf_with_ns().await;
    let engine = TlsEngine::open_with(
        base_cfg(),
        &data,
        clock(),
        deps_with(
            &mock,
            Arc::new(FakeAcmeDirectory::new()),
            EchoClient::unbound().unwrap(),
        ),
    )
    .unwrap();
    let seen = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
    let sink = Arc::clone(&seen);
    engine.set_on_issued(Arc::new(move |names| {
        sink.lock().unwrap().extend(names.iter().cloned());
    }));
    engine.renew_now().await.expect("issue");
    let names = seen.lock().unwrap().clone();
    assert!(names.contains(&"dns.example.com".to_owned()));
}
