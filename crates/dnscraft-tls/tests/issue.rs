//! Full issuance flow against Fake ACME + mock Cloudflare + loopback auth NS.

#![allow(clippy::unwrap_used, clippy::expect_used)]

#[path = "support/mock_cloudflare.rs"]
mod mock_cloudflare;

use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime};

static TEMP_SEQ: AtomicU64 = AtomicU64::new(0);

use dnscraft_proto::{Class, Message, RData, Record};
use dnscraft_tls::{
    AcmeConfig, AcmeDirectoryKind, AriWindow, CertResolver, CertStore, Clock, CloudflareClient,
    CloudflareConfig, DEFAULT_EXPIRY_WARN, DynDnsConfig, FakeAcmeDirectory, FakeAcmeFail, KeyType,
    ManualClock, Secret, TlsConfig, TlsError, TlsStatus, ari_certificate_id, challenge_txt_name,
    current_ari_window, issue, plan_renewal,
};
use mock_cloudflare::{MockCloudflare, MockZone};
use tokio::net::UdpSocket;

const TOKEN: &str = "issue-test-token";
const DOMAIN: &str = "example.com";
const ZONE_ID: &str = "zone-example";

struct Env {
    data: PathBuf,
    store: CertStore,
    resolver: CertResolver,
    cf: CloudflareClient,
    mock: MockCloudflare,
    clock: Arc<ManualClock>,
    cfg: TlsConfig,
}

fn temp_dir(label: &str) -> PathBuf {
    let n = TEMP_SEQ.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!(
        "dnscraft-tls-issue-{label}-{}-{n}",
        std::process::id(),
    ));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn new_clock() -> Arc<ManualClock> {
    Arc::new(ManualClock::new(
        SystemTime::UNIX_EPOCH + Duration::from_secs(2_000_000),
    ))
}

async fn setup(key_type: KeyType, prop_timeout: Duration) -> Env {
    let challenge = challenge_txt_name(&format!("dns.{DOMAIN}"));
    let data = temp_dir("setup");

    // Bind auth NS first so its address can go into the Cloudflare zone fixture.
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
            let values = mock_ns.txt_contents(&challenge).await;
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

    let store = CertStore::open(&data).unwrap();
    let resolver = CertResolver::new();
    let cf = CloudflareClient::with_base_url(
        Secret::new(TOKEN),
        DOMAIN,
        &CloudflareConfig { zone_id: None },
        mock.base_url(),
    )
    .unwrap();

    let mut cfg = TlsConfig {
        public_domain: DOMAIN.into(),
        key_type,
        acme: AcmeConfig {
            enabled: true,
            directory: AcmeDirectoryKind::Staging,
            email: "admin@example.com".into(),
            propagation_timeout: prop_timeout,
            propagation_poll: Duration::from_secs(5),
        },
        cloudflare: CloudflareConfig { zone_id: None },
        dyndns: DynDnsConfig {
            enabled: false,
            ..DynDnsConfig::default()
        },
        allow_http_for_tests: true,
        ..TlsConfig::default()
    };
    cfg.validate_with_token(|_| Ok(Secret::new(TOKEN))).unwrap();

    Env {
        data,
        store,
        resolver,
        cf,
        mock,
        clock: new_clock(),
        cfg,
    }
}

async fn drive_clock(clock: &ManualClock, poll: Duration, steps: u32) {
    for _ in 0..steps {
        tokio::task::yield_now().await;
        tokio::time::sleep(Duration::from_millis(30)).await;
        clock.advance(poll);
    }
}

async fn issue_with_clock_drive(acme: &FakeAcmeDirectory, env: &Env) -> Result<(), TlsError> {
    let clk = env.clock.clone();
    let driver = {
        let c = clk.clone();
        tokio::spawn(async move {
            drive_clock(&c, Duration::from_secs(5), 10).await;
        })
    };
    let result = issue(
        acme,
        &env.cf,
        &env.store,
        &env.resolver,
        &env.cfg,
        clk.as_ref(),
    )
    .await;
    driver.abort();
    result
}

fn leaf_curve(chain_pem: &[u8]) -> &'static str {
    let (_, pem) = x509_parser::pem::parse_x509_pem(chain_pem).expect("pem");
    let cert = pem.parse_x509().expect("x509");
    let params = cert
        .public_key()
        .algorithm
        .parameters
        .as_ref()
        .and_then(|p| p.as_oid().ok())
        .map(|o| o.to_id_string())
        .unwrap_or_default();
    // secp384r1 = 1.3.132.0.34, secp256r1 = 1.2.840.10045.3.1.7
    if params == "1.3.132.0.34" {
        "p384"
    } else {
        "p256"
    }
}

#[tokio::test]
async fn issue_fake_stores_installs_and_deletes_txt() {
    let env = setup(KeyType::EcdsaP256, Duration::from_secs(60)).await;
    let challenge = challenge_txt_name(&format!("dns.{DOMAIN}"));

    issue_with_clock_drive(&FakeAcmeDirectory::new(), &env)
        .await
        .expect("issue");

    assert!(env.resolver.has_cert());
    let loaded = env.store.load().unwrap().expect("cert on disk");
    assert!(
        loaded.identifiers.iter().any(|i| i == "dns.example.com")
            && loaded.identifiers.iter().any(|i| i == "*.dns.example.com")
    );
    let left = env.mock.txt_contents(&challenge).await;
    assert!(left.is_empty(), "TXT must be deleted: {left:?}");
    let _ = fs::remove_dir_all(&env.data);
}

#[tokio::test]
async fn issue_honours_p384_key_type() {
    let env = setup(KeyType::EcdsaP384, Duration::from_secs(60)).await;
    issue_with_clock_drive(&FakeAcmeDirectory::new(), &env)
        .await
        .unwrap();
    let loaded = env.store.load().unwrap().unwrap();
    assert_eq!(leaf_curve(&loaded.chain_pem), "p384");
    let _ = fs::remove_dir_all(&env.data);
}

#[tokio::test]
async fn failure_at_challenge_keeps_previous_cert() {
    let env = setup(KeyType::EcdsaP256, Duration::from_secs(60)).await;
    issue_with_clock_drive(&FakeAcmeDirectory::new(), &env)
        .await
        .unwrap();
    let before = env.store.load().unwrap().unwrap().chain_pem;

    let env2_clock = new_clock();
    let driver = {
        let c = env2_clock.clone();
        tokio::spawn(async move {
            drive_clock(&c, Duration::from_secs(5), 10).await;
        })
    };
    let err = issue(
        &FakeAcmeDirectory::failing(FakeAcmeFail::Challenge),
        &env.cf,
        &env.store,
        &env.resolver,
        &env.cfg,
        env2_clock.as_ref(),
    )
    .await
    .unwrap_err();
    driver.abort();

    assert_eq!(err.code(), "tls.acme.challenge");
    assert_eq!(env.store.load().unwrap().unwrap().chain_pem, before);
    assert!(env.resolver.has_cert());
    let _ = fs::remove_dir_all(&env.data);
}

#[tokio::test]
async fn failure_at_finalize_keeps_previous_cert() {
    let env = setup(KeyType::EcdsaP256, Duration::from_secs(60)).await;
    issue_with_clock_drive(&FakeAcmeDirectory::new(), &env)
        .await
        .unwrap();
    let before = env.store.load().unwrap().unwrap().chain_pem;

    let clk = new_clock();
    let driver = {
        let c = clk.clone();
        tokio::spawn(async move {
            drive_clock(&c, Duration::from_secs(5), 10).await;
        })
    };
    let err = issue(
        &FakeAcmeDirectory::failing(FakeAcmeFail::Finalize),
        &env.cf,
        &env.store,
        &env.resolver,
        &env.cfg,
        clk.as_ref(),
    )
    .await
    .unwrap_err();
    driver.abort();

    assert_eq!(err.code(), "tls.acme.order");
    assert_eq!(env.store.load().unwrap().unwrap().chain_pem, before);
    let _ = fs::remove_dir_all(&env.data);
}

#[tokio::test]
async fn failure_at_propagation_keeps_previous_cert() {
    let env = setup(KeyType::EcdsaP256, Duration::from_secs(60)).await;
    issue_with_clock_drive(&FakeAcmeDirectory::new(), &env)
        .await
        .unwrap();
    let before = env.store.load().unwrap().unwrap().chain_pem;

    // New mock whose NS never answers → wait_for_txt times out.
    let dead = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let dead_addr = dead.local_addr().unwrap();
    let mock2 = MockCloudflare::start(
        TOKEN,
        MockZone {
            id: ZONE_ID.into(),
            name: DOMAIN.into(),
            name_servers: vec![dead_addr.to_string()],
        },
    )
    .await;
    let cf2 = CloudflareClient::with_base_url(
        Secret::new(TOKEN),
        DOMAIN,
        &CloudflareConfig { zone_id: None },
        mock2.base_url(),
    )
    .unwrap();
    let mut cfg = env.cfg.clone();
    cfg.acme.propagation_timeout = Duration::from_secs(10);
    cfg.acme.propagation_poll = Duration::from_secs(5);

    let clk = new_clock();
    let driver = {
        let c = clk.clone();
        tokio::spawn(async move {
            drive_clock(&c, Duration::from_secs(5), 6).await;
        })
    };
    let err = issue(
        &FakeAcmeDirectory::new(),
        &cf2,
        &env.store,
        &env.resolver,
        &cfg,
        clk.as_ref(),
    )
    .await
    .unwrap_err();
    driver.abort();

    assert_eq!(err.code(), "tls.acme.propagation");
    assert!(matches!(err, TlsError::AcmePropagation));
    assert_eq!(env.store.load().unwrap().unwrap().chain_pem, before);
    drop(dead);
    let _ = fs::remove_dir_all(&env.data);
}

fn leaf_der_of(chain_pem: &[u8]) -> Vec<u8> {
    let (_, pem) = x509_parser::pem::parse_x509_pem(chain_pem).expect("pem");
    pem.contents
}

fn unix(t: SystemTime) -> u64 {
    t.duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs()
}

fn status_of(env: &Env, now: SystemTime) -> TlsStatus {
    TlsStatus::from_cert(
        env.store.load().unwrap().as_ref(),
        &env.store.load_state(),
        now,
        DEFAULT_EXPIRY_WARN,
        &AcmeDirectoryKind::Staging,
        true,
    )
}

#[tokio::test]
async fn renewal_installs_new_cert_and_passes_replaces() {
    let env = setup(KeyType::EcdsaP256, Duration::from_secs(60)).await;
    let acme = FakeAcmeDirectory::new();

    issue_with_clock_drive(&acme, &env).await.unwrap();
    let first = env.store.load().unwrap().unwrap();
    let first_id = ari_certificate_id(&first.chain_pem).expect("fake cert has an AKI");
    assert_eq!(first.meta.ari_cert_id.as_deref(), Some(first_id.as_str()));
    assert_eq!(env.resolver.leaf_der(), Some(leaf_der_of(&first.chain_pem)));

    issue_with_clock_drive(&acme, &env).await.unwrap();
    let second = env.store.load().unwrap().unwrap();

    // New cert (new key + serial) on disk and in the resolver.
    assert_ne!(second.chain_pem, first.chain_pem);
    assert_ne!(second.key.as_bytes(), first.key.as_bytes());
    assert_ne!(second.meta.ari_cert_id, first.meta.ari_cert_id);
    assert_eq!(
        env.resolver.leaf_der(),
        Some(leaf_der_of(&second.chain_pem))
    );

    // First order has nothing to replace; the renewal replaces the first cert.
    assert_eq!(acme.replaces_log(), vec![None, Some(first_id)]);
    let _ = fs::remove_dir_all(&env.data);
}

#[tokio::test]
async fn failed_renewal_records_stable_code_and_success_clears_it() {
    let env = setup(KeyType::EcdsaP256, Duration::from_secs(60)).await;
    issue_with_clock_drive(&FakeAcmeDirectory::new(), &env)
        .await
        .unwrap();
    let good = env.store.load().unwrap().unwrap();
    let st = status_of(&env, env.clock.now());
    assert_eq!(st.last_error, None);
    assert!(st.last_issue.is_some());
    assert!(st.last_renew_attempt.is_some());
    let issued_at = st.last_issue.unwrap();

    // Failed renewal: old cert stays on disk and in the resolver.
    let err = issue_with_clock_drive(&FakeAcmeDirectory::failing(FakeAcmeFail::Finalize), &env)
        .await
        .unwrap_err();
    assert_eq!(err.code(), "tls.acme.order");
    let after = env.store.load().unwrap().unwrap();
    assert_eq!(after.chain_pem, good.chain_pem);
    assert_eq!(after.key.as_bytes(), good.key.as_bytes());
    assert_eq!(env.resolver.leaf_der(), Some(leaf_der_of(&good.chain_pem)));
    let st = status_of(&env, env.clock.now());
    assert_eq!(st.last_error.as_deref(), Some("tls.acme.order"));
    assert_eq!(
        st.last_issue,
        Some(issued_at),
        "last_issue only moves on success"
    );
    assert!(st.last_renew_attempt.unwrap() >= issued_at);
    // Never the message, only the code.
    let state_json = fs::read_to_string(env.store.dir().join("state.json")).unwrap();
    assert!(!state_json.contains("fake finalize failure"));

    // Successful renewal clears the error and moves last_issue forward.
    env.clock.advance(Duration::from_secs(3600));
    issue_with_clock_drive(&FakeAcmeDirectory::new(), &env)
        .await
        .unwrap();
    let st = status_of(&env, env.clock.now());
    assert_eq!(st.last_error, None);
    assert!(st.last_issue.unwrap() > issued_at);
    let _ = fs::remove_dir_all(&env.data);
}

#[tokio::test]
async fn first_issuance_failure_is_recorded_without_a_cert() {
    let env = setup(KeyType::EcdsaP256, Duration::from_secs(60)).await;
    let err = issue_with_clock_drive(&FakeAcmeDirectory::failing(FakeAcmeFail::Challenge), &env)
        .await
        .unwrap_err();
    assert_eq!(err.code(), "tls.acme.challenge");

    assert!(env.store.load().unwrap().is_none());
    assert!(!env.resolver.has_cert());
    let st = status_of(&env, env.clock.now());
    assert_eq!(st.last_error.as_deref(), Some("tls.acme.challenge"));
    assert!(st.last_renew_attempt.is_some());
    assert_eq!(st.last_issue, None);
    assert!(st.not_after.is_none());
    let _ = fs::remove_dir_all(&env.data);
}

#[tokio::test]
async fn stale_challenge_txt_is_deleted_before_new_ones_are_created() {
    let env = setup(KeyType::EcdsaP256, Duration::from_secs(60)).await;
    let challenge = challenge_txt_name(&format!("dns.{DOMAIN}"));
    let stale = env
        .cf
        .create_txt(&challenge, "stale-orphan-value", 120)
        .await
        .unwrap();
    // Setup traffic (zone lookup + seed) is not part of the ordering we check.
    let seeded = env.mock.requests().await.len();

    issue_with_clock_drive(&FakeAcmeDirectory::new(), &env)
        .await
        .unwrap();

    assert!(
        env.mock.records().await.is_empty(),
        "stale and fresh TXT must all be gone"
    );
    let log = env.mock.requests().await;
    let log = &log[seeded..];
    let delete_stale = log
        .iter()
        .position(|r| r.method == "DELETE" && r.path.ends_with(&format!("/{}", stale.id)))
        .expect("stale record deleted");
    let first_create = log
        .iter()
        .position(|r| r.method == "POST" && r.path.ends_with("/dns_records"))
        .expect("new TXT created");
    assert!(
        delete_stale < first_create,
        "orphan cleanup must precede creation: delete@{delete_stale} create@{first_create}"
    );
    let _ = fs::remove_dir_all(&env.data);
}

#[tokio::test]
async fn ari_window_from_ca_drives_the_schedule() {
    let env = setup(KeyType::EcdsaP256, Duration::from_secs(60)).await;
    let now = env.clock.now();
    let window = AriWindow {
        start: now + Duration::from_secs(86_400),
        end: now + Duration::from_secs(2 * 86_400),
    };
    let acme = FakeAcmeDirectory::with_ari_window(window);

    // No cert yet: issue immediately, no ARI lookup.
    assert_eq!(plan_renewal(&acme, &env.store, &env.cfg, now).await, now);
    assert_eq!(
        current_ari_window(&acme, &env.store, &env.cfg.acme).await,
        None
    );

    issue_with_clock_drive(&acme, &env).await.unwrap();
    let now = env.clock.now();
    assert_eq!(
        current_ari_window(&acme, &env.store, &env.cfg.acme).await,
        Some(window)
    );
    let due = plan_renewal(&acme, &env.store, &env.cfg, now).await;
    assert!(
        due >= window.start && due <= window.end,
        "due {} outside ARI window",
        unix(due)
    );

    // CA without ARI: fall back to not_after - renew_before.
    let no_ari = FakeAcmeDirectory::new();
    let loaded = env.store.load().unwrap().unwrap();
    let due = plan_renewal(&no_ari, &env.store, &env.cfg, now).await;
    assert_eq!(due, loaded.not_after - env.cfg.renew_before);
    let _ = fs::remove_dir_all(&env.data);
}
