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
    AcmeConfig, AcmeDirectoryKind, CertResolver, CertStore, CloudflareClient, CloudflareConfig,
    DynDnsConfig, FakeAcmeDirectory, FakeAcmeFail, KeyType, ManualClock, Secret, TlsConfig,
    TlsError, challenge_txt_name, issue,
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
