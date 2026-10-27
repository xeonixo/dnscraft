//! Ignored integration tests against a local Pebble ACME server.
//!
//! See `crates/dnscraft-tls/README.md` for the `docker run` recipe.
//! Run with: `cargo test -p dnscraft-tls -- --ignored pebble`

#![allow(clippy::unwrap_used, clippy::expect_used)]

#[path = "support/mock_cloudflare.rs"]
mod mock_cloudflare;

use std::env;
use std::fs;
use std::path::PathBuf;
use std::time::Duration;

use dnscraft_proto::{Class, Message, RData, Record};
use dnscraft_tls::{
    AcmeConfig, AcmeDirectory, AcmeDirectoryKind, CertResolver, CertStore, CloudflareClient,
    CloudflareConfig, DynDnsConfig, InstantAcme, Secret, SystemClock, TlsConfig,
    challenge_txt_name, current_ari_window, issue,
};
use mock_cloudflare::{MockCloudflare, MockZone};
use tokio::net::UdpSocket;

fn temp_data_dir(label: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "dnscraft-tls-pebble-{label}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn pebble_env() -> (Vec<u8>, String) {
    let root_path = env::var("PEBBLE_ROOT_CA")
        .expect("set PEBBLE_ROOT_CA to Pebble's test CA PEM (e.g. pebble.minica.pem); see README");
    let root_pem = fs::read(&root_path).expect("read PEBBLE_ROOT_CA");
    let directory_url = env::var("PEBBLE_DIRECTORY_URL")
        .unwrap_or_else(|_| "https://localhost:14000/dir".to_owned());
    (root_pem, directory_url)
}

/// Create an account against local Pebble, persist it, and reload it.
///
/// Environment:
/// - `PEBBLE_DIRECTORY_URL` (default `https://localhost:14000/dir`)
/// - `PEBBLE_ROOT_CA` — path to Pebble's test CA PEM (required)
#[tokio::test]
#[ignore = "requires local Pebble; see crates/dnscraft-tls/README.md"]
async fn pebble_account_create_and_reload() {
    let (root_pem, directory_url) = pebble_env();

    let data = temp_data_dir("account");
    let store = CertStore::open(&data).unwrap();
    let acme = InstantAcme::with_extra_roots(&root_pem).expect("HTTP client with Pebble root");
    let cfg = AcmeConfig {
        enabled: true,
        directory: AcmeDirectoryKind::Url(directory_url),
        email: "pebble-test@example.com".into(),
        propagation_timeout: Duration::from_secs(120),
        propagation_poll: Duration::from_secs(5),
        account: dnscraft_tls::AcmeAccountConfig {
            tos_agreed: true,
            ..Default::default()
        },
    };

    acme.ensure_account(&store, &cfg)
        .await
        .expect("create account against Pebble");
    let first = store.load_account().unwrap().expect("account.json written");
    assert!(!first.is_empty());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(store.dir().join("account.json"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
    }

    // Reload via a fresh InstantAcme (simulates process restart).
    let acme2 = InstantAcme::with_extra_roots(&root_pem).unwrap();
    acme2
        .ensure_account(&store, &cfg)
        .await
        .expect("reload account from store against Pebble");
    let second = store.load_account().unwrap().unwrap();
    assert_eq!(second, first, "reload must not rewrite credentials");
    let stored: serde_json::Value = serde_json::from_slice(&second).unwrap();
    assert_eq!(stored["directory"], cfg.directory.url());

    let _ = fs::remove_dir_all(&data);
}

/// Issue a cert for `dns.example.com` + `*.dns.example.com` via Pebble + mock CF.
///
/// Requires `PEBBLE_VA_ALWAYS_VALID=1` so Pebble does not need real DNS. The
/// mock Cloudflare + loopback auth NS still satisfy our own `wait_for_txt`.
#[tokio::test]
#[ignore = "requires local Pebble; see crates/dnscraft-tls/README.md"]
async fn pebble_issue_dns_example_com() {
    let (root_pem, directory_url) = pebble_env();
    const DOMAIN: &str = "example.com";
    const TOKEN: &str = "pebble-issue-token";
    let challenge = challenge_txt_name(&format!("dns.{DOMAIN}"));

    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let ns = sock.local_addr().unwrap();
    let mock = MockCloudflare::start(
        TOKEN,
        MockZone {
            id: "zone-pebble".into(),
            name: DOMAIN.into(),
            name_servers: vec![ns.to_string()],
        },
    )
    .await;
    let mock_ns = mock.clone();
    let owner = challenge.clone();
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
            let values = mock_ns.txt_contents(&owner).await;
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

    let data = temp_data_dir("issue");
    let store = CertStore::open(&data).unwrap();
    let resolver = CertResolver::new();
    let acme = InstantAcme::with_extra_roots(&root_pem).unwrap();
    let cf = CloudflareClient::with_base_url(
        Secret::new(TOKEN),
        DOMAIN,
        &CloudflareConfig { zone_id: None },
        mock.base_url(),
    )
    .unwrap();

    let mut cfg = TlsConfig {
        public_domain: DOMAIN.into(),
        acme: AcmeConfig {
            enabled: true,
            directory: AcmeDirectoryKind::Url(directory_url),
            email: "pebble-issue@example.com".into(),
            propagation_timeout: Duration::from_secs(30),
            propagation_poll: Duration::from_secs(2),
            account: dnscraft_tls::AcmeAccountConfig {
                tos_agreed: true,
                ..Default::default()
            },
        },
        dyndns: DynDnsConfig {
            enabled: false,
            ..DynDnsConfig::default()
        },
        allow_http_for_tests: true,
        ..TlsConfig::default()
    };
    cfg.validate_with_token(|_| Ok(Secret::new(TOKEN))).unwrap();

    issue(&acme, &cf, &store, &resolver, &cfg, &SystemClock)
        .await
        .expect("Pebble issue");

    assert!(resolver.has_cert());
    let loaded = store.load().unwrap().expect("cert on disk");
    assert!(loaded.identifiers.iter().any(|i| i == "dns.example.com"));
    assert!(loaded.identifiers.iter().any(|i| i == "*.dns.example.com"));
    assert!(
        mock.txt_contents(&challenge).await.is_empty(),
        "challenge TXT cleaned up"
    );

    // Renewal: a second issue replaces the first cert (ARI `replaces`).
    let first_chain = loaded.chain_pem.clone();
    let first_leaf = resolver.leaf_der().expect("leaf installed");
    assert!(
        loaded.meta.ari_cert_id.is_some(),
        "ARI id stored in meta.json"
    );
    let window = current_ari_window(&acme, &store, &cfg.acme).await;
    assert!(window.is_some(), "Pebble advertises renewalInfo");

    issue(&acme, &cf, &store, &resolver, &cfg, &SystemClock)
        .await
        .expect("Pebble renew (order with replaces)");
    let renewed = store.load().unwrap().expect("renewed cert on disk");
    assert_ne!(
        renewed.chain_pem, first_chain,
        "renewal must mint a new cert"
    );
    assert_ne!(
        resolver.leaf_der().expect("leaf installed"),
        first_leaf,
        "resolver must serve the renewed cert"
    );
    assert_ne!(renewed.meta.ari_cert_id, loaded.meta.ari_cert_id);
    assert_eq!(store.load_state().last_error, None);

    let _ = fs::remove_dir_all(&data);
}
