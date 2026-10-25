//! Ignored integration test against a local Pebble ACME server.
//!
//! See `crates/dnscraft-tls/README.md` for the `docker run` recipe.
//! Run with: `cargo test -p dnscraft-tls -- --ignored pebble`

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::env;
use std::fs;
use std::path::PathBuf;
use std::time::Duration;

use dnscraft_tls::{AcmeConfig, AcmeDirectory, AcmeDirectoryKind, CertStore, InstantAcme};

fn temp_data_dir() -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "dnscraft-tls-pebble-{}-{}",
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

/// Create an account against local Pebble, persist it, and reload it.
///
/// Environment:
/// - `PEBBLE_DIRECTORY_URL` (default `https://localhost:14000/dir`)
/// - `PEBBLE_ROOT_CA` — path to Pebble's test CA PEM (required)
#[tokio::test]
#[ignore = "requires local Pebble; see crates/dnscraft-tls/README.md"]
async fn pebble_account_create_and_reload() {
    let root_path = env::var("PEBBLE_ROOT_CA")
        .expect("set PEBBLE_ROOT_CA to Pebble's test CA PEM (e.g. pebble.minica.pem); see README");
    let root_pem = fs::read(&root_path).expect("read PEBBLE_ROOT_CA");
    let directory_url = env::var("PEBBLE_DIRECTORY_URL")
        .unwrap_or_else(|_| "https://localhost:14000/dir".to_owned());

    let data = temp_data_dir();
    let store = CertStore::open(&data).unwrap();
    let acme = InstantAcme::with_extra_roots(&root_pem).expect("HTTP client with Pebble root");
    let cfg = AcmeConfig {
        enabled: true,
        directory: AcmeDirectoryKind::Url(directory_url),
        email: "pebble-test@example.com".into(),
        propagation_timeout: Duration::from_secs(120),
        propagation_poll: Duration::from_secs(5),
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

    let _ = fs::remove_dir_all(&data);
}
