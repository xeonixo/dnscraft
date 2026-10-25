//! ACME account persistence (fake directory; no network).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::time::Duration;

use dnscraft_tls::{
    AcmeConfig, AcmeDirectory, AcmeDirectoryKind, CertStore, FakeAcmeDirectory, KeyType, TlsConfig,
};

fn temp_data_dir(label: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "dnscraft-tls-acme-{label}-{}-{}",
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

fn acme_cfg() -> AcmeConfig {
    AcmeConfig {
        enabled: true,
        directory: AcmeDirectoryKind::Staging,
        email: "admin@example.com".into(),
        propagation_timeout: Duration::from_secs(120),
        propagation_poll: Duration::from_secs(5),
    }
}

#[tokio::test]
async fn acme_fake_credentials_persisted_0600_and_reloaded() {
    let data = temp_data_dir("fake");
    let store = CertStore::open(&data).unwrap();
    let fake = FakeAcmeDirectory {
        account_id: "acct-test".into(),
    };
    let cfg = acme_cfg();

    assert!(store.load_account().unwrap().is_none());
    fake.ensure_account(&store, &cfg).await.unwrap();

    let path = store.dir().join("account.json");
    assert!(path.exists());
    #[cfg(unix)]
    {
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }
    let first = store.load_account().unwrap().unwrap();
    let v: serde_json::Value = serde_json::from_slice(&first).unwrap();
    assert_eq!(v["id"], "acct-test");
    assert_eq!(v["directory"], AcmeDirectoryKind::Staging.url());

    // Second call must not overwrite (reload path).
    let fake2 = FakeAcmeDirectory {
        account_id: "should-not-write".into(),
    };
    fake2.ensure_account(&store, &cfg).await.unwrap();
    let second = store.load_account().unwrap().unwrap();
    assert_eq!(second, first);

    let _ = fs::remove_dir_all(&data);
}

#[tokio::test]
async fn acme_fake_rewrites_account_when_directory_changes() {
    let data = temp_data_dir("dirchange");
    let store = CertStore::open(&data).unwrap();
    let mut cfg = acme_cfg();

    FakeAcmeDirectory {
        account_id: "staging-acct".into(),
    }
    .ensure_account(&store, &cfg)
    .await
    .unwrap();
    let staging = store.load_account().unwrap().unwrap();

    cfg.directory = AcmeDirectoryKind::Production;
    FakeAcmeDirectory {
        account_id: "prod-acct".into(),
    }
    .ensure_account(&store, &cfg)
    .await
    .unwrap();
    let prod = store.load_account().unwrap().unwrap();
    assert_ne!(prod, staging);
    let v: serde_json::Value = serde_json::from_slice(&prod).unwrap();
    assert_eq!(v["id"], "prod-acct");
    assert_eq!(v["directory"], AcmeDirectoryKind::Production.url());

    // A legacy file without a directory field is also replaced.
    store.save_account(br#"{"id":"legacy"}"#).unwrap();
    FakeAcmeDirectory::default()
        .ensure_account(&store, &cfg)
        .await
        .unwrap();
    let v: serde_json::Value =
        serde_json::from_slice(&store.load_account().unwrap().unwrap()).unwrap();
    assert_eq!(v["id"], "fake");

    let _ = fs::remove_dir_all(&data);
}

#[tokio::test]
async fn acme_fake_skips_when_disabled() {
    let data = temp_data_dir("disabled");
    let store = CertStore::open(&data).unwrap();
    let mut cfg = acme_cfg();
    cfg.enabled = false;
    FakeAcmeDirectory::default()
        .ensure_account(&store, &cfg)
        .await
        .unwrap();
    assert!(store.load_account().unwrap().is_none());
    let _ = fs::remove_dir_all(&data);
}

#[test]
fn acme_directory_kind_urls() {
    assert!(
        AcmeDirectoryKind::Production
            .url()
            .contains("acme-v02.api.letsencrypt.org")
    );
    assert!(
        AcmeDirectoryKind::Staging
            .url()
            .contains("acme-staging-v02")
    );
    let custom = AcmeDirectoryKind::Url("https://acme.example.com/directory".into());
    assert_eq!(custom.url(), "https://acme.example.com/directory");
}

#[test]
fn acme_config_in_tls_defaults() {
    let cfg = TlsConfig {
        key_type: KeyType::EcdsaP256,
        ..TlsConfig::default()
    };
    assert!(cfg.acme.enabled);
    assert_eq!(cfg.acme.directory, AcmeDirectoryKind::Production);
}
