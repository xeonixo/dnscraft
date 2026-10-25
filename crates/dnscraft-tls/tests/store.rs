//! Certificate store round-trip, modes, and corrupt-PEM behaviour.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

use dnscraft_tls::{CertMeta, CertResolver, CertStore, KeyPem, TlsError};
use rcgen::generate_simple_self_signed;

fn temp_data_dir(label: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "dnscraft-tls-store-{label}-{}-{}",
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

fn self_signed(sans: &[&str]) -> (Vec<u8>, Vec<u8>) {
    let names: Vec<String> = sans.iter().map(|s| (*s).to_owned()).collect();
    let certified = generate_simple_self_signed(names).unwrap();
    (
        certified.cert.pem().into_bytes(),
        certified.signing_key.serialize_pem().into_bytes(),
    )
}

#[test]
fn store_round_trip_save_load_and_modes() {
    let data = temp_data_dir("roundtrip");
    let store = CertStore::open(&data).unwrap();

    #[cfg(unix)]
    {
        let mode = fs::metadata(store.dir()).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700);
    }

    let (chain, key) = self_signed(&["dns.example.com", "*.dns.example.com"]);
    store
        .save(&chain, &key, &CertMeta::default())
        .expect("save");

    #[cfg(unix)]
    for name in ["cert.pem", "key.pem", "meta.json"] {
        let path = store.dir().join(name);
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "{name}");
    }

    let loaded = store.load().unwrap().expect("loaded");
    assert_eq!(loaded.chain_pem, chain);
    assert_eq!(loaded.key.as_bytes(), key.as_slice());
    assert!(
        loaded
            .identifiers
            .iter()
            .any(|i| i == "dns.example.com" || i == "*.dns.example.com")
    );
    assert!(loaded.not_after > std::time::SystemTime::UNIX_EPOCH);

    // Account round trip.
    store.save_account(b"{\"account\":true}").unwrap();
    assert_eq!(
        store.load_account().unwrap().as_deref(),
        Some(br#"{"account":true}"#.as_slice())
    );

    let _ = fs::remove_dir_all(&data);
}

#[test]
fn store_open_tightens_wide_directory_mode() {
    let data = temp_data_dir("chmod");
    let tls = data.join("tls");
    fs::create_dir_all(&tls).unwrap();
    #[cfg(unix)]
    {
        let mut perms = fs::metadata(&tls).unwrap().permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&tls, perms).unwrap();
    }
    let store = CertStore::open(&data).unwrap();
    #[cfg(unix)]
    {
        let mode = fs::metadata(store.dir()).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700);
    }
    let _ = fs::remove_dir_all(&data);
}

#[test]
fn store_corrupt_pem_keeps_files_and_old_resolver_cert() {
    let data = temp_data_dir("corrupt");
    let store = CertStore::open(&data).unwrap();
    let resolver = CertResolver::new();

    let (chain_a, key_a) = self_signed(&["dns.example.com"]);
    store.save(&chain_a, &key_a, &CertMeta::default()).unwrap();
    resolver.install(&chain_a, &key_a).unwrap();
    assert!(resolver.has_cert());

    // Corrupt on disk.
    fs::write(store.dir().join("cert.pem"), b"NOT A PEM").unwrap();
    let err = store.load().expect_err("corrupt");
    assert_eq!(err.code(), "tls.store.corrupt");
    // Files kept.
    assert!(store.dir().join("cert.pem").exists());
    assert!(store.dir().join("key.pem").exists());
    // Resolver still has A.
    assert!(resolver.has_cert());

    // Corrupt import must not replace A.
    let err = resolver.import(&store, b"bad", b"bad").expect_err("import");
    assert_eq!(err.code(), "tls.store.corrupt");
    assert!(resolver.has_cert());

    let _ = fs::remove_dir_all(&data);
}

#[test]
fn store_key_pem_never_in_debug_display() {
    let (_, key_bytes) = self_signed(&["dns.example.com"]);
    let key = KeyPem::parse(&key_bytes).unwrap();
    let shown = format!("{key:?} {key}");
    assert!(!shown.contains("BEGIN"));
    assert!(!shown.contains("PRIVATE"));
    assert!(key_bytes.windows(5).any(|w| w == b"BEGIN"));

    let data = temp_data_dir("debug");
    let store = CertStore::open(&data).unwrap();
    let (chain, key_b) = self_signed(&["dns.example.com"]);
    store.save(&chain, &key_b, &CertMeta::default()).unwrap();
    let loaded = store.load().unwrap().unwrap();
    let shown = format!("{loaded:?}");
    assert!(!shown.contains("BEGIN PRIVATE"));
    assert!(!shown.contains("BEGIN EC"));

    let resolver = CertResolver::new();
    resolver.install(&chain, &key_b).unwrap();
    let shown = format!("{resolver:?}");
    assert!(!shown.contains("BEGIN"));

    // Error paths must not echo key material.
    let err = TlsError::StoreCorrupt {
        message: "x".into(),
    };
    assert!(!format!("{err:?}").contains("BEGIN PRIVATE"));

    let _ = fs::remove_dir_all(&data);
}

#[test]
fn store_import_persists_and_installs() {
    let data = temp_data_dir("import");
    let store = CertStore::open(&data).unwrap();
    let resolver = CertResolver::new();
    let (chain, key) = self_signed(&["dns.example.com"]);
    resolver.import(&store, &chain, &key).unwrap();
    assert!(resolver.has_cert());
    let loaded = store.load().unwrap().unwrap();
    assert_eq!(loaded.chain_pem, chain);
    let _ = fs::remove_dir_all(&data);
}

#[test]
fn store_empty_load_is_none() {
    let data = temp_data_dir("empty");
    let store = CertStore::open(&data).unwrap();
    assert!(store.load().unwrap().is_none());
    let _ = fs::remove_dir_all(&data);
}

#[test]
fn store_save_rejects_mismatched_key_without_touching_disk() {
    let data = temp_data_dir("save-mismatch");
    let store = CertStore::open(&data).unwrap();
    let (chain_a, key_a) = self_signed(&["dns.example.com"]);
    let (_chain_b, key_b) = self_signed(&["dns.example.com"]);
    store.save(&chain_a, &key_a, &CertMeta::default()).unwrap();
    let cert_before = fs::read(store.dir().join("cert.pem")).unwrap();
    let key_before = fs::read(store.dir().join("key.pem")).unwrap();
    let meta_before = fs::read(store.dir().join("meta.json")).unwrap();

    let err = store
        .save(&chain_a, &key_b, &CertMeta::default())
        .expect_err("mismatched key");
    assert_eq!(err.code(), "tls.store.corrupt");
    assert!(!format!("{err} {err:?}").contains("PRIVATE"));

    assert_eq!(fs::read(store.dir().join("cert.pem")).unwrap(), cert_before);
    assert_eq!(fs::read(store.dir().join("key.pem")).unwrap(), key_before);
    assert_eq!(
        fs::read(store.dir().join("meta.json")).unwrap(),
        meta_before
    );

    let _ = fs::remove_dir_all(&data);
}

#[test]
fn store_load_rejects_mismatched_pair_and_keeps_files() {
    let data = temp_data_dir("load-mismatch");
    let store = CertStore::open(&data).unwrap();
    let (chain_a, _key_a) = self_signed(&["dns.example.com"]);
    let (_chain_b, key_b) = self_signed(&["dns.example.com"]);
    // Simulates a crash between the cert and key writes of a save.
    fs::write(store.dir().join("cert.pem"), &chain_a).unwrap();
    fs::write(store.dir().join("key.pem"), &key_b).unwrap();

    let err = store.load().expect_err("mismatched pair");
    assert_eq!(err.code(), "tls.store.corrupt");
    assert!(!format!("{err} {err:?}").contains("PRIVATE"));
    assert!(store.dir().join("cert.pem").exists());
    assert!(store.dir().join("key.pem").exists());

    let _ = fs::remove_dir_all(&data);
}
