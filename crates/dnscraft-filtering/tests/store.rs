#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::field_reassign_with_default
)]

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, SystemTime};

use dnscraft_filtering::{
    ListId, ListMeta, ListSourceSpec, ListStore, ManualClock, MetaError, StoreConfig, StoreError,
};

static COUNTER: AtomicU32 = AtomicU32::new(0);

/// Unique temp dir, removed on drop.
struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let p = std::env::temp_dir().join(format!("dnscraft-store-{}-{n}", std::process::id()));
        let _ = fs::remove_dir_all(&p);
        fs::create_dir_all(&p).unwrap();
        Self(p)
    }
    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn id(s: &str) -> ListId {
    ListId::new(s).unwrap()
}

fn lists_dir(t: &TempDir) -> PathBuf {
    t.path().join("filtering/lists")
}

fn small_cap_store(t: &TempDir, max: u64) -> ListStore {
    let cfg = StoreConfig {
        max_body_bytes: max,
        ..StoreConfig::default()
    };
    ListStore::open_with(
        t.path(),
        cfg,
        Arc::new(ManualClock::new(SystemTime::UNIX_EPOCH)),
    )
    .unwrap()
}

#[test]
fn round_trip_body_and_meta() {
    let t = TempDir::new();
    let store = ListStore::open(t.path()).unwrap();
    assert_eq!(store.read_body(&id("a")).unwrap(), None);
    assert_eq!(store.read_meta(&id("a")).unwrap(), None);

    let mut meta = ListMeta::default();
    meta.source = Some("https://example.org/list.txt".into());
    meta.etag = Some("\"abc\"".into());
    meta.last_modified = Some("Wed, 01 Jan 2025 00:00:00 GMT".into());
    meta.last_attempt = Some(10);
    meta.last_success = Some(10);
    meta.http_status = Some(200);
    meta.rules_parsed = 5;
    meta.rules_skipped = 1;
    meta.last_error = Some(MetaError {
        code: "filter_fetch.timeout".into(),
        params: [("secs".to_string(), "30".to_string())].into(),
    });
    store
        .write_body(&id("a"), "||example.com^\n", &meta)
        .unwrap();
    assert_eq!(
        store.read_body(&id("a")).unwrap().unwrap(),
        "||example.com^\n"
    );
    assert_eq!(store.read_meta(&id("a")).unwrap().unwrap(), meta);

    // Reopening sees the cached data without any fetch.
    let again = ListStore::open(t.path()).unwrap();
    assert_eq!(
        again.read_body(&id("a")).unwrap().unwrap(),
        "||example.com^\n"
    );

    store.remove(&id("a")).unwrap();
    store.remove(&id("a")).unwrap();
    assert_eq!(store.read_body(&id("a")).unwrap(), None);
    assert_eq!(store.read_meta(&id("a")).unwrap(), None);
}

#[test]
fn unknown_fields_are_ignored() {
    let t = TempDir::new();
    let store = ListStore::open(t.path()).unwrap();
    fs::write(
        lists_dir(&t).join("a.meta.json"),
        r#"{"version":1,"etag":"x","future_field":{"a":1}}"#,
    )
    .unwrap();
    let meta = store.read_meta(&id("a")).unwrap().unwrap();
    assert_eq!(meta.etag.as_deref(), Some("x"));
}

#[test]
fn corrupt_and_future_meta_recover_as_none() {
    let t = TempDir::new();
    let store = ListStore::open(t.path()).unwrap();
    let dir = lists_dir(&t);
    for (name, content) in [
        ("a", "not json{{"),
        ("b", r#"{"version":2,"etag":"x"}"#),
        ("c", r#"{"etag":"x"}"#),
        ("d", ""),
    ] {
        fs::write(dir.join(format!("{name}.meta.json")), content).unwrap();
        assert_eq!(store.read_meta(&id(name)).unwrap(), None, "{name}");
    }
}

#[test]
fn failed_write_leaves_old_content_intact() {
    // Simulation: the target `<id>.txt` is occupied by a directory, so the
    // rename fails after the temp file was written. The metadata must survive
    // and no stray temp file may remain.
    let t = TempDir::new();
    let store = ListStore::open(t.path()).unwrap();
    let meta = ListMeta::default();
    store.write_meta(&id("a"), &meta).unwrap();
    fs::create_dir(lists_dir(&t).join("a.txt")).unwrap();
    let err = store.write_body(&id("a"), "new\n", &meta).unwrap_err();
    assert_eq!(err.code(), "filter_store.io");
    assert_eq!(store.read_meta(&id("a")).unwrap().unwrap(), meta);
    let stray: Vec<_> = fs::read_dir(lists_dir(&t))
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|n| n.ends_with(".tmp"))
        .collect();
    assert!(stray.is_empty(), "stray temp files: {stray:?}");
    fs::remove_dir(lists_dir(&t).join("a.txt")).unwrap();

    // A leftover `<id>.txt.tmp` from an older version or a crash is never
    // touched: temp names are unique and created exclusively.
    store.write_body(&id("a"), "old\n", &meta).unwrap();
    fs::write(lists_dir(&t).join("a.txt.tmp"), "half writ").unwrap();
    store.write_body(&id("a"), "new\n", &meta).unwrap();
    assert_eq!(store.read_body(&id("a")).unwrap().unwrap(), "new\n");
    assert_eq!(
        fs::read_to_string(lists_dir(&t).join("a.txt.tmp")).unwrap(),
        "half writ"
    );
}

#[cfg(unix)]
#[test]
fn temp_file_never_follows_a_planted_symlink() {
    let t = TempDir::new();
    let store = ListStore::open(t.path()).unwrap();
    let victim = t.path().join("victim.txt");
    fs::write(&victim, "precious").unwrap();
    std::os::unix::fs::symlink(&victim, lists_dir(&t).join("a.txt.tmp")).unwrap();
    store
        .write_body(&id("a"), "new\n", &ListMeta::default())
        .unwrap();
    assert_eq!(fs::read_to_string(&victim).unwrap(), "precious");
    assert_eq!(store.read_body(&id("a")).unwrap().unwrap(), "new\n");
}

#[cfg(unix)]
#[test]
fn written_files_are_private() {
    use std::os::unix::fs::PermissionsExt;
    let t = TempDir::new();
    let store = ListStore::open(t.path()).unwrap();
    store
        .write_body(&id("a"), "x\n", &ListMeta::default())
        .unwrap();
    for f in ["a.txt", "a.meta.json"] {
        let mode = fs::metadata(lists_dir(&t).join(f))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "{f}");
    }
}

#[test]
fn oversize_body_is_refused() {
    let t = TempDir::new();
    let store = small_cap_store(&t, 16);
    let meta = ListMeta::default();

    // Refused on write.
    let err = store
        .write_body(&id("a"), &"x".repeat(17), &meta)
        .unwrap_err();
    assert!(matches!(err, StoreError::TooLarge { .. }));
    assert_eq!(err.code(), "filter_store.too_large");
    assert_eq!(store.read_body(&id("a")).unwrap(), None);

    // Refused on read (tampered data dir).
    fs::write(lists_dir(&t).join("b.txt"), "y".repeat(17)).unwrap();
    let err = store.read_body(&id("b")).unwrap_err();
    assert_eq!(err.code(), "filter_store.too_large");

    // Exactly at the cap is fine.
    store.write_body(&id("c"), &"z".repeat(16), &meta).unwrap();
    assert_eq!(store.read_body(&id("c")).unwrap().unwrap().len(), 16);
}

#[test]
fn list_ids_are_enumerated() {
    let t = TempDir::new();
    let store = ListStore::open(t.path()).unwrap();
    assert!(store.list_ids().unwrap().is_empty());
    let meta = ListMeta::default();
    store.write_body(&id("beta"), "x", &meta).unwrap();
    store.write_body(&id("alpha"), "x", &meta).unwrap();
    store.write_meta(&id("meta-only"), &meta).unwrap();
    fs::write(lists_dir(&t).join("Bad Name.txt"), "x").unwrap();
    fs::write(lists_dir(&t).join("alpha.txt.tmp"), "x").unwrap();
    let ids: Vec<String> = store
        .list_ids()
        .unwrap()
        .iter()
        .map(ToString::to_string)
        .collect();
    assert_eq!(ids, ["alpha", "beta", "meta-only"]);
}

#[cfg(unix)]
#[test]
fn directories_are_private() {
    use std::os::unix::fs::PermissionsExt;
    let t = TempDir::new();
    let data = t.path().join("fresh");
    let store = ListStore::open(&data).unwrap();
    for d in [
        data.join("filtering"),
        data.join("filtering/lists"),
        store.services_dir().to_path_buf(),
    ] {
        let mode = fs::metadata(&d).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700, "{}", d.display());
    }
}

#[test]
fn file_source_is_read_directly_and_capped() {
    let t = TempDir::new();
    let store = small_cap_store(&t, 32);
    let file = t.path().join("local.txt");
    fs::write(&file, "||local.example^\n").unwrap();
    assert_eq!(store.read_file_source(&file).unwrap(), "||local.example^\n");
    // Never copied into the store.
    assert!(store.list_ids().unwrap().is_empty());

    fs::write(&file, "x".repeat(33)).unwrap();
    assert_eq!(
        store.read_file_source(&file).unwrap_err().code(),
        "filter_store.too_large"
    );
    let missing = t.path().join("missing.txt");
    assert_eq!(
        store.read_file_source(&missing).unwrap_err().code(),
        "filter_store.io"
    );
}

#[test]
fn source_validation_is_https_only_with_test_hatch() {
    let strict = StoreConfig::default();
    let lax = StoreConfig {
        allow_http_for_tests: true,
        ..StoreConfig::default()
    };
    let url = |s: &str| ListSourceSpec::Url(s.to_string());

    assert!(url("https://example.org/a.txt").validate(&strict).is_ok());
    assert!(url("HTTPS://example.org/a.txt").validate(&strict).is_ok());
    for bad in [
        "http://example.org/a",
        "ftp://x/a",
        "example.org/a",
        "file:///etc/x",
        "",
    ] {
        let err = url(bad).validate(&strict).unwrap_err();
        assert_eq!(err.code(), "filter_store.invalid_source", "{bad}");
    }
    assert!(url("https://").validate(&strict).is_err());
    assert!(url("https:///path").validate(&strict).is_err());
    assert!(url("https://a b/").validate(&strict).is_err());

    assert!(url("http://127.0.0.1:8080/a").validate(&lax).is_ok());
    assert!(url("ftp://x/a").validate(&lax).is_err());

    assert!(
        ListSourceSpec::File("/tmp/x.txt".into())
            .validate(&strict)
            .is_ok()
    );
    assert!(
        ListSourceSpec::File(PathBuf::new())
            .validate(&strict)
            .is_err()
    );
}

#[test]
fn clock_is_injected() {
    let t = TempDir::new();
    let clock = Arc::new(ManualClock::new(
        SystemTime::UNIX_EPOCH + Duration::from_secs(1000),
    ));
    let store = ListStore::open_with(t.path(), StoreConfig::default(), clock.clone()).unwrap();
    assert_eq!(store.now_unix(), 1000);
    clock.advance(Duration::from_secs(5));
    assert_eq!(store.now_unix(), 1005);
}
