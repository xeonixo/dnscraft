#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::field_reassign_with_default
)]

#[path = "support/http.rs"]
mod http;

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, SystemTime};

use dnscraft_filtering::{
    FetchError, FetchOutcome, Fetcher, FetcherConfig, ListId, ListMeta, ListSourceSpec, ListStore,
    ManualClock, StoreConfig,
};
use http::{Route, TestServer};

static COUNTER: AtomicU32 = AtomicU32::new(0);

struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let p = std::env::temp_dir().join(format!("dnscraft-fetch-{}-{n}", std::process::id()));
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

struct Env {
    _dir: TempDir,
    store: ListStore,
    fetcher: Fetcher,
    clock: Arc<ManualClock>,
}

fn env_with(max: u64, timeout: Duration) -> Env {
    let dir = TempDir::new();
    let clock = Arc::new(ManualClock::new(
        SystemTime::UNIX_EPOCH + Duration::from_secs(1_000),
    ));
    let mut cfg = StoreConfig::default();
    cfg.allow_http_for_tests = true;
    cfg.max_body_bytes = max;
    let store = ListStore::open_with(dir.path(), cfg, clock.clone()).unwrap();
    let mut fc = FetcherConfig::default();
    fc.timeout = timeout;
    let fetcher = Fetcher::with_config(&store, fc).unwrap();
    Env {
        _dir: dir,
        store,
        fetcher,
        clock,
    }
}

fn env() -> Env {
    env_with(1024 * 1024, Duration::from_secs(10))
}

fn id() -> ListId {
    ListId::new("list-a").unwrap()
}

fn url(s: &TestServer, p: &str) -> ListSourceSpec {
    ListSourceSpec::Url(s.url(p))
}

fn failed(o: FetchOutcome) -> (ListMeta, FetchError) {
    match o {
        FetchOutcome::Failed { meta, error } => (meta, error),
        other => panic!("expected Failed, got {other:?}"),
    }
}

fn gzip(data: &[u8]) -> Vec<u8> {
    let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    enc.write_all(data).unwrap();
    enc.finish().unwrap()
}

#[tokio::test]
async fn ok_200_updates_and_stores() {
    let e = env();
    let srv = TestServer::start(vec![(
        "/l.txt",
        Route::ok("||ads.example^\n")
            .etag("\"v1\"")
            .header("Last-Modified", "Wed, 01 Jan 2025 00:00:00 GMT"),
    )])
    .await;
    let out = e
        .fetcher
        .fetch_and_store(&e.store, &id(), &url(&srv, "/l.txt"))
        .await;
    let FetchOutcome::Updated { body, meta } = out else {
        panic!("expected Updated");
    };
    assert_eq!(body, "||ads.example^\n");
    assert_eq!(meta.etag.as_deref(), Some("\"v1\""));
    assert_eq!(meta.http_status, Some(200));
    assert_eq!(meta.last_attempt, Some(1000));
    assert_eq!(meta.last_success, Some(1000));
    assert!(meta.last_error.is_none());
    assert_eq!(e.store.read_body(&id()).unwrap().unwrap(), body);
    assert_eq!(e.store.read_meta(&id()).unwrap().unwrap(), meta);
    let ua = &srv.requests()[0].headers["user-agent"];
    assert!(ua.starts_with("DNScraft/") && ua.contains("github.com/xeonixo/dnscraft"));
}

#[tokio::test]
async fn not_modified_304_keeps_body_and_sends_conditional_headers() {
    let e = env();
    let srv = TestServer::start(vec![(
        "/l.txt",
        Route::ok("||ads.example^\n")
            .etag("\"v1\"")
            .header("Last-Modified", "Wed, 01 Jan 2025 00:00:00 GMT"),
    )])
    .await;
    let src = url(&srv, "/l.txt");
    e.fetcher.fetch_and_store(&e.store, &id(), &src).await;
    e.clock.advance(Duration::from_secs(60));
    let out = e.fetcher.fetch_and_store(&e.store, &id(), &src).await;
    let FetchOutcome::NotModified { meta } = out else {
        panic!("expected NotModified, got {out:?}");
    };
    assert_eq!(meta.http_status, Some(304));
    assert_eq!(meta.last_attempt, Some(1060));
    assert_eq!(meta.last_success, Some(1060));
    assert_eq!(meta.etag.as_deref(), Some("\"v1\""));
    assert_eq!(
        e.store.read_body(&id()).unwrap().unwrap(),
        "||ads.example^\n"
    );
    let second = &srv.requests()[1].headers;
    assert_eq!(second["if-none-match"], "\"v1\"");
    assert_eq!(second["if-modified-since"], "Wed, 01 Jan 2025 00:00:00 GMT");
    assert!(!srv.requests()[0].headers.contains_key("if-none-match"));
}

#[tokio::test]
async fn http_404_fails_and_keeps_last_good_body() {
    let e = env();
    let srv = TestServer::start(vec![("/l.txt", Route::ok("good\n"))]).await;
    e.fetcher
        .fetch_and_store(&e.store, &id(), &url(&srv, "/l.txt"))
        .await;
    e.clock.advance(Duration::from_secs(10));
    let out = e
        .fetcher
        .fetch_and_store(&e.store, &id(), &url(&srv, "/missing"))
        .await;
    let (meta, error) = failed(out);
    assert_eq!(error, FetchError::HttpStatus(404));
    assert_eq!(error.code(), "filter_fetch.http_status");
    assert_eq!(meta.http_status, Some(404));
    let me = e
        .store
        .read_meta(&id())
        .unwrap()
        .unwrap()
        .last_error
        .unwrap();
    assert_eq!(me.code, "filter_fetch.http_status");
    assert_eq!(me.params["status"], "404");
    assert_eq!(meta.last_attempt, Some(1010));
    assert_eq!(meta.last_success, Some(1000));
    assert_eq!(e.store.read_body(&id()).unwrap().unwrap(), "good\n");
}

#[tokio::test]
async fn oversize_content_length_aborts_immediately() {
    let e = env_with(1000, Duration::from_secs(10));
    let srv = TestServer::start(vec![("/big", Route::ok(vec![b'a'; 5000]))]).await;
    let (meta, error) = failed(e.fetcher.fetch(&id(), &url(&srv, "/big"), None).await);
    assert_eq!(error, FetchError::TooLarge { max: 1000 });
    assert_eq!(error.code(), "filter_fetch.too_large");
    assert_eq!(meta.last_error.unwrap().code, "filter_fetch.too_large");
}

#[tokio::test]
async fn oversize_chunked_stream_aborts_early() {
    let e = env_with(100 * 1024, Duration::from_secs(10));
    let total = 20 * 1024 * 1024;
    let srv = TestServer::start(vec![(
        "/s",
        Route::ok("").stream(total, 64 * 1024, Duration::from_millis(5)),
    )])
    .await;
    let (_, error) = failed(e.fetcher.fetch(&id(), &url(&srv, "/s"), None).await);
    assert_eq!(error, FetchError::TooLarge { max: 100 * 1024 });
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(
        srv.bytes_sent() < 2 * 1024 * 1024,
        "server wrote {} bytes",
        srv.bytes_sent()
    );
}

#[tokio::test]
async fn slow_server_times_out() {
    let e = env_with(1024 * 1024, Duration::from_millis(300));
    let srv = TestServer::start(vec![(
        "/slow",
        Route::ok("abcdefghij").chunked(1, Duration::from_millis(200)),
    )])
    .await;
    let (_, error) = failed(e.fetcher.fetch(&id(), &url(&srv, "/slow"), None).await);
    assert_eq!(error, FetchError::Timeout);
    assert_eq!(error.code(), "filter_fetch.timeout");
}

#[tokio::test]
async fn connect_failure_is_reported() {
    let e = env();
    // Bind and drop to get a port nobody listens on.
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    drop(l);
    let src = ListSourceSpec::Url(format!("http://{addr}/x"));
    let (_, error) = failed(e.fetcher.fetch(&id(), &src, None).await);
    assert_eq!(error.code(), "filter_fetch.connect");
}

#[tokio::test]
async fn redirect_to_non_https_target_is_refused() {
    let e = env();
    for target in [
        "ftp://example.invalid/l.txt",
        "http://example.invalid/l.txt",
    ] {
        let srv = TestServer::start(vec![("/r", Route::redirect(target))]).await;
        let (_, error) = failed(e.fetcher.fetch(&id(), &url(&srv, "/r"), None).await);
        assert_eq!(error.code(), "filter_fetch.redirect_refused", "{target}");
    }
}

#[tokio::test]
async fn redirect_to_loopback_http_is_followed_with_test_hatch() {
    let e = env();
    let srv = TestServer::start(vec![
        ("/a", Route::redirect("/b")),
        ("/b", Route::ok("hello\n")),
    ])
    .await;
    let out = e.fetcher.fetch(&id(), &url(&srv, "/a"), None).await;
    assert!(matches!(out, FetchOutcome::Updated { .. }), "{out:?}");
}

#[tokio::test]
async fn five_redirects_ok_six_too_many() {
    let e = env();
    let mut routes: Vec<(String, Route)> = (0..6)
        .map(|i| (format!("/r{i}"), Route::redirect(&format!("/r{}", i + 1))))
        .collect();
    routes.push(("/r6".into(), Route::redirect("/end")));
    routes.push(("/end".into(), Route::ok("done\n")));
    let srv = TestServer::start(
        routes
            .iter()
            .map(|(p, r)| (p.as_str(), r.clone()))
            .collect(),
    )
    .await;

    // /r1 -> ... -> /r6 -> /end is 6 redirects.
    let (_, error) = failed(e.fetcher.fetch(&id(), &url(&srv, "/r1"), None).await);
    assert_eq!(error, FetchError::TooManyRedirects);
    assert_eq!(error.code(), "filter_fetch.too_many_redirects");

    // /r2 -> ... -> /end is exactly 5 redirects.
    let out = e.fetcher.fetch(&id(), &url(&srv, "/r2"), None).await;
    assert!(matches!(out, FetchOutcome::Updated { .. }), "{out:?}");
}

#[tokio::test]
async fn binary_body_is_not_text() {
    let e = env();
    let mut with_nul = b"||a.example^\n".to_vec();
    with_nul.push(0);
    let garbage: Vec<u8> = (0..400).map(|i| 0x80 | (i % 0x7f) as u8).collect();
    let srv = TestServer::start(vec![
        ("/nul", Route::ok(with_nul)),
        ("/bin", Route::ok(garbage)),
    ])
    .await;
    for p in ["/nul", "/bin"] {
        let (_, error) = failed(e.fetcher.fetch(&id(), &url(&srv, p), None).await);
        assert_eq!(error, FetchError::NotText, "{p}");
        assert_eq!(error.code(), "filter_fetch.not_text");
    }
}

#[tokio::test]
async fn invalid_utf8_is_converted_lossily() {
    let e = env();
    let mut body = "||ads.example^\n".repeat(50).into_bytes();
    body.extend_from_slice(b"# caf\xe9\n");
    let srv = TestServer::start(vec![("/l", Route::ok(body))]).await;
    let out = e.fetcher.fetch(&id(), &url(&srv, "/l"), None).await;
    let FetchOutcome::Updated { body, .. } = out else {
        panic!("expected Updated, got {out:?}");
    };
    assert!(body.contains("caf\u{FFFD}"));
}

#[tokio::test]
async fn gzip_body_is_decoded() {
    let e = env();
    let text = "||ads.example^\n".repeat(10);
    let srv = TestServer::start(vec![(
        "/z",
        Route::ok(gzip(text.as_bytes())).header("Content-Encoding", "gzip"),
    )])
    .await;
    let out = e.fetcher.fetch(&id(), &url(&srv, "/z"), None).await;
    let FetchOutcome::Updated { body, .. } = out else {
        panic!("expected Updated, got {out:?}");
    };
    assert_eq!(body, text);
}

#[tokio::test]
async fn gzip_decompressed_size_counts_against_cap() {
    let e = env_with(100 * 1024, Duration::from_secs(10));
    let bomb = gzip(&vec![b'a'; 4 * 1024 * 1024]);
    assert!(bomb.len() < 100 * 1024, "fixture must be small compressed");
    let srv = TestServer::start(vec![(
        "/bomb",
        Route::ok(bomb).header("Content-Encoding", "gzip"),
    )])
    .await;
    let (_, error) = failed(e.fetcher.fetch(&id(), &url(&srv, "/bomb"), None).await);
    assert_eq!(error, FetchError::TooLarge { max: 100 * 1024 });
}

#[tokio::test]
async fn file_source_changed_and_unchanged() {
    let e = env();
    let path = e.store.services_dir().join("local.txt");
    fs::write(&path, "||one.example^\n").unwrap();
    let src = ListSourceSpec::File(path.clone());

    let out = e.fetcher.fetch(&id(), &src, None).await;
    let FetchOutcome::Updated { body, meta } = out else {
        panic!("expected Updated");
    };
    assert_eq!(body, "||one.example^\n");
    assert_eq!(meta.last_success, Some(1000));
    assert_eq!(meta.http_status, None);

    let out = e.fetcher.fetch(&id(), &src, Some(&meta)).await;
    assert!(matches!(out, FetchOutcome::NotModified { .. }), "{out:?}");

    fs::write(&path, "||two.example^\n").unwrap();
    let out = e.fetcher.fetch(&id(), &src, Some(&meta)).await;
    assert!(matches!(out, FetchOutcome::Updated { .. }), "{out:?}");

    fs::remove_file(&path).unwrap();
    let (_, error) = failed(e.fetcher.fetch(&id(), &src, Some(&meta)).await);
    assert_eq!(error.code(), "filter_fetch.io");
}

#[tokio::test]
async fn http_url_rejected_without_test_hatch() {
    let dir = TempDir::new();
    let store = ListStore::open(dir.path()).unwrap();
    let fetcher = Fetcher::new(&store).unwrap();
    let src = ListSourceSpec::Url("http://127.0.0.1:1/x".into());
    let (_, error) = failed(fetcher.fetch(&id(), &src, None).await);
    assert_eq!(error.code(), "filter_fetch.io");
}
