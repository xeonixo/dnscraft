//! Task D1b: reliable reloads, catalog keep-last-good, scheduler lifecycle.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::field_reassign_with_default
)]

#[path = "support/http.rs"]
mod http;

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, SystemTime};

use dnscraft_filtering::{
    DomainName, FilterConfig, FilterEngine, FilterSetConfig, ListConfig, ListId, ListSelection,
    ListSourceSpec, ListStore, ManualClock, SERVICES_I18N_STEM, SERVICES_STEM, ServiceCatalog,
    ServicesFetchKind, ServicesUrls, SetId, StoreConfig, Verdict, seed_services_cache,
};
use http::{Route, TestServer};

static COUNTER: AtomicU32 = AtomicU32::new(0);

struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let p = std::env::temp_dir().join(format!(
            "dnscraft-reliability-{tag}-{}-{n}",
            std::process::id()
        ));
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

fn lid(s: &str) -> ListId {
    ListId::new(s).unwrap()
}
fn sid(s: &str) -> SetId {
    SetId::new(s).unwrap()
}
fn dn(s: &str) -> DomainName {
    s.parse().unwrap()
}
fn t0() -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(1_000)
}

fn store_in(dir: &TempDir, clock: &Arc<ManualClock>) -> ListStore {
    let mut sc = StoreConfig::default();
    sc.allow_http_for_tests = true;
    ListStore::open_with(dir.path(), sc, clock.clone()).unwrap()
}

fn list_url(id: &str, url: String) -> ListConfig {
    ListConfig {
        id: lid(id),
        name: id.to_owned(),
        source: ListSourceSpec::Url(url),
        enabled: true,
    }
}

fn set_with(id: &str, lists: &[&str]) -> FilterSetConfig {
    let mut s = FilterSetConfig::new(sid(id), id);
    s.lists = lists.iter().map(|l| lid(l)).collect();
    s
}

fn config(lists: Vec<ListConfig>, sets: Vec<FilterSetConfig>, secs: u64) -> FilterConfig {
    FilterConfig {
        lists,
        sets,
        update_interval: Duration::from_secs(secs),
        ..FilterConfig::default()
    }
}

fn blocked(eng: &FilterEngine, set: &str, name: &str) -> bool {
    matches!(
        eng.match_name(&sid(set), &dn(name), 1, t0()).unwrap(),
        Verdict::Blocked(_)
    )
}

fn services_urls(server: &TestServer) -> ServicesUrls {
    ServicesUrls {
        services: server.url("/services.json"),
        i18n: server.url("/services_i18n.json"),
    }
}

const GOOD_SERVICES: &str = r#"{
  "blocked_services": [
    {"id": "acmechat", "name": "Acme Chat", "group": "messenger",
     "icon_svg": "<svg/>", "rules": ["||chat.acme.test^"]}
  ],
  "groups": [{"id": "messenger"}]
}"#;

fn service_set() -> FilterSetConfig {
    let mut s = FilterSetConfig::new(sid("s"), "s");
    s.services = vec!["acmechat".into()];
    s
}

// ---- 1. apply_config failure ------------------------------------------------

#[tokio::test]
async fn failed_apply_config_returns_err_and_keeps_old_state() {
    let dir = TempDir::new("badcfg");
    let clock = Arc::new(ManualClock::new(t0()));
    let store = store_in(&dir, &clock);
    let server = TestServer::start(vec![("/a.txt", Route::ok("||ads.example^\n"))]).await;
    let good = config(
        vec![list_url("a", server.url("/a.txt"))],
        vec![set_with("default", &["a"])],
        3600,
    );
    let eng = FilterEngine::open_without_scheduler(good.clone(), store, clock).unwrap();
    eng.set_services_urls(services_urls(&server)).unwrap();
    eng.update_lists(ListSelection::All).await;
    assert!(blocked(&eng, "default", "ads.example"));

    // Unknown list.
    let bad = config(
        good.lists.clone(),
        vec![set_with("default", &["nope"])],
        7200,
    );
    let err = eng.apply_config(bad).await.unwrap_err();
    assert_eq!(err.code(), "filter_engine.build_failed");

    // Duplicate set id.
    let dup = config(
        good.lists.clone(),
        vec![set_with("default", &["a"]), set_with("default", &["a"])],
        7200,
    );
    let err = eng.apply_config(dup).await.unwrap_err();
    assert_eq!(err.code(), "filter_engine.build_failed");

    // Old snapshot and old config keep serving.
    assert!(blocked(&eng, "default", "ads.example"));
    assert_eq!(eng.update_interval(), Duration::from_secs(3600));

    // The next update still works against the last good config.
    let server2 = TestServer::start(vec![(
        "/a.txt",
        Route::ok("||ads.example^\n||more.example^\n"),
    )])
    .await;
    let mut next = good.clone();
    next.lists = vec![list_url("a", server2.url("/a.txt"))];
    eng.apply_config(next).await.unwrap();
    eng.update_lists(ListSelection::All).await;
    assert!(blocked(&eng, "default", "more.example"));
}

// ---- 2. cancellation --------------------------------------------------------

#[tokio::test]
async fn cancelled_apply_config_does_not_wedge_engine() {
    let dir = TempDir::new("cancel");
    let clock = Arc::new(ManualClock::new(t0()));
    let store = store_in(&dir, &clock);
    let cfg = config(vec![], vec![set_with("default", &[])], 3600);
    let eng = FilterEngine::open_without_scheduler(cfg.clone(), store, clock).unwrap();

    eng.set_build_delay_for_tests(Duration::from_millis(600));
    let cancelled =
        tokio::time::timeout(Duration::from_millis(50), eng.apply_config(cfg.clone())).await;
    assert!(cancelled.is_err(), "build should still be running");

    eng.set_build_delay_for_tests(Duration::ZERO);
    let second = tokio::time::timeout(Duration::from_secs(10), eng.apply_config(cfg)).await;
    assert!(
        matches!(second, Ok(Ok(_))),
        "engine wedged after cancellation: {second:?}"
    );
}

// ---- 3. services catalog ----------------------------------------------------

#[tokio::test]
async fn malformed_services_update_keeps_cache_across_restart() {
    let dir = TempDir::new("restart");
    let clock = Arc::new(ManualClock::new(t0()));
    let store = store_in(&dir, &clock);
    seed_services_cache(&store, SERVICES_STEM, GOOD_SERVICES).unwrap();
    seed_services_cache(&store, SERVICES_I18N_STEM, "{}").unwrap();
    let cfg = config(vec![], vec![service_set()], 3600);
    let eng =
        FilterEngine::open_without_scheduler(cfg.clone(), store.clone(), clock.clone()).unwrap();

    let server = TestServer::start(vec![
        (
            "/services.json",
            Route::ok("{ not a catalog").etag("\"bad\""),
        ),
        ("/services_i18n.json", Route::ok("{}")),
    ])
    .await;
    eng.set_services_urls(services_urls(&server)).unwrap();
    let report = eng.update_services().await;
    assert_eq!(report.error_code, Some("filter_services.malformed"));
    assert_eq!(eng.services_last_error(), Some("filter_services.malformed"));
    drop(eng);

    // The bad ETag must not have been stored.
    let meta = store.read_services_meta(SERVICES_STEM).unwrap().unwrap();
    assert_ne!(meta.etag.as_deref(), Some("\"bad\""));

    // Restart from the same store.
    let eng2 = FilterEngine::open_without_scheduler(cfg, store, clock).unwrap();
    assert!(eng2.services().is_some(), "catalog lost after restart");
    assert!(blocked(&eng2, "s", "chat.acme.test"));
}

#[tokio::test]
async fn unchanged_services_catalog_does_not_rebuild_snapshot() {
    let dir = TempDir::new("norebuild");
    let clock = Arc::new(ManualClock::new(t0()));
    let store = store_in(&dir, &clock);
    let cfg = config(vec![], vec![service_set()], 3600);
    let eng = FilterEngine::open_without_scheduler(cfg, store, clock).unwrap();
    let server = TestServer::start(vec![
        ("/services.json", Route::ok(GOOD_SERVICES).etag("\"v1\"")),
        ("/services_i18n.json", Route::ok("{}").etag("\"i1\"")),
    ])
    .await;
    eng.set_services_urls(services_urls(&server)).unwrap();

    let before = eng.snapshot();
    let r1 = eng.update_services().await;
    assert_eq!(r1.services_fetch, ServicesFetchKind::Updated);
    let after_first = eng.snapshot();
    assert!(!Arc::ptr_eq(&before, &after_first), "first update rebuilds");
    assert!(blocked(&eng, "s", "chat.acme.test"));

    let r2 = eng.update_services().await;
    assert_eq!(r2.services_fetch, ServicesFetchKind::NotModified);
    assert!(
        Arc::ptr_eq(&after_first, &eng.snapshot()),
        "304 must not rebuild"
    );
}

#[tokio::test]
async fn oversized_services_body_is_refused_by_dedicated_cap() {
    let dir = TempDir::new("svccap");
    let clock = Arc::new(ManualClock::new(t0()));
    let store = store_in(&dir, &clock);
    let cfg = config(vec![], vec![service_set()], 3600);
    let eng = FilterEngine::open_without_scheduler(cfg, store, clock).unwrap();
    // 5 MiB: under the 64 MiB list cap, over the 4 MiB services cap.
    let server = TestServer::start(vec![
        (
            "/services.json",
            Route::ok(GOOD_SERVICES).stream(5 * 1024 * 1024, 64 * 1024, Duration::ZERO),
        ),
        ("/services_i18n.json", Route::ok("{}")),
    ])
    .await;
    eng.set_services_urls(services_urls(&server)).unwrap();
    let report = eng.update_services().await;
    assert_eq!(report.services_fetch, ServicesFetchKind::Failed);
    assert!(eng.services().is_none());
}

#[test]
fn catalog_limits_and_id_validation() {
    let mut entries = Vec::new();
    // Invalid ids are skipped.
    entries.push(r#"{"id": "Bad Id!", "rules": ["||a.test^"]}"#.to_owned());
    entries.push(r#"{"id": "ok_service-1", "rules": ["||b.test^"]}"#.to_owned());
    // Too many rules: capped.
    let rules: Vec<String> = (0..1_500).map(|i| format!("\"||r{i}.test^\"")).collect();
    entries.push(format!(
        r#"{{"id": "manyrules", "rules": [{}]}}"#,
        rules.join(",")
    ));
    // Huge icon: dropped, service kept.
    let icon = "x".repeat(16 * 1024 + 1);
    entries.push(format!(
        r#"{{"id": "bigicon", "icon_svg": "{icon}", "rules": ["||c.test^"]}}"#
    ));
    // Too many services.
    for i in 0..2_100 {
        entries.push(format!(r#"{{"id": "svc-{i}", "rules": []}}"#));
    }
    let json = format!(r#"{{"blocked_services": [{}]}}"#, entries.join(","));
    let cat = ServiceCatalog::parse(&json, None).unwrap();

    assert!(cat.get("Bad Id!").is_none());
    assert!(cat.get("ok_service-1").is_some());
    assert_eq!(cat.services().len(), 2_000);
    assert_eq!(
        cat.get("manyrules").unwrap().rules_body().lines().count(),
        1_000
    );
    let big = cat.get("bigicon").unwrap();
    assert!(big.icon.is_empty());
    assert!(!big.rules_body().is_empty());
    assert!(cat.stats().skipped_malformed >= 1);
    assert!(cat.stats().skipped_over_limit >= 100);
    assert_eq!(cat.stats().skipped_rules, 500);
    assert_eq!(cat.stats().dropped_icons, 1);
}

// ---- 5. scheduler lifecycle --------------------------------------------------

#[tokio::test]
async fn dropping_last_engine_handle_ends_scheduler() {
    let dir = TempDir::new("cycle");
    let clock = Arc::new(ManualClock::new(t0()));
    let store = store_in(&dir, &clock);
    let cfg = config(vec![], vec![set_with("default", &[])], 3600);
    let eng = FilterEngine::new(cfg, store, clock).unwrap();
    let weak = Arc::downgrade(&eng);
    // Let the scheduler task start and park.
    tokio::time::sleep(Duration::from_millis(50)).await;
    drop(eng);
    tokio::time::timeout(Duration::from_secs(5), async {
        while weak.upgrade().is_some() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("engine leaked: scheduler keeps it alive");
}

#[tokio::test]
async fn failing_rounds_retry_with_backoff_before_the_interval() {
    let dir = TempDir::new("backoff");
    let clock = Arc::new(ManualClock::new(t0()));
    let store = store_in(&dir, &clock);
    let server = TestServer::start(vec![
        (
            "/services.json",
            Route {
                status: 500,
                ..Route::ok("")
            },
        ),
        ("/services_i18n.json", Route::ok("{}")),
    ])
    .await;
    let cfg = config(vec![], vec![set_with("default", &[])], 3600);
    let eng = FilterEngine::new(cfg, store, clock.clone()).unwrap();
    eng.set_services_urls(services_urls(&server)).unwrap();
    // Let the scheduler task park on its first (one interval) wait.
    tokio::time::sleep(Duration::from_millis(200)).await;
    let fetches = || {
        server
            .requests()
            .iter()
            .filter(|r| r.path == "/services.json")
            .count()
    };
    let settle = |n: usize| async move {
        for _ in 0..500 {
            if fetches() >= n {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        // The next delay is computed after the round finishes; let it settle
        // before the test moves the clock again.
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(fetches(), n, "unexpected number of update rounds");
    };
    // Regular round after one interval (jitter is at most 10 %).
    clock.advance(Duration::from_secs(4000));
    settle(1).await;
    // A failed round retries after 5 min, far earlier than the 1 h interval.
    clock.advance(Duration::from_secs(360));
    settle(2).await;
    // The second consecutive failure doubles the retry delay to 10 min.
    clock.advance(Duration::from_secs(720));
    settle(3).await;
}

// ---- 6. update_now ------------------------------------------------------------

#[tokio::test]
async fn update_now_fetches_each_list_once() {
    let dir = TempDir::new("once");
    let clock = Arc::new(ManualClock::new(t0()));
    let store = store_in(&dir, &clock);
    let server = TestServer::start(vec![
        ("/a.txt", Route::ok("||a.example^\n")),
        ("/b.txt", Route::ok("||b.example^\n")),
    ])
    .await;
    let cfg = config(
        vec![
            list_url("a", server.url("/a.txt")),
            list_url("b", server.url("/b.txt")),
        ],
        vec![set_with("default", &["a", "b"])],
        3600,
    );
    let eng = FilterEngine::new(cfg, store, clock).unwrap();
    eng.set_services_urls(services_urls(&server)).unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;
    eng.update_now().await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    let count = |p: &str| server.requests().iter().filter(|r| r.path == p).count();
    assert_eq!(count("/a.txt"), 1);
    assert_eq!(count("/b.txt"), 1);
}
