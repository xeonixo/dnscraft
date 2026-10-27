//! Task L3: hot reload, startup without network, schedule with manual clock.

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
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::thread;
use std::time::{Duration, Instant, SystemTime};

use dnscraft_filtering::{
    Clock, DEFAULT_MAX_BODY_BYTES, DomainName, FilterConfig, FilterEngine, FilterSetConfig,
    ListConfig, ListId, ListMeta, ListSelection, ListSourceSpec, ListStore, ManualClock, SetId,
    SkipReason, StoreConfig, Verdict,
};
use http::{Route, TestServer};

static COUNTER: AtomicU32 = AtomicU32::new(0);

struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let p =
            std::env::temp_dir().join(format!("dnscraft-reload-{tag}-{}-{n}", std::process::id()));
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

fn write_file(path: &Path, body: &str) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    let mut f = fs::File::create(path).unwrap();
    f.write_all(body.as_bytes()).unwrap();
}

fn seed_store(store: &ListStore, id: &str, body: &str) {
    let mut meta = ListMeta::default();
    meta.last_success = Some(store.now_unix());
    meta.last_attempt = Some(store.now_unix());
    meta.rules_parsed = body
        .lines()
        .filter(|l| !l.is_empty() && !l.starts_with('!'))
        .count() as u64;
    store.write_body(&lid(id), body, &meta).unwrap();
}

fn base_config(lists: Vec<ListConfig>, sets: Vec<FilterSetConfig>) -> FilterConfig {
    FilterConfig {
        lists,
        sets,
        update_interval: Duration::from_secs(3600),
        ..FilterConfig::default()
    }
}

fn list_file(id: &str, path: PathBuf) -> ListConfig {
    ListConfig {
        id: lid(id),
        name: id.to_owned(),
        source: ListSourceSpec::File(path),
        enabled: true,
    }
}

fn list_url(id: &str, url: String) -> ListConfig {
    ListConfig {
        id: lid(id),
        name: id.to_owned(),
        source: ListSourceSpec::Url(url),
        enabled: true,
    }
}

fn one_set(lists: &[&str]) -> FilterSetConfig {
    let mut s = FilterSetConfig::new(sid("default"), "default");
    s.lists = lists.iter().map(|l| lid(l)).collect();
    s
}

#[tokio::test]
async fn startup_builds_from_cache_without_network() {
    let dir = TempDir::new("startup");
    let clock = Arc::new(ManualClock::new(t0()));
    let mut sc = StoreConfig::default();
    sc.allow_http_for_tests = true;
    let store = ListStore::open_with(dir.path(), sc, clock.clone()).unwrap();

    // Deliberately unreachable URL — must not be contacted on open.
    seed_store(&store, "a", "||ads.example^\n||tracker.example^\n");
    let cfg = base_config(
        vec![list_url(
            "a",
            "https://127.0.0.1:1/this-must-not-be-fetched".into(),
        )],
        vec![one_set(&["a"])],
    );

    let eng = FilterEngine::open_without_scheduler(cfg, store, clock).unwrap();
    let v = eng
        .match_name(&sid("default"), &dn("ads.example"), 1, t0())
        .unwrap();
    assert!(matches!(v, Verdict::Blocked(_)), "{v:?}");

    let status = eng.list_status();
    assert_eq!(status.len(), 1);
    assert!(status[0].rules_parsed >= 2);
    assert_eq!(status[0].unique_contribution, 2);
}

#[tokio::test]
async fn unique_contribution_on_small_fixture() {
    let dir = TempDir::new("unique");
    let clock = Arc::new(ManualClock::new(t0()));
    let store = ListStore::open_with(dir.path(), StoreConfig::default(), clock.clone()).unwrap();

    let fa = dir.path().join("a.txt");
    let fb = dir.path().join("b.txt");
    write_file(&fa, "||ads.example^\n||shared.example^\n");
    write_file(&fb, "||shared.example^\n||other.example^\n");

    let cfg = base_config(
        vec![list_file("a", fa), list_file("b", fb)],
        vec![one_set(&["a", "b"])],
    );
    let eng = FilterEngine::open_without_scheduler(cfg, store, clock).unwrap();
    let status = eng.list_status();
    let a = status.iter().find(|s| s.id == lid("a")).unwrap();
    let b = status.iter().find(|s| s.id == lid("b")).unwrap();
    assert_eq!(a.unique_contribution, 2, "{a:?}");
    assert_eq!(b.unique_contribution, 1, "{b:?}"); // other.example only
}

#[tokio::test]
async fn concurrent_matching_during_rebuild_never_blocks_and_never_half_built() {
    let dir = TempDir::new("concurrent");
    let clock = Arc::new(ManualClock::new(t0()));
    let store = ListStore::open_with(dir.path(), StoreConfig::default(), clock.clone()).unwrap();

    let body_v1 = "||ads.example^\n";
    seed_store(&store, "a", body_v1);
    let path = dir.path().join("lists-src").join("a.txt");
    write_file(&path, body_v1);

    let cfg = base_config(vec![list_file("a", path.clone())], vec![one_set(&["a"])]);
    let eng = FilterEngine::open_without_scheduler(cfg, store.clone(), clock).unwrap();

    let stop = Arc::new(AtomicBool::new(false));
    let eng_m = Arc::clone(&eng);
    let stop_m = Arc::clone(&stop);
    let matcher = thread::spawn(move || {
        let mut max_lock = Duration::ZERO;
        let mut n = 0u64;
        while !stop_m.load(Ordering::SeqCst) {
            let t0 = Instant::now();
            let snap = eng_m.snapshot_arc();
            let elapsed = t0.elapsed();
            if elapsed > max_lock {
                max_lock = elapsed;
            }
            let v = snap
                .match_name(
                    &sid("default"),
                    &dn("ads.example"),
                    1,
                    SystemTime::UNIX_EPOCH,
                )
                .unwrap();
            assert!(
                matches!(v, Verdict::Blocked(_)),
                "must never see a half-built or empty index, got {v:?}"
            );
            n += 1;
        }
        (max_lock, n)
    });

    for i in 0..20 {
        let body = format!("||ads.example^\n||extra{i}.example^\n");
        write_file(&path, &body);
        seed_store(&store, "a", &body);
        let mut set = FilterSetConfig::new(sid("default"), "default");
        set.lists = vec![lid("a")];
        let cfg = base_config(vec![list_file("a", path.clone())], vec![set]);
        eng.apply_config(cfg).await.unwrap();
    }

    stop.store(true, Ordering::SeqCst);
    let (max_lock, n) = matcher.join().unwrap();
    assert!(n > 100, "matcher should have run many times, got {n}");
    assert!(
        max_lock < Duration::from_millis(1),
        "snapshot Arc clone blocked for {max_lock:?}"
    );
}

#[tokio::test]
async fn failed_update_keeps_last_good() {
    let dir = TempDir::new("fail");
    let clock = Arc::new(ManualClock::new(t0()));
    let mut sc = StoreConfig::default();
    sc.allow_http_for_tests = true;
    let store = ListStore::open_with(dir.path(), sc, clock.clone()).unwrap();

    seed_store(&store, "a", "||ads.example^\n");

    let server = TestServer::start(vec![("/bad.txt", Route::status(500))]).await;
    let cfg = base_config(
        vec![list_url("a", server.url("/bad.txt"))],
        vec![one_set(&["a"])],
    );
    let eng = FilterEngine::open_without_scheduler(cfg, store.clone(), clock).unwrap();

    assert!(matches!(
        eng.match_name(&sid("default"), &dn("ads.example"), 1, t0())
            .unwrap(),
        Verdict::Blocked(_)
    ));

    let statuses = eng.update_lists(ListSelection::All).await;
    let st = statuses.iter().find(|s| s.id == lid("a")).unwrap();
    assert_eq!(
        st.error_code.as_deref(),
        Some("filter_list.fetch_failed"),
        "{st:?}"
    );

    assert!(matches!(
        eng.match_name(&sid("default"), &dn("ads.example"), 1, t0())
            .unwrap(),
        Verdict::Blocked(_)
    ));
    assert!(
        store
            .read_body(&lid("a"))
            .unwrap()
            .unwrap()
            .contains("ads.example")
    );
}

#[tokio::test]
async fn schedule_with_manual_clock() {
    let dir = TempDir::new("sched");
    let clock = Arc::new(ManualClock::new(t0()));
    let mut sc = StoreConfig::default();
    sc.allow_http_for_tests = true;
    let store = ListStore::open_with(dir.path(), sc, clock.clone()).unwrap();

    let server = TestServer::start(vec![(
        "/list.txt",
        Route::ok("||ads.example^\n||from-sched.example^\n"),
    )])
    .await;

    let mut cfg = base_config(
        vec![list_url("a", server.url("/list.txt"))],
        vec![one_set(&["a"])],
    );
    cfg.update_interval = Duration::from_secs(100);

    let eng = FilterEngine::open(cfg, store, Arc::clone(&clock) as Arc<dyn Clock>).unwrap();

    assert_eq!(
        eng.match_name(&sid("default"), &dn("ads.example"), 1, t0())
            .unwrap(),
        Verdict::Pass
    );

    // Let the scheduler task park on wait_until before we advance the clock.
    tokio::time::sleep(Duration::from_millis(50)).await;
    clock.advance(Duration::from_secs(120));
    for _ in 0..100 {
        if !server.requests().is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        !server.requests().is_empty(),
        "scheduler should have fetched after clock advance"
    );

    for _ in 0..50 {
        let v = eng
            .match_name(&sid("default"), &dn("ads.example"), 1, t0())
            .unwrap();
        if matches!(v, Verdict::Blocked(_)) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("expected block after scheduled update");
}

#[tokio::test]
async fn update_now_fetches_immediately() {
    let dir = TempDir::new("now");
    let clock = Arc::new(ManualClock::new(t0()));
    let mut sc = StoreConfig::default();
    sc.allow_http_for_tests = true;
    let store = ListStore::open_with(dir.path(), sc, clock.clone()).unwrap();

    let server = TestServer::start(vec![("/list.txt", Route::ok("||ads.example^\n"))]).await;

    let cfg = base_config(
        vec![list_url("a", server.url("/list.txt"))],
        vec![one_set(&["a"])],
    );
    let eng = FilterEngine::open_without_scheduler(cfg, store, clock).unwrap();
    assert_eq!(
        eng.match_name(&sid("default"), &dn("ads.example"), 1, t0())
            .unwrap(),
        Verdict::Pass
    );

    let _ = eng.update_now().await;
    assert!(matches!(
        eng.match_name(&sid("default"), &dn("ads.example"), 1, t0())
            .unwrap(),
        Verdict::Blocked(_)
    ));
}

#[tokio::test]
async fn on_disk_rule_text_via_store() {
    let dir = TempDir::new("text");
    let clock = Arc::new(ManualClock::new(t0()));
    let store = ListStore::open_with(dir.path(), StoreConfig::default(), clock.clone()).unwrap();
    let body = "! comment\n||ads.example^\n";
    seed_store(&store, "a", body);
    let path = dir.path().join("a-src.txt");
    write_file(&path, body);

    let cfg = base_config(vec![list_file("a", path)], vec![one_set(&["a"])]);
    let eng = FilterEngine::open_without_scheduler(cfg, store, clock).unwrap();
    let v = eng
        .match_name(&sid("default"), &dn("ads.example"), 1, t0())
        .unwrap();
    let Verdict::Blocked(r) = v else {
        panic!("{v:?}");
    };
    assert_eq!(&*r.rule, "||ads.example^");
}

#[test]
fn default_max_list_size_matches_the_store_default() {
    let cfg = FilterConfig::default();
    assert_eq!(cfg.max_list_size_mb, 64);
    assert_eq!(cfg.max_list_size_bytes(), DEFAULT_MAX_BODY_BYTES);
}

/// GF1 regression: `max_list_size_mb` from `FilterConfig` reaches the store's
/// body cap instead of leaving the store default (64 MiB) in charge.
#[tokio::test]
async fn config_max_list_size_mb_caps_list_bodies() {
    let dir = TempDir::new("max-size");
    let clock = Arc::new(ManualClock::new(t0()));
    let store = ListStore::open_with(dir.path(), StoreConfig::default(), clock.clone()).unwrap();
    let path = dir.path().join("big.txt");
    let line = "||host000000.example^\n";
    let mut body = String::new();
    while body.len() <= 2 * 1024 * 1024 {
        body.push_str(line);
    }
    write_file(&path, &body);

    let mut cfg = base_config(vec![list_file("big", path)], vec![one_set(&["big"])]);
    cfg.max_list_size_mb = 1;
    let eng = FilterEngine::open_without_scheduler(cfg, store, clock).unwrap();
    let statuses = eng.update_lists(ListSelection::All).await;
    let st = statuses.iter().find(|s| s.id == lid("big")).unwrap();
    assert_eq!(
        st.error_code.as_deref(),
        Some("filter_list.too_large"),
        "{st:?}"
    );
    assert!(st.last_attempt.is_some());
}

/// GF4 regression: the last HTTP status and the skip breakdown are surfaced.
#[tokio::test]
async fn list_status_reports_http_status_and_skips_by_reason() {
    let dir = TempDir::new("status");
    let clock = Arc::new(ManualClock::new(t0()));
    let store = ListStore::open_with(dir.path(), StoreConfig::default(), clock.clone()).unwrap();
    let mut meta = ListMeta::default();
    meta.last_attempt = Some(store.now_unix());
    meta.last_success = Some(store.now_unix());
    meta.http_status = Some(200);
    store
        .write_body(&lid("a"), "||ads.example^\n##.ad\n||bad..name^\n", &meta)
        .unwrap();

    let cfg = base_config(
        vec![list_url("a", "https://lists.example.com/a.txt".into())],
        vec![one_set(&["a"])],
    );
    let eng = FilterEngine::open_without_scheduler(cfg, store, clock).unwrap();
    let st = eng.list_status().into_iter().next().unwrap();
    assert_eq!(st.http_status, Some(200), "{st:?}");
    assert_eq!(st.rules_parsed, 1, "{st:?}");
    assert_eq!(st.rules_skipped, 2, "{st:?}");
    assert_eq!(
        st.skipped_by_reason.get(SkipReason::Unsupported(
            dnscraft_filtering::UnsupportedKind::Cosmetic
        )),
        1,
        "{st:?}"
    );
    assert_eq!(
        st.skipped_by_reason.get(SkipReason::InvalidDomain),
        1,
        "{st:?}"
    );
}
