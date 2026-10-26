//! Task M3: runtime per-set pause overlay.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use dnscraft_filtering::{
    Clock, DomainName, FilterConfig, FilterEngine, FilterSetConfig, ListBodies, ListId, ListStore,
    ManualClock, SetId, SnapshotBuilder, StoreConfig, Verdict,
};

#[derive(Debug, Default)]
struct MapBodies {
    map: HashMap<ListId, Arc<str>>,
}

impl ListBodies for MapBodies {
    fn body(&self, id: &ListId) -> Option<Arc<str>> {
        self.map.get(id).cloned()
    }
}

fn sid(s: &str) -> SetId {
    SetId::new(s).unwrap()
}
fn dn(s: &str) -> DomainName {
    s.parse().unwrap()
}
fn t(secs: u64) -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(secs)
}

fn config(paused_until: Option<SystemTime>, custom: &str) -> FilterConfig {
    let mut set = FilterSetConfig::new(sid("s"), "s");
    set.paused_until = paused_until;
    set.custom_rules = custom.to_owned();
    FilterConfig {
        sets: vec![set],
        ..FilterConfig::default()
    }
}

fn engine(cfg: &FilterConfig) -> FilterEngine {
    FilterEngine::from_snapshot(
        SnapshotBuilder::new(Arc::new(MapBodies::default()) as Arc<dyn ListBodies>)
            .build(cfg)
            .unwrap(),
    )
}

fn verdict(eng: &FilterEngine, name: &str, now: SystemTime) -> Verdict {
    eng.match_name(&sid("s"), &dn(name), 1, now).unwrap()
}

/// Store-backed engine for `apply_config` and concurrency tests.
fn store_engine(
    tag: &str,
    cfg: FilterConfig,
) -> (Arc<FilterEngine>, Arc<ManualClock>, std::path::PathBuf) {
    let dir = std::env::temp_dir().join(format!("dnscraft-pause-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let clock = Arc::new(ManualClock::new(t(0)));
    let store = ListStore::open_with(
        &dir,
        StoreConfig::default(),
        Arc::clone(&clock) as Arc<dyn Clock>,
    )
    .unwrap();
    let eng =
        FilterEngine::open_without_scheduler(cfg, store, Arc::clone(&clock) as Arc<dyn Clock>)
            .unwrap();
    (eng, clock, dir)
}

#[test]
fn pause_is_active_until_exactly_the_deadline_then_resumes() {
    let eng = engine(&config(None, "||ads.example^\n"));
    let clock = ManualClock::new(t(0));
    eng.set_paused_until(&sid("s"), Some(t(100))).unwrap();
    assert_eq!(eng.paused_until(&sid("s")), Some(t(100)));

    assert_eq!(verdict(&eng, "ads.example", clock.now()), Verdict::Pass);

    clock.advance(Duration::from_secs(100) - Duration::from_nanos(1));
    assert_eq!(verdict(&eng, "ads.example", clock.now()), Verdict::Pass);

    clock.advance(Duration::from_nanos(1));
    assert!(matches!(
        verdict(&eng, "ads.example", clock.now()),
        Verdict::Blocked(_)
    ));
}

#[test]
fn resume_mid_way_clears_the_pause() {
    let eng = engine(&config(None, "||ads.example^\n"));
    let clock = ManualClock::new(t(0));
    eng.set_paused_until(&sid("s"), Some(t(100))).unwrap();

    clock.advance(Duration::from_secs(50));
    assert_eq!(verdict(&eng, "ads.example", clock.now()), Verdict::Pass);

    eng.set_paused_until(&sid("s"), None).unwrap();
    assert_eq!(eng.paused_until(&sid("s")), None);
    assert!(matches!(
        verdict(&eng, "ads.example", clock.now()),
        Verdict::Blocked(_)
    ));
}

#[test]
fn a_new_pause_replaces_the_earlier_one() {
    let eng = engine(&config(None, "||ads.example^\n"));
    eng.set_paused_until(&sid("s"), Some(t(100))).unwrap();
    // Shorter new pause replaces the old one (no stacking).
    eng.set_paused_until(&sid("s"), Some(t(50))).unwrap();
    assert_eq!(eng.paused_until(&sid("s")), Some(t(50)));
    assert_eq!(verdict(&eng, "ads.example", t(40)), Verdict::Pass);
    assert!(matches!(
        verdict(&eng, "ads.example", t(60)),
        Verdict::Blocked(_)
    ));

    // Longer new pause replaces it too.
    eng.set_paused_until(&sid("s"), Some(t(200))).unwrap();
    assert_eq!(eng.paused_until(&sid("s")), Some(t(200)));
    assert_eq!(verdict(&eng, "ads.example", t(150)), Verdict::Pass);
}

#[test]
fn configured_pause_still_works_and_effective_is_the_later_deadline() {
    let eng = engine(&config(Some(t(100)), "||ads.example^\n"));
    assert_eq!(eng.paused_until(&sid("s")), Some(t(100)));
    assert_eq!(verdict(&eng, "ads.example", t(99)), Verdict::Pass);
    assert!(matches!(
        verdict(&eng, "ads.example", t(100)),
        Verdict::Blocked(_)
    ));

    // Overlay shorter than the config: config wins.
    eng.set_paused_until(&sid("s"), Some(t(50))).unwrap();
    assert_eq!(eng.paused_until(&sid("s")), Some(t(100)));
    assert_eq!(verdict(&eng, "ads.example", t(75)), Verdict::Pass);

    // Overlay longer than the config: overlay wins.
    eng.set_paused_until(&sid("s"), Some(t(200))).unwrap();
    assert_eq!(eng.paused_until(&sid("s")), Some(t(200)));
    assert_eq!(verdict(&eng, "ads.example", t(150)), Verdict::Pass);

    // Clearing only the overlay falls back to the config pause.
    eng.set_paused_until(&sid("s"), None).unwrap();
    assert_eq!(eng.paused_until(&sid("s")), Some(t(100)));
}

#[test]
fn unknown_set_pause_is_rejected_with_a_stable_code() {
    let eng = engine(&config(None, ""));
    let err = eng.set_paused_until(&sid("nope"), Some(t(10))).unwrap_err();
    assert_eq!(err.code(), "filter_set.unknown");
    assert_eq!(eng.paused_until(&sid("nope")), None);
}

#[test]
fn pause_applies_to_chain_and_answer_ip() {
    let eng = engine(&config(None, "||tracker.example^\n||192.0.2.1^\n"));
    let names = vec![dn("page.example"), dn("tracker.example")];
    assert!(matches!(
        eng.match_chain(&sid("s"), &names, 1, t(0)).unwrap(),
        Verdict::Blocked(_)
    ));
    let ip = "192.0.2.1".parse().unwrap();
    assert!(matches!(
        eng.match_answer_ip(&sid("s"), ip, t(0)).unwrap(),
        Verdict::Blocked(_)
    ));

    eng.set_paused_until(&sid("s"), Some(t(100))).unwrap();
    assert_eq!(
        eng.match_chain(&sid("s"), &names, 1, t(50)).unwrap(),
        Verdict::Pass
    );
    assert_eq!(
        eng.match_answer_ip(&sid("s"), ip, t(50)).unwrap(),
        Verdict::Pass
    );
}

#[tokio::test]
async fn pause_overlay_survives_apply_config() {
    let cfg = config(None, "||ads.example^\n");
    let (eng, clock, dir) = store_engine("apply", cfg.clone());
    eng.set_paused_until(&sid("s"), Some(t(100))).unwrap();

    clock.advance(Duration::from_secs(10));
    eng.apply_config(cfg).await.unwrap();
    assert_eq!(eng.paused_until(&sid("s")), Some(t(100)));
    assert_eq!(verdict(&eng, "ads.example", clock.now()), Verdict::Pass);

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn pause_and_apply_config_do_not_deadlock() {
    let cfg = config(None, "||ads.example^\n");
    let (eng, clock, dir) = store_engine("concurrent", cfg.clone());

    let reloader = {
        let eng = Arc::clone(&eng);
        let cfg = cfg.clone();
        async move {
            for _ in 0..20 {
                eng.apply_config(cfg.clone()).await.unwrap();
            }
        }
    };
    let pauser = {
        let eng = Arc::clone(&eng);
        let clock = Arc::clone(&clock);
        async move {
            for i in 0..200 {
                if i % 2 == 0 {
                    eng.set_paused_until(&sid("s"), Some(t(1_000))).unwrap();
                } else {
                    eng.set_paused_until(&sid("s"), None).unwrap();
                }
                let _ = eng.match_name(&sid("s"), &dn("ads.example"), 1, clock.now());
                let _ = eng.match_chain(
                    &sid("s"),
                    &[dn("page.example"), dn("ads.example")],
                    1,
                    clock.now(),
                );
            }
        }
    };
    tokio::time::timeout(Duration::from_secs(10), async {
        tokio::join!(reloader, pauser);
    })
    .await
    .expect("apply_config and pause setter deadlocked");

    let _ = std::fs::remove_dir_all(&dir);
}
