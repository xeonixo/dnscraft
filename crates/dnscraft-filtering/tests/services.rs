//! Task L4: blocked-services catalog (hand-written fixtures, no AdGuard GPL data).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::field_reassign_with_default
)]

#[path = "support/http.rs"]
mod http;

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, SystemTime};

use dnscraft_filtering::{
    DomainName, FilterConfig, FilterEngine, FilterSetConfig, ListBodies, ListId, ListStore,
    ManualClock, RuleSource, SERVICES_I18N_STEM, SERVICES_STEM, ServiceCatalog, ServicesUrls,
    SetId, SnapshotBuilder, StoreConfig, Verdict, seed_services_cache,
};
use http::{Route, TestServer};

static COUNTER: AtomicU32 = AtomicU32::new(0);

struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let p = std::env::temp_dir().join(format!(
            "dnscraft-services-{tag}-{}-{n}",
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

/// Tiny hand-written catalog — not copied from AdGuard HostlistsRegistry.
const FIXTURE_SERVICES: &str = r#"{
  "blocked_services": [
    {
      "id": "acmechat",
      "name": "Acme Chat",
      "group": "messenger",
      "icon_svg": "<svg xmlns=\"http://www.w3.org/2000/svg\"><circle r=\"1\"/></svg>",
      "rules": ["||chat.acme.test^", "||cdn.acme.test^"]
    },
    {
      "id": "acmetube",
      "name": "Acme Tube",
      "group": "streaming",
      "icon_svg": "<svg xmlns=\"http://www.w3.org/2000/svg\"><rect width=\"1\" height=\"1\"/></svg>",
      "rules": ["||tube.acme.test^"]
    },
    {
      "id": "broken",
      "name": "Broken",
      "group": "messenger",
      "icon_svg": "",
      "rules": "not-an-array"
    },
    null,
    {"name": "missing-id", "rules": ["||x.test^"]}
  ],
  "groups": [{"id": "messenger"}, {"id": "streaming"}]
}"#;

const FIXTURE_I18N: &str = r#"{
  "groups": {
    "messenger": {
      "en": {"name": "Messaging"},
      "de": {"name": "Messenger"}
    },
    "streaming": {
      "en": {"name": "Streaming"},
      "de": {"name": "Streaming-Dienste"}
    }
  },
  "services": {
    "acmechat": {
      "en": {"name": "Acme Chat"},
      "de": {"name": "Acme Chat DE"}
    },
    "acmetube": {
      "en": {"name": "Acme Tube"},
      "de": {"name": "Acme Tube DE"}
    }
  }
}"#;

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
fn t0() -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(1_000)
}

fn fixture_catalog() -> Arc<ServiceCatalog> {
    Arc::new(ServiceCatalog::parse(FIXTURE_SERVICES, Some(FIXTURE_I18N)).unwrap())
}

#[test]
fn fixture_catalog_loads_and_skips_malformed_entries() {
    let cat = fixture_catalog();
    assert_eq!(cat.services().len(), 2);
    assert_eq!(cat.stats().accepted, 2);
    assert!(cat.stats().skipped_malformed >= 2);
    let chat = cat.get("acmechat").unwrap();
    assert_eq!(chat.name, "Acme Chat");
    assert_eq!(chat.group, "messenger");
    assert!(chat.icon.contains("<svg"));
    assert!(chat.rules_body().contains("chat.acme.test"));
}

#[test]
fn translated_names_locale_with_english_fallback() {
    let cat = fixture_catalog();
    assert_eq!(cat.translated_name("acmechat", "de"), Some("Acme Chat DE"));
    assert_eq!(cat.translated_name("acmechat", "en"), Some("Acme Chat"));
    // Unknown locale → English from i18n.
    assert_eq!(cat.translated_name("acmechat", "fr"), Some("Acme Chat"));
    assert_eq!(cat.translated_group("messenger", "de"), "Messenger");
    assert_eq!(cat.translated_group("messenger", "ja"), "Messaging");
    assert_eq!(cat.translated_group("unknown_group", "de"), "unknown_group");
}

#[test]
fn toggling_service_per_set_changes_verdicts() {
    let cat = fixture_catalog();
    let bodies: Arc<dyn ListBodies> = Arc::new(MapBodies::default());

    let mut set_off = FilterSetConfig::new(sid("off"), "off");
    set_off.services = vec![];
    let mut set_on = FilterSetConfig::new(sid("on"), "on");
    set_on.services = vec!["acmechat".into()];
    let mut set_other = FilterSetConfig::new(sid("tube"), "tube");
    set_other.services = vec!["acmetube".into()];

    let cfg = FilterConfig {
        lists: vec![],
        sets: vec![set_off, set_on, set_other],
        ..FilterConfig::default()
    };
    let snap = SnapshotBuilder::new(bodies)
        .with_catalog(Some(cat))
        .build(&cfg)
        .unwrap();

    let now = t0();
    assert!(matches!(
        snap.match_name(&sid("off"), &dn("chat.acme.test"), 1, now)
            .unwrap(),
        Verdict::Pass
    ));
    match snap
        .match_name(&sid("on"), &dn("chat.acme.test"), 1, now)
        .unwrap()
    {
        Verdict::Blocked(r) => {
            assert!(
                matches!(r.source, RuleSource::Service { ref id } if id.as_ref() == "acmechat")
            );
            assert!(r.rule.contains("chat.acme.test"));
        }
        other => panic!("expected Blocked, got {other:?}"),
    }
    assert!(matches!(
        snap.match_name(&sid("on"), &dn("tube.acme.test"), 1, now)
            .unwrap(),
        Verdict::Pass
    ));
    assert!(matches!(
        snap.match_name(&sid("tube"), &dn("tube.acme.test"), 1, now)
            .unwrap(),
        Verdict::Blocked(_)
    ));
}

#[test]
fn unknown_service_ids_reported_not_fatal() {
    let cat = fixture_catalog();
    let bodies: Arc<dyn ListBodies> = Arc::new(MapBodies::default());
    let mut set = FilterSetConfig::new(sid("s"), "s");
    set.services = vec!["acmechat".into(), "does-not-exist".into()];
    let cfg = FilterConfig {
        sets: vec![set],
        ..FilterConfig::default()
    };
    let snap = SnapshotBuilder::new(bodies)
        .with_catalog(Some(cat))
        .build(&cfg)
        .unwrap();
    assert_eq!(
        snap.unknown_services(&sid("s")).unwrap(),
        &["does-not-exist".to_owned()]
    );
    assert!(matches!(
        snap.match_name(&sid("s"), &dn("chat.acme.test"), 1, t0())
            .unwrap(),
        Verdict::Blocked(_)
    ));
}

#[test]
fn wholly_malformed_json_is_an_error() {
    let err = ServiceCatalog::parse("{not json", None).unwrap_err();
    assert_eq!(err.code(), "filter_services.malformed");
    let err = ServiceCatalog::parse(r#"{"groups":[]}"#, None).unwrap_err();
    assert_eq!(err.code(), "filter_services.malformed");
}

#[tokio::test]
async fn malformed_update_keeps_previous_and_reports_code() {
    let dir = TempDir::new("keep");
    let mut sc = StoreConfig::default();
    sc.allow_http_for_tests = true;
    let clock = Arc::new(ManualClock::new(t0()));
    let store = ListStore::open_with(dir.path(), sc, Arc::clone(&clock) as _).unwrap();
    seed_services_cache(&store, SERVICES_STEM, FIXTURE_SERVICES).unwrap();
    seed_services_cache(&store, SERVICES_I18N_STEM, FIXTURE_I18N).unwrap();

    let mut set = FilterSetConfig::new(sid("s"), "s");
    set.services = vec!["acmechat".into()];
    let cfg = FilterConfig {
        sets: vec![set],
        ..FilterConfig::default()
    };
    let eng = FilterEngine::open_without_scheduler(cfg, store.clone(), clock).unwrap();
    assert!(eng.services().is_some());
    assert!(matches!(
        eng.match_name(&sid("s"), &dn("chat.acme.test"), 1, t0())
            .unwrap(),
        Verdict::Blocked(_)
    ));

    let server = TestServer::start(vec![
        ("/services.json", Route::ok("{ this is not a catalog")),
        ("/services_i18n.json", Route::ok("{}")),
    ])
    .await;
    eng.set_services_urls(ServicesUrls {
        services: server.url("/services.json"),
        i18n: server.url("/services_i18n.json"),
    })
    .unwrap();

    let report = eng.update_services().await;
    assert!(report.catalog.is_none());
    assert_eq!(report.error_code, Some("filter_services.malformed"));
    assert_eq!(eng.services_last_error(), Some("filter_services.malformed"));
    // Previous catalog still active.
    assert_eq!(
        eng.services().unwrap().get("acmechat").unwrap().name,
        "Acme Chat"
    );
    assert!(matches!(
        eng.match_name(&sid("s"), &dn("chat.acme.test"), 1, t0())
            .unwrap(),
        Verdict::Blocked(_)
    ));
}

#[tokio::test]
async fn engine_loads_cached_catalog_offline() {
    let dir = TempDir::new("offline");
    let clock = Arc::new(ManualClock::new(t0()));
    let store =
        ListStore::open_with(dir.path(), StoreConfig::default(), Arc::clone(&clock) as _).unwrap();
    seed_services_cache(&store, SERVICES_STEM, FIXTURE_SERVICES).unwrap();
    seed_services_cache(&store, SERVICES_I18N_STEM, FIXTURE_I18N).unwrap();

    let mut set = FilterSetConfig::new(sid("s"), "s");
    set.services = vec!["acmetube".into()];
    let cfg = FilterConfig {
        sets: vec![set],
        ..FilterConfig::default()
    };
    let eng = FilterEngine::open_without_scheduler(cfg, store, clock).unwrap();
    let cat = eng.services().expect("catalog from cache");
    assert_eq!(cat.translated_name("acmetube", "de"), Some("Acme Tube DE"));
    assert!(matches!(
        eng.match_name(&sid("s"), &dn("tube.acme.test"), 1, t0())
            .unwrap(),
        Verdict::Blocked(_)
    ));
}

#[tokio::test]
async fn services_updated_at_reports_the_cached_download_time() {
    let dir = TempDir::new("updated-at");
    let clock = Arc::new(ManualClock::new(t0()));
    let store =
        ListStore::open_with(dir.path(), StoreConfig::default(), Arc::clone(&clock) as _).unwrap();
    let cfg = FilterConfig::default();
    let eng =
        FilterEngine::open_without_scheduler(cfg, store.clone(), Arc::clone(&clock) as _).unwrap();
    assert_eq!(eng.services_updated_at(), None, "no catalog cached yet");
    seed_services_cache(&store, SERVICES_STEM, FIXTURE_SERVICES).unwrap();
    assert!(eng.services_updated_at().is_some());
}

#[test]
fn no_catalog_means_unavailable() {
    let dir = TempDir::new("none");
    let clock = Arc::new(ManualClock::new(t0()));
    let store =
        ListStore::open_with(dir.path(), StoreConfig::default(), Arc::clone(&clock) as _).unwrap();
    let cfg = FilterConfig::default();
    let eng = FilterEngine::open_without_scheduler(cfg, store, clock).unwrap();
    assert!(eng.services().is_none());
}
