//! Boot reconcile (`apply_stored_current`) must not download filter catalogs.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod support;

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use axum::Router;
use axum::http::StatusCode;
use axum::routing::get;
use dnscraft_filtering::{Clock as FilterClock, ServicesUrls, StoreConfig};
use serde_json::json;

use dnscraft_api::{Audit, ConfigActor, ConfigService, ConfigStore, Db, ModuleAppliers};
use support::{BridgeClock, FilterApplier, NOW, TempDir, TestServer, at, seed_config};

fn full_snapshot() -> serde_json::Value {
    json!({
        "filtering": {
            "lists": [],
            "sets": [{
                "id": "default",
                "name": "Default",
                "lists": [],
                "custom_rules": "||offline.example^",
                "services": [],
                "block_mode": "refused",
                "mcp_rules": []
            }]
        },
        "clients": {},
        "policy": {},
        "listeners": {},
        "tls": {},
    })
}

#[tokio::test]
async fn apply_stored_current_does_not_fetch_remote_catalog() {
    static FETCHES: AtomicUsize = AtomicUsize::new(0);
    let server = TestServer::start(
        Router::new()
            .route(
                "/services.json",
                get(|| async {
                    FETCHES.fetch_add(1, Ordering::SeqCst);
                    (StatusCode::OK, "{}")
                }),
            )
            .route(
                "/services_i18n.json",
                get(|| async {
                    FETCHES.fetch_add(1, Ordering::SeqCst);
                    (StatusCode::OK, "{}")
                }),
            ),
    )
    .await;

    let temp = TempDir::new("stored-offline");
    let clock = BridgeClock::new(at(NOW));
    let filter_clock: Arc<dyn FilterClock> = Arc::clone(&clock) as Arc<dyn FilterClock>;
    let store_config = StoreConfig {
        allow_http_for_tests: true,
        ..Default::default()
    };
    let store = dnscraft_filtering::ListStore::open_with(
        temp.path(),
        store_config,
        Arc::clone(&filter_clock),
    )
    .expect("store");
    let engine = dnscraft_filtering::FilterEngine::open_without_scheduler(
        seed_config(),
        store,
        filter_clock,
    )
    .expect("engine");
    engine
        .set_services_urls(ServicesUrls {
            services: server.url("/services.json"),
            i18n: server.url("/services_i18n.json"),
        })
        .unwrap();

    let db = Db::open_in_memory(Arc::clone(&clock) as Arc<dyn dnscraft_api::Clock>)
        .await
        .unwrap();
    let audit = Audit::new(db.clone());
    let service = ConfigService::new(
        ConfigStore::new(db),
        audit,
        ModuleAppliers {
            filtering: Some(FilterApplier::new(Arc::clone(&engine))),
            filtering_engine: Some(Arc::clone(&engine)),
            ..ModuleAppliers::default()
        },
        "node-a",
    );

    let body = full_snapshot();
    service
        .replace(body, &ConfigActor::local(), None)
        .await
        .expect("versioned write may refresh lists");
    let hits_after_replace = FETCHES.load(Ordering::SeqCst);
    assert!(
        hits_after_replace >= 2,
        "replace should refresh the services catalog (hits={hits_after_replace})"
    );

    FETCHES.store(0, Ordering::SeqCst);
    assert_eq!(
        service.apply_stored_current().await.unwrap(),
        Some(1),
        "re-applies the stored row"
    );
    assert_eq!(
        FETCHES.load(Ordering::SeqCst),
        0,
        "boot reconcile must not hit remote catalog URLs"
    );
    assert!(
        engine.services().is_none(),
        "catalog stays unavailable without a cached services.json"
    );
}

#[tokio::test]
async fn seed_if_empty_does_not_fetch_remote_catalog() {
    static FETCHES: AtomicUsize = AtomicUsize::new(0);
    let server = TestServer::start(
        Router::new()
            .route(
                "/services.json",
                get(|| async {
                    FETCHES.fetch_add(1, Ordering::SeqCst);
                    (StatusCode::OK, "{}")
                }),
            )
            .route(
                "/services_i18n.json",
                get(|| async {
                    FETCHES.fetch_add(1, Ordering::SeqCst);
                    (StatusCode::OK, "{}")
                }),
            ),
    )
    .await;

    let temp = TempDir::new("seed-offline");
    let clock = BridgeClock::new(at(NOW));
    let filter_clock: Arc<dyn FilterClock> = Arc::clone(&clock) as Arc<dyn FilterClock>;
    let store_config = StoreConfig {
        allow_http_for_tests: true,
        ..Default::default()
    };
    let store = dnscraft_filtering::ListStore::open_with(
        temp.path(),
        store_config,
        Arc::clone(&filter_clock),
    )
    .expect("store");
    let engine = dnscraft_filtering::FilterEngine::open_without_scheduler(
        seed_config(),
        store,
        filter_clock,
    )
    .expect("engine");
    engine
        .set_services_urls(ServicesUrls {
            services: server.url("/services.json"),
            i18n: server.url("/services_i18n.json"),
        })
        .unwrap();

    let db = Db::open_in_memory(Arc::clone(&clock) as Arc<dyn dnscraft_api::Clock>)
        .await
        .unwrap();
    let audit = Audit::new(db.clone());
    let service = ConfigService::new(
        ConfigStore::new(db),
        audit,
        ModuleAppliers {
            filtering: Some(FilterApplier::new(Arc::clone(&engine))),
            filtering_engine: Some(Arc::clone(&engine)),
            ..ModuleAppliers::default()
        },
        "node-a",
    );

    assert_eq!(
        service.seed_if_empty(full_snapshot()).await.unwrap(),
        Some(1),
        "first boot seed stores version 1"
    );
    assert_eq!(
        FETCHES.load(Ordering::SeqCst),
        0,
        "bootstrap seed must not download the services catalog"
    );
    assert!(
        engine.services().is_none(),
        "catalog stays unavailable without a cached services.json"
    );
}

#[tokio::test]
async fn apply_synced_config_does_not_fetch_remote_catalog() {
    static FETCHES: AtomicUsize = AtomicUsize::new(0);
    let server = TestServer::start(
        Router::new()
            .route(
                "/services.json",
                get(|| async {
                    FETCHES.fetch_add(1, Ordering::SeqCst);
                    (StatusCode::OK, "{}")
                }),
            )
            .route(
                "/services_i18n.json",
                get(|| async {
                    FETCHES.fetch_add(1, Ordering::SeqCst);
                    (StatusCode::OK, "{}")
                }),
            ),
    )
    .await;

    let temp = TempDir::new("sync-offline");
    let clock = BridgeClock::new(at(NOW));
    let filter_clock: Arc<dyn FilterClock> = Arc::clone(&clock) as Arc<dyn FilterClock>;
    let store_config = StoreConfig {
        allow_http_for_tests: true,
        ..Default::default()
    };
    let store = dnscraft_filtering::ListStore::open_with(
        temp.path(),
        store_config,
        Arc::clone(&filter_clock),
    )
    .expect("store");
    let engine = dnscraft_filtering::FilterEngine::open_without_scheduler(
        seed_config(),
        store,
        filter_clock,
    )
    .expect("engine");
    engine
        .set_services_urls(ServicesUrls {
            services: server.url("/services.json"),
            i18n: server.url("/services_i18n.json"),
        })
        .unwrap();

    let db = Db::open_in_memory(Arc::clone(&clock) as Arc<dyn dnscraft_api::Clock>)
        .await
        .unwrap();
    let audit = Audit::new(db.clone());
    let service = ConfigService::new(
        ConfigStore::new(db),
        audit,
        ModuleAppliers {
            filtering: Some(FilterApplier::new(Arc::clone(&engine))),
            filtering_engine: Some(Arc::clone(&engine)),
            ..ModuleAppliers::default()
        },
        "node-b",
    );

    assert_eq!(
        service
            .apply_synced_config(full_snapshot(), 1)
            .await
            .expect("cluster push applies offline"),
        1
    );
    assert_eq!(
        FETCHES.load(Ordering::SeqCst),
        0,
        "cluster sync must not block on catalog download"
    );
}
