//! WP5: blocked-services catalog listing and the per-set toggle.
//!
//! The catalog comes from an in-memory `services.json`-shaped document through
//! a test `ServiceCatalogProvider`; no download happens.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, UNIX_EPOCH};

use axum::body::Body;
use axum::extract::connect_info::MockConnectInfo;
use axum::http::{Method, Request, StatusCode};
use dnscraft_api::{
    AppState, Audit, ConfigService, ConfigStore, Db, ManualClock, ModuleAppliers,
    ServiceCatalogProvider,
};
use dnscraft_filtering::ServiceCatalog;
use serde_json::{Value, json};
use tower::ServiceExt as _;

const CATALOG: &str = r#"{
    "blocked_services": [
        {"id": "video", "name": "Video", "group": "social", "rules": ["||video.example^"]}
    ],
    "groups": [{"id": "social"}]
}"#;

struct FakeCatalog(Arc<ServiceCatalog>);

impl ServiceCatalogProvider for FakeCatalog {
    fn catalog(&self) -> Option<Arc<ServiceCatalog>> {
        Some(self.0.clone())
    }

    fn updated_at(&self) -> Option<u64> {
        Some(1_700_000_000)
    }
}

async fn harness(with_catalog: bool) -> AppState {
    let clock = Arc::new(ManualClock::new(
        UNIX_EPOCH + Duration::from_secs(1_700_000_000),
    ));
    let db = Db::open_in_memory(clock.clone()).await.unwrap();
    let service = ConfigService::new(
        ConfigStore::new(db.clone()),
        Audit::new(db.clone()),
        ModuleAppliers::default(),
        "node-a",
    );
    let state = AppState::new()
        .with_clock(clock)
        .with_db(db)
        .with_config_service(Arc::new(service));
    if with_catalog {
        let catalog = ServiceCatalog::parse(CATALOG, None).unwrap();
        state.with_service_catalog(Arc::new(FakeCatalog(Arc::new(catalog))))
    } else {
        state
    }
}

async fn call(
    state: &AppState,
    method: Method,
    uri: &str,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let router = state
        .clone()
        .router()
        .layer(MockConnectInfo(SocketAddr::from(([127, 0, 0, 1], 40_000))));
    let request = match body {
        Some(body) => Request::builder()
            .method(method)
            .uri(uri)
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap(),
        None => Request::builder()
            .method(method)
            .uri(uri)
            .body(Body::empty())
            .unwrap(),
    };
    let response = router.oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

/// Stores a config with one filter set `default` so the toggle has a target.
async fn seed_set(state: &AppState) {
    let config = json!({
        "filtering": {"sets": [{"id": "default"}]},
        "clients": {},
        "policy": {},
        "listeners": {},
        "tls": {},
    });
    let (status, body) = call(state, Method::PUT, "/api/v1/config", Some(config)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

#[tokio::test]
async fn catalog_without_provider_reports_unavailable() {
    let state = harness(false).await;
    let (status, body) = call(&state, Method::GET, "/api/v1/filtering/services", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["data"]["available"], false);
    assert_eq!(body["data"]["items"], json!([]));

    let (status, body) = call(
        &state,
        Method::PUT,
        "/api/v1/filtering/services/video",
        Some(json!({"filter_set_id": "default", "enabled": true})),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"]["code"], "filtering.catalog.unavailable");
}

#[tokio::test]
async fn toggle_sets_the_service_in_one_filter_set() {
    let state = harness(true).await;
    seed_set(&state).await;

    let (_, body) = call(&state, Method::GET, "/api/v1/filtering/services", None).await;
    assert_eq!(body["data"]["available"], true);
    assert_eq!(body["data"]["items"][0]["id"], "video");
    assert_eq!(body["data"]["items"][0]["enabled"]["default"], false);

    let (status, body) = call(
        &state,
        Method::PUT,
        "/api/v1/filtering/services/video",
        Some(json!({"filter_set_id": "default", "enabled": true})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["data"]["enabled"], true);

    let (_, body) = call(&state, Method::GET, "/api/v1/filtering/services", None).await;
    assert_eq!(body["data"]["items"][0]["enabled"]["default"], true);

    // Switching off removes it again and keeps the set otherwise intact.
    let (status, _) = call(
        &state,
        Method::PUT,
        "/api/v1/filtering/services/video",
        Some(json!({"filter_set_id": "default", "enabled": false})),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (_, body) = call(&state, Method::GET, "/api/v1/config", None).await;
    assert_eq!(
        body["data"]["config"]["filtering"]["sets"][0]["services"],
        json!([])
    );
}

#[tokio::test]
async fn toggle_rejects_unknown_service_and_unknown_set() {
    let state = harness(true).await;
    seed_set(&state).await;

    let (status, body) = call(
        &state,
        Method::PUT,
        "/api/v1/filtering/services/nope",
        Some(json!({"filter_set_id": "default", "enabled": true})),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"]["code"], "filtering.service.unknown");

    let (status, body) = call(
        &state,
        Method::PUT,
        "/api/v1/filtering/services/video",
        Some(json!({"filter_set_id": "missing", "enabled": true})),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["error"]["code"], "control_api.not_found");
}

#[tokio::test]
async fn locale_is_validated_and_names_follow_it() {
    let state = harness(true).await;
    let (status, body) = call(
        &state,
        Method::GET,
        "/api/v1/filtering/services?locale=de%20x",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"]["code"], "filtering.service.invalid");

    let (status, body) = call(
        &state,
        Method::GET,
        "/api/v1/filtering/services?locale=de",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["data"]["locale"], "de");
    // Without translations the default name is used.
    assert_eq!(body["data"]["items"][0]["name"], "Video");
}
