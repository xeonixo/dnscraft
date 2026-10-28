//! A11: per-module config CRUD routes.
//!
//! These exercise the HTTP surface end to end against a real `ConfigService`
//! (SQLite-backed version store, no module appliers wired). Validation that
//! belongs to a module must surface that module's code, and cross-module
//! references must be checked before a new version is stored.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use axum::body::Body;
use axum::extract::connect_info::MockConnectInfo;
use axum::http::{Request, StatusCode, header};
use serde_json::{Value, json};
use tower::ServiceExt as _;

use dnscraft_api::{
    AppState, Audit, AuthState, ConfigService, ConfigStore, Db, ManualClock, ModuleAppliers, Scope,
    SessionStore, TokenStore,
};

struct Harness {
    state: AppState,
    service: Arc<ConfigService>,
}

async fn harness() -> Harness {
    let clock = Arc::new(ManualClock::new(
        SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000),
    ));
    let db = Db::open_in_memory(clock).await.unwrap();
    let service = Arc::new(ConfigService::new(
        ConfigStore::new(db.clone()),
        Audit::new(db),
        ModuleAppliers::default(),
        "node-a",
    ));
    let state = AppState::new().with_config_service(Arc::clone(&service));
    Harness { state, service }
}

async fn call(
    state: &AppState,
    method: &str,
    uri: &str,
    body: Option<Value>,
    if_match: Option<&str>,
) -> (StatusCode, Value) {
    let router = state
        .clone()
        .router()
        .layer(MockConnectInfo(SocketAddr::from(([127, 0, 0, 1], 40_000))));
    let mut builder = Request::builder().method(method).uri(uri);
    if let Some(value) = if_match {
        builder = builder.header(header::IF_MATCH, value);
    }
    let request = match body {
        Some(body) => builder
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_string()))
            .unwrap(),
        None => builder.body(Body::empty()).unwrap(),
    };
    let res = router.oneshot(request).await.unwrap();
    let status = res.status();
    let bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .unwrap();
    (status, serde_json::from_slice(&bytes).unwrap())
}

async fn get(state: &AppState, uri: &str) -> (StatusCode, Value) {
    call(state, "GET", uri, None, None).await
}

async fn put(state: &AppState, uri: &str, body: Value) -> (StatusCode, Value) {
    call(state, "PUT", uri, Some(body), None).await
}

async fn post(state: &AppState, uri: &str, body: Option<Value>) -> (StatusCode, Value) {
    call(state, "POST", uri, body, None).await
}

async fn delete(state: &AppState, uri: &str, body: Option<Value>) -> (StatusCode, Value) {
    call(state, "DELETE", uri, body, None).await
}

fn code(response: &Value) -> &str {
    response["error"]["code"].as_str().unwrap_or("")
}

async fn current_version(harness: &Harness) -> Option<i64> {
    harness.service.current().await.unwrap().0
}

/// Creates the minimum chain needed by policy resources: filter set → profile.
async fn seed_profile(state: &AppState, profile: &str) {
    let (status, response) = put(
        state,
        "/api/v1/filter-sets",
        json!({ "id": "default", "name": "Default" }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{response}");
    let (status, response) = put(
        state,
        &format!("/api/v1/policy/profiles/{profile}"),
        json!({ "filter_set": "default" }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{response}");
}

#[tokio::test]
async fn policy_views_crud_round_trip() {
    let h = harness().await;
    seed_profile(&h.state, "default").await;

    let (status, response) = post(
        &h.state,
        "/api/v1/policy/views/lan",
        Some(json!({ "profile": "default", "subnets": ["192.168.1.0/24"] })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{response}");
    assert_eq!(response["data"]["view"]["id"], "lan");
    assert_eq!(response["data"]["view"]["profile"], "default");

    let (status, response) = get(&h.state, "/api/v1/policy/views").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(response["data"]["views"][0]["id"], "lan");

    let (status, response) = get(&h.state, "/api/v1/policy/views/lan").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(response["data"]["view"]["is_default"], false);

    let (status, response) = put(
        &h.state,
        "/api/v1/policy/views/lan",
        json!({ "profile": "default", "is_default": true }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{response}");
    assert_eq!(response["data"]["view"]["is_default"], true);

    // A body id that disagrees with the path is a module validation error.
    let (status, response) = put(
        &h.state,
        "/api/v1/policy/views/lan",
        json!({ "id": "other", "profile": "default" }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(code(&response), "policy.config.invalid");

    let (status, response) = delete(&h.state, "/api/v1/policy/views/lan", None).await;
    assert_eq!(status, StatusCode::OK, "{response}");
    let (status, response) = get(&h.state, "/api/v1/policy/views/lan").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(response["error"]["code"], "control_api.not_found");
}

#[tokio::test]
async fn policy_profiles_and_pause_round_trip() {
    let h = harness().await;
    seed_profile(&h.state, "kids").await;

    let (status, response) = get(&h.state, "/api/v1/policy/profiles/kids").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(response["data"]["profile"]["filter_set"], "default");

    let (status, response) = put(
        &h.state,
        "/api/v1/policy/profiles/kids",
        json!({ "filter_set": "default", "suppress_aaaa": true }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{response}");
    assert_eq!(response["data"]["profile"]["suppress_aaaa"], true);

    let (status, response) = put(
        &h.state,
        "/api/v1/policy/pause",
        json!({ "global": { "until": 1_700_003_600u64 } }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{response}");
    let (status, response) = get(&h.state, "/api/v1/policy/pause").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        response["data"]["pause"]["global"]["until"],
        1_700_003_600u64
    );

    let (status, response) = delete(&h.state, "/api/v1/policy/pause", None).await;
    assert_eq!(status, StatusCode::OK, "{response}");
    assert_eq!(response["data"]["deleted"], true);

    let (status, response) = delete(&h.state, "/api/v1/policy/profiles/kids", None).await;
    assert_eq!(status, StatusCode::OK, "{response}");
    let (status, response) = get(&h.state, "/api/v1/policy/profiles/kids").await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{response}");
}

#[tokio::test]
async fn filter_sets_and_lists_crud() {
    let h = harness().await;

    let (status, response) = put(
        &h.state,
        "/api/v1/filter-lists",
        json!({ "id": "ads", "name": "Ads", "source": { "url": "https://example.com/ads.txt" } }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{response}");
    assert_eq!(response["data"]["created"], true);

    let (status, response) = put(
        &h.state,
        "/api/v1/filter-sets",
        json!({ "id": "default", "name": "Default", "lists": ["ads"] }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{response}");
    assert_eq!(response["data"]["filter_set"]["block_mode"], "refused");

    let (status, response) = get(&h.state, "/api/v1/filter-lists").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(response["data"]["filter_lists"][0]["id"], "ads");
    let (status, response) = get(&h.state, "/api/v1/filter-sets").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(response["data"]["filter_sets"][0]["lists"][0], "ads");

    let (status, response) = delete(
        &h.state,
        "/api/v1/filter-sets",
        Some(json!({ "id": "default" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{response}");
    let (status, response) = delete(
        &h.state,
        "/api/v1/filter-lists",
        Some(json!({ "id": "ads" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{response}");

    // Module validation codes, not generic control-api codes.
    let (status, response) = put(
        &h.state,
        "/api/v1/filter-lists",
        json!({ "id": "bad", "source": { "url": "http://example.com/list.txt" } }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(code(&response), "filter_store.invalid_source");

    let (status, response) = put(&h.state, "/api/v1/filter-sets", json!({ "id": "Bad_ID" })).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(code(&response), "filter_id.invalid_char");
}

#[tokio::test]
async fn clients_manual_crud_and_sync() {
    let h = harness().await;

    let (status, response) = post(
        &h.state,
        "/api/v1/clients/manual",
        Some(json!({ "name": "laptop", "ip": "192.168.1.10" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{response}");
    assert_eq!(response["data"]["entry"]["identity"], "192.168.1.10");

    let (status, response) = get(&h.state, "/api/v1/clients/manual").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(response["data"]["manual"][0]["name"], "laptop");
    let (status, response) = get(&h.state, "/api/v1/clients").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(response["data"]["manual"][0]["name"], "laptop");
    assert!(response["data"]["clients"].as_array().unwrap().is_empty());

    let (status, response) = put(
        &h.state,
        "/api/v1/clients/manual",
        json!({ "name": "laptop", "cidr": "192.168.1.0/24" }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{response}");
    assert_eq!(response["data"]["created"], false);

    let (status, response) = post(
        &h.state,
        "/api/v1/clients/manual",
        Some(json!({ "name": "laptop", "ip": "192.168.1.11" })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(code(&response), "clients.name.collision");

    let (status, response) = post(
        &h.state,
        "/api/v1/clients/manual",
        Some(json!({ "name": "phone", "cidr": "192.168.1.0/24" })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(code(&response), "clients.ip.conflict");

    let (status, response) = post(&h.state, "/api/v1/clients/sync", None).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(code(&response), "clients.sync.not_configured");

    let (status, response) = delete(
        &h.state,
        "/api/v1/clients/manual",
        Some(json!({ "name": "laptop" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{response}");
}

#[tokio::test]
async fn listeners_and_tls_crud() {
    let h = harness().await;

    let (status, response) = put(
        &h.state,
        "/api/v1/listeners",
        json!({
            "id": "lan",
            "protocol": "udp53",
            "address": "127.0.0.1:53",
            "nodes": ["garage", " garage ", "office", ""]
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{response}");
    assert_eq!(response["data"]["listener"]["exposure"], "local");
    assert_eq!(
        response["data"]["listener"]["nodes"],
        json!(["garage", "office"])
    );

    let (status, response) = get(&h.state, "/api/v1/listeners").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(response["data"]["listeners"][0]["id"], "lan");
    assert_eq!(
        response["data"]["listeners"][0]["nodes"],
        json!(["garage", "office"])
    );

    let (status, response) = put(
        &h.state,
        "/api/v1/listeners",
        json!({ "id": "bad", "protocol": "tcp53", "address": "0.0.0.0:53", "exposure": "public" }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(code(&response), "listeners.config.public_plaintext");

    let (status, response) =
        delete(&h.state, "/api/v1/listeners", Some(json!({ "id": "lan" }))).await;
    assert_eq!(status, StatusCode::OK, "{response}");

    let (status, response) = put(
        &h.state,
        "/api/v1/tls",
        json!({ "public_domain": "dns.example.com" }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{response}");
    let (status, response) = get(&h.state, "/api/v1/tls").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(response["data"]["tls"]["public_domain"], "dns.example.com");

    let (status, response) = put(
        &h.state,
        "/api/v1/tls",
        json!({ "public_domain": "dns.example.com", "mystery": true }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(code(&response), "tls.config.invalid");

    let (status, response) = delete(&h.state, "/api/v1/tls", None).await;
    assert_eq!(status, StatusCode::OK, "{response}");
    let (status, response) = get(&h.state, "/api/v1/tls").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(response["data"]["tls"], json!({}));
}

#[tokio::test]
async fn cross_module_references_are_validated_before_apply() {
    let h = harness().await;

    // Profile → filter set.
    let (status, response) = put(
        &h.state,
        "/api/v1/policy/profiles/home",
        json!({ "filter_set": "missing" }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(code(&response), "policy.config.unknown_filter_set");
    assert_eq!(current_version(&h).await, None, "no version on rejection");

    // View → profile.
    let (status, response) = post(
        &h.state,
        "/api/v1/policy/views/lan",
        Some(json!({ "profile": "ghost" })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(code(&response), "policy.config.invalid");
    assert_eq!(current_version(&h).await, None);

    // Filter set → filter list.
    let (status, response) = put(
        &h.state,
        "/api/v1/filter-sets",
        json!({ "id": "default", "lists": ["missing"] }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(code(&response), "filter_set.unknown_list");
    assert_eq!(current_version(&h).await, None);

    // Profile → forward zone, with the zone directory stored under `resolver`.
    let (status, response) = put(
        &h.state,
        "/api/v1/config",
        json!({
            "filtering": {},
            "clients": {},
            "policy": {},
            "listeners": {},
            "tls": {},
            "resolver": { "forward_zones": [{ "id": "corp" }] }
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{response}");
    let (status, response) = put(&h.state, "/api/v1/filter-sets", json!({ "id": "default" })).await;
    assert_eq!(status, StatusCode::OK, "{response}");

    let (status, response) = put(
        &h.state,
        "/api/v1/policy/profiles/home",
        json!({ "filter_set": "default", "forward_zones": ["unknown"] }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(code(&response), "policy.config.unknown_forward_zone");

    let (status, response) = put(
        &h.state,
        "/api/v1/policy/profiles/home",
        json!({ "filter_set": "default", "forward_zones": ["corp"] }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{response}");
}

const IDLE: Duration = Duration::from_secs(60 * 60);
const ABSOLUTE: Duration = Duration::from_secs(12 * 3600);
const MAX_TTL: Duration = Duration::from_secs(365 * 24 * 3600);

/// A full snapshot with one filter set that references a list which does not exist.
fn invalid_snapshot() -> Value {
    json!({
        "filtering": { "sets": [{ "id": "default", "lists": ["missing"] }] },
        "clients": {},
        "policy": {},
        "listeners": {},
        "tls": {},
    })
}

fn valid_snapshot() -> Value {
    json!({
        "filtering": {},
        "clients": {},
        "policy": {},
        "listeners": {},
        "tls": {},
    })
}

async fn validate(state: &AppState, body: Value, auth: Option<&str>) -> (StatusCode, Value) {
    let router = state
        .clone()
        .router()
        .layer(MockConnectInfo(SocketAddr::from(([127, 0, 0, 1], 40_000))));
    let mut builder = Request::builder()
        .method("POST")
        .uri("/api/v1/config/validate")
        .header(header::CONTENT_TYPE, "application/json");
    if let Some(auth) = auth {
        builder = builder.header(header::AUTHORIZATION, auth);
    }
    let request = builder.body(Body::from(body.to_string())).unwrap();
    let res = router.oneshot(request).await.unwrap();
    let status = res.status();
    let bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .unwrap();
    (status, serde_json::from_slice(&bytes).unwrap())
}

#[tokio::test]
async fn validate_valid_config_ok_no_apply() {
    let h = harness().await;
    let (status, response) = validate(&h.state, valid_snapshot(), None).await;
    assert_eq!(status, StatusCode::OK, "{response}");
    assert_eq!(response["data"]["valid"], true);
    assert_eq!(response["data"]["errors"], json!([]));
    assert_eq!(current_version(&h).await, None, "nothing was stored");
    let (_, config) = get(&h.state, "/api/v1/config").await;
    assert!(config["data"]["config"].is_null(), "nothing was applied");
}

#[tokio::test]
async fn validate_invalid_config_returns_errors() {
    let h = harness().await;
    let (status, response) = validate(&h.state, invalid_snapshot(), None).await;
    assert_eq!(status, StatusCode::OK, "errors are data: {response}");
    assert_eq!(response["data"]["valid"], false);
    let errors = response["data"]["errors"].as_array().unwrap();
    assert_eq!(errors.len(), 1);
    assert_eq!(errors[0]["code"], "filter_set.unknown_list");
    assert_eq!(errors[0]["params"]["list"], "missing");
    assert!(errors[0]["path"].is_null());
}

#[tokio::test]
async fn validate_does_not_bump_config_version() {
    let h = harness().await;
    let (status, _) = put(&h.state, "/api/v1/config", valid_snapshot()).await;
    assert_eq!(status, StatusCode::OK);
    let (_, before) = get(&h.state, "/api/v1/config/versions").await;

    validate(&h.state, valid_snapshot(), None).await;
    validate(&h.state, invalid_snapshot(), None).await;

    assert_eq!(current_version(&h).await, Some(1));
    let (_, after) = get(&h.state, "/api/v1/config/versions").await;
    assert_eq!(before, after, "no version row and no audit-visible change");
}

#[tokio::test]
async fn validate_reports_diff() {
    let h = harness().await;
    let (status, _) = put(&h.state, "/api/v1/config", valid_snapshot()).await;
    assert_eq!(status, StatusCode::OK);

    let (status, response) = validate(&h.state, invalid_snapshot(), None).await;
    assert_eq!(status, StatusCode::OK, "{response}");
    let diff = &response["data"]["diff"];
    assert_eq!(diff["changed_sections"], json!(["filtering"]));
    assert_eq!(diff["added"], json!(["filtering.sets"]));
    assert_eq!(diff["removed"], json!([]));
    assert_eq!(diff["changed"], json!([]));
}

#[tokio::test]
async fn validate_unauthenticated_401() {
    let clock = Arc::new(ManualClock::new(
        SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000),
    ));
    let db = Db::open_in_memory(clock).await.unwrap();
    let service = Arc::new(ConfigService::new(
        ConfigStore::new(db.clone()),
        Audit::new(db.clone()),
        ModuleAppliers::default(),
        "node-a",
    ));
    let auth = AuthState::new(
        SessionStore::new(db.clone(), IDLE, ABSOLUTE),
        TokenStore::new(db.clone(), MAX_TTL),
    );
    let state = AppState::new().with_config_service(service).with_auth(auth);
    let (status, response) = validate(&state, valid_snapshot(), None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{response}");
    assert_eq!(code(&response), "control_api.auth.unauthenticated");
}

#[tokio::test]
async fn validate_viewer_403() {
    let clock = Arc::new(ManualClock::new(
        SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000),
    ));
    let db = Db::open_in_memory(clock).await.unwrap();
    let service = Arc::new(ConfigService::new(
        ConfigStore::new(db.clone()),
        Audit::new(db.clone()),
        ModuleAppliers::default(),
        "node-a",
    ));
    let tokens = TokenStore::new(db.clone(), MAX_TTL);
    let auth = AuthState::new(
        SessionStore::new(db.clone(), IDLE, ABSOLUTE),
        TokenStore::new(db.clone(), MAX_TTL),
    );
    let viewer = tokens
        .create("v".into(), "viewer".into(), Scope::Viewer, None)
        .await
        .unwrap();
    let state = AppState::new().with_config_service(service).with_auth(auth);
    let bearer = format!("Bearer {}", viewer.plaintext().expose());
    let (status, response) = validate(&state, valid_snapshot(), Some(&bearer)).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{response}");
    assert_eq!(code(&response), "control_api.auth.insufficient_scope");
}
