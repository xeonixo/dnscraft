//! A10: atomic config apply, rollback, `If-Match` and the `mcp_rules` merge.
//!
//! The module appliers are recording fakes: the tests assert the exact apply
//! order, replay of the previous snapshot, and that a failed apply never
//! becomes the current version — without touching a real DNS module.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use axum::body::Body;
use axum::extract::connect_info::MockConnectInfo;
use axum::http::{Request, StatusCode, header};
use serde_json::{Value, json};
use tower::ServiceExt as _;

use dnscraft_api::{
    AppState, Audit, ConfigActor, ConfigService, ConfigStore, ControlApiError, Db, ManualClock,
    ModuleAppliers, ModuleFuture,
};

type Log = Arc<Mutex<Vec<String>>>;

/// A module applier that records `name:marker` and can be told to fail.
struct Fake {
    name: &'static str,
    log: Log,
    fail: Arc<AtomicBool>,
    reject: Arc<AtomicBool>,
}

impl Fake {
    fn new(name: &'static str, log: &Log) -> Self {
        Self {
            name,
            log: Arc::clone(log),
            fail: Arc::new(AtomicBool::new(false)),
            reject: Arc::new(AtomicBool::new(false)),
        }
    }

    fn entry<'a>(&'a self, config: &'a Value) -> ModuleFuture<'a> {
        Box::pin(async move {
            let marker = config.get("marker").and_then(Value::as_str).unwrap_or("-");
            self.log
                .lock()
                .unwrap()
                .push(format!("{}:{marker}", self.name));
            if self.fail.load(Ordering::SeqCst) {
                return Err(ControlApiError::Module {
                    code: "policy.config.unknown_filter_set",
                    params: Some(json!({ "filter_set": "missing" })),
                });
            }
            Ok(())
        })
    }

    fn check_validate(&self) -> Result<(), ControlApiError> {
        if self.reject.load(Ordering::SeqCst) {
            return Err(ControlApiError::Module {
                code: "policy.config.invalid",
                params: None,
            });
        }
        Ok(())
    }
}

macro_rules! impl_apply {
    ($trait:ident) => {
        impl $trait for Fake {
            fn validate(&self, _config: &Value) -> Result<(), ControlApiError> {
                self.check_validate()
            }

            fn apply<'a>(&'a self, config: &'a Value) -> ModuleFuture<'a> {
                self.entry(config)
            }
        }
    };
}

use dnscraft_api::{ApplyClients, ApplyFiltering, ApplyListeners, ApplyPolicy, ApplyTls};
impl_apply!(ApplyFiltering);
impl_apply!(ApplyClients);
impl_apply!(ApplyPolicy);
impl_apply!(ApplyListeners);
impl_apply!(ApplyTls);

struct Harness {
    service: Arc<ConfigService>,
    log: Log,
    policy_fail: Arc<AtomicBool>,
    policy_reject: Arc<AtomicBool>,
    db: Db,
}

async fn harness() -> Harness {
    let clock = Arc::new(ManualClock::new(
        SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000),
    ));
    let db = Db::open_in_memory(clock).await.unwrap();
    let log: Log = Arc::new(Mutex::new(Vec::new()));
    let policy_fail = Arc::new(AtomicBool::new(false));
    let policy_reject = Arc::new(AtomicBool::new(false));

    let filtering = Fake::new("filtering", &log);
    let clients = Fake::new("clients", &log);
    let policy = Fake::new("policy", &log);
    let listeners = Fake::new("listeners", &log);
    let tls = Fake::new("tls", &log);
    policy_fail.store(false, Ordering::SeqCst);
    let modules = ModuleAppliers {
        filtering: Some(Arc::new(filtering)),
        clients: Some(Arc::new(clients)),
        policy: Some(Arc::new(RecordingPolicy {
            inner: policy,
            fail: Arc::clone(&policy_fail),
            reject: Arc::clone(&policy_reject),
        })),
        listeners: Some(Arc::new(listeners)),
        tls: Some(Arc::new(tls)),
    };
    let service = Arc::new(ConfigService::new(
        ConfigStore::new(db.clone()),
        Audit::new(db.clone()),
        modules,
        "node-a",
    ));
    Harness {
        service,
        log,
        policy_fail,
        policy_reject,
        db,
    }
}

/// Policy applier whose failure flag the test can flip between calls.
struct RecordingPolicy {
    inner: Fake,
    fail: Arc<AtomicBool>,
    reject: Arc<AtomicBool>,
}

impl ApplyPolicy for RecordingPolicy {
    fn validate(&self, _config: &Value) -> Result<(), ControlApiError> {
        if self.reject.load(Ordering::SeqCst) {
            return Err(ControlApiError::Module {
                code: "policy.config.invalid",
                params: None,
            });
        }
        self.inner.check_validate()
    }

    fn apply<'a>(&'a self, config: &'a Value) -> ModuleFuture<'a> {
        let log = Arc::clone(&self.inner.log);
        let fail = Arc::clone(&self.fail);
        Box::pin(async move {
            let marker = config.get("marker").and_then(Value::as_str).unwrap_or("-");
            log.lock()
                .unwrap()
                .push(format!("{}:{marker}", self.inner.name));
            if fail.load(Ordering::SeqCst) {
                return Err(ControlApiError::Module {
                    code: "policy.config.unknown_filter_set",
                    params: Some(json!({ "filter_set": "missing" })),
                });
            }
            Ok(())
        })
    }
}

fn actor() -> ConfigActor {
    ConfigActor::new("admin@example.com", "user")
}

/// A full snapshot with one marker per section, so replay is observable.
fn snapshot(marker: &str) -> Value {
    json!({
        "filtering": { "marker": marker, "sets": [] },
        "clients": { "marker": marker },
        "policy": { "marker": marker },
        "listeners": { "marker": marker },
        "tls": { "marker": marker }
    })
}

fn entries(log: &Log) -> Vec<String> {
    log.lock().unwrap().clone()
}

async fn get(state: AppState, uri: &str) -> (StatusCode, Value) {
    let router = state
        .router()
        .layer(MockConnectInfo(SocketAddr::from(([127, 0, 0, 1], 40_000))));
    let res = router
        .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = res.status();
    let bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .unwrap();
    (status, serde_json::from_slice(&bytes).unwrap())
}

async fn put(
    state: AppState,
    uri: &str,
    body: Value,
    if_match: Option<&str>,
) -> (StatusCode, Value) {
    let router = state
        .router()
        .layer(MockConnectInfo(SocketAddr::from(([127, 0, 0, 1], 40_000))));
    let mut builder = Request::builder()
        .method("PUT")
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/json");
    if let Some(value) = if_match {
        builder = builder.header(header::IF_MATCH, value);
    }
    let res = router
        .oneshot(builder.body(Body::from(body.to_string())).unwrap())
        .await
        .unwrap();
    let status = res.status();
    let bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .unwrap();
    (status, serde_json::from_slice(&bytes).unwrap())
}

#[tokio::test]
async fn valid_config_applies_in_order_and_increments_version() {
    let h = harness().await;
    let version = h
        .service
        .replace(snapshot("v1"), &actor(), None)
        .await
        .unwrap();

    assert_eq!(version, 1);
    assert_eq!(
        entries(&h.log),
        [
            "filtering:v1",
            "clients:v1",
            "policy:v1",
            "listeners:v1",
            "tls:v1"
        ]
    );
    let (current, stored) = h.service.current().await.unwrap();
    assert_eq!(current, Some(1));
    assert_eq!(stored.unwrap()["policy"]["marker"], "v1");
}

#[tokio::test]
async fn policy_failure_replays_previous_snapshot_and_keeps_old_version() {
    let h = harness().await;
    h.service
        .replace(snapshot("v1"), &actor(), None)
        .await
        .unwrap();
    h.log.lock().unwrap().clear();

    h.policy_fail.store(true, Ordering::SeqCst);
    let err = h
        .service
        .replace(snapshot("v2"), &actor(), None)
        .await
        .unwrap_err();
    assert_eq!(err.code(), "policy.config.unknown_filter_set");
    assert_eq!(
        entries(&h.log),
        [
            "filtering:v2",
            "clients:v2",
            "policy:v2",
            // Replay of the previous snapshot up to (and including) policy.
            "filtering:v1",
            "clients:v1",
            "policy:v1",
        ]
    );

    let (current, stored) = h.service.current().await.unwrap();
    assert_eq!(current, Some(1), "a failed apply must not create a version");
    assert_eq!(stored.unwrap()["policy"]["marker"], "v1");
    assert_eq!(h.service.versions(10, 0).await.unwrap().len(), 1);
}

#[tokio::test]
async fn invalid_config_returns_stable_code_and_calls_no_module() {
    let h = harness().await;
    let mut body = snapshot("v1");
    body["bogus"] = json!(true);

    let err = h.service.replace(body, &actor(), None).await.unwrap_err();
    assert_eq!(err.code(), "control_api.config.invalid");
    assert!(entries(&h.log).is_empty(), "no module may be touched");

    let mut body = snapshot("v1");
    body["filtering"]["sets"] = json!([{ "id": "default", "bogus": true }]);
    let err = h.service.replace(body, &actor(), None).await.unwrap_err();
    assert_eq!(err.code(), "control_api.config.invalid");
    assert!(entries(&h.log).is_empty());
}

#[tokio::test]
async fn filter_set_pause_is_runtime_state_not_config() {
    // GA18: `paused_until` is no longer a versioned set field.
    let h = harness().await;
    let mut body = snapshot("v1");
    body["filtering"]["sets"] = json!([{ "id": "default", "paused_until": null }]);
    let err = h.service.replace(body, &actor(), None).await.unwrap_err();
    assert_eq!(err.code(), "control_api.config.invalid");
    assert!(entries(&h.log).is_empty());
}

#[tokio::test]
async fn module_validation_error_calls_no_module_and_keeps_code() {
    let h = harness().await;
    h.policy_reject.store(true, Ordering::SeqCst);

    let err = h
        .service
        .replace(snapshot("v1"), &actor(), None)
        .await
        .unwrap_err();
    assert_eq!(err.code(), "policy.config.invalid");
    assert!(entries(&h.log).is_empty());
    assert_eq!(h.service.current().await.unwrap().0, None);
}

#[tokio::test]
async fn stale_if_match_is_rejected_before_apply() {
    let h = harness().await;
    h.service
        .replace(snapshot("v1"), &actor(), None)
        .await
        .unwrap();
    h.log.lock().unwrap().clear();

    let err = h
        .service
        .replace(snapshot("v2"), &actor(), Some("\"999\""))
        .await
        .unwrap_err();
    assert_eq!(err.code(), "control_api.config.version");
    assert!(entries(&h.log).is_empty());

    // The current version is accepted, including the weak form.
    let version = h
        .service
        .replace(snapshot("v2"), &actor(), Some("W/\"1\""))
        .await
        .unwrap();
    assert_eq!(version, 2);
}

fn set_with_rules(id: &str, rules: Value) -> Value {
    json!({ "id": id, "name": "Default", "mcp_rules": rules })
}

fn rule(domain: &str) -> Value {
    json!({
        "id": "r1",
        "domain": domain,
        "include_subdomains": true,
        "created_at": 1_700_000_000u64,
        "expires_at": 1_700_003_600u64,
        "token_id": "tok-1"
    })
}

#[tokio::test]
async fn omitted_mcp_rules_are_carried_over_and_empty_list_deletes_them() {
    let h = harness().await;
    let mut body = snapshot("v1");
    body["filtering"]["sets"] =
        json!([set_with_rules("default", json!([rule("ads.example.com")]))]);
    h.service.replace(body, &actor(), None).await.unwrap();

    // Omit `mcp_rules`: the stored rule is carried over unchanged.
    let mut body = snapshot("v2");
    body["filtering"]["sets"] = json!([{ "id": "default", "name": "Default" }]);
    h.service.replace(body, &actor(), None).await.unwrap();
    let (_, stored) = h.service.current().await.unwrap();
    let stored = stored.unwrap();
    let rules = stored["filtering"]["sets"][0]["mcp_rules"]
        .as_array()
        .unwrap();
    assert_eq!(rules.len(), 1);
    assert_eq!(rules[0]["domain"], "ads.example.com");
    assert_eq!(rules[0]["token_id"], "tok-1");

    // Explicit empty list deletes them.
    let mut body = snapshot("v3");
    body["filtering"]["sets"] = json!([set_with_rules("default", json!([]))]);
    h.service.replace(body, &actor(), None).await.unwrap();
    let (_, stored) = h.service.current().await.unwrap();
    assert_eq!(
        stored.unwrap()["filtering"]["sets"][0]["mcp_rules"],
        json!([])
    );
}

#[tokio::test]
async fn unknown_field_inside_mcp_rule_is_rejected() {
    let h = harness().await;
    let mut bad_rule = rule("ads.example.com");
    bad_rule["unexpected"] = json!(1);
    let mut body = snapshot("v1");
    body["filtering"]["sets"] = json!([set_with_rules("default", json!([bad_rule]))]);

    let err = h.service.replace(body, &actor(), None).await.unwrap_err();
    assert_eq!(err.code(), "control_api.config.invalid");
    assert!(entries(&h.log).is_empty());
}

#[tokio::test]
async fn rollback_restores_exact_snapshot_and_is_audited() {
    let h = harness().await;
    let mut v1 = snapshot("v1");
    v1["filtering"]["sets"] = json!([set_with_rules("default", json!([rule("one.example.com")]))]);
    let v1 = h.service.replace(v1, &actor(), None).await.unwrap();

    let mut v2 = snapshot("v2");
    v2["filtering"]["sets"] = json!([set_with_rules("default", json!([rule("two.example.com")]))]);
    h.service.replace(v2, &actor(), None).await.unwrap();
    let outcome = h.service.rollback(v1 as u64, &actor(), None).await.unwrap();
    assert_eq!(outcome.restored_from, v1);
    assert_eq!(outcome.version, 3);

    let (current, restored) = h.service.current().await.unwrap();
    assert_eq!(current, Some(3));
    let stored_v1 = h.service.versions(10, 0).await.unwrap()[0];
    assert_eq!(stored_v1.0, 3);
    assert_eq!(
        restored.unwrap()["filtering"]["sets"][0]["mcp_rules"][0]["domain"],
        "one.example.com"
    );

    let audit = h.db.audit_list(10, 0).await.unwrap();
    let rollback = audit
        .iter()
        .find(|record| record.action == "config.rollback")
        .expect("rollback audit record");
    assert_eq!(rollback.result, "ok");
    assert_eq!(rollback.actor_id, "admin@example.com");
    assert_eq!(rollback.node_id, "node-a");
    assert!(
        rollback
            .after
            .as_deref()
            .is_some_and(|after| after.contains("mcp_rules")),
        "restored snapshot is recorded in the audit entry"
    );
}

#[tokio::test]
async fn rollback_of_unknown_version_is_404_code() {
    let h = harness().await;
    h.service
        .replace(snapshot("v1"), &actor(), None)
        .await
        .unwrap();
    let err = h.service.rollback(42, &actor(), None).await.unwrap_err();
    assert_eq!(err.code(), "control_api.config.unknown_version");
}

#[tokio::test]
async fn http_config_round_trip_excludes_secrets_and_returns_versions() {
    let h = harness().await;
    let mut body = snapshot("v1");
    body["tls"]["cloudflare_api_token"] = json!("super-secret-value");
    body["tls"]["node_private_key"] = json!("-----BEGIN PRIVATE KEY-----");

    let state = AppState::new().with_config_service(Arc::clone(&h.service));
    let (status, response) = put(state.clone(), "/api/v1/config", body, None).await;
    assert_eq!(status, StatusCode::OK, "{response}");
    assert_eq!(response["data"]["version"], 1);

    let (status, exported) = get(state.clone(), "/api/v1/config").await;
    assert_eq!(status, StatusCode::OK);
    let text = exported.to_string();
    assert!(
        !text.contains("super-secret-value"),
        "secret leaked: {text}"
    );
    assert!(!text.contains("BEGIN PRIVATE KEY"), "key leaked: {text}");
    assert_eq!(exported["data"]["version"], 1);
    assert_eq!(
        exported["data"]["config"]["tls"]["cloudflare_api_token"],
        "redacted"
    );

    let (status, versions) = get(state, "/api/v1/config/versions").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(versions["data"]["current_version"], 1);
    assert_eq!(versions["data"]["versions"][0]["version"], 1);
    assert_eq!(versions["data"]["has_more"], false);
}

#[tokio::test]
async fn http_put_unknown_field_returns_config_invalid_envelope() {
    let h = harness().await;
    let state = AppState::new().with_config_service(Arc::clone(&h.service));
    let mut body = snapshot("v1");
    body["policy"]["mystery"] = json!(1);
    // Unknown fields are rejected at the top level and in filter sets; a
    // section-local unknown key is accepted unless the module rejects it.
    body["mystery_section"] = json!(1);
    let (status, response) = put(state, "/api/v1/config", body, None).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(response["error"]["code"], "control_api.config.invalid");
}

#[tokio::test]
async fn http_put_module_error_propagates_module_code() {
    let h = harness().await;
    let state = AppState::new().with_config_service(Arc::clone(&h.service));
    h.policy_reject.store(true, Ordering::SeqCst);
    let (status, response) = put(state, "/api/v1/config", snapshot("v1"), None).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(response["error"]["code"], "policy.config.invalid");
}

#[tokio::test]
async fn bootstrap_seed_initialises_only_an_empty_store() {
    // GA28: TOML/env values become version 1 only when SQLite has no config.
    let h = harness().await;
    assert_eq!(
        h.service.seed_if_empty(snapshot("boot")).await.unwrap(),
        Some(1)
    );
    assert_eq!(h.service.current().await.unwrap().0, Some(1));
    // A later start with different bootstrap values changes nothing.
    assert_eq!(
        h.service.seed_if_empty(snapshot("later")).await.unwrap(),
        None
    );
    let (_, stored) = h.service.current().await.unwrap();
    assert_eq!(stored.unwrap()["filtering"]["marker"], "boot");
}
