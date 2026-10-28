//! WP2 update check and WP3 automatic backups.
//!
//! The release service is a loopback fake that counts requests, so the
//! opt-out test can prove that no outbound call happens. Backup files go to a
//! fresh temp directory. No internet, no wall-clock waits.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, UNIX_EPOCH};

use axum::Json;
use axum::Router;
use axum::body::Body;
use axum::extract::State;
use axum::extract::connect_info::MockConnectInfo;
use axum::http::{Method, Request, StatusCode};
use axum::routing::get;
use dnscraft_api::{
    AppState, Audit, ConfigService, ConfigStore, Db, ManualClock, ModuleAppliers, run_backup_if_due,
};
use serde_json::{Value, json};
use tokio::net::TcpListener;
use tower::ServiceExt as _;

const BASE_SECS: u64 = 1_700_000_000;

/// Loopback stand-in for the GitHub latest-release endpoint.
struct FakeRelease {
    hits: Arc<AtomicUsize>,
    url: String,
}

async fn fake_release(State(hits): State<Arc<AtomicUsize>>) -> Json<Value> {
    hits.fetch_add(1, Ordering::SeqCst);
    Json(json!({
        "tag_name": "v9.9.9",
        "html_url": "https://github.com/xeonixo/dnscraft/releases/tag/v9.9.9",
    }))
}

async fn fake_release_server() -> FakeRelease {
    let hits = Arc::new(AtomicUsize::new(0));
    let app = Router::new()
        .route("/release", get(fake_release))
        .with_state(hits.clone());
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let address: SocketAddr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    FakeRelease {
        hits,
        url: format!("http://{address}/release"),
    }
}

/// A loopback address with nothing listening.
async fn closed_port_url() -> String {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);
    format!("http://{address}/release")
}

fn temp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("dnscraft-system-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

struct Harness {
    state: AppState,
    clock: Arc<ManualClock>,
    dir: PathBuf,
}

async fn harness(name: &str, release_url: &str) -> Harness {
    let clock = Arc::new(ManualClock::new(
        UNIX_EPOCH + Duration::from_secs(BASE_SECS),
    ));
    let db = Db::open_in_memory(clock.clone()).await.unwrap();
    let service = ConfigService::new(
        ConfigStore::new(db.clone()),
        Audit::new(db.clone()),
        ModuleAppliers::default(),
        "node-a",
    );
    let dir = temp_dir(name);
    let state = AppState::new()
        .with_clock(clock.clone())
        .with_db(db)
        .with_config_service(Arc::new(service))
        .with_backup_dir(dir.clone())
        .with_update_api_url(release_url);
    Harness { state, clock, dir }
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

/// Read-modify-write of the stored config, as a client would do it.
async fn enable_update_check(state: &AppState) {
    let (_, current) = call(state, Method::GET, "/api/v1/config", None).await;
    let mut config = if current["data"]["config"].is_null() {
        json!({"filtering": {}, "clients": {}, "policy": {}, "listeners": {}, "tls": {}})
    } else {
        current["data"]["config"].clone()
    };
    config["control_api_settings"] = json!({"update_check": true});
    let (status, body) = call(state, Method::PUT, "/api/v1/config", Some(config)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

#[tokio::test]
async fn update_check_is_off_by_default_and_makes_no_outbound_call() {
    let release = fake_release_server().await;
    let h = harness("update-off", &release.url).await;

    let (status, body) = call(&h.state, Method::GET, "/api/v1/update/check", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["data"]["enabled"], false);
    assert!(body["data"]["latest"].is_null());
    assert_eq!(
        release.hits.load(Ordering::SeqCst),
        0,
        "no outbound request"
    );
}

#[tokio::test]
async fn update_check_reports_a_newer_release_and_caches_it() {
    let release = fake_release_server().await;
    let h = harness("update-on", &release.url).await;
    enable_update_check(&h.state).await;

    let (status, body) = call(&h.state, Method::GET, "/api/v1/update/check", None).await;
    assert_eq!(status, StatusCode::OK);
    let data = &body["data"];
    assert_eq!(data["enabled"], true);
    assert_eq!(data["latest"], "9.9.9");
    assert_eq!(data["update_available"], true);
    assert!(
        data["release_url"]
            .as_str()
            .unwrap()
            .starts_with("https://")
    );

    // A second read inside the 24 h window reuses the cache.
    let _ = call(&h.state, Method::GET, "/api/v1/update/check", None).await;
    assert_eq!(release.hits.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn unreachable_release_service_is_a_coded_field_not_a_500() {
    let url = closed_port_url().await;
    let h = harness("update-down", &url).await;
    enable_update_check(&h.state).await;

    let (status, body) = call(&h.state, Method::GET, "/api/v1/update/check", None).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body["data"]["latest"].is_null());
    assert_eq!(body["data"]["update_available"], false);
    assert_eq!(
        body["data"]["error"]["code"],
        "control_api.update.unreachable"
    );
}

#[tokio::test]
async fn backup_settings_validate_retention_and_persist_in_config() {
    let url = closed_port_url().await;
    let h = harness("backup-settings", &url).await;

    let (status, body) = call(
        &h.state,
        Method::PUT,
        "/api/v1/backups/settings",
        Some(json!({"enabled": true, "retention_count": 0})),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"]["code"], "control_api.backups.invalid");

    let (status, _) = call(
        &h.state,
        Method::PUT,
        "/api/v1/backups/settings",
        Some(json!({"enabled": true, "retention_count": 3})),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, body) = call(&h.state, Method::GET, "/api/v1/backups", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["data"]["enabled"], true);
    assert_eq!(body["data"]["retention_count"], 3);
    assert!(body["data"]["last_run"].is_null());
    assert!(body["data"]["next_run"].is_string());
}

#[tokio::test]
async fn scheduled_backup_runs_when_due_and_keeps_the_retention_count() {
    let url = closed_port_url().await;
    let h = harness("backup-run", &url).await;
    let (status, _) = call(
        &h.state,
        Method::PUT,
        "/api/v1/backups/settings",
        Some(json!({"enabled": true, "retention_count": 2})),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Three runs, each a day apart: only the two newest files remain.
    for day in 0..3 {
        if day > 0 {
            h.clock.advance(Duration::from_secs(25 * 3600));
        }
        assert!(
            run_backup_if_due(&h.state).await.unwrap(),
            "day {day} is due"
        );
    }
    let files: Vec<_> = std::fs::read_dir(&h.dir).unwrap().flatten().collect();
    assert_eq!(files.len(), 2, "{files:?}");

    // Not due again within the same day.
    assert!(!run_backup_if_due(&h.state).await.unwrap());

    let (_, body) = call(&h.state, Method::GET, "/api/v1/backups", None).await;
    assert_eq!(body["data"]["last_run"]["result"], "ok");
    assert_eq!(body["data"]["files"], 2);
    let _ = std::fs::remove_dir_all(&h.dir);
}

#[tokio::test]
async fn backups_are_not_run_while_disabled() {
    let url = closed_port_url().await;
    let h = harness("backup-off", &url).await;
    assert!(!run_backup_if_due(&h.state).await.unwrap());
    assert!(!h.dir.exists());
}

#[tokio::test]
async fn control_api_settings_accept_only_the_documented_runtime_keys() {
    let url = closed_port_url().await;
    let h = harness("settings-keys", &url).await;
    let base = json!({"filtering": {}, "clients": {}, "policy": {}, "listeners": {}, "tls": {}});

    for bad in [
        json!({"oidc": {"token_skew_seconds": 2}}),
        json!({"query_log": {"retention_days": 0}}),
        json!({"oidc": {"client_secret": "x"}}),
        json!({"unknown": true}),
    ] {
        let mut config = base.clone();
        config["control_api_settings"] = bad.clone();
        let (status, body) = call(&h.state, Method::PUT, "/api/v1/config", Some(config)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{bad}: {body}");
        assert_eq!(body["error"]["code"], "control_api.config.invalid");
    }

    let mut config = base.clone();
    config["control_api_settings"] = json!({
        "oidc": {"admin_group": "ops", "token_skew_seconds": 60},
        "query_log": {"retention_days": 90},
    });
    let (status, body) = call(&h.state, Method::PUT, "/api/v1/config", Some(config)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (_, body) = call(&h.state, Method::GET, "/api/v1/config", None).await;
    assert_eq!(
        body["data"]["config"]["control_api_settings"]["query_log"]["retention_days"],
        90
    );
}
