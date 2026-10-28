//! GA4 integration tests: `GET /api/v1/audit` (admin-only, newest first).
//!
//! Everything is driven in-process with a `ManualClock` (no sockets, no
//! wall-clock sleeps) and loopback `MockConnectInfo` for the rate limiter.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use axum::body::Body;
use axum::extract::connect_info::MockConnectInfo;
use axum::http::{Request, StatusCode, header};
use serde_json::{Value, json};
use tower::ServiceExt as _;

use dnscraft_api::{
    AppState, Audit, AuthState, ConfigChangeRecord, Db, ManualClock, Scope, SessionStore,
    TokenStore,
};

const IDLE: Duration = Duration::from_secs(60 * 60);
const ABSOLUTE: Duration = Duration::from_secs(12 * 3600);
const MAX_TTL: Duration = Duration::from_secs(365 * 24 * 3600);
/// A value that must never survive into an audit response.
const SECRET: &str = "hunter2-not-in-the-log";

fn clock() -> Arc<ManualClock> {
    Arc::new(ManualClock::new(SystemTime::UNIX_EPOCH))
}

fn auth_state(db: &Db) -> AuthState {
    AuthState::new(
        SessionStore::new(db.clone(), IDLE, ABSOLUTE),
        TokenStore::new(db.clone(), MAX_TTL),
    )
}

fn bearer(value: &str) -> String {
    format!("Bearer {value}")
}

fn test_addr() -> std::net::SocketAddr {
    std::net::SocketAddr::from(([127, 0, 0, 1], 40_000))
}

async fn send(router: axum::Router, req: Request<Body>) -> (StatusCode, Value) {
    let res = router.oneshot(req).await.unwrap();
    let status = res.status();
    let bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .unwrap();
    (status, serde_json::from_slice(&bytes).unwrap())
}

async fn get_req(router: &axum::Router, uri: &str, auth: Option<&str>) -> (StatusCode, Value) {
    let mut builder = Request::builder().method("GET").uri(uri);
    if let Some(auth) = auth {
        builder = builder.header(header::AUTHORIZATION, auth);
    }
    send(router.clone(), builder.body(Body::empty()).unwrap()).await
}

async fn tokens(db: &Db, actor: &str, scope: Scope) -> String {
    let token = TokenStore::new(db.clone(), MAX_TTL)
        .create(actor.into(), "test".into(), scope, None)
        .await
        .unwrap();
    token.plaintext().expose().to_owned()
}

fn change(action: &str, config_version: i64, before: Value) -> ConfigChangeRecord {
    ConfigChangeRecord {
        node_id: "node-a".into(),
        actor_id: "admin".into(),
        actor_type: "user".into(),
        action: action.into(),
        config_version: Some(config_version),
        before: Some(before),
        after: None,
        result: "ok".into(),
        error_code: None,
    }
}

#[tokio::test]
async fn admin_lists_audit_newest_first_without_secrets() {
    let clock = clock();
    let db = Db::open_in_memory(clock.clone()).await.unwrap();
    let admin = tokens(&db, "admin", Scope::Admin).await;
    let viewer = tokens(&db, "viewer", Scope::Viewer).await;

    let audit = Audit::new(db.clone());
    audit
        .record_config_change(change(
            "config.write",
            1,
            json!({ "tls": { "password": SECRET } }),
        ))
        .await
        .unwrap();
    clock.advance(Duration::from_secs(10));
    audit
        .record_config_change(change("config.rollback", 2, json!({ "tls": {} })))
        .await
        .unwrap();

    let router = AppState::new()
        .with_auth(auth_state(&db))
        .with_db(db.clone())
        .router()
        .layer(MockConnectInfo(test_addr()));

    let (status, body) = get_req(&router, "/api/v1/audit", Some(&bearer(admin.as_str()))).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let rows = body["data"]["audit"].as_array().unwrap();
    assert_eq!(rows.len(), 2);
    // Newest first (`time DESC`).
    assert_eq!(rows[0]["action"], "config.rollback");
    assert_eq!(rows[1]["action"], "config.write");
    assert_eq!(rows[1]["node_id"], "node-a");
    assert_eq!(rows[1]["actor_type"], "user");
    assert_eq!(rows[1]["config_version"], json!(1));
    assert!(rows[1]["before_digest"].is_string());

    // Secret material was masked before storage and never appears on the wire.
    assert!(
        rows[1]["before"].as_str().unwrap().contains("redacted"),
        "before snapshot: {}",
        rows[1]["before"]
    );
    assert!(!body.to_string().contains(SECRET), "secret leaked: {body}");

    // `limit` is capped by the shared pagination parser.
    let (status, body) = get_req(
        &router,
        "/api/v1/audit?limit=501",
        Some(&bearer(admin.as_str())),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"]["code"], "control_api.pagination.invalid");

    // A viewer may not read the audit log.
    let (status, body) = get_req(&router, "/api/v1/audit", Some(&bearer(viewer.as_str()))).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["error"]["code"], "control_api.auth.insufficient_scope");
}

#[tokio::test]
async fn token_create_and_revoke_are_audited() {
    let db = Db::open_in_memory(clock()).await.unwrap();
    let admin = tokens(&db, "admin", Scope::Admin).await;
    let router = AppState::new()
        .with_auth(auth_state(&db))
        .with_db(db.clone())
        .router()
        .layer(MockConnectInfo(test_addr()));

    let create = Request::builder()
        .method("POST")
        .uri("/api/v1/auth/tokens")
        .header(header::AUTHORIZATION, bearer(admin.as_str()))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            json!({ "name": "ci", "scope": "viewer" }).to_string(),
        ))
        .unwrap();
    let (status, body) = send(router.clone(), create).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let id = body["data"]["id"].as_str().unwrap().to_owned();

    let revoke = Request::builder()
        .method("DELETE")
        .uri(format!("/api/v1/auth/tokens/{id}"))
        .header(header::AUTHORIZATION, bearer(admin.as_str()))
        .body(Body::empty())
        .unwrap();
    let (status, body) = send(router.clone(), revoke).await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let (status, body) = get_req(&router, "/api/v1/audit", Some(&bearer(admin.as_str()))).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let rows = body["data"]["audit"].as_array().unwrap();
    let actions: Vec<&str> = rows.iter().filter_map(|r| r["action"].as_str()).collect();
    assert!(actions.contains(&"auth.token.create"), "{actions:?}");
    assert!(actions.contains(&"auth.token.revoke"), "{actions:?}");
    let revoked = rows
        .iter()
        .find(|r| r["action"] == "auth.token.revoke")
        .unwrap();
    assert_eq!(revoked["object_id"], json!(id));
    assert_eq!(revoked["result"], "ok");
}
