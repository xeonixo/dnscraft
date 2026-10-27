//! A6 integration tests: cookie sessions + CSRF.
//!
//! These drive the session/CSRF middleware in-process (no socket) with a
//! `ManualClock`, so idle and absolute expiry are exercised without wall-clock
//! sleeps.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use axum::Json;
use axum::body::Body;
use axum::extract::Extension;
use axum::http::{Request, StatusCode, header};
use axum::middleware;
use axum::routing::{get, post};
use serde_json::{Value, json};
use tower::ServiceExt as _;

use dnscraft_api::{
    Db, ManualClock, Principal, Role, SessionStore, auth_middleware, secure_cookie,
    session_set_cookie,
};

const IDLE: Duration = Duration::from_secs(60 * 60);
const ABSOLUTE: Duration = Duration::from_secs(12 * 3600);

fn test_clock() -> Arc<ManualClock> {
    Arc::new(ManualClock::new(SystemTime::UNIX_EPOCH))
}

async fn store(clock: Arc<ManualClock>) -> SessionStore {
    let db = Db::open_in_memory(clock).await.unwrap();
    SessionStore::new(db, IDLE, ABSOLUTE)
}

fn cookie_header(created: &dnscraft_api::CreatedSession) -> String {
    format!("dnscraft_session={}", created.cookie().expose())
}

/// A router with one mutating `/api/v1` route, one read `/api/v1` route and one
/// `/mcp/v1` route, all wrapped by the session/CSRF middleware. Handlers report
/// whether a [`Principal`] was authenticated.
fn test_router(auth: SessionStore) -> axum::Router {
    async fn mutating(principal: Option<Extension<Principal>>) -> Json<Value> {
        principal_json(principal)
    }
    async fn reading(principal: Option<Extension<Principal>>) -> Json<Value> {
        principal_json(principal)
    }
    async fn mcp(principal: Option<Extension<Principal>>) -> Json<Value> {
        Json(json!({ "authenticated": principal.is_some() }))
    }
    axum::Router::new()
        .route("/api/v1/thing", post(mutating))
        .route("/api/v1/read", get(reading))
        .route("/mcp/v1/thing", post(mcp))
        .layer(middleware::from_fn_with_state(auth, auth_middleware))
}

fn principal_json(principal: Option<Extension<Principal>>) -> Json<Value> {
    match principal {
        Some(Extension(principal)) => Json(json!({
            "authenticated": true,
            "actor_id": principal.actor_id,
            "role": principal.role.as_str(),
        })),
        None => Json(json!({ "authenticated": false })),
    }
}

async fn send(router: &axum::Router, req: Request<Body>) -> (StatusCode, Value) {
    let res = router.clone().oneshot(req).await.unwrap();
    let status = res.status();
    let bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .unwrap();
    (status, serde_json::from_slice(&bytes).unwrap())
}

#[tokio::test]
async fn auth_session_csrf_requires_valid_token_on_mutating_request() {
    let store = store(test_clock()).await;
    let created = store.create("u1".into(), Role::Admin).await.unwrap();
    let router = test_router(store);
    let cookie = cookie_header(&created);

    // Correct token → authenticated.
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/thing")
        .header(header::COOKIE, &cookie)
        .header("x-csrf-token", created.csrf_token().expose())
        .body(Body::empty())
        .unwrap();
    let (status, body) = send(&router, req).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["authenticated"], true);
    assert_eq!(body["actor_id"], "u1");
    assert_eq!(body["role"], "admin");

    // Missing token → 403 control_api.auth.csrf.
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/thing")
        .header(header::COOKIE, &cookie)
        .body(Body::empty())
        .unwrap();
    let (status, body) = send(&router, req).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["error"]["code"], "control_api.auth.csrf");

    // Wrong token → 403 control_api.auth.csrf.
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/thing")
        .header(header::COOKIE, &cookie)
        .header("x-csrf-token", "wrong-token")
        .body(Body::empty())
        .unwrap();
    let (status, body) = send(&router, req).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["error"]["code"], "control_api.auth.csrf");
}

#[tokio::test]
async fn auth_session_bearer_request_is_exempt_from_csrf() {
    let store = store(test_clock()).await;
    // A valid session exists, but the request authenticates as a bearer token:
    // CSRF must not be required even though a session cookie is also present.
    let created = store.create("u1".into(), Role::Viewer).await.unwrap();
    let router = test_router(store);

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/thing")
        .header(header::AUTHORIZATION, "Bearer some-token")
        .header(header::COOKIE, cookie_header(&created))
        .body(Body::empty())
        .unwrap();
    let (status, body) = send(&router, req).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["authenticated"], false);
}

#[tokio::test]
async fn auth_session_cookie_authorizes_api_v1_read_without_csrf() {
    let store = store(test_clock()).await;
    let created = store.create("u1".into(), Role::Viewer).await.unwrap();
    let router = test_router(store);

    let req = Request::builder()
        .method("GET")
        .uri("/api/v1/read")
        .header(header::COOKIE, cookie_header(&created))
        .body(Body::empty())
        .unwrap();
    let (status, body) = send(&router, req).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["authenticated"], true);
    assert_eq!(body["role"], "viewer");
}

#[tokio::test]
async fn auth_session_cookie_is_not_accepted_on_mcp() {
    let store = store(test_clock()).await;
    let created = store.create("u1".into(), Role::Admin).await.unwrap();
    let router = test_router(store);

    // The same valid session cookie (with its correct CSRF token) must not
    // authenticate /mcp/v1 — MCP is bearer-token-only.
    let req = Request::builder()
        .method("POST")
        .uri("/mcp/v1/thing")
        .header(header::COOKIE, cookie_header(&created))
        .header("x-csrf-token", created.csrf_token().expose())
        .body(Body::empty())
        .unwrap();
    let (status, body) = send(&router, req).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["authenticated"], false);
}

#[tokio::test]
async fn auth_session_idle_expiry_manual_clock() {
    let clock = test_clock();
    let store = store(clock.clone()).await;
    let created = store.create("u1".into(), Role::Viewer).await.unwrap();
    let cookie = created.cookie().expose().to_owned();

    assert!(store.validate(&cookie).await.is_ok());

    // Advance just past the idle window: no wall-clock wait.
    clock.advance(IDLE + Duration::from_secs(1));
    let err = store.validate(&cookie).await.unwrap_err();
    assert_eq!(err.code(), "control_api.auth.session_expired");
}

#[tokio::test]
async fn auth_session_absolute_expiry_manual_clock() {
    let clock = test_clock();
    // Long idle, short absolute lifetime: crossing the absolute limit must win
    // even though the session is nowhere near idle.
    let db = Db::open_in_memory(clock.clone()).await.unwrap();
    let store = SessionStore::new(db, Duration::from_secs(3600), Duration::from_secs(120));
    let created = store.create("u1".into(), Role::Viewer).await.unwrap();
    let cookie = created.cookie().expose().to_owned();

    assert!(store.validate(&cookie).await.is_ok());
    clock.advance(Duration::from_secs(119));
    assert!(store.validate(&cookie).await.is_ok());

    clock.advance(Duration::from_secs(2)); // now 121 s, past the 120 s absolute limit
    let err = store.validate(&cookie).await.unwrap_err();
    assert_eq!(err.code(), "control_api.auth.session_expired");
}

#[tokio::test]
async fn auth_session_logout_invalidates_immediately() {
    let store = store(test_clock()).await;
    let created = store.create("u1".into(), Role::Admin).await.unwrap();
    let cookie = created.cookie().expose().to_owned();

    assert!(store.validate(&cookie).await.is_ok());
    store.logout(&cookie).await.unwrap();
    let err = store.validate(&cookie).await.unwrap_err();
    assert_eq!(err.code(), "control_api.auth.session_expired");
}

#[test]
fn auth_session_cookie_attributes_http_only_samesite_lax_and_secure_flag() {
    let plain = session_set_cookie("abc", false);
    assert!(plain.starts_with("dnscraft_session=abc"));
    assert!(plain.contains("HttpOnly"));
    assert!(plain.contains("SameSite=Lax"));
    assert!(!plain.contains("Secure"));

    let secure = session_set_cookie("abc", true);
    assert!(secure.contains("HttpOnly"));
    assert!(secure.contains("SameSite=Lax"));
    assert!(secure.contains("; Secure"));
}

#[test]
fn auth_session_secure_cookie_follows_tls_and_forwarded_proto() {
    assert!(secure_cookie(true, None));
    assert!(secure_cookie(false, Some("https")));
    assert!(secure_cookie(false, Some("HTTPS")));
    assert!(!secure_cookie(false, None));
    assert!(!secure_cookie(false, Some("http")));
}
