//! A8 integration tests: local break-glass login with lockout and audit.
//!
//! These drive `POST /api/v1/auth/local/login` through the production router
//! in-process (no socket) with a `ManualClock`, so lockout expiry is exercised
//! without wall-clock sleeps. They were written before the implementation
//! (red first) and cover the A8 acceptance criteria.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use axum::body::Body;
use axum::extract::connect_info::MockConnectInfo;
use axum::http::{HeaderMap, Request, StatusCode, header};
use serde_json::{Value, json};
use tower::ServiceExt as _;

use dnscraft_api::{
    AppState, Auth, AuthState, ControlApiError, Db, LocalAccountStore, ManualClock, Role,
    SessionStore, TokenStore,
};

const IDLE: Duration = Duration::from_secs(60 * 60);
const ABSOLUTE: Duration = Duration::from_secs(12 * 3600);
const MAX_TTL: Duration = Duration::from_secs(365 * 24 * 3600);
const MAX_ATTEMPTS: u32 = 5;
const WINDOW: Duration = Duration::from_secs(15 * 60);
const PASSWORD: &str = "correct horse battery staple";

fn clock() -> Arc<ManualClock> {
    Arc::new(ManualClock::new(SystemTime::UNIX_EPOCH))
}

fn test_addr() -> std::net::SocketAddr {
    std::net::SocketAddr::from(([127, 0, 0, 1], 40_000))
}

async fn db(clock: Arc<ManualClock>) -> Db {
    Db::open_in_memory(clock).await.unwrap()
}

/// Builds the router with a local account `admin` whose password is [`PASSWORD`].
async fn setup(clock: Arc<ManualClock>) -> (axum::Router, LocalAccountStore, SessionStore, Db) {
    let db = db(clock).await;
    let sessions = SessionStore::new(db.clone(), IDLE, ABSOLUTE);
    let auth = AuthState::new(
        Auth::new(sessions.clone()),
        TokenStore::new(db.clone(), MAX_TTL),
    );
    let local = LocalAccountStore::new(db.clone(), MAX_ATTEMPTS, WINDOW);
    local.upsert("admin", PASSWORD, Role::Admin).await.unwrap();
    let app = AppState::new()
        .with_auth(auth)
        .with_local_login(local.clone());
    let router = app.router().layer(MockConnectInfo(test_addr()));
    (router, local, sessions, db)
}

async fn send(router: axum::Router, req: Request<Body>) -> (StatusCode, HeaderMap, Value) {
    let res = router.oneshot(req).await.unwrap();
    let status = res.status();
    let headers = res.headers().clone();
    let bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .unwrap();
    let body = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, headers, body)
}

async fn login(
    router: &axum::Router,
    username: &str,
    password: &str,
) -> (StatusCode, HeaderMap, Value) {
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/auth/local/login")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            json!({ "username": username, "password": password }).to_string(),
        ))
        .unwrap();
    send(router.clone(), req).await
}

/// Extracts the `dnscraft_session` value from a `Set-Cookie` header.
fn session_cookie(headers: &HeaderMap) -> String {
    let raw = headers
        .get(header::SET_COOKIE)
        .expect("login must set a session cookie")
        .to_str()
        .unwrap();
    raw.split(';')
        .next()
        .unwrap()
        .trim()
        .strip_prefix("dnscraft_session=")
        .expect("session cookie name")
        .to_owned()
}

#[tokio::test]
async fn correct_password_creates_a_cookie_session() {
    let (router, _, sessions, _) = setup(clock()).await;

    let (status, headers, body) = login(&router, "admin", PASSWORD).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["data"]["actor_id"], "admin");
    assert_eq!(body["data"]["role"], "admin");
    let csrf = body["data"]["csrf_token"].as_str().unwrap();
    assert!(!csrf.is_empty());

    let cookie_header = headers
        .get(header::SET_COOKIE)
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();
    assert!(cookie_header.contains("HttpOnly"), "{cookie_header}");
    assert!(cookie_header.contains("SameSite=Lax"), "{cookie_header}");
    assert!(!cookie_header.contains(PASSWORD));

    // The cookie authenticates a real session with the account's role.
    let cookie = session_cookie(&headers);
    let principal = sessions.validate(&cookie).await.unwrap();
    assert_eq!(principal.actor_id, "admin");
    assert_eq!(principal.role, Role::Admin);

    // The plaintext password never appears in the response.
    assert!(!body.to_string().contains(PASSWORD));
}

#[tokio::test]
async fn session_cookie_secure_flag_follows_forwarded_proto() {
    let (router, _, _, _) = setup(clock()).await;

    // No TLS and no forwarded proto: the cookie carries no `Secure` flag.
    let (_, headers, _) = login(&router, "admin", PASSWORD).await;
    let cookie = headers.get(header::SET_COOKIE).unwrap().to_str().unwrap();
    assert!(!cookie.contains("; Secure"), "{cookie}");

    // A terminating reverse proxy reports https: the cookie must be flagged
    // `Secure` so the browser never sends it over plaintext.
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/auth/local/login")
        .header(header::CONTENT_TYPE, "application/json")
        .header("x-forwarded-proto", "https")
        .body(Body::from(
            json!({ "username": "admin", "password": PASSWORD }).to_string(),
        ))
        .unwrap();
    let (_, headers, _) = send(router.clone(), req).await;
    let cookie = headers.get(header::SET_COOKIE).unwrap().to_str().unwrap();
    assert!(cookie.contains("; Secure"), "{cookie}");
}

#[tokio::test]
async fn login_rejects_cross_site_origin() {
    let (router, _, _, _) = setup(clock()).await;

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/auth/local/login")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::ORIGIN, "https://evil.example")
        .header(header::HOST, "dns.example")
        .body(Body::from(
            json!({ "username": "admin", "password": PASSWORD }).to_string(),
        ))
        .unwrap();
    let (status, _, body) = send(router.clone(), req).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["error"]["code"], "control_api.auth.invalid_origin");

    // A same-origin request passes.
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/auth/local/login")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::ORIGIN, "https://dns.example")
        .header(header::HOST, "dns.example")
        .body(Body::from(
            json!({ "username": "admin", "password": PASSWORD }).to_string(),
        ))
        .unwrap();
    let (status, _, _) = send(router.clone(), req).await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn logout_revokes_the_session_and_clears_the_cookie() {
    let (router, _, sessions, _) = setup(clock()).await;
    let (_, headers, body) = login(&router, "admin", PASSWORD).await;
    let cookie = session_cookie(&headers);
    let csrf = body["data"]["csrf_token"].as_str().unwrap().to_owned();

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/auth/logout")
        .header(header::COOKIE, format!("dnscraft_session={cookie}"))
        .header("x-csrf-token", csrf)
        .body(Body::empty())
        .unwrap();
    let (status, headers, _) = send(router.clone(), req).await;
    assert_eq!(status, StatusCode::OK);

    assert!(sessions.validate(&cookie).await.is_err());
    let set_cookie = headers.get(header::SET_COOKIE).unwrap().to_str().unwrap();
    assert!(set_cookie.contains("Max-Age=0"), "{set_cookie}");
}

#[tokio::test]
async fn wrong_password_fails_with_auth_local() {
    let (router, _, _, _) = setup(clock()).await;

    let (status, headers, body) = login(&router, "admin", "not the password").await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert_eq!(body["error"]["code"], "control_api.auth.local");
    assert!(headers.get(header::SET_COOKIE).is_none());

    // A single failure does not lock the account.
    let (status, _, _) = login(&router, "admin", PASSWORD).await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn unknown_account_fails_with_auth_local() {
    let (router, _, _, _) = setup(clock()).await;

    let (status, _, body) = login(&router, "nobody", PASSWORD).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"]["code"], "control_api.auth.local");
}

#[tokio::test]
async fn lockout_after_max_attempts_unlocks_after_window_on_manual_clock() {
    let clock = clock();
    let (router, _, _, _) = setup(clock.clone()).await;

    // The first four failures are credential failures.
    for attempt in 1..MAX_ATTEMPTS {
        let (status, _, body) = login(&router, "admin", "wrong").await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "attempt {attempt}: {body}"
        );
        assert_eq!(body["error"]["code"], "control_api.auth.local");
    }

    // The attempt that reaches the limit locks the account.
    let (status, _, body) = login(&router, "admin", "wrong").await;
    assert_eq!(status, StatusCode::LOCKED, "{body}");
    assert_eq!(body["error"]["code"], "control_api.auth.locked");

    // A correct password is rejected while locked, with no session cookie.
    let (status, headers, body) = login(&router, "admin", PASSWORD).await;
    assert_eq!(status, StatusCode::LOCKED);
    assert_eq!(body["error"]["code"], "control_api.auth.locked");
    assert!(headers.get(header::SET_COOKIE).is_none());

    // One second before the window expires the account is still locked.
    clock.advance(WINDOW - Duration::from_secs(1));
    let (status, _, body) = login(&router, "admin", PASSWORD).await;
    assert_eq!(status, StatusCode::LOCKED, "{body}");

    // Once the window has fully elapsed the account unlocks and the correct
    // password works again — no wall-clock sleep.
    clock.advance(Duration::from_secs(1));
    let (status, _, body) = login(&router, "admin", PASSWORD).await;
    assert_eq!(status, StatusCode::OK, "{body}");

    // The counter was reset: one new failure is a plain credential failure.
    let (status, _, body) = login(&router, "admin", "wrong").await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert_eq!(body["error"]["code"], "control_api.auth.local");
}

#[tokio::test]
async fn every_success_and_failure_is_audited_without_the_password() {
    let (router, _, _, db) = setup(clock()).await;

    let (status, _, _) = login(&router, "admin", PASSWORD).await;
    assert_eq!(status, StatusCode::OK);
    let (status, _, _) = login(&router, "admin", "wrong").await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _, _) = login(&router, "nobody", "wrong").await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let records = db.audit_list(20, 0).await.unwrap();
    assert_eq!(records.len(), 3, "{records:?}");

    let mut results: Vec<(&str, Option<&str>)> = records
        .iter()
        .map(|r| (r.result.as_str(), r.error_code.as_deref()))
        .collect();
    results.sort();
    assert_eq!(
        results,
        [
            ("error", Some("control_api.auth.local")),
            ("error", Some("control_api.auth.local")),
            ("ok", None),
        ]
    );

    for record in &records {
        assert_eq!(record.action, "auth.local.login");
        assert_eq!(record.actor_type, "user");
        assert!(record.before.is_none() && record.after.is_none());
        assert!(
            !format!("{record:?}").contains(PASSWORD),
            "password leaked into audit: {record:?}"
        );
    }
    assert!(
        !format!("{records:?}").contains(PASSWORD),
        "password leaked into the audit list"
    );
}

#[tokio::test]
async fn audit_records_the_locked_attempt_too() {
    let clock = clock();
    let (router, _, _, db) = setup(clock).await;

    for _ in 0..MAX_ATTEMPTS {
        let _ = login(&router, "admin", "wrong").await;
    }
    let (status, _, _) = login(&router, "admin", PASSWORD).await;
    assert_eq!(status, StatusCode::LOCKED);

    let records = db.audit_list(20, 0).await.unwrap();
    assert_eq!(records.len(), MAX_ATTEMPTS as usize + 1);
    assert!(
        records
            .iter()
            .any(|r| r.error_code.as_deref() == Some("control_api.auth.locked")),
        "a locked attempt must be audited: {records:?}"
    );
}

#[test]
fn existing_error_codes_and_statuses_still_hold() {
    assert_eq!(ControlApiError::AuthLocal.code(), "control_api.auth.local");
    assert_eq!(
        ControlApiError::AuthLocked.code(),
        "control_api.auth.locked"
    );
}
