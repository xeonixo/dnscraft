//! WX8: session list and revoke (`/api/v1/auth/sessions`).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use axum::body::Body;
use axum::extract::connect_info::MockConnectInfo;
use axum::http::{Method, Request, StatusCode};
use serde_json::Value;
use tower::ServiceExt as _;

use dnscraft_api::{
    AppState, AuthState, CreatedSession, Db, ManualClock, Role, Scope, SessionStore, TokenStore,
};

const IDLE: Duration = Duration::from_secs(60 * 60);
const ABSOLUTE: Duration = Duration::from_secs(12 * 3600);
const MAX_TTL: Duration = Duration::from_secs(365 * 24 * 3600);

async fn fixture() -> (AppState, SessionStore, TokenStore) {
    let clock = Arc::new(ManualClock::new(
        SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000),
    ));
    let db = Db::open_in_memory(clock).await.unwrap();
    let sessions = SessionStore::new(db.clone(), IDLE, ABSOLUTE);
    let tokens = TokenStore::new(db.clone(), MAX_TTL);
    let state = AppState::new()
        .with_db(db)
        .with_auth(AuthState::new(sessions.clone(), tokens.clone()));
    (state, sessions, tokens)
}

async fn call(
    state: &AppState,
    method: Method,
    uri: &str,
    headers: &[(&str, String)],
) -> (StatusCode, Value) {
    let router = state
        .clone()
        .router()
        .layer(MockConnectInfo(SocketAddr::from(([127, 0, 0, 1], 40_000))));
    let mut builder = Request::builder().method(method).uri(uri);
    for (name, value) in headers {
        builder = builder.header(*name, value);
    }
    let res = router
        .oneshot(builder.body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = res.status();
    let bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

fn cookie(created: &CreatedSession) -> (&'static str, String) {
    (
        "cookie",
        format!("dnscraft_session={}", created.cookie().expose()),
    )
}

/// The CSRF header a cookie-authenticated mutation must echo.
fn csrf(created: &CreatedSession) -> (&'static str, String) {
    ("x-csrf-token", created.csrf_token().expose().to_owned())
}

#[tokio::test]
async fn viewer_lists_and_revokes_only_own_sessions() {
    let (state, sessions, _) = fixture().await;
    let meta = dnscraft_api::SessionMeta {
        ip: Some("192.0.2.0".into()),
        client_label: Some("Firefox on Linux".into()),
    };
    let alice = sessions
        .create_with_meta("alice".into(), Role::Viewer, meta)
        .await
        .unwrap();
    let alice_other = sessions.create("alice".into(), Role::Viewer).await.unwrap();
    let bob = sessions.create("bob".into(), Role::Viewer).await.unwrap();

    // Viewer scope defaults to own: alice sees two, marks her current one.
    let (status, body) = call(
        &state,
        Method::GET,
        "/api/v1/auth/sessions",
        &[cookie(&alice)],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let items = body["data"]["items"].as_array().unwrap();
    assert_eq!(items.len(), 2, "{body}");
    assert!(items.iter().all(|item| item["actor_id"] == "alice"));
    let mine = items
        .iter()
        .find(|item| item["client_label"] == "Firefox on Linux")
        .unwrap();
    assert_eq!(mine["ip"], "192.0.2.0");
    assert_eq!(mine["current"], true);
    // The public id is not the cookie, and the cookie never appears.
    let text = body.to_string();
    assert!(!text.contains(alice.cookie().expose()), "{text}");

    // Viewer may not ask for everyone.
    let (status, body) = call(
        &state,
        Method::GET,
        "/api/v1/auth/sessions?scope=all",
        &[cookie(&alice)],
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["error"]["code"], "control_api.auth.insufficient_scope");

    // Own non-current session: revoke succeeds, then the victim gets 401.
    let other_id = items
        .iter()
        .map(|item| item["id"].as_str().unwrap().to_owned())
        .find(|id| id != mine["id"].as_str().unwrap())
        .unwrap();
    let (status, body) = call(
        &state,
        Method::DELETE,
        &format!("/api/v1/auth/sessions/{other_id}"),
        &[cookie(&alice), csrf(&alice)],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(
        sessions
            .validate(alice_other.cookie().expose())
            .await
            .is_err()
    );

    // Current session: refused with session_current (use logout instead).
    let current_id = mine["id"].as_str().unwrap().to_owned();
    let (status, body) = call(
        &state,
        Method::DELETE,
        &format!("/api/v1/auth/sessions/{current_id}"),
        &[cookie(&alice), csrf(&alice)],
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["error"]["code"], "control_api.auth.session_current");

    // Another actor's session is invisible to alice: 404, not 403.
    let bob_id = {
        let (_, body) = call(
            &state,
            Method::GET,
            "/api/v1/auth/sessions?scope=own",
            &[cookie(&bob)],
        )
        .await;
        body["data"]["items"][0]["id"].as_str().unwrap().to_owned()
    };
    let (status, body) = call(
        &state,
        Method::DELETE,
        &format!("/api/v1/auth/sessions/{bob_id}"),
        &[cookie(&alice), csrf(&alice)],
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["error"]["code"], "control_api.auth.unknown_session");
    assert!(sessions.validate(bob.cookie().expose()).await.is_ok());
}

#[tokio::test]
async fn admin_lists_all_sessions_and_revokes_another_one() {
    let (state, sessions, tokens) = fixture().await;
    let admin_token = tokens
        .create("admin".into(), "ops".into(), Scope::Admin, None)
        .await
        .unwrap();
    let bearer = (
        "authorization",
        format!("Bearer {}", admin_token.plaintext().expose()),
    );
    let victim = sessions
        .create("victim".into(), Role::Viewer)
        .await
        .unwrap();

    let (status, body) = call(
        &state,
        Method::GET,
        "/api/v1/auth/sessions",
        std::slice::from_ref(&bearer),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let victim_id = body["data"]["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["actor_id"] == "victim")
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();

    let (status, body) = call(
        &state,
        Method::DELETE,
        &format!("/api/v1/auth/sessions/{victim_id}"),
        std::slice::from_ref(&bearer),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["data"]["revoked"], true);
    assert!(sessions.validate(victim.cookie().expose()).await.is_err());
}
