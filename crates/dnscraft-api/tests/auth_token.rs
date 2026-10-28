//! A7 integration tests: bearer tokens, the four scopes and centralized RBAC.
//!
//! These drive the middleware in-process (no socket) with a `ManualClock`, so
//! token expiry is exercised without wall-clock sleeps. They were written
//! before the implementation (red first) and cover the A7 acceptance criteria.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use axum::Json;
use axum::body::Body;
use axum::extract::Extension;
use axum::extract::connect_info::MockConnectInfo;
use axum::http::{Request, StatusCode, header};
use axum::middleware;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use serde_json::{Value, json};
use tower::ServiceExt as _;

use dnscraft_api::{
    AppState, AuthState, Authenticated, ControlApiError, Db, ManualClock, Role, Scope,
    SessionStore, SystemClock, TlsMode, TlsStatus, TlsStatusProvider, TokenStore, auth_middleware,
    rbac_middleware,
};

const IDLE: Duration = Duration::from_secs(60 * 60);
const ABSOLUTE: Duration = Duration::from_secs(12 * 3600);
const MAX_TTL: Duration = Duration::from_secs(365 * 24 * 3600);

fn clock() -> Arc<ManualClock> {
    Arc::new(ManualClock::new(SystemTime::UNIX_EPOCH))
}

async fn db(clock: Arc<ManualClock>) -> Db {
    Db::open_in_memory(clock).await.unwrap()
}

fn auth_state(db: &Db) -> AuthState {
    AuthState::new(
        SessionStore::new(db.clone(), IDLE, ABSOLUTE),
        TokenStore::new(db.clone(), MAX_TTL),
    )
}

fn tokens(db: &Db) -> TokenStore {
    TokenStore::new(db.clone(), MAX_TTL)
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

async fn post_req(router: &axum::Router, uri: &str, auth: Option<&str>) -> (StatusCode, Value) {
    let mut builder = Request::builder().method("POST").uri(uri);
    if let Some(auth) = auth {
        builder = builder.header(header::AUTHORIZATION, auth);
    }
    send(router.clone(), builder.body(Body::empty()).unwrap()).await
}

async fn delete_req(router: &axum::Router, uri: &str, auth: Option<&str>) -> (StatusCode, Value) {
    let mut builder = Request::builder().method("DELETE").uri(uri);
    if let Some(auth) = auth {
        builder = builder.header(header::AUTHORIZATION, auth);
    }
    send(router.clone(), builder.body(Body::empty()).unwrap()).await
}

/// A router with one read and one write `/api/v1` route plus one `/mcp/v1`
/// route, wrapped in the same two middleware layers the production router uses.
fn rbac_router(app: AppState, sessions: SessionStore) -> axum::Router {
    async fn read(Extension(auth): Extension<Authenticated>) -> Json<Value> {
        principal_json(&auth)
    }
    async fn write(Extension(auth): Extension<Authenticated>) -> Json<Value> {
        principal_json(&auth)
    }
    async fn mcp(Extension(auth): Extension<Authenticated>) -> Json<Value> {
        principal_json(&auth)
    }
    axum::Router::new()
        .route("/api/v1/read", get(read))
        .route("/api/v1/write", post(write))
        .route("/mcp/v1", post(mcp))
        .with_state(app.clone())
        .layer(middleware::from_fn_with_state(app.clone(), rbac_middleware))
        .layer(middleware::from_fn_with_state(sessions, auth_middleware))
}

fn principal_json(auth: &Authenticated) -> Json<Value> {
    Json(json!({
        "authenticated": true,
        "actor_id": auth.actor_id(),
        "scope": auth.scope().as_str(),
    }))
}

/// A minimal TLS status provider so the token-create response can report the
/// bootstrap certificate warning.
struct FakeTls(TlsMode);

impl TlsStatusProvider for FakeTls {
    fn status(&self) -> TlsStatus {
        TlsStatus::new(self.0, "00".repeat(32))
    }
}

#[test]
fn new_auth_codes_have_documented_statuses() {
    assert_eq!(
        ControlApiError::AuthUnauthenticated.code(),
        "control_api.auth.unauthenticated"
    );
    assert_eq!(
        ControlApiError::AuthInvalidScope.code(),
        "control_api.auth.invalid_scope"
    );
    assert_eq!(
        ControlApiError::AuthInvalidOrigin.code(),
        "control_api.auth.invalid_origin"
    );
    assert_eq!(
        ControlApiError::AuthUnauthenticated
            .into_response()
            .status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        ControlApiError::AuthInvalidScope.into_response().status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        ControlApiError::AuthInvalidOrigin.into_response().status(),
        StatusCode::FORBIDDEN
    );
}

#[tokio::test]
async fn token_plaintext_is_returned_once_and_only_the_hash_is_stored() {
    let db = db(clock()).await;
    let store = tokens(&db);
    let app = AppState::new().with_auth(auth_state(&db));
    let admin = store
        .create("admin".into(), "admin".into(), Scope::Admin, None)
        .await
        .unwrap();
    let router = app.router().layer(MockConnectInfo(test_addr()));

    let body = json!({ "name": "ci", "scope": "mcp:read" });
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/auth/tokens")
        .header(header::AUTHORIZATION, bearer(admin.plaintext().expose()))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    let (status, first) = send(router.clone(), req).await;
    assert_eq!(status, StatusCode::OK, "{first}");
    let plaintext = first["data"]["token"].as_str().unwrap().to_owned();
    assert_eq!(plaintext.len(), 64);
    assert_eq!(first["data"]["scope"], "mcp:read");
    assert_eq!(first["data"]["warnings"], json!([]));
    // The token appears exactly once in its own response.
    assert_eq!(first.to_string().matches(&plaintext).count(), 1);

    // A second creation response never repeats the first plaintext.
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/auth/tokens")
        .header(header::AUTHORIZATION, bearer(admin.plaintext().expose()))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            json!({ "name": "other", "scope": "viewer" }).to_string(),
        ))
        .unwrap();
    let (status, second) = send(router, req).await;
    assert_eq!(status, StatusCode::OK);
    assert!(!second.to_string().contains(&plaintext));

    // The stored principal exposes only the hash/id, never the plaintext (the
    // raw SQLite assertion lives in the `tokens` unit tests).
    let principal = store.authenticate(&plaintext).await.unwrap();
    assert_eq!(principal.actor_id(), "admin");
    assert_eq!(principal.scope(), Scope::McpRead);
    assert_eq!(principal.id().len(), 64);
    assert_ne!(principal.id(), plaintext);
    assert!(!format!("{principal:?}").contains(&plaintext));
}

#[tokio::test]
async fn revoked_token_immediately_fails_unauthenticated() {
    let db = db(clock()).await;
    let store = tokens(&db);
    let auth = auth_state(&db);
    let sessions = auth.sessions().clone();
    let router = rbac_router(AppState::new().with_auth(auth), sessions);

    let token = store
        .create("u1".into(), "t".into(), Scope::Viewer, None)
        .await
        .unwrap();
    let header = bearer(token.plaintext().expose());
    let (status, _) = get_req(&router, "/api/v1/read", Some(&header)).await;
    assert_eq!(status, StatusCode::OK);

    store.revoke(token.id()).await.unwrap();
    let (status, body) = get_req(&router, "/api/v1/read", Some(&header)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"]["code"], "control_api.auth.unauthenticated");
}

#[tokio::test]
async fn scopes_are_the_four_fixed_values() {
    for (name, scope, mcp) in [
        ("viewer", Scope::Viewer, false),
        ("admin", Scope::Admin, false),
        ("mcp:read", Scope::McpRead, true),
        ("mcp:write", Scope::McpWrite, true),
    ] {
        assert_eq!(Scope::parse(name), Some(scope));
        assert_eq!(scope.as_str(), name);
        assert_eq!(
            scope.family(),
            if mcp {
                dnscraft_api::EndpointFamily::Mcp
            } else {
                dnscraft_api::EndpointFamily::Api
            }
        );
    }
    assert_eq!(Scope::parse("owner"), None);
}

#[tokio::test]
async fn viewer_cannot_call_admin_route_but_admin_can() {
    let db = db(clock()).await;
    let store = tokens(&db);
    let auth = auth_state(&db);
    let sessions = auth.sessions().clone();
    let router = rbac_router(AppState::new().with_auth(auth), sessions);

    let viewer = store
        .create("v".into(), "viewer".into(), Scope::Viewer, None)
        .await
        .unwrap();
    let admin = store
        .create("a".into(), "admin".into(), Scope::Admin, None)
        .await
        .unwrap();

    let (status, _) = get_req(
        &router,
        "/api/v1/read",
        Some(&bearer(viewer.plaintext().expose())),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, body) = post_req(
        &router,
        "/api/v1/write",
        Some(&bearer(viewer.plaintext().expose())),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["error"]["code"], "control_api.auth.insufficient_scope");
    assert_eq!(body["error"]["params"]["required"], "admin");

    let (status, body) = post_req(
        &router,
        "/api/v1/write",
        Some(&bearer(admin.plaintext().expose())),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["scope"], "admin");
}

#[tokio::test]
async fn wrong_endpoint_family_is_rejected_with_invalid_scope() {
    let db = db(clock()).await;
    let store = tokens(&db);
    let auth = auth_state(&db);
    let sessions = auth.sessions().clone();
    // The family check only runs when the MCP endpoint is enabled; a disabled
    // endpoint is a 404 (GM10).
    let mcp = dnscraft_mcp::McpConfig {
        enabled: true,
        ..Default::default()
    };
    let router = rbac_router(
        AppState::new().with_auth(auth).with_mcp_config(mcp),
        sessions,
    );

    let viewer = store
        .create("v".into(), "viewer".into(), Scope::Viewer, None)
        .await
        .unwrap();
    let mcp_read = store
        .create("v".into(), "mcp".into(), Scope::McpRead, None)
        .await
        .unwrap();

    // viewer/admin tokens are not valid on /mcp/v1.
    let (status, body) = post_req(
        &router,
        "/mcp/v1",
        Some(&bearer(viewer.plaintext().expose())),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["error"]["code"], "control_api.auth.invalid_scope");

    // mcp:* tokens are not valid on /api/v1 (read or write).
    for (method, path) in [("GET", "/api/v1/read"), ("POST", "/api/v1/write")] {
        let req = Request::builder()
            .method(method)
            .uri(path)
            .header(header::AUTHORIZATION, bearer(mcp_read.plaintext().expose()))
            .body(Body::empty())
            .unwrap();
        let (status, body) = send(router.clone(), req).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{method} {path}");
        assert_eq!(body["error"]["code"], "control_api.auth.invalid_scope");
    }

    // The same MCP token works on its own family.
    let (status, body) = post_req(
        &router,
        "/mcp/v1",
        Some(&bearer(mcp_read.plaintext().expose())),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["scope"], "mcp:read");
}

#[tokio::test]
async fn missing_or_malformed_token_returns_unauthenticated() {
    let db = db(clock()).await;
    let auth = auth_state(&db);
    let sessions = auth.sessions().clone();
    let router = rbac_router(AppState::new().with_auth(auth), sessions);

    for auth in [
        None,
        Some("Bearer"),
        Some("Bearer "),
        Some("Basic abc"),
        Some("Bearer not-a-real-token"),
    ] {
        let (status, body) = get_req(&router, "/api/v1/read", auth).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "header {auth:?}");
        assert_eq!(
            body["error"]["code"], "control_api.auth.unauthenticated",
            "header {auth:?}"
        );
    }
}

#[tokio::test]
async fn token_creation_requires_admin_and_all_four_scopes_are_selectable() {
    let db = db(clock()).await;
    let store = tokens(&db);
    let app = AppState::new().with_auth(auth_state(&db));
    let router = app.router().layer(MockConnectInfo(test_addr()));

    let viewer = store
        .create("v".into(), "viewer".into(), Scope::Viewer, None)
        .await
        .unwrap();
    let admin = store
        .create("a".into(), "admin".into(), Scope::Admin, None)
        .await
        .unwrap();

    let create = |auth: &str, scope: &'static str| {
        let req = Request::builder()
            .method("POST")
            .uri("/api/v1/auth/tokens")
            .header(header::AUTHORIZATION, auth.to_owned())
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(
                json!({ "name": "n", "scope": scope }).to_string(),
            ))
            .unwrap();
        (req, router.clone())
    };

    // A viewer cannot create tokens.
    let (req, r) = create(&bearer(viewer.plaintext().expose()), "mcp:write");
    let (status, body) = send(r, req).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["error"]["code"], "control_api.auth.insufficient_scope");

    // An admin can select each of the four scopes; each token is unique.
    let mut seen = Vec::new();
    for scope in ["viewer", "admin", "mcp:read", "mcp:write"] {
        let (req, r) = create(&bearer(admin.plaintext().expose()), scope);
        let (status, body) = send(r, req).await;
        assert_eq!(status, StatusCode::OK, "{scope}: {body}");
        assert_eq!(body["data"]["scope"], scope);
        let token = body["data"]["token"].as_str().unwrap().to_owned();
        assert!(!seen.contains(&token));
        seen.push(token);
    }
}

#[tokio::test]
async fn token_create_reports_self_signed_warning_while_bootstrap_cert_is_served() {
    let db = db(clock()).await;
    let store = tokens(&db);
    let app = AppState::new()
        .with_auth(auth_state(&db))
        .with_tls(Arc::new(FakeTls(TlsMode::SelfSigned)));
    let router = app.router().layer(MockConnectInfo(test_addr()));
    let admin = store
        .create("a".into(), "admin".into(), Scope::Admin, None)
        .await
        .unwrap();

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/auth/tokens")
        .header(header::AUTHORIZATION, bearer(admin.plaintext().expose()))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            json!({ "name": "mcp", "scope": "mcp:read" }).to_string(),
        ))
        .unwrap();
    let (status, body) = send(router.clone(), req).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body["data"]["warnings"],
        json!(["control_api.tls.self_signed"])
    );

    let app = AppState::new()
        .with_auth(auth_state(&db))
        .with_tls(Arc::new(FakeTls(TlsMode::Acme)));
    let router = app.router().layer(MockConnectInfo(test_addr()));
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/auth/tokens")
        .header(header::AUTHORIZATION, bearer(admin.plaintext().expose()))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            json!({ "name": "mcp2", "scope": "mcp:read" }).to_string(),
        ))
        .unwrap();
    let (status, body) = send(router, req).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["data"]["warnings"], json!([]));
}

#[tokio::test]
async fn session_role_still_authorizes_api_and_is_enforced_by_rbac() {
    let clock = Arc::new(SystemClock);
    let db = Db::open_in_memory(clock).await.unwrap();
    let auth = auth_state(&db);
    let sessions = auth.sessions().clone();
    let viewer_session = auth
        .sessions()
        .create("u1".into(), Role::Viewer)
        .await
        .unwrap();
    let app = AppState::new().with_auth(auth);
    let router = rbac_router(app, sessions);

    let cookie = format!("dnscraft_session={}", viewer_session.cookie().expose());
    let req = Request::builder()
        .method("GET")
        .uri("/api/v1/read")
        .header(header::COOKIE, &cookie)
        .body(Body::empty())
        .unwrap();
    let (status, body) = send(router.clone(), req).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["scope"], "viewer");

    // A viewer session cannot take an admin action.
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/write")
        .header(header::COOKIE, &cookie)
        .header("x-csrf-token", viewer_session.csrf_token().expose())
        .body(Body::empty())
        .unwrap();
    let (status, body) = send(router, req).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["error"]["code"], "control_api.auth.insufficient_scope");
}

#[tokio::test]
async fn auth_me_reports_session_identity_and_csrf_token() {
    let db = db(clock()).await;
    let auth = auth_state(&db);
    let session = auth
        .sessions()
        .create("alice".into(), Role::Admin)
        .await
        .unwrap();
    let router = AppState::new()
        .with_auth(auth)
        .router()
        .layer(MockConnectInfo(test_addr()));

    let req = Request::builder()
        .method("GET")
        .uri("/api/v1/auth/me")
        .header(
            header::COOKIE,
            format!("dnscraft_session={}", session.cookie().expose()),
        )
        .body(Body::empty())
        .unwrap();
    let (status, body) = send(router.clone(), req).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["data"]["role"], "admin");
    assert_eq!(body["data"]["actor_id"], "alice");
    assert_eq!(body["data"]["actor_type"], "user");
    assert_eq!(
        body["data"]["csrf_token"].as_str().unwrap(),
        session.csrf_token().expose()
    );

    // Without credentials the route is 401, not 200-with-null.
    let req = Request::builder()
        .method("GET")
        .uri("/api/v1/auth/me")
        .body(Body::empty())
        .unwrap();
    let (status, body) = send(router, req).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"]["code"], "control_api.auth.unauthenticated");
}

#[tokio::test]
async fn admin_lists_tokens_without_plaintext_and_viewer_is_denied() {
    let db = db(clock()).await;
    let store = tokens(&db);
    let app = AppState::new().with_auth(auth_state(&db));
    let router = app.router().layer(MockConnectInfo(test_addr()));

    let admin = store
        .create("admin".into(), "admin".into(), Scope::Admin, None)
        .await
        .unwrap();
    let first = store
        .create("alice".into(), "laptop".into(), Scope::Viewer, None)
        .await
        .unwrap();
    let second = store
        .create(
            "bob".into(),
            "ci".into(),
            Scope::McpRead,
            Some(Duration::from_secs(3600)),
        )
        .await
        .unwrap();

    let (status, body) = get_req(
        &router,
        "/api/v1/auth/tokens",
        Some(&bearer(admin.plaintext().expose())),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let rows = body["data"]["tokens"].as_array().unwrap();
    assert_eq!(rows.len(), 3);

    // Each token is listed by stored hash and metadata only.
    for created in [&first, &second] {
        let row = rows
            .iter()
            .find(|row| row["id"] == created.id())
            .unwrap_or_else(|| panic!("{} not listed", created.name()));
        assert_eq!(row["name"], created.name());
        assert_eq!(row["scope"], created.scope().as_str());
        assert_eq!(row["actor_id"], created.actor_id());
        // Timestamps are RFC 3339 strings (GA20), not Unix integers.
        let fmt = |t: i64| {
            time::OffsetDateTime::from_unix_timestamp(t)
                .unwrap()
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap()
        };
        assert_eq!(row["created_at"], json!(fmt(created.created_at())));
        assert_eq!(row["expires_at"], json!(created.expires_at().map(fmt)));
    }

    // No plaintext token ever appears in the list response.
    let text = body.to_string();
    for created in [&admin, &first, &second] {
        assert!(
            !text.contains(created.plaintext().expose()),
            "plaintext leaked for {}",
            created.name()
        );
    }

    // A viewer cannot list tokens.
    let viewer = store
        .create("v".into(), "viewer".into(), Scope::Viewer, None)
        .await
        .unwrap();
    let (status, body) = get_req(
        &router,
        "/api/v1/auth/tokens",
        Some(&bearer(viewer.plaintext().expose())),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["error"]["code"], "control_api.auth.insufficient_scope");
}

#[tokio::test]
async fn admin_revokes_token_and_unknown_or_viewer_is_rejected() {
    let db = db(clock()).await;
    let store = tokens(&db);
    let app = AppState::new().with_auth(auth_state(&db));
    let router = app.router().layer(MockConnectInfo(test_addr()));

    let admin = store
        .create("admin".into(), "admin".into(), Scope::Admin, None)
        .await
        .unwrap();
    let target = store
        .create("bob".into(), "ci".into(), Scope::Viewer, None)
        .await
        .unwrap();
    let target_header = bearer(target.plaintext().expose());

    // The token authenticates before revocation.
    let (status, _) = get_req(&router, "/api/v1/auth/me", Some(&target_header)).await;
    assert_eq!(status, StatusCode::OK);

    let uri = format!("/api/v1/auth/tokens/{}", target.id());
    let (status, body) = delete_req(&router, &uri, Some(&bearer(admin.plaintext().expose()))).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["data"]["deleted"], true);

    // Revocation takes effect on the very next request.
    let (status, body) = get_req(&router, "/api/v1/auth/me", Some(&target_header)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"]["code"], "control_api.auth.unauthenticated");

    // An unknown id is a 404, not an authentication failure.
    let (status, body) = delete_req(
        &router,
        "/api/v1/auth/tokens/does-not-exist",
        Some(&bearer(admin.plaintext().expose())),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["error"]["code"], "control_api.auth.unknown_token");

    // A viewer cannot revoke any token.
    let viewer = store
        .create("v".into(), "viewer".into(), Scope::Viewer, None)
        .await
        .unwrap();
    let victim = store
        .create("c".into(), "victim".into(), Scope::Viewer, None)
        .await
        .unwrap();
    let uri = format!("/api/v1/auth/tokens/{}", victim.id());
    let (status, body) =
        delete_req(&router, &uri, Some(&bearer(viewer.plaintext().expose()))).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["error"]["code"], "control_api.auth.insufficient_scope");
}

#[tokio::test]
async fn auth_me_reports_bearer_identity_without_csrf() {
    let db = db(clock()).await;
    let token = tokens(&db)
        .create("bob".into(), "ci".into(), Scope::Viewer, None)
        .await
        .unwrap();
    let router = AppState::new()
        .with_auth(auth_state(&db))
        .router()
        .layer(MockConnectInfo(test_addr()));

    let req = Request::builder()
        .method("GET")
        .uri("/api/v1/auth/me")
        .header(header::AUTHORIZATION, bearer(token.plaintext().expose()))
        .body(Body::empty())
        .unwrap();
    let (status, body) = send(router, req).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["data"]["role"], "viewer");
    assert_eq!(body["data"]["actor_id"], "bob");
    assert_eq!(body["data"]["actor_type"], "token");
    assert!(body["data"]["csrf_token"].is_null());
}
