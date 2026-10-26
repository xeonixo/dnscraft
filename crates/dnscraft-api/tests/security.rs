//! A14: consolidated security regression tests for the control-api threat model.
//!
//! Each test names one threat from SPEC-control-api.md § Security / § Threat
//! model. The per-task suites already cover the individual acceptance criteria;
//! this file keeps the security-critical regressions in one place, adds the
//! missing path-traversal and public-listener-isolation checks, and proves the
//! internal-only bind rule end to end. All data is in-memory, all addresses are
//! documentation ranges, and no test touches the internet.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use axum::Json;
use axum::body::Body;
use axum::extract::Extension;
use axum::extract::connect_info::MockConnectInfo;
use axum::http::{Request, StatusCode, header};
use axum::middleware;
use axum::response::IntoResponse;
use axum::routing::post;
use serde_json::{Value, json};
use tower::ServiceExt as _;

use dnscraft_api::{
    AppState, Audit, Auth, ConfigChangeRecord, ConfigService, ConfigStore, ControlApiConfig,
    ControlApiError, Db, ManualClock, ModuleAppliers, Principal, QueryLog, QueryLogConfig,
    QueryLogFilter, RateLimitConfig, RateLimiter, Role, Scope, SessionStore, TokenStore,
    auth_middleware, serve,
};
use dnscraft_listeners::{DohPath, parse_doh_path};

fn test_addr() -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], 40_000))
}

fn clock() -> Arc<ManualClock> {
    Arc::new(ManualClock::new(
        SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000),
    ))
}

async fn send(router: axum::Router, req: Request<Body>) -> (StatusCode, Value) {
    let res = router.oneshot(req).await.unwrap();
    let status = res.status();
    let bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .unwrap();
    (status, serde_json::from_slice(&bytes).unwrap())
}

async fn call(
    state: &AppState,
    method: &str,
    uri: &str,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let router = state.clone().router().layer(MockConnectInfo(test_addr()));
    let builder = Request::builder().method(method).uri(uri);
    let req = match body {
        Some(body) => builder
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_string()))
            .unwrap(),
        None => builder.body(Body::empty()).unwrap(),
    };
    send(router, req).await
}

async fn config_state() -> AppState {
    let db = Db::open_in_memory(clock()).await.unwrap();
    let service = Arc::new(ConfigService::new(
        ConfigStore::new(db.clone()),
        Audit::new(db),
        ModuleAppliers::default(),
        "node-a",
    ));
    AppState::new().with_config_service(service)
}

// --- threat: internal-only bind -------------------------------------------

/// The API never binds a wildcard or public address. `serve` validates before
/// it opens a socket, so a misconfiguration fails closed rather than exposing
/// the API on every interface.
#[tokio::test]
async fn security_api_refuses_wildcard_and_public_bind_addresses() {
    for bind in ["0.0.0.0", "::", "198.51.100.10"] {
        let config = ControlApiConfig {
            bind: bind.parse().unwrap(),
            ..ControlApiConfig::default()
        };
        assert_eq!(
            config.validate().unwrap_err().code(),
            "control_api.config.invalid",
            "{bind}"
        );

        let err = serve(config, AppState::new(), None).await.unwrap_err();
        assert_eq!(
            err.code(),
            "control_api.config.invalid",
            "{bind} must be rejected before bind"
        );
    }

    // Loopback remains the accepted default.
    assert!(ControlApiConfig::default().validate().is_ok());
}

// --- threat: API reachable through a public DoH/DoT listener --------------

/// Public DNS listeners understand only `/dns-query` and `/dns-query/<id>`.
/// Every control-api path is `Other`, which the listener answers with a bare
/// 404 and never routes into the API.
#[test]
fn security_public_doh_listener_serves_only_dns_query_paths() {
    assert_eq!(parse_doh_path("/dns-query"), DohPath::Bare);
    assert_eq!(
        parse_doh_path("/dns-query/phone"),
        DohPath::ClientId("phone".to_owned())
    );
    for api_path in [
        "/api/v1/status",
        "/api/v1/config",
        "/api/v1/query-log",
        "/healthz",
        "/readyz",
        "/mcp/v1",
        "/",
    ] {
        assert_eq!(
            parse_doh_path(api_path),
            DohPath::Other,
            "{api_path} must not be a public DoH route"
        );
    }
}

/// The inverse boundary: the internal control-api router never serves a DNS
/// query path.
#[tokio::test]
async fn security_control_api_router_does_not_serve_dns_query_paths() {
    let state = AppState::new();
    for path in ["/dns-query", "/dns-query/phone"] {
        let (status, body) = call(&state, "GET", path, None).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{path}");
        assert_eq!(body["error"]["code"], "control_api.not_found", "{path}");
    }
}

// --- threat: path traversal ------------------------------------------------

/// Path traversal is rejected on every config path, including the raw
/// `PUT /config` snapshot (a bypass for the per-list route's guard before A14).
/// The control-api data directory is a server-side bootstrap value and is
/// never accepted from a request.
#[tokio::test]
async fn security_path_traversal_is_rejected_on_every_config_path() {
    let state = config_state().await;
    let traversal = json!({
        "id": "evil",
        "name": "evil",
        "source": { "file": "../../etc/passwd" },
        "enabled": true,
    });

    let (status, body) = call(
        &state,
        "PUT",
        "/api/v1/filter-lists",
        Some(traversal.clone()),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"]["code"], "filter_store.invalid_source");

    // An absolute path is rejected the same way — it would read a file outside
    // the data directory rather than traverse into it.
    let (status, body) = call(
        &state,
        "PUT",
        "/api/v1/filter-lists",
        Some(json!({
            "id": "abs",
            "name": "abs",
            "source": { "file": "/etc/passwd" },
            "enabled": true,
        })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"]["code"], "filter_store.invalid_source");

    // The raw snapshot must not be a traversal bypass.
    let (status, body) = call(
        &state,
        "PUT",
        "/api/v1/config",
        Some(json!({
            "filtering": { "lists": [traversal] },
            "clients": {},
            "policy": {},
            "listeners": {},
            "tls": {},
        })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["error"]["code"], "control_api.config.invalid");

    // Positive control: the same snapshot with a traversal-free path is
    // accepted, so the rejection above is the `..` guard and not some other
    // shape validation.
    let (status, body) = call(
        &state,
        "PUT",
        "/api/v1/config",
        Some(json!({
            "filtering": { "lists": [{
                "id": "safe",
                "name": "safe",
                "source": { "file": "custom.hosts" },
                "enabled": true,
            }] },
            "clients": {},
            "policy": {},
            "listeners": {},
            "tls": {},
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let (status, body) = call(
        &state,
        "PUT",
        "/api/v1/config",
        Some(json!({
            "data_dir": "/tmp/attacker",
            "filtering": {},
            "clients": {},
            "policy": {},
            "listeners": {},
            "tls": {},
        })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"]["code"], "control_api.config.invalid");

    // A route segment is an identifier, never a filesystem path.
    let (status, body) = call(
        &state,
        "GET",
        "/api/v1/policy/views/..%2F..%2Fetc%2Fpasswd",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["error"]["code"], "control_api.not_found");
}

// --- threat: blind SSRF via filter-list URL --------------------------------

/// A filter-list `url` must be https and must not point at an internal host
/// (loopback/private/link-local/ULA) — a blind SSRF against the node's own
/// services is rejected at config time.
#[tokio::test]
async fn security_filter_list_url_rejects_internal_hosts() {
    let state = config_state().await;
    for host in [
        "127.0.0.1",
        "169.254.169.254",
        "192.168.1.10",
        "[::1]",
        "[fd00::1]",
    ] {
        let (status, body) = call(
            &state,
            "PUT",
            "/api/v1/filter-lists",
            Some(json!({
                "id": "ssrf",
                "name": "ssrf",
                "source": { "url": format!("https://{host}/blocklist.txt") },
                "enabled": true,
            })),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{host}: {body}");
        assert_eq!(body["error"]["code"], "filter_store.invalid_source");
    }

    // A public hostname is accepted.
    let (status, body) = call(
        &state,
        "PUT",
        "/api/v1/filter-lists",
        Some(json!({
            "id": "public",
            "name": "public",
            "source": { "url": "https://example.com/blocklist.txt" },
            "enabled": true,
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

// --- threat: SQL injection -------------------------------------------------

/// User values reach SQL only as bind parameters. An injection payload in a kv
/// key and a query-log filter is stored/filtered as data, and the tables
/// survive.
#[tokio::test]
async fn security_sql_injection_is_treated_as_data() {
    let db = Db::open_in_memory(clock()).await.unwrap();
    let injection = "'; DROP TABLE audit_log; --";

    db.kv_set(injection, injection).await.unwrap();
    assert_eq!(
        db.kv_get(injection).await.unwrap().as_deref(),
        Some(injection)
    );

    let log = QueryLog::new(db.clone(), QueryLogConfig::default(), "node-a");
    let filter = QueryLogFilter {
        domain: Some(injection.to_owned()),
        ..QueryLogFilter::default()
    };
    assert!(log.list(&filter).await.unwrap().records.is_empty());
    // The filter was bound as data: both tables still answer normal queries.
    assert!(
        log.list(&QueryLogFilter::default())
            .await
            .unwrap()
            .records
            .is_empty()
    );
    assert!(db.audit_list(1, 0).await.unwrap().is_empty());
}

// --- threat: CSRF bypass ---------------------------------------------------

fn csrf_router(auth: Auth) -> axum::Router {
    async fn mutating(principal: Option<Extension<Principal>>) -> Json<Value> {
        Json(match principal {
            Some(Extension(principal)) => {
                json!({ "authenticated": true, "actor_id": principal.actor_id })
            }
            None => json!({ "authenticated": false }),
        })
    }
    axum::Router::new()
        .route("/api/v1/thing", post(mutating))
        .layer(middleware::from_fn_with_state(auth, auth_middleware))
}

/// Cookie-session mutations require the matching synchronizer token; a missing
/// or cross-session token cannot bypass CSRF.
#[tokio::test]
async fn security_csrf_bypass_is_rejected_for_cookie_sessions() {
    let db = Db::open_in_memory(clock()).await.unwrap();
    let sessions = SessionStore::new(
        db,
        Duration::from_secs(60 * 60),
        Duration::from_secs(12 * 3600),
    );
    let first = sessions.create("u1".into(), Role::Admin).await.unwrap();
    let second = sessions.create("u2".into(), Role::Viewer).await.unwrap();
    let router = csrf_router(Auth::new(sessions));
    let cookie = format!("dnscraft_session={}", first.cookie().expose());

    let (status, body) = send(
        router.clone(),
        Request::builder()
            .method("POST")
            .uri("/api/v1/thing")
            .header(header::COOKIE, &cookie)
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["error"]["code"], "control_api.auth.csrf");

    // A token minted for another session is not a bypass.
    let (status, body) = send(
        router.clone(),
        Request::builder()
            .method("POST")
            .uri("/api/v1/thing")
            .header(header::COOKIE, &cookie)
            .header("x-csrf-token", second.csrf_token().expose())
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["error"]["code"], "control_api.auth.csrf");

    // The matching token authenticates the request.
    let (status, body) = send(
        router,
        Request::builder()
            .method("POST")
            .uri("/api/v1/thing")
            .header(header::COOKIE, &cookie)
            .header("x-csrf-token", first.csrf_token().expose())
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["authenticated"], true);
}

// --- threat: forwarded-header spoofing ------------------------------------

fn small_rate_config() -> RateLimitConfig {
    RateLimitConfig {
        read_per_second: 2,
        write_per_second: 2,
        auth_per_second: 2,
        burst_factor: 2,
    }
}

fn rate_state(trusted: Vec<IpAddr>) -> AppState {
    let limiter = RateLimiter::with_capacity(small_rate_config(), clock(), trusted, 8);
    AppState::new().with_rate_limiter(Arc::new(limiter))
}

async fn call_with_header(
    state: &AppState,
    name: &'static str,
    value: &str,
) -> (StatusCode, Value) {
    let router = state.clone().router().layer(MockConnectInfo(test_addr()));
    send(
        router,
        Request::builder()
            .uri("/api/v1/status")
            .header(name, value)
            .body(Body::empty())
            .unwrap(),
    )
    .await
}

/// The source IP comes from the socket peer. `X-Forwarded-For` is honoured
/// only when that peer is a configured trusted proxy, so an untrusted client
/// cannot mint fresh rate-limit buckets per request.
#[tokio::test]
async fn security_forwarded_header_spoofing_is_ignored_from_untrusted_peers() {
    let untrusted = rate_state(Vec::new());
    for i in 0..4 {
        let (status, _) =
            call_with_header(&untrusted, "x-forwarded-for", &format!("198.51.100.{i}")).await;
        assert_eq!(status, StatusCode::OK, "request {i}");
    }
    let (status, body) = call_with_header(&untrusted, "x-forwarded-for", "203.0.113.7").await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(body["error"]["code"], "control_api.rate_limited");

    // The same header is honoured only from the configured proxy peer.
    let trusted = rate_state(vec![test_addr().ip()]);
    for i in 0..4 {
        let (status, _) =
            call_with_header(&trusted, "x-forwarded-for", &format!("198.51.100.{i}")).await;
        assert_eq!(status, StatusCode::OK, "trusted request {i}");
    }
    let (status, _) = call_with_header(&trusted, "x-forwarded-for", "203.0.113.7").await;
    assert_eq!(status, StatusCode::OK);
}

// --- threat: token/session replay -----------------------------------------

/// Revoking a token and logging out a session take effect on the next use; the
/// old material cannot be replayed.
#[tokio::test]
async fn security_revoked_token_and_logged_out_session_cannot_be_replayed() {
    let db = Db::open_in_memory(clock()).await.unwrap();

    let tokens = TokenStore::new(db.clone(), Duration::from_secs(365 * 24 * 3600));
    let token = tokens
        .create("u1".into(), "ci".into(), Scope::Admin, None)
        .await
        .unwrap();
    let plaintext = token.plaintext().expose().to_owned();
    assert!(tokens.authenticate(&plaintext).await.is_ok());
    tokens.revoke(token.id()).await.unwrap();
    assert_eq!(
        tokens.authenticate(&plaintext).await.unwrap_err().code(),
        "control_api.auth.unauthenticated"
    );

    let sessions = SessionStore::new(
        db,
        Duration::from_secs(60 * 60),
        Duration::from_secs(12 * 3600),
    );
    let session = sessions.create("u1".into(), Role::Admin).await.unwrap();
    let cookie = session.cookie().expose().to_owned();
    assert!(sessions.validate(&cookie).await.is_ok());
    sessions.logout(&cookie).await.unwrap();
    assert_eq!(
        sessions.validate(&cookie).await.unwrap_err().code(),
        "control_api.auth.session_expired"
    );
}

// --- threat: secret leakage ------------------------------------------------

/// Secrets are redacted before they reach SQLite (config snapshots and audit
/// before/after), and an internal error never copies its detail into the HTTP
/// envelope.
#[tokio::test]
async fn security_secrets_never_leak_through_config_audit_or_errors() {
    let db = Db::open_in_memory(clock()).await.unwrap();
    let store = ConfigStore::new(db.clone());
    let snapshot = json!({
        "auth": { "oidc_client_secret": "s3cr3t-value", "issuer": "https://auth.example.net" },
        "tls": { "private_key": "-----BEGIN PRIVATE KEY-----" },
        "session_ttl": 3600,
    });

    let version = store.store(&snapshot).await.unwrap();
    let loaded = store.load(version).await.unwrap().unwrap();
    assert_eq!(loaded["auth"]["oidc_client_secret"], "redacted");
    assert_eq!(loaded["tls"]["private_key"], "redacted");
    // Non-secret values survive so the snapshot is still useful.
    assert_eq!(loaded["auth"]["issuer"], "https://auth.example.net");
    assert_eq!(loaded["session_ttl"], 3600);
    assert!(!loaded.to_string().contains("s3cr3t-value"));

    let audit = Audit::new(db.clone());
    audit
        .record_config_change(ConfigChangeRecord {
            node_id: "node-a".into(),
            actor_id: "admin".into(),
            actor_type: "user".into(),
            action: "config.write".into(),
            config_version: Some(version),
            before: None,
            after: Some(snapshot),
            result: "ok".into(),
            error_code: None,
        })
        .await
        .unwrap();
    let rows = db.audit_list(10, 0).await.unwrap();
    let recorded = format!("{rows:?}");
    assert!(
        !recorded.contains("s3cr3t-value"),
        "secret in audit: {recorded}"
    );
    assert!(!recorded.contains("BEGIN PRIVATE KEY"), "key in audit");

    // An internal error logs its detail but returns only the stable code.
    let error = ControlApiError::Internal {
        message: "open /secret/path: permission denied".to_owned(),
    };
    let res = error.into_response();
    let bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .unwrap();
    let text = String::from_utf8(bytes.to_vec()).unwrap();
    assert!(
        !text.contains("/secret/path"),
        "internal detail leaked: {text}"
    );
    assert!(
        text.contains("control_api.internal"),
        "missing code: {text}"
    );
}
