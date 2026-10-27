//! WX3/WX4 integration tests: `GET /api/v1/resolver/upstreams` and
//! `POST /api/v1/resolver/cache/flush`.
//!
//! A real `Resolver` runs against the in-process testkit hierarchy on loopback,
//! so the cache holds real entries and flush counts are real.

#![allow(clippy::unwrap_used, clippy::expect_used)]

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
use dnscraft_proto::{Class, Name, RecordType};
use dnscraft_resolver::dnssec::TrustAnchors;
use dnscraft_resolver::{Query, RequestFlags, Resolver, ResolverConfig};
use dnscraft_testkit::Hierarchy;

const IDLE: Duration = Duration::from_secs(60 * 60);
const ABSOLUTE: Duration = Duration::from_secs(12 * 3600);
const MAX_TTL: Duration = Duration::from_secs(365 * 24 * 3600);

fn clock() -> Arc<ManualClock> {
    Arc::new(ManualClock::new(SystemTime::UNIX_EPOCH))
}

fn test_addr() -> std::net::SocketAddr {
    std::net::SocketAddr::from(([127, 0, 0, 1], 40_000))
}

/// A resolver over the loopback hierarchy, with no forward zones.
async fn resolver(h: &Hierarchy) -> Arc<Resolver> {
    let overrides = h
        .nameserver_addrs()
        .iter()
        .map(|(n, a)| (Name::from_ascii(&n.to_string()).unwrap(), *a))
        .collect();
    let config = ResolverConfig {
        root_hints: h.root_hints(),
        query_timeout: Duration::from_millis(500),
        nameserver_addr_overrides: overrides,
        trust_anchors: TrustAnchors::empty(),
        ..ResolverConfig::default()
    };
    Arc::new(Resolver::new(config).await.unwrap())
}

/// Populates the cache with one answer for `name`.
async fn warm(r: &Resolver, name: &str) {
    let query = Query {
        name: Name::from_ascii(name).unwrap(),
        qtype: RecordType::A,
        qclass: Class::IN,
    };
    r.resolve(&query, RequestFlags::default()).await.unwrap();
}

struct Harness {
    router: axum::Router,
    db: Db,
}

async fn harness(resolver: Option<Arc<Resolver>>) -> Harness {
    let clock = clock();
    let db = Db::open_in_memory(clock.clone()).await.unwrap();
    let config = Arc::new(ConfigService::new(
        ConfigStore::new(db.clone()),
        Audit::new(db.clone()),
        ModuleAppliers::default(),
        "node-a",
    ));
    let auth = AuthState::new(
        SessionStore::new(db.clone(), IDLE, ABSOLUTE),
        TokenStore::new(db.clone(), MAX_TTL),
    );
    let mut state = AppState::new()
        .with_auth(auth)
        .with_db(db.clone())
        .with_config_service(config);
    if let Some(resolver) = resolver {
        state = state.with_resolver(resolver);
    }
    let router = state.router().layer(MockConnectInfo(test_addr()));
    Harness { router, db }
}

async fn token(db: &Db, actor: &str, scope: Scope) -> String {
    TokenStore::new(db.clone(), MAX_TTL)
        .create(actor.into(), "test".into(), scope, None)
        .await
        .unwrap()
        .plaintext()
        .expose()
        .to_owned()
}

async fn send(router: &axum::Router, req: Request<Body>) -> (StatusCode, Value) {
    let res = router.clone().oneshot(req).await.unwrap();
    let status = res.status();
    let bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .unwrap();
    (status, serde_json::from_slice(&bytes).unwrap())
}

async fn get(router: &axum::Router, uri: &str, bearer: Option<&str>) -> (StatusCode, Value) {
    let mut builder = Request::builder().method("GET").uri(uri);
    if let Some(bearer) = bearer {
        builder = builder.header(header::AUTHORIZATION, format!("Bearer {bearer}"));
    }
    send(router, builder.body(Body::empty()).unwrap()).await
}

async fn post(
    router: &axum::Router,
    uri: &str,
    bearer: Option<&str>,
    body: Option<&str>,
) -> (StatusCode, Value) {
    let mut builder = Request::builder().method("POST").uri(uri);
    if let Some(bearer) = bearer {
        builder = builder.header(header::AUTHORIZATION, format!("Bearer {bearer}"));
    }
    let req = match body {
        Some(body) => builder
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_owned()))
            .unwrap(),
        None => builder.body(Body::empty()).unwrap(),
    };
    send(router, req).await
}

#[tokio::test]
async fn upstreams_viewer_200() {
    let h = Hierarchy::start().await.unwrap();
    let harness = harness(Some(resolver(&h).await)).await;
    let viewer = token(&harness.db, "viewer", Scope::Viewer).await;

    let (status, body) = get(
        &harness.router,
        "/api/v1/resolver/upstreams",
        Some(viewer.as_str()),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["data"]["window_seconds"], json!(300));
    let items = body["data"]["items"].as_array().unwrap();
    let recursion = items.iter().find(|i| i["kind"] == "recursion").unwrap();
    // Priming already exchanged with the loopback root, so the recursion row
    // has samples; the wire shape is what this test pins.
    assert_eq!(recursion["state"], "unknown");
    assert!(recursion["samples"].as_u64().unwrap() >= 1, "{recursion}");
    assert!(recursion["rtt_ms"]["p50"].is_number(), "{recursion}");
    assert!(recursion["rtt_ms"]["p95"].is_number(), "{recursion}");
    assert!(recursion["last_checked"].as_str().unwrap().ends_with('Z'));
    assert!(recursion["last_error"].is_null());
}

#[tokio::test]
async fn upstreams_unauthenticated_401() {
    let h = Hierarchy::start().await.unwrap();
    let harness = harness(Some(resolver(&h).await)).await;

    let (status, body) = get(&harness.router, "/api/v1/resolver/upstreams", None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert_eq!(body["error"]["code"], "control_api.auth.unauthenticated");
}

#[tokio::test]
async fn upstreams_without_forward_zones_returns_recursion_only() {
    let h = Hierarchy::start().await.unwrap();
    let harness = harness(Some(resolver(&h).await)).await;
    let viewer = token(&harness.db, "viewer", Scope::Viewer).await;

    let (status, body) = get(
        &harness.router,
        "/api/v1/resolver/upstreams",
        Some(viewer.as_str()),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let items = body["data"]["items"].as_array().unwrap();
    assert_eq!(items.len(), 1, "{items:?}");
    assert_eq!(items[0]["name"], "recursion");
    assert_eq!(items[0]["kind"], "recursion");
    assert!(items[0]["zone"].is_null());
    assert!(items[0]["address"].is_null());
    assert_eq!(items[0]["protocol"], "dns");
}

#[tokio::test]
async fn upstreams_without_resolver_is_not_ready() {
    let harness = harness(None).await;
    let viewer = token(&harness.db, "viewer", Scope::Viewer).await;

    let (status, body) = get(
        &harness.router,
        "/api/v1/resolver/upstreams",
        Some(viewer.as_str()),
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    assert_eq!(body["error"]["code"], "control_api.not_ready");
}

#[tokio::test]
async fn flush_admin_200_audited() {
    let h = Hierarchy::start().await.unwrap();
    let resolver = resolver(&h).await;
    warm(&resolver, "www.example.test.").await;
    let harness = harness(Some(resolver)).await;
    let admin = token(&harness.db, "admin", Scope::Admin).await;

    let (status, body) = post(
        &harness.router,
        "/api/v1/resolver/cache/flush",
        Some(admin.as_str()),
        Some(r#"{"domain":"example.test"}"#),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["data"]["scope"], "domain");
    assert_eq!(body["data"]["domain"], "example.test");
    let evicted = body["data"]["evicted"].as_u64().unwrap();
    assert!(evicted >= 1, "{body}");

    // The flush is audited with scope, domain and evicted.
    let (status, audit) = get(&harness.router, "/api/v1/audit", Some(admin.as_str())).await;
    assert_eq!(status, StatusCode::OK, "{audit}");
    let row = audit["data"]["audit"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["action"] == "resolver.cache.flush")
        .expect("flush audit row");
    assert_eq!(row["result"], "ok");
    let after: Value = serde_json::from_str(row["after"].as_str().unwrap()).unwrap();
    assert_eq!(after["scope"], "domain");
    assert_eq!(after["domain"], "example.test");
    assert_eq!(after["evicted"], json!(evicted));
}

#[tokio::test]
async fn flush_viewer_403() {
    let h = Hierarchy::start().await.unwrap();
    let harness = harness(Some(resolver(&h).await)).await;
    let viewer = token(&harness.db, "viewer", Scope::Viewer).await;

    let (status, body) = post(
        &harness.router,
        "/api/v1/resolver/cache/flush",
        Some(viewer.as_str()),
        Some("{}"),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["error"]["code"], "control_api.auth.insufficient_scope");
}

#[tokio::test]
async fn flush_invalid_domain_400() {
    let h = Hierarchy::start().await.unwrap();
    let harness = harness(Some(resolver(&h).await)).await;
    let admin = token(&harness.db, "admin", Scope::Admin).await;

    for bad in [
        r#"{"domain":"a..b"}"#,
        r#"{"domain":"*.example.com"}"#,
        r#"{"domain":""}"#,
        r#"{"domain":42}"#,
        "not json",
    ] {
        let (status, body) = post(
            &harness.router,
            "/api/v1/resolver/cache/flush",
            Some(admin.as_str()),
            Some(bad),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{bad}: {body}");
        assert_eq!(
            body["error"]["code"], "control_api.resolver.flush.invalid_domain",
            "{bad}"
        );
    }
}

#[tokio::test]
async fn flush_empty_body_flushes_all() {
    let h = Hierarchy::start().await.unwrap();
    let resolver = resolver(&h).await;
    warm(&resolver, "www.example.test.").await;
    let harness = harness(Some(Arc::clone(&resolver))).await;
    let admin = token(&harness.db, "admin", Scope::Admin).await;
    assert!(resolver.cached_bytes() > 0);

    // No body at all: flush everything.
    let (status, body) = post(
        &harness.router,
        "/api/v1/resolver/cache/flush",
        Some(admin.as_str()),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["data"]["scope"], "all");
    assert!(body["data"]["domain"].is_null());
    assert!(body["data"]["evicted"].as_u64().unwrap() >= 1, "{body}");
    assert_eq!(resolver.cached_bytes(), 0);

    // Empty object: same result, nothing left to evict.
    let (status, body) = post(
        &harness.router,
        "/api/v1/resolver/cache/flush",
        Some(admin.as_str()),
        Some("{}"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["data"]["scope"], "all");
    assert_eq!(body["data"]["evicted"], json!(0));
}
