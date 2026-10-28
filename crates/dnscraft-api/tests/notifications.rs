//! WX7: webhook channels, host allowlist, secret handling and the egress guard.
//!
//! No delivery reaches a real host. The egress test targets `localhost`, which
//! resolves to loopback locally and is refused by the private-address rule.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, UNIX_EPOCH};

use axum::body::Body;
use axum::extract::connect_info::MockConnectInfo;
use axum::http::{Method, Request, StatusCode};
use dnscraft_api::{AppState, Audit, ConfigService, ConfigStore, Db, ManualClock, ModuleAppliers};
use serde_json::{Value, json};
use tower::ServiceExt as _;

async fn harness() -> AppState {
    let clock = Arc::new(ManualClock::new(
        UNIX_EPOCH + Duration::from_secs(1_700_000_000),
    ));
    let db = Db::open_in_memory(clock.clone()).await.unwrap();
    let service = ConfigService::new(
        ConfigStore::new(db.clone()),
        Audit::new(db.clone()),
        ModuleAppliers::default(),
        "node-a",
    );
    AppState::new()
        .with_clock(clock)
        .with_db(db)
        .with_config_service(Arc::new(service))
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

fn channel(id: &str, url: &str) -> Value {
    json!({"id": id, "type": "webhook", "enabled": true, "url": url, "events": ["tls.cert.expiring"]})
}

#[tokio::test]
async fn empty_section_lists_no_channels_and_no_secrets() {
    let state = harness().await;
    let (status, body) = call(&state, Method::GET, "/api/v1/notifications", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["data"]["channels"], json!([]));
    assert_eq!(body["data"]["allowed_hosts"], json!([]));
    assert_eq!(body["data"]["allow_private_destinations"], false);
    assert!(body["data"]["event_catalog"].as_array().unwrap().len() >= 4);
}

#[tokio::test]
async fn empty_allowlist_rejects_every_host() {
    let state = harness().await;
    let (status, body) = call(
        &state,
        Method::PUT,
        "/api/v1/notifications",
        Some(json!({"channels": [channel("ops", "https://hooks.example.com/in")]})),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(
        body["error"]["code"],
        "control_api.notifications.host_not_allowed"
    );
}

#[tokio::test]
async fn put_stores_the_channel_redacted_and_versioned() {
    let state = harness().await;
    let (status, body) = call(
        &state,
        Method::PUT,
        "/api/v1/notifications",
        Some(json!({
            "allowed_hosts": ["example.com"],
            "channels": [{
                "id": "ops",
                "type": "webhook",
                "enabled": true,
                "url": "https://hooks.example.com:8443/in/abc?token=query-secret",
                "events": ["tls.cert.expiring"],
                "secret": "s3cr3t-value"
            }]
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body["data"]["config_version"].is_number());

    let (_, body) = call(&state, Method::GET, "/api/v1/notifications", None).await;
    let text = body.to_string();
    assert!(!text.contains("s3cr3t-value"), "secret returned: {text}");
    assert!(!text.contains("query-secret"), "query returned: {text}");
    let channel = &body["data"]["channels"][0];
    assert_eq!(channel["host"], "hooks.example.com");
    assert!(channel["url"].is_null(), "the URL is never returned");
    assert_eq!(channel["has_secret"], true);

    // The config snapshot keeps only the host: the URL is a secret in kv.
    let (_, config) = call(&state, Method::GET, "/api/v1/config", None).await;
    let text = config.to_string();
    assert!(!text.contains("/in/abc"), "URL path in snapshot: {text}");
    assert!(!text.contains("query-secret"), "URL query in snapshot: {text}");
    assert_eq!(
        config["data"]["config"]["notifications"]["channels"][0]["host"],
        "hooks.example.com"
    );
}

#[tokio::test]
async fn secret_is_kept_when_omitted_and_cleared_on_null() {
    let state = harness().await;
    let base = |secret: Option<Value>| {
        let mut channel = channel("ops", "https://hooks.example.com/in");
        if let Some(secret) = secret {
            channel["secret"] = secret;
        }
        json!({"allowed_hosts": ["example.com"], "channels": [channel]})
    };
    let (status, _) = call(
        &state,
        Method::PUT,
        "/api/v1/notifications",
        Some(base(Some(json!("first")))),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, _) = call(
        &state,
        Method::PUT,
        "/api/v1/notifications",
        Some(base(None)),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (_, body) = call(&state, Method::GET, "/api/v1/notifications", None).await;
    assert_eq!(body["data"]["channels"][0]["has_secret"], true);

    let (status, _) = call(
        &state,
        Method::PUT,
        "/api/v1/notifications",
        Some(base(Some(Value::Null))),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (_, body) = call(&state, Method::GET, "/api/v1/notifications", None).await;
    assert_eq!(body["data"]["channels"][0]["has_secret"], false);
}

#[tokio::test]
async fn plain_http_and_credentials_in_urls_are_rejected() {
    let state = harness().await;
    for url in [
        "http://hooks.example.com/in",
        "https://user:pw@hooks.example.com/in",
    ] {
        let (status, body) = call(
            &state,
            Method::PUT,
            "/api/v1/notifications",
            Some(json!({"allowed_hosts": ["example.com"], "channels": [channel("ops", url)]})),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{url}");
        assert_eq!(body["error"]["code"], "control_api.notifications.invalid");
    }
}

#[tokio::test]
async fn test_send_to_a_private_destination_is_refused_before_any_request() {
    let state = harness().await;
    let (status, _) = call(
        &state,
        Method::PUT,
        "/api/v1/notifications",
        Some(json!({
            "allowed_hosts": ["localhost"],
            "channels": [channel("local", "https://localhost:9/hook")]
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, body) = call(
        &state,
        Method::POST,
        "/api/v1/notifications/test",
        Some(json!({"channel_id": "local"})),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(
        body["error"]["code"],
        "control_api.notifications.egress_denied"
    );
}

#[tokio::test]
async fn test_send_to_an_unknown_channel_is_404() {
    let state = harness().await;
    let (status, body) = call(
        &state,
        Method::POST,
        "/api/v1/notifications/test",
        Some(json!({"channel_id": "nobody"})),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(
        body["error"]["code"],
        "control_api.notifications.unknown_channel"
    );
}
