//! Server-core integration tests: envelopes, routing, readiness and HTTP
//! status mapping. The router is driven in-process via `tower` (no socket).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::net::SocketAddr;

use axum::body::Body;
use axum::extract::connect_info::MockConnectInfo;
use axum::http::{Request, StatusCode, header};
use serde_json::Value;
use tower::ServiceExt as _;

use dnscraft_api::AppState;

/// The peer address the rate-limiter middleware sees in these in-process tests.
fn test_addr() -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], 40_000))
}

async fn send(state: AppState, req: Request<Body>) -> (StatusCode, Value) {
    let router = state.router().layer(MockConnectInfo(test_addr()));
    let res = router.oneshot(req).await.unwrap();
    let status = res.status();
    let bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .unwrap();
    (status, serde_json::from_slice(&bytes).unwrap())
}

async fn get(state: AppState, uri: &str) -> (StatusCode, Value) {
    send(
        state,
        Request::builder().uri(uri).body(Body::empty()).unwrap(),
    )
    .await
}

#[tokio::test]
async fn healthz_returns_liveness_only() {
    let (status, body) = get(AppState::new(), "/healthz").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, serde_json::json!({ "data": { "ok": true } }));
}

#[tokio::test]
async fn readyz_is_ready_when_no_module_is_not_ready() {
    let (status, body) = get(AppState::new(), "/readyz").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, serde_json::json!({ "data": { "ready": true } }));
}

#[tokio::test]
async fn readyz_reports_only_module_names_when_not_ready() {
    let state = AppState::new();
    state.readiness().set_not_ready("resolver");
    state.readiness().set_not_ready("listener");

    let (status, body) = get(state, "/readyz").await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        body,
        serde_json::json!({
            "error": {
                "code": "control_api.not_ready",
                "params": { "modules": ["listener", "resolver"] }
            }
        })
    );
}

#[tokio::test]
async fn unknown_route_returns_not_found_envelope() {
    let (status, body) = get(AppState::new(), "/api/v1/does-not-exist").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["error"]["code"], "control_api.not_found");
}

#[tokio::test]
async fn known_path_with_wrong_method_returns_method_not_allowed() {
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/status")
        .body(Body::empty())
        .unwrap();
    let (status, body) = send(AppState::new(), req).await;
    assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(body["error"]["code"], "control_api.method_not_allowed");
    assert_eq!(body["error"]["params"]["method"], "POST");
    assert_eq!(body["error"]["params"]["path"], "/api/v1/status");
}

#[tokio::test]
async fn v1_prefix_is_reachable() {
    let (status, body) = get(AppState::new(), "/api/v1/status").await;
    assert_eq!(status, StatusCode::OK);
    assert!(body["data"].is_object());
}

#[tokio::test]
async fn non_get_on_healthz_is_method_not_allowed_not_not_found() {
    let req = Request::builder()
        .method("DELETE")
        .uri("/healthz")
        .body(Body::empty())
        .unwrap();
    let (status, body) = send(AppState::new(), req).await;
    assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(body["error"]["code"], "control_api.method_not_allowed");
}

#[tokio::test]
async fn response_content_type_is_json() {
    let router = AppState::new().router().layer(MockConnectInfo(test_addr()));
    let res = router
        .oneshot(
            Request::builder()
                .uri("/healthz")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let ct = res
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(ct.starts_with("application/json"), "content-type {ct}");
}
