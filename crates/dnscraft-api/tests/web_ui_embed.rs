//! Regression tests for the `web-ui` embed: SPA asset serving, security
//! headers, and JSON 404 preservation for `/api/` and `/mcp/` misses.
//!
//! Gated via `[[test]] required-features = ["web-ui"]` in Cargo.toml.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::net::SocketAddr;

use axum::body::Body;
use axum::extract::connect_info::MockConnectInfo;
use axum::http::{Request, StatusCode, header};
use axum::response::Response;
use serde_json::Value;
use tower::ServiceExt as _;

use dnscraft_api::AppState;

fn test_addr() -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], 40_000))
}

async fn oneshot(req: Request<Body>) -> Response {
    let router = AppState::new().router().layer(MockConnectInfo(test_addr()));
    router.oneshot(req).await.unwrap()
}

async fn get(uri: &str) -> Response {
    oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap()).await
}

fn header_str(res: &Response, name: axum::http::HeaderName) -> &str {
    res.headers()
        .get(name)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
}

fn assert_html_security_headers(res: &Response) {
    let ct = header_str(res, header::CONTENT_TYPE);
    assert!(
        ct.starts_with("text/html"),
        "expected text/html, got {ct:?}"
    );
    assert_eq!(header_str(res, header::CACHE_CONTROL), "no-cache");
    let csp = header_str(res, header::CONTENT_SECURITY_POLICY);
    assert!(!csp.is_empty(), "missing Content-Security-Policy");
    assert!(
        csp.contains("form-action 'self'"),
        "CSP missing form-action 'self': {csp:?}"
    );
    assert_eq!(
        header_str(res, header::X_CONTENT_TYPE_OPTIONS),
        "nosniff"
    );
    assert_eq!(header_str(res, header::REFERRER_POLICY), "no-referrer");
}

async fn json_body(res: Response) -> (StatusCode, Value) {
    let status = res.status();
    let bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .unwrap();
    (status, serde_json::from_slice(&bytes).unwrap())
}

#[tokio::test]
async fn get_root_serves_html_with_security_headers() {
    let res = get("/").await;
    assert_eq!(res.status(), StatusCode::OK);
    assert_html_security_headers(&res);
    let body = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .unwrap();
    assert!(!body.is_empty());
    assert!(
        std::str::from_utf8(&body).unwrap().contains("DNScraft"),
        "expected placeholder HTML body"
    );
}

#[tokio::test]
async fn get_spa_route_falls_back_to_index_html() {
    let res = get("/settings").await;
    assert_eq!(res.status(), StatusCode::OK);
    assert_html_security_headers(&res);
    let ct = header_str(&res, header::CONTENT_TYPE);
    assert!(
        !ct.contains("octet-stream"),
        "SPA fallback must not be octet-stream, got {ct:?}"
    );
}

#[tokio::test]
async fn api_miss_stays_json_not_found() {
    let (status, body) = json_body(get("/api/v1/does-not-exist").await).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["error"]["code"], "control_api.not_found");
    // Ensure we did not accidentally serve HTML.
    assert!(body["error"].is_object());
}

#[tokio::test]
async fn exact_api_stays_json_not_found() {
    let (status, body) = json_body(get("/api").await).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["error"]["code"], "control_api.not_found");
}

#[tokio::test]
async fn mcp_miss_stays_json_not_found() {
    let (status, body) = json_body(get("/mcp/v1/nope").await).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["error"]["code"], "control_api.not_found");
}

#[tokio::test]
async fn exact_mcp_stays_json_not_found() {
    let (status, body) = json_body(get("/mcp").await).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["error"]["code"], "control_api.not_found");
}

#[tokio::test]
async fn path_traversal_is_rejected() {
    let res = get("/../index.html").await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn head_root_returns_headers_without_body() {
    let res = oneshot(
        Request::builder()
            .method("HEAD")
            .uri("/")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK);
    assert_html_security_headers(&res);
    let body = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .unwrap();
    assert!(body.is_empty(), "HEAD must not return a body");
}
