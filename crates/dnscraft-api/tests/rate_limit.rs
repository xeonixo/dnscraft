//! A5 integration tests: HTTP rate limiting via the router middleware.
//!
//! These drive the router in-process (no socket) with a `MockConnectInfo` peer
//! and a `ManualClock`, so refill and the trusted-peer rule are exercised
//! without wall-clock sleeps.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use axum::body::Body;
use axum::extract::connect_info::MockConnectInfo;
use axum::http::{Request, StatusCode};
use serde_json::Value;
use tower::ServiceExt as _;

use dnscraft_api::{AppState, ManualClock, RateLimitConfig, RateLimiter};

/// The peer address the middleware sees in these in-process tests.
fn test_addr() -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], 40_000))
}

/// A small config with burst = 2 * 2 = 4 tokens per bucket.
fn small_config() -> RateLimitConfig {
    RateLimitConfig {
        read_per_second: 2,
        write_per_second: 2,
        auth_per_second: 2,
        burst_factor: 2,
    }
}

fn clock() -> Arc<ManualClock> {
    Arc::new(ManualClock::new(SystemTime::UNIX_EPOCH))
}

fn state(clock: Arc<ManualClock>, trusted: Vec<IpAddr>) -> AppState {
    let limiter = RateLimiter::with_capacity(small_config(), clock, trusted, 8);
    AppState::new().with_rate_limiter(Arc::new(limiter))
}

fn router(state: &AppState) -> axum::Router {
    state.clone().router().layer(MockConnectInfo(test_addr()))
}

async fn send(state: &AppState, req: Request<Body>) -> (StatusCode, Value) {
    let res = router(state).oneshot(req).await.unwrap();
    let status = res.status();
    let bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .unwrap();
    (status, serde_json::from_slice(&bytes).unwrap())
}

async fn get(state: &AppState, uri: &str) -> (StatusCode, Value) {
    send(
        state,
        Request::builder().uri(uri).body(Body::empty()).unwrap(),
    )
    .await
}

#[tokio::test]
async fn flood_beyond_burst_returns_429_with_rate_limited_envelope() {
    let state = state(clock(), Vec::new());
    for i in 0..4 {
        let (status, _) = get(&state, "/api/v1/status").await;
        assert_eq!(status, StatusCode::OK, "request {i} should succeed");
    }
    let (status, body) = get(&state, "/api/v1/status").await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(body["error"]["code"], "control_api.rate_limited");
}

#[tokio::test]
async fn rate_limited_response_carries_retry_after_header() {
    let state = state(clock(), Vec::new());
    for _ in 0..4 {
        get(&state, "/api/v1/status").await;
    }
    let res = router(&state)
        .oneshot(
            Request::builder()
                .uri("/api/v1/status")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::TOO_MANY_REQUESTS);
    let retry_after = res
        .headers()
        .get("retry-after")
        .and_then(|v| v.to_str().ok())
        .expect("retry-after header");
    assert!(retry_after.parse::<u64>().is_ok(), "seconds: {retry_after}");
}

#[tokio::test]
async fn clock_refills_without_sleeping() {
    let clock = clock();
    let state = state(clock.clone(), Vec::new());
    for _ in 0..4 {
        assert_eq!(get(&state, "/api/v1/status").await.0, StatusCode::OK);
    }
    assert_eq!(
        get(&state, "/api/v1/status").await.0,
        StatusCode::TOO_MANY_REQUESTS
    );
    // One clock second refills 2 read tokens — no wall-clock wait.
    clock.advance(Duration::from_secs(1));
    assert_eq!(get(&state, "/api/v1/status").await.0, StatusCode::OK);
    assert_eq!(get(&state, "/api/v1/status").await.0, StatusCode::OK);
    assert_eq!(
        get(&state, "/api/v1/status").await.0,
        StatusCode::TOO_MANY_REQUESTS
    );
}

#[tokio::test]
async fn source_ip_comes_from_peer_not_spoofable_header() {
    // Untrusted peer: X-Forwarded-For is ignored, so different spoofed headers
    // still share the single peer bucket and hit the burst cap together.
    let state = state(clock(), Vec::new());
    for i in 0..4 {
        let req = Request::builder()
            .uri("/api/v1/status")
            .header("x-forwarded-for", format!("198.51.100.{i}"))
            .body(Body::empty())
            .unwrap();
        let (status, _) = send(&state, req).await;
        assert_eq!(status, StatusCode::OK, "request {i}");
    }
    let req = Request::builder()
        .uri("/api/v1/status")
        .header("x-forwarded-for", "198.51.100.99")
        .body(Body::empty())
        .unwrap();
    let (status, _) = send(&state, req).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn trusted_proxy_honours_forwarded_header() {
    // The peer is a configured trusted proxy, so each distinct X-Forwarded-For
    // gets its own bucket (each fresh with a full burst).
    let peer = test_addr().ip();
    let state = state(clock(), vec![peer]);
    for i in 0..4 {
        let req = Request::builder()
            .uri("/api/v1/status")
            .header("x-forwarded-for", format!("198.51.100.{i}"))
            .body(Body::empty())
            .unwrap();
        let (status, _) = send(&state, req).await;
        assert_eq!(status, StatusCode::OK, "request {i}");
    }
    // A fifth distinct source is not limited — the header was honoured.
    let req = Request::builder()
        .uri("/api/v1/status")
        .header("x-forwarded-for", "198.51.100.99")
        .body(Body::empty())
        .unwrap();
    let (status, _) = send(&state, req).await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn write_methods_use_a_separate_bucket() {
    let state = state(clock(), Vec::new());
    // POST to the GET-only status route → method-not-allowed, but each request
    // still consumes a write token (the middleware runs before routing).
    for _ in 0..4 {
        let req = Request::builder()
            .method("POST")
            .uri("/api/v1/status")
            .body(Body::empty())
            .unwrap();
        let (status, _) = send(&state, req).await;
        assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
    }
    // The write bucket is now exhausted…
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/status")
        .body(Body::empty())
        .unwrap();
    let (status, _) = send(&state, req).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    // …while the read bucket is untouched.
    assert_eq!(get(&state, "/api/v1/status").await.0, StatusCode::OK);
}
