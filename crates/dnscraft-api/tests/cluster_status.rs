//! CL6: `GET /api/v1/status` cluster fields.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use axum::body::Body;
use axum::extract::connect_info::MockConnectInfo;
use axum::http::{Request, StatusCode};
use serde_json::Value;
use tower::ServiceExt as _;

use dnscraft_api::{AppState, ClusterStatus, ClusterStatusHandle};

const NOW: u64 = 1_700_000_000;

fn at(seconds: u64) -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(seconds)
}

async fn status_body(state: AppState) -> Value {
    let router = state
        .router()
        .layer(MockConnectInfo(SocketAddr::from(([127, 0, 0, 1], 40_000))));
    let response = router
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/v1/status")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

#[tokio::test]
async fn status_includes_the_six_cluster_fields_when_clustered() {
    let status = Arc::new(ClusterStatusHandle::new());
    status.set(ClusterStatus {
        role: "sub_node".to_owned(),
        node_id: "node-b".to_owned(),
        master_reachable: false,
        applied_version: Some(4),
        lag: 2,
        queue_depth: 3,
        last_sync: Some(at(NOW)),
        degraded_nodes: 1,
        last_apply_error: None,
    });
    let state = AppState::new().with_cluster_status(status);
    let body = status_body(state).await;
    let cluster = &body["data"]["cluster"];
    assert_eq!(cluster["role"], "sub_node");
    assert_eq!(cluster["master_reachable"], false);
    assert_eq!(cluster["applied_version"], 4);
    assert_eq!(cluster["lag"], 2);
    assert_eq!(cluster["queue_depth"], 3);
    assert_eq!(cluster["last_sync"], "2023-11-14T22:13:20Z");
    assert_eq!(cluster["degraded_nodes"], 1);
}

#[tokio::test]
async fn status_omits_the_cluster_object_when_standalone() {
    let body = status_body(AppState::new()).await;
    assert!(
        body["data"].get("cluster").is_none(),
        "standalone status must omit cluster fields: {body}"
    );
}
