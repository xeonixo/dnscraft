//! CL7: `/api/v1/cluster/*` admin endpoints against an in-memory registry.
//!
//! Everything is driven in-process with frozen clocks (no wall-clock sleeps,
//! no sockets) and loopback `MockConnectInfo` for the rate limiter.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use axum::body::Body;
use axum::extract::connect_info::MockConnectInfo;
use axum::http::{Request, StatusCode, header};
use serde_json::{Value, json};
use tower::ServiceExt as _;

use dnscraft_api::{
    AppState, Auth, AuthState, ClusterStore, Db, ManualClock as ApiClock, OfflineWriteQueue, Scope,
    SessionStore, TokenStore,
};
use dnscraft_cluster::{EnqueueOutcome, OfflineWritesConfig, RelayedActor, WriteRelay};
use dnscraft_common::clock::ManualClock as ClusterClock;

const NOW: u64 = 1_700_000_000;
const TOKEN_TTL: Duration = Duration::from_secs(900);
const IDLE: Duration = Duration::from_secs(60 * 60);
const ABSOLUTE: Duration = Duration::from_secs(12 * 3600);
const MAX_TTL: Duration = Duration::from_secs(365 * 24 * 3600);

fn at(seconds: u64) -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(seconds)
}

fn rfc3339(seconds: u64) -> String {
    chrono::DateTime::from_timestamp(seconds as i64, 0)
        .unwrap()
        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

struct Harness {
    state: AppState,
    store: Option<ClusterStore>,
    queue: Option<Arc<OfflineWriteQueue>>,
    viewer: String,
    admin: String,
}

async fn harness(with_cluster: bool, with_queue: bool) -> Harness {
    let db = Db::open_in_memory(Arc::new(ApiClock::new(at(NOW))))
        .await
        .unwrap();
    let auth = AuthState::new(
        Auth::new(SessionStore::new(db.clone(), IDLE, ABSOLUTE)),
        TokenStore::new(db.clone(), MAX_TTL),
    );
    let tokens = TokenStore::new(db.clone(), MAX_TTL);
    let viewer = tokens
        .create(
            "viewer-a".to_owned(),
            "viewer".to_owned(),
            Scope::Viewer,
            None,
        )
        .await
        .unwrap();
    let admin = tokens
        .create("admin-a".to_owned(), "admin".to_owned(), Scope::Admin, None)
        .await
        .unwrap();

    let mut state = AppState::new()
        .with_clock(Arc::new(ApiClock::new(at(NOW))))
        .with_auth(auth);
    let mut store = None;
    let mut queue = None;
    if with_cluster {
        let cluster = ClusterStore::open_in_memory(Arc::new(ClusterClock::new(at(NOW))), TOKEN_TTL)
            .await
            .unwrap();
        if with_queue {
            let q = Arc::new(OfflineWriteQueue::new(
                cluster.clone(),
                OfflineWritesConfig::default(),
            ));
            state = state.with_offline_write_queue(Arc::clone(&q));
            queue = Some(q);
        }
        state = state.with_cluster_store(Arc::new(cluster.clone()));
        store = Some(cluster);
    }
    Harness {
        state,
        store,
        queue,
        viewer: viewer.plaintext().expose().to_owned(),
        admin: admin.plaintext().expose().to_owned(),
    }
}

async fn send(
    h: &Harness,
    method: &str,
    uri: &str,
    token: Option<&str>,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let mut builder = Request::builder().method(method).uri(uri);
    if let Some(token) = token {
        builder = builder.header(header::AUTHORIZATION, format!("Bearer {token}"));
    }
    let request = match body {
        Some(body) => builder
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_string()))
            .unwrap(),
        None => builder.body(Body::empty()).unwrap(),
    };
    let router = h
        .state
        .clone()
        .router()
        .layer(MockConnectInfo(SocketAddr::from(([127, 0, 0, 1], 40_000))));
    let res = router.oneshot(request).await.unwrap();
    let status = res.status();
    let bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .unwrap();
    (status, serde_json::from_slice(&bytes).unwrap())
}

async fn mint(h: &Harness, node_id: &str) -> (StatusCode, Value) {
    send(
        h,
        "POST",
        "/api/v1/cluster/join-tokens",
        Some(&h.admin),
        Some(json!({ "node_id": node_id })),
    )
    .await
}

#[tokio::test]
async fn mint_then_redeem_is_one_time() {
    let h = harness(true, false).await;
    let (status, body) = mint(&h, "node-a").await;
    assert_eq!(status, StatusCode::OK);
    let token = body["data"]["token"].as_str().unwrap();
    assert_eq!(token.len(), 64, "join token is 32 random bytes as hex");
    assert_eq!(
        body["data"]["expires_at"],
        json!(rfc3339(NOW + TOKEN_TTL.as_secs()))
    );

    // A second mint is a fresh plaintext.
    let (_, other) = mint(&h, "node-b").await;
    assert_ne!(token, other["data"]["token"].as_str().unwrap());

    // Redemption works once; the replay is rejected.
    let store = h.store.as_ref().unwrap();
    store.redeem_join_token(token, "node-a").await.unwrap();
    assert_eq!(
        store
            .redeem_join_token(token, "node-a")
            .await
            .unwrap_err()
            .code(),
        "cluster.join.token_invalid"
    );
}

#[tokio::test]
async fn list_nodes_returns_joined_nodes_with_role() {
    let h = harness(true, false).await;
    let store = h.store.as_ref().unwrap();
    store
        .register_node("node-a", &"ab".repeat(32))
        .await
        .unwrap();
    store
        .register_node("node-b", &"cd".repeat(32))
        .await
        .unwrap();

    let (status, body) = send(&h, "GET", "/api/v1/cluster/nodes", Some(&h.admin), None).await;
    assert_eq!(status, StatusCode::OK);
    let nodes = body["data"].as_array().unwrap();
    assert_eq!(nodes.len(), 2);
    assert_eq!(
        nodes[0],
        json!({
            "node_id": "node-a",
            "role": "sub_node",
            "fingerprint": "ab".repeat(32),
            "joined_at": rfc3339(NOW),
            "last_seen": rfc3339(NOW),
            "applied_config_version": Value::Null,
            "revoked": false,
        })
    );
    assert_eq!(nodes[1]["node_id"], "node-b");
}

#[tokio::test]
async fn revoke_marks_node_revoked() {
    let h = harness(true, false).await;
    let store = h.store.as_ref().unwrap();
    store
        .register_node("node-a", &"ab".repeat(32))
        .await
        .unwrap();

    let (status, body) = send(
        &h,
        "DELETE",
        "/api/v1/cluster/nodes/node-a",
        Some(&h.admin),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body["data"],
        json!({ "node_id": "node-a", "revoked": true })
    );
    assert!(store.get_node("node-a").await.unwrap().unwrap().revoked);
}

#[tokio::test]
async fn write_without_a_queue_is_not_found() {
    let h = harness(true, false).await;
    let (status, body) = send(&h, "GET", "/api/v1/cluster/writes/r1", Some(&h.admin), None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["error"]["code"], "control_api.not_found");
}

#[tokio::test]
async fn write_with_a_queue_reports_its_state() {
    let h = harness(true, true).await;
    let queue = h.queue.as_ref().unwrap();
    let outcome = queue
        .enqueue(WriteRelay {
            request_id: "r1".to_owned(),
            idempotency_key: Some("idem-1".to_owned()),
            if_match: Some("1".to_owned()),
            method: "PUT".to_owned(),
            path: "/api/v1/config".to_owned(),
            body: json!({ "filtering": {} }),
            actor: RelayedActor {
                actor_id: "u1".to_owned(),
                actor_type: "user".to_owned(),
                scope: "admin".to_owned(),
            },
        })
        .await
        .unwrap();
    assert!(matches!(outcome, EnqueueOutcome::Queued(_)));

    let (status, body) = send(&h, "GET", "/api/v1/cluster/writes/r1", Some(&h.admin), None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["data"]["request_id"], "r1");
    assert_eq!(body["data"]["state"], "pending");
    assert_eq!(body["data"]["queued_at"], json!(rfc3339(NOW)));

    // Unknown request ids are 404, not an empty record.
    let (status, body) = send(
        &h,
        "GET",
        "/api/v1/cluster/writes/missing",
        Some(&h.admin),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["error"]["code"], "control_api.not_found");
}

#[tokio::test]
async fn viewer_is_denied_and_admin_is_allowed() {
    let h = harness(true, true).await;

    for (method, uri, body) in [
        ("GET", "/api/v1/cluster/nodes", None),
        (
            "POST",
            "/api/v1/cluster/join-tokens",
            Some(json!({ "node_id": "node-a" })),
        ),
        ("DELETE", "/api/v1/cluster/nodes/node-a", None),
        ("GET", "/api/v1/cluster/writes/r1", None),
    ] {
        let (status, response) = send(&h, method, uri, Some(&h.viewer), body).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{method} {uri}");
        assert_eq!(
            response["error"]["code"], "control_api.auth.insufficient_scope",
            "{method} {uri}"
        );
    }

    let (status, _) = send(&h, "GET", "/api/v1/cluster/nodes", Some(&h.admin), None).await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = mint(&h, "node-a").await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn standalone_node_has_no_cluster_routes() {
    let h = harness(false, false).await;
    assert!(h.store.is_none());
    let (status, body) = send(&h, "GET", "/api/v1/cluster/nodes", Some(&h.admin), None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["error"]["code"], "control_api.not_found");
}
