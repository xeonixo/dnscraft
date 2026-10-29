//! Exception proposals: listing, owner confirm and reject over HTTP.
//!
//! Proposals are made through MCP (see `mcp_write.rs`); here they are seeded
//! straight into the stored config and decided through the REST endpoints.

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
    AppState, Audit, AuthState, Clock, ConfigActor, ConfigService, ConfigStore, Db, ManualClock,
    ModuleAppliers, Scope, SessionStore, TokenStore,
};
use dnscraft_mcp::McpConfig;

const IDLE: Duration = Duration::from_secs(60 * 60);
const ABSOLUTE: Duration = Duration::from_secs(12 * 3600);
const MAX_TTL: Duration = Duration::from_secs(365 * 24 * 3600);
const NOW: u64 = 1_700_000_000;
const DAY: u64 = 24 * 3600;

struct Harness {
    state: AppState,
    service: Arc<ConfigService>,
    db: Db,
    admin: String,
}

async fn harness_with(mcp: McpConfig) -> Harness {
    let clock = Arc::new(ManualClock::new(
        SystemTime::UNIX_EPOCH + Duration::from_secs(NOW),
    ));
    let db = Db::open_in_memory(Arc::clone(&clock) as Arc<dyn Clock>)
        .await
        .unwrap();
    let auth = AuthState::new(
        SessionStore::new(db.clone(), IDLE, ABSOLUTE),
        TokenStore::new(db.clone(), MAX_TTL),
    );
    let token = TokenStore::new(db.clone(), MAX_TTL)
        .create("admin-a".to_owned(), "admin".to_owned(), Scope::Admin, None)
        .await
        .unwrap();
    let service = Arc::new(ConfigService::new(
        ConfigStore::new(db.clone()),
        Audit::new(db.clone()),
        ModuleAppliers::default(),
        "node-a",
    ));
    let state = AppState::new()
        .with_clock(Arc::clone(&clock) as Arc<dyn Clock>)
        .with_auth(auth)
        .with_config_service(Arc::clone(&service))
        .with_mcp_config(mcp);
    Harness {
        state,
        service,
        db,
        admin: token.plaintext().expose().to_owned(),
    }
}

async fn harness() -> Harness {
    harness_with(McpConfig::default()).await
}

async fn send(
    state: &AppState,
    token: &str,
    method: &str,
    uri: &str,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let builder = Request::builder()
        .method(method)
        .uri(uri)
        .header(header::AUTHORIZATION, format!("Bearer {token}"));
    let request = match body {
        Some(body) => builder
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_string()))
            .unwrap(),
        None => builder.body(Body::empty()).unwrap(),
    };
    let router = state
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

async fn seed_set(h: &Harness, custom_rules: &str) {
    let body = json!({ "id": "default", "name": "Default", "custom_rules": custom_rules });
    let (status, response) =
        send(&h.state, &h.admin, "PUT", "/api/v1/filter-sets", Some(body)).await;
    assert_eq!(status, StatusCode::OK, "{response}");
}

fn proposal(id: &str, domain: &str, include: bool, expires_at: u64) -> Value {
    json!({
        "id": id,
        "domain": domain,
        "include_subdomains": include,
        "reason": "article page",
        "created_at": NOW,
        "expires_at": expires_at,
        "token_id": "tok",
    })
}

async fn seed_proposals(h: &Harness, proposals: Vec<Value>) {
    h.service
        .mutate(&ConfigActor::new("seed", "system"), "test.seed", move |v| {
            v["filtering"]["sets"][0]["mcp_proposals"] = Value::Array(proposals);
            Ok(true)
        })
        .await
        .unwrap();
}

async fn stored_set(h: &Harness) -> Value {
    let (_, snapshot) = h.service.current().await.unwrap();
    snapshot.unwrap()["filtering"]["sets"][0].clone()
}

#[tokio::test]
async fn proposals_are_listed_and_survive_a_filter_set_round_trip() {
    let h = harness().await;
    seed_set(&h, "||keep.example.com^").await;
    seed_proposals(
        &h,
        vec![
            proposal("p1", "cdn.tinypass.com", false, NOW + DAY),
            proposal("old", "gone.example.com", false, NOW - 1),
        ],
    )
    .await;

    let (status, body) = send(
        &h.state,
        &h.admin,
        "GET",
        "/api/v1/filtering/mcp-proposals",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let listed = body["data"]["proposals"].as_array().unwrap();
    assert_eq!(listed.len(), 1, "expired proposals are not listed: {body}");
    assert_eq!(listed[0]["id"], "p1");
    assert_eq!(listed[0]["filter_set_id"], "default");
    assert_eq!(listed[0]["domain"], "cdn.tinypass.com");
    assert!(listed[0]["rule_text"].as_str().unwrap().starts_with("@@"));

    // The web UI writes back the set it read, including `mcp_proposals`; the
    // stored proposals must neither be rejected nor replaced by that body.
    let write_back = json!({
        "id": "default", "name": "Default", "custom_rules": "||keep.example.com^",
        "mcp_proposals": [],
    });
    let (status, response) = send(
        &h.state,
        &h.admin,
        "PUT",
        "/api/v1/filter-sets",
        Some(write_back),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{response}");
    assert_eq!(
        stored_set(&h).await["mcp_proposals"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
}

#[tokio::test]
async fn confirming_adds_one_allow_line_and_removes_the_proposal() {
    let h = harness().await;
    seed_set(&h, "||keep.example.com^").await;
    seed_proposals(
        &h,
        vec![proposal("p1", "cdn.tinypass.com", true, NOW + DAY)],
    )
    .await;
    let before = h.service.current().await.unwrap().0.unwrap();

    let uri = "/api/v1/filtering/mcp-proposals/p1/confirm";
    let (status, body) = send(&h.state, &h.admin, "POST", uri, None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["data"]["decision"], "confirmed");
    assert_eq!(body["data"]["rule_text"], "@@||cdn.tinypass.com^");

    let set = stored_set(&h).await;
    assert_eq!(
        set["custom_rules"],
        "||keep.example.com^\n@@||cdn.tinypass.com^\n"
    );
    assert!(set["mcp_proposals"].as_array().unwrap().is_empty());
    assert_eq!(h.service.current().await.unwrap().0.unwrap(), before + 1);
    let audit = h.db.audit_list(20, 0).await.unwrap();
    assert!(
        audit
            .iter()
            .any(|row| row.action == "mcp.confirm_exception")
    );

    let (status, _) = send(&h.state, &h.admin, "POST", uri, None).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "a decided proposal is gone");
}

#[tokio::test]
async fn rejecting_changes_no_rules_and_expired_proposals_cannot_be_confirmed() {
    let h = harness().await;
    seed_set(&h, "||keep.example.com^").await;
    seed_proposals(
        &h,
        vec![
            proposal("p1", "cdn.tinypass.com", false, NOW + DAY),
            proposal("old", "gone.example.com", false, NOW - 1),
        ],
    )
    .await;

    let (status, body) = send(
        &h.state,
        &h.admin,
        "POST",
        "/api/v1/filtering/mcp-proposals/p1/reject",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["data"]["decision"], "rejected");
    assert_eq!(stored_set(&h).await["custom_rules"], "||keep.example.com^");

    let (status, _) = send(
        &h.state,
        &h.admin,
        "POST",
        "/api/v1/filtering/mcp-proposals/old/confirm",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(stored_set(&h).await["custom_rules"], "||keep.example.com^");
}

#[tokio::test]
async fn only_an_admin_can_decide_a_proposal() {
    let h = harness().await;
    seed_set(&h, "").await;
    seed_proposals(
        &h,
        vec![proposal("p1", "cdn.tinypass.com", false, NOW + DAY)],
    )
    .await;
    let tokens = TokenStore::new(h.db.clone(), MAX_TTL);
    let viewer = tokens
        .create(
            "viewer-a".to_owned(),
            "viewer".to_owned(),
            Scope::Viewer,
            None,
        )
        .await
        .unwrap();
    let mcp = tokens
        .create("mcp-a".to_owned(), "mcp".to_owned(), Scope::McpWrite, None)
        .await
        .unwrap();

    let uri = "/api/v1/filtering/mcp-proposals/p1/confirm";
    for token in [viewer.plaintext().expose(), mcp.plaintext().expose()] {
        let (status, _) = send(&h.state, token, "POST", uri, None).await;
        assert!(
            status == StatusCode::FORBIDDEN || status == StatusCode::UNAUTHORIZED,
            "got {status}"
        );
    }
    let (status, _) = send(
        &h.state,
        viewer.plaintext().expose(),
        "GET",
        "/api/v1/filtering/mcp-proposals",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "a viewer may read the list");
    assert_eq!(
        stored_set(&h).await["mcp_proposals"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
}
