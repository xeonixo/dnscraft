//! Policy records, Client-ID registry and view node routes over HTTP.
//!
//! Same harness as `config_http.rs`: a real `ConfigService` without module
//! appliers, so these tests cover the route contract and the module's own
//! validation of request bodies, not the policy build.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use axum::body::Body;
use axum::extract::connect_info::MockConnectInfo;
use axum::http::{Request, StatusCode, header};
use serde_json::{Value, json};
use tower::ServiceExt as _;

use dnscraft_api::{AppState, Audit, ConfigService, ConfigStore, Db, ManualClock, ModuleAppliers};

struct Harness {
    state: AppState,
}

async fn harness() -> Harness {
    let clock = Arc::new(ManualClock::new(
        SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000),
    ));
    let db = Db::open_in_memory(clock).await.unwrap();
    let service = Arc::new(ConfigService::new(
        ConfigStore::new(db.clone()),
        Audit::new(db),
        ModuleAppliers::default(),
        "node-a",
    ));
    let state = AppState::new().with_config_service(service);
    Harness { state }
}

async fn call(
    state: &AppState,
    method: &str,
    uri: &str,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let router = state
        .clone()
        .router()
        .layer(MockConnectInfo(SocketAddr::from(([127, 0, 0, 1], 40_000))));
    let builder = Request::builder().method(method).uri(uri);
    let request = match body {
        Some(body) => builder
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_string()))
            .unwrap(),
        None => builder.body(Body::empty()).unwrap(),
    };
    let res = router.oneshot(request).await.unwrap();
    let status = res.status();
    let bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .unwrap();
    (status, serde_json::from_slice(&bytes).unwrap())
}

async fn get(state: &AppState, uri: &str) -> (StatusCode, Value) {
    call(state, "GET", uri, None).await
}

async fn put(state: &AppState, uri: &str, body: Value) -> (StatusCode, Value) {
    call(state, "PUT", uri, Some(body)).await
}

async fn post(state: &AppState, uri: &str, body: Value) -> (StatusCode, Value) {
    call(state, "POST", uri, Some(body)).await
}

async fn delete(state: &AppState, uri: &str, body: Option<Value>) -> (StatusCode, Value) {
    call(state, "DELETE", uri, body).await
}

fn code(response: &Value) -> &str {
    response["error"]["code"].as_str().unwrap_or("")
}

/// Filter set → profile → default view, the minimum for a policy snapshot.
async fn seed_policy(state: &AppState) {
    let (status, response) = put(
        state,
        "/api/v1/filter-sets",
        json!({ "id": "default", "name": "Default" }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{response}");
    let (status, response) = put(
        state,
        "/api/v1/policy/profiles/default",
        json!({ "filter_set": "default" }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{response}");
    let (status, response) = put(
        state,
        "/api/v1/policy/views/default",
        json!({ "profile": "default", "is_default": true }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{response}");
}

#[tokio::test]
async fn records_upsert_list_and_delete_by_name_and_type() {
    let h = harness().await;
    seed_policy(&h.state).await;

    let (status, response) = put(
        &h.state,
        "/api/v1/policy/records",
        json!({
            "name": "NAS.lan.example.com",
            "type": "a",
            "rdata": "192.0.2.10",
            "overrides": { "guests": "192.0.2.50" },
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{response}");
    let record = &response["data"]["record"];
    assert_eq!(record["name"], "nas.lan.example.com.");
    assert_eq!(record["type"], "A");
    assert_eq!(record["ttl"], 60);
    assert_eq!(record["rdata"], "192.0.2.10");
    assert_eq!(record["overrides"]["guests"], "192.0.2.50");

    // Same name and type replaces the entry instead of adding a second one.
    let (status, response) = post(
        &h.state,
        "/api/v1/policy/records",
        json!({ "name": "nas.lan.example.com", "type": "A", "ttl": 300, "rdata": "192.0.2.11" }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{response}");

    let (status, response) = get(&h.state, "/api/v1/policy/records").await;
    assert_eq!(status, StatusCode::OK);
    let records = response["data"]["records"].as_array().unwrap();
    assert_eq!(records.len(), 1, "{response}");
    assert_eq!(records[0]["ttl"], 300);
    assert_eq!(records[0]["rdata"], "192.0.2.11");
    assert_eq!(records[0]["overrides"], json!({}));

    // Other record types at the same name are a separate entry.
    let (status, response) = put(
        &h.state,
        "/api/v1/policy/records",
        json!({ "name": "nas.lan.example.com", "type": "TXT", "rdata": "hello" }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{response}");
    let (_, response) = get(&h.state, "/api/v1/policy/records").await;
    assert_eq!(response["data"]["records"].as_array().unwrap().len(), 2);

    let (status, response) = delete(
        &h.state,
        "/api/v1/policy/records",
        Some(json!({ "name": "nas.lan.example.com", "type": "A" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{response}");
    assert_eq!(response["data"]["deleted"], true);

    let (status, response) = delete(
        &h.state,
        "/api/v1/policy/records",
        Some(json!({ "name": "nas.lan.example.com", "type": "A" })),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{response}");
    assert_eq!(response["error"]["code"], "control_api.not_found");
}

#[tokio::test]
async fn records_reject_bad_types_and_values() {
    let h = harness().await;
    seed_policy(&h.state).await;

    let cases = [
        json!({ "name": "a.example.com", "type": "NS", "rdata": "ns.example.net." }),
        json!({ "name": "a.example.com", "type": "A", "rdata": "not-an-address" }),
        json!({ "name": "a.example.com", "type": "AAAA", "rdata": "192.0.2.1" }),
        json!({ "name": "a.example.com", "type": "MX", "rdata": "mail.example.com." }),
        json!({ "name": "a.example.com", "type": "SRV", "rdata": "1 5 5060" }),
        json!({ "name": "bad name!.example.com", "type": "A", "rdata": "192.0.2.1" }),
        json!({ "name": "a.example.com", "type": "A", "rdata": "192.0.2.1",
               "overrides": { "Guests": "192.0.2.2" } }),
        json!({ "name": "a.example.com", "type": "A", "rdata": "192.0.2.1", "ttl": 60, "bogus": 1 }),
    ];
    for body in cases {
        let (status, response) = put(&h.state, "/api/v1/policy/records", body.clone()).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body} -> {response}");
        assert_eq!(code(&response), "policy.config.invalid", "{body}");
    }
}

#[tokio::test]
async fn records_accept_mx_srv_and_ptr_presentation() {
    let h = harness().await;
    seed_policy(&h.state).await;

    let (status, response) = put(
        &h.state,
        "/api/v1/policy/records",
        json!({ "name": "mail.lan.example.com", "type": "MX", "rdata": "10 mx.example.com." }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{response}");
    assert_eq!(response["data"]["record"]["rdata"], "10 mx.example.com.");

    let (status, response) = put(
        &h.state,
        "/api/v1/policy/records",
        json!({
            "name": "_sip._tcp.lan.example.com",
            "type": "SRV",
            "rdata": "1 5 5060 sip.lan.example.com.",
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{response}");
    assert_eq!(
        response["data"]["record"]["rdata"],
        "1 5 5060 sip.lan.example.com."
    );

    let (status, response) = put(
        &h.state,
        "/api/v1/policy/records",
        json!({ "name": "10.2.0.192.in-addr.arpa", "type": "PTR", "rdata": "nas.lan.example.com." }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{response}");
    assert_eq!(response["data"]["record"]["type"], "PTR");
}

#[tokio::test]
async fn client_id_registry_create_list_delete() {
    let h = harness().await;
    seed_policy(&h.state).await;

    let (status, response) = post(
        &h.state,
        "/api/v1/policy/client-ids",
        json!({ "id": "iphone-k7q2x9" }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{response}");
    assert_eq!(response["data"]["client_id"], "iphone-k7q2x9");

    let (status, response) = post(
        &h.state,
        "/api/v1/policy/client-ids",
        json!({ "id": "iphone-k7q2x9" }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{response}");
    assert_eq!(code(&response), "policy.config.invalid");

    let (status, response) = post(
        &h.state,
        "/api/v1/policy/client-ids",
        json!({ "id": "iPhone" }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{response}");
    assert_eq!(code(&response), "policy.config.invalid");

    let (status, response) = get(&h.state, "/api/v1/policy/client-ids").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(response["data"]["client_ids"], json!(["iphone-k7q2x9"]));

    let (status, response) =
        delete(&h.state, "/api/v1/policy/client-ids/iphone-k7q2x9", None).await;
    assert_eq!(status, StatusCode::OK, "{response}");
    assert_eq!(response["data"]["deleted"], true);

    let (status, response) =
        delete(&h.state, "/api/v1/policy/client-ids/iphone-k7q2x9", None).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{response}");
}

#[tokio::test]
async fn views_carry_nodes_and_no_longer_accept_client_ids_or_records() {
    let h = harness().await;
    seed_policy(&h.state).await;

    let (status, response) = put(
        &h.state,
        "/api/v1/policy/views/lan",
        json!({ "profile": "default", "subnets": ["192.0.2.0/24"], "nodes": ["node-1"] }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{response}");
    assert_eq!(response["data"]["view"]["nodes"], json!(["node-1"]));

    let (status, response) = get(&h.state, "/api/v1/policy/views/lan").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(response["data"]["view"]["nodes"], json!(["node-1"]));
    assert!(response["data"]["view"].get("client_ids").is_none());
    assert!(response["data"]["view"].get("records").is_none());

    let (status, response) = put(
        &h.state,
        "/api/v1/policy/views/lan",
        json!({ "profile": "default", "nodes": ["Node_1"] }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{response}");
    assert_eq!(code(&response), "policy.config.invalid");

    // The default view must exist on every node.
    let (status, response) = put(
        &h.state,
        "/api/v1/policy/views/default",
        json!({ "profile": "default", "is_default": true, "nodes": ["node-1"] }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{response}");
    assert_eq!(code(&response), "policy.config.invalid");

    for extra in [
        json!({ "client_ids": ["iphone-k7q2x9"] }),
        json!({ "records": [] }),
    ] {
        let mut body = json!({ "profile": "default" });
        body.as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        let (status, response) = put(&h.state, "/api/v1/policy/views/lan", body).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{response}");
        assert_eq!(code(&response), "policy.config.invalid");
    }
}
