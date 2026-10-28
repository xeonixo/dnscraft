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
    assert_eq!(
        response["data"]["client_ids"],
        json!([{ "id": "iphone-k7q2x9", "label": null, "device": null, "view": null }])
    );

    let (status, response) =
        delete(&h.state, "/api/v1/policy/client-ids/iphone-k7q2x9", None).await;
    assert_eq!(status, StatusCode::OK, "{response}");
    assert_eq!(response["data"]["deleted"], true);

    let (status, response) =
        delete(&h.state, "/api/v1/policy/client-ids/iphone-k7q2x9", None).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{response}");
}

/// Stored policy `client_ids` as the config endpoint returns them.
async fn stored_client_ids(state: &AppState) -> Value {
    let (status, response) = get(state, "/api/v1/config").await;
    assert_eq!(status, StatusCode::OK, "{response}");
    response["data"]["config"]["policy"]["client_ids"].clone()
}

#[tokio::test]
async fn client_ids_take_labels_and_devices_and_keep_plain_strings() {
    let h = harness().await;
    seed_policy(&h.state).await;

    // A bare id is stored as a string, exactly as before.
    let (status, response) = post(
        &h.state,
        "/api/v1/policy/client-ids",
        json!({ "id": "phone" }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{response}");
    assert_eq!(response["data"]["client_id"], "phone");
    assert_eq!(stored_client_ids(&h.state).await, json!(["phone"]));

    // Label is trimmed; device is stored as given (trimmed).
    let (status, response) = post(
        &h.state,
        "/api/v1/policy/client-ids",
        json!({ "id": "tablet", "label": "  Anna's iPad ", "device": " lan-ipad-1 " }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{response}");

    // Mixed list: strings are normalised to objects, order is preserved.
    let (status, response) = get(&h.state, "/api/v1/policy/client-ids").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        response["data"]["client_ids"],
        json!([
            { "id": "phone", "label": null, "device": null, "view": null },
            { "id": "tablet", "label": "Anna's iPad", "device": "lan-ipad-1", "view": null }
        ])
    );
    assert_eq!(
        stored_client_ids(&h.state).await,
        json!(["phone", { "id": "tablet", "label": "Anna's iPad", "device": "lan-ipad-1" }])
    );

    // A blank label is no label.
    let (status, response) = post(
        &h.state,
        "/api/v1/policy/client-ids",
        json!({ "id": "blank", "label": "   " }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{response}");
    assert_eq!(
        stored_client_ids(&h.state).await.as_array().unwrap()[2],
        json!("blank")
    );

    // Unknown keys and non-string fields are rejected.
    for body in [
        json!({ "id": "x1", "colour": "red" }),
        json!({ "id": "x2", "label": 5 }),
    ] {
        let (status, response) = post(&h.state, "/api/v1/policy/client-ids", body).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{response}");
        assert_eq!(code(&response), "policy.config.invalid");
    }
}

#[tokio::test]
async fn client_id_put_updates_label_and_device_without_touching_the_id() {
    let h = harness().await;
    seed_policy(&h.state).await;
    let (status, response) = post(
        &h.state,
        "/api/v1/policy/client-ids",
        json!({ "id": "tablet", "label": "Anna's iPad" }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{response}");
    let (status, response) = post(
        &h.state,
        "/api/v1/policy/client-ids",
        json!({ "id": "laptop", "label": "Laptop" }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{response}");

    // Only the given field changes.
    let (status, response) = put(
        &h.state,
        "/api/v1/policy/client-ids/tablet",
        json!({ "device": "lan-ipad-1" }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{response}");
    assert_eq!(
        response["data"]["client_id"],
        json!({ "id": "tablet", "label": "Anna's iPad", "device": "lan-ipad-1", "view": null })
    );

    // Null clears a field; "" after trimming clears it too.
    let (status, response) = put(
        &h.state,
        "/api/v1/policy/client-ids/tablet",
        json!({ "label": null }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{response}");
    assert_eq!(
        response["data"]["client_id"],
        json!({ "id": "tablet", "label": null, "device": "lan-ipad-1", "view": null })
    );
    let (status, response) = put(
        &h.state,
        "/api/v1/policy/client-ids/tablet",
        json!({ "label": "  ", "device": null }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{response}");
    assert_eq!(
        response["data"]["client_id"],
        json!({ "id": "tablet", "label": null, "device": null, "view": null })
    );
    // Back to the plain string form once it carries no metadata.
    assert_eq!(
        stored_client_ids(&h.state).await,
        json!(["tablet", { "id": "laptop", "label": "Laptop" }])
    );

    // Unknown id is not found; the id itself cannot be changed.
    let (status, response) = put(
        &h.state,
        "/api/v1/policy/client-ids/ghost",
        json!({ "label": "Ghost" }),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{response}");
    assert_eq!(code(&response), "control_api.not_found");
    let (status, response) = put(
        &h.state,
        "/api/v1/policy/client-ids/tablet",
        json!({ "id": "other" }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{response}");
    assert_eq!(code(&response), "policy.config.invalid");
}

#[tokio::test]
async fn client_id_labels_are_validated_and_unique_case_insensitively() {
    let h = harness().await;
    seed_policy(&h.state).await;
    for id in ["tablet", "laptop"] {
        let (status, response) = post(
            &h.state,
            "/api/v1/policy/client-ids",
            json!({ "id": id, "label": format!("{id} label") }),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{response}");
    }

    // Duplicate label (case-insensitive) names the field.
    let (status, response) = put(
        &h.state,
        "/api/v1/policy/client-ids/tablet",
        json!({ "label": "LAPTOP LABEL" }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{response}");
    assert_eq!(code(&response), "policy.config.invalid");
    assert_eq!(response["error"]["params"]["field"], "label");
    // Keeping one's own label is not a duplicate.
    let (status, response) = put(
        &h.state,
        "/api/v1/policy/client-ids/tablet",
        json!({ "label": "tablet label" }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{response}");

    // 64 characters is the limit; 65 is rejected.
    let (status, response) = put(
        &h.state,
        "/api/v1/policy/client-ids/tablet",
        json!({ "label": "x".repeat(65) }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{response}");
    assert_eq!(response["error"]["params"]["field"], "label");
    let (status, response) = put(
        &h.state,
        "/api/v1/policy/client-ids/tablet",
        json!({ "label": "x".repeat(64) }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{response}");

    // Control characters are rejected in label and device.
    let (status, response) = put(
        &h.state,
        "/api/v1/policy/client-ids/tablet",
        json!({ "label": "bad\u{7}label" }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{response}");
    let (status, response) = post(
        &h.state,
        "/api/v1/policy/client-ids",
        json!({ "id": "bell", "device": "a\nb" }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{response}");
    assert_eq!(response["error"]["params"]["field"], "device");

    // Device is free text up to 128 characters.
    let (status, response) = put(
        &h.state,
        "/api/v1/policy/client-ids/laptop",
        json!({ "device": "d".repeat(129) }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{response}");
    assert_eq!(response["error"]["params"]["field"], "device");
}

#[tokio::test]
async fn old_string_snapshot_round_trips_and_rolls_back_unchanged() {
    let h = harness().await;
    seed_policy(&h.state).await;
    let (status, response) = post(
        &h.state,
        "/api/v1/policy/client-ids",
        json!({ "id": "phone" }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{response}");
    let before = response["data"]["version"].as_u64().unwrap();
    let plain = stored_client_ids(&h.state).await;

    // Adding metadata to another entry does not rewrite the plain one.
    let (status, response) = post(
        &h.state,
        "/api/v1/policy/client-ids",
        json!({ "id": "tablet", "label": "Anna" }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{response}");
    assert_eq!(stored_client_ids(&h.state).await[0], json!("phone"));

    // Rolling back to the earlier version restores the string form exactly.
    let (status, response) = call(
        &h.state,
        "POST",
        &format!("/api/v1/config/versions/{before}/rollback"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{response}");
    assert_eq!(stored_client_ids(&h.state).await, plain);
    assert_eq!(plain, json!(["phone"]));
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

/// Seeds a second, non-default view `unterwegs` (no subnets: reached by pin only).
async fn seed_unterwegs_view(state: &AppState) {
    let (status, response) = put(
        state,
        "/api/v1/policy/views/unterwegs",
        json!({ "profile": "default" }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{response}");
}

#[tokio::test]
async fn client_id_view_pin_create_put_get_and_clear() {
    let h = harness().await;
    seed_policy(&h.state).await;
    seed_unterwegs_view(&h.state).await;

    // POST with a pin: the response and the list carry `view`.
    let (status, response) = post(
        &h.state,
        "/api/v1/policy/client-ids",
        json!({ "id": "phone", "view": "unterwegs" }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{response}");
    let (status, response) = get(&h.state, "/api/v1/policy/client-ids").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        response["data"]["client_ids"],
        json!([{ "id": "phone", "label": null, "device": null, "view": "unterwegs" }])
    );
    // Stored as an object without null keys.
    assert_eq!(
        stored_client_ids(&h.state).await,
        json!([{ "id": "phone", "view": "unterwegs" }])
    );

    // PUT without `view` leaves the pin alone.
    let (status, response) = put(
        &h.state,
        "/api/v1/policy/client-ids/phone",
        json!({ "label": "Anna's phone" }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{response}");
    assert_eq!(
        response["data"]["client_id"],
        json!({ "id": "phone", "label": "Anna's phone", "device": null, "view": "unterwegs" })
    );

    // `view: null` clears the pin; the metadata-free entry is a bare string again.
    let (status, response) = put(
        &h.state,
        "/api/v1/policy/client-ids/phone",
        json!({ "label": null, "view": null }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{response}");
    assert_eq!(response["data"]["client_id"]["view"], Value::Null);
    assert_eq!(stored_client_ids(&h.state).await, json!(["phone"]));

    // Setting a pin by PUT.
    let (status, response) = put(
        &h.state,
        "/api/v1/policy/client-ids/phone",
        json!({ "view": "unterwegs" }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{response}");
    assert_eq!(response["data"]["client_id"]["view"], "unterwegs");
}

#[tokio::test]
async fn client_id_view_must_exist() {
    let h = harness().await;
    seed_policy(&h.state).await;
    seed_unterwegs_view(&h.state).await;

    let (status, response) = post(
        &h.state,
        "/api/v1/policy/client-ids",
        json!({ "id": "phone", "view": "ghost" }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{response}");
    assert_eq!(code(&response), "policy.config.invalid");
    assert_eq!(response["error"]["params"]["field"], "view");
    assert!(response["error"]["params"]["reason"].is_string());

    post(
        &h.state,
        "/api/v1/policy/client-ids",
        json!({ "id": "phone" }),
    )
    .await;
    let (status, response) = put(
        &h.state,
        "/api/v1/policy/client-ids/phone",
        json!({ "view": "ghost" }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{response}");
    assert_eq!(code(&response), "policy.config.invalid");
    assert_eq!(response["error"]["params"]["field"], "view");
    // The rejected write did not change the entry.
    assert_eq!(stored_client_ids(&h.state).await, json!(["phone"]));

    // Non-string view values are rejected by the PUT parser.
    let (status, response) = put(
        &h.state,
        "/api/v1/policy/client-ids/phone",
        json!({ "view": 3 }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{response}");
    assert_eq!(code(&response), "policy.config.invalid");
}

#[tokio::test]
async fn view_with_pinned_client_ids_cannot_be_deleted() {
    let h = harness().await;
    seed_policy(&h.state).await;
    seed_unterwegs_view(&h.state).await;
    let (status, response) = post(
        &h.state,
        "/api/v1/policy/client-ids",
        json!({ "id": "phone", "view": "unterwegs" }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{response}");
    let (status, response) = post(
        &h.state,
        "/api/v1/policy/client-ids",
        json!({ "id": "tablet", "view": "unterwegs" }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{response}");

    let (status, response) = delete(&h.state, "/api/v1/policy/views/unterwegs", None).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{response}");
    assert_eq!(code(&response), "policy.config.invalid");
    assert_eq!(
        response["error"]["params"],
        json!({
            "reason": "view_in_use",
            "view": "unterwegs",
            "client_ids": ["phone", "tablet"],
        })
    );

    // Clearing the pins unblocks the delete.
    for id in ["phone", "tablet"] {
        let (status, response) = put(
            &h.state,
            &format!("/api/v1/policy/client-ids/{id}"),
            json!({ "view": null }),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{response}");
    }
    let (status, response) = delete(&h.state, "/api/v1/policy/views/unterwegs", None).await;
    assert_eq!(status, StatusCode::OK, "{response}");
}
