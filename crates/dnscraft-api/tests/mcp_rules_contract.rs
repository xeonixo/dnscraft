//! M22: custom-rule endpoints and the `mcp_rules` config contract.
//!
//! These exercise the HTTP surface against a real SQLite version store and the
//! config apply lock, including the cap race, expiry validation and the
//! protected-domain coverage rule.

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
    AppState, Audit, AuthState, Clock, ConfigService, ConfigStore, Db, ManualClock, ModuleAppliers,
    Scope, SessionStore, TokenStore,
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

async fn seed_set(h: &Harness, custom_rules: &str, mcp_rules: Option<Value>) {
    let mut body = json!({
        "id": "default",
        "name": "Default",
        "custom_rules": custom_rules,
    });
    if let Some(rules) = mcp_rules {
        body["mcp_rules"] = rules;
    }
    let (status, response) =
        send(&h.state, &h.admin, "PUT", "/api/v1/filter-sets", Some(body)).await;
    assert_eq!(status, StatusCode::OK, "{response}");
}

async fn current_rules(h: &Harness) -> Vec<Value> {
    let (_, snapshot) = h.service.current().await.unwrap();
    snapshot.unwrap()["filtering"]["sets"][0]["mcp_rules"]
        .as_array()
        .cloned()
        .unwrap_or_default()
}

fn stored_rule(id: &str, domain: &str) -> Value {
    json!({
        "id": id,
        "domain": domain,
        "include_subdomains": false,
        "created_at": NOW,
        "expires_at": NOW + 30 * DAY,
        "token_id": "tok",
    })
}

#[tokio::test]
async fn custom_rules_add_remove_versions_and_audit() {
    let h = harness().await;
    seed_set(&h, "||keep.example.com^", None).await;
    let before = h.service.current().await.unwrap().0.unwrap();

    let (status, response) = send(
        &h.state,
        &h.admin,
        "POST",
        "/api/v1/filtering/custom-rules",
        Some(json!({
            "domain": "ADS.Example.COM.",
            "include_subdomains": true,
            "reason": "test rule"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{response}");
    let data = &response["data"];
    assert_eq!(data["domain"], "ads.example.com");
    assert_eq!(data["rule_text"], "||ads.example.com^");
    assert_eq!(data["filter_set_id"], "default");
    assert_eq!(data["include_subdomains"], true);
    let added_version = data["config_version"].as_i64().unwrap();
    assert!(added_version > before);

    let rules = current_rules(&h).await;
    assert_eq!(rules.len(), 1);
    assert_eq!(rules[0]["domain"], "ads.example.com");
    assert_eq!(rules[0]["expires_at"], NOW + 30 * DAY);
    let (_, snapshot) = h.service.current().await.unwrap();
    assert_eq!(
        snapshot.unwrap()["filtering"]["sets"][0]["custom_rules"],
        "||keep.example.com^",
        "MCP rules never edit the custom_rules text"
    );

    let audits = h.db.audit_list(20, 0).await.unwrap();
    let add = audits
        .iter()
        .find(|record| record.action == "mcp.add_rule")
        .expect("add audit entry");
    assert_eq!(add.config_version, Some(added_version));
    assert_eq!(add.result, "ok");
    assert!(add.after.is_some(), "the add audit carries the rule");
    assert_eq!(
        audits
            .iter()
            .filter(|record| record.action == "mcp.add_rule")
            .count(),
        1
    );

    let (status, response) = send(
        &h.state,
        &h.admin,
        "DELETE",
        "/api/v1/filtering/custom-rules",
        Some(json!({ "domain": "ADS.EXAMPLE.COM." })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{response}");
    let removed_version = response["data"]["config_version"].as_i64().unwrap();
    assert_eq!(response["data"]["removed"], true);
    assert!(removed_version > added_version);
    assert!(current_rules(&h).await.is_empty());

    let remove_audit =
        h.db.audit_list(20, 0)
            .await
            .unwrap()
            .into_iter()
            .find(|record| record.action == "mcp.remove_rule")
            .expect("remove audit entry");
    assert_eq!(remove_audit.config_version, Some(removed_version));

    let (status, response) = send(
        &h.state,
        &h.admin,
        "DELETE",
        "/api/v1/filtering/custom-rules",
        Some(json!({ "domain": "ads.example.com" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{response}");
    assert_eq!(response["data"]["removed"], false);
    assert_eq!(response["data"]["config_version"], Value::Null);
    assert_eq!(
        h.service.current().await.unwrap().0.unwrap(),
        removed_version,
        "a no-op delete stores no version"
    );
}

#[tokio::test]
async fn custom_rules_reject_invalid_domains_and_expiries() {
    let h = harness().await;
    seed_set(&h, "", None).await;

    for (domain, code) in [
        ("*.example.com", "filter_build.pattern_not_allowed"),
        ("192.0.2.1", "filter_build.pattern_not_allowed"),
        ("localhost", "mcp.domain_too_broad"),
        ("bad domain.example.com", "filter_build.invalid_domain"),
    ] {
        let (status, response) = send(
            &h.state,
            &h.admin,
            "POST",
            "/api/v1/filtering/custom-rules",
            Some(json!({ "domain": domain, "include_subdomains": false })),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{domain}: {response}");
        assert_eq!(response["error"]["code"], code, "{domain}");
    }

    let (status, response) = send(
        &h.state,
        &h.admin,
        "POST",
        "/api/v1/filtering/custom-rules",
        Some(json!({
            "domain": "later.example.com",
            "include_subdomains": false,
            "expires_at": NOW + 31 * DAY
        })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{response}");
    assert_eq!(response["error"]["code"], "mcp.duration_exceeds_maximum");

    let (status, response) = send(
        &h.state,
        &h.admin,
        "POST",
        "/api/v1/filtering/custom-rules",
        Some(json!({
            "domain": "past.example.com",
            "include_subdomains": false,
            "expires_at": NOW - 1
        })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{response}");
    assert_eq!(response["error"]["code"], "mcp.duration_exceeds_maximum");

    let (status, response) = send(
        &h.state,
        &h.admin,
        "POST",
        "/api/v1/filtering/custom-rules",
        Some(json!({
            "domain": "early.example.com",
            "include_subdomains": false,
            "expires_at": NOW + 3600
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{response}");
    assert_eq!(current_rules(&h).await[0]["expires_at"], NOW + 3600);
}

#[tokio::test]
async fn custom_rules_enforce_protected_domains() {
    let h = harness_with(McpConfig {
        protected_domains: vec!["auth.example.net".to_owned()],
        ..McpConfig::default()
    })
    .await;
    seed_set(&h, "", None).await;

    for (domain, include) in [
        ("auth.example.net", false),
        ("auth.example.net", true),
        ("example.net", true),
    ] {
        let (status, response) = send(
            &h.state,
            &h.admin,
            "POST",
            "/api/v1/filtering/custom-rules",
            Some(json!({ "domain": domain, "include_subdomains": include })),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "{domain}/{include}: {response}"
        );
        assert_eq!(response["error"]["code"], "mcp.protected_domain");
    }

    for domain in ["example.net", "other.example.net"] {
        let (status, response) = send(
            &h.state,
            &h.admin,
            "POST",
            "/api/v1/filtering/custom-rules",
            Some(json!({ "domain": domain, "include_subdomains": false })),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{domain}: {response}");
    }

    // Removal replays the check with the stored rule's flag.
    let rules = current_rules(&h).await;
    assert_eq!(rules.len(), 2);
    let (status, response) = send(
        &h.state,
        &h.admin,
        "DELETE",
        "/api/v1/filtering/custom-rules",
        Some(json!({ "domain": "example.net" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{response}");
    assert_eq!(response["data"]["removed"], true);
}

#[tokio::test]
async fn cap_check_is_serialised_by_the_apply_lock() {
    let h = harness_with(McpConfig {
        max_custom_rules_per_set: 10,
        ..McpConfig::default()
    })
    .await;
    let rules: Vec<Value> = (0..9)
        .map(|index| stored_rule(&format!("r{index}"), &format!("r{index}.example.com")))
        .collect();
    seed_set(&h, "", Some(Value::Array(rules))).await;
    let before = h.service.current().await.unwrap().0.unwrap();

    let first = send(
        &h.state,
        &h.admin,
        "POST",
        "/api/v1/filtering/custom-rules",
        Some(json!({ "domain": "one.example.com", "include_subdomains": false })),
    );
    let second = send(
        &h.state,
        &h.admin,
        "POST",
        "/api/v1/filtering/custom-rules",
        Some(json!({ "domain": "two.example.com", "include_subdomains": false })),
    );
    let ((first_status, first_body), (second_status, second_body)) = tokio::join!(first, second);

    let results = [(first_status, &first_body), (second_status, &second_body)];
    let ok = results
        .iter()
        .filter(|(status, _)| *status == StatusCode::OK)
        .count();
    let limited = results
        .iter()
        .filter(|(status, body)| {
            *status == StatusCode::BAD_REQUEST && body["error"]["code"] == "mcp.rule_limit_exceeded"
        })
        .count();
    assert_eq!(ok, 1, "{first_body} / {second_body}");
    assert_eq!(limited, 1, "{first_body} / {second_body}");
    assert_eq!(current_rules(&h).await.len(), 10);
    assert_eq!(h.service.current().await.unwrap().0.unwrap(), before + 1);
}

#[tokio::test]
async fn mcp_rules_contract_carries_deletes_and_rolls_back() {
    let h = harness().await;
    seed_set(&h, "||keep.example.com^", None).await;

    let (status, response) = send(
        &h.state,
        &h.admin,
        "POST",
        "/api/v1/filtering/custom-rules",
        Some(json!({ "domain": "rule.example.com", "include_subdomains": false })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{response}");
    let with_rule = response["data"]["config_version"].as_i64().unwrap();
    assert_eq!(current_rules(&h).await.len(), 1);

    let (_, mut snapshot) = h.service.current().await.unwrap();
    let snapshot = snapshot.as_mut().unwrap();
    snapshot["filtering"]["sets"][0]
        .as_object_mut()
        .unwrap()
        .remove("mcp_rules");
    let (status, response) = send(
        &h.state,
        &h.admin,
        "PUT",
        "/api/v1/config",
        Some(snapshot.clone()),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{response}");
    assert_eq!(
        current_rules(&h).await.len(),
        1,
        "omitting mcp_rules carries the rules over"
    );

    snapshot["filtering"]["sets"][0]["mcp_rules"] = json!([]);
    let (status, response) = send(
        &h.state,
        &h.admin,
        "PUT",
        "/api/v1/config",
        Some(snapshot.clone()),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{response}");
    assert!(current_rules(&h).await.is_empty());

    let (status, response) = send(
        &h.state,
        &h.admin,
        "POST",
        &format!("/api/v1/config/versions/{with_rule}/rollback"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{response}");
    assert_eq!(current_rules(&h).await.len(), 1);
    assert_eq!(current_rules(&h).await[0]["domain"], "rule.example.com");
}
