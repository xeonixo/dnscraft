//! M20: MCP-facing read endpoints on `/api/v1`.
//!
//! Covers `filtering/explain-block`, `policy/test-query` and
//! `filtering/mcp-rules`, including viewer/admin access and the dry-run
//! side-effect guarantees.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use axum::body::Body;
use axum::extract::connect_info::MockConnectInfo;
use axum::http::{Request, StatusCode, header};
use serde_json::{Value, json};
use tower::ServiceExt as _;

use dnscraft_api::{
    AppState, Audit, Auth, AuthState, ConfigService, ConfigStore, Db, ManualClock, ModuleAppliers,
    Scope, SessionStore, TokenStore,
};
use dnscraft_filtering::{
    BlockMode, FilterConfig, FilterEngine, FilterSetConfig, ListBodies, ListId,
    ManualClock as FilterClock, SetId, SnapshotBuilder,
};
use dnscraft_policy::{
    NoClients, PolicyConfig, PolicyEngine, ProfileConfig, ProfileId, ViewConfig, ViewId,
    ViewRecordConfig,
};
use dnscraft_proto::{Name, RData};
use dnscraft_resolver::{Resolver, ResolverConfig};

const IDLE: Duration = Duration::from_secs(60 * 60);
const ABSOLUTE: Duration = Duration::from_secs(12 * 3600);
const MAX_TTL: Duration = Duration::from_secs(365 * 24 * 3600);
const NOW: u64 = 1_700_000_000;

#[derive(Debug, Default)]
struct EmptyBodies;

impl ListBodies for EmptyBodies {
    fn body(&self, _id: &ListId) -> Option<Arc<str>> {
        None
    }
}

fn sid(id: &str) -> SetId {
    SetId::new(id).unwrap()
}

fn filter_engine() -> Arc<FilterEngine> {
    let mut set = FilterSetConfig::new(sid("default"), "Default");
    set.custom_rules = "||ads.example.com^".to_owned();
    set.block_mode = BlockMode::NxDomain;
    let mut strict = FilterSetConfig::new(sid("strict"), "Strict");
    strict.custom_rules = "||ads.example.com^".to_owned();
    strict.block_mode = BlockMode::NxDomain;
    Arc::new(FilterEngine::from_snapshot(
        SnapshotBuilder::new(Arc::new(EmptyBodies) as Arc<dyn ListBodies>)
            .build(&FilterConfig {
                lists: Vec::new(),
                sets: vec![set, strict],
                ..FilterConfig::default()
            })
            .unwrap(),
    ))
}

fn profile() -> ProfileConfig {
    ProfileConfig {
        id: ProfileId::new("default").unwrap(),
        filter_set: sid("default"),
        suppress_aaaa: false,
        firefox_canary: false,
        icloud_private_relay: false,
        rebind: None,
        rebind_exceptions: Vec::new(),
        forward_zones: None,
        safesearch: Default::default(),
        schedules: Vec::new(),
    }
}

fn view() -> ViewConfig {
    ViewConfig {
        id: ViewId::new("default").unwrap(),
        is_default: true,
        subnets: Vec::new(),
        client_ids: Vec::new(),
        records: vec![ViewRecordConfig {
            name: Name::from_ascii("local.example.com.").unwrap(),
            ttl: 60,
            rdata: RData::A(Ipv4Addr::new(192, 0, 2, 1)),
        }],
        profile: ProfileId::new("default").unwrap(),
    }
}

async fn policy_engine(filter: Arc<FilterEngine>) -> Arc<PolicyEngine> {
    let resolver = Arc::new(Resolver::new(ResolverConfig::default()).await.unwrap());
    Arc::new(
        PolicyEngine::new(
            PolicyConfig {
                views: vec![view()],
                profiles: vec![profile()],
                ..PolicyConfig::default()
            },
            filter,
            resolver,
            Arc::new(NoClients),
            Arc::new(FilterClock::new(
                SystemTime::UNIX_EPOCH + Duration::from_secs(NOW),
            )),
        )
        .unwrap(),
    )
}

struct Harness {
    state: AppState,
    viewer: String,
    admin: String,
    policy: Arc<PolicyEngine>,
}

async fn harness() -> Harness {
    let db = Db::open_in_memory(Arc::new(ManualClock::new(
        SystemTime::UNIX_EPOCH + Duration::from_secs(NOW),
    )))
    .await
    .unwrap();
    let clock = Arc::new(ManualClock::new(
        SystemTime::UNIX_EPOCH + Duration::from_secs(NOW),
    ));
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
    let service = Arc::new(ConfigService::new(
        ConfigStore::new(db.clone()),
        Audit::new(db),
        ModuleAppliers::default(),
        "node-a",
    ));
    let filter = filter_engine();
    let policy = policy_engine(Arc::clone(&filter)).await;
    let state = AppState::new()
        .with_clock(clock)
        .with_auth(auth)
        .with_config_service(service)
        .with_filter_engine(filter)
        .with_policy_engine(Arc::clone(&policy));
    Harness {
        state,
        viewer: viewer.plaintext().expose().to_owned(),
        admin: admin.plaintext().expose().to_owned(),
        policy,
    }
}

async fn send(
    state: &AppState,
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

async fn seed_rules(state: &AppState, token: &str) {
    let (status, response) = send(
        state,
        "PUT",
        "/api/v1/filter-sets",
        Some(token),
        Some(json!({
            "id": "default",
            "name": "Default",
            "mcp_rules": [
                {
                    "id": "active",
                    "domain": "ads.example.com",
                    "include_subdomains": false,
                    "created_at": NOW,
                    "expires_at": NOW + 3600,
                    "token_id": "tok",
                },
                {
                    "id": "active2",
                    "domain": "tracker.example.com",
                    "include_subdomains": true,
                    "created_at": NOW,
                    "expires_at": NOW + 3600,
                    "token_id": "tok",
                },
                {
                    "id": "expired",
                    "domain": "old.example.com",
                    "include_subdomains": false,
                    "created_at": NOW - 7200,
                    "expires_at": NOW - 1,
                    "token_id": "tok",
                }
            ]
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{response}");
}

#[tokio::test]
async fn filtering_read_explain_block_canonicalises_and_reports_reason() {
    let h = harness().await;
    let (status, response) = send(
        &h.state,
        "POST",
        "/api/v1/filtering/explain-block",
        Some(&h.viewer),
        Some(json!({ "domain": "ADS.Example.COM.", "qtype": "A" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{response}");
    assert_eq!(response["data"]["domain"], "ads.example.com");
    assert_eq!(response["data"]["verdict"], "blocked");
    assert_eq!(response["data"]["filter_set_id"], "default");
    assert_eq!(
        response["data"]["reason"]["rule_text"],
        "||ads.example.com^"
    );

    let (status, response) = send(
        &h.state,
        "POST",
        "/api/v1/filtering/explain-block",
        Some(&h.viewer),
        Some(json!({ "domain": "not a domain", "qtype": "A" })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{response}");
    assert_eq!(response["error"]["code"], "filter_name.invalid_char");
}

/// `explain_block` resolves `profile_id` through the stored policy profile to
/// the configured `filter_set`, never by treating the profile id as a set id.
#[tokio::test]
async fn explain_block_resolves_a_profile_to_its_configured_filter_set() {
    let h = harness().await;
    for set in [
        json!({ "id": "default", "name": "Default" }),
        json!({ "id": "strict", "name": "Strict" }),
    ] {
        let (status, response) = send(
            &h.state,
            "PUT",
            "/api/v1/filter-sets",
            Some(&h.admin),
            Some(set),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{response}");
    }
    let (status, response) = send(
        &h.state,
        "PUT",
        "/api/v1/policy/profiles/kids",
        Some(&h.admin),
        Some(json!({ "filter_set": "strict" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{response}");

    let (status, response) = send(
        &h.state,
        "POST",
        "/api/v1/filtering/explain-block",
        Some(&h.viewer),
        Some(json!({
            "domain": "ads.example.com",
            "profile_id": "kids",
            "qtype": "A"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{response}");
    assert_eq!(response["data"]["profile_id"], "kids");
    assert_eq!(response["data"]["filter_set_id"], "strict");
    assert_eq!(response["data"]["verdict"], "blocked");

    // An unknown profile is an error, never a silent fallback to the default.
    let (status, response) = send(
        &h.state,
        "POST",
        "/api/v1/filtering/explain-block",
        Some(&h.viewer),
        Some(json!({
            "domain": "ads.example.com",
            "profile_id": "missing",
            "qtype": "A"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{response}");
    assert_eq!(response["error"]["code"], "policy.config.invalid");

    // An unparsable filter-set id on the listing endpoint is an error too.
    let (status, response) = send(
        &h.state,
        "GET",
        "/api/v1/filtering/mcp-rules?filter_set_id=bad%20id",
        Some(&h.viewer),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{response}");
    assert_eq!(
        response["error"]["code"],
        "policy.config.unknown_filter_set"
    );
}

#[tokio::test]
async fn policy_test_query_is_a_dry_run_without_log_or_cache_writes() {
    let h = harness().await;
    let stats_before = h.policy.stats();
    let (status, response) = send(
        &h.state,
        "POST",
        "/api/v1/policy/test-query",
        Some(&h.admin),
        Some(json!({
            "domain": "local.example.com",
            "qtype": "A",
            "source_ip": "192.0.2.10",
            "protocol": "udp53"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{response}");
    assert_eq!(response["data"]["filter"], Value::Null);
    assert_eq!(response["data"]["answer"]["rcode"], "NOERROR");
    assert_eq!(
        response["data"]["answer"]["records"][0]["data"],
        "192.0.2.1"
    );
    assert_eq!(h.policy.stats(), stats_before);

    let (status, response) = send(
        &h.state,
        "POST",
        "/api/v1/policy/test-query",
        Some(&h.admin),
        Some(json!({
            "domain": "local.example.com",
            "qtype": "A",
            "source_ip": "not-an-ip",
            "protocol": "udp53"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{response}");
    assert_eq!(response["error"]["code"], "mcp.invalid_input");
}

#[tokio::test]
async fn mcp_rules_listing_excludes_expired_and_paginates() {
    let h = harness().await;
    seed_rules(&h.state, &h.admin).await;

    let (status, response) = send(
        &h.state,
        "GET",
        "/api/v1/filtering/mcp-rules?filter_set_id=default&limit=1",
        Some(&h.viewer),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{response}");
    let data = &response["data"];
    assert_eq!(data["kind"], "rules");
    assert_eq!(data["rules"].as_array().unwrap().len(), 1);
    assert_eq!(data["rules"][0]["id"], "active");
    assert_eq!(data["has_more"], true);
    assert_eq!(data["next_offset"], 1);

    let (status, response) = send(
        &h.state,
        "GET",
        "/api/v1/filtering/mcp-rules?kind=bogus",
        Some(&h.admin),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{response}");
    assert_eq!(response["error"]["code"], "mcp.invalid_input");
}

#[tokio::test]
async fn read_endpoints_require_authentication() {
    let h = harness().await;
    for (method, uri, body) in [
        (
            "POST",
            "/api/v1/filtering/explain-block",
            Some(json!({ "domain": "ads.example.com", "qtype": "A" })),
        ),
        (
            "POST",
            "/api/v1/policy/test-query",
            Some(json!({
                "domain": "local.example.com",
                "qtype": "A",
                "source_ip": "192.0.2.10",
                "protocol": "udp53"
            })),
        ),
        ("GET", "/api/v1/filtering/mcp-rules", None),
    ] {
        let (status, response) = send(&h.state, method, uri, None, body).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{uri}: {response}");
        assert_eq!(
            response["error"]["code"],
            "control_api.auth.unauthenticated"
        );
    }
}

#[tokio::test]
async fn viewer_cannot_use_write_filtering_routes() {
    let h = harness().await;
    let (status, response) = send(
        &h.state,
        "POST",
        "/api/v1/filtering/custom-rules",
        Some(&h.viewer),
        Some(json!({ "domain": "blocked.example.com", "include_subdomains": false })),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{response}");
    assert_eq!(
        response["error"]["code"],
        "control_api.auth.insufficient_scope"
    );
}
