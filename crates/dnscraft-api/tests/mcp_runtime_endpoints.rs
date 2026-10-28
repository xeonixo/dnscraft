//! M23: temporary-allow, pause and resume endpoints over real runtime state.
//!
//! The filter engine is built with the same frozen clock as the control API so
//! the exact expiry instants are deterministic. Protected-host derivation is
//! exercised through the endpoints after a config change, and directly for all
//! five sources.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime};

use axum::body::Body;
use axum::extract::connect_info::MockConnectInfo;
use axum::http::{Request, StatusCode, header};
use serde_json::{Value, json};
use tower::ServiceExt as _;

use dnscraft_api::{
    AppState, Audit, AuthState, Clock, ConfigActor, ConfigService, ConfigStore, Db, ManualClock,
    ModuleAppliers, Scope, SessionStore, TokenStore, derive_protected_domains,
};
use dnscraft_filtering::{
    BlockMode, Clock as FilterClockTrait, DomainName, FilterConfig, FilterEngine, FilterSetConfig,
    ListStore, ManualClock as FilterClock, RuleSource, SetId, StoreConfig, Verdict,
};
use dnscraft_mcp::McpConfig;

const IDLE: Duration = Duration::from_secs(60 * 60);
const ABSOLUTE: Duration = Duration::from_secs(12 * 3600);
const MAX_TTL: Duration = Duration::from_secs(365 * 24 * 3600);
const NOW: u64 = 1_700_000_000;

fn at(seconds: u64) -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(seconds)
}

fn rfc3339(seconds: u64) -> String {
    time::OffsetDateTime::from_unix_timestamp(seconds as i64)
        .unwrap_or(time::OffsetDateTime::UNIX_EPOCH)
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default()
}

/// A unique, self-cleaning temporary directory.
struct TempDir(PathBuf);

impl TempDir {
    fn new(name: &str) -> Self {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let id = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("dnscraft-m23-{name}-{}-{id}", std::process::id()));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).unwrap();
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn snapshot(public_domain: Option<&str>) -> Value {
    json!({
        "filtering": {
            "lists": [],
            "sets": [{
                "id": "default",
                "name": "Default",
                "lists": [],
                "custom_rules": "||ads.example.com^",
                "services": [],
                "block_mode": "refused"
            }]
        },
        "clients": {},
        "policy": {},
        "listeners": {},
        "tls": public_domain.map_or_else(|| json!({}), |domain| json!({ "public_domain": domain })),
        "resolver": {}
    })
}

fn engine(temp: &TempDir) -> Arc<FilterEngine> {
    let clock = Arc::new(FilterClock::new(at(NOW)));
    let mut set = FilterSetConfig::new(SetId::new("default").unwrap(), "Default");
    set.custom_rules = "||ads.example.com^".to_owned();
    set.block_mode = BlockMode::NxDomain;
    let config = FilterConfig {
        lists: Vec::new(),
        sets: vec![set],
        ..FilterConfig::default()
    };
    let store = ListStore::open_with(
        temp.path(),
        StoreConfig::default(),
        Arc::clone(&clock) as Arc<dyn FilterClockTrait>,
    )
    .unwrap();
    FilterEngine::open_without_scheduler(config, store, clock).unwrap()
}

struct Harness {
    state: AppState,
    service: Arc<ConfigService>,
    db: Db,
    admin: String,
    filter: Arc<FilterEngine>,
    clock: Arc<ManualClock>,
    _temp: TempDir,
}

async fn harness_with(mcp: McpConfig, snapshot: Value, issuer: Option<&str>) -> Harness {
    let temp = TempDir::new("runtime");
    let filter = engine(&temp);
    let clock = Arc::new(ManualClock::new(at(NOW)));
    let db = Db::open_in_memory(Arc::clone(&clock) as Arc<dyn Clock>)
        .await
        .unwrap();
    let auth = AuthState::new(
        SessionStore::new(db.clone(), IDLE, ABSOLUTE),
        TokenStore::new(db.clone(), MAX_TTL),
    );
    let admin = TokenStore::new(db.clone(), MAX_TTL)
        .create("admin-a".to_owned(), "admin".to_owned(), Scope::Admin, None)
        .await
        .unwrap();
    let service = Arc::new(ConfigService::new(
        ConfigStore::new(db.clone()),
        Audit::new(db.clone()),
        ModuleAppliers::default(),
        "node-a",
    ));
    service
        .replace(snapshot, &ConfigActor::local(), None)
        .await
        .unwrap();
    let mut state = AppState::new()
        .with_clock(Arc::clone(&clock) as Arc<dyn Clock>)
        .with_auth(auth)
        .with_config_service(Arc::clone(&service))
        .with_filter_engine(Arc::clone(&filter))
        .with_mcp_config(mcp);
    if let Some(issuer) = issuer {
        state = state.with_oidc_issuer(issuer);
    }
    Harness {
        state,
        service,
        db,
        admin: admin.plaintext().expose().to_owned(),
        filter,
        clock,
        _temp: temp,
    }
}

async fn harness() -> Harness {
    harness_with(McpConfig::default(), snapshot(None), None).await
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

fn default_set() -> SetId {
    SetId::new("default").unwrap()
}

fn verify(filter: &FilterEngine, name: &str, now: u64) -> Verdict {
    filter
        .match_name(
            &default_set(),
            &DomainName::parse(name).unwrap(),
            1,
            at(now),
        )
        .unwrap()
}

#[tokio::test]
async fn temp_allows_take_effect_exactly_and_are_not_versioned() {
    let h = harness().await;
    let before = h.service.current().await.unwrap().0.unwrap();

    let (status, response) = send(
        &h.state,
        &h.admin,
        "POST",
        "/api/v1/filtering/temporary-allows",
        Some(json!({
            "domain": "ADS.Example.COM.",
            "include_subdomains": true,
            "duration": "PT15M",
            "reason": "owner test"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{response}");
    let data = &response["data"];
    assert_eq!(data["domain"], "ads.example.com");
    assert_eq!(data["include_subdomains"], true);
    assert_eq!(data["filter_set_id"], "default");
    assert_eq!(data["created_at"], rfc3339(NOW));
    assert_eq!(data["expires_at"], rfc3339(NOW + 900));

    let Verdict::Allowed(reason) = verify(&h.filter, "ads.example.com", NOW) else {
        panic!("temporary allow did not win at the same instant");
    };
    assert_eq!(reason.source, RuleSource::TemporaryAllow);
    assert!(matches!(
        verify(&h.filter, "child.ads.example.com", NOW),
        Verdict::Allowed(_)
    ));
    assert!(matches!(
        verify(&h.filter, "ads.example.com", NOW + 900),
        Verdict::Blocked(_)
    ));

    let (version, stored) = h.service.current().await.unwrap();
    assert_eq!(version.unwrap(), before, "runtime state creates no version");
    assert!(
        !stored.unwrap().to_string().contains("temporary"),
        "temporary allows never enter the stored snapshot"
    );

    let audits = h.db.audit_list(20, 0).await.unwrap();
    let allow = audits
        .iter()
        .find(|record| record.action == "mcp.allow_temporarily")
        .expect("allow audit entry");
    assert_eq!(allow.result, "ok");
    assert_eq!(allow.config_version, Some(before));
}

#[tokio::test]
async fn temp_allow_validation_covers_durations_protected_and_unknown_sets() {
    let h = harness_with(
        McpConfig {
            max_temporary_allow_duration: Duration::from_secs(900),
            protected_domains: vec!["extra.example.org".to_owned()],
            ..McpConfig::default()
        },
        snapshot(Some("example.net")),
        Some("https://auth.example.org/realms/main"),
    )
    .await;

    let (status, response) = send(
        &h.state,
        &h.admin,
        "POST",
        "/api/v1/filtering/temporary-allows",
        Some(json!({
            "domain": "later.example.com",
            "include_subdomains": false,
            "duration": "PT1H"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{response}");
    assert_eq!(response["error"]["code"], "mcp.duration_exceeds_maximum");

    for (domain, code) in [
        ("localhost", "mcp.domain_too_broad"),
        ("*.example.com", "filter_build.pattern_not_allowed"),
        ("example.net", "mcp.protected_domain"),
        ("dns.example.net", "mcp.protected_domain"),
        ("node.dns.example.net", "mcp.protected_domain"),
        ("auth.example.org", "mcp.protected_domain"),
        ("extra.example.org", "mcp.protected_domain"),
    ] {
        let (status, response) = send(
            &h.state,
            &h.admin,
            "POST",
            "/api/v1/filtering/temporary-allows",
            Some(json!({
                "domain": domain,
                "include_subdomains": true,
                "duration": "PT15M"
            })),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{domain}: {response}");
        assert_eq!(response["error"]["code"], code, "{domain}");
    }

    let (status, response) = send(
        &h.state,
        &h.admin,
        "POST",
        "/api/v1/filtering/temporary-allows",
        Some(json!({
            "domain": "other.example.org",
            "include_subdomains": false,
            "duration": "PT15M",
            "filter_set_id": "missing"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{response}");
    assert_eq!(
        response["error"]["code"],
        "policy.config.unknown_filter_set"
    );

    let (status, response) = send(
        &h.state,
        &h.admin,
        "POST",
        "/api/v1/filtering/temporary-allows",
        Some(json!({
            "domain": "other.example.org",
            "include_subdomains": false,
            "duration": "PT15M"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{response}");
}

#[tokio::test]
async fn pause_and_resume_take_effect_immediately_and_are_not_versioned() {
    let h = harness().await;
    let before = h.service.current().await.unwrap().0.unwrap();

    let (status, response) = send(
        &h.state,
        &h.admin,
        "POST",
        "/api/v1/filtering/pause",
        Some(json!({ "duration": "PT5M" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{response}");
    assert_eq!(response["data"]["filter_set_id"], "default");
    assert_eq!(response["data"]["paused_until"], rfc3339(NOW + 300));
    assert!(matches!(
        verify(&h.filter, "ads.example.com", NOW),
        Verdict::Pass
    ));
    assert!(matches!(
        verify(&h.filter, "ads.example.com", NOW + 300),
        Verdict::Blocked(_)
    ));

    let (status, response) = send(
        &h.state,
        &h.admin,
        "GET",
        "/api/v1/filtering/mcp-rules?kind=pauses",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{response}");
    assert_eq!(response["data"]["pauses"].as_array().map(Vec::len), Some(1));
    assert_eq!(
        response["data"]["pauses"][0]["paused_until"],
        rfc3339(NOW + 300)
    );

    let (status, response) = send(
        &h.state,
        &h.admin,
        "POST",
        "/api/v1/filtering/resume",
        Some(json!({})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{response}");
    assert_eq!(response["data"]["resumed"], true);
    assert!(matches!(
        verify(&h.filter, "ads.example.com", NOW),
        Verdict::Blocked(_)
    ));

    let (status, response) = send(
        &h.state,
        &h.admin,
        "POST",
        "/api/v1/filtering/resume",
        Some(json!({})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{response}");
    assert_eq!(response["data"]["resumed"], false);

    assert_eq!(
        h.service.current().await.unwrap().0.unwrap(),
        before,
        "pause and resume are runtime state"
    );

    let (status, response) = send(
        &h.state,
        &h.admin,
        "POST",
        "/api/v1/filtering/pause",
        Some(json!({ "duration": "PT4H" })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{response}");
    assert_eq!(response["error"]["code"], "mcp.invalid_input");

    let (status, response) = send(
        &h.state,
        &h.admin,
        "POST",
        "/api/v1/filtering/pause",
        Some(json!({ "duration": "PT5M", "filter_set_id": "missing" })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{response}");
    assert_eq!(
        response["error"]["code"],
        "policy.config.unknown_filter_set"
    );

    let audits = h.db.audit_list(20, 0).await.unwrap();
    for action in ["mcp.pause_filter_set", "mcp.resume_filter_set"] {
        let ok: Vec<_> = audits
            .iter()
            .filter(|record| record.action == action && record.result == "ok")
            .collect();
        assert!(!ok.is_empty(), "{action}");
    }
    assert!(
        audits.iter().any(|record| {
            record.action == "mcp.pause_filter_set"
                && record.result == "error"
                && record.error_code.as_deref() == Some("policy.config.unknown_filter_set")
        }),
        "unknown-set pause is audited"
    );
}

#[tokio::test]
async fn protected_derivation_updates_after_a_config_apply() {
    let h = harness_with(
        McpConfig::default(),
        snapshot(Some("example.net")),
        Some("https://auth.example.org/realms/main"),
    )
    .await;

    for domain in ["example.net", "dns.example.net", "auth.example.org"] {
        let (status, response) = send(
            &h.state,
            &h.admin,
            "POST",
            "/api/v1/filtering/temporary-allows",
            Some(json!({
                "domain": domain,
                "include_subdomains": false,
                "duration": "PT5M"
            })),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{domain}: {response}");
        assert_eq!(response["error"]["code"], "mcp.protected_domain");
    }

    let (status, response) = send(
        &h.state,
        &h.admin,
        "PUT",
        "/api/v1/config",
        Some(snapshot(Some("example.org"))),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{response}");

    for domain in ["example.org", "dns.example.org"] {
        let (status, response) = send(
            &h.state,
            &h.admin,
            "POST",
            "/api/v1/filtering/temporary-allows",
            Some(json!({
                "domain": domain,
                "include_subdomains": false,
                "duration": "PT5M"
            })),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{domain}: {response}");
        assert_eq!(response["error"]["code"], "mcp.protected_domain");
    }

    let (status, response) = send(
        &h.state,
        &h.admin,
        "POST",
        "/api/v1/filtering/temporary-allows",
        Some(json!({
            "domain": "example.net",
            "include_subdomains": false,
            "duration": "PT5M"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{response}");
}

#[test]
fn protected_derivation_covers_all_five_sources() {
    let config = json!({
        "filtering": {
            "lists": [
                { "id": "ads", "source": { "url": "https://lists.example.com/ads.txt" } },
                { "id": "local", "source": { "file": "blocklist.txt" } }
            ]
        },
        "listeners": { "ddr": { "target": "node1" } },
        "tls": {
            "public_domain": "example.net",
            "acme": { "directory": "staging" },
            "dyndns": {
                "hostname": "node1.dns.example.net",
                "reserved_labels": ["node2"],
                "echo_url": "https://echo.example.net/cdn-cgi/trace"
            }
        },
        "resolver": { "forward_zones": [{ "zone": "site-b.internal" }] }
    });
    let list = derive_protected_domains(
        Some(&config),
        Some("https://auth.example.org/realms/main"),
        ["extra.example.org".to_owned()],
    )
    .unwrap();
    for expected in [
        "example.net",
        "dns.example.net",
        "node1.dns.example.net",
        "node2.dns.example.net",
        "auth.example.org",
        "acme-staging-v02.api.letsencrypt.org",
        "api.cloudflare.com",
        "echo.example.net",
        "lists.example.com",
        "site-b.internal",
        "extra.example.org",
    ] {
        assert!(
            list.entries().iter().any(|entry| entry == expected),
            "missing {expected}: {:?}",
            list.entries()
        );
    }
    assert!(
        !list
            .entries()
            .iter()
            .any(|entry| entry.contains("blocklist"))
    );
}

#[tokio::test]
async fn internal_errors_do_not_leak_detail() {
    let temp = TempDir::new("internal");
    let filter = engine(&temp);
    let clock = Arc::new(ManualClock::new(at(NOW)));
    let db = Db::open_in_memory(Arc::clone(&clock) as Arc<dyn Clock>)
        .await
        .unwrap();
    let auth = AuthState::new(
        SessionStore::new(db.clone(), IDLE, ABSOLUTE),
        TokenStore::new(db.clone(), MAX_TTL),
    );
    let admin = TokenStore::new(db.clone(), MAX_TTL)
        .create("admin-a".to_owned(), "admin".to_owned(), Scope::Admin, None)
        .await
        .unwrap();
    let state = AppState::new()
        .with_clock(clock)
        .with_auth(auth)
        .with_filter_engine(filter);

    let (status, response) = send(
        &state,
        admin.plaintext().expose(),
        "POST",
        "/api/v1/filtering/temporary-allows",
        Some(json!({
            "domain": "other.example.org",
            "include_subdomains": false,
            "duration": "PT5M"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "{response}");
    assert_eq!(response["error"]["code"], "control_api.internal");
    let body = response.to_string();
    assert!(!body.contains("not configured"), "{body}");
    assert!(!body.contains("filter engine"), "{body}");
}

/// Cluster CL3b: the runtime hook applies all three command kinds directly to
/// the local filter engine and forwards module error codes unchanged.
#[tokio::test]
async fn cluster_runtime_commands_reach_the_filter_engine() {
    let h = harness().await;
    let set = default_set();
    let version_before = h.service.current().await.unwrap().0;
    let audits_before = h.db.audit_list(20, 0).await.unwrap().len();

    h.state
        .apply_runtime_command(
            "pause",
            &json!({ "filter_set_id": "default", "duration": "PT15M" }),
        )
        .await
        .unwrap();
    assert_eq!(h.filter.paused_until(&set), Some(at(NOW + 900)));

    h.state
        .apply_runtime_command("resume", &json!({ "filter_set_id": "default" }))
        .await
        .unwrap();
    assert_eq!(h.filter.paused_until(&set), None);

    // The broadcast carries the master's absolute deadline.
    h.state
        .apply_runtime_command(
            "temporary_allow",
            &json!({
                "filter_set_id": "default",
                "domain": "ads.example.com",
                "include_subdomains": true,
                "expires_at": rfc3339(NOW + 900),
            }),
        )
        .await
        .unwrap();
    assert!(matches!(
        verify(&h.filter, "ads.example.com", NOW),
        Verdict::Allowed(_)
    ));
    assert!(matches!(
        verify(&h.filter, "child.ads.example.com", NOW),
        Verdict::Allowed(_)
    ));
    assert_eq!(
        h.filter.list_temporary_allows(&set, at(NOW)).unwrap().len(),
        1
    );

    // Invalid payloads come back with the module's own code, not a new one.
    let err = h
        .state
        .apply_runtime_command(
            "pause",
            &json!({ "filter_set_id": "default", "duration": "PT2M" }),
        )
        .await
        .unwrap_err();
    assert_eq!(err.code(), "mcp.invalid_input");

    let err = h
        .state
        .apply_runtime_command(
            "temporary_allow",
            &json!({
                "filter_set_id": "missing",
                "domain": "ads.example.com",
                "expires_at": rfc3339(NOW + 300),
            }),
        )
        .await
        .unwrap_err();
    assert_eq!(err.code(), "policy.config.unknown_filter_set");

    let err = h
        .state
        .apply_runtime_command(
            "pause",
            &json!({ "filter_set_id": "default", "duration": "PT1H", "expires_at": rfc3339(NOW + 2 * 3600) }),
        )
        .await
        .unwrap_err();
    assert_eq!(err.code(), "mcp.invalid_input");

    // Volatile: no config version and no audit entry.
    assert_eq!(h.service.current().await.unwrap().0, version_before);
    assert_eq!(h.db.audit_list(20, 0).await.unwrap().len(), audits_before);
}

/// GM7: `kind=pauses` lists only an active pause.
#[tokio::test]
async fn list_mcp_pauses_omit_an_expired_pause() {
    let h = harness().await;
    h.filter
        .set_paused_until(&default_set(), Some(at(NOW + 300)))
        .unwrap();
    let uri = "/api/v1/filtering/mcp-rules?kind=pauses";
    let (status, response) = send(&h.state, &h.admin, "GET", uri, None).await;
    assert_eq!(status, StatusCode::OK, "{response}");
    assert_eq!(response["data"]["pauses"].as_array().map(Vec::len), Some(1));

    h.clock.advance(Duration::from_secs(301));
    let (status, response) = send(&h.state, &h.admin, "GET", uri, None).await;
    assert_eq!(status, StatusCode::OK, "{response}");
    assert_eq!(response["data"]["pauses"].as_array().map(Vec::len), Some(0));
}

/// GM5: a blocked explanation names the block mode of the set.
#[tokio::test]
async fn explain_block_reports_the_block_mode() {
    let h = harness().await;
    let (status, response) = send(
        &h.state,
        &h.admin,
        "POST",
        "/api/v1/filtering/explain-block",
        Some(json!({ "domain": "ads.example.com", "qtype": "A" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{response}");
    assert_eq!(response["data"]["verdict"], "blocked", "{response}");
    let mode = response["data"]["reason"]["block_mode"]
        .as_str()
        .unwrap_or_default();
    assert!(
        ["refused", "nxdomain", "null_ip", "custom_ip"].contains(&mode),
        "block_mode must name the set's mode: {response}"
    );
}

/// GM15: the temporary-allow reason reaches the audit row, sanitized.
#[tokio::test]
async fn temporary_allow_keeps_its_reason_in_the_audit() {
    let h = harness().await;
    let (status, response) = send(
        &h.state,
        &h.admin,
        "POST",
        "/api/v1/filtering/temporary-allows",
        Some(json!({
            "domain": "example.org",
            "include_subdomains": true,
            "duration": "PT5M",
            "reason": "ticket\n42"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{response}");
    let audits = h.db.audit_list(20, 0).await.unwrap();
    let allow = audits
        .iter()
        .find(|record| record.action == "mcp.allow_temporarily")
        .expect("allow audit entry");
    let after: Value = serde_json::from_str(allow.after.as_deref().unwrap()).unwrap();
    let reason = after["reason"].as_str().unwrap();
    assert_eq!(reason, "ticket\u{FFFD}42");
}

/// GM10: with MCP disabled, `/mcp/v1` is a plain 404 even without credentials.
#[tokio::test]
async fn disabled_mcp_endpoint_is_not_found_before_authentication() {
    let h = harness().await;
    let request = Request::builder()
        .method("POST")
        .uri("/mcp/v1")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from("{}"))
        .unwrap();
    let router = h
        .state
        .clone()
        .router()
        .layer(MockConnectInfo(SocketAddr::from(([127, 0, 0, 1], 40_000))));
    let res = router.oneshot(request).await.unwrap();
    assert_eq!(res.status(), StatusCode::NOT_FOUND);
    let bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .unwrap();
    let body: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(body["error"]["code"], "control_api.not_found", "{body}");
}
