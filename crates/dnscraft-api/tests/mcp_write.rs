//! M24: the write side of [`McpBackend`] over real stores and engines.
//!
//! Every mutation goes through the same config apply lock as the REST
//! endpoints, the protected list and the per-set cap are evaluated inside that
//! lock, and the MCP layer's `record_audit` is the only audit writer. The
//! scripted MCP client at the end proves the gate/scope matrix and the
//! `mcp.audit_failed` contract against the real transport.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;
use std::time::Duration;

use serde_json::{Value, json};

use dnscraft_api::{
    Audit, AuditRecord, Clock as ApiClock, ConfigActor, ConfigService, ConfigStore, Db,
    ModuleAppliers, Scope, TokenStore, mcp_backend_for_test_writes,
};
use dnscraft_filtering::{Clock as FilterClock, DomainName, FilterEngine, SetId, Verdict};
use dnscraft_mcp::dto::{
    AddRuleParams, AuditEntry, AuditResult, PauseDuration, PauseParams, RemoveRuleParams,
    TempAllowParams, TokenScope,
};
use dnscraft_mcp::{BackendError, McpBackend, McpConfig};

mod support;
use support::{
    BridgeClock, DAY, FilterApplier, NOW, TempDir, at, build_engine, mcp_router, mcp_tool, rfc3339,
    seed_config, snapshot, tool_error_code, tool_is_error, tool_output,
};

const MAX_TTL: Duration = Duration::from_secs(365 * 24 * 3600);

struct Harness {
    backend: Arc<dyn McpBackend>,
    engine: Arc<FilterEngine>,
    service: Arc<ConfigService>,
    tokens: TokenStore,
    db: Db,
    clock: Arc<BridgeClock>,
    _temp: TempDir,
}

async fn harness_with(
    mcp: McpConfig,
    public_domain: Option<&str>,
    seed_rules: Option<Value>,
    with_audit: bool,
) -> Harness {
    let temp = TempDir::new("write");
    let clock = BridgeClock::new(at(NOW));
    let db = Db::open_in_memory(Arc::clone(&clock) as Arc<dyn ApiClock>)
        .await
        .expect("open database");
    let audit = with_audit.then(|| Arc::new(Audit::new(db.clone())));
    let filter_clock: Arc<dyn FilterClock> = clock.clone();
    let engine = build_engine(&temp, seed_config(), filter_clock);
    let service = Arc::new(ConfigService::new(
        ConfigStore::new(db.clone()),
        Audit::new(db.clone()),
        ModuleAppliers {
            filtering: Some(FilterApplier::new(Arc::clone(&engine))),
            ..ModuleAppliers::default()
        },
        "node-a",
    ));
    let mut seed = snapshot(public_domain, "||ads.example.com^");
    if let Some(rules) = seed_rules {
        seed["filtering"]["sets"][0]["mcp_rules"] = rules;
    }
    service
        .mutate(
            &ConfigActor::new("seed", "system"),
            "test.seed",
            move |value| {
                *value = seed;
                Ok(true)
            },
        )
        .await
        .expect("seed config");
    let tokens = TokenStore::new(db.clone(), MAX_TTL);
    let backend = mcp_backend_for_test_writes(
        Arc::clone(&engine),
        Arc::clone(&service),
        audit,
        Some(tokens.clone()),
        Arc::clone(&clock) as Arc<dyn ApiClock>,
        mcp,
        None,
    );
    Harness {
        backend,
        engine,
        service,
        tokens,
        db,
        clock,
        _temp: temp,
    }
}

async fn harness() -> Harness {
    harness_with(McpConfig::default(), None, None, true).await
}

fn default_set() -> SetId {
    SetId::new("default").expect("default set")
}

fn verdict(engine: &FilterEngine, name: &str, second: u64) -> Verdict {
    engine
        .match_name(
            &default_set(),
            &DomainName::parse(name).expect("valid domain"),
            1,
            at(second),
        )
        .expect("match")
}

fn blocked(engine: &FilterEngine, name: &str, second: u64) -> bool {
    matches!(verdict(engine, name, second), Verdict::Blocked(_))
}

fn passed(engine: &FilterEngine, name: &str, second: u64) -> bool {
    matches!(verdict(engine, name, second), Verdict::Pass)
}

async fn current_rules(h: &Harness) -> Vec<Value> {
    let (_, snapshot) = h.service.current().await.expect("current config");
    snapshot.expect("stored snapshot")["filtering"]["sets"][0]["mcp_rules"]
        .as_array()
        .cloned()
        .unwrap_or_default()
}

async fn current_version(h: &Harness) -> i64 {
    h.service
        .current()
        .await
        .expect("current config")
        .0
        .expect("stored version")
}

async fn audits(h: &Harness) -> Vec<AuditRecord> {
    h.db.audit_list(100, 0).await.expect("audit rows")
}

fn stored_rule(domain: &str, include_subdomains: bool, expires_at: u64) -> Value {
    json!({
        "id": format!("seed-{}", domain.replace('.', "-")),
        "domain": domain,
        "include_subdomains": include_subdomains,
        "created_at": NOW - 60,
        "expires_at": expires_at,
        "token_id": "seed",
    })
}

fn rule_set(entries: Vec<Value>) -> Value {
    Value::Array(entries)
}

fn add_params(domain: &str, include_subdomains: bool, lifetime_seconds: u64) -> AddRuleParams {
    AddRuleParams {
        domain: domain.to_owned(),
        include_subdomains,
        filter_set_id: None,
        lifetime_seconds,
    }
}

fn code(err: BackendError) -> String {
    err.code().to_owned()
}

// ---------------------------------------------------------------------------
// Token identity
// ---------------------------------------------------------------------------

#[tokio::test]
async fn validate_token_returns_identity_scopes_and_rejects_non_mcp_tokens() {
    let h = harness().await;
    let write = h
        .tokens
        .create(
            "actor-w".to_owned(),
            "write".to_owned(),
            Scope::McpWrite,
            None,
        )
        .await
        .expect("write token");
    let read = h
        .tokens
        .create(
            "actor-r".to_owned(),
            "read".to_owned(),
            Scope::McpRead,
            None,
        )
        .await
        .expect("read token");

    let info = h
        .backend
        .validate_token(write.plaintext().expose())
        .await
        .expect("write token validates");
    assert_eq!(info.token_id, write.id());
    assert_eq!(info.actor_id, "actor-w");
    assert_eq!(info.scope, TokenScope::McpWrite);

    let info = h
        .backend
        .validate_token(read.plaintext().expose())
        .await
        .expect("read token validates");
    assert_eq!(info.scope, TokenScope::McpRead);

    let admin = h
        .tokens
        .create("actor-a".to_owned(), "admin".to_owned(), Scope::Admin, None)
        .await
        .expect("admin token");
    assert_eq!(
        code(
            h.backend
                .validate_token(admin.plaintext().expose())
                .await
                .expect_err("admin token is not an MCP token")
        ),
        "control_api.auth.invalid_scope"
    );

    assert_eq!(
        code(
            h.backend
                .validate_token("unknown-token")
                .await
                .expect_err("unknown token")
        ),
        "control_api.auth.unauthenticated"
    );

    h.tokens.revoke(write.id()).await.expect("revoke");
    assert_eq!(
        code(
            h.backend
                .validate_token(write.plaintext().expose())
                .await
                .expect_err("revoked token")
        ),
        "control_api.auth.unauthenticated"
    );

    let expiring = h
        .tokens
        .create(
            "actor-e".to_owned(),
            "expiring".to_owned(),
            Scope::McpRead,
            Some(Duration::from_secs(60)),
        )
        .await
        .expect("expiring token");
    h.clock.advance(Duration::from_secs(61));
    assert_eq!(
        code(
            h.backend
                .validate_token(expiring.plaintext().expose())
                .await
                .expect_err("expired token")
        ),
        "control_api.auth.unauthenticated"
    );
}

// ---------------------------------------------------------------------------
// allow_temporarily
// ---------------------------------------------------------------------------

#[tokio::test]
async fn allow_temporarily_beats_a_block_and_expires_exactly() {
    let h = harness().await;
    assert!(blocked(&h.engine, "ads.example.com", NOW + 1));
    assert!(blocked(&h.engine, "sub.ads.example.com", NOW + 1));
    let version = current_version(&h).await;

    let result = h
        .backend
        .allow_temporarily(TempAllowParams {
            domain: "Ads.Example.COM.".to_owned(),
            include_subdomains: true,
            duration: PauseDuration::Pt5M,
            filter_set_id: None,
            reason: "legitimate site".to_owned(),
        })
        .await
        .expect("allow");
    assert_eq!(result.created_at, rfc3339(NOW));
    assert_eq!(result.expires_at, rfc3339(NOW + 300));
    assert_eq!(result.filter_set_id, "default");

    assert!(matches!(
        verdict(&h.engine, "ads.example.com", NOW + 1),
        Verdict::Allowed(_)
    ));
    assert!(matches!(
        verdict(&h.engine, "sub.ads.example.com", NOW + 1),
        Verdict::Allowed(_)
    ));
    assert!(
        blocked(&h.engine, "ads.example.com", NOW + 300),
        "the allow stops at the exact expiry"
    );
    assert_eq!(
        current_version(&h).await,
        version,
        "runtime state creates no config version"
    );
}

#[tokio::test]
async fn allow_temporarily_validates_duration_scope_and_target() {
    let h = harness_with(
        McpConfig {
            max_temporary_allow_duration: Duration::from_secs(300),
            protected_domains: vec!["extra.example.org".to_owned()],
            ..McpConfig::default()
        },
        Some("dns.example.net"),
        None,
        true,
    )
    .await;

    let too_long = h
        .backend
        .allow_temporarily(TempAllowParams {
            domain: "ok.example.com".to_owned(),
            include_subdomains: false,
            duration: PauseDuration::Pt15M,
            filter_set_id: None,
            reason: String::new(),
        })
        .await
        .expect_err("duration above the max");
    assert_eq!(too_long.code(), "mcp.duration_exceeds_maximum");

    for domain in ["example.net", "dns.example.net", "a.dns.example.net"] {
        let err = h
            .backend
            .allow_temporarily(TempAllowParams {
                domain: domain.to_owned(),
                include_subdomains: true,
                duration: PauseDuration::Pt5M,
                filter_set_id: None,
                reason: String::new(),
            })
            .await
            .expect_err("protected");
        assert_eq!(err.code(), "mcp.protected_domain", "{domain}");
    }
    assert_eq!(
        h.backend
            .allow_temporarily(TempAllowParams {
                domain: "extra.example.org".to_owned(),
                include_subdomains: false,
                duration: PauseDuration::Pt5M,
                filter_set_id: None,
                reason: String::new(),
            })
            .await
            .expect_err("owner-protected")
            .code(),
        "mcp.protected_domain"
    );

    assert_eq!(
        h.backend
            .allow_temporarily(TempAllowParams {
                domain: "com".to_owned(),
                include_subdomains: true,
                duration: PauseDuration::Pt5M,
                filter_set_id: None,
                reason: String::new(),
            })
            .await
            .expect_err("too broad")
            .code(),
        "mcp.domain_too_broad"
    );
    assert_eq!(
        h.backend
            .allow_temporarily(TempAllowParams {
                domain: "*.example.com".to_owned(),
                include_subdomains: true,
                duration: PauseDuration::Pt5M,
                filter_set_id: None,
                reason: String::new(),
            })
            .await
            .expect_err("pattern")
            .code(),
        "filter_build.pattern_not_allowed"
    );
    assert_eq!(
        h.backend
            .allow_temporarily(TempAllowParams {
                domain: "ok.example.com".to_owned(),
                include_subdomains: false,
                duration: PauseDuration::Pt5M,
                filter_set_id: Some("missing".to_owned()),
                reason: String::new(),
            })
            .await
            .expect_err("unknown set")
            .code(),
        "policy.config.unknown_filter_set"
    );
}

// ---------------------------------------------------------------------------
// add_custom_rule / find_mcp_rule / remove_custom_rule
// ---------------------------------------------------------------------------

#[tokio::test]
async fn add_custom_rule_stores_structured_rule_and_a_config_version() {
    let h = harness().await;
    let result = h
        .backend
        .add_custom_rule(add_params("Track.Example.COM.", true, 3600))
        .await
        .expect("add rule");
    assert_eq!(result.rule_text, "||track.example.com^");
    assert_eq!(result.filter_set_id, "default");
    assert_eq!(result.created_at, rfc3339(NOW));
    assert_eq!(result.expires_at, rfc3339(NOW + 3600));
    assert_eq!(result.config_version, Some(2));

    let stored = current_rules(&h).await;
    assert_eq!(stored.len(), 1);
    assert_eq!(stored[0]["id"], result.rule_id);
    assert_eq!(stored[0]["domain"], "track.example.com");
    assert_eq!(stored[0]["include_subdomains"], true);
    assert_eq!(stored[0]["created_at"], NOW);
    assert_eq!(stored[0]["expires_at"], NOW + 3600);
    assert_eq!(
        stored[0]["token_id"], "",
        "the DTO carries no token id (reported gap)"
    );
    assert!(blocked(&h.engine, "track.example.com", NOW + 1));
    assert!(blocked(&h.engine, "a.track.example.com", NOW + 1));
    assert!(
        !blocked(&h.engine, "track.example.com", NOW + 3600),
        "the rule stops at the exact expiry"
    );

    let find = h
        .backend
        .find_mcp_rule("track.example.com", None)
        .await
        .expect("find")
        .expect("stored");
    assert_eq!(find.id, result.rule_id);
    assert_eq!(find.domain, "track.example.com");
    assert!(find.include_subdomains);
    assert_eq!(find.rule_text, "||track.example.com^");
    assert_eq!(find.filter_set_id, "default");
    assert_eq!(
        h.backend
            .find_mcp_rule("other.example.com", None)
            .await
            .expect("find missing"),
        None
    );
    assert_eq!(
        h.backend
            .find_mcp_rule("not a domain", None)
            .await
            .expect_err("invalid domain")
            .code(),
        "filter_name.invalid_char"
    );

    let removed = h
        .backend
        .remove_custom_rule(RemoveRuleParams {
            domain: "track.example.com".to_owned(),
            filter_set_id: None,
        })
        .await
        .expect("remove");
    assert!(removed.removed);
    assert_eq!(removed.config_version, Some(3));
    assert!(current_rules(&h).await.is_empty());
    assert!(passed(&h.engine, "track.example.com", NOW + 1));

    let again = h
        .backend
        .remove_custom_rule(RemoveRuleParams {
            domain: "track.example.com".to_owned(),
            filter_set_id: None,
        })
        .await
        .expect("remove missing");
    assert!(!again.removed);
    assert_eq!(again.config_version, None);
    assert_eq!(
        current_version(&h).await,
        3,
        "a no-op remove stores no version"
    );
}

#[tokio::test]
async fn add_custom_rule_rejects_protected_lifetime_unknown_set_and_cap() {
    let h = harness_with(
        McpConfig {
            max_custom_rules_per_set: 10,
            ..McpConfig::default()
        },
        Some("dns.example.net"),
        Some(rule_set(
            (0..10)
                .map(|i| stored_rule(&format!("r{i}.example.com"), false, NOW + DAY))
                .collect(),
        )),
        true,
    )
    .await;
    let version = current_version(&h).await;
    let audit_count = audits(&h).await.len();

    for domain in ["example.net", "dns.example.net"] {
        let err = h
            .backend
            .add_custom_rule(add_params(domain, true, 3600))
            .await
            .expect_err("protected");
        assert_eq!(err.code(), "mcp.protected_domain", "{domain}");
    }
    let err = h
        .backend
        .add_custom_rule(add_params("free.example.com", true, 3600))
        .await
        .expect_err("cap");
    assert_eq!(err.code(), "mcp.rule_limit_exceeded");
    assert_eq!(
        err.params().as_ref().and_then(|p| p.get("max")),
        Some(&json!(10))
    );

    for lifetime in [0, 30 * DAY + 1] {
        assert_eq!(
            h.backend
                .add_custom_rule(add_params("free.example.com", true, lifetime))
                .await
                .expect_err("lifetime")
                .code(),
            "mcp.duration_exceeds_maximum",
            "{lifetime}"
        );
    }
    assert_eq!(
        h.backend
            .add_custom_rule(AddRuleParams {
                domain: "free.example.com".to_owned(),
                include_subdomains: true,
                filter_set_id: Some("missing".to_owned()),
                lifetime_seconds: 3600,
            })
            .await
            .expect_err("unknown set")
            .code(),
        "policy.config.unknown_filter_set"
    );

    assert_eq!(
        current_version(&h).await,
        version,
        "no rejected add versions"
    );
    assert_eq!(
        audits(&h).await.len(),
        audit_count,
        "the backend never audits a mutation itself"
    );

    // Expired rules do not count toward the cap.
    let expired = harness_with(
        McpConfig {
            max_custom_rules_per_set: 10,
            ..McpConfig::default()
        },
        None,
        Some(rule_set(
            (0..10)
                .map(|i| stored_rule(&format!("r{i}.example.com"), false, NOW))
                .collect(),
        )),
        true,
    )
    .await;
    let added = expired
        .backend
        .add_custom_rule(add_params("free.example.com", true, 3600))
        .await
        .expect("expired rules free the cap");
    assert_eq!(added.config_version, Some(2));
}

#[tokio::test]
async fn remove_custom_rule_uses_the_stored_include_flag_for_protection() {
    let included = harness_with(
        McpConfig {
            protected_domains: vec!["sub.example.net".to_owned()],
            ..McpConfig::default()
        },
        None,
        Some(rule_set(vec![stored_rule("example.net", true, NOW + DAY)])),
        true,
    )
    .await;
    let err = included
        .backend
        .remove_custom_rule(RemoveRuleParams {
            domain: "example.net".to_owned(),
            filter_set_id: None,
        })
        .await
        .expect_err("covering rule is protected");
    assert_eq!(err.code(), "mcp.protected_domain");
    assert_eq!(current_rules(&included).await.len(), 1);

    let exact = harness_with(
        McpConfig {
            protected_domains: vec!["sub.example.net".to_owned()],
            ..McpConfig::default()
        },
        None,
        Some(rule_set(vec![stored_rule("example.net", false, NOW + DAY)])),
        true,
    )
    .await;
    let removed = exact
        .backend
        .remove_custom_rule(RemoveRuleParams {
            domain: "example.net".to_owned(),
            filter_set_id: None,
        })
        .await
        .expect("exact rule does not cover the protected subdomain");
    assert!(removed.removed);
    assert!(current_rules(&exact).await.is_empty());
}

#[tokio::test]
async fn find_and_remove_still_see_expired_rules() {
    let h = harness().await;
    h.backend
        .add_custom_rule(add_params("old.example.com", false, 60))
        .await
        .expect("add short rule");
    h.clock.advance(Duration::from_secs(61));
    assert!(!blocked(&h.engine, "old.example.com", NOW + 61));

    let found = h
        .backend
        .find_mcp_rule("old.example.com", None)
        .await
        .expect("find")
        .expect("expired rules are still stored");
    assert!(!found.include_subdomains);
    let removed = h
        .backend
        .remove_custom_rule(RemoveRuleParams {
            domain: "old.example.com".to_owned(),
            filter_set_id: None,
        })
        .await
        .expect("remove");
    assert!(removed.removed);
    assert_eq!(removed.config_version, Some(3));
    assert!(current_rules(&h).await.is_empty());
}

// ---------------------------------------------------------------------------
// pause / resume
// ---------------------------------------------------------------------------

#[tokio::test]
async fn pause_and_resume_change_runtime_state_only() {
    let h = harness().await;
    let version = current_version(&h).await;

    let paused = h
        .backend
        .pause_filter_set(PauseParams {
            filter_set_id: None,
            duration: PauseDuration::Pt15M,
        })
        .await
        .expect("pause");
    assert_eq!(paused.filter_set_id, "default");
    assert_eq!(paused.paused_until, rfc3339(NOW + 900));
    assert!(passed(&h.engine, "ads.example.com", NOW + 1));
    assert!(
        blocked(&h.engine, "ads.example.com", NOW + 900),
        "the pause stops at the exact expiry"
    );

    let resumed = h.backend.resume_filter_set(None).await.expect("resume");
    assert!(resumed.resumed);
    assert_eq!(resumed.was_paused_until, Some(rfc3339(NOW + 900)));
    assert!(blocked(&h.engine, "ads.example.com", NOW + 1));

    let again = h
        .backend
        .resume_filter_set(None)
        .await
        .expect("resume un-paused");
    assert!(!again.resumed);
    assert_eq!(again.was_paused_until, None);
    assert_eq!(current_version(&h).await, version);
}

#[tokio::test]
async fn pause_rejects_duration_above_the_configured_maximum_and_unknown_sets() {
    let h = harness_with(
        McpConfig {
            max_pause_duration: Duration::from_secs(300),
            ..McpConfig::default()
        },
        None,
        None,
        true,
    )
    .await;
    assert_eq!(
        h.backend
            .pause_filter_set(PauseParams {
                filter_set_id: None,
                duration: PauseDuration::Pt15M,
            })
            .await
            .expect_err("too long")
            .code(),
        "mcp.duration_exceeds_maximum"
    );
    assert_eq!(
        h.backend
            .pause_filter_set(PauseParams {
                filter_set_id: Some("missing".to_owned()),
                duration: PauseDuration::Pt5M,
            })
            .await
            .expect_err("unknown set")
            .code(),
        "policy.config.unknown_filter_set"
    );
    assert_eq!(
        h.backend
            .resume_filter_set(Some("missing"))
            .await
            .expect_err("unknown set")
            .code(),
        "policy.config.unknown_filter_set"
    );
}

// ---------------------------------------------------------------------------
// Audit
// ---------------------------------------------------------------------------

#[tokio::test]
async fn exactly_one_audit_row_per_committed_mutation() {
    let h = harness().await;
    let baseline = audits(&h).await.len();
    assert_eq!(
        audits(&h)
            .await
            .iter()
            .filter(|record| record.action == "test.seed")
            .count(),
        1,
        "the test seed is the only pre-existing row"
    );

    let added = h
        .backend
        .add_custom_rule(add_params("audited.example.com", true, 3600))
        .await
        .expect("add");
    assert_eq!(
        audits(&h).await.len(),
        baseline,
        "the backend mutation itself writes no audit row"
    );
    h.backend
        .record_audit(AuditEntry {
            action: "mcp.add_rule".to_owned(),
            actor_id: "tok-1".to_owned(),
            before: None,
            after: json!({
                "domain": "audited.example.com",
                "config_version": added.config_version,
            }),
            result: AuditResult::Success,
            error_code: None,
        })
        .await
        .expect("record");
    assert_eq!(audits(&h).await.len(), baseline + 1);

    h.backend
        .remove_custom_rule(RemoveRuleParams {
            domain: "audited.example.com".to_owned(),
            filter_set_id: None,
        })
        .await
        .expect("remove");
    h.backend
        .record_audit(AuditEntry {
            action: "mcp.remove_rule".to_owned(),
            actor_id: "tok-1".to_owned(),
            before: Some(json!({ "domain": "audited.example.com" })),
            after: json!({ "removed": true, "config_version": 3 }),
            result: AuditResult::Success,
            error_code: None,
        })
        .await
        .expect("record");

    let rows = audits(&h).await;
    assert_eq!(rows.len(), baseline + 2);
    assert_eq!(
        rows.iter()
            .filter(|record| record.action == "mcp.add_rule")
            .count(),
        1
    );
    assert_eq!(
        rows.iter()
            .filter(|record| record.action == "mcp.remove_rule")
            .count(),
        1
    );
    let add = rows
        .iter()
        .find(|record| record.action == "mcp.add_rule")
        .expect("add audit");
    assert_eq!(add.actor_type, "token");
    assert_eq!(add.actor_id, "tok-1");
    assert_eq!(add.result, "success");
    assert_eq!(add.config_version, Some(2));
    let remove = rows
        .iter()
        .find(|record| record.action == "mcp.remove_rule")
        .expect("remove audit");
    assert_eq!(remove.config_version, Some(3));
}

#[tokio::test]
async fn record_audit_redacts_secrets_and_preserves_error_context() {
    let h = harness().await;
    h.backend
        .record_audit(AuditEntry {
            action: "mcp.add_rule".to_owned(),
            actor_id: "tok-2".to_owned(),
            before: Some(json!({ "domain": "x.example.com" })),
            after: json!({
                "domain": "x.example.com",
                "config_version": 9,
                "api_key": "super-secret",
                "authorization": "Bearer abc",
                "note": "Basic Zm9v",
            }),
            result: AuditResult::Error,
            error_code: Some("mcp.protected_domain".to_owned()),
        })
        .await
        .expect("record");

    let row = audits(&h)
        .await
        .into_iter()
        .find(|record| record.action == "mcp.add_rule")
        .expect("audit row");
    assert_eq!(row.actor_type, "token");
    assert_eq!(row.result, "error");
    assert_eq!(row.error_code.as_deref(), Some("mcp.protected_domain"));
    assert_eq!(row.config_version, Some(9));
    let after: Value = serde_json::from_str(row.after.as_deref().expect("after")).expect("json");
    assert_eq!(after["domain"], "x.example.com");
    assert_eq!(after["api_key"], "redacted");
    assert_eq!(after["authorization"], "redacted");
    assert_eq!(after["note"], "redacted");
    let before: Value = serde_json::from_str(row.before.as_deref().expect("before")).expect("json");
    assert_eq!(before["domain"], "x.example.com");
}

#[tokio::test]
async fn record_audit_reports_an_unavailable_log() {
    let h = harness_with(McpConfig::default(), None, None, false).await;
    let err = h
        .backend
        .record_audit(AuditEntry {
            action: "mcp.add_rule".to_owned(),
            actor_id: "tok".to_owned(),
            before: None,
            after: json!({}),
            result: AuditResult::Success,
            error_code: None,
        })
        .await
        .expect_err("no audit log");
    assert_eq!(err.code(), "control_api.internal");
}

// ---------------------------------------------------------------------------
// MCP transport: gate, scope, and the audit-failure contract
// ---------------------------------------------------------------------------

async fn write_token(h: &Harness) -> String {
    h.tokens
        .create(
            "actor-w".to_owned(),
            "write".to_owned(),
            Scope::McpWrite,
            None,
        )
        .await
        .expect("write token")
        .plaintext()
        .expose()
        .to_owned()
}

#[tokio::test]
async fn mcp_write_tool_runs_the_backend_and_writes_one_audit_row() {
    let h = harness().await;
    let token = write_token(&h).await;
    let config = McpConfig {
        enabled: true,
        write_tools_enabled: true,
        ..McpConfig::default()
    };
    let router = mcp_router(h.backend.clone(), config);

    let (status, body) = mcp_tool(
        &router,
        &token,
        "add_rule",
        json!({ "domain": "mcp.example.com", "include_subdomains": true }),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert!(!tool_is_error(&body), "{body}");
    let output = tool_output(&body);
    assert_eq!(output["domain"], "mcp.example.com");
    assert_eq!(output["rule_text"], "||mcp.example.com^");

    assert_eq!(current_version(&h).await, 2);
    let stored = current_rules(&h).await;
    assert_eq!(stored.len(), 1);
    assert_eq!(stored[0]["domain"], "mcp.example.com");
    assert_eq!(stored[0]["expires_at"], NOW + 30 * DAY);

    let rows = audits(&h).await;
    let add: Vec<_> = rows
        .iter()
        .filter(|record| record.action == "mcp.add_rule")
        .collect();
    assert_eq!(add.len(), 1);
    assert_eq!(add[0].actor_type, "token");
    assert_eq!(add[0].config_version, Some(2));
    assert_eq!(add[0].result, "success");
}

#[tokio::test]
async fn mcp_write_gate_and_scope_matrix() {
    let h = harness().await;
    let write = write_token(&h).await;
    let read_token = h
        .tokens
        .create(
            "actor-r".to_owned(),
            "read".to_owned(),
            Scope::McpRead,
            None,
        )
        .await
        .expect("read token");
    let read = read_token.plaintext().expose().to_owned();
    let enabled = mcp_router(
        h.backend.clone(),
        McpConfig {
            enabled: true,
            write_tools_enabled: true,
            ..McpConfig::default()
        },
    );
    let disabled = mcp_router(
        h.backend.clone(),
        McpConfig {
            enabled: true,
            write_tools_enabled: false,
            ..McpConfig::default()
        },
    );

    let args = json!({ "domain": "gated.example.com" });

    let (status, body) = mcp_tool(&enabled, &read, "add_rule", args.clone()).await;
    assert_eq!(status, 200);
    assert_eq!(
        tool_error_code(&body),
        "control_api.auth.insufficient_scope",
        "{body}"
    );

    let (status, body) = mcp_tool(&disabled, &write, "add_rule", args.clone()).await;
    assert_eq!(status, 200);
    assert_eq!(tool_error_code(&body), "mcp.write_tools_disabled");
    assert!(tool_is_error(&body));

    let (status, body) = mcp_tool(&disabled, "", "add_rule", args.clone()).await;
    assert_eq!(status, 401);
    assert_eq!(body["error"]["code"], "control_api.auth.unauthenticated");

    let admin = h
        .tokens
        .create("actor-a".to_owned(), "admin".to_owned(), Scope::Admin, None)
        .await
        .expect("admin token");
    let (status, body) = mcp_tool(
        &enabled,
        admin.plaintext().expose(),
        "add_rule",
        args.clone(),
    )
    .await;
    assert_eq!(status, 403);
    assert_eq!(body["error"]["code"], "control_api.auth.invalid_scope");

    h.tokens
        .revoke(read_token.id())
        .await
        .expect("revoke read token");
    let (status, _body) = mcp_tool(&enabled, &read, "add_rule", args.clone()).await;
    assert_eq!(status, 401);

    assert_eq!(
        current_version(&h).await,
        1,
        "no rejected call stored a version"
    );
    assert!(current_rules(&h).await.is_empty());
}

#[tokio::test]
async fn audit_failure_after_a_committed_mutation_surfaces_as_mcp_audit_failed() {
    let h = harness_with(McpConfig::default(), None, None, false).await;
    let token = write_token(&h).await;
    let router = mcp_router(
        h.backend.clone(),
        McpConfig {
            enabled: true,
            write_tools_enabled: true,
            ..McpConfig::default()
        },
    );

    let (status, body) = mcp_tool(
        &router,
        &token,
        "add_rule",
        json!({ "domain": "unrecorded.example.com" }),
    )
    .await;
    assert_eq!(status, 200);
    assert!(tool_is_error(&body), "{body}");
    assert_eq!(tool_error_code(&body), "mcp.audit_failed");

    assert_eq!(
        current_version(&h).await,
        2,
        "the rule was committed before the audit write failed"
    );
    assert_eq!(current_rules(&h).await.len(), 1);
    assert!(blocked(&h.engine, "unrecorded.example.com", NOW + 1));
}
