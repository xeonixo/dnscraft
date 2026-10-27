//! M25: end-to-end flows through the real control-api listener.
//!
//! Every flow drives a scripted MCP client over HTTP against the real router,
//! with a real filtering engine, a real policy engine over the testkit DNS
//! hierarchy, an in-memory SQLite store and one advanceable clock shared by the
//! control API and the filtering engine.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Duration;

use axum::http::StatusCode;
use serde_json::{Value, json};

use dnscraft_api::{
    AppState, Audit, AuthState, Clock as ApiClock, ConfigActor, ConfigService, ConfigStore,
    CreatedToken, Db, ModuleAppliers, QueryLog, QueryLogConfig, QueryLogFilter, Scope,
    SessionStore, TokenStore, derive_protected_domains, mcp_backend_for_test_writes,
};
use dnscraft_filtering::{Clock as FilterClock, DomainName, FilterEngine, SetId, Verdict};
use dnscraft_listeners::QueryEvent;
use dnscraft_mcp::{McpBackend, McpConfig};
use dnscraft_policy::{
    AnswerOrigin, DecisionRecord, DecisionStep, DecisionTimings, DnsProtocol, ListenerId,
    NoClients, PolicyConfig, PolicyEngine, ProfileConfig, ProfileId, RequestContext,
    SelectionCause, ViewConfig, ViewId,
};
use dnscraft_proto::{Class, Name, Rcode, RecordType};
use dnscraft_resolver::dnssec::TrustAnchors;
use dnscraft_resolver::{AnswerSource, DnssecStatus, Query, Resolver, ResolverConfig};
use dnscraft_testkit::Hierarchy;

mod support;
use support::{
    BridgeClock, DAY, FilterApplier, NOW, TempDir, TestServer, at, build_engine,
    filter_config_from_json, mcp_http, rfc3339, snapshot, tool_error_code, tool_is_error,
    tool_output,
};

const IDLE: Duration = Duration::from_secs(60 * 60);
const ABSOLUTE: Duration = Duration::from_secs(12 * 3600);
const MAX_TTL: Duration = Duration::from_secs(365 * 24 * 3600);
/// `McpConfig::default().max_block_rule_lifetime`.
const RULE_LIFETIME: u64 = 30 * DAY;

fn gate_on() -> McpConfig {
    McpConfig {
        enabled: true,
        write_tools_enabled: true,
        ..McpConfig::default()
    }
}

fn policy_config() -> PolicyConfig {
    let profile = ProfileConfig {
        id: ProfileId::new("default").unwrap(),
        filter_set: SetId::new("default").unwrap(),
        suppress_aaaa: false,
        firefox_canary: false,
        icloud_private_relay: false,
        rebind: None,
        rebind_exceptions: Vec::new(),
        forward_zones: None,
        safesearch: dnscraft_policy::SafeSearchConfig::default(),
        schedules: Vec::new(),
    };
    let view = ViewConfig {
        id: ViewId::new("default").unwrap(),
        is_default: true,
        subnets: Vec::new(),
        client_ids: Vec::new(),
        records: Vec::new(),
        profile: ProfileId::new("default").unwrap(),
    };
    PolicyConfig {
        default_rebind: true,
        ptr_prefixes: Vec::new(),
        local_nxdomain_suffixes: Vec::new(),
        rebind_check_forward_zones: Vec::new(),
        views: vec![view],
        profiles: vec![profile],
    }
}

fn resolver_config(hierarchy: &Hierarchy) -> ResolverConfig {
    let overrides = hierarchy
        .nameserver_addrs()
        .iter()
        .map(|(name, address)| (Name::from_ascii(&name.to_string()).unwrap(), *address))
        .collect::<HashMap<_, _>>();
    ResolverConfig {
        root_hints: hierarchy.root_hints(),
        query_timeout: Duration::from_millis(300),
        nameserver_addr_overrides: overrides,
        trust_anchors: TrustAnchors::empty(),
        prefetch: false,
        ..ResolverConfig::default()
    }
}

fn request_context(domain: &str) -> RequestContext {
    RequestContext {
        source_ip: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
        protocol: DnsProtocol::Udp53,
        listener_id: ListenerId::new("udp-53").unwrap(),
        client_id: None,
        query: Query {
            name: Name::from_ascii(domain).unwrap(),
            qtype: RecordType::A,
            qclass: Class::IN,
        },
        flags: dnscraft_policy::ClientFlags::default(),
        test_query: false,
    }
}

/// `snapshot` with `count` active MCP rules seeded into the default set.
fn snapshot_with_rules(count: usize) -> Value {
    let rules: Vec<Value> = (0..count)
        .map(|index| {
            json!({
                "id": format!("seed-{index}"),
                "domain": format!("blocked{index}.example.test"),
                "include_subdomains": false,
                "created_at": NOW - 60,
                "expires_at": NOW + DAY,
                "token_id": "seed",
            })
        })
        .collect();
    let mut value = snapshot(None, "");
    value["filtering"]["sets"][0]["mcp_rules"] = json!(rules);
    value
}

/// The same snapshot with every `mcp_rules` field removed.
fn without_mcp_rules(value: &Value) -> Value {
    let mut copy = value.clone();
    if let Some(sets) = copy["filtering"]["sets"].as_array_mut() {
        for set in sets {
            if let Some(object) = set.as_object_mut() {
                object.remove("mcp_rules");
            }
        }
    }
    copy
}

/// The same snapshot with every `mcp_rules` field set to an explicit empty list.
fn with_empty_mcp_rules(value: &Value) -> Value {
    let mut copy = value.clone();
    if let Some(sets) = copy["filtering"]["sets"].as_array_mut() {
        for set in sets {
            if let Some(object) = set.as_object_mut() {
                object.insert("mcp_rules".to_owned(), json!([]));
            }
        }
    }
    copy
}

struct Harness {
    server: TestServer,
    client: reqwest::Client,
    backend: Arc<dyn McpBackend>,
    service: Arc<ConfigService>,
    filter: Arc<FilterEngine>,
    policy: Arc<PolicyEngine>,
    resolver: Arc<Resolver>,
    query_log: Arc<QueryLog>,
    clock: Arc<BridgeClock>,
    tokens: TokenStore,
    admin: CreatedToken,
    viewer: CreatedToken,
    write: CreatedToken,
    read: CreatedToken,
    mcp_enabled: bool,
    _hierarchy: Hierarchy,
    _temp: TempDir,
}

impl Harness {
    async fn new(mcp: McpConfig, seed: Value, oidc_issuer: Option<&str>) -> Self {
        let temp = TempDir::new("e2e");
        let clock = BridgeClock::new(at(NOW));
        let filter_config = filter_config_from_json(&seed["filtering"]).expect("seed filtering");
        let filter = build_engine(
            &temp,
            filter_config,
            Arc::clone(&clock) as Arc<dyn FilterClock>,
        );

        let db = Db::open_in_memory(Arc::clone(&clock) as Arc<dyn ApiClock>)
            .await
            .expect("open database");
        let hierarchy = Hierarchy::start().await.expect("start DNS hierarchy");
        let resolver = Arc::new(
            Resolver::new(resolver_config(&hierarchy))
                .await
                .expect("build resolver"),
        );
        let policy = Arc::new(
            PolicyEngine::new(
                policy_config(),
                Arc::clone(&filter),
                Arc::clone(&resolver),
                Arc::new(NoClients),
                Arc::clone(&clock) as Arc<dyn FilterClock>,
            )
            .expect("build policy engine"),
        );
        let query_log = Arc::new(QueryLog::new(
            db.clone(),
            QueryLogConfig::default(),
            "node-a",
        ));
        let tokens = TokenStore::new(db.clone(), MAX_TTL);
        let auth = AuthState::new(
            SessionStore::new(db.clone(), IDLE, ABSOLUTE),
            tokens.clone(),
        );
        let admin = tokens
            .create("admin".to_owned(), "admin".to_owned(), Scope::Admin, None)
            .await
            .expect("admin token");
        let viewer = tokens
            .create(
                "viewer".to_owned(),
                "viewer".to_owned(),
                Scope::Viewer,
                None,
            )
            .await
            .expect("viewer token");
        let write = tokens
            .create(
                "mcp-writer".to_owned(),
                "mcp-writer".to_owned(),
                Scope::McpWrite,
                None,
            )
            .await
            .expect("write token");
        let read = tokens
            .create(
                "mcp-reader".to_owned(),
                "mcp-reader".to_owned(),
                Scope::McpRead,
                None,
            )
            .await
            .expect("read token");

        let service = Arc::new(ConfigService::new(
            ConfigStore::new(db.clone()),
            Audit::new(db.clone()),
            ModuleAppliers {
                filtering: Some(FilterApplier::new(Arc::clone(&filter))),
                ..ModuleAppliers::default()
            },
            "node-a",
        ));
        service
            .replace(seed.clone(), &ConfigActor::local(), None)
            .await
            .expect("seed config");

        // A production assembler derives the protected entries from the stored
        // config and the OIDC issuer and passes them to the MCP layer.
        let derived = derive_protected_domains(Some(&seed), oidc_issuer, Vec::new())
            .expect("derive protected domains");
        let mut mcp_config = mcp;
        for entry in derived.entries() {
            if !mcp_config.protected_domains.contains(entry) {
                mcp_config.protected_domains.push(entry.clone());
            }
        }

        let backend = mcp_backend_for_test_writes(
            Arc::clone(&filter),
            Some(Arc::clone(&policy)),
            Some(Arc::clone(&query_log)),
            Arc::clone(&service),
            Some(Arc::new(Audit::new(db.clone()))),
            Some(tokens.clone()),
            Arc::clone(&clock) as Arc<dyn ApiClock>,
            mcp_config.clone(),
            oidc_issuer.map(str::to_owned),
        );

        let mut state = AppState::new()
            .with_clock(Arc::clone(&clock) as Arc<dyn ApiClock>)
            .with_auth(auth)
            .with_config_service(Arc::clone(&service))
            .with_filter_engine(Arc::clone(&filter))
            .with_policy_engine(Arc::clone(&policy))
            .with_query_log(Arc::clone(&query_log))
            .with_mcp_config(mcp_config.clone());
        if let Some(issuer) = oidc_issuer {
            state = state.with_oidc_issuer(issuer);
        }

        // The process assembler nests the transport inside `build_router`
        // before the auth and rate-limit layers. `AppState` has no public hook
        // for a test backend, so the transport is nested on the assembled
        // router here; its bearer-token validation runs inside the transport
        // either way, which is what the scope matrix exercises.
        let mut router = state.router();
        if mcp_config.enabled {
            router = router.nest_service(
                "/mcp/v1",
                dnscraft_mcp::service(Arc::clone(&backend), mcp_config.clone()),
            );
        }
        let server = TestServer::start(router).await;
        let client = reqwest::Client::new();

        Self {
            server,
            client,
            backend,
            service,
            filter,
            policy,
            resolver,
            query_log,
            clock,
            tokens,
            admin,
            viewer,
            write,
            read,
            mcp_enabled: mcp_config.enabled,
            _hierarchy: hierarchy,
            _temp: temp,
        }
    }

    fn url(&self, path: &str) -> String {
        self.server.url(path)
    }

    fn admin_token(&self) -> &str {
        self.admin.plaintext().expose()
    }

    fn viewer_token(&self) -> &str {
        self.viewer.plaintext().expose()
    }

    fn write_token(&self) -> &str {
        self.write.plaintext().expose()
    }

    fn read_token(&self) -> &str {
        self.read.plaintext().expose()
    }

    fn backend(&self) -> &Arc<dyn McpBackend> {
        &self.backend
    }

    async fn tool(
        &self,
        bearer: Option<&str>,
        name: &str,
        arguments: Value,
    ) -> (StatusCode, Value) {
        assert!(self.mcp_enabled, "MCP endpoint is not mounted");
        mcp_http(
            &self.client,
            &self.url("/mcp/v1"),
            bearer,
            "tools/call",
            Some(name),
            json!({ "name": name, "arguments": arguments }),
        )
        .await
    }

    async fn tool_ok(&self, bearer: &str, name: &str, arguments: Value) -> Value {
        let (status, body) = self.tool(Some(bearer), name, arguments).await;
        assert_eq!(status, StatusCode::OK, "tool {name}: {body}");
        assert!(!tool_is_error(&body), "tool {name} failed: {body}");
        tool_output(&body)
    }

    async fn mcp_method(&self, bearer: Option<&str>, method: &str) -> (StatusCode, Value) {
        mcp_http(
            &self.client,
            &self.url("/mcp/v1"),
            bearer,
            method,
            None,
            json!({}),
        )
        .await
    }

    async fn test_query(&self, domain: &str) -> Value {
        self.tool_ok(
            self.read_token(),
            "test_query",
            json!({
                "domain": domain,
                "qtype": "A",
                "source_ip": "192.0.2.10",
                "protocol": "udp53",
            }),
        )
        .await
    }

    async fn rules(&self, bearer: &str) -> Vec<Value> {
        let output = self
            .tool_ok(bearer, "list_mcp_rules", json!({ "kind": "rules" }))
            .await;
        output["rules"].as_array().cloned().unwrap_or_default()
    }

    async fn http(
        &self,
        method: reqwest::Method,
        path: &str,
        bearer: Option<&str>,
        body: Option<&Value>,
    ) -> (StatusCode, Value) {
        let mut request = self.client.request(method, self.url(path));
        if let Some(bearer) = bearer {
            request = request.header("Authorization", format!("Bearer {bearer}"));
        }
        if let Some(body) = body {
            request = request
                .header("Content-Type", "application/json")
                .body(body.to_string());
        }
        let response = request.send().await.expect("control-api request");
        let status = response.status();
        let text = response.text().await.expect("control-api body");
        (status, serde_json::from_str(&text).unwrap_or(Value::Null))
    }

    async fn put_config(&self, body: &Value) -> (StatusCode, Value) {
        self.http(
            reqwest::Method::PUT,
            "/api/v1/config",
            Some(self.admin_token()),
            Some(body),
        )
        .await
    }

    async fn log_rows(&self) -> usize {
        self.query_log
            .list(&QueryLogFilter {
                limit: 100,
                ..QueryLogFilter::default()
            })
            .await
            .expect("list query log")
            .records
            .len()
    }

    /// Runs the real policy path (not a test query) for `domain`.
    async fn real_query(&self, domain: &str) -> dnscraft_policy::PolicyAnswer {
        self.policy
            .handle(request_context(domain))
            .await
            .expect("policy query")
    }

    fn verdict(&self, engine: &FilterEngine, domain: &str) -> Verdict {
        let name = DomainName::parse(domain).expect("domain");
        engine
            .match_name(&SetId::new("default").unwrap(), &name, 1, self.clock.now())
            .expect("match name")
    }
}

fn error_code(body: &Value) -> &str {
    body["error"]["code"].as_str().unwrap_or_default()
}

// ---------------------------------------------------------------------------
// Flow 1: add rule, observe blocking, expire it, watch every surface
// ---------------------------------------------------------------------------

#[tokio::test]
async fn flow1_add_rule_blocks_and_expires() {
    let h = Harness::new(gate_on(), snapshot(None, ""), None).await;
    let write = h.write_token().to_owned();
    let read = h.read_token().to_owned();

    assert!(h.rules(&read).await.is_empty());

    let added = h
        .tool_ok(
            &write,
            "add_rule",
            json!({ "domain": "www.example.test", "include_subdomains": true }),
        )
        .await;
    assert_eq!(added["rule_text"], "||www.example.test^");
    assert_eq!(added["filter_set_id"], "default");
    assert_eq!(added["domain"], "www.example.test");
    assert_eq!(added["expires_at"], rfc3339(NOW + RULE_LIFETIME));

    let test = h.test_query("www.example.test").await;
    assert_eq!(test["verdict"], "blocked");
    assert_eq!(test["filter"]["rule_text"], "||www.example.test^");

    let answer = h.real_query("www.example.test").await;
    assert!(answer.record.filter.is_some(), "real query must be blocked");
    assert!(answer.loggable);

    let rules = h.rules(&read).await;
    assert_eq!(rules.len(), 1);
    assert_eq!(rules[0]["domain"], "www.example.test");
    assert_eq!(rules[0]["expires_at"], rfc3339(NOW + RULE_LIFETIME));

    // The stored rule records the MCP token that created it.
    let (_, stored) = h.service.current().await.expect("current config");
    let stored = stored.expect("stored snapshot");
    let stored_rule = &stored["filtering"]["sets"][0]["mcp_rules"][0];
    assert_eq!(stored_rule["token_id"], h.write.id());

    // At the exact expiry instant the rule is already inactive (strict).
    h.clock.set(at(NOW + RULE_LIFETIME));
    let test = h.test_query("www.example.test").await;
    assert_eq!(test["verdict"], "allowed");
    assert_eq!(test["answer"]["rcode"], "NOERROR");
    assert_eq!(test["answer"]["records"][0]["data"], "192.0.2.1");

    let answer = h.real_query("www.example.test").await;
    assert!(answer.record.filter.is_none());
    assert!(h.rules(&read).await.is_empty());

    // Past the expiry it stays unblocked.
    h.clock.advance(Duration::from_secs(DAY));
    assert_eq!(h.test_query("www.example.test").await["verdict"], "allowed");
    assert!(h.rules(&read).await.is_empty());
}

// ---------------------------------------------------------------------------
// Flow 2: temporary allow, pause, resume, restart from the stored config
// ---------------------------------------------------------------------------

#[tokio::test]
async fn flow2_allow_pause_resume_and_restart() {
    let seed = snapshot(None, "||www.example.test^\n||ads.example.test^");
    let h = Harness::new(gate_on(), seed, None).await;
    let write = h.write_token().to_owned();

    assert_eq!(h.test_query("ads.example.test").await["verdict"], "blocked");

    let allowed = h
        .tool_ok(
            &write,
            "allow_temporarily",
            json!({
                "domain": "ads.example.test",
                "include_subdomains": true,
                "duration": "PT1H",
            }),
        )
        .await;
    assert_eq!(allowed["expires_at"], rfc3339(NOW + 3600));
    assert_eq!(h.test_query("ads.example.test").await["verdict"], "allowed");

    // One second before the expiry the allow is still active.
    h.clock.set(at(NOW + 3599));
    assert_eq!(h.test_query("ads.example.test").await["verdict"], "allowed");

    // Exactly at the expiry it is gone.
    h.clock.set(at(NOW + 3600));
    assert_eq!(h.test_query("ads.example.test").await["verdict"], "blocked");
    assert_eq!(h.test_query("www.example.test").await["verdict"], "blocked");

    let paused = h
        .tool_ok(&write, "pause_filter_set", json!({ "duration": "PT1H" }))
        .await;
    assert_eq!(paused["paused_until"], rfc3339(NOW + 7200));
    assert_eq!(h.test_query("www.example.test").await["verdict"], "allowed");
    assert_eq!(h.test_query("ads.example.test").await["verdict"], "allowed");
    assert_eq!(
        h.filter.paused_until(&SetId::new("default").unwrap()),
        Some(at(NOW + 7200))
    );

    let resumed = h.tool_ok(&write, "resume_filter_set", json!({})).await;
    assert_eq!(resumed["resumed"], true);
    assert_eq!(h.test_query("www.example.test").await["verdict"], "blocked");
    assert!(
        h.filter
            .paused_until(&SetId::new("default").unwrap())
            .is_none()
    );

    // An MCP rule is part of the stored config.
    let added = h
        .tool_ok(
            &write,
            "add_rule",
            json!({ "domain": "tracker.example.test", "include_subdomains": false }),
        )
        .await;
    assert_eq!(added["rule_text"], "|tracker.example.test^");

    // Set runtime overlays that a restart must drop.
    h.tool_ok(
        &write,
        "allow_temporarily",
        json!({
            "domain": "ads.example.test",
            "include_subdomains": true,
            "duration": "PT1H",
        }),
    )
    .await;
    assert!(matches!(
        h.verdict(&h.filter, "ads.example.test"),
        Verdict::Allowed(_)
    ));
    h.tool_ok(&write, "pause_filter_set", json!({ "duration": "PT1H" }))
        .await;
    assert!(
        h.filter
            .paused_until(&SetId::new("default").unwrap())
            .is_some()
    );

    // Restart: rebuild the filtering engine from the stored config only.
    let (_, stored) = h.service.current().await.expect("current config");
    let stored = stored.expect("stored snapshot");
    let restarted = build_engine(
        &h._temp,
        filter_config_from_json(&stored["filtering"]).expect("stored filtering"),
        Arc::clone(&h.clock) as Arc<dyn FilterClock>,
    );
    assert!(
        matches!(
            h.verdict(&restarted, "tracker.example.test"),
            Verdict::Blocked(_)
        ),
        "the MCP rule survives a restart"
    );
    assert!(
        matches!(
            h.verdict(&restarted, "ads.example.test"),
            Verdict::Blocked(_)
        ),
        "a temporary allow never survives a restart"
    );
    assert!(
        restarted
            .paused_until(&SetId::new("default").unwrap())
            .is_none(),
        "a pause never survives a restart"
    );
    assert!(matches!(
        h.verdict(&restarted, "www.example.test"),
        Verdict::Blocked(_)
    ));
}

// ---------------------------------------------------------------------------
// Flow 3: config replace/rollback, cap, protected domains
// ---------------------------------------------------------------------------

#[tokio::test]
async fn flow3_config_replace_rollback_rules() {
    let h = Harness::new(gate_on(), snapshot(None, ""), None).await;
    let write = h.write_token().to_owned();
    let read = h.read_token().to_owned();

    h.tool_ok(
        &write,
        "add_rule",
        json!({ "domain": "tracker.example.test", "include_subdomains": true }),
    )
    .await;
    let (_, versions) = h
        .http(
            reqwest::Method::GET,
            "/api/v1/config/versions",
            Some(h.admin_token()),
            None,
        )
        .await;
    let rule_version = versions["data"]["current_version"]
        .as_u64()
        .expect("version");

    // PUT without `mcp_rules` keeps the stored rules.
    let (status, body) = h.put_config(&without_mcp_rules(&snapshot(None, ""))).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(h.rules(&read).await.len(), 1);
    assert_eq!(
        h.test_query("tracker.example.test").await["verdict"],
        "blocked"
    );

    // An explicit empty list deletes them.
    let (status, body) = h
        .put_config(&with_empty_mcp_rules(&snapshot(None, "")))
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(h.rules(&read).await.is_empty());
    assert_eq!(
        h.test_query("tracker.example.test").await["verdict"],
        "allowed"
    );

    // Rollback restores the version that still carried the rule.
    let (status, body) = h
        .http(
            reqwest::Method::POST,
            &format!("/api/v1/config/versions/{rule_version}/rollback"),
            Some(h.admin_token()),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["data"]["restored_from"], rule_version);
    assert_eq!(h.rules(&read).await.len(), 1);
    assert_eq!(
        h.test_query("tracker.example.test").await["verdict"],
        "blocked"
    );
}

#[tokio::test]
async fn flow3_cap_and_protected_domains() {
    let mut mcp = gate_on();
    mcp.max_custom_rules_per_set = 10;
    let h = Harness::new(
        mcp,
        snapshot_with_rules(10),
        Some("https://auth.example.org/realms/main"),
    )
    .await;
    let write = h.write_token().to_owned();

    let (status, body) = h
        .tool(
            Some(&write),
            "add_rule",
            json!({ "domain": "other.example.test", "include_subdomains": false }),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert!(tool_is_error(&body), "cap must reject the rule: {body}");
    assert_eq!(tool_error_code(&body), "mcp.rule_limit_exceeded");

    // The OIDC issuer host is protected even when the rule cap is reached.
    let (_, body) = h
        .tool(
            Some(&write),
            "add_rule",
            json!({ "domain": "auth.example.org", "include_subdomains": false }),
        )
        .await;
    assert!(tool_is_error(&body), "OIDC issuer host must be protected");
    assert_eq!(tool_error_code(&body), "mcp.protected_domain");
}

#[tokio::test]
async fn flow3_protected_domains_from_node_config() {
    let h = Harness::new(gate_on(), snapshot(Some("example.net"), ""), None).await;
    let write = h.write_token().to_owned();

    for domain in ["example.net", "dns.example.net", "host.example.net"] {
        let (_, body) = h
            .tool(
                Some(&write),
                "add_rule",
                json!({ "domain": domain, "include_subdomains": false }),
            )
            .await;
        assert!(tool_is_error(&body), "{domain} must be protected: {body}");
        assert_eq!(tool_error_code(&body), "mcp.protected_domain", "{domain}");
    }

    // The backend rejects the same targets when reached directly.
    let error = h
        .backend()
        .add_custom_rule(dnscraft_mcp::dto::AddRuleParams {
            domain: "example.net".to_owned(),
            include_subdomains: false,
            filter_set_id: None,
            lifetime_seconds: RULE_LIFETIME,
            token_id: String::new(),
            reason: String::new(),
        })
        .await
        .expect_err("backend must reject a protected domain");
    assert_eq!(error.code(), "mcp.protected_domain");
    let params = error.params().expect("error params");
    assert_eq!(
        params.get("domain").and_then(Value::as_str),
        Some("example.net")
    );
    assert!(
        params.get("protected_domain").is_none(),
        "the matched protected entry must not be disclosed: {params}"
    );
}

// ---------------------------------------------------------------------------
// Flow 4: token scopes, gate, revocation, disabled endpoint
// ---------------------------------------------------------------------------

#[tokio::test]
async fn flow4_scope_matrix_across_families() {
    let h = Harness::new(gate_on(), snapshot(None, ""), None).await;

    // mcp:read may use both MCP tool classes that are reads.
    let (status, body) = h.mcp_method(Some(h.read_token()), "tools/list").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["result"]["tools"].as_array().map(Vec::len), Some(13));
    assert!(h.rules(h.read_token()).await.is_empty());

    // mcp:read may not call a write tool.
    let (status, body) = h
        .tool(
            Some(h.read_token()),
            "add_rule",
            json!({ "domain": "scope.example.test", "include_subdomains": false }),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert!(tool_is_error(&body));
    assert_eq!(
        tool_error_code(&body),
        "control_api.auth.insufficient_scope"
    );

    // mcp:write may.
    h.tool_ok(
        h.write_token(),
        "add_rule",
        json!({ "domain": "scope.example.test", "include_subdomains": false }),
    )
    .await;

    // An API-scope token is rejected by the MCP endpoint.
    let (status, body) = h.mcp_method(Some(h.admin_token()), "tools/list").await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(error_code(&body), "control_api.auth.invalid_scope");

    // Missing credentials are unauthenticated.
    let (status, body) = h.mcp_method(None, "tools/list").await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(error_code(&body), "control_api.auth.unauthenticated");

    // MCP tokens are invalid on /api/v1.
    let (status, body) = h
        .http(
            reqwest::Method::GET,
            "/api/v1/config",
            Some(h.write_token()),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(error_code(&body), "control_api.auth.invalid_scope");

    // A viewer may read non-config API routes.
    let (status, body) = h
        .http(
            reqwest::Method::GET,
            "/api/v1/query-log",
            Some(h.viewer_token()),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    // A viewer may not write config.
    let (status, body) = h
        .http(
            reqwest::Method::PUT,
            "/api/v1/config",
            Some(h.viewer_token()),
            Some(&snapshot(None, "")),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(error_code(&body), "control_api.auth.insufficient_scope");

    // Admin may.
    let (status, body) = h.put_config(&snapshot(None, "")).await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

#[tokio::test]
async fn flow4_write_gate_disabled() {
    let mut mcp = gate_on();
    mcp.write_tools_enabled = false;
    let h = Harness::new(mcp, snapshot(None, ""), None).await;

    let (status, body) = h
        .tool(
            Some(h.write_token()),
            "add_rule",
            json!({ "domain": "gate.example.test", "include_subdomains": false }),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert!(tool_is_error(&body));
    assert_eq!(tool_error_code(&body), "mcp.write_tools_disabled");

    // Read tools stay available with the write gate closed.
    assert!(h.rules(h.read_token()).await.is_empty());
}

#[tokio::test]
async fn flow4_revoked_token_is_rejected() {
    let h = Harness::new(gate_on(), snapshot(None, ""), None).await;
    let revoked = h.write_token().to_owned();
    h.tokens.revoke(h.write.id()).await.expect("revoke token");

    let (status, body) = h.mcp_method(Some(&revoked), "tools/list").await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(error_code(&body), "control_api.auth.unauthenticated");
}

#[tokio::test]
async fn flow4_disabled_endpoint_is_not_mounted() {
    let h = Harness::new(
        McpConfig {
            enabled: false,
            ..McpConfig::default()
        },
        snapshot(None, ""),
        None,
    )
    .await;

    let (status, body) = h.mcp_method(Some(h.read_token()), "tools/list").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(error_code(&body), "control_api.not_found");
}

// ---------------------------------------------------------------------------
// test_query is read-only for the query log and the resolver cache
// ---------------------------------------------------------------------------

fn sample_event(seconds: u64) -> QueryEvent {
    let selection = SelectionCause::Subnet {
        network: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 0)),
        prefix_len: 24,
    };
    QueryEvent {
        time: at(seconds),
        protocol: DnsProtocol::Udp53,
        listener_id: ListenerId::new("udp-53").unwrap(),
        source: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
        client_id: None,
        query: Query {
            name: Name::from_ascii("www.example.test.").unwrap(),
            qtype: RecordType::A,
            qclass: Class::IN,
        },
        rcode: Rcode::NOERROR,
        answer_size: 128,
        duration: Duration::from_millis(1),
        decision: DecisionRecord {
            view_id: ViewId::new("default").unwrap(),
            profile_id: ProfileId::new("default").unwrap(),
            selection,
            client_id: None,
            filter_set: SetId::new("default").unwrap(),
            steps: vec![
                DecisionStep::Selected { cause: selection },
                DecisionStep::Resolve {
                    source: AnswerSource::Recursion,
                    dnssec: DnssecStatus::Indeterminate,
                },
            ],
            filter: None,
            forward_zone: None,
            dnssec: Some(DnssecStatus::Indeterminate),
            answer_source: AnswerOrigin::Resolver,
            timings: DecisionTimings {
                select_us: 2,
                filter_us: 0,
                resolve_us: 940,
                total_us: 950,
            },
            rcode: Rcode::NOERROR,
        },
        loggable: true,
    }
}

#[tokio::test]
async fn test_query_leaves_query_log_and_cache_unchanged() {
    let h = Harness::new(gate_on(), snapshot(None, "||ads.example.test^"), None).await;

    h.query_log
        .insert_batch(vec![sample_event(NOW)])
        .await
        .expect("seed query log");
    assert_eq!(h.log_rows().await, 1);

    // Populate the resolver cache through the real (non-test) policy path.
    let answer = h.real_query("www.example.test").await;
    assert!(answer.record.filter.is_none());
    h.resolver.wait_idle().await;
    let cache_before = h.resolver.stats().cache_entries;
    assert!(cache_before > 0, "the real query must warm the cache");
    let logs_before = h.log_rows().await;

    // A test query resolves (and would poison the cache had it written) and a
    // blocked test query never resolves at all.
    let allowed = h.test_query("www.example.test").await;
    assert_eq!(allowed["verdict"], "allowed");
    assert_eq!(allowed["answer"]["records"][0]["data"], "192.0.2.1");
    let blocked = h.test_query("ads.example.test").await;
    assert_eq!(blocked["verdict"], "blocked");
    h.resolver.wait_idle().await;

    assert_eq!(h.log_rows().await, logs_before);
    assert_eq!(h.resolver.stats().cache_entries, cache_before);
}
