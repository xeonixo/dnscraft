//! Shared fixtures for the MCP write and end-to-end tests.
//!
//! The harness keeps one advanceable clock behind both the control-api and the
//! filtering clock traits, so a config apply, the stored rules and the engine
//! snapshot all observe the same instant. The filtering adapter mirrors what a
//! production assembler does: it turns the stored `filtering` section into a
//! [`FilterConfig`] and applies it to the real engine.

#![allow(dead_code)]

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Once};
use std::time::{Duration, SystemTime};

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use serde_json::{Value, json};
use tokio::sync::Notify;
use tower::ServiceExt as _;

use dnscraft_api::{ApplyFiltering, Clock as ApiClock, ControlApiError, ModuleFuture};
use dnscraft_filtering::{
    BlockMode, Clock as FilterClock, DomainName, FilterConfig, FilterSetConfig, ListConfig, ListId,
    ListSourceSpec, McpRule, McpRuleId, SetId,
};
use dnscraft_filtering::{ListStore, StoreConfig};

/// Fixed test instant (2023-11-14T22:13:20Z).
pub const NOW: u64 = 1_700_000_000;
/// One day in seconds.
pub const DAY: u64 = 24 * 3600;
/// MCP protocol revision sent by every request.
pub const MCP_VERSION: &str = "2026-07-28";

/// `SystemTime` at `seconds` after the Unix epoch.
pub fn at(seconds: u64) -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(seconds)
}

/// RFC 3339 rendering of `seconds` after the epoch (seconds precision, `Z`).
pub fn rfc3339(seconds: u64) -> String {
    time::OffsetDateTime::from_unix_timestamp(seconds as i64)
        .unwrap_or(time::OffsetDateTime::UNIX_EPOCH)
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default()
}

/// A unique directory under the OS temp dir, removed on drop.
pub struct TempDir(PathBuf);

impl TempDir {
    /// Creates a fresh directory tagged with `name`.
    pub fn new(name: &str) -> Self {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let id = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("dnscraft-mcp-{name}-{}-{id}", std::process::id()));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).expect("create temp dir");
        Self(path)
    }

    /// The directory path.
    pub fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// One instant shared by the control-api and filtering clocks.
#[derive(Debug)]
pub struct BridgeClock {
    now: Mutex<SystemTime>,
    tick: Arc<Notify>,
}

impl BridgeClock {
    /// Creates a shared clock frozen at `start`.
    pub fn new(start: SystemTime) -> Arc<Self> {
        Arc::new(Self {
            now: Mutex::new(start),
            tick: Arc::new(Notify::new()),
        })
    }

    /// The current instant.
    pub fn now(&self) -> SystemTime {
        *self
            .now
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Moves the clock forward and wakes filtering waiters.
    pub fn advance(&self, by: Duration) {
        let mut now = self
            .now
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *now += by;
        self.tick.notify_waiters();
    }

    /// Sets the clock to an absolute instant and wakes filtering waiters.
    pub fn set(&self, to: SystemTime) {
        *self
            .now
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = to;
        self.tick.notify_waiters();
    }
}

impl ApiClock for BridgeClock {
    fn now(&self) -> SystemTime {
        Self::now(self)
    }

    fn tick_notify(&self) -> Option<Arc<Notify>> {
        Some(Arc::clone(&self.tick))
    }
}

/// Builds a matching-capable filtering engine over `config`.
pub fn build_engine(
    temp: &TempDir,
    config: FilterConfig,
    clock: Arc<dyn FilterClock>,
) -> Arc<dnscraft_filtering::FilterEngine> {
    let store = ListStore::open_with(temp.path(), StoreConfig::default(), Arc::clone(&clock))
        .expect("open list store");
    dnscraft_filtering::FilterEngine::open_without_scheduler(config, store, clock)
        .expect("open filtering engine")
}

/// The default seed: one set blocking `ads.example.com` and its subdomains.
pub fn seed_config() -> FilterConfig {
    let mut set = FilterSetConfig::new(SetId::new("default").expect("default set"), "Default");
    set.custom_rules = "||ads.example.com^".to_owned();
    set.block_mode = BlockMode::Refused;
    FilterConfig {
        lists: Vec::new(),
        sets: vec![set],
        ..FilterConfig::default()
    }
}

/// A complete five-section config snapshot plus empty clients/policy/listeners.
///
/// `public_domain` populates `tls.public_domain`, which the protected-domain
/// derivation turns into `example.net` (and `dns.example.net`) entries.
pub fn snapshot(public_domain: Option<&str>, custom_rules: &str) -> Value {
    json!({
        "filtering": {
            "lists": [],
            "sets": [{
                "id": "default",
                "name": "Default",
                "lists": [],
                "custom_rules": custom_rules,
                "services": [],
                "block_mode": "refused",
                "mcp_rules": []
            }]
        },
        "clients": {},
        "policy": {},
        "listeners": {},
        "tls": public_domain.map_or_else(|| json!({}), |domain| json!({ "public_domain": domain })),
        "resolver": {}
    })
}

/// Applies the control-api's stored `filtering` section to the real engine.
pub struct FilterApplier {
    engine: Arc<dnscraft_filtering::FilterEngine>,
}

impl FilterApplier {
    /// Wraps `engine`.
    pub fn new(engine: Arc<dnscraft_filtering::FilterEngine>) -> Arc<Self> {
        Arc::new(Self { engine })
    }
}

impl ApplyFiltering for FilterApplier {
    fn validate(&self, config: &Value) -> Result<(), ControlApiError> {
        filter_config_from_json(config).map(|_| ())
    }

    fn apply<'a>(&'a self, config: &'a Value) -> ModuleFuture<'a> {
        Box::pin(async move {
            let parsed = filter_config_from_json(config)?;
            self.engine
                .apply_config(parsed)
                .await
                .map(|_| ())
                .map_err(|err| ControlApiError::Internal {
                    message: format!("filter apply: {err}"),
                })
        })
    }
}

fn invalid(reason: impl Into<String>) -> ControlApiError {
    ControlApiError::Module {
        code: "filtering.config.invalid",
        params: Some(json!({ "reason": reason.into() })),
    }
}

fn json_time(value: &Value) -> Result<SystemTime, ControlApiError> {
    match value {
        Value::Number(number) => number
            .as_u64()
            .map(at)
            .ok_or_else(|| invalid("timestamp must be unix seconds or RFC 3339")),
        Value::String(raw) => {
            time::OffsetDateTime::parse(raw, &time::format_description::well_known::Rfc3339)
                .ok()
                .and_then(|time| u64::try_from(time.unix_timestamp()).ok())
                .map(at)
                .ok_or_else(|| invalid("timestamp must be unix seconds or RFC 3339"))
        }
        _ => Err(invalid("timestamp must be unix seconds or RFC 3339")),
    }
}

fn string_field<'a>(value: &'a Value, key: &str) -> Result<&'a str, ControlApiError> {
    value
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| invalid(format!("missing string field `{key}`")))
}

/// Parses a stored `filtering` section into the filtering crate's config.
///
/// Supports the shapes the control-api routes store: string list ids, an ISO
/// block mode (or a `custom_ip` object), an RFC 3339 `paused_until`, and
/// structured `mcp_rules`.
pub fn filter_config_from_json(value: &Value) -> Result<FilterConfig, ControlApiError> {
    let empty = Vec::new();
    let mut lists = Vec::new();
    for list in value
        .get("lists")
        .and_then(Value::as_array)
        .unwrap_or(&empty)
    {
        let id = ListId::new(string_field(list, "id")?).map_err(|_| invalid("invalid list id"))?;
        let name = list
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        let source = list.get("source").ok_or_else(|| invalid("list source"))?;
        let source = if let Some(url) = source.get("url").and_then(Value::as_str) {
            ListSourceSpec::Url(url.to_owned())
        } else if let Some(file) = source.get("file").and_then(Value::as_str) {
            ListSourceSpec::File(PathBuf::from(file))
        } else {
            return Err(invalid("list source must be a `url` or `file`"));
        };
        lists.push(ListConfig {
            id,
            name,
            source,
            enabled: list.get("enabled").and_then(Value::as_bool).unwrap_or(true),
        });
    }

    let mut sets = Vec::new();
    for set in value
        .get("sets")
        .and_then(Value::as_array)
        .unwrap_or(&empty)
    {
        let id = SetId::new(string_field(set, "id")?).map_err(|_| invalid("invalid set id"))?;
        let mut config = FilterSetConfig::new(
            id,
            set.get("name").and_then(Value::as_str).unwrap_or_default(),
        );
        for list in set.get("lists").and_then(Value::as_array).unwrap_or(&empty) {
            let id = list
                .as_str()
                .ok_or_else(|| invalid("set lists must be strings"))
                .and_then(|id| ListId::new(id).map_err(|_| invalid("invalid list id")))?;
            config.lists.push(id);
        }
        config.custom_rules = set
            .get("custom_rules")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        config.services = set
            .get("services")
            .and_then(Value::as_array)
            .map(|services| {
                services
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default();
        config.block_mode = match set.get("block_mode") {
            None | Some(Value::Null) => BlockMode::Refused,
            Some(Value::String(mode)) => match mode.as_str() {
                "refused" => BlockMode::Refused,
                "nxdomain" => BlockMode::NxDomain,
                "null_ip" => BlockMode::NullIp,
                other => return Err(invalid(format!("unknown block_mode `{other}`"))),
            },
            Some(Value::Object(map)) => {
                let custom = map
                    .get("custom_ip")
                    .and_then(Value::as_object)
                    .unwrap_or(map);
                BlockMode::CustomIp {
                    v4: custom
                        .get("v4")
                        .and_then(Value::as_str)
                        .and_then(|ip| ip.parse().ok()),
                    v6: custom
                        .get("v6")
                        .and_then(Value::as_str)
                        .and_then(|ip| ip.parse().ok()),
                }
            }
            Some(_) => return Err(invalid("block_mode must be a string or object")),
        };
        config.paused_until = match set.get("paused_until") {
            None | Some(Value::Null) => None,
            Some(value) => Some(json_time(value)?),
        };
        for rule in set
            .get("mcp_rules")
            .and_then(Value::as_array)
            .unwrap_or(&empty)
        {
            let id = McpRuleId::new(string_field(rule, "id")?)
                .map_err(|_| invalid("invalid mcp rule id"))?;
            let domain = DomainName::parse(string_field(rule, "domain")?)
                .map_err(|_| invalid("invalid mcp rule domain"))?;
            config.mcp_rules.push(McpRule {
                id,
                domain,
                include_subdomains: rule
                    .get("include_subdomains")
                    .and_then(Value::as_bool)
                    .unwrap_or(false),
                created_at: json_time(
                    rule.get("created_at")
                        .ok_or_else(|| invalid("mcp rule created_at"))?,
                )?,
                expires_at: json_time(
                    rule.get("expires_at")
                        .ok_or_else(|| invalid("mcp rule expires_at"))?,
                )?,
                token_id: rule
                    .get("token_id")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned(),
            });
        }
        sets.push(config);
    }

    Ok(FilterConfig {
        lists,
        sets,
        ..FilterConfig::default()
    })
}

/// Installs the rustls ring provider once per test process.
///
/// Required before a [`reqwest`] client (built with `rustls-no-provider`) or a
/// TLS peer is created.
pub fn install_crypto() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

/// A real loopback HTTP server for `router`, aborted on drop.
pub struct TestServer {
    address: std::net::SocketAddr,
    task: tokio::task::JoinHandle<()>,
}

impl TestServer {
    /// Binds an OS-assigned loopback port and serves `router` on it.
    pub async fn start(router: Router) -> Self {
        install_crypto();
        let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind test server");
        let address = listener.local_addr().expect("test server address");
        let task = tokio::spawn(async move {
            let service = router.into_make_service_with_connect_info::<std::net::SocketAddr>();
            let _ = axum::serve(listener, service).await;
        });
        Self { address, task }
    }

    /// Absolute URL of `path` on this server.
    pub fn url(&self, path: &str) -> String {
        format!("http://{}{path}", self.address)
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Mounts the MCP service for `backend` on a bare router.
pub fn mcp_router(
    backend: Arc<dyn dnscraft_mcp::McpBackend>,
    config: dnscraft_mcp::McpConfig,
) -> Router {
    install_crypto();
    Router::new().nest_service("/mcp/v1", dnscraft_mcp::service(backend, config))
}

fn meta() -> Value {
    json!({
        "io.modelcontextprotocol/protocolVersion": MCP_VERSION,
        "io.modelcontextprotocol/clientCapabilities": {},
    })
}

/// Calls the MCP endpoint over a real HTTP connection.
///
/// `bearer` is omitted entirely when `None`, which exercises the
/// unauthenticated path.
pub async fn mcp_http(
    client: &reqwest::Client,
    url: &str,
    bearer: Option<&str>,
    method: &str,
    name: Option<&str>,
    mut params: Value,
) -> (reqwest::StatusCode, Value) {
    if let Value::Object(map) = &mut params {
        map.insert("_meta".into(), meta());
    }
    let mut request = client
        .post(url)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::ACCEPT, "application/json, text/event-stream")
        .header("MCP-Protocol-Version", MCP_VERSION)
        .header("Mcp-Method", method);
    if let Some(bearer) = bearer {
        request = request.header(header::AUTHORIZATION, format!("Bearer {bearer}"));
    }
    if let Some(name) = name {
        request = request.header("Mcp-Name", name);
    }
    let body = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": params,
    });
    let response = request
        .body(body.to_string())
        .send()
        .await
        .expect("MCP request");
    let status = response.status();
    let text = response.text().await.expect("MCP response body");
    (status, serde_json::from_str(&text).unwrap_or(Value::Null))
}

/// Scripted MCP client: calls `method` with `params` and returns the status and
/// JSON-RPC body.
pub async fn mcp_call(
    router: &Router,
    bearer: &str,
    method: &str,
    name: Option<&str>,
    mut params: Value,
) -> (StatusCode, Value) {
    if let Value::Object(map) = &mut params {
        map.insert("_meta".into(), meta());
    }
    let mut builder = Request::builder()
        .method("POST")
        .uri("/mcp/v1")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::ACCEPT, "application/json, text/event-stream")
        .header("MCP-Protocol-Version", MCP_VERSION)
        .header("Mcp-Method", method)
        .header(header::HOST, "localhost")
        .header(header::AUTHORIZATION, format!("Bearer {bearer}"));
    if let Some(name) = name {
        builder = builder.header("Mcp-Name", name);
    }
    let body = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": params,
    })
    .to_string();
    let response = router
        .clone()
        .oneshot(builder.body(Body::from(body)).expect("request"))
        .await
        .expect("router response");
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("response body");
    let body = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, body)
}

/// Calls one tool and returns the status and JSON-RPC body.
pub async fn mcp_tool(
    router: &Router,
    bearer: &str,
    name: &str,
    arguments: Value,
) -> (StatusCode, Value) {
    mcp_call(
        router,
        bearer,
        "tools/call",
        Some(name),
        json!({ "name": name, "arguments": arguments }),
    )
    .await
}

/// The structured payload of a successful tool result.
pub fn tool_output(body: &Value) -> Value {
    body["result"]["content"][0]["text"]
        .as_str()
        .and_then(|text| serde_json::from_str(text).ok())
        .unwrap_or(Value::Null)
}

/// The stable code of a failed tool call.
pub fn tool_error_code(body: &Value) -> &str {
    body["result"]["structuredContent"]["error"]["code"]
        .as_str()
        .unwrap_or_default()
}

/// Whether a tool call reported `isError`.
pub fn tool_is_error(body: &Value) -> bool {
    body["result"]["isError"].as_bool().unwrap_or(false)
}
