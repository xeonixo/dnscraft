//! Shared test backend.
//!
//! An in-memory [`McpBackend`] whose success/error responses and blocking
//! behaviour are configurable per test. It never touches the network.

#![allow(dead_code)]

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use dnscraft_mcp::backend::{BackendError, McpBackend};
use dnscraft_mcp::dto::{
    AddRuleParams, AddRuleResult, AuditEntry, ClientInfo, ClientListParams, ClientListResult,
    ExplainBlockResult, ListRulesParams, ListRulesResult, NodeStatus, PauseDuration, PauseResult,
    QType, QueryDetail, QueryLogEntry, QueryLogResult, QueryLogSearch, RemoveRuleParams,
    RemoveRuleResult, ResumeResult, StatsParams, StatsResult, TempAllowParams, TempAllowResult,
    TestQueryParams, TestQueryResult, TokenInfo, TokenScope,
};
use tokio::sync::Notify;

fn slot<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Configurable in-memory backend.
#[derive(Default)]
pub struct MockBackend {
    status: Mutex<Option<Result<NodeStatus, BackendError>>>,
    token: Mutex<Option<Result<TokenInfo, BackendError>>>,
    status_delay: Mutex<Option<Arc<Notify>>>,
    /// Number of `get_status` calls started.
    pub status_calls: AtomicUsize,
    /// Number of `get_status` calls still running.
    status_active: AtomicUsize,
    /// Number of `validate_token` calls.
    pub token_calls: AtomicUsize,
    query_rows: Mutex<Vec<QueryLogEntry>>,
    query_log_error: Mutex<Option<BackendError>>,
    /// Parameters of the most recent `search_query_log` call.
    pub last_search: Mutex<Option<QueryLogSearch>>,
    /// Number of `search_query_log` calls.
    pub search_calls: AtomicUsize,
    query_detail: Mutex<Option<Result<QueryDetail, BackendError>>>,
    /// Id of the most recent `get_query` call.
    pub last_query_id: Mutex<Option<String>>,
    explain_result: Mutex<Option<Result<ExplainBlockResult, BackendError>>>,
    /// Arguments of the most recent `explain_block` call.
    pub last_explain: Mutex<Option<(String, Option<String>, QType)>>,
    test_query_result: Mutex<Option<Result<TestQueryResult, BackendError>>>,
    /// Parameters of the most recent `test_query` call.
    pub last_test_query: Mutex<Option<TestQueryParams>>,
    stats_result: Mutex<Option<Result<StatsResult, BackendError>>>,
    /// Parameters of the most recent `get_stats` call.
    pub last_stats: Mutex<Option<StatsParams>>,
    client_rows: Mutex<Vec<ClientInfo>>,
    client_error: Mutex<Option<BackendError>>,
    /// Parameters of the most recent `list_clients` call.
    pub last_clients: Mutex<Option<ClientListParams>>,
}

/// Decrements the active counter even when the tool future is cancelled.
struct ActiveGuard<'a>(&'a AtomicUsize);

impl Drop for ActiveGuard<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

impl MockBackend {
    /// A backend that accepts `token` and returns `status`.
    pub fn new(status: NodeStatus, token: TokenInfo) -> Self {
        let backend = Self::default();
        backend.set_status(Ok(status));
        backend.set_token(Ok(token));
        backend
    }

    /// Set the `get_status` result.
    pub fn set_status(&self, value: Result<NodeStatus, BackendError>) {
        if let Ok(mut slot) = self.status.lock() {
            *slot = Some(value);
        }
    }

    /// Set the `validate_token` result.
    pub fn set_token(&self, value: Result<TokenInfo, BackendError>) {
        if let Ok(mut slot) = self.token.lock() {
            *slot = Some(value);
        }
    }

    /// Make `get_status` wait on `gate` before returning.
    pub fn delay_status_until(&self, gate: Arc<Notify>) {
        if let Ok(mut slot) = self.status_delay.lock() {
            *slot = Some(gate);
        }
    }

    /// Number of `get_status` calls currently running (cancellation drops this).
    pub fn active_status_calls(&self) -> usize {
        self.status_active.load(Ordering::SeqCst)
    }

    /// Seed the rows returned by `search_query_log` (paginated by the mock).
    pub fn set_query_log(&self, rows: Vec<QueryLogEntry>) {
        *slot(&self.query_rows) = rows;
    }

    /// Make `search_query_log` fail with `error`.
    pub fn set_query_log_error(&self, error: BackendError) {
        *slot(&self.query_log_error) = Some(error);
    }

    /// Set the `get_query` result.
    pub fn set_query_detail(&self, value: Result<QueryDetail, BackendError>) {
        *slot(&self.query_detail) = Some(value);
    }

    /// Parameters of the most recent `search_query_log` call.
    pub fn last_search(&self) -> Option<QueryLogSearch> {
        slot(&self.last_search).clone()
    }

    /// Id of the most recent `get_query` call.
    pub fn last_query_id(&self) -> Option<String> {
        slot(&self.last_query_id).clone()
    }

    /// Set the `explain_block` result.
    pub fn set_explain(&self, value: Result<ExplainBlockResult, BackendError>) {
        *slot(&self.explain_result) = Some(value);
    }

    /// Arguments of the most recent `explain_block` call.
    pub fn last_explain(&self) -> Option<(String, Option<String>, QType)> {
        slot(&self.last_explain).clone()
    }

    /// Set the `test_query` result.
    pub fn set_test_query(&self, value: Result<TestQueryResult, BackendError>) {
        *slot(&self.test_query_result) = Some(value);
    }

    /// Parameters of the most recent `test_query` call.
    pub fn last_test_query(&self) -> Option<TestQueryParams> {
        slot(&self.last_test_query).clone()
    }

    /// Set the `get_stats` result.
    pub fn set_stats(&self, value: Result<StatsResult, BackendError>) {
        *slot(&self.stats_result) = Some(value);
    }

    /// Parameters of the most recent `get_stats` call.
    pub fn last_stats(&self) -> Option<StatsParams> {
        slot(&self.last_stats).clone()
    }

    /// Seed the rows returned by `list_clients` (paginated by the mock).
    pub fn set_clients(&self, rows: Vec<ClientInfo>) {
        *slot(&self.client_rows) = rows;
    }

    /// Make `list_clients` fail with `error`.
    pub fn set_clients_error(&self, error: BackendError) {
        *slot(&self.client_error) = Some(error);
    }

    /// Parameters of the most recent `list_clients` call.
    pub fn last_clients(&self) -> Option<ClientListParams> {
        slot(&self.last_clients).clone()
    }

    fn status_result(&self) -> Result<NodeStatus, BackendError> {
        match self.status.lock() {
            Ok(slot) => slot.clone().unwrap_or_else(|| Ok(NodeStatus::default())),
            Err(poisoned) => poisoned
                .into_inner()
                .clone()
                .unwrap_or_else(|| Ok(NodeStatus::default())),
        }
    }

    fn token_result(&self) -> Result<TokenInfo, BackendError> {
        match self.token.lock() {
            Ok(slot) => slot.clone().unwrap_or_else(|| {
                Ok(TokenInfo {
                    token_id: "tok-test".into(),
                    scope: TokenScope::McpWrite,
                    actor_id: "actor-test".into(),
                })
            }),
            Err(poisoned) => poisoned.into_inner().clone().unwrap_or_else(|| {
                Ok(TokenInfo {
                    token_id: "tok-test".into(),
                    scope: TokenScope::McpWrite,
                    actor_id: "actor-test".into(),
                })
            }),
        }
    }

    fn delay(&self) -> Option<Arc<Notify>> {
        match self.status_delay.lock() {
            Ok(slot) => slot.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }
}

#[async_trait::async_trait]
impl McpBackend for MockBackend {
    async fn validate_token(&self, _token: &str) -> Result<TokenInfo, BackendError> {
        self.token_calls.fetch_add(1, Ordering::SeqCst);
        self.token_result()
    }

    async fn search_query_log(
        &self,
        params: QueryLogSearch,
    ) -> Result<QueryLogResult, BackendError> {
        *slot(&self.last_search) = Some(params.clone());
        self.search_calls.fetch_add(1, Ordering::SeqCst);
        if let Some(error) = slot(&self.query_log_error).clone() {
            return Err(error);
        }
        let rows = slot(&self.query_rows);
        let queries: Vec<QueryLogEntry> = rows
            .iter()
            .skip(params.offset as usize)
            .take(params.limit as usize)
            .cloned()
            .collect();
        let next = params.offset.saturating_add(queries.len() as u32);
        let has_more = (next as usize) < rows.len();
        Ok(QueryLogResult {
            queries,
            has_more,
            next_offset: has_more.then_some(next),
        })
    }

    async fn get_query(&self, id: &str) -> Result<QueryDetail, BackendError> {
        *slot(&self.last_query_id) = Some(id.to_owned());
        slot(&self.query_detail)
            .clone()
            .unwrap_or_else(|| Ok(QueryDetail::default()))
    }

    async fn explain_block(
        &self,
        domain: &str,
        profile_id: Option<&str>,
        qtype: QType,
    ) -> Result<ExplainBlockResult, BackendError> {
        *slot(&self.last_explain) = Some((domain.to_owned(), profile_id.map(str::to_owned), qtype));
        slot(&self.explain_result)
            .clone()
            .unwrap_or_else(|| Ok(ExplainBlockResult::default()))
    }

    async fn test_query(&self, params: TestQueryParams) -> Result<TestQueryResult, BackendError> {
        *slot(&self.last_test_query) = Some(params);
        slot(&self.test_query_result)
            .clone()
            .unwrap_or_else(|| Ok(TestQueryResult::default()))
    }

    async fn get_stats(&self, params: StatsParams) -> Result<StatsResult, BackendError> {
        *slot(&self.last_stats) = Some(params);
        slot(&self.stats_result)
            .clone()
            .unwrap_or_else(|| Ok(StatsResult::default()))
    }

    async fn list_clients(
        &self,
        params: ClientListParams,
    ) -> Result<ClientListResult, BackendError> {
        *slot(&self.last_clients) = Some(params.clone());
        if let Some(error) = slot(&self.client_error).clone() {
            return Err(error);
        }
        let rows = slot(&self.client_rows);
        let clients: Vec<ClientInfo> = rows
            .iter()
            .skip(params.offset as usize)
            .take(params.limit as usize)
            .cloned()
            .collect();
        let next = params.offset.saturating_add(clients.len() as u32);
        let has_more = (next as usize) < rows.len();
        Ok(ClientListResult {
            clients,
            has_more,
            next_offset: has_more.then_some(next),
        })
    }

    async fn get_status(&self) -> Result<NodeStatus, BackendError> {
        self.status_calls.fetch_add(1, Ordering::SeqCst);
        self.status_active.fetch_add(1, Ordering::SeqCst);
        let _guard = ActiveGuard(&self.status_active);
        if let Some(gate) = self.delay() {
            gate.notified().await;
        }
        self.status_result()
    }

    async fn list_mcp_rules(
        &self,
        _params: ListRulesParams,
    ) -> Result<ListRulesResult, BackendError> {
        Ok(ListRulesResult::default())
    }

    async fn allow_temporarily(
        &self,
        _params: TempAllowParams,
    ) -> Result<TempAllowResult, BackendError> {
        Ok(TempAllowResult::default())
    }

    async fn add_custom_rule(&self, _params: AddRuleParams) -> Result<AddRuleResult, BackendError> {
        Ok(AddRuleResult::default())
    }

    async fn remove_custom_rule(
        &self,
        _params: RemoveRuleParams,
    ) -> Result<RemoveRuleResult, BackendError> {
        Ok(RemoveRuleResult::default())
    }

    async fn pause_filter_set(
        &self,
        _filter_set_id: &str,
        _duration: PauseDuration,
    ) -> Result<PauseResult, BackendError> {
        Ok(PauseResult::default())
    }

    async fn resume_filter_set(&self, _filter_set_id: &str) -> Result<ResumeResult, BackendError> {
        Ok(ResumeResult::default())
    }

    async fn record_audit(&self, _entry: AuditEntry) -> Result<(), BackendError> {
        Ok(())
    }
}

/// A write-scope token used by most tests.
pub fn write_token() -> TokenInfo {
    TokenInfo {
        token_id: "tok-write".into(),
        scope: TokenScope::McpWrite,
        actor_id: "actor".into(),
    }
}

/// A read-scope token.
pub fn read_token() -> TokenInfo {
    TokenInfo {
        token_id: "tok-read".into(),
        scope: TokenScope::McpRead,
        actor_id: "actor".into(),
    }
}

/// Real-HTTP harness shared by the read-tool tests.
pub mod harness {
    use std::net::SocketAddr;
    use std::sync::{Arc, Once};

    use axum::Router;
    use dnscraft_mcp::{McpConfig, TokenInfo};
    use serde_json::{Value, json};

    use super::MockBackend;

    /// Protocol revision sent by every request.
    pub const VERSION: &str = "2026-07-28";
    /// Raw bearer token used by every request.
    pub const TOKEN: &str = "test-token";

    fn install_crypto() {
        static ONCE: Once = Once::new();
        ONCE.call_once(|| {
            let _ = rustls::crypto::ring::default_provider().install_default();
        });
    }

    /// A running server and its backend.
    pub struct TestServer {
        /// Endpoint URL.
        pub url: String,
        /// The shared mock backend.
        pub backend: Arc<MockBackend>,
    }

    /// Spawn a server with `config` that accepts `token`.
    pub async fn spawn_with(config: McpConfig, token: TokenInfo) -> TestServer {
        install_crypto();
        let backend = Arc::new(MockBackend::default());
        backend.set_token(Ok(token));
        let router =
            Router::new().nest_service("/mcp/v1", dnscraft_mcp::service(backend.clone(), config));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address: SocketAddr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        TestServer {
            url: format!("http://{address}/mcp/v1"),
            backend,
        }
    }

    /// Spawn a default-config server with a read-scope token.
    pub async fn spawn(config: McpConfig) -> TestServer {
        spawn_with(config, super::read_token()).await
    }

    fn meta() -> Value {
        json!({
            "io.modelcontextprotocol/protocolVersion": VERSION,
            "io.modelcontextprotocol/clientCapabilities": {},
        })
    }

    async fn call(
        client: &reqwest::Client,
        url: &str,
        method: &str,
        name: Option<&str>,
        mut params: Value,
    ) -> (reqwest::StatusCode, Value) {
        if let Value::Object(map) = &mut params {
            map.insert("_meta".into(), meta());
        }
        let mut request = client
            .post(url)
            .header("Content-Type", "application/json")
            .header("Accept", "application/json, text/event-stream")
            .header("MCP-Protocol-Version", VERSION)
            .header("Mcp-Method", method)
            .header("Authorization", format!("Bearer {TOKEN}"))
            .body(
                json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params })
                    .to_string(),
            );
        if let Some(name) = name {
            request = request.header("Mcp-Name", name);
        }
        let response = request.send().await.expect("request should be sent");
        let status = response.status();
        let text = response.text().await.expect("response should have a body");
        (status, serde_json::from_str(&text).unwrap_or(Value::Null))
    }

    /// Call a tool and return the HTTP status and JSON-RPC body.
    pub async fn tool_call(
        client: &reqwest::Client,
        server: &TestServer,
        name: &str,
        arguments: Value,
    ) -> (reqwest::StatusCode, Value) {
        call(
            client,
            &server.url,
            "tools/call",
            Some(name),
            json!({ "name": name, "arguments": arguments }),
        )
        .await
    }

    /// List the tools the server exposes.
    pub async fn list_tools(client: &reqwest::Client, server: &TestServer) -> Value {
        let (_, body) = call(client, &server.url, "tools/list", None, json!({})).await;
        body
    }

    /// Parse the JSON payload carried by a successful tool result.
    pub fn tool_output(body: &Value) -> Value {
        let text = body["result"]["content"][0]["text"]
            .as_str()
            .expect("tool content should be one text item");
        serde_json::from_str(text).expect("tool text should be JSON")
    }

    /// The stable code of a failed tool call.
    pub fn error_code(body: &Value) -> &str {
        body["result"]["structuredContent"]["error"]["code"]
            .as_str()
            .expect("tool error should carry a code")
    }
}
