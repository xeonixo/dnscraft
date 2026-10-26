//! Shared test backend.
//!
//! An in-memory [`McpBackend`] whose success/error responses and blocking
//! behaviour are configurable per test. It never touches the network.

#![allow(dead_code)]

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use dnscraft_mcp::backend::{BackendError, McpBackend};
use dnscraft_mcp::dto::{
    AddRuleParams, AddRuleResult, AuditEntry, ClientListParams, ClientListResult,
    ExplainBlockResult, ListRulesParams, ListRulesResult, NodeStatus, PauseDuration, PauseResult,
    QType, QueryDetail, QueryLogResult, QueryLogSearch, RemoveRuleParams, RemoveRuleResult,
    ResumeResult, StatsParams, StatsResult, TempAllowParams, TempAllowResult, TestQueryParams,
    TestQueryResult, TokenInfo, TokenScope,
};
use tokio::sync::Notify;

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
        _params: QueryLogSearch,
    ) -> Result<QueryLogResult, BackendError> {
        Ok(QueryLogResult::default())
    }

    async fn get_query(&self, _id: &str) -> Result<QueryDetail, BackendError> {
        Ok(QueryDetail::default())
    }

    async fn explain_block(
        &self,
        _domain: &str,
        _profile_id: Option<&str>,
        _qtype: QType,
    ) -> Result<ExplainBlockResult, BackendError> {
        Ok(ExplainBlockResult::default())
    }

    async fn test_query(&self, _params: TestQueryParams) -> Result<TestQueryResult, BackendError> {
        Ok(TestQueryResult::default())
    }

    async fn get_stats(&self, _params: StatsParams) -> Result<StatsResult, BackendError> {
        Ok(StatsResult::default())
    }

    async fn list_clients(
        &self,
        _params: ClientListParams,
    ) -> Result<ClientListResult, BackendError> {
        Ok(ClientListResult::default())
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
