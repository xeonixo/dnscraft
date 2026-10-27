//! Control API for DNScraft (config, query log, statistics, audit, auth).
//!
//! This crate owns the internal-only HTTP API that configures DNScraft, exposes
//! the query log and statistics, records an audit trail, and authenticates
//! callers (OIDC, local break-glass login, and API bearer tokens). It does not
//! decide which DNS answers are produced; it calls the policy, clients,
//! listeners, resolver and tls module APIs and persists their configuration as
//! typed values.
//!
//! A0: crate skeleton, config model, error type.
//! A1: SQLite storage and migrations.
//! A2: config snapshot/version store + audit log with secret redaction.
//! A3: HTTP server core — router, envelopes, pagination.
//! A4: internal-only bind + TLS bootstrap (self-signed → ACME handover).
//! (Further tasks are listed in `tasks/archive/todo-control-api.md`.)

#![deny(missing_docs)]

mod api;
mod audit;
mod clock;
mod cluster;
mod cluster_status;
mod config;
mod config_apply;
mod error;
mod mcp_backend;
mod modules;
mod notifications;
mod protected_list;
mod query_log;
mod secret;
mod server;
mod stats;
mod storage;
mod tls;

pub use api::auth::{
    ActorType, Auth, AuthSnapshot, AuthState, Authenticated, CreatedSession, CreatedToken,
    EndpointFamily, LocalAccountSnapshot, LocalAccountStore, OidcSettings, OidcState, Principal,
    Requirement, Role, Scope, SessionStore, TokenPrincipal, TokenSnapshot, TokenStore,
    auth_middleware, authorize, rbac_middleware, requirement, secure_cookie, session_set_cookie,
};
pub use api::rate_limit::{DEFAULT_MAX_TRACKED_SOURCES, RateLimiter};
pub use audit::{Audit, ConfigChangeRecord};
pub use clock::{Clock, ManualClock, SystemClock};
pub use cluster::{
    ClusterRuntime, ClusterRuntimeOptions, ConfigWriteExecutor, QueryLogIngest, QueryLogOutbox,
    StateAuthApplier, StateRuntimeApplier, SyncedConfigApplier, TlsCertInstaller, backfill_logs,
    node_scoped_views,
};
pub use cluster_status::{ClusterStatus, ClusterStatusHandle, ClusterStatusProvider};
pub use config::{
    AuthConfig, ControlApiConfig, DEFAULT_API_TOKEN_MAX_TTL, DEFAULT_AUTH_PER_SECOND, DEFAULT_BIND,
    DEFAULT_BURST_FACTOR, DEFAULT_LOCAL_LOGIN_LOCK_WINDOW, DEFAULT_LOCAL_LOGIN_MAX_ATTEMPTS,
    DEFAULT_MAX_ROWS_PER_REQUEST, DEFAULT_OIDC_TOKEN_SKEW, DEFAULT_PORT, DEFAULT_READ_PER_SECOND,
    DEFAULT_RETENTION_DAYS, DEFAULT_SESSION_ABSOLUTE_TIMEOUT, DEFAULT_SESSION_IDLE_TIMEOUT,
    DEFAULT_WRITE_PER_SECOND, IpTruncate, QueryLogConfig, RateLimitConfig,
};
pub use config_apply::{ConfigActor, ConfigService, RollbackOutcome, SharedConfigService};
pub use dnscraft_cluster::{ClusterStore, OfflineWriteQueue};
pub use error::ControlApiError;
pub use mcp_backend::{McpBackendInner, mcp_backend_inner};
#[doc(hidden)]
pub use mcp_backend::{
    mcp_backend_for_test, mcp_backend_for_test_writes, mcp_backend_for_test_writes_with_broadcast,
};
pub use modules::{
    ApplyClients, ApplyFiltering, ApplyListeners, ApplyPolicy, ApplyTls, ModuleAppliers,
    ModuleFuture,
};
pub use protected_list::{derive_protected_domains, populate_mcp_protected_domains};
pub use query_log::{
    ClientEnricher, ClientView, Order, OrderBy, QueryLog, QueryLogFilter, QueryLogPage,
    QueryLogSink,
};
pub use secret::Secret;
pub use server::{AppState, Readiness, serve};
pub use stats::{
    CacheStats, ROLLUP_RETENTION_DAYS, RollupRow, RollupWindow, StatsOverview, TOP_CLIENTS_MAX,
    TOP_DOMAINS_MAX, TopBy, TopClient, TopClients, TopDomain, TopDomains,
};
pub use storage::{AuditRecord, ConfigStore, Db};
pub use tls::{
    AriStatus, CertSource, ControlApiTls, EngineStatusProvider, EngineTlsAdmin, IssueOutcome,
    IssueRecord, StoreHealth, TlsActionFuture, TlsAdmin, TlsMode, TlsStatus, TlsStatusFuture,
    TlsStatusProvider, TlsValueFuture,
};
