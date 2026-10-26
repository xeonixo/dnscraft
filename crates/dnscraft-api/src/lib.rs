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
//! (Further tasks are listed in `tasks/todo-control-api.md`.)

#![deny(missing_docs)]

mod api;
mod audit;
mod clock;
mod config;
mod error;
mod secret;
mod server;
mod storage;
mod tls;

pub use api::auth::{
    Auth, AuthState, Authenticated, CreatedSession, CreatedToken, EndpointFamily,
    LocalAccountStore, Principal, Role, Scope, SessionStore, TokenPrincipal, TokenStore,
    auth_middleware, rbac_middleware, secure_cookie, session_set_cookie,
};
pub use api::rate_limit::{DEFAULT_MAX_TRACKED_SOURCES, RateLimiter};
pub use audit::{Audit, ConfigChangeRecord};
pub use clock::{Clock, ManualClock, SystemClock};
pub use config::{
    AuthConfig, ControlApiConfig, DEFAULT_API_TOKEN_MAX_TTL, DEFAULT_AUTH_PER_SECOND, DEFAULT_BIND,
    DEFAULT_BURST_FACTOR, DEFAULT_LOCAL_LOGIN_LOCK_WINDOW, DEFAULT_LOCAL_LOGIN_MAX_ATTEMPTS,
    DEFAULT_MAX_ROWS_PER_REQUEST, DEFAULT_OIDC_TOKEN_SKEW, DEFAULT_PORT, DEFAULT_READ_PER_SECOND,
    DEFAULT_RETENTION_DAYS, DEFAULT_SESSION_ABSOLUTE_TIMEOUT, DEFAULT_SESSION_IDLE_TIMEOUT,
    DEFAULT_WRITE_PER_SECOND, IpTruncate, QueryLogConfig, RateLimitConfig,
};
pub use error::ControlApiError;
pub use secret::Secret;
pub use server::{AppState, Readiness, serve};
pub use storage::{AuditRecord, ConfigStore, Db};
pub use tls::{ControlApiTls, TlsMode, TlsStatus, TlsStatusProvider};
