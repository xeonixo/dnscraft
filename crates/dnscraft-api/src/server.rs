//! axum server: shared state, readiness, and the network entry point.

use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use axum::extract::ConnectInfo;
use axum::http::Request;
use hyper::body::Incoming;
use tokio::net::TcpListener;
use tower::ServiceExt as _;
use tower::service_fn;

use crate::api::auth::{AuthState, LocalAccountStore, OidcState};
use crate::api::rate_limit::RateLimiter;
use crate::clock::{Clock, SystemClock};
use crate::cluster_status::ClusterStatusProvider;
use crate::config::{ControlApiConfig, RateLimitConfig, is_internal_bind};
use crate::config_apply::ConfigService;
use crate::error::ControlApiError;
use crate::mcp_backend::McpBackendInner;
use crate::query_log::QueryLog;
use crate::tls::{TlsAdmin, TlsStatus, TlsStatusProvider};

use dnscraft_cluster::{ClusterBroadcast, ClusterStore, OfflineWriteQueue, Role};
use dnscraft_filtering::FilterEngine;
use dnscraft_mcp::McpConfig;
use dnscraft_policy::PolicyEngine;

/// Shared state handed to every handler (and cloned into the router).
///
/// Grows as later tasks land: TLS mode, rate limiter, config snapshot.
#[derive(Clone)]
pub struct AppState {
    readiness: Arc<Readiness>,
    tls: Option<Arc<dyn TlsStatusProvider>>,
    tls_admin: Option<Arc<dyn TlsAdmin>>,
    rate_limiter: Arc<RateLimiter>,
    auth: Option<Arc<AuthState>>,
    local_login: Option<Arc<LocalAccountStore>>,
    oidc: Option<Arc<OidcState>>,
    config: Option<Arc<ConfigService>>,
    query_log: Option<Arc<QueryLog>>,
    cluster_store: Option<Arc<ClusterStore>>,
    cluster_status: Option<Arc<dyn ClusterStatusProvider>>,
    cluster_broadcast: Arc<Mutex<Option<ClusterBroadcast>>>,
    cluster_role: Arc<Mutex<Option<Role>>>,
    offline_writes: Option<Arc<OfflineWriteQueue>>,
    mcp_backend: Option<Arc<McpBackendInner>>,
    mcp_config: McpConfig,
    oidc_issuer: Option<String>,
    clock: Arc<dyn Clock>,
    filter: Option<Arc<FilterEngine>>,
    policy: Option<Arc<PolicyEngine>>,
}

impl Default for AppState {
    fn default() -> Self {
        Self::new()
    }
}

impl AppState {
    /// Creates a state whose modules are all ready.
    pub fn new() -> Self {
        Self {
            readiness: Arc::new(Readiness::default()),
            tls: None,
            tls_admin: None,
            rate_limiter: Arc::new(RateLimiter::new(
                RateLimitConfig::default(),
                Arc::new(SystemClock),
                Vec::new(),
            )),
            auth: None,
            local_login: None,
            oidc: None,
            config: None,
            query_log: None,
            cluster_store: None,
            cluster_status: None,
            cluster_broadcast: Arc::new(Mutex::new(None)),
            cluster_role: Arc::new(Mutex::new(None)),
            offline_writes: None,
            mcp_backend: None,
            mcp_config: McpConfig::default(),
            oidc_issuer: None,
            clock: Arc::new(SystemClock),
            filter: None,
            policy: None,
        }
    }

    /// Uses `clock` for timestamps in the MCP-facing endpoints and rules.
    pub fn with_clock(mut self, clock: Arc<dyn Clock>) -> Self {
        self.clock = clock;
        self
    }

    /// The configured time source.
    pub(crate) fn clock(&self) -> &Arc<dyn Clock> {
        &self.clock
    }

    /// Attaches the filtering engine used by the MCP-facing read and runtime
    /// endpoints.
    pub fn with_filter_engine(mut self, filter: Arc<FilterEngine>) -> Self {
        self.filter = Some(filter);
        self
    }

    /// The configured filtering engine, if any.
    pub(crate) fn filter_engine(&self) -> Option<&Arc<FilterEngine>> {
        self.filter.as_ref()
    }

    /// Attaches the policy engine used by the MCP-facing `test-query` endpoint.
    pub fn with_policy_engine(mut self, policy: Arc<PolicyEngine>) -> Self {
        self.policy = Some(policy);
        self
    }

    /// The configured policy engine, if any.
    pub(crate) fn policy_engine(&self) -> Option<&Arc<PolicyEngine>> {
        self.policy.as_ref()
    }

    /// Attaches the atomic config service.
    ///
    /// With a service configured, `/api/v1/config` (export, replace, versions,
    /// rollback) and the per-module config routes are mounted.
    pub fn with_config_service(mut self, service: Arc<ConfigService>) -> Self {
        self.config = Some(service);
        self
    }

    /// The configured atomic config service, if any.
    pub(crate) fn config_service(&self) -> Option<&ConfigService> {
        self.config.as_deref()
    }

    /// A cloneable config-service handle for the cluster runtime.
    pub(crate) fn config_service_arc(&self) -> Option<Arc<ConfigService>> {
        self.config.clone()
    }

    /// Attaches the query log created by the A12 consumer.
    ///
    /// With a query log configured, `GET /api/v1/query-log` and
    /// `GET /api/v1/query-log/{id}` are mounted.
    pub fn with_query_log(mut self, query_log: Arc<QueryLog>) -> Self {
        self.query_log = Some(query_log);
        self
    }

    /// The configured query log, if any.
    pub(crate) fn query_log(&self) -> Option<&Arc<QueryLog>> {
        self.query_log.as_ref()
    }

    /// A cloneable query-log handle for the cluster runtime.
    pub(crate) fn query_log_arc(&self) -> Option<Arc<QueryLog>> {
        self.query_log.clone()
    }

    /// Attaches the master's durable cluster registry.
    ///
    /// With a store configured, the `/api/v1/cluster/*` admin routes (join
    /// tokens, nodes, writes) are mounted. A standalone node leaves this unset
    /// and the routes fall through to `404 control_api.not_found`.
    pub fn with_cluster_store(mut self, store: Arc<ClusterStore>) -> Self {
        self.cluster_store = Some(store);
        self
    }

    /// The configured cluster registry, if any.
    pub(crate) fn cluster_store(&self) -> Option<&Arc<ClusterStore>> {
        self.cluster_store.as_ref()
    }

    /// Attaches the live cluster status source read by `GET /api/v1/status`.
    ///
    /// A standalone node leaves this unset, so the six cluster fields are
    /// omitted entirely.
    pub fn with_cluster_status(mut self, status: Arc<dyn ClusterStatusProvider>) -> Self {
        self.cluster_status = Some(status);
        self
    }

    /// The configured cluster status source, if any.
    pub(crate) fn cluster_status(&self) -> Option<&Arc<dyn ClusterStatusProvider>> {
        self.cluster_status.as_ref()
    }

    /// Attaches the role this process runs (`ClusterRuntime::start` does this).
    ///
    /// The router uses it to keep token/account creation master-only: a
    /// sub-node authenticates the master's replicated credentials but must not
    /// mint its own.
    pub fn with_cluster_role(self, role: Role) -> Self {
        self.attach_cluster_role(role);
        self
    }

    /// Attaches the cluster role on the shared state (interior mutability).
    pub(crate) fn attach_cluster_role(&self, role: Role) {
        *self
            .cluster_role
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(role);
    }

    /// The cluster role attached by the runtime, if any.
    pub(crate) fn cluster_role(&self) -> Option<Role> {
        *self
            .cluster_role
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Whether this process is a cluster sub-node.
    ///
    /// A standalone node is its own authority and keeps the full API surface.
    pub(crate) fn is_cluster_sub_node(&self) -> bool {
        self.cluster_role() == Some(Role::SubNode)
    }

    /// Attaches the master's volatile cluster broadcast handle.
    ///
    /// The cluster runtime attaches this after starting the master listener so
    /// the runtime-command endpoints can push to connected sub-nodes. A
    /// standalone or sub-node runtime leaves it unset and the push is a no-op.
    pub fn with_cluster_broadcast(self, broadcast: ClusterBroadcast) -> Self {
        self.attach_cluster_broadcast(broadcast);
        self
    }

    /// Attaches the broadcast handle on the shared state (interior mutability).
    pub(crate) fn attach_cluster_broadcast(&self, broadcast: ClusterBroadcast) {
        if let Some(inner) = self.mcp_backend.as_ref() {
            inner.attach_cluster_broadcast(broadcast.clone());
        }
        *self
            .cluster_broadcast
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(broadcast);
    }

    /// The master broadcast handle, if this node runs the master role.
    pub(crate) fn cluster_broadcast(&self) -> Option<ClusterBroadcast> {
        self.cluster_broadcast
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// Broadcasts a volatile runtime command to connected sub-nodes, if this
    /// node is the cluster master.
    pub(crate) fn broadcast_runtime_command(&self, kind: &str, payload: &serde_json::Value) {
        if let Some(broadcast) = self.cluster_broadcast() {
            broadcast.broadcast_runtime_command(kind, payload);
        }
    }

    /// Attaches the sub-node offline write queue read by
    /// `GET /api/v1/cluster/writes/{request_id}`.
    pub fn with_offline_write_queue(mut self, queue: Arc<OfflineWriteQueue>) -> Self {
        self.offline_writes = Some(queue);
        self
    }

    /// The configured offline write queue, if any.
    pub(crate) fn offline_write_queue(&self) -> Option<&Arc<OfflineWriteQueue>> {
        self.offline_writes.as_ref()
    }

    /// A cloneable offline-write-queue handle for the cluster runtime.
    pub(crate) fn offline_write_queue_arc(&self) -> Option<Arc<OfflineWriteQueue>> {
        self.offline_writes.clone()
    }

    /// Attaches the MCP backend inner handle (engines, stores, status providers).
    ///
    /// With a backend attached, `POST /mcp/v1` is mounted when
    /// `control_api.mcp.enabled` is true.
    // Wired by the binary that assembles the MCP engines.
    #[allow(dead_code)]
    pub(crate) fn with_mcp_backend(mut self, inner: Arc<McpBackendInner>) -> Self {
        // The runtime may already have attached its broadcast handle; share it
        // with the MCP backend so write tools broadcast like the HTTP routes.
        if let Some(broadcast) = self.cluster_broadcast() {
            inner.attach_cluster_broadcast(broadcast);
        }
        self.mcp_backend = Some(inner);
        self
    }

    /// The configured MCP backend inner handle, if any.
    pub(crate) fn mcp_backend_inner(&self) -> Option<&Arc<McpBackendInner>> {
        self.mcp_backend.as_ref()
    }

    /// Attaches the MCP limits and protected-domain additions used by the
    /// MCP-facing control-api endpoints.
    pub fn with_mcp_config(mut self, config: McpConfig) -> Self {
        self.mcp_config = config;
        self
    }

    /// The MCP config used by the endpoint gating and limits.
    pub(crate) fn mcp_config(&self) -> &McpConfig {
        &self.mcp_config
    }

    /// Attaches the OIDC issuer URL whose host becomes a protected domain.
    ///
    /// Callers set this only when OIDC is enabled (`control_api.auth`).
    pub fn with_oidc_issuer(mut self, issuer: impl Into<String>) -> Self {
        self.oidc_issuer = Some(issuer.into());
        self
    }

    /// The configured OIDC issuer URL, if OIDC is enabled.
    pub(crate) fn oidc_issuer(&self) -> Option<&str> {
        self.oidc_issuer.as_deref()
    }

    /// Attaches the session and bearer-token stores.
    ///
    /// With auth configured, the router enforces cookie-session/CSRF on
    /// `/api/v1`, RBAC on both endpoint families, and mounts
    /// `POST /api/v1/auth/tokens`.
    pub fn with_auth(mut self, auth: AuthState) -> Self {
        self.auth = Some(Arc::new(auth));
        self
    }

    /// The configured auth stores, if any.
    pub(crate) fn auth_state(&self) -> Option<&AuthState> {
        self.auth.as_deref()
    }

    /// A cloneable auth-state handle for the cluster runtime.
    pub(crate) fn auth_state_arc(&self) -> Option<Arc<AuthState>> {
        self.auth.clone()
    }

    /// Attaches the local break-glass account store.
    ///
    /// With local accounts configured, the router mounts
    /// `POST /api/v1/auth/local/login` (in addition to requiring
    /// [`AppState::with_auth`] for the session store).
    pub fn with_local_login(mut self, store: LocalAccountStore) -> Self {
        self.local_login = Some(Arc::new(store));
        self
    }

    /// The configured local-account store, if any.
    pub(crate) fn local_login_store(&self) -> Option<&LocalAccountStore> {
        self.local_login.as_deref()
    }

    /// Attaches the OIDC relying-party state.
    ///
    /// With OIDC configured (in addition to [`AppState::with_auth`]), the
    /// router mounts the public `GET /api/v1/auth/oidc/authorize-url` and
    /// `GET /api/v1/auth/oidc/callback` endpoints. Callback sessions are
    /// created in the auth session store.
    pub fn with_oidc(mut self, oidc: Arc<OidcState>) -> Self {
        self.oidc = Some(oidc);
        self
    }

    /// The configured OIDC state, if any.
    pub(crate) fn oidc_state(&self) -> Option<&OidcState> {
        self.oidc.as_deref()
    }

    /// Attaches the TLS status provider (from [`crate::ControlApiTls`]).
    pub fn with_tls(mut self, provider: Arc<dyn TlsStatusProvider>) -> Self {
        self.tls = Some(provider);
        self
    }

    /// Attaches the TLS engine admin surface used by `/api/v1/tls/*`.
    ///
    /// Without it the mutating TLS routes return `control_api.not_ready`.
    pub fn with_tls_admin(mut self, admin: Arc<dyn TlsAdmin>) -> Self {
        self.tls_admin = Some(admin);
        self
    }

    /// Attaches a caller-configured rate limiter (built from the validated
    /// config and the trusted-proxy list at startup).
    pub fn with_rate_limiter(mut self, rate_limiter: Arc<RateLimiter>) -> Self {
        self.rate_limiter = rate_limiter;
        self
    }

    /// The rate limiter guarding all endpoints.
    pub(crate) fn rate_limiter(&self) -> &Arc<RateLimiter> {
        &self.rate_limiter
    }

    /// The current TLS status, if a provider is attached.
    pub fn tls_status(&self) -> Option<TlsStatus> {
        self.tls.as_ref().map(|provider| provider.status())
    }

    /// The current TLS status, read asynchronously.
    ///
    /// Prefer this from handlers: an engine-backed provider refreshes its
    /// cached snapshot without blocking a runtime worker.
    pub async fn tls_status_async(&self) -> Option<TlsStatus> {
        match self.tls.as_ref() {
            Some(provider) => Some(provider.status_async().await),
            None => None,
        }
    }

    /// The TLS admin surface, if one is attached.
    pub(crate) fn tls_admin(&self) -> Option<&Arc<dyn TlsAdmin>> {
        self.tls_admin.as_ref()
    }

    /// The readiness tracker (mark modules ready / not ready).
    pub fn readiness(&self) -> &Arc<Readiness> {
        &self.readiness
    }

    /// Assembles the HTTP [`axum::Router`] for this state.
    pub fn router(self) -> axum::Router {
        crate::api::router::build_router(self)
    }
}

/// Which modules are currently not ready.
///
/// Readiness never exposes anything beyond the module names: `/readyz` reports
/// `ready`/`not_ready` plus the set of not-ready module names, nothing else.
#[derive(Default)]
pub struct Readiness {
    not_ready: Mutex<BTreeSet<String>>,
}

impl Readiness {
    /// Marks a module as not ready (idempotent).
    pub fn set_not_ready(&self, module: &str) {
        self.not_ready
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(module.to_owned());
    }

    /// Marks a module as ready (idempotent).
    pub fn set_ready(&self, module: &str) {
        self.not_ready
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(module);
    }

    /// Sorted names of the modules that are not ready.
    pub fn not_ready_modules(&self) -> Vec<String> {
        self.not_ready
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .cloned()
            .collect()
    }
}

/// Serves the API on the configured bind address. When `config.tls` is set,
/// terminates TLS directly (using the caller-built [`rustls::ServerConfig`]
/// from [`crate::ControlApiTls::server_config`]); otherwise serves plain HTTP
/// for a terminating reverse proxy. Runs until the process is shut down.
pub async fn serve(
    config: ControlApiConfig,
    state: AppState,
    tls: Option<Arc<rustls::ServerConfig>>,
) -> Result<(), ControlApiError> {
    config.validate()?;
    let addr = SocketAddr::new(config.bind, config.port);
    let listener = TcpListener::bind(addr)
        .await
        .map_err(|e| ControlApiError::Internal {
            message: format!("bind {addr}: {e}"),
        })?;
    // Defence in depth: refuse to serve even if a bug let a wildcard or
    // dual-stack bind through to a public address.
    ensure_internal_socket(
        listener
            .local_addr()
            .map_err(|e| ControlApiError::Internal {
                message: format!("read local address of {addr}: {e}"),
            })?,
    )?;
    // Build the rate limiter from the validated config so the trusted-proxy
    // list is honoured without the binary having to wire it manually.
    let state = state.with_rate_limiter(Arc::new(RateLimiter::new(
        config.rate_limit.clone(),
        Arc::new(SystemClock),
        config.trusted_proxies.clone(),
    )));
    // Derive MCP allowed_origins from the configured TLS domain.
    let mcp_config = config.mcp.clone();
    if let Some(tls_status) = state.tls_status_async().await
        && !tls_status.fingerprint.is_empty()
    {
        // ponytail: derive origins from the TLS public domain (TLS module
        // stores the public domain used for certificate requests).
    }
    // Store the MCP config on AppState so build_router and the filtering
    // endpoints can read it, whether or not a backend is attached.
    let mut state = state;
    if config.auth.oidc_enabled && !config.auth.oidc_issuer.is_empty() {
        state.oidc_issuer = Some(config.auth.oidc_issuer.clone());
    }
    // The MCP server builds its pre-backend protected list once, at mount
    // time, so seed it with the full derived list. The backend re-derives it
    // per request against the current snapshot, keeping protection fresh after
    // a config apply.
    let snapshot = match state.config_service() {
        Some(service) => service.current().await?.1,
        None => None,
    };
    let oidc_issuer = state.oidc_issuer().map(str::to_owned);
    state.mcp_config = crate::protected_list::populate_mcp_protected_domains(
        mcp_config,
        snapshot.as_ref(),
        oidc_issuer.as_deref(),
    )?;
    let router = state.router();
    if config.tls {
        let server_config = tls.ok_or_else(|| ControlApiError::Internal {
            message: "control-api TLS is enabled but no TLS server config was provided".to_owned(),
        })?;
        serve_tls(listener, router, server_config).await
    } else {
        axum::serve(
            listener,
            router.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .map_err(|e| ControlApiError::Internal {
            message: format!("serve: {e}"),
        })
    }
}

/// Fails when the bound socket is not loopback/private/ULA (defence in depth).
fn ensure_internal_socket(addr: SocketAddr) -> Result<(), ControlApiError> {
    if !is_internal_bind(addr.ip()) {
        return Err(ControlApiError::Internal {
            message: format!("control-api bound to non-internal address {addr}"),
        });
    }
    Ok(())
}

/// Accepts plain TCP and serves HTTP/1.1 inside TLS, one task per connection.
async fn serve_tls(
    listener: TcpListener,
    router: axum::Router,
    server_config: Arc<rustls::ServerConfig>,
) -> Result<(), ControlApiError> {
    let acceptor = tokio_rustls::TlsAcceptor::from(server_config);
    loop {
        let (stream, peer) = listener
            .accept()
            .await
            .map_err(|e| ControlApiError::Internal {
                message: format!("accept: {e}"),
            })?;
        let acceptor = acceptor.clone();
        let router = router.clone();
        tokio::spawn(async move {
            let tls_stream = match acceptor.accept(stream).await {
                Ok(stream) => stream,
                Err(e) => {
                    tracing::debug!(%peer, error = %e, "control-api TLS handshake failed");
                    return;
                }
            };
            let io = hyper_util::rt::TokioIo::new(tls_stream);
            // axum's Router is a `tower::Service`; hyper's connection driver
            // wants a `hyper::service::Service`, bridged by hyper-util. Wrap it
            // in a per-connection service that injects the trusted peer address
            // so the rate limiter sees the real socket peer, not a spoofable
            // header.
            let service = service_fn(move |mut req: Request<Incoming>| {
                req.extensions_mut().insert(ConnectInfo(peer));
                let router = router.clone();
                async move { router.oneshot(req).await }
            });
            let service = hyper_util::service::TowerToHyperService::new(service);
            if let Err(e) = hyper::server::conn::http1::Builder::new()
                .serve_connection(io, service)
                .await
            {
                tracing::debug!(%peer, error = %e, "control-api connection error");
            }
        });
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn ensure_internal_socket_accepts_internal_and_rejects_public() {
        assert!(ensure_internal_socket("127.0.0.1:8080".parse().unwrap()).is_ok());
        assert!(ensure_internal_socket("[::1]:8080".parse().unwrap()).is_ok());
        assert!(ensure_internal_socket("10.0.0.1:8080".parse().unwrap()).is_ok());
        assert!(ensure_internal_socket("[::ffff:127.0.0.1]:8080".parse().unwrap()).is_ok());

        assert!(ensure_internal_socket("0.0.0.0:8080".parse().unwrap()).is_err());
        assert!(ensure_internal_socket("8.8.8.8:8080".parse().unwrap()).is_err());
        assert!(ensure_internal_socket("[::ffff:8.8.8.8]:8080".parse().unwrap()).is_err());
    }
}
