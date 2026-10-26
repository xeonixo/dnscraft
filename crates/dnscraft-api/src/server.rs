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
use crate::clock::SystemClock;
use crate::config::{ControlApiConfig, RateLimitConfig, is_internal_bind};
use crate::config_apply::ConfigService;
use crate::error::ControlApiError;
use crate::query_log::QueryLog;
use crate::tls::{TlsStatus, TlsStatusProvider};

/// Shared state handed to every handler (and cloned into the router).
///
/// Grows as later tasks land: TLS mode, rate limiter, config snapshot.
#[derive(Clone)]
pub struct AppState {
    readiness: Arc<Readiness>,
    tls: Option<Arc<dyn TlsStatusProvider>>,
    rate_limiter: Arc<RateLimiter>,
    auth: Option<Arc<AuthState>>,
    local_login: Option<Arc<LocalAccountStore>>,
    oidc: Option<Arc<OidcState>>,
    config: Option<Arc<ConfigService>>,
    query_log: Option<Arc<QueryLog>>,
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
        }
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
