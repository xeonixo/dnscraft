//! axum server: shared state, readiness, and the network entry point.

use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use tokio::net::TcpListener;

use crate::config::{ControlApiConfig, is_internal_bind};
use crate::error::ControlApiError;
use crate::tls::{TlsStatus, TlsStatusProvider};

/// Shared state handed to every handler (and cloned into the router).
///
/// Grows as later tasks land: TLS mode, rate limiter, config snapshot.
#[derive(Clone)]
pub struct AppState {
    readiness: Arc<Readiness>,
    tls: Option<Arc<dyn TlsStatusProvider>>,
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
        }
    }

    /// Attaches the TLS status provider (from [`crate::ControlApiTls`]).
    pub fn with_tls(mut self, provider: Arc<dyn TlsStatusProvider>) -> Self {
        self.tls = Some(provider);
        self
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
    let router = state.router();
    if config.tls {
        let server_config = tls.ok_or_else(|| ControlApiError::Internal {
            message: "control-api TLS is enabled but no TLS server config was provided".to_owned(),
        })?;
        serve_tls(listener, router, server_config).await
    } else {
        axum::serve(listener, router)
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
    // axum's Router is a `tower::Service`; hyper's connection driver wants a
    // `hyper::service::Service`, bridged by hyper-util.
    let service = hyper_util::service::TowerToHyperService::new(router);
    loop {
        let (stream, peer) = listener
            .accept()
            .await
            .map_err(|e| ControlApiError::Internal {
                message: format!("accept: {e}"),
            })?;
        let acceptor = acceptor.clone();
        let service = service.clone();
        tokio::spawn(async move {
            let tls_stream = match acceptor.accept(stream).await {
                Ok(stream) => stream,
                Err(e) => {
                    tracing::debug!(%peer, error = %e, "control-api TLS handshake failed");
                    return;
                }
            };
            let io = hyper_util::rt::TokioIo::new(tls_stream);
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
