//! axum server: shared state, readiness, and the network entry point.

use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use tokio::net::TcpListener;

use crate::config::ControlApiConfig;
use crate::error::ControlApiError;

/// Shared state handed to every handler (and cloned into the router).
///
/// Grows as later tasks land: TLS mode, rate limiter, config snapshot.
#[derive(Clone)]
pub struct AppState {
    readiness: Arc<Readiness>,
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
        }
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

/// Serves the API on the configured bind address (plain HTTP in A3; TLS is
/// added by A4). Runs until the process is shut down.
pub async fn serve(config: ControlApiConfig, state: AppState) -> Result<(), ControlApiError> {
    config.validate()?;
    let addr = SocketAddr::new(config.bind, config.port);
    let listener = TcpListener::bind(addr)
        .await
        .map_err(|e| ControlApiError::Internal {
            message: format!("bind {addr}: {e}"),
        })?;
    let router = state.router();
    axum::serve(listener, router)
        .await
        .map_err(|e| ControlApiError::Internal {
            message: format!("serve: {e}"),
        })
}
