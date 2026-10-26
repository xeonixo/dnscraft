//! DNScraft server: minimal TOML bootstrap and JSON-lines query log.
//!
//! The heavy lifting (config parsing, engine construction, event formatting)
//! lives here so [`main.rs`](crate) stays a thin exit-code shim.

mod config;
mod engine;
mod events;

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use dnscraft_listeners::{ChannelSink, Clock, ListenerSet, QueryEventSink, SystemClock};
use dnscraft_policy::PolicyEngine;
use dnscraft_tls::CertResolver;
use tokio::task::JoinHandle;

pub use config::{
    Config, ListenerToml, TLS_CERT_ENV, TLS_KEY_ENV, TlsSecrets, tls_secrets_from_env,
};

/// Top-level startup/runtime error; every variant maps to exit code 2.
#[derive(Debug)]
pub enum Error {
    /// Configuration file / parse / mapping or usage error.
    Config(String),
    /// TLS certificate installation failed.
    Tls(String),
    /// Startup failed (resolver, policy, listener set).
    Startup(String),
}

impl Error {
    pub(crate) fn config(message: impl Into<String>) -> Self {
        Self::Config(message.into())
    }

    pub(crate) fn tls(message: impl Into<String>) -> Self {
        Self::Tls(message.into())
    }

    pub(crate) fn startup(message: impl Into<String>) -> Self {
        Self::Startup(message.into())
    }

    /// Process exit code for any error (2 = usage / config / startup failure).
    pub fn exit_code(&self) -> i32 {
        2
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Config(message) => write!(f, "config: {message}"),
            Self::Tls(message) => write!(f, "tls: {message}"),
            Self::Startup(message) => write!(f, "startup: {message}"),
        }
    }
}

impl std::error::Error for Error {}

/// A running server: the listener set plus the JSON event writer task.
pub struct App {
    set: ListenerSet<PolicyEngine>,
    writer: JoinHandle<()>,
}

impl App {
    /// Gracefully stops listeners and drains the event writer.
    pub async fn shutdown(self, grace: Duration) {
        self.set.shutdown(grace).await;
        // The channel closes once every listener has dropped its sink, so the
        // writer finishes soon after; the timeout is a backstop against a
        // leaked sender holding the writer (and the process) open.
        let _ = tokio::time::timeout(Duration::from_secs(2), self.writer).await;
    }
}

/// Builds a server from a parsed config, reading TLS secrets from the
/// environment and emitting JSON-lines query events on stdout.
pub async fn build(config: Config) -> Result<App, Error> {
    let listeners = config.listeners_config()?;
    let engine = engine::build_engine().await?;

    let certs = match tls_secrets_from_env()? {
        Some(secrets) => {
            let resolver = Arc::new(CertResolver::new());
            resolver
                .install(&secrets.chain_pem, &secrets.key_pem)
                .map_err(|e| Error::tls(format!("certificate install: {e}")))?;
            Some(resolver)
        }
        None => None,
    };

    let (sink, rx) = ChannelSink::new(1024);
    let sink: Arc<dyn QueryEventSink> = sink;
    let clock: Arc<dyn Clock> = Arc::new(SystemClock);
    let set = ListenerSet::start(listeners, engine, certs, sink, clock, config.public_domain)
        .await
        .map_err(|e| Error::startup(format!("listeners: {e}")))?;

    let writer = tokio::spawn(events::write_events(rx));
    Ok(App { set, writer })
}

/// Loads `config_path`, builds and runs until SIGTERM/SIGINT, then shuts down.
///
/// Returns `Ok(())` on a graceful shutdown (exit code 0) and an [`Error`] for
/// any config or startup failure (exit code 2).
pub async fn run(config_path: Option<&str>) -> Result<(), Error> {
    let path = config_path.ok_or_else(|| Error::config("usage: dnscraft <config.toml>"))?;
    let text =
        std::fs::read_to_string(path).map_err(|e| Error::config(format!("read `{path}`: {e}")))?;
    let config: Config =
        toml::from_str(&text).map_err(|e| Error::config(format!("parse `{path}`: {e}")))?;

    let app = build(config).await?;
    eprintln!("dnscraft: listening");
    wait_for_shutdown_signal().await;
    app.shutdown(Duration::from_secs(5)).await;
    Ok(())
}

/// Resolves to the first of SIGTERM or SIGINT.
async fn wait_for_shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let Ok(mut term) = signal(SignalKind::terminate()) else {
            return;
        };
        let Ok(mut interrupt) = signal(SignalKind::interrupt()) else {
            return;
        };
        tokio::select! {
            _ = term.recv() => {}
            _ = interrupt.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}
