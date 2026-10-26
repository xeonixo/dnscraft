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

use dnscraft_listeners::{
    ChannelSink, Clock, ListenerSet, ListenersStatus, QueryEventSink, SystemClock,
};
use dnscraft_policy::PolicyEngine;
use dnscraft_tls::CertResolver;
use tokio::task::JoinHandle;
use tracing_subscriber::EnvFilter;

pub use config::{
    Config, ListenerToml, TLS_CERT_ENV, TLS_KEY_ENV, TlsSecrets, tls_secrets_from_env,
};
pub use engine::build_engine;

/// Top-level startup/runtime error; every error maps to exit code 2.
///
/// Each error carries a stable, locale-neutral `code()` of the form
/// `dnscraft.<area>.<reason>` printed on stderr as `dnscraft: <code>: <message>`.
#[derive(Debug)]
pub struct Error {
    code: &'static str,
    message: String,
}

impl Error {
    pub(crate) fn config(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    pub(crate) fn tls(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    pub(crate) fn startup(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    /// Stable, locale-neutral code (see the module docs).
    pub fn code(&self) -> &'static str {
        self.code
    }

    /// Human-readable detail (never contains secret material).
    pub fn message(&self) -> &str {
        &self.message
    }

    /// Process exit code for any error (2 = usage / config / startup failure).
    pub fn exit_code(&self) -> i32 {
        2
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for Error {}

/// Initialises a stderr tracing subscriber: level from `RUST_LOG`, default `warn`.
///
/// Called by the binary shim before [`run`] so listener / TLS warnings become
/// visible. Idempotent — a second call is a no-op.
pub fn init_tracing() {
    let filter = env_filter_from(std::env::var("RUST_LOG").ok().as_deref());
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .try_init();
}

/// Builds the log filter: `RUST_LOG` when set and parseable, `warn` otherwise.
fn env_filter_from(spec: Option<&str>) -> EnvFilter {
    match spec {
        Some(spec) => EnvFilter::try_new(spec).unwrap_or_else(|_| EnvFilter::new("warn")),
        None => EnvFilter::new("warn"),
    }
}

/// Parses a TOML config, mapping parse failures onto stable error codes.
///
/// A serde "unknown field" failure is distinguishable and gets
/// `dnscraft.config.unknown_field` instead of `dnscraft.config.parse`.
pub(crate) fn parse_config(text: &str, source: &str) -> Result<Config, Error> {
    toml::from_str::<Config>(text).map_err(|e| {
        let message = e.to_string();
        if message.contains("unknown field") {
            Error::config(
                "dnscraft.config.unknown_field",
                format!("parse `{source}`: {message}"),
            )
        } else {
            Error::config(
                "dnscraft.config.parse",
                format!("parse `{source}`: {message}"),
            )
        }
    })
}

/// A running server: the listener set plus the JSON event writer task.
pub struct App {
    set: ListenerSet<PolicyEngine>,
    writer: JoinHandle<()>,
}

impl App {
    /// Current listener status (bind state, bound addresses, counters).
    pub fn listener_status(&self) -> ListenersStatus {
        self.set.status()
    }

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
///
/// `clock` drives the policy engine (schedules, pauses). Production passes
/// [`dnscraft_filtering::SystemClock`]; tests inject a manual clock.
pub async fn build(
    config: Config,
    clock: Arc<dyn dnscraft_filtering::Clock>,
) -> Result<App, Error> {
    let listeners = config.listeners_config()?;
    let engine = engine::build_engine(clock).await?;

    let certs = match tls_secrets_from_env()? {
        Some(secrets) => {
            let resolver = Arc::new(CertResolver::new());
            resolver
                .install(
                    secrets.chain_pem.expose().as_bytes(),
                    secrets.key_pem.expose().as_bytes(),
                )
                .map_err(|e| {
                    Error::tls("dnscraft.tls.install", format!("certificate install: {e}"))
                })?;
            Some(resolver)
        }
        None => None,
    };

    let (sink, rx) = ChannelSink::new(1024);
    let sink: Arc<dyn QueryEventSink> = sink;
    let clock: Arc<dyn Clock> = Arc::new(SystemClock);
    let set = ListenerSet::start(listeners, engine, certs, sink, clock, config.public_domain)
        .await
        .map_err(|e| Error::startup("dnscraft.startup.listeners", format!("listeners: {e}")))?;

    if !config.allow_partial_bind {
        let failures: Vec<String> = set
            .status()
            .listeners
            .iter()
            .filter(|l| l.error.is_some())
            .map(|l| format!("{} (id {})", l.configured_address, l.id.as_str()))
            .collect();
        if !failures.is_empty() {
            set.shutdown(Duration::ZERO).await;
            return Err(Error::startup(
                "dnscraft.startup.bind",
                format!("listener bind failed: {}", failures.join(", ")),
            ));
        }
    }

    let writer = tokio::spawn(events::write_events(rx));
    Ok(App { set, writer })
}

/// Loads `config_path`, builds and runs until SIGTERM/SIGINT, then shuts down.
///
/// Returns `Ok(())` on a graceful shutdown (exit code 0) and an [`Error`] for
/// any config or startup failure (exit code 2).
pub async fn run(config_path: Option<&str>) -> Result<(), Error> {
    let path = config_path
        .ok_or_else(|| Error::config("dnscraft.config.usage", "usage: dnscraft <config.toml>"))?;
    let text = std::fs::read_to_string(path)
        .map_err(|e| Error::config("dnscraft.config.read", format!("read `{path}`: {e}")))?;
    let config = parse_config(&text, path)?;

    let clock: Arc<dyn dnscraft_filtering::Clock> = Arc::new(dnscraft_filtering::SystemClock);
    let app = build(config, clock).await?;
    for line in listening_lines(&app.listener_status()) {
        eprintln!("{line}");
    }
    wait_for_shutdown_signal().await;
    app.shutdown(Duration::from_secs(5)).await;
    Ok(())
}

/// One `dnscraft: listening on <addr> (<protocol>, <id>)` line per bound listener.
fn listening_lines(status: &ListenersStatus) -> Vec<String> {
    status
        .listeners
        .iter()
        .filter_map(|l| {
            l.bound.map(|addr| {
                format!(
                    "dnscraft: listening on {addr} ({}, {})",
                    l.protocol.as_str(),
                    l.id.as_str()
                )
            })
        })
        .collect()
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

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    use std::sync::Mutex;

    /// Every stable code is unique and well-formed, and errors print as
    /// `dnscraft: <code>: <message>` (the format the main shim relies on).
    #[test]
    fn error_codes_are_unique_and_well_formed() {
        let errors = [
            Error::config("dnscraft.config.usage", "x"),
            Error::config("dnscraft.config.read", "x"),
            Error::config("dnscraft.config.parse", "x"),
            Error::config("dnscraft.config.unknown_field", "x"),
            Error::config("dnscraft.config.invalid_listener", "x"),
            Error::config("dnscraft.config.tls_env_incomplete", "x"),
            Error::startup("dnscraft.startup.bind", "x"),
            Error::startup("dnscraft.startup.resolver", "x"),
            Error::startup("dnscraft.startup.policy", "x"),
            Error::startup("dnscraft.startup.listeners", "x"),
            Error::tls("dnscraft.tls.install", "x"),
        ];
        let mut codes: Vec<&str> = errors.iter().map(Error::code).collect();
        for code in &codes {
            assert!(
                code.starts_with("dnscraft."),
                "code {code} must use the dnscraft. prefix"
            );
            assert!(
                code.chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '.' || c == '_'),
                "code {code} must be locale-neutral ascii"
            );
        }
        codes.sort_unstable();
        codes.dedup();
        assert_eq!(codes.len(), errors.len(), "duplicate error codes");
    }

    #[test]
    fn error_displays_code_and_message() {
        let err = Error::config("dnscraft.config.parse", "bad toml");
        assert_eq!(err.code(), "dnscraft.config.parse");
        assert_eq!(err.message(), "bad toml");
        assert_eq!(err.to_string(), "dnscraft.config.parse: bad toml");
        assert_eq!(err.exit_code(), 2);
    }

    #[test]
    fn parse_config_rejects_unknown_fields() {
        let text = "public_domain = \"example.com\"\nexposur = \"public\"\n";
        let err = parse_config(text, "cfg.toml").unwrap_err();
        assert_eq!(err.code(), "dnscraft.config.unknown_field");
        assert!(err.message().contains("unknown field"), "{}", err.message());
    }

    /// Production source must never use the frozen manual clock; the
    /// injectable clock parameter exists so only tests reach for it.
    #[test]
    fn no_manual_clock_in_production_source() {
        let needle = concat!("Manual", "Clock");
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        for entry in std::fs::read_dir(&dir).unwrap() {
            let path = entry.unwrap().path();
            if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                continue;
            }
            let text = std::fs::read_to_string(&path).unwrap();
            assert!(
                !text.contains(needle),
                "{} must not use the manual clock in production",
                path.display()
            );
        }
    }

    #[test]
    fn env_filter_defaults_to_warn() {
        assert_eq!(env_filter_from(None).to_string(), "warn");
        assert_eq!(env_filter_from(Some("hello[")).to_string(), "warn");
        assert!(env_filter_from(Some("debug")).to_string().contains("debug"));
    }

    /// A warn line emitted through the subscriber is captured (so the
    /// default-warn subscriber is proven to let warnings through).
    #[test]
    fn warn_lines_are_captured() {
        static CAPTURED: Mutex<String> = Mutex::new(String::new());
        struct Capture;
        impl std::io::Write for Capture {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                CAPTURED
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .push_str(&String::from_utf8_lossy(buf));
                Ok(buf.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        CAPTURED.lock().unwrap_or_else(|e| e.into_inner()).clear();
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::WARN)
            .with_writer(|| Capture)
            .finish();
        tracing::subscriber::with_default(subscriber, || {
            tracing::warn!("dnscraft.startup.bind: listener bind failed");
        });
        let captured = CAPTURED.lock().unwrap_or_else(|e| e.into_inner());
        assert!(
            captured.contains("dnscraft.startup.bind"),
            "warn line not captured: {captured}"
        );
    }
}
