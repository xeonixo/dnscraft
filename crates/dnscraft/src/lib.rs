//! DNScraft server: minimal TOML bootstrap and JSON-lines query log.
//!
//! The heavy lifting (config parsing, engine construction, event formatting)
//! lives here so [`main.rs`](crate) stays a thin exit-code shim.

mod apply;
mod config;
mod control_api;
mod engine;
mod events;

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use dnscraft_api::{Audit, ConfigService, ConfigStore, Db, QueryLog};
use dnscraft_listeners::{
    ChannelSink, Clock, ListenerSet, ListenersConfig, ListenersStatus, QueryEventSink, SystemClock,
};
use dnscraft_policy::PolicyEngine;
use dnscraft_tls::CertResolver;
use serde_json::Value;
use tokio::task::JoinHandle;
use tracing_subscriber::EnvFilter;

pub use config::{
    Config, IpTruncate, ListenerToml, LogConfig, LogSettings, TLS_CERT_ENV, TLS_CERT_FILE_ENV,
    TLS_KEY_ENV, TLS_KEY_FILE_ENV, TlsSecrets, tls_secrets_from_env,
};
pub use engine::{Engines, build_engine};

/// SQLite file holding the config versions and the audit log (`data_dir`).
const CONFIG_DB_FILE: &str = "dnscraft.db";
/// Audit node id for a standalone (non-cluster) assembler.
const CONFIG_NODE_ID: &str = "local";
/// Bounded query-log channel capacity; a full channel drops events and counts
/// them as `control_api.query_log.dropped`.
const QUERY_LOG_CHANNEL_CAPACITY: usize = 4096;
/// Capacity of the opt-in stdout JSON-lines debug channel.
const STDOUT_LOG_CHANNEL_CAPACITY: usize = 1024;

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

/// A running server: the listener set, the SQLite query-log consumer and the
/// optional stdout debug writer.
pub struct App {
    set: Arc<ListenerSet<PolicyEngine>>,
    writer: Option<JoinHandle<()>>,
    /// SQLite query-log consumer task.
    query_log_task: Option<JoinHandle<()>>,
    sink: Arc<dyn QueryEventSink>,
    /// Engines kept alive for the control-api assembly.
    engines: Engines,
    /// Atomic config service; control-api attaches to this handle.
    config_service: Arc<ConfigService>,
    /// Control-api HTTP listener task (aborted on shutdown); `None` when it
    /// stopped during startup and the DNS listeners keep serving.
    api: Option<JoinHandle<Result<(), Error>>>,
}

impl App {
    /// Current listener status (bind state, bound addresses, counters).
    pub fn listener_status(&self) -> ListenersStatus {
        self.set.status()
    }

    /// The shared atomic config service (control-api and MCP attach here).
    pub fn config_service(&self) -> Arc<ConfigService> {
        Arc::clone(&self.config_service)
    }

    /// The live engines assembled at startup.
    pub fn engines(&self) -> &Engines {
        &self.engines
    }

    /// Gracefully stops listeners and drains both event consumers.
    pub async fn shutdown(self, grace: Duration) {
        if let Some(set) = Arc::into_inner(self.set) {
            set.shutdown(grace).await;
        } else {
            // A clone of the set outlived the app; the listener tasks are
            // dropped with their join handles.
            tracing::warn!("listener set still shared at shutdown");
        }
        let dropped = self.sink.events_dropped();
        // Release the app's sender so each consumer sees the channel close
        // once every listener has dropped its clone, then drain. The timeout
        // is a backstop against a leaked sender holding a task (and the
        // process) open.
        drop(self.sink);
        if let Some(writer) = self.writer {
            let _ = tokio::time::timeout(Duration::from_secs(2), writer).await;
        }
        if let Some(query_log) = self.query_log_task {
            let _ = tokio::time::timeout(Duration::from_secs(2), query_log).await;
        }
        // `serve` has no shutdown hook, so the API listener is stopped by
        // aborting its task.
        if let Some(api) = self.api {
            api.abort();
            let _ = api.await;
        }
        if dropped > 0 {
            eprintln!("dnscraft: {dropped} query events dropped");
        }
    }
}

/// Builds a server from a parsed config, reading TLS secrets from the
/// environment.
///
/// Query events go to the SQLite query log by default. When `[log] queries` is
/// explicitly enabled, the same events are also teed to the JSON-lines stdout
/// debug writer. `clock` drives the policy engine (schedules, pauses).
/// Production passes [`dnscraft_filtering::SystemClock`]; tests inject a manual
/// clock.
pub async fn build(
    mut config: Config,
    clock: Arc<dyn dnscraft_filtering::Clock>,
) -> Result<App, Error> {
    let listeners = config.listeners_config()?;
    let log = config.log_settings()?;
    let engines = engine::build_engines(&config, clock).await?;

    // AS9: SQLite config store under `data_dir`, seeded from the TOML config on
    // first run. A non-empty store wins; the live engines were still built from
    // TOML in this phase.
    let snapshot = config_snapshot(&config, &listeners)?;
    let data_dir = engine::engine_data_dir(&config);
    let db_path = data_dir.join(CONFIG_DB_FILE);
    let db = Db::open(&db_path, Arc::new(dnscraft_api::SystemClock))
        .await
        .map_err(|e| Error::startup("dnscraft.startup.store", format!("config store: {e}")))?;
    let store = ConfigStore::new(db.clone());
    seed_config_store(&store, &snapshot).await?;

    // AS12: SQLite query-log consumer over the same database. The bounded
    // sink keeps the answer path non-blocking; the consumer batch-inserts and
    // applies retention. The client enricher comes from the live directory.
    let query_log = Arc::new(
        QueryLog::new(
            db.clone(),
            config.control_api.query_log.clone(),
            CONFIG_NODE_ID,
        )
        .with_client_enricher(Arc::new(engine::EngineClients {
            engine: Arc::clone(&engines.clients),
        })),
    );
    let (query_sink, query_rx) = QueryLog::channel(QUERY_LOG_CHANNEL_CAPACITY);
    let query_sink: Arc<dyn QueryEventSink> = query_sink;
    let handle = tokio::runtime::Handle::try_current().map_err(|e| {
        Error::startup(
            "dnscraft.startup.query_log",
            format!("query-log consumer: {e}"),
        )
    })?;
    let query_log_task = Some(handle.spawn(Arc::clone(&query_log).run(query_rx)));

    // The JSON-lines stdout writer is an explicit debug opt-in; the SQLite
    // sink is always the primary sink.
    let (sink, writer) = if log.queries {
        let (stdout, rx) = ChannelSink::new(STDOUT_LOG_CHANNEL_CAPACITY);
        let writer = tokio::task::spawn_blocking(move || {
            events::write_events_blocking(rx, log.ip_truncate);
        });
        let sink: Arc<dyn QueryEventSink> = Arc::new(events::TeeSink::new(query_sink, stdout));
        (sink, Some(writer))
    } else {
        (query_sink, None)
    };

    // A configured `[tls]` engine owns certificate renewal; otherwise keep the
    // environment-PEM bootstrap for encrypted listeners.
    let certs = match engines.tls.as_ref() {
        Some(engine) => Some(engine.resolver()),
        None => match tls_secrets_from_env()? {
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
        },
    };

    let listener_sink = Arc::clone(&sink);
    let clock: Arc<dyn Clock> = Arc::new(SystemClock);
    let api_acme = certs.clone();
    let set = Arc::new(
    let node_id = config
        .node_id()
        .map_err(|e| Error::startup("dnscraft.startup.node_id", format!("node_id: {e}")))?;
        ListenerSet::start(
            listeners,
            Arc::clone(&engines.policy),
            certs,
            listener_sink,
            clock,
            config.public_domain.clone(),
        )
            Some(node_id),
        .await
        .map_err(|e| Error::startup("dnscraft.startup.listeners", format!("listeners: {e}")))?,
    );

    if !config.allow_partial_bind {
        let failures: Vec<String> = set
            .status()
            .listeners
            .iter()
            .filter(|l| l.error.is_some())
            .map(|l| format!("{} (id {})", l.configured_address, l.id.as_str()))
            .collect();
        if !failures.is_empty() {
            if let Some(set) = Arc::into_inner(set) {
                set.shutdown(Duration::ZERO).await;
            }
            return Err(Error::startup(
                "dnscraft.startup.bind",
                format!("listener bind failed: {}", failures.join(", ")),
            ));
        }
    }

    let modules = apply::appliers(&engines, &set);
    let config_service = Arc::new(ConfigService::new(
        store,
        Audit::new(db.clone()),
        modules,
        CONFIG_NODE_ID,
    ));

    // AS10/AS11: serve the control-api (and mount `/mcp/v1` when enabled)
    // alongside the DNS listeners.
    let control_api = control_api::start(
        &mut config,
        &engines,
        &db,
        &data_dir,
        &query_log,
        Arc::clone(&config_service),
        api_acme,
    )
    .await?;

    Ok(App {
        set,
        writer,
        query_log_task,
        sink,
        engines,
        config_service,
        api: control_api.task,
    })
}

/// The five-section JSON snapshot seeded into an empty config store.
///
/// Uses exactly the top-level keys [`ConfigService`] applies. `listeners` is
/// the mapped [`ListenersConfig`] (listeners + limits + public + ddr), which
/// is what `ApplyListeners` consumes.
fn config_snapshot(config: &Config, listeners: &ListenersConfig) -> Result<Value, Error> {
    Ok(serde_json::json!({
        "filtering": section("filtering", &config.filtering)?,
        "clients": section("clients", &config.clients)?,
        "policy": section("policy", &config.policy)?,
        "listeners": section("listeners", listeners)?,
        "tls": section("tls", &config.tls)?,
    }))
}

/// Serializes one TOML section for the bootstrap snapshot.
fn section<T: serde::Serialize>(name: &str, value: &T) -> Result<Value, Error> {
    serde_json::to_value(value).map_err(|e| {
        Error::startup(
            "dnscraft.startup.config_seed",
            format!("serialize `{name}` for the config store: {e}"),
        )
    })
}

/// Seeds an empty config store; a store that already has a snapshot is kept.
///
/// D4: the TOML file is a first-run bootstrap only. It never overwrites an
/// operator's stored (API-managed) configuration; a single warning says so.
async fn seed_config_store(store: &ConfigStore, snapshot: &Value) -> Result<(), Error> {
    let seed_err = |e: dnscraft_api::ControlApiError| {
        Error::startup("dnscraft.startup.config_seed", format!("config store: {e}"))
    };
    match store.current().await.map_err(seed_err)? {
        Some(version) => {
            tracing::warn!(
                version,
                "config store already holds a snapshot; keeping it instead of re-seeding from TOML"
            );
        }
        None => {
            let version = store.store(snapshot).await.map_err(seed_err)?;
            tracing::info!(version, "seeded the config store from TOML");
        }
    }
    Ok(())
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
            Error::config("dnscraft.config.invalid_log", "x"),
            Error::config("dnscraft.config.tls_env_incomplete", "x"),
            Error::config("dnscraft.config.tls_env_conflict", "x"),
            Error::startup("dnscraft.startup.bind", "x"),
            Error::startup("dnscraft.startup.resolver", "x"),
            Error::startup("dnscraft.startup.filtering", "x"),
            Error::startup("dnscraft.startup.clients", "x"),
            Error::startup("dnscraft.startup.policy", "x"),
            Error::startup("dnscraft.startup.tls", "x"),
            Error::startup("dnscraft.startup.listeners", "x"),
            Error::startup("dnscraft.startup.store", "x"),
            Error::startup("dnscraft.startup.query_log", "x"),
            Error::startup("dnscraft.startup.config_seed", "x"),
            Error::startup("dnscraft.startup.control_api", "x"),
            Error::startup("dnscraft.startup.control_api_tls", "x"),
            Error::startup("dnscraft.startup.control_api_auth", "x"),
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

    /// The bootstrap snapshot carries exactly the five applied sections, and
    /// each one is valid JSON for the applier that consumes it.
    #[test]
    fn config_snapshot_has_the_five_applied_sections() {
        let snapshot = config_snapshot(&Config::default(), &ListenersConfig::default()).unwrap();

        let mut keys: Vec<&str> = snapshot
            .as_object()
            .map(|map| map.keys().map(String::as_str).collect())
            .unwrap_or_default();
        keys.sort_unstable();
        assert_eq!(
            keys,
            vec!["clients", "filtering", "listeners", "policy", "tls"]
        );
        for section in keys {
            assert!(
                snapshot[section].is_object(),
                "section `{section}` must be a JSON object"
            );
        }
    }

    /// D4: seeding runs once; a store that already has a snapshot is kept.
    #[tokio::test]
    async fn seed_never_overwrites_an_existing_snapshot() {
        let db = Db::open_in_memory(Arc::new(dnscraft_api::SystemClock))
            .await
            .unwrap();
        let store = ConfigStore::new(db);

        let first = config_snapshot(&Config::default(), &ListenersConfig::default()).unwrap();
        seed_config_store(&store, &first).await.unwrap();
        assert_eq!(store.current().await.unwrap(), Some(1));

        let mut second = first.clone();
        second["filtering"] = serde_json::json!({ "changed": true });
        seed_config_store(&store, &second).await.unwrap();

        assert_eq!(store.current().await.unwrap(), Some(1), "no second seed");
        assert_eq!(store.load(1).await.unwrap(), Some(first));
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
