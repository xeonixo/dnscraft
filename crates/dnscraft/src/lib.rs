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

use dnscraft_api::{Audit, ClusterRuntime, ConfigService, ConfigStore, Db, QueryLog};
use dnscraft_cluster::{ClusterConfig, Role};
use dnscraft_listeners::{
    ChannelSink, Clock, ListenerSet, ListenersConfig, ListenersStatus, QueryEventSink, SystemClock,
};
use dnscraft_policy::PolicyEngine;
use dnscraft_tls::CertResolver;
use serde_json::Value;
use std::path::Path;
use tokio::task::JoinHandle;
use tracing_subscriber::EnvFilter;

pub use config::{
    CLUSTER_JOIN_TOKEN_ENV, CLUSTER_JOIN_TOKEN_FILE_ENV, CLUSTER_MASTER_CERT_FILE_ENV, Config,
    Enrollment, IpTruncate, ListenerToml, LogConfig, LogSettings, TLS_CERT_ENV, TLS_CERT_FILE_ENV,
    TLS_KEY_ENV, TLS_KEY_FILE_ENV, TlsSecrets, enrollment_from_env, tls_secrets_from_env,
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
/// Cluster registry and offline-write queue file under `data_dir` (same name
/// the cluster runtime uses for the master registry).
const CLUSTER_DB_FILE: &str = "cluster.db";

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

/// Crate targets that take the configured `[log] level`; everything else is
/// held at `warn`.
const DNSCRAFT_TARGETS: [&str; 12] = [
    "dnscraft",
    "dnscraft_api",
    "dnscraft_clients",
    "dnscraft_cluster",
    "dnscraft_common",
    "dnscraft_filtering",
    "dnscraft_listeners",
    "dnscraft_mcp",
    "dnscraft_policy",
    "dnscraft_proto",
    "dnscraft_resolver",
    "dnscraft_tls",
];

/// Installs the stderr tracing subscriber. Called by [`run`] once the config
/// is read, so `[log] level` applies. Idempotent — a second call is a no-op.
pub fn init_tracing(level: tracing::Level) {
    let filter = env_filter_from(std::env::var("RUST_LOG").ok().as_deref(), level);
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .try_init();
}

/// Builds the log filter: `RUST_LOG` when set, non-blank and parseable;
/// otherwise `level` for the dnscraft crates and `warn` for everything else.
fn env_filter_from(env: Option<&str>, level: tracing::Level) -> EnvFilter {
    env.filter(|spec| !spec.trim().is_empty())
        .and_then(|spec| EnvFilter::try_new(spec).ok())
        .unwrap_or_else(|| EnvFilter::new(configured_directives(level)))
}

/// `warn,dnscraft=<level>,dnscraft_api=<level>,…` for the configured level.
fn configured_directives(level: tracing::Level) -> String {
    let level = level.to_string().to_ascii_lowercase();
    std::iter::once("warn".to_owned())
        .chain(
            DNSCRAFT_TARGETS
                .iter()
                .map(|target| format!("{target}={level}")),
        )
        .collect::<Vec<_>>()
        .join(",")
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
    /// The `[cluster]` role (master or sub-node); `None` when standalone.
    cluster: Option<ClusterRuntime>,
    /// Hourly scheduled-backup check task; aborted on shutdown.
    backup: JoinHandle<()>,
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

    /// The cluster runtime, when `[cluster]` enables a master or sub-node role.
    pub fn cluster(&self) -> Option<&ClusterRuntime> {
        self.cluster.as_ref()
    }

    /// Gracefully stops listeners and drains both event consumers.
    pub async fn shutdown(self, grace: Duration) {
        // Stop the cluster first so no relayed write or log batch is in flight
        // while the local stores close.
        if let Some(cluster) = self.cluster {
            cluster.shutdown().await;
        }
        self.backup.abort();
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
            tracing::warn!(dropped, "query events dropped");
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
    config: Config,
    clock: Arc<dyn dnscraft_filtering::Clock>,
) -> Result<App, Error> {
    build_with_enrollment(config, clock, enrollment_from_env()?).await
}

/// Like [`build`], with the sub-node enrollment material passed in instead of
/// read from the environment (embedding and tests).
pub async fn build_with_enrollment(
    mut config: Config,
    clock: Arc<dyn dnscraft_filtering::Clock>,
    enrollment: Enrollment,
) -> Result<App, Error> {
    let listeners = config.listeners_config()?;
    let log = config.log_settings()?;
    // Validate `[cluster]` before any listener binds.
    let cluster = cluster_settings(&config, &engine::engine_data_dir(&config))?;
    let engines = engine::build_engines(&config, clock).await?;

    // AS9: SQLite config store under `data_dir`. TOML seeds an empty store once;
    // after that the stored snapshot is applied to the live engines below (D4).
    let snapshot = config_snapshot(&config, &listeners)?;
    let data_dir = engine::engine_data_dir(&config);
    let db_path = data_dir.join(CONFIG_DB_FILE);
    let db = Db::open(&db_path, Arc::new(dnscraft_api::SystemClock))
        .await
        .map_err(|e| Error::startup("dnscraft.startup.store", format!("config store: {e}")))?;
    let store = ConfigStore::new(db.clone());

    // AS12: SQLite query-log consumer over the same database. The bounded
    // sink keeps the answer path non-blocking; the consumer batch-inserts and
    // applies retention. The client enricher comes from the live directory.
    let (query_sink, query_rx) = QueryLog::channel(QUERY_LOG_CHANNEL_CAPACITY);
    // The sink is attached so the overview reports `query_log.dropped`.
    let query_log = Arc::new(
        QueryLog::new(
            db.clone(),
            config.control_api.query_log.clone(),
            CONFIG_NODE_ID,
        )
        .with_client_enricher(Arc::new(engine::EngineClients {
            engine: Arc::clone(&engines.clients),
        }))
        .with_sink(Arc::clone(&query_sink)),
    );
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
    let node_id = config
        .node_id()
        .map_err(|e| Error::startup("dnscraft.startup.node_id", format!("node_id: {e}")))?;
    let set = Arc::new(
        ListenerSet::start(
            listeners,
            Arc::clone(&engines.policy),
            certs,
            listener_sink,
            clock,
            config.public_domain.clone(),
            Some(node_id.clone()),
        )
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

    let modules = apply::appliers(&engines, &set, &query_log, &db, node_id.as_str());
    let config_service = Arc::new(ConfigService::new(
        store,
        Audit::new(db.clone()),
        modules,
        CONFIG_NODE_ID,
    ));
    // A sub-node takes its configuration from the master's first snapshot, so
    // it never seeds from TOML: a seeded v1 would make the master's v1 a no-op
    // on apply (`apply_synced_config` skips the version it already holds).
    if cluster.as_ref().map(|c| c.role) != Some(Role::SubNode) {
        seed_config_store(&config_service, snapshot).await?;
    }
    apply_stored_config(&config_service).await?;

    // AS10/AS11: serve the control-api (and mount `/mcp/v1` when enabled)
    // alongside the DNS listeners.
    let control_api = control_api::start(
        &mut config,
        &engines,
        &set,
        &db,
        &data_dir,
        &query_log,
        Arc::clone(&config_service),
        api_acme,
        cluster.as_ref(),
        &enrollment,
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
        cluster: control_api.cluster,
        backup: control_api.backup,
    })
}

/// Validates `[cluster]` and resolves its certificate paths.
///
/// Returns `None` when the cluster is absent or standalone. Relative cluster
/// TLS paths (the SPEC defaults are `data/cluster/...`) resolve under
/// `data_dir`, so the CA and node key land in the node's data directory.
fn cluster_settings(config: &Config, data_dir: &Path) -> Result<Option<ClusterConfig>, Error> {
    let Some(mut cluster) = config.cluster.clone() else {
        return Ok(None);
    };
    cluster.validate().map_err(|error| {
        Error::config(
            "dnscraft.config.invalid_cluster",
            format!("[cluster]: {error}"),
        )
    })?;
    if cluster.role == Role::Standalone {
        return Ok(None);
    }
    for path in [
        &mut cluster.tls.ca_cert,
        &mut cluster.tls.node_cert,
        &mut cluster.tls.node_key,
    ] {
        if path.is_relative() {
            *path = data_dir.join(&*path);
        }
    }
    Ok(Some(cluster))
}

/// The five-section JSON snapshot seeded into an empty config store.
///
/// Uses exactly the top-level keys [`ConfigService`] applies. `listeners` is
/// the mapped [`ListenersConfig`] (listeners + limits + public + ddr), which
/// is what `ApplyListeners` consumes.
fn config_snapshot(config: &Config, listeners: &ListenersConfig) -> Result<Value, Error> {
    // The effective filter/policy the engines run (default set and view added
    // when the TOML omits them), so the stored snapshot validates and matches.
    let (filtering, policy) =
        engine::default_filter_and_policy(config.filtering.clone(), config.policy.clone())?;
    let mut filtering = section("filtering", &filtering)?;
    // A pause is runtime state, never stored config (the API rejects the key).
    if let Some(sets) = filtering.get_mut("sets").and_then(Value::as_array_mut) {
        for set in sets {
            if let Some(set) = set.as_object_mut() {
                set.remove("paused_until");
            }
        }
    }
    Ok(serde_json::json!({
        "filtering": filtering,
        "clients": section("clients", &config.clients)?,
        "policy": section("policy", &policy)?,
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

/// Seeds an empty config store from the TOML snapshot (GA28, D4).
///
/// The TOML file is bootstrap-only for an empty store. Non-versioned server
/// fields (`data_dir`, `[control_api]` bind/TLS/MCP, `[cluster]`, `[resolver]`,
/// `[log]`) still come from TOML on every start; versioned DNS modules and
/// `control_api_settings` live in SQLite once seeded.
async fn seed_config_store(config_service: &ConfigService, snapshot: Value) -> Result<(), Error> {
    match config_service.seed_if_empty(snapshot).await {
        Ok(Some(_)) => Ok(()),
        Ok(None) => {
            tracing::warn!(
                "config store already holds a snapshot; keeping it instead of re-seeding from TOML"
            );
            Ok(())
        }
        Err(e) => Err(Error::startup(
            "dnscraft.startup.config_seed",
            format!("config store: {e}"),
        )),
    }
}

/// Reconciles live module engines with the current SQLite snapshot (D4).
async fn apply_stored_config(config_service: &ConfigService) -> Result<(), Error> {
    match config_service.apply_stored_current().await {
        Ok(Some(version)) => {
            tracing::info!(version, "applied the stored config to live engines");
            Ok(())
        }
        Ok(None) => Ok(()),
        Err(e) => Err(Error::startup(
            "dnscraft.startup.config_apply",
            format!("config store: {e}"),
        )),
    }
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
    let log = config.log_settings()?;
    init_tracing(log.level);

    let clock: Arc<dyn dnscraft_filtering::Clock> = Arc::new(dnscraft_filtering::SystemClock);
    let app = build(config, clock).await?;
    log_listeners(&app.listener_status());
    tracing::info!("dnscraft started");
    wait_for_shutdown_signal().await;
    tracing::info!("shutdown signal received, stopping");
    app.shutdown(Duration::from_secs(5)).await;
    tracing::info!("dnscraft stopped");
    Ok(())
}

/// One `listening on <addr>` info event per bound listener.
fn log_listeners(status: &ListenersStatus) {
    for listener in &status.listeners {
        if let Some(addr) = listener.bound {
            tracing::info!(
                protocol = listener.protocol.as_str(),
                listener = listener.id.as_str(),
                "listening on {addr}"
            );
        }
    }
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
            Error::startup("dnscraft.startup.cluster", "x"),
            Error::config("dnscraft.config.invalid_cluster", "x"),
            Error::config("dnscraft.config.cluster_env", "x"),
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

    /// `[cluster]` is idle when absent or standalone; a sub-node's default
    /// relative TLS paths resolve under the data directory; a role mismatch
    /// fails with its stable code before any listener binds.
    #[test]
    fn cluster_settings_resolve_relative_paths_and_reject_mismatches() {
        let data_dir = Path::new("/var/lib/dnscraft");
        let parse = |cluster: &str| -> Config {
            toml::from_str(&format!("public_domain = \"example.com\"\n{cluster}\n")).unwrap()
        };

        let config = Config::default();
        assert!(cluster_settings(&config, data_dir).unwrap().is_none());
        let standalone = parse("[cluster]\nrole = \"standalone\"\n");
        assert!(cluster_settings(&standalone, data_dir).unwrap().is_none());

        let sub = parse(
            "[cluster]\nrole = \"sub_node\"\nnode_id = \"sub-a\"\nmaster_url = \"https://master.example.com:8443\"\n",
        );
        let cluster = cluster_settings(&sub, data_dir).unwrap().unwrap();
        assert_eq!(cluster.tls.ca_cert, data_dir.join("data/cluster/ca.pem"));
        assert_eq!(cluster.tls.node_key, data_dir.join("data/cluster/node.key"));

        // A master without `[cluster.listen]` fails validation.
        let master = parse("[cluster]\nrole = \"master\"\nnode_id = \"master-a\"\n");
        let err = cluster_settings(&master, data_dir).unwrap_err();
        assert_eq!(err.code(), "dnscraft.config.invalid_cluster");
    }

    #[test]
    fn configured_level_applies_to_dnscraft_crates_and_warn_elsewhere() {
        let configured = env_filter_from(None, tracing::Level::INFO).to_string();
        for target in DNSCRAFT_TARGETS {
            assert!(
                configured.contains(&format!("{target}=info")),
                "{configured}"
            );
        }
        // EnvFilter orders directives by specificity; the bare `warn` default is last.
        assert!(configured.ends_with(",warn"), "{configured}");
        assert_eq!(
            env_filter_from(Some("  "), tracing::Level::DEBUG).to_string(),
            env_filter_from(None, tracing::Level::DEBUG).to_string()
        );
    }

    #[test]
    fn rust_log_overrides_configured_level_when_parseable() {
        let from_env = env_filter_from(Some("trace"), tracing::Level::ERROR).to_string();
        assert_eq!(from_env, "trace");
        let invalid = env_filter_from(Some("hello["), tracing::Level::DEBUG).to_string();
        assert_eq!(
            invalid,
            env_filter_from(None, tracing::Level::DEBUG).to_string(),
            "an invalid RUST_LOG falls back to the configured level"
        );
        assert!(invalid.contains("dnscraft_cluster=debug"), "{invalid}");
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
