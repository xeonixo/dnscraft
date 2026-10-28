//! Control-API and MCP assembly.
//!
//! Builds [`AppState`] from the parsed `[control_api]` block and the live
//! engines, then serves it on the internal bind alongside the DNS listeners.
//! The MCP backend is attached only when `control_api.mcp.enabled` is true.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use dnscraft_api::{
    AppState, Audit, AuthState, ClusterRuntime, ClusterRuntimeOptions, ClusterStore, ConfigService,
    ControlApiTls, Db, EngineStatusProvider, EngineTlsAdmin, LocalAccountStore, OfflineWriteQueue,
    OidcState, QueryLog, Readiness, ServiceCatalogProvider, SessionStore, SystemClock,
    TlsStatusProvider, TokenStore, mcp_backend_inner, run_backup_if_due,
};
use dnscraft_cluster::{ClusterConfig, Role};
use dnscraft_filtering::{FilterEngine, ServiceCatalog};
use dnscraft_listeners::ListenerSet;
use dnscraft_policy::PolicyEngine;
use dnscraft_tls::CertResolver;
use tokio::task::JoinHandle;

use crate::engine::{EngineDirectory, Engines};
use crate::{CLUSTER_DB_FILE, CONFIG_NODE_ID, Config, Enrollment, Error};

/// How long [`start`] waits after spawning `serve` to catch an immediate
/// startup failure (invalid config, bind error, TLS setup).
///
/// `serve` binds before it awaits, so a healthy server is still running after
/// the grace window and only a failure returns early.
const STARTUP_GRACE: Duration = Duration::from_millis(50);

/// How often the scheduled backup check runs. `run_backup_if_due` itself
/// enforces the 24 h interval, so this only bounds the delay.
const BACKUP_CHECK_INTERVAL: Duration = Duration::from_secs(60 * 60);

/// The running control-api HTTP listener.
pub(crate) struct ControlApi {
    /// The `serve` task; aborted on [`crate::App::shutdown`]. `None` when the
    /// task already finished during startup (its output was consumed while
    /// detecting the failure).
    pub task: Option<JoinHandle<Result<(), Error>>>,
    /// The cluster runtime when `[cluster]` enables a role.
    pub cluster: Option<ClusterRuntime>,
    /// The hourly scheduled-backup check (aborted on shutdown).
    pub backup: JoinHandle<()>,
}

/// Assembles the control-api state and starts serving.
///
/// `acme` is the TLS module's certificate resolver (shared with the DNS
/// listeners) when one exists; without it the API listener serves only the
/// persisted self-signed bootstrap certificate.
///
/// `config.control_api.mcp.allowed_origins` is filled in here (from the node
/// hostname the TLS certificate covers) before `serve` reads the config, so the
/// MCP transport validates browser origins against the real public host.
/// `set` is the running listener set: its status feeds `/readyz` (GA29) and
/// `get_status` (GM4), and is held weakly so shutdown can still consume it.
/// `cluster` (validated `[cluster]`, `None` when standalone) starts before the
/// listener serves, so the admin routes are mounted from the first request.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn start(
    config: &mut Config,
    engines: &Engines,
    set: &Arc<ListenerSet<PolicyEngine>>,
    db: &Db,
    data_dir: &Path,
    query_log: &Arc<QueryLog>,
    config_service: Arc<ConfigService>,
    acme: Option<Arc<CertResolver>>,
    cluster: Option<&ClusterConfig>,
    enrollment: &Enrollment,
) -> Result<ControlApi, Error> {
    let api_config = config.control_api.clone();
    // The cluster certificate installer writes into the resolver the DNS
    // listeners use; keep a handle before the TLS branch below consumes `acme`.
    let cluster_resolver = acme.clone();
    api_config.validate().map_err(|error| {
        Error::startup(
            "dnscraft.startup.control_api",
            format!("control-api config: {error}"),
        )
    })?;

    let hostname = api_hostname(config);
    let mut mcp_config = api_config.mcp.clone();
    mcp_config.allowed_origins = api_origin(&api_config, &hostname).into_iter().collect();
    // `serve` rebuilds `AppState::mcp_config` from `config.mcp`, so persist the
    // derived origin there as well as giving the backend its own copy.
    config.control_api.mcp = mcp_config.clone();

    // AS10: direct TLS with the tls module's resolver and the self-signed
    // bootstrap; a reverse-proxy setup (`tls = false`) serves plain HTTP.
    let listener_tls = if api_config.tls {
        let acme = acme.unwrap_or_else(|| Arc::new(CertResolver::new()));
        let tls =
            ControlApiTls::bootstrap(&hostname, data_dir, &SystemClock, acme).map_err(|error| {
                Error::startup(
                    "dnscraft.startup.control_api_tls",
                    format!("control-api TLS: {error}"),
                )
            })?;
        Some(tls)
    } else {
        None
    };
    let listener_status = listener_tls.as_ref().map(ControlApiTls::status_provider);
    let tls_server_config = listener_tls.as_ref().map(ControlApiTls::server_config);

    // AS10: auth stores over the shared config/audit database. The token store
    // is attached to the MCP backend below so bearer tokens validate there too.
    let auth_config = &api_config.auth;
    let oidc = OidcState::from_config(auth_config).map_err(|error| {
        Error::startup(
            "dnscraft.startup.control_api_auth",
            format!("control-api OIDC: {error}"),
        )
    })?;
    let local_accounts = LocalAccountStore::new(
        db.clone(),
        auth_config.local_login_max_attempts,
        auth_config.local_login_lock_window,
    );
    if auth_config.local_login_enabled {
        seed_break_glass_admin(&local_accounts).await?;
    }
    let sessions = SessionStore::new(
        db.clone(),
        auth_config.session_idle_timeout,
        auth_config.session_absolute_timeout,
    );
    let tokens = TokenStore::new(db.clone(), auth_config.api_token_max_ttl);
    let mut auth_state = AuthState::new(sessions, tokens);
    if auth_config.local_login_enabled {
        auth_state = auth_state.with_local_accounts(local_accounts.clone());
    }
    if let Some(oidc) = oidc.as_ref() {
        auth_state = auth_state.with_oidc(oidc);
    }
    let mcp_tokens = auth_state.tokens().clone();
    let oidc_issuer = oidc
        .as_ref()
        .map(|_| auth_config.oidc_issuer.trim().to_owned());

    // TLS status: the engine supplies certificate detail; the API listener
    // supplies the mode and fingerprint a handshake actually serves.
    let tls_status: Option<Arc<dyn TlsStatusProvider>> = match engines.tls.as_ref() {
        Some(engine) => {
            let provider = EngineStatusProvider::new(Arc::clone(engine));
            let provider = match listener_status.as_ref() {
                Some(listener) => provider.with_listener_status(Arc::clone(listener)),
                None => provider,
            };
            Some(Arc::new(provider))
        }
        None => listener_status,
    };

    // AS10: `AppState` from the config service, engines, auth, TLS and MCP
    // limits. `serve` fills the rate limiter and the derived protected list.
    // AS12: the query log is attached so the query-log and stats routes mount.
    let mut state = AppState::new()
        .with_config_service(Arc::clone(&config_service))
        .with_filter_engine(Arc::clone(&engines.filtering))
        .with_policy_engine(Arc::clone(&engines.policy))
        .with_resolver(Arc::clone(&engines.resolver))
        .with_auth(auth_state)
        .with_query_log(Arc::clone(query_log))
        .with_mcp_config(mcp_config.clone())
        .with_version(env!("CARGO_PKG_VERSION"))
        .with_db(db.clone())
        .with_backup_dir(data_dir.join("backups"))
        .with_service_catalog(Arc::new(EngineServices {
            engine: Arc::clone(&engines.filtering),
        }));
    if auth_config.local_login_enabled {
        state = state.with_local_login(local_accounts);
    }
    if let Some(oidc) = oidc {
        if let Some(issuer) = oidc_issuer.as_ref() {
            state = state.with_oidc_issuer(issuer.clone());
        }
        state = state.with_oidc(Arc::new(oidc));
    }
    if let Some(provider) = tls_status.as_ref() {
        state = state.with_tls(Arc::clone(provider));
    }
    if let Some(engine) = engines.tls.as_ref() {
        // UI-stored token (kv) overrides a missing env token after restart.
        if let Ok(Some(token)) = dnscraft_api::cloudflare_token_from_db(&db).await {
            let _ = engine
                .set_cloudflare_token(dnscraft_tls::Secret::new(token))
                .await;
        }
        state = state.with_tls_admin(Arc::new(EngineTlsAdmin::new(Arc::clone(engine))));
    }
    // GA6c: the client directory behind `/clients` and `/clients/sync`.
    let directory = Arc::new(EngineDirectory {
        engine: Arc::clone(&engines.clients),
    });
    state = state.with_clients(directory.clone());
    report_readiness(state.readiness(), engines, set);

    // Cluster role: the master's listener, registry and TLS signer, or the
    // sub-node's reconnect loop. Started before the MCP backend so the MCP
    // write tools share the master's broadcast handle.
    let cluster_runtime = match cluster {
        Some(cluster) => {
            let (next, runtime) = start_cluster(
                cluster,
                enrollment,
                state,
                engines,
                cluster_resolver,
                data_dir,
            )
            .await?;
            state = next;
            Some(runtime)
        }
        None => None,
    };

    // AS11: mount `/mcp/v1` when enabled, wiring the AS12 query log so the
    // log and stats tools read the live SQLite pipeline.
    if mcp_config.enabled {
        // Weak: the listener set is consumed on shutdown, so the status
        // closure must not keep it alive.
        let listeners = Arc::downgrade(set);
        state = state.with_mcp_backend(mcp_backend_inner(
            Arc::clone(&engines.filtering),
            Arc::clone(&engines.policy),
            Some(Arc::clone(query_log)),
            Arc::clone(&config_service),
            Arc::new(Audit::new(db.clone())),
            mcp_tokens,
            Arc::new(SystemClock),
            tls_status,
            directory,
            Arc::clone(&engines.resolver),
            Arc::new(move || {
                listeners
                    .upgrade()
                    .map(|set| set.status())
                    .unwrap_or_default()
            }),
            CONFIG_NODE_ID,
            env!("CARGO_PKG_VERSION"),
            mcp_config,
            oidc_issuer,
        ));
    }

    // Scheduled backups run from the same state the API serves.
    let backup_state = state.clone();
    let backup = tokio::spawn(async move {
        let mut ticker = tokio::time::interval(BACKUP_CHECK_INTERVAL);
        loop {
            ticker.tick().await;
            if let Err(error) = run_backup_if_due(&backup_state).await {
                tracing::warn!(code = error.code(), "scheduled backup failed");
            }
        }
    });

    let serve_config = config.control_api.clone();
    let mut task = tokio::spawn(async move {
        match dnscraft_api::serve(serve_config, state, tls_server_config).await {
            Ok(()) => Ok(()),
            Err(error) => {
                let error = Error::startup(
                    "dnscraft.startup.control_api",
                    format!("control-api: {error}"),
                );
                tracing::error!("{error}");
                Err(error)
            }
        }
    });

    // A failure here (for example the port is already bound by another
    // process) must not take the DNS listeners down: they are already serving
    // and the error is reported with its stable code. Invalid control-api
    // configuration and TLS/OIDC setup still fail `build` above. A running
    // server never returns here.
    if let Ok(finished) = tokio::time::timeout(STARTUP_GRACE, &mut task).await {
        match finished {
            Ok(Ok(())) => {
                tracing::error!("dnscraft.startup.control_api: control-api stopped during startup")
            }
            // The task already logged its own code and message.
            Ok(Err(_)) => {}
            Err(join_error) => {
                tracing::error!("dnscraft.startup.control_api: control-api task: {join_error}")
            }
        }
        // Polling the handle to completion consumed its output; there is
        // nothing left to abort at shutdown.
        return Ok(ControlApi {
            task: None,
            cluster: cluster_runtime,
            backup,
        });
    }
    Ok(ControlApi {
        task: Some(task),
        cluster: cluster_runtime,
        backup,
    })
}

/// Blocked-services catalog for `GET /api/v1/filtering/services`, read live
/// from the filtering engine (`available: false` while none is cached).
struct EngineServices {
    engine: Arc<FilterEngine>,
}

impl ServiceCatalogProvider for EngineServices {
    fn catalog(&self) -> Option<Arc<ServiceCatalog>> {
        self.engine.services()
    }

    fn updated_at(&self) -> Option<u64> {
        self.engine.services_updated_at()
    }
}

/// Starts the `[cluster]` role and attaches its handles to `state`.
///
/// A sub-node gets its offline-write queue first (the runtime reads it while
/// starting). The master exposes its registry, status and, when `[tls]` is
/// configured, a CSR signer backed by the TLS engine.
async fn start_cluster(
    cluster: &ClusterConfig,
    enrollment: &Enrollment,
    mut state: AppState,
    engines: &Engines,
    tls_resolver: Option<Arc<CertResolver>>,
    data_dir: &Path,
) -> Result<(AppState, ClusterRuntime), Error> {
    if cluster.role == Role::SubNode && cluster.offline_writes.enabled {
        let store = ClusterStore::open(
            &data_dir.join(CLUSTER_DB_FILE),
            Arc::new(SystemClock),
            cluster.join.token_ttl,
        )
        .await
        .map_err(|error| {
            Error::startup(
                "dnscraft.startup.cluster",
                format!("cluster store: {error}"),
            )
        })?;
        let queue = OfflineWriteQueue::new(store, cluster.offline_writes.clone());
        state = state.with_offline_write_queue(Arc::new(queue));
    }

    let mut options = ClusterRuntimeOptions::new(data_dir);
    options.tls_resolver = tls_resolver;
    options.join_token = enrollment.join_token.clone();
    options.master_cert_pem = enrollment.master_cert_pem.clone();
    let runtime = ClusterRuntime::start(cluster.clone(), &state, options)
        .await
        .map_err(|error| Error::startup("dnscraft.startup.cluster", format!("cluster: {error}")))?;

    if let Some(store) = runtime.cluster_store() {
        state = state.with_cluster_store(Arc::new(store));
    }
    state = state.with_cluster_status(runtime.status_handle());
    if let Some(engine) = engines.tls.as_ref() {
        runtime.attach_tls_engine(Arc::clone(engine));
    }
    Ok((state, runtime))
}

/// GA29: registers each module producer and reports it from the live engine.
///
/// `/readyz` stays 503 until every registered module reports ready. The
/// listeners report not ready while any configured listener failed to bind
/// (possible with `allow_partial_bind`).
fn report_readiness(readiness: &Readiness, engines: &Engines, set: &ListenerSet<PolicyEngine>) {
    let listeners_bound = set
        .status()
        .listeners
        .iter()
        .all(|listener| listener.error.is_none());
    let mut modules = vec![
        ("resolver", true),
        ("filtering", true),
        ("clients", true),
        ("policy", true),
        ("listeners", listeners_bound),
    ];
    if engines.tls.is_some() {
        modules.push(("tls", true));
    }
    for (module, ready) in modules {
        readiness.expect_module(module);
        if ready {
            readiness.set_ready(module);
        } else {
            readiness.set_not_ready(module);
        }
    }
}

/// The hostname the API is addressed by.
///
/// Prefers the node hostname the TLS/DynDNS module manages
/// (`<node>.dns.<public_domain>`); otherwise the wildcard-covered
/// `dns.<public_domain>`, and `localhost` when no public domain is configured.
fn api_hostname(config: &Config) -> String {
    let node = config.tls.dyndns.hostname.trim().trim_end_matches('.');
    if !node.is_empty() {
        return node.to_owned();
    }
    let tls_domain = config.tls.public_domain.trim().trim_end_matches('.');
    let domain = if tls_domain.is_empty() {
        config.public_domain.trim().trim_end_matches('.')
    } else {
        tls_domain
    };
    if domain.is_empty() {
        "localhost".to_owned()
    } else {
        format!("dns.{domain}")
    }
}

/// The browser origin the API listener is reached at, if it has a public name.
///
/// Direct TLS on a non-443 port includes the port (an `Origin` header always
/// carries it); reverse-proxy mode is reached on the proxy's 443.
fn api_origin(api: &dnscraft_api::ControlApiConfig, hostname: &str) -> Option<String> {
    if hostname.eq_ignore_ascii_case("localhost") {
        return None;
    }
    Some(if api.tls && api.port != 443 {
        format!("https://{hostname}:{}", api.port)
    } else {
        format!("https://{hostname}")
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn config(public_domain: &str) -> Config {
        Config {
            public_domain: public_domain.to_owned(),
            ..Config::default()
        }
    }

    #[test]
    fn hostname_prefers_the_node_name_then_the_wildcard_then_localhost() {
        let mut cfg = config("example.com");
        assert_eq!(api_hostname(&cfg), "dns.example.com");

        cfg.tls.public_domain = "example.net".to_owned();
        assert_eq!(api_hostname(&cfg), "dns.example.net");

        cfg.tls.dyndns.hostname = "node1.dns.example.net.".to_owned();
        assert_eq!(api_hostname(&cfg), "node1.dns.example.net");

        assert_eq!(api_hostname(&config("")), "localhost");
    }

    #[test]
    fn origin_includes_the_direct_tls_port_but_not_the_proxy_443() {
        let mut api = dnscraft_api::ControlApiConfig::default();
        assert_eq!(
            api_origin(&api, "dns.example.com").as_deref(),
            Some("https://dns.example.com:8080")
        );
        api.port = 443;
        assert_eq!(
            api_origin(&api, "dns.example.com").as_deref(),
            Some("https://dns.example.com")
        );
        api.tls = false;
        assert_eq!(
            api_origin(&api, "dns.example.com").as_deref(),
            Some("https://dns.example.com")
        );
        assert_eq!(api_origin(&api, "localhost"), None);
    }
}

/// Seeds the `break-glass` admin from `DNSCRAFT_ADMIN_PASSWORD_FILE` on a fresh
/// install (no local accounts yet). Existing accounts are never overwritten, so
/// removing the file after first boot is safe.
async fn seed_break_glass_admin(accounts: &LocalAccountStore) -> Result<(), Error> {
    let Some(path) = std::env::var_os("DNSCRAFT_ADMIN_PASSWORD_FILE") else {
        return Ok(());
    };
    let fail = |message: String| Error::startup("dnscraft.startup.control_api_auth", message);
    let existing = accounts
        .snapshot_entries()
        .await
        .map_err(|error| fail(format!("control-api local accounts: {error}")))?;
    if !existing.is_empty() {
        return Ok(());
    }
    let password = std::fs::read_to_string(&path)
        .map_err(|error| fail(format!("DNSCRAFT_ADMIN_PASSWORD_FILE: {error}")))?;
    accounts
        .upsert("break-glass", password.trim(), dnscraft_api::Role::Admin)
        .await
        .map_err(|error| fail(format!("seeding break-glass admin: {error}")))
}
