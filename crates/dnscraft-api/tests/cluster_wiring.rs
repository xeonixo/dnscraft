//! CL6/CL15: control-api ↔ cluster wiring.
//!
//! Covers the trait implementations (config apply/rollback, auth snapshot,
//! runtime command, cert install, relay RBAC, log outbox/ingest), the master
//! publish hook, a real loopback master + sub-node convergence, the status
//! fields, and node-scoped policy views. No wall-clock sleeps and no outbound
//! network: loopback `127.0.0.1:0` only.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use async_trait::async_trait;
use serde_json::{Value, json};

use dnscraft_api::{
    AppState, ApplyFiltering, Audit, AuthState, ClusterRuntime, ClusterRuntimeOptions,
    ClusterStatusHandle, ConfigActor, ConfigService, ConfigStore, ConfigWriteExecutor,
    ControlApiError, Db, LocalAccountStore, ManualClock as ApiClock, ModuleAppliers, ModuleFuture,
    OidcState, QueryLog, QueryLogIngest, QueryLogOutbox, SessionStore, StateAuthApplier,
    StateRuntimeApplier, SyncedConfigApplier, TlsCertInstaller, TokenStore,
    mcp_backend_for_test_writes_with_broadcast, node_scoped_views,
};
use dnscraft_cluster::{
    AuthSnapshotApplier, CertInstaller, ClusterCa, ClusterClient, ClusterConfig, ClusterServer,
    ClusterServerConfig, ClusterStore, ConfigApplier, JoinConfig, ListenConfig, LogConfig,
    LogIngest, LogOutbox, LogRecord, LogStreamer, NodeIdentity, OfflineWriteQueue,
    OfflineWritesConfig, PendingNodeIdentity, QuotaConfig, RelayResponse, RelayedActor, Role,
    RuntimeCommandApplier, TlsPaths, WriteExecutor, WriteRelay,
};
use dnscraft_common::clock::ManualClock as ClusterClock;
use dnscraft_common::secret::Secret;
use dnscraft_mcp::McpConfig;
use dnscraft_mcp::dto::{PauseDuration, PauseParams};

const NOW: u64 = 1_700_000_000;
const TOKEN_TTL: Duration = Duration::from_secs(15 * 60);
const NODE_CERT_TTL: Duration = Duration::from_secs(90 * 24 * 3600);
const IDLE: Duration = Duration::from_secs(60 * 60);
const ABSOLUTE: Duration = Duration::from_secs(12 * 3600);
const MAX_TTL: Duration = Duration::from_secs(365 * 24 * 3600);

fn at(seconds: u64) -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(seconds)
}

/// A unique, self-cleaning temporary directory.
struct TempDir(PathBuf);

impl TempDir {
    fn new(name: &str) -> Self {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let id = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "dnscraft-cluster-wiring-{name}-{}-{id}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).unwrap();
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

async fn service(node_id: &str, modules: ModuleAppliers) -> (Arc<ConfigService>, Db) {
    let db = Db::open_in_memory(Arc::new(ApiClock::new(at(NOW))))
        .await
        .unwrap();
    let service = Arc::new(ConfigService::new(
        ConfigStore::new(db.clone()),
        Audit::new(db.clone()),
        modules,
        node_id,
    ));
    (service, db)
}

fn snapshot(marker: &str) -> Value {
    json!({
        "filtering": { "lists": [], "sets": [], "marker": marker },
        "clients": {},
        "policy": {},
        "listeners": {},
        "tls": {},
    })
}

fn master_config(dir: &Path) -> ClusterConfig {
    ClusterConfig {
        role: Role::Master,
        node_id: "master".to_owned(),
        master_url: None,
        listen: Some(ListenConfig {
            bind: IpAddr::V4(Ipv4Addr::LOCALHOST),
            port: 0,
        }),
        join: JoinConfig::default(),
        timing: Default::default(),
        offline_writes: OfflineWritesConfig::default(),
        log: LogConfig::default(),
        quota: QuotaConfig::default(),
        tls: TlsPaths {
            ca_cert: dir.join("ca.pem"),
            node_cert: dir.join("node.pem"),
            node_key: dir.join("node.key"),
        },
    }
}

fn sub_node_config(dir: &Path, url: &str) -> ClusterConfig {
    ClusterConfig {
        role: Role::SubNode,
        node_id: "node-b".to_owned(),
        master_url: Some(url.to_owned()),
        listen: None,
        join: JoinConfig::default(),
        timing: Default::default(),
        offline_writes: OfflineWritesConfig::default(),
        log: LogConfig::default(),
        quota: QuotaConfig::default(),
        tls: TlsPaths {
            ca_cert: dir.join("node-ca.pem"),
            node_cert: dir.join("node.pem"),
            node_key: dir.join("node.key"),
        },
    }
}

struct NoWrites;

#[async_trait]
impl WriteExecutor for NoWrites {
    async fn execute(
        &self,
        _node_id: &str,
        _request_id: &str,
        _actor: RelayedActor,
        _method: String,
        _path: String,
        _body: Value,
        _if_match: Option<String>,
        _idempotency_key: Option<String>,
    ) -> Result<RelayResponse, dnscraft_cluster::ClusterError> {
        Err(dnscraft_cluster::ClusterError::Internal {
            message: "write relay is not used in this test".to_owned(),
        })
    }
}

struct NoLogs;

#[async_trait]
impl LogIngest for NoLogs {
    async fn ingest(
        &self,
        _node_id: &str,
        _first_seq: u64,
        _last_seq: u64,
        _records: &[LogRecord],
    ) -> Result<u64, dnscraft_cluster::ClusterError> {
        Err(dnscraft_cluster::ClusterError::Internal {
            message: "log ingest is not used in this test".to_owned(),
        })
    }

    async fn highest_seq(&self, _node_id: &str) -> Result<u64, dnscraft_cluster::ClusterError> {
        Ok(0)
    }
}

/// Master log ingest that reports a fixed highest sequence and accepts batches.
struct RecordingLogs {
    highest: AtomicU64,
}

#[async_trait]
impl LogIngest for RecordingLogs {
    async fn ingest(
        &self,
        _node_id: &str,
        _first_seq: u64,
        last_seq: u64,
        _records: &[LogRecord],
    ) -> Result<u64, dnscraft_cluster::ClusterError> {
        self.highest.store(last_seq, Ordering::SeqCst);
        Ok(last_seq)
    }

    async fn highest_seq(&self, _node_id: &str) -> Result<u64, dnscraft_cluster::ClusterError> {
        Ok(self.highest.load(Ordering::SeqCst))
    }
}

/// Outbox with rows `first..=last`, resuming from `next`.
struct MockLogOutbox {
    rows: Vec<LogRecord>,
    first: u64,
    next: Mutex<u64>,
}

impl MockLogOutbox {
    fn new(first: u64, last: u64, next: u64) -> Self {
        let rows = (first..=last)
            .map(|seq| LogRecord {
                id: format!("r{seq}"),
                record: json!({ "id": format!("r{seq}"), "seq": seq }),
            })
            .collect();
        Self {
            rows,
            first,
            next: Mutex::new(next),
        }
    }
}

#[async_trait]
impl LogOutbox for MockLogOutbox {
    async fn next_unacked_seq(&self) -> Result<u64, dnscraft_cluster::ClusterError> {
        Ok(*self.next.lock().unwrap())
    }

    async fn fetch_batch(
        &self,
        from_seq: u64,
        max_records: usize,
    ) -> Result<Vec<LogRecord>, dnscraft_cluster::ClusterError> {
        let start = from_seq.saturating_sub(self.first) as usize;
        Ok(self
            .rows
            .iter()
            .skip(start)
            .take(max_records)
            .cloned()
            .collect())
    }

    async fn ack(&self, seq: u64) -> Result<(), dnscraft_cluster::ClusterError> {
        *self.next.lock().unwrap() = seq + 1;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// ConfigApplier
// ---------------------------------------------------------------------------

struct ConditionalFiltering;

impl ApplyFiltering for ConditionalFiltering {
    fn apply<'a>(&'a self, config: &'a Value) -> ModuleFuture<'a> {
        Box::pin(async move {
            if config.get("fail").and_then(Value::as_bool) == Some(true) {
                return Err(ControlApiError::Module {
                    code: "filtering.config.invalid",
                    params: Some(json!({ "reason": "injected" })),
                });
            }
            Ok(())
        })
    }
}

#[tokio::test]
async fn config_applier_applies_the_pushed_version() {
    let (service, _) = service("node-b", ModuleAppliers::default()).await;
    let applier = SyncedConfigApplier::new(Arc::clone(&service), "node-b");

    let applied = applier.apply(7, &snapshot("v7")).await.unwrap();
    assert_eq!(applied, 7);
    assert_eq!(service.current().await.unwrap().0, Some(7));
}

#[tokio::test]
async fn config_applier_failure_rolls_back_and_reports_cluster_config_apply() {
    let (service, _) = service(
        "node-b",
        ModuleAppliers {
            filtering: Some(Arc::new(ConditionalFiltering)),
            ..ModuleAppliers::default()
        },
    )
    .await;
    let applier = SyncedConfigApplier::new(Arc::clone(&service), "node-b");

    applier.apply(5, &snapshot("old")).await.unwrap();
    let error = applier
        .apply(
            6,
            &snapshot("new-fail").merging(json!({ "filtering": { "fail": true } })),
        )
        .await
        .expect_err("the injected module apply fails");

    assert_eq!(error.code(), "cluster.config.apply");
    assert!(
        error.to_string().contains("filtering.config.invalid"),
        "{error}"
    );
    // The sub-node stays on the previous version and snapshot.
    let (version, stored) = service.current().await.unwrap();
    assert_eq!(version, Some(5));
    assert_eq!(stored.unwrap()["filtering"]["marker"], "old");
}

/// Tiny helper so the failing snapshot keeps the required sections.
trait MergeJson {
    fn merging(self, patch: Value) -> Value;
}

impl MergeJson for Value {
    fn merging(mut self, patch: Value) -> Value {
        let (Some(target), Some(patch)) = (self.as_object_mut(), patch.as_object()) else {
            return self;
        };
        for (key, value) in patch {
            target.insert(key.clone(), value.clone());
        }
        self
    }
}

// ---------------------------------------------------------------------------
// Master publish hook
// ---------------------------------------------------------------------------

#[tokio::test]
async fn master_apply_publishes_to_config_sync() {
    let dir = TempDir::new("publish");
    let (service, _) = service("master", ModuleAppliers::default()).await;
    let status = Arc::new(ClusterStatusHandle::new());
    let state = AppState::new()
        .with_config_service(Arc::clone(&service))
        .with_cluster_status(status.clone());
    let mut options = ClusterRuntimeOptions::new(dir.path());
    options.clock = Arc::new(ClusterClock::new(SystemTime::now()));
    options.status = Arc::clone(&status);
    let runtime = ClusterRuntime::start(master_config(dir.path()), &state, options)
        .await
        .unwrap();

    assert_eq!(runtime.role(), Role::Master);
    let sync = runtime.config_sync().expect("master config sync");
    assert_eq!(sync.current_version(), None);

    let version = service
        .replace(snapshot("published"), &ConfigActor::local(), None)
        .await
        .unwrap();
    assert_eq!(version, 1);

    // The publish hook is a spawned watch task; yield until it runs.
    for _ in 0..200 {
        if sync.current_version() == Some(version) {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert_eq!(sync.current_version(), Some(1));
    let current = status.status().expect("master status");
    assert_eq!(current.role, "master");
    assert!(current.master_reachable);
    assert_eq!(current.applied_version, Some(1));
    assert!(current.last_sync.is_some());

    runtime.shutdown().await;
}

// ---------------------------------------------------------------------------
// Real loopback master + sub-node convergence
// ---------------------------------------------------------------------------

#[tokio::test]
async fn sub_node_applies_a_master_push_and_acks_zero_lag() {
    let dir = TempDir::new("converge");
    // rustls validates the freshly enrolled node certificate against the real
    // clock, so the test clock starts at wall-clock now and never advances.
    let clock = Arc::new(ClusterClock::new(SystemTime::now()));
    let store = ClusterStore::open_in_memory(clock.clone(), TOKEN_TTL)
        .await
        .unwrap();
    let ca = ClusterCa::load_or_generate(&dir.path().join("ca.pem")).unwrap();
    let server = ClusterServer::start(
        ClusterServerConfig {
            listen: ListenConfig {
                bind: IpAddr::V4(Ipv4Addr::LOCALHOST),
                port: 0,
            },
            server_name: "127.0.0.1".to_owned(),
            node_cert_ttl: NODE_CERT_TTL,
            quota: QuotaConfig::default(),
            timing: dnscraft_cluster::TimingConfig::default(),
        },
        ca,
        store.clone(),
        clock.clone(),
        Arc::new(NoWrites),
        Arc::new(NoLogs),
        None,
    )
    .await
    .unwrap();
    let url = format!("https://127.0.0.1:{}", server.addr().port());

    let token = store.mint_join_token("node-b").await.unwrap();
    let pending = PendingNodeIdentity::generate("node-b").unwrap();
    let response = ClusterClient::enroll(
        &url,
        server.server_cert_pem(),
        pending.request(Secret::new(token.expose())),
    )
    .await
    .unwrap();
    let paths = TlsPaths {
        ca_cert: dir.path().join("node-b-ca.pem"),
        node_cert: dir.path().join("node-b.pem"),
        node_key: dir.path().join("node-b.key"),
    };
    let identity = pending.persist(&response, &paths).unwrap();
    assert!(NodeIdentity::load(&paths).is_ok());

    let (service, _) = service("node-b", ModuleAppliers::default()).await;
    let applier = SyncedConfigApplier::new(Arc::clone(&service), "node-b");
    let client = ClusterClient::new(&url, &identity, clock.clone()).unwrap();
    let notify = tokio::sync::Notify::new();
    let mut stream = client.connect(&notify).await.unwrap();

    server
        .config_sync()
        .publish(3, &snapshot("converged"))
        .unwrap();
    let applied = client.apply_next(&mut stream, &applier).await.unwrap();
    assert_eq!(applied, Some(3));
    assert_eq!(service.current().await.unwrap().0, Some(3));
    assert_eq!(
        service.current().await.unwrap().1.unwrap()["filtering"]["marker"],
        "converged"
    );
    // The client posted the ack, so the master reports zero lag.
    assert_eq!(server.config_sync().node_lag("node-b").unwrap().lag, 0);

    server.shutdown().await;
}

#[tokio::test]
async fn sub_node_backfill_reports_a_gap_after_reconnect() {
    let dir = TempDir::new("backfill-gap");
    let clock = Arc::new(ClusterClock::new(SystemTime::now()));
    let store = ClusterStore::open_in_memory(clock.clone(), TOKEN_TTL)
        .await
        .unwrap();
    let ca = ClusterCa::load_or_generate(&dir.path().join("ca.pem")).unwrap();
    let logs = Arc::new(RecordingLogs {
        highest: AtomicU64::new(10),
    });
    let server = ClusterServer::start(
        ClusterServerConfig {
            listen: ListenConfig {
                bind: IpAddr::V4(Ipv4Addr::LOCALHOST),
                port: 0,
            },
            server_name: "127.0.0.1".to_owned(),
            node_cert_ttl: NODE_CERT_TTL,
            quota: QuotaConfig::default(),
            timing: dnscraft_cluster::TimingConfig::default(),
        },
        ca,
        store.clone(),
        clock.clone(),
        Arc::new(NoWrites),
        logs,
        None,
    )
    .await
    .unwrap();
    let url = format!("https://127.0.0.1:{}", server.addr().port());

    let token = store.mint_join_token("node-b").await.unwrap();
    let pending = PendingNodeIdentity::generate("node-b").unwrap();
    let response = ClusterClient::enroll(
        &url,
        server.server_cert_pem(),
        pending.request(Secret::new(token.expose())),
    )
    .await
    .unwrap();
    let paths = TlsPaths {
        ca_cert: dir.path().join("node-b-ca.pem"),
        node_cert: dir.path().join("node-b.pem"),
        node_key: dir.path().join("node-b.key"),
    };
    let identity = pending.persist(&response, &paths).unwrap();

    let client = ClusterClient::new(&url, &identity, clock.clone()).unwrap();
    let notify = tokio::sync::Notify::new();
    let stream = client.connect(&notify).await.unwrap();
    assert_eq!(stream.master_highest_log_seq(), Some(10));

    // The node's buffer already dropped 11..=49; reconnect must report the
    // gap rather than silently resuming past it.
    let outbox = Arc::new(MockLogOutbox::new(50, 60, 50));
    let streamer = LogStreamer::new(outbox, Arc::new(client), LogConfig::default(), clock);
    let backfill = dnscraft_api::backfill_logs(&streamer, 10).await.unwrap();
    assert_eq!(backfill.from_seq, 50);
    assert_eq!(backfill.missing, 39);
    assert_eq!(
        backfill.gap().expect("gap is reported").code(),
        "cluster.log_gap"
    );
    assert_eq!(backfill.flushed.unwrap().last_seq, 60);

    drop(stream);
    server.shutdown().await;
}

#[tokio::test]
async fn runtime_master_publishes_and_sub_node_converges_end_to_end() {
    let master_dir = TempDir::new("runtime-master");
    let node_dir = TempDir::new("runtime-node");
    let clock = Arc::new(ClusterClock::new(SystemTime::now()));

    let (master_service, _) = service("master", ModuleAppliers::default()).await;
    let master_status = Arc::new(ClusterStatusHandle::new());
    let master_state = AppState::new()
        .with_config_service(Arc::clone(&master_service))
        .with_cluster_status(master_status.clone());
    let mut master_options = ClusterRuntimeOptions::new(master_dir.path());
    master_options.clock = clock.clone();
    master_options.status = master_status;
    let master = ClusterRuntime::start(
        master_config(master_dir.path()),
        &master_state,
        master_options,
    )
    .await
    .unwrap();

    let url = format!("https://{}", master.listen_addr().unwrap());
    let server_cert = master.server_cert_pem().unwrap().to_owned();
    let token = master
        .cluster_store()
        .unwrap()
        .mint_join_token("node-b")
        .await
        .unwrap();

    let (node_service, _) = service("node-b", ModuleAppliers::default()).await;
    let node_status = Arc::new(ClusterStatusHandle::new());
    let node_state = AppState::new()
        .with_config_service(Arc::clone(&node_service))
        .with_cluster_status(node_status.clone());
    let mut node_options = ClusterRuntimeOptions::new(node_dir.path());
    node_options.clock = clock;
    node_options.status = node_status.clone();
    node_options.join_token = Some(Secret::new(token.expose()));
    node_options.master_cert_pem = Some(server_cert);
    let node = ClusterRuntime::start(
        sub_node_config(node_dir.path(), &url),
        &node_state,
        node_options,
    )
    .await
    .unwrap();

    // The sub-node connects and reports reachable (no wall-clock sleep: yield
    // until the spawned connection task makes progress).
    for _ in 0..20_000 {
        if node_status
            .status()
            .is_some_and(|status| status.master_reachable)
        {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert!(
        node_status
            .status()
            .is_some_and(|status| status.master_reachable),
        "sub-node never connected: {:?}",
        node_status.status()
    );

    // A config write on the master must reach the sub-node through the runtime.
    let version = master_service
        .replace(snapshot("e2e"), &ConfigActor::local(), None)
        .await
        .unwrap();
    let sync = master.config_sync().unwrap();
    for _ in 0..20_000 {
        if sync.current_version() == Some(version) {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert_eq!(
        sync.current_version(),
        Some(version),
        "master watcher did not publish; node lag: {:?}",
        sync.node_lag("node-b")
    );
    for _ in 0..20_000 {
        if node_service.current().await.unwrap().0 == Some(version)
            && node_status
                .status()
                .is_some_and(|status| status.applied_version == Some(version))
        {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert_eq!(node_service.current().await.unwrap().0, Some(version));
    let applied = node_status.status().unwrap();
    assert_eq!(applied.role, "sub_node");
    assert_eq!(applied.applied_version, Some(version));
    assert_eq!(applied.lag, 0);
    assert!(applied.last_sync.is_some());

    for _ in 0..20_000 {
        if sync.node_lag("node-b").is_some_and(|node| node.lag == 0) {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert_eq!(sync.node_lag("node-b").unwrap().lag, 0);

    node.shutdown().await;
    master.shutdown().await;
}

// ---------------------------------------------------------------------------
// Auth snapshot apply
// ---------------------------------------------------------------------------

fn oidc_state() -> OidcState {
    use dnscraft_api::AuthConfig;
    let config = AuthConfig {
        oidc_enabled: true,
        oidc_issuer: "https://id.example.com".to_owned(),
        oidc_client_id: "dnscraft".to_owned(),
        oidc_client_secret: dnscraft_api::Secret::new("super-secret-client"),
        ..AuthConfig::default()
    };
    OidcState::from_config_with_clock(&config, Arc::new(ApiClock::new(at(NOW))))
        .unwrap()
        .unwrap()
}

async fn auth_state(db: Db, with_local: bool) -> AuthState {
    let oidc = oidc_state();
    let state = AuthState::new(
        SessionStore::new(db.clone(), IDLE, ABSOLUTE),
        TokenStore::new(db.clone(), MAX_TTL),
    )
    .with_oidc(&oidc);
    if with_local {
        state.with_local_accounts(LocalAccountStore::new(db, 5, Duration::from_secs(15 * 60)))
    } else {
        state
    }
}

#[tokio::test]
async fn auth_snapshot_apply_replaces_local_state_with_hashes_only() {
    // Master: one token, one break-glass account, OIDC settings.
    let master_db = Db::open_in_memory(Arc::new(ApiClock::new(at(NOW))))
        .await
        .unwrap();
    let master = auth_state(master_db.clone(), true).await;
    let created = master
        .tokens()
        .create(
            "alice".to_owned(),
            "ci".to_owned(),
            dnscraft_api::Scope::Admin,
            None,
        )
        .await
        .unwrap();
    let plaintext = created.plaintext().expose().to_owned();
    let accounts = LocalAccountStore::new(master_db.clone(), 5, Duration::from_secs(900));
    accounts
        .upsert("break-glass", "hunter2", dnscraft_api::Role::Admin)
        .await
        .unwrap();
    let pushed = master.auth_snapshot().await.unwrap();
    let wire = serde_json::to_value(&pushed).unwrap();
    assert!(!wire.to_string().contains(&plaintext));
    assert!(!wire.to_string().contains("hunter2"));
    assert!(!wire.to_string().contains("super-secret-client"));

    // Sub-node: an old token that must be replaced.
    let sub_db = Db::open_in_memory(Arc::new(ApiClock::new(at(NOW))))
        .await
        .unwrap();
    let sub = auth_state(sub_db, true).await;
    let old = sub
        .tokens()
        .create(
            "old".to_owned(),
            "old".to_owned(),
            dnscraft_api::Scope::Viewer,
            None,
        )
        .await
        .unwrap();
    let old_plaintext = old.plaintext().expose().to_owned();
    assert!(sub.tokens().authenticate(&old_plaintext).await.is_ok());

    StateAuthApplier::new(Arc::new(sub.clone()))
        .apply(&wire)
        .await
        .unwrap();

    // The master token now authenticates locally; the old token is gone.
    let principal = sub.tokens().authenticate(&plaintext).await.unwrap();
    assert_eq!(principal.actor_id(), "alice");
    assert_eq!(
        sub.tokens()
            .authenticate(&old_plaintext)
            .await
            .unwrap_err()
            .code(),
        "control_api.auth.unauthenticated"
    );
    let applied = sub.auth_snapshot().await.unwrap();
    assert_eq!(applied.tokens, pushed.tokens);
    assert_eq!(applied.local_accounts, pushed.local_accounts);
    assert_eq!(applied.oidc, pushed.oidc);
    assert_eq!(applied.session_epoch, pushed.session_epoch);
}

// ---------------------------------------------------------------------------
// Runtime command
// ---------------------------------------------------------------------------

fn filter_engine(temp: &TempDir) -> Arc<dnscraft_filtering::FilterEngine> {
    use dnscraft_filtering::{
        BlockMode, Clock as FilterClock, FilterConfig, FilterEngine, FilterSetConfig, ListStore,
        SetId, StoreConfig,
    };
    let clock: Arc<dyn FilterClock> = Arc::new(dnscraft_filtering::ManualClock::new(at(NOW)));
    let mut set = FilterSetConfig::new(SetId::new("default").unwrap(), "Default");
    set.block_mode = BlockMode::NxDomain;
    let config = FilterConfig {
        lists: Vec::new(),
        sets: vec![set],
        ..FilterConfig::default()
    };
    let store = ListStore::open_with(temp.path(), StoreConfig::default(), clock.clone()).unwrap();
    FilterEngine::open_without_scheduler(config, store, clock).unwrap()
}

#[tokio::test]
async fn runtime_applier_pauses_resumes_and_temporarily_allows() {
    let temp = TempDir::new("runtime");
    let filter = filter_engine(&temp);
    let state = AppState::new()
        .with_clock(Arc::new(ApiClock::new(at(NOW))))
        .with_filter_engine(Arc::clone(&filter));
    let applier = StateRuntimeApplier::new(state);
    let set = dnscraft_filtering::SetId::new("default").unwrap();

    applier
        .apply_runtime_command(
            "pause",
            &json!({ "filter_set_id": "default", "duration": "PT5M" }),
        )
        .await
        .unwrap();
    assert!(filter.paused_until(&set).is_some());
    applier
        .apply_runtime_command("resume", &json!({ "filter_set_id": "default" }))
        .await
        .unwrap();
    assert!(filter.paused_until(&set).is_none());
    applier
        .apply_runtime_command(
            "temporary_allow",
            &json!({
                "filter_set_id": "default",
                "domain": "allowed.example.com",
                "duration": "PT5M",
            }),
        )
        .await
        .unwrap();
    // An unknown kind is surfaced as `cluster.runtime_command.failed`.
    let error = applier
        .apply_runtime_command("nope", &json!({}))
        .await
        .unwrap_err();
    assert_eq!(error.code(), "cluster.runtime_command.failed");
}

// ---------------------------------------------------------------------------
// Cert install
// ---------------------------------------------------------------------------

#[tokio::test]
async fn cert_installer_installs_a_pushed_chain_without_restart() {
    let dir = TempDir::new("cert");
    let resolver = Arc::new(dnscraft_tls::CertResolver::new());
    let store = dnscraft_tls::CertStore::open(dir.path()).unwrap();
    let installer = TlsCertInstaller::new(Arc::clone(&resolver), store);

    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let params = rcgen::CertificateParams::new(vec!["cert.example.com".to_owned()]).unwrap();
    let cert = params.self_signed(&key).unwrap();
    let expected_leaf = cert.der().as_ref().to_vec();

    installer
        .install(&cert.pem(), &Secret::new(key.serialize_pem()))
        .await
        .unwrap();
    assert!(resolver.has_cert());
    assert_eq!(resolver.leaf_der().unwrap(), expected_leaf);
}

// ---------------------------------------------------------------------------
// RBAC relay
// ---------------------------------------------------------------------------

#[tokio::test]
async fn relayed_viewer_write_is_rejected_and_admin_write_applies_once() {
    let (service, _) = service("master", ModuleAppliers::default()).await;
    let executor =
        ConfigWriteExecutor::new(Arc::clone(&service), Arc::new(ClusterClock::new(at(NOW))));
    let viewer = RelayedActor {
        actor_id: "viewer-a".to_owned(),
        actor_type: "user".to_owned(),
        scope: "viewer".to_owned(),
    };
    let response = executor
        .execute(
            "node-a",
            "req-viewer",
            viewer,
            "PUT".to_owned(),
            "/api/v1/config".to_owned(),
            snapshot("denied"),
            None,
            None,
        )
        .await
        .unwrap();
    assert_eq!(response.status, 403);
    assert_eq!(
        response.body["error"]["code"],
        "control_api.auth.insufficient_scope"
    );
    assert_eq!(service.current().await.unwrap().0, None);

    let admin = RelayedActor {
        actor_id: "admin-a".to_owned(),
        actor_type: "user".to_owned(),
        scope: "admin".to_owned(),
    };
    let first = executor
        .execute(
            "node-a",
            "req-idem-1",
            admin.clone(),
            "PUT".to_owned(),
            "/api/v1/config".to_owned(),
            snapshot("applied"),
            None,
            Some("idem-1".to_owned()),
        )
        .await
        .unwrap();
    assert_eq!(first.status, 200);
    assert_eq!(first.body["data"]["version"], 1);

    // A retry with the same Idempotency-Key returns the stored response and
    // does not create a second config version.
    let retry = executor
        .execute(
            "node-a",
            "req-idem-2",
            admin,
            "PUT".to_owned(),
            "/api/v1/config".to_owned(),
            snapshot("applied"),
            None,
            Some("idem-1".to_owned()),
        )
        .await
        .unwrap();
    assert_eq!(retry.body, first.body);
    assert_eq!(service.current().await.unwrap().0, Some(1));
}

#[tokio::test]
async fn relayed_retry_with_the_same_request_id_applies_once() {
    let (service, db) = service("master", ModuleAppliers::default()).await;
    let executor =
        ConfigWriteExecutor::new(Arc::clone(&service), Arc::new(ClusterClock::new(at(NOW))));
    let admin = RelayedActor {
        actor_id: "admin-a".to_owned(),
        actor_type: "user".to_owned(),
        scope: "admin".to_owned(),
    };

    // No Idempotency-Key: the always-present request_id is the dedupe key, so
    // a keyless retry after a lost response must not apply twice.
    let first = executor
        .execute(
            "node-a",
            "req-keyless",
            admin.clone(),
            "PUT".to_owned(),
            "/api/v1/config".to_owned(),
            snapshot("applied"),
            None,
            None,
        )
        .await
        .unwrap();
    assert_eq!(first.status, 200);
    assert_eq!(first.body["data"]["version"], 1);

    let retry = executor
        .execute(
            "node-a",
            "req-keyless",
            admin,
            "PUT".to_owned(),
            "/api/v1/config".to_owned(),
            snapshot("applied"),
            None,
            None,
        )
        .await
        .unwrap();
    assert_eq!(retry.body, first.body);
    assert_eq!(service.current().await.unwrap().0, Some(1));
    assert_eq!(db.audit_list(10, 0).await.unwrap().len(), 1);
}

#[tokio::test]
async fn relayed_answer_survives_a_master_restart() {
    let (service, db) = service("master", ModuleAppliers::default()).await;
    let dir =
        std::env::temp_dir().join(format!("dnscraft-api-relay-{}-{}", std::process::id(), NOW));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("cluster.db");
    let clock = Arc::new(ClusterClock::new(at(NOW)));
    let admin = RelayedActor {
        actor_id: "admin-a".to_owned(),
        actor_type: "user".to_owned(),
        scope: "admin".to_owned(),
    };

    let store = ClusterStore::open(&path, clock.clone(), TOKEN_TTL)
        .await
        .unwrap();
    let executor = ConfigWriteExecutor::with_store(Arc::clone(&service), clock.clone(), store);
    let first = executor
        .execute(
            "node-a",
            "req-restart",
            admin.clone(),
            "PUT".to_owned(),
            "/api/v1/config".to_owned(),
            snapshot("applied"),
            None,
            None,
        )
        .await
        .unwrap();
    assert_eq!(first.status, 200);
    drop(executor);

    // A new master process on the same database answers the retry from the
    // stored response; the write is not applied a second time.
    let store = ClusterStore::open(&path, clock.clone(), TOKEN_TTL)
        .await
        .unwrap();
    let restarted = ConfigWriteExecutor::with_store(Arc::clone(&service), clock, store);
    let retry = restarted
        .execute(
            "node-a",
            "req-restart",
            admin,
            "PUT".to_owned(),
            "/api/v1/config".to_owned(),
            snapshot("applied"),
            None,
            None,
        )
        .await
        .unwrap();
    assert_eq!(retry.status, 200);
    assert_eq!(retry.body, first.body);
    assert_eq!(service.current().await.unwrap().0, Some(1));
    assert_eq!(db.audit_list(10, 0).await.unwrap().len(), 1);

    drop(restarted);
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn relayed_unknown_actor_type_is_rejected_without_audit() {
    let (service, db) = service("master", ModuleAppliers::default()).await;
    let executor =
        ConfigWriteExecutor::new(Arc::clone(&service), Arc::new(ClusterClock::new(at(NOW))));
    let mut actor = admin_actor();
    actor.actor_type = "service".to_owned();

    let response = executor
        .execute(
            "node-a",
            "req-unknown-actor",
            actor,
            "PUT".to_owned(),
            "/api/v1/config".to_owned(),
            snapshot("bad-actor"),
            None,
            None,
        )
        .await
        .unwrap();
    assert_eq!(response.status, 403);
    assert_eq!(
        response.body["error"]["code"],
        "control_api.auth.invalid_scope"
    );
    assert_eq!(service.current().await.unwrap().0, None);
    assert!(
        db.audit_list(10, 0).await.unwrap().is_empty(),
        "an unknown actor type must never be persisted"
    );
}

#[tokio::test]
async fn relayed_write_audits_the_originating_node_and_direct_writes_the_local_node() {
    let (service, db) = service("master", ModuleAppliers::default()).await;
    let executor =
        ConfigWriteExecutor::new(Arc::clone(&service), Arc::new(ClusterClock::new(at(NOW))));
    let admin = RelayedActor {
        actor_id: "admin-a".to_owned(),
        actor_type: "user".to_owned(),
        scope: "admin".to_owned(),
    };

    let response = executor
        .execute(
            "node-b",
            "req-audit",
            admin,
            "PUT".to_owned(),
            "/api/v1/config".to_owned(),
            snapshot("relayed"),
            None,
            None,
        )
        .await
        .unwrap();
    assert_eq!(response.status, 200);

    // A direct write on the master keeps the master's own identity.
    let version = service
        .replace(
            snapshot("direct"),
            &ConfigActor::new("admin-a", "user"),
            None,
        )
        .await
        .unwrap();
    assert_eq!(version, 2);

    let rows = db.audit_list(10, 0).await.unwrap();
    assert_eq!(rows.len(), 2);
    // Newest first: the direct write, then the relayed write.
    assert_eq!(rows[0].node_id, "master");
    assert_eq!(rows[0].actor_id, "admin-a");
    assert_eq!(rows[1].node_id, "node-b");
    assert_eq!(rows[1].actor_id, "admin-a");
}

// ---------------------------------------------------------------------------
// Relay surface
// ---------------------------------------------------------------------------

fn admin_actor() -> RelayedActor {
    RelayedActor {
        actor_id: "admin-a".to_owned(),
        actor_type: "user".to_owned(),
        scope: "admin".to_owned(),
    }
}

#[tokio::test]
async fn relayed_module_writes_dispatch_through_the_config_service() {
    let (service, db) = service("master", ModuleAppliers::default()).await;
    let executor =
        ConfigWriteExecutor::new(Arc::clone(&service), Arc::new(ClusterClock::new(at(NOW))));

    let writes = [
        (
            "POST",
            "/api/v1/filter-sets",
            json!({
                "id": "family",
                "name": "Family",
                "lists": [],
                "custom_rules": "",
                "services": [],
                "block_mode": "nxdomain",
            }),
        ),
        (
            "POST",
            "/api/v1/listeners",
            json!({ "id": "l1", "protocol": "udp53", "address": "127.0.0.1:53" }),
        ),
        (
            "PUT",
            "/api/v1/policy/profiles/kids",
            json!({ "filter_set": "family" }),
        ),
        (
            "PUT",
            "/api/v1/policy/views/kids",
            json!({ "profile": "kids", "subnets": ["10.0.0.0/8"] }),
        ),
        (
            "PUT",
            "/api/v1/tls",
            json!({ "public_domain": "dns.example.com" }),
        ),
        (
            "POST",
            "/api/v1/clients/manual",
            json!({ "name": "laptop", "ip": "192.0.2.10" }),
        ),
        (
            "PUT",
            "/api/v1/policy/pause",
            json!({ "until": "2026-01-01T00:00:00Z" }),
        ),
        ("DELETE", "/api/v1/policy/pause", json!({})),
        ("DELETE", "/api/v1/listeners", json!({ "id": "l1" })),
    ];
    for (method, path, body) in writes {
        let response = executor
            .execute(
                "node-b",
                &format!("req-{method}-{path}"),
                admin_actor(),
                method.to_owned(),
                path.to_owned(),
                body,
                None,
                None,
            )
            .await
            .unwrap();
        assert_eq!(response.status, 200, "{method} {path}: {:?}", response.body);
        assert!(response.body["data"]["version"].is_i64(), "{path}");
    }

    let (version, snapshot) = service.current().await.unwrap();
    assert_eq!(version, Some(9));
    let snapshot = snapshot.unwrap();
    assert_eq!(snapshot["filtering"]["sets"][0]["id"], "family");
    assert_eq!(snapshot["listeners"]["listeners"], json!([]));
    assert_eq!(snapshot["policy"]["profiles"][0]["id"], "kids");
    assert_eq!(snapshot["policy"]["views"][0]["id"], "kids");
    assert_eq!(snapshot["tls"]["public_domain"], "dns.example.com");
    assert_eq!(snapshot["clients"]["manual"][0]["name"], "laptop");
    assert!(snapshot["policy"].get("pause").is_none());

    // Rollback is relayed through the same path and audits the sub-node too.
    let rollback = executor
        .execute(
            "node-b",
            "req-rollback",
            admin_actor(),
            "POST".to_owned(),
            "/api/v1/config/versions/1/rollback".to_owned(),
            json!({}),
            None,
            None,
        )
        .await
        .unwrap();
    assert_eq!(rollback.status, 200);
    assert_eq!(rollback.body["data"]["restored_from"], 1);
    assert_eq!(service.current().await.unwrap().0, Some(10));

    let rows = db.audit_list(100, 0).await.unwrap();
    assert_eq!(rows.len(), 10);
    assert!(rows.iter().all(|row| row.node_id == "node-b"), "{rows:?}");
    assert!(rows.iter().all(|row| row.actor_id == "admin-a"));
}

#[tokio::test]
async fn relayed_non_config_routes_are_rejected_without_applying() {
    let (service, db) = service("master", ModuleAppliers::default()).await;
    let executor =
        ConfigWriteExecutor::new(Arc::clone(&service), Arc::new(ClusterClock::new(at(NOW))));

    for path in [
        "/api/v1/auth/tokens",
        "/api/v1/tls/status",
        "/api/v1/tls/renew",
        "/api/v1/clients/sync",
        "/api/v1/cluster/join-tokens",
    ] {
        let response = executor
            .execute(
                "node-b",
                &format!("req-nonconfig-{path}"),
                admin_actor(),
                "POST".to_owned(),
                path.to_owned(),
                json!({}),
                None,
                None,
            )
            .await
            .unwrap();
        assert_eq!(response.status, 404, "{path}: {:?}", response.body);
        assert_eq!(response.body["error"]["code"], "control_api.not_found");
    }
    assert_eq!(service.current().await.unwrap().0, None);
    assert!(db.audit_list(10, 0).await.unwrap().is_empty());
}

// ---------------------------------------------------------------------------
// Master broadcast triggers
// ---------------------------------------------------------------------------

#[tokio::test]
async fn master_runtime_command_endpoint_broadcasts_to_the_sub_node() {
    use tower::ServiceExt as _;

    let master_dir = TempDir::new("broadcast-master");
    let node_dir = TempDir::new("broadcast-node");
    let api_clock = Arc::new(ApiClock::new(at(NOW)));
    let cluster_clock = Arc::new(ClusterClock::new(SystemTime::now()));

    let master_filter = filter_engine(&master_dir);
    let (master_service, _) = service("master", ModuleAppliers::default()).await;
    let master_status = Arc::new(ClusterStatusHandle::new());
    let master_state = AppState::new()
        .with_config_service(Arc::clone(&master_service))
        .with_cluster_status(master_status.clone())
        .with_clock(api_clock.clone())
        .with_filter_engine(Arc::clone(&master_filter));
    let mut master_options = ClusterRuntimeOptions::new(master_dir.path());
    master_options.clock = cluster_clock.clone();
    master_options.status = master_status.clone();
    let master = ClusterRuntime::start(
        master_config(master_dir.path()),
        &master_state,
        master_options,
    )
    .await
    .unwrap();

    let url = format!("https://{}", master.listen_addr().unwrap());
    let server_cert = master.server_cert_pem().unwrap().to_owned();
    let token = master
        .cluster_store()
        .unwrap()
        .mint_join_token("node-b")
        .await
        .unwrap();

    let node_filter = filter_engine(&node_dir);
    let (node_service, _) = service("node-b", ModuleAppliers::default()).await;
    let node_status = Arc::new(ClusterStatusHandle::new());
    let node_state = AppState::new()
        .with_config_service(Arc::clone(&node_service))
        .with_cluster_status(node_status.clone())
        .with_clock(api_clock)
        .with_filter_engine(Arc::clone(&node_filter));
    let mut node_options = ClusterRuntimeOptions::new(node_dir.path());
    node_options.clock = cluster_clock;
    node_options.status = node_status.clone();
    node_options.join_token = Some(Secret::new(token.expose()));
    node_options.master_cert_pem = Some(server_cert);
    let node = ClusterRuntime::start(
        sub_node_config(node_dir.path(), &url),
        &node_state,
        node_options,
    )
    .await
    .unwrap();

    for _ in 0..20_000 {
        if node_status
            .status()
            .is_some_and(|status| status.master_reachable)
        {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert!(
        node_status
            .status()
            .is_some_and(|status| status.master_reachable),
        "sub-node never connected"
    );

    let set = dnscraft_filtering::SetId::new("default").unwrap();
    let post = |path: &str, body: Value| {
        axum::http::Request::builder()
            .method("POST")
            .uri(path)
            .header(axum::http::header::CONTENT_TYPE, "application/json")
            .extension(axum::extract::ConnectInfo(std::net::SocketAddr::from((
                [127, 0, 0, 1],
                40000,
            ))))
            .body(axum::body::Body::from(body.to_string()))
            .unwrap()
    };
    let response = master_state
        .clone()
        .router()
        .oneshot(post(
            "/api/v1/filtering/pause",
            json!({ "filter_set_id": "default", "duration": "PT5M" }),
        ))
        .await
        .unwrap();
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    assert_eq!(
        status,
        axum::http::StatusCode::OK,
        "{}",
        String::from_utf8_lossy(&body)
    );
    for _ in 0..20_000 {
        if node_filter.paused_until(&set).is_some() {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert!(
        node_filter.paused_until(&set).is_some(),
        "sub-node did not apply the broadcast pause"
    );

    let response = master_state
        .clone()
        .router()
        .oneshot(post(
            "/api/v1/filtering/resume",
            json!({ "filter_set_id": "default" }),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), axum::http::StatusCode::OK);
    for _ in 0..20_000 {
        if node_filter.paused_until(&set).is_none() {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert!(
        node_filter.paused_until(&set).is_none(),
        "sub-node did not apply the broadcast resume"
    );

    node.shutdown().await;
    master.shutdown().await;
}

#[tokio::test]
async fn sub_node_retries_after_a_failed_config_apply_and_recovers() {
    let master_dir = TempDir::new("retry-master");
    let node_dir = TempDir::new("retry-node");
    let api_clock = Arc::new(ApiClock::new(at(NOW)));
    let cluster_clock = Arc::new(ClusterClock::new(SystemTime::now()));

    let (master_service, _) = service("master", ModuleAppliers::default()).await;
    let master_status = Arc::new(ClusterStatusHandle::new());
    let master_state = AppState::new()
        .with_config_service(Arc::clone(&master_service))
        .with_cluster_status(master_status.clone())
        .with_clock(api_clock.clone());
    let mut master_options = ClusterRuntimeOptions::new(master_dir.path());
    master_options.clock = cluster_clock.clone();
    master_options.status = master_status.clone();
    let master = ClusterRuntime::start(
        master_config(master_dir.path()),
        &master_state,
        master_options,
    )
    .await
    .unwrap();

    let url = format!("https://{}", master.listen_addr().unwrap());
    let server_cert = master.server_cert_pem().unwrap().to_owned();
    let token = master
        .cluster_store()
        .unwrap()
        .mint_join_token("node-b")
        .await
        .unwrap();

    let (node_service, _) = service("node-b", ModuleAppliers::default()).await;
    let node_status = Arc::new(ClusterStatusHandle::new());
    let node_state = AppState::new()
        .with_config_service(Arc::clone(&node_service))
        .with_cluster_status(node_status.clone())
        .with_clock(api_clock)
        .with_filter_engine(filter_engine(&node_dir));
    let mut node_options = ClusterRuntimeOptions::new(node_dir.path());
    node_options.clock = cluster_clock;
    node_options.status = node_status.clone();
    node_options.join_token = Some(Secret::new(token.expose()));
    node_options.master_cert_pem = Some(server_cert);
    let node = ClusterRuntime::start(
        sub_node_config(node_dir.path(), &url),
        &node_state,
        node_options,
    )
    .await
    .unwrap();

    for _ in 0..20_000 {
        if node_status
            .status()
            .is_some_and(|status| status.master_reachable)
        {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert!(
        node_status
            .status()
            .is_some_and(|status| status.master_reachable),
        "sub-node never connected"
    );

    // Watch for the transient `master_reachable = false` the apply failure
    // must set while the node tears down and reconnects.
    let saw_disconnect = Arc::new(AtomicBool::new(false));
    let watcher = {
        let status = Arc::clone(&node_status);
        let flag = Arc::clone(&saw_disconnect);
        tokio::spawn(async move {
            loop {
                if status
                    .status()
                    .is_some_and(|status| !status.master_reachable)
                {
                    flag.store(true, Ordering::SeqCst);
                    return;
                }
                tokio::task::yield_now().await;
            }
        })
    };

    // Version 1 carries a default view valid only on node-a, so node-b's
    // apply must fail.
    let mut invalid = snapshot("invalid");
    invalid["policy"] = json!({
        "views": [{ "id": "only-a", "is_default": true, "nodes": ["node-a"] }],
    });
    let actor = ConfigActor::new("test", "user");
    master_service
        .replace(invalid, &actor, None)
        .await
        .expect("master stores the invalid snapshot");

    for _ in 0..20_000 {
        if saw_disconnect.load(Ordering::SeqCst) {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert!(
        saw_disconnect.load(Ordering::SeqCst),
        "the failed apply never reported the master as unreachable"
    );

    // A later healthy version must still reach the node: the loop retried
    // instead of dying on the first apply error.
    master_service
        .replace(snapshot("healthy"), &actor, None)
        .await
        .expect("master stores the healthy snapshot");
    for _ in 0..40_000 {
        if node_service.current().await.unwrap().0 == Some(2) {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert_eq!(
        node_service.current().await.unwrap(),
        (Some(2), Some(snapshot("healthy"))),
        "the sub-node stayed stranded after a config apply failure"
    );
    watcher.abort();

    node.shutdown().await;
    master.shutdown().await;
}

#[tokio::test]
async fn mcp_runtime_tools_broadcast_to_the_sub_node() {
    let master_dir = TempDir::new("mcp-broadcast-master");
    let node_dir = TempDir::new("mcp-broadcast-node");
    let api_clock = Arc::new(ApiClock::new(at(NOW)));
    let cluster_clock = Arc::new(ClusterClock::new(SystemTime::now()));

    let master_filter = filter_engine(&master_dir);
    let (master_service, _) = service("master", ModuleAppliers::default()).await;
    let master_status = Arc::new(ClusterStatusHandle::new());
    let master_state = AppState::new()
        .with_config_service(Arc::clone(&master_service))
        .with_cluster_status(master_status.clone())
        .with_clock(api_clock.clone())
        .with_filter_engine(Arc::clone(&master_filter));
    let mut master_options = ClusterRuntimeOptions::new(master_dir.path());
    master_options.clock = cluster_clock.clone();
    master_options.status = master_status.clone();
    let master = ClusterRuntime::start(
        master_config(master_dir.path()),
        &master_state,
        master_options,
    )
    .await
    .unwrap();

    // The MCP backend is built independently of `AppState`; share the master
    // broadcast handle explicitly, as the production assembly does.
    let broadcast = Arc::new(Mutex::new(None));
    let backend_clock = Arc::clone(&api_clock) as Arc<dyn dnscraft_api::Clock>;
    let backend = mcp_backend_for_test_writes_with_broadcast(
        Arc::clone(&master_filter),
        None,
        None,
        Arc::clone(&master_service),
        None,
        None,
        backend_clock,
        McpConfig::default(),
        None,
        Arc::clone(&broadcast),
    );

    let url = format!("https://{}", master.listen_addr().unwrap());
    let server_cert = master.server_cert_pem().unwrap().to_owned();
    let token = master
        .cluster_store()
        .unwrap()
        .mint_join_token("node-b")
        .await
        .unwrap();

    let node_filter = filter_engine(&node_dir);
    let (node_service, _) = service("node-b", ModuleAppliers::default()).await;
    let node_status = Arc::new(ClusterStatusHandle::new());
    let node_state = AppState::new()
        .with_config_service(Arc::clone(&node_service))
        .with_cluster_status(node_status.clone())
        .with_clock(api_clock)
        .with_filter_engine(Arc::clone(&node_filter));
    let mut node_options = ClusterRuntimeOptions::new(node_dir.path());
    node_options.clock = cluster_clock;
    node_options.status = node_status.clone();
    node_options.join_token = Some(Secret::new(token.expose()));
    node_options.master_cert_pem = Some(server_cert);
    let node = ClusterRuntime::start(
        sub_node_config(node_dir.path(), &url),
        &node_state,
        node_options,
    )
    .await
    .unwrap();

    for _ in 0..20_000 {
        if node_status
            .status()
            .is_some_and(|status| status.master_reachable)
        {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert!(
        node_status
            .status()
            .is_some_and(|status| status.master_reachable),
        "sub-node never connected"
    );
    *broadcast
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = master.broadcast_handle();

    let set = dnscraft_filtering::SetId::new("default").unwrap();
    backend
        .pause_filter_set(PauseParams {
            filter_set_id: None,
            duration: PauseDuration::Pt5M,
        })
        .await
        .expect("MCP pause");
    for _ in 0..20_000 {
        if node_filter.paused_until(&set).is_some() {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert!(
        node_filter.paused_until(&set).is_some(),
        "sub-node did not apply the MCP broadcast pause"
    );

    backend.resume_filter_set(None).await.expect("MCP resume");
    for _ in 0..20_000 {
        if node_filter.paused_until(&set).is_none() {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert!(
        node_filter.paused_until(&set).is_none(),
        "sub-node did not apply the MCP broadcast resume"
    );

    node.shutdown().await;
    master.shutdown().await;
}

#[tokio::test]
async fn admin_revoke_closes_a_connected_sub_node_stream() {
    use tower::ServiceExt as _;

    let master_dir = TempDir::new("revoke-master");
    let node_dir = TempDir::new("revoke-node");
    let api_clock = Arc::new(ApiClock::new(at(NOW)));
    let cluster_clock = Arc::new(ClusterClock::new(SystemTime::now()));

    let (master_service, _) = service("master", ModuleAppliers::default()).await;
    let master_status = Arc::new(ClusterStatusHandle::new());
    let master_state = AppState::new()
        .with_config_service(Arc::clone(&master_service))
        .with_cluster_status(master_status.clone())
        .with_clock(api_clock.clone());
    let mut master_options = ClusterRuntimeOptions::new(master_dir.path());
    master_options.clock = cluster_clock.clone();
    master_options.status = master_status.clone();
    let master = ClusterRuntime::start(
        master_config(master_dir.path()),
        &master_state,
        master_options,
    )
    .await
    .unwrap();

    let store = Arc::new(master.cluster_store().unwrap());
    let url = format!("https://{}", master.listen_addr().unwrap());
    let server_cert = master.server_cert_pem().unwrap().to_owned();
    let token = store.mint_join_token("node-b").await.unwrap();

    let (node_service, _) = service("node-b", ModuleAppliers::default()).await;
    let node_status = Arc::new(ClusterStatusHandle::new());
    let node_state = AppState::new()
        .with_config_service(Arc::clone(&node_service))
        .with_cluster_status(node_status.clone())
        .with_clock(api_clock);
    let mut node_options = ClusterRuntimeOptions::new(node_dir.path());
    node_options.clock = cluster_clock;
    node_options.status = node_status.clone();
    node_options.join_token = Some(Secret::new(token.expose()));
    node_options.master_cert_pem = Some(server_cert);
    let node = ClusterRuntime::start(
        sub_node_config(node_dir.path(), &url),
        &node_state,
        node_options,
    )
    .await
    .unwrap();

    for _ in 0..20_000 {
        if node_status
            .status()
            .is_some_and(|status| status.master_reachable)
        {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert!(
        node_status
            .status()
            .is_some_and(|status| status.master_reachable),
        "sub-node never connected"
    );
    for _ in 0..20_000 {
        if !master.config_sync().unwrap().lag().is_empty() {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert_eq!(master.config_sync().unwrap().lag().len(), 1);

    // The admin surface only exists when the registry is attached.
    let admin_state = master_state.clone().with_cluster_store(store);
    let request = axum::http::Request::builder()
        .method("DELETE")
        .uri("/api/v1/cluster/nodes/node-b")
        .extension(axum::extract::ConnectInfo(std::net::SocketAddr::from((
            [127, 0, 0, 1],
            40_000,
        ))))
        .body(axum::body::Body::empty())
        .unwrap();
    let response = admin_state.router().oneshot(request).await.unwrap();
    assert_eq!(response.status(), axum::http::StatusCode::OK);

    // The sender is gone, so the stream ends and no reconnect succeeds.
    assert!(
        master.config_sync().unwrap().lag().is_empty(),
        "the revoked node must be unregistered immediately"
    );
    for _ in 0..20_000 {
        if !node_status
            .status()
            .is_some_and(|status| status.master_reachable)
        {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert!(
        !node_status.status().unwrap().master_reachable,
        "the revoked node's stream must end"
    );

    // A later publish has no target.
    master_service
        .replace(snapshot("after-revoke"), &ConfigActor::local(), None)
        .await
        .unwrap();
    assert!(master.config_sync().unwrap().lag().is_empty());

    node.shutdown().await;
    master.shutdown().await;
}

#[tokio::test]
async fn master_auth_change_pushes_a_snapshot_the_sub_node_applies() {
    let master_dir = TempDir::new("auth-master");
    let node_dir = TempDir::new("auth-node");
    let cluster_clock = Arc::new(ClusterClock::new(SystemTime::now()));

    let master_auth = auth_state(
        Db::open_in_memory(Arc::new(ApiClock::new(at(NOW))))
            .await
            .unwrap(),
        false,
    )
    .await;
    let (master_service, _) = service("master", ModuleAppliers::default()).await;
    let master_status = Arc::new(ClusterStatusHandle::new());
    let master_state = AppState::new()
        .with_config_service(Arc::clone(&master_service))
        .with_cluster_status(master_status.clone())
        .with_auth(master_auth.clone());
    let mut master_options = ClusterRuntimeOptions::new(master_dir.path());
    master_options.clock = cluster_clock.clone();
    master_options.status = master_status;
    let master = ClusterRuntime::start(
        master_config(master_dir.path()),
        &master_state,
        master_options,
    )
    .await
    .unwrap();

    let url = format!("https://{}", master.listen_addr().unwrap());
    let server_cert = master.server_cert_pem().unwrap().to_owned();
    let token = master
        .cluster_store()
        .unwrap()
        .mint_join_token("node-b")
        .await
        .unwrap();

    let node_auth = auth_state(
        Db::open_in_memory(Arc::new(ApiClock::new(at(NOW))))
            .await
            .unwrap(),
        false,
    )
    .await;
    let (node_service, _) = service("node-b", ModuleAppliers::default()).await;
    let node_status = Arc::new(ClusterStatusHandle::new());
    let node_state = AppState::new()
        .with_config_service(Arc::clone(&node_service))
        .with_cluster_status(node_status.clone())
        .with_auth(node_auth.clone());
    let mut node_options = ClusterRuntimeOptions::new(node_dir.path());
    node_options.clock = cluster_clock;
    node_options.status = node_status.clone();
    node_options.join_token = Some(Secret::new(token.expose()));
    node_options.master_cert_pem = Some(server_cert);
    let node = ClusterRuntime::start(
        sub_node_config(node_dir.path(), &url),
        &node_state,
        node_options,
    )
    .await
    .unwrap();

    for _ in 0..20_000 {
        if node_status
            .status()
            .is_some_and(|status| status.master_reachable)
        {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert!(
        node_status
            .status()
            .is_some_and(|status| status.master_reachable),
        "sub-node never connected"
    );

    let created = master_auth
        .tokens()
        .create(
            "alice".to_owned(),
            "ci".to_owned(),
            dnscraft_api::Scope::Admin,
            None,
        )
        .await
        .unwrap();
    let plaintext = created.plaintext().expose().to_owned();
    for _ in 0..20_000 {
        if node_auth.tokens().authenticate(&plaintext).await.is_ok() {
            break;
        }
        tokio::task::yield_now().await;
    }
    let principal = node_auth
        .tokens()
        .authenticate(&plaintext)
        .await
        .expect("sub-node applied the pushed auth snapshot");
    assert_eq!(principal.actor_id(), "alice");
    assert_eq!(
        node_auth.auth_snapshot().await.unwrap().session_epoch,
        master_auth.auth_snapshot().await.unwrap().session_epoch
    );

    node.shutdown().await;
    master.shutdown().await;
}

#[tokio::test]
async fn sub_node_receives_auth_snapshot_on_connect() {
    let master_dir = TempDir::new("connect-auth-master");
    let node_dir = TempDir::new("connect-auth-node");
    let cluster_clock = Arc::new(ClusterClock::new(SystemTime::now()));

    let master_auth = auth_state(
        Db::open_in_memory(Arc::new(ApiClock::new(at(NOW))))
            .await
            .unwrap(),
        false,
    )
    .await;
    // Created before the node ever connects: no change notification follows,
    // so only the connect-time snapshot can deliver it.
    let created = master_auth
        .tokens()
        .create(
            "alice".to_owned(),
            "ci".to_owned(),
            dnscraft_api::Scope::Admin,
            None,
        )
        .await
        .unwrap();
    let plaintext = created.plaintext().expose().to_owned();

    let (master_service, _) = service("master", ModuleAppliers::default()).await;
    let master_status = Arc::new(ClusterStatusHandle::new());
    let master_state = AppState::new()
        .with_config_service(Arc::clone(&master_service))
        .with_cluster_status(master_status.clone())
        .with_auth(master_auth.clone());
    let mut master_options = ClusterRuntimeOptions::new(master_dir.path());
    master_options.clock = cluster_clock.clone();
    master_options.status = master_status;
    let master = ClusterRuntime::start(
        master_config(master_dir.path()),
        &master_state,
        master_options,
    )
    .await
    .unwrap();

    let url = format!("https://{}", master.listen_addr().unwrap());
    let server_cert = master.server_cert_pem().unwrap().to_owned();
    let token = master
        .cluster_store()
        .unwrap()
        .mint_join_token("node-b")
        .await
        .unwrap();

    let node_auth = auth_state(
        Db::open_in_memory(Arc::new(ApiClock::new(at(NOW))))
            .await
            .unwrap(),
        false,
    )
    .await;
    let (node_service, _) = service("node-b", ModuleAppliers::default()).await;
    let node_status = Arc::new(ClusterStatusHandle::new());
    let node_state = AppState::new()
        .with_config_service(Arc::clone(&node_service))
        .with_cluster_status(node_status.clone())
        .with_auth(node_auth.clone());
    let mut node_options = ClusterRuntimeOptions::new(node_dir.path());
    node_options.clock = cluster_clock;
    node_options.status = node_status;
    node_options.join_token = Some(Secret::new(token.expose()));
    node_options.master_cert_pem = Some(server_cert);
    let node = ClusterRuntime::start(
        sub_node_config(node_dir.path(), &url),
        &node_state,
        node_options,
    )
    .await
    .unwrap();

    for _ in 0..20_000 {
        if node_auth.tokens().authenticate(&plaintext).await.is_ok() {
            break;
        }
        tokio::task::yield_now().await;
    }
    node_auth
        .tokens()
        .authenticate(&plaintext)
        .await
        .expect("the connect-time auth snapshot must reach the node");

    node.shutdown().await;
    master.shutdown().await;
}

#[tokio::test]
async fn offline_replay_is_dropped_after_the_token_is_revoked() {
    let master_dir = TempDir::new("replay-master");
    let node_dir = TempDir::new("replay-node");
    let cluster_clock = Arc::new(ClusterClock::new(SystemTime::now()));

    let master_auth = auth_state(
        Db::open_in_memory(Arc::new(ApiClock::new(at(NOW))))
            .await
            .unwrap(),
        false,
    )
    .await;
    let created = master_auth
        .tokens()
        .create(
            "alice".to_owned(),
            "queued".to_owned(),
            dnscraft_api::Scope::Admin,
            None,
        )
        .await
        .unwrap();
    let (master_service, _) = service("master", ModuleAppliers::default()).await;

    // The sub-node caches the pre-revocation snapshot, then the token is
    // revoked on the master while the node is offline.
    let node_auth = auth_state(
        Db::open_in_memory(Arc::new(ApiClock::new(at(NOW))))
            .await
            .unwrap(),
        false,
    )
    .await;
    node_auth
        .apply_auth_snapshot(&master_auth.auth_snapshot().await.unwrap())
        .await
        .unwrap();
    master_auth.tokens().revoke(created.id()).await.unwrap();

    let queue_store = ClusterStore::open_in_memory(cluster_clock.clone(), TOKEN_TTL)
        .await
        .unwrap();
    let queue = Arc::new(OfflineWriteQueue::new(
        queue_store,
        OfflineWritesConfig {
            enabled: true,
            queue_max_entries: 10,
            max_age: Duration::from_secs(3600),
        },
    ));
    queue
        .enqueue(WriteRelay {
            request_id: "queued-1".to_owned(),
            idempotency_key: Some("idem-1".to_owned()),
            if_match: Some("\"v1\"".to_owned()),
            method: "PUT".to_owned(),
            path: "/api/v1/config".to_owned(),
            body: snapshot("offline"),
            actor: RelayedActor {
                actor_id: "alice".to_owned(),
                actor_type: "token".to_owned(),
                scope: "admin".to_owned(),
            },
        })
        .await
        .unwrap();

    let master_status = Arc::new(ClusterStatusHandle::new());
    let master_state = AppState::new()
        .with_config_service(Arc::clone(&master_service))
        .with_cluster_status(master_status.clone())
        .with_auth(master_auth);
    let mut master_options = ClusterRuntimeOptions::new(master_dir.path());
    master_options.clock = cluster_clock.clone();
    master_options.status = master_status;
    let master = ClusterRuntime::start(
        master_config(master_dir.path()),
        &master_state,
        master_options,
    )
    .await
    .unwrap();

    let url = format!("https://{}", master.listen_addr().unwrap());
    let server_cert = master.server_cert_pem().unwrap().to_owned();
    let token = master
        .cluster_store()
        .unwrap()
        .mint_join_token("node-b")
        .await
        .unwrap();

    let (node_service, _) = service("node-b", ModuleAppliers::default()).await;
    let node_status = Arc::new(ClusterStatusHandle::new());
    let node_state = AppState::new()
        .with_config_service(Arc::clone(&node_service))
        .with_cluster_status(node_status.clone())
        .with_auth(node_auth)
        .with_offline_write_queue(Arc::clone(&queue));
    let mut node_options = ClusterRuntimeOptions::new(node_dir.path());
    node_options.clock = cluster_clock;
    node_options.status = node_status;
    node_options.join_token = Some(Secret::new(token.expose()));
    node_options.master_cert_pem = Some(server_cert);
    let node = ClusterRuntime::start(
        sub_node_config(node_dir.path(), &url),
        &node_state,
        node_options,
    )
    .await
    .unwrap();

    for _ in 0..20_000 {
        if queue.status().await.unwrap().expired == 1 {
            break;
        }
        tokio::task::yield_now().await;
    }
    let status = queue.status().await.unwrap();
    assert_eq!(status.expired, 1, "stale queued write must be dropped");
    assert_eq!(status.applied, 0);
    assert_eq!(status.failed, 0);
    assert_eq!(
        master_service.current().await.unwrap().0,
        None,
        "the master must never execute a write from a revoked token"
    );

    node.shutdown().await;
    master.shutdown().await;
}

// ---------------------------------------------------------------------------
// Node-scoped policy views
// ---------------------------------------------------------------------------

fn views_snapshot() -> Value {
    json!({
        "filtering": { "lists": [], "sets": [] },
        "clients": {},
        "policy": {
            "profiles": [
                { "id": "prof" }
            ],
            "views": [
                {
                    "id": "all", "is_default": true,
                    "subnets": ["0.0.0.0/0"], "client_ids": [],
                    "records": [], "profile": "prof"
                },
                {
                    "id": "node-a-only", "is_default": false,
                    "nodes": ["node-a"],
                    "subnets": ["10.0.0.0/8"], "client_ids": [],
                    "records": [], "profile": "prof"
                },
                {
                    "id": "node-b-only", "is_default": false,
                    "nodes": ["node-b"],
                    "subnets": ["10.0.0.0/8"], "client_ids": [],
                    "records": [], "profile": "prof"
                }
            ]
        },
        "listeners": {},
        "tls": {}
    })
}

#[tokio::test]
async fn node_scoped_views_are_filtered_per_node_at_apply_time() {
    let filtered = node_scoped_views(&views_snapshot(), "node-a").unwrap();
    let ids: Vec<&str> = filtered["policy"]["views"]
        .as_array()
        .unwrap()
        .iter()
        .map(|view| view["id"].as_str().unwrap())
        .collect();
    assert_eq!(ids, ["all", "node-a-only"]);

    let (service, _) = service("node-b", ModuleAppliers::default()).await;
    let applier = SyncedConfigApplier::new(Arc::clone(&service), "node-b");
    applier.apply(2, &views_snapshot()).await.unwrap();
    let stored = service.current().await.unwrap().1.unwrap();
    let ids: Vec<&str> = stored["policy"]["views"]
        .as_array()
        .unwrap()
        .iter()
        .map(|view| view["id"].as_str().unwrap())
        .collect();
    assert_eq!(ids, ["all", "node-b-only"]);
}

#[tokio::test]
async fn a_default_view_invalid_on_the_node_is_rejected() {
    let mut snapshot = views_snapshot();
    snapshot["policy"]["views"][0]["nodes"] = json!(["node-b"]);
    let error = node_scoped_views(&snapshot, "node-a").unwrap_err();
    assert_eq!(error.code(), "cluster.config.apply");
    assert!(error.to_string().contains("policy.config.invalid"));
}

// ---------------------------------------------------------------------------
// Log outbox / ingest
// ---------------------------------------------------------------------------

fn remote_record(id: &str, seq: u64) -> LogRecord {
    LogRecord {
        id: id.to_owned(),
        record: json!({
            "id": id,
            "time_us": NOW * 1_000_000 + seq,
            "source_ip": "192.0.2.10",
            "query_name": format!("q{seq}.example.com"),
            "listener_id": "l1",
            "protocol": "udp53",
            "source_ip_truncated": false,
            "client_id": null,
            "client_name": null,
            "query_type": "A",
            "query_class": "IN",
            "view_id": "all",
            "profile_id": "prof",
            "status": "allowed",
            "answer_source": "cache",
            "rcode": "NOERROR",
            "record": { "id": id, "node_id": "node-b" }
        }),
    }
}

#[tokio::test]
async fn master_ingest_deduplicates_and_the_outbox_resumes_from_the_cursor() {
    let db = Db::open_in_memory(Arc::new(ApiClock::new(at(NOW))))
        .await
        .unwrap();
    let log = Arc::new(QueryLog::new(
        db,
        dnscraft_api::QueryLogConfig::default(),
        "node-b",
    ));
    let ingest = QueryLogIngest::new(Arc::clone(&log));
    let first = vec![remote_record("r1", 1), remote_record("r2", 2)];

    assert_eq!(ingest.ingest("node-b", 1, 2, &first).await.unwrap(), 2);
    // Replayed batch: deduplicated, no error, same cursor.
    assert_eq!(ingest.ingest("node-b", 1, 2, &first).await.unwrap(), 2);
    assert_eq!(ingest.highest_seq("node-b").await.unwrap(), 2);

    let outbox = QueryLogOutbox::new(Arc::clone(&log));
    let from = outbox.next_unacked_seq().await.unwrap();
    assert_eq!(from, 1);
    let batch = outbox.fetch_batch(from, 10).await.unwrap();
    assert_eq!(batch.len(), 2);
    assert_eq!(batch[0].id, "r1");
    assert_eq!(batch[1].id, "r2");

    // A repeated seq with a different record id is rejected.
    let mut forged = remote_record("other", 2);
    forged.record["time_us"] = json!(NOW * 1_000_000 + 2);
    let error = ingest
        .ingest("node-b", 2, 2, std::slice::from_ref(&forged))
        .await
        .unwrap_err();
    assert_eq!(error.code(), "cluster.log_stream.invalid");
}

#[tokio::test]
async fn master_ingest_is_per_node_and_acks_only_contiguously() {
    let db = Db::open_in_memory(Arc::new(ApiClock::new(at(NOW))))
        .await
        .unwrap();
    let log = Arc::new(QueryLog::new(
        db,
        dnscraft_api::QueryLogConfig::default(),
        "master",
    ));
    let ingest = QueryLogIngest::new(Arc::clone(&log));

    // The same record id on two different nodes must not collide: dedupe is
    // per-node, so both rows are stored.
    let shared = remote_record("shared-id", 1);
    assert_eq!(
        ingest
            .ingest("node-a", 1, 1, std::slice::from_ref(&shared))
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        ingest
            .ingest("node-b", 1, 1, std::slice::from_ref(&shared))
            .await
            .unwrap(),
        1
    );
    assert_eq!(ingest.highest_seq("node-a").await.unwrap(), 1);
    assert_eq!(ingest.highest_seq("node-b").await.unwrap(), 1);

    // A gap at seq 2 must not advance node-a's ack past it.
    let third = remote_record("a3", 3);
    assert_eq!(
        ingest
            .ingest("node-a", 3, 3, std::slice::from_ref(&third))
            .await
            .unwrap(),
        1
    );
    let second = remote_record("a2", 2);
    assert_eq!(
        ingest
            .ingest("node-a", 2, 2, std::slice::from_ref(&second))
            .await
            .unwrap(),
        3
    );
}

#[tokio::test]
async fn master_rejects_remote_log_rows_with_invalid_fields_before_inserting() {
    let db = Db::open_in_memory(Arc::new(ApiClock::new(at(NOW))))
        .await
        .unwrap();
    let log = Arc::new(QueryLog::new(
        db,
        dnscraft_api::QueryLogConfig::default(),
        "node-b",
    ));
    let ingest = QueryLogIngest::new(Arc::clone(&log));

    let mut long_name = remote_record("r1", 1);
    long_name.record["query_name"] = json!("a".repeat(256));
    let error = ingest
        .ingest("node-b", 1, 1, std::slice::from_ref(&long_name))
        .await
        .unwrap_err();
    assert_eq!(error.code(), "cluster.log_stream.invalid");

    let mut bad_ip = remote_record("r2", 2);
    bad_ip.record["source_ip"] = json!("not-an-ip");
    let error = ingest
        .ingest("node-b", 2, 2, std::slice::from_ref(&bad_ip))
        .await
        .unwrap_err();
    assert_eq!(error.code(), "cluster.log_stream.invalid");

    let mut bad_status = remote_record("r3", 3);
    bad_status.record["status"] = json!("totally-made-up");
    let error = ingest
        .ingest("node-b", 3, 3, std::slice::from_ref(&bad_status))
        .await
        .unwrap_err();
    assert_eq!(error.code(), "cluster.log_stream.invalid");

    assert_eq!(
        ingest.highest_seq("node-b").await.unwrap(),
        0,
        "invalid rows must be rejected before any insert"
    );

    // A valid batch still ingests after the rejected ones.
    assert_eq!(
        ingest
            .ingest("node-b", 1, 1, &[remote_record("ok", 1)])
            .await
            .unwrap(),
        1
    );
}
