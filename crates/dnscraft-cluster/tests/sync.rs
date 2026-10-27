//! Loopback proof of the config-sync slice: master push → digest check →
//! applier → ack → zero lag, plus digest mismatch, apply failure, and
//! reconnect reconciliation (stale node and master-wins). Also proves the
//! certificate push (exact chain+key, failure code) and auth-snapshot push.
//!
//! Real sockets on `127.0.0.1:0`, generated CA/certs via `rcgen`, an injectable
//! [`ManualClock`], a mock [`ConfigApplier`], and no wall-clock waits.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::fs;
use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use async_trait::async_trait;
use dnscraft_cluster::{
    AuthSnapshotApplier, CertInstaller, ClusterCa, ClusterClient, ClusterError, ClusterServer,
    ClusterServerConfig, ClusterStore, ConfigApplier, ConfigPush, ListenConfig, LogIngest,
    LogRecord, NodeIdentity, PendingNodeIdentity, QuotaConfig, RelayResponse, RelayedActor,
    TlsPaths, WriteExecutor,
};
use dnscraft_common::clock::ManualClock;
use dnscraft_common::secret::Secret;
use serde_json::{Value, json};

const NODE_CERT_TTL: Duration = Duration::from_secs(90 * 24 * 3600);
const TOKEN_TTL: Duration = Duration::from_secs(15 * 60);

/// Records applies and can be told to fail (simulating a rollback).
#[derive(Default)]
struct MockApplier {
    current: Mutex<Option<i64>>,
    applied: Mutex<Vec<(i64, Value)>>,
    fail: bool,
}

impl MockApplier {
    fn failing() -> Self {
        Self {
            fail: true,
            ..Self::default()
        }
    }

    fn current(&self) -> Option<i64> {
        *self.current.lock().unwrap()
    }

    fn applied(&self) -> Vec<(i64, Value)> {
        self.applied.lock().unwrap().clone()
    }
}

#[async_trait]
impl ConfigApplier for MockApplier {
    async fn apply(&self, version: i64, snapshot: &Value) -> Result<i64, ClusterError> {
        if self.fail {
            return Err(ClusterError::ConfigApply {
                message: "mock apply failure".to_owned(),
            });
        }
        *self.current.lock().unwrap() = Some(version);
        self.applied
            .lock()
            .unwrap()
            .push((version, snapshot.clone()));
        Ok(version)
    }
}

/// Records installed certificate material and can be told to fail.
#[derive(Default)]
struct MockCertInstaller {
    seen: Mutex<Vec<(String, String)>>,
    fail: bool,
}

impl MockCertInstaller {
    fn failing() -> Self {
        Self {
            fail: true,
            ..Self::default()
        }
    }

    fn seen(&self) -> Vec<(String, String)> {
        self.seen.lock().unwrap().clone()
    }
}

#[async_trait]
impl CertInstaller for MockCertInstaller {
    async fn install(&self, chain_pem: &str, private_key: &Secret) -> Result<(), ClusterError> {
        if self.fail {
            return Err(ClusterError::Internal {
                message: "mock install failure".to_owned(),
            });
        }
        self.seen
            .lock()
            .unwrap()
            .push((chain_pem.to_owned(), private_key.expose().to_owned()));
        Ok(())
    }
}

/// Records applied auth snapshots.
#[derive(Default)]
struct MockAuthSnapshot {
    seen: Mutex<Vec<Value>>,
}

impl MockAuthSnapshot {
    fn seen(&self) -> Vec<Value> {
        self.seen.lock().unwrap().clone()
    }
}

#[async_trait]
impl AuthSnapshotApplier for MockAuthSnapshot {
    async fn apply(&self, snapshot: &Value) -> Result<(), ClusterError> {
        self.seen.lock().unwrap().push(snapshot.clone());
        Ok(())
    }
}

/// Write relay is not exercised here.
struct NoWrites;

#[async_trait]
impl WriteExecutor for NoWrites {
    async fn execute(
        &self,
        _node_id: &str,
        _actor: RelayedActor,
        _method: String,
        _path: String,
        _body: Value,
        _if_match: Option<String>,
        _idempotency_key: Option<String>,
    ) -> Result<RelayResponse, ClusterError> {
        Err(ClusterError::Internal {
            message: "write relay not used in this test".to_owned(),
        })
    }
}

/// Log ingest is not exercised here.
struct NoLogs;

#[async_trait]
impl LogIngest for NoLogs {
    async fn ingest(
        &self,
        _node_id: &str,
        _first_seq: u64,
        _last_seq: u64,
        _records: &[LogRecord],
    ) -> Result<u64, ClusterError> {
        Err(ClusterError::Internal {
            message: "log ingest not used in this test".to_owned(),
        })
    }

    async fn highest_seq(&self, _node_id: &str) -> Result<u64, ClusterError> {
        Ok(0)
    }
}

/// A unique, self-cleaning temporary directory.
struct TestDir(PathBuf);

impl TestDir {
    fn new(name: &str) -> Self {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let id = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "dnscraft-cluster-sync-{name}-{}-{id}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).unwrap();
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// A real master listening on loopback.
struct Master {
    server: ClusterServer,
    store: ClusterStore,
    clock: Arc<ManualClock>,
    dir: TestDir,
    url: String,
}

async fn start_master(name: &str) -> Master {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let dir = TestDir::new(name);
    // Real wall-clock start keeps freshly issued certificates valid for
    // rustls; time then only moves when a test advances it.
    let clock = Arc::new(ManualClock::new(SystemTime::now()));
    let ca = ClusterCa::load_or_generate(&dir.path().join("ca.pem")).unwrap();
    let store = ClusterStore::open_in_memory(clock.clone(), TOKEN_TTL)
        .await
        .unwrap();
    let server = ClusterServer::start(
        ClusterServerConfig {
            listen: ListenConfig {
                bind: IpAddr::V4(Ipv4Addr::LOCALHOST),
                port: 0,
            },
            server_name: "127.0.0.1".to_owned(),
            node_cert_ttl: NODE_CERT_TTL,
            quota: QuotaConfig::default(),
        },
        ca,
        store.clone(),
        clock.clone(),
        Arc::new(NoWrites),
        Arc::new(NoLogs),
    )
    .await
    .unwrap();
    let url = format!("https://{}", server.addr());
    Master {
        server,
        store,
        clock,
        dir,
        url,
    }
}

/// Mints a token, enrolls `node_id`, and persists the returned identity.
async fn enroll_node(master: &Master, node_id: &str) -> NodeIdentity {
    let token = master.store.mint_join_token(node_id).await.unwrap();
    let pending = PendingNodeIdentity::generate(node_id).unwrap();
    let response = ClusterClient::enroll(
        &master.url,
        master.server.server_cert_pem(),
        pending.request(Secret::new(token.expose())),
    )
    .await
    .unwrap();
    let paths = TlsPaths {
        ca_cert: master.dir.path().join(format!("{node_id}-ca.pem")),
        node_cert: master.dir.path().join(format!("{node_id}.pem")),
        node_key: master.dir.path().join(format!("{node_id}.key")),
    };
    pending.persist(&response, &paths).unwrap()
}

async fn client_for(master: &Master, node_id: &str) -> ClusterClient {
    let identity = enroll_node(master, node_id).await;
    ClusterClient::new(&master.url, &identity, master.clock.clone()).unwrap()
}

#[tokio::test]
async fn push_apply_ack_reaches_zero_lag() {
    let master = start_master("happy").await;
    let client = client_for(&master, "node-a").await;
    let mut stream = client.open_stream().await.unwrap();

    let snapshot = json!({ "version": 7, "policy": { "views": [{ "nodes": ["node-a"] }] } });
    master.server.config_sync().publish(7, &snapshot).unwrap();

    let applier = MockApplier::default();
    let applied = client.apply_next(&mut stream, &applier).await.unwrap();
    assert_eq!(applied, Some(7));
    assert_eq!(applier.current(), Some(7));
    assert_eq!(applier.applied(), vec![(7, snapshot.clone())]);

    let lag = master.server.config_sync().node_lag("node-a").unwrap();
    assert_eq!(lag.pushed_version, 7);
    assert_eq!(lag.applied_version, 7);
    assert_eq!(lag.lag, 0);

    let node = master.store.get_node("node-a").await.unwrap().unwrap();
    assert_eq!(node.applied_config_version, Some(7));

    drop(stream);
    master.server.shutdown().await;
}

#[tokio::test]
async fn digest_mismatch_is_not_applied() {
    let master = start_master("digest").await;
    let client = client_for(&master, "node-a").await;

    let mut push = ConfigPush::new(3, &json!({ "version": 3 })).unwrap();
    push.sha256 = "00".repeat(32);

    let applier = MockApplier::default();
    let error = client.apply_push(&push, &applier).await.unwrap_err();
    assert_eq!(error.code(), "cluster.config.apply");
    assert_eq!(applier.current(), None);
    assert!(applier.applied().is_empty());

    master.server.shutdown().await;
}

#[tokio::test]
async fn reconnect_with_a_stale_node_gets_the_current_snapshot() {
    let master = start_master("stale").await;
    let client = client_for(&master, "node-b").await;

    let snapshot = json!({ "version": 5 });
    master.server.config_sync().publish(5, &snapshot).unwrap();

    let mut stream = client.open_stream_with(Some(3), None).await.unwrap();
    let applier = MockApplier::default();
    let applied = client.apply_next(&mut stream, &applier).await.unwrap();
    assert_eq!(applied, Some(5));
    assert_eq!(applier.current(), Some(5));
    assert_eq!(applier.applied(), vec![(5, snapshot)]);

    let lag = master.server.config_sync().node_lag("node-b").unwrap();
    assert_eq!(lag.lag, 0);

    drop(stream);
    master.server.shutdown().await;
}

#[tokio::test]
async fn a_sub_node_ahead_of_the_master_is_overwritten() {
    let master = start_master("ahead").await;
    let client = client_for(&master, "node-c").await;

    let snapshot = json!({ "version": 4 });
    master.server.config_sync().publish(4, &snapshot).unwrap();

    // The node claims version 9; a single writer means this cannot happen, so
    // the master is authoritative and pushes its snapshot anyway.
    let mut stream = client.open_stream_with(Some(9), None).await.unwrap();
    let applier = MockApplier::default();
    let applied = client.apply_next(&mut stream, &applier).await.unwrap();
    assert_eq!(applied, Some(4));
    assert_eq!(applier.current(), Some(4));
    assert_eq!(applier.applied(), vec![(4, snapshot)]);

    let lag = master.server.config_sync().node_lag("node-c").unwrap();
    assert_eq!(lag.lag, 0);

    drop(stream);
    master.server.shutdown().await;
}

#[tokio::test]
async fn cert_push_reaches_the_installer_with_the_exact_chain_and_key() {
    let master = start_master("cert-push").await;
    let client = client_for(&master, "node-a").await;
    let mut stream = client.open_stream().await.unwrap();
    let installer = MockCertInstaller::default();

    let chain = "-----BEGIN CERTIFICATE-----\nleaf-certificate\n-----END CERTIFICATE-----\n";
    let key = Secret::new("-----BEGIN PRIVATE KEY-----\nkey-material\n-----END PRIVATE KEY-----\n");
    master.server.push_cert(chain, &key);

    assert!(
        client
            .apply_cert_next(&mut stream, &installer)
            .await
            .unwrap()
    );
    assert_eq!(
        installer.seen(),
        vec![(chain.to_owned(), key.expose().to_owned())]
    );

    drop(stream);
    master.server.shutdown().await;
}

#[tokio::test]
async fn failing_cert_install_is_reported_as_cert_push_failed() {
    let master = start_master("cert-fail").await;
    let client = client_for(&master, "node-a").await;
    let mut stream = client.open_stream().await.unwrap();
    let installer = MockCertInstaller::failing();

    master.server.push_cert(
        "-----BEGIN CERTIFICATE-----\nleaf\n-----END CERTIFICATE-----\n",
        &Secret::new("-----BEGIN PRIVATE KEY-----\nkey-material\n-----END PRIVATE KEY-----\n"),
    );

    let error = client
        .apply_cert_next(&mut stream, &installer)
        .await
        .unwrap_err();
    assert_eq!(error.code(), "cluster.cert_push.failed");
    assert!(installer.seen().is_empty());

    drop(stream);
    master.server.shutdown().await;
}

#[tokio::test]
async fn auth_snapshot_push_reaches_the_applier() {
    let master = start_master("auth-snapshot").await;
    let client = client_for(&master, "node-a").await;
    let mut stream = client.open_stream().await.unwrap();
    let applier = MockAuthSnapshot::default();

    let snapshot = json!({
        "token_hashes": ["sha256:abc"],
        "session_epoch": 3,
        "oidc": { "issuer": "https://id.example" },
    });
    master.server.push_auth_snapshot(&snapshot);

    assert!(
        client
            .apply_auth_snapshot_next(&mut stream, &applier)
            .await
            .unwrap()
    );
    assert_eq!(applier.seen(), vec![snapshot]);

    drop(stream);
    master.server.shutdown().await;
}

#[tokio::test]
async fn apply_failure_keeps_the_previous_version_and_does_not_ack() {
    let master = start_master("apply-fail").await;
    let client = client_for(&master, "node-d").await;
    let mut stream = client.open_stream().await.unwrap();

    master
        .server
        .config_sync()
        .publish(8, &json!({ "version": 8 }))
        .unwrap();

    let applier = MockApplier::failing();
    let error = client.apply_next(&mut stream, &applier).await.unwrap_err();
    assert_eq!(error.code(), "cluster.config.apply");
    assert_eq!(applier.current(), None);
    assert!(applier.applied().is_empty());

    // No ack reached the master, so lag stays positive and the stored applied
    // version is unchanged.
    let lag = master.server.config_sync().node_lag("node-d").unwrap();
    assert!(lag.lag > 0);
    let node = master.store.get_node("node-d").await.unwrap().unwrap();
    assert_eq!(node.applied_config_version, None);

    drop(stream);
    master.server.shutdown().await;
}
