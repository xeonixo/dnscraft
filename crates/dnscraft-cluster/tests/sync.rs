//! Loopback proof of the config-sync slice: master push → digest check →
//! applier → ack → zero lag, plus digest mismatch, apply failure, and
//! reconnect reconciliation (stale node and master-wins). Also proves the
//! TLS renewal notice (names only) and the per-node certificate request (the
//! node's key never reaches the master), and the auth-snapshot push.
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
    StreamRecord, TlsCsrSigner, TlsPaths, WriteExecutor,
};
use dnscraft_common::clock::ManualClock;
use dnscraft_common::secret::Secret;
use rcgen::{CertificateSigningRequestParams, Issuer, KeyPair};
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
        _request_id: &str,
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

/// Signs a node's CSR with the test cluster CA (the master's ACME stand-in).
/// It sees only the CSR, never a key.
struct CaSigner {
    ca_dir: PathBuf,
    seen: Mutex<Vec<String>>,
}

#[async_trait]
impl TlsCsrSigner for CaSigner {
    async fn sign(&self, _node_id: &str, csr_pem: &str) -> Result<String, ClusterError> {
        self.seen.lock().unwrap().push(csr_pem.to_owned());
        let ca_pem = fs::read_to_string(self.ca_dir.join("ca.pem")).unwrap();
        let ca_key =
            KeyPair::from_pem(&fs::read_to_string(self.ca_dir.join("ca.key")).unwrap()).unwrap();
        let issuer = Issuer::from_ca_cert_pem(&ca_pem, ca_key).unwrap();
        let csr = CertificateSigningRequestParams::from_pem(csr_pem).unwrap();
        let cert = csr.params.signed_by(&csr.public_key, &issuer).unwrap();
        Ok(cert.pem())
    }
}

#[tokio::test]
async fn tls_renewal_notice_carries_names_and_no_key() {
    let master = start_master("tls-notice").await;
    let client = client_for(&master, "node-a").await;
    let mut stream = client.open_stream().await.unwrap();

    let names = vec!["example.net".to_owned(), "*.example.net".to_owned()];
    master.server.notify_tls_renewed(&names);

    let record = stream.next_record().await.unwrap();
    let StreamRecord::TlsRenewed(notice) = &record else {
        panic!("expected a tls_renewed notice, got {record:?}");
    };
    assert_eq!(notice.names, names);
    assert!(!format!("{record:?}").contains("PRIVATE KEY"));

    drop(stream);
    master.server.shutdown().await;
}

#[tokio::test]
async fn node_requests_its_own_certificate_and_the_master_never_sees_its_key() {
    let master = start_master("tls-csr").await;
    let client = client_for(&master, "node-a").await;
    let signer = Arc::new(CaSigner {
        ca_dir: master.dir.path().to_owned(),
        seen: Mutex::new(Vec::new()),
    });
    master.server.attach_tls_signer(signer.clone());
    let installer = MockCertInstaller::default();
    let names = vec!["example.net".to_owned(), "*.example.net".to_owned()];

    client
        .request_tls_certificate(&names, &installer)
        .await
        .unwrap();
    client
        .request_tls_certificate(&names, &installer)
        .await
        .unwrap();

    // The master signed two CSRs and each one carries no key material.
    let csrs = signer.seen.lock().unwrap().clone();
    assert_eq!(csrs.len(), 2);
    assert!(csrs.iter().all(|csr| !csr.contains("PRIVATE KEY")));
    assert_ne!(csrs[0], csrs[1], "each request uses a fresh node key");

    // The node installs the signed chain with its own key, and a new key per request.
    let seen = installer.seen();
    assert_eq!(seen.len(), 2);
    assert_ne!(seen[0].1, seen[1].1);
    assert!(seen[0].0.starts_with("-----BEGIN CERTIFICATE-----"));
    assert!(KeyPair::from_pem(&seen[0].1).is_ok());

    master.server.shutdown().await;
}

#[tokio::test]
async fn tls_certificate_request_without_a_signer_is_refused() {
    let master = start_master("tls-nosigner").await;
    let client = client_for(&master, "node-a").await;
    let installer = MockCertInstaller::default();

    let error = client
        .request_tls_certificate(&["example.net".to_owned()], &installer)
        .await
        .unwrap_err();
    assert_eq!(error.code(), "cluster.internal");
    assert!(installer.seen().is_empty());

    master.server.shutdown().await;
}

struct FixedCert;

#[async_trait]
impl dnscraft_cluster::TlsCertificateSource for FixedCert {
    async fn certificate(&self) -> Option<(String, String)> {
        Some(("CHAIN".to_owned(), "KEY".to_owned()))
    }
}

#[tokio::test]
async fn certificate_is_pushed_on_connect_and_on_renewal_to_capable_nodes_only() {
    let master = start_master("tls-push").await;
    master.server.attach_tls_source(Arc::new(FixedCert));
    let identity = enroll_node(&master, "node-a").await;
    let capable = ClusterClient::new(&master.url, &identity, master.clock.clone())
        .unwrap()
        .with_tls_certificate(true);
    let old_identity = enroll_node(&master, "node-old").await;
    let old = ClusterClient::new(&master.url, &old_identity, master.clock.clone()).unwrap();

    let mut stream = capable.open_stream().await.unwrap();
    let mut old_stream = old.open_stream().await.unwrap();
    // The old node must see no certificate record, only its hello/config flow.
    let mut saw_push = false;
    for _ in 0..4 {
        if let StreamRecord::TlsCertificatePush(push) = stream.next_record().await.unwrap() {
            assert_eq!(
                (push.chain_pem.as_str(), push.key_pem.as_str()),
                ("CHAIN", "KEY")
            );
            saw_push = true;
            break;
        }
    }
    assert!(saw_push, "connect-time push missing");

    // A renewal pushes again, again only to the capable node.
    let broadcast = master.server.broadcast_handle();
    assert_eq!(broadcast.push_tls_certificate("CHAIN2", "KEY2"), 1);
    loop {
        if let StreamRecord::TlsCertificatePush(push) = stream.next_record().await.unwrap() {
            assert_eq!(push.chain_pem, "CHAIN2");
            break;
        }
    }
    master.server.broadcast_runtime_command("probe", &json!({}));
    loop {
        let record = old_stream.next_record().await.unwrap();
        assert!(!matches!(record, StreamRecord::TlsCertificatePush(_)));
        if matches!(record, StreamRecord::RuntimeCommand(_)) {
            break;
        }
    }

    drop(stream);
    drop(old_stream);
    master.server.shutdown().await;
}

#[tokio::test]
async fn revoked_node_cannot_request_a_tls_certificate() {
    let master = start_master("tls-revoked").await;
    let client = client_for(&master, "node-a").await;
    master.server.attach_tls_signer(Arc::new(CaSigner {
        ca_dir: master.dir.path().to_owned(),
        seen: Mutex::new(Vec::new()),
    }));
    master.store.revoke("node-a").await.unwrap();
    let installer = MockCertInstaller::default();

    let error = client
        .request_tls_certificate(&["example.net".to_owned()], &installer)
        .await
        .unwrap_err();
    assert_eq!(error.code(), "cluster.node.revoked");
    assert!(installer.seen().is_empty());

    master.server.shutdown().await;
}

#[tokio::test]
async fn failing_cert_install_is_reported_as_cert_push_failed() {
    let master = start_master("cert-fail").await;
    let client = client_for(&master, "node-a").await;
    master.server.attach_tls_signer(Arc::new(CaSigner {
        ca_dir: master.dir.path().to_owned(),
        seen: Mutex::new(Vec::new()),
    }));
    let installer = MockCertInstaller::failing();

    let error = client
        .request_tls_certificate(&["example.net".to_owned()], &installer)
        .await
        .unwrap_err();
    assert_eq!(error.code(), "cluster.cert_push.failed");
    assert!(installer.seen().is_empty());

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
