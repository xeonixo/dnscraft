//! Consolidated threat-model regression suite for the cluster crate.
//!
//! Each test names one threat from `SPEC-cluster.md` § Security considerations
//! → Threat model and proves the crate-owned mitigation end to end over real
//! loopback mTLS. Mitigations that live in a not-yet-wired control-api surface
//! are marked with a `CL15 wiring:` comment instead of being faked.
//!
//! Real sockets on `127.0.0.1:0`, generated CA/certs via `rcgen`, an injectable
//! [`ManualClock`], and no wall-clock waits.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs;
use std::net::{IpAddr, Ipv4Addr};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use async_trait::async_trait;
use dnscraft_cluster::{
    AuthSnapshotPush, CertPush, ClusterCa, ClusterClient, ClusterConfig, ClusterError,
    ClusterServer, ClusterServerConfig, ClusterStore, ConfigPush, EnrollRequest, ListenConfig,
    LogBatch, LogIngest, LogRecord, NodeIdentity, PROTOCOL_VERSION, PendingNodeIdentity,
    QuotaConfig, RelayResponse, RelayedActor, StreamRecord, TlsPaths, WriteExecutor, WriteRelay,
    cert_fingerprint,
};
use dnscraft_common::clock::ManualClock;
use dnscraft_common::secret::Secret;
use rcgen::{
    BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose, PKCS_ECDSA_P256_SHA256,
};
use reqwest::Client;
use rustls::RootCertStore;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use serde_json::{Value, json};
use time::OffsetDateTime;

const NODE_CERT_TTL: Duration = Duration::from_secs(90 * 24 * 3600);
const TOKEN_TTL: Duration = Duration::from_secs(15 * 60);

/// One write that reached the master executor.
#[derive(Clone)]
struct Call {
    actor: RelayedActor,
    idempotency_key: Option<String>,
}

/// Master-side executor: records the actor verbatim, dedupes on
/// `Idempotency-Key`, and can re-check RBAC like the canonical handler.
struct MasterExecutor {
    calls: Mutex<Vec<Call>>,
    applied: Mutex<HashMap<String, RelayResponse>>,
    applies: AtomicU32,
    require_admin: bool,
}

impl MasterExecutor {
    fn new(require_admin: bool) -> Self {
        Self {
            calls: Mutex::new(Vec::new()),
            applied: Mutex::new(HashMap::new()),
            applies: AtomicU32::new(0),
            require_admin,
        }
    }

    fn calls(&self) -> Vec<Call> {
        self.calls.lock().unwrap().clone()
    }

    fn applies(&self) -> u32 {
        self.applies.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl WriteExecutor for MasterExecutor {
    async fn execute(
        &self,
        _node_id: &str,
        _request_id: &str,
        actor: RelayedActor,
        _method: String,
        _path: String,
        _body: Value,
        _if_match: Option<String>,
        idempotency_key: Option<String>,
    ) -> Result<RelayResponse, ClusterError> {
        self.calls.lock().unwrap().push(Call {
            actor: actor.clone(),
            idempotency_key: idempotency_key.clone(),
        });

        // The actor is transport-supplied: the master re-checks it and never
        // trusts the sub-node's judgement.
        if self.require_admin && actor.scope != "admin" {
            return Ok(RelayResponse {
                status: 403,
                body: json!({ "error": { "code": "control_api.auth.insufficient_scope" } }),
            });
        }

        let key = idempotency_key
            .unwrap_or_else(|| format!("unordered-{}", self.calls.lock().unwrap().len()));
        if let Some(cached) = self.applied.lock().unwrap().get(&key) {
            return Ok(cached.clone());
        }
        self.applies.fetch_add(1, Ordering::SeqCst);
        let response = RelayResponse {
            status: 200,
            body: json!({ "data": { "config_version": 7 } }),
        };
        self.applied.lock().unwrap().insert(key, response.clone());
        Ok(response)
    }
}

#[derive(Default)]
struct NodeLogs {
    seqs: BTreeMap<u64, String>,
    ids: HashSet<String>,
    highest: u64,
}

#[derive(Default)]
struct IngestState {
    nodes: BTreeMap<String, NodeLogs>,
    records: Vec<LogRecord>,
    inserted: usize,
    duplicates: usize,
}

/// Master ingest that dedupes `(node_id, seq)` and `(node_id, record_id)` and
/// keeps the opaque records it received.
#[derive(Default)]
struct RecordingIngest {
    state: Mutex<IngestState>,
}

impl RecordingIngest {
    fn inserted(&self) -> usize {
        self.state.lock().unwrap().inserted
    }

    fn records(&self) -> Vec<LogRecord> {
        self.state.lock().unwrap().records.clone()
    }
}

#[async_trait]
impl LogIngest for RecordingIngest {
    async fn ingest(
        &self,
        node_id: &str,
        first_seq: u64,
        last_seq: u64,
        records: &[LogRecord],
    ) -> Result<u64, ClusterError> {
        let mut guard = self.state.lock().unwrap();
        let state = &mut *guard;
        state.records.extend(records.iter().cloned());
        let IngestState {
            nodes,
            inserted,
            duplicates,
            ..
        } = state;
        let node = nodes.entry(node_id.to_owned()).or_default();

        for (offset, record) in records.iter().enumerate() {
            let seq = first_seq + offset as u64;
            match node.seqs.get(&seq) {
                Some(existing) if existing != &record.id => {
                    return Err(ClusterError::LogStreamInvalid {
                        reason: "repeated seq carries a different record".to_owned(),
                    });
                }
                Some(_) => {
                    *duplicates += 1;
                    continue;
                }
                None if node.ids.contains(&record.id) => {
                    *duplicates += 1;
                    continue;
                }
                None => {
                    node.seqs.insert(seq, record.id.clone());
                    node.ids.insert(record.id.clone());
                    *inserted += 1;
                }
            }
        }

        let expected = node.highest.saturating_add(1);
        if first_seq > expected {
            node.highest = node.highest.max(last_seq);
        } else {
            while node.seqs.contains_key(&node.highest.saturating_add(1)) {
                node.highest += 1;
            }
        }
        Ok(node.highest)
    }

    async fn highest_seq(&self, node_id: &str) -> Result<u64, ClusterError> {
        Ok(self
            .state
            .lock()
            .unwrap()
            .nodes
            .get(node_id)
            .map_or(0, |node| node.highest))
    }
}

/// Log ingest is not exercised by a test.
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
            "dnscraft-cluster-security-{name}-{}-{id}",
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
    url: String,
}

impl Master {
    async fn shutdown(self) {
        self.server.shutdown().await;
    }
}

fn clock() -> Arc<ManualClock> {
    // Real wall-clock start keeps freshly issued certificates valid for rustls;
    // time only moves when a test advances it.
    Arc::new(ManualClock::new(SystemTime::now()))
}

async fn start_server(
    clock: Arc<ManualClock>,
    store: ClusterStore,
    ca: ClusterCa,
    executor: Arc<dyn WriteExecutor>,
    ingest: Arc<dyn LogIngest>,
    quota: QuotaConfig,
) -> Master {
    let server = ClusterServer::start(
        ClusterServerConfig {
            listen: ListenConfig {
                bind: IpAddr::V4(Ipv4Addr::LOCALHOST),
                port: 0,
            },
            server_name: "127.0.0.1".to_owned(),
            node_cert_ttl: NODE_CERT_TTL,
            quota,
            timing: dnscraft_cluster::TimingConfig::default(),
        },
        ca,
        store.clone(),
        clock.clone(),
        executor,
        ingest,
        None,
    )
    .await
    .unwrap();
    let url = format!("https://{}", server.addr());
    Master {
        server,
        store,
        clock,
        url,
    }
}

async fn start_master(
    dir: &TestDir,
    clock: Arc<ManualClock>,
    executor: Arc<dyn WriteExecutor>,
    ingest: Arc<dyn LogIngest>,
    quota: QuotaConfig,
) -> Master {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let ca = ClusterCa::load_or_generate(&dir.path().join("ca.pem")).unwrap();
    let store = ClusterStore::open_in_memory(clock.clone(), TOKEN_TTL)
        .await
        .unwrap();
    start_server(clock, store, ca, executor, ingest, quota).await
}

/// Mints a token, enrolls `node_id`, and persists the returned identity.
async fn enroll_node(dir: &TestDir, master: &Master, node_id: &str) -> NodeIdentity {
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
        ca_cert: dir.path().join(format!("{node_id}-ca.pem")),
        node_cert: dir.path().join(format!("{node_id}.pem")),
        node_key: dir.path().join(format!("{node_id}.key")),
    };
    pending.persist(&response, &paths).unwrap()
}

fn client(master: &Master, identity: &NodeIdentity) -> ClusterClient {
    ClusterClient::new(&master.url, identity, master.clock.clone()).unwrap()
}

fn relay(idempotency: &str) -> WriteRelay {
    WriteRelay {
        request_id: format!("req-{idempotency}"),
        idempotency_key: Some(idempotency.to_owned()),
        if_match: Some("\"v1\"".to_owned()),
        method: "PUT".to_owned(),
        path: "/api/v1/config/filter-sets/x".to_owned(),
        body: json!({ "filtering": { "lists": [] } }),
        actor: RelayedActor {
            actor_id: "user-1".to_owned(),
            actor_type: "user".to_owned(),
            scope: "admin".to_owned(),
        },
    }
}

fn batch_for(node_id: &str, seq: u64) -> LogBatch {
    let id = format!("{node_id}-r{seq}");
    LogBatch {
        protocol: PROTOCOL_VERSION,
        node_id: node_id.to_owned(),
        first_seq: seq,
        last_seq: seq,
        records: vec![LogRecord {
            id: id.clone(),
            record: json!({ "id": id, "seq": seq }),
        }],
    }
}

/// reqwest HTTP/2 client trusting `ca_pem`, optionally presenting a client
/// certificate (`cert_pem`, PKCS #8 DER key).
fn http_client(ca_pem: &str, identity: Option<(&str, &[u8])>) -> Client {
    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from_pem_slice(ca_pem.as_bytes()).unwrap())
        .unwrap();
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(roots);
    let mut tls = match identity {
        Some((cert_pem, key_der)) => {
            let certs = CertificateDer::pem_slice_iter(cert_pem.as_bytes())
                .collect::<Result<Vec<_>, _>>()
                .unwrap();
            let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_der.to_vec()));
            builder.with_client_auth_cert(certs, key).unwrap()
        }
        None => builder.with_no_client_auth(),
    };
    tls.alpn_protocols = vec![b"h2".to_vec()];
    Client::builder()
        .use_preconfigured_tls(tls)
        .build()
        .unwrap()
}

async fn open_stream(client: &Client, master_url: &str) -> reqwest::Response {
    client
        .get(format!("{master_url}/cluster/v1/stream"))
        .header("x-cluster-protocol", PROTOCOL_VERSION.to_string())
        .send()
        .await
        .unwrap()
}

/// Reads a JSON error response as `(status, code)`.
async fn error_code(response: reqwest::Response) -> (u16, String) {
    let status = response.status().as_u16();
    let text = response.text().await.unwrap();
    let body: Value = serde_json::from_str(&text).unwrap();
    let code = body["error"]["code"].as_str().unwrap().to_owned();
    (status, code)
}

/// A leaf signed by the master's real cluster CA, optionally already expired.
///
/// Returns `(cert_pem, key_der, fingerprint)`.
fn leaf_from_cluster_ca(dir: &Path, node_id: &str, expired: bool) -> (String, Vec<u8>, String) {
    let ca_pem = fs::read_to_string(dir.join("ca.pem")).unwrap();
    let ca_key_pem = fs::read_to_string(dir.join("ca.key")).unwrap();
    let ca_key = KeyPair::from_pem(&ca_key_pem).unwrap();
    let issuer = Issuer::from_ca_cert_pem(&ca_pem, ca_key).unwrap();

    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let mut params = CertificateParams::new(vec![node_id.to_owned()]).unwrap();
    params.is_ca = IsCa::NoCa;
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![
        ExtendedKeyUsagePurpose::ClientAuth,
        ExtendedKeyUsagePurpose::ServerAuth,
    ];
    if expired {
        let now = OffsetDateTime::from(SystemTime::now());
        params.not_before = now - time::Duration::hours(48);
        params.not_after = now - time::Duration::hours(24);
    }
    let cert = params.signed_by(&key, &issuer).unwrap();
    (
        cert.pem(),
        key.serialize_der(),
        cert_fingerprint(cert.der()),
    )
}

/// A leaf under a self-signed foreign CA (a MITM on the cluster path).
fn foreign_leaf(node_id: &str) -> (String, Vec<u8>) {
    let ca_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let mut params = CertificateParams::new(Vec::new()).unwrap();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    let ca_cert = params.self_signed(&ca_key).unwrap();
    let issuer = Issuer::from_ca_cert_pem(&ca_cert.pem(), ca_key).unwrap();

    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let mut params = CertificateParams::new(vec![node_id.to_owned()]).unwrap();
    params.is_ca = IsCa::NoCa;
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![
        ExtendedKeyUsagePurpose::ClientAuth,
        ExtendedKeyUsagePurpose::ServerAuth,
    ];
    let cert = params.signed_by(&key, &issuer).unwrap();
    (cert.pem(), key.serialize_der())
}

// --- threat: malicious/compromised sub-node -------------------------------

/// A compromised sub-node cannot mint or elevate an actor: the relayed actor
/// is forwarded verbatim and the master re-checks its scope.
#[tokio::test]
async fn threat_malicious_sub_node_cannot_escalate_privileges() {
    let dir = TestDir::new("escalation");
    let executor = Arc::new(MasterExecutor::new(true));
    let master = start_master(
        &dir,
        clock(),
        executor.clone(),
        Arc::new(NoLogs),
        QuotaConfig::default(),
    )
    .await;
    let identity = enroll_node(&dir, &master, "node-a").await;
    let node = client(&master, &identity);

    let mut viewer = relay("viewer-write");
    viewer.actor.scope = "viewer".to_owned();
    let response = node.relay_write(viewer.clone()).await.unwrap();
    assert_eq!(response.status, 403);
    assert_eq!(
        response.body["error"]["code"],
        "control_api.auth.insufficient_scope"
    );

    let calls = executor.calls();
    assert_eq!(calls.len(), 1);
    assert_eq!(
        calls[0].actor, viewer.actor,
        "the crate forwards the actor unchanged; it never elevates it"
    );

    // The same node's admin write still works, so the refusal was scope-based.
    let response = node.relay_write(relay("admin-write")).await.unwrap();
    assert_eq!(response.status, 200);
    assert_eq!(response.body["data"]["config_version"], 7);

    master.shutdown().await;
}

/// Revocation contains a compromised sub-node: every protected request
/// re-checks the registry, so an open session loses its write path.
#[tokio::test]
async fn threat_compromised_sub_node_is_contained_by_revocation() {
    let dir = TestDir::new("revocation");
    let executor = Arc::new(MasterExecutor::new(false));
    let master = start_master(
        &dir,
        clock(),
        executor.clone(),
        Arc::new(NoLogs),
        QuotaConfig::default(),
    )
    .await;
    let identity = enroll_node(&dir, &master, "node-a").await;
    let node = client(&master, &identity);
    let _stream = node.open_stream().await.unwrap();
    assert!(node.heartbeat(Some(1), 0).await.unwrap().ok);

    master.store.revoke("node-a").await.unwrap();

    // A relayed write over the still-open session is refused before it can
    // execute (the response carries the documented code verbatim).
    let response = node.relay_write(relay("after-revoke")).await.unwrap();
    assert_eq!(response.status, 403);
    assert_eq!(response.body["error"]["code"], "cluster.node.revoked");
    assert!(
        executor.calls().is_empty(),
        "a revoked node's write must never reach the executor"
    );

    let error = node.heartbeat(Some(1), 0).await.unwrap_err();
    assert_eq!(error.code(), "cluster.node.revoked");
    let error = node
        .open_stream()
        .await
        .err()
        .expect("a revoked node cannot resume a stream");
    assert_eq!(error.code(), "cluster.node.revoked");

    master.shutdown().await;
}

/// Revocation closes the live stream: no further config, auth or certificate
/// push reaches the node, and a later publish sees no registered subscriber.
#[tokio::test]
async fn revocation_disconnects_the_live_stream() {
    let dir = TestDir::new("revoke-stream");
    let executor = Arc::new(MasterExecutor::new(false));
    let master = start_master(
        &dir,
        clock(),
        executor.clone(),
        Arc::new(NoLogs),
        QuotaConfig::default(),
    )
    .await;
    let identity = enroll_node(&dir, &master, "node-a").await;
    let node = client(&master, &identity);
    let mut stream = node.open_stream().await.unwrap();

    master.store.revoke("node-a").await.unwrap();
    // This is exactly what `DELETE /api/v1/cluster/nodes/{id}` now does.
    master.server.broadcast_handle().disconnect("node-a");

    // The NDJSON body ends when the sender is dropped.
    assert!(
        stream.next_record().await.is_err(),
        "a revoked node's stream must end"
    );

    // A subsequent publish cannot reach it: it is no longer registered.
    master
        .server
        .config_sync()
        .publish(1, &json!({ "config_version": 1 }))
        .unwrap();
    assert!(
        master.server.config_sync().lag().is_empty(),
        "revoked node must not remain a broadcast target"
    );

    // Next connection is refused with the documented code.
    let error = node
        .open_stream()
        .await
        .err()
        .expect("a revoked node cannot resume a stream");
    assert_eq!(error.code(), "cluster.node.revoked");

    master.shutdown().await;
}

/// Defence in depth: a revoke that bypasses the disconnect path still ends the
/// stream with `cluster.node.revoked` before the next push is delivered.
#[tokio::test]
async fn revocation_racing_registration_ends_the_stream_on_the_next_push() {
    let dir = TestDir::new("revoke-race");
    let executor = Arc::new(MasterExecutor::new(false));
    let master = start_master(
        &dir,
        clock(),
        executor.clone(),
        Arc::new(NoLogs),
        QuotaConfig::default(),
    )
    .await;
    let identity = enroll_node(&dir, &master, "node-a").await;
    let node = client(&master, &identity);
    let mut stream = node.open_stream().await.unwrap();

    // Flag only: the sender is not dropped.
    master.store.revoke("node-a").await.unwrap();
    master
        .server
        .config_sync()
        .publish(2, &json!({ "config_version": 2 }))
        .unwrap();

    match stream.next_record().await.unwrap() {
        StreamRecord::Error { error } => assert_eq!(error.code, "cluster.node.revoked"),
        other => panic!("expected cluster.node.revoked, got {other:?}"),
    }

    master.shutdown().await;
}

/// A stolen user credential still fails the master's scope re-check, and
/// nothing is applied.
#[tokio::test]
async fn threat_stolen_user_credential_fails_the_master_scope_recheck() {
    let dir = TestDir::new("stolen");
    let executor = Arc::new(MasterExecutor::new(true));
    let master = start_master(
        &dir,
        clock(),
        executor.clone(),
        Arc::new(NoLogs),
        QuotaConfig::default(),
    )
    .await;
    let identity = enroll_node(&dir, &master, "node-a").await;
    let node = client(&master, &identity);

    let mut stolen = relay("stolen-user");
    stolen.actor = RelayedActor {
        actor_id: "user-stolen".to_owned(),
        actor_type: "user".to_owned(),
        scope: "viewer".to_owned(),
    };
    let response = node.relay_write(stolen).await.unwrap();
    assert_eq!(response.status, 403);
    assert_eq!(
        response.body["error"]["code"],
        "control_api.auth.insufficient_scope"
    );
    assert_eq!(executor.applies(), 0, "no config version was produced");

    master.shutdown().await;
}

// --- threat: replay -------------------------------------------------------

/// A replayed cluster message does not double-apply: the master dedupes on the
/// idempotency key, and a replay cannot re-run the write under a new actor.
#[tokio::test]
async fn threat_replayed_cluster_message_does_not_double_apply() {
    let dir = TestDir::new("replay");
    let executor = Arc::new(MasterExecutor::new(false));
    let master = start_master(
        &dir,
        clock(),
        executor.clone(),
        Arc::new(NoLogs),
        QuotaConfig::default(),
    )
    .await;
    let identity = enroll_node(&dir, &master, "node-a").await;
    let node = client(&master, &identity);

    let original = relay("idem-replay");
    let first = node.relay_write(original.clone()).await.unwrap();
    assert_eq!(first.status, 200);
    assert_eq!(first.body["data"]["config_version"], 7);

    // The attacker replays the same message, swapping in a more powerful actor.
    let mut replay = original;
    replay.actor.scope = "admin".to_owned();
    let second = node.relay_write(replay).await.unwrap();

    assert_eq!(second, first, "a replay returns the cached response");
    assert_eq!(executor.applies(), 1, "one apply per idempotency key");
    assert_eq!(executor.calls().len(), 2, "both deliveries were received");
    assert_eq!(
        executor.calls()[1].idempotency_key.as_deref(),
        Some("idem-replay")
    );

    master.shutdown().await;
}

// --- threat: MITM on the cluster path -------------------------------------

/// The cluster path rejects every MITM/impersonation variant with the
/// documented code: missing certificate, foreign CA, unregistered fingerprint,
/// a re-issued certificate that does not match the registry, a revoked node and
/// an expired certificate.
#[tokio::test]
async fn threat_mitm_on_the_cluster_path_is_rejected() {
    let dir = TestDir::new("mitm");
    let master = start_master(
        &dir,
        clock(),
        Arc::new(MasterExecutor::new(false)),
        Arc::new(NoLogs),
        QuotaConfig::default(),
    )
    .await;
    let ca_pem = master.server.ca_cert_pem().to_owned();

    // No client certificate at all.
    let anonymous = http_client(&ca_pem, None);
    let response = open_stream(&anonymous, &master.url).await;
    assert_eq!(
        error_code(response).await,
        (403, "cluster.transport.tls".to_owned())
    );

    // A certificate signed by a foreign CA: rustls rejects the handshake, so
    // no HTTP body can carry the code.
    let (foreign_cert, foreign_key) = foreign_leaf("node-w");
    let wrong_ca = http_client(&ca_pem, Some((&foreign_cert, &foreign_key)));
    assert!(
        wrong_ca
            .get(format!("{}/cluster/v1/stream", master.url))
            .header("x-cluster-protocol", PROTOCOL_VERSION.to_string())
            .send()
            .await
            .is_err(),
        "a foreign-CA certificate was accepted"
    );

    // A valid chain for an unregistered node.
    let (stranger_cert, stranger_key, _) = leaf_from_cluster_ca(dir.path(), "node-z", false);
    let stranger = http_client(&ca_pem, Some((&stranger_cert, &stranger_key)));
    let response = open_stream(&stranger, &master.url).await;
    assert_eq!(
        error_code(response).await,
        (403, "cluster.node.unknown".to_owned())
    );

    // A re-issued certificate for an enrolled node: the fingerprint no longer
    // matches the registry, so it is not the same identity.
    let enrolled = enroll_node(&dir, &master, "node-a").await;
    let (reissued_cert, reissued_key, _) = leaf_from_cluster_ca(dir.path(), "node-a", false);
    let reissued = http_client(&ca_pem, Some((&reissued_cert, &reissued_key)));
    let response = open_stream(&reissued, &master.url).await;
    assert_eq!(
        error_code(response).await,
        (403, "cluster.node.unknown".to_owned())
    );

    // A registered, revoked node.
    let revoked = enroll_node(&dir, &master, "node-b").await;
    master.store.revoke("node-b").await.unwrap();
    let der = revoked.key().serialize_der();
    let revoked_http = http_client(&ca_pem, Some((revoked.node_cert_pem(), &der)));
    let response = open_stream(&revoked_http, &master.url).await;
    assert_eq!(
        error_code(response).await,
        (403, "cluster.node.revoked".to_owned())
    );

    // An expired certificate is rejected during the mTLS handshake even though
    // its fingerprint is registered.
    let (expired_cert, expired_key, fingerprint) =
        leaf_from_cluster_ca(dir.path(), "node-exp", true);
    master
        .store
        .register_node("node-exp", &fingerprint)
        .await
        .unwrap();
    let expired = http_client(&ca_pem, Some((&expired_cert, &expired_key)));
    assert!(
        expired
            .get(format!("{}/cluster/v1/stream", master.url))
            .header("x-cluster-protocol", PROTOCOL_VERSION.to_string())
            .send()
            .await
            .is_err(),
        "an expired node certificate was accepted"
    );

    // Sanity: the genuinely enrolled identity is still able to connect.
    assert!(client(&master, &enrolled).open_stream().await.is_ok());

    master.shutdown().await;
}

// --- threat: untrusted query-log content ----------------------------------

/// Query-log content is treated as untrusted data: the envelope is schema
/// validated, payload identity is never authoritative, and records stay opaque
/// (never inspected, formatted or reinterpreted by the crate).
#[tokio::test]
async fn threat_untrusted_query_log_content_is_validated_not_trusted() {
    let dir = TestDir::new("query-log");
    let ingest = Arc::new(RecordingIngest::default());
    let master = start_master(
        &dir,
        clock(),
        Arc::new(MasterExecutor::new(false)),
        ingest.clone(),
        QuotaConfig::default(),
    )
    .await;
    let identity = enroll_node(&dir, &master, "node-a").await;
    let node = client(&master, &identity);

    let hostile = json!({
        "query": "'; DROP TABLE query_log; --",
        "control": "line\r\nINJECTED",
        "spoofed_node_id": "node-b",
        "actor": { "actor_id": "admin", "scope": "admin" },
        "timestamp": "2099-01-01T00:00:00Z",
        "blob": "A".repeat(4096),
    });
    let batch = LogBatch {
        protocol: PROTOCOL_VERSION,
        node_id: "node-a".to_owned(),
        first_seq: 1,
        last_seq: 1,
        records: vec![LogRecord {
            id: "r1".to_owned(),
            record: hostile.clone(),
        }],
    };
    assert_eq!(node.post_logs(&batch).await.unwrap(), 1);

    // Opaque: the record reached ingest unchanged and never reached Debug.
    assert_eq!(ingest.records(), vec![batch.records[0].clone()]);
    assert!(!format!("{batch:?}").contains("DROP TABLE"));
    assert!(!format!("{:?}", batch.records[0]).contains("DROP TABLE"));

    // The payload `node_id` is not authority: a mismatch is rejected.
    let mut spoofed = batch.clone();
    spoofed.node_id = "node-b".to_owned();
    assert_eq!(
        node.post_logs(&spoofed).await.unwrap_err().code(),
        "cluster.log_stream.invalid"
    );

    // A truncated batch (records lost in transit) is rejected, not inserted.
    let mut truncated = batch.clone();
    truncated.last_seq = 2;
    assert_eq!(
        node.post_logs(&truncated).await.unwrap_err().code(),
        "cluster.log_stream.invalid"
    );

    // Truncated JSON is rejected with the same documented code.
    let der = identity.key().serialize_der();
    let raw = http_client(
        master.server.ca_cert_pem(),
        Some((identity.node_cert_pem(), &der)),
    );
    let response = raw
        .post(format!("{}/cluster/v1/logs", master.url))
        .header("content-type", "application/json")
        .body(r#"{"protocol":1,"node_id":"node-a","first_seq":1,"last_"#)
        .send()
        .await
        .unwrap();
    assert_eq!(
        error_code(response).await,
        (400, "cluster.log_stream.invalid".to_owned())
    );

    assert_eq!(ingest.inserted(), 1, "only the valid batch was ingested");

    // CL15 wiring: the master-side `LogIngest` implementation performs the
    // schema validation of individual records, length caps and the parameter
    // bound INSERT; this crate hands records through as opaque `Value`s.

    master.shutdown().await;
}

// --- threat: CA key / secret leakage --------------------------------------

/// The CA private key lives only on the master at mode 0600 and never appears
/// in config, certificates, Debug output or error text; token and key material
/// are redacted everywhere the crate exposes them.
#[tokio::test]
async fn threat_ca_key_and_secrets_never_leak() {
    let dir = TestDir::new("secrets");
    let master = start_master(
        &dir,
        clock(),
        Arc::new(MasterExecutor::new(false)),
        Arc::new(NoLogs),
        QuotaConfig::default(),
    )
    .await;
    let identity = enroll_node(&dir, &master, "node-a").await;

    let key_path = dir.path().join("ca.key");
    let mode = fs::metadata(&key_path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "the cluster CA key must be mode 0600");
    let key_pem = fs::read_to_string(&key_path).unwrap();
    assert!(key_pem.contains("PRIVATE KEY"));

    let ca = ClusterCa::load_or_generate(&dir.path().join("ca.pem")).unwrap();
    assert!(!format!("{ca:?}").contains("PRIVATE KEY"));
    assert!(!format!("{ca:?}").contains(key_pem.trim()));
    assert!(!master.server.ca_cert_pem().contains("PRIVATE KEY"));
    assert!(!master.server.server_cert_pem().contains("PRIVATE KEY"));

    // The CA key is not a config-export surface: `[cluster.tls]` has no key.
    let error = ClusterConfig::from_toml(
        "[cluster]\nrole = \"master\"\nnode_id = \"node-a\"\n\
         [cluster.listen]\nbind = \"127.0.0.1\"\n\
         [cluster.tls]\nca_key = \"data/cluster/ca.key\"\n",
    )
    .unwrap_err();
    assert_eq!(error.code(), "cluster.role.invalid");

    // Node key, join token, enrol request, and every opaque payload are
    // redacted by Debug.
    let node_key = identity.key().serialize_pem();
    assert!(!format!("{identity:?}").contains(&node_key));
    assert!(!format!("{identity:?}").contains("PRIVATE KEY"));
    let pending = PendingNodeIdentity::generate("node-pending").unwrap();
    assert!(!format!("{pending:?}").contains("PRIVATE KEY"));

    let token = master.store.mint_join_token("node-token").await.unwrap();
    let exposed = token.expose().to_owned();
    assert!(!format!("{token:?}").contains(&exposed));
    assert!(format!("{token:?}").contains("[redacted]"));

    let request = EnrollRequest::new(
        "node-a",
        Secret::new("one-time-join-token"),
        "csr-pem-placeholder",
    );
    assert!(!format!("{request:?}").contains("one-time-join-token"));

    let push = ConfigPush::new(1, &json!({ "secret": "do-not-log" })).unwrap();
    assert!(!format!("{push:?}").contains("do-not-log"));
    let cert = CertPush {
        protocol: PROTOCOL_VERSION,
        chain_pem: "chain".to_owned(),
        private_key: Secret::new("super-secret-key"),
    };
    assert!(!format!("{cert:?}").contains("super-secret-key"));
    let auth = AuthSnapshotPush {
        protocol: PROTOCOL_VERSION,
        snapshot: json!({ "token_hash": "leaked-hash" }),
    };
    assert!(!format!("{auth:?}").contains("leaked-hash"));
    let mut write = relay("secret-write");
    write.body = json!({ "private_key": "do-not-log" });
    assert!(!format!("{write:?}").contains("do-not-log"));
    let record = LogRecord {
        id: "r1".to_owned(),
        record: json!({ "secret": "do-not-log" }),
    };
    assert!(!format!("{record:?}").contains("do-not-log"));

    // Error text carries only the stable code and non-secret detail.
    for rendered in [
        ClusterError::TransportTls {
            message: "handshake failed".to_owned(),
        }
        .to_string(),
        ClusterError::Internal {
            message: "database open failed".to_owned(),
        }
        .to_string(),
    ] {
        assert!(!rendered.contains("PRIVATE KEY"));
    }

    // CL15 wiring: audit rows, `/api/v1/config` export and backups are
    // control-api surfaces; no cluster wire type so much as has a field for the
    // CA key, and `ClusterCa` holds it only in a non-`Serialize` `Secret`.

    master.shutdown().await;
}

// --- threat: audit integrity ----------------------------------------------

/// Every forwarded write reaches the master exactly once with the actor intact;
/// the master (not the payload) binds it to the authenticated node and emits
/// the audit entry.
#[tokio::test]
async fn threat_forwarded_write_produces_one_master_side_entry() {
    let dir = TestDir::new("audit");
    let executor = Arc::new(MasterExecutor::new(false));
    let master = start_master(
        &dir,
        clock(),
        executor.clone(),
        Arc::new(NoLogs),
        QuotaConfig::default(),
    )
    .await;
    let identity = enroll_node(&dir, &master, "node-a").await;
    let node = client(&master, &identity);

    let expected = relay("idem-audit");
    let response = node.relay_write(expected.clone()).await.unwrap();
    assert_eq!(response.status, 200);

    let calls = executor.calls();
    assert_eq!(calls.len(), 1, "one master-side write/audit per relay");
    assert_eq!(calls[0].actor, expected.actor);
    assert_eq!(calls[0].idempotency_key, expected.idempotency_key);

    // `node_id` cannot be supplied by the payload: `WriteRelay` has no such
    // field, and the mTLS certificate is the only identity source.
    let wire = serde_json::to_value(&expected).unwrap();
    let mut keys: Vec<&str> = wire
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        [
            "actor",
            "body",
            "idempotency_key",
            "if_match",
            "method",
            "path",
            "request_id"
        ]
    );

    // CL15 wiring: `WriteExecutor::execute` does not receive `node_id`; the
    // control-api assembler must pass the mTLS identity into the audit record
    // along with `config_version` and the before/after digests.

    master.shutdown().await;
}

// --- threat: per-node quota exhaustion ------------------------------------

/// Per-node quotas bound a faulty node's relay rate and log bandwidth without
/// affecting healthy nodes.
#[tokio::test]
async fn threat_per_node_quotas_bound_a_faulty_node() {
    let dir = TestDir::new("quotas");
    let payload_a1 = batch_for("node-a", 1);
    let payload_a2 = batch_for("node-a", 2);
    let payload_b1 = batch_for("node-b", 1);
    let max_log_bytes = [&payload_a1, &payload_a2, &payload_b1]
        .iter()
        .map(|batch| serde_json::to_vec(batch).unwrap().len() as u64)
        .max()
        .unwrap();

    let master = start_master(
        &dir,
        clock(),
        Arc::new(MasterExecutor::new(false)),
        Arc::new(RecordingIngest::default()),
        QuotaConfig {
            max_relay_requests_per_second: 2,
            max_log_bytes_per_second: max_log_bytes,
            ..QuotaConfig::default()
        },
    )
    .await;
    let identity_a = enroll_node(&dir, &master, "node-a").await;
    let node_a = client(&master, &identity_a);
    let identity_b = enroll_node(&dir, &master, "node-b").await;
    let node_b = client(&master, &identity_b);

    // Relay flood: node-a is rate limited, node-b keeps its own bucket.
    node_a.relay_write(relay("a1")).await.unwrap();
    node_a.relay_write(relay("a2")).await.unwrap();
    let rejected = node_a.relay_write(relay("a3")).await.unwrap();
    assert_eq!(rejected.status, 429);
    assert_eq!(rejected.body["error"]["code"], "cluster.quota.exceeded");
    node_b.relay_write(relay("b1")).await.unwrap();

    // Log bandwidth: one full batch drains node-a's second; node-b is fine.
    node_a.post_logs(&payload_a1).await.unwrap();
    assert_eq!(
        node_a.post_logs(&payload_a1).await.unwrap_err().code(),
        "cluster.quota.exceeded"
    );
    node_b.post_logs(&payload_b1).await.unwrap();

    // Clock-driven refill, no sleep.
    master.clock.advance(Duration::from_secs(1));
    node_a.post_logs(&payload_a2).await.unwrap();

    master.shutdown().await;
}

/// Connections the master accepts at once (`MAX_CONNECTIONS` in `server.rs`).
const CONNECTION_CAP: usize = 128;

#[tokio::test]
async fn threat_connection_flood_is_capped_and_slots_are_released() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    let dir = TestDir::new("conn-cap");
    let master = start_master(
        &dir,
        clock(),
        Arc::new(MasterExecutor::new(false)),
        Arc::new(NoLogs),
        QuotaConfig::default(),
    )
    .await;
    let addr = master.server.addr();

    // Silent peers occupy every slot: accepted, but waiting for a ClientHello.
    let mut idle = Vec::with_capacity(CONNECTION_CAP);
    for _ in 0..CONNECTION_CAP {
        idle.push(TcpStream::connect(addr).await.unwrap());
    }

    // One more peer sends junk. Over the cap it is not accepted, so nothing
    // answers: the read must not complete (a bounded wait proves the negative).
    let mut extra = TcpStream::connect(addr).await.unwrap();
    extra.write_all(b"GET / HTTP/1.1\r\n\r\n").await.unwrap();
    let mut answer = Vec::new();
    let blocked =
        tokio::time::timeout(Duration::from_millis(300), extra.read_to_end(&mut answer)).await;
    assert!(
        blocked.is_err(),
        "connection beyond the cap must not be served"
    );

    // Dropping one silent peer frees its slot; the queued peer is then accepted,
    // fails the handshake on its junk (TLS alert) and is closed (EOF).
    drop(idle.pop());
    tokio::time::timeout(Duration::from_secs(10), extra.read_to_end(&mut answer))
        .await
        .expect("queued connection is served once a slot frees")
        .unwrap();

    drop(idle);
    master.shutdown().await;
}
