//! Loopback proof of the master-side per-node quotas and clock-skew warning:
//! a node flooding `/writes` or `/logs` above its per-second budget is
//! rejected, a skewed heartbeat is flagged without being rejected, and an
//! offline queue depth above the cap is reported in the heartbeat status.
//!
//! Real sockets on `127.0.0.1:0`, generated CA/certs via `rcgen`, an injectable
//! [`ManualClock`], and no wall-clock waits.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::fs;
use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime};

use async_trait::async_trait;
use dnscraft_cluster::{
    ClusterCa, ClusterClient, ClusterError, ClusterServer, ClusterServerConfig, ClusterStore,
    HeartbeatRequest, HeartbeatResponse, ListenConfig, LogBatch, LogIngest, LogRecord,
    NodeIdentity, PROTOCOL_VERSION, PendingNodeIdentity, QuotaConfig, RelayResponse, RelayedActor,
    TlsPaths, WriteExecutor, WriteRelay,
};
use dnscraft_common::clock::{Clock, ManualClock};
use dnscraft_common::secret::Secret;
use reqwest::Client;
use rustls::RootCertStore;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use serde_json::{Value, json};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

const NODE_CERT_TTL: Duration = Duration::from_secs(90 * 24 * 3600);
const TOKEN_TTL: Duration = Duration::from_secs(15 * 60);

/// Accepts every relayed write.
struct MockWrites;

#[async_trait]
impl WriteExecutor for MockWrites {
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
        Ok(RelayResponse {
            status: 200,
            body: json!({ "ok": true }),
        })
    }
}

/// Accepts every log batch and acks its last sequence.
struct MockLogs;

#[async_trait]
impl LogIngest for MockLogs {
    async fn ingest(
        &self,
        _node_id: &str,
        _first_seq: u64,
        last_seq: u64,
        _records: &[LogRecord],
    ) -> Result<u64, ClusterError> {
        Ok(last_seq)
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
            "dnscraft-cluster-quota-{name}-{}-{id}",
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

async fn start_master(name: &str, quota: QuotaConfig) -> Master {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let dir = TestDir::new(name);
    // Real wall-clock start keeps the freshly issued certificates valid for
    // rustls; time only moves when the test advances it.
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
            quota,
            timing: dnscraft_cluster::TimingConfig::default(),
        },
        ca,
        store.clone(),
        clock.clone(),
        Arc::new(MockWrites),
        Arc::new(MockLogs),
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

fn client(master: &Master, identity: &NodeIdentity) -> ClusterClient {
    ClusterClient::new(&master.url, identity, master.clock.clone()).unwrap()
}

fn relay(request_id: &str) -> WriteRelay {
    WriteRelay {
        request_id: request_id.to_owned(),
        idempotency_key: None,
        if_match: None,
        method: "PUT".to_owned(),
        path: "/api/v1/config/filter-sets/x".to_owned(),
        body: json!({}),
        actor: RelayedActor {
            actor_id: "user-1".to_owned(),
            actor_type: "user".to_owned(),
            scope: "admin".to_owned(),
        },
    }
}

fn batch(node_id: &str) -> LogBatch {
    LogBatch {
        protocol: PROTOCOL_VERSION,
        node_id: node_id.to_owned(),
        first_seq: 1,
        last_seq: 1,
        records: vec![LogRecord {
            id: "record-1".to_owned(),
            record: json!({ "id": "record-1" }),
        }],
    }
}

/// reqwest HTTP/2 client trusting `ca_pem` and presenting the node identity.
fn http_client(ca_pem: &str, identity: &NodeIdentity) -> Client {
    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from_pem_slice(ca_pem.as_bytes()).unwrap())
        .unwrap();
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(roots);
    let certs = CertificateDer::pem_slice_iter(identity.node_cert_pem().as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(identity.key().serialize_der()));
    let mut tls = builder.with_client_auth_cert(certs, key).unwrap();
    tls.alpn_protocols = vec![b"h2".to_vec()];
    Client::builder()
        .use_preconfigured_tls(tls)
        .build()
        .unwrap()
}

/// Sends a heartbeat with an explicit node clock and parses the status.
async fn heartbeat(
    master: &Master,
    identity: &NodeIdentity,
    queue_depth: u32,
    time: Option<String>,
) -> HeartbeatResponse {
    let request = HeartbeatRequest {
        protocol: PROTOCOL_VERSION,
        applied_version: None,
        queue_depth,
        time,
    };
    let response = http_client(master.server.ca_cert_pem(), identity)
        .post(format!("{}/cluster/v1/heartbeat", master.url))
        .header("content-type", "application/json")
        .body(serde_json::to_vec(&request).unwrap())
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 200);
    serde_json::from_slice(&response.bytes().await.unwrap()).unwrap()
}

fn has_warning(response: &HeartbeatResponse, code: &str) -> bool {
    response.warnings.iter().any(|warning| warning.code == code)
}

fn rfc3339(time: SystemTime) -> String {
    OffsetDateTime::from(time).format(&Rfc3339).unwrap()
}

#[tokio::test]
async fn relay_flood_is_rejected_per_node_and_refills_with_the_clock() {
    let master = start_master(
        "relay-flood",
        QuotaConfig {
            max_relay_requests_per_second: 2,
            ..QuotaConfig::default()
        },
    )
    .await;
    let identity = enroll_node(&master, "node-a").await;
    let node = client(&master, &identity);

    node.relay_write(relay("a1")).await.unwrap();
    node.relay_write(relay("a2")).await.unwrap();
    // `relay_write` returns the master's status and body verbatim.
    let rejected = node.relay_write(relay("a3")).await.unwrap();
    assert_eq!(rejected.status, 429);
    assert_eq!(rejected.body["error"]["code"], "cluster.quota.exceeded");

    // The limit is per node: another node still has its full bucket.
    let other = enroll_node(&master, "node-b").await;
    client(&master, &other)
        .relay_write(relay("b1"))
        .await
        .unwrap();

    // One second of injected clock time refills the bucket; no sleep.
    master.clock.advance(Duration::from_secs(1));
    node.relay_write(relay("a4")).await.unwrap();

    master.server.shutdown().await;
}

#[tokio::test]
async fn log_byte_flood_is_rejected_and_refills_with_the_clock() {
    let payload = batch("node-a");
    let bytes = serde_json::to_vec(&payload).unwrap().len() as u64;
    let master = start_master(
        "log-flood",
        QuotaConfig {
            max_log_bytes_per_second: bytes,
            ..QuotaConfig::default()
        },
    )
    .await;
    let identity = enroll_node(&master, "node-a").await;
    let node = client(&master, &identity);

    // The burst budget is exactly one serialized batch.
    node.post_logs(&payload).await.unwrap();
    let error = node.post_logs(&payload).await.unwrap_err();
    assert_eq!(error.code(), "cluster.quota.exceeded");

    master.clock.advance(Duration::from_secs(1));
    node.post_logs(&payload).await.unwrap();

    master.server.shutdown().await;
}

#[tokio::test]
async fn skewed_heartbeat_is_flagged_but_accepted() {
    let master = start_master("skew", QuotaConfig::default()).await;
    let identity = enroll_node(&master, "node-a").await;
    let now = master.clock.now();

    // Default warning threshold is 5 minutes.
    let skewed = heartbeat(
        &master,
        &identity,
        0,
        Some(rfc3339(now - Duration::from_secs(10 * 60))),
    )
    .await;
    assert!(skewed.ok);
    assert!(has_warning(&skewed, "cluster.clock_skew"));

    let in_sync = heartbeat(&master, &identity, 0, Some(rfc3339(now))).await;
    assert!(in_sync.ok);
    assert!(!has_warning(&in_sync, "cluster.clock_skew"));

    master.server.shutdown().await;
}

#[tokio::test]
async fn queue_depth_over_the_cap_is_reported_in_status() {
    let master = start_master(
        "queue-cap",
        QuotaConfig {
            max_queued_offline_writes: 5,
            ..QuotaConfig::default()
        },
    )
    .await;
    let identity = enroll_node(&master, "node-a").await;

    let at_cap = heartbeat(&master, &identity, 5, None).await;
    assert!(!has_warning(&at_cap, "cluster.offline_write_queue_full"));

    // Over the cap: still a successful heartbeat, but flagged.
    let over = heartbeat(&master, &identity, 6, None).await;
    assert!(over.ok);
    assert!(has_warning(&over, "cluster.offline_write_queue_full"));

    master.server.shutdown().await;
}

#[tokio::test]
async fn unacked_push_past_the_apply_timeout_is_stale_in_heartbeat() {
    let master = start_master("stale", QuotaConfig::default()).await;
    let identity = enroll_node(&master, "node-a").await;

    // A connected node that never acknowledges the push it is sent.
    let stream = client(&master, &identity).open_stream().await.unwrap();
    master
        .server
        .config_sync()
        .publish(1, &serde_json::json!({ "a": 1 }))
        .unwrap();
    assert!(master.server.degraded_nodes().is_empty());

    // The default `config_apply_timeout` is 30 seconds.
    master.clock.advance(Duration::from_secs(30));
    assert_eq!(master.server.degraded_nodes(), vec!["node-a".to_owned()]);
    let stale = heartbeat(&master, &identity, 0, None).await;
    assert!(has_warning(&stale, "cluster.config.stale"));

    drop(stream);
    master.server.shutdown().await;
}

#[tokio::test]
async fn heartbeat_flood_is_rejected_per_node() {
    let master = start_master("heartbeat-flood", QuotaConfig::default()).await;
    let identity = enroll_node(&master, "node-a").await;
    let request = HeartbeatRequest {
        protocol: PROTOCOL_VERSION,
        applied_version: None,
        queue_depth: 0,
        time: None,
    };
    let raw = http_client(master.server.ca_cert_pem(), &identity);
    let mut last_status = 0;
    // The burst is 10 heartbeats; the eleventh at the same clock instant is refused.
    for _ in 0..11 {
        let response = raw
            .post(format!("{}/cluster/v1/heartbeat", master.url))
            .header("content-type", "application/json")
            .body(serde_json::to_vec(&request).unwrap())
            .send()
            .await
            .unwrap();
        last_status = response.status().as_u16();
    }
    assert_eq!(last_status, 429);

    master.server.shutdown().await;
}

#[tokio::test]
async fn enroll_attempts_are_rate_limited_listener_wide() {
    let master = start_master("enroll-flood", QuotaConfig::default()).await;
    let pending = PendingNodeIdentity::generate("node-a").unwrap();
    let mut last_code = String::new();
    for _ in 0..11 {
        let error = ClusterClient::enroll(
            &master.url,
            master.server.server_cert_pem(),
            pending.request(Secret::new("not-a-real-token")),
        )
        .await
        .unwrap_err();
        last_code = error.code().to_owned();
    }
    assert_eq!(last_code, "cluster.quota.exceeded");

    master.server.shutdown().await;
}

#[tokio::test]
async fn one_node_cannot_hold_more_than_its_connection_cap() {
    let master = start_master("connection-cap", QuotaConfig::default()).await;
    let identity = enroll_node(&master, "node-a").await;

    // Each client has its own HTTP/2 connection pool, so each stream is its own
    // TCP connection. The cap is eight per node.
    let mut streams = Vec::new();
    for _ in 0..8 {
        let node = client(&master, &identity);
        streams.push(node.open_stream().await.unwrap());
    }
    let extra = client(&master, &identity);
    let Err(error) = extra.open_stream().await else {
        panic!("a ninth connection must be refused");
    };
    assert_eq!(error.code(), "cluster.master_unavailable");

    // A slot frees when a connection ends.
    streams.pop();
    let reopened = client(&master, &identity).open_stream().await;
    assert!(reopened.is_ok());

    master.server.shutdown().await;
}

#[tokio::test]
async fn node_ahead_of_the_master_is_a_master_conflict_warning() {
    let master = start_master("conflict", QuotaConfig::default()).await;
    let identity = enroll_node(&master, "node-a").await;
    master
        .server
        .config_sync()
        .publish(3, &serde_json::json!({ "a": 3 }))
        .unwrap();

    let request = HeartbeatRequest {
        protocol: PROTOCOL_VERSION,
        applied_version: Some(4),
        queue_depth: 0,
        time: None,
    };
    let response = http_client(master.server.ca_cert_pem(), &identity)
        .post(format!("{}/cluster/v1/heartbeat", master.url))
        .header("content-type", "application/json")
        .body(serde_json::to_vec(&request).unwrap())
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 200);
    let body: HeartbeatResponse = serde_json::from_slice(&response.bytes().await.unwrap()).unwrap();
    assert!(has_warning(&body, "cluster.master_conflict"));

    master.server.shutdown().await;
}
