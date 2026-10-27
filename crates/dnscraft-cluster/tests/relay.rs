//! Loopback proof of the write-relay and runtime-broadcast slice:
//! a relayed write reaches the master executor with the actor unchanged and
//! its response comes back verbatim, exhausted retries return
//! `cluster.write_relay_failed`, and a broadcast runtime command reaches every
//! connected sub-node (with applier failures reported).
//!
//! Real sockets on `127.0.0.1:0`, generated CA/certs via `rcgen`, an injectable
//! [`ManualClock`], mock hooks, and no wall-clock waits.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::fs;
use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use async_trait::async_trait;
use dnscraft_cluster::{
    ClusterCa, ClusterClient, ClusterError, ClusterServer, ClusterServerConfig, ClusterStore,
    ListenConfig, LogIngest, LogRecord, NodeIdentity, PendingNodeIdentity, QuotaConfig,
    RelayResponse, RelayedActor, RuntimeCommandApplier, TlsPaths, WriteExecutor, WriteRelay,
};
use dnscraft_common::clock::ManualClock;
use dnscraft_common::secret::Secret;
use serde_json::{Value, json};

const NODE_CERT_TTL: Duration = Duration::from_secs(90 * 24 * 3600);
const TOKEN_TTL: Duration = Duration::from_secs(15 * 60);

/// One `execute` call recorded by [`MockExecutor`].
struct Call {
    node_id: String,
    actor: RelayedActor,
    method: String,
    path: String,
    body: Value,
    if_match: Option<String>,
    idempotency_key: Option<String>,
}

/// Records relayed writes and returns a fixed response.
struct MockExecutor {
    calls: Mutex<Vec<Call>>,
    response: RelayResponse,
}

impl MockExecutor {
    fn new(response: RelayResponse) -> Self {
        Self {
            calls: Mutex::new(Vec::new()),
            response,
        }
    }

    fn calls(&self) -> Vec<Call> {
        std::mem::take(&mut *self.calls.lock().unwrap())
    }
}

#[async_trait]
impl WriteExecutor for MockExecutor {
    async fn execute(
        &self,
        node_id: &str,
        actor: RelayedActor,
        method: String,
        path: String,
        body: Value,
        if_match: Option<String>,
        idempotency_key: Option<String>,
    ) -> Result<RelayResponse, ClusterError> {
        self.calls.lock().unwrap().push(Call {
            node_id: node_id.to_owned(),
            actor,
            method,
            path,
            body,
            if_match,
            idempotency_key,
        });
        Ok(self.response.clone())
    }
}

/// Records runtime commands and can be told to fail.
#[derive(Default)]
struct MockRuntime {
    seen: Mutex<Vec<(String, Value)>>,
    fail: bool,
}

impl MockRuntime {
    fn failing() -> Self {
        Self {
            fail: true,
            ..Self::default()
        }
    }

    fn seen(&self) -> Vec<(String, Value)> {
        self.seen.lock().unwrap().clone()
    }
}

#[async_trait]
impl RuntimeCommandApplier for MockRuntime {
    async fn apply_runtime_command(&self, kind: &str, payload: &Value) -> Result<(), ClusterError> {
        if self.fail {
            return Err(ClusterError::Internal {
                message: "mock runtime failure".to_owned(),
            });
        }
        self.seen
            .lock()
            .unwrap()
            .push((kind.to_owned(), payload.clone()));
        Ok(())
    }
}

/// A unique, self-cleaning temporary directory.
struct TestDir(PathBuf);

impl TestDir {
    fn new(name: &str) -> Self {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let id = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "dnscraft-cluster-relay-{name}-{}-{id}",
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

/// A real master listening on loopback.
struct Master {
    server: ClusterServer,
    store: ClusterStore,
    clock: Arc<ManualClock>,
    dir: TestDir,
    url: String,
}

async fn start_master(name: &str, executor: Arc<dyn WriteExecutor>) -> Master {
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
        executor,
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

fn relay(actor: RelayedActor) -> WriteRelay {
    WriteRelay {
        request_id: "req-1".to_owned(),
        idempotency_key: Some("idem-1".to_owned()),
        if_match: Some("\"v7\"".to_owned()),
        method: "PUT".to_owned(),
        path: "/api/v1/config".to_owned(),
        body: json!({ "policy": { "views": [] } }),
        actor,
    }
}

fn actor() -> RelayedActor {
    RelayedActor {
        actor_id: "user-7".to_owned(),
        actor_type: "user".to_owned(),
        scope: "admin".to_owned(),
    }
}

#[tokio::test]
async fn relayed_write_reaches_the_executor_and_the_response_is_verbatim() {
    let response = RelayResponse {
        status: 201,
        body: json!({ "data": { "config_version": 8, "created": true } }),
    };
    let executor = Arc::new(MockExecutor::new(response.clone()));
    let master = start_master("happy", executor.clone()).await;
    let client = client_for(&master, "node-a").await;

    let expected = relay(actor());
    let relayed = client.relay_write(expected.clone()).await.unwrap();
    assert_eq!(relayed, response);

    let calls = executor.calls();
    assert_eq!(calls.len(), 1);
    let call = &calls[0];
    // The master derives the originating node from the mTLS certificate.
    assert_eq!(call.node_id, "node-a");
    assert_eq!(call.actor, expected.actor);
    assert_eq!(call.method, expected.method);
    assert_eq!(call.path, expected.path);
    assert_eq!(call.body, expected.body);
    assert_eq!(call.if_match, expected.if_match);
    assert_eq!(call.idempotency_key, expected.idempotency_key);

    master.server.shutdown().await;
}

#[tokio::test]
async fn exhausted_retries_return_write_relay_failed() {
    let executor = Arc::new(MockExecutor::new(RelayResponse {
        status: 200,
        body: json!({ "data": {} }),
    }));
    let master = start_master("retry", executor).await;
    let client = client_for(&master, "node-a").await;
    let clock = master.clock.clone();

    // Close the listener: every retry is a transport failure.
    master.server.shutdown().await;

    let handle = tokio::spawn(async move { client.relay_write(relay(actor())).await });
    // Drive the manual clock until the relay gives up. Each advance wakes the
    // backoff waiter; the bounded loop replaces a wall-clock timeout.
    for _ in 0..1000 {
        if handle.is_finished() {
            break;
        }
        clock.advance(Duration::from_secs(1));
        tokio::task::yield_now().await;
    }
    assert!(handle.is_finished(), "relay did not exhaust its retries");
    let error = handle.await.unwrap().unwrap_err();
    assert_eq!(error.code(), "cluster.write_relay_failed");
}

#[tokio::test]
async fn runtime_command_broadcast_reaches_every_connected_node() {
    let executor = Arc::new(MockExecutor::new(RelayResponse {
        status: 200,
        body: json!({ "data": {} }),
    }));
    let master = start_master("broadcast", executor).await;
    let client_a = client_for(&master, "node-a").await;
    let client_b = client_for(&master, "node-b").await;
    let mut stream_a = client_a.open_stream().await.unwrap();
    let mut stream_b = client_b.open_stream().await.unwrap();

    let applier_a = MockRuntime::default();
    let applier_b = MockRuntime::default();

    let pause = json!({ "paused": true });
    master.server.broadcast_runtime_command("pause", &pause);

    assert!(
        client_a
            .apply_runtime_next(&mut stream_a, &applier_a)
            .await
            .unwrap()
    );
    assert!(
        client_b
            .apply_runtime_next(&mut stream_b, &applier_b)
            .await
            .unwrap()
    );
    assert_eq!(applier_a.seen(), vec![("pause".to_owned(), pause.clone())]);
    assert_eq!(applier_b.seen(), vec![("pause".to_owned(), pause)]);

    // A failing applier is reported as cluster.runtime_command.failed while
    // the other node still applies the same command.
    let failing = MockRuntime::failing();
    master
        .server
        .broadcast_runtime_command("resume", &json!({ "paused": false }));

    assert!(
        client_a
            .apply_runtime_next(&mut stream_a, &applier_a)
            .await
            .unwrap()
    );
    let error = client_b
        .apply_runtime_next(&mut stream_b, &failing)
        .await
        .unwrap_err();
    assert_eq!(error.code(), "cluster.runtime_command.failed");
    assert_eq!(applier_a.seen().len(), 2);

    drop(stream_a);
    drop(stream_b);
    master.server.shutdown().await;
}
