//! Fault-injection matrix for the cluster crate.
//!
//! Each test injects one fault from `SPEC-cluster.md` § Testing strategy item 3
//! — drop, delay, reorder/duplicate, truncate, partition and restart — through
//! the crate's own seams: a controllable executor, the real `ClusterServer` /
//! `ClusterClient` on loopback, the durable SQLite store, and the injectable
//! [`ManualClock`]. No wall-clock sleeps and no real network.
//!
//! Faults that can only be exercised through the not-yet-wired control-api path
//! are marked with a `CL15 wiring:` comment instead of being faked.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use async_trait::async_trait;
use dnscraft_cluster::{
    ClusterCa, ClusterClient, ClusterError, ClusterServer, ClusterServerConfig, ClusterStore,
    ConfigApplier, EnqueueOutcome, ListenConfig, LogBatch, LogConfig, LogIngest, LogOutbox,
    LogRecord, LogStreamer, NodeIdentity, OfflineWriteQueue, OfflineWriteState,
    OfflineWritesConfig, PROTOCOL_VERSION, PendingNodeIdentity, QuotaConfig, RelayResponse,
    RelayedActor, StreamRecord, TlsPaths, WriteExecutor, WriteRelay,
};
use dnscraft_common::clock::ManualClock;
use dnscraft_common::secret::Secret;
use serde_json::{Value, json};

const NODE_CERT_TTL: Duration = Duration::from_secs(90 * 24 * 3600);
const TOKEN_TTL: Duration = Duration::from_secs(15 * 60);
const OFFLINE_MAX_AGE: Duration = Duration::from_secs(3600);

/// Master-side executor: records the idempotency keys it received, dedupes on
/// them, and counts actual applies (the "config-version count").
struct MasterExecutor {
    keys: Mutex<Vec<Option<String>>>,
    applied: Mutex<HashSet<String>>,
    applies: AtomicU32,
}

impl MasterExecutor {
    fn new() -> Self {
        Self {
            keys: Mutex::new(Vec::new()),
            applied: Mutex::new(HashSet::new()),
            applies: AtomicU32::new(0),
        }
    }

    fn keys(&self) -> Vec<Option<String>> {
        self.keys.lock().unwrap().clone()
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
        _actor: RelayedActor,
        _method: String,
        _path: String,
        _body: Value,
        _if_match: Option<String>,
        idempotency_key: Option<String>,
    ) -> Result<RelayResponse, ClusterError> {
        let index = {
            let mut keys = self.keys.lock().unwrap();
            keys.push(idempotency_key.clone());
            keys.len()
        };
        let key = idempotency_key.unwrap_or_else(|| format!("unordered-{index}"));
        if self.applied.lock().unwrap().insert(key) {
            self.applies.fetch_add(1, Ordering::SeqCst);
        }
        Ok(RelayResponse {
            status: 200,
            body: json!({ "data": { "config_version": 7 } }),
        })
    }
}

/// Sub-node-side executor that forwards the queue's relay through the real
/// mTLS `ClusterClient`.
struct ClientExecutor {
    client: Arc<ClusterClient>,
    counter: AtomicU64,
}

#[async_trait]
impl WriteExecutor for ClientExecutor {
    async fn execute(
        &self,
        _node_id: &str,
        _request_id: &str,
        actor: RelayedActor,
        method: String,
        path: String,
        body: Value,
        if_match: Option<String>,
        idempotency_key: Option<String>,
    ) -> Result<RelayResponse, ClusterError> {
        let id = self.counter.fetch_add(1, Ordering::SeqCst);
        self.client
            .relay_write(WriteRelay {
                request_id: format!("replay-{id}"),
                idempotency_key,
                if_match,
                method,
                path,
                body,
                actor,
            })
            .await
    }
}

/// Applies the first attempt on the master but loses the response (ambiguous
/// ack), then answers the retry from its idempotency cache.
struct AmbiguousAckExecutor {
    clock: Arc<ManualClock>,
    calls: AtomicU32,
    applies: AtomicU32,
}

#[async_trait]
impl WriteExecutor for AmbiguousAckExecutor {
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
        if self.calls.fetch_add(1, Ordering::SeqCst) == 0 {
            self.applies.fetch_add(1, Ordering::SeqCst);
            // Let the retry backoff elapse without a wall-clock sleep.
            self.clock.advance(Duration::from_secs(5));
            return Err(ClusterError::MasterUnavailable);
        }
        Ok(RelayResponse {
            status: 200,
            body: json!({ "data": { "config_version": 3 } }),
        })
    }
}

/// Records applied config versions.
#[derive(Default)]
struct RecordingApplier {
    applied: Mutex<Vec<(i64, Value)>>,
}

impl RecordingApplier {
    fn applied(&self) -> Vec<(i64, Value)> {
        self.applied.lock().unwrap().clone()
    }
}

#[async_trait]
impl ConfigApplier for RecordingApplier {
    async fn apply(&self, version: i64, snapshot: &Value) -> Result<i64, ClusterError> {
        self.applied
            .lock()
            .unwrap()
            .push((version, snapshot.clone()));
        Ok(version)
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
    calls: Vec<(String, u64, u64)>,
    gaps: Vec<(String, u64, u64)>,
    inserted: usize,
    duplicates: usize,
}

/// Master ingest that dedupes `(node_id, seq)` and `(node_id, record_id)` and
/// records gaps, mirroring the contract the real ingest implements.
#[derive(Default)]
struct MockIngest {
    state: Mutex<IngestState>,
}

impl MockIngest {
    fn inserted(&self) -> usize {
        self.state.lock().unwrap().inserted
    }

    fn duplicates(&self) -> usize {
        self.state.lock().unwrap().duplicates
    }

    fn calls(&self) -> Vec<(String, u64, u64)> {
        self.state.lock().unwrap().calls.clone()
    }

    fn gaps(&self) -> Vec<(String, u64, u64)> {
        self.state.lock().unwrap().gaps.clone()
    }
}

#[async_trait]
impl LogIngest for MockIngest {
    async fn ingest(
        &self,
        node_id: &str,
        first_seq: u64,
        last_seq: u64,
        records: &[LogRecord],
    ) -> Result<u64, ClusterError> {
        let mut guard = self.state.lock().unwrap();
        let state = &mut *guard;
        state.calls.push((node_id.to_owned(), first_seq, last_seq));
        let IngestState {
            nodes,
            gaps,
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
            gaps.push((node_id.to_owned(), expected, first_seq - 1));
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

/// In-memory log outbox whose rows are keyed by `seq`.
struct MockOutbox {
    rows: Mutex<BTreeMap<u64, LogRecord>>,
    next: Mutex<u64>,
}

impl MockOutbox {
    fn new(start: u64, end: u64, next: u64) -> Self {
        let rows = (start..=end)
            .map(|seq| {
                let id = format!("r{seq}");
                (
                    seq,
                    LogRecord {
                        id: id.clone(),
                        record: json!({ "id": id, "seq": seq }),
                    },
                )
            })
            .collect();
        Self {
            rows: Mutex::new(rows),
            next: Mutex::new(next),
        }
    }

    /// Pretends the previous ack was lost, so the same rows are sent again.
    fn rewind(&self, next: u64) {
        *self.next.lock().unwrap() = next;
    }
}

#[async_trait]
impl LogOutbox for MockOutbox {
    async fn next_unacked_seq(&self) -> Result<u64, ClusterError> {
        Ok(*self.next.lock().unwrap())
    }

    async fn fetch_batch(
        &self,
        from_seq: u64,
        max_records: usize,
    ) -> Result<Vec<LogRecord>, ClusterError> {
        let rows = self.rows.lock().unwrap();
        Ok(rows
            .range(from_seq..)
            .take(max_records)
            .map(|(_, record)| record.clone())
            .collect())
    }

    async fn ack(&self, seq: u64) -> Result<(), ClusterError> {
        let mut next = self.next.lock().unwrap();
        *next = (*next).max(seq.saturating_add(1));
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
            "dnscraft-cluster-injection-{name}-{}-{id}",
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
) -> Master {
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

async fn in_memory_master(
    dir: &TestDir,
    clock: Arc<ManualClock>,
    executor: Arc<dyn WriteExecutor>,
    ingest: Arc<dyn LogIngest>,
) -> Master {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let ca = ClusterCa::load_or_generate(&dir.path().join("ca.pem")).unwrap();
    let store = ClusterStore::open_in_memory(clock.clone(), TOKEN_TTL)
        .await
        .unwrap();
    start_server(clock, store, ca, executor, ingest).await
}

/// A master backed by the durable SQLite database and CA in `dir`.
async fn durable_master(
    dir: &TestDir,
    clock: Arc<ManualClock>,
    executor: Arc<dyn WriteExecutor>,
    ingest: Arc<dyn LogIngest>,
) -> Master {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let ca = ClusterCa::load_or_generate(&dir.path().join("ca.pem")).unwrap();
    let store = ClusterStore::open(&dir.path().join("cluster.db"), clock.clone(), TOKEN_TTL)
        .await
        .unwrap();
    start_server(clock, store, ca, executor, ingest).await
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

fn queue_config() -> OfflineWritesConfig {
    OfflineWritesConfig {
        enabled: true,
        queue_max_entries: 10,
        max_age: OFFLINE_MAX_AGE,
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

// --- fault: drop / delay (config push) ------------------------------------

/// A dropped config push (delivered but never acked) is retried on the
/// master's clock-driven backoff until it converges.
#[tokio::test]
async fn config_push_converges_after_a_dropped_delivery() {
    let dir = TestDir::new("drop");
    let clock = clock();
    let master = in_memory_master(
        &dir,
        clock.clone(),
        Arc::new(MasterExecutor::new()),
        Arc::new(NoLogs),
    )
    .await;
    let identity = enroll_node(&dir, &master, "node-a").await;
    let node = client(&master, &identity);
    let mut stream = node.open_stream().await.unwrap();

    let snapshot = json!({ "version": 7, "policy": { "views": [] } });
    master.server.config_sync().publish(7, &snapshot).unwrap();

    // The push arrives but is dropped before the applier sees it, so no ack
    // reaches the master.
    let dropped = stream.next_record().await.unwrap();
    assert!(matches!(dropped, StreamRecord::ConfigPush(_)));

    // The retry deadline is driven by the injected clock, never a sleep.
    clock.advance(Duration::from_secs(1));

    let applier = RecordingApplier::default();
    let applied = node.apply_next(&mut stream, &applier).await.unwrap();
    assert_eq!(applied, Some(7));
    assert_eq!(applier.applied(), vec![(7, snapshot)]);

    let lag = master.server.config_sync().node_lag("node-a").unwrap();
    assert_eq!(
        (lag.pushed_version, lag.applied_version, lag.lag),
        (7, 7, 0),
        "the push must eventually converge"
    );

    drop(stream);
    master.shutdown().await;
}

/// A partition (stream loss) while a new snapshot is published converges on
/// reconnect from the node's last applied version.
#[tokio::test]
async fn config_push_converges_after_a_partition() {
    let dir = TestDir::new("partition");
    let clock = clock();
    let master = in_memory_master(
        &dir,
        clock,
        Arc::new(MasterExecutor::new()),
        Arc::new(NoLogs),
    )
    .await;
    let identity = enroll_node(&dir, &master, "node-a").await;
    let node = client(&master, &identity);
    let applier = RecordingApplier::default();

    let mut stream = node.open_stream().await.unwrap();
    let first = json!({ "version": 1 });
    master.server.config_sync().publish(1, &first).unwrap();
    assert_eq!(
        node.apply_next(&mut stream, &applier).await.unwrap(),
        Some(1)
    );

    // Partition: the connection dies, then the master publishes version 2 while
    // the node is offline.
    drop(stream);
    let second = json!({ "version": 2 });
    master.server.config_sync().publish(2, &second).unwrap();

    // Reconnect with the last applied version; the master pushes the current
    // full snapshot and lag returns to zero.
    let mut stream = node.open_stream_with(Some(1), None).await.unwrap();
    assert_eq!(
        node.apply_next(&mut stream, &applier).await.unwrap(),
        Some(2)
    );
    assert_eq!(applier.applied(), vec![(1, first), (2, second)]);
    assert_eq!(
        master.server.config_sync().node_lag("node-a").unwrap().lag,
        0
    );

    drop(stream);
    master.shutdown().await;
}

// --- fault: duplicate / retry (writes) ------------------------------------

/// Duplicate delivery (a retry after an unknown outcome) applies exactly once:
/// the idempotency key rides through unchanged and the master dedupes.
#[tokio::test]
async fn forwarded_write_is_exactly_once_under_duplicate_delivery() {
    let dir = TestDir::new("duplicate-write");
    let executor = Arc::new(MasterExecutor::new());
    let master = in_memory_master(&dir, clock(), executor.clone(), Arc::new(NoLogs)).await;
    let identity = enroll_node(&dir, &master, "node-a").await;
    let node = client(&master, &identity);

    let message = relay("idem-dup");
    let first = node.relay_write(message.clone()).await.unwrap();
    let retry = node.relay_write(message).await.unwrap();

    assert_eq!(first.status, 200);
    assert_eq!(first, retry, "the retry sees the same response");
    assert_eq!(
        executor.applies(),
        1,
        "one config-version bump for two deliveries"
    );
    assert_eq!(
        executor.keys(),
        vec![Some("idem-dup".to_owned()), Some("idem-dup".to_owned())],
        "the sub-node must pass the same Idempotency-Key on the retry"
    );

    master.shutdown().await;
}

/// An ambiguous ack (master applied, response lost) is replayed without a
/// second apply.
#[tokio::test]
async fn ambiguous_ack_does_not_double_apply() {
    let clock = Arc::new(ManualClock::new(
        SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000),
    ));
    let store = ClusterStore::open_in_memory(clock.clone(), TOKEN_TTL)
        .await
        .unwrap();
    let queue = OfflineWriteQueue::new(store, queue_config());
    queue.enqueue(relay("idem-ambiguous")).await.unwrap();

    let executor = AmbiguousAckExecutor {
        clock: clock.clone(),
        calls: AtomicU32::new(0),
        applies: AtomicU32::new(0),
    };
    let outcome = queue.replay_all(&executor).await.unwrap();

    assert_eq!(outcome.applied, 1);
    assert_eq!(outcome.failed, 0);
    assert_eq!(executor.calls.load(Ordering::SeqCst), 2, "one retry");
    assert_eq!(
        executor.applies.load(Ordering::SeqCst),
        1,
        "the retry must not apply a second config version"
    );
    assert_eq!(queue.status().await.unwrap().applied, 1);
    assert_eq!(
        queue
            .get("req-idem-ambiguous")
            .await
            .unwrap()
            .unwrap()
            .state,
        OfflineWriteState::Applied
    );
}

// --- fault: outage (log backfill) -----------------------------------------

/// A log outage shorter than the buffer backfills with zero duplicates; one
/// longer than the buffer records `cluster.log_gap` and continues without
/// panicking.
#[tokio::test]
async fn backfill_short_outage_is_duplicate_free_and_long_outage_records_a_gap() {
    let dir = TestDir::new("backfill");
    let ingest = Arc::new(MockIngest::default());
    let master = in_memory_master(
        &dir,
        clock(),
        Arc::new(MasterExecutor::new()),
        ingest.clone(),
    )
    .await;
    let identity = enroll_node(&dir, &master, "node-a").await;
    let node = Arc::new(client(&master, &identity));

    let streamer = |outbox: Arc<MockOutbox>| {
        LogStreamer::new(
            outbox,
            node.clone(),
            LogConfig {
                batch_max_records: 100,
                ..LogConfig::default()
            },
            master.clock.clone(),
        )
    };

    // First flush: sequences 1..=10 reach the master.
    let streamer_a = streamer(Arc::new(MockOutbox::new(1, 10, 1)));
    assert_eq!(
        streamer_a.flush_once().await.unwrap().unwrap().acked_seq,
        10
    );
    assert_eq!(ingest.inserted(), 10);

    // Short outage: the buffer still holds 11..=15, so backfill from the
    // master's highest sequence has no gap and no duplicate rows.
    let short = Arc::new(MockOutbox::new(11, 15, 11));
    let short_streamer = streamer(short.clone());
    let backfill = short_streamer.backfill(10).await.unwrap();
    assert_eq!((backfill.from_seq, backfill.missing), (11, 0));
    assert_eq!(backfill.gap(), None);
    assert_eq!(ingest.inserted(), 15);
    assert_eq!(ingest.duplicates(), 0);

    // A lost ack replays the same rows: the master dedupes, so no new rows.
    short.rewind(11);
    short_streamer.backfill(10).await.unwrap();
    assert_eq!(ingest.inserted(), 15, "replay inserted no new rows");
    assert_eq!(ingest.duplicates(), 5);

    // Long outage: rows 16..=49 were dropped by buffer retention, so backfill
    // resumes at 50 and records the missing range.
    let long = Arc::new(MockOutbox::new(50, 55, 50));
    let long_streamer = streamer(long);
    let backfill = long_streamer.backfill(15).await.unwrap();
    assert_eq!((backfill.from_seq, backfill.missing), (50, 34));
    assert_eq!(
        backfill.gap().unwrap().code(),
        "cluster.log_gap",
        "the over-long outage is reported, not silently skipped"
    );
    assert_eq!(
        ClusterError::LogBufferDropped {
            count: backfill.missing
        }
        .code(),
        "cluster.log_buffer_dropped",
        "the sub-node-side drop count uses its documented code"
    );
    assert_eq!(ingest.gaps(), vec![("node-a".to_owned(), 16, 49)]);
    assert_eq!(ingest.inserted(), 21);
    assert_eq!(backfill.flushed.unwrap().last_seq, 55);

    master.shutdown().await;
}

// --- fault: restart (sub-node queue) --------------------------------------

/// The sub-node's SQLite offline queue survives a process restart and replays
/// every buffered write exactly once through the real mTLS relay.
#[tokio::test]
async fn offline_write_queue_survives_restart_and_replays_exactly_once() {
    let dir = TestDir::new("queue-restart");
    let clock = clock();
    let executor = Arc::new(MasterExecutor::new());
    let master = durable_master(&dir, clock.clone(), executor.clone(), Arc::new(NoLogs)).await;
    let identity = enroll_node(&dir, &master, "node-a").await;

    // Enqueue two writes, then "crash" the sub-node by dropping the queue.
    let node_db = dir.path().join("node.db");
    let store = ClusterStore::open(&node_db, clock.clone(), TOKEN_TTL)
        .await
        .unwrap();
    let queue = OfflineWriteQueue::new(store, queue_config());
    assert!(matches!(
        queue.enqueue(relay("q1")).await.unwrap(),
        EnqueueOutcome::Queued(_)
    ));
    assert!(matches!(
        queue.enqueue(relay("q2")).await.unwrap(),
        EnqueueOutcome::Queued(_)
    ));
    drop(queue);

    // Restart: reopen the same database and replay through the real client.
    let reopened = ClusterStore::open(&node_db, clock.clone(), TOKEN_TTL)
        .await
        .unwrap();
    let queue = OfflineWriteQueue::new(reopened, queue_config());
    assert_eq!(queue.status().await.unwrap().pending, 2);

    let node = Arc::new(client(&master, &identity));
    let outcome = queue
        .replay_all(&ClientExecutor {
            client: node,
            counter: AtomicU64::new(0),
        })
        .await
        .unwrap();

    assert_eq!(outcome.applied, 2);
    assert_eq!(queue.status().await.unwrap().applied, 2);
    assert_eq!(
        executor.applies(),
        2,
        "one master apply per buffered write, none lost or duplicated"
    );
    assert_eq!(
        executor.keys(),
        vec![Some("q1".to_owned()), Some("q2".to_owned())],
        "the original idempotency keys are preserved across the restart"
    );

    master.shutdown().await;
}

// --- fault: restart (master) ----------------------------------------------

/// Restarting the master against the same SQLite database keeps the registry
/// and the node's certificate valid, so sessions resume without re-enrolling.
#[tokio::test]
async fn master_restart_against_the_same_database_resumes() {
    let dir = TestDir::new("master-restart");
    let clock = clock();

    let first = durable_master(
        &dir,
        clock.clone(),
        Arc::new(MasterExecutor::new()),
        Arc::new(NoLogs),
    )
    .await;
    let identity = enroll_node(&dir, &first, "node-a").await;
    let node = client(&first, &identity);
    let mut stream = node.open_stream().await.unwrap();
    let snapshot = json!({ "version": 3 });
    first.server.config_sync().publish(3, &snapshot).unwrap();
    assert_eq!(
        node.apply_next(&mut stream, &RecordingApplier::default())
            .await
            .unwrap(),
        Some(3)
    );
    drop(stream);
    first.shutdown().await;

    // Restart the master on the same CA + SQLite database.
    let executor = Arc::new(MasterExecutor::new());
    let second = durable_master(&dir, clock.clone(), executor.clone(), Arc::new(NoLogs)).await;

    let nodes = second.store.list_nodes().await.unwrap();
    assert_eq!(nodes.len(), 1);
    assert_eq!(nodes[0].node_id, "node-a");
    assert_eq!(nodes[0].applied_config_version, Some(3));
    assert!(!nodes[0].revoked);

    // The persisted identity still authenticates: no new join token, no re-enroll.
    let resumed = ClusterClient::new(&second.url, &identity, clock).unwrap();
    assert!(resumed.heartbeat(Some(3), 0).await.unwrap().ok);
    let response = resumed.relay_write(relay("after-restart")).await.unwrap();
    assert_eq!(response.status, 200);
    assert_eq!(executor.applies(), 1);

    second.shutdown().await;
}

// --- fault: truncate / reorder (log batches) ------------------------------

/// A duplicated log batch is deduped, while a truncated or out-of-order batch
/// is rejected with `cluster.log_stream.invalid` before ingest.
#[tokio::test]
async fn truncated_and_duplicate_log_batches_are_handled() {
    let dir = TestDir::new("log-faults");
    let ingest = Arc::new(MockIngest::default());
    let master = in_memory_master(
        &dir,
        clock(),
        Arc::new(MasterExecutor::new()),
        ingest.clone(),
    )
    .await;
    let identity = enroll_node(&dir, &master, "node-a").await;
    let node = client(&master, &identity);

    let batch = batch_for("node-a", 1);
    assert_eq!(node.post_logs(&batch).await.unwrap(), 1);
    assert_eq!(
        node.post_logs(&batch).await.unwrap(),
        1,
        "duplicate delivery"
    );
    assert_eq!(ingest.inserted(), 1);
    assert_eq!(ingest.duplicates(), 1);

    // Truncated: the range claims two records but only one travelled.
    let mut truncated = batch_for("node-a", 2);
    truncated.last_seq = 3;
    assert_eq!(
        node.post_logs(&truncated).await.unwrap_err().code(),
        "cluster.log_stream.invalid"
    );

    // Out-of-order range never reaches ingest.
    let mut reversed = batch_for("node-a", 3);
    reversed.first_seq = 3;
    reversed.last_seq = 2;
    assert_eq!(
        node.post_logs(&reversed).await.unwrap_err().code(),
        "cluster.log_stream.invalid"
    );

    assert_eq!(
        ingest.calls().len(),
        2,
        "only the two valid duplicate deliveries reached ingest"
    );

    // CL15 wiring: protocol-version handshake failure is covered by
    // `tests/join.rs::enroll_connect_hello_and_heartbeat`; no duplicate test.

    master.shutdown().await;
}
