//! Loopback proof of log streaming: ordered batches with a contiguous ack,
//! idempotent replay after a lost ack, payload `node_id` rejection, reconnect
//! backfill from `last_acked_log_seq`, and gap reporting after a buffer
//! overrun.
//!
//! Real sockets on `127.0.0.1:0`, generated CA/certs via `rcgen`, an injectable
//! [`ManualClock`], mock [`LogOutbox`]/[`LogIngest`] hooks, and no wall-clock
//! waits.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use async_trait::async_trait;
use dnscraft_cluster::{
    ClusterCa, ClusterClient, ClusterError, ClusterServer, ClusterServerConfig, ClusterStore,
    ListenConfig, LogBatch, LogConfig, LogIngest, LogOutbox, LogRecord, LogStreamer, NodeIdentity,
    PendingNodeIdentity, QuotaConfig, RelayResponse, RelayedActor, TlsPaths, WriteExecutor,
};
use dnscraft_common::clock::ManualClock;
use dnscraft_common::secret::Secret;
use serde_json::{Value, json};

const NODE_CERT_TTL: Duration = Duration::from_secs(90 * 24 * 3600);
const TOKEN_TTL: Duration = Duration::from_secs(15 * 60);

/// Write relay is not exercised here.
struct NoWrites;

#[async_trait]
impl WriteExecutor for NoWrites {
    async fn execute(
        &self,
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

/// In-memory outbox whose rows are keyed by `seq`.
struct MockOutbox {
    rows: Mutex<BTreeMap<u64, LogRecord>>,
    next: Mutex<u64>,
    ack_enabled: AtomicBool,
}

impl MockOutbox {
    /// Rows `start..=end`; resuming from `next`.
    fn new(start: u64, end: u64, next: u64) -> Self {
        let rows = (start..=end)
            .map(|seq| {
                let id = format!("r{seq}");
                (
                    seq,
                    LogRecord {
                        id: id.clone(),
                        record: json!({ "id": id, "seq": seq, "secret": "do-not-log" }),
                    },
                )
            })
            .collect();
        Self {
            rows: Mutex::new(rows),
            next: Mutex::new(next),
            ack_enabled: AtomicBool::new(true),
        }
    }

    fn ignore_acks(&self, ignore: bool) {
        self.ack_enabled.store(!ignore, Ordering::SeqCst);
    }

    fn next(&self) -> u64 {
        *self.next.lock().unwrap()
    }
}

#[async_trait]
impl LogOutbox for MockOutbox {
    async fn next_unacked_seq(&self) -> Result<u64, ClusterError> {
        Ok(self.next())
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
        if self.ack_enabled.load(Ordering::SeqCst) {
            let mut next = self.next.lock().unwrap();
            *next = (*next).max(seq.saturating_add(1));
        }
        Ok(())
    }
}

/// Master ingest that dedupes `(node_id, seq)` and `(node_id, record_id)` and
/// records gaps.
#[derive(Default)]
struct MockIngest {
    state: Mutex<IngestState>,
}

#[derive(Default)]
struct IngestState {
    seq_ids: BTreeMap<u64, String>,
    ids: HashSet<String>,
    highest: u64,
    gaps: Vec<(u64, u64)>,
    inserted: usize,
    duplicates: usize,
    calls: Vec<(u64, u64)>,
}

impl MockIngest {
    fn inserted(&self) -> usize {
        self.state.lock().unwrap().inserted
    }

    fn duplicates(&self) -> usize {
        self.state.lock().unwrap().duplicates
    }

    fn highest(&self) -> u64 {
        self.state.lock().unwrap().highest
    }

    fn gaps(&self) -> Vec<(u64, u64)> {
        self.state.lock().unwrap().gaps.clone()
    }

    fn calls(&self) -> Vec<(u64, u64)> {
        self.state.lock().unwrap().calls.clone()
    }
}

#[async_trait]
impl LogIngest for MockIngest {
    async fn ingest(
        &self,
        _node_id: &str,
        first_seq: u64,
        last_seq: u64,
        records: &[LogRecord],
    ) -> Result<u64, ClusterError> {
        let mut state = self.state.lock().unwrap();
        state.calls.push((first_seq, last_seq));

        for (offset, record) in records.iter().enumerate() {
            let seq = first_seq + offset as u64;
            match state.seq_ids.get(&seq) {
                Some(existing) if existing != &record.id => {
                    return Err(ClusterError::LogStreamInvalid {
                        reason: "repeated seq carries a different record".to_owned(),
                    });
                }
                Some(_) => {
                    state.duplicates += 1;
                    continue;
                }
                None if state.ids.contains(&record.id) => {
                    state.duplicates += 1;
                    continue;
                }
                None => {
                    state.seq_ids.insert(seq, record.id.clone());
                    state.ids.insert(record.id.clone());
                    state.inserted += 1;
                }
            }
        }

        let expected = state.highest.saturating_add(1);
        if first_seq > expected {
            state.gaps.push((expected, first_seq - 1));
            // The gap is recorded, so the stream is contiguous again from the
            // batch's end.
            state.highest = state.highest.max(last_seq);
        } else {
            while state.seq_ids.contains_key(&state.highest.saturating_add(1)) {
                state.highest += 1;
            }
        }
        Ok(state.highest)
    }

    async fn highest_seq(&self, _node_id: &str) -> Result<u64, ClusterError> {
        Ok(self.highest())
    }
}

/// A unique, self-cleaning temporary directory.
struct TestDir(PathBuf);

impl TestDir {
    fn new(name: &str) -> Self {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let id = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "dnscraft-cluster-logs-{name}-{}-{id}",
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

async fn start_master(name: &str, ingest: Arc<dyn LogIngest>) -> Master {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let dir = TestDir::new(name);
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
        ingest,
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

async fn client_for(master: &Master, node_id: &str) -> Arc<ClusterClient> {
    let identity = enroll_node(master, node_id).await;
    Arc::new(ClusterClient::new(&master.url, &identity, master.clock.clone()).unwrap())
}

fn streamer(
    outbox: Arc<MockOutbox>,
    client: Arc<ClusterClient>,
    clock: Arc<ManualClock>,
    batch_max_records: u32,
) -> LogStreamer {
    LogStreamer::new(
        outbox,
        client,
        LogConfig {
            batch_max_records,
            ..LogConfig::default()
        },
        clock,
    )
}

#[tokio::test]
async fn ordered_streaming_acks_the_highest_contiguous_seq() {
    let ingest = Arc::new(MockIngest::default());
    let master = start_master("ordered", Arc::clone(&ingest) as Arc<dyn LogIngest>).await;
    let client = client_for(&master, "node-a").await;
    let outbox = Arc::new(MockOutbox::new(1, 10, 1));
    let streamer = streamer(
        Arc::clone(&outbox),
        Arc::clone(&client),
        master.clock.clone(),
        4,
    );

    let first = streamer.flush_once().await.unwrap().unwrap();
    assert_eq!(
        (
            first.first_seq,
            first.last_seq,
            first.acked_seq,
            first.records
        ),
        (1, 4, 4, 4)
    );
    assert_eq!(outbox.next(), 5);

    let second = streamer.flush_once().await.unwrap().unwrap();
    assert_eq!(
        (
            second.first_seq,
            second.last_seq,
            second.acked_seq,
            second.records
        ),
        (5, 8, 8, 4)
    );

    let third = streamer.flush_once().await.unwrap().unwrap();
    assert_eq!(
        (
            third.first_seq,
            third.last_seq,
            third.acked_seq,
            third.records
        ),
        (9, 10, 10, 2)
    );
    assert!(!third.full);

    assert!(streamer.flush_once().await.unwrap().is_none());
    assert_eq!(ingest.calls(), vec![(1, 4), (5, 8), (9, 10)]);
    assert_eq!(ingest.highest(), 10);
    assert_eq!(ingest.inserted(), 10);
    assert_eq!(ingest.duplicates(), 0);

    master.server.shutdown().await;
}

#[tokio::test]
async fn lost_ack_replays_with_zero_duplicate_rows() {
    let ingest = Arc::new(MockIngest::default());
    let master = start_master("lost-ack", Arc::clone(&ingest) as Arc<dyn LogIngest>).await;
    let client = client_for(&master, "node-a").await;
    let outbox = Arc::new(MockOutbox::new(1, 4, 1));
    let streamer = streamer(
        Arc::clone(&outbox),
        Arc::clone(&client),
        master.clock.clone(),
        10,
    );

    // The master ingested the batch but the ack never reached the sub-node.
    outbox.ignore_acks(true);
    let sent = streamer.flush_once().await.unwrap().unwrap();
    assert_eq!(sent.acked_seq, 4);
    assert_eq!(outbox.next(), 1);
    assert_eq!(ingest.inserted(), 4);

    // Replay after the lost ack: the ingest dedupes both keys.
    outbox.ignore_acks(false);
    let replay = streamer.flush_once().await.unwrap().unwrap();
    assert_eq!(
        (replay.first_seq, replay.last_seq, replay.acked_seq),
        (1, 4, 4)
    );
    assert_eq!(outbox.next(), 5);
    assert_eq!(ingest.inserted(), 4);
    assert_eq!(ingest.duplicates(), 4);
    assert_eq!(ingest.highest(), 4);

    master.server.shutdown().await;
}

#[tokio::test]
async fn payload_node_id_mismatch_is_rejected() {
    let ingest = Arc::new(MockIngest::default());
    let master = start_master("mismatch", Arc::clone(&ingest) as Arc<dyn LogIngest>).await;
    let client = client_for(&master, "node-a").await;

    let batch = LogBatch {
        protocol: dnscraft_cluster::PROTOCOL_VERSION,
        node_id: "node-b".to_owned(),
        first_seq: 1,
        last_seq: 1,
        records: vec![LogRecord {
            id: "r1".to_owned(),
            record: json!({ "id": "r1" }),
        }],
    };
    let error = client.post_logs(&batch).await.unwrap_err();
    assert_eq!(error.code(), "cluster.log_stream.invalid");
    assert!(ingest.calls().is_empty());

    master.server.shutdown().await;
}

#[tokio::test]
async fn backfill_resumes_from_the_master_highest_seq() {
    let ingest = Arc::new(MockIngest::default());
    let master = start_master("backfill", Arc::clone(&ingest) as Arc<dyn LogIngest>).await;
    let client = client_for(&master, "node-a").await;

    // The master already has 1..=5; the node's ack cursor is still at 1.
    let seed = MockOutbox::new(1, 5, 1);
    let seed_records = seed.fetch_batch(1, 10).await.unwrap();
    ingest.ingest("node-a", 1, 5, &seed_records).await.unwrap();

    let stream = client.open_stream().await.unwrap();
    assert_eq!(stream.master_highest_log_seq(), Some(5));

    let outbox = Arc::new(MockOutbox::new(1, 10, 1));
    let streamer = streamer(
        Arc::clone(&outbox),
        Arc::clone(&client),
        master.clock.clone(),
        10,
    );
    let backfill = streamer.backfill(5).await.unwrap();
    assert_eq!(backfill.from_seq, 6);
    assert_eq!(backfill.missing, 0);
    assert_eq!(backfill.gap(), None);
    let flushed = backfill.flushed.unwrap();
    assert_eq!((flushed.first_seq, flushed.last_seq), (6, 10));
    assert_eq!(outbox.next(), 11);
    assert_eq!(ingest.highest(), 10);

    drop(stream);
    master.server.shutdown().await;
}

#[tokio::test]
async fn over_long_outage_reports_a_gap_and_continues() {
    let ingest = Arc::new(MockIngest::default());
    let master = start_master("gap", Arc::clone(&ingest) as Arc<dyn LogIngest>).await;
    let client = client_for(&master, "node-a").await;

    // The master has 1..=10, but retention dropped the node's buffer up to 49.
    let seed = MockOutbox::new(1, 10, 1);
    let seed_records = seed.fetch_batch(1, 10).await.unwrap();
    ingest.ingest("node-a", 1, 10, &seed_records).await.unwrap();

    let stream = client.open_stream().await.unwrap();
    assert_eq!(stream.master_highest_log_seq(), Some(10));

    let outbox = Arc::new(MockOutbox::new(50, 60, 50));
    let streamer = streamer(
        Arc::clone(&outbox),
        Arc::clone(&client),
        master.clock.clone(),
        500,
    );
    let backfill = streamer.backfill(10).await.unwrap();
    assert_eq!(backfill.from_seq, 50);
    assert_eq!(backfill.missing, 39);
    assert_eq!(backfill.gap(), Some(ClusterError::LogGap { missing: 39 }));

    let flushed = backfill.flushed.unwrap();
    assert_eq!((flushed.first_seq, flushed.last_seq), (50, 60));
    assert_eq!(outbox.next(), 61);
    assert_eq!(ingest.gaps(), vec![(11, 49)]);
    // 10 seeded rows + the 11 rows after the recorded gap.
    assert_eq!(ingest.inserted(), 21);
    assert_eq!(ingest.highest(), 60);

    drop(stream);
    master.server.shutdown().await;
}
