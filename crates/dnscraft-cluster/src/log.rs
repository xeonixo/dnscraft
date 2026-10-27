//! Sub-node → master query-log streaming and backfill.
//!
//! A sub-node batches contiguous unacked rows from its local outbox
//! ([`LogOutbox`]) and `POST`s them to `/cluster/v1/logs` as a [`LogBatch`].
//! The master validates the envelope, hands the records to its ingest hook
//! ([`LogIngest`]), and answers with the highest **contiguous** [`LogAck`].
//! Replayed batches are safe because the ingest deduplicates
//! `(node_id, record_id)` and `(node_id, seq)`.
//!
//! Log records are opaque: the crate carries [`LogRecord::record`] as
//! [`serde_json::Value`] and never inspects, logs, or formats it. Both traits
//! are supplied by the caller, keeping this crate independent of control-api.
//!
//! After a reconnect the sub-node calls [`LogStreamer::backfill`] with the
//! master's `highest_seq`, read from the stream `hello`
//! ([`crate::ClusterStream::master_highest_log_seq`]). If the local buffer has
//! already dropped rows below that point, [`Backfill::gap`] reports
//! `cluster.log_gap` and streaming continues from the oldest buffered row.

use std::fmt;
use std::sync::Arc;

use dnscraft_common::clock::{Clock, add_duration, wait_until};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::sync::Notify;

use crate::PROTOCOL_VERSION;
use crate::client::ClusterClient;
use crate::config::LogConfig;
use crate::error::ClusterError;

/// One query-log row carried by a batch.
///
/// `record` is opaque; its `Debug` representation is redacted. `id` is the
/// stable record id the master's ingest uses for `(node_id, record_id)`
/// deduplication.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct LogRecord {
    /// Stable record id (query-log row id).
    pub id: String,
    /// Opaque query-log document, never inspected by this crate.
    pub record: Value,
}

impl fmt::Debug for LogRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LogRecord")
            .field("id", &self.id)
            .field("record", &"<opaque>")
            .finish()
    }
}

/// `POST /cluster/v1/logs` request body.
///
/// `record` ordering is ascending and contiguous from `first_seq` through
/// `last_seq`; the master rejects anything else as
/// `cluster.log_stream.invalid`. `node_id` must match the authenticated
/// certificate; the master never trusts it.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct LogBatch {
    /// Cluster protocol version; must equal [`PROTOCOL_VERSION`].
    pub protocol: u32,
    /// Sender's `node_id`; rejected when it differs from the certificate.
    pub node_id: String,
    /// Sequence of the first record (1-based).
    pub first_seq: u64,
    /// Sequence of the last record.
    pub last_seq: u64,
    /// Records in ascending `seq` order.
    pub records: Vec<LogRecord>,
}

impl fmt::Debug for LogBatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LogBatch")
            .field("protocol", &self.protocol)
            .field("node_id", &self.node_id)
            .field("first_seq", &self.first_seq)
            .field("last_seq", &self.last_seq)
            .field("records", &format_args!("<{} opaque>", self.records.len()))
            .finish()
    }
}

impl LogBatch {
    /// Validates the envelope against the authenticated certificate identity.
    ///
    /// Rejects a protocol mismatch ([`ClusterError::ProtocolVersion`]), a
    /// payload `node_id` that differs from `authenticated_node`, an empty
    /// record list, a zero `first_seq`, and a `first_seq`/`last_seq` range
    /// whose length does not equal the record count (all
    /// `cluster.log_stream.invalid`).
    pub fn validate(&self, authenticated_node: &str) -> Result<(), ClusterError> {
        if self.protocol != PROTOCOL_VERSION {
            return Err(ClusterError::ProtocolVersion);
        }
        if self.node_id != authenticated_node {
            return Err(invalid(
                "payload node_id does not match the authenticated certificate",
            ));
        }
        if self.records.is_empty() {
            return Err(invalid("a log batch must contain at least one record"));
        }
        if self.first_seq == 0 {
            return Err(invalid("log sequence numbers start at 1"));
        }
        let span = self
            .last_seq
            .checked_sub(self.first_seq)
            .and_then(|span| span.checked_add(1));
        if span != Some(self.records.len() as u64) {
            return Err(invalid("first_seq/last_seq do not match the record count"));
        }
        Ok(())
    }
}

/// `POST /cluster/v1/logs` response body.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogAck {
    /// Highest contiguous `seq` the master has stored for the node (`0` when
    /// it has none).
    pub acked_seq: u64,
}

/// Sub-node outbox hook (wired to the query-log store's `seq`/ack cursor).
///
/// The implementation owns durability: [`LogOutbox::ack`] must persist the
/// cursor so a restart resumes from the last acknowledged sequence.
#[async_trait::async_trait]
pub trait LogOutbox: Send + Sync {
    /// Next sequence to send: the highest acknowledged `seq` + 1, advanced
    /// past any rows the buffer dropped under `buffer_retention` (so a gap can
    /// be reported rather than retried forever).
    async fn next_unacked_seq(&self) -> Result<u64, ClusterError>;

    /// Returns up to `max_records` contiguous rows starting at `from_seq`, in
    /// ascending order. Returns fewer (possibly none) when the buffer has no
    /// more rows or the oldest buffered row is already newer than `from_seq`.
    async fn fetch_batch(
        &self,
        from_seq: u64,
        max_records: usize,
    ) -> Result<Vec<LogRecord>, ClusterError>;

    /// Marks every `seq` up to and including `seq` as acknowledged.
    async fn ack(&self, seq: u64) -> Result<(), ClusterError>;
}

/// Master ingest hook.
///
/// Implementations preserve the originating time and `node_id`, insert with
/// `ON CONFLICT DO NOTHING` on both `(node_id, record_id)` and
/// `(node_id, seq)`, and count duplicates without erroring. A repeated `seq`
/// carrying a different record id must return
/// [`ClusterError::LogStreamInvalid`].
#[async_trait::async_trait]
pub trait LogIngest: Send + Sync {
    /// Ingests one contiguous batch and returns the highest contiguous `seq`
    /// now stored for `node_id` (`0` when none).
    ///
    /// When `first_seq` is beyond the expected sequence the implementation
    /// records the missing range (`cluster.log_gap`, bounded by buffer
    /// retention) and continues.
    async fn ingest(
        &self,
        node_id: &str,
        first_seq: u64,
        last_seq: u64,
        records: &[LogRecord],
    ) -> Result<u64, ClusterError>;

    /// Highest contiguous `seq` stored for `node_id`, or `0`.
    async fn highest_seq(&self, node_id: &str) -> Result<u64, ClusterError>;
}

/// What one successful flush sent and acknowledged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FlushOutcome {
    /// First sequence in the batch.
    pub first_seq: u64,
    /// Last sequence in the batch.
    pub last_seq: u64,
    /// Highest contiguous sequence acknowledged by the master.
    pub acked_seq: u64,
    /// Number of records in the batch.
    pub records: usize,
    /// Whether the outbox returned a full batch (more rows may be ready).
    pub full: bool,
}

/// Result of a reconnect backfill.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Backfill {
    /// Sequence the sub-node resumed from (`max(oldest buffered,
    /// master_highest + 1)`).
    pub from_seq: u64,
    /// Number of sequences lost to buffer retention (`0` when none).
    pub missing: u64,
    /// The batch sent, if any rows were still buffered.
    pub flushed: Option<FlushOutcome>,
}

impl Backfill {
    /// `cluster.log_gap` for the lost range, when `missing > 0`.
    pub fn gap(&self) -> Option<ClusterError> {
        (self.missing > 0).then_some(ClusterError::LogGap {
            missing: self.missing,
        })
    }
}

/// Batches a sub-node's unacked log rows and posts them to the master.
///
/// Sends one batch at a time: that is within `max_inflight_batches` and keeps
/// per-node ordering strict. `max_batch_bytes` is enforced by trimming the
/// batch (at least one record is always sent so a large row cannot stall the
/// stream).
pub struct LogStreamer {
    outbox: Arc<dyn LogOutbox>,
    client: Arc<ClusterClient>,
    config: LogConfig,
    clock: Arc<dyn Clock>,
}

impl LogStreamer {
    /// Creates a streamer over the node's outbox and mTLS client.
    pub fn new(
        outbox: Arc<dyn LogOutbox>,
        client: Arc<ClusterClient>,
        config: LogConfig,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            outbox,
            client,
            config,
            clock,
        }
    }

    /// Sends the next batch from the local outbox, if any rows are waiting.
    pub async fn flush_once(&self) -> Result<Option<FlushOutcome>, ClusterError> {
        let from_seq = self.outbox.next_unacked_seq().await?;
        self.flush_from(from_seq).await
    }

    /// Sends one batch starting at `from_seq`.
    ///
    /// Acks the master's contiguous sequence locally so the next flush resumes
    /// after it. Returns `None` when the outbox has nothing to send.
    pub async fn flush_from(&self, from_seq: u64) -> Result<Option<FlushOutcome>, ClusterError> {
        if from_seq == 0 {
            return Err(invalid("log sequence numbers start at 1"));
        }
        let max_records =
            usize::try_from(self.config.batch_max_records.max(1)).unwrap_or(usize::MAX);
        let mut records = self.outbox.fetch_batch(from_seq, max_records).await?;
        if records.is_empty() {
            return Ok(None);
        }
        records.truncate(max_records);
        let records = self.fit_to_bytes(from_seq, records);
        let full = records.len() >= max_records;
        let count = records.len() as u64;
        let last_seq = from_seq
            .checked_add(count - 1)
            .ok_or_else(|| invalid("log sequence number overflow"))?;
        let batch = LogBatch {
            protocol: PROTOCOL_VERSION,
            node_id: self.client.node_id().to_owned(),
            first_seq: from_seq,
            last_seq,
            records,
        };
        let acked_seq = self.client.post_logs(&batch).await?;
        if acked_seq >= from_seq {
            self.outbox.ack(acked_seq).await?;
        }
        Ok(Some(FlushOutcome {
            first_seq: from_seq,
            last_seq,
            acked_seq,
            records: usize::try_from(count).unwrap_or(usize::MAX),
            full,
        }))
    }

    /// Resumes after a reconnect from the master's highest stored sequence.
    ///
    /// Unlike [`flush_once`](Self::flush_once) this also detects a buffer
    /// overrun: if the local outbox has already dropped rows the master lacks,
    /// the loss is reported ([`Backfill::gap`]) and sending resumes from the
    /// oldest buffered row. The returned [`LogGap`](ClusterError::LogGap)
    /// count is bounded by `buffer_retention`.
    pub async fn backfill(&self, master_highest: u64) -> Result<Backfill, ClusterError> {
        let local = self.outbox.next_unacked_seq().await?;
        let want = master_highest.saturating_add(1);
        let from_seq = local.max(want);
        let missing = from_seq.saturating_sub(want);
        let flushed = self.flush_from(from_seq).await?;
        Ok(Backfill {
            from_seq,
            missing,
            flushed,
        })
    }

    /// Streams until `shutdown` fires.
    ///
    /// A full batch is sent immediately; otherwise the loop waits
    /// `batch_interval` (injectable clock, no wall-clock sleeps). Errors are
    /// returned so the caller can reconnect and [`backfill`](Self::backfill).
    pub async fn run(&self, shutdown: &Notify) -> Result<(), ClusterError> {
        loop {
            if let Some(outcome) = self.flush_once().await?
                && outcome.full
            {
                continue;
            }
            let deadline = add_duration(self.clock.now(), self.config.batch_interval);
            tokio::select! {
                () = wait_until(self.clock.as_ref(), deadline, shutdown) => {}
                () = shutdown.notified() => return Ok(()),
            }
        }
    }

    /// Trims `records` so the serialized batch fits `max_batch_bytes`.
    ///
    /// At least one record is kept: a single oversized row must still make
    /// progress or the outbox head would never drain.
    fn fit_to_bytes(&self, first_seq: u64, mut records: Vec<LogRecord>) -> Vec<LogRecord> {
        let max_bytes = self.config.max_batch_bytes.max(1);
        let mut total = serde_json::to_vec(&LogBatch {
            protocol: PROTOCOL_VERSION,
            node_id: self.client.node_id().to_owned(),
            first_seq,
            last_seq: first_seq,
            records: Vec::new(),
        })
        .map_or(0, |bytes| bytes.len() as u64);
        let mut keep = 0;
        for record in &records {
            let size = serde_json::to_vec(record).map_or(0, |bytes| bytes.len() as u64) + 1;
            if keep > 0 && total.saturating_add(size) > max_bytes {
                break;
            }
            total = total.saturating_add(size);
            keep += 1;
        }
        records.truncate(keep.max(1));
        // `last_seq` may use more digits than `first_seq`; trim exactly.
        while records.len() > 1 {
            let last_seq = first_seq.saturating_add(records.len() as u64 - 1);
            let size = serde_json::to_vec(&LogBatch {
                protocol: PROTOCOL_VERSION,
                node_id: self.client.node_id().to_owned(),
                first_seq,
                last_seq,
                records: records.clone(),
            })
            .map_or(0, |bytes| bytes.len() as u64);
            if size <= max_bytes {
                break;
            }
            records.pop();
        }
        records
    }
}

fn invalid(reason: &str) -> ClusterError {
    ClusterError::LogStreamInvalid {
        reason: reason.to_owned(),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use serde_json::json;

    fn record(id: &str) -> LogRecord {
        LogRecord {
            id: id.to_owned(),
            record: json!({ "id": id, "secret": "do-not-log" }),
        }
    }

    fn batch(node_id: &str, first_seq: u64, last_seq: u64) -> LogBatch {
        LogBatch {
            protocol: PROTOCOL_VERSION,
            node_id: node_id.to_owned(),
            first_seq,
            last_seq,
            records: (first_seq..=last_seq)
                .map(|seq| record(&format!("r{seq}")))
                .collect(),
        }
    }

    #[test]
    fn debug_never_prints_records() {
        let batch = batch("node-a", 1, 2);
        let rendered = format!("{batch:?}");
        assert!(!rendered.contains("do-not-log"));
        assert!(rendered.contains("<2 opaque>"));

        let rendered = format!("{:?}", batch.records[0]);
        assert!(!rendered.contains("do-not-log"));
        assert!(rendered.contains("<opaque>"));
    }

    #[test]
    fn validate_rejects_wrong_node_and_ragged_range() {
        assert_eq!(
            batch("node-b", 1, 2).validate("node-a").unwrap_err().code(),
            "cluster.log_stream.invalid"
        );

        let mut ragged = batch("node-a", 1, 2);
        ragged.last_seq = 3;
        assert_eq!(
            ragged.validate("node-a").unwrap_err().code(),
            "cluster.log_stream.invalid"
        );

        assert!(batch("node-a", 1, 2).validate("node-a").is_ok());
    }

    #[test]
    fn validate_rejects_empty_and_zero_start() {
        let mut empty = batch("node-a", 1, 1);
        empty.records.clear();
        empty.last_seq = 0;
        assert_eq!(
            empty.validate("node-a").unwrap_err().code(),
            "cluster.log_stream.invalid"
        );

        let mut zero = batch("node-a", 1, 1);
        zero.first_seq = 0;
        assert_eq!(
            zero.validate("node-a").unwrap_err().code(),
            "cluster.log_stream.invalid"
        );
    }
}
