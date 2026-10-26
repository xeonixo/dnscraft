//! Shared length-prefixed query loop for Do53 TCP and DoT (RFC 7766).
//!
//! Reader task + per-connection permits + drain on EOF/idle + write deadline.
//! Callers own accept / TLS; this module only runs the framed session.

use std::net::IpAddr;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, SystemTime};

use dnscraft_policy::{ClientId, DnsProtocol};
use dnscraft_proto::{EdnsOption, Message, Rcode};
use tokio::io::{AsyncRead, AsyncWrite, BufReader, split};
use tokio::sync::{Notify, OwnedSemaphorePermit, Semaphore, mpsc, watch};
use tokio::task::JoinSet;

use crate::admission::{Admission, AdmitDecision, ClientIdState};
use crate::clock::{Clock, wait_until};
use crate::config::{Limits, ListenerConfig};
use crate::core::{QueryMeta, error_reply_from_wire, handle_wire};
use crate::framing::{self, FrameError, MAX_MESSAGE_LEN};
use crate::handler::QueryHandler;

/// EDNS option code for TCP keepalive (RFC 7828).
pub const OPTION_TCP_KEEPALIVE: u16 = 11;

/// Counters for one framed (TCP / DoT) listener.
#[derive(Debug, Default)]
pub struct FramedStats {
    /// Accepted connections that entered the query loop.
    pub accepted: AtomicU64,
    /// Connections closed (any reason).
    pub closed: AtomicU64,
    /// Rejected because the peer was a public source on Do53.
    pub dropped_public: AtomicU64,
    /// Rejected by admission Drop (e.g. ban).
    pub dropped_admission: AtomicU64,
    /// Per-query REFUSED answers (rate limit).
    pub refused: AtomicU64,
    /// Rejected because `max_connections_per_listener` was full.
    pub rejected_conn_cap: AtomicU64,
    /// Rejected because `max_connections_per_source` was full.
    pub rejected_per_source: AtomicU64,
    /// Queries admitted into `handle_wire`.
    pub queries: AtomicU64,
    /// Answers written to the peer.
    pub answered: AtomicU64,
    /// Framing errors (bad length / short read after length).
    pub framing_errors: AtomicU64,
    /// Idle-timeout closes (RFC 7766 §6.2.3: no outstanding queries).
    pub idle_timeouts: AtomicU64,
    /// Writer write-deadline timeouts (`tcp_idle_timeout`).
    pub write_timeouts: AtomicU64,
}

impl FramedStats {
    pub(crate) fn bump(field: &AtomicU64) {
        field.fetch_add(1, Ordering::Relaxed);
    }
}

/// Shared state for one framed listener (accept loop + connections).
pub(crate) struct FramedShared<H: ?Sized> {
    pub listener: ListenerConfig,
    pub limits: Limits,
    pub handler: Arc<H>,
    pub admission: Mutex<Admission>,
    pub clock: Arc<dyn Clock>,
    pub stats: Arc<FramedStats>,
    pub conn_cap: Arc<Semaphore>,
    pub per_source: Mutex<std::collections::HashMap<IpAddr, u32>>,
}

/// Per-connection transport metadata (protocol, padding, Client ID from SNI).
#[derive(Clone, Debug)]
pub(crate) struct ConnIdentity {
    pub protocol: DnsProtocol,
    pub pad: bool,
    pub client_id: ClientIdState,
}

impl ConnIdentity {
    fn meta_client_id(&self) -> Option<ClientId> {
        match &self.client_id {
            ClientIdState::Registered(id) => Some(id.clone()),
            ClientIdState::Absent | ClientIdState::Unknown => None,
        }
    }
}

pub(crate) enum ConnEnd {
    Framing,
    Idle,
    Banned,
    WriteTimeout,
    Peer,
    Io,
}

impl ConnEnd {
    fn abort_queries(&self) -> bool {
        matches!(
            self,
            ConnEnd::Banned | ConnEnd::Framing | ConnEnd::WriteTimeout | ConnEnd::Io
        )
    }

    pub(crate) fn bump_stats(&self, stats: &FramedStats) {
        match self {
            ConnEnd::Framing => FramedStats::bump(&stats.framing_errors),
            ConnEnd::Idle => FramedStats::bump(&stats.idle_timeouts),
            ConnEnd::Banned => FramedStats::bump(&stats.dropped_admission),
            ConnEnd::WriteTimeout => FramedStats::bump(&stats.write_timeouts),
            ConnEnd::Peer | ConnEnd::Io => {}
        }
    }
}

struct Outstanding {
    count: AtomicUsize,
    drained: Notify,
}

impl Outstanding {
    fn new() -> Self {
        Self {
            count: AtomicUsize::new(0),
            drained: Notify::new(),
        }
    }

    fn get(&self) -> usize {
        self.count.load(Ordering::Acquire)
    }

    fn acquire(&self) {
        self.count.fetch_add(1, Ordering::AcqRel);
    }

    fn release(&self) {
        let prev = self.count.fetch_sub(1, Ordering::AcqRel);
        debug_assert!(prev >= 1, "outstanding underflow");
        if prev == 1 {
            self.drained.notify_waiters();
        }
    }
}

struct OutstandingGuard(Arc<Outstanding>);

impl Drop for OutstandingGuard {
    fn drop(&mut self) {
        self.0.release();
    }
}

enum ReaderEvent {
    Frame {
        datagram: Vec<u8>,
        permit: OwnedSemaphorePermit,
    },
    End(ConnEnd),
}

/// Runs the framed query loop on an already-accepted (and possibly TLS-wrapped) stream.
pub(crate) async fn run_framed_connection<H, S>(
    shared: Arc<FramedShared<H>>,
    stream: S,
    peer: std::net::SocketAddr,
    identity: ConnIdentity,
) -> Result<(), ConnEnd>
where
    H: QueryHandler + 'static,
    S: AsyncRead + AsyncWrite + Send + 'static,
{
    let (reader, writer) = split(stream);
    let reader = BufReader::new(reader);
    let (answer_tx, answer_rx) = mpsc::channel::<Vec<u8>>(64);
    let (cancel_tx, mut cancel_rx) = watch::channel(false);
    let slot_cap = shared.limits.max_queries_per_connection.max(1) as usize;
    let query_slots = Arc::new(Semaphore::new(slot_cap));
    let outstanding = Arc::new(Outstanding::new());
    let mut queries: JoinSet<()> = JoinSet::new();

    let (frame_tx, mut frame_rx) = mpsc::channel::<ReaderEvent>(8);
    let reader_slots = Arc::clone(&query_slots);
    let reader_task = tokio::spawn(async move {
        reader_loop(reader, reader_slots, frame_tx).await;
    });

    let write_stats = Arc::clone(&shared.stats);
    let write_clock = Arc::clone(&shared.clock);
    let write_idle = shared.limits.tcp_idle_timeout;
    let write_task = tokio::spawn(async move {
        writer_loop(
            writer,
            answer_rx,
            write_clock,
            write_idle,
            write_stats,
            cancel_tx,
        )
        .await
    });

    let idle = shared.limits.tcp_idle_timeout;
    let mut idle_deadline: Option<SystemTime> = Some(add_duration(shared.clock.now(), idle));
    let identity = Arc::new(identity);

    let result = loop {
        if *cancel_rx.borrow() {
            break Err(ConnEnd::WriteTimeout);
        }

        let no_outstanding = outstanding.get() == 0;
        if !no_outstanding {
            idle_deadline = None;
        } else if idle_deadline.is_none() {
            idle_deadline = Some(add_duration(shared.clock.now(), idle));
        }

        tokio::select! {
            biased;
            changed = cancel_rx.changed() => {
                if changed.is_err() || *cancel_rx.borrow() {
                    break Err(ConnEnd::WriteTimeout);
                }
            }
            () = wait_idle_or_drain(
                shared.clock.as_ref(),
                idle_deadline,
                &outstanding,
            ) => {
                if outstanding.get() == 0 {
                    if let Some(deadline) = idle_deadline
                        && shared.clock.now() >= deadline
                    {
                        break Err(ConnEnd::Idle);
                    }
                    idle_deadline = Some(add_duration(shared.clock.now(), idle));
                }
            }
            ev = frame_rx.recv() => {
                match ev {
                    None => break Err(ConnEnd::Io),
                    Some(ReaderEvent::End(e)) => break Err(e),
                    Some(ReaderEvent::Frame { datagram, permit }) => {
                        match dispatch_frame(
                            &shared,
                            peer.ip(),
                            datagram,
                            permit,
                            &answer_tx,
                            &mut queries,
                            &outstanding,
                            &identity,
                        )
                        .await
                        {
                            Ok(()) => {
                                if outstanding.get() == 0 {
                                    idle_deadline =
                                        Some(add_duration(shared.clock.now(), idle));
                                } else {
                                    idle_deadline = None;
                                }
                            }
                            Err(e) => break Err(e),
                        }
                    }
                }
            }
        }
    };

    reader_task.abort();
    let _ = reader_task.await;

    let abort = result.as_ref().err().is_some_and(|e| e.abort_queries());
    drop(answer_tx);
    if abort {
        queries.abort_all();
    }
    while queries.join_next().await.is_some() {}
    let writer_end = write_task.await;
    match result {
        Err(ConnEnd::Peer) | Err(ConnEnd::Idle) => match writer_end {
            Ok(WriterEnd::Timeout) => Err(ConnEnd::WriteTimeout),
            Ok(WriterEnd::Io) => Err(ConnEnd::Io),
            _ => result,
        },
        other => {
            let _ = writer_end;
            other
        }
    }
}

async fn wait_idle_or_drain(
    clock: &dyn Clock,
    idle_deadline: Option<SystemTime>,
    outstanding: &Outstanding,
) {
    if outstanding.get() == 0 {
        if let Some(deadline) = idle_deadline {
            wait_until(clock, deadline, &outstanding.drained).await;
        } else {
            std::future::pending::<()>().await;
        }
        return;
    }
    loop {
        let notified = outstanding.drained.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();
        if outstanding.get() == 0 {
            return;
        }
        notified.await;
        if outstanding.get() == 0 {
            return;
        }
    }
}

async fn reader_loop<R: AsyncRead + Unpin>(
    mut reader: R,
    query_slots: Arc<Semaphore>,
    frame_tx: mpsc::Sender<ReaderEvent>,
) {
    loop {
        let permit = match query_slots.clone().acquire_owned().await {
            Ok(p) => p,
            Err(_) => {
                let _ = frame_tx.send(ReaderEvent::End(ConnEnd::Io)).await;
                return;
            }
        };
        match framing::read_frame(&mut reader).await {
            Ok(datagram) => {
                if frame_tx
                    .send(ReaderEvent::Frame { datagram, permit })
                    .await
                    .is_err()
                {
                    return;
                }
            }
            Err(FrameError::UnexpectedEof) => {
                drop(permit);
                let _ = frame_tx.send(ReaderEvent::End(ConnEnd::Peer)).await;
                return;
            }
            Err(FrameError::InvalidLength(_)) => {
                drop(permit);
                let _ = frame_tx.send(ReaderEvent::End(ConnEnd::Framing)).await;
                return;
            }
            Err(FrameError::Io(_)) => {
                drop(permit);
                let _ = frame_tx.send(ReaderEvent::End(ConnEnd::Io)).await;
                return;
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn dispatch_frame<H>(
    shared: &Arc<FramedShared<H>>,
    peer_ip: IpAddr,
    datagram: Vec<u8>,
    permit: OwnedSemaphorePermit,
    tx: &mpsc::Sender<Vec<u8>>,
    queries: &mut JoinSet<()>,
    outstanding: &Arc<Outstanding>,
    identity: &Arc<ConnIdentity>,
) -> Result<(), ConnEnd>
where
    H: QueryHandler + 'static,
{
    let now = shared.clock.now();
    let decision = {
        let mut adm = shared
            .admission
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        adm.check(&shared.listener, peer_ip, &identity.client_id, now)
    };

    match decision {
        AdmitDecision::Drop { .. } => {
            drop(permit);
            Err(ConnEnd::Banned)
        }
        AdmitDecision::Refuse { .. } => {
            FramedStats::bump(&shared.stats.refused);
            if let Some(bytes) = error_reply_from_wire(
                &datagram,
                Rcode::REFUSED,
                MAX_MESSAGE_LEN,
                shared.limits.udp_payload_max,
            ) {
                let _ = tx.send(bytes).await;
            }
            drop(permit);
            Ok(())
        }
        AdmitDecision::Admit => {
            FramedStats::bump(&shared.stats.queries);
            outstanding.acquire();
            let shared = Arc::clone(shared);
            let tx = tx.clone();
            let outstanding = Arc::clone(outstanding);
            let identity = Arc::clone(identity);
            queries.spawn(async move {
                let _permit = permit;
                let _guard = OutstandingGuard(outstanding);
                if let Some(bytes) = process_query(&shared, peer_ip, datagram, &identity).await {
                    let _ = tx.send(bytes).await;
                }
            });
            Ok(())
        }
    }
}

enum WriterEnd {
    Done,
    Timeout,
    Io,
}

async fn writer_loop<W: AsyncWrite + Unpin>(
    mut writer: W,
    mut rx: mpsc::Receiver<Vec<u8>>,
    clock: Arc<dyn Clock>,
    idle: Duration,
    stats: Arc<FramedStats>,
    cancel: watch::Sender<bool>,
) -> WriterEnd {
    while let Some(msg) = rx.recv().await {
        let deadline = add_duration(clock.now(), idle);
        let wake = Notify::new();
        let outcome = tokio::select! {
            r = framing::write_frame(&mut writer, &msg) => {
                match r {
                    Ok(()) => {
                        FramedStats::bump(&stats.answered);
                        None
                    }
                    Err(_) => Some(WriterEnd::Io),
                }
            }
            () = wait_until(clock.as_ref(), deadline, &wake) => Some(WriterEnd::Timeout),
        };
        if let Some(end) = outcome {
            let _ = cancel.send(true);
            return end;
        }
    }
    WriterEnd::Done
}

async fn process_query<H>(
    shared: &FramedShared<H>,
    peer_ip: IpAddr,
    datagram: Vec<u8>,
    identity: &ConnIdentity,
) -> Option<Vec<u8>>
where
    H: QueryHandler,
{
    let want_keepalive = client_requested_keepalive(&datagram);
    let meta = QueryMeta {
        protocol: identity.protocol,
        listener_id: shared.listener.id.clone(),
        source: peer_ip,
        client_id: identity.meta_client_id(),
        size_limit: MAX_MESSAGE_LEN,
        pad: identity.pad,
        udp_payload_max: shared.limits.udp_payload_max,
    };
    let deadline = add_duration(shared.clock.now(), shared.limits.query_timeout);
    let wake = Notify::new();
    let out = tokio::select! {
        r = handle_wire(&datagram, meta, &*shared.handler) => r,
        () = wait_until(shared.clock.as_ref(), deadline, &wake) => {
            return error_reply_from_wire(
                &datagram,
                Rcode::SERVFAIL,
                MAX_MESSAGE_LEN,
                shared.limits.udp_payload_max,
            );
        }
    }?;

    if want_keepalive {
        Some(attach_tcp_keepalive(&out.bytes, shared.limits.tcp_idle_timeout).unwrap_or(out.bytes))
    } else {
        Some(out.bytes)
    }
}

fn client_requested_keepalive(wire: &[u8]) -> bool {
    let Ok(msg) = Message::decode(wire) else {
        return false;
    };
    msg.edns.as_ref().is_some_and(|e| {
        e.options.iter().any(|o| match o {
            EdnsOption::Unknown { code, .. } => *code == OPTION_TCP_KEEPALIVE,
            _ => false,
        })
    })
}

fn attach_tcp_keepalive(wire: &[u8], idle: Duration) -> Option<Vec<u8>> {
    let mut msg = Message::decode(wire).ok()?;
    let edns = msg.edns.as_mut()?;
    edns.options.retain(
        |o| !matches!(o, EdnsOption::Unknown { code, .. } if *code == OPTION_TCP_KEEPALIVE),
    );
    let units = duration_to_keepalive_units(idle);
    edns.options.push(EdnsOption::Unknown {
        code: OPTION_TCP_KEEPALIVE,
        data: units.to_be_bytes().to_vec().into(),
    });
    msg.encode_with_limit(MAX_MESSAGE_LEN).ok()
}

/// RFC 7828 timeout unit = 100 ms.
pub fn duration_to_keepalive_units(d: Duration) -> u16 {
    let ms = d.as_millis().min(u128::from(u16::MAX) * 100);
    u16::try_from(ms / 100).unwrap_or(u16::MAX)
}

fn add_duration(now: SystemTime, d: Duration) -> SystemTime {
    now.checked_add(d).unwrap_or(SystemTime::UNIX_EPOCH)
}
