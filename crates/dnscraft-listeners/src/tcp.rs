//! Do53 TCP listener (RFC 7766 framing, pipelining, idle timeout).

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime};

use dnscraft_policy::DnsProtocol;
use dnscraft_proto::{EdnsOption, Message, Rcode};
use tokio::io::{AsyncRead, AsyncWrite, BufReader, split};
use tokio::net::{TcpListener as TokioTcpListener, TcpStream};
use tokio::sync::{Notify, OwnedSemaphorePermit, Semaphore, mpsc, oneshot, watch};
use tokio::task::JoinSet;

use crate::admission::{Admission, AdmitDecision, ClientIdState, SourceClass};
use crate::clock::{Clock, wait_until};
use crate::config::{Limits, ListenerConfig, PublicConfig};
use crate::core::{QueryMeta, error_reply_from_wire, handle_wire};
use crate::error::ListenersError;
use crate::framing::{self, FrameError, MAX_MESSAGE_LEN};
use crate::handler::QueryHandler;
use crate::socket::bind_tcp;

/// EDNS option code for TCP keepalive (RFC 7828).
pub const OPTION_TCP_KEEPALIVE: u16 = 11;

/// Counters for one TCP listener.
#[derive(Debug, Default)]
pub struct TcpStats {
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

impl TcpStats {
    fn bump(field: &AtomicU64) {
        field.fetch_add(1, Ordering::Relaxed);
    }
}

/// Inputs for [`serve_tcp`].
pub struct TcpServeParams<H: ?Sized> {
    /// Listener id / bind / exposure.
    pub listener: ListenerConfig,
    /// Shared limits.
    pub limits: Limits,
    /// Public ban / tracking settings.
    pub public: PublicConfig,
    /// Policy or test handler.
    pub handler: Arc<H>,
    /// Wall clock.
    pub clock: Arc<dyn Clock>,
    /// Counters.
    pub stats: Arc<TcpStats>,
    /// Bound address (port 0 friendly).
    pub bound: oneshot::Sender<SocketAddr>,
    /// Set to `true` to stop accepting.
    pub shutdown: watch::Receiver<bool>,
}

struct TcpShared<H: ?Sized> {
    listener: ListenerConfig,
    limits: Limits,
    handler: Arc<H>,
    admission: Mutex<Admission>,
    clock: Arc<dyn Clock>,
    stats: Arc<TcpStats>,
    conn_cap: Arc<Semaphore>,
    per_source: Mutex<HashMap<IpAddr, u32>>,
}

/// Runs one Do53 TCP listener until `params.shutdown` becomes `true`.
pub async fn serve_tcp<H>(params: TcpServeParams<H>) -> Result<(), ListenersError>
where
    H: QueryHandler + 'static,
{
    let TcpServeParams {
        listener,
        limits,
        public,
        handler,
        clock,
        stats,
        bound,
        mut shutdown,
    } = params;

    let std_listener = bind_tcp(listener.address)?;
    let local = std_listener
        .local_addr()
        .map_err(|e| ListenersError::bind(listener.address, e))?;
    let listener_tok = TokioTcpListener::from_std(std_listener)
        .map_err(|e| ListenersError::bind(listener.address, e))?;
    let _ = bound.send(local);

    let conn_cap = Arc::new(Semaphore::new(
        limits.max_connections_per_listener.max(1) as usize
    ));
    let shared = Arc::new(TcpShared {
        admission: Mutex::new(Admission::new(&limits, &public)),
        listener,
        limits,
        handler,
        clock,
        stats,
        conn_cap,
        per_source: Mutex::new(HashMap::new()),
    });

    loop {
        tokio::select! {
            biased;
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    return Ok(());
                }
            }
            accepted = listener_tok.accept() => {
                let Ok((stream, peer)) = accepted else {
                    continue;
                };
                handle_accept(Arc::clone(&shared), stream, peer);
            }
        }
    }
}

fn handle_accept<H>(shared: Arc<TcpShared<H>>, stream: TcpStream, peer: SocketAddr)
where
    H: QueryHandler + 'static,
{
    // Do53-only: public sources are closed at accept. Encrypted transports (DoT in N7)
    // must run full Admission with Client ID instead of this accept-time close.
    if SourceClass::of(peer.ip()) == SourceClass::Public {
        TcpStats::bump(&shared.stats.dropped_public);
        drop(stream);
        return;
    }

    let Ok(conn_permit) = shared.conn_cap.clone().try_acquire_owned() else {
        TcpStats::bump(&shared.stats.rejected_conn_cap);
        drop(stream);
        return;
    };

    {
        let mut map = shared
            .per_source
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let count = map.entry(peer.ip().to_canonical()).or_insert(0);
        if *count >= shared.limits.max_connections_per_source {
            TcpStats::bump(&shared.stats.rejected_per_source);
            drop(conn_permit);
            drop(stream);
            return;
        }
        *count += 1;
    }

    TcpStats::bump(&shared.stats.accepted);
    tokio::spawn(async move {
        let _conn_permit = conn_permit;
        let source = peer.ip().to_canonical();
        if let Err(e) = run_connection(Arc::clone(&shared), stream, peer).await {
            match e {
                ConnEnd::Framing => TcpStats::bump(&shared.stats.framing_errors),
                ConnEnd::Idle => TcpStats::bump(&shared.stats.idle_timeouts),
                ConnEnd::Banned => TcpStats::bump(&shared.stats.dropped_admission),
                ConnEnd::WriteTimeout => TcpStats::bump(&shared.stats.write_timeouts),
                ConnEnd::Peer | ConnEnd::Io => {}
            }
        }
        {
            let mut map = shared
                .per_source
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Some(c) = map.get_mut(&source) {
                *c = c.saturating_sub(1);
                if *c == 0 {
                    map.remove(&source);
                }
            }
        }
        TcpStats::bump(&shared.stats.closed);
    });
}

enum ConnEnd {
    Framing,
    Idle,
    Banned,
    WriteTimeout,
    Peer,
    Io,
}

impl ConnEnd {
    /// Abort in-flight queries (ban, framing, writer failure). EOF/idle drain instead.
    fn abort_queries(&self) -> bool {
        matches!(
            self,
            ConnEnd::Banned | ConnEnd::Framing | ConnEnd::WriteTimeout | ConnEnd::Io
        )
    }
}

async fn run_connection<H, S>(
    shared: Arc<TcpShared<H>>,
    stream: S,
    peer: SocketAddr,
) -> Result<(), ConnEnd>
where
    H: QueryHandler + 'static,
    S: AsyncRead + AsyncWrite + Send + 'static,
{
    let (reader, writer) = split(stream);
    let mut reader = BufReader::new(reader);
    let (tx, rx) = mpsc::channel::<Vec<u8>>(64);
    // Level-triggered: writer sets `true` on error/timeout; read loop observes without racing Notify.
    let (cancel_tx, mut cancel_rx) = watch::channel(false);
    let slot_cap = shared.limits.max_queries_per_connection.max(1) as usize;
    let query_slots = Arc::new(Semaphore::new(slot_cap));
    let mut queries: JoinSet<()> = JoinSet::new();

    let write_stats = Arc::clone(&shared.stats);
    let write_clock = Arc::clone(&shared.clock);
    let write_idle = shared.limits.tcp_idle_timeout;
    let write_task = tokio::spawn(async move {
        writer_loop(writer, rx, write_clock, write_idle, write_stats, cancel_tx).await
    });

    let idle = shared.limits.tcp_idle_timeout;
    let activity = Notify::new();

    let result = loop {
        if *cancel_rx.borrow() {
            break Err(ConnEnd::WriteTimeout);
        }

        // Backpressure: hold a per-connection slot before reading the next frame.
        // Read-idle (RFC 7766 §6.2.3) only while no query is outstanding.
        let idle_now = query_slots.available_permits() == slot_cap;
        let permit = if idle_now {
            let deadline = add_duration(shared.clock.now(), idle);
            tokio::select! {
                biased;
                changed = cancel_rx.changed() => {
                    if changed.is_err() || *cancel_rx.borrow() {
                        break Err(ConnEnd::WriteTimeout);
                    }
                    continue;
                }
                () = wait_until(shared.clock.as_ref(), deadline, &activity) => {
                    break Err(ConnEnd::Idle);
                }
                p = query_slots.clone().acquire_owned() => {
                    match p {
                        Ok(p) => p,
                        Err(_) => break Err(ConnEnd::Io),
                    }
                }
            }
        } else {
            tokio::select! {
                biased;
                changed = cancel_rx.changed() => {
                    if changed.is_err() || *cancel_rx.borrow() {
                        break Err(ConnEnd::WriteTimeout);
                    }
                    continue;
                }
                p = query_slots.clone().acquire_owned() => {
                    match p {
                        Ok(p) => p,
                        Err(_) => break Err(ConnEnd::Io),
                    }
                }
            }
        };

        // Only our speculative permit held ⇒ still "idle" for the read wait.
        let read_idle = query_slots.available_permits() == slot_cap - 1;
        let frame = if read_idle {
            let deadline = add_duration(shared.clock.now(), idle);
            tokio::select! {
                biased;
                changed = cancel_rx.changed() => {
                    drop(permit);
                    if changed.is_err() || *cancel_rx.borrow() {
                        break Err(ConnEnd::WriteTimeout);
                    }
                    continue;
                }
                r = framing::read_frame(&mut reader) => r,
                () = wait_until(shared.clock.as_ref(), deadline, &activity) => {
                    drop(permit);
                    break Err(ConnEnd::Idle);
                }
            }
        } else {
            tokio::select! {
                biased;
                changed = cancel_rx.changed() => {
                    drop(permit);
                    if changed.is_err() || *cancel_rx.borrow() {
                        break Err(ConnEnd::WriteTimeout);
                    }
                    continue;
                }
                r = framing::read_frame(&mut reader) => r,
            }
        };

        match frame {
            Ok(datagram) => {
                activity.notify_waiters();
                match dispatch_frame(&shared, peer.ip(), datagram, permit, &tx, &mut queries).await
                {
                    Ok(()) => {}
                    Err(e) => break Err(e),
                }
            }
            Err(FrameError::UnexpectedEof) => break Err(ConnEnd::Peer),
            Err(FrameError::InvalidLength(_)) => break Err(ConnEnd::Framing),
            Err(FrameError::Io(_)) => break Err(ConnEnd::Io),
        }
    };

    // Stop reading. Dropping `tx` lets the writer finish after in-flight query clones release.
    let abort = result.as_ref().err().is_some_and(|e| e.abort_queries());
    drop(tx);
    if abort {
        queries.abort_all();
    }
    while queries.join_next().await.is_some() {}
    // Await the writer exactly once (no select on JoinHandle; no abort of a drained writer).
    let writer_end = write_task.await;
    match result {
        Err(ConnEnd::Peer) | Err(ConnEnd::Idle) => {
            // Graceful: prefer writer's timeout/IO if it failed while flushing.
            match writer_end {
                Ok(WriterEnd::Timeout) => Err(ConnEnd::WriteTimeout),
                Ok(WriterEnd::Io) => Err(ConnEnd::Io),
                _ => result,
            }
        }
        other => {
            let _ = writer_end;
            other
        }
    }
}

async fn dispatch_frame<H>(
    shared: &Arc<TcpShared<H>>,
    peer_ip: IpAddr,
    datagram: Vec<u8>,
    permit: OwnedSemaphorePermit,
    tx: &mpsc::Sender<Vec<u8>>,
    queries: &mut JoinSet<()>,
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
        adm.check(&shared.listener, peer_ip, &ClientIdState::Absent, now)
    };

    match decision {
        AdmitDecision::Drop { .. } => {
            drop(permit);
            Err(ConnEnd::Banned)
        }
        AdmitDecision::Refuse { .. } => {
            TcpStats::bump(&shared.stats.refused);
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
            TcpStats::bump(&shared.stats.queries);
            let shared = Arc::clone(shared);
            let tx = tx.clone();
            queries.spawn(async move {
                let _permit = permit;
                if let Some(bytes) = process_query(&shared, peer_ip, datagram).await {
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
    stats: Arc<TcpStats>,
    cancel: watch::Sender<bool>,
) -> WriterEnd {
    while let Some(msg) = rx.recv().await {
        let deadline = add_duration(clock.now(), idle);
        let wake = Notify::new();
        let outcome = tokio::select! {
            r = framing::write_frame(&mut writer, &msg) => {
                match r {
                    Ok(()) => {
                        TcpStats::bump(&stats.answered);
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
    shared: &TcpShared<H>,
    peer_ip: IpAddr,
    datagram: Vec<u8>,
) -> Option<Vec<u8>>
where
    H: QueryHandler,
{
    let want_keepalive = client_requested_keepalive(&datagram);
    let meta = QueryMeta {
        protocol: DnsProtocol::Tcp53,
        listener_id: shared.listener.id.clone(),
        source: peer_ip,
        client_id: None,
        size_limit: MAX_MESSAGE_LEN,
        pad: false,
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
