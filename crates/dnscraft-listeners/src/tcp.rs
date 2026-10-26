//! Do53 TCP listener (RFC 7766 framing, pipelining, idle timeout).

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime};

use dnscraft_policy::DnsProtocol;
use dnscraft_proto::{EdnsOption, Message};
use tokio::io::{AsyncRead, AsyncWrite, BufReader, split};
use tokio::net::{TcpListener as TokioTcpListener, TcpStream};
use tokio::sync::{Notify, Semaphore, mpsc, oneshot, watch};

use crate::admission::{Admission, AdmitDecision, ClientIdState};
use crate::clock::{Clock, wait_until};
use crate::config::{Limits, ListenerConfig, PublicConfig};
use crate::core::{QueryMeta, handle_wire};
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
    /// Rejected by other admission decisions.
    pub dropped_admission: AtomicU64,
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
    /// Idle-timeout closes.
    pub idle_timeouts: AtomicU64,
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
    let now = shared.clock.now();
    let decision = {
        let mut adm = shared
            .admission
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        adm.check(&shared.listener, peer.ip(), &ClientIdState::Absent, now)
    };
    match decision {
        AdmitDecision::Admit => {}
        AdmitDecision::Drop { code } | AdmitDecision::Refuse { code } => {
            if code == "listeners.admission.public_do53" {
                TcpStats::bump(&shared.stats.dropped_public);
            } else {
                TcpStats::bump(&shared.stats.dropped_admission);
            }
            drop(stream);
            return;
        }
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
    Peer,
    Io,
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
    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(64);
    let stats = Arc::clone(&shared.stats);

    let write_task = tokio::spawn(async move {
        let mut writer = writer;
        while let Some(msg) = rx.recv().await {
            if framing::write_frame(&mut writer, &msg).await.is_err() {
                break;
            }
            TcpStats::bump(&stats.answered);
        }
    });

    let idle = shared.limits.tcp_idle_timeout;
    let activity = Notify::new();

    let result = loop {
        let deadline = add_duration(shared.clock.now(), idle);
        let frame = tokio::select! {
            r = framing::read_frame(&mut reader) => r,
            () = wait_until(shared.clock.as_ref(), deadline, &activity) => {
                break Err(ConnEnd::Idle);
            }
        };

        match frame {
            Ok(datagram) => {
                activity.notify_waiters();
                TcpStats::bump(&shared.stats.queries);
                let shared = Arc::clone(&shared);
                let tx = tx.clone();
                let peer_ip = peer.ip();
                tokio::spawn(async move {
                    if let Some(bytes) = process_query(&shared, peer_ip, datagram).await {
                        let _ = tx.send(bytes).await;
                    }
                });
            }
            Err(FrameError::UnexpectedEof) => break Err(ConnEnd::Peer),
            Err(FrameError::InvalidLength(_)) => break Err(ConnEnd::Framing),
            Err(FrameError::Io(_)) => break Err(ConnEnd::Io),
        }
    };

    drop(tx);
    let _ = write_task.await;
    result
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
        () = wait_until(shared.clock.as_ref(), deadline, &wake) => None,
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
