//! Do53 TCP listener (RFC 7766 framing, pipelining, idle timeout).

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::Mutex;

use dnscraft_policy::DnsProtocol;
use tokio::net::{TcpListener as TokioTcpListener, TcpStream};
use tokio::sync::{Semaphore, oneshot, watch};

use std::sync::RwLock;

use crate::admission::{Admission, ClientIdState, SourceClass};
use crate::clock::Clock;
use crate::config::{Limits, ListenerConfig};
use crate::conn::{ConnIdentity, FramedShared, FramedStats, run_framed_connection};
use crate::ddr::DdrEndpoints;
use crate::error::ListenersError;
use crate::events::QueryEventSink;
use crate::handler::QueryHandler;
use crate::socket::bind_tcp;

pub use crate::conn::{OPTION_TCP_KEEPALIVE, duration_to_keepalive_units};

/// Counters for one Do53 TCP listener ([`FramedStats`]).
pub type TcpStats = FramedStats;

/// Inputs for [`serve_tcp`].
pub struct TcpServeParams<H: ?Sized> {
    /// Listener id / bind / exposure.
    pub listener: ListenerConfig,
    /// Shared limits.
    pub limits: Limits,
    /// Shared admission (bans / rates) across listeners.
    pub admission: Arc<Mutex<Admission>>,
    /// Policy or test handler.
    pub handler: Arc<H>,
    /// Wall clock.
    pub clock: Arc<dyn Clock>,
    /// Counters.
    pub stats: Arc<TcpStats>,
    /// DDR endpoints for `_dns.resolver.arpa` (local Do53).
    pub ddr: Option<Arc<RwLock<DdrEndpoints>>>,
    /// Query-log sink; `None` skips emission.
    pub event_sink: Option<Arc<dyn QueryEventSink>>,
    /// Bound address (port 0 friendly).
    pub bound: oneshot::Sender<SocketAddr>,
    /// Set to `true` to stop accepting.
    pub shutdown: watch::Receiver<bool>,
}

/// Runs one Do53 TCP listener until `params.shutdown` becomes `true`.
pub async fn serve_tcp<H>(params: TcpServeParams<H>) -> Result<(), ListenersError>
where
    H: QueryHandler + 'static,
{
    let TcpServeParams {
        listener,
        limits,
        admission,
        handler,
        clock,
        stats,
        ddr,
        event_sink,
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

    let conn_cap_n = limits.max_connections_per_listener.max(1);
    let conn_cap = Arc::new(Semaphore::new(conn_cap_n as usize));
    let inflight = Arc::new(Semaphore::new(
        limits.max_inflight_per_listener.max(1) as usize
    ));
    let shared = Arc::new(FramedShared {
        admission,
        listener,
        limits,
        handler,
        clock,
        stats,
        conn_cap,
        inflight,
        per_source: Mutex::new(HashMap::new()),
        ddr,
        event_sink,
        shutdown: shutdown.clone(),
    });

    loop {
        tokio::select! {
            biased;
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    let _ = shared.conn_cap.acquire_many(conn_cap_n).await;
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

fn handle_accept<H>(shared: Arc<FramedShared<H>>, stream: TcpStream, peer: SocketAddr)
where
    H: QueryHandler + 'static,
{
    // Do53-only: public sources are closed at accept. Encrypted transports (DoT)
    // use full Admission with Client ID instead of this accept-time close.
    let class = {
        let adm = shared
            .admission
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        adm.classify(peer.ip())
    };
    if class == SourceClass::Public {
        FramedStats::bump(&shared.stats.dropped_public);
        drop(stream);
        return;
    }

    let Ok(conn_permit) = shared.conn_cap.clone().try_acquire_owned() else {
        FramedStats::bump(&shared.stats.rejected_conn_cap);
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
            FramedStats::bump(&shared.stats.rejected_per_source);
            drop(conn_permit);
            drop(stream);
            return;
        }
        *count += 1;
    }

    FramedStats::bump(&shared.stats.accepted);
    tokio::spawn(async move {
        let _conn_permit = conn_permit;
        let source = peer.ip().to_canonical();
        let arrival = stream
            .local_addr()
            .map(|a| a.ip().to_canonical())
            .unwrap_or(source);
        let identity = ConnIdentity {
            protocol: DnsProtocol::Tcp53,
            pad: false,
            client_id: ClientIdState::Absent,
            arrival,
        };
        if let Err(e) = run_framed_connection(Arc::clone(&shared), stream, peer, identity).await {
            e.bump_stats(&shared.stats);
        }
        release_per_source(&shared, source);
        FramedStats::bump(&shared.stats.closed);
    });
}

fn release_per_source<H: ?Sized>(shared: &FramedShared<H>, source: IpAddr) {
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
