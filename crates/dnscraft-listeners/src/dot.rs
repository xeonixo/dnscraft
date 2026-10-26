//! DNS over TLS listener (RFC 7858): framed TCP over rustls.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::Mutex;

use dnscraft_policy::DnsProtocol;
use dnscraft_tls::CertResolver;
use rustls::ServerConfig;
use tokio::net::{TcpListener as TokioTcpListener, TcpStream};
use tokio::sync::{Semaphore, oneshot, watch};

use crate::admission::Admission;
use crate::clock::Clock;
use crate::config::{Limits, ListenerConfig};
use crate::conn::{ConnIdentity, FramedShared, FramedStats, run_framed_connection};
use crate::error::ListenersError;
use crate::handler::QueryHandler;
use crate::socket::bind_tcp;
use crate::tls::{
    ALPN_DOT, AcceptEncrypted, ListenerCertResolver, SniGate, TlsStats, accept_encrypted,
    tcp_server_config,
};

/// Counters for one DoT listener (same shape as Do53 TCP framed stats).
pub type DotStats = FramedStats;

/// Inputs for [`serve_dot`].
pub struct DotServeParams<H: ?Sized> {
    /// Listener id / bind / exposure.
    pub listener: ListenerConfig,
    /// Shared limits (includes `tls_handshake_timeout`).
    pub limits: Limits,
    /// Shared admission (bans / rates) across listeners.
    pub admission: Arc<Mutex<Admission>>,
    /// Policy or test handler.
    pub handler: Arc<H>,
    /// Wall clock.
    pub clock: Arc<dyn Clock>,
    /// Framed-connection counters.
    pub stats: Arc<DotStats>,
    /// TLS handshake / SNI counters.
    pub tls_stats: Arc<TlsStats>,
    /// Hot-reloadable certificate store.
    pub certs: Arc<CertResolver>,
    /// SNI domain / reserved labels / Client-ID registry.
    pub sni_gate: Arc<SniGate>,
    /// Bound address (port 0 friendly).
    pub bound: oneshot::Sender<SocketAddr>,
    /// Set to `true` to stop accepting.
    pub shutdown: watch::Receiver<bool>,
}

/// Runs one DoT listener until `params.shutdown` becomes `true`.
///
/// Accept path: ban check → connection caps → TLS (`accept_encrypted` with SNI
/// admission) → framed query loop with padding and Client ID from SNI.
pub async fn serve_dot<H>(params: DotServeParams<H>) -> Result<(), ListenersError>
where
    H: QueryHandler + 'static,
{
    let DotServeParams {
        listener,
        limits,
        admission,
        handler,
        clock,
        stats,
        tls_stats,
        certs,
        sni_gate,
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

    let resolver = ListenerCertResolver::local(Arc::clone(&certs), Arc::clone(&tls_stats));
    let tls_config: Arc<ServerConfig> = tcp_server_config(resolver, &[ALPN_DOT]);

    let conn_cap = Arc::new(Semaphore::new(
        limits.max_connections_per_listener.max(1) as usize
    ));
    let shared = Arc::new(FramedShared {
        admission,
        listener,
        limits,
        handler,
        clock,
        stats,
        conn_cap,
        per_source: Mutex::new(HashMap::new()),
        ddr: None,
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
                handle_accept(
                    Arc::clone(&shared),
                    stream,
                    peer,
                    Arc::clone(&tls_config),
                    Arc::clone(&certs),
                    Arc::clone(&sni_gate),
                    Arc::clone(&tls_stats),
                );
            }
        }
    }
}

fn handle_accept<H>(
    shared: Arc<FramedShared<H>>,
    stream: TcpStream,
    peer: SocketAddr,
    tls_config: Arc<ServerConfig>,
    certs: Arc<CertResolver>,
    sni_gate: Arc<SniGate>,
    tls_stats: Arc<TlsStats>,
) where
    H: QueryHandler + 'static,
{
    // Banned public source: close before any TLS work.
    {
        let now = shared.clock.now();
        let mut adm = shared
            .admission
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if adm.is_banned(peer.ip(), now) {
            FramedStats::bump(&shared.stats.dropped_admission);
            drop(stream);
            return;
        }
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
        let exposure = shared.listener.exposure;
        let handshake_timeout = shared.limits.tls_handshake_timeout;

        let accepted = accept_encrypted(
            stream,
            AcceptEncrypted {
                config: tls_config,
                exposure,
                gate: sni_gate.as_ref(),
                certs: certs.as_ref(),
                admission: shared.admission.as_ref(),
                peer: peer.ip(),
                clock: shared.clock.as_ref(),
                handshake_timeout,
                stats: tls_stats.as_ref(),
            },
        )
        .await;

        match accepted {
            Ok(tls) => {
                let arrival = peer.ip().to_canonical();
                let identity = ConnIdentity {
                    protocol: DnsProtocol::DoT,
                    pad: true,
                    client_id: tls.client_id,
                    arrival,
                };
                if let Err(e) =
                    run_framed_connection(Arc::clone(&shared), tls.stream, peer, identity).await
                {
                    e.bump_stats(&shared.stats);
                }
            }
            Err(_) => {
                // SNI reject / no_cert / handshake fail already counted on tls_stats.
            }
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
