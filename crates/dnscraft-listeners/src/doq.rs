//! DNS over QUIC (RFC 9250): one query per bidirectional stream, ALPN `doq`.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime};

use dnscraft_policy::DnsProtocol;
use dnscraft_proto::{Message, Rcode};
use dnscraft_tls::CertResolver;
use quinn::crypto::rustls::{HandshakeData, QuicServerConfig};
use quinn::{Endpoint, EndpointConfig, RecvStream, SendStream, ServerConfig, TokioRuntime, VarInt};
use rustls::ServerConfig as RustlsServerConfig;
use tokio::sync::{Notify, Semaphore, oneshot, watch};

use crate::admission::{Admission, AdmitDecision, ClientIdState, public_client_id_required};
use crate::bans::StrikeReason;
use crate::clock::{Clock, wait_until};
use crate::config::{Limits, ListenerConfig};
use crate::core::{QueryMeta, error_reply_from_wire, handle_wire};
use crate::error::ListenersError;
use crate::framing::{MAX_MESSAGE_LEN, write_frame};
use crate::handler::QueryHandler;
use crate::socket::bind_udp;
use crate::tls::{
    ALPN_DOQ, ListenerCertResolver, PublicSniOutcome, SniGate, TlsStats, apply_sni_strike,
    apply_tls_handshake_strike, client_id_state_local, inspect_public_sni, quic_server_config,
};

/// RFC 9250 §4.3: `DOQ_PROTOCOL_ERROR` (0x2).
pub const DOQ_PROTOCOL_ERROR: VarInt = VarInt::from_u32(0x2);
/// RFC 9250 §4.3: `DOQ_NO_ERROR` (0x0).
pub const DOQ_NO_ERROR: VarInt = VarInt::from_u32(0x0);
/// RFC 9250 §4.3: `DOQ_EXCESSIVE_LOAD` (0x4).
pub const DOQ_EXCESSIVE_LOAD: VarInt = VarInt::from_u32(0x4);

/// Counters for one DoQ listener.
#[derive(Debug, Default)]
pub struct DoqStats {
    /// Connections that completed the QUIC handshake and entered stream serve.
    pub accepted: AtomicU64,
    /// Connections closed (any reason).
    pub closed: AtomicU64,
    /// Rejected because `max_connections_per_listener` was full.
    pub rejected_conn_cap: AtomicU64,
    /// Rejected because `max_connections_per_source` was full.
    pub rejected_per_source: AtomicU64,
    /// Banned public source refused before handshake.
    pub dropped_banned: AtomicU64,
    /// Queries admitted into `handle_wire`.
    pub queries: AtomicU64,
    /// Answers written to a stream.
    pub answered: AtomicU64,
    /// Per-query REFUSED answers (rate limit).
    pub refused: AtomicU64,
    /// Connections closed with [`DOQ_PROTOCOL_ERROR`].
    pub protocol_errors: AtomicU64,
    /// Idle-timeout connection closes (quinn transport).
    pub idle_timeouts: AtomicU64,
}

impl DoqStats {
    fn bump(field: &AtomicU64) {
        field.fetch_add(1, Ordering::Relaxed);
    }
}

/// Inputs for [`serve_doq`].
pub struct DoqServeParams<H: ?Sized> {
    /// Listener id / bind / exposure.
    pub listener: ListenerConfig,
    /// Shared limits (QUIC stream cap, idle = `tcp_idle_timeout`).
    pub limits: Limits,
    /// Shared admission (bans / rates) across listeners.
    pub admission: Arc<Mutex<Admission>>,
    /// Policy or test handler.
    pub handler: Arc<H>,
    /// Wall clock (admission / strikes / handshake deadline).
    pub clock: Arc<dyn Clock>,
    /// DoQ counters.
    pub stats: Arc<DoqStats>,
    /// TLS / SNI counters.
    pub tls_stats: Arc<TlsStats>,
    /// Hot-reloadable certificates.
    pub certs: Arc<CertResolver>,
    /// SNI domain / reserved labels / Client-ID registry.
    pub sni_gate: Arc<SniGate>,
    /// Bound address (port 0 friendly).
    pub bound: oneshot::Sender<SocketAddr>,
    /// Set to `true` to stop accepting.
    pub shutdown: watch::Receiver<bool>,
}

struct DoqShared<H: ?Sized> {
    listener: ListenerConfig,
    limits: Limits,
    handler: Arc<H>,
    admission: Arc<Mutex<Admission>>,
    clock: Arc<dyn Clock>,
    stats: Arc<DoqStats>,
    tls_stats: Arc<TlsStats>,
    sni_gate: Arc<SniGate>,
    certs: Arc<CertResolver>,
    conn_cap: Arc<Semaphore>,
    per_source: Mutex<HashMap<IpAddr, u32>>,
}

/// Runs one DoQ listener until `params.shutdown` becomes `true`.
///
/// Binds via [`bind_udp`] (IPv6 = V6ONLY), builds a quinn [`Endpoint`] with the
/// N6 QUIC rustls config (ALPN `doq` only, 0-RTT off), and serves one DNS query
/// per client-initiated bidirectional stream.
pub async fn serve_doq<H>(params: DoqServeParams<H>) -> Result<(), ListenersError>
where
    H: QueryHandler + 'static,
{
    let DoqServeParams {
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

    let std_sock = bind_udp(listener.address)?;
    let local = std_sock
        .local_addr()
        .map_err(|e| ListenersError::bind(listener.address, e))?;
    let _ = bound.send(local);

    let resolver = ListenerCertResolver::local(Arc::clone(&certs), Arc::clone(&tls_stats));
    // DoQ-only: advertise `doq`, not `h3` (N12 owns HTTP/3 on the same port).
    let mut rustls_cfg: RustlsServerConfig = (*quic_server_config(resolver)).clone();
    rustls_cfg.alpn_protocols = vec![ALPN_DOQ.to_vec()];

    let quic_crypto =
        QuicServerConfig::try_from(rustls_cfg).map_err(|e| ListenersError::TlsHandshake {
            message: format!("QuicServerConfig: {e}"),
        })?;
    let mut server_config = ServerConfig::with_crypto(Arc::new(quic_crypto));

    let mut transport = quinn::TransportConfig::default();
    transport.max_concurrent_bidi_streams(VarInt::from_u32(
        limits.max_quic_streams_per_connection.max(1),
    ));
    // DoQ forbids unidirectional streams (RFC 9250 §3.2).
    transport.max_concurrent_uni_streams(VarInt::from_u32(0));
    let idle = limits.tcp_idle_timeout;
    let idle_timeout = idle.try_into().map_err(|_| {
        ListenersError::config(format!(
            "tcp_idle_timeout {idle:?} is not a valid QUIC IdleTimeout"
        ))
    })?;
    transport.max_idle_timeout(Some(idle_timeout));
    server_config.transport_config(Arc::new(transport));

    let endpoint = Endpoint::new(
        EndpointConfig::default(),
        Some(server_config),
        std_sock,
        Arc::new(TokioRuntime),
    )
    .map_err(|e| ListenersError::bind(listener.address, e))?;

    let conn_cap = Arc::new(Semaphore::new(
        limits.max_connections_per_listener.max(1) as usize
    ));
    let shared = Arc::new(DoqShared {
        admission,
        listener,
        limits,
        handler,
        clock,
        stats,
        tls_stats,
        sni_gate,
        certs,
        conn_cap,
        per_source: Mutex::new(HashMap::new()),
    });

    loop {
        tokio::select! {
            biased;
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    endpoint.close(DOQ_NO_ERROR, b"shutdown");
                    return Ok(());
                }
            }
            incoming = endpoint.accept() => {
                let Some(incoming) = incoming else {
                    // Endpoint closed.
                    return Ok(());
                };
                handle_incoming(Arc::clone(&shared), incoming);
            }
        }
    }
}

fn handle_incoming<H>(shared: Arc<DoqShared<H>>, incoming: quinn::Incoming)
where
    H: QueryHandler + 'static,
{
    let peer = incoming.remote_address();
    let source = peer.ip().to_canonical();

    // Banned public source: refuse before any QUIC/TLS work.
    {
        let now = shared.clock.now();
        let mut adm = shared
            .admission
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if adm.is_banned(source, now) {
            DoqStats::bump(&shared.stats.dropped_banned);
            incoming.refuse();
            return;
        }
    }

    let Ok(conn_permit) = shared.conn_cap.clone().try_acquire_owned() else {
        DoqStats::bump(&shared.stats.rejected_conn_cap);
        incoming.refuse();
        return;
    };

    {
        let mut map = shared
            .per_source
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let count = map.entry(source).or_insert(0);
        if *count >= shared.limits.max_connections_per_source {
            DoqStats::bump(&shared.stats.rejected_per_source);
            drop(conn_permit);
            incoming.refuse();
            return;
        }
        *count += 1;
    }

    if !shared.certs.has_cert() {
        TlsStats::bump(&shared.tls_stats.no_cert);
        drop(conn_permit);
        release_per_source(&shared, source);
        incoming.refuse();
        return;
    }

    tokio::spawn(async move {
        let _conn_permit = conn_permit;
        let handshake_timeout = shared.limits.tls_handshake_timeout;
        let exposure = shared.listener.exposure;
        let connecting = match incoming.accept() {
            Ok(c) => c,
            Err(_) => {
                TlsStats::bump(&shared.tls_stats.handshake_fail);
                {
                    let mut adm = shared
                        .admission
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    apply_tls_handshake_strike(&mut adm, exposure, source, shared.clock.now());
                }
                release_per_source(&shared, source);
                DoqStats::bump(&shared.stats.closed);
                return;
            }
        };

        let deadline = add_duration(shared.clock.now(), handshake_timeout);
        let wake = Notify::new();
        let conn = tokio::select! {
            r = connecting => match r {
                Ok(c) => c,
                Err(_) => {
                    TlsStats::bump(&shared.tls_stats.handshake_fail);
                    {
                        let mut adm = shared
                            .admission
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner);
                        apply_tls_handshake_strike(&mut adm, exposure, source, shared.clock.now());
                    }
                    release_per_source(&shared, source);
                    DoqStats::bump(&shared.stats.closed);
                    return;
                }
            },
            () = wait_until(shared.clock.as_ref(), deadline, &wake) => {
                TlsStats::bump(&shared.tls_stats.handshake_timeouts);
                {
                    let mut adm = shared
                        .admission
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    apply_tls_handshake_strike(&mut adm, exposure, source, shared.clock.now());
                }
                release_per_source(&shared, source);
                DoqStats::bump(&shared.stats.closed);
                return;
            }
        };

        let client_id = match resolve_sni_client_id(&shared, &conn, source) {
            Ok(id) => id,
            Err(()) => {
                // Public SNI reject: stats/strikes already applied; close quietly.
                conn.close(DOQ_NO_ERROR, b"");
                release_per_source(&shared, source);
                DoqStats::bump(&shared.stats.closed);
                return;
            }
        };

        DoqStats::bump(&shared.stats.accepted);
        serve_connection(Arc::clone(&shared), conn, peer, client_id).await;
        release_per_source(&shared, source);
        DoqStats::bump(&shared.stats.closed);
    });
}

/// Returns Client ID state, or `Err(())` when the connection must be dropped
/// (public SNI reject — counters/strikes already recorded).
fn resolve_sni_client_id<H: ?Sized>(
    shared: &DoqShared<H>,
    conn: &quinn::Connection,
    peer: IpAddr,
) -> Result<ClientIdState, ()> {
    let sni = conn
        .handshake_data()
        .and_then(|d| {
            d.downcast_ref::<HandshakeData>()
                .map(|h| h.server_name.clone())
        })
        .flatten();
    let sni_ref = sni.as_deref();

    let class = {
        let adm = shared
            .admission
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        adm.classify(peer)
    };

    if !public_client_id_required(shared.listener.exposure, class) {
        // Local, or private source on a public listener.
        return Ok(client_id_state_local(sni_ref, shared.sni_gate.as_ref()));
    }

    match inspect_public_sni(sni_ref, shared.sni_gate.as_ref()) {
        PublicSniOutcome::Accept { client_id } => Ok(ClientIdState::Registered(client_id)),
        outcome => {
            if outcome.should_strike() {
                TlsStats::bump(&shared.tls_stats.sni_reject_strike);
            } else {
                TlsStats::bump(&shared.tls_stats.sni_reject_no_strike);
            }
            {
                let mut adm = shared
                    .admission
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                apply_sni_strike(&mut adm, peer, &outcome, shared.clock.now());
            }
            Err(())
        }
    }
}

async fn serve_connection<H>(
    shared: Arc<DoqShared<H>>,
    conn: quinn::Connection,
    peer: SocketAddr,
    client_id: ClientIdState,
) where
    H: QueryHandler + 'static,
{
    let stream_cap = Arc::new(Semaphore::new(
        shared.limits.max_quic_streams_per_connection.max(1) as usize,
    ));

    loop {
        match conn.accept_bi().await {
            Ok((send, recv)) => {
                let Ok(permit) = stream_cap.clone().try_acquire_owned() else {
                    // Transport already caps concurrent streams; treat overflow as load.
                    conn.close(DOQ_EXCESSIVE_LOAD, b"stream cap");
                    return;
                };
                let shared = Arc::clone(&shared);
                let conn = conn.clone();
                let client_id = client_id.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    if let Err(code) =
                        handle_stream(Arc::clone(&shared), &conn, send, recv, peer, &client_id)
                            .await
                    {
                        DoqStats::bump(&shared.stats.protocol_errors);
                        conn.close(code, b"");
                    }
                });
            }
            Err(e) => {
                if matches!(e, quinn::ConnectionError::TimedOut) {
                    DoqStats::bump(&shared.stats.idle_timeouts);
                }
                return;
            }
        }
    }
}

async fn handle_stream<H>(
    shared: Arc<DoqShared<H>>,
    conn: &quinn::Connection,
    mut send: SendStream,
    mut recv: RecvStream,
    peer: SocketAddr,
    client_id: &ClientIdState,
) -> Result<(), VarInt>
where
    H: QueryHandler + 'static,
{
    let deadline = add_duration(shared.clock.now(), shared.limits.query_timeout);
    let wake = Notify::new();

    // Per-stream deadline covers read_to_end + handle_wire (RFC 9250 query budget).
    let wire = tokio::select! {
        r = read_doq_message(&mut recv) => match r {
            Ok(w) => w,
            Err(DoqReadError::Protocol) => {
                strike_framing(&shared, peer.ip());
                return Err(DOQ_PROTOCOL_ERROR);
            }
            Err(DoqReadError::Closed) => {
                return Ok(());
            }
        },
        () = wait_until(shared.clock.as_ref(), deadline, &wake) => {
            // Incomplete message: reset/stop the stream (no DNS answer).
            let _ = recv.stop(DOQ_NO_ERROR);
            let _ = send.reset(DOQ_NO_ERROR);
            return Ok(());
        }
    };

    // RFC 9250 §4.2.1: Message ID must be 0.
    match Message::decode(&wire) {
        Ok(msg) if msg.header.id == 0 => {}
        Ok(_) => {
            strike_framing(&shared, peer.ip());
            return Err(DOQ_PROTOCOL_ERROR);
        }
        Err(_) => {
            strike_framing(&shared, peer.ip());
            return Err(DOQ_PROTOCOL_ERROR);
        }
    }

    let now = shared.clock.now();
    let decision = {
        let mut adm = shared
            .admission
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        adm.check(&shared.listener, peer.ip(), client_id, now)
    };

    match decision {
        AdmitDecision::Drop { .. } => {
            conn.close(DOQ_NO_ERROR, b"banned");
            return Ok(());
        }
        AdmitDecision::Refuse { .. } => {
            DoqStats::bump(&shared.stats.refused);
            if let Some(bytes) = error_reply_from_wire(
                &wire,
                Rcode::REFUSED,
                MAX_MESSAGE_LEN,
                shared.limits.udp_payload_max,
            ) {
                let out = force_doq_id0(bytes);
                let _ = write_frame(&mut send, &out).await;
                let _ = send.finish();
            }
            return Ok(());
        }
        AdmitDecision::Admit => {}
    }

    let meta = QueryMeta {
        protocol: DnsProtocol::DoQ,
        listener_id: shared.listener.id.clone(),
        source: peer.ip().to_canonical(),
        client_id: match client_id {
            ClientIdState::Registered(id) => Some(id.clone()),
            _ => None,
        },
        size_limit: MAX_MESSAGE_LEN,
        pad: true,
        udp_payload_max: shared.limits.udp_payload_max,
    };

    DoqStats::bump(&shared.stats.queries);
    let out_bytes = tokio::select! {
        r = handle_wire(&wire, meta, &*shared.handler) => match r {
            Some(out) => out.bytes,
            None => {
                strike_framing(&shared, peer.ip());
                return Err(DOQ_PROTOCOL_ERROR);
            }
        },
        () = wait_until(shared.clock.as_ref(), deadline, &wake) => {
            // Message was complete: answer SERVFAIL within the remaining budget.
            match error_reply_from_wire(
                &wire,
                Rcode::SERVFAIL,
                MAX_MESSAGE_LEN,
                shared.limits.udp_payload_max,
            ) {
                Some(bytes) => force_doq_id0(bytes),
                None => {
                    let _ = send.reset(DOQ_NO_ERROR);
                    return Ok(());
                }
            }
        }
    };

    if write_frame(&mut send, &out_bytes).await.is_err() {
        return Ok(());
    }
    let _ = send.finish();
    DoqStats::bump(&shared.stats.answered);
    Ok(())
}

fn force_doq_id0(mut bytes: Vec<u8>) -> Vec<u8> {
    if bytes.len() >= 2 {
        bytes[0] = 0;
        bytes[1] = 0;
    }
    bytes
}

enum DoqReadError {
    Protocol,
    Closed,
}

/// Reads one length-prefixed DNS message and requires STREAM FIN with no trailing bytes.
async fn read_doq_message(recv: &mut RecvStream) -> Result<Vec<u8>, DoqReadError> {
    let data = match recv.read_to_end(MAX_MESSAGE_LEN + 2).await {
        Ok(d) => d,
        Err(_) => return Err(DoqReadError::Protocol),
    };
    if data.is_empty() {
        return Err(DoqReadError::Closed);
    }
    if data.len() < 2 {
        return Err(DoqReadError::Protocol);
    }
    let len = u16::from_be_bytes([data[0], data[1]]) as usize;
    if len == 0 || len > MAX_MESSAGE_LEN || data.len() != 2 + len {
        return Err(DoqReadError::Protocol);
    }
    Ok(data[2..].to_vec())
}

fn strike_framing<H: ?Sized>(shared: &DoqShared<H>, peer: IpAddr) {
    let mut adm = shared
        .admission
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    adm.strike(
        peer.to_canonical(),
        StrikeReason::MalformedFraming,
        shared.clock.now(),
    );
}

fn release_per_source<H: ?Sized>(shared: &DoqShared<H>, source: IpAddr) {
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

fn add_duration(now: SystemTime, d: Duration) -> SystemTime {
    now.checked_add(d).unwrap_or(SystemTime::UNIX_EPOCH)
}
