//! DNS over HTTPS (RFC 8484) over HTTP/2 and HTTP/1.1 via hyper.

use bytes::Bytes;
use dnscraft_policy::{ClientId, DnsProtocol};
use dnscraft_proto::{Message, Rcode, RecordType};
use dnscraft_tls::CertResolver;
use dnscraft_tls::ClientIdRegistry;
use http::{Request, Response, StatusCode, header};
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::server::conn::auto::Builder as AutoBuilder;
use rustls::ServerConfig;
use std::collections::HashMap;
use std::convert::Infallible;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use tokio::net::{TcpListener as TokioTcpListener, TcpStream};
use tokio::sync::{Notify, Semaphore, oneshot, watch};
use tokio::time::Instant as TokioInstant;
use tokio_rustls::TlsAcceptor;

use crate::admission::{Admission, AdmitDecision, ClientIdState, public_client_id_required};
use crate::bans::StrikeReason;
use crate::clock::{Clock, add_duration, wait_until};
use crate::config::{Exposure, Limits, ListenerConfig};
use crate::core::{QueryMeta, error_reply_from_wire, handle_wire};
use crate::doh_request::{
    DNS_MESSAGE_TYPE, DohPath, DohWireError, content_type_of, extract_wire, parse_doh_path,
};
use crate::error::ListenersError;
use crate::events::{QueryEventSink, emit_optional};
use crate::framing::MAX_MESSAGE_LEN;
use crate::handler::QueryHandler;
use crate::socket::bind_tcp;
use crate::tls::{
    ALPN_H2, ALPN_HTTP_1_1, ListenerCertResolver, SniGate, TlsStats, apply_tls_handshake_strike,
    is_handshake_timeout, tcp_server_config, tls_acceptor, tls_handshake_timeout,
};

/// Counters for one DoH listener.
#[derive(Debug, Default)]
pub struct DohStats {
    /// Accepted TLS connections that entered HTTP serving.
    pub accepted: AtomicU64,
    /// Connections closed.
    pub closed: AtomicU64,
    /// Rejected because `max_connections_per_listener` was full.
    pub rejected_conn_cap: AtomicU64,
    /// Rejected because `max_connections_per_source` was full.
    pub rejected_per_source: AtomicU64,
    /// Banned public source closed before TLS.
    pub dropped_banned: AtomicU64,
    /// Successful DNS answers (HTTP 200).
    pub answered: AtomicU64,
    /// HTTP 404 (path / unknown Client ID).
    pub http_404: AtomicU64,
    /// HTTP 429 rate limit.
    pub http_429: AtomicU64,
    /// Ban strikes recorded for unknown public path ids.
    pub path_strikes: AtomicU64,
}

impl DohStats {
    fn bump(field: &AtomicU64) {
        field.fetch_add(1, Ordering::Relaxed);
    }
}

/// Inputs for [`serve_doh`].
pub struct DohServeParams<H: ?Sized> {
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
    /// HTTP / admission counters.
    pub stats: Arc<DohStats>,
    /// TLS handshake counters.
    pub tls_stats: Arc<TlsStats>,
    /// Hot-reloadable certificates.
    pub certs: Arc<CertResolver>,
    /// Client-ID registry (path `<id>` lookup); SNI gate domain unused for DoH path admission.
    pub sni_gate: Arc<SniGate>,
    /// Query-log sink; `None` skips emission.
    pub event_sink: Option<Arc<dyn QueryEventSink>>,
    /// Bound address (port 0 friendly).
    pub bound: oneshot::Sender<SocketAddr>,
    /// Set to `true` to stop accepting.
    pub shutdown: watch::Receiver<bool>,
}

struct DohShared<H: ?Sized> {
    listener: ListenerConfig,
    limits: Limits,
    handler: Arc<H>,
    admission: Arc<Mutex<Admission>>,
    clock: Arc<dyn Clock>,
    stats: Arc<DohStats>,
    sni_gate: Arc<SniGate>,
    conn_cap: Arc<Semaphore>,
    per_source: Mutex<HashMap<IpAddr, u32>>,
    event_sink: Option<Arc<dyn QueryEventSink>>,
}

/// Runs one DoH (HTTP/2 + HTTP/1.1) listener until `params.shutdown` is `true`.
///
/// Client ID comes from the URL path (not SNI). TLS uses DoH-only ALPN
/// (`h2` / `http/1.1`); cert resolver is presence-only.
pub async fn serve_doh<H>(params: DohServeParams<H>) -> Result<(), ListenersError>
where
    H: QueryHandler + 'static,
{
    let DohServeParams {
        listener,
        limits,
        admission,
        handler,
        clock,
        stats,
        tls_stats,
        certs,
        sni_gate,
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

    // Cert presence only — DoH Client ID is path-based (SPEC-listeners).
    let resolver = ListenerCertResolver::local(Arc::clone(&certs), Arc::clone(&tls_stats));
    let tls_config: Arc<ServerConfig> = tcp_server_config(resolver, &[ALPN_H2, ALPN_HTTP_1_1]);
    let acceptor = tls_acceptor(Arc::clone(&tls_config));

    let conn_cap = Arc::new(Semaphore::new(
        limits.max_connections_per_listener.max(1) as usize
    ));
    let shared = Arc::new(DohShared {
        admission,
        listener,
        limits,
        handler,
        clock,
        stats,
        sni_gate,
        conn_cap,
        per_source: Mutex::new(HashMap::new()),
        event_sink,
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
                    acceptor.clone(),
                    Arc::clone(&certs),
                    Arc::clone(&tls_stats),
                );
            }
        }
    }
}

fn handle_accept<H>(
    shared: Arc<DohShared<H>>,
    stream: TcpStream,
    peer: SocketAddr,
    acceptor: TlsAcceptor,
    certs: Arc<CertResolver>,
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
            DohStats::bump(&shared.stats.dropped_banned);
            drop(stream);
            return;
        }
    }

    let Ok(conn_permit) = shared.conn_cap.clone().try_acquire_owned() else {
        DohStats::bump(&shared.stats.rejected_conn_cap);
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
            DohStats::bump(&shared.stats.rejected_per_source);
            drop(conn_permit);
            drop(stream);
            return;
        }
        *count += 1;
    }

    DohStats::bump(&shared.stats.accepted);
    tokio::spawn(async move {
        let _conn_permit = conn_permit;
        let source = peer.ip().to_canonical();
        let handshake_timeout = shared.limits.tls_handshake_timeout;
        let exposure = shared.listener.exposure;

        if !certs.has_cert() {
            TlsStats::bump(&tls_stats.no_cert);
            release_per_source(&shared, source);
            DohStats::bump(&shared.stats.closed);
            return;
        }

        let tls = match tls_handshake_timeout(
            acceptor.accept(stream),
            shared.clock.as_ref(),
            handshake_timeout,
        )
        .await
        {
            Ok(s) => s,
            Err(e) => {
                if is_handshake_timeout(&e) {
                    TlsStats::bump(&tls_stats.handshake_timeouts);
                } else {
                    TlsStats::bump(&tls_stats.handshake_fail);
                }
                {
                    let mut adm = shared
                        .admission
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    apply_tls_handshake_strike(&mut adm, exposure, peer.ip(), shared.clock.now());
                }
                release_per_source(&shared, source);
                DohStats::bump(&shared.stats.closed);
                return;
            }
        };

        let io = TokioIo::new(tls);
        let idle_timeout = shared.limits.tcp_idle_timeout;
        let max_streams = shared.limits.max_queries_per_connection.max(1);
        let activity = Arc::new(ConnActivity::new());
        let svc_shared = Arc::clone(&shared);
        let peer_ip = peer.ip();
        let act = Arc::clone(&activity);
        let service = service_fn(move |req: Request<Incoming>| {
            let shared = Arc::clone(&svc_shared);
            let act = Arc::clone(&act);
            async move {
                act.begin();
                let resp = handle_http(shared, peer_ip, req).await;
                act.end();
                Ok::<_, Infallible>(resp)
            }
        });

        // TokioTimer enables http1 header_read_timeout (partial headers).
        // Application idle (h1 + h2) is tracked below — PING keep-alive is not activity.
        let mut builder = AutoBuilder::new(TokioExecutor::new());
        builder
            .http1()
            .timer(TokioTimer::new())
            .header_read_timeout(Some(idle_timeout));
        builder
            .http2()
            .timer(TokioTimer::new())
            .max_concurrent_streams(max_streams);

        let conn = builder.serve_connection(io, service);
        tokio::pin!(conn);
        let mut shutting_down = false;
        loop {
            let deadline = activity.idle_deadline(idle_timeout);
            let in_flight = activity.in_flight();
            tokio::select! {
                r = conn.as_mut() => {
                    let _ = r;
                    break;
                }
                () = activity.notified() => {}
                () = tokio::time::sleep_until(deadline), if in_flight == 0 && !shutting_down => {
                    if activity.in_flight() == 0 && TokioInstant::now() >= activity.last_end() + idle_timeout {
                        shutting_down = true;
                        conn.as_mut().graceful_shutdown();
                    }
                }
            }
        }

        release_per_source(&shared, source);
        DohStats::bump(&shared.stats.closed);
    });
}

/// Per-connection HTTP activity for application idle close (h1 keep-alive and h2).
struct ConnActivity {
    in_flight: AtomicUsize,
    last_end: Mutex<TokioInstant>,
    wake: Notify,
}

impl ConnActivity {
    fn new() -> Self {
        Self {
            in_flight: AtomicUsize::new(0),
            last_end: Mutex::new(TokioInstant::now()),
            wake: Notify::new(),
        }
    }

    fn begin(&self) {
        self.in_flight.fetch_add(1, Ordering::Relaxed);
        self.wake.notify_waiters();
    }

    fn end(&self) {
        self.in_flight.fetch_sub(1, Ordering::Relaxed);
        *self
            .last_end
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = TokioInstant::now();
        self.wake.notify_waiters();
    }

    fn in_flight(&self) -> usize {
        self.in_flight.load(Ordering::Relaxed)
    }

    fn last_end(&self) -> TokioInstant {
        *self
            .last_end
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn idle_deadline(&self, idle: std::time::Duration) -> TokioInstant {
        self.last_end() + idle
    }

    fn notified(&self) -> tokio::sync::futures::Notified<'_> {
        self.wake.notified()
    }
}

fn release_per_source<H: ?Sized>(shared: &DohShared<H>, source: IpAddr) {
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

async fn handle_http<H>(
    shared: Arc<DohShared<H>>,
    peer: IpAddr,
    req: Request<Incoming>,
) -> Response<Full<Bytes>>
where
    H: QueryHandler,
{
    let path = parse_doh_path(req.uri().path());
    let client_id_state = match resolve_path_client_id(&shared, peer, &path) {
        Ok(state) => state,
        Err(status) => return status_empty(status),
    };

    let (parts, body) = req.into_parts();
    let collected = match Limited::new(body, MAX_MESSAGE_LEN + 1).collect().await {
        Ok(c) => c.to_bytes(),
        Err(_) => {
            return status_empty(StatusCode::PAYLOAD_TOO_LARGE);
        }
    };
    if collected.len() > MAX_MESSAGE_LEN {
        return status_empty(StatusCode::PAYLOAD_TOO_LARGE);
    }

    let wire = match extract_wire(
        &parts.method,
        &parts.uri,
        content_type_of(&parts.headers),
        &collected,
    ) {
        Ok(w) => w,
        Err(e) => {
            let status = match e {
                DohWireError::BadRequest => StatusCode::BAD_REQUEST,
                DohWireError::MethodNotAllowed => StatusCode::METHOD_NOT_ALLOWED,
                DohWireError::UnsupportedMediaType => StatusCode::UNSUPPORTED_MEDIA_TYPE,
                DohWireError::PayloadTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            };
            return status_empty(status);
        }
    };

    let now = shared.clock.now();
    let decision = {
        let mut adm = shared
            .admission
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        adm.check(&shared.listener, peer, &client_id_state, now)
    };

    match decision {
        AdmitDecision::Drop {
            code: "listeners.banned",
        } => {
            // Spec: close; with HTTP we answer 403 and drop.
            return status_empty(StatusCode::FORBIDDEN);
        }
        AdmitDecision::Drop { .. } => {
            return status_empty(StatusCode::FORBIDDEN);
        }
        AdmitDecision::Refuse {
            code: "listeners.rate_limited",
        } => {
            DohStats::bump(&shared.stats.http_429);
            return status_empty(StatusCode::TOO_MANY_REQUESTS);
        }
        AdmitDecision::Refuse { .. } => {
            // Unknown client id should have been 404 already; treat as forbidden.
            return status_empty(StatusCode::FORBIDDEN);
        }
        AdmitDecision::Admit => {}
    }

    let meta = QueryMeta {
        protocol: DnsProtocol::DoH,
        listener_id: shared.listener.id.clone(),
        exposure: shared.listener.exposure,
        source: peer,
        arrival: peer.to_canonical(),
        client_id: match &client_id_state {
            ClientIdState::Registered(id) => Some(id.clone()),
            _ => None,
        },
        size_limit: MAX_MESSAGE_LEN,
        pad: true,
        udp_payload_max: shared.limits.udp_payload_max,
        ddr: None,
    };

    let deadline = add_duration(shared.clock.now(), shared.limits.query_timeout);
    let wake = Notify::new();
    let out_bytes = tokio::select! {
        r = handle_wire(&wire, meta, &*shared.handler) => match r {
            Some(out) => {
                emit_optional(&shared.event_sink, shared.clock.as_ref(), out.event);
                out.bytes
            }
            None => return status_empty(StatusCode::BAD_REQUEST),
        },
        () = wait_until(shared.clock.as_ref(), deadline, &wake) => {
            match error_reply_from_wire(
                &wire,
                Rcode::SERVFAIL,
                MAX_MESSAGE_LEN,
                shared.limits.udp_payload_max,
            ) {
                Some(mut bytes) => {
                    // DoH message id must be 0 (RFC 8484).
                    if bytes.len() >= 2 {
                        bytes[0] = 0;
                        bytes[1] = 0;
                    }
                    bytes
                }
                None => return status_empty(StatusCode::BAD_REQUEST),
            }
        }
    };

    DohStats::bump(&shared.stats.answered);
    let mut builder = Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, DNS_MESSAGE_TYPE);
    if let Some(max_age) = cache_max_age(&out_bytes) {
        builder = builder.header(header::CACHE_CONTROL, format!("max-age={max_age}"));
    }
    builder
        .body(Full::new(Bytes::from(out_bytes)))
        .unwrap_or_else(|_| status_empty(StatusCode::INTERNAL_SERVER_ERROR))
}

fn resolve_path_client_id<H: ?Sized>(
    shared: &DohShared<H>,
    peer: IpAddr,
    path: &DohPath,
) -> Result<ClientIdState, StatusCode> {
    let exposure = shared.listener.exposure;
    let class = {
        let adm = shared
            .admission
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        adm.classify(peer)
    };
    // Private source on a public listener → local path rules.
    let effective = if public_client_id_required(exposure, class) {
        Exposure::Public
    } else {
        Exposure::Local
    };

    match (effective, path) {
        (Exposure::Local, DohPath::Bare) => Ok(ClientIdState::Absent),
        (Exposure::Local, DohPath::ClientId(id)) => {
            if ClientIdRegistry::is_registered(shared.sni_gate.registry.as_ref(), id) {
                Ok(ClientId::new(id)
                    .map(ClientIdState::Registered)
                    .unwrap_or(ClientIdState::Absent))
            } else {
                // Local: unknown id ignored.
                Ok(ClientIdState::Absent)
            }
        }
        (Exposure::Local, DohPath::Other) => {
            DohStats::bump(&shared.stats.http_404);
            Err(StatusCode::NOT_FOUND)
        }
        (Exposure::Public, DohPath::ClientId(id)) => {
            if ClientIdRegistry::is_registered(shared.sni_gate.registry.as_ref(), id) {
                match ClientId::new(id) {
                    Ok(cid) => Ok(ClientIdState::Registered(cid)),
                    Err(_) => {
                        DohStats::bump(&shared.stats.http_404);
                        Err(StatusCode::NOT_FOUND)
                    }
                }
            } else {
                // Unknown id → 404 + strike.
                DohStats::bump(&shared.stats.http_404);
                DohStats::bump(&shared.stats.path_strikes);
                {
                    let mut adm = shared
                        .admission
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    adm.strike(peer, StrikeReason::UnknownClientId, shared.clock.now());
                }
                Err(StatusCode::NOT_FOUND)
            }
        }
        (Exposure::Public, DohPath::Bare | DohPath::Other) => {
            DohStats::bump(&shared.stats.http_404);
            Err(StatusCode::NOT_FOUND)
        }
    }
}

fn status_empty(status: StatusCode) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .body(Full::new(Bytes::new()))
        .unwrap_or_else(|_| Response::new(Full::new(Bytes::new())))
}

/// `Cache-Control: max-age` for NOERROR/NXDOMAIN = minimum RR TTL in the message.
pub fn cache_max_age(wire: &[u8]) -> Option<u32> {
    let msg = Message::decode(wire).ok()?;
    match msg.rcode() {
        Rcode::NOERROR | Rcode::NXDOMAIN => {}
        _ => return None,
    }
    let mut min: Option<u32> = None;
    for rr in msg
        .answers
        .iter()
        .chain(msg.authorities.iter())
        .chain(msg.additionals.iter())
    {
        if rr.rtype() == RecordType::OPT {
            continue;
        }
        min = Some(match min {
            Some(m) => m.min(rr.ttl),
            None => rr.ttl,
        });
    }
    min
}
