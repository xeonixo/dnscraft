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
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as AutoBuilder;
use rustls::ServerConfig;
use std::collections::HashMap;
use std::convert::Infallible;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::net::{TcpListener as TokioTcpListener, TcpStream};
use tokio::sync::{Semaphore, oneshot, watch};
use tokio_rustls::TlsAcceptor;

use crate::admission::{Admission, AdmitDecision, ClientIdState};
use crate::bans::StrikeReason;
use crate::clock::Clock;
use crate::config::{Exposure, Limits, ListenerConfig, PublicConfig};
use crate::core::{QueryMeta, handle_wire};
use crate::doh_request::{
    DNS_MESSAGE_TYPE, DohPath, DohWireError, content_type_of, extract_wire, parse_doh_path,
};
use crate::error::ListenersError;
use crate::framing::MAX_MESSAGE_LEN;
use crate::handler::QueryHandler;
use crate::socket::bind_tcp;
use crate::tls::{
    ListenerCertResolver, SniGate, TlsStats, tcp_server_config, tls_acceptor, tls_handshake_timeout,
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
    /// Public ban / tracking settings.
    pub public: PublicConfig,
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
    /// Bound address (port 0 friendly).
    pub bound: oneshot::Sender<SocketAddr>,
    /// Set to `true` to stop accepting.
    pub shutdown: watch::Receiver<bool>,
}

struct DohShared<H: ?Sized> {
    listener: ListenerConfig,
    limits: Limits,
    handler: Arc<H>,
    admission: Mutex<Admission>,
    clock: Arc<dyn Clock>,
    stats: Arc<DohStats>,
    sni_gate: Arc<SniGate>,
    conn_cap: Arc<Semaphore>,
    per_source: Mutex<HashMap<IpAddr, u32>>,
}

/// Runs one DoH (HTTP/2 + HTTP/1.1) listener until `params.shutdown` is `true`.
///
/// Client ID comes from the URL path (not SNI). TLS uses the N6 TCP-family config
/// (ALPN `h2` / `http/1.1`); the public SNI gate is **not** applied so apex /
/// shared hostnames can present the certificate.
pub async fn serve_doh<H>(params: DohServeParams<H>) -> Result<(), ListenersError>
where
    H: QueryHandler + 'static,
{
    let DohServeParams {
        listener,
        limits,
        public,
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

    // Cert presence only — DoH Client ID is path-based (SPEC-listeners).
    let resolver = ListenerCertResolver::local(Arc::clone(&certs), Arc::clone(&tls_stats));
    let tls_config: Arc<ServerConfig> = tcp_server_config(resolver);
    let acceptor = tls_acceptor(Arc::clone(&tls_config));

    let conn_cap = Arc::new(Semaphore::new(
        limits.max_connections_per_listener.max(1) as usize
    ));
    let shared = Arc::new(DohShared {
        admission: Mutex::new(Admission::new(&limits, &public)),
        listener,
        limits,
        handler,
        clock,
        stats,
        sni_gate,
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
                if matches!(
                    &e,
                    ListenersError::TlsHandshake { message } if message.contains("timeout")
                ) {
                    TlsStats::bump(&tls_stats.handshake_timeouts);
                } else {
                    TlsStats::bump(&tls_stats.handshake_fail);
                }
                release_per_source(&shared, source);
                DohStats::bump(&shared.stats.closed);
                return;
            }
        };

        let io = TokioIo::new(tls);
        let svc_shared = Arc::clone(&shared);
        let peer_ip = peer.ip();
        let service = service_fn(move |req: Request<Incoming>| {
            let shared = Arc::clone(&svc_shared);
            async move { Ok::<_, Infallible>(handle_http(shared, peer_ip, req).await) }
        });

        let _ = AutoBuilder::new(TokioExecutor::new())
            .serve_connection(io, service)
            .await;

        release_per_source(&shared, source);
        DohStats::bump(&shared.stats.closed);
    });
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
        source: peer,
        client_id: match &client_id_state {
            ClientIdState::Registered(id) => Some(id.clone()),
            _ => None,
        },
        size_limit: MAX_MESSAGE_LEN,
        pad: true,
        udp_payload_max: shared.limits.udp_payload_max,
    };

    let Some(out) = handle_wire(&wire, meta, &*shared.handler).await else {
        return status_empty(StatusCode::BAD_REQUEST);
    };

    DohStats::bump(&shared.stats.answered);
    let mut builder = Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, DNS_MESSAGE_TYPE);
    if let Some(max_age) = cache_max_age(&out.bytes) {
        builder = builder.header(header::CACHE_CONTROL, format!("max-age={max_age}"));
    }
    builder
        .body(Full::new(Bytes::from(out.bytes)))
        .unwrap_or_else(|_| status_empty(StatusCode::INTERNAL_SERVER_ERROR))
}

fn resolve_path_client_id<H: ?Sized>(
    shared: &DohShared<H>,
    peer: IpAddr,
    path: &DohPath,
) -> Result<ClientIdState, StatusCode> {
    let exposure = shared.listener.exposure;
    match (exposure, path) {
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
