//! DNS over HTTPS (RFC 8484) over HTTP/2 and HTTP/1.1 via hyper.

use bytes::Bytes;
use dnscraft_policy::{ClientId, DnsProtocol};
use dnscraft_proto::{Message, Rcode, RecordType};
use dnscraft_tls::CertResolver;
use dnscraft_tls::ClientIdRegistry;
use http::{HeaderMap, Method, Request, Response, StatusCode, Uri, header};
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
use std::sync::atomic::{AtomicU16, AtomicU64, AtomicUsize, Ordering};
use std::time::{Instant, SystemTime};
use tokio::net::{TcpListener as TokioTcpListener, TcpStream};
use tokio::sync::{Notify, Semaphore, oneshot, watch};
use tokio_rustls::TlsAcceptor;

use crate::admission::{
    Admission, AdmitDecision, ClientIdState, SourceClass, public_client_id_required,
};
use crate::bans::StrikeReason;
use crate::clock::{Clock, add_duration, wait_until};
use crate::config::{Exposure, Limits, ListenerConfig};
use crate::core::{QueryMeta, error_event_from_wire, error_result_from_wire, handle_wire};
use crate::doh_request::{
    DNS_MESSAGE_TYPE, DohPath, DohWireError, MAX_DOH_HEADER_LIST_SIZE, content_type_of,
    extract_wire, parse_doh_path,
};
use crate::error::ListenersError;
use crate::events::{QueryEventSink, emit_optional};
use crate::framing::MAX_MESSAGE_LEN;
use crate::handler::QueryHandler;
use crate::socket::bind_tcp;
use crate::tls::{
    ListenerCertResolver, SniGate, TlsStats, apply_tls_handshake_strike, is_handshake_timeout,
    tcp_server_config, tls_acceptor, tls_handshake_timeout,
};
use crate::web::{WebBody, WebSlot};

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
    /// HTTP/3 requests whose header/body read deadline fired (stream reset).
    pub request_timeouts: AtomicU64,
    /// HTTP/3 request processing errors (resolve / recv / send failures).
    pub request_errors: AtomicU64,
}

impl DohStats {
    pub(crate) fn bump(field: &AtomicU64) {
        field.fetch_add(1, Ordering::Relaxed);
    }
}

/// `Alt-Svc` max-age (seconds) when advertising HTTP/3.
pub const ALT_SVC_MAX_AGE: u32 = 86_400;

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
    /// UDP port for `Alt-Svc` when [`ListenerConfig::h3`] (0 = omit until set).
    pub alt_svc_port: Arc<AtomicU16>,
    /// Serves non-DoH paths for private sources on a local listener (web UI / API); empty → `404`.
    pub web: Arc<WebSlot>,
    /// Bound address (port 0 friendly).
    pub bound: oneshot::Sender<SocketAddr>,
    /// Set to `true` to stop accepting.
    pub shutdown: watch::Receiver<bool>,
}

/// Shared DoH request state (HTTP/2 and HTTP/3).
pub(crate) struct DohShared<H: ?Sized> {
    pub(crate) listener: ListenerConfig,
    pub(crate) limits: Limits,
    pub(crate) handler: Arc<H>,
    pub(crate) admission: Arc<Mutex<Admission>>,
    pub(crate) clock: Arc<dyn Clock>,
    pub(crate) stats: Arc<DohStats>,
    pub(crate) sni_gate: Arc<SniGate>,
    pub(crate) conn_cap: Arc<Semaphore>,
    /// Listener-wide in-flight query cap (shared by all connections).
    pub(crate) inflight: Arc<Semaphore>,
    pub(crate) per_source: Mutex<HashMap<IpAddr, u32>>,
    pub(crate) event_sink: Option<Arc<dyn QueryEventSink>>,
    pub(crate) alt_svc_port: Arc<AtomicU16>,
    /// Web UI / API hand-off (HTTP/1.1 and HTTP/2 only).
    pub(crate) web: Arc<WebSlot>,
    /// Listener shutdown signal (graceful connection drain).
    pub(crate) shutdown: watch::Receiver<bool>,
}

/// Wire answer produced by [`process_doh_request`] (status + headers + body).
pub(crate) struct DohHttpParts {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: Bytes,
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
        alt_svc_port,
        web,
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
    let tls_policy = listener.tls_policy.clone().unwrap_or_default();
    let alpn: Vec<&[u8]> = tls_policy.alpn.iter().map(String::as_bytes).collect();
    let tls_config: Arc<ServerConfig> = tcp_server_config(resolver, &alpn, &tls_policy);
    let acceptor = tls_acceptor(Arc::clone(&tls_config));

    let conn_cap_n = limits.max_connections_per_listener.max(1);
    let conn_cap = Arc::new(Semaphore::new(conn_cap_n as usize));
    let inflight = Arc::new(Semaphore::new(
        limits.max_inflight_per_listener.max(1) as usize
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
        inflight,
        per_source: Mutex::new(HashMap::new()),
        event_sink,
        alt_svc_port,
        web,
        shutdown: shutdown.clone(),
    });

    loop {
        tokio::select! {
            biased;
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    // Stop accepting; connection tasks call `graceful_shutdown`
                    // and release their permits once in-flight requests finish.
                    let _ = shared.conn_cap.acquire_many(conn_cap_n).await;
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
            release_per_source(&shared.per_source, source);
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
                release_per_source(&shared.per_source, source);
                DohStats::bump(&shared.stats.closed);
                return;
            }
        };

        let io = TokioIo::new(tls);
        let idle_timeout = shared.limits.tcp_idle_timeout;
        let max_streams = shared.limits.max_queries_per_connection.max(1);
        let activity = Arc::new(ConnActivity::new(shared.clock.now()));
        let svc_shared = Arc::clone(&shared);
        let act = Arc::clone(&activity);
        let service = service_fn(move |req: Request<Incoming>| {
            let shared = Arc::clone(&svc_shared);
            let act = Arc::clone(&act);
            let clock = Arc::clone(&svc_shared.clock);
            async move {
                act.begin();
                let resp = route(shared, peer, req).await;
                act.end(clock.as_ref());
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
            .max_concurrent_streams(max_streams)
            .max_header_list_size(MAX_DOH_HEADER_LIST_SIZE as u32);

        let conn = builder.serve_connection(io, service);
        tokio::pin!(conn);
        let mut listener_shutdown = shared.shutdown.clone();
        let mut shutting_down = *listener_shutdown.borrow();
        if shutting_down {
            conn.as_mut().graceful_shutdown();
        }
        loop {
            let deadline = add_duration(activity.last_activity(), idle_timeout);
            let in_flight = activity.in_flight();
            tokio::select! {
                r = conn.as_mut() => {
                    let _ = r;
                    break;
                }
                changed = listener_shutdown.changed() => {
                    if changed.is_err() || *listener_shutdown.borrow() {
                        shutting_down = true;
                        conn.as_mut().graceful_shutdown();
                    }
                }
                () = activity.notified() => {}
                () = wait_until(shared.clock.as_ref(), deadline, activity.wake()), if in_flight == 0 && !shutting_down => {
                    if activity.in_flight() == 0 && shared.clock.now() >= add_duration(activity.last_activity(), idle_timeout) {
                        shutting_down = true;
                        conn.as_mut().graceful_shutdown();
                    }
                }
            }
        }

        release_per_source(&shared.per_source, source);
        DohStats::bump(&shared.stats.closed);
    });
}

/// Per-connection application activity for idle close (shared by DoH, DoH/3, DoQ).
pub(crate) struct ConnActivity {
    last: Mutex<SystemTime>,
    wake: Notify,
    in_flight: AtomicUsize,
}

impl ConnActivity {
    pub(crate) fn new(now: SystemTime) -> Self {
        Self {
            last: Mutex::new(now),
            wake: Notify::new(),
            in_flight: AtomicUsize::new(0),
        }
    }

    pub(crate) fn in_flight(&self) -> usize {
        self.in_flight.load(Ordering::Relaxed)
    }

    /// Marks one request/stream started.
    pub(crate) fn begin(&self) {
        self.in_flight.fetch_add(1, Ordering::Relaxed);
        self.wake.notify_waiters();
    }

    /// Marks one finished without stamping `last_activity`.
    pub(crate) fn finish(&self) {
        self.in_flight.fetch_sub(1, Ordering::Relaxed);
        self.wake.notify_waiters();
    }

    /// Marks one finished and stamps `last_activity` from `clock`.
    pub(crate) fn end(&self, clock: &dyn Clock) {
        self.in_flight.fetch_sub(1, Ordering::Relaxed);
        self.touch(clock);
    }

    /// Stamps `last_activity` from `clock` and wakes idle waiters.
    pub(crate) fn touch(&self, clock: &dyn Clock) {
        *self
            .last
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = clock.now();
        self.wake.notify_waiters();
    }

    pub(crate) fn last_activity(&self) -> SystemTime {
        *self
            .last
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    pub(crate) fn notified(&self) -> tokio::sync::futures::Notified<'_> {
        self.wake.notified()
    }

    pub(crate) fn wake(&self) -> &Notify {
        &self.wake
    }
}

/// Decrements (and prunes at zero) the per-source connection counter.
pub(crate) fn release_per_source(per_source: &Mutex<HashMap<IpAddr, u32>>, source: IpAddr) {
    let mut map = per_source
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some(c) = map.get_mut(&source) {
        *c = c.saturating_sub(1);
        if *c == 0 {
            map.remove(&source);
        }
    }
}

/// Sends a non-DoH path from a private source to the web handler (if any);
/// everything else is DoH.
async fn route<H>(
    shared: Arc<DohShared<H>>,
    peer: SocketAddr,
    req: Request<Incoming>,
) -> Response<WebBody>
where
    H: QueryHandler,
{
    if let Some(web) = shared.web.get()
        && parse_doh_path(req.uri().path()) == DohPath::Other
        && web_allowed(&shared, peer.ip())
    {
        let is_login = req.method() == Method::POST && req.uri().path() == WEB_LOGIN_PATH;
        let response = web(peer, req).await;
        // A failed sign-in or a forbidden request counts toward the shared ban (public sources
        // only; `Admission::strike` ignores private ones). Plain 401s are not counted: the SPA
        // probes `/auth/me` on every page load.
        let status = response.status();
        if status == StatusCode::FORBIDDEN
            || (is_login
                && matches!(
                    status,
                    StatusCode::UNAUTHORIZED | StatusCode::LOCKED | StatusCode::TOO_MANY_REQUESTS
                ))
        {
            let now = shared.clock.now();
            shared
                .admission
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .strike(peer.ip(), StrikeReason::WebAuth, now);
        }
        return response;
    }
    handle_http(shared, peer.ip(), req).await.map(|body| {
        body.map_err(|never| -> Box<dyn std::error::Error + Send + Sync> { match never {} })
            .boxed_unsync()
    })
}

/// Path of the break-glass sign-in (failures count as web strikes).
const WEB_LOGIN_PATH: &str = "/api/v1/auth/local/login";

/// Whether `peer` may reach the web handler: private sources always; public sources only on a
/// public listener while public web access is on and the source is not banned.
fn web_allowed<H: ?Sized>(shared: &DohShared<H>, peer: IpAddr) -> bool {
    if private_source(shared, peer) {
        return true;
    }
    let now = shared.clock.now();
    shared.web.public()
        && shared.listener.exposure == Exposure::Public
        && !shared
            .admission
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .is_banned(peer, now)
}

/// `true` for a private TCP peer: the web UI is routed by source, never for public sources. On a
/// public-exposure listener this extends the rule that already gives private sources local DNS
/// rules; the owner opts in per listener with `control_api.shared_doh_listener`.
fn private_source<H: ?Sized>(shared: &DohShared<H>, peer: IpAddr) -> bool {
    shared
        .admission
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .classify(peer)
        == SourceClass::Private
}

async fn handle_http<H>(
    shared: Arc<DohShared<H>>,
    peer: IpAddr,
    req: Request<Incoming>,
) -> Response<Full<Bytes>>
where
    H: QueryHandler,
{
    let (parts, body) = req.into_parts();
    let collected = match Limited::new(body, MAX_MESSAGE_LEN + 1).collect().await {
        Ok(c) => c.to_bytes(),
        Err(_) => {
            strike_malformed(&shared, peer);
            return status_empty(StatusCode::PAYLOAD_TOO_LARGE);
        }
    };
    if collected.len() > MAX_MESSAGE_LEN {
        strike_malformed(&shared, peer);
        return status_empty(StatusCode::PAYLOAD_TOO_LARGE);
    }

    let parts_out = process_doh_request(
        &shared,
        peer,
        &parts.method,
        &parts.uri,
        &parts.headers,
        collected,
    )
    .await;
    parts_to_response(parts_out)
}

/// Shared DoH path/admission/`handle_wire` for HTTP/1.1, HTTP/2, and HTTP/3.
pub(crate) async fn process_doh_request<H>(
    shared: &Arc<DohShared<H>>,
    peer: IpAddr,
    method: &Method,
    uri: &Uri,
    headers: &HeaderMap,
    body: Bytes,
) -> DohHttpParts
where
    H: QueryHandler,
{
    let path = parse_doh_path(uri.path());
    let client_id_state = match resolve_path_client_id(shared, peer, &path) {
        Ok(state) => state,
        Err(status) => return empty_parts(status),
    };

    let wire = match extract_wire(method, uri, content_type_of(headers), &body) {
        Ok(w) => w,
        Err(e) => {
            strike_malformed(shared, peer);
            let status = match e {
                DohWireError::BadRequest => StatusCode::BAD_REQUEST,
                DohWireError::MethodNotAllowed => StatusCode::METHOD_NOT_ALLOWED,
                DohWireError::UnsupportedMediaType => StatusCode::UNSUPPORTED_MEDIA_TYPE,
                DohWireError::PayloadTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            };
            return empty_parts(status);
        }
    };

    let started = Instant::now();
    let meta = QueryMeta {
        protocol: DnsProtocol::DoH,
        listener_id: shared.listener.id.clone(),
        node_id: shared.listener.node_id.clone(),
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
            DohStats::bump(&shared.stats.dropped_banned);
            return empty_parts(StatusCode::FORBIDDEN);
        }
        AdmitDecision::Drop { .. } => {
            return empty_parts(StatusCode::FORBIDDEN);
        }
        AdmitDecision::Refuse {
            code: "listeners.rate_limited",
        } => {
            DohStats::bump(&shared.stats.http_429);
            emit_optional(
                &shared.event_sink,
                shared.clock.as_ref(),
                error_event_from_wire(&wire, &meta, Rcode::REFUSED, 0, started.elapsed()),
            );
            return empty_parts(StatusCode::TOO_MANY_REQUESTS);
        }
        AdmitDecision::Refuse { .. } => {
            emit_optional(
                &shared.event_sink,
                shared.clock.as_ref(),
                error_event_from_wire(&wire, &meta, Rcode::REFUSED, 0, started.elapsed()),
            );
            return empty_parts(StatusCode::FORBIDDEN);
        }
        AdmitDecision::Admit => {}
    }

    // Listener-wide in-flight cap (in addition to per-connection HTTP limits):
    // wait rather than reject so HTTP/2 streams apply backpressure.
    let Ok(_inflight) = Arc::clone(&shared.inflight).acquire_owned().await else {
        return empty_parts(StatusCode::SERVICE_UNAVAILABLE);
    };

    let deadline = add_duration(shared.clock.now(), shared.limits.query_timeout);
    let wake = Notify::new();
    let out_bytes = tokio::select! {
        r = handle_wire(&wire, meta.clone(), &*shared.handler) => match r {
            Some(out) => {
                emit_optional(&shared.event_sink, shared.clock.as_ref(), out.event);
                out.bytes
            }
            // Core drop rule (QR=1 / unparseable header): no DNS answer.
            None => return empty_parts(StatusCode::BAD_REQUEST),
        },
        () = wait_until(shared.clock.as_ref(), deadline, &wake) => {
            match error_result_from_wire(
                &wire,
                Rcode::SERVFAIL,
                MAX_MESSAGE_LEN,
                shared.limits.udp_payload_max,
                &meta,
                started,
            ) {
                Some(out) => {
                    emit_optional(&shared.event_sink, shared.clock.as_ref(), out.event);
                    let mut bytes = out.bytes;
                    if bytes.len() >= 2 {
                        bytes[0] = 0;
                        bytes[1] = 0;
                    }
                    bytes
                }
                None => return empty_parts(StatusCode::BAD_REQUEST),
            }
        }
    };

    DohStats::bump(&shared.stats.answered);
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        header::HeaderValue::from_static(DNS_MESSAGE_TYPE),
    );
    if let Some(max_age) = cache_max_age(&out_bytes)
        && let Ok(v) = header::HeaderValue::from_str(&format!("max-age={max_age}"))
    {
        headers.insert(header::CACHE_CONTROL, v);
    }
    maybe_alt_svc(shared, &mut headers);

    DohHttpParts {
        status: StatusCode::OK,
        headers,
        body: Bytes::from(out_bytes),
    }
}

fn maybe_alt_svc<H: ?Sized>(shared: &DohShared<H>, headers: &mut HeaderMap) {
    if !shared.listener.h3 {
        return;
    }
    let port = shared.alt_svc_port.load(Ordering::Relaxed);
    if port == 0 {
        return;
    }
    let value = format!("h3=\":{port}\"; ma={ALT_SVC_MAX_AGE}");
    if let Ok(v) = header::HeaderValue::from_str(&value) {
        headers.insert(header::ALT_SVC, v);
    }
}

/// Records a [`StrikeReason::MalformedFraming`] ban strike for a malformed DoH
/// request (bad method/type/base64 or oversized body). Public sources only.
pub(crate) fn strike_malformed<H: ?Sized>(shared: &DohShared<H>, peer: IpAddr) {
    let now = shared.clock.now();
    let mut adm = shared
        .admission
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    adm.strike(peer, StrikeReason::MalformedFraming, now);
}

fn empty_parts(status: StatusCode) -> DohHttpParts {
    DohHttpParts {
        status,
        headers: HeaderMap::new(),
        body: Bytes::new(),
    }
}

fn parts_to_response(parts: DohHttpParts) -> Response<Full<Bytes>> {
    let mut builder = Response::builder().status(parts.status);
    for (name, value) in parts.headers.iter() {
        builder = builder.header(name, value);
    }
    builder
        .body(Full::new(parts.body))
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
