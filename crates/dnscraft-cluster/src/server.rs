//! Master-side mTLS listener for the cluster control plane.
//!
//! A second internal listener (separate from control-api) serves
//! `/cluster/v1/*` over TLS 1.3 + HTTP/2. Every presented client certificate
//! must chain to the dedicated cluster CA; after the handshake the leaf's
//! `node_id` SAN and SHA-256 fingerprint are checked against the durable node
//! registry before any protected route runs. `node_id` is therefore always the
//! authenticated certificate identity, never a request field.
//!
//! `POST /cluster/v1/enroll` is the bootstrap exception: enrollment happens
//! before the node has a certificate, so its trust comes from the one-time,
//! `node_id`-bound join token and the CSR binding ([`crate::enroll`]). A client
//! certificate presented to the enroll route, if any, is still chain-validated
//! by rustls.
//!
//! Version negotiation uses the `x-cluster-protocol` request header on the
//! stream; a mismatch yields one `error` record carrying
//! `cluster.protocol.version` and closes the stream.

use std::convert::Infallible;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use axum::body::{Body, Bytes};
use axum::extract::{Extension, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, Uri, header};
use axum::middleware;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use dnscraft_common::clock::Clock;
use dnscraft_common::secret::Secret;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::service::TowerToHyperService;
use rcgen::{
    CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose,
    PKCS_ECDSA_P256_SHA256, SanType,
};
use rustls::RootCertStore;
use rustls::server::WebPkiClientVerifier;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use serde::{Deserialize, Serialize};
use serde_json::json;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use tokio::net::TcpListener;
use tokio::sync::{mpsc, watch};
use tokio_rustls::TlsAcceptor;
use tokio_stream::wrappers::ReceiverStream;

use crate::ca::{ClusterCa, cert_fingerprint, node_id_from_der};
use crate::config::{ListenConfig, QuotaConfig};
use crate::enroll::{PROTOCOL_VERSION, enroll as run_enroll};
use crate::error::ClusterError;
use crate::log::{LogAck, LogBatch, LogIngest};
use crate::quota::QuotaLimiter;
use crate::relay::{RuntimeCommand, WriteExecutor, WriteRelay};
use crate::store::ClusterStore;
use crate::sync::{
    AuthSnapshotPush, CertPush, ConfigAck, ConfigSync, Hello, StreamError, StreamRecord,
};

/// Request header carrying the sub-node's cluster protocol version.
pub(crate) const PROTOCOL_HEADER: &str = "x-cluster-protocol";

const NDJSON: &str = "application/x-ndjson";

/// Master hook that produces the current auth snapshot for a connecting node.
///
/// The stream handler calls this once per (re)connection, after `hello`, so a
/// node that was offline across a revocation reconciles before it replays any
/// buffered write. The snapshot is opaque to this crate.
#[async_trait::async_trait]
pub trait AuthSnapshotSource: Send + Sync {
    /// Returns the serialized [`crate::AuthSnapshotPush`] payload.
    async fn snapshot(&self) -> Result<serde_json::Value, ClusterError>;
}

/// Bootstrap configuration for the master's cluster listener.
#[derive(Debug, Clone)]
pub struct ClusterServerConfig {
    /// Address to bind. Only loopback/private/ULA addresses are valid
    /// (`[cluster.listen]`).
    pub listen: ListenConfig,
    /// SAN placed on the master's server certificate. Must match the host in
    /// the sub-node's `master_url` (a DNS name or an IP address).
    pub server_name: String,
    /// Lifetime of certificates issued to joining nodes (`[cluster.join]`).
    pub node_cert_ttl: Duration,
    /// Per-node quotas enforced by the master (`[cluster.quota]`).
    pub quota: QuotaConfig,
}

/// `POST /cluster/v1/heartbeat` request body.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct HeartbeatRequest {
    /// Cluster protocol version; must equal [`PROTOCOL_VERSION`].
    pub protocol: u32,
    /// Last config version the node applied, if it has one.
    pub applied_version: Option<i64>,
    /// Local queue depth reported for status.
    pub queue_depth: u32,
    /// Node wall-clock time when the heartbeat was sent (RFC 3339).
    ///
    /// Used only for the `cluster.clock_skew` status warning; absent or
    /// malformed values are accepted without a skew check.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub time: Option<String>,
}

/// A non-fatal condition reported alongside a successful heartbeat.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct StatusWarning {
    /// Stable `cluster.<area>.<reason>` code.
    pub code: String,
    /// Structured context (thresholds, counts); never secret.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub params: Option<serde_json::Value>,
}

/// `POST /cluster/v1/heartbeat` response body.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct HeartbeatResponse {
    /// Always `true` on success.
    pub ok: bool,
    /// Master clock time the heartbeat was processed (RFC 3339).
    pub received_at: String,
    /// Non-fatal status warnings (`cluster.clock_skew`, queue over cap).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<StatusWarning>,
}

/// A cheaply cloneable handle to the master's volatile broadcast channel.
///
/// Obtained from [`ClusterServer::broadcast_handle`] so a caller (for example
/// the control-api cluster runtime) can push runtime commands, certificates and
/// auth snapshots after the server has been moved into its owning runtime.
#[derive(Clone)]
pub struct ClusterBroadcast {
    config_sync: Arc<ConfigSync>,
    clock: Arc<dyn Clock>,
}

impl ClusterBroadcast {
    /// Broadcasts a volatile runtime command to every connected node.
    ///
    /// Nothing is persisted or retried; nodes connecting later do not see it.
    pub fn broadcast_runtime_command(&self, kind: &str, payload: &serde_json::Value) {
        let command = RuntimeCommand {
            kind: kind.to_owned(),
            filter_set_id: None,
            payload: payload.clone(),
            issued_at: rfc3339(self.clock.now()),
        };
        self.config_sync
            .broadcast(StreamRecord::RuntimeCommand(command));
    }

    /// Broadcasts a renewed certificate/key to every connected node.
    ///
    /// Best-effort: a node that is offline keeps its previous certificate. The
    /// key travels only over the mTLS stream and is never logged.
    pub fn push_cert(&self, chain_pem: &str, private_key: &Secret) {
        self.config_sync.broadcast(StreamRecord::CertPush(CertPush {
            protocol: PROTOCOL_VERSION,
            chain_pem: chain_pem.to_owned(),
            private_key: private_key.clone(),
        }));
    }

    /// Broadcasts an auth snapshot to every connected node.
    ///
    /// Best-effort: a full per-node queue drops the push, and offline nodes
    /// reconcile from the snapshot the master sends when they reconnect.
    pub fn push_auth_snapshot(&self, snapshot: &serde_json::Value) {
        self.config_sync
            .broadcast(StreamRecord::AuthSnapshotPush(AuthSnapshotPush {
                protocol: PROTOCOL_VERSION,
                snapshot: snapshot.clone(),
            }));
    }

    /// Ends a node's live downstream stream by dropping its sender.
    ///
    /// The stream task sees the closed channel, ends the NDJSON response, and
    /// unregisters itself. Called after a node is revoked so a compromised
    /// node stops receiving config, auth and certificate pushes immediately.
    pub fn disconnect(&self, node_id: &str) {
        self.config_sync.unregister(node_id);
    }
}

/// A running master cluster listener.
///
/// The server owns its own master certificate (issued by the cluster CA) so a
/// sub-node can pin its fingerprint for the bootstrap enroll.
pub struct ClusterServer {
    addr: SocketAddr,
    ca_cert_pem: String,
    server_cert_pem: String,
    config_sync: Arc<ConfigSync>,
    clock: Arc<dyn Clock>,
    shutdown: watch::Sender<bool>,
    handle: Option<tokio::task::JoinHandle<()>>,
}

impl ClusterServer {
    /// Binds the cluster listener and starts accepting mTLS HTTP/2 connections.
    ///
    /// `store` is shared with the caller (`ClusterStore` is cheaply cloneable)
    /// so the admin surface can read the registry. `write_executor` runs
    /// relayed writes after re-checking RBAC, `log_ingest` stores query
    /// logs streamed by sub-nodes, and `auth_snapshot` (when wired) is pushed
    /// to every node as it (re)connects. The master certificate is issued by
    /// `ca` for `config.server_name`; its fingerprint is exposed by
    /// [`Self::server_cert_pem`] for bootstrap pinning.
    #[allow(clippy::too_many_arguments)]
    pub async fn start(
        config: ClusterServerConfig,
        ca: ClusterCa,
        store: ClusterStore,
        clock: Arc<dyn Clock>,
        write_executor: Arc<dyn WriteExecutor>,
        log_ingest: Arc<dyn LogIngest>,
        auth_snapshot: Option<Arc<dyn AuthSnapshotSource>>,
    ) -> Result<Self, ClusterError> {
        // Defence in depth: the cluster listener is never exposed publicly.
        if config.listen.bind.is_unspecified()
            || !dnscraft_common::net::is_private(config.listen.bind)
        {
            return Err(ClusterError::RoleInvalid {
                reason: "cluster.listen.bind must be a loopback or private/ULA address".to_owned(),
            });
        }
        let bind = SocketAddr::new(config.listen.bind, config.listen.port);
        let listener = TcpListener::bind(bind)
            .await
            .map_err(|error| ClusterError::Internal {
                message: format!("bind cluster listener {bind}: {error}"),
            })?;
        let addr = listener
            .local_addr()
            .map_err(|error| ClusterError::Internal {
                message: format!("read cluster listener address: {error}"),
            })?;

        let (server_cert_pem, server_key_pem) = issue_server_certificate(
            &ca,
            &config.server_name,
            config.node_cert_ttl,
            clock.as_ref(),
        )?;
        let tls = server_tls_config(ca.cert_pem(), &server_cert_pem, &server_key_pem)?;
        let acceptor = TlsAcceptor::from(Arc::new(tls));

        let (shutdown, mut shutdown_rx) = watch::channel(false);
        let config_sync = ConfigSync::start(clock.clone(), shutdown_rx.clone());

        let state = Arc::new(ServerState {
            ca,
            store,
            clock: Arc::clone(&clock),
            node_cert_ttl: config.node_cert_ttl,
            config_sync: Arc::clone(&config_sync),
            quotas: QuotaLimiter::new(config.quota),
            write_executor,
            log_ingest,
            auth_snapshot,
        });
        let router = router(Arc::clone(&state));

        let handle = tokio::spawn(async move {
            loop {
                tokio::select! {
                    changed = shutdown_rx.changed() => {
                        if changed.is_err() || *shutdown_rx.borrow() {
                            break;
                        }
                    }
                    accepted = listener.accept() => {
                        let Ok((stream, _peer)) = accepted else {
                            continue;
                        };
                        let acceptor = acceptor.clone();
                        let router = router.clone();
                        tokio::spawn(async move {
                            let Ok(tls) = acceptor.accept(stream).await else {
                                // Handshake failure (for example a client
                                // certificate signed by another CA). The
                                // documented `cluster.transport.tls` code
                                // cannot be delivered once the handshake is
                                // rejected; there is no HTTP channel left.
                                return;
                            };
                            let peer = tls
                                .get_ref()
                                .1
                                .peer_certificates()
                                .and_then(|certs| certs.first())
                                .map(|der| PeerIdentity::from_der(der.as_ref()));
                            let io = TokioIo::new(tls);
                            let service = TowerToHyperService::new(router.layer(Extension(peer)));
                            let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                                .serve_connection(io, service)
                                .await;
                        });
                    }
                }
            }
        });

        Ok(Self {
            addr,
            ca_cert_pem: state.ca.cert_pem().to_owned(),
            server_cert_pem,
            config_sync,
            clock,
            shutdown,
            handle: Some(handle),
        })
    }

    /// The bound listener address (useful when the configured port was `0`).
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// The cluster CA certificate (PEM), for distributing to joined nodes.
    pub fn ca_cert_pem(&self) -> &str {
        &self.ca_cert_pem
    }

    /// The master's own server certificate (PEM), for bootstrap pinning.
    pub fn server_cert_pem(&self) -> &str {
        &self.server_cert_pem
    }

    /// The master-side config broadcast/lag registry.
    ///
    /// Call [`ConfigSync::publish`](crate::ConfigSync::publish) after every
    /// successful local config apply or rollback.
    pub fn config_sync(&self) -> &ConfigSync {
        self.config_sync.as_ref()
    }

    /// A cheaply cloneable handle to the config broadcast registry.
    ///
    /// Lets a caller (for example the control-api cluster runtime) publish from
    /// a spawned task without borrowing the server.
    pub fn config_sync_handle(&self) -> Arc<ConfigSync> {
        Arc::clone(&self.config_sync)
    }

    /// A cloneable broadcast handle for the master's volatile pushes.
    pub fn broadcast_handle(&self) -> ClusterBroadcast {
        ClusterBroadcast {
            config_sync: Arc::clone(&self.config_sync),
            clock: Arc::clone(&self.clock),
        }
    }

    /// Broadcasts a volatile runtime command to every connected node.
    ///
    /// Nothing is persisted or retried: nodes connect later do not see the
    /// command, and a command sent while a node is offline is lost (the
    /// caller re-issues it when needed).
    pub fn broadcast_runtime_command(&self, kind: &str, payload: &serde_json::Value) {
        self.broadcast_handle()
            .broadcast_runtime_command(kind, payload);
    }

    /// Broadcasts a renewed certificate/key to every connected node.
    ///
    /// Best-effort like [`Self::broadcast_runtime_command`]: a node that is
    /// offline keeps its previous certificate. The key travels only over the
    /// mTLS stream and is never logged.
    pub fn push_cert(&self, chain_pem: &str, private_key: &Secret) {
        self.broadcast_handle().push_cert(chain_pem, private_key);
    }

    /// Broadcasts an encrypted auth snapshot to every connected node.
    ///
    /// Best-effort: offline nodes reconcile from the master's next snapshot.
    pub fn push_auth_snapshot(&self, snapshot: &serde_json::Value) {
        self.broadcast_handle().push_auth_snapshot(snapshot);
    }

    /// Stops accepting new connections and waits for the accept loop to exit.
    ///
    /// Established connections finish on their own; dropping the server also
    /// signals shutdown.
    pub async fn shutdown(mut self) {
        let _ = self.shutdown.send(true);
        if let Some(handle) = self.handle.take() {
            let _ = handle.await;
        }
    }
}

impl Drop for ClusterServer {
    fn drop(&mut self) {
        let _ = self.shutdown.send(true);
    }
}

/// State shared by every route.
struct ServerState {
    ca: ClusterCa,
    store: ClusterStore,
    clock: Arc<dyn Clock>,
    node_cert_ttl: Duration,
    config_sync: Arc<ConfigSync>,
    quotas: QuotaLimiter,
    write_executor: Arc<dyn WriteExecutor>,
    log_ingest: Arc<dyn LogIngest>,
    auth_snapshot: Option<Arc<dyn AuthSnapshotSource>>,
}

/// Authenticated peer identity extracted from the client certificate chain.
#[derive(Clone, Debug)]
struct PeerIdentity {
    fingerprint: String,
    node_id: Option<String>,
}

impl PeerIdentity {
    fn from_der(der: &[u8]) -> Self {
        Self {
            fingerprint: cert_fingerprint(der),
            node_id: node_id_from_der(der),
        }
    }
}

/// `node_id` proven by the authenticated client certificate for one request.
#[derive(Clone, Debug)]
struct AuthenticatedNode(String);

fn router(state: Arc<ServerState>) -> Router {
    let protected = Router::new()
        .route("/cluster/v1/stream", get(stream))
        .route("/cluster/v1/ack", post(config_ack))
        .route("/cluster/v1/heartbeat", post(heartbeat))
        .route("/cluster/v1/logs", post(log_batch))
        .route("/cluster/v1/writes", post(write_relay))
        .route_layer(middleware::from_fn_with_state(
            Arc::clone(&state),
            authenticate,
        ));

    Router::new()
        .route("/cluster/v1/enroll", post(enroll))
        .merge(protected)
        .fallback(not_found)
        .with_state(state)
}

/// Binds every protected request to a registered, non-revoked certificate.
///
/// `node_id` comes from the certificate SAN; the registry is queried by that
/// id and its stored fingerprint must equal the presented certificate's
/// fingerprint. A request payload is never consulted.
async fn authenticate(
    State(state): State<Arc<ServerState>>,
    mut request: axum::extract::Request,
    next: middleware::Next,
) -> Response {
    let peer = request
        .extensions()
        .get::<Option<PeerIdentity>>()
        .cloned()
        .flatten();
    let Some(peer) = peer else {
        return error_response(&ClusterError::TransportTls {
            message: "client certificate required".to_owned(),
        });
    };
    let Some(node_id) = peer.node_id else {
        return error_response(&ClusterError::TransportTls {
            message: "client certificate has no node_id DNS SAN".to_owned(),
        });
    };

    match state.store.get_node(&node_id).await {
        Ok(Some(node)) if node.revoked => error_response(&ClusterError::NodeRevoked { node_id }),
        Ok(Some(node)) if node.fingerprint != peer.fingerprint => {
            error_response(&ClusterError::NodeUnknown { node_id })
        }
        Ok(Some(_)) => {
            request.extensions_mut().insert(AuthenticatedNode(node_id));
            next.run(request).await
        }
        Ok(None) => error_response(&ClusterError::NodeUnknown { node_id }),
        Err(error) => error_response(&error),
    }
}

async fn enroll(
    State(state): State<Arc<ServerState>>,
    Json(request): Json<crate::enroll::EnrollRequest>,
) -> Response {
    match run_enroll(
        &state.ca,
        &state.store,
        state.clock.as_ref(),
        state.node_cert_ttl,
        request,
    )
    .await
    {
        Ok(response) => Json(response).into_response(),
        Err(error) => error_response(&error),
    }
}

async fn heartbeat(
    State(state): State<Arc<ServerState>>,
    Extension(auth): Extension<AuthenticatedNode>,
    Json(request): Json<HeartbeatRequest>,
) -> Response {
    if request.protocol != PROTOCOL_VERSION {
        return error_response(&ClusterError::ProtocolVersion);
    }
    if let Err(error) = state.store.mark_seen(&auth.0).await {
        return error_response(&error);
    }
    if let Some(version) = request.applied_version
        && let Err(error) = state
            .store
            .set_applied_config_version(&auth.0, version)
            .await
    {
        return error_response(&error);
    }
    let now = state.clock.now();
    let mut warnings = Vec::new();
    if let Some(warning) = clock_skew_warning(
        request.time.as_deref(),
        now,
        state.quotas.limits().clock_skew_warning,
    ) {
        warnings.push(warning);
    }
    let queue_cap = state.quotas.limits().max_queued_offline_writes;
    if request.queue_depth > queue_cap {
        warnings.push(StatusWarning {
            code: ClusterError::OfflineWriteQueueFull.code().to_owned(),
            params: Some(json!({
                "queue_depth": request.queue_depth,
                "max_queued_offline_writes": queue_cap,
            })),
        });
    }
    Json(HeartbeatResponse {
        ok: true,
        received_at: rfc3339(now),
        warnings,
    })
    .into_response()
}

/// Warns when the node's reported clock differs from the master's by more than
/// `threshold`. A missing or unparseable timestamp is not fatal.
fn clock_skew_warning(
    reported: Option<&str>,
    now: SystemTime,
    threshold: Duration,
) -> Option<StatusWarning> {
    let reported = OffsetDateTime::parse(reported?, &Rfc3339).ok()?;
    let reported = SystemTime::from(reported);
    let skew = now
        .duration_since(reported)
        .unwrap_or_else(|error| error.duration());
    (skew > threshold).then(|| StatusWarning {
        code: ClusterError::ClockSkew.code().to_owned(),
        params: Some(json!({ "skew_seconds": skew.as_secs() })),
    })
}

/// Long-lived NDJSON downstream channel.
///
/// The sub-node may send its [`Hello`] as the GET request body; the header is
/// kept as a fallback for older peers. A protocol mismatch ends the stream with
/// a single `error` record. On success the master sends its `hello`, registers
/// the node for config pushes, and reconciles the node's `applied_version`
/// (master-wins on divergence).
async fn stream(
    State(state): State<Arc<ServerState>>,
    Extension(auth): Extension<AuthenticatedNode>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let hello = if body.is_empty() {
        None
    } else {
        match serde_json::from_slice::<StreamRecord>(&body) {
            Ok(StreamRecord::Hello(hello)) => Some(hello),
            _ => return error_record(&ClusterError::ProtocolVersion),
        }
    };
    let peer_protocol = hello.as_ref().map(|hello| hello.protocol).or_else(|| {
        headers
            .get(PROTOCOL_HEADER)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<u32>().ok())
    });
    if peer_protocol.is_some_and(|version| version != PROTOCOL_VERSION) {
        return error_record(&ClusterError::ProtocolVersion);
    }

    let last_applied_version = hello.as_ref().and_then(|hello| hello.last_applied_version);
    let (records, mut record_rx) = mpsc::channel::<StreamRecord>(8);
    // Backfill cursor: the sub-node resumes logging from this + 1.
    let master_highest_log_seq = state
        .log_ingest
        .highest_seq(&auth.0)
        .await
        .unwrap_or_default();
    let _ = records.try_send(StreamRecord::Hello(Hello {
        protocol: PROTOCOL_VERSION,
        node_id: auth.0.clone(),
        last_applied_version: state.config_sync.current_version(),
        last_acked_log_seq: Some(master_highest_log_seq),
    }));
    // Reconcile auth on every (re)connection: the change watcher alone means a
    // node that was offline across a revocation would keep the stale snapshot.
    // The channel is empty here, so this cannot be dropped by backpressure.
    if let Some(source) = &state.auth_snapshot
        && let Ok(snapshot) = source.snapshot().await
    {
        let _ = records.try_send(StreamRecord::AuthSnapshotPush(AuthSnapshotPush {
            protocol: PROTOCOL_VERSION,
            snapshot,
        }));
    }
    state
        .config_sync
        .register(&auth.0, last_applied_version, records);

    let (tx, rx) = mpsc::channel::<Result<Bytes, Infallible>>(8);
    let config_sync = Arc::clone(&state.config_sync);
    let store = state.store.clone();
    let node_id = auth.0.clone();
    tokio::spawn(async move {
        loop {
            tokio::select! {
                record = record_rx.recv() => {
                    let Some(record) = record else { break };
                    // Defence in depth: a revoke that did not go through the
                    // admin disconnect path still terminates the stream before
                    // the next push is delivered.
                    if let Ok(Some(node)) = store.get_node(&node_id).await
                        && node.revoked
                    {
                        let error = StreamRecord::Error {
                            error: StreamError {
                                code: ClusterError::NodeRevoked {
                                    node_id: node_id.clone(),
                                }
                                .code()
                                .to_owned(),
                                params: Some(json!({ "node_id": &node_id })),
                            },
                        };
                        if let Ok(line) = serde_json::to_string(&error) {
                            let mut bytes = line.into_bytes();
                            bytes.push(b'\n');
                            let _ = tx.send(Ok(Bytes::from(bytes))).await;
                        }
                        break;
                    }
                    let Ok(line) = serde_json::to_string(&record) else { continue };
                    let mut bytes = line.into_bytes();
                    bytes.push(b'\n');
                    if tx.send(Ok(Bytes::from(bytes))).await.is_err() {
                        break;
                    }
                }
                () = tx.closed() => break,
            }
        }
        config_sync.unregister(&node_id);
    });

    let mut response = Body::from_stream(ReceiverStream::new(rx)).into_response();
    response
        .headers_mut()
        .insert(header::CONTENT_TYPE, HeaderValue::from_static(NDJSON));
    response
}

/// `POST /cluster/v1/ack` — records a sub-node's applied config version.
async fn config_ack(
    State(state): State<Arc<ServerState>>,
    Extension(auth): Extension<AuthenticatedNode>,
    Json(ack): Json<ConfigAck>,
) -> Response {
    if ack.applied_version < 0 {
        return error_response(&ClusterError::ConfigApply {
            message: "applied_version must not be negative".to_owned(),
        });
    }
    state.config_sync.ack(&auth.0, ack.applied_version);
    match state
        .store
        .set_applied_config_version(&auth.0, ack.applied_version)
        .await
    {
        Ok(()) => Json(json!({ "ok": true })).into_response(),
        Err(error) => error_response(&error),
    }
}

/// `POST /cluster/v1/logs` — ingests one contiguous query-log batch.
///
/// The body is parsed by hand so a malformed batch yields
/// `cluster.log_stream.invalid` rather than axum's rejection. `node_id` is
/// taken from the certificate; the payload copy must match it. The ingest hook
/// owns deduplication and gap recording.
async fn log_batch(
    State(state): State<Arc<ServerState>>,
    Extension(auth): Extension<AuthenticatedNode>,
    body: Bytes,
) -> Response {
    // Charge the raw payload before parsing, so malformed floods are bounded
    // too. Exceeding the per-node byte budget rejects the batch; the node keeps
    // its contiguous sequence and can retry after the bucket refills.
    if !state
        .quotas
        .allow_log_bytes(&auth.0, body.len() as u64, state.clock.now())
    {
        return error_response(&quota_exceeded(&auth.0, "log byte"));
    }
    let batch: LogBatch = match serde_json::from_slice(&body) {
        Ok(batch) => batch,
        Err(_) => {
            return error_response(&ClusterError::LogStreamInvalid {
                reason: "malformed log batch".to_owned(),
            });
        }
    };
    if let Err(error) = batch.validate(&auth.0) {
        return error_response(&error);
    }
    match state
        .log_ingest
        .ingest(&auth.0, batch.first_seq, batch.last_seq, &batch.records)
        .await
    {
        Ok(acked_seq) => Json(LogAck { acked_seq }).into_response(),
        Err(error) => error_response(&error),
    }
}

/// `POST /cluster/v1/writes` — executes a write relayed by a sub-node.
///
/// The same status and body the canonical handler produced are returned, so
/// the sub-node can relay them verbatim. RBAC re-check, persistence, apply and
/// idempotency belong to the [`WriteExecutor`].
async fn write_relay(
    State(state): State<Arc<ServerState>>,
    Extension(auth): Extension<AuthenticatedNode>,
    Json(relay): Json<WriteRelay>,
) -> Response {
    if !state.quotas.allow_relay(&auth.0, state.clock.now()) {
        return error_response(&quota_exceeded(&auth.0, "relay request"));
    }
    match state
        .write_executor
        .execute(
            &auth.0,
            relay.actor,
            relay.method,
            relay.path,
            relay.body,
            relay.if_match,
            relay.idempotency_key,
        )
        .await
    {
        Ok(response) => {
            let status =
                StatusCode::from_u16(response.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
            (status, Json(response.body)).into_response()
        }
        Err(error) => error_response(&error),
    }
}

/// A node exceeded one of its `[cluster.quota]` rate limits (HTTP 429).
fn quota_exceeded(node_id: &str, what: &str) -> ClusterError {
    ClusterError::QuotaExceeded {
        node_id: node_id.to_owned(),
        what: what.to_owned(),
    }
}

/// A stream terminated by one `error` record.
fn error_record(error: &ClusterError) -> Response {
    let record = StreamRecord::Error {
        error: StreamError {
            code: error.code().to_owned(),
            params: None,
        },
    };
    let line = serde_json::to_string(&record).unwrap_or_default();
    let mut response = Body::from(format!("{line}\n")).into_response();
    response
        .headers_mut()
        .insert(header::CONTENT_TYPE, HeaderValue::from_static(NDJSON));
    response
}

/// Phase 4/5 routes exist but are not served yet.
async fn not_found(uri: Uri) -> Response {
    (
        StatusCode::NOT_FOUND,
        Json(json!({
            "error": {
                "code": "control_api.not_found",
                "params": { "what": uri.path() },
            },
        })),
    )
        .into_response()
}

fn error_response(error: &ClusterError) -> Response {
    let status = match error {
        ClusterError::TransportTls { .. }
        | ClusterError::NodeUnknown { .. }
        | ClusterError::NodeRevoked { .. }
        | ClusterError::JoinTokenInvalid
        | ClusterError::JoinTokenExpired => StatusCode::FORBIDDEN,
        ClusterError::NodeAlreadyJoined { .. } => StatusCode::CONFLICT,
        ClusterError::ProtocolVersion
        | ClusterError::RoleInvalid { .. }
        | ClusterError::LogStreamInvalid { .. }
        | ClusterError::LogGap { .. } => StatusCode::BAD_REQUEST,
        ClusterError::MasterUnavailable => StatusCode::SERVICE_UNAVAILABLE,
        ClusterError::QuotaExceeded { .. } => StatusCode::TOO_MANY_REQUESTS,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    };
    let mut body = json!({ "error": { "code": error.code() } });
    match error {
        ClusterError::NodeUnknown { node_id } | ClusterError::NodeRevoked { node_id } => {
            body["error"]["params"] = json!({ "node_id": node_id });
        }
        ClusterError::NodeAlreadyJoined { node_id } => {
            body["error"]["params"] = json!({ "node_id": node_id });
        }
        ClusterError::RoleInvalid { reason } | ClusterError::LogStreamInvalid { reason } => {
            body["error"]["params"] = json!({ "reason": reason });
        }
        ClusterError::LogGap { missing } => {
            body["error"]["params"] = json!({ "missing": missing });
        }
        ClusterError::QuotaExceeded { node_id, what } => {
            body["error"]["params"] = json!({ "node_id": node_id, "what": what });
        }
        _ => {}
    }
    (status, Json(body)).into_response()
}

/// Issues the master's own server certificate from the cluster CA.
fn issue_server_certificate(
    ca: &ClusterCa,
    server_name: &str,
    ttl: Duration,
    clock: &dyn Clock,
) -> Result<(String, String), ClusterError> {
    let key =
        KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).map_err(|error| ClusterError::Internal {
            message: format!("master key generation: {error}"),
        })?;
    let mut params =
        CertificateParams::new(Vec::new()).map_err(|error| ClusterError::Internal {
            message: format!("master certificate params: {error}"),
        })?;
    params
        .distinguished_name
        .push(DnType::CommonName, server_name);
    params.subject_alt_names = vec![server_name_san(server_name)?];
    params.is_ca = IsCa::NoCa;
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![
        ExtendedKeyUsagePurpose::ServerAuth,
        ExtendedKeyUsagePurpose::ClientAuth,
    ];
    params.not_before = OffsetDateTime::from(clock.now());
    let ttl = time::Duration::try_from(ttl).map_err(|_| ClusterError::Internal {
        message: "master certificate lifetime is out of range".to_owned(),
    })?;
    params.not_after =
        params
            .not_before
            .checked_add(ttl)
            .ok_or_else(|| ClusterError::Internal {
                message: "master certificate lifetime overflows".to_owned(),
            })?;
    params.use_authority_key_identifier_extension = true;

    let cert = ca.sign(&params, &key)?;
    Ok((cert.pem(), key.serialize_pem()))
}

fn server_name_san(server_name: &str) -> Result<SanType, ClusterError> {
    if let Ok(ip) = server_name.parse::<IpAddr>() {
        return Ok(SanType::IpAddress(ip));
    }
    // `CertificateParams::new` parses DNS names into the correct SAN type.
    CertificateParams::new(vec![server_name.to_owned()])
        .ok()
        .and_then(|params| params.subject_alt_names.into_iter().next())
        .ok_or_else(|| ClusterError::Internal {
            message: format!("invalid cluster server_name {server_name:?}"),
        })
}

/// TLS 1.3 + HTTP/2 server, client certificates chained to the cluster CA.
fn server_tls_config(
    ca_cert_pem: &str,
    server_cert_pem: &str,
    server_key_pem: &str,
) -> Result<rustls::ServerConfig, ClusterError> {
    let mut roots = RootCertStore::empty();
    let ca = CertificateDer::from_pem_slice(ca_cert_pem.as_bytes())
        .map_err(|error| tls_config_error(format!("cluster CA PEM: {error}")))?;
    roots
        .add(ca)
        .map_err(|error| tls_config_error(format!("cluster CA root: {error}")))?;

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    // `allow_unauthenticated` is required by the bootstrap enroll route: a
    // node has no certificate before it enrolls. Protected routes require the
    // peer certificate at the HTTP layer. Any certificate that *is* presented
    // must chain to the cluster CA here, during the handshake.
    let verifier = WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider.clone())
        .allow_unauthenticated()
        .build()
        .map_err(|error| tls_config_error(format!("client certificate verifier: {error}")))?;

    let certs = CertificateDer::pem_slice_iter(server_cert_pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| tls_config_error(format!("master certificate PEM: {error}")))?;
    let key = PrivateKeyDer::from_pem_slice(server_key_pem.as_bytes())
        .map_err(|error| tls_config_error(format!("master key PEM: {error}")))?;

    let mut config = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|error| tls_config_error(format!("TLS 1.3: {error}")))?
        .with_client_cert_verifier(verifier)
        .with_single_cert(certs, key)
        .map_err(|error| tls_config_error(format!("master certificate/key: {error}")))?;
    config.alpn_protocols = vec![b"h2".to_vec()];
    Ok(config)
}

fn tls_config_error(message: String) -> ClusterError {
    ClusterError::TransportTls { message }
}

/// RFC 3339 (UTC, seconds precision) for a [`SystemTime`].
pub(crate) fn rfc3339(time: SystemTime) -> String {
    OffsetDateTime::from(time)
        .format(&Rfc3339)
        .unwrap_or_default()
}
