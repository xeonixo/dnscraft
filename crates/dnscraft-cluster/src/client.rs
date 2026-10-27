//! Sub-node outbound mTLS client.
//!
//! The sub-node always dials the master (the master never dials a sub-node).
//! The client presents its node certificate for the mTLS channel opened by
//! [`ClusterClient::open_stream`], sends heartbeats, and performs the one-time
//! enrollment over a certificate-pinned bootstrap connection.
//!
//! Reconnects use exponential backoff driven by the injectable
//! [`Clock`] ([`ClusterClient::connect`]); there are no wall-clock sleeps.

use std::sync::Arc;
use std::time::Duration;

use dnscraft_common::clock::{Clock, add_duration, wait_until};
use reqwest::Client;
use rustls::RootCertStore;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{ring as ring_provider, verify_tls12_signature, verify_tls13_signature};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, Error as RustlsError};
use serde::Deserialize;

use crate::ca::cert_fingerprint;
use crate::config::{
    DEFAULT_MASTER_TIMEOUT, DEFAULT_RECONNECT_BACKOFF, DEFAULT_RECONNECT_BACKOFF_MAX,
};
use crate::enroll::{EnrollRequest, EnrollResponse, PROTOCOL_VERSION};
use crate::error::ClusterError;
use crate::identity::NodeIdentity;
use crate::log::{LogAck, LogBatch};
use crate::relay::{RelayResponse, RuntimeCommand, RuntimeCommandApplier, WriteRelay};
use crate::server::{HeartbeatRequest, HeartbeatResponse, PROTOCOL_HEADER, rfc3339};
use crate::sync::{
    AuthSnapshotApplier, AuthSnapshotPush, CertInstaller, CertPush, ConfigAck, ConfigApplier,
    ConfigPush, Hello, StreamError, StreamRecord,
};

const ENROLL_PATH: &str = "/cluster/v1/enroll";
const STREAM_PATH: &str = "/cluster/v1/stream";
const HEARTBEAT_PATH: &str = "/cluster/v1/heartbeat";
const ACK_PATH: &str = "/cluster/v1/ack";
const LOGS_PATH: &str = "/cluster/v1/logs";
const RELAY_PATH: &str = "/cluster/v1/writes";
const NDJSON: &str = "application/x-ndjson";

/// A sub-node's HTTP/2 mTLS client for the master's cluster listener.
pub struct ClusterClient {
    http: Client,
    base_url: String,
    node_id: String,
    clock: Arc<dyn Clock>,
}

impl ClusterClient {
    /// Builds an mTLS client from a persisted node identity.
    ///
    /// The client trusts `identity.ca_cert_pem()` and presents the node
    /// certificate/key. `node_id` is read from the certificate's DNS SAN, so
    /// the client and master agree on the identity the channel carries.
    pub fn new(
        master_url: &str,
        identity: &NodeIdentity,
        clock: Arc<dyn Clock>,
    ) -> Result<Self, ClusterError> {
        let base_url = normalize_master_url(master_url)?;
        let node_id = node_id_from_pem(identity.node_cert_pem())?;
        Ok(Self {
            http: mtls_client(identity)?,
            base_url,
            node_id,
            clock,
        })
    }

    /// The `node_id` carried by this node's certificate.
    pub fn node_id(&self) -> &str {
        &self.node_id
    }

    /// Enrolls this node over a bootstrap connection that trusts exactly
    /// `master_cert_pem` (SHA-256 pin).
    ///
    /// This is the only request made without a node certificate. The join
    /// token travels once, inside [`EnrollRequest`].
    pub async fn enroll(
        master_url: &str,
        master_cert_pem: &str,
        request: EnrollRequest,
    ) -> Result<EnrollResponse, ClusterError> {
        let base_url = normalize_master_url(master_url)?;
        let http = pinned_client(master_cert_pem)?;
        let body = serde_json::to_vec(&request).map_err(|error| ClusterError::Internal {
            message: format!("encode enroll request: {error}"),
        })?;
        let response = http
            .post(format!("{base_url}{ENROLL_PATH}"))
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(body)
            .send()
            .await
            .map_err(master_unavailable)?;
        json_body(ensure_success(response).await?).await
    }

    /// Opens the long-lived downstream stream and consumes the `hello`.
    pub async fn open_stream(&self) -> Result<ClusterStream, ClusterError> {
        self.open_stream_with(None, None).await
    }

    /// Opens the stream, sending [`Hello`] with the node's applied version and
    /// last acknowledged log sequence.
    ///
    /// The `Hello` travels as the GET request body (NDJSON); the protocol
    /// header is kept for compatibility. The returned [`ClusterStream`] keeps
    /// the response open for push records.
    pub async fn open_stream_with(
        &self,
        last_applied_version: Option<i64>,
        last_acked_log_seq: Option<u64>,
    ) -> Result<ClusterStream, ClusterError> {
        let hello = StreamRecord::Hello(Hello {
            protocol: PROTOCOL_VERSION,
            node_id: self.node_id.clone(),
            last_applied_version,
            last_acked_log_seq,
        });
        let body = serde_json::to_vec(&hello).map_err(|error| ClusterError::Internal {
            message: format!("encode stream hello: {error}"),
        })?;
        let response = self
            .http
            .get(format!("{}{STREAM_PATH}", self.base_url))
            .header(PROTOCOL_HEADER, PROTOCOL_VERSION.to_string())
            .header(reqwest::header::CONTENT_TYPE, NDJSON)
            .body(body)
            .send()
            .await
            .map_err(master_unavailable)?;
        let mut response = ensure_success(response).await?;

        let mut buffer = Vec::new();
        let line = read_line(&mut response, &mut buffer).await?;
        let record: StreamRecord =
            serde_json::from_slice(&line).map_err(|error| ClusterError::TransportTls {
                message: format!("invalid stream hello: {error}"),
            })?;
        match record {
            StreamRecord::Hello(Hello {
                protocol,
                node_id,
                last_acked_log_seq,
                ..
            }) => {
                if protocol != PROTOCOL_VERSION {
                    return Err(ClusterError::ProtocolVersion);
                }
                if node_id != self.node_id {
                    return Err(ClusterError::TransportTls {
                        message: "master bound the stream to another node_id".to_owned(),
                    });
                }
                Ok(ClusterStream {
                    node_id,
                    protocol,
                    master_highest_log_seq: last_acked_log_seq,
                    response,
                    buffer,
                })
            }
            StreamRecord::Error { error } => Err(map_wire_error(&error)),
            _ => Err(ClusterError::TransportTls {
                message: "master did not start the stream with hello".to_owned(),
            }),
        }
    }

    /// Reads one stream record, applying and acking a `config_push`.
    ///
    /// Returns the applied version when a push was handled, `None` for any
    /// other record. A digest mismatch or applier failure is returned without
    /// acking; the applier owns rollback.
    pub async fn apply_next(
        &self,
        stream: &mut ClusterStream,
        applier: &dyn ConfigApplier,
    ) -> Result<Option<i64>, ClusterError> {
        match stream.next_record().await? {
            StreamRecord::ConfigPush(push) => self.apply_push(&push, applier).await.map(Some),
            StreamRecord::Error { error } => Err(map_wire_error(&error)),
            _ => Ok(None),
        }
    }

    /// Verifies a push digest, applies it, and posts [`ConfigAck`].
    ///
    /// The snapshot is never applied on a digest mismatch
    /// (`cluster.config.apply`). An applier error propagates unchanged and no
    /// ack is sent, so the master keeps retrying and the previous version
    /// stays active.
    pub async fn apply_push(
        &self,
        push: &ConfigPush,
        applier: &dyn ConfigApplier,
    ) -> Result<i64, ClusterError> {
        if push.protocol != PROTOCOL_VERSION {
            return Err(ClusterError::ProtocolVersion);
        }
        push.verify_digest()?;
        let applied_version = applier.apply(push.config_version, &push.snapshot).await?;
        self.post_ack(applied_version).await?;
        Ok(applied_version)
    }

    /// Reads one stream record; applies a broadcast runtime command.
    ///
    /// Returns `true` when a command was applied, `false` for any other
    /// record. The command is not queued: if the applier fails the error is
    /// [`ClusterError::RuntimeCommandFailed`] and the command is dropped.
    pub async fn apply_runtime_next(
        &self,
        stream: &mut ClusterStream,
        applier: &dyn RuntimeCommandApplier,
    ) -> Result<bool, ClusterError> {
        match stream.next_record().await? {
            StreamRecord::RuntimeCommand(command) => {
                self.apply_runtime_command(&command, applier).await?;
                Ok(true)
            }
            StreamRecord::Error { error } => Err(map_wire_error(&error)),
            _ => Ok(false),
        }
    }

    /// Applies one runtime command through `applier`.
    ///
    /// Any applier failure is reported as `cluster.runtime_command.failed`.
    pub async fn apply_runtime_command(
        &self,
        command: &RuntimeCommand,
        applier: &dyn RuntimeCommandApplier,
    ) -> Result<(), ClusterError> {
        applier
            .apply_runtime_command(&command.kind, &command.payload)
            .await
            .map_err(|error| match error {
                ClusterError::RuntimeCommandFailed { .. } => error,
                other => ClusterError::RuntimeCommandFailed {
                    message: other.to_string(),
                },
            })
    }

    /// Reads one stream record; installs a pushed certificate.
    ///
    /// Returns `true` when a `cert_push` was handled, `false` for any other
    /// record. The key is handed to the installer by reference and never
    /// formatted or logged here.
    pub async fn apply_cert_next(
        &self,
        stream: &mut ClusterStream,
        installer: &dyn CertInstaller,
    ) -> Result<bool, ClusterError> {
        match stream.next_record().await? {
            StreamRecord::CertPush(push) => {
                self.apply_cert(&push, installer).await?;
                Ok(true)
            }
            StreamRecord::Error { error } => Err(map_wire_error(&error)),
            _ => Ok(false),
        }
    }

    /// Installs one pushed certificate/key through `installer`.
    ///
    /// Any installer failure is reported as `cluster.cert_push.failed`.
    pub async fn apply_cert(
        &self,
        push: &CertPush,
        installer: &dyn CertInstaller,
    ) -> Result<(), ClusterError> {
        if push.protocol != PROTOCOL_VERSION {
            return Err(ClusterError::ProtocolVersion);
        }
        installer
            .install(&push.chain_pem, &push.private_key)
            .await
            .map_err(|error| match error {
                ClusterError::CertPushFailed { .. } => error,
                other => ClusterError::CertPushFailed {
                    message: other.to_string(),
                },
            })
    }

    /// Reads one stream record; applies a pushed auth snapshot.
    ///
    /// Returns `true` when an `auth_snapshot` was applied, `false` for any
    /// other record.
    pub async fn apply_auth_snapshot_next(
        &self,
        stream: &mut ClusterStream,
        applier: &dyn AuthSnapshotApplier,
    ) -> Result<bool, ClusterError> {
        match stream.next_record().await? {
            StreamRecord::AuthSnapshotPush(push) => {
                self.apply_auth_snapshot(&push, applier).await?;
                Ok(true)
            }
            StreamRecord::Error { error } => Err(map_wire_error(&error)),
            _ => Ok(false),
        }
    }

    /// Applies one auth snapshot through `applier`; its error propagates
    /// unchanged.
    pub async fn apply_auth_snapshot(
        &self,
        push: &AuthSnapshotPush,
        applier: &dyn AuthSnapshotApplier,
    ) -> Result<(), ClusterError> {
        if push.protocol != PROTOCOL_VERSION {
            return Err(ClusterError::ProtocolVersion);
        }
        applier.apply(&push.snapshot).await
    }

    async fn post_ack(&self, applied_version: i64) -> Result<(), ClusterError> {
        let body = serde_json::to_vec(&StreamRecord::Ack(ConfigAck { applied_version })).map_err(
            |error| ClusterError::Internal {
                message: format!("encode config ack: {error}"),
            },
        )?;
        let response = self
            .http
            .post(format!("{}{ACK_PATH}", self.base_url))
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(body)
            .send()
            .await
            .map_err(master_unavailable)?;
        ensure_success(response).await?;
        Ok(())
    }

    /// Posts one log batch and returns the master's highest contiguous `seq`.
    ///
    /// `node_id` is sent for the wire shape only; the master derives the real
    /// identity from the client certificate and rejects a mismatch with
    /// `cluster.log_stream.invalid`. The records are opaque to this crate.
    pub async fn post_logs(&self, batch: &LogBatch) -> Result<u64, ClusterError> {
        let body = serde_json::to_vec(batch).map_err(|error| ClusterError::Internal {
            message: format!("encode log batch: {error}"),
        })?;
        let response = self
            .http
            .post(format!("{}{LOGS_PATH}", self.base_url))
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(body)
            .send()
            .await
            .map_err(master_unavailable)?;
        let ack: LogAck = json_body(ensure_success(response).await?).await?;
        Ok(ack.acked_seq)
    }

    /// Sends one heartbeat; `applied_version`/`queue_depth` are reported as-is.
    ///
    /// The master derives `node_id` from the client certificate, never from
    /// this body. The node's current clock time is included so the master can
    /// flag `cluster.clock_skew`; it is advisory, never an authority.
    pub async fn heartbeat(
        &self,
        applied_version: Option<i64>,
        queue_depth: u32,
    ) -> Result<HeartbeatResponse, ClusterError> {
        let request = HeartbeatRequest {
            protocol: PROTOCOL_VERSION,
            applied_version,
            queue_depth,
            time: Some(rfc3339(self.clock.now())),
        };
        let body = serde_json::to_vec(&request).map_err(|error| ClusterError::Internal {
            message: format!("encode heartbeat: {error}"),
        })?;
        let response = self
            .http
            .post(format!("{}{HEARTBEAT_PATH}", self.base_url))
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(body)
            .send()
            .await
            .map_err(master_unavailable)?;
        json_body(ensure_success(response).await?).await
    }

    /// Relays one write to the master and returns its response verbatim.
    ///
    /// Transport failures are retried with the same encoded [`WriteRelay`]
    /// (same `request_id` and `Idempotency-Key`) using clock-driven backoff
    /// until [`DEFAULT_MASTER_TIMEOUT`] elapses, then
    /// [`ClusterError::WriteRelayFailed`]. A response from the master, including
    /// a `4xx`/`5xx`, is returned unchanged and never retried. The sub-node
    /// never applies the write locally.
    pub async fn relay_write(&self, relay: WriteRelay) -> Result<RelayResponse, ClusterError> {
        let body = serde_json::to_vec(&relay).map_err(|error| ClusterError::Internal {
            message: format!("encode write relay: {error}"),
        })?;
        let deadline = add_duration(self.clock.now(), DEFAULT_MASTER_TIMEOUT);
        let wake = tokio::sync::Notify::new();
        let mut backoff = Backoff::new(DEFAULT_RECONNECT_BACKOFF, DEFAULT_RECONNECT_BACKOFF_MAX);
        loop {
            match self.post_relay(&body).await {
                Ok(response) => return Ok(response),
                Err(ClusterError::MasterUnavailable) => {
                    let now = self.clock.now();
                    let remaining = deadline.duration_since(now).unwrap_or(Duration::ZERO);
                    if remaining.is_zero() {
                        return Err(ClusterError::WriteRelayFailed);
                    }
                    let delay = backoff.next_delay().min(remaining);
                    wait_until(self.clock.as_ref(), add_duration(now, delay), &wake).await;
                    if self.clock.now() >= deadline {
                        return Err(ClusterError::WriteRelayFailed);
                    }
                }
                Err(error) => return Err(error),
            }
        }
    }

    async fn post_relay(&self, body: &[u8]) -> Result<RelayResponse, ClusterError> {
        let response = self
            .http
            .post(format!("{}{RELAY_PATH}", self.base_url))
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(body.to_vec())
            .send()
            .await
            .map_err(master_unavailable)?;
        let status = response.status().as_u16();
        let bytes = response.bytes().await.map_err(master_unavailable)?;
        let body = serde_json::from_slice(&bytes).map_err(|_| ClusterError::WriteRelayFailed)?;
        Ok(RelayResponse { status, body })
    }

    /// Opens the stream, retrying transient failures with exponential backoff.
    ///
    /// Waits are driven by the injected [`Clock`] (no wall-clock sleeps) and
    /// are interrupted by `shutdown`. Authentication, revocation and protocol
    /// failures are returned immediately because retrying cannot fix them.
    pub async fn connect(
        &self,
        shutdown: &tokio::sync::Notify,
    ) -> Result<ClusterStream, ClusterError> {
        self.connect_with(None, None, shutdown).await
    }

    /// [`connect`](Self::connect) with the node's last applied version and log
    /// sequence, so the master reconciles config immediately on reconnect.
    pub async fn connect_with(
        &self,
        last_applied_version: Option<i64>,
        last_acked_log_seq: Option<u64>,
        shutdown: &tokio::sync::Notify,
    ) -> Result<ClusterStream, ClusterError> {
        let mut backoff = Backoff::new(DEFAULT_RECONNECT_BACKOFF, DEFAULT_RECONNECT_BACKOFF_MAX);
        loop {
            match self
                .open_stream_with(last_applied_version, last_acked_log_seq)
                .await
            {
                Ok(stream) => return Ok(stream),
                Err(ClusterError::MasterUnavailable) => {}
                Err(error) => return Err(error),
            }

            let delay = backoff.next_delay();
            let deadline = add_duration(self.clock.now(), delay);
            tokio::select! {
                () = wait_until(self.clock.as_ref(), deadline, shutdown) => {}
                () = shutdown.notified() => return Err(ClusterError::MasterUnavailable),
            }
        }
    }
}

/// A live downstream stream whose `hello` has been validated.
pub struct ClusterStream {
    node_id: String,
    protocol: u32,
    master_highest_log_seq: Option<u64>,
    /// Kept alive so the HTTP/2 response body stays open.
    response: reqwest::Response,
    /// Leftover bytes after the last record read.
    buffer: Vec<u8>,
}

impl ClusterStream {
    /// The `node_id` the master derived from this connection's certificate.
    pub fn node_id(&self) -> &str {
        &self.node_id
    }

    /// The negotiated cluster protocol version.
    pub fn protocol(&self) -> u32 {
        self.protocol
    }

    /// Highest contiguous log `seq` the master has stored for this node.
    ///
    /// Pass it to [`crate::LogStreamer::backfill`] after a reconnect; `None`
    /// means the master sent no log cursor.
    pub fn master_highest_log_seq(&self) -> Option<u64> {
        self.master_highest_log_seq
    }

    /// Reads the next NDJSON record from the master.
    pub async fn next_record(&mut self) -> Result<StreamRecord, ClusterError> {
        loop {
            let line = read_line(&mut self.response, &mut self.buffer).await?;
            if line.iter().all(u8::is_ascii_whitespace) {
                continue;
            }
            return serde_json::from_slice(&line).map_err(|error| ClusterError::TransportTls {
                message: format!("invalid cluster stream record: {error}"),
            });
        }
    }
}

#[derive(Debug, Deserialize)]
struct ErrorEnvelope {
    error: StreamError,
}

fn map_wire_error(error: &StreamError) -> ClusterError {
    let node_id = error
        .params
        .as_ref()
        .and_then(|params| params.get("node_id"))
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default()
        .to_owned();
    match error.code.as_str() {
        "cluster.join.token_invalid" => ClusterError::JoinTokenInvalid,
        "cluster.join.token_expired" => ClusterError::JoinTokenExpired,
        "cluster.node.already_joined" => ClusterError::NodeAlreadyJoined { node_id },
        "cluster.node.unknown" => ClusterError::NodeUnknown { node_id },
        "cluster.node.revoked" => ClusterError::NodeRevoked { node_id },
        "cluster.protocol.version" => ClusterError::ProtocolVersion,
        "cluster.log_stream.invalid" => ClusterError::LogStreamInvalid {
            reason: "rejected by the master".to_owned(),
        },
        "cluster.log_gap" => ClusterError::LogGap {
            missing: error
                .params
                .as_ref()
                .and_then(|params| params.get("missing"))
                .and_then(serde_json::Value::as_u64)
                .unwrap_or_default(),
        },
        "cluster.master_unavailable" => ClusterError::MasterUnavailable,
        "cluster.quota.exceeded" => ClusterError::QuotaExceeded {
            node_id,
            what: error
                .params
                .as_ref()
                .and_then(|params| params.get("what"))
                .and_then(serde_json::Value::as_str)
                .unwrap_or("quota")
                .to_owned(),
        },
        "cluster.internal" => ClusterError::Internal {
            message: "rejected by the master".to_owned(),
        },
        "cluster.transport.tls" => ClusterError::TransportTls {
            message: "rejected by the cluster listener".to_owned(),
        },
        other => ClusterError::TransportTls {
            message: format!("master returned {other}"),
        },
    }
}

/// Rejects a non-2xx response with the master's `cluster.*` code.
async fn ensure_success(response: reqwest::Response) -> Result<reqwest::Response, ClusterError> {
    let status = response.status();
    if status.is_success() {
        return Ok(response);
    }
    let bytes = response.bytes().await.unwrap_or_default();
    match serde_json::from_slice::<ErrorEnvelope>(&bytes) {
        Ok(envelope) => Err(map_wire_error(&envelope.error)),
        Err(_) => Err(ClusterError::TransportTls {
            message: format!("master returned HTTP {status}"),
        }),
    }
}

fn master_unavailable(_error: reqwest::Error) -> ClusterError {
    ClusterError::MasterUnavailable
}

/// Decodes a successful JSON response body.
async fn json_body<T: serde::de::DeserializeOwned>(
    response: reqwest::Response,
) -> Result<T, ClusterError> {
    let bytes = response.bytes().await.map_err(master_unavailable)?;
    serde_json::from_slice(&bytes).map_err(|error| ClusterError::TransportTls {
        message: format!("invalid cluster response: {error}"),
    })
}

fn normalize_master_url(master_url: &str) -> Result<String, ClusterError> {
    let trimmed = master_url.trim_end_matches('/');
    if !trimmed.starts_with("https://") {
        return Err(ClusterError::RoleInvalid {
            reason: "master_url must be https://".to_owned(),
        });
    }
    Ok(trimmed.to_owned())
}

fn node_id_from_pem(cert_pem: &str) -> Result<String, ClusterError> {
    let der = CertificateDer::from_pem_slice(cert_pem.as_bytes()).map_err(|error| {
        ClusterError::TransportTls {
            message: format!("node certificate PEM: {error}"),
        }
    })?;
    crate::ca::node_id_from_der(der.as_ref()).ok_or(ClusterError::TransportTls {
        message: "node certificate has no node_id DNS SAN".to_owned(),
    })
}

/// mTLS client: cluster CA roots, node certificate/key, TLS 1.3, ALPN h2.
fn mtls_client(identity: &NodeIdentity) -> Result<Client, ClusterError> {
    let mut roots = RootCertStore::empty();
    let ca =
        CertificateDer::from_pem_slice(identity.ca_cert_pem().as_bytes()).map_err(|error| {
            ClusterError::TransportTls {
                message: format!("cluster CA PEM: {error}"),
            }
        })?;
    roots.add(ca).map_err(|error| ClusterError::TransportTls {
        message: format!("cluster CA root: {error}"),
    })?;

    let certs = CertificateDer::pem_slice_iter(identity.node_cert_pem().as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| ClusterError::TransportTls {
            message: format!("node certificate PEM: {error}"),
        })?;
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(identity.key().serialize_der()));

    let provider = Arc::new(ring_provider::default_provider());
    let mut tls = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|error| ClusterError::TransportTls {
            message: format!("TLS 1.3: {error}"),
        })?
        .with_root_certificates(roots)
        .with_client_auth_cert(certs, key)
        .map_err(|error| ClusterError::TransportTls {
            message: format!("node certificate/key: {error}"),
        })?;
    tls.alpn_protocols = vec![b"h2".to_vec()];
    http_client(tls)
}

/// Bootstrap client: trusts exactly the pinned master certificate.
fn pinned_client(master_cert_pem: &str) -> Result<Client, ClusterError> {
    let cert = CertificateDer::from_pem_slice(master_cert_pem.as_bytes()).map_err(|error| {
        ClusterError::TransportTls {
            message: format!("master certificate PEM: {error}"),
        }
    })?;
    let provider = Arc::new(ring_provider::default_provider());
    let verifier = Arc::new(PinVerifier {
        fingerprint: cert_fingerprint(cert.as_ref()),
        schemes: provider.signature_verification_algorithms,
    });
    let mut tls = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|error| ClusterError::TransportTls {
            message: format!("TLS 1.3: {error}"),
        })?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    tls.alpn_protocols = vec![b"h2".to_vec()];
    http_client(tls)
}

fn http_client(tls: rustls::ClientConfig) -> Result<Client, ClusterError> {
    Client::builder()
        .use_preconfigured_tls(tls)
        .connect_timeout(DEFAULT_MASTER_TIMEOUT)
        .build()
        .map_err(|error| ClusterError::TransportTls {
            message: format!("build cluster HTTP client: {error}"),
        })
}

/// Leaf-certificate pin verifier used only for bootstrap enrollment.
#[derive(Debug)]
struct PinVerifier {
    fingerprint: String,
    schemes: rustls::crypto::WebPkiSupportedAlgorithms,
}

impl ServerCertVerifier for PinVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        if cert_fingerprint(end_entity.as_ref()) != self.fingerprint {
            return Err(RustlsError::InvalidCertificate(
                rustls::CertificateError::ApplicationVerificationFailure,
            ));
        }
        // The pin is the identity; the bootstrap URL may be an IP or a name
        // that does not appear in the master's SAN.
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        verify_tls12_signature(message, cert, dss, &self.schemes)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        verify_tls13_signature(message, cert, dss, &self.schemes)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.schemes.supported_schemes()
    }
}

/// Reads one newline-terminated NDJSON line, buffering the remainder.
async fn read_line(
    response: &mut reqwest::Response,
    buffer: &mut Vec<u8>,
) -> Result<Vec<u8>, ClusterError> {
    loop {
        if let Some(position) = buffer.iter().position(|byte| *byte == b'\n') {
            let mut line: Vec<u8> = buffer.drain(..=position).collect();
            line.pop();
            return Ok(line);
        }
        match response.chunk().await {
            Ok(Some(chunk)) => buffer.extend_from_slice(&chunk),
            Ok(None) if !buffer.is_empty() => return Ok(std::mem::take(buffer)),
            Ok(None) => {
                return Err(ClusterError::MasterUnavailable);
            }
            Err(_error) => {
                return Err(ClusterError::MasterUnavailable);
            }
        }
    }
}

/// Exponential reconnect backoff.
pub(crate) struct Backoff {
    current: Duration,
    max: Duration,
}

impl Backoff {
    pub(crate) fn new(initial: Duration, max: Duration) -> Self {
        Self {
            current: initial,
            max,
        }
    }

    pub(crate) fn next_delay(&mut self) -> Duration {
        let delay = self.current;
        self.current = (delay * 2).min(self.max);
        delay
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn backoff_doubles_up_to_the_cap() {
        let mut backoff = Backoff::new(Duration::from_secs(1), Duration::from_secs(5));
        assert_eq!(backoff.next_delay(), Duration::from_secs(1));
        assert_eq!(backoff.next_delay(), Duration::from_secs(2));
        assert_eq!(backoff.next_delay(), Duration::from_secs(4));
        assert_eq!(backoff.next_delay(), Duration::from_secs(5));
        assert_eq!(backoff.next_delay(), Duration::from_secs(5));
    }

    #[test]
    fn wire_errors_map_to_stable_cluster_variants() {
        let error = StreamError {
            code: "cluster.node.revoked".to_owned(),
            params: Some(serde_json::json!({ "node_id": "node-a" })),
        };
        assert_eq!(
            map_wire_error(&error),
            ClusterError::NodeRevoked {
                node_id: "node-a".to_owned()
            }
        );
        assert_eq!(
            map_wire_error(&StreamError {
                code: "cluster.protocol.version".to_owned(),
                params: None,
            }),
            ClusterError::ProtocolVersion
        );
    }
}
