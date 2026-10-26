//! TLS server configs, SNI admission, and handshake helpers (N6).
//!
//! Builds ring-backed [`rustls::ServerConfig`]s from
//! [`dnscraft_tls::CertResolver`]. Public Client-ID SNI checks happen in
//! [`accept_encrypted`] / DoQ post-handshake (not in the cert resolver), so
//! ban strikes see the peer address. Per-protocol ALPN is set by the caller.

use std::fmt;
use std::future::Future;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime};

use dnscraft_policy::{ClientId, PolicyEngine};
use dnscraft_tls::{CertResolver, ClientIdRegistry, ReservedLabels, SniKind, parse_client_id_sni};
use rustls::ServerConfig;
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::Notify;
use tokio_rustls::server::TlsStream;
use tokio_rustls::{LazyConfigAcceptor, TlsAcceptor};

use crate::admission::{Admission, ClientIdState, public_client_id_required};
use crate::bans::StrikeReason;
use crate::clock::{Clock, add_duration, wait_until};
use crate::config::Exposure;
use crate::error::ListenersError;

/// ALPN for DNS over TLS (RFC 7858).
pub const ALPN_DOT: &[u8] = b"dot";
/// ALPN for HTTP/2 (DoH).
pub const ALPN_H2: &[u8] = b"h2";
/// ALPN for HTTP/1.1 (DoH fallback).
pub const ALPN_HTTP_1_1: &[u8] = b"http/1.1";
/// ALPN for DNS over QUIC (RFC 9250).
pub const ALPN_DOQ: &[u8] = b"doq";
/// ALPN for HTTP/3 (DoH).
pub const ALPN_H3: &[u8] = b"h3";

/// Counters for TLS admission / handshake failures.
#[derive(Debug, Default)]
pub struct TlsStats {
    /// Handshakes that failed because no certificate was installed.
    pub no_cert: AtomicU64,
    /// Public SNI rejections that count as a ban strike (missing / unknown id).
    pub sni_reject_strike: AtomicU64,
    /// Public SNI rejections without a strike (node hostname / apex / other).
    pub sni_reject_no_strike: AtomicU64,
    /// Completed handshakes that timed out under [`tls_handshake_timeout`].
    pub handshake_timeouts: AtomicU64,
    /// Other handshake I/O / rustls failures.
    pub handshake_fail: AtomicU64,
}

impl TlsStats {
    pub(crate) fn bump(field: &AtomicU64) {
        field.fetch_add(1, Ordering::Relaxed);
    }
}

/// L0 adapter: policy snapshot as [`ClientIdRegistry`].
///
/// Lower-cases the lookup key because [`PolicyEngine::is_client_id_registered`]
/// is case-sensitive. Follows [`PolicyEngine::apply_config`] automatically
/// (shared `Arc`).
#[derive(Clone)]
pub struct PolicyClientIds(pub Arc<PolicyEngine>);

impl fmt::Debug for PolicyClientIds {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("PolicyClientIds").finish()
    }
}

impl ClientIdRegistry for PolicyClientIds {
    fn is_registered(&self, client_id: &str) -> bool {
        self.0
            .is_client_id_registered(&client_id.to_ascii_lowercase())
    }
}

/// Public-listener SNI gate (domain + reserved labels + registry).
#[derive(Clone)]
pub struct SniGate {
    /// Apex domain (e.g. `example.com`) for `<id>.dns.<domain>`.
    pub public_domain: String,
    /// Node hostnames and fixed reserved labels.
    pub reserved: ReservedLabels,
    /// Registered Client IDs (typically [`PolicyClientIds`]).
    pub registry: Arc<dyn ClientIdRegistry>,
}

impl fmt::Debug for SniGate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SniGate")
            .field("public_domain", &self.public_domain)
            .field("reserved", &self.reserved)
            .finish_non_exhaustive()
    }
}

/// Result of evaluating a public ClientHello SNI.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PublicSniOutcome {
    /// Registered Client ID — proceed with handshake.
    Accept {
        /// Lower-cased registered id.
        client_id: ClientId,
    },
    /// Reject the handshake.
    Reject {
        /// When true, callers must [`Admission::strike`] with
        /// [`StrikeReason::UnknownClientId`].
        strike: bool,
        /// Classification used for logging / metrics.
        kind: SniRejectKind,
    },
}

/// Why a public SNI was rejected.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum SniRejectKind {
    /// No SNI extension.
    Missing,
    /// `<id>.dns.<domain>` but id is not registered.
    UnknownClientId,
    /// Reserved node hostname under `dns.<domain>`.
    NodeHostname,
    /// Exactly `dns.<domain>`.
    Apex,
    /// Unrelated or malformed name.
    Other,
}

impl PublicSniOutcome {
    /// Whether [`Admission::strike`] is required.
    pub fn should_strike(&self) -> bool {
        matches!(self, Self::Reject { strike: true, .. })
    }
}

/// Classifies SNI for a **public** encrypted listener.
///
/// Missing SNI and unknown Client IDs reject **with** a strike. Node hostname,
/// apex, and other names reject **without** a strike (SPEC-listeners / SPEC-tls).
pub fn inspect_public_sni(sni: Option<&str>, gate: &SniGate) -> PublicSniOutcome {
    let Some(sni) = sni else {
        return PublicSniOutcome::Reject {
            strike: true,
            kind: SniRejectKind::Missing,
        };
    };
    match parse_client_id_sni(sni, &gate.public_domain, &gate.reserved) {
        SniKind::ClientId(id) => {
            if gate.registry.is_registered(&id) {
                // parse_client_id_sni already lower-cased; ClientId::new accepts it.
                match ClientId::new(&id) {
                    Ok(client_id) => PublicSniOutcome::Accept { client_id },
                    Err(_) => PublicSniOutcome::Reject {
                        strike: true,
                        kind: SniRejectKind::UnknownClientId,
                    },
                }
            } else {
                PublicSniOutcome::Reject {
                    strike: true,
                    kind: SniRejectKind::UnknownClientId,
                }
            }
        }
        SniKind::NodeHostname => PublicSniOutcome::Reject {
            strike: false,
            kind: SniRejectKind::NodeHostname,
        },
        SniKind::Apex => PublicSniOutcome::Reject {
            strike: false,
            kind: SniRejectKind::Apex,
        },
        SniKind::Other => PublicSniOutcome::Reject {
            strike: false,
            kind: SniRejectKind::Other,
        },
    }
}

/// Local listener: registered SNI → [`ClientIdState::Registered`]; anything
/// else (including unknown id) → [`ClientIdState::Absent`] (ignored, not rejected).
pub fn client_id_state_local(sni: Option<&str>, gate: &SniGate) -> ClientIdState {
    let Some(sni) = sni else {
        return ClientIdState::Absent;
    };
    match parse_client_id_sni(sni, &gate.public_domain, &gate.reserved) {
        SniKind::ClientId(id) if gate.registry.is_registered(&id) => ClientId::new(&id)
            .map(ClientIdState::Registered)
            .unwrap_or(ClientIdState::Absent),
        _ => ClientIdState::Absent,
    }
}

/// Records a ban strike when [`PublicSniOutcome::should_strike`] is true.
pub fn apply_sni_strike(
    admission: &mut Admission,
    peer: IpAddr,
    outcome: &PublicSniOutcome,
    now: SystemTime,
) {
    if outcome.should_strike() {
        admission.strike(peer, StrikeReason::UnknownClientId, now);
    }
}

/// Strike a public source on a public listener for a failed / timed-out handshake.
pub fn apply_tls_handshake_strike(
    admission: &mut Admission,
    exposure: Exposure,
    peer: IpAddr,
    now: SystemTime,
) {
    let class = admission.classify(peer);
    if public_client_id_required(exposure, class) {
        admission.strike(peer, StrikeReason::TlsHandshake, now);
    }
}

/// [`ResolvesServerCert`] over [`CertResolver`]: cert presence only.
///
/// Public SNI / Client-ID admission is enforced in [`accept_encrypted`] (DoT)
/// or after the QUIC handshake (DoQ), where the peer IP is available for
/// strikes. Hot reload remains via [`CertResolver::install`].
pub struct ListenerCertResolver {
    inner: Arc<CertResolver>,
    stats: Arc<TlsStats>,
}

impl fmt::Debug for ListenerCertResolver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ListenerCertResolver")
            .field("has_cert", &self.inner.has_cert())
            .finish()
    }
}

impl ListenerCertResolver {
    /// Cert presence only (local and public listeners).
    pub fn local(inner: Arc<CertResolver>, stats: Arc<TlsStats>) -> Arc<Self> {
        Arc::new(Self { inner, stats })
    }

    /// Underlying hot-reloadable certificate store.
    pub fn cert_resolver(&self) -> &Arc<CertResolver> {
        &self.inner
    }

    /// Shared TLS counters.
    pub fn stats(&self) -> &Arc<TlsStats> {
        &self.stats
    }
}

impl ResolvesServerCert for ListenerCertResolver {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        if !self.inner.has_cert() {
            TlsStats::bump(&self.stats.no_cert);
            return None;
        }
        self.inner.resolve(client_hello)
    }
}

/// TCP-family server config: TLS 1.2+, ALPN set by the protocol family.
///
/// DoT passes only [`ALPN_DOT`]; DoH passes [`ALPN_H2`] + [`ALPN_HTTP_1_1`].
pub fn tcp_server_config(
    resolver: Arc<dyn ResolvesServerCert + 'static>,
    alpn: &[&[u8]],
) -> Arc<ServerConfig> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut cfg = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap_or_else(|e| panic!("ring provider supports default protocol versions: {e}"))
        .with_no_client_auth()
        .with_cert_resolver(resolver);
    cfg.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    // No session tickets: each handshake re-resolves the cert (hot reload visible).
    cfg.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
    Arc::new(cfg)
}

/// QUIC-family server config: TLS 1.3 only, ALPN `doq` / `h3`, 0-RTT off.
pub fn quic_server_config(resolver: Arc<dyn ResolvesServerCert + 'static>) -> Arc<ServerConfig> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut cfg = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap_or_else(|e| panic!("ring provider supports TLS 1.3: {e}"))
        .with_no_client_auth()
        .with_cert_resolver(resolver);
    cfg.alpn_protocols = vec![ALPN_DOQ.to_vec(), ALPN_H3.to_vec()];
    // 0-RTT disabled (replay risk, RFC 9250 §4.5). Do not copy the spike's u32::MAX.
    cfg.max_early_data_size = 0;
    cfg.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
    Arc::new(cfg)
}

/// Runs `handshake` until it completes or `clock` reaches `deadline`.
pub async fn handshake_until<F, T, E>(
    handshake: F,
    clock: &dyn Clock,
    deadline: SystemTime,
) -> Result<T, ListenersError>
where
    F: Future<Output = Result<T, E>>,
    E: std::fmt::Display,
{
    let wake = Notify::new();
    tokio::select! {
        r = handshake => r.map_err(|e| ListenersError::TlsHandshake {
            message: e.to_string(),
        }),
        () = wait_until(clock, deadline, &wake) => {
            Err(ListenersError::TlsHandshake {
                message: "handshake timeout".into(),
            })
        }
    }
}

/// Runs `handshake` until it completes or `clock` passes `timeout` from now.
///
/// Callers (N7+) wrap `TlsAcceptor::accept` / `StartHandshake::into_stream`.
pub async fn tls_handshake_timeout<F, T, E>(
    handshake: F,
    clock: &dyn Clock,
    timeout: Duration,
) -> Result<T, ListenersError>
where
    F: Future<Output = Result<T, E>>,
    E: std::fmt::Display,
{
    let deadline = add_duration(clock.now(), timeout);
    handshake_until(handshake, clock, deadline).await
}

/// Whether a TLS error is the handshake-timeout sentinel.
pub fn is_handshake_timeout(err: &ListenersError) -> bool {
    matches!(err, ListenersError::TlsHandshake { message } if message.contains("timeout"))
}

/// Accepted encrypted connection plus the Client ID for [`crate::core::QueryMeta`].
pub struct AcceptedTls<IO> {
    /// TLS stream after a successful handshake.
    pub stream: TlsStream<IO>,
    /// Client ID state for admission / policy.
    pub client_id: ClientIdState,
}

/// Inputs for [`accept_encrypted`].
pub struct AcceptEncrypted<'a> {
    /// rustls server config (TCP family; ALPN already set).
    pub config: Arc<ServerConfig>,
    /// Local vs public SNI rules.
    pub exposure: Exposure,
    /// Domain / reserved / registry for SNI parsing.
    pub gate: &'a SniGate,
    /// Hot-reloadable cert store (`has_cert` checked before handshake).
    pub certs: &'a CertResolver,
    /// Ban table for public SNI / handshake strikes.
    pub admission: &'a Mutex<Admission>,
    /// Peer address (strikes are no-op for private sources).
    pub peer: IpAddr,
    /// Clock for handshake deadline and strike timestamps.
    pub clock: &'a dyn Clock,
    /// Bound for ClientHello **and** the rest of the handshake (one deadline).
    pub handshake_timeout: Duration,
    /// Counters (`no_cert`, SNI rejects, timeouts).
    pub stats: &'a TlsStats,
}

/// Accepts TLS with SNI admission, optional strike, and a single handshake deadline.
///
/// Prefer this over raw [`TlsAcceptor`] on public listeners so strikes are
/// recorded with the peer IP. The public SNI gate applies only when both
/// exposure and source class are Public; private sources on a public listener
/// use local rules (id optional).
pub async fn accept_encrypted<IO>(
    stream: IO,
    params: AcceptEncrypted<'_>,
) -> Result<AcceptedTls<IO>, ListenersError>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    let AcceptEncrypted {
        config,
        exposure,
        gate,
        certs,
        admission,
        peer,
        clock,
        handshake_timeout,
        stats,
    } = params;

    let deadline = add_duration(clock.now(), handshake_timeout);

    let start = match handshake_until(
        LazyConfigAcceptor::new(rustls::server::Acceptor::default(), stream),
        clock,
        deadline,
    )
    .await
    {
        Ok(s) => s,
        Err(e) => {
            record_handshake_failure(admission, exposure, peer, clock, stats, &e);
            return Err(e);
        }
    };

    if !certs.has_cert() {
        TlsStats::bump(&stats.no_cert);
        return Err(ListenersError::TlsNoCert);
    }

    let sni_owned = start.client_hello().server_name().map(str::to_owned);
    let sni = sni_owned.as_deref();
    let source_class = {
        let adm = admission
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        adm.classify(peer)
    };
    let client_id = if public_client_id_required(exposure, source_class) {
        match inspect_public_sni(sni, gate) {
            PublicSniOutcome::Accept { client_id } => ClientIdState::Registered(client_id),
            outcome @ PublicSniOutcome::Reject { .. } => {
                if outcome.should_strike() {
                    TlsStats::bump(&stats.sni_reject_strike);
                } else {
                    TlsStats::bump(&stats.sni_reject_no_strike);
                }
                {
                    let mut adm = admission
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    apply_sni_strike(&mut adm, peer, &outcome, clock.now());
                }
                return Err(ListenersError::AdmissionUnknownClientId);
            }
        }
    } else {
        // Local listener, or private source on a public listener.
        client_id_state_local(sni, gate)
    };

    let stream = match handshake_until(start.into_stream(config), clock, deadline).await {
        Ok(s) => s,
        Err(e) => {
            record_handshake_failure(admission, exposure, peer, clock, stats, &e);
            return Err(e);
        }
    };

    Ok(AcceptedTls { stream, client_id })
}

fn record_handshake_failure(
    admission: &Mutex<Admission>,
    exposure: Exposure,
    peer: IpAddr,
    clock: &dyn Clock,
    stats: &TlsStats,
    err: &ListenersError,
) {
    if is_handshake_timeout(err) {
        TlsStats::bump(&stats.handshake_timeouts);
    } else {
        TlsStats::bump(&stats.handshake_fail);
    }
    let mut adm = admission
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    apply_tls_handshake_strike(&mut adm, exposure, peer, clock.now());
}

/// Convenience: [`TlsAcceptor`] from a server config (local / already gated).
pub fn tls_acceptor(config: Arc<ServerConfig>) -> TlsAcceptor {
    TlsAcceptor::from(config)
}
