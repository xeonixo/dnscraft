//! TLS bootstrap: a persisted self-signed certificate that hands over to the
//! ACME [`dnscraft_tls::CertResolver`] the moment a real certificate exists.
//!
//! On first start (or when the self-signed certificate expires, or the node
//! hostname changes) control-api generates an ECDSA P-256 certificate with
//! [`rcgen`] (ring backend) for `hostname` + `localhost`, persists it under the
//! data directory with the private key at mode 0600, and serves it through a
//! [`ResolvesServerCert`] that falls back to the self-signed certificate only
//! while the ACME resolver has no certificate. The switch is automatic: a new
//! handshake re-resolves and sees the ACME certificate with no restart.

use std::fmt;
use std::fs;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::time::SystemTime;

use rustls::crypto::ring::default_provider;
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::Secret;
use crate::audit::sha256_hex;
use crate::clock::Clock;
use crate::error::ControlApiError;
use dnscraft_common::clock::unix_seconds;

/// Certificate validity: one year.
const VALIDITY_SECS: i64 = 365 * 24 * 3600;
/// Backward skew applied to `not_before` so a slightly-ahead client clock
/// still trusts the freshly generated certificate.
const NOT_BEFORE_SKEW_SECS: i64 = 3600;

/// Subdirectory of the data directory holding the bootstrap certificate.
const BOOTSTRAP_DIR: &str = "control-api";
const CERT_FILE: &str = "tls-cert.pem";
const KEY_FILE: &str = "tls-key.pem";
const META_FILE: &str = "tls-meta.json";

/// Which certificate the API listener is serving.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TlsMode {
    /// A real (ACME-issued) certificate from the `tls` module.
    Acme,
    /// An operator-uploaded certificate (`tls.certificate`).
    Manual,
    /// The persisted self-signed bootstrap certificate.
    SelfSigned,
}

impl TlsMode {
    /// Wire / status name (`acme` | `manual` | `self_signed`).
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Acme => "acme",
            Self::Manual => "manual",
            Self::SelfSigned => "self_signed",
        }
    }
}

/// Where the active certificate came from (contract § A).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CertSource {
    /// Obtained automatically through ACME.
    Acme,
    /// Uploaded by an operator through `PUT /api/v1/tls/certificate`.
    Manual,
}

/// ACME Renewal Information (ARI) window (contract § B, Q4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AriStatus {
    /// Suggested start of the renewal window.
    #[serde(with = "rfc3339_opt", skip_serializing_if = "Option::is_none")]
    pub suggested_window_start: Option<SystemTime>,
    /// Suggested end of the renewal window.
    #[serde(with = "rfc3339_opt", skip_serializing_if = "Option::is_none")]
    pub suggested_window_end: Option<SystemTime>,
    /// ARI certificate id (`base64url` digest of the leaf).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub certificate_id: Option<String>,
    /// Whether the CA advertises ARI.
    pub supported: bool,
}

/// Outcome of one issuance attempt (contract § B, Q8).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IssueOutcome {
    /// A certificate was obtained for the first time.
    Issued,
    /// An existing certificate was renewed.
    Renewed,
    /// The attempt failed (see [`IssueRecord::error`]).
    Failed,
}

/// One bounded issuance-history entry (contract § B, Q8).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct IssueRecord {
    /// When the attempt finished.
    #[serde(with = "rfc3339")]
    pub timestamp: SystemTime,
    /// What happened.
    pub outcome: IssueOutcome,
    /// Stable `tls.*` code when the attempt failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Leaf serial (colon-hex), when a certificate exists.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub serial: Option<String>,
}

/// Certificate-store health (contract § B, Q15).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct StoreHealth {
    /// Store directory the engine writes to.
    pub path: String,
    /// Whether the last write probe succeeded.
    pub writable: bool,
    /// Last successful write, if any.
    #[serde(with = "rfc3339_opt", skip_serializing_if = "Option::is_none")]
    pub last_write: Option<SystemTime>,
    /// Whether the persisted state failed to parse.
    pub corrupt: bool,
}

/// TLS state reported by `GET /api/v1/tls/status` (contract § B + § G).
///
/// `mode` and `fingerprint` describe the certificate the API listener is
/// currently serving; every other field is a typed projection of the
/// `dnscraft_tls::TlsStatus` snapshot. Private keys and Cloudflare token
/// material are never part of this DTO.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TlsStatus {
    /// Whether the ACME, manual or self-signed certificate is active.
    pub mode: TlsMode,
    /// SHA-256 fingerprint (lowercase hex) of the leaf certificate.
    pub fingerprint: String,
    /// Certificate source (ACME or operator upload).
    pub source: CertSource,
    /// Leaf `notAfter`.
    #[serde(with = "rfc3339_opt", skip_serializing_if = "Option::is_none")]
    pub not_after: Option<SystemTime>,
    /// Leaf `notBefore`.
    #[serde(with = "rfc3339_opt", skip_serializing_if = "Option::is_none")]
    pub not_before: Option<SystemTime>,
    /// Whole days remaining until `not_after` (negative when expired).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub days_to_expiry: Option<i64>,
    /// DNS SANs from the leaf.
    pub identifiers: Vec<String>,
    /// Issuer distinguished name (RFC 4514).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    /// Subject distinguished name (RFC 4514).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    /// Leaf serial (colon-hex).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub serial: Option<String>,
    /// Signature algorithm (for example `ECDSA-P256-SHA256`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature_algorithm: Option<String>,
    /// Leaf key-usage names.
    pub key_usage: Vec<String>,
    /// Fullchain PEM (leaf first), **certificates only — never a key**.
    pub chain: Vec<String>,
    /// ACME Renewal Information window.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ari: Option<AriStatus>,
    /// Bounded issuance history (last 10).
    pub history: Vec<IssueRecord>,
    /// Last successful issue/renew.
    #[serde(with = "rfc3339_opt", skip_serializing_if = "Option::is_none")]
    pub last_issue: Option<SystemTime>,
    /// Last renew attempt (success or failure).
    #[serde(with = "rfc3339_opt", skip_serializing_if = "Option::is_none")]
    pub last_renew_attempt: Option<SystemTime>,
    /// Next scheduled renewal.
    #[serde(with = "rfc3339_opt", skip_serializing_if = "Option::is_none")]
    pub next_renew_at: Option<SystemTime>,
    /// Next scheduled DynDNS pass.
    #[serde(with = "rfc3339_opt", skip_serializing_if = "Option::is_none")]
    pub next_dyndns_at: Option<SystemTime>,
    /// Last successful DynDNS pass.
    #[serde(with = "rfc3339_opt", skip_serializing_if = "Option::is_none")]
    pub last_dyndns_success: Option<SystemTime>,
    /// ACME directory URL currently configured.
    pub acme_directory: String,
    /// Whether this node creates ACME orders.
    pub acme_enabled: bool,
    /// Last stable error code (`tls.*`), if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
    /// `true` when days-to-expiry is below the warn threshold.
    pub cert_expiring: bool,
    /// `true` when `not_after` is in the past.
    pub cert_expired: bool,
    /// `true` when the certificate was revoked.
    pub revoked: bool,
    /// Last DynDNS IPv4.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dyndns_ipv4: Option<String>,
    /// Last DynDNS IPv6.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dyndns_ipv6: Option<String>,
    /// Last successful DynDNS change.
    #[serde(with = "rfc3339_opt", skip_serializing_if = "Option::is_none")]
    pub dyndns_last_change: Option<SystemTime>,
    /// `true` when the published records are known stale.
    pub dyndns_stale: bool,
    /// Certificate-store health.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub store: Option<StoreHealth>,
}

impl TlsStatus {
    /// An empty status carrying only the listener-level mode + fingerprint.
    pub fn new(mode: TlsMode, fingerprint: impl Into<String>) -> Self {
        Self {
            mode,
            fingerprint: fingerprint.into(),
            source: match mode {
                TlsMode::Manual => CertSource::Manual,
                TlsMode::Acme | TlsMode::SelfSigned => CertSource::Acme,
            },
            not_after: None,
            not_before: None,
            days_to_expiry: None,
            identifiers: Vec::new(),
            issuer: None,
            subject: None,
            serial: None,
            signature_algorithm: None,
            key_usage: Vec::new(),
            chain: Vec::new(),
            ari: None,
            history: Vec::new(),
            last_issue: None,
            last_renew_attempt: None,
            next_renew_at: None,
            next_dyndns_at: None,
            last_dyndns_success: None,
            acme_directory: String::new(),
            acme_enabled: false,
            last_error: None,
            cert_expiring: false,
            cert_expired: false,
            revoked: false,
            dyndns_ipv4: None,
            dyndns_ipv6: None,
            dyndns_last_change: None,
            dyndns_stale: false,
            store: None,
        }
    }

    /// Projects an engine status onto the control-api DTO.
    ///
    /// The certificate-detail, ARI, history, scheduling, store-health, stale
    /// and revocation fields are part of the extended `dnscraft_tls::TlsStatus`
    /// (contract § B); they are merged here as the tls crate lands them.
    pub fn from_engine(
        engine: &dnscraft_tls::TlsStatus,
        mode: TlsMode,
        fingerprint: impl Into<String>,
    ) -> Self {
        let mut status = Self::new(mode, fingerprint);
        status.not_after = engine.not_after;
        status.not_before = engine.not_before;
        status.issuer = engine.issuer.clone();
        status.subject = engine.subject.clone();
        status.serial = engine.serial.clone();
        status.signature_algorithm = engine.signature_algorithm.clone();
        status.key_usage = engine.key_usage.clone();
        status.chain = engine.chain.clone();
        status.days_to_expiry = engine.days_to_expiry;
        status.identifiers = engine.identifiers.clone();
        status.last_issue = engine.last_issue;
        status.last_renew_attempt = engine.last_renew_attempt;
        status.history = engine
            .history
            .iter()
            .map(|record| IssueRecord {
                timestamp: record.timestamp,
                outcome: issue_outcome(&record.outcome),
                error: record.error.clone(),
                serial: record.serial.clone(),
            })
            .collect();
        status.acme_directory = engine.acme_directory.clone();
        status.acme_enabled = engine.acme_enabled;
        status.ari = engine.ari.as_ref().map(|ari| AriStatus {
            suggested_window_start: ari.suggested_window_start,
            suggested_window_end: ari.suggested_window_end,
            certificate_id: ari.certificate_id.clone(),
            supported: ari.supported,
        });
        status.next_renew_at = engine.next_renew_at;
        status.next_dyndns_at = engine.next_dyndns_at;
        status.last_dyndns_success = engine.last_dyndns_success;
        status.dyndns_stale = engine.dyndns_stale;
        status.store = engine.store.as_ref().map(|store| StoreHealth {
            path: store.path.clone(),
            writable: store.writable,
            last_write: store.last_write,
            corrupt: store.corrupt,
        });
        status.revoked = engine.revoked;
        status.last_error = engine.last_error.clone();
        status.cert_expiring = engine.cert_expiring;
        status.cert_expired = engine.cert_expired;
        status.dyndns_ipv4 = engine.dyndns_ipv4.clone();
        status.dyndns_ipv6 = engine.dyndns_ipv6.clone();
        status.dyndns_last_change = engine.dyndns_last_change;
        status
    }
}

/// Maps the engine's issue outcome onto the DTO enum.
///
/// The tls crate's `IssueOutcome` is public on the value but not yet re-exported
/// at the crate root (contract § B); compare its serialized name until it is.
fn issue_outcome<T: Serialize>(outcome: &T) -> IssueOutcome {
    match serde_json::to_value(outcome)
        .ok()
        .as_ref()
        .and_then(Value::as_str)
    {
        Some("issued") => IssueOutcome::Issued,
        Some("renewed") => IssueOutcome::Renewed,
        _ => IssueOutcome::Failed,
    }
}

/// Live source of [`TlsStatus`], read on every status request so a certificate
/// installed after start is reflected without a restart.
pub trait TlsStatusProvider: Send + Sync {
    /// The current TLS status.
    fn status(&self) -> TlsStatus;

    /// Async status read for providers backed by an async lock.
    ///
    /// The default delegates to [`Self::status`]; engine-backed providers
    /// override it so they never block a runtime worker.
    fn status_async(&self) -> TlsStatusFuture<'_> {
        Box::pin(async move { self.status() })
    }
}

/// Boxed future for an async status read.
pub type TlsStatusFuture<'a> = Pin<Box<dyn Future<Output = TlsStatus> + Send + 'a>>;

/// A [`TlsStatusProvider`] that merges the engine's certificate detail with the
/// listener's active mode + fingerprint.
///
/// The listener provider (from [`ControlApiTls`]) wins for `mode` and
/// `fingerprint` because it observes what a handshake actually serves; the
/// engine supplies expiry, issuance and DynDNS state.
///
/// `TlsEngine::status()` takes a blocking read on a Tokio lock, so this provider
/// caches the engine projection and refreshes it through [`TlsStatusProvider::status_async`]
/// (used by the status endpoints). The synchronous `status()` never blocks.
pub struct EngineStatusProvider {
    engine: Arc<dnscraft_tls::TlsEngine>,
    listener: Option<Arc<dyn TlsStatusProvider>>,
    cached: std::sync::RwLock<TlsStatus>,
}

impl EngineStatusProvider {
    /// Wraps an engine; mode/fingerprint default to `acme` + empty until a
    /// listener provider is attached with [`Self::with_listener_status`].
    pub fn new(engine: Arc<dnscraft_tls::TlsEngine>) -> Self {
        Self {
            engine,
            listener: None,
            cached: std::sync::RwLock::new(TlsStatus::new(TlsMode::Acme, "")),
        }
    }

    /// Also reads the listener-level mode + fingerprint from `listener`.
    pub fn with_listener_status(mut self, listener: Arc<dyn TlsStatusProvider>) -> Self {
        self.listener = Some(listener);
        self
    }

    /// Reads the engine status and updates the cache.
    fn refresh(&self) -> TlsStatusFuture<'_> {
        Box::pin(async move {
            let (mode, fingerprint) = self.listener_mode();
            let status =
                TlsStatus::from_engine(&self.engine.status_async().await, mode, fingerprint);
            *self
                .cached
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = status.clone();
            status
        })
    }

    fn listener_mode(&self) -> (TlsMode, String) {
        self.listener.as_ref().map_or_else(
            || (TlsMode::Acme, String::new()),
            |listener| {
                let status = listener.status();
                (status.mode, status.fingerprint)
            },
        )
    }
}

impl TlsStatusProvider for EngineStatusProvider {
    fn status(&self) -> TlsStatus {
        let mut status = self
            .cached
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        let (mode, fingerprint) = self.listener_mode();
        status.mode = mode;
        status.fingerprint = fingerprint;
        status
    }

    fn status_async(&self) -> TlsStatusFuture<'_> {
        self.refresh()
    }
}

/// Boxed future for a mutating TLS admin action.
pub type TlsActionFuture<'a> =
    Pin<Box<dyn Future<Output = Result<(), ControlApiError>> + Send + 'a>>;

/// Boxed future for a TLS admin action that returns a JSON report.
pub type TlsValueFuture<'a> =
    Pin<Box<dyn Future<Output = Result<Value, ControlApiError>> + Send + 'a>>;

/// The engine operations exposed under `/api/v1/tls/*`.
///
/// Handlers depend on this narrow trait so tests can substitute a fake and the
/// binary wires the real [`dnscraft_tls::TlsEngine`] once its admin methods land
/// (contract § D). Implementations must never return private-key or token
/// material.
pub trait TlsAdmin: Send + Sync {
    /// Installs an operator-uploaded certificate and switches to `manual` mode.
    fn upload_manual_cert(
        &self,
        cert_pem: &str,
        key_pem: &Secret,
        chain_pem: Option<&str>,
    ) -> TlsActionFuture<'_>;
    /// Revokes the active certificate for `reason`.
    fn revoke(&self, reason: &str) -> TlsActionFuture<'_>;
    /// Forces a re-issue with a fresh key pair.
    fn rotate_key(&self) -> TlsActionFuture<'_>;
    /// Runs one issuance/renewal now.
    fn renew_now(&self) -> TlsActionFuture<'_>;
    /// Runs one DynDNS pass now and returns its report.
    fn dyndns_now(&self) -> TlsValueFuture<'_>;
    /// Dry-run connectivity / configuration preflight.
    fn preflight(&self) -> TlsValueFuture<'_>;
    /// Exports the fullchain PEM (certificates only, leaf first).
    fn export_cert(&self) -> Result<String, ControlApiError>;
    /// ACME account status (EAB, ToS, rollover).
    fn account_status(&self) -> TlsValueFuture<'_>;
    /// Current ACME order / progress.
    fn order_status(&self) -> Result<Value, ControlApiError>;
    /// Expected DNS record inventory and live check.
    fn record_inventory(&self) -> TlsValueFuture<'_>;
    /// DynDNS audit trail.
    fn dyndns_audit(&self) -> TlsValueFuture<'_>;
}

/// [`TlsAdmin`] over the real engine.
///
/// `renew_now`, `dyndns_now` and the read reports are wired to the engine
/// methods that already exist; the remaining operations land with the
/// `dnscraft-tls` admin surface (contract § D).
pub struct EngineTlsAdmin {
    engine: Arc<dnscraft_tls::TlsEngine>,
}

impl EngineTlsAdmin {
    /// Wraps the shared engine.
    pub fn new(engine: Arc<dnscraft_tls::TlsEngine>) -> Self {
        Self { engine }
    }
}

impl TlsAdmin for EngineTlsAdmin {
    fn upload_manual_cert(
        &self,
        cert_pem: &str,
        key_pem: &Secret,
        chain_pem: Option<&str>,
    ) -> TlsActionFuture<'_> {
        let cert = cert_pem.to_owned();
        let key = dnscraft_tls::Secret::new(key_pem.expose());
        let chain = chain_pem.unwrap_or("").to_owned();
        Box::pin(async move {
            self.engine
                .upload_manual_cert(&cert, &key, &chain)
                .await
                .map_err(|error| ControlApiError::from_tls(&error))
        })
    }

    fn revoke(&self, reason: &str) -> TlsActionFuture<'_> {
        let reason = reason.to_owned();
        Box::pin(async move {
            self.engine
                .revoke(Some(reason.as_str()))
                .await
                .map_err(|error| ControlApiError::from_tls(&error))
        })
    }

    fn rotate_key(&self) -> TlsActionFuture<'_> {
        Box::pin(async move {
            self.engine
                .rotate_key()
                .await
                .map_err(|error| ControlApiError::from_tls(&error))
        })
    }

    fn renew_now(&self) -> TlsActionFuture<'_> {
        Box::pin(async move {
            self.engine
                .renew_now()
                .await
                .map_err(|error| ControlApiError::from_tls(&error))
        })
    }

    fn dyndns_now(&self) -> TlsValueFuture<'_> {
        Box::pin(async move {
            let result = self
                .engine
                .dyndns_now()
                .await
                .map_err(|error| ControlApiError::from_tls(&error))?;
            Ok(json!({
                "ipv4": result.ipv4.map(|ip| ip.to_string()),
                "ipv6": result.ipv6.map(|ip| ip.to_string()),
                "skipped_no_route": result.skipped_no_route,
                "changed": result.changed,
                "last_change": result.last_change.map(rfc3339),
            }))
        })
    }

    fn preflight(&self) -> TlsValueFuture<'_> {
        Box::pin(async move {
            let report = self.engine.preflight().await;
            Ok(json!({
                "ok": report.ok,
                "checks": report
                    .checks
                    .into_iter()
                    .map(|check| json!({
                        "name": check.name,
                        "ok": check.ok,
                        "code": check.code,
                        "message": check.message,
                    }))
                    .collect::<Vec<_>>(),
            }))
        })
    }

    fn export_cert(&self) -> Result<String, ControlApiError> {
        self.engine
            .export_cert()
            .map_err(|error| ControlApiError::from_tls(&error))
    }

    fn account_status(&self) -> TlsValueFuture<'_> {
        Box::pin(async move {
            let account = self
                .engine
                .acme_account_status()
                .await
                .map_err(|error| ControlApiError::from_tls(&error))?;
            Ok(json!({
                "exists": account.exists,
                "directory": account.directory,
                "account_id": account.account_id,
                "tos_agreed": account.tos_agreed,
                "eab_configured": account.eab_configured,
                "auto_deactivate": account.auto_deactivate,
                "deactivated": account.deactivated,
            }))
        })
    }

    fn order_status(&self) -> Result<Value, ControlApiError> {
        let order = self.engine.order_status();
        Ok(json!({
            "state": order.state,
            "identifiers": order.identifiers,
            "challenges": order
                .challenges
                .into_iter()
                .map(|challenge| json!({
                    "identifier": challenge.identifier,
                    "txt_name": challenge.txt_name,
                    "status": challenge.status,
                }))
                .collect::<Vec<_>>(),
            "next_attempt_at": order.next_attempt_at.map(rfc3339),
            "last_error": order.last_error,
        }))
    }

    fn record_inventory(&self) -> TlsValueFuture<'_> {
        Box::pin(async move {
            let records = self
                .engine
                .record_inventory()
                .await
                .map_err(|error| ControlApiError::from_tls(&error))?;
            Ok(json!({
                "records": records
                    .into_iter()
                    .map(|record| json!({
                        "name": record.name,
                        "record_type": record.record_type,
                        "content": record.content,
                        "managed": record.managed,
                        "conflict": record.conflict,
                    }))
                    .collect::<Vec<_>>(),
            }))
        })
    }

    fn dyndns_audit(&self) -> TlsValueFuture<'_> {
        Box::pin(async move {
            let entries = self.engine.dyndns_audit().await;
            Ok(json!({
                "entries": entries
                    .into_iter()
                    .map(|entry| json!({
                        "timestamp": rfc3339(entry.timestamp),
                        "name": entry.name,
                        "record_type": entry.record_type,
                        "content": entry.content,
                    }))
                    .collect::<Vec<_>>(),
            }))
        })
    }
}

/// RFC 3339 (UTC, seconds precision) for a [`SystemTime`].
fn rfc3339(time: SystemTime) -> String {
    let datetime: chrono::DateTime<chrono::Utc> = time.into();
    datetime.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

/// Serde `with` adapter: [`SystemTime`] ↔ RFC 3339 string.
mod rfc3339 {
    use std::time::SystemTime;

    use serde::Serializer;

    pub(super) fn serialize<S: Serializer>(
        time: &SystemTime,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&super::rfc3339(*time))
    }
}

/// Serde `with` adapter: `Option<SystemTime>` ↔ RFC 3339 string.
mod rfc3339_opt {
    use std::time::SystemTime;

    use serde::Serializer;

    pub(super) fn serialize<S: Serializer>(
        time: &Option<SystemTime>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        match time {
            Some(time) => serializer.serialize_str(&super::rfc3339(*time)),
            None => serializer.serialize_none(),
        }
    }
}

/// Asks the ACME certificate resolver first, falling back to the self-signed
/// bootstrap certificate while no ACME certificate exists.
trait AcmeResolver: Send + Sync {
    /// The certificate to serve, if any.
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>>;
    /// DER of the leaf certificate to serve, if any (for the status fingerprint).
    fn leaf_der(&self) -> Option<Vec<u8>>;
}

impl AcmeResolver for dnscraft_tls::CertResolver {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        ResolvesServerCert::resolve(self, client_hello)
    }

    fn leaf_der(&self) -> Option<Vec<u8>> {
        dnscraft_tls::CertResolver::leaf_der(self)
    }
}

/// The bootstrap certificate, ready to hand to rustls.
struct SelfSignedCert {
    certified: Arc<CertifiedKey>,
    fingerprint: String,
}

/// A [`ResolvesServerCert`] that returns the ACME certificate when present and
/// the self-signed bootstrap certificate otherwise.
struct FallbackResolver {
    acme: Arc<dyn AcmeResolver>,
    self_signed: Arc<CertifiedKey>,
    self_signed_fingerprint: String,
}

impl FallbackResolver {
    fn status(&self) -> TlsStatus {
        match self.acme.leaf_der() {
            Some(leaf) => TlsStatus::new(TlsMode::Acme, sha256_hex(&leaf)),
            None => TlsStatus::new(TlsMode::SelfSigned, self.self_signed_fingerprint.clone()),
        }
    }
}

impl fmt::Debug for FallbackResolver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // rustls requires `ResolvesServerCert: Debug`; print only the status so
        // the self-signed private key never leaks through a Debug format.
        f.debug_struct("FallbackResolver")
            .field("status", &self.status())
            .finish_non_exhaustive()
    }
}

impl TlsStatusProvider for FallbackResolver {
    fn status(&self) -> TlsStatus {
        FallbackResolver::status(self)
    }
}

impl ResolvesServerCert for FallbackResolver {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        // A self-signed certificate is never served once the ACME resolver has
        // a certificate for this handshake.
        self.acme
            .resolve(client_hello)
            .or_else(|| Some(self.self_signed.clone()))
    }
}

/// The TLS stack for the API listener: a [`ResolvesServerCert`] fallback chain
/// plus a ready-to-use rustls [`rustls::ServerConfig`].
///
/// Build it once with [`ControlApiTls::bootstrap`] and hand the pieces to the
/// server: `status_provider` into [`crate::AppState`] and `server_config` into
/// [`crate::serve`].
pub struct ControlApiTls {
    resolver: Arc<FallbackResolver>,
    server_config: Arc<rustls::ServerConfig>,
}

impl ControlApiTls {
    /// Loads (or generates and persists) the self-signed bootstrap certificate
    /// and prepares the ACME → self-signed fallback resolver.
    ///
    /// `acme` is the shared `tls` module certificate resolver. `data_dir` is the
    /// node data directory; the bootstrap certificate lives in its
    /// `control-api/` subdirectory.
    pub fn bootstrap(
        hostname: &str,
        data_dir: &Path,
        clock: &dyn Clock,
        acme: Arc<dnscraft_tls::CertResolver>,
    ) -> Result<Self, ControlApiError> {
        let cert = load_or_generate(hostname, data_dir, clock)?;
        let resolver = Arc::new(FallbackResolver {
            acme,
            self_signed: cert.certified,
            self_signed_fingerprint: cert.fingerprint,
        });
        let server_config = server_config(resolver.clone());
        Ok(Self {
            resolver,
            server_config,
        })
    }

    /// The current TLS status (`acme` | `self_signed` + fingerprint).
    pub fn status(&self) -> TlsStatus {
        self.resolver.status()
    }

    /// A live [`TlsStatusProvider`] to install in [`crate::AppState`].
    pub fn status_provider(&self) -> Arc<dyn TlsStatusProvider> {
        self.resolver.clone()
    }

    /// The rustls [`rustls::ServerConfig`] for the API listener.
    pub fn server_config(&self) -> Arc<rustls::ServerConfig> {
        self.server_config.clone()
    }
}

impl fmt::Debug for ControlApiTls {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Deliberately prints only the status: the resolver holds the private
        // key and must never surface through Debug.
        f.debug_struct("ControlApiTls")
            .field("status", &self.status())
            .finish_non_exhaustive()
    }
}

/// A freshly generated certificate plus its on-disk representation.
struct GeneratedCert {
    certified: Arc<CertifiedKey>,
    fingerprint: String,
    cert_pem: String,
    key_pem: Secret,
    not_after_unix: i64,
}

/// Disk locations of the bootstrap certificate inside `data_dir`.
struct BootstrapPaths {
    dir: PathBuf,
    cert: PathBuf,
    key: PathBuf,
    meta: PathBuf,
}

impl BootstrapPaths {
    fn new(data_dir: &Path) -> Self {
        let dir = data_dir.join(BOOTSTRAP_DIR);
        Self {
            cert: dir.join(CERT_FILE),
            key: dir.join(KEY_FILE),
            meta: dir.join(META_FILE),
            dir,
        }
    }
}

/// Metadata persisted alongside the certificate, used to detect expiry and
/// hostname changes without parsing the certificate.
#[derive(Debug, Serialize, Deserialize)]
struct BootstrapMeta {
    hostname: String,
    not_after_unix: i64,
}

/// Loads the persisted certificate, or generates a new one when it is missing,
/// expired, or was created for a different hostname.
fn load_or_generate(
    hostname: &str,
    data_dir: &Path,
    clock: &dyn Clock,
) -> Result<SelfSignedCert, ControlApiError> {
    let paths = BootstrapPaths::new(data_dir);
    if let Some(cert) = try_load(hostname, &paths, clock)? {
        return Ok(cert);
    }
    let generated = generate(hostname, clock)?;
    persist(&paths, hostname, &generated)?;
    Ok(SelfSignedCert {
        certified: generated.certified,
        fingerprint: generated.fingerprint,
    })
}

/// Attempts to reuse the persisted certificate; `Ok(None)` means "regenerate".
fn try_load(
    hostname: &str,
    paths: &BootstrapPaths,
    clock: &dyn Clock,
) -> Result<Option<SelfSignedCert>, ControlApiError> {
    let cert_pem = match fs::read(&paths.cert) {
        Ok(bytes) => bytes,
        Err(_) => return Ok(None),
    };
    let key_pem = match fs::read(&paths.key) {
        Ok(bytes) => bytes,
        Err(_) => return Ok(None),
    };
    let meta_bytes = match fs::read(&paths.meta) {
        Ok(bytes) => bytes,
        Err(_) => return Ok(None),
    };
    let meta: BootstrapMeta = match serde_json::from_slice(&meta_bytes) {
        Ok(meta) => meta,
        Err(_) => return Ok(None),
    };
    if meta.hostname != hostname || unix_seconds(clock.now()) >= meta.not_after_unix {
        return Ok(None);
    }
    let certified = certified_key_from_pem(&cert_pem, &key_pem).map_err(|message| {
        ControlApiError::Internal {
            message: format!("load control-api TLS bootstrap certificate: {message}"),
        }
    })?;
    let fingerprint = sha256_hex(certified.cert.first().map_or(&[], |leaf| leaf.as_ref()));
    Ok(Some(SelfSignedCert {
        certified: Arc::new(certified),
        fingerprint,
    }))
}

/// Generates the self-signed ECDSA P-256 certificate and its key.
fn generate(hostname: &str, clock: &dyn Clock) -> Result<GeneratedCert, ControlApiError> {
    let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).map_err(|e| {
        ControlApiError::Internal {
            message: format!("generate control-api TLS key: {e}"),
        }
    })?;
    let mut sans = vec![hostname.to_owned()];
    if hostname != "localhost" {
        sans.push("localhost".to_owned());
    }
    let mut params =
        rcgen::CertificateParams::new(sans).map_err(|e| ControlApiError::Internal {
            message: format!("build control-api TLS certificate parameters: {e}"),
        })?;
    let now_unix = unix_seconds(clock.now());
    let not_after_unix = now_unix + VALIDITY_SECS;
    params.not_before = offset(now_unix - NOT_BEFORE_SKEW_SECS)?;
    params.not_after = offset(not_after_unix)?;
    let cert = params
        .self_signed(&key_pair)
        .map_err(|e| ControlApiError::Internal {
            message: format!("sign control-api TLS certificate: {e}"),
        })?;

    let leaf = cert.der().clone();
    let fingerprint = sha256_hex(leaf.as_ref());
    let private_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der()));
    let certified =
        CertifiedKey::from_der(vec![leaf], private_key, &default_provider()).map_err(|e| {
            ControlApiError::Internal {
                message: format!("build control-api TLS CertifiedKey: {e}"),
            }
        })?;

    Ok(GeneratedCert {
        certified: Arc::new(certified),
        fingerprint,
        cert_pem: cert.pem(),
        key_pem: Secret::new(key_pair.serialize_pem()),
        not_after_unix,
    })
}

/// Persists the certificate, private key (0600) and metadata (atomically, 0700 dir).
fn persist(
    paths: &BootstrapPaths,
    hostname: &str,
    generated: &GeneratedCert,
) -> Result<(), ControlApiError> {
    fs::create_dir_all(&paths.dir).map_err(|e| ControlApiError::Internal {
        message: format!(
            "create control-api TLS directory {}: {e}",
            paths.dir.display()
        ),
    })?;
    set_mode(&paths.dir, 0o700)?;
    write_atomic(&paths.key, generated.key_pem.expose().as_bytes(), 0o600)?;
    write_atomic(&paths.cert, generated.cert_pem.as_bytes(), 0o644)?;
    let meta = BootstrapMeta {
        hostname: hostname.to_owned(),
        not_after_unix: generated.not_after_unix,
    };
    let meta_bytes = serde_json::to_vec(&meta).map_err(|e| ControlApiError::Internal {
        message: format!("serialize control-api TLS metadata: {e}"),
    })?;
    write_atomic(&paths.meta, &meta_bytes, 0o644)?;
    Ok(())
}

/// Builds a ring-backed rustls [`rustls::ServerConfig`] around the fallback resolver.
fn server_config(resolver: Arc<FallbackResolver>) -> Arc<rustls::ServerConfig> {
    let provider = Arc::new(default_provider());
    let mut config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap_or_else(|e| panic!("ring provider supports the default protocol versions: {e}"))
        .with_no_client_auth()
        .with_cert_resolver(resolver);
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    // No session tickets: each handshake re-resolves the certificate so the
    // ACME → self-signed switch is visible to new connections immediately.
    config.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
    Arc::new(config)
}

/// Writes `contents` to `path` atomically (temp sibling + rename) with `mode`.
fn write_atomic(path: &Path, contents: &[u8], mode: u32) -> Result<(), ControlApiError> {
    let tmp = temp_sibling(path);
    fs::write(&tmp, contents).map_err(|e| ControlApiError::Internal {
        message: format!("write {}: {e}", tmp.display()),
    })?;
    set_mode(&tmp, mode)?;
    fs::rename(&tmp, path).map_err(|e| ControlApiError::Internal {
        message: format!("rename {} -> {}: {e}", tmp.display(), path.display()),
    })
}

fn temp_sibling(path: &Path) -> PathBuf {
    let mut name = path
        .file_name()
        .map_or_else(|| "file".to_owned(), |n| n.to_string_lossy().into_owned());
    name.push_str(".tmp");
    path.with_file_name(name)
}

/// Parses PEM into a ring-backed [`CertifiedKey`] (leaf first).
fn certified_key_from_pem(chain_pem: &[u8], key_pem: &[u8]) -> Result<CertifiedKey, String> {
    let certs: Result<Vec<_>, _> = CertificateDer::pem_slice_iter(chain_pem).collect();
    let certs = certs.map_err(|e| format!("certificate PEM: {e}"))?;
    if certs.is_empty() {
        return Err("certificate PEM contains no certificates".to_owned());
    }
    let key =
        PrivateKeyDer::from_pem_slice(key_pem).map_err(|e| format!("private key PEM: {e}"))?;
    CertifiedKey::from_der(certs, key, &default_provider())
        .map_err(|e| format!("cannot build CertifiedKey: {e}"))
}

fn offset(unix: i64) -> Result<time::OffsetDateTime, ControlApiError> {
    time::OffsetDateTime::from_unix_timestamp(unix).map_err(|e| ControlApiError::Internal {
        message: format!("invalid TLS certificate timestamp {unix}: {e}"),
    })
}

/// Sets `path` permissions to `mode` (no-op on non-unix platforms).
#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) -> Result<(), ControlApiError> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).map_err(|e| {
        ControlApiError::Internal {
            message: format!("set mode {mode:o} on {}: {e}", path.display()),
        }
    })
}

#[cfg(not(unix))]
fn set_mode(_path: &Path, _mode: u32) -> Result<(), ControlApiError> {
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{Duration, SystemTime};

    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use rustls::pki_types::{ServerName, UnixTime};

    use super::*;
    use crate::clock::ManualClock;

    /// A unique, self-cleaning temporary directory.
    struct TempDir(PathBuf);

    impl TempDir {
        fn new(name: &str) -> Self {
            static COUNTER: AtomicU64 = AtomicU64::new(0);
            let id = COUNTER.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir()
                .join(format!("dnscraft-api-{name}-{}-{id}", std::process::id()));
            let _ = fs::remove_dir_all(&path);
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    /// A fake ACME resolver that flips between "no cert" and "a cert".
    struct FakeAcme {
        cert: Mutex<Option<Arc<CertifiedKey>>>,
    }

    impl FakeAcme {
        fn empty() -> Self {
            Self {
                cert: Mutex::new(None),
            }
        }

        fn install(&self, cert: Arc<CertifiedKey>) {
            *self.cert.lock().unwrap() = Some(cert);
        }
    }

    impl AcmeResolver for FakeAcme {
        fn resolve(&self, _client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
            self.cert.lock().unwrap().clone()
        }

        fn leaf_der(&self) -> Option<Vec<u8>> {
            self.cert
                .lock()
                .unwrap()
                .as_ref()
                .and_then(|k| k.cert.first())
                .map(|c| c.as_ref().to_vec())
        }
    }

    /// A client cert verifier that accepts anything but records the leaf DER,
    /// so a test can assert which certificate the server actually presented.
    #[derive(Debug)]
    struct CaptureVerifier {
        leaf: Mutex<Option<Vec<u8>>>,
    }

    impl ServerCertVerifier for CaptureVerifier {
        fn verify_server_cert(
            &self,
            end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp_response: &[u8],
            _now: UnixTime,
        ) -> Result<ServerCertVerified, rustls::Error> {
            *self.leaf.lock().unwrap() = Some(end_entity.as_ref().to_vec());
            Ok(ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &rustls::DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &rustls::DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            default_provider()
                .signature_verification_algorithms
                .supported_schemes()
        }
    }

    /// Builds a self-signed rustls [`CertifiedKey`] for the given SANs.
    fn make_certified(sans: &[&str]) -> Arc<CertifiedKey> {
        let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let params =
            rcgen::CertificateParams::new(sans.iter().map(|s| s.to_string()).collect::<Vec<_>>())
                .unwrap();
        let cert = params.self_signed(&key_pair).unwrap();
        let private_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der()));
        Arc::new(
            CertifiedKey::from_der(vec![cert.der().clone()], private_key, &default_provider())
                .unwrap(),
        )
    }

    fn bootstrap(hostname: &str, dir: &Path, clock: &ManualClock) -> ControlApiTls {
        ControlApiTls::bootstrap(
            hostname,
            dir,
            clock,
            Arc::new(dnscraft_tls::CertResolver::new()),
        )
        .unwrap()
    }

    #[cfg(unix)]
    fn mode(path: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    /// Runs a full TLS handshake against `server_config` and returns the DER of
    /// the certificate the server presented.
    async fn handshake_leaf(server_config: Arc<rustls::ServerConfig>) -> Vec<u8> {
        let capture = Arc::new(CaptureVerifier {
            leaf: Mutex::new(None),
        });
        let client_config = Arc::new(
            rustls::ClientConfig::builder_with_provider(Arc::new(default_provider()))
                .with_safe_default_protocol_versions()
                .unwrap()
                .dangerous()
                .with_custom_certificate_verifier(capture.clone())
                .with_no_client_auth(),
        );
        let acceptor = tokio_rustls::TlsAcceptor::from(server_config);
        let connector = tokio_rustls::TlsConnector::from(client_config);
        let (server_io, client_io) = tokio::io::duplex(64 * 1024);
        let server_name = ServerName::try_from("node.example.com").unwrap();

        let server = tokio::spawn(async move {
            let _tls = acceptor.accept(server_io).await.unwrap();
        });
        let client = tokio::spawn(async move {
            let _tls = connector.connect(server_name, client_io).await.unwrap();
        });
        let _ = tokio::join!(server, client);
        capture.leaf.lock().unwrap().clone().unwrap()
    }

    #[test]
    fn generates_self_signed_cert_with_0600_key_and_0700_dir() {
        let dir = TempDir::new("gen");
        let clock = ManualClock::new(SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000));
        let tls = bootstrap("node.example.com", dir.path(), &clock);
        assert_eq!(tls.status().mode, TlsMode::SelfSigned);
        assert_eq!(tls.status().fingerprint.len(), 64);

        #[cfg(unix)]
        {
            assert_eq!(mode(&dir.path().join("control-api")), 0o700);
            assert_eq!(mode(&dir.path().join("control-api/tls-key.pem")), 0o600);
        }
    }

    #[test]
    fn reuses_cert_across_restarts_with_the_same_fingerprint() {
        let dir = TempDir::new("reuse");
        let clock = ManualClock::new(SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000));
        let first = bootstrap("node.example.com", dir.path(), &clock);
        let cert_pem = fs::read(dir.path().join("control-api/tls-cert.pem")).unwrap();
        let second = bootstrap("node.example.com", dir.path(), &clock);
        assert_eq!(first.status().fingerprint, second.status().fingerprint);
        // The persisted certificate is untouched by the second load.
        assert_eq!(
            cert_pem,
            fs::read(dir.path().join("control-api/tls-cert.pem")).unwrap()
        );
    }

    #[test]
    fn regenerates_when_expired() {
        let dir = TempDir::new("expire");
        let clock = ManualClock::new(SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000));
        let first = bootstrap("node.example.com", dir.path(), &clock);
        clock.advance(Duration::from_secs(VALIDITY_SECS as u64 + 1));
        let second = bootstrap("node.example.com", dir.path(), &clock);
        assert_ne!(first.status().fingerprint, second.status().fingerprint);
    }

    #[test]
    fn regenerates_when_hostname_changes() {
        let dir = TempDir::new("hostname");
        let clock = ManualClock::new(SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000));
        let first = bootstrap("node-a.example.com", dir.path(), &clock);
        let second = bootstrap("node-b.example.com", dir.path(), &clock);
        assert_ne!(first.status().fingerprint, second.status().fingerprint);
    }

    #[test]
    fn fingerprint_is_sha256_of_the_leaf_der() {
        let dir = TempDir::new("fp");
        let clock = ManualClock::new(SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000));
        let tls = bootstrap("node.example.com", dir.path(), &clock);
        let cert_pem = fs::read(dir.path().join("control-api/tls-cert.pem")).unwrap();
        let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(&cert_pem)
            .map(|c| c.unwrap())
            .collect();
        assert_eq!(tls.status().fingerprint, sha256_hex(certs[0].as_ref()));
    }

    #[test]
    fn status_flips_from_self_signed_to_acme() {
        let fake = Arc::new(FakeAcme::empty());
        let resolver = FallbackResolver {
            acme: fake.clone(),
            self_signed: make_certified(&["node.example.com"]),
            self_signed_fingerprint: "self-signed-fp".to_owned(),
        };
        assert_eq!(resolver.status().mode, TlsMode::SelfSigned);
        assert_eq!(resolver.status().fingerprint, "self-signed-fp");

        let acme = make_certified(&["node.example.com"]);
        let acme_fingerprint = sha256_hex(acme.cert[0].as_ref());
        fake.install(acme);
        assert_eq!(resolver.status().mode, TlsMode::Acme);
        assert_eq!(resolver.status().fingerprint, acme_fingerprint);
    }

    #[tokio::test]
    async fn handshake_serves_self_signed_then_switches_to_acme() {
        let self_signed = make_certified(&["node.example.com", "localhost"]);
        let acme_cert = make_certified(&["node.example.com"]);
        let fake = Arc::new(FakeAcme::empty());
        let fallback = FallbackResolver {
            acme: fake.clone(),
            self_signed: self_signed.clone(),
            self_signed_fingerprint: "fp".to_owned(),
        };
        let server_config = server_config(Arc::new(fallback));

        let first = handshake_leaf(server_config.clone()).await;
        assert_eq!(first.as_slice(), self_signed.cert[0].as_ref());

        fake.install(acme_cert.clone());
        let second = handshake_leaf(server_config).await;
        assert_eq!(second.as_slice(), acme_cert.cert[0].as_ref());
    }

    #[test]
    fn private_key_material_never_appears_in_debug_or_status() {
        let dir = TempDir::new("secrecy");
        let clock = ManualClock::new(SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000));
        let tls = bootstrap("node.example.com", dir.path(), &clock);
        let key_pem = fs::read_to_string(dir.path().join("control-api/tls-key.pem")).unwrap();
        assert!(key_pem.contains("PRIVATE KEY"));

        let debug = format!("{tls:?}");
        let status = format!("{:?}", tls.status());
        assert!(!debug.contains("PRIVATE KEY") && !debug.contains(&key_pem));
        assert!(!status.contains("PRIVATE KEY") && !status.contains(&key_pem));
    }
}
