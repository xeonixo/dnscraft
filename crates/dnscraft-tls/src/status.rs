//! Observable TLS status for the control API / alerts.

use std::time::{Duration, SystemTime};

use serde::{Deserialize, Serialize};

use crate::config::AcmeDirectoryKind;
use crate::store::{IssueState, LoadedCert};

/// Where the served certificate came from.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CertSource {
    /// Issued by ACME (or the bootstrap self-signed fallback).
    #[default]
    Acme,
    /// Uploaded by an operator and persisted in the store.
    Manual,
}

/// Parsed leaf-certificate detail exposed in [`TlsStatus`].
///
/// Cert-only: this type never carries private key material.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CertDetail {
    /// Leaf `notBefore`.
    pub not_before: Option<SystemTime>,
    /// Issuer distinguished name (RFC 4514).
    pub issuer: Option<String>,
    /// Subject distinguished name (RFC 4514).
    pub subject: Option<String>,
    /// Leaf serial as colon-separated upper-case hex.
    pub serial: Option<String>,
    /// Signature algorithm short name (e.g. `ecdsa-with-SHA256`).
    pub signature_algorithm: Option<String>,
    /// Basic key-usage flags (e.g. `digitalSignature`, `keyCertSign`).
    pub key_usage: Vec<String>,
    /// Served chain as PEM blocks, leaf first, certificates only.
    pub chain: Vec<String>,
}

/// ACME Renewal Information (ARI, RFC 9773) state for the stored leaf.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AriStatus {
    /// Suggested window start, when the CA returned one.
    pub suggested_window_start: Option<SystemTime>,
    /// Suggested window end, when the CA returned one.
    pub suggested_window_end: Option<SystemTime>,
    /// ARI certificate id (`<aki>.<serial>`), when derivable.
    pub certificate_id: Option<String>,
    /// `true` when the CA returned a suggested window.
    pub supported: bool,
}

impl AriStatus {
    /// Builds status from an optional suggested window and certificate id.
    pub fn new(
        start: Option<SystemTime>,
        end: Option<SystemTime>,
        certificate_id: Option<String>,
    ) -> Self {
        Self {
            suggested_window_start: start,
            suggested_window_end: end,
            certificate_id,
            supported: start.is_some() && end.is_some(),
        }
    }
}

/// Outcome of one issue/renew attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IssueOutcome {
    /// First certificate obtained.
    Issued,
    /// Existing certificate replaced.
    Renewed,
    /// Attempt failed; the previous certificate (if any) is kept.
    Failed,
}

/// One bounded issue/renew history entry (`state.json`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IssueRecord {
    /// Wall time of the attempt.
    pub timestamp: SystemTime,
    /// Attempt outcome.
    pub outcome: IssueOutcome,
    /// Stable `tls.*` error code on failure.
    #[serde(default)]
    pub error: Option<String>,
    /// Leaf serial after a successful attempt.
    #[serde(default)]
    pub serial: Option<String>,
}

/// On-disk store health for the status UI.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct StoreHealth {
    /// Directory that holds the TLS files.
    pub path: String,
    /// `true` when a probe file could be created and removed.
    pub writable: bool,
    /// Last successful write time (`cert.pem` or `state.json` mtime).
    pub last_write: Option<SystemTime>,
    /// `true` when the stored certificate/key cannot be loaded.
    pub corrupt: bool,
}

/// One DynDNS write (audit trail entry, persisted in `state.json`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DynDnsAuditEntry {
    /// Wall time of the write.
    pub timestamp: SystemTime,
    /// Record owner name.
    pub name: String,
    /// Record type (`A` / `AAAA`).
    pub record_type: String,
    /// Value written.
    pub content: String,
}

/// Rate-limit / quota visibility for the most recent ACME attempt.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RateLimitStatus {
    /// `true` when the last attempt was rejected by a CA rate limit.
    pub limited: bool,
    /// Parsed `Retry-After` delay, when the CA provided one.
    pub retry_after: Option<Duration>,
    /// Wall time at which a retry is allowed, when known.
    pub retry_at: Option<SystemTime>,
}

/// One preflight check result.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreflightCheck {
    /// Check name (stable identifier).
    pub name: String,
    /// `true` when the check passed.
    pub ok: bool,
    /// Stable `tls.*` code when the check failed.
    pub code: Option<String>,
    /// Human-readable detail for logs.
    pub message: Option<String>,
}

/// Dry-run report returned by [`crate::TlsEngine::preflight`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreflightReport {
    /// `true` when every check passed.
    pub ok: bool,
    /// Individual checks.
    pub checks: Vec<PreflightCheck>,
}

impl PreflightReport {
    /// Builds a report from individual checks (sets [`Self::ok`]).
    pub fn from_checks(checks: Vec<PreflightCheck>) -> Self {
        Self {
            ok: checks.iter().all(|c| c.ok),
            checks,
        }
    }

    /// Converts a failed report into [`crate::TlsError::AcmePreflightFailed`].
    pub fn into_result(self) -> Result<Self, crate::TlsError> {
        if self.ok {
            Ok(self)
        } else {
            let failed = self
                .checks
                .iter()
                .filter(|c| !c.ok)
                .map(|c| c.name.as_str())
                .collect::<Vec<_>>()
                .join(", ");
            Err(crate::TlsError::AcmePreflightFailed {
                message: format!("failed checks: {failed}"),
            })
        }
    }
}

/// Numbers for a metrics exporter (SPEC-tls.md Observability). Counters are
/// process-lifetime totals since the engine opened.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TlsMetrics {
    /// Whole days until the served certificate expires (negative when expired).
    pub days_to_expiry: Option<i64>,
    /// ACME issuances/renewals that succeeded.
    pub renew_success_total: u64,
    /// ACME issuances/renewals that failed.
    pub renew_failure_total: u64,
}

/// Snapshot of certificate and DynDNS state (UI / alerts).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TlsStatus {
    /// Leaf `notAfter`, if a cert is loaded.
    pub not_after: Option<SystemTime>,
    /// Leaf `notBefore`, if a cert is loaded.
    pub not_before: Option<SystemTime>,
    /// Leaf issuer distinguished name (RFC 4514).
    pub issuer: Option<String>,
    /// Leaf subject distinguished name (RFC 4514).
    pub subject: Option<String>,
    /// Leaf serial as colon-separated upper-case hex.
    pub serial: Option<String>,
    /// Leaf signature algorithm short name.
    pub signature_algorithm: Option<String>,
    /// Leaf basic key-usage flags.
    pub key_usage: Vec<String>,
    /// Served chain as PEM blocks (leaf first, certificates only).
    pub chain: Vec<String>,
    /// Where the served certificate came from.
    pub source: CertSource,
    /// Whole days remaining until `not_after` (negative when expired).
    pub days_to_expiry: Option<i64>,
    /// DNS SANs from the leaf.
    pub identifiers: Vec<String>,
    /// Last successful issue/renew wall time.
    pub last_issue: Option<SystemTime>,
    /// Last renew attempt (success or failure).
    pub last_renew_attempt: Option<SystemTime>,
    /// Bounded (last 10) issue/renew history.
    pub history: Vec<IssueRecord>,
    /// ACME directory URL currently configured.
    pub acme_directory: String,
    /// Whether this node creates ACME orders.
    pub acme_enabled: bool,
    /// ARI state for the stored leaf, when a certificate exists.
    pub ari: Option<AriStatus>,
    /// When the next renewal is scheduled.
    pub next_renew_at: Option<SystemTime>,
    /// When the next DynDNS pass is scheduled.
    pub next_dyndns_at: Option<SystemTime>,
    /// Last successful DynDNS pass wall time.
    pub last_dyndns_success: Option<SystemTime>,
    /// `true` when the last DynDNS pass failed.
    pub dyndns_stale: bool,
    /// Store health snapshot.
    pub store: Option<StoreHealth>,
    /// `true` when the stored certificate was revoked locally.
    pub revoked: bool,
    /// Last stable error code (`tls.*`), if any.
    pub last_error: Option<String>,
    /// `true` when days-to-expiry is below the warn threshold (and not yet expired).
    pub cert_expiring: bool,
    /// `true` when `not_after` is in the past.
    pub cert_expired: bool,
    /// Last DynDNS IPv4 (L9).
    pub dyndns_ipv4: Option<String>,
    /// Last DynDNS IPv6 (L9).
    pub dyndns_ipv6: Option<String>,
    /// Last successful DynDNS change time (L9).
    pub dyndns_last_change: Option<SystemTime>,
}

impl TlsStatus {
    /// Builds status from an optional loaded cert, the persisted issue state
    /// ([`crate::CertStore::load_state`]) and config knobs.
    ///
    /// ARI, scheduling and store health are filled by [`crate::TlsEngine`],
    /// which owns those inputs.
    pub fn from_cert(
        loaded: Option<&LoadedCert>,
        state: &IssueState,
        now: SystemTime,
        expiry_warn: Duration,
        directory: &AcmeDirectoryKind,
        acme_enabled: bool,
    ) -> Self {
        let mut s = Self {
            acme_directory: directory.url().to_owned(),
            acme_enabled,
            last_error: state.last_error.clone(),
            last_issue: state.last_issue_unix.map(unix_to_system),
            last_renew_attempt: state.last_renew_attempt_unix.map(unix_to_system),
            history: state.history.clone(),
            revoked: state.revoked,
            ..Self::default()
        };
        let Some(cert) = loaded else {
            return s;
        };
        s.not_after = Some(cert.not_after);
        s.not_before = cert.detail.not_before;
        s.issuer = cert.detail.issuer.clone();
        s.subject = cert.detail.subject.clone();
        s.serial = cert.detail.serial.clone();
        s.signature_algorithm = cert.detail.signature_algorithm.clone();
        s.key_usage = cert.detail.key_usage.clone();
        s.chain = cert.detail.chain.clone();
        s.source = cert.meta.source;
        s.identifiers = cert.identifiers.clone();
        s.days_to_expiry = Some(days_between(now, cert.not_after));
        let (expiring, expired) = cert_flags(cert.not_after, now, expiry_warn);
        s.cert_expiring = expiring;
        s.cert_expired = expired;
        s
    }
}

/// Returns `(cert_expiring, cert_expired)`.
///
/// - Expired when `now >= not_after`.
/// - Expiring when not expired and `not_after - now < expiry_warn`.
pub fn cert_flags(not_after: SystemTime, now: SystemTime, expiry_warn: Duration) -> (bool, bool) {
    if now >= not_after {
        return (false, true);
    }
    let remaining = not_after.duration_since(now).unwrap_or(Duration::ZERO);
    (remaining < expiry_warn, false)
}

fn unix_to_system(secs: i64) -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(secs.max(0) as u64)
}

fn days_between(now: SystemTime, not_after: SystemTime) -> i64 {
    match not_after.duration_since(now) {
        Ok(d) => (d.as_secs() / 86_400) as i64,
        Err(e) => -((e.duration().as_secs() / 86_400) as i64),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::pem_util::{KeyPem, parse_leaf_info};
    use rcgen::{KeyPair, PKCS_ECDSA_P256_SHA256};

    #[test]
    fn cert_detail_is_parsed_cert_only() {
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let key_pem = key.serialize_pem();
        let params = rcgen::CertificateParams::new(vec![
            "dns.example.com".into(),
            "*.dns.example.com".into(),
        ])
        .unwrap();
        let cert = params.self_signed(&key).unwrap();
        let chain = cert.pem();

        let info = parse_leaf_info(chain.as_bytes()).unwrap();
        let detail = &info.detail;
        assert!(detail.not_before.is_some());
        assert!(detail.issuer.as_deref().is_some_and(|s| !s.is_empty()));
        assert!(detail.subject.as_deref().is_some_and(|s| !s.is_empty()));
        let serial = detail.serial.as_deref().unwrap();
        assert!(!serial.is_empty());
        assert!(
            serial
                .split(':')
                .all(|p| p.len() == 2 && p.chars().all(|c| c.is_ascii_hexdigit())),
            "{serial}"
        );
        assert_eq!(
            detail.signature_algorithm.as_deref(),
            Some("ecdsa-with-SHA256")
        );
        assert_eq!(detail.chain.len(), 1);
        assert!(detail.chain[0].starts_with("-----BEGIN CERTIFICATE-----"));

        let loaded = LoadedCert {
            chain_pem: chain.into_bytes(),
            key: KeyPem::from_bytes(key_pem.clone().into_bytes()),
            not_after: info.not_after,
            identifiers: info.identifiers.clone(),
            meta: crate::store::CertMeta {
                source: CertSource::Manual,
                ..Default::default()
            },
            detail: info.detail,
        };
        let state = IssueState {
            history: vec![IssueRecord {
                timestamp: SystemTime::UNIX_EPOCH,
                outcome: IssueOutcome::Issued,
                error: None,
                serial: Some("AB".into()),
            }],
            revoked: true,
            ..IssueState::default()
        };
        let status = TlsStatus::from_cert(
            Some(&loaded),
            &state,
            info.not_after - Duration::from_secs(86_400),
            Duration::from_secs(14 * 86_400),
            &AcmeDirectoryKind::Staging,
            true,
        );
        assert_eq!(status.source, CertSource::Manual);
        assert_eq!(status.history.len(), 1);
        assert!(status.revoked);
        assert!(status.cert_expiring);
        assert!(!format!("{status:?}").contains("PRIVATE KEY"));
        assert!(!format!("{status:?}").contains(&key_pem));
    }

    #[test]
    fn ari_status_supported_requires_both_bounds() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        assert!(!AriStatus::new(Some(now), None, None).supported);
        let ari = AriStatus::new(
            Some(now),
            Some(now + Duration::from_secs(60)),
            Some("id".into()),
        );
        assert!(ari.supported);
        assert_eq!(ari.certificate_id.as_deref(), Some("id"));
    }

    #[test]
    fn preflight_into_result_reports_failed_checks() {
        let ok = PreflightReport::from_checks(vec![PreflightCheck {
            name: "config".into(),
            ok: true,
            code: None,
            message: None,
        }]);
        assert!(ok.clone().into_result().is_ok());
        let bad = PreflightReport::from_checks(vec![
            PreflightCheck {
                name: "config".into(),
                ok: true,
                code: None,
                message: None,
            },
            PreflightCheck {
                name: "store".into(),
                ok: false,
                code: Some("tls.store.unhealthy".into()),
                message: None,
            },
        ]);
        let err = bad.into_result().expect_err("not ok");
        assert_eq!(err.code(), "tls.acme.preflight.failed");
        assert!(err.to_string().contains("store"));
    }
}
