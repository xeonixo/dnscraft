//! Observable TLS status for the control API / alerts.

use std::time::{Duration, SystemTime};

use crate::config::AcmeDirectoryKind;
use crate::store::LoadedCert;

/// Snapshot of certificate and DynDNS state (UI / alerts).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TlsStatus {
    /// Leaf `notAfter`, if a cert is loaded.
    pub not_after: Option<SystemTime>,
    /// Whole days remaining until `not_after` (negative when expired).
    pub days_to_expiry: Option<i64>,
    /// DNS SANs from the leaf.
    pub identifiers: Vec<String>,
    /// Last successful issue/renew wall time.
    pub last_issue: Option<SystemTime>,
    /// Last renew attempt (success or failure).
    pub last_renew_attempt: Option<SystemTime>,
    /// ACME directory URL currently configured.
    pub acme_directory: String,
    /// Whether this node creates ACME orders.
    pub acme_enabled: bool,
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
    /// Builds status from an optional loaded cert and config knobs.
    pub fn from_cert(
        loaded: Option<&LoadedCert>,
        now: SystemTime,
        expiry_warn: Duration,
        directory: &AcmeDirectoryKind,
        acme_enabled: bool,
    ) -> Self {
        let mut s = Self {
            acme_directory: directory.url().to_owned(),
            acme_enabled,
            last_error: loaded.and_then(|c| c.meta.last_error.clone()),
            ..Self::default()
        };
        let Some(cert) = loaded else {
            return s;
        };
        s.not_after = Some(cert.not_after);
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

fn days_between(now: SystemTime, not_after: SystemTime) -> i64 {
    match not_after.duration_since(now) {
        Ok(d) => (d.as_secs() / 86_400) as i64,
        Err(e) => -((e.duration().as_secs() / 86_400) as i64),
    }
}
