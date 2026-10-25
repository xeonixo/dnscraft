//! Error types with stable, locale-neutral codes.
//!
//! Every error exposes a `code()` of the form `area.reason` for APIs and i18n.
//! Human-readable text is for logs, not for end users.
//!
//! Rate-limit hints live on [`TlsError::retry_after`] (structured
//! [`Duration`]), not buried in the message string.
//!
//! ## `TlsError` codes
//!
//! | Variant | Code |
//! |---|---|
//! | [`TlsError::ConfigInvalid`] | `tls.config.invalid` |
//! | [`TlsError::SecretMissing`] | `tls.secret.missing` |
//! | [`TlsError::AcmeAccount`] | `tls.acme.account` |
//! | [`TlsError::AcmeOrder`] | `tls.acme.order` |
//! | [`TlsError::AcmeChallenge`] | `tls.acme.challenge` |
//! | [`TlsError::AcmeRateLimited`] | `tls.acme.rate_limited` |
//! | [`TlsError::AcmePropagation`] | `tls.acme.propagation` |
//! | [`TlsError::CloudflareHttp`] | `tls.cloudflare.http` |
//! | [`TlsError::CloudflareZone`] | `tls.cloudflare.zone` |
//! | [`TlsError::StoreIo`] | `tls.store.io` |
//! | [`TlsError::StoreCorrupt`] | `tls.store.corrupt` |
//! | [`TlsError::DyndnsEcho`] | `tls.dyndns.echo` |
//! | [`TlsError::DyndnsUpdate`] | `tls.dyndns.update` |
//! | [`TlsError::DyndnsEntryConflict`] | `tls.dyndns.entry_conflict` |
//! | [`TlsError::CertExpiring`] | `tls.cert.expiring` |
//! | [`TlsError::CertExpired`] | `tls.cert.expired` |

use std::time::Duration;

/// Top-level error of the TLS module.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum TlsError {
    /// Configuration values are inconsistent or out of range.
    #[error("invalid TLS config: {reason}")]
    ConfigInvalid {
        /// Why validation failed.
        reason: String,
    },
    /// A required secret env var / `*_FILE` is absent or empty.
    #[error("secret {name} is missing")]
    SecretMissing {
        /// Environment variable name (not the secret value).
        name: String,
    },
    /// ACME account create or load failed.
    #[error("ACME account error: {message}")]
    AcmeAccount {
        /// Detail for logs.
        message: String,
    },
    /// ACME new-order or finalize failed.
    #[error("ACME order error: {message}")]
    AcmeOrder {
        /// Detail for logs.
        message: String,
    },
    /// DNS-01 challenge ready/validation failed.
    #[error("ACME challenge error: {message}")]
    AcmeChallenge {
        /// Detail for logs.
        message: String,
    },
    /// Let's Encrypt rate limit or Retry-After.
    #[error("ACME rate limited: {message}")]
    AcmeRateLimited {
        /// Detail for logs.
        message: String,
        /// Parsed `Retry-After` delay when the CA provided one.
        retry_after: Option<Duration>,
    },
    /// Challenge TXT not visible on authoritative nameservers before timeout.
    #[error("ACME DNS-01 propagation timed out")]
    AcmePropagation,
    /// Cloudflare API non-success (including 401/403/429).
    #[error("Cloudflare API error: {message}")]
    CloudflareHttp {
        /// Detail for logs (must not include the API token).
        message: String,
        /// Parsed `Retry-After` delay when the API provided one.
        retry_after: Option<Duration>,
    },
    /// Zone id / name resolution failed.
    #[error("Cloudflare zone not found: {message}")]
    CloudflareZone {
        /// Detail for logs.
        message: String,
    },
    /// Disk read/write/permissions for the certificate store.
    #[error("TLS store I/O: {message}")]
    StoreIo {
        /// Detail for logs.
        message: String,
    },
    /// PEM or metadata unreadable; previous material is kept when present.
    #[error("TLS store corrupt: {message}")]
    StoreCorrupt {
        /// Detail for logs.
        message: String,
    },
    /// Public IP echo failed or was unparseable.
    #[error("DynDNS echo failed: {message}")]
    DyndnsEcho {
        /// Detail for logs.
        message: String,
    },
    /// A/AAAA upsert failed (node, wildcard, or apex).
    #[error("DynDNS update failed: {message}")]
    DyndnsUpdate {
        /// Detail for logs.
        message: String,
    },
    /// More than one node claims `public_entry`.
    #[error("more than one node claims public_entry")]
    DyndnsEntryConflict,
    /// Status flag: days-to-expiry is below the warn threshold.
    #[error("certificate is expiring")]
    CertExpiring,
    /// Status flag: `not_after` is in the past.
    #[error("certificate has expired")]
    CertExpired,
}

impl TlsError {
    /// Stable, locale-neutral code exposed through the API.
    pub fn code(&self) -> &'static str {
        match self {
            Self::ConfigInvalid { .. } => "tls.config.invalid",
            Self::SecretMissing { .. } => "tls.secret.missing",
            Self::AcmeAccount { .. } => "tls.acme.account",
            Self::AcmeOrder { .. } => "tls.acme.order",
            Self::AcmeChallenge { .. } => "tls.acme.challenge",
            Self::AcmeRateLimited { .. } => "tls.acme.rate_limited",
            Self::AcmePropagation => "tls.acme.propagation",
            Self::CloudflareHttp { .. } => "tls.cloudflare.http",
            Self::CloudflareZone { .. } => "tls.cloudflare.zone",
            Self::StoreIo { .. } => "tls.store.io",
            Self::StoreCorrupt { .. } => "tls.store.corrupt",
            Self::DyndnsEcho { .. } => "tls.dyndns.echo",
            Self::DyndnsUpdate { .. } => "tls.dyndns.update",
            Self::DyndnsEntryConflict => "tls.dyndns.entry_conflict",
            Self::CertExpiring => "tls.cert.expiring",
            Self::CertExpired => "tls.cert.expired",
        }
    }

    /// Convenience constructor for [`TlsError::ConfigInvalid`].
    pub(crate) fn config(reason: impl Into<String>) -> Self {
        Self::ConfigInvalid {
            reason: reason.into(),
        }
    }

    /// Cloudflare HTTP error without a Retry-After hint.
    pub(crate) fn cloudflare_http(message: impl Into<String>) -> Self {
        Self::CloudflareHttp {
            message: message.into(),
            retry_after: None,
        }
    }

    /// Structured `Retry-After` delay, when the upstream provided one.
    ///
    /// Prefer this over scraping [`Display`] / message text.
    pub fn retry_after(&self) -> Option<Duration> {
        match self {
            Self::CloudflareHttp { retry_after, .. }
            | Self::AcmeRateLimited { retry_after, .. } => *retry_after,
            _ => None,
        }
    }
}

/// Parses an HTTP `Retry-After` header value as a delay in seconds.
///
/// HTTP-date forms are ignored (Cloudflare and ACME use delta-seconds).
pub fn parse_retry_after_header(value: &str) -> Option<Duration> {
    let secs: u64 = value.trim().parse().ok()?;
    Some(Duration::from_secs(secs))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn codes_are_unique_and_well_formed() {
        let all: Vec<TlsError> = vec![
            TlsError::config("x"),
            TlsError::SecretMissing { name: "X".into() },
            TlsError::AcmeAccount {
                message: "x".into(),
            },
            TlsError::AcmeOrder {
                message: "x".into(),
            },
            TlsError::AcmeChallenge {
                message: "x".into(),
            },
            TlsError::AcmeRateLimited {
                message: "x".into(),
                retry_after: Some(Duration::from_secs(12)),
            },
            TlsError::AcmePropagation,
            TlsError::CloudflareHttp {
                message: "x".into(),
                retry_after: Some(Duration::from_secs(30)),
            },
            TlsError::CloudflareZone {
                message: "x".into(),
            },
            TlsError::StoreIo {
                message: "x".into(),
            },
            TlsError::StoreCorrupt {
                message: "x".into(),
            },
            TlsError::DyndnsEcho {
                message: "x".into(),
            },
            TlsError::DyndnsUpdate {
                message: "x".into(),
            },
            TlsError::DyndnsEntryConflict,
            TlsError::CertExpiring,
            TlsError::CertExpired,
        ];
        let mut seen = std::collections::HashSet::new();
        for err in &all {
            let code = err.code();
            assert!(seen.insert(code), "duplicate code {code}");
            let (area, reason) = code.split_once('.').expect("area.reason");
            assert_eq!(area, "tls");
            let ok =
                |s: &str| !s.is_empty() && s.chars().all(|c| c.is_ascii_lowercase() || c == '_');
            // reason may contain a further dot (e.g. config.invalid)
            for part in reason.split('.') {
                assert!(ok(part), "{code}");
            }
            assert!(!err.to_string().is_empty());
        }
        assert_eq!(seen.len(), 16);
        assert_eq!(
            TlsError::CloudflareHttp {
                message: "x".into(),
                retry_after: Some(Duration::from_secs(30)),
            }
            .retry_after(),
            Some(Duration::from_secs(30))
        );
        assert_eq!(TlsError::AcmePropagation.retry_after(), None);
        assert_eq!(
            parse_retry_after_header(" 45 "),
            Some(Duration::from_secs(45))
        );
        assert_eq!(parse_retry_after_header("Wed, 01 Jan 2020"), None);
    }
}
