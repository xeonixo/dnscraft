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
//! | [`TlsError::StorePermissions`] | `tls.store.permissions` |
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
        /// HTTP status when the response was received.
        status: Option<u16>,
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
    /// `key.pem` or `account.json` is readable by group/other (expected `0600`).
    ///
    /// The message names the file and mode only — never key or account bytes.
    /// Files are left in place for the operator to `chmod`.
    #[error("TLS store file {file} mode {mode:04o} allows group/other access (expected 0600)")]
    StorePermissions {
        /// Basename only (`key.pem` / `account.json`).
        file: String,
        /// Permission bits (`mode & 0o777`).
        mode: u32,
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
            Self::StorePermissions { .. } => "tls.store.permissions",
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

    /// Cloudflare HTTP error without a Retry-After hint or status.
    pub(crate) fn cloudflare_http(message: impl Into<String>) -> Self {
        Self::CloudflareHttp {
            message: message.into(),
            retry_after: None,
            status: None,
        }
    }

    /// Cloudflare HTTP error with a known status (and optional Retry-After).
    pub(crate) fn cloudflare_http_status(
        message: impl Into<String>,
        status: u16,
        retry_after: Option<Duration>,
    ) -> Self {
        Self::CloudflareHttp {
            message: message.into(),
            retry_after,
            status: Some(status),
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

/// Maximum accepted length of a `Retry-After` header value.
const RETRY_AFTER_MAX_LEN: usize = 64;

/// IMF-fixdate (RFC 9110 §5.6.7), e.g. `Sun, 06 Nov 1994 08:49:37 GMT`.
///
/// Fixed format only — no RFC 2822 comments or obsolete forms (avoids the
/// RUSTSEC-2026-0009 `Rfc2822` parser entirely).
const IMF_FIXDATE: &[time::format_description::BorrowedFormatItem<'static>] = time::macros::format_description!(
    "[weekday repr:short], [day] [month repr:short] [year] [hour]:[minute]:[second] GMT"
);

/// Parses an HTTP `Retry-After` header (RFC 9110 §10.2.3).
///
/// Accepts delta-seconds and HTTP-date as IMF-fixdate. Past dates yield a zero
/// delay. Values longer than [`RETRY_AFTER_MAX_LEN`], RFC 2822 comment forms,
/// and other non-IMF dates are rejected.
pub fn parse_retry_after_header(value: &str) -> Option<Duration> {
    let value = value.trim();
    if value.len() > RETRY_AFTER_MAX_LEN {
        return None;
    }
    if let Ok(secs) = value.parse::<u64>() {
        return Some(Duration::from_secs(secs));
    }
    // IMF-fixdate has no numeric offset; "GMT" is a literal meaning UTC.
    let then = time::PrimitiveDateTime::parse(value, &IMF_FIXDATE)
        .ok()?
        .assume_utc();
    let now = time::OffsetDateTime::now_utc();
    let secs = (then - now).whole_seconds();
    if secs <= 0 {
        Some(Duration::from_secs(0))
    } else {
        Some(Duration::from_secs(secs as u64))
    }
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
                status: Some(429),
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
            TlsError::StorePermissions {
                file: "key.pem".into(),
                mode: 0o644,
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
        assert_eq!(seen.len(), 17);
        assert_eq!(
            TlsError::CloudflareHttp {
                message: "x".into(),
                retry_after: Some(Duration::from_secs(30)),
                status: Some(429),
            }
            .retry_after(),
            Some(Duration::from_secs(30))
        );
        assert_eq!(TlsError::AcmePropagation.retry_after(), None);
    }

    #[test]
    fn retry_after_delta_seconds() {
        assert_eq!(
            parse_retry_after_header(" 45 "),
            Some(Duration::from_secs(45))
        );
        assert_eq!(parse_retry_after_header("0"), Some(Duration::from_secs(0)));
    }

    #[test]
    fn retry_after_imf_fixdate_past_is_zero() {
        assert_eq!(
            parse_retry_after_header("Wed, 01 Jan 2020 00:00:00 GMT"),
            Some(Duration::from_secs(0))
        );
    }

    #[test]
    fn retry_after_imf_fixdate_future_is_positive() {
        let delay =
            parse_retry_after_header("Wed, 01 Jan 2098 00:00:00 GMT").expect("future IMF-fixdate");
        assert!(
            delay > Duration::from_secs(3600),
            "expected multi-hour delay, got {delay:?}"
        );
    }

    #[test]
    fn retry_after_rejects_rfc2822_comments_and_overlong() {
        // Nested comments are valid RFC 2822 but not IMF-fixdate — must not parse.
        assert_eq!(parse_retry_after_header("(a(b(c)))"), None);
        assert_eq!(
            parse_retry_after_header("Wed, 01 Jan 2020 00:00:00 GMT (comment)"),
            None
        );
        let overlong = "x".repeat(RETRY_AFTER_MAX_LEN + 1);
        assert_eq!(parse_retry_after_header(&overlong), None);
    }
}
