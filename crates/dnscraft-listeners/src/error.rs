//! Error types with stable, locale-neutral codes.
//!
//! Every error exposes a `code()` of the form `listeners.<area>.<reason>` for
//! APIs and i18n. Human-readable text is for logs, not for end users.
//!
//! ## `ListenersError` codes
//!
//! | Variant | Code |
//! |---|---|
//! | [`ListenersError::ConfigInvalid`] | `listeners.config.invalid` |
//! | [`ListenersError::ConfigPublicPlaintext`] | `listeners.config.public_plaintext` |
//! | [`ListenersError::ConfigDuplicateId`] | `listeners.config.duplicate_id` |
//! | [`ListenersError::Bind`] | `listeners.bind` |
//! | [`ListenersError::TlsNoCert`] | `listeners.tls.no_cert` |
//! | [`ListenersError::TlsHandshake`] | `listeners.tls.handshake` |
//! | [`ListenersError::AdmissionPublicDo53`] | `listeners.admission.public_do53` |
//! | [`ListenersError::AdmissionUnknownClientId`] | `listeners.admission.unknown_client_id` |
//! | [`ListenersError::RateLimited`] | `listeners.rate_limited` |
//! | [`ListenersError::Banned`] | `listeners.banned` |
//! | [`ListenersError::DohBadRequest`] | `listeners.doh.bad_request` |
//! | [`ListenersError::DoqProtocol`] | `listeners.doq.protocol` |

use std::io;

/// Top-level error of the listeners module.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]

pub enum ListenersError {
    /// Configuration values are inconsistent or out of range.
    #[error("invalid listeners config: {reason}")]
    ConfigInvalid {
        /// Why validation failed.
        reason: String,
    },
    /// A public listener uses a plaintext protocol (`udp53` / `tcp53`).
    #[error("public exposure is not allowed for plaintext protocol {protocol}")]
    ConfigPublicPlaintext {
        /// Protocol that was rejected.
        protocol: String,
    },
    /// Two listeners share the same id.
    #[error("duplicate listener id `{id}`")]
    ConfigDuplicateId {
        /// The duplicated id.
        id: String,
    },
    /// Binding a socket failed.
    #[error("bind failed on {address}: {message}")]
    Bind {
        /// Address that failed to bind.
        address: String,
        /// OS / library detail for logs.
        message: String,
    },
    /// Encrypted listener has no certificate installed.
    #[error("no TLS certificate installed")]
    TlsNoCert,
    /// TLS handshake failed.
    #[error("TLS handshake failed: {message}")]
    TlsHandshake {
        /// Detail for logs.
        message: String,
    },
    /// Do53 query or connection from a public source (dropped / closed).
    #[error("Do53 from a public source")]
    AdmissionPublicDo53,
    /// Public encrypted listener saw an unknown or missing Client ID.
    #[error("unknown or missing Client ID")]
    AdmissionUnknownClientId,
    /// Source or Client ID exceeded its token bucket.
    #[error("rate limited")]
    RateLimited,
    /// Source IP is temporarily banned.
    #[error("source banned")]
    Banned,
    /// Malformed DoH request (bad base64, wrong content-type, …).
    #[error("bad DoH request: {message}")]
    DohBadRequest {
        /// Detail for logs.
        message: String,
    },
    /// DoQ protocol violation (e.g. non-zero message id).
    #[error("DoQ protocol error: {message}")]
    DoqProtocol {
        /// Detail for logs.
        message: String,
    },
}

impl ListenersError {
    /// Stable, locale-neutral code exposed through the API.
    pub fn code(&self) -> &'static str {
        match self {
            Self::ConfigInvalid { .. } => "listeners.config.invalid",
            Self::ConfigPublicPlaintext { .. } => "listeners.config.public_plaintext",
            Self::ConfigDuplicateId { .. } => "listeners.config.duplicate_id",
            Self::Bind { .. } => "listeners.bind",
            Self::TlsNoCert => "listeners.tls.no_cert",
            Self::TlsHandshake { .. } => "listeners.tls.handshake",
            Self::AdmissionPublicDo53 => "listeners.admission.public_do53",
            Self::AdmissionUnknownClientId => "listeners.admission.unknown_client_id",
            Self::RateLimited => "listeners.rate_limited",
            Self::Banned => "listeners.banned",
            Self::DohBadRequest { .. } => "listeners.doh.bad_request",
            Self::DoqProtocol { .. } => "listeners.doq.protocol",
        }
    }

    /// Convenience constructor for [`ListenersError::ConfigInvalid`].
    pub(crate) fn config(reason: impl Into<String>) -> Self {
        Self::ConfigInvalid {
            reason: reason.into(),
        }
    }

    pub(crate) fn bind(address: impl std::fmt::Display, err: impl std::fmt::Display) -> Self {
        Self::Bind {
            address: address.to_string(),
            message: err.to_string(),
        }
    }
}

impl From<io::Error> for ListenersError {
    fn from(err: io::Error) -> Self {
        Self::Bind {
            address: String::new(),
            message: err.to_string(),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn codes_are_unique_and_well_formed() {
        let all = [
            ListenersError::config("x"),
            ListenersError::ConfigPublicPlaintext {
                protocol: "udp53".into(),
            },
            ListenersError::ConfigDuplicateId { id: "a".into() },
            ListenersError::Bind {
                address: "127.0.0.1:53".into(),
                message: "x".into(),
            },
            ListenersError::TlsNoCert,
            ListenersError::TlsHandshake {
                message: "x".into(),
            },
            ListenersError::AdmissionPublicDo53,
            ListenersError::AdmissionUnknownClientId,
            ListenersError::RateLimited,
            ListenersError::Banned,
            ListenersError::DohBadRequest {
                message: "x".into(),
            },
            ListenersError::DoqProtocol {
                message: "x".into(),
            },
        ];
        let mut codes: Vec<&str> = all.iter().map(ListenersError::code).collect();
        for code in &codes {
            assert!(
                code.starts_with("listeners."),
                "code {code} must use listeners. prefix"
            );
            assert!(
                code.chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '.' || c == '_'),
                "code {code} must be locale-neutral ascii"
            );
        }
        codes.sort_unstable();
        codes.dedup();
        assert_eq!(codes.len(), all.len(), "duplicate error codes");
    }
}
