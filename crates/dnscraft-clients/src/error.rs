//! Error types with stable, locale-neutral codes.
//!
//! Every error exposes a `code()` of the form `area.reason` for APIs and i18n.
//! Human-readable text is for logs, not for end users.
//!
//! ## `ClientsError` codes
//!
//! | Variant | Code |
//! |---|---|
//! | [`ClientsError::ConfigInvalid`] | `clients.config.invalid` |
//! | [`ClientsError::SecretMissing`] | `clients.secret.missing` |
//! | [`ClientsError::TlsUntrusted`] | `clients.tls.untrusted` |
//! | [`ClientsError::TlsHandshake`] | `clients.tls.handshake` |
//! | [`ClientsError::Connect`] | `clients.connect` |
//! | [`ClientsError::HttpStatus`] | `clients.http.status` |
//! | [`ClientsError::HttpBody`] | `clients.http.body` |
//! | [`ClientsError::SyncPartial`] | `clients.sync.partial` |
//! | [`ClientsError::SyncBackoff`] | `clients.sync.backoff` |
//! | [`ClientsError::SyncNotOwner`] | `clients.sync.not_owner` |
//! | [`ClientsError::TooMany`] | `clients.too_many` |
//! | [`ClientsError::IpConflict`] | `clients.ip.conflict` |
//! | [`ClientsError::NameCollision`] | `clients.name.collision` |

/// Top-level error of the clients module.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]

pub enum ClientsError {
    /// Configuration values are inconsistent or out of range.
    #[error("invalid clients config: {reason}")]
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
    /// Gateway certificate does not match the configured pin or CA.
    #[error("gateway TLS untrusted: {message}")]
    TlsUntrusted {
        /// Detail for logs.
        message: String,
    },
    /// Other TLS handshake failures (protocol, alert, …).
    #[error("gateway TLS handshake failed: {message}")]
    TlsHandshake {
        /// Detail for logs.
        message: String,
    },
    /// TCP connect or DNS resolution of the gateway hostname failed.
    #[error("gateway connect failed: {message}")]
    Connect {
        /// Detail for logs.
        message: String,
    },
    /// Non-success HTTP status from the gateway (incl. 401/403/429).
    #[error("gateway HTTP {status}: {message}")]
    HttpStatus {
        /// HTTP status code.
        status: u16,
        /// Detail for logs (must not include the API key).
        message: String,
    },
    /// Response body unusable (truncated, oversize, fatal JSON parse).
    #[error("gateway HTTP body error: {message}")]
    HttpBody {
        /// Detail for logs.
        message: String,
    },
    /// Some pages of a sync failed; the last good snapshot is kept.
    #[error("sync partial: {message}")]
    SyncPartial {
        /// Detail for logs.
        message: String,
    },
    /// [`ClientEngine::sync_now`] refused because a 429/5xx backoff window is active.
    #[error("sync backoff active: {message}")]
    SyncBackoff {
        /// Detail for logs.
        message: String,
    },
    /// This node is bound to a UniFi profile but is not its `sync_owner`.
    #[error("sync not owner: {message}")]
    SyncNotOwner {
        /// Detail for logs.
        message: String,
    },
    /// Hard client / address cap exceeded.
    #[error("too many clients: {message}")]
    TooMany {
        /// Detail for logs.
        message: String,
    },
    /// Informational: two clients claimed one IP; loser dropped from the index.
    ///
    /// Usually surfaced as a counter rather than a fatal apply failure.
    #[error("IP conflict: {message}")]
    IpConflict {
        /// Detail for logs.
        message: String,
    },
    /// Reserved for validation that refuses ambiguous manuals (rare; usually auto-suffix).
    #[error("name collision: {message}")]
    NameCollision {
        /// Detail for logs.
        message: String,
    },
}

impl ClientsError {
    /// Stable, locale-neutral code exposed through the API.
    pub fn code(&self) -> &'static str {
        match self {
            Self::ConfigInvalid { .. } => "clients.config.invalid",
            Self::SecretMissing { .. } => "clients.secret.missing",
            Self::TlsUntrusted { .. } => "clients.tls.untrusted",
            Self::TlsHandshake { .. } => "clients.tls.handshake",
            Self::Connect { .. } => "clients.connect",
            Self::HttpStatus { .. } => "clients.http.status",
            Self::HttpBody { .. } => "clients.http.body",
            Self::SyncPartial { .. } => "clients.sync.partial",
            Self::SyncBackoff { .. } => "clients.sync.backoff",
            Self::SyncNotOwner { .. } => "clients.sync.not_owner",
            Self::TooMany { .. } => "clients.too_many",
            Self::IpConflict { .. } => "clients.ip.conflict",
            Self::NameCollision { .. } => "clients.name.collision",
        }
    }

    /// Convenience constructor for [`ClientsError::ConfigInvalid`].
    pub(crate) fn config(reason: impl Into<String>) -> Self {
        Self::ConfigInvalid {
            reason: reason.into(),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn codes_are_unique_and_well_formed() {
        let all: Vec<ClientsError> = vec![
            ClientsError::config("x"),
            ClientsError::SecretMissing { name: "X".into() },
            ClientsError::TlsUntrusted {
                message: "x".into(),
            },
            ClientsError::TlsHandshake {
                message: "x".into(),
            },
            ClientsError::Connect {
                message: "x".into(),
            },
            ClientsError::HttpStatus {
                status: 401,
                message: "x".into(),
            },
            ClientsError::HttpBody {
                message: "x".into(),
            },
            ClientsError::SyncPartial {
                message: "x".into(),
            },
            ClientsError::SyncBackoff {
                message: "x".into(),
            },
            ClientsError::SyncNotOwner {
                message: "x".into(),
            },
            ClientsError::TooMany {
                message: "x".into(),
            },
            ClientsError::IpConflict {
                message: "x".into(),
            },
            ClientsError::NameCollision {
                message: "x".into(),
            },
        ];
        let mut seen = std::collections::HashSet::new();
        for err in &all {
            let code = err.code();
            assert!(seen.insert(code), "duplicate code {code}");
            let (area, reason) = code.split_once('.').expect("area.reason");
            assert_eq!(area, "clients");
            let ok =
                |s: &str| !s.is_empty() && s.chars().all(|c| c.is_ascii_lowercase() || c == '_');
            for part in reason.split('.') {
                assert!(ok(part), "{code}");
            }
            assert!(!err.to_string().is_empty());
        }
        assert_eq!(seen.len(), 13);
    }
}
