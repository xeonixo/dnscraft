//! Cluster errors with stable `cluster.<area>.<reason>` codes.
//!
//! The codes in the table of `SPEC-cluster.md` § Error codes are reproduced
//! verbatim. [`ClusterError::Internal`] is the crate's fallback for backend
//! failures (filesystem, rcgen, SQLite) that have no protocol-level code; it is
//! never used for a condition the spec names.

/// Top-level error of the cluster module.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ClusterError {
    /// Role/config mismatch detected at startup.
    #[error("invalid cluster configuration: {reason}")]
    RoleInvalid {
        /// Why validation failed.
        reason: String,
    },
    /// A sub-node cannot reach the master for an operation that cannot be buffered.
    #[error("cluster master unavailable")]
    MasterUnavailable,
    /// A second master or a node version ahead of the master was detected.
    #[error("cluster master conflict")]
    MasterConflict,
    /// `node_id` or certificate fingerprint is not registered on the master.
    #[error("unknown cluster node {node_id}")]
    NodeUnknown {
        /// The unregistered node.
        node_id: String,
    },
    /// Revoked node identity.
    #[error("cluster node {node_id} is revoked")]
    NodeRevoked {
        /// The revoked node.
        node_id: String,
    },
    /// The node is still active and cannot be removed.
    #[error("cluster node {node_id} is not revoked")]
    NodeNotRevoked {
        /// The active node.
        node_id: String,
    },
    /// `node_id` is already registered.
    #[error("cluster node {node_id} has already joined")]
    NodeAlreadyJoined {
        /// The already-registered node.
        node_id: String,
    },
    /// Join token unknown, already used, or bound to another `node_id`.
    #[error("join token is invalid")]
    JoinTokenInvalid,
    /// Join token past its TTL.
    #[error("join token has expired")]
    JoinTokenExpired,
    /// mTLS handshake or certificate validation failure.
    #[error("cluster transport TLS failure: {message}")]
    TransportTls {
        /// Detail for logs (never key material).
        message: String,
    },
    /// Unsupported cluster protocol version.
    #[error("unsupported cluster protocol version")]
    ProtocolVersion,
    /// A sub-node failed to apply a pushed snapshot.
    #[error("cluster config apply failed: {message}")]
    ConfigApply {
        /// Detail for logs.
        message: String,
    },
    /// A sub-node's applied version is behind the master beyond the threshold.
    #[error("cluster config is stale")]
    ConfigStale,
    /// Forwarded write transport failed before a master response.
    #[error("cluster write relay failed")]
    WriteRelayFailed,
    /// Offline buffering requested without `Idempotency-Key` or `If-Match`.
    #[error("offline writes require Idempotency-Key and If-Match")]
    OfflineWriteRequiresIdempotency,
    /// Offline queue cap reached.
    #[error("cluster offline write queue is full")]
    OfflineWriteQueueFull,
    /// Buffered write returned `409` on replay and was not applied.
    #[error("cluster offline write conflicted on replay")]
    OfflineWriteConflict,
    /// Buffered write exceeded `max_age` and was dropped.
    #[error("cluster offline write expired")]
    OfflineWriteExpired,
    /// Malformed, oversized, out-of-order or `node_id`-mismatched log batch.
    #[error("invalid cluster log batch: {reason}")]
    LogStreamInvalid {
        /// Why the batch was rejected.
        reason: String,
    },
    /// A sub-node dropped buffered log rows (informational/status count).
    #[error("dropped {count} buffered log rows")]
    LogBufferDropped {
        /// Number of rows dropped.
        count: u64,
    },
    /// A batch arrived after a sequence gap (informational/status count).
    #[error("cluster log gap of {missing} sequence(s)")]
    LogGap {
        /// Number of missing sequence numbers.
        missing: u64,
    },
    /// A node failed to apply a broadcast runtime command.
    #[error("runtime command failed: {message}")]
    RuntimeCommandFailed {
        /// Detail for logs.
        message: String,
    },
    /// A sub-node failed to install a pushed certificate/key.
    #[error("certificate push failed: {message}")]
    CertPushFailed {
        /// Detail for logs.
        message: String,
    },
    /// Node clock skew above the threshold (status warning).
    #[error("cluster clock skew detected")]
    ClockSkew,
    /// A node exceeded one of its `[cluster.quota]` rate limits (HTTP 429).
    #[error("quota exceeded for node {node_id}: {what}")]
    QuotaExceeded {
        /// The node that exceeded the quota.
        node_id: String,
        /// Which quota (`relay request` / `log byte`).
        what: String,
    },
    /// Backend failure (filesystem, rcgen, SQLite). Crate-internal fallback.
    #[error("cluster internal error: {message}")]
    Internal {
        /// Detail for logs.
        message: String,
    },
}

impl ClusterError {
    /// Stable, locale-neutral code exposed through the API.
    pub fn code(&self) -> &'static str {
        match self {
            Self::RoleInvalid { .. } => "cluster.role.invalid",
            Self::MasterUnavailable => "cluster.master_unavailable",
            Self::MasterConflict => "cluster.master_conflict",
            Self::NodeUnknown { .. } => "cluster.node.unknown",
            Self::NodeRevoked { .. } => "cluster.node.revoked",
            Self::NodeNotRevoked { .. } => "cluster.node.not_revoked",
            Self::NodeAlreadyJoined { .. } => "cluster.node.already_joined",
            Self::JoinTokenInvalid => "cluster.join.token_invalid",
            Self::JoinTokenExpired => "cluster.join.token_expired",
            Self::TransportTls { .. } => "cluster.transport.tls",
            Self::ProtocolVersion => "cluster.protocol.version",
            Self::ConfigApply { .. } => "cluster.config.apply",
            Self::ConfigStale => "cluster.config.stale",
            Self::WriteRelayFailed => "cluster.write_relay_failed",
            Self::OfflineWriteRequiresIdempotency => "cluster.offline_write_requires_idempotency",
            Self::OfflineWriteQueueFull => "cluster.offline_write_queue_full",
            Self::OfflineWriteConflict => "cluster.offline_write_conflict",
            Self::OfflineWriteExpired => "cluster.offline_write_expired",
            Self::LogStreamInvalid { .. } => "cluster.log_stream.invalid",
            Self::LogBufferDropped { .. } => "cluster.log_buffer_dropped",
            Self::LogGap { .. } => "cluster.log_gap",
            Self::RuntimeCommandFailed { .. } => "cluster.runtime_command.failed",
            Self::CertPushFailed { .. } => "cluster.cert_push.failed",
            Self::ClockSkew => "cluster.clock_skew",
            Self::QuotaExceeded { .. } => "cluster.quota.exceeded",
            Self::Internal { .. } => "cluster.internal",
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    /// One instance of every variant, so the code list is exhaustive by
    /// construction.
    fn all_errors() -> Vec<ClusterError> {
        vec![
            ClusterError::RoleInvalid { reason: "x".into() },
            ClusterError::MasterUnavailable,
            ClusterError::MasterConflict,
            ClusterError::NodeUnknown {
                node_id: "node-a".into(),
            },
            ClusterError::NodeRevoked {
                node_id: "node-a".into(),
            },
            ClusterError::NodeNotRevoked {
                node_id: "node-a".into(),
            },
            ClusterError::NodeAlreadyJoined {
                node_id: "node-a".into(),
            },
            ClusterError::JoinTokenInvalid,
            ClusterError::JoinTokenExpired,
            ClusterError::TransportTls {
                message: "x".into(),
            },
            ClusterError::ProtocolVersion,
            ClusterError::ConfigApply {
                message: "x".into(),
            },
            ClusterError::ConfigStale,
            ClusterError::WriteRelayFailed,
            ClusterError::OfflineWriteRequiresIdempotency,
            ClusterError::OfflineWriteQueueFull,
            ClusterError::OfflineWriteConflict,
            ClusterError::OfflineWriteExpired,
            ClusterError::LogStreamInvalid { reason: "x".into() },
            ClusterError::LogBufferDropped { count: 3 },
            ClusterError::LogGap { missing: 2 },
            ClusterError::RuntimeCommandFailed {
                message: "x".into(),
            },
            ClusterError::CertPushFailed {
                message: "x".into(),
            },
            ClusterError::ClockSkew,
            ClusterError::QuotaExceeded {
                node_id: "node-a".into(),
                what: "relay request".into(),
            },
            ClusterError::Internal {
                message: "x".into(),
            },
        ]
    }

    #[test]
    fn codes_are_unique_and_well_formed() {
        let all = all_errors();
        let mut codes: Vec<&str> = all.iter().map(ClusterError::code).collect();
        for (error, code) in all.iter().zip(&codes) {
            assert!(
                code.chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '.' || c == '_'),
                "code {code} from {error:?} must be locale-neutral ascii"
            );
            assert!(
                code.starts_with("cluster."),
                "code {code} must be namespaced"
            );
            // Every code has an area and a reason, never an empty segment.
            assert!(
                code.split('.').all(|segment| !segment.is_empty()),
                "code {code} has an empty segment"
            );
        }
        codes.sort_unstable();
        let count = codes.len();
        codes.dedup();
        assert_eq!(count, codes.len(), "duplicate cluster error code");
    }

    #[test]
    fn every_spec_code_exists() {
        let expected = [
            "cluster.role.invalid",
            "cluster.master_unavailable",
            "cluster.master_conflict",
            "cluster.node.unknown",
            "cluster.node.revoked",
            "cluster.node.not_revoked",
            "cluster.node.already_joined",
            "cluster.join.token_invalid",
            "cluster.join.token_expired",
            "cluster.transport.tls",
            "cluster.protocol.version",
            "cluster.config.apply",
            "cluster.config.stale",
            "cluster.write_relay_failed",
            "cluster.offline_write_requires_idempotency",
            "cluster.offline_write_queue_full",
            "cluster.offline_write_conflict",
            "cluster.offline_write_expired",
            "cluster.log_stream.invalid",
            "cluster.log_buffer_dropped",
            "cluster.log_gap",
            "cluster.runtime_command.failed",
            "cluster.cert_push.failed",
            "cluster.clock_skew",
        ];
        let codes = all_errors()
            .iter()
            .map(ClusterError::code)
            .collect::<Vec<_>>();
        for code in expected {
            assert!(codes.contains(&code), "missing spec code {code}");
        }
    }
}
