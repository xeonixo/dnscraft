//! Cluster status surface for `GET /api/v1/status` (CL6).
//!
//! A standalone node installs no handle, so the six contract fields are omitted
//! entirely. A master or sub-node runtime updates the shared
//! [`ClusterStatusHandle`] as it starts, publishes and applies snapshots.

use std::sync::Mutex;
use std::time::SystemTime;

use serde_json::{Value, json};

/// The six cluster fields exposed under `cluster` by `GET /api/v1/status`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClusterStatus {
    /// `master` or `sub_node`.
    pub role: String,
    /// Whether this node currently has a usable master connection. Always
    /// `true` on the master itself.
    pub master_reachable: bool,
    /// Last config version applied locally, if any.
    pub applied_version: Option<i64>,
    /// Versions this node is behind the master (floored at zero).
    pub lag: i64,
    /// Pending offline writes (sub-node) or zero on the master.
    pub queue_depth: u32,
    /// Last successful config apply/publish, if any.
    pub last_sync: Option<SystemTime>,
}

impl ClusterStatus {
    /// Serializes the six fields in the contract's shape.
    pub fn to_json(&self) -> Value {
        json!({
            "role": self.role,
            "master_reachable": self.master_reachable,
            "applied_version": self.applied_version,
            "lag": self.lag,
            "queue_depth": self.queue_depth,
            "last_sync": self.last_sync.map(rfc3339),
        })
    }
}

/// Live source of [`ClusterStatus`] for `GET /api/v1/status`.
pub trait ClusterStatusProvider: Send + Sync {
    /// The current cluster status, or `None` when this node is standalone.
    fn cluster_status(&self) -> Option<ClusterStatus>;
}

/// Shared mutable [`ClusterStatus`] updated by the cluster runtime.
///
/// Attach it to [`AppState::with_cluster_status`](crate::AppState::with_cluster_status)
/// before starting the runtime; a standalone node never installs one and the
/// status endpoint then omits the `cluster` object entirely.
#[derive(Default)]
pub struct ClusterStatusHandle {
    status: Mutex<Option<ClusterStatus>>,
}

impl ClusterStatusHandle {
    /// Creates an empty handle (standalone until [`Self::set`] is called).
    pub fn new() -> Self {
        Self::default()
    }

    /// Replaces the published status.
    pub fn set(&self, status: ClusterStatus) {
        *self
            .status
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(status);
    }

    /// Mutates the published status in place, if there is one.
    pub fn update(&self, update: impl FnOnce(&mut ClusterStatus)) {
        if let Some(status) = self
            .status
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_mut()
        {
            update(status);
        }
    }

    /// The current status, if set.
    pub fn status(&self) -> Option<ClusterStatus> {
        self.status
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }
}

impl ClusterStatusProvider for ClusterStatusHandle {
    fn cluster_status(&self) -> Option<ClusterStatus> {
        self.status()
    }
}

/// RFC 3339 (UTC, seconds precision).
fn rfc3339(time: SystemTime) -> String {
    time::OffsetDateTime::from(time)
        .format(time::macros::format_description!(
            "[year]-[month]-[day]T[hour]:[minute]:[second]Z"
        ))
        .unwrap_or_default()
}
