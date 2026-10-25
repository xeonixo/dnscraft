//! Coarse policy status for the UI / control-api.

use std::sync::Arc;

use crate::ids::ProfileId;
use crate::schedule::{active_schedule, offset_in_week};
use crate::snapshot::PolicySnapshot;

/// Active schedule id for one profile (status only).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProfileScheduleStatus {
    /// Profile id.
    pub profile_id: ProfileId,
    /// Active schedule id, or `None` when no window is active.
    pub active_schedule_id: Option<Arc<str>>,
}

/// Snapshot of whether deferred pipeline features are evaluated, plus live
/// schedule status.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyStatus {
    /// SafeSearch rewrite (pipeline steps 5–6) is evaluated.
    pub safesearch_applied: bool,
    /// Schedule windows that swap the filter set are evaluated.
    pub schedules_applied: bool,
    /// Per-profile active schedule id at `status()` time (policy clock).
    pub active_schedules: Vec<ProfileScheduleStatus>,
}

impl PolicyStatus {
    /// Builds status from the current snapshot and clock.
    pub(crate) fn from_snapshot(snapshot: &PolicySnapshot, now: std::time::SystemTime) -> Self {
        let offset = offset_in_week(now);
        let active_schedules = snapshot
            .profiles
            .iter()
            .map(|p| ProfileScheduleStatus {
                profile_id: p.id.clone(),
                active_schedule_id: active_schedule(&p.config.schedules, offset)
                    .map(|s| s.id.clone()),
            })
            .collect();
        Self {
            safesearch_applied: true,
            schedules_applied: true,
            active_schedules,
        }
    }
}
