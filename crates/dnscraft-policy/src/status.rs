//! Coarse policy status for the UI / control-api.

/// Snapshot of whether deferred pipeline features are evaluated yet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PolicyStatus {
    /// SafeSearch rewrite (pipeline steps 5–6) is evaluated.
    pub safesearch_applied: bool,
    /// Schedule windows that would swap the filter set (until P14).
    pub schedules_applied: bool,
}

impl PolicyStatus {
    /// Status for the current engine.
    pub(crate) fn current() -> Self {
        Self {
            safesearch_applied: true,
            schedules_applied: false,
        }
    }
}
