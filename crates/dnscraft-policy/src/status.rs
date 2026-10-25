//! Coarse policy status for the UI / control-api.

/// Snapshot of whether stubbed features are applied yet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PolicyStatus {
    /// SafeSearch rewrite (pipeline steps 5–6) is not evaluated in v1.
    pub safesearch_applied: bool,
    /// Schedule windows that would swap the filter set are not evaluated in v1.
    pub schedules_applied: bool,
}

impl PolicyStatus {
    /// Status for the current engine: stubs report “not applied yet”.
    pub(crate) fn stubs() -> Self {
        Self {
            safesearch_applied: false,
            schedules_applied: false,
        }
    }
}
