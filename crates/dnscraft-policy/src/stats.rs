//! Per-view and per-profile query counters.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::decision::{AnswerOrigin, DecisionRecord, DecisionStep};
use crate::ids::{ProfileId, ViewId};

/// Snapshot of all policy counters at one point in time.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct PolicyStats {
    /// Per-view counters, sorted by view id.
    pub views: Vec<ViewStats>,
    /// Per-profile counters, sorted by profile id.
    pub profiles: Vec<ProfileStats>,
}

/// Counters for one view.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ViewStats {
    /// The view.
    pub view: ViewId,
    /// Queries handled for this view.
    pub queries: u64,
    /// Queries whose final answer was a filter block (qname / chain / answer-IP).
    pub blocked: u64,
    /// Queries answered from view local records or the client directory.
    pub local_hits: u64,
}

/// Counters for one profile.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ProfileStats {
    /// The profile.
    pub profile: ProfileId,
    /// Queries handled under this profile.
    pub queries: u64,
    /// Filter-block answers under this profile.
    pub blocked: u64,
    /// Local view / client-directory answers under this profile.
    pub local_hits: u64,
}

#[derive(Debug, Default)]
struct Counters {
    queries: AtomicU64,
    blocked: AtomicU64,
    local_hits: AtomicU64,
}

impl Counters {
    fn snapshot(&self) -> (u64, u64, u64) {
        (
            self.queries.load(Ordering::Relaxed),
            self.blocked.load(Ordering::Relaxed),
            self.local_hits.load(Ordering::Relaxed),
        )
    }

    fn record(&self, decision: &DecisionRecord) {
        self.queries.fetch_add(1, Ordering::Relaxed);
        if is_blocked(decision) {
            self.blocked.fetch_add(1, Ordering::Relaxed);
        }
        if is_local_hit(decision) {
            self.local_hits.fetch_add(1, Ordering::Relaxed);
        }
    }
}

fn is_blocked(decision: &DecisionRecord) -> bool {
    decision.steps.iter().any(|s| {
        matches!(
            s,
            DecisionStep::FilterBlocked
                | DecisionStep::AnswerChainBlocked
                | DecisionStep::AnswerIpBlocked
        )
    })
}

fn is_local_hit(decision: &DecisionRecord) -> bool {
    matches!(
        decision.answer_source,
        AnswerOrigin::LocalView | AnswerOrigin::LocalClient
    )
}

/// Atomic counter table keyed by view and profile id.
#[derive(Debug, Default)]
pub(crate) struct StatsTable {
    views: HashMap<ViewId, Counters>,
    profiles: HashMap<ProfileId, Counters>,
}

impl StatsTable {
    pub(crate) fn new(
        views: impl IntoIterator<Item = ViewId>,
        profiles: impl IntoIterator<Item = ProfileId>,
    ) -> Self {
        Self {
            views: views
                .into_iter()
                .map(|v| (v, Counters::default()))
                .collect(),
            profiles: profiles
                .into_iter()
                .map(|p| (p, Counters::default()))
                .collect(),
        }
    }

    pub(crate) fn record(&self, decision: &DecisionRecord) {
        if let Some(c) = self.views.get(&decision.view_id) {
            c.record(decision);
        }
        if let Some(c) = self.profiles.get(&decision.profile_id) {
            c.record(decision);
        }
    }

    /// Ensures counters exist for the given ids (config reload). Existing
    /// counters for matching ids are kept so totals survive hot reload.
    pub(crate) fn ensure(
        &mut self,
        views: impl IntoIterator<Item = ViewId>,
        profiles: impl IntoIterator<Item = ProfileId>,
    ) {
        for v in views {
            self.views.entry(v).or_default();
        }
        for p in profiles {
            self.profiles.entry(p).or_default();
        }
    }

    pub(crate) fn snapshot(&self) -> PolicyStats {
        let mut views: Vec<ViewStats> = self
            .views
            .iter()
            .map(|(view, c)| {
                let (queries, blocked, local_hits) = c.snapshot();
                ViewStats {
                    view: view.clone(),
                    queries,
                    blocked,
                    local_hits,
                }
            })
            .collect();
        views.sort_by(|a, b| a.view.cmp(&b.view));
        let mut profiles: Vec<ProfileStats> = self
            .profiles
            .iter()
            .map(|(profile, c)| {
                let (queries, blocked, local_hits) = c.snapshot();
                ProfileStats {
                    profile: profile.clone(),
                    queries,
                    blocked,
                    local_hits,
                }
            })
            .collect();
        profiles.sort_by(|a, b| a.profile.cmp(&b.profile));
        PolicyStats { views, profiles }
    }
}
