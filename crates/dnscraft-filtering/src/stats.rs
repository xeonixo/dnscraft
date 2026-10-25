//! Cheap in-memory match counters.
//!
//! Every `match_*` call increments the set's `matches` once (Relaxed). A
//! blocking or allowing verdict also bumps `blocks` / `allows`, and when the
//! winning [`Reason`](crate::Reason) names a list, that list's counters move
//! the same way. No locks on the hot path.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::types::{ListId, Reason, RuleSource, SetId, Verdict};

/// Snapshot of all counters at one point in time.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct FilterStats {
    /// Per-set counters, sorted by set id.
    pub sets: Vec<SetStats>,
    /// Per-list counters, sorted by list id.
    pub lists: Vec<ListStats>,
}

/// Counters for one filter set.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SetStats {
    /// The set.
    pub set: SetId,
    /// Match calls against this set.
    pub matches: u64,
    /// Calls that returned [`Verdict::Blocked`] or [`Verdict::Rewrite`].
    pub blocks: u64,
    /// Calls that returned [`Verdict::Allowed`].
    pub allows: u64,
}

/// Counters for one filter list.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ListStats {
    /// The list.
    pub list: ListId,
    /// Match calls whose winning rule came from this list.
    pub matches: u64,
    /// Of those, blocking/rewrite verdicts.
    pub blocks: u64,
    /// Of those, allow verdicts.
    pub allows: u64,
}

#[derive(Debug, Default)]
struct Counters {
    matches: AtomicU64,
    blocks: AtomicU64,
    allows: AtomicU64,
}

impl Counters {
    fn snapshot(&self) -> (u64, u64, u64) {
        (
            self.matches.load(Ordering::Relaxed),
            self.blocks.load(Ordering::Relaxed),
            self.allows.load(Ordering::Relaxed),
        )
    }

    fn record(&self, verdict: &Verdict) {
        self.matches.fetch_add(1, Ordering::Relaxed);
        match verdict {
            Verdict::Blocked(_) | Verdict::Rewrite(_, _) => {
                self.blocks.fetch_add(1, Ordering::Relaxed);
            }
            Verdict::Allowed(_) => {
                self.allows.fetch_add(1, Ordering::Relaxed);
            }
            Verdict::Pass => {}
        }
    }
}

/// Atomic counter table keyed by set and list.
#[derive(Debug)]
pub(crate) struct StatsTable {
    sets: HashMap<SetId, Counters>,
    lists: HashMap<ListId, Counters>,
}

impl StatsTable {
    /// Empty table covering the given sets and lists (others stay at zero and
    /// are omitted from [`Self::snapshot`] until a set/list is registered).
    pub(crate) fn new(
        sets: impl IntoIterator<Item = SetId>,
        lists: impl IntoIterator<Item = ListId>,
    ) -> Self {
        Self {
            sets: sets.into_iter().map(|s| (s, Counters::default())).collect(),
            lists: lists
                .into_iter()
                .map(|l| (l, Counters::default()))
                .collect(),
        }
    }

    pub(crate) fn record(&self, set: &SetId, verdict: &Verdict) {
        if let Some(c) = self.sets.get(set) {
            c.record(verdict);
        }
        if let Some(list) = winning_list(verdict) {
            if let Some(c) = self.lists.get(list) {
                c.record(verdict);
            }
        }
    }

    pub(crate) fn snapshot(&self) -> FilterStats {
        let mut sets: Vec<SetStats> = self
            .sets
            .iter()
            .map(|(set, c)| {
                let (matches, blocks, allows) = c.snapshot();
                SetStats {
                    set: set.clone(),
                    matches,
                    blocks,
                    allows,
                }
            })
            .collect();
        sets.sort_by(|a, b| a.set.cmp(&b.set));
        let mut lists: Vec<ListStats> = self
            .lists
            .iter()
            .map(|(list, c)| {
                let (matches, blocks, allows) = c.snapshot();
                ListStats {
                    list: list.clone(),
                    matches,
                    blocks,
                    allows,
                }
            })
            .collect();
        lists.sort_by(|a, b| a.list.cmp(&b.list));
        FilterStats { sets, lists }
    }
}

fn winning_list(verdict: &Verdict) -> Option<&ListId> {
    let reason: &Reason = match verdict {
        Verdict::Allowed(r) | Verdict::Blocked(r) | Verdict::Rewrite(_, r) => r,
        Verdict::Pass => return None,
    };
    match &reason.source {
        RuleSource::List { list, .. } => Some(list),
        _ => None,
    }
}
