//! Thin mutable layer over an immutable [`Snapshot`].
//!
//! Holds temporary allows (outside the index) and match counters. The full
//! hot-reload / scheduler engine lands in Task L3; this type is enough for
//! matching with temps and reading [`FilterStats`].

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, RwLock};
use std::time::SystemTime;

use crate::error::FilterError;
use crate::name::DomainName;
use crate::snapshot::{Snapshot, resolve_chain};
use crate::stats::{FilterStats, StatsTable};
use crate::temp_allow::TempAllow;
use crate::types::{ListId, SetId, Verdict};

/// Matching facade with temporary allows and counters.
///
/// Readers share one immutable [`Snapshot`]. Temporary allows sit in a small
/// `RwLock` map per set so adding one never rebuilds the index. Counters use
/// Relaxed atomics only.
#[derive(Debug)]
pub struct FilterEngine {
    snapshot: Arc<Snapshot>,
    temps: RwLock<HashMap<SetId, Vec<TempAllow>>>,
    stats: StatsTable,
}

impl FilterEngine {
    /// Wraps a built snapshot. Counters start at zero for every set and every
    /// list that appears in any set.
    pub fn new(snapshot: Snapshot) -> Self {
        let mut list_ids: Vec<ListId> = Vec::new();
        for id in snapshot.set_ids() {
            if let Some(facts) = snapshot.list_facts(id) {
                for f in facts {
                    if !list_ids.contains(&f.list) {
                        list_ids.push(f.list.clone());
                    }
                }
            }
        }
        let set_ids: Vec<SetId> = snapshot.set_ids().cloned().collect();
        Self {
            snapshot: Arc::new(snapshot),
            temps: RwLock::new(HashMap::new()),
            stats: StatsTable::new(set_ids, list_ids),
        }
    }

    /// The underlying immutable snapshot.
    pub fn snapshot(&self) -> &Snapshot {
        &self.snapshot
    }

    /// Shared handle to the snapshot (for concurrent readers).
    pub fn snapshot_arc(&self) -> Arc<Snapshot> {
        Arc::clone(&self.snapshot)
    }

    /// Matches `name` in `set` at `now`, honouring temporary allows and pause.
    pub fn match_name(
        &self,
        set: &SetId,
        name: &DomainName,
        qtype: u16,
        now: SystemTime,
    ) -> Result<Verdict, FilterError> {
        let v = self.match_name_inner(set, name, qtype, now)?;
        self.stats.record(set, &v);
        Ok(v)
    }

    /// CNAME-chain match (see [`Snapshot::match_chain`]), with temporary
    /// allows. Counters increment once for the whole call.
    pub fn match_chain(
        &self,
        set: &SetId,
        names: &[DomainName],
        qtype: u16,
        now: SystemTime,
    ) -> Result<Verdict, FilterError> {
        if self.snapshot.shared_index(set).is_none() {
            return Err(FilterError::UnknownSet(set.to_string()));
        }
        if self.snapshot.paused_until(set).is_some_and(|u| now < u) {
            let v = Verdict::Pass;
            self.stats.record(set, &v);
            return Ok(v);
        }
        let v = resolve_chain(names, |name| self.match_one_active(set, name, qtype, now));
        self.stats.record(set, &v);
        Ok(v)
    }

    /// IP-answer match with counters (temporary allows do not apply to IPs).
    pub fn match_answer_ip(
        &self,
        set: &SetId,
        ip: IpAddr,
        now: SystemTime,
    ) -> Result<Verdict, FilterError> {
        let v = self.snapshot.match_answer_ip(set, ip, now)?;
        self.stats.record(set, &v);
        Ok(v)
    }

    /// Adds or replaces a temporary allow for `set`.
    ///
    /// An existing allow for the same domain (regardless of
    /// `include_subdomains`) is replaced. Does not rebuild the snapshot.
    pub fn allow_temporarily(&self, set: &SetId, rule: TempAllow) -> Result<(), FilterError> {
        if self.snapshot.shared_index(set).is_none() {
            return Err(FilterError::UnknownSet(set.to_string()));
        }
        let mut guard = self.temps.write().unwrap_or_else(|e| e.into_inner());
        let list = guard.entry(set.clone()).or_default();
        if let Some(pos) = list.iter().position(|a| a.domain == rule.domain) {
            list[pos] = rule;
        } else {
            list.push(rule);
        }
        Ok(())
    }

    /// Removes the temporary allow for `domain` in `set`, if any.
    ///
    /// Returns `true` when an entry was removed.
    pub fn remove_temporary_allow(
        &self,
        set: &SetId,
        domain: &DomainName,
    ) -> Result<bool, FilterError> {
        if self.snapshot.shared_index(set).is_none() {
            return Err(FilterError::UnknownSet(set.to_string()));
        }
        let mut guard = self.temps.write().unwrap_or_else(|e| e.into_inner());
        let Some(list) = guard.get_mut(set) else {
            return Ok(false);
        };
        let before = list.len();
        list.retain(|a| &a.domain != domain);
        Ok(list.len() != before)
    }

    /// Active temporary allows for `set` at `now` (expired entries omitted).
    pub fn list_temporary_allows(
        &self,
        set: &SetId,
        now: SystemTime,
    ) -> Result<Vec<TempAllow>, FilterError> {
        if self.snapshot.shared_index(set).is_none() {
            return Err(FilterError::UnknownSet(set.to_string()));
        }
        let guard = self.temps.read().unwrap_or_else(|e| e.into_inner());
        Ok(guard
            .get(set)
            .into_iter()
            .flatten()
            .filter(|a| now < a.until)
            .cloned()
            .collect())
    }

    /// Current match counters.
    pub fn stats(&self) -> FilterStats {
        self.stats.snapshot()
    }

    fn match_name_inner(
        &self,
        set: &SetId,
        name: &DomainName,
        qtype: u16,
        now: SystemTime,
    ) -> Result<Verdict, FilterError> {
        if self.snapshot.shared_index(set).is_none() {
            return Err(FilterError::UnknownSet(set.to_string()));
        }
        if self.snapshot.paused_until(set).is_some_and(|u| now < u) {
            return Ok(Verdict::Pass);
        }
        if let Some(v) = self.temp_verdict(set, name, now) {
            return Ok(v);
        }
        self.snapshot.match_name(set, name, qtype, now)
    }

    /// Match one name while the set is known and not paused (used by chain).
    fn match_one_active(
        &self,
        set: &SetId,
        name: &DomainName,
        qtype: u16,
        now: SystemTime,
    ) -> Verdict {
        if let Some(v) = self.temp_verdict(set, name, now) {
            return v;
        }
        match self.snapshot.match_name(set, name, qtype, now) {
            Ok(v) => v,
            Err(_) => Verdict::Pass,
        }
    }

    fn temp_verdict(&self, set: &SetId, name: &DomainName, now: SystemTime) -> Option<Verdict> {
        let guard = self.temps.read().unwrap_or_else(|e| e.into_inner());
        let list = guard.get(set)?;
        list.iter()
            .rev()
            .find(|a| a.matches(name, now))
            .map(TempAllow::to_verdict)
    }
}
