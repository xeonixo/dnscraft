//! Hot-reload filter engine: immutable snapshots, temps, counters, scheduler.
//!
//! Readers clone an [`Arc<Snapshot>`] under a short [`RwLock`] hold so matching
//! never waits on a rebuild. Rebuilds run on `spawn_blocking` and swap
//! atomically; at most one rebuild runs at a time (further requests coalesce).

use std::collections::HashMap;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::sync::{Notify, oneshot};

use crate::clock::Clock;
use crate::error::FilterError;
use crate::fetch::{FetchOutcome, Fetcher};
use crate::name::DomainName;
use crate::scheduler::UpdateScheduler;
use crate::set::{FilterConfig, ListBodies, SnapshotError};
use crate::snapshot::{Snapshot, SnapshotBuilder, resolve_chain};
use crate::stats::{FilterStats, StatsTable};
use crate::store::{ListSourceSpec, ListStore, MetaError, StoreListBodies};
use crate::temp_allow::TempAllow;
use crate::types::{ListId, SetId, Verdict};

/// Which lists [`FilterEngine::update_lists`] should refresh.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ListSelection {
    /// Every enabled list in the current config.
    All,
    /// Only these list ids (unknown ids are ignored).
    These(Vec<ListId>),
}

/// Status of one configured list after fetch/build.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ListStatus {
    /// List id.
    pub id: ListId,
    /// Last update attempt (wall clock).
    pub last_attempt: Option<SystemTime>,
    /// Last successful update.
    pub last_success: Option<SystemTime>,
    /// Stable error code of the last failed attempt, if any.
    pub error_code: Option<String>,
    /// Rules accepted by the parser in the last successful build.
    pub rules_parsed: u64,
    /// Rules skipped by the parser in the last successful build.
    pub rules_skipped: u64,
    /// Unique contribution after dedup in a set that uses this list
    /// (maximum across sets when the list appears in several combinations).
    pub unique_contribution: usize,
}

/// Result of [`FilterEngine::apply_config`] (and the rebuild half of an update).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReloadReport {
    /// Per-list status after the operation.
    pub lists: Vec<ListStatus>,
}

#[derive(Default)]
struct Coalesce {
    /// A rebuild is running on a blocking thread.
    busy: bool,
    /// Follow-up work queued while busy (`apply_config` and/or list update).
    pending_config: Option<FilterConfig>,
    pending_lists: Option<ListSelection>,
    /// Waiters for the current (coalesced) rebuild to finish.
    waiters: Vec<oneshot::Sender<()>>,
}

impl std::fmt::Debug for Coalesce {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Coalesce")
            .field("busy", &self.busy)
            .field("pending_config", &self.pending_config.is_some())
            .field("pending_lists", &self.pending_lists)
            .field("waiters", &self.waiters.len())
            .finish()
    }
}

/// Matching facade with temporary allows, counters, hot reload and scheduling.
#[derive(Debug)]
pub struct FilterEngine {
    snapshot: RwLock<Arc<Snapshot>>,
    temps: RwLock<HashMap<SetId, Vec<TempAllow>>>,
    stats: RwLock<StatsTable>,
    /// Present when constructed via [`Self::open`]; absent for matching-only.
    inner: Option<EngineInner>,
}

#[derive(Debug)]
struct EngineInner {
    store: ListStore,
    bodies: Arc<StoreListBodies>,
    fetcher: Fetcher,
    /// Injected clock (scheduler / tests); matching takes `now` explicitly.
    #[allow(dead_code)]
    clock: Arc<dyn Clock>,
    config: RwLock<FilterConfig>,
    list_status: RwLock<HashMap<ListId, ListStatus>>,
    coalesce: Mutex<Coalesce>,
    /// Wakes the scheduler early ("update now").
    kick: Arc<Notify>,
    scheduler: Mutex<Option<UpdateScheduler>>,
}

impl FilterEngine {
    /// Matching-only engine over a pre-built snapshot (no store, no scheduler).
    ///
    /// Used by unit tests and callers that build snapshots themselves.
    /// [`Self::apply_config`] / [`Self::update_lists`] return
    /// [`FilterError::NoStore`].
    pub fn new(snapshot: Snapshot) -> Self {
        let (set_ids, list_ids) = ids_from_snapshot(&snapshot);
        Self {
            snapshot: RwLock::new(Arc::new(snapshot)),
            temps: RwLock::new(HashMap::new()),
            stats: RwLock::new(StatsTable::new(set_ids, list_ids)),
            inner: None,
        }
    }

    /// Builds from cached lists (no network), then starts the update scheduler.
    ///
    /// Local `File` sources are read if not yet cached. HTTP lists without a
    /// cache contribute nothing until [`Self::update_lists`].
    pub fn open(
        config: FilterConfig,
        store: ListStore,
        clock: Arc<dyn Clock>,
    ) -> Result<Arc<Self>, FilterError> {
        let files = file_fallbacks(&config);
        let bodies = Arc::new(StoreListBodies::new(store.clone(), files));
        let snapshot = build_snapshot(Arc::clone(&bodies) as Arc<dyn ListBodies>, &config)?;
        let status = status_from_snapshot(&snapshot, &config, &store);
        let fetcher = Fetcher::new(&store).map_err(|e| FilterError::BuildFailed {
            message: e.to_string(),
        })?;
        let (set_ids, list_ids) = ids_from_snapshot(&snapshot);
        let kick = Arc::new(Notify::new());
        let eng = Arc::new(Self {
            snapshot: RwLock::new(Arc::new(snapshot)),
            temps: RwLock::new(HashMap::new()),
            stats: RwLock::new(StatsTable::new(set_ids, list_ids)),
            inner: Some(EngineInner {
                store,
                bodies,
                fetcher,
                clock: Arc::clone(&clock),
                config: RwLock::new(config),
                list_status: RwLock::new(status),
                coalesce: Mutex::new(Coalesce::default()),
                kick: Arc::clone(&kick),
                scheduler: Mutex::new(None),
            }),
        });
        let sched = UpdateScheduler::start(Arc::clone(&eng), clock);
        if let Some(inner) = eng.inner.as_ref() {
            *inner
                .scheduler
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(sched);
        }
        let _ = kick;
        Ok(eng)
    }

    /// Same as [`Self::open`] but does not start the background scheduler.
    ///
    /// Tests that drive updates manually use this.
    pub fn open_without_scheduler(
        config: FilterConfig,
        store: ListStore,
        clock: Arc<dyn Clock>,
    ) -> Result<Arc<Self>, FilterError> {
        let files = file_fallbacks(&config);
        let bodies = Arc::new(StoreListBodies::new(store.clone(), files));
        let snapshot = build_snapshot(Arc::clone(&bodies) as Arc<dyn ListBodies>, &config)?;
        let status = status_from_snapshot(&snapshot, &config, &store);
        let fetcher = Fetcher::new(&store).map_err(|e| FilterError::BuildFailed {
            message: e.to_string(),
        })?;
        let (set_ids, list_ids) = ids_from_snapshot(&snapshot);
        Ok(Arc::new(Self {
            snapshot: RwLock::new(Arc::new(snapshot)),
            temps: RwLock::new(HashMap::new()),
            stats: RwLock::new(StatsTable::new(set_ids, list_ids)),
            inner: Some(EngineInner {
                store,
                bodies,
                fetcher,
                clock,
                config: RwLock::new(config),
                list_status: RwLock::new(status),
                coalesce: Mutex::new(Coalesce::default()),
                kick: Arc::new(Notify::new()),
                scheduler: Mutex::new(None),
            }),
        }))
    }

    /// Shared handle to the current immutable snapshot.
    ///
    /// The lock is held only for the `Arc` clone.
    pub fn snapshot_arc(&self) -> Arc<Snapshot> {
        let guard = self
            .snapshot
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        Arc::clone(&*guard)
    }

    /// Alias for [`Self::snapshot_arc`].
    pub fn snapshot(&self) -> Arc<Snapshot> {
        self.snapshot_arc()
    }

    /// Configured update interval (default 24 h when matching-only).
    pub fn update_interval(&self) -> Duration {
        self.inner.as_ref().map_or_else(
            || crate::set::DEFAULT_UPDATE_INTERVAL,
            |i| {
                i.config
                    .read()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .update_interval
            },
        )
    }

    /// Applies a new config: rebuild on a blocking thread, swap atomically.
    pub async fn apply_config(&self, config: FilterConfig) -> Result<ReloadReport, FilterError> {
        let Some(inner) = self.inner.as_ref() else {
            return Err(FilterError::NoStore);
        };
        inner.bodies.set_files(file_fallbacks(&config));
        *inner
            .config
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = config.clone();
        self.enqueue_rebuild(Some(config), None).await
    }

    /// Fetches the selected lists, then rebuilds the snapshot from the store.
    ///
    /// A failed fetch keeps the last good body; a failed rebuild keeps the
    /// last good snapshot. Returns per-list status either way.
    pub async fn update_lists(&self, which: ListSelection) -> Vec<ListStatus> {
        let Some(inner) = self.inner.as_ref() else {
            return Vec::new();
        };
        let config = inner
            .config
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        let targets = select_lists(&config, &which);
        for (id, source) in targets {
            let outcome = inner
                .fetcher
                .fetch_and_store(&inner.store, &id, &source)
                .await;
            update_meta_status(inner, &id, &outcome);
            // Persist parse counts after rebuild; fetch meta already written.
            let _ = outcome;
        }
        match self.enqueue_rebuild(None, Some(which)).await {
            Ok(report) => report.lists,
            Err(_) => self.list_status(),
        }
    }

    /// Triggers an immediate list update (wakes the scheduler if running).
    pub async fn update_now(&self) -> Vec<ListStatus> {
        if let Some(inner) = self.inner.as_ref() {
            inner.kick.notify_waiters();
            if let Some(sched) = inner
                .scheduler
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .as_ref()
            {
                sched.kick();
            }
        }
        self.update_lists(ListSelection::All).await
    }

    /// Per-list status (last attempt/success, error, parse counts, unique
    /// contribution).
    pub fn list_status(&self) -> Vec<ListStatus> {
        let Some(inner) = self.inner.as_ref() else {
            return Vec::new();
        };
        let guard = inner
            .list_status
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut v: Vec<_> = guard.values().cloned().collect();
        v.sort_by(|a, b| a.id.cmp(&b.id));
        v
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
        self.stats
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .record(set, &v);
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
        let snap = self.snapshot_arc();
        if snap.shared_index(set).is_none() {
            return Err(FilterError::UnknownSet(set.to_string()));
        }
        if snap.paused_until(set).is_some_and(|u| now < u) {
            let v = Verdict::Pass;
            self.stats
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .record(set, &v);
            return Ok(v);
        }
        let v = resolve_chain(names, |name| {
            self.match_one_active(&snap, set, name, qtype, now)
        });
        self.stats
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .record(set, &v);
        Ok(v)
    }

    /// IP-answer match with counters (temporary allows do not apply to IPs).
    pub fn match_answer_ip(
        &self,
        set: &SetId,
        ip: IpAddr,
        now: SystemTime,
    ) -> Result<Verdict, FilterError> {
        let v = self.snapshot_arc().match_answer_ip(set, ip, now)?;
        self.stats
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .record(set, &v);
        Ok(v)
    }

    /// Adds or replaces a temporary allow for `set`.
    ///
    /// An existing allow for the same domain (regardless of
    /// `include_subdomains`) is replaced. Does not rebuild the snapshot.
    pub fn allow_temporarily(&self, set: &SetId, rule: TempAllow) -> Result<(), FilterError> {
        if self.snapshot_arc().shared_index(set).is_none() {
            return Err(FilterError::UnknownSet(set.to_string()));
        }
        let mut guard = self
            .temps
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
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
        if self.snapshot_arc().shared_index(set).is_none() {
            return Err(FilterError::UnknownSet(set.to_string()));
        }
        let mut guard = self
            .temps
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
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
        if self.snapshot_arc().shared_index(set).is_none() {
            return Err(FilterError::UnknownSet(set.to_string()));
        }
        let guard = self
            .temps
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
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
        self.stats
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .snapshot()
    }

    async fn enqueue_rebuild(
        &self,
        config: Option<FilterConfig>,
        lists: Option<ListSelection>,
    ) -> Result<ReloadReport, FilterError> {
        let Some(inner) = self.inner.as_ref() else {
            return Err(FilterError::NoStore);
        };
        let (tx, rx) = oneshot::channel();
        let run_now = {
            let mut g = inner
                .coalesce
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if g.busy {
                if let Some(c) = config {
                    g.pending_config = Some(c);
                }
                if let Some(l) = lists {
                    g.pending_lists = Some(merge_selection(g.pending_lists.take(), l));
                }
                g.waiters.push(tx);
                false
            } else {
                g.busy = true;
                if let Some(c) = config {
                    g.pending_config = Some(c);
                }
                if let Some(l) = lists {
                    g.pending_lists = Some(l);
                }
                g.waiters.push(tx);
                true
            }
        };
        if run_now {
            self.run_coalesced_rebuilds().await;
        }
        let _ = rx.await;
        Ok(ReloadReport {
            lists: self.list_status(),
        })
    }

    async fn run_coalesced_rebuilds(&self) {
        let Some(inner) = self.inner.as_ref() else {
            return;
        };
        loop {
            let (cfg_opt, _lists_opt, waiters) = {
                let mut g = inner
                    .coalesce
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                let cfg = g.pending_config.take().unwrap_or_else(|| {
                    inner
                        .config
                        .read()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .clone()
                });
                // Apply latest config before build.
                *inner
                    .config
                    .write()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) = cfg.clone();
                inner.bodies.set_files(file_fallbacks(&cfg));
                let lists = g.pending_lists.take();
                let waiters = std::mem::take(&mut g.waiters);
                (cfg, lists, waiters)
            };

            let bodies = Arc::clone(&inner.bodies);
            let store = inner.store.clone();
            let build_result = tokio::task::spawn_blocking(move || {
                let cfg = cfg_opt;
                build_snapshot(bodies as Arc<dyn ListBodies>, &cfg).map(|snap| (snap, cfg))
            })
            .await;

            match build_result {
                Ok(Ok((snap, cfg))) => {
                    let status = status_from_snapshot(&snap, &cfg, &store);
                    let (sets, lists) = ids_from_snapshot(&snap);
                    {
                        let mut st = self
                            .stats
                            .write()
                            .unwrap_or_else(std::sync::PoisonError::into_inner);
                        st.ensure(sets, lists);
                    }
                    {
                        *inner
                            .list_status
                            .write()
                            .unwrap_or_else(std::sync::PoisonError::into_inner) = status;
                    }
                    {
                        *self
                            .snapshot
                            .write()
                            .unwrap_or_else(std::sync::PoisonError::into_inner) = Arc::new(snap);
                    }
                }
                Ok(Err(e)) => {
                    tracing::warn!(error = %e, code = e.code(), "filter rebuild failed; keeping last good snapshot");
                }
                Err(e) => {
                    tracing::warn!(error = %e, "filter rebuild task failed; keeping last good snapshot");
                }
            }

            for w in waiters {
                let _ = w.send(());
            }

            let again = {
                let mut g = inner
                    .coalesce
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                if g.pending_config.is_some() || g.pending_lists.is_some() || !g.waiters.is_empty()
                {
                    true
                } else {
                    g.busy = false;
                    false
                }
            };
            if !again {
                return;
            }
        }
    }

    fn match_name_inner(
        &self,
        set: &SetId,
        name: &DomainName,
        qtype: u16,
        now: SystemTime,
    ) -> Result<Verdict, FilterError> {
        let snap = self.snapshot_arc();
        if snap.shared_index(set).is_none() {
            return Err(FilterError::UnknownSet(set.to_string()));
        }
        if snap.paused_until(set).is_some_and(|u| now < u) {
            return Ok(Verdict::Pass);
        }
        if let Some(v) = self.temp_verdict(set, name, now) {
            return Ok(v);
        }
        snap.match_name(set, name, qtype, now)
    }

    fn match_one_active(
        &self,
        snap: &Snapshot,
        set: &SetId,
        name: &DomainName,
        qtype: u16,
        now: SystemTime,
    ) -> Verdict {
        if let Some(v) = self.temp_verdict(set, name, now) {
            return v;
        }
        match snap.match_name(set, name, qtype, now) {
            Ok(v) => v,
            Err(_) => Verdict::Pass,
        }
    }

    fn temp_verdict(&self, set: &SetId, name: &DomainName, now: SystemTime) -> Option<Verdict> {
        let guard = self
            .temps
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let list = guard.get(set)?;
        list.iter()
            .rev()
            .find(|a| a.matches(name, now))
            .map(TempAllow::to_verdict)
    }
}

fn build_snapshot(
    bodies: Arc<dyn ListBodies>,
    config: &FilterConfig,
) -> Result<Snapshot, FilterError> {
    SnapshotBuilder::new(bodies)
        .build(config)
        .map_err(|e: SnapshotError| FilterError::BuildFailed {
            message: e.to_string(),
        })
}

fn ids_from_snapshot(snapshot: &Snapshot) -> (Vec<SetId>, Vec<ListId>) {
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
    (set_ids, list_ids)
}

fn file_fallbacks(config: &FilterConfig) -> HashMap<ListId, PathBuf> {
    let mut m = HashMap::new();
    for l in &config.lists {
        if let ListSourceSpec::File(path) = &l.source {
            m.insert(l.id.clone(), path.clone());
        }
    }
    m
}

fn select_lists(config: &FilterConfig, which: &ListSelection) -> Vec<(ListId, ListSourceSpec)> {
    match which {
        ListSelection::All => config
            .lists
            .iter()
            .filter(|l| l.enabled)
            .map(|l| (l.id.clone(), l.source.clone()))
            .collect(),
        ListSelection::These(ids) => config
            .lists
            .iter()
            .filter(|l| l.enabled && ids.contains(&l.id))
            .map(|l| (l.id.clone(), l.source.clone()))
            .collect(),
    }
}

fn merge_selection(a: Option<ListSelection>, b: ListSelection) -> ListSelection {
    match (a, b) {
        (None, x) => x,
        (_, ListSelection::All) | (Some(ListSelection::All), _) => ListSelection::All,
        (Some(ListSelection::These(mut a)), ListSelection::These(b)) => {
            for id in b {
                if !a.contains(&id) {
                    a.push(id);
                }
            }
            ListSelection::These(a)
        }
    }
}

fn unix_to_system(secs: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(secs)
}

fn status_from_snapshot(
    snapshot: &Snapshot,
    config: &FilterConfig,
    store: &ListStore,
) -> HashMap<ListId, ListStatus> {
    let mut unique: HashMap<ListId, usize> = HashMap::new();
    let mut parsed: HashMap<ListId, u64> = HashMap::new();
    let mut skipped: HashMap<ListId, u64> = HashMap::new();
    for set in snapshot.set_ids() {
        if let Some(facts) = snapshot.list_facts(set) {
            for f in facts {
                let e = unique.entry(f.list.clone()).or_insert(0);
                *e = (*e).max(f.unique_contribution);
                parsed.insert(f.list.clone(), f.rules_parsed as u64);
                let sk: u64 = f.skipped.total() as u64;
                skipped.insert(f.list.clone(), sk);
            }
        }
    }
    let mut out = HashMap::new();
    for l in &config.lists {
        let meta = store.read_meta(&l.id).ok().flatten().unwrap_or_default();
        out.insert(
            l.id.clone(),
            ListStatus {
                id: l.id.clone(),
                last_attempt: meta.last_attempt.map(unix_to_system),
                last_success: meta.last_success.map(unix_to_system),
                error_code: meta.last_error.map(|e| e.code),
                rules_parsed: parsed.get(&l.id).copied().unwrap_or(meta.rules_parsed),
                rules_skipped: skipped.get(&l.id).copied().unwrap_or(meta.rules_skipped),
                unique_contribution: unique.get(&l.id).copied().unwrap_or(0),
            },
        );
    }
    out
}

fn update_meta_status(inner: &EngineInner, id: &ListId, outcome: &FetchOutcome) {
    let meta = outcome.meta();
    let mut guard = inner
        .list_status
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let entry = guard.entry(id.clone()).or_insert_with(|| ListStatus {
        id: id.clone(),
        last_attempt: None,
        last_success: None,
        error_code: None,
        rules_parsed: 0,
        rules_skipped: 0,
        unique_contribution: 0,
    });
    entry.last_attempt = meta.last_attempt.map(unix_to_system);
    entry.last_success = meta.last_success.map(unix_to_system);
    entry.error_code = meta.last_error.as_ref().map(|e: &MetaError| e.code.clone());
    // Keep parse/unique numbers until rebuild refreshes them.
    let _ = meta;
}
