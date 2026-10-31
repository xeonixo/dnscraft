//! Hot-reload filter engine: immutable snapshots, temps, counters, scheduler.
//!
//! Readers clone an [`Arc<Snapshot>`] under a short [`RwLock`] hold so matching
//! never waits on a rebuild. Rebuilds run on `spawn_blocking` and swap
//! atomically; at most one rebuild runs at a time (further requests coalesce).

use std::collections::HashMap;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::sync::oneshot;

use crate::clock::{Clock, SystemClock};
use crate::error::FilterError;
use crate::fetch::{FetchOutcome, Fetcher};
use crate::name::DomainName;
use crate::parser::SkipCounts;
use crate::scheduler::UpdateScheduler;
use crate::services::{
    ServiceCatalog, ServicesUpdateReport, ServicesUrls, update_services_catalog,
};
use crate::set::{FilterConfig, ListBodies, SnapshotError};
use crate::snapshot::{Snapshot, SnapshotBuilder, resolve_chain};
use crate::stats::{FilterStats, StatsTable};
use crate::store::{ListSourceSpec, ListStore, MetaError, StoreListBodies};
use crate::temp_allow::TempAllow;
use crate::types::{ListId, SetId, Verdict};

/// Which lists [`FilterEngine::update_lists`] should refresh.
#[derive(Clone, Debug, PartialEq, Eq)]

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
    /// Stable error code of the last failed attempt, if any
    /// (`filter_list.fetch_failed`, `filter_list.too_large`, …).
    pub error_code: Option<String>,
    /// HTTP status of the last attempt, when it got a response.
    pub http_status: Option<u16>,
    /// Rules accepted by the parser in the last successful build.
    pub rules_parsed: u64,
    /// Rules skipped by the parser in the last successful build.
    pub rules_skipped: u64,
    /// Skipped items broken down by reason (the sum is
    /// [`Self::rules_skipped`] while the list has a body in a set).
    pub skipped_by_reason: SkipCounts,
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
    waiters: Vec<oneshot::Sender<RebuildResult>>,
}

/// Outcome handed to every caller waiting on a coalesced rebuild.
type RebuildResult = Result<ReloadReport, FilterError>;

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
    /// Runtime pause overlay; survives `apply_config` (see
    /// [`FilterEngine::set_paused_until`]).
    pauses: RwLock<HashMap<SetId, SystemTime>>,
    stats: RwLock<StatsTable>,
    /// Present when constructed via [`Self::open`]; absent for matching-only.
    inner: Option<EngineInner>,
}

#[derive(Debug)]
struct EngineInner {
    store: ListStore,
    fetcher: Fetcher,
    /// Injected clock (scheduler / [`Self::now`]); matching still takes `now`
    /// explicitly so tests can freeze time without a [`ManualClock`](crate::ManualClock).
    clock: Arc<dyn Clock>,
    config: RwLock<FilterConfig>,
    list_status: RwLock<HashMap<ListId, ListStatus>>,
    coalesce: Mutex<Coalesce>,
    scheduler: Mutex<Option<UpdateScheduler>>,
    /// Artificial delay (ms) inside each rebuild; tests only.
    build_delay_ms: AtomicU64,
    /// Runtime blocked-services catalog (`None` = feature unavailable).
    catalog: RwLock<Option<Arc<ServiceCatalog>>>,
    /// Last services update/parse error code (`filter_services.*`), if any.
    services_error: RwLock<Option<&'static str>>,
    /// Catalog download URLs (overridable in tests).
    services_urls: RwLock<ServicesUrls>,
}

impl FilterEngine {
    /// Builds from cached lists and services catalog (no network), then starts
    /// the update scheduler.
    ///
    /// This is the SPEC primary constructor (`new(config, store, clock)`).
    /// Local `File` sources are read if not yet cached. HTTP lists without a
    /// cache contribute nothing until [`Self::update_lists`]. Without a cached
    /// `services.json`, [`Self::services`] returns `None`.
    ///
    /// Matching methods take an explicit `now` so callers (and tests) can pass
    /// a frozen time; use [`Self::now`] for the injected clock.
    pub fn new(
        config: FilterConfig,
        store: ListStore,
        clock: Arc<dyn Clock>,
    ) -> Result<Arc<Self>, FilterError> {
        let eng = Self::open_without_scheduler(config, store, Arc::clone(&clock))?;
        let sched = UpdateScheduler::start(&eng, clock);
        if let Some(inner) = eng.inner.as_ref() {
            *inner
                .scheduler
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(sched);
        }
        Ok(eng)
    }

    /// Matching-only engine over a pre-built snapshot (no store, no scheduler).
    ///
    /// Test helper and callers that build snapshots themselves. Prefer
    /// [`Self::new`] for production. [`Self::apply_config`] /
    /// [`Self::update_lists`] return [`FilterError::NoStore`].
    pub fn from_snapshot(snapshot: Snapshot) -> Self {
        let (set_ids, list_ids) = ids_from_snapshot(&snapshot);
        Self {
            snapshot: RwLock::new(Arc::new(snapshot)),
            temps: RwLock::new(HashMap::new()),
            pauses: RwLock::new(HashMap::new()),
            stats: RwLock::new(StatsTable::new(set_ids, list_ids)),
            inner: None,
        }
    }

    /// Same as [`Self::new`] but does not start the background
    /// scheduler. Tests that drive updates manually use this.
    pub fn open_without_scheduler(
        config: FilterConfig,
        store: ListStore,
        clock: Arc<dyn Clock>,
    ) -> Result<Arc<Self>, FilterError> {
        // `FilterConfig` is the source of truth for the per-list size cap
        // (`max_list_size_mb`); apply it to a list-only clone so the blocked-
        // services catalog keeps its own (larger) cap in `store`.
        let mut list_store = store.clone();
        list_store.set_max_body_bytes(config.max_list_size_bytes());
        let (catalog, services_error) = load_catalog_offline(&store);
        let snapshot = build_snapshot(
            list_bodies(&list_store, &config),
            &config,
            catalog.clone(),
            Arc::clone(&clock),
        )?;
        let status = status_from_snapshot(&snapshot, &config, &list_store);
        let fetcher = Fetcher::new(&store).map_err(|e| FilterError::BuildFailed {
            message: e.to_string(),
        })?;
        let (set_ids, list_ids) = ids_from_snapshot(&snapshot);
        Ok(Arc::new(Self {
            snapshot: RwLock::new(Arc::new(snapshot)),
            temps: RwLock::new(HashMap::new()),
            pauses: RwLock::new(HashMap::new()),
            stats: RwLock::new(StatsTable::new(set_ids, list_ids)),
            inner: Some(EngineInner {
                store,
                fetcher,
                clock,
                config: RwLock::new(config),
                list_status: RwLock::new(status),
                coalesce: Mutex::new(Coalesce::default()),
                scheduler: Mutex::new(None),
                build_delay_ms: AtomicU64::new(0),
                catalog: RwLock::new(catalog),
                services_error: RwLock::new(services_error),
                services_urls: RwLock::new(ServicesUrls::default()),
            }),
        }))
    }

    /// Makes every rebuild sleep this long on its blocking thread (tests that
    /// need to cancel a caller mid-build). No effect on matching-only engines.
    #[doc(hidden)]
    pub fn set_build_delay_for_tests(&self, delay: Duration) {
        if let Some(inner) = self.inner.as_ref() {
            let ms = u64::try_from(delay.as_millis()).unwrap_or(u64::MAX);
            inner.build_delay_ms.store(ms, Ordering::SeqCst);
        }
    }

    /// Shared handle to the current immutable snapshot.
    ///
    /// The lock is held only for the `Arc` clone so matching never waits on a
    /// rebuild.
    pub fn snapshot(&self) -> Arc<Snapshot> {
        let guard = self
            .snapshot
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        Arc::clone(&*guard)
    }

    /// Current time from the injected clock, or the system clock when this
    /// engine is matching-only ([`Self::from_snapshot`]).
    pub fn now(&self) -> SystemTime {
        match self.inner.as_ref() {
            Some(inner) => inner.clock.now(),
            None => SystemClock.now(),
        }
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
    ///
    /// The config is committed only when the rebuild succeeds. On failure
    /// (for example a set naming an unknown list, or a duplicate id) this
    /// returns the error, the previous snapshot keeps serving and later
    /// rebuilds keep using the last good config. Requests that coalesce with
    /// a running rebuild share one outcome; the newest config wins.
    ///
    /// Dropping the returned future (for example on a timeout) never blocks
    /// later calls.
    pub async fn apply_config(&self, config: FilterConfig) -> Result<ReloadReport, FilterError> {
        self.enqueue_rebuild(Some(config), None).await
    }

    /// Fetches the selected lists (and the services catalog when `All`), then
    /// rebuilds the snapshot from the store.
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
        if matches!(which, ListSelection::All) {
            let _ = self.refresh_services_catalog().await;
        }
        let targets = select_lists(&config, &which);
        // Fetch and persist with the cap of the current config
        // (`max_list_size_mb`), not the cap the store was opened with.
        let mut store = inner.store.clone();
        store.set_max_body_bytes(config.max_list_size_bytes());
        let ids: Vec<ListId> = targets.iter().map(|(id, _)| id.clone()).collect();
        for (id, source) in targets {
            let outcome = inner.fetcher.fetch_and_store(&store, &id, &source).await;
            update_meta_status(inner, &id, &outcome);
            // Persist parse counts after rebuild; fetch meta already written.
            let _ = outcome;
        }
        let lists = match self.enqueue_rebuild(None, Some(which)).await {
            Ok(report) => report.lists,
            Err(_) => self.list_status(),
        };
        for status in lists.iter().filter(|s| ids.contains(&s.id)) {
            log_list_refresh(status);
        }
        lists
    }

    /// Downloads/caches the blocked-services catalog and rebuilds if it changed.
    ///
    /// On a malformed body the previous catalog is kept and
    /// [`Self::services_last_error`] reports `filter_services.malformed`.
    pub async fn update_services(&self) -> ServicesUpdateReport {
        let report = self.refresh_services_catalog().await;
        if report.catalog.is_some() && report.changed {
            let _ = self.enqueue_rebuild(None, None).await;
        }
        report
    }

    /// Overrides catalog download URLs (tests with a local HTTP server).
    pub fn set_services_urls(&self, urls: ServicesUrls) -> Result<(), FilterError> {
        let Some(inner) = self.inner.as_ref() else {
            return Err(FilterError::NoStore);
        };
        *inner
            .services_urls
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = urls;
        Ok(())
    }

    /// The current blocked-services catalog, or `None` when unavailable.
    pub fn services(&self) -> Option<Arc<ServiceCatalog>> {
        let inner = self.inner.as_ref()?;
        inner
            .catalog
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// Stable error code of the last failed services update/parse, if any.
    pub fn services_last_error(&self) -> Option<&'static str> {
        let inner = self.inner.as_ref()?;
        *inner
            .services_error
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Configuration last installed by [`Self::apply_config`], when store-backed.
    pub fn installed_config(&self) -> Option<FilterConfig> {
        let inner = self.inner.as_ref()?;
        Some(
            inner
                .config
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone(),
        )
    }

    /// Unix seconds of the last successful `services.json` download (from the
    /// cache metadata), or `None` when no catalog is cached.
    pub fn services_updated_at(&self) -> Option<u64> {
        let inner = self.inner.as_ref()?;
        inner
            .store
            .read_services_meta(crate::services::SERVICES_STEM)
            .ok()
            .flatten()?
            .last_success
    }

    /// Runs one immediate update round of every enabled list.
    ///
    /// This fetches directly (exactly once per list) and does not wake the
    /// scheduler, so "update now" can never cause a second fetch round.
    pub async fn update_now(&self) -> Vec<ListStatus> {
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
        let snap = self.snapshot();
        if snap.shared_index(set).is_none() {
            return Err(FilterError::UnknownSet(set.to_string()));
        }
        if self.effective_pause(&snap, set).is_some_and(|u| now < u) {
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

    /// Per-name verdicts for a CNAME chain, one per input name, in order.
    /// Same matching as [`Self::match_chain`] but without stats recording, so
    /// callers can show every hop. Pause yields `Pass` for every name.
    pub fn match_each(
        &self,
        set: &SetId,
        names: &[DomainName],
        qtype: u16,
        now: SystemTime,
    ) -> Result<Vec<Verdict>, FilterError> {
        let snap = self.snapshot();
        if snap.shared_index(set).is_none() {
            return Err(FilterError::UnknownSet(set.to_string()));
        }
        if self.effective_pause(&snap, set).is_some_and(|u| now < u) {
            return Ok(vec![Verdict::Pass; names.len()]);
        }
        Ok(names
            .iter()
            .map(|name| self.match_one_active(&snap, set, name, qtype, now))
            .collect())
    }

    /// IP-answer match with counters (temporary allows do not apply to IPs).
    pub fn match_answer_ip(
        &self,
        set: &SetId,
        ip: IpAddr,
        now: SystemTime,
    ) -> Result<Verdict, FilterError> {
        let snap = self.snapshot();
        let v = if self.effective_pause(&snap, set).is_some_and(|u| now < u) {
            Verdict::Pass
        } else {
            snap.match_answer_ip(set, ip, now)?
        };
        self.stats
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .record(set, &v);
        Ok(v)
    }

    /// Pauses `set` until `until` (or resumes with `None`) immediately.
    ///
    /// The pause lives in an in-memory overlay, not in the config: no snapshot
    /// rebuild happens, a later call replaces an earlier pause, and the
    /// overlay is **not cleared by [`Self::apply_config`]**. A configured
    /// [`crate::FilterSetConfig::paused_until`] still applies; the later of the two
    /// deadlines wins. Unknown set → [`FilterError::UnknownSet`].
    pub fn set_paused_until(
        &self,
        set: &SetId,
        until: Option<SystemTime>,
    ) -> Result<(), FilterError> {
        if self.snapshot().shared_index(set).is_none() {
            return Err(FilterError::UnknownSet(set.to_string()));
        }
        let mut guard = self
            .pauses
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match until {
            Some(until) => {
                guard.insert(set.clone(), until);
            }
            None => {
                guard.remove(set);
            }
        }
        Ok(())
    }

    /// Effective pause deadline of `set`: the overlay or the configured
    /// `paused_until`, whichever ends later.
    pub fn paused_until(&self, set: &SetId) -> Option<SystemTime> {
        self.effective_pause(&self.snapshot(), set)
    }

    fn effective_pause(&self, snap: &Snapshot, set: &SetId) -> Option<SystemTime> {
        let overlay = self
            .pauses
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(set)
            .copied();
        match (overlay, snap.paused_until(set)) {
            (Some(a), Some(b)) => Some(a.max(b)),
            (a, b) => a.or(b),
        }
    }

    /// Adds or replaces a temporary allow for `set`.
    ///
    /// An existing allow for the same domain (regardless of
    /// `include_subdomains`) is replaced. Does not rebuild the snapshot.
    pub fn allow_temporarily(&self, set: &SetId, mut rule: TempAllow) -> Result<(), FilterError> {
        if self.snapshot().shared_index(set).is_none() {
            return Err(FilterError::UnknownSet(set.to_string()));
        }
        let mut guard = self
            .temps
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let list = guard.entry(set.clone()).or_default();
        let now = self.now();
        rule.created_at = now;
        list.retain(|a| now < a.until);
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
        if self.snapshot().shared_index(set).is_none() {
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

    /// Active temporary allows for `set` at `now` (expired entries omitted
    /// and dropped from memory).
    pub fn list_temporary_allows(
        &self,
        set: &SetId,
        now: SystemTime,
    ) -> Result<Vec<TempAllow>, FilterError> {
        if self.snapshot().shared_index(set).is_none() {
            return Err(FilterError::UnknownSet(set.to_string()));
        }
        let mut guard = self
            .temps
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some(list) = guard.get_mut(set) else {
            return Ok(Vec::new());
        };
        list.retain(|a| now < a.until);
        Ok(list.clone())
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
    ) -> RebuildResult {
        let Some(inner) = self.inner.as_ref() else {
            return Err(FilterError::NoStore);
        };
        let (tx, rx) = oneshot::channel();
        let run_now = {
            let mut g = inner
                .coalesce
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Some(c) = config {
                g.pending_config = Some(c);
            }
            if let Some(l) = lists {
                g.pending_lists = Some(merge_selection(g.pending_lists.take(), l));
            }
            g.waiters.push(tx);
            let run_now = !g.busy;
            g.busy = true;
            run_now
        };
        if run_now {
            self.run_coalesced_rebuilds().await;
        }
        rx.await.unwrap_or_else(|_| {
            Err(FilterError::BuildFailed {
                message: "rebuild was cancelled".to_owned(),
            })
        })
    }

    /// Runs rebuilds until no follow-up work is queued. Every waiter gets the
    /// build result; the config is committed only after a successful build.
    ///
    /// If this future is dropped mid-way, [`BusyGuard`] resets the coalescing
    /// state and fails the remaining waiters so the next call can run.
    async fn run_coalesced_rebuilds(&self) {
        let Some(inner) = self.inner.as_ref() else {
            return;
        };
        let mut guard = BusyGuard {
            coalesce: &inner.coalesce,
            armed: true,
        };
        loop {
            let (pending_cfg, waiters) = {
                let mut g = inner
                    .coalesce
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                g.pending_lists = None;
                (g.pending_config.take(), std::mem::take(&mut g.waiters))
            };
            let cfg = pending_cfg.unwrap_or_else(|| {
                inner
                    .config
                    .read()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .clone()
            });

            let mut store = inner.store.clone();
            store.set_max_body_bytes(cfg.max_list_size_bytes());
            let bodies = list_bodies(&store, &cfg);
            let catalog = inner
                .catalog
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone();
            let delay = inner.build_delay_ms.load(Ordering::SeqCst);
            let clock = Arc::clone(&inner.clock);
            let build_result = tokio::task::spawn_blocking(move || {
                if delay > 0 {
                    std::thread::sleep(Duration::from_millis(delay));
                }
                build_snapshot(bodies, &cfg, catalog, clock).map(|snap| (snap, cfg))
            })
            .await;

            let outcome: RebuildResult = match build_result {
                Ok(Ok((snap, cfg))) => {
                    let status = status_from_snapshot(&snap, &cfg, &store);
                    let (sets, lists) = ids_from_snapshot(&snap);
                    self.stats
                        .write()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .ensure(sets, lists);
                    *inner
                        .list_status
                        .write()
                        .unwrap_or_else(std::sync::PoisonError::into_inner) = status;
                    *inner
                        .config
                        .write()
                        .unwrap_or_else(std::sync::PoisonError::into_inner) = cfg;
                    *self
                        .snapshot
                        .write()
                        .unwrap_or_else(std::sync::PoisonError::into_inner) = Arc::new(snap);
                    Ok(ReloadReport {
                        lists: self.list_status(),
                    })
                }
                Ok(Err(e)) => {
                    tracing::warn!(error = %e, code = e.code(), "filter rebuild failed; keeping last good snapshot and config");
                    Err(e)
                }
                Err(e) => {
                    tracing::warn!(error = %e, "filter rebuild task failed; keeping last good snapshot and config");
                    Err(FilterError::BuildFailed {
                        message: format!("rebuild task failed: {e}"),
                    })
                }
            };

            for w in waiters {
                let _ = w.send(outcome.clone());
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
                guard.armed = false;
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
        let snap = self.snapshot();
        if snap.shared_index(set).is_none() {
            return Err(FilterError::UnknownSet(set.to_string()));
        }
        if self.effective_pause(&snap, set).is_some_and(|u| now < u) {
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

    /// Fetches the catalog; on success replaces the in-memory catalog and
    /// clears the error. On failure keeps the previous catalog and records the
    /// error code.
    async fn refresh_services_catalog(&self) -> ServicesUpdateReport {
        let Some(inner) = self.inner.as_ref() else {
            return ServicesUpdateReport {
                catalog: None,
                error_code: Some(FilterError::NoStore.code()),
                services_fetch: crate::services::FetchOutcomeKind::Failed,
                i18n_fetch: crate::services::FetchOutcomeKind::Failed,
                changed: false,
            };
        };
        let urls = inner
            .services_urls
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        let report = update_services_catalog(&inner.fetcher, &inner.store, &urls).await;
        if let Some(cat) = &report.catalog {
            *inner
                .catalog
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(Arc::new(cat.clone()));
            *inner
                .services_error
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
        } else if let Some(code) = report.error_code {
            *inner
                .services_error
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(code);
        }
        report
    }
}

/// Resets the coalescing state when the rebuild loop is dropped mid-way
/// (caller cancelled), so the engine never stays `busy` forever. Remaining
/// waiters are dropped and observe a "cancelled" error.
struct BusyGuard<'a> {
    coalesce: &'a Mutex<Coalesce>,
    armed: bool,
}

impl Drop for BusyGuard<'_> {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let mut g = self
            .coalesce
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        g.busy = false;
        g.pending_config = None;
        g.pending_lists = None;
        g.waiters.clear();
    }
}

/// A fresh body provider for one build, with `config`'s local-file fallbacks.
///
/// Each snapshot keeps the provider it was built with, so a failed build
/// never changes what the serving snapshot reads.
fn list_bodies(store: &ListStore, config: &FilterConfig) -> Arc<dyn ListBodies> {
    Arc::new(StoreListBodies::new(store.clone(), file_fallbacks(config)))
}

fn load_catalog_offline(store: &ListStore) -> (Option<Arc<ServiceCatalog>>, Option<&'static str>) {
    match ServiceCatalog::load_cached(store) {
        Ok(Some(c)) => (Some(Arc::new(c)), None),
        Ok(None) => (None, None),
        Err(e) => {
            tracing::warn!(
                error = %e,
                code = e.code(),
                "cached services catalog unusable; feature unavailable until a good update"
            );
            (None, Some(e.code()))
        }
    }
}

fn build_snapshot(
    bodies: Arc<dyn ListBodies>,
    config: &FilterConfig,
    catalog: Option<Arc<ServiceCatalog>>,
    clock: Arc<dyn Clock>,
) -> Result<Snapshot, FilterError> {
    SnapshotBuilder::new(bodies)
        .with_catalog(catalog)
        .with_clock(clock)
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
    let mut skipped: HashMap<ListId, SkipCounts> = HashMap::new();
    for set in snapshot.set_ids() {
        if let Some(facts) = snapshot.list_facts(set) {
            for f in facts {
                let e = unique.entry(f.list.clone()).or_insert(0);
                *e = (*e).max(f.unique_contribution);
                parsed.insert(f.list.clone(), f.rules_parsed as u64);
                skipped.insert(f.list.clone(), f.skipped.clone());
            }
        }
    }
    let mut out = HashMap::new();
    for l in &config.lists {
        let meta = store.read_meta(&l.id).ok().flatten().unwrap_or_default();
        let breakdown = skipped.get(&l.id).cloned().unwrap_or_default();
        out.insert(
            l.id.clone(),
            ListStatus {
                id: l.id.clone(),
                last_attempt: meta.last_attempt.map(unix_to_system),
                last_success: meta.last_success.map(unix_to_system),
                error_code: meta.last_error.map(|e| e.code),
                http_status: meta.http_status,
                rules_parsed: parsed.get(&l.id).copied().unwrap_or(meta.rules_parsed),
                rules_skipped: skipped
                    .get(&l.id)
                    .map_or(meta.rules_skipped, |s| s.total() as u64),
                skipped_by_reason: breakdown,
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
        http_status: None,
        rules_parsed: 0,
        rules_skipped: 0,
        skipped_by_reason: SkipCounts::default(),
        unique_contribution: 0,
    });
    entry.last_attempt = meta.last_attempt.map(unix_to_system);
    entry.last_success = meta.last_success.map(unix_to_system);
    entry.error_code = meta.last_error.as_ref().map(|e: &MetaError| e.code.clone());
    entry.http_status = meta.http_status;
    // Keep parse/unique numbers until rebuild refreshes them.
    let _ = meta;
}

/// One info event per refreshed list, or a warn event when its fetch failed
/// (the last good rules stay in use).
fn log_list_refresh(status: &ListStatus) {
    match &status.error_code {
        Some(code) => tracing::warn!(
            list = %status.id,
            error_code = code.as_str(),
            http_status = ?status.http_status,
            "filter list refresh failed; keeping the stored rules"
        ),
        None => tracing::info!(
            list = %status.id,
            http_status = ?status.http_status,
            rules_parsed = status.rules_parsed,
            rules_skipped = status.rules_skipped,
            "filter list refreshed"
        ),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::clock::ManualClock;
    use crate::set::FilterSetConfig;
    use crate::store::StoreConfig;

    fn at(secs: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(secs)
    }

    fn allow(domain: &str, until: SystemTime) -> TempAllow {
        TempAllow {
            domain: domain.parse().unwrap(),
            include_subdomains: false,
            until,
            created_at: UNIX_EPOCH,
        }
    }

    fn stored_temps(eng: &FilterEngine, set: &SetId) -> usize {
        eng.temps
            .read()
            .unwrap()
            .get(set)
            .map_or(0, std::vec::Vec::len)
    }

    #[tokio::test]
    async fn expired_temporary_allows_are_pruned_on_insert_and_list() {
        let dir = std::env::temp_dir().join(format!("dnscraft-engine-unit-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let clock = Arc::new(ManualClock::new(at(1_000)));
        let store =
            ListStore::open_with(&dir, StoreConfig::default(), Arc::clone(&clock) as _).unwrap();
        let set = SetId::new("s").unwrap();
        let cfg = FilterConfig {
            sets: vec![FilterSetConfig::new(set.clone(), "s")],
            ..FilterConfig::default()
        };
        let eng = FilterEngine::open_without_scheduler(cfg, store, clock.clone()).unwrap();

        eng.allow_temporarily(&set, allow("a.example", at(1_010)))
            .unwrap();
        eng.allow_temporarily(&set, allow("b.example", at(1_010)))
            .unwrap();
        assert_eq!(stored_temps(&eng, &set), 2);

        // Insert after expiry drops the expired entries.
        clock.advance(Duration::from_secs(20));
        eng.allow_temporarily(&set, allow("c.example", at(2_000)))
            .unwrap();
        assert_eq!(stored_temps(&eng, &set), 1);

        // Listing after expiry drops them too.
        eng.allow_temporarily(&set, allow("d.example", at(1_030)))
            .unwrap();
        assert_eq!(stored_temps(&eng, &set), 2);
        let listed = eng.list_temporary_allows(&set, at(1_040)).unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(stored_temps(&eng, &set), 1);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn temporary_allows_are_stamped_with_creation_time() {
        let dir =
            std::env::temp_dir().join(format!("dnscraft-engine-created-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let clock = Arc::new(ManualClock::new(at(1_000)));
        let store =
            ListStore::open_with(&dir, StoreConfig::default(), Arc::clone(&clock) as _).unwrap();
        let set = SetId::new("s").unwrap();
        let cfg = FilterConfig {
            sets: vec![FilterSetConfig::new(set.clone(), "s")],
            ..FilterConfig::default()
        };
        let eng = FilterEngine::open_without_scheduler(cfg, store, clock.clone()).unwrap();

        // `allow()` supplies UNIX_EPOCH; the engine must overwrite it.
        eng.allow_temporarily(&set, allow("a.example", at(2_000)))
            .unwrap();
        clock.advance(Duration::from_secs(10));
        eng.allow_temporarily(&set, allow("b.example", at(2_000)))
            .unwrap();

        let listed = eng.list_temporary_allows(&set, at(1_010)).unwrap();
        assert_eq!(listed.len(), 2);
        let created = |domain: &str| {
            listed
                .iter()
                .find(|a| a.domain.as_str() == domain)
                .unwrap()
                .created_at
        };
        assert_eq!(created("a.example"), at(1_000));
        assert_eq!(created("b.example"), at(1_010));

        let _ = std::fs::remove_dir_all(&dir);
    }
}
