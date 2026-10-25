//! Background UniFi sync engine: Arc snapshot, poll loop, stale/backoff.
//!
//! Lookups clone an [`Arc<ClientLookup>`] under a short [`RwLock`] hold and
//! never await. Sync runs on a background task that holds only a [`Weak`]
//! reference, so dropping the engine aborts the loop.

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock, Weak};
use std::time::Duration;

use tokio::sync::{Mutex as AsyncMutex, Notify};
use tokio::task::JoinHandle;

use crate::cache::{self, CachePayload};
use crate::clock::{self, Clock};
use crate::config::{ClientsConfig, UnifiConfig};
use crate::error::ClientsError;
use crate::gateway::GatewayClient;
use crate::lookup::ClientLookup;
use crate::merge::{self, NetworkInfo, UnifiObservation};
use crate::secret::Secret;
use crate::state::State;
use crate::status::ClientsStatus;
use crate::sync::{self, SyncResult};
use crate::types::ClientSource;
use tracing::warn;

/// Base backoff after a 429 / 5xx (doubles each consecutive failure).
const BACKOFF_BASE: Duration = Duration::from_secs(5);
/// Cap for exponential backoff.
const BACKOFF_CAP: Duration = Duration::from_secs(5 * 60);

/// Result of [`ClientEngine::sync_now`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SyncReport {
    /// Lookup generation after this attempt.
    pub generation: u64,
    /// True when observations/networks changed and the snapshot was rebuilt.
    pub rebuilt: bool,
    /// Clients in the current lookup.
    pub client_count: usize,
    /// Classic error `code()` when Integration still succeeded.
    pub classic_error: Option<&'static str>,
}

struct SyncScheduler {
    handle: Option<JoinHandle<()>>,
}

impl std::fmt::Debug for SyncScheduler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SyncScheduler")
            .field("running", &self.handle.is_some())
            .finish()
    }
}

impl Drop for SyncScheduler {
    fn drop(&mut self) {
        if let Some(h) = self.handle.take() {
            h.abort();
        }
    }
}

/// Client identity engine: manuals + UniFi sync → hot-path lookup.
pub struct ClientEngine {
    inner: Arc<Inner>,
    /// Background poll task; aborted on drop.
    scheduler: Mutex<Option<SyncScheduler>>,
}

impl std::fmt::Debug for ClientEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientEngine")
            .field("inner", &*self.inner)
            .finish_non_exhaustive()
    }
}

struct Inner {
    clock: Arc<dyn Clock>,
    data_dir: PathBuf,
    config: RwLock<ClientsConfig>,
    api_key: RwLock<Option<Secret>>,
    lookup: RwLock<Arc<ClientLookup>>,
    state: RwLock<State>,
    cached_obs: RwLock<Vec<UnifiObservation>>,
    cached_nets: RwLock<Vec<NetworkInfo>>,
    content_hash: AtomicU64,
    generation: AtomicU64,
    status: RwLock<ClientsStatus>,
    backoff_failures: AtomicU64,
    backoff_until: RwLock<Option<std::time::SystemTime>>,
    kick: Arc<Notify>,
    stop: Arc<AtomicBool>,
    /// Counts sync attempts (tests: poll cadence / drop).
    sync_attempts: AtomicU64,
    /// True while the poll loop is blocked in [`clock::wait_until`] (tests).
    scheduler_parked: AtomicBool,
    /// Serialises merge+install for [`ClientEngine::run_sync`] and
    /// [`ClientEngine::apply_config`] (gateway fetch runs outside this lock).
    sync_lock: AsyncMutex<()>,
    /// Reused [`GatewayClient`] rebuilt when UniFi connection settings change.
    gateway: Mutex<Option<(UnifiConfig, Arc<GatewayClient>)>>,
}

impl std::fmt::Debug for Inner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientEngineInner")
            .field("data_dir", &self.data_dir)
            .field("generation", &self.generation.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

impl ClientEngine {
    /// Validates `config`, builds an initial manuals-only snapshot, starts the
    /// poll loop. When UniFi is enabled, the API key is read via
    /// [`ClientsConfig::validate`].
    pub fn new(
        config: ClientsConfig,
        data_dir: PathBuf,
        clock: Arc<dyn Clock>,
    ) -> Result<Arc<Self>, ClientsError> {
        Self::new_with_secret(config, data_dir, clock, None)
    }

    /// Like [`Self::new`], but uses `api_key` when provided (tests inject a key
    /// without touching process environment).
    pub fn new_with_secret(
        mut config: ClientsConfig,
        data_dir: PathBuf,
        clock: Arc<dyn Clock>,
        api_key: Option<Secret>,
    ) -> Result<Arc<Self>, ClientsError> {
        let key = if config.unifi.enabled {
            let k = match api_key {
                Some(k) => k,
                None => crate::secret::read_secret(crate::secret::UNIFI_API_KEY_ENV)?,
            };
            let for_validate = k.clone();
            config.validate_with_secret(move |_| Ok(for_validate))?;
            Some(k)
        } else {
            config.validate_with_secret(|_| Ok(Secret::new("unused")))?;
            None
        };

        let now = clock.now();
        let cached = cache::load(&data_dir).unwrap_or_else(|e| {
            warn!(error = %e, "clients cache load io error; starting fresh");
            None
        });

        let (lookup, state, obs, nets, from_cache) = if let Some(payload) = cached {
            match merge::build(
                &config.manual,
                &payload.observations,
                &payload.networks,
                &payload.state,
                &config,
                now,
            ) {
                Ok(built) => (
                    built.lookup,
                    built.state,
                    payload.observations,
                    payload.networks,
                    true,
                ),
                Err(e) => {
                    warn!(
                        code = e.code(),
                        "clients cache merge failed; starting manuals-only"
                    );
                    let built =
                        merge::build(&config.manual, &[], &[], &State::default(), &config, now)?;
                    (built.lookup, built.state, Vec::new(), Vec::new(), false)
                }
            }
        } else {
            let built = merge::build(&config.manual, &[], &[], &State::default(), &config, now)?;
            (built.lookup, built.state, Vec::new(), Vec::new(), false)
        };

        let generation = 1u64;
        let content_hash = if from_cache {
            hash_content(&obs, &nets, &lookup)
        } else {
            0
        };
        let status = ClientsStatus {
            last_attempt: None,
            last_success: None,
            // Cache is served before the first live poll; mark stale until sync confirms.
            stale: config.unifi.enabled,
            client_count: lookup.len(),
            manual_count: config.manual.len(),
            unifi_count: lookup
                .clients()
                .iter()
                .filter(|c| c.source == ClientSource::Unifi)
                .count(),
            address_count: count_addresses(&lookup),
            last_error: None,
            poll_interval: config.unifi.poll_interval,
            generation,
        };

        let inner = Arc::new(Inner {
            clock: Arc::clone(&clock),
            data_dir,
            config: RwLock::new(config),
            api_key: RwLock::new(key),
            lookup: RwLock::new(Arc::new(lookup)),
            state: RwLock::new(state),
            cached_obs: RwLock::new(obs),
            cached_nets: RwLock::new(nets),
            content_hash: AtomicU64::new(content_hash),
            generation: AtomicU64::new(generation),
            status: RwLock::new(status),
            backoff_failures: AtomicU64::new(0),
            backoff_until: RwLock::new(None),
            kick: Arc::new(Notify::new()),
            stop: Arc::new(AtomicBool::new(false)),
            sync_attempts: AtomicU64::new(0),
            scheduler_parked: AtomicBool::new(false),
            sync_lock: AsyncMutex::new(()),
            gateway: Mutex::new(None),
        });

        let eng = Arc::new(Self {
            inner: Arc::clone(&inner),
            scheduler: Mutex::new(None),
        });
        let sched = start_scheduler(Arc::downgrade(&eng), Arc::clone(&clock));
        *eng.scheduler
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(sched);
        Ok(eng)
    }

    /// Hot-path snapshot (cheap `Arc` clone).
    pub fn lookup(&self) -> Arc<ClientLookup> {
        Arc::clone(
            &self
                .inner
                .lookup
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        )
    }

    /// Current status (cheap clone).
    pub fn status(&self) -> ClientsStatus {
        self.inner
            .status
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// Data directory reserved for the last-good cache (C9).
    pub fn data_dir(&self) -> &std::path::Path {
        &self.inner.data_dir
    }

    /// Test/observability: number of sync attempts since construction.
    pub fn sync_attempts(&self) -> u64 {
        self.inner.sync_attempts.load(Ordering::Relaxed)
    }

    /// Test helper: true while the poll loop is waiting for the next deadline.
    pub fn scheduler_parked(&self) -> bool {
        self.inner.scheduler_parked.load(Ordering::SeqCst)
    }

    /// Test helper: replace cached UniFi rows used by [`Self::apply_config`]
    /// (e.g. to force a post-validate merge failure without minting 10k gateway
    /// clients).
    #[doc(hidden)]
    pub fn set_cached_observations_for_test(&self, obs: Vec<UnifiObservation>) {
        *self
            .inner
            .cached_obs
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = obs;
    }

    /// Replaces config and rebuilds immediately from cached UniFi observations
    /// (manual edits need no gateway round-trip).
    ///
    /// Order under the sync lock: validate → build → only on success store
    /// config, install the snapshot, and persist. A failed build leaves the
    /// previous config and lookup untouched.
    pub async fn apply_config(&self, mut config: ClientsConfig) -> Result<(), ClientsError> {
        let _guard = self.inner.sync_lock.lock().await;

        if config.unifi.enabled {
            let key_guard = self
                .inner
                .api_key
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let Some(k) = key_guard.as_ref() else {
                return Err(ClientsError::SecretMissing {
                    name: crate::secret::UNIFI_API_KEY_ENV.into(),
                });
            };
            let key = k.clone();
            drop(key_guard);
            config.validate_with_secret(move |_| Ok(key))?;
        } else {
            config.validate_with_secret(|_| Ok(Secret::new("unused")))?;
        }

        let now = self.inner.clock.now();
        let obs = self
            .inner
            .cached_obs
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        let nets = self
            .inner
            .cached_nets
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        let prev = self
            .inner
            .state
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        // Build *before* swapping config so a TooMany / domain failure cannot
        // leave a broken config active for later polls.
        let built = merge::build(&config.manual, &obs, &nets, &prev, &config, now)?;

        let unifi_changed = {
            let old = self
                .inner
                .config
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            old.unifi != config.unifi
        };
        *self
            .inner
            .config
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = config;
        if unifi_changed {
            *self
                .inner
                .gateway
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
        }
        self.install_snapshot(built.lookup, built.state, &obs, &nets, true);
        self.persist_cache();
        self.inner.kick.notify_one();
        Ok(())
    }

    /// Runs one sync immediately.
    ///
    /// Does not kick the poll loop (that would race a second sync). The
    /// background timer continues on its own schedule.
    pub async fn sync_now(&self) -> Result<SyncReport, ClientsError> {
        self.run_sync().await
    }

    async fn run_sync(&self) -> Result<SyncReport, ClientsError> {
        self.inner.sync_attempts.fetch_add(1, Ordering::Relaxed);
        let now = self.inner.clock.now();
        {
            let mut st = self
                .inner
                .status
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            st.last_attempt = Some(now);
        }

        let cfg = self
            .inner
            .config
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();

        if !cfg.unifi.enabled {
            let _guard = self.inner.sync_lock.lock().await;
            let cfg = self
                .inner
                .config
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone();
            let now = self.inner.clock.now();
            let prev = self
                .inner
                .state
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone();
            let built = merge::build(&cfg.manual, &[], &[], &prev, &cfg, now)?;
            let rebuilt = self.install_snapshot(built.lookup, built.state, &[], &[], false);
            self.clear_backoff();
            self.mark_success(None);
            return Ok(SyncReport {
                generation: self.inner.generation.load(Ordering::Relaxed),
                rebuilt,
                client_count: self.lookup().len(),
                classic_error: None,
            });
        }

        // Honour backoff window for 429/5xx.
        if let Some(until) = *self
            .inner
            .backoff_until
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            && now < until
        {
            return Err(ClientsError::SyncBackoff {
                message: "sync backoff active".into(),
            });
        }

        let key = self
            .inner
            .api_key
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
            .ok_or_else(|| ClientsError::SecretMissing {
                name: crate::secret::UNIFI_API_KEY_ENV.into(),
            })?;

        let gw = match self.gateway_for(&cfg.unifi, key) {
            Ok(g) => g,
            Err(e) => {
                self.on_sync_error(&e);
                return Err(e);
            }
        };

        // Fetch outside the sync lock so apply_config is not blocked on gateway
        // timeouts; merge under the lock with the config current at install time.
        let fetched = match sync::fetch_once(gw.as_ref(), &cfg.unifi).await {
            Ok(f) => f,
            Err(e) => {
                self.on_sync_error(&e);
                return Err(e);
            }
        };

        let _guard = self.inner.sync_lock.lock().await;
        let cfg = self
            .inner
            .config
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        let now = self.inner.clock.now();
        let prev = self
            .inner
            .state
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        let merge = match merge::build(
            &cfg.manual,
            &fetched.observations,
            &fetched.networks,
            &prev,
            &cfg,
            now,
        ) {
            Ok(m) => m,
            Err(e) => {
                self.on_sync_error(&e);
                return Err(e);
            }
        };
        Ok(self.apply_sync_result(SyncResult {
            merge,
            observations: fetched.observations,
            networks: fetched.networks,
            site_id: fetched.site_id,
            classic_site_key: fetched.classic_site_key,
            skipped_rows: fetched.skipped_rows,
            classic_error: fetched.classic_error,
        }))
    }

    fn gateway_for(
        &self,
        unifi: &UnifiConfig,
        key: Secret,
    ) -> Result<Arc<GatewayClient>, ClientsError> {
        let mut slot = self
            .inner
            .gateway
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some((cfg, gw)) = slot.as_ref()
            && cfg == unifi
        {
            return Ok(Arc::clone(gw));
        }
        let gw = Arc::new(GatewayClient::new(unifi, key)?);
        *slot = Some((unifi.clone(), Arc::clone(&gw)));
        Ok(gw)
    }

    fn apply_sync_result(&self, result: SyncResult) -> SyncReport {
        let classic_err = result.classic_error.as_ref().map(|e| e.code());
        let rebuilt = self.install_snapshot(
            result.merge.lookup,
            result.merge.state,
            &result.observations,
            &result.networks,
            false,
        );
        self.persist_cache();
        self.clear_backoff();
        self.mark_success(classic_err);
        SyncReport {
            generation: self.inner.generation.load(Ordering::Relaxed),
            rebuilt,
            client_count: self.lookup().len(),
            classic_error: classic_err,
        }
    }

    fn persist_cache(&self) {
        let payload = CachePayload {
            state: self
                .inner
                .state
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone(),
            observations: self
                .inner
                .cached_obs
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone(),
            networks: self
                .inner
                .cached_nets
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone(),
        };
        if let Err(e) = cache::save(&self.inner.data_dir, &payload) {
            warn!(error = %e, "clients cache write failed; continuing");
        }
    }

    fn install_snapshot(
        &self,
        lookup: ClientLookup,
        state: State,
        obs: &[UnifiObservation],
        nets: &[NetworkInfo],
        force_rebuild: bool,
    ) -> bool {
        let hash = hash_content(obs, nets, &lookup);
        let prev = self.inner.content_hash.load(Ordering::Relaxed);
        // Always keep merge `State` (IPv6 last-seen, offline retain). Skipping
        // that on an unchanged content hash made TTLs freeze at the first sighting.
        *self
            .inner
            .state
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = state;

        if !force_rebuild && hash == prev && prev != 0 {
            return false;
        }
        self.inner.content_hash.store(hash, Ordering::Relaxed);
        let next_gen = self.inner.generation.fetch_add(1, Ordering::Relaxed) + 1;
        *self
            .inner
            .lookup
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Arc::new(lookup);
        *self
            .inner
            .cached_obs
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = obs.to_vec();
        *self
            .inner
            .cached_nets
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = nets.to_vec();
        self.refresh_status_counts(next_gen);
        true
    }

    fn refresh_status_counts(&self, generation: u64) {
        let lookup = self.lookup();
        let cfg = self
            .inner
            .config
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut st = self
            .inner
            .status
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        st.client_count = lookup.len();
        st.manual_count = cfg.manual.len();
        st.unifi_count = lookup
            .clients()
            .iter()
            .filter(|c| c.source == ClientSource::Unifi)
            .count();
        st.address_count = count_addresses(&lookup);
        st.poll_interval = cfg.unifi.poll_interval;
        st.generation = generation;
    }

    fn mark_success(&self, classic_error: Option<&'static str>) {
        let now = self.inner.clock.now();
        let mut st = self
            .inner
            .status
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        st.last_success = Some(now);
        st.stale = false;
        // Classic soft-failure is recorded but does not mark the whole sync stale.
        st.last_error = classic_error;
    }

    fn on_sync_error(&self, err: &ClientsError) {
        let mut st = self
            .inner
            .status
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        st.stale = true;
        st.last_error = Some(err.code());

        if let ClientsError::HttpStatus { status, .. } = err
            && (*status == 429 || *status >= 500)
        {
            let n = self.inner.backoff_failures.fetch_add(1, Ordering::Relaxed) + 1;
            let shift = (n - 1).min(16);
            let delay = BACKOFF_BASE.saturating_mul(1u32 << shift).min(BACKOFF_CAP);
            let until = self.inner.clock.now() + delay;
            *self
                .inner
                .backoff_until
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(until);
        }
    }

    fn clear_backoff(&self) {
        self.inner.backoff_failures.store(0, Ordering::Relaxed);
        *self
            .inner
            .backoff_until
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
    }

    fn poll_interval(&self) -> Duration {
        self.inner
            .config
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .unifi
            .poll_interval
    }

    fn next_wait(&self) -> Duration {
        let now = self.inner.clock.now();
        if let Some(until) = *self
            .inner
            .backoff_until
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            && until > now
        {
            return until.duration_since(now).unwrap_or(Duration::from_secs(1));
        }
        jittered(self.poll_interval(), now)
    }
}

impl Drop for ClientEngine {
    fn drop(&mut self) {
        self.inner.stop.store(true, Ordering::SeqCst);
        self.inner.kick.notify_waiters();
        let _ = self
            .scheduler
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
    }
}

fn start_scheduler(engine: Weak<ClientEngine>, clock: Arc<dyn Clock>) -> SyncScheduler {
    let handle = tokio::spawn(async move {
        // First live sync immediately, then jittered poll interval.
        let mut first = true;
        loop {
            let Some(eng) = engine.upgrade() else {
                return;
            };
            if eng.inner.stop.load(Ordering::SeqCst) {
                return;
            }
            if first {
                first = false;
                let _ = eng.run_sync().await;
                continue;
            }
            let wait = eng.next_wait();
            let kick = Arc::clone(&eng.inner.kick);
            let deadline = clock.now() + wait;
            eng.inner.scheduler_parked.store(true, Ordering::SeqCst);
            drop(eng);
            clock::wait_until(clock.as_ref(), deadline, kick.as_ref()).await;
            let Some(eng) = engine.upgrade() else {
                return;
            };
            eng.inner.scheduler_parked.store(false, Ordering::SeqCst);
            if eng.inner.stop.load(Ordering::SeqCst) {
                return;
            }
            let _ = eng.run_sync().await;
        }
    });
    SyncScheduler {
        handle: Some(handle),
    }
}

/// Interval ±10 %, never below one second (unless base is below one second —
/// then floor at `base` so short test intervals still work).
pub(crate) fn jittered(base: Duration, salt: std::time::SystemTime) -> Duration {
    if base.is_zero() {
        return Duration::from_secs(1);
    }
    let nanos = base.as_nanos().min(u128::from(u64::MAX)) as u64;
    let span = nanos / 10;
    let mix = salt
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
        .wrapping_mul(0x9E37_79B9_7F4A_7C15);
    let signed = (mix as i64) >> 32;
    let max = span as i64;
    let delta = if max == 0 {
        0
    } else {
        signed.rem_euclid(max.saturating_mul(2).saturating_add(1)) - max
    };
    let floor = if base >= Duration::from_secs(1) {
        1_000_000_000u64
    } else {
        base.as_nanos() as u64
    };
    let adjusted = nanos.saturating_add_signed(delta).max(floor);
    Duration::from_nanos(adjusted)
}

fn hash_content(obs: &[UnifiObservation], nets: &[NetworkInfo], lookup: &ClientLookup) -> u64 {
    let mut h = DefaultHasher::new();
    // Order-independent: sort by stable ids so HashMap iteration cannot flap
    // the generation counter on every poll.
    let mut obs_order: Vec<&UnifiObservation> = obs.iter().collect();
    obs_order.sort_by(|a, b| a.id.as_str().cmp(b.id.as_str()));
    obs_order.len().hash(&mut h);
    for o in obs_order {
        o.id.as_str().hash(&mut h);
        o.online.hash(&mut h);
        o.network_id.hash(&mut h);
        let mut addrs = o.addresses.clone();
        addrs.sort();
        for a in addrs {
            a.hash(&mut h);
        }
    }
    let mut net_order: Vec<&NetworkInfo> = nets.iter().collect();
    net_order.sort_by(|a, b| a.id.cmp(&b.id));
    for n in net_order {
        n.id.hash(&mut h);
        n.domain_name.hash(&mut h);
        n.vlan_id.hash(&mut h);
    }
    // Fold lookup (manuals) with sorted clients so order never flaps.
    hash_lookup_into(lookup, &mut h);
    h.finish()
}

fn hash_lookup_into(lookup: &ClientLookup, h: &mut DefaultHasher) {
    let mut clients: Vec<_> = lookup.clients().iter().collect();
    clients.sort_by(|a, b| a.id.as_str().cmp(b.id.as_str()));
    clients.len().hash(h);
    for c in clients {
        c.id.as_str().hash(h);
        c.dns_label.hash(h);
        c.local_domain.hash(h);
        c.online.hash(h);
        let mut addrs: Vec<_> = c.addresses.iter().copied().collect();
        addrs.sort();
        for a in addrs {
            a.hash(h);
        }
    }
}

fn count_addresses(lookup: &ClientLookup) -> usize {
    lookup.clients().iter().map(|c| c.addresses.len()).sum()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use std::time::{Duration, SystemTime};

    #[test]
    fn jitter_stays_within_ten_percent() {
        let base = Duration::from_secs(1000);
        for i in 0..50 {
            let salt = SystemTime::UNIX_EPOCH + Duration::from_secs(i * 17);
            let j = jittered(base, salt);
            assert!(j >= Duration::from_secs(900), "{j:?}");
            assert!(j <= Duration::from_secs(1100), "{j:?}");
        }
    }
}
