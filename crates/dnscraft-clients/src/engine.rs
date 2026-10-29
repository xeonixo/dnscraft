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

use tokio::sync::{Mutex as AsyncMutex, Notify, watch};
use tokio::task::JoinHandle;

use crate::Secret;
use crate::cache::{self, CachePayload};
use crate::clock::{self, Clock};
use crate::config::{ClientsConfig, LOCAL_NODE_ID, UnifiConfig};
use crate::error::ClientsError;
use crate::gateway::GatewayClient;
use crate::lookup::ClientLookup;
use crate::merge::{self, MergeStats, NetworkInfo, UnifiObservation};
use crate::state::State;
use crate::status::ClientsStatus;
use crate::sync::{self, SyncResult};
use crate::types::{ClientSource, MacAddr};
use dnscraft_common::config::jittered;
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
    /// IP claims resolved by dropping a loser from the index during this merge.
    pub ip_conflicts: u64,
    /// True when this fetch was discarded without install: UniFi config changed
    /// mid-flight, UniFi was disabled, or a newer fetch already installed.
    ///
    /// Not an error — the last-good snapshot and status stay as they were (no
    /// `stale` / `last_error` update).
    pub superseded: bool,
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
    /// Cluster / local node id used for UniFi profile binding and sync_owner.
    node_id: String,
    config: RwLock<ClientsConfig>,
    api_key: RwLock<Option<Secret>>,
    lookup: RwLock<Arc<ClientLookup>>,
    state: RwLock<State>,
    cached_obs: RwLock<Vec<UnifiObservation>>,
    cached_nets: RwLock<Vec<NetworkInfo>>,
    content_hash: AtomicU64,
    generation: AtomicU64,
    /// Mirrors `generation`; lets the API layer push every installed snapshot.
    generation_tx: watch::Sender<u64>,
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
    /// Monotonic id assigned to each gateway fetch before it starts.
    next_fetch_seq: AtomicU64,
    /// Highest fetch (or apply_config) sequence that has installed a snapshot.
    /// In-flight fetches with `seq <= installed_seq` are discarded under the lock.
    installed_seq: AtomicU64,
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
        config: ClientsConfig,
        data_dir: PathBuf,
        clock: Arc<dyn Clock>,
        api_key: Option<Secret>,
    ) -> Result<Arc<Self>, ClientsError> {
        Self::new_with_secret_and_node(config, data_dir, clock, api_key, LOCAL_NODE_ID)
    }

    /// Like [`Self::new_with_secret`], binding UniFi profiles to `node_id`.
    pub fn new_with_secret_and_node(
        mut config: ClientsConfig,
        data_dir: PathBuf,
        clock: Arc<dyn Clock>,
        api_key: Option<Secret>,
        node_id: impl Into<String>,
    ) -> Result<Arc<Self>, ClientsError> {
        let node_id = node_id.into();
        config.migrate_legacy_unifi();
        let needs_key =
            config.unifi.enabled || config.unifi_profiles.iter().any(|p| p.connection.enabled);
        let key = if needs_key {
            match api_key {
                Some(k) => Some(k),
                None => Some(crate::read_secret(crate::UNIFI_API_KEY_ENV)?),
            }
        } else {
            api_key
        };
        if let Some(ref k) = key {
            let for_validate = k.clone();
            config.validate_with_secret(move |_| Ok(for_validate.clone()))?;
        } else {
            config.validate_with_secret(|_| Ok(Secret::new("unused")))?;
        }
        config.resolve_for_node(&node_id);
        if config.unifi.enabled && key.is_none() {
            return Err(ClientsError::SecretMissing {
                name: crate::UNIFI_API_KEY_ENV.to_owned(),
            });
        }

        let now = clock.now();
        let cached = cache::load(&data_dir).unwrap_or_else(|e| {
            warn!(error = %e, "clients cache load io error; starting fresh");
            None
        });

        let (lookup, state, obs, nets, from_cache, ip_conflicts) = if let Some(payload) = cached {
            if config.unifi.enabled {
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
                        built.stats.ip_conflicts,
                    ),
                    Err(e) => {
                        warn!(
                            code = e.code(),
                            "clients cache merge failed; starting manuals-only"
                        );
                        let built = merge::build(
                            &config.manual,
                            &[],
                            &[],
                            &State::default(),
                            &config,
                            now,
                        )?;
                        (
                            built.lookup,
                            built.state,
                            Vec::new(),
                            Vec::new(),
                            false,
                            built.stats.ip_conflicts,
                        )
                    }
                }
            } else {
                // UniFi disabled: cached observations/networks must not be
                // served. Keep first-seen labels only; drop retained inventory
                // so it cannot resurrect UniFi clients.
                let mut prev = payload.state;
                prev.retained.clear();
                prev.last_unifi.clear();
                prev.ipv6_last_seen.clear();
                let built = merge::build(&config.manual, &[], &[], &prev, &config, now)?;
                (
                    built.lookup,
                    built.state,
                    Vec::new(),
                    Vec::new(),
                    false,
                    built.stats.ip_conflicts,
                )
            }
        } else {
            let built = merge::build(&config.manual, &[], &[], &State::default(), &config, now)?;
            (
                built.lookup,
                built.state,
                Vec::new(),
                Vec::new(),
                false,
                built.stats.ip_conflicts,
            )
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
            ip_conflicts,
            sync_successes: 0,
            sync_failures: 0,
        };

        let inner = Arc::new(Inner {
            clock: Arc::clone(&clock),
            data_dir,
            node_id,
            config: RwLock::new(config),
            api_key: RwLock::new(key),
            lookup: RwLock::new(Arc::new(lookup)),
            state: RwLock::new(state),
            cached_obs: RwLock::new(obs),
            cached_nets: RwLock::new(nets),
            content_hash: AtomicU64::new(content_hash),
            generation: AtomicU64::new(generation),
            generation_tx: watch::channel(generation).0,
            status: RwLock::new(status),
            backoff_failures: AtomicU64::new(0),
            backoff_until: RwLock::new(None),
            kick: Arc::new(Notify::new()),
            stop: Arc::new(AtomicBool::new(false)),
            sync_attempts: AtomicU64::new(0),
            scheduler_parked: AtomicBool::new(false),
            sync_lock: AsyncMutex::new(()),
            gateway: Mutex::new(None),
            next_fetch_seq: AtomicU64::new(0),
            installed_seq: AtomicU64::new(0),
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
    ///
    /// When [`UnifiConfig::enabled`] is false, the rebuild uses **empty**
    /// observations/networks (spec: UniFi contributes nothing; manuals only),
    /// clears the in-memory UniFi cache, and persists that. First-seen DNS
    /// **labels** in [`State`] are kept so a later re-enable can reuse them;
    /// retained-offline inventory / IPv6 TTL maps are dropped with the
    /// observations (they would otherwise reappear as UniFi clients).
    pub async fn apply_config(&self, config: ClientsConfig) -> Result<(), ClientsError> {
        self.apply_config_with_secret(config, crate::read_secret)
            .await
    }

    /// Like [`Self::apply_config`], but uses `lookup` for the UniFi API key.
    ///
    /// Tests inject a fake lookup so they never mutate process environment.
    /// When UniFi is being enabled the key is re-read through `lookup`; a key
    /// loaded at construction is used only as a fallback.
    pub async fn apply_config_with_secret(
        &self,
        mut config: ClientsConfig,
        lookup: impl FnMut(&str) -> Result<Secret, ClientsError>,
    ) -> Result<(), ClientsError> {
        let _guard = self.inner.sync_lock.lock().await;
        config.migrate_legacy_unifi();
        let node_id = self.inner.node_id.clone();
        let needs_key =
            config.unifi.enabled || config.unifi_profiles.iter().any(|p| p.connection.enabled);
        let mut lookup = lookup;
        let fresh_key = if needs_key {
            let stored = self
                .inner
                .api_key
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone();
            let key = match lookup(crate::UNIFI_API_KEY_ENV) {
                Ok(k) => k,
                Err(e) => stored.ok_or(e)?,
            };
            let for_validate = key.clone();
            config.validate_with_secret(move |_| Ok(for_validate.clone()))?;
            config.resolve_for_node(&node_id);
            Some(key)
        } else {
            config.validate_with_secret(|_| Ok(Secret::new("unused")))?;
            config.resolve_for_node(&node_id);
            None
        };

        let now = self.inner.clock.now();
        let unifi_on = config.unifi.enabled;
        let (obs, nets, prev) = if unifi_on {
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
            (obs, nets, prev)
        } else {
            // Manuals only: drop UniFi inventory so retain cannot resurrect rows.
            let mut prev = self
                .inner
                .state
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone();
            prev.retained.clear();
            prev.last_unifi.clear();
            prev.ipv6_last_seen.clear();
            (Vec::new(), Vec::new(), prev)
        };
        // Build *before* swapping config so a TooMany / domain failure cannot
        // leave a broken config active for later polls.
        let built = merge::build(&config.manual, &obs, &nets, &prev, &config, now)?;
        self.record_merge_stats(&built.stats);

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
        if let Some(key) = fresh_key {
            *self
                .inner
                .api_key
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(key);
        }
        if unifi_changed {
            *self
                .inner
                .gateway
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
        }
        self.install_snapshot(built.lookup, built.state, &obs, &nets, true);
        // Invalidate in-flight fetches that started before this apply.
        let seq = self.inner.next_fetch_seq.load(Ordering::Relaxed);
        self.inner.installed_seq.store(seq, Ordering::Relaxed);
        self.persist_cache();
        self.inner.kick.notify_one();
        Ok(())
    }

    /// Runs one sync immediately.
    ///
    /// Does not kick the poll loop (that would race a second sync). The
    /// background timer continues on its own schedule.
    ///
    /// Returns [`ClientsError::SyncNotOwner`] when this node is bound to a
    /// UniFi profile but is not its `sync_owner`.
    pub async fn sync_now(&self) -> Result<SyncReport, ClientsError> {
        let cfg = self
            .inner
            .config
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        let bound = cfg.bound_profile(&self.inner.node_id);
        if bound.is_some() && !cfg.is_sync_owner(&self.inner.node_id) {
            return Err(ClientsError::SyncNotOwner {
                message: format!(
                    "node `{}` is not sync_owner for its UniFi profile",
                    self.inner.node_id
                ),
            });
        }
        self.run_sync().await
    }

    /// Installs a UniFi directory snapshot pushed from the sync_owner (non-owners).
    ///
    /// Replaces cached UniFi observations/networks and rebuilds the lookup;
    /// manuals come from the current config.
    pub async fn apply_unifi_directory(
        &self,
        observations: Vec<UnifiObservation>,
        networks: Vec<NetworkInfo>,
    ) -> Result<SyncReport, ClientsError> {
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
        let built = merge::build(&cfg.manual, &observations, &networks, &prev, &cfg, now)?;
        self.record_merge_stats(&built.stats);
        let rebuilt =
            self.install_snapshot(built.lookup, built.state, &observations, &networks, true);
        let generation = self
            .inner
            .status
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .generation;
        {
            let mut st = self
                .inner
                .status
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            st.last_success = Some(now);
            st.stale = false;
            st.last_error = None;
        }
        self.persist_cache();
        Ok(SyncReport {
            generation,
            rebuilt,
            client_count: self
                .inner
                .lookup
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .len(),
            classic_error: None,
            ip_conflicts: built.stats.ip_conflicts,
            superseded: false,
        })
    }

    /// Receiver that fires whenever a new lookup snapshot is installed
    /// (poll, manual sync, config apply, directory push).
    pub fn subscribe_generation(&self) -> watch::Receiver<u64> {
        self.inner.generation_tx.subscribe()
    }

    /// This engine's cluster / local node id.
    pub fn node_id(&self) -> &str {
        &self.inner.node_id
    }

    /// Installs or clears the in-memory UniFi API key (from kv / `SecretPush`).
    pub fn set_api_key(&self, key: Option<Secret>) {
        *self
            .inner
            .api_key
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = key;
    }

    /// Bound UniFi profile id for this node, when configured.
    pub fn bound_profile_id(&self) -> Option<String> {
        let cfg = self
            .inner
            .config
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        cfg.unifi_bindings.get(&self.inner.node_id).cloned()
    }

    /// True when this node is the sync_owner of its bound UniFi profile.
    pub fn is_sync_owner(&self) -> bool {
        let cfg = self
            .inner
            .config
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        cfg.is_sync_owner(&self.inner.node_id)
    }

    /// Cached UniFi observations/networks for directory uplink / push.
    pub fn export_unifi_directory(&self) -> (Vec<UnifiObservation>, Vec<NetworkInfo>, u64) {
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
        let generation = self
            .inner
            .status
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .generation;
        (obs, nets, generation)
    }

    /// Applies a cluster directory push when this node is bound to `profile_id`
    /// and is not the sync_owner (owners already have local data).
    pub async fn apply_directory_push(
        &self,
        profile_id: &str,
        observations: Vec<UnifiObservation>,
        networks: Vec<NetworkInfo>,
    ) -> Result<Option<SyncReport>, ClientsError> {
        let cfg = self
            .inner
            .config
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        let bound = cfg.unifi_bindings.get(&self.inner.node_id);
        if bound.map(String::as_str) != Some(profile_id) {
            return Ok(None);
        }
        if cfg.is_sync_owner(&self.inner.node_id) {
            return Ok(None);
        }
        Ok(Some(
            self.apply_unifi_directory(observations, networks).await?,
        ))
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
            if cfg.unifi.enabled {
                // Enabled again while we waited for the lock — fall through by
                // returning a no-op; the next poll/sync_now will fetch.
                return Ok(self.superseded_report());
            }
            let now = self.inner.clock.now();
            let mut prev = self
                .inner
                .state
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone();
            prev.retained.clear();
            prev.last_unifi.clear();
            prev.ipv6_last_seen.clear();
            let built = merge::build(&cfg.manual, &[], &[], &prev, &cfg, now)?;
            self.record_merge_stats(&built.stats);
            let ip_conflicts = built.stats.ip_conflicts;
            let rebuilt = self.install_snapshot(built.lookup, built.state, &[], &[], true);
            let seq = self.inner.next_fetch_seq.load(Ordering::Relaxed);
            self.inner.installed_seq.store(seq, Ordering::Relaxed);
            self.persist_cache();
            self.clear_backoff();
            self.mark_success(None);
            return Ok(SyncReport {
                generation: self.inner.generation.load(Ordering::Relaxed),
                rebuilt,
                client_count: self.lookup().len(),
                classic_error: None,
                ip_conflicts,
                superseded: false,
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
                name: crate::UNIFI_API_KEY_ENV.into(),
            })?;

        let fetched_with = cfg.unifi.clone();
        let gw = match self.gateway_for(&fetched_with, key) {
            Ok(g) => g,
            Err(e) => {
                self.on_sync_error(&e);
                return Err(e);
            }
        };

        // Sequence taken *before* the fetch so a concurrent newer fetch/apply
        // can win even if this request finishes first on the wire.
        let fetch_seq = self.inner.next_fetch_seq.fetch_add(1, Ordering::Relaxed) + 1;

        // Fetch outside the sync lock so apply_config is not blocked on gateway
        // timeouts; merge under the lock with the config current at install time.
        let fetched = match sync::fetch_once(gw.as_ref(), &fetched_with).await {
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
        // Discard when UniFi was disabled / connection settings changed, or a
        // newer fetch/apply already installed.
        if !cfg.unifi.enabled
            || cfg.unifi != fetched_with
            || fetch_seq <= self.inner.installed_seq.load(Ordering::Relaxed)
        {
            return Ok(self.superseded_report());
        }
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
        self.inner.installed_seq.store(fetch_seq, Ordering::Relaxed);
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

    fn superseded_report(&self) -> SyncReport {
        SyncReport {
            generation: self.inner.generation.load(Ordering::Relaxed),
            rebuilt: false,
            client_count: self.lookup().len(),
            classic_error: None,
            ip_conflicts: 0,
            superseded: true,
        }
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
        let stats = result.merge.stats;
        let rebuilt = self.install_snapshot(
            result.merge.lookup,
            result.merge.state,
            &result.observations,
            &result.networks,
            false,
        );
        self.record_merge_stats(&stats);
        self.persist_cache();
        self.clear_backoff();
        self.mark_success(classic_err);
        SyncReport {
            generation: self.inner.generation.load(Ordering::Relaxed),
            rebuilt,
            client_count: self.lookup().len(),
            classic_error: classic_err,
            ip_conflicts: stats.ip_conflicts,
            superseded: false,
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
        self.inner.generation_tx.send_replace(next_gen);
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
        st.sync_successes += 1;
        // Classic soft-failure is recorded but does not mark the whole sync stale.
        st.last_error = classic_error;
    }

    fn record_merge_stats(&self, stats: &MergeStats) {
        if stats.ip_conflicts == 0 {
            return;
        }
        let mut st = self
            .inner
            .status
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        st.ip_conflicts = st.ip_conflicts.saturating_add(stats.ip_conflicts);
    }

    fn on_sync_error(&self, err: &ClientsError) {
        let mut st = self
            .inner
            .status
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        st.stale = true;
        st.last_error = Some(err.code());
        st.sync_failures += 1;

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

fn hash_content(obs: &[UnifiObservation], nets: &[NetworkInfo], lookup: &ClientLookup) -> u64 {
    let mut h = DefaultHasher::new();
    // Order-independent: sort by stable ids so HashMap iteration cannot flap
    // the generation counter on every poll.
    let mut obs_order: Vec<&UnifiObservation> = obs.iter().collect();
    obs_order.sort_by(|a, b| a.id.as_str().cmp(b.id.as_str()));
    obs_order.len().hash(&mut h);
    for o in obs_order {
        o.id.as_str().hash(&mut h);
        o.display_name.hash(&mut h);
        o.online.hash(&mut h);
        o.network_id.hash(&mut h);
        o.last_seen.hash(&mut h);
        hash_macs(&o.macs, &mut h);
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
        n.name.hash(&mut h);
        n.domain_name.hash(&mut h);
        n.vlan_id.hash(&mut h);
        n.ipv4_prefix.hash(&mut h);
        n.ipv6_prefix.hash(&mut h);
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
        c.display_name.hash(h);
        c.dns_label.hash(h);
        c.local_domain.hash(h);
        c.source.hash(h);
        c.online.hash(h);
        c.last_seen.hash(h);
        hash_macs(&c.macs, h);
        c.vlan.is_some().hash(h);
        if let Some(v) = &c.vlan {
            v.id.hash(h);
            v.name.hash(h);
            v.domain_name.hash(h);
        }
        let mut addrs: Vec<_> = c.addresses.iter().copied().collect();
        addrs.sort();
        for a in addrs {
            a.hash(h);
        }
    }
}

fn hash_macs(macs: &[MacAddr], h: &mut DefaultHasher) {
    let mut octets: Vec<[u8; 6]> = macs.iter().map(MacAddr::octets).collect();
    octets.sort_unstable();
    for m in octets {
        m.hash(h);
    }
}

fn count_addresses(lookup: &ClientLookup) -> usize {
    lookup.clients().iter().map(|c| c.addresses.len()).sum()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use std::net::IpAddr;
    use std::time::{Duration, SystemTime};

    use crate::config::ClientsConfig;
    use crate::merge::{self, NetworkInfo, UnifiObservation};
    use crate::state::State;
    use crate::types::{ClientId, MacAddr};

    fn sample_obs() -> UnifiObservation {
        UnifiObservation {
            id: ClientId::new("u1").unwrap(),
            display_name: "Phone".into(),
            macs: vec![MacAddr::from_octets([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01])],
            addresses: vec!["198.51.100.10".parse().unwrap()],
            network_id: Some("n1".into()),
            last_seen: Some(SystemTime::UNIX_EPOCH + Duration::from_secs(10)),
            online: true,
        }
    }

    fn sample_net() -> NetworkInfo {
        NetworkInfo {
            id: "n1".into(),
            name: "IoT".into(),
            vlan_id: Some(40),
            ipv4_prefix: Some("198.51.100.0/24".parse().unwrap()),
            ipv6_prefix: None,
            domain_name: Some("iot.example.com".into()),
        }
    }

    fn build_lookup(obs: &UnifiObservation, net: &NetworkInfo) -> ClientLookup {
        let cfg = ClientsConfig::default();
        merge::build(
            &[],
            std::slice::from_ref(obs),
            std::slice::from_ref(net),
            &State::default(),
            &cfg,
            SystemTime::UNIX_EPOCH + Duration::from_secs(100),
        )
        .unwrap()
        .lookup
    }

    fn hash(obs: &[UnifiObservation], nets: &[NetworkInfo], lookup: &ClientLookup) -> u64 {
        hash_content(obs, nets, lookup)
    }

    #[test]
    fn hash_includes_observation_fields() {
        let net = sample_net();
        let base_obs = sample_obs();
        let lookup = build_lookup(&base_obs, &net);
        let base = hash(
            std::slice::from_ref(&base_obs),
            std::slice::from_ref(&net),
            &lookup,
        );

        let mut renamed = base_obs.clone();
        renamed.display_name = "Renamed".into();
        assert_ne!(
            base,
            hash(
                std::slice::from_ref(&renamed),
                std::slice::from_ref(&net),
                &lookup
            )
        );

        let mut remac = base_obs.clone();
        remac.macs = vec![MacAddr::from_octets([1, 2, 3, 4, 5, 6])];
        assert_ne!(
            base,
            hash(
                std::slice::from_ref(&remac),
                std::slice::from_ref(&net),
                &lookup
            )
        );

        let mut reseen = base_obs;
        reseen.last_seen = Some(SystemTime::UNIX_EPOCH + Duration::from_secs(99));
        assert_ne!(
            base,
            hash(
                std::slice::from_ref(&reseen),
                std::slice::from_ref(&net),
                &lookup
            )
        );
    }

    #[test]
    fn hash_includes_network_fields() {
        let obs = sample_obs();
        let base_net = sample_net();
        let lookup = build_lookup(&obs, &base_net);
        let base = hash(
            std::slice::from_ref(&obs),
            std::slice::from_ref(&base_net),
            &lookup,
        );

        let mut renamed = base_net.clone();
        renamed.name = "LAN".into();
        assert_ne!(
            base,
            hash(
                std::slice::from_ref(&obs),
                std::slice::from_ref(&renamed),
                &lookup
            )
        );

        let mut reprefixed = base_net;
        reprefixed.ipv4_prefix = Some("192.0.2.0/24".parse().unwrap());
        assert_ne!(base, hash(&[obs], &[reprefixed], &lookup));
    }

    #[test]
    fn hash_includes_lookup_client_fields() {
        // Fold lookup-only fields (display name, MACs, last-seen, VLAN) with
        // empty observations/networks so only `hash_lookup_into` can differ.
        let net = sample_net();
        let obs = sample_obs();
        let base_lookup = build_lookup(&obs, &net);
        let base = hash(&[], &[], &base_lookup);

        let mut renamed = obs.clone();
        renamed.display_name = "Renamed".into();
        assert_ne!(base, hash(&[], &[], &build_lookup(&renamed, &net)));

        let mut remac = obs.clone();
        remac.macs = vec![MacAddr::from_octets([1, 2, 3, 4, 5, 6])];
        assert_ne!(base, hash(&[], &[], &build_lookup(&remac, &net)));

        let mut reseen = obs;
        reseen.last_seen = Some(SystemTime::UNIX_EPOCH + Duration::from_secs(99));
        assert_ne!(base, hash(&[], &[], &build_lookup(&reseen, &net)));

        let mut renamed_net = net;
        renamed_net.name = "LAN".into();
        assert_ne!(
            base,
            hash(&[], &[], &build_lookup(&sample_obs(), &renamed_net))
        );
    }

    #[test]
    fn hash_ignores_address_order() {
        let net = sample_net();
        let mut a = sample_obs();
        a.addresses = vec![
            IpAddr::from([198, 51, 100, 10]),
            IpAddr::from([198, 51, 100, 11]),
        ];
        let mut b = a.clone();
        b.addresses.reverse();
        let lookup = build_lookup(&a, &net);
        assert_eq!(
            hash(&[a], std::slice::from_ref(&net), &lookup),
            hash(&[b], &[net], &lookup)
        );
    }

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
