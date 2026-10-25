//! [`TlsEngine`]: load certs, schedule renewal and DynDNS, expose status.

use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Weak};
use std::time::Duration;

use tokio::sync::{Mutex, Notify, RwLock, broadcast};
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

use crate::acme::{AcmeBackend, InstantAcme};
use crate::clock::Clock;
use crate::cloudflare::{CLOUDFLARE_API_BASE, CloudflareClient};
use crate::config::TlsConfig;
use crate::dyndns::{DynDnsResult, EchoClient, dyndns_interval, dyndns_once};
use crate::error::TlsError;
use crate::issue::issue;
use crate::renew::{
    AriWindow, RenewFn, RenewScheduler, ScheduleFn, StatusFn, current_ari_window, next_renewal,
};
use crate::resolver::CertResolver;
use crate::secret::{CLOUDFLARE_API_TOKEN_ENV, Secret, read_secret};
use crate::status::TlsStatus;
use crate::store::CertStore;

/// Injectable dependencies for [`TlsEngine::open_with`] (tests / custom ACME).
pub struct EngineDeps {
    /// ACME directory + order backend.
    pub acme: Arc<dyn AcmeBackend>,
    /// Cloudflare API base (`None` → production).
    pub cloudflare_base_url: Option<String>,
    /// Public IP echo client.
    pub echo: EchoClient,
    /// Cloudflare API token.
    pub token: Secret,
}

/// Owns the certificate store, hot-reload resolver, and background tasks.
///
/// Drop aborts the renew scheduler and DynDNS loop. Background tasks hold only
/// a [`Weak`] to the shared state so they exit when the engine is dropped.
pub struct TlsEngine {
    inner: Arc<EngineInner>,
    renew: Option<RenewScheduler>,
    dyndns_handle: Option<JoinHandle<()>>,
    stop: Arc<Notify>,
}

/// Shared state held by the engine and (weakly) by background tasks.
///
/// Public so lifecycle tests can [`TlsEngine::downgrade`] and observe drop.
pub struct EngineInner {
    clock: Arc<dyn Clock>,
    store: CertStore,
    resolver: Arc<CertResolver>,
    config: RwLock<TlsConfig>,
    acme: Arc<dyn AcmeBackend>,
    cloudflare: RwLock<CloudflareClient>,
    echo: EchoClient,
    token: RwLock<Secret>,
    cloudflare_base_url: Option<String>,
    status: RwLock<TlsStatus>,
    ari_window: RwLock<Option<AriWindow>>,
    /// Single-flight issuance: waiters join the in-flight attempt.
    issue_flight: Mutex<Option<broadcast::Sender<Result<(), TlsError>>>>,
    /// Single-flight for DynDNS.
    dyndns_lock: Mutex<()>,
    acme_enabled: Arc<AtomicBool>,
    dyndns_enabled: Arc<AtomicBool>,
}

impl Drop for TlsEngine {
    fn drop(&mut self) {
        self.stop.notify_waiters();
        if let Some(r) = self.renew.take() {
            drop(r);
        }
        if let Some(h) = self.dyndns_handle.take() {
            h.abort();
        }
    }
}

impl TlsEngine {
    /// Opens the engine with production ACME / Cloudflare / echo clients.
    ///
    /// Loads any last-good certificate into the resolver even when ACME or
    /// Cloudflare are unreachable. Background tasks start on the current Tokio
    /// runtime.
    pub fn open(
        mut config: TlsConfig,
        data_dir: &Path,
        clock: Arc<dyn Clock>,
    ) -> Result<Self, TlsError> {
        config.validate()?;
        let token = if config.acme.enabled || config.dyndns.enabled {
            read_secret(CLOUDFLARE_API_TOKEN_ENV)?
        } else {
            Secret::new("")
        };
        let deps = EngineDeps {
            acme: Arc::new(InstantAcme::new()?),
            cloudflare_base_url: None,
            echo: EchoClient::new()?,
            token,
        };
        Self::open_with(config, data_dir, clock, deps)
    }

    /// Like [`Self::open`] with injectable ACME, Cloudflare base URL, and echo.
    pub fn open_with(
        mut config: TlsConfig,
        data_dir: &Path,
        clock: Arc<dyn Clock>,
        deps: EngineDeps,
    ) -> Result<Self, TlsError> {
        let token_for_validate = deps.token.clone();
        config.validate_with_token(|_| Ok(token_for_validate))?;

        let store = CertStore::open(data_dir)?;
        let resolver = Arc::new(CertResolver::new());

        // Permission problems on key.pem / account.json must not panic or abort
        // open: refuse to install a too-open key, record tls.store.permissions
        // in state/status, leave files for the operator to chmod (see README).
        let mut permissions_err: Option<TlsError> = None;
        if let Err(e) = store.check_account_permissions() {
            permissions_err = Some(e);
        }
        let loaded = match store.load() {
            Ok(v) => v,
            Err(e @ TlsError::StorePermissions { .. }) => {
                permissions_err = Some(e);
                None
            }
            Err(e) => return Err(e),
        };
        if let Some(loaded) = loaded {
            if let Err(e) = resolver.install(&loaded.chain_pem, loaded.key.as_bytes()) {
                warn!(code = e.code(), "stored cert could not be installed: {e}");
            } else {
                info!("loaded last-good certificate into resolver");
            }
        }
        if let Some(ref e) = permissions_err {
            warn!(code = e.code(), "{e}");
            let mut state = store.load_state();
            state.last_error = Some(e.code().to_owned());
            if let Err(save_err) = store.save_state(&state) {
                warn!(
                    code = save_err.code(),
                    "could not persist store permissions error"
                );
            }
        }

        let base = deps
            .cloudflare_base_url
            .clone()
            .unwrap_or_else(|| CLOUDFLARE_API_BASE.to_owned());
        let cloudflare = CloudflareClient::with_base_url(
            deps.token.clone(),
            config.public_domain.clone(),
            &config.cloudflare,
            base,
        )?;

        let acme_enabled = Arc::new(AtomicBool::new(config.acme.enabled));
        let dyndns_enabled = Arc::new(AtomicBool::new(config.dyndns.enabled));

        let status = TlsStatus::from_cert(
            store.load().ok().flatten().as_ref(),
            &store.load_state(),
            clock.now(),
            config.expiry_warn,
            &config.acme.directory,
            config.acme.enabled,
        );

        let inner = Arc::new(EngineInner {
            clock: Arc::clone(&clock),
            store,
            resolver,
            config: RwLock::new(config),
            acme: deps.acme,
            cloudflare: RwLock::new(cloudflare),
            echo: deps.echo,
            token: RwLock::new(deps.token),
            cloudflare_base_url: deps.cloudflare_base_url,
            status: RwLock::new(status),
            ari_window: RwLock::new(None),
            issue_flight: Mutex::new(None),
            dyndns_lock: Mutex::new(()),
            acme_enabled: Arc::clone(&acme_enabled),
            dyndns_enabled: Arc::clone(&dyndns_enabled),
        });

        let stop = Arc::new(Notify::new());
        let renew = start_renew_scheduler(Arc::clone(&inner), Arc::clone(&acme_enabled));
        let dyndns_handle = start_dyndns_loop(Arc::clone(&inner), Arc::clone(&stop));

        {
            let weak = Arc::downgrade(&inner);
            tokio::spawn(async move {
                if let Some(inner) = weak.upgrade() {
                    inner.refresh_ari().await;
                    inner.refresh_status().await;
                }
            });
        }

        Ok(Self {
            inner,
            renew: Some(renew),
            dyndns_handle: Some(dyndns_handle),
            stop,
        })
    }

    /// Shared cert resolver for listeners.
    pub fn resolver(&self) -> Arc<CertResolver> {
        Arc::clone(&self.inner.resolver)
    }

    /// Snapshot of certificate / DynDNS / error status.
    ///
    /// Prefer [`Self::status_async`] from async code (this may block briefly).
    pub fn status(&self) -> TlsStatus {
        self.inner.status.blocking_read().clone()
    }

    /// Async status read.
    pub async fn status_async(&self) -> TlsStatus {
        self.inner.status.read().await.clone()
    }

    /// Validates `config`, swaps it in, and updates background flags.
    ///
    /// A change of `public_domain` triggers a renewal when ACME is enabled.
    /// Does not kick the scheduler for that renewal (avoids a duplicate order
    /// after `renew_now` finishes).
    pub async fn apply_config(&self, mut config: TlsConfig) -> Result<(), TlsError> {
        let token = self.inner.token.read().await.clone();
        config.validate_with_token(|_| Ok(token.clone()))?;

        let old_domain = self.inner.config.read().await.public_domain.clone();
        let domain_changed = old_domain != config.public_domain;
        let acme_on = config.acme.enabled;

        self.inner.acme_enabled.store(acme_on, Ordering::SeqCst);
        self.inner
            .dyndns_enabled
            .store(config.dyndns.enabled, Ordering::SeqCst);

        let base = self
            .inner
            .cloudflare_base_url
            .clone()
            .unwrap_or_else(|| CLOUDFLARE_API_BASE.to_owned());
        let cf = CloudflareClient::with_base_url(
            token,
            config.public_domain.clone(),
            &config.cloudflare,
            base,
        )?;
        *self.inner.cloudflare.write().await = cf;
        *self.inner.config.write().await = config;

        self.inner.refresh_ari().await;
        self.inner.refresh_status().await;

        if domain_changed && acme_on {
            info!(old = %old_domain, "public_domain changed; renewing");
            let _ = self.renew_now().await;
        } else if let Some(r) = &self.renew {
            r.kick();
        }
        Ok(())
    }

    /// Runs one issuance/renewal now (single-flight with the scheduler).
    pub async fn renew_now(&self) -> Result<(), TlsError> {
        self.inner.do_issue().await
    }

    /// Runs one DynDNS pass now (single-flight with the background loop).
    pub async fn dyndns_now(&self) -> Result<DynDnsResult, TlsError> {
        self.inner.do_dyndns().await
    }

    /// Weak reference to the shared state (drop / lifecycle tests).
    pub fn downgrade(&self) -> Weak<EngineInner> {
        Arc::downgrade(&self.inner)
    }
}

impl EngineInner {
    async fn do_issue(&self) -> Result<(), TlsError> {
        // Join an in-flight attempt instead of starting a second order
        // (InstantAcme holds one pending order; kick-during-renew must not
        // double-order).
        let tx = {
            let mut slot = self.issue_flight.lock().await;
            if let Some(tx) = slot.as_ref() {
                let mut rx = tx.subscribe();
                drop(slot);
                return match rx.recv().await {
                    Ok(r) => r,
                    Err(_) => Err(TlsError::AcmeOrder {
                        message: "in-flight issuance dropped".into(),
                    }),
                };
            }
            let (tx, _rx) = broadcast::channel(16);
            *slot = Some(tx.clone());
            tx
        };

        let cfg = self.config.read().await.clone();
        let result = if !cfg.acme.enabled {
            Err(TlsError::config("ACME is disabled"))
        } else {
            let cf = self.cloudflare.read().await.clone();
            issue(
                self.acme.as_ref(),
                &cf,
                &self.store,
                self.resolver.as_ref(),
                &cfg,
                self.clock.as_ref(),
            )
            .await
        };

        let _ = tx.send(result.clone());
        *self.issue_flight.lock().await = None;

        // Refresh ARI so ScheduleFn does not immediately re-fire after a kick
        // that arrived during this renew.
        self.refresh_ari().await;
        self.refresh_status().await;
        result
    }

    async fn do_dyndns(&self) -> Result<DynDnsResult, TlsError> {
        let _guard = self.dyndns_lock.lock().await;
        let cfg = self.config.read().await.clone();
        if !cfg.dyndns.enabled {
            return Ok(DynDnsResult::default());
        }
        let cf = self.cloudflare.read().await.clone();
        let result = dyndns_once(&cfg.dyndns, &cfg.public_domain, &self.echo, &cf).await;
        match &result {
            Ok(r) => {
                let mut st = self.status.write().await;
                if let Some(v4) = r.ipv4 {
                    st.dyndns_ipv4 = Some(v4.to_string());
                }
                if let Some(v6) = r.ipv6 {
                    st.dyndns_ipv6 = Some(v6.to_string());
                }
                if let Some(t) = r.last_change {
                    st.dyndns_last_change = Some(t);
                }
                if r.changed {
                    st.last_error = None;
                }
            }
            Err(e) => {
                let mut st = self.status.write().await;
                st.last_error = Some(e.code().to_owned());
            }
        }
        result
    }

    async fn refresh_ari(&self) {
        let cfg = self.config.read().await.clone();
        let window = current_ari_window(self.acme.as_ref(), &self.store, &cfg.acme).await;
        *self.ari_window.write().await = window;
    }

    async fn refresh_status(&self) {
        let cfg = self.config.read().await.clone();
        let loaded = self.store.load().ok().flatten();
        let state = self.store.load_state();
        let mut next = TlsStatus::from_cert(
            loaded.as_ref(),
            &state,
            self.clock.now(),
            cfg.expiry_warn,
            &cfg.acme.directory,
            cfg.acme.enabled,
        );
        {
            let prev = self.status.read().await;
            next.dyndns_ipv4 = prev.dyndns_ipv4.clone();
            next.dyndns_ipv6 = prev.dyndns_ipv6.clone();
            next.dyndns_last_change = prev.dyndns_last_change;
        }
        *self.status.write().await = next;
    }
}

fn start_renew_scheduler(inner: Arc<EngineInner>, acme_enabled: Arc<AtomicBool>) -> RenewScheduler {
    let weak_sched: Weak<EngineInner> = Arc::downgrade(&inner);
    let weak_renew = Arc::downgrade(&inner);
    let weak_status = Arc::downgrade(&inner);

    let schedule: ScheduleFn = Arc::new(move |now| {
        let Some(inner) = weak_sched.upgrade() else {
            return now;
        };
        // blocking_read is OK: ScheduleFn is sync and called from the renew task.
        let cfg = inner.config.blocking_read();
        let ari = *inner.ari_window.blocking_read();
        let not_after = inner.store.load().ok().flatten().map(|c| c.not_after);
        next_renewal(not_after, cfg.renew_before, ari, now)
    });

    let renew: RenewFn = Arc::new(move || {
        let weak = weak_renew.clone();
        Box::pin(async move {
            let Some(inner) = weak.upgrade() else {
                return Ok(());
            };
            inner.do_issue().await
        })
    });

    let on_status: StatusFn = Arc::new(move || {
        let Some(inner) = weak_status.upgrade() else {
            return TlsStatus::default();
        };
        inner.status.blocking_read().clone()
    });

    RenewScheduler::start(
        Arc::clone(&inner.clock),
        acme_enabled,
        schedule,
        renew,
        on_status,
    )
}

fn start_dyndns_loop(inner: Arc<EngineInner>, stop: Arc<Notify>) -> JoinHandle<()> {
    let weak = Arc::downgrade(&inner);
    tokio::spawn(async move {
        loop {
            let Some(inner) = weak.upgrade() else {
                return;
            };
            if inner.dyndns_enabled.load(Ordering::SeqCst) {
                match inner.do_dyndns().await {
                    Ok(r) => {
                        if r.changed {
                            debug!("DynDNS updated records");
                        }
                    }
                    Err(e) => warn!(code = e.code(), "DynDNS failed: {e}"),
                }
            }
            let interval = {
                let cfg = inner.config.read().await;
                if cfg.dyndns.enabled {
                    dyndns_interval(cfg.dyndns.interval)
                } else {
                    Duration::from_secs(60)
                }
            };
            drop(inner);

            tokio::select! {
                () = stop.notified() => return,
                () = tokio::time::sleep(interval) => {}
            }
        }
    })
}
