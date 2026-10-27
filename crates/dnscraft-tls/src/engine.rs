//! [`TlsEngine`]: load certs, schedule renewal and DynDNS, expose status.

use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Weak};
use std::time::{Duration, SystemTime};

use tokio::sync::{Mutex, Notify, RwLock, broadcast};
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

use crate::acme::{
    AcmeAccountStatus, AcmeBackend, AcmeOrderStatus, InstantAcme, RevocationReason, account_status,
};
use crate::clock::Clock;
use crate::cloudflare::{CLOUDFLARE_API_BASE, CloudflareClient};
use crate::config::{DnsProviderKind, TlsConfig};
use crate::dyndns::{DynDnsResult, EchoClient, InventoryRecord, dyndns_interval, dyndns_pass};
use crate::error::TlsError;
use crate::issue::issue;
use crate::pem_util::{certified_key_from_pem, fingerprint_sha256, parse_leaf_info};
use crate::renew::{
    AriWindow, RenewFn, RenewScheduler, ScheduleFn, StatusFn, current_ari_window, next_renewal,
};
use crate::resolver::CertResolver;
use crate::status::{
    AriStatus, CertSource, DynDnsAuditEntry, IssueOutcome, IssueRecord, PreflightCheck,
    PreflightReport, RateLimitStatus, TlsStatus,
};
use crate::store::{CertMeta, CertStore, push_dyndns_audit, push_history};
use crate::{CLOUDFLARE_API_TOKEN_ENV, Secret, read_secret};

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
    rate_limit: RwLock<RateLimitStatus>,
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
        if let Some(loaded) = &loaded {
            if state_revoked(&store) {
                warn!("stored certificate is marked revoked; not serving it");
            } else if let Err(e) = resolver.install(&loaded.chain_pem, loaded.key.as_bytes()) {
                warn!(code = e.code(), "stored cert could not be installed: {e}");
            } else {
                info!("loaded last-good certificate into resolver");
            }
        }

        // Bootstrap manual material only when the store has no certificate yet;
        // a later API upload must not be reverted on restart.
        if loaded.is_none()
            && !state_revoked(&store)
            && let Some(manual) = &config.manual
        {
            let fullchain = manual.fullchain_pem();
            match store.save(
                fullchain.as_bytes(),
                manual.key_pem.expose().as_bytes(),
                &CertMeta {
                    source: CertSource::Manual,
                    ..CertMeta::default()
                },
            ) {
                Ok(()) => {
                    if let Err(e) =
                        resolver.install(fullchain.as_bytes(), manual.key_pem.expose().as_bytes())
                    {
                        warn!(code = e.code(), "manual cert could not be installed: {e}");
                    } else {
                        info!("installed configured manual certificate");
                    }
                }
                Err(e) => warn!(code = e.code(), "manual cert could not be saved: {e}"),
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
            &config.dns_provider.cloudflare,
            base,
        )?
        .with_zones(config.dns_provider.zones.clone());

        let acme_enabled = Arc::new(AtomicBool::new(config.acme.enabled));
        let dyndns_enabled = Arc::new(AtomicBool::new(config.dyndns.enabled));

        let status = build_status(&config, &store, clock.as_ref(), None);

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
            rate_limit: RwLock::new(RateLimitStatus::default()),
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
        let acme_was_on = self.inner.acme_enabled.load(Ordering::SeqCst);
        let auto_deactivate = config.acme.account.auto_deactivate;
        let manual = config.manual.clone();

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
            &config.dns_provider.cloudflare,
            base,
        )?
        .with_zones(config.dns_provider.zones.clone());
        *self.inner.cloudflare.write().await = cf;
        *self.inner.config.write().await = config;

        // Bootstrap manual material only when the store has no certificate yet
        // (mirror `open`): never revert a newer API upload, and never clear a
        // persisted revocation by re-installing configured material.
        let no_cert = matches!(self.inner.store.load(), Ok(None));
        if let Some(manual) = manual
            && no_cert
            && !state_revoked(&self.inner.store)
        {
            self.upload_manual_cert(&manual.cert_pem, &manual.key_pem, &manual.chain_pem)
                .await?;
        }

        if acme_was_on && !acme_on && auto_deactivate {
            let cfg = self.inner.config.read().await.clone();
            if let Err(e) = self
                .inner
                .acme
                .deactivate_account(&self.inner.store, &cfg.acme)
                .await
            {
                warn!(code = e.code(), "ACME account deactivation failed: {e}");
            } else {
                info!("ACME account deactivated");
            }
        }

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

    /// Validates and installs an operator-supplied certificate + key + chain.
    ///
    /// The key is written to `key.pem` (0o600) and never returned or logged.
    /// Persisted metadata records [`CertSource::Manual`].
    pub async fn upload_manual_cert(
        &self,
        cert_pem: &str,
        key_pem: &Secret,
        chain_pem: &str,
    ) -> Result<(), TlsError> {
        let fullchain = join_pem(cert_pem, chain_pem);
        let key_bytes = key_pem.expose().as_bytes();
        certified_key_from_pem(fullchain.as_bytes(), key_bytes).map_err(|message| {
            TlsError::CertManualInvalid {
                message: format!("certificate/key mismatch or invalid PEM: {message}"),
            }
        })?;
        let info = parse_leaf_info(fullchain.as_bytes()).map_err(|message| {
            TlsError::CertManualInvalid {
                message: format!("leaf certificate: {message}"),
            }
        })?;
        self.inner.store.save(
            fullchain.as_bytes(),
            key_bytes,
            &CertMeta {
                source: CertSource::Manual,
                ..CertMeta::default()
            },
        )?;
        self.inner
            .resolver
            .install(fullchain.as_bytes(), key_bytes)
            .map_err(|e| TlsError::CertManualInvalid {
                message: format!("install: {e}"),
            })?;

        let now = self.inner.clock.now();
        let mut state = self.inner.store.load_state();
        state.last_error = None;
        state.last_issue_unix = Some(unix_secs(now));
        state.last_renew_attempt_unix = Some(unix_secs(now));
        state.revoked = false;
        state.revoked_reason = None;
        push_history(
            &mut state,
            IssueRecord {
                timestamp: now,
                outcome: IssueOutcome::Issued,
                error: None,
                serial: info.detail.serial,
            },
        );
        self.inner.store.save_state(&state)?;

        self.inner.refresh_ari().await;
        self.inner.refresh_status().await;
        Ok(())
    }

    /// Revokes the stored certificate (ACME CA when applicable) and stops serving it.
    ///
    /// `reason` accepts `key_compromise`, `superseded`, … (see
    /// [`RevocationReason::parse`]); `None` means `unspecified`.
    pub async fn revoke(&self, reason: Option<&str>) -> Result<(), TlsError> {
        let cfg = self.inner.config.read().await.clone();
        let loaded = self.inner.store.load()?.ok_or(TlsError::CertAbsent)?;
        let parsed = RevocationReason::parse(reason.unwrap_or("unspecified"))?;

        if loaded.meta.source == CertSource::Acme && cfg.acme.enabled {
            self.inner
                .acme
                .revoke_certificate(&self.inner.store, &cfg.acme, &loaded.chain_pem, parsed)
                .await?;
        }

        let mut state = self.inner.store.load_state();
        state.revoked = true;
        state.revoked_reason = Some(reason.unwrap_or("unspecified").to_owned());
        state.last_error = Some(TlsError::CertRevoked.code().to_owned());
        self.inner.store.save_state(&state)?;
        self.inner.resolver.clear();
        self.inner.refresh_status().await;
        Ok(())
    }

    /// Offline dry-run: checks config, store health, trust pin, account and DNS provider.
    ///
    /// Never contacts the CA, Cloudflare, or the echo service.
    pub async fn preflight(&self) -> PreflightReport {
        let cfg = self.inner.config.read().await.clone();
        let mut checks = Vec::new();

        let health = self.inner.store.health();
        checks.push(PreflightCheck {
            name: "store".into(),
            ok: health.writable && !health.corrupt,
            code: (!health.writable || health.corrupt).then(|| {
                TlsError::StoreUnhealthy {
                    message: String::new(),
                }
                .code()
                .to_owned()
            }),
            message: Some(format!(
                "path={} writable={} corrupt={}",
                health.path, health.writable, health.corrupt
            )),
        });

        let loaded = self.inner.store.load().ok().flatten();
        checks.push(PreflightCheck {
            name: "certificate".into(),
            ok: loaded.is_some() || !health.corrupt,
            code: health.corrupt.then(|| {
                TlsError::StoreUnhealthy {
                    message: String::new(),
                }
                .code()
                .to_owned()
            }),
            message: Some(if loaded.is_some() {
                "certificate loaded".into()
            } else {
                "no certificate yet".into()
            }),
        });

        if let Some(pin) = &cfg.trust_pin {
            let actual = loaded.as_ref().and_then(|cert| {
                crate::pem_util::parse_cert_chain(&cert.chain_pem)
                    .ok()
                    .and_then(|certs| certs.first().map(|der| fingerprint_sha256(der.as_ref())))
            });
            let ok = actual
                .as_deref()
                .is_some_and(|fp| fp.eq_ignore_ascii_case(&pin.sha256));
            checks.push(PreflightCheck {
                name: "trust_pin".into(),
                ok,
                code: (!ok).then(|| TlsError::PinMismatch.code().to_owned()),
                message: actual.map(|actual| format!("actual sha256={actual}")),
            });
        }

        if cfg.acme.enabled {
            let status = account_status(&self.inner.store, &cfg.acme).ok();
            let ok = status.as_ref().is_some_and(|s| s.exists || s.tos_agreed);
            checks.push(PreflightCheck {
                name: "acme_account".into(),
                ok,
                code: (!ok).then(|| {
                    TlsError::AcmeAccountTos {
                        message: String::new(),
                    }
                    .code()
                    .to_owned()
                }),
                message: status.map(|s| format!("exists={} directory={}", s.exists, s.directory)),
            });

            let (ok, code) = match cfg.dns_provider.kind {
                DnsProviderKind::Cloudflare => (true, None),
                DnsProviderKind::Manual => (
                    false,
                    Some(
                        TlsError::DnsManual {
                            message: String::new(),
                        }
                        .code()
                        .to_owned(),
                    ),
                ),
                DnsProviderKind::None => (
                    false,
                    Some(
                        TlsError::DnsProviderAuth {
                            message: String::new(),
                        }
                        .code()
                        .to_owned(),
                    ),
                ),
            };
            checks.push(PreflightCheck {
                name: "dns_provider".into(),
                ok,
                code,
                message: Some(format!("kind={:?}", cfg.dns_provider.kind)),
            });
        }

        PreflightReport::from_checks(checks)
    }

    /// Forces a new certificate with a fresh private key.
    pub async fn rotate_key(&self) -> Result<(), TlsError> {
        let acme_enabled = self.inner.config.read().await.acme.enabled;
        if !acme_enabled {
            return Err(TlsError::CertRotateFailed {
                message: "ACME is disabled".into(),
            });
        }
        self.inner
            .do_issue()
            .await
            .map_err(|e| TlsError::CertRotateFailed {
                message: format!("{}: {e}", e.code()),
            })
    }

    /// Fullchain PEM export (certificates only; never the private key).
    pub fn export_cert(&self) -> Result<String, TlsError> {
        let loaded = self.inner.store.load()?.ok_or(TlsError::CertAbsent)?;
        let text = String::from_utf8(loaded.chain_pem).map_err(|_| TlsError::StoreCorrupt {
            message: "cert.pem is not UTF-8".into(),
        })?;
        if text.contains("PRIVATE KEY") {
            return Err(TlsError::StoreCorrupt {
                message: "refusing to export a bundle containing a private key".into(),
            });
        }
        Ok(text)
    }

    /// ACME account state (never includes the account key).
    pub async fn acme_account_status(&self) -> Result<AcmeAccountStatus, TlsError> {
        let cfg = self.inner.config.read().await.clone();
        account_status(&self.inner.store, &cfg.acme)
    }

    /// Most recent ACME order progress snapshot.
    pub fn order_status(&self) -> AcmeOrderStatus {
        self.inner.acme.order_status()
    }

    /// Rate-limit state of the most recent ACME attempt.
    pub async fn rate_limit_status(&self) -> RateLimitStatus {
        self.inner.rate_limit.read().await.clone()
    }

    /// Lists the A/AAAA records this node manages.
    pub async fn record_inventory(&self) -> Result<Vec<InventoryRecord>, TlsError> {
        let cfg = self.inner.config.read().await.clone();
        if !cfg.dns_provider.uses_cloudflare() {
            return Err(TlsError::DnsProviderAuth {
                message: "record inventory requires dns_provider.kind = cloudflare".into(),
            });
        }
        let cloudflare = self.inner.cloudflare.read().await.clone();
        crate::dyndns::record_inventory(&cfg.dyndns, &cfg.public_domain, &cloudflare).await
    }

    /// DynDNS audit trail (bounded, oldest first).
    pub async fn dyndns_audit(&self) -> Vec<DynDnsAuditEntry> {
        self.inner.store.load_state().dyndns_audit
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

        *self.rate_limit.write().await = rate_limit_after(&result, self.clock.now());

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
        let (result, outcome) = dyndns_pass(&cfg.dyndns, &cfg.public_domain, &self.echo, &cf).await;
        let now = self.clock.now();
        let next = now + dyndns_interval(cfg.dyndns.interval);

        // Persist audit for every write that succeeded, even when a later write
        // in this pass failed.
        if !result.audit.is_empty() {
            let mut state = self.store.load_state();
            push_dyndns_audit(&mut state, result.audit.iter().cloned());
            if let Err(e) = self.store.save_state(&state) {
                warn!(code = e.code(), "could not persist DynDNS audit: {e}");
            }
        }

        match &outcome {
            Ok(()) => {
                let mut st = self.status.write().await;
                if let Some(v4) = result.ipv4 {
                    st.dyndns_ipv4 = Some(v4.to_string());
                }
                if let Some(v6) = result.ipv6 {
                    st.dyndns_ipv6 = Some(v6.to_string());
                }
                if let Some(t) = result.last_change {
                    st.dyndns_last_change = Some(t);
                }
                st.dyndns_stale = false;
                st.last_dyndns_success = Some(now);
                st.next_dyndns_at = Some(next);
                if result.changed {
                    st.last_error = None;
                }
            }
            Err(e) => {
                let mut st = self.status.write().await;
                st.last_error = Some(e.code().to_owned());
                st.dyndns_stale = true;
                st.next_dyndns_at = Some(next);
            }
        }
        outcome.map(|()| result)
    }

    async fn refresh_ari(&self) {
        let cfg = self.config.read().await.clone();
        let window = current_ari_window(self.acme.as_ref(), &self.store, &cfg.acme).await;
        *self.ari_window.write().await = window;
    }

    async fn refresh_status(&self) {
        let cfg = self.config.read().await.clone();
        let window = *self.ari_window.read().await;
        let mut next = build_status(&cfg, &self.store, self.clock.as_ref(), window);
        {
            let prev = self.status.read().await;
            next.dyndns_ipv4 = prev.dyndns_ipv4.clone();
            next.dyndns_ipv6 = prev.dyndns_ipv6.clone();
            next.dyndns_last_change = prev.dyndns_last_change;
            next.dyndns_stale = prev.dyndns_stale;
            next.last_dyndns_success = prev.last_dyndns_success;
            next.next_dyndns_at = prev.next_dyndns_at.or(next.next_dyndns_at);
        }
        *self.status.write().await = next;
    }
}

fn state_revoked(store: &CertStore) -> bool {
    store.load_state().revoked
}

/// Rate-limit status for the most recent ACME attempt.
///
/// A non-rate-limit failure (or success) clears a previous rate-limit state:
/// the status always describes the latest attempt, never an older one.
fn rate_limit_after(result: &Result<(), TlsError>, now: SystemTime) -> RateLimitStatus {
    match result {
        Err(e) if e.code() == "tls.acme.rate_limited" => RateLimitStatus {
            limited: true,
            retry_after: e.retry_after(),
            retry_at: e.retry_after().map(|delay| now + delay),
        },
        _ => RateLimitStatus::default(),
    }
}

/// Leaf PEM followed by an optional intermediate chain PEM.
fn join_pem(cert_pem: &str, chain_pem: &str) -> String {
    let mut out = cert_pem.trim().to_owned();
    let chain = chain_pem.trim();
    if !chain.is_empty() {
        out.push('\n');
        out.push_str(chain);
    }
    out.push('\n');
    out
}

fn unix_secs(t: SystemTime) -> i64 {
    t.duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn build_status(
    cfg: &TlsConfig,
    store: &CertStore,
    clock: &dyn Clock,
    window: Option<AriWindow>,
) -> TlsStatus {
    let loaded = store.load().ok().flatten();
    let state = store.load_state();
    let now = clock.now();
    let mut status = TlsStatus::from_cert(
        loaded.as_ref(),
        &state,
        now,
        cfg.expiry_warn,
        &cfg.acme.directory,
        cfg.acme.enabled,
    );
    status.ari = loaded.as_ref().map(|cert| {
        AriStatus::new(
            window.map(|w| w.start),
            window.map(|w| w.end),
            cert.meta.ari_cert_id.clone(),
        )
    });
    status.next_renew_at = cfg.acme.enabled.then(|| {
        next_renewal(
            loaded.as_ref().map(|c| c.not_after),
            cfg.renew_before,
            window,
            now,
        )
    });
    status.store = Some(store.health());
    if cfg.dyndns.enabled {
        status.next_dyndns_at = Some(now + dyndns_interval(cfg.dyndns.interval));
    }
    status
}

fn start_renew_scheduler(inner: Arc<EngineInner>, acme_enabled: Arc<AtomicBool>) -> RenewScheduler {
    let weak_sched: Weak<EngineInner> = Arc::downgrade(&inner);
    let weak_renew = Arc::downgrade(&inner);
    let weak_status = Arc::downgrade(&inner);

    let schedule: ScheduleFn = Arc::new(move |now| {
        let Some(inner) = weak_sched.upgrade() else {
            return now;
        };
        // Called from the Tokio renew task — never `blocking_read` (panics in runtime).
        let Ok(cfg) = inner.config.try_read() else {
            return now;
        };
        let Ok(ari) = inner.ari_window.try_read() else {
            return now;
        };
        let ari = *ari;
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
        // Called from the Tokio renew task — never `blocking_read` (panics in runtime).
        match inner.status.try_read() {
            Ok(guard) => guard.clone(),
            Err(_) => TlsStatus::default(),
        }
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod unit {
    use super::*;

    #[test]
    fn rate_limit_status_reflects_most_recent_attempt() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000);
        let limited = Err(TlsError::AcmeRateLimited {
            message: "slow down".into(),
            retry_after: Some(Duration::from_secs(120)),
        });
        let status = rate_limit_after(&limited, now);
        assert!(status.limited);
        assert_eq!(status.retry_after, Some(Duration::from_secs(120)));
        assert_eq!(status.retry_at, Some(now + Duration::from_secs(120)));

        // A later attempt failing for another reason clears the stale state.
        let other = Err(TlsError::AcmeOrder {
            message: "boom".into(),
        });
        let status = rate_limit_after(&other, now);
        assert!(!status.limited);
        assert_eq!(status.retry_after, None);
        assert_eq!(status.retry_at, None);
    }
}
