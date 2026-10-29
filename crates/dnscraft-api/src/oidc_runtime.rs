//! Live OIDC relying-party state that can be rebuilt from WebUI settings.
//!
//! Bootstrap [`AuthConfig`] supplies defaults; `control_api_settings.oidc`
//! overlays non-secret fields; the client secret comes from kv (WebUI) or the
//! bootstrap/env value. [`OidcRuntime::apply`] rebuilds [`OidcState`] without a
//! process restart so Authentik (or any OIDC IdP) can be configured in the UI.

use std::sync::{Arc, Mutex, PoisonError, RwLock};
use std::time::Duration;

use serde_json::Value;

use crate::api::auth::{AuthState, OidcState};
use crate::config::AuthConfig;
use crate::error::ControlApiError;
use crate::oidc_secrets;
use crate::storage::Db;
use crate::Secret;
use dnscraft_common::clock::Clock;

/// Shared slots AppState and the config apply path both use.
#[derive(Clone)]
pub struct OidcRuntime {
    bootstrap: AuthConfig,
    overlay: Arc<Mutex<OidcOverlay>>,
    slot: Arc<RwLock<Option<Arc<OidcState>>>>,
    issuer: Arc<RwLock<Option<String>>>,
    auth: Arc<Mutex<Option<Arc<AuthState>>>>,
    db: Db,
    clock: Arc<dyn Clock>,
}

/// Non-secret fields last applied from `control_api_settings.oidc`.
#[derive(Clone, Debug, Default)]
struct OidcOverlay {
    enabled: Option<bool>,
    issuer: Option<String>,
    client_id: Option<String>,
    admin_group: Option<String>,
    groups_claim: Option<String>,
    token_skew: Option<Duration>,
}

impl OidcRuntime {
    /// Builds a runtime around bootstrap auth settings and empty live state.
    pub fn new(bootstrap: AuthConfig, db: Db, clock: Arc<dyn Clock>) -> Self {
        Self {
            bootstrap,
            overlay: Arc::new(Mutex::new(OidcOverlay::default())),
            slot: Arc::new(RwLock::new(None)),
            issuer: Arc::new(RwLock::new(None)),
            auth: Arc::new(Mutex::new(None)),
            db,
            clock,
        }
    }

    /// The live OIDC state slot shared with [`crate::AppState`].
    pub fn slot(&self) -> Arc<RwLock<Option<Arc<OidcState>>>> {
        Arc::clone(&self.slot)
    }

    /// The live issuer slot shared with [`crate::AppState`].
    pub fn issuer_slot(&self) -> Arc<RwLock<Option<String>>> {
        Arc::clone(&self.issuer)
    }

    /// Attaches auth so cluster snapshots pick up OIDC setting changes.
    pub fn attach_auth(&self, auth: Arc<AuthState>) {
        *self
            .auth
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(auth);
    }

    /// Overwrites the bootstrap client secret (typically from env at startup).
    pub fn set_bootstrap_secret(&mut self, secret: Secret) {
        self.bootstrap.oidc_client_secret = secret;
    }

    /// Whether a live OIDC relying party is currently active.
    pub fn enabled(&self) -> bool {
        self.slot
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .is_some()
    }

    /// Parses `control_api_settings.oidc` and rebuilds the live relying party.
    pub async fn apply(&self, section: Option<&Value>) -> Result<(), ControlApiError> {
        {
            let mut overlay = self.overlay.lock().unwrap_or_else(PoisonError::into_inner);
            *overlay = OidcOverlay::from_value(section)?;
        }
        self.rebuild().await
    }

    /// Rebuilds from the last overlay after a secret change.
    pub async fn rebuild(&self) -> Result<(), ControlApiError> {
        let overlay = self
            .overlay
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        let mut auth = self.bootstrap.clone();
        overlay.apply_to(&mut auth);

        let kv_secret = oidc_secrets::get_client_secret(&self.db).await?;
        if let Some(secret) = kv_secret {
            auth.oidc_client_secret = Secret::new(secret);
        }

        let next = OidcState::from_config_with_clock(&auth, Arc::clone(&self.clock))?;
        let issuer = next
            .as_ref()
            .map(|state| state.settings().issuer)
            .filter(|issuer| !issuer.is_empty());
        let settings = next.as_ref().map(OidcState::settings);

        *self.slot.write().unwrap_or_else(PoisonError::into_inner) =
            next.map(Arc::new);
        *self
            .issuer
            .write()
            .unwrap_or_else(PoisonError::into_inner) = issuer;

        if let Some(auth_state) = self
            .auth
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()
        {
            auth_state.set_oidc_settings(settings);
        }
        Ok(())
    }
}

impl OidcOverlay {
    fn from_value(section: Option<&Value>) -> Result<Self, ControlApiError> {
        let Some(value) = section else {
            return Ok(Self::default());
        };
        let object = value.as_object().ok_or_else(|| ControlApiError::config(
            "control_api_settings.oidc must be an object",
        ))?;
        let mut overlay = Self::default();
        for (key, field) in object {
            match key.as_str() {
                "enabled" => {
                    overlay.enabled = Some(field.as_bool().ok_or_else(|| {
                        ControlApiError::config("control_api_settings.oidc.enabled must be a boolean")
                    })?);
                }
                "issuer" => {
                    overlay.issuer = Some(
                        field
                            .as_str()
                            .ok_or_else(|| {
                                ControlApiError::config(
                                    "control_api_settings.oidc.issuer must be a string",
                                )
                            })?
                            .to_owned(),
                    );
                }
                "client_id" => {
                    overlay.client_id = Some(
                        field
                            .as_str()
                            .ok_or_else(|| {
                                ControlApiError::config(
                                    "control_api_settings.oidc.client_id must be a string",
                                )
                            })?
                            .to_owned(),
                    );
                }
                "admin_group" => {
                    overlay.admin_group = Some(
                        field
                            .as_str()
                            .ok_or_else(|| {
                                ControlApiError::config(
                                    "control_api_settings.oidc.admin_group must be a string",
                                )
                            })?
                            .to_owned(),
                    );
                }
                "groups_claim" => {
                    overlay.groups_claim = Some(
                        field
                            .as_str()
                            .ok_or_else(|| {
                                ControlApiError::config(
                                    "control_api_settings.oidc.groups_claim must be a string",
                                )
                            })?
                            .to_owned(),
                    );
                }
                "token_skew_seconds" => {
                    let secs = field.as_u64().ok_or_else(|| {
                        ControlApiError::config(
                            "control_api_settings.oidc.token_skew_seconds must be 5..=300",
                        )
                    })?;
                    if !(5..=300).contains(&secs) {
                        return Err(ControlApiError::config(
                            "control_api_settings.oidc.token_skew_seconds must be 5..=300",
                        ));
                    }
                    overlay.token_skew = Some(Duration::from_secs(secs));
                }
                other => {
                    return Err(ControlApiError::config(format!(
                        "unknown field `control_api_settings.oidc.{other}`"
                    )));
                }
            }
        }
        Ok(overlay)
    }

    fn apply_to(&self, auth: &mut AuthConfig) {
        if let Some(enabled) = self.enabled {
            auth.oidc_enabled = enabled;
        }
        if let Some(issuer) = &self.issuer {
            auth.oidc_issuer = issuer.clone();
        }
        if let Some(client_id) = &self.client_id {
            auth.oidc_client_id = client_id.clone();
        }
        if let Some(admin_group) = &self.admin_group {
            auth.oidc_admin_group = admin_group.clone();
        }
        if let Some(groups_claim) = &self.groups_claim {
            auth.oidc_groups_claim = groups_claim.clone();
        }
        if let Some(skew) = self.token_skew {
            auth.oidc_token_skew = skew;
        }
    }
}
