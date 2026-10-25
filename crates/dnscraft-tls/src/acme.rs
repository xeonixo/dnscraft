//! ACME directory / account wiring (instant-acme, account create & load).
//!
//! Order / challenge / finalize land in L7 behind [`AcmeOrder`]. This module
//! only proves account persistence and the reqwest [`HttpClient`] adapter.

use async_trait::async_trait;
use instant_acme::{Account, AccountCredentials, NewAccount};
use tracing::{debug, info};

use crate::acme_http::ReqwestHttpClient;
use crate::config::AcmeConfig;
use crate::error::TlsError;
use crate::store::CertStore;

/// ACME directory operations used by issuance and renewal.
///
/// Production uses [`InstantAcme`]. Unit tests use a fake that never talks to
/// a real CA.
#[async_trait]
pub trait AcmeDirectory: Send + Sync {
    /// Ensures an ACME account exists: loads `account.json` when present,
    /// otherwise creates one and persists credentials (mode 0600 via the store).
    async fn ensure_account(&self, store: &CertStore, cfg: &AcmeConfig) -> Result<(), TlsError>;
}

/// ACME order operations (DNS-01, finalize, download). Filled in by L7.
///
/// Defined here so the issuance flow can take `&dyn AcmeOrder` without a later
/// trait split.
#[async_trait]
pub trait AcmeOrder: Send + Sync {
    /// Placeholder so the trait is object-safe and ready for L7 methods.
    async fn ready_for_orders(&self) -> Result<(), TlsError> {
        Ok(())
    }
}

/// instant-acme backend: account create/load only (L4 spike).
pub struct InstantAcme {
    http: ReqwestHttpClient,
}

impl InstantAcme {
    /// Production/staging client trusting the public webpki roots.
    pub fn new() -> Result<Self, TlsError> {
        Ok(Self {
            http: ReqwestHttpClient::new()?,
        })
    }

    /// Client that trusts an extra PEM root (Pebble / private CA tests).
    pub fn with_extra_roots(root_pem: &[u8]) -> Result<Self, TlsError> {
        Ok(Self {
            http: ReqwestHttpClient::with_extra_roots(root_pem)?,
        })
    }

    fn builder(&self) -> instant_acme::AccountBuilder {
        Account::builder_with_http(Box::new(self.http.clone()))
    }
}

#[async_trait]
impl AcmeDirectory for InstantAcme {
    async fn ensure_account(&self, store: &CertStore, cfg: &AcmeConfig) -> Result<(), TlsError> {
        if !cfg.enabled {
            return Ok(());
        }
        let directory_url = cfg.directory.url().to_owned();

        if let Some(bytes) = store.load_account()? {
            let creds: AccountCredentials =
                serde_json::from_slice(&bytes).map_err(|e| TlsError::AcmeAccount {
                    message: format!("deserialize account.json: {e}"),
                })?;
            self.builder()
                .from_credentials(creds)
                .await
                .map_err(|e| TlsError::AcmeAccount {
                    message: format!("load ACME account: {e}"),
                })?;
            debug!(%directory_url, "restored ACME account from store");
            return Ok(());
        }

        let mailto = format!("mailto:{}", cfg.email.trim());
        let new_account = NewAccount {
            contact: &[mailto.as_str()],
            terms_of_service_agreed: true,
            only_return_existing: false,
        };
        let (_account, creds) = self
            .builder()
            .create(&new_account, directory_url.clone(), None)
            .await
            .map_err(|e| TlsError::AcmeAccount {
                message: format!("create ACME account: {e}"),
            })?;

        let json = serde_json::to_vec_pretty(&creds).map_err(|e| TlsError::AcmeAccount {
            message: format!("serialize account credentials: {e}"),
        })?;
        store.save_account(&json)?;
        info!(%directory_url, "created and persisted ACME account");
        Ok(())
    }
}

#[async_trait]
impl AcmeOrder for InstantAcme {}

/// Test helper ACME directory that never contacts a CA.
///
/// Persists a stand-in JSON blob so account file modes and reload can be tested
/// without Pebble or Let's Encrypt.
#[derive(Debug, Default)]
pub struct FakeAcmeDirectory {
    /// Payload written on first [`AcmeDirectory::ensure_account`].
    pub create_payload: Vec<u8>,
}

#[async_trait]
impl AcmeDirectory for FakeAcmeDirectory {
    async fn ensure_account(&self, store: &CertStore, cfg: &AcmeConfig) -> Result<(), TlsError> {
        if !cfg.enabled {
            return Ok(());
        }
        if store.load_account()?.is_some() {
            return Ok(());
        }
        let payload = if self.create_payload.is_empty() {
            br#"{"id":"fake","fake":true}"#.to_vec()
        } else {
            self.create_payload.clone()
        };
        store.save_account(&payload)?;
        Ok(())
    }
}

#[async_trait]
impl AcmeOrder for FakeAcmeDirectory {}
