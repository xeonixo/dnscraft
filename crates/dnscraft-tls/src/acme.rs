//! ACME directory / account / order wiring (instant-acme + fake).
//!
//! [`AcmeDirectory`] persists the account. [`AcmeOrder`] runs DNS-01 orders:
//! collect challenge TXT values, then after propagation finalize and download
//! the certificate. Production uses [`InstantAcme`]; unit tests use
//! [`FakeAcmeDirectory`].

use std::sync::Mutex;

use async_trait::async_trait;
use instant_acme::{
    Account, AccountCredentials, AuthorizationStatus, ChallengeType, Identifier, NewAccount,
    NewOrder, Order, OrderStatus, RetryPolicy,
};
use rcgen::{
    CertificateParams, DistinguishedName, KeyPair, PKCS_ECDSA_P256_SHA256, PKCS_ECDSA_P384_SHA384,
};
use tracing::{debug, info};

use crate::acme_http::ReqwestHttpClient;
use crate::config::{AcmeConfig, KeyType};
use crate::error::TlsError;
use crate::store::CertStore;

/// One DNS-01 TXT value that must be published before challenges are marked ready.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Dns01Txt {
    /// Owner name, e.g. `_acme-challenge.dns.example.com`.
    pub name: String,
    /// TXT RDATA (base64url SHA-256 of the key authorization).
    pub value: String,
}

/// ACME directory operations used by issuance and renewal.
#[async_trait]
pub trait AcmeDirectory: Send + Sync {
    /// Ensures an ACME account exists: loads `account.json` when present,
    /// otherwise creates one and persists credentials (mode 0600 via the store).
    async fn ensure_account(&self, store: &CertStore, cfg: &AcmeConfig) -> Result<(), TlsError>;
}

/// ACME order operations (DNS-01 collect → finalize → download).
///
/// Call [`Self::start_dns01_order`] first, publish the returned TXT records and
/// wait for propagation, then [`Self::finish_dns01_order`]. On failure call
/// [`Self::abort_order`] so a later attempt starts clean.
#[async_trait]
pub trait AcmeOrder: Send + Sync {
    /// Creates an order for `identifiers` and returns the DNS-01 TXT records
    /// that must be published (typically two values at one name for apex +
    /// wildcard).
    async fn start_dns01_order(
        &self,
        store: &CertStore,
        cfg: &AcmeConfig,
        identifiers: &[String],
    ) -> Result<Vec<Dns01Txt>, TlsError>;

    /// After TXT is visible: set challenges ready, poll, finalize with a fresh
    /// ECDSA key of `key_type`, download the chain. Returns `(chain_pem, key_pem)`.
    async fn finish_dns01_order(&self, key_type: KeyType) -> Result<(Vec<u8>, Vec<u8>), TlsError>;

    /// Drops any in-flight order without finalizing.
    async fn abort_order(&self);
}

/// instant-acme backend.
pub struct InstantAcme {
    http: ReqwestHttpClient,
    pending: Mutex<Option<Order>>,
}

impl InstantAcme {
    /// Production/staging client trusting the public webpki roots.
    pub fn new() -> Result<Self, TlsError> {
        Ok(Self {
            http: ReqwestHttpClient::new()?,
            pending: Mutex::new(None),
        })
    }

    /// Client that trusts an extra PEM root (Pebble / private CA tests).
    pub fn with_extra_roots(root_pem: &[u8]) -> Result<Self, TlsError> {
        Ok(Self {
            http: ReqwestHttpClient::with_extra_roots(root_pem)?,
            pending: Mutex::new(None),
        })
    }

    fn builder(&self) -> instant_acme::AccountBuilder {
        Account::builder_with_http(Box::new(self.http.clone()))
    }

    async fn load_or_create_account(
        &self,
        store: &CertStore,
        cfg: &AcmeConfig,
    ) -> Result<Account, TlsError> {
        let directory_url = cfg.directory.url().to_owned();
        let stored = store.load_account()?;
        if let Some(bytes) = stored
            .as_deref()
            .filter(|b| stored_directory_matches(b, &directory_url))
        {
            let creds: AccountCredentials =
                serde_json::from_slice(bytes).map_err(|e| TlsError::AcmeAccount {
                    message: format!("deserialize account.json: {e}"),
                })?;
            let account = self
                .builder()
                .from_credentials(creds)
                .await
                .map_err(map_acme_account)?;
            debug!(%directory_url, "restored ACME account from store");
            return Ok(account);
        }

        if stored.is_some() {
            info!(%directory_url, "stored ACME account is for another directory; creating a new one");
        }
        let mailto = format!("mailto:{}", cfg.email.trim());
        let new_account = NewAccount {
            contact: &[mailto.as_str()],
            terms_of_service_agreed: true,
            only_return_existing: false,
        };
        let (account, creds) = self
            .builder()
            .create(&new_account, directory_url.clone(), None)
            .await
            .map_err(map_acme_account)?;

        let json = serde_json::to_vec_pretty(&creds).map_err(|e| TlsError::AcmeAccount {
            message: format!("serialize account credentials: {e}"),
        })?;
        store.save_account(&json)?;
        info!(%directory_url, "created and persisted ACME account");
        Ok(account)
    }
}

#[async_trait]
impl AcmeDirectory for InstantAcme {
    async fn ensure_account(&self, store: &CertStore, cfg: &AcmeConfig) -> Result<(), TlsError> {
        if !cfg.enabled {
            return Ok(());
        }
        let _ = self.load_or_create_account(store, cfg).await?;
        Ok(())
    }
}

#[async_trait]
impl AcmeOrder for InstantAcme {
    async fn start_dns01_order(
        &self,
        store: &CertStore,
        cfg: &AcmeConfig,
        identifiers: &[String],
    ) -> Result<Vec<Dns01Txt>, TlsError> {
        let account = self.load_or_create_account(store, cfg).await?;
        let idents: Vec<Identifier> = identifiers
            .iter()
            .map(|s| Identifier::Dns(s.clone()))
            .collect();
        let mut order = account
            .new_order(&NewOrder::new(idents.as_slice()))
            .await
            .map_err(map_acme_order)?;

        let mut txts = Vec::new();
        let mut authorizations = order.authorizations();
        while let Some(result) = authorizations.next().await {
            let mut authz = result.map_err(map_acme_challenge)?;
            match authz.status {
                AuthorizationStatus::Pending => {}
                AuthorizationStatus::Valid => continue,
                other => {
                    return Err(TlsError::AcmeChallenge {
                        message: format!("authorization not pending: {other:?}"),
                    });
                }
            }
            let challenge =
                authz
                    .challenge(ChallengeType::Dns01)
                    .ok_or_else(|| TlsError::AcmeChallenge {
                        message: "no dns-01 challenge on authorization".into(),
                    })?;
            let dns_name = match challenge.identifier().identifier {
                Identifier::Dns(d) => d.clone(),
                other => {
                    return Err(TlsError::AcmeChallenge {
                        message: format!("unsupported identifier {other:?}"),
                    });
                }
            };
            txts.push(Dns01Txt {
                name: format!("_acme-challenge.{dns_name}"),
                value: challenge.key_authorization().dns_value(),
            });
        }

        *self
            .pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(order);
        Ok(txts)
    }

    async fn finish_dns01_order(&self, key_type: KeyType) -> Result<(Vec<u8>, Vec<u8>), TlsError> {
        let mut order = self
            .pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
            .ok_or_else(|| TlsError::AcmeOrder {
                message: "no pending order".into(),
            })?;

        // Mark every DNS-01 challenge ready.
        {
            let mut authorizations = order.authorizations();
            while let Some(result) = authorizations.next().await {
                let mut authz = result.map_err(map_acme_challenge)?;
                if authz.status == AuthorizationStatus::Valid {
                    continue;
                }
                let mut challenge = authz.challenge(ChallengeType::Dns01).ok_or_else(|| {
                    TlsError::AcmeChallenge {
                        message: "no dns-01 challenge to set ready".into(),
                    }
                })?;
                challenge.set_ready().await.map_err(map_acme_challenge)?;
            }
        }

        let status = order
            .poll_ready(&RetryPolicy::default())
            .await
            .map_err(map_acme_challenge)?;
        if status != OrderStatus::Ready {
            return Err(TlsError::AcmeChallenge {
                message: format!("order not ready: {status:?}"),
            });
        }

        let (chain_pem, key_pem) = finalize_with_key_type(&mut order, key_type).await?;
        Ok((chain_pem, key_pem))
    }

    async fn abort_order(&self) {
        *self
            .pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
    }
}

async fn finalize_with_key_type(
    order: &mut Order,
    key_type: KeyType,
) -> Result<(Vec<u8>, Vec<u8>), TlsError> {
    let mut names = Vec::new();
    {
        let mut identifiers = order.identifiers();
        while let Some(result) = identifiers.next().await {
            names.push(result.map_err(map_acme_order)?.to_string());
        }
    }

    let alg = match key_type {
        KeyType::EcdsaP256 => &PKCS_ECDSA_P256_SHA256,
        KeyType::EcdsaP384 => &PKCS_ECDSA_P384_SHA384,
    };
    let private_key = KeyPair::generate_for(alg).map_err(|e| TlsError::AcmeOrder {
        message: format!("generate key: {e}"),
    })?;
    let mut params = CertificateParams::new(names).map_err(|e| TlsError::AcmeOrder {
        message: format!("CSR params: {e}"),
    })?;
    params.distinguished_name = DistinguishedName::new();
    let csr = params
        .serialize_request(&private_key)
        .map_err(|e| TlsError::AcmeOrder {
            message: format!("CSR: {e}"),
        })?;

    order
        .finalize_csr(csr.der())
        .await
        .map_err(map_acme_order)?;
    let chain = order
        .poll_certificate(&RetryPolicy::default())
        .await
        .map_err(map_acme_order)?;
    Ok((chain.into_bytes(), private_key.serialize_pem().into_bytes()))
}

fn map_acme_account(e: instant_acme::Error) -> TlsError {
    TlsError::AcmeAccount {
        message: redact_acme_err(&e),
    }
}

fn map_acme_order(e: instant_acme::Error) -> TlsError {
    if is_rate_limited(&e) {
        return TlsError::AcmeRateLimited {
            message: redact_acme_err(&e),
        };
    }
    TlsError::AcmeOrder {
        message: redact_acme_err(&e),
    }
}

fn map_acme_challenge(e: instant_acme::Error) -> TlsError {
    if is_rate_limited(&e) {
        return TlsError::AcmeRateLimited {
            message: redact_acme_err(&e),
        };
    }
    TlsError::AcmeChallenge {
        message: redact_acme_err(&e),
    }
}

fn is_rate_limited(e: &instant_acme::Error) -> bool {
    match e {
        instant_acme::Error::Api(p) => p
            .r#type
            .as_deref()
            .is_some_and(|t| t.contains("rateLimited")),
        _ => {
            let s = e.to_string();
            s.contains("rateLimited") || s.contains("rate limit")
        }
    }
}

fn redact_acme_err(e: &instant_acme::Error) -> String {
    // Errors must never carry private key material; instant-acme messages are
    // problem documents / status text only.
    e.to_string()
}

/// True when the stored `account.json` was created for `directory_url`.
fn stored_directory_matches(account_json: &[u8], directory_url: &str) -> bool {
    serde_json::from_slice::<serde_json::Value>(account_json)
        .ok()
        .and_then(|v| v.get("directory")?.as_str().map(|d| d == directory_url))
        .unwrap_or(false)
}

/// Where [`FakeAcmeDirectory`] should fail (for negative tests).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum FakeAcmeFail {
    /// Fail when challenges would be marked ready.
    Challenge,
    /// Fail at finalize / certificate mint.
    Finalize,
}

#[doc(hidden)]
#[derive(Debug, Default)]
pub struct FakeAcmeDirectory {
    /// Account id written on creation; empty means `"fake"`.
    pub account_id: String,
    /// Optional injected failure.
    pub fail_at: Option<FakeAcmeFail>,
    pending: Mutex<Option<FakePending>>,
}

#[derive(Debug)]
struct FakePending {
    identifiers: Vec<String>,
    txts: Vec<Dns01Txt>,
}

impl FakeAcmeDirectory {
    /// Builds a fake with optional failure injection.
    pub fn new() -> Self {
        Self::default()
    }

    /// Fake that writes `account_id` into the stand-in `account.json`.
    pub fn with_account_id(account_id: impl Into<String>) -> Self {
        Self {
            account_id: account_id.into(),
            ..Self::default()
        }
    }

    /// Fails at the given step.
    pub fn failing(fail: FakeAcmeFail) -> Self {
        Self {
            fail_at: Some(fail),
            ..Self::default()
        }
    }
}

#[async_trait]
impl AcmeDirectory for FakeAcmeDirectory {
    async fn ensure_account(&self, store: &CertStore, cfg: &AcmeConfig) -> Result<(), TlsError> {
        if !cfg.enabled {
            return Ok(());
        }
        let url = cfg.directory.url();
        if let Some(bytes) = store.load_account()?
            && stored_directory_matches(&bytes, url)
        {
            return Ok(());
        }
        let id = if self.account_id.is_empty() {
            "fake"
        } else {
            self.account_id.as_str()
        };
        let payload = serde_json::to_vec(&serde_json::json!({
            "id": id,
            "directory": url,
            "fake": true,
        }))
        .map_err(|e| TlsError::AcmeAccount {
            message: format!("serialize fake account: {e}"),
        })?;
        store.save_account(&payload)?;
        Ok(())
    }
}

#[async_trait]
impl AcmeOrder for FakeAcmeDirectory {
    async fn start_dns01_order(
        &self,
        store: &CertStore,
        cfg: &AcmeConfig,
        identifiers: &[String],
    ) -> Result<Vec<Dns01Txt>, TlsError> {
        self.ensure_account(store, cfg).await?;
        let mut txts = Vec::new();
        for (i, ident) in identifiers.iter().enumerate() {
            let host = ident.strip_prefix("*.").unwrap_or(ident.as_str());
            txts.push(Dns01Txt {
                name: format!("_acme-challenge.{host}"),
                value: format!("fake-dns01-value-{i}"),
            });
        }
        *self
            .pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(FakePending {
            identifiers: identifiers.to_vec(),
            txts: txts.clone(),
        });
        Ok(txts)
    }

    async fn finish_dns01_order(&self, key_type: KeyType) -> Result<(Vec<u8>, Vec<u8>), TlsError> {
        let pending = self
            .pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
            .ok_or_else(|| TlsError::AcmeOrder {
                message: "no pending fake order".into(),
            })?;

        if self.fail_at == Some(FakeAcmeFail::Challenge) {
            return Err(TlsError::AcmeChallenge {
                message: "fake challenge failure".into(),
            });
        }
        if self.fail_at == Some(FakeAcmeFail::Finalize) {
            return Err(TlsError::AcmeOrder {
                message: "fake finalize failure".into(),
            });
        }

        // Touch pending.txts so the field is considered used (values already published).
        let _ = &pending.txts;

        mint_self_signed(&pending.identifiers, key_type)
    }

    async fn abort_order(&self) {
        *self
            .pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
    }
}

fn mint_self_signed(
    identifiers: &[String],
    key_type: KeyType,
) -> Result<(Vec<u8>, Vec<u8>), TlsError> {
    let alg = match key_type {
        KeyType::EcdsaP384 => &PKCS_ECDSA_P384_SHA384,
        KeyType::EcdsaP256 => &PKCS_ECDSA_P256_SHA256,
    };
    let key = KeyPair::generate_for(alg).map_err(|e| TlsError::AcmeOrder {
        message: format!("fake keygen: {e}"),
    })?;
    let mut params =
        CertificateParams::new(identifiers.to_vec()).map_err(|e| TlsError::AcmeOrder {
            message: format!("fake cert params: {e}"),
        })?;
    params.distinguished_name = DistinguishedName::new();
    let cert = params.self_signed(&key).map_err(|e| TlsError::AcmeOrder {
        message: format!("fake self-sign: {e}"),
    })?;
    Ok((cert.pem().into_bytes(), key.serialize_pem().into_bytes()))
}

/// Builds the default identifier set for `public_domain`.
pub fn default_identifiers(public_domain: &str) -> [String; 2] {
    [
        format!("dns.{public_domain}"),
        format!("*.dns.{public_domain}"),
    ]
}

/// Challenge TXT owner for an ACME DNS identifier (`dns.x` or `*.dns.x`).
pub fn challenge_txt_name(identifier: &str) -> String {
    let host = identifier.strip_prefix("*.").unwrap_or(identifier);
    format!("_acme-challenge.{host}")
}
