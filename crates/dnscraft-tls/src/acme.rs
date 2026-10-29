//! ACME directory / account / order wiring (instant-acme + fake).
//!
//! [`AcmeDirectory`] persists the account. [`AcmeOrder`] runs DNS-01 orders:
//! collect challenge TXT values, then after propagation finalize and download
//! the certificate. Production uses [`InstantAcme`]; unit tests use
//! [`FakeAcmeDirectory`].

use std::borrow::Cow;
use std::sync::Mutex;
use std::time::SystemTime;

use async_trait::async_trait;
use instant_acme::{
    Account, AccountCredentials, AuthorizationStatus, CertificateIdentifier, ChallengeType,
    ExternalAccountKey, Identifier, NewAccount, NewOrder, Order, OrderStatus, RetryPolicy,
    RevocationReason as AcmeRevocationReason, RevocationRequest,
};
use rcgen::{
    CertificateParams, CertificateSigningRequestParams, DistinguishedName, Issuer, KeyPair,
    PKCS_ECDSA_P256_SHA256, PKCS_ECDSA_P384_SHA384, SanType,
};
use rustls_pki_types::CertificateSigningRequestDer;
use tracing::{debug, info, warn};

use crate::acme_http::ReqwestHttpClient;
use crate::config::{AcmeConfig, KeyType};
use crate::error::TlsError;
use crate::pem_util::parse_cert_chain;
use crate::renew::{AriWindow, backoff_delay};
use crate::store::CertStore;

/// One DNS-01 TXT value that must be published before challenges are marked ready.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Dns01Txt {
    /// Owner name, e.g. `_acme-challenge.dns.example.com`.
    pub name: String,
    /// TXT RDATA (base64url SHA-256 of the key authorization).
    pub value: String,
}

/// One DNS-01 challenge's progress.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChallengeProgress {
    /// ACME identifier (`dns.x` / `*.dns.x`).
    pub identifier: String,
    /// TXT owner name (`_acme-challenge.…`).
    pub txt_name: String,
    /// Challenge state (`pending` / `valid` / `invalid`).
    pub status: String,
}

/// Order/progress snapshot exposed by [`AcmeOrder::order_status`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AcmeOrderStatus {
    /// `idle` / `pending` / `valid` / `invalid`.
    pub state: String,
    /// Ordered identifiers.
    pub identifiers: Vec<String>,
    /// Per-challenge progress.
    pub challenges: Vec<ChallengeProgress>,
    /// Scheduled next attempt, when a backoff is active.
    pub next_attempt_at: Option<SystemTime>,
    /// Last stable error code for this order.
    pub last_error: Option<String>,
}

impl Default for AcmeOrderStatus {
    fn default() -> Self {
        Self {
            state: "idle".into(),
            identifiers: Vec::new(),
            challenges: Vec::new(),
            next_attempt_at: None,
            last_error: None,
        }
    }
}

/// ACME account state exposed by [`crate::TlsEngine::acme_account_status`].
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AcmeAccountStatus {
    /// `true` when a usable `account.json` exists for the configured directory.
    pub exists: bool,
    /// Configured directory URL.
    pub directory: String,
    /// Account id, when known.
    pub account_id: Option<String>,
    /// Config agreed to the CA terms of service.
    pub tos_agreed: bool,
    /// Config supplied an External Account Binding key.
    pub eab_configured: bool,
    /// Config deactivates the account when ACME is disabled.
    pub auto_deactivate: bool,
    /// `true` when the account was deactivated (credentials removed).
    pub deactivated: bool,
}

/// Certificate revocation reason (RFC 5280 §5.3.1).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum RevocationReason {
    /// No reason given.
    #[default]
    Unspecified,
    /// Private key compromised.
    KeyCompromise,
    /// CA compromised.
    CaCompromise,
    /// Affiliation changed.
    AffiliationChanged,
    /// Certificate superseded.
    Superseded,
    /// Cessation of operation.
    CessationOfOperation,
    /// Certificate on hold.
    CertificateHold,
    /// Remove from CRL.
    RemoveFromCrl,
    /// Privilege withdrawn.
    PrivilegeWithdrawn,
    /// Attribute authority compromised.
    AaCompromise,
}

impl RevocationReason {
    /// Parses a locale-neutral reason string (`key_compromise`, `superseded`, …).
    pub fn parse(input: &str) -> Result<Self, TlsError> {
        let key: String = input
            .chars()
            .filter(|c| c.is_ascii_alphanumeric())
            .map(|c| c.to_ascii_lowercase())
            .collect();
        Ok(match key.as_str() {
            "" | "unspecified" => Self::Unspecified,
            "keycompromise" => Self::KeyCompromise,
            "cacompromise" => Self::CaCompromise,
            "affiliationchanged" => Self::AffiliationChanged,
            "superseded" => Self::Superseded,
            "cessationofoperation" => Self::CessationOfOperation,
            "certificatehold" => Self::CertificateHold,
            "removefromcrl" => Self::RemoveFromCrl,
            "privilegewithdrawn" => Self::PrivilegeWithdrawn,
            "aacompromise" => Self::AaCompromise,
            _ => {
                return Err(TlsError::ConfigInvalid {
                    reason: format!("unknown revocation reason {input:?}"),
                });
            }
        })
    }

    fn to_acme(self) -> AcmeRevocationReason {
        match self {
            Self::Unspecified => AcmeRevocationReason::Unspecified,
            Self::KeyCompromise => AcmeRevocationReason::KeyCompromise,
            Self::CaCompromise => AcmeRevocationReason::CaCompromise,
            Self::AffiliationChanged => AcmeRevocationReason::AffiliationChanged,
            Self::Superseded => AcmeRevocationReason::Superseded,
            Self::CessationOfOperation => AcmeRevocationReason::CessationOfOperation,
            Self::CertificateHold => AcmeRevocationReason::CertificateHold,
            Self::RemoveFromCrl => AcmeRevocationReason::RemoveFromCrl,
            Self::PrivilegeWithdrawn => AcmeRevocationReason::PrivilegeWithdrawn,
            Self::AaCompromise => AcmeRevocationReason::AaCompromise,
        }
    }
}

/// ACME directory operations used by issuance and renewal.
#[async_trait]
pub trait AcmeDirectory: Send + Sync {
    /// Ensures an ACME account exists: loads `account.json` when present,
    /// otherwise creates one and persists credentials (mode 0600 via the store).
    async fn ensure_account(&self, store: &CertStore, cfg: &AcmeConfig) -> Result<(), TlsError>;

    /// Rolls the ACME account key and persists the new credentials.
    async fn rollover_key(&self, _store: &CertStore, _cfg: &AcmeConfig) -> Result<(), TlsError> {
        Err(TlsError::AcmeAccountRollover {
            message: "account key rollover is not supported by this backend".into(),
        })
    }

    /// Deactivates the ACME account and removes `account.json`.
    async fn deactivate_account(
        &self,
        _store: &CertStore,
        _cfg: &AcmeConfig,
    ) -> Result<(), TlsError> {
        Err(TlsError::AcmeAccount {
            message: "account deactivation is not supported by this backend".into(),
        })
    }
}

/// Combined ACME backend for [`crate::TlsEngine`] (object-safe).
pub trait AcmeBackend: AcmeDirectory + AcmeOrder {}

impl<T: AcmeDirectory + AcmeOrder> AcmeBackend for T {}

/// ACME order operations (DNS-01 collect → finalize → download).
///
/// Also exposes ACME Renewal Information (ARI, RFC 9773): [`Self::certificate_id`]
/// computes the id stored in `meta.json` and passed as `replaces` on the next
/// order; [`Self::renewal_window`] fetches the CA's suggested window.
///
/// Call [`Self::start_dns01_order`] first, publish the returned TXT records and
/// wait for propagation, then [`Self::finish_dns01_order`]. On failure call
/// [`Self::abort_order`] so a later attempt starts clean.
#[async_trait]
pub trait AcmeOrder: Send + Sync {
    /// Creates an order for `identifiers` and returns the DNS-01 TXT records
    /// that must be published (typically two values at one name for apex +
    /// wildcard).
    ///
    /// `replaces` is the ARI certificate id (`<aki>.<serial>`, as returned by
    /// [`Self::certificate_id`]) of the certificate this order renews.
    async fn start_dns01_order(
        &self,
        store: &CertStore,
        cfg: &AcmeConfig,
        identifiers: &[String],
        replaces: Option<&str>,
    ) -> Result<Vec<Dns01Txt>, TlsError>;

    /// After TXT is visible: set challenges ready, poll, finalize with a fresh
    /// ECDSA key of `key_type`, download the chain. Returns `(chain_pem, key_pem)`.
    async fn finish_dns01_order(&self, key_type: KeyType) -> Result<(Vec<u8>, Vec<u8>), TlsError>;

    /// Like [`Self::finish_dns01_order`], but finalizes with the caller's
    /// DER-encoded CSR. The private key never reaches this crate; returns the
    /// chain PEM.
    async fn finish_dns01_order_csr(&self, _csr_der: &[u8]) -> Result<Vec<u8>, TlsError> {
        Err(TlsError::AcmeOrder {
            message: "CSR finalization is not supported by this backend".into(),
        })
    }

    /// Drops any in-flight order without finalizing.
    async fn abort_order(&self);

    /// ARI certificate id of the leaf in `chain_pem`, or `None` when it cannot
    /// be derived (e.g. no Authority Key Identifier).
    fn certificate_id(&self, chain_pem: &[u8]) -> Option<String> {
        ari_certificate_id(chain_pem)
    }

    /// The CA's suggested renewal window for the leaf in `chain_pem`.
    ///
    /// Returns `None` when the CA has no `renewalInfo`, the id cannot be
    /// derived, or the request fails. ARI is advisory: implementations log at
    /// debug/warn and never turn a failure into an error.
    async fn renewal_window(
        &self,
        store: &CertStore,
        cfg: &AcmeConfig,
        chain_pem: &[u8],
    ) -> Option<AriWindow>;

    /// Snapshot of the most recent order's progress.
    fn order_status(&self) -> AcmeOrderStatus {
        AcmeOrderStatus::default()
    }

    /// Revokes the leaf in `chain_pem` at the CA.
    async fn revoke_certificate(
        &self,
        _store: &CertStore,
        _cfg: &AcmeConfig,
        _chain_pem: &[u8],
        _reason: RevocationReason,
    ) -> Result<(), TlsError> {
        Err(TlsError::AcmeOrder {
            message: "certificate revocation is not supported by this backend".into(),
        })
    }
}

/// ARI certificate id (`<base64url aki>.<base64url serial>`) of the first
/// certificate in `chain_pem`.
pub fn ari_certificate_id(chain_pem: &[u8]) -> Option<String> {
    let certs = parse_cert_chain(chain_pem).ok()?;
    CertificateIdentifier::try_from(&certs[0])
        .ok()
        .map(|id| id.to_string())
}

/// Splits a stored `<aki>.<serial>` id back into a [`CertificateIdentifier`].
fn parse_ari_id(id: &str) -> Option<CertificateIdentifier<'static>> {
    let (aki, serial) = id.split_once('.')?;
    if serial.contains('.') || aki.is_empty() || serial.is_empty() {
        return None;
    }
    Some(CertificateIdentifier {
        authority_key_identifier: Cow::Owned(aki.to_owned()),
        serial: Cow::Owned(serial.to_owned()),
    })
}

/// instant-acme backend.
pub struct InstantAcme {
    http: ReqwestHttpClient,
    pending: Mutex<Option<Order>>,
    progress: Mutex<AcmeOrderStatus>,
}

impl InstantAcme {
    /// Production/staging client trusting the public webpki roots.
    pub fn new() -> Result<Self, TlsError> {
        Ok(Self {
            http: ReqwestHttpClient::new()?,
            pending: Mutex::new(None),
            progress: Mutex::new(AcmeOrderStatus::default()),
        })
    }

    /// Client that trusts an extra PEM root (Pebble / private CA tests).
    pub fn with_extra_roots(root_pem: &[u8]) -> Result<Self, TlsError> {
        Ok(Self {
            http: ReqwestHttpClient::with_extra_roots(root_pem)?,
            pending: Mutex::new(None),
            progress: Mutex::new(AcmeOrderStatus::default()),
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
        if !cfg.account.tos_agreed {
            return Err(TlsError::AcmeAccountTos {
                message: "acme.account.tos_agreed must be true to create an account".into(),
            });
        }
        let mailto = format!("mailto:{}", cfg.email.trim());
        let new_account = NewAccount {
            contact: &[mailto.as_str()],
            terms_of_service_agreed: cfg.account.tos_agreed,
            only_return_existing: false,
        };
        let eab = cfg
            .account
            .eab
            .as_ref()
            .map(|e| ExternalAccountKey::new(e.kid.clone(), e.hmac_key.expose().as_bytes()));
        let (account, creds) = self
            .builder()
            .create(&new_account, directory_url.clone(), eab.as_ref())
            .await
            .map_err(|e| match &eab {
                Some(_) => TlsError::AcmeAccountEab {
                    message: e.to_string(),
                },
                None => map_acme_account(e),
            })?;

        save_account_credentials(store, &creds)?;
        info!(%directory_url, "created and persisted ACME account");
        Ok(account)
    }
}

fn save_account_credentials(store: &CertStore, creds: &AccountCredentials) -> Result<(), TlsError> {
    let json = serde_json::to_vec_pretty(creds).map_err(|e| TlsError::AcmeAccount {
        message: format!("serialize account credentials: {e}"),
    })?;
    store.save_account(&json)
}

/// Persists that the account was deactivated (credentials removed).
fn mark_account_deactivated(store: &CertStore) -> Result<(), TlsError> {
    let mut state = store.load_state();
    state.acme_account_deactivated = true;
    store.save_state(&state)
}

/// Clears the deactivated marker after an account exists again.
fn mark_account_active(store: &CertStore) -> Result<(), TlsError> {
    let mut state = store.load_state();
    if state.acme_account_deactivated {
        state.acme_account_deactivated = false;
        store.save_state(&state)?;
    }
    Ok(())
}

impl InstantAcme {
    /// Creates the order and collects its DNS-01 TXT values (no progress writes).
    async fn start_dns01_order_inner(
        &self,
        store: &CertStore,
        cfg: &AcmeConfig,
        identifiers: &[String],
        replaces: Option<&str>,
    ) -> Result<Vec<Dns01Txt>, TlsError> {
        let account = self.load_or_create_account(store, cfg).await?;
        let idents: Vec<Identifier> = identifiers
            .iter()
            .map(|s| Identifier::Dns(s.clone()))
            .collect();
        let mut new_order = NewOrder::new(idents.as_slice());
        if let Some(id) = replaces {
            match parse_ari_id(id) {
                Some(cert_id) => new_order = new_order.replaces(cert_id),
                None => warn!("stored ARI certificate id is malformed; ordering without replaces"),
            }
        }
        let mut order = account
            .new_order(&new_order)
            .await
            .map_err(|e| map_acme_order(e, self.http.take_last_retry_after()))?;

        let mut txts = Vec::new();
        let mut authorizations = order.authorizations();
        while let Some(result) = authorizations.next().await {
            let mut authz =
                result.map_err(|e| map_acme_challenge(e, self.http.take_last_retry_after()))?;
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
}

#[async_trait]
impl AcmeDirectory for InstantAcme {
    async fn ensure_account(&self, store: &CertStore, cfg: &AcmeConfig) -> Result<(), TlsError> {
        if !cfg.enabled {
            return Ok(());
        }
        let _ = self.load_or_create_account(store, cfg).await?;
        mark_account_active(store)?;
        Ok(())
    }

    async fn rollover_key(&self, store: &CertStore, cfg: &AcmeConfig) -> Result<(), TlsError> {
        let mut account = self.load_or_create_account(store, cfg).await?;
        let creds = account
            .update_key()
            .await
            .map_err(|e| TlsError::AcmeAccountRollover {
                message: e.to_string(),
            })?;
        save_account_credentials(store, &creds)
    }

    async fn deactivate_account(
        &self,
        store: &CertStore,
        cfg: &AcmeConfig,
    ) -> Result<(), TlsError> {
        let account = self.load_or_create_account(store, cfg).await?;
        account
            .deactivate()
            .await
            .map_err(|e| TlsError::AcmeAccount {
                message: e.to_string(),
            })?;
        store.clear_account()?;
        mark_account_deactivated(store)
    }
}

#[async_trait]
impl AcmeOrder for InstantAcme {
    async fn start_dns01_order(
        &self,
        store: &CertStore,
        cfg: &AcmeConfig,
        identifiers: &[String],
        replaces: Option<&str>,
    ) -> Result<Vec<Dns01Txt>, TlsError> {
        match self
            .start_dns01_order_inner(store, cfg, identifiers, replaces)
            .await
        {
            Ok(txts) => {
                *self
                    .progress
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) = AcmeOrderStatus {
                    state: "pending".into(),
                    identifiers: identifiers.to_vec(),
                    challenges: txts
                        .iter()
                        .map(|t| ChallengeProgress {
                            identifier: t
                                .name
                                .strip_prefix("_acme-challenge.")
                                .unwrap_or(&t.name)
                                .to_owned(),
                            txt_name: t.name.clone(),
                            status: "pending".into(),
                        })
                        .collect(),
                    next_attempt_at: None,
                    last_error: None,
                };
                Ok(txts)
            }
            Err(e) => {
                // Early failures must not leave the previous order's progress
                // visible through `order_status`.
                let mut progress = self
                    .progress
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                progress.identifiers = identifiers.to_vec();
                progress.challenges.clear();
                mark_failed(&mut progress, &e);
                Err(e)
            }
        }
    }

    async fn finish_dns01_order(&self, key_type: KeyType) -> Result<(Vec<u8>, Vec<u8>), TlsError> {
        self.finish_pending(key_type, None).await
    }

    async fn finish_dns01_order_csr(&self, csr_der: &[u8]) -> Result<Vec<u8>, TlsError> {
        self.finish_pending(KeyType::EcdsaP256, Some(csr_der))
            .await
            .map(|(chain, _key)| chain)
    }

    fn order_status(&self) -> AcmeOrderStatus {
        self.progress
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    async fn revoke_certificate(
        &self,
        store: &CertStore,
        cfg: &AcmeConfig,
        chain_pem: &[u8],
        reason: RevocationReason,
    ) -> Result<(), TlsError> {
        let certs = parse_cert_chain(chain_pem).map_err(|message| TlsError::AcmeOrder {
            message: format!("revocation: {message}"),
        })?;
        let account = self.load_or_create_account(store, cfg).await?;
        let request = RevocationRequest {
            certificate: &certs[0],
            reason: Some(reason.to_acme()),
        };
        account
            .revoke(&request)
            .await
            .map_err(|e| TlsError::AcmeOrder {
                message: format!("revocation: {e}"),
            })
    }
    async fn abort_order(&self) {
        *self
            .pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
        let mut progress = self
            .progress
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if progress.state == "pending" {
            progress.state = "invalid".into();
        }
    }

    async fn renewal_window(
        &self,
        store: &CertStore,
        cfg: &AcmeConfig,
        chain_pem: &[u8],
    ) -> Option<AriWindow> {
        let id = self
            .certificate_id(chain_pem)
            .and_then(|s| parse_ari_id(&s))?;
        let account = match self.load_or_create_account(store, cfg).await {
            Ok(a) => a,
            Err(e) => {
                warn!(code = e.code(), "ARI skipped: no ACME account: {e}");
                return None;
            }
        };
        match account.renewal_info(&id).await {
            Ok((info, _retry_after)) => Some(AriWindow {
                start: info.suggested_window.start.into(),
                end: info.suggested_window.end.into(),
            }),
            Err(e) => {
                debug!("ARI unavailable: {e}");
                None
            }
        }
    }
}

impl InstantAcme {
    /// Marks the pending order's challenges ready, then finalizes it with a
    /// generated key (`csr_der == None`, returns `(chain, key)`) or with the
    /// caller's CSR (returns `(chain, empty)`). Updates order progress.
    async fn finish_pending(
        &self,
        key_type: KeyType,
        csr_der: Option<&[u8]>,
    ) -> Result<(Vec<u8>, Vec<u8>), TlsError> {
        let result = async {
            let mut order = self
                .pending
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take()
                .ok_or_else(|| TlsError::AcmeOrderPending {
                    message: "no pending order".into(),
                })?;

            // Mark every DNS-01 challenge ready.
            {
                let mut authorizations = order.authorizations();
                while let Some(result) = authorizations.next().await {
                    let mut authz = result
                        .map_err(|e| map_acme_challenge(e, self.http.take_last_retry_after()))?;
                    if authz.status == AuthorizationStatus::Valid {
                        continue;
                    }
                    let mut challenge = authz.challenge(ChallengeType::Dns01).ok_or_else(|| {
                        TlsError::AcmeChallenge {
                            message: "no dns-01 challenge to set ready".into(),
                        }
                    })?;
                    challenge
                        .set_ready()
                        .await
                        .map_err(|e| map_acme_challenge(e, self.http.take_last_retry_after()))?;
                }
            }

            let status = order
                .poll_ready(&RetryPolicy::default())
                .await
                .map_err(|e| map_acme_challenge(e, self.http.take_last_retry_after()))?;
            if status != OrderStatus::Ready {
                return Err(TlsError::AcmeChallenge {
                    message: format!("order not ready: {status:?}"),
                });
            }

            finalize(&mut order, key_type, csr_der, &self.http).await
        }
        .await;
        {
            let mut progress = self
                .progress
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            match &result {
                Ok(_) => {
                    progress.state = "valid".into();
                    progress.next_attempt_at = None;
                    progress.last_error = None;
                    for challenge in &mut progress.challenges {
                        challenge.status = "valid".into();
                    }
                }
                Err(e) => mark_failed(&mut progress, e),
            }
        }
        result
    }
}

/// DNS names (lowercase) a PKCS #10 request asks for. Rejects a request whose
/// signature does not verify (proof of possession), a non-DNS SAN, or none.
pub(crate) fn csr_dns_names(csr_der: &[u8]) -> Result<Vec<String>, TlsError> {
    let der = CertificateSigningRequestDer::from(csr_der);
    let csr = CertificateSigningRequestParams::from_der(&der).map_err(|e| TlsError::AcmeOrder {
        message: format!("CSR: {e}"),
    })?;
    let mut names: Vec<String> = Vec::new();
    for san in &csr.params.subject_alt_names {
        let SanType::DnsName(name) = san else {
            return Err(TlsError::AcmeOrder {
                message: "CSR may request DNS names only".into(),
            });
        };
        let name = name.to_string().to_ascii_lowercase();
        if !names.contains(&name) {
            names.push(name);
        }
    }
    if names.is_empty() {
        return Err(TlsError::AcmeOrder {
            message: "CSR requests no DNS name".into(),
        });
    }
    Ok(names)
}

/// Finalizes `order` with the caller's CSR when given (empty key returned), or
/// with a fresh key of `key_type`. Returns `(chain_pem, key_pem)`.
async fn finalize(
    order: &mut Order,
    key_type: KeyType,
    csr_der: Option<&[u8]>,
    http: &ReqwestHttpClient,
) -> Result<(Vec<u8>, Vec<u8>), TlsError> {
    let mut names = Vec::new();
    {
        let mut identifiers = order.identifiers();
        while let Some(result) = identifiers.next().await {
            names.push(
                result
                    .map_err(|e| map_acme_order(e, http.take_last_retry_after()))?
                    .to_string(),
            );
        }
    }

    if let Some(der) = csr_der {
        order
            .finalize_csr(der)
            .await
            .map_err(|e| map_acme_order(e, http.take_last_retry_after()))?;
        let chain = order
            .poll_certificate(&RetryPolicy::default())
            .await
            .map_err(|e| map_acme_order(e, http.take_last_retry_after()))?;
        return Ok((chain.into_bytes(), Vec::new()));
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
        .map_err(|e| map_acme_order(e, http.take_last_retry_after()))?;
    let chain = order
        .poll_certificate(&RetryPolicy::default())
        .await
        .map_err(|e| map_acme_order(e, http.take_last_retry_after()))?;
    Ok((chain.into_bytes(), private_key.serialize_pem().into_bytes()))
}

fn map_acme_account(e: instant_acme::Error) -> TlsError {
    TlsError::AcmeAccount {
        message: e.to_string(),
    }
}

fn map_acme_order(e: instant_acme::Error, retry_after: Option<std::time::Duration>) -> TlsError {
    if is_rate_limited(&e) {
        return TlsError::AcmeRateLimited {
            message: e.to_string(),
            retry_after,
        };
    }
    TlsError::AcmeOrder {
        message: e.to_string(),
    }
}

fn map_acme_challenge(
    e: instant_acme::Error,
    retry_after: Option<std::time::Duration>,
) -> TlsError {
    if is_rate_limited(&e) {
        return TlsError::AcmeRateLimited {
            message: e.to_string(),
            retry_after,
        };
    }
    TlsError::AcmeChallenge {
        message: e.to_string(),
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

/// True when the stored `account.json` was created for `directory_url`.
fn stored_directory_matches(account_json: &[u8], directory_url: &str) -> bool {
    serde_json::from_slice::<serde_json::Value>(account_json)
        .ok()
        .and_then(|v| v.get("directory")?.as_str().map(|d| d == directory_url))
        .unwrap_or(false)
}

/// Reads ACME account state from `account.json` and `cfg.account`.
///
/// Never returns the account key. A stored account for another directory is
/// reported as absent (a new account will be created on the next issuance).
pub fn account_status(store: &CertStore, cfg: &AcmeConfig) -> Result<AcmeAccountStatus, TlsError> {
    let directory = cfg.directory.url().to_owned();
    let stored = store.load_account()?;
    let account_id = stored
        .as_deref()
        .filter(|bytes| stored_directory_matches(bytes, &directory))
        .and_then(|bytes| {
            serde_json::from_slice::<serde_json::Value>(bytes)
                .ok()?
                .get("id")?
                .as_str()
                .map(str::to_owned)
        });
    Ok(AcmeAccountStatus {
        exists: account_id.is_some(),
        directory,
        account_id,
        tos_agreed: cfg.account.tos_agreed,
        eab_configured: cfg.account.eab.is_some(),
        auto_deactivate: cfg.account.auto_deactivate,
        // Credentials are removed on deactivation; the marker survives so the
        // status can distinguish "deactivated" from "never created".
        deactivated: stored.is_none() && store.load_state().acme_account_deactivated,
    })
}

/// Marks `progress` invalid and schedules the next attempt from the renew
/// backoff (honouring a CA `Retry-After` hint).
fn mark_failed(progress: &mut AcmeOrderStatus, err: &TlsError) {
    progress.state = "invalid".into();
    progress.last_error = Some(err.code().to_owned());
    progress.next_attempt_at = Some(SystemTime::now() + backoff_delay(0, err.retry_after()));
}

/// Where [`FakeAcmeDirectory`] should fail (for negative tests).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]

pub enum FakeAcmeFail {
    /// Fail while creating the order (before any challenge TXT is returned).
    Start,
    /// Reject an order that carries `replaces` with `alreadyReplaced` (ARI).
    AlreadyReplaced,
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
    /// ARI window returned by [`AcmeOrder::renewal_window`]; `None` = CA without ARI.
    pub ari_window: Option<AriWindow>,
    pending: Mutex<Option<FakePending>>,
    replaces_log: Mutex<Vec<Option<String>>>,
    progress: Mutex<AcmeOrderStatus>,
    revocation_log: Mutex<Vec<RevocationReason>>,
}

#[derive(Debug)]
struct FakePending {
    identifiers: Vec<String>,
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

    /// Fake whose CA advertises `window` as the ARI suggested renewal window.
    pub fn with_ari_window(window: AriWindow) -> Self {
        Self {
            ari_window: Some(window),
            ..Self::default()
        }
    }

    /// The `replaces` argument of every `start_dns01_order` call so far, in order.
    pub fn replaces_log(&self) -> Vec<Option<String>> {
        self.replaces_log
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// Revocation reasons accepted by this fake, in order.
    pub fn revocation_log(&self) -> Vec<RevocationReason> {
        self.revocation_log
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }
}

impl FakeAcmeDirectory {
    /// Fake order creation (no progress writes).
    async fn start_dns01_order_inner(
        &self,
        store: &CertStore,
        cfg: &AcmeConfig,
        identifiers: &[String],
        replaces: Option<&str>,
    ) -> Result<Vec<Dns01Txt>, TlsError> {
        self.ensure_account(store, cfg).await?;
        if self.fail_at == Some(FakeAcmeFail::Start) {
            return Err(TlsError::AcmeOrder {
                message: "fake start failure".into(),
            });
        }
        self.replaces_log
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(replaces.map(str::to_owned));
        if self.fail_at == Some(FakeAcmeFail::AlreadyReplaced) && replaces.is_some() {
            return Err(TlsError::AcmeOrder {
                message: "urn:ietf:params:acme:error:alreadyReplaced".into(),
            });
        }
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
        });
        Ok(txts)
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
            mark_account_active(store)?;
            return Ok(());
        }
        if !cfg.account.tos_agreed {
            return Err(TlsError::AcmeAccountTos {
                message: "acme.account.tos_agreed must be true".into(),
            });
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
        mark_account_active(store)?;
        Ok(())
    }

    async fn rollover_key(&self, store: &CertStore, cfg: &AcmeConfig) -> Result<(), TlsError> {
        self.ensure_account(store, cfg).await
    }

    async fn deactivate_account(
        &self,
        store: &CertStore,
        _cfg: &AcmeConfig,
    ) -> Result<(), TlsError> {
        store.clear_account()?;
        mark_account_deactivated(store)
    }
}

#[async_trait]
impl AcmeOrder for FakeAcmeDirectory {
    async fn start_dns01_order(
        &self,
        store: &CertStore,
        cfg: &AcmeConfig,
        identifiers: &[String],
        replaces: Option<&str>,
    ) -> Result<Vec<Dns01Txt>, TlsError> {
        match self
            .start_dns01_order_inner(store, cfg, identifiers, replaces)
            .await
        {
            Ok(txts) => {
                *self
                    .progress
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) = AcmeOrderStatus {
                    state: "pending".into(),
                    identifiers: identifiers.to_vec(),
                    challenges: txts
                        .iter()
                        .map(|t| ChallengeProgress {
                            identifier: t
                                .name
                                .strip_prefix("_acme-challenge.")
                                .unwrap_or(&t.name)
                                .to_owned(),
                            txt_name: t.name.clone(),
                            status: "pending".into(),
                        })
                        .collect(),
                    next_attempt_at: None,
                    last_error: None,
                };
                Ok(txts)
            }
            Err(e) => {
                let mut progress = self
                    .progress
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                progress.identifiers = identifiers.to_vec();
                progress.challenges.clear();
                mark_failed(&mut progress, &e);
                Err(e)
            }
        }
    }

    async fn finish_dns01_order(&self, key_type: KeyType) -> Result<(Vec<u8>, Vec<u8>), TlsError> {
        self.finish_fake(key_type, None).await
    }

    async fn finish_dns01_order_csr(&self, csr_der: &[u8]) -> Result<Vec<u8>, TlsError> {
        self.finish_fake(KeyType::EcdsaP256, Some(csr_der))
            .await
            .map(|(chain, _key)| chain)
    }

    async fn abort_order(&self) {
        *self
            .pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
        let mut progress = self
            .progress
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if progress.state == "pending" {
            progress.state = "invalid".into();
        }
    }

    fn order_status(&self) -> AcmeOrderStatus {
        self.progress
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    async fn revoke_certificate(
        &self,
        _store: &CertStore,
        _cfg: &AcmeConfig,
        _chain_pem: &[u8],
        reason: RevocationReason,
    ) -> Result<(), TlsError> {
        self.revocation_log
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(reason);
        Ok(())
    }

    async fn renewal_window(
        &self,
        _store: &CertStore,
        _cfg: &AcmeConfig,
        _chain_pem: &[u8],
    ) -> Option<AriWindow> {
        self.ari_window
    }
}

impl FakeAcmeDirectory {
    /// Shared finish: generated key (`None`) or the caller's CSR (`Some`).
    async fn finish_fake(
        &self,
        key_type: KeyType,
        csr_der: Option<&[u8]>,
    ) -> Result<(Vec<u8>, Vec<u8>), TlsError> {
        let pending = self
            .pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
            .ok_or_else(|| TlsError::AcmeOrder {
                message: "no pending fake order".into(),
            })?;

        let result = if self.fail_at == Some(FakeAcmeFail::Challenge) {
            Err(TlsError::AcmeChallenge {
                message: "fake challenge failure".into(),
            })
        } else if self.fail_at == Some(FakeAcmeFail::Finalize) {
            Err(TlsError::AcmeOrder {
                message: "fake finalize failure".into(),
            })
        } else if let Some(der) = csr_der {
            mint_for_csr(&pending.identifiers, der).map(|chain| (chain, Vec::new()))
        } else {
            mint_self_signed(&pending.identifiers, key_type)
        };
        {
            let mut progress = self
                .progress
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            match &result {
                Ok(_) => {
                    progress.state = "valid".into();
                    progress.next_attempt_at = None;
                    progress.last_error = None;
                    for challenge in &mut progress.challenges {
                        challenge.status = "valid".into();
                    }
                }
                Err(e) => mark_failed(&mut progress, e),
            }
        }
        result
    }
}

/// Signs the caller's CSR like a CA would: the CSR names must equal the order's
/// identifiers, and the leaf carries the CSR's public key (no key is generated).
fn mint_for_csr(identifiers: &[String], csr_der: &[u8]) -> Result<Vec<u8>, TlsError> {
    let mut names = csr_dns_names(csr_der)?;
    let mut wanted = identifiers.to_vec();
    names.sort();
    wanted.sort();
    if names != wanted {
        return Err(TlsError::AcmeOrder {
            message: "fake CA: CSR names differ from the order identifiers".into(),
        });
    }
    let mut csr =
        CertificateSigningRequestParams::from_der(&CertificateSigningRequestDer::from(csr_der))
            .map_err(|e| TlsError::AcmeOrder {
                message: format!("fake CSR: {e}"),
            })?;
    csr.params.use_authority_key_identifier_extension = true;
    let ca_key =
        KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).map_err(|e| TlsError::AcmeOrder {
            message: format!("fake CA key: {e}"),
        })?;
    let ca = CertificateParams::new(vec!["dnscraft fake ca".to_owned()]).map_err(|e| {
        TlsError::AcmeOrder {
            message: format!("fake CA params: {e}"),
        }
    })?;
    let issuer = Issuer::new(ca, ca_key);
    let cert = csr.signed_by(&issuer).map_err(|e| TlsError::AcmeOrder {
        message: format!("fake sign: {e}"),
    })?;
    Ok(cert.pem().into_bytes())
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
    // ARI ids need an AKI; real CAs always set one.
    params.use_authority_key_identifier_extension = true;
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn rate_limited_error() -> instant_acme::Error {
        instant_acme::Problem {
            r#type: Some("urn:ietf:params:acme:error:rateLimited".into()),
            detail: Some("too many orders".into()),
            status: Some(429),
            subproblems: Vec::new(),
        }
        .into()
    }

    #[test]
    fn map_acme_order_keeps_captured_retry_after() {
        let hint = Some(Duration::from_secs(77));
        let err = map_acme_order(rate_limited_error(), hint);
        assert_eq!(err.code(), "tls.acme.rate_limited");
        assert_eq!(err.retry_after(), hint);
    }

    #[test]
    fn map_acme_challenge_keeps_captured_retry_after() {
        let hint = Some(Duration::from_secs(33));
        let err = map_acme_challenge(rate_limited_error(), hint);
        assert_eq!(err.code(), "tls.acme.rate_limited");
        assert_eq!(err.retry_after(), hint);
    }

    #[test]
    fn map_acme_order_rate_limit_without_hint_is_none() {
        let err = map_acme_order(rate_limited_error(), None);
        assert_eq!(err.code(), "tls.acme.rate_limited");
        assert_eq!(err.retry_after(), None);
    }

    #[test]
    fn revocation_reason_parses_common_spellings() {
        assert_eq!(
            RevocationReason::parse("key_compromise").unwrap(),
            RevocationReason::KeyCompromise
        );
        assert_eq!(
            RevocationReason::parse("KeyCompromise").unwrap(),
            RevocationReason::KeyCompromise
        );
        assert_eq!(
            RevocationReason::parse("cessation-of-operation").unwrap(),
            RevocationReason::CessationOfOperation
        );
        assert_eq!(
            RevocationReason::parse("").unwrap(),
            RevocationReason::Unspecified
        );
        let err = RevocationReason::parse("because").expect_err("unknown");
        assert_eq!(err.code(), "tls.config.invalid");
    }

    #[tokio::test]
    async fn fake_account_status_reads_id_and_never_key() {
        let dir = std::env::temp_dir().join(format!(
            "dnscraft-tls-account-status-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let store = CertStore::open(&dir).unwrap();
        let cfg = AcmeConfig {
            directory: crate::config::AcmeDirectoryKind::Staging,
            account: crate::config::AcmeAccountConfig {
                tos_agreed: true,
                ..Default::default()
            },
            ..AcmeConfig::default()
        };
        let before = account_status(&store, &cfg).unwrap();
        assert!(!before.exists);

        FakeAcmeDirectory::with_account_id("acct-7")
            .ensure_account(&store, &cfg)
            .await
            .unwrap();
        let after = account_status(&store, &cfg).unwrap();
        assert!(after.exists);
        assert_eq!(after.account_id.as_deref(), Some("acct-7"));
        assert!(after.tos_agreed);
        assert!(!after.eab_configured);
        assert!(!format!("{after:?}").contains("key"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn fake_rejects_account_creation_without_tos() {
        let dir = std::env::temp_dir().join(format!(
            "dnscraft-tls-account-tos-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let store = CertStore::open(&dir).unwrap();
        let cfg = AcmeConfig::default();
        let err = FakeAcmeDirectory::new()
            .ensure_account(&store, &cfg)
            .await
            .expect_err("tos not agreed");
        assert_eq!(err.code(), "tls.acme.account.tos");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
