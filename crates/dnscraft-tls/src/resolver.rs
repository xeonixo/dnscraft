//! Hot-reloadable rustls server certificate resolver.
//!
//! Listeners clone an [`Arc`]`<`[`CertResolver`]`>` and use it as
//! [`ResolvesServerCert`]. [`CertResolver::install`] swaps the
//! [`CertifiedKey`] under a lock so new handshakes see the new cert while
//! existing connections keep the key they already negotiated.

use std::fmt;
use std::sync::{Arc, RwLock};

use rustls::crypto::ring::default_provider;
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;

use crate::error::TlsError;
use crate::pem_util::{parse_cert_chain, parse_private_key};
use crate::store::{CertMeta, CertStore};

/// Shared rustls server cert resolver; listeners clone [`Arc`].
///
/// Initially empty: [`ResolvesServerCert::resolve`] returns `None` until
/// [`Self::install`] or [`Self::import`] succeeds.
pub struct CertResolver {
    current: RwLock<Option<Arc<CertifiedKey>>>,
}

impl fmt::Debug for CertResolver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let installed = self
            .current
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .is_some();
        f.debug_struct("CertResolver")
            .field("installed", &installed)
            .finish()
    }
}

impl Default for CertResolver {
    fn default() -> Self {
        Self::new()
    }
}

impl CertResolver {
    /// Creates an empty resolver (no certificate until install/import).
    pub fn new() -> Self {
        Self {
            current: RwLock::new(None),
        }
    }

    /// Returns true if a certificate is currently installed.
    pub fn has_cert(&self) -> bool {
        self.current
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .is_some()
    }

    /// Builds a [`CertifiedKey`] with the ring provider and swaps it in.
    ///
    /// Does not touch the disk store. On parse/key errors the previous cert
    /// (if any) remains installed.
    pub fn install(&self, chain_pem: &[u8], key_pem: &[u8]) -> Result<(), TlsError> {
        let key = certified_key_from_pem(chain_pem, key_pem)?;
        *self
            .current
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(Arc::new(key));
        Ok(())
    }

    /// Validates PEM, persists via [`CertStore::save`], then installs.
    ///
    /// Intended for a future cluster push of cert+key to sub-nodes. A corrupt
    /// PEM leaves both disk and the in-memory cert unchanged.
    pub fn import(
        &self,
        store: &CertStore,
        chain_pem: &[u8],
        key_pem: &[u8],
    ) -> Result<(), TlsError> {
        // Validate first so we never write or swap on bad input.
        let _ = certified_key_from_pem(chain_pem, key_pem)?;
        let meta = CertMeta::default();
        store.save(chain_pem, key_pem, &meta)?;
        self.install(chain_pem, key_pem)
    }

    /// Installs a certificate previously loaded from the store.
    pub fn install_loaded(&self, loaded: &crate::store::LoadedCert) -> Result<(), TlsError> {
        self.install(&loaded.chain_pem, loaded.key.as_bytes())
    }
}

impl ResolvesServerCert for CertResolver {
    fn resolve(&self, _client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        self.current
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }
}

fn certified_key_from_pem(chain_pem: &[u8], key_pem: &[u8]) -> Result<CertifiedKey, TlsError> {
    let certs =
        parse_cert_chain(chain_pem).map_err(|message| TlsError::StoreCorrupt { message })?;
    let key = parse_private_key(key_pem).map_err(|message| TlsError::StoreCorrupt { message })?;
    CertifiedKey::from_der(certs, key, &default_provider()).map_err(|e| TlsError::StoreCorrupt {
        message: format!("cannot build CertifiedKey: {e}"),
    })
}
