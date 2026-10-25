//! Minimal rustls `ResolvesServerCert` backed by an rcgen self-signed cert.
//! Mirrors the shape of `dnscraft_tls::CertResolver` for the spike only.

use std::sync::{Arc, RwLock};

use rcgen::generate_simple_self_signed;
use rustls::crypto::ring::default_provider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;

/// Spike-only resolver: one installed cert under a lock.
#[derive(Debug)]
pub struct SpikeCertResolver {
    current: RwLock<Option<Arc<CertifiedKey>>>,
}

impl SpikeCertResolver {
    /// Self-signed for `localhost`; returns the resolver and the leaf DER for clients.
    pub fn with_localhost() -> Result<(Arc<Self>, CertificateDer<'static>), String> {
        let certified =
            generate_simple_self_signed(vec!["localhost".into()]).map_err(|e| e.to_string())?;
        let cert_der = CertificateDer::from(certified.cert.der().to_vec());
        let key_der =
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(certified.signing_key.serialize_der()));
        let key = CertifiedKey::from_der(vec![cert_der.clone()], key_der, &default_provider())
            .map_err(|e| format!("CertifiedKey::from_der: {e}"))?;
        let resolver = Arc::new(Self {
            current: RwLock::new(Some(Arc::new(key))),
        });
        Ok((resolver, cert_der))
    }
}

impl ResolvesServerCert for SpikeCertResolver {
    fn resolve(&self, _client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        self.current
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }
}
