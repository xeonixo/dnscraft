//! PEM parsing helpers shared by the store and cert resolver.

use std::fmt;

use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};

use crate::store::{LeafInfo, leaf_info_from_der};

/// PEM-encoded private key that never appears in [`Debug`] or [`Display`].
#[derive(Clone, PartialEq, Eq)]
pub struct KeyPem(Vec<u8>);

impl KeyPem {
    /// Wraps raw PEM bytes (already validated or about to be).
    pub fn from_bytes(bytes: impl Into<Vec<u8>>) -> Self {
        Self(bytes.into())
    }

    /// Parses and validates that the bytes contain a private key PEM.
    pub fn parse(pem: &[u8]) -> Result<Self, String> {
        let _ = PrivateKeyDer::from_pem_slice(pem).map_err(|e| format!("key PEM: {e}"))?;
        Ok(Self(pem.to_vec()))
    }

    /// The PEM bytes. Callers must not log this.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for KeyPem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("KeyPem([redacted])")
    }
}

impl fmt::Display for KeyPem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[redacted]")
    }
}

/// Parses all certificates from a PEM bundle (leaf first).
pub fn parse_cert_chain(pem: &[u8]) -> Result<Vec<CertificateDer<'static>>, String> {
    let certs: Result<Vec<_>, _> = CertificateDer::pem_slice_iter(pem).collect();
    let certs = certs.map_err(|e| format!("cert PEM: {e}"))?;
    if certs.is_empty() {
        return Err("cert PEM contains no certificates".into());
    }
    Ok(certs)
}

/// Parses the private key from PEM.
pub fn parse_private_key(pem: &[u8]) -> Result<PrivateKeyDer<'static>, String> {
    PrivateKeyDer::from_pem_slice(pem).map_err(|e| format!("key PEM: {e}"))
}

/// Leaf `notAfter` + identifiers from the first certificate in a PEM chain.
pub fn parse_leaf_info(chain_pem: &[u8]) -> Result<LeafInfo, String> {
    let certs = parse_cert_chain(chain_pem)?;
    leaf_info_from_der(certs[0].as_ref())
}
