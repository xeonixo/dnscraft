//! PEM parsing helpers shared by the store and cert resolver.

use std::fmt;

use rustls::crypto::ring::default_provider;
use rustls::sign::CertifiedKey;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use zeroize::Zeroizing;

use crate::store::{LeafInfo, leaf_info_from_der};

/// PEM-encoded private key that never appears in [`Debug`] / [`Display`] and is
/// wiped on drop.
#[derive(Clone, PartialEq, Eq)]
pub struct KeyPem(Zeroizing<Vec<u8>>);

impl KeyPem {
    /// Wraps raw PEM bytes (already validated or about to be).
    pub fn from_bytes(bytes: impl Into<Vec<u8>>) -> Self {
        Self(Zeroizing::new(bytes.into()))
    }

    /// Parses and validates that the bytes contain a private key PEM.
    pub fn parse(pem: &[u8]) -> Result<Self, String> {
        let _ = PrivateKeyDer::from_pem_slice(pem).map_err(|e| format!("key PEM: {e}"))?;
        Ok(Self(Zeroizing::new(pem.to_vec())))
    }

    /// The PEM bytes. Callers must not log this.
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_slice()
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

/// Leaf `notAfter`, identifiers and cert detail from a PEM chain.
///
/// The detail's `chain` holds each certificate as a PEM block, leaf first;
/// private keys are never included.
pub fn parse_leaf_info(chain_pem: &[u8]) -> Result<LeafInfo, String> {
    let certs = parse_cert_chain(chain_pem)?;
    let mut info = leaf_info_from_der(certs[0].as_ref())?;
    info.detail.chain = cert_pem_blocks(chain_pem);
    Ok(info)
}

/// Splits a PEM bundle into certificate blocks (drops any non-cert section).
fn cert_pem_blocks(pem: &[u8]) -> Vec<String> {
    const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
    const END: &str = "-----END CERTIFICATE-----";
    let text = String::from_utf8_lossy(pem);
    let mut out = Vec::new();
    let mut rest = text.as_ref();
    while let Some(begin) = rest.find(BEGIN) {
        let tail = &rest[begin..];
        let Some(end) = tail.find(END) else {
            break;
        };
        let end = end + END.len();
        out.push(tail[..end].trim().to_owned());
        rest = &tail[end..];
    }
    out
}

/// Lower-case hex SHA-256 of a DER blob (certificate fingerprint).
///
/// Used for trust pinning; never applied to private key material.
pub fn fingerprint_sha256(der: &[u8]) -> String {
    let digest = ring::digest::digest(&ring::digest::SHA256, der);
    digest.as_ref().iter().map(|b| format!("{b:02x}")).collect()
}

/// Builds a ring-backed [`CertifiedKey`] from PEM, verifying the key matches
/// the leaf certificate. Errors never contain key material.
pub fn certified_key_from_pem(chain_pem: &[u8], key_pem: &[u8]) -> Result<CertifiedKey, String> {
    let certs = parse_cert_chain(chain_pem)?;
    let key = parse_private_key(key_pem)?;
    CertifiedKey::from_der(certs, key, &default_provider())
        .map_err(|e| format!("cannot build CertifiedKey: {e}"))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use rcgen::generate_simple_self_signed;

    #[test]
    fn parse_rejects_empty_and_garbage() {
        assert!(parse_cert_chain(b"").is_err());
        assert!(parse_cert_chain(b"not pem").is_err());
        assert!(parse_private_key(b"not pem").is_err());
        assert!(KeyPem::parse(b"not pem").is_err());
    }

    #[test]
    fn round_trip_self_signed() {
        let certified = generate_simple_self_signed(vec!["dns.example.com".into()]).unwrap();
        let chain = certified.cert.pem();
        let key = certified.signing_key.serialize_pem();
        let parsed = KeyPem::parse(key.as_bytes()).unwrap();
        assert_eq!(parsed.as_bytes(), key.as_bytes());
        let info = parse_leaf_info(chain.as_bytes()).unwrap();
        assert!(
            info.identifiers
                .iter()
                .any(|i| i == "dns.example.com" || i.contains("example.com"))
        );
        certified_key_from_pem(chain.as_bytes(), key.as_bytes()).unwrap();

        let detail = parse_leaf_info(chain.as_bytes()).unwrap().detail;
        assert_eq!(detail.chain, vec![chain.trim().to_owned()]);
        assert!(!detail.chain[0].contains("PRIVATE KEY"));

        let fp1 = fingerprint_sha256(parse_cert_chain(chain.as_bytes()).unwrap()[0].as_ref());
        let fp2 = fingerprint_sha256(parse_cert_chain(chain.as_bytes()).unwrap()[0].as_ref());
        assert_eq!(fp1, fp2);
        assert_eq!(fp1.len(), 64);
        assert!(
            fp1.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        );
    }

    #[test]
    fn cert_blocks_ignore_non_certificate_pem() {
        let certified = generate_simple_self_signed(vec!["dns.example.com".into()]).unwrap();
        let cert = certified.cert.pem();
        let key = certified.signing_key.serialize_pem();
        let bundle = format!("{key}\n{cert}");
        let blocks = cert_pem_blocks(bundle.as_bytes());
        assert_eq!(blocks.len(), 1);
        assert!(blocks[0].starts_with("-----BEGIN CERTIFICATE-----"));
        assert!(!blocks[0].contains("PRIVATE KEY"));
    }
}
