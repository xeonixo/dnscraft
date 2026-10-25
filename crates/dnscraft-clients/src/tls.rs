//! TLS client configuration for the UniFi gateway.
//!
//! Builds a rustls [`ClientConfig`] (ring provider) for each [`TlsMode`]:
//! pin (SHA-256 of leaf DER), CA-file roots, or opt-in insecure.

use std::fs;
use std::sync::Arc;

use ring::digest::{SHA256, digest};
use rustls::ClientConfig;
use rustls::SignatureScheme;
use rustls::client::WebPkiServerVerifier;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{ring as rustls_ring, verify_tls12_signature, verify_tls13_signature};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, Error as RustlsError, RootCertStore};
use rustls_pki_types::pem::PemObject;
use tracing::warn;

use crate::config::TlsMode;
use crate::error::ClientsError;

/// Stable code logged when [`TlsMode::Insecure`] is applied.
pub const INSECURE_WARN_CODE: &str = "clients.tls.insecure";

/// SHA-256 of a certificate's DER encoding (32 bytes). Used for pin bootstrap.
pub fn leaf_sha256(der: &[u8]) -> [u8; 32] {
    let d = digest(&SHA256, der);
    let mut out = [0u8; 32];
    out.copy_from_slice(d.as_ref());
    out
}

/// Builds a rustls client config for the given trust mode.
///
/// Uses an explicit ring provider on the builder — does **not** call
/// [`rustls::crypto::CryptoProvider::install_default`] (that is a process-wide
/// side effect reserved for the binary / test harness).
pub fn build_client_config(mode: &TlsMode) -> Result<ClientConfig, ClientsError> {
    let provider = Arc::new(rustls_ring::default_provider());

    match mode {
        TlsMode::Pin(pin) => {
            let verifier = Arc::new(PinVerifier {
                pin: *pin,
                schemes: provider.signature_verification_algorithms,
            });
            Ok(ClientConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions()
                .map_err(|e| ClientsError::config(format!("tls protocol versions: {e}")))?
                .dangerous()
                .with_custom_certificate_verifier(verifier)
                .with_no_client_auth())
        }
        TlsMode::CaFile(path) => {
            let pem = fs::read(path).map_err(|e| {
                ClientsError::config(format!("read ca_file {}: {e}", path.display()))
            })?;
            let mut roots = RootCertStore::empty();
            let mut added = 0usize;
            for item in CertificateDer::pem_slice_iter(&pem) {
                let cert = item.map_err(|e| {
                    ClientsError::config(format!("parse ca_file {}: {e}", path.display()))
                })?;
                roots.add(cert).map_err(|e| {
                    ClientsError::config(format!("add ca from {}: {e}", path.display()))
                })?;
                added += 1;
            }
            if added == 0 {
                return Err(ClientsError::config(format!(
                    "ca_file {} contains no certificates",
                    path.display()
                )));
            }
            let verifier =
                WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider.clone())
                    .build()
                    .map_err(|e| ClientsError::config(format!("ca verifier: {e}")))?;
            Ok(ClientConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions()
                .map_err(|e| ClientsError::config(format!("tls protocol versions: {e}")))?
                .with_webpki_verifier(verifier)
                .with_no_client_auth())
        }
        TlsMode::Insecure => {
            warn!(
                code = INSECURE_WARN_CODE,
                "UniFi TLS mode is insecure (accept-any certificate); use pin or ca_file in production"
            );
            let verifier = Arc::new(InsecureVerifier {
                schemes: provider.signature_verification_algorithms,
            });
            Ok(ClientConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions()
                .map_err(|e| ClientsError::config(format!("tls protocol versions: {e}")))?
                .dangerous()
                .with_custom_certificate_verifier(verifier)
                .with_no_client_auth())
        }
    }
}

/// Pin verifier: leaf DER SHA-256 must match; handshake signatures still checked.
#[derive(Debug)]
struct PinVerifier {
    pin: [u8; 32],
    schemes: rustls::crypto::WebPkiSupportedAlgorithms,
}

impl ServerCertVerifier for PinVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        let got = leaf_sha256(end_entity.as_ref());
        if got != self.pin {
            return Err(RustlsError::InvalidCertificate(
                rustls::CertificateError::ApplicationVerificationFailure,
            ));
        }
        // Hostname is intentionally not checked: UniFi gateways commonly present
        // a self-signed cert whose CN/SAN does not match the IP URL.
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        verify_tls12_signature(message, cert, dss, &self.schemes)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        verify_tls13_signature(message, cert, dss, &self.schemes)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.schemes.supported_schemes()
    }
}

/// Accept-any verifier (opt-in insecure mode). Signatures are still verified
/// so the handshake is cryptographically sound; only identity is skipped.
#[derive(Debug)]
struct InsecureVerifier {
    schemes: rustls::crypto::WebPkiSupportedAlgorithms,
}

impl ServerCertVerifier for InsecureVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        verify_tls12_signature(message, cert, dss, &self.schemes)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        verify_tls13_signature(message, cert, dss, &self.schemes)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.schemes.supported_schemes()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn leaf_sha256_is_32_bytes_and_stable() {
        let a = leaf_sha256(b"hello");
        let b = leaf_sha256(b"hello");
        let c = leaf_sha256(b"world");
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_eq!(a.len(), 32);
    }
}
