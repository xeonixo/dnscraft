//! rustls client config shared by the reqwest-based HTTP clients.
//!
//! reqwest 0.13 has no webpki-roots feature and defaults to the platform
//! verifier and aws-lc. The crypto policy is ring-only with the bundled
//! Mozilla roots, so every client is built with an explicit config.

use std::sync::Arc;

use rustls::pki_types::CertificateDer;
use rustls::{ClientConfig, RootCertStore};

/// Builds a ring-backed client config trusting the webpki roots plus
/// `extra_roots` (DER; used only by the local Pebble test).
pub(crate) fn client_config(
    extra_roots: &[CertificateDer<'static>],
) -> Result<ClientConfig, rustls::Error> {
    let mut roots = RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };
    for cert in extra_roots {
        roots.add(cert.clone())?;
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    Ok(ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .with_root_certificates(roots)
        .with_no_client_auth())
}
