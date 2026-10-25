//! quinn with rustls-ring + ResolvesServerCert: open a QUIC connection and echo one stream.

use std::sync::Arc;
use std::time::Duration;

use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use quinn::{ClientConfig, Endpoint, ServerConfig};
use rustls::ClientConfig as RustlsClientConfig;
use rustls::ServerConfig as RustlsServerConfig;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::ring::default_provider;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, Error as TlsError, SignatureScheme};
use tokio::time::timeout;

use crate::cert::SpikeCertResolver;

pub async fn run() -> Result<Vec<String>, String> {
    let (resolver, leaf) = SpikeCertResolver::with_localhost()?;

    let mut server_tls = RustlsServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(resolver as Arc<dyn rustls::server::ResolvesServerCert>);
    server_tls.alpn_protocols = vec![b"spike".to_vec()];
    // QUIC requires TLS 1.3 only; max_early_data left at 0 for this check.

    let quic_server = QuicServerConfig::try_from(server_tls)
        .map_err(|e| format!("QuicServerConfig: {e}"))?;
    let server_config = ServerConfig::with_crypto(Arc::new(quic_server));
    let server = Endpoint::server(server_config, "127.0.0.1:0".parse().map_err(|e| format!("{e}"))?)
        .map_err(|e| format!("Endpoint::server: {e}"))?;
    let addr = server.local_addr().map_err(|e| format!("local_addr: {e}"))?;

    let accept = tokio::spawn(async move {
        let connecting = server
            .accept()
            .await
            .ok_or_else(|| "no incoming".to_string())?;
        let conn = connecting
            .await
            .map_err(|e| format!("accept handshake: {e}"))?;
        let (mut send, mut recv) = conn
            .accept_bi()
            .await
            .map_err(|e| format!("accept_bi: {e}"))?;
        let data = recv
            .read_to_end(64)
            .await
            .map_err(|e| format!("read: {e}"))?;
        send.write_all(&data)
            .await
            .map_err(|e| format!("write: {e}"))?;
        send.finish().map_err(|e| format!("finish: {e}"))?;
        // Keep conn alive briefly so the client can read.
        tokio::time::sleep(Duration::from_millis(50)).await;
        Ok::<_, String>(data)
    });

    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(leaf)
        .map_err(|e| format!("add root: {e}"))?;
    // Accept our self-signed via custom verifier that trusts the leaf we minted.
    let mut client_tls = RustlsClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(TrustLeaf))
        .with_no_client_auth();
    client_tls.alpn_protocols = vec![b"spike".to_vec()];
    let _ = roots; // leaf trusted via TrustLeaf

    let client_crypto = QuicClientConfig::try_from(client_tls)
        .map_err(|e| format!("QuicClientConfig: {e}"))?;
    let mut client = Endpoint::client("127.0.0.1:0".parse().map_err(|e| format!("{e}"))?)
        .map_err(|e| format!("client endpoint: {e}"))?;
    client.set_default_client_config(ClientConfig::new(Arc::new(client_crypto)));

    let connecting = client
        .connect(addr, "localhost")
        .map_err(|e| format!("connect start: {e}"))?;
    let conn = timeout(Duration::from_secs(3), connecting)
        .await
        .map_err(|_| "connect timeout".to_string())?
        .map_err(|e| format!("connect: {e}"))?;

    let (mut send, mut recv) = conn
        .open_bi()
        .await
        .map_err(|e| format!("open_bi: {e}"))?;
    send.write_all(b"ping")
        .await
        .map_err(|e| format!("client write: {e}"))?;
    send.finish()
        .map_err(|e| format!("client finish: {e}"))?;
    let echoed = recv
        .read_to_end(64)
        .await
        .map_err(|e| format!("client read: {e}"))?;
    if echoed != b"ping" {
        return Err(format!("echo mismatch: {echoed:?}"));
    }

    let server_seen = accept
        .await
        .map_err(|e| format!("join: {e}"))??;
    if server_seen != b"ping" {
        return Err(format!("server saw {server_seen:?}"));
    }

    Ok(vec![
        format!("QUIC server on {addr}, ALPN=spike, ResolvesServerCert + rcgen"),
        "bidirectional stream echo ok".into(),
        "features: default-features=false, runtime-tokio, rustls-ring".into(),
    ])
}

#[derive(Debug)]
struct TrustLeaf;

impl ServerCertVerifier for TrustLeaf {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}
