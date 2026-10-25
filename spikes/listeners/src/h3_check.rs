//! h3 0.0.8 + h3-quinn 0.0.10: one HTTP/3 GET on a quinn endpoint (Rust client).

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::{Buf, Bytes};
use futures::future;
use h3::error::ConnectionError;
use http::{Request, StatusCode};
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

static ALPN: &[u8] = b"h3";

pub async fn run() -> Result<Vec<String>, String> {
    let (resolver, _leaf) = SpikeCertResolver::with_localhost()?;

    let mut server_tls = RustlsServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(resolver as Arc<dyn rustls::server::ResolvesServerCert>);
    server_tls.alpn_protocols = vec![ALPN.to_vec()];
    server_tls.max_early_data_size = u32::MAX;

    let server_config = ServerConfig::with_crypto(Arc::new(
        QuicServerConfig::try_from(server_tls).map_err(|e| format!("QuicServerConfig: {e}"))?,
    ));
    let endpoint =
        Endpoint::server(server_config, "127.0.0.1:0".parse().map_err(|e| format!("{e}"))?)
            .map_err(|e| format!("server endpoint: {e}"))?;
    let addr = endpoint.local_addr().map_err(|e| format!("local_addr: {e}"))?;

    let server_task = tokio::spawn(async move {
        let connecting = endpoint
            .accept()
            .await
            .ok_or_else(|| "no h3 incoming".to_string())?;
        let conn = connecting
            .await
            .map_err(|e| format!("h3 accept: {e}"))?;
        let mut h3_conn = h3::server::Connection::new(h3_quinn::Connection::new(conn))
            .await
            .map_err(|e| format!("h3::server::Connection: {e}"))?;

        let resolver = match h3_conn.accept().await {
            Ok(Some(r)) => r,
            Ok(None) => return Err("h3 accept returned None".into()),
            Err(e) => return Err(format!("h3 accept err: {e}")),
        };

        let (req, mut stream) = resolver
            .resolve_request()
            .await
            .map_err(|e| format!("resolve_request: {e}"))?;
        let path = req.uri().path().to_owned();

        let resp = http::Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "text/plain")
            .body(())
            .map_err(|e| format!("response builder: {e}"))?;
        stream
            .send_response(resp)
            .await
            .map_err(|e| format!("send_response: {e}"))?;
        stream
            .send_data(Bytes::from_static(b"h3-ok"))
            .await
            .map_err(|e| format!("send_data: {e}"))?;
        stream
            .finish()
            .await
            .map_err(|e| format!("finish: {e}"))?;

        // Hold the connection briefly so the client can drain the response.
        // Dropping immediately surfaces as ApplicationClose H3_NO_ERROR on recv_response.
        tokio::time::sleep(Duration::from_millis(200)).await;
        drop(h3_conn);
        Ok::<_, String>(path)
    });

    tokio::task::yield_now().await;

    let body = timeout(Duration::from_secs(5), h3_get(addr, "/spike"))
        .await
        .map_err(|_| "h3 client timeout".to_string())??;

    let path = server_task
        .await
        .map_err(|e| format!("server join: {e}"))??;

    if body != b"h3-ok" {
        return Err(format!("unexpected body: {body:?}"));
    }

    Ok(vec![
        format!("HTTP/3 GET {path} → 200 body=h3-ok on {addr}"),
        "client: in-process Rust (h3::client + h3_quinn); curl Features include HTTP3".into(),
        "API notes: h3::server::Connection::accept → RequestResolver::resolve_request;".into(),
        "  QuicServerConfig::try_from(rustls::ServerConfig); ALPN must be b\"h3\";".into(),
        "  do not drop server Connection before the client finishes reading;".into(),
        "  h3-quinn re-exports quinn — feature-unify on rustls-ring only; pre-1.0 churn.".into(),
    ])
}

async fn h3_get(addr: SocketAddr, path: &str) -> Result<Vec<u8>, String> {
    let mut client_tls = RustlsClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(TrustAny))
        .with_no_client_auth();
    client_tls.alpn_protocols = vec![ALPN.to_vec()];

    let mut client = Endpoint::client("127.0.0.1:0".parse().map_err(|e| format!("{e}"))?)
        .map_err(|e| format!("client ep: {e}"))?;
    client.set_default_client_config(ClientConfig::new(Arc::new(
        QuicClientConfig::try_from(client_tls).map_err(|e| format!("QuicClientConfig: {e}"))?,
    )));

    let conn = client
        .connect(addr, "localhost")
        .map_err(|e| format!("connect start: {e}"))?
        .await
        .map_err(|e| format!("connect: {e}"))?;

    let quinn_conn = h3_quinn::Connection::new(conn);
    let (mut driver, mut send_request) = h3::client::new(quinn_conn)
        .await
        .map_err(|e| format!("h3::client::new: {e}"))?;

    let drive = tokio::spawn(async move {
        let err: ConnectionError = future::poll_fn(|cx| driver.poll_close(cx)).await;
        err
    });

    let uri = format!("https://localhost{path}");
    let req = Request::builder()
        .uri(uri)
        .body(())
        .map_err(|e| format!("req: {e}"))?;
    let mut stream = send_request
        .send_request(req)
        .await
        .map_err(|e| format!("send_request: {e}"))?;
    stream
        .finish()
        .await
        .map_err(|e| format!("client finish: {e}"))?;
    let resp = stream
        .recv_response()
        .await
        .map_err(|e| format!("recv_response: {e}"))?;
    if resp.status() != StatusCode::OK {
        return Err(format!("status {}", resp.status()));
    }
    let mut body = Vec::new();
    while let Some(mut chunk) = stream
        .recv_data()
        .await
        .map_err(|e| format!("recv_data: {e}"))?
    {
        body.extend_from_slice(chunk.chunk());
        chunk.advance(chunk.remaining());
    }

    drop(send_request);
    drop(stream);
    let _ = drive.await;
    let _ = client;
    Ok(body)
}

#[derive(Debug)]
struct TrustAny;

impl ServerCertVerifier for TrustAny {
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
