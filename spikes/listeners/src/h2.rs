//! hyper 1 + hyper-util: HTTP/2 over tokio-rustls with ALPN h2.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http::{Request, Response, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as AutoBuilder;
use rustls::ServerConfig as RustlsServerConfig;
use rustls::ClientConfig as RustlsClientConfig;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::ring::default_provider;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, Error as TlsError, SignatureScheme};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use tokio::time::timeout;
use tokio_rustls::{TlsAcceptor, TlsConnector};

use crate::cert::SpikeCertResolver;

pub async fn run() -> Result<Vec<String>, String> {
    let (resolver, _leaf) = SpikeCertResolver::with_localhost()?;

    let mut server_tls = RustlsServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(resolver as Arc<dyn rustls::server::ResolvesServerCert>);
    server_tls.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    let acceptor = TlsAcceptor::from(Arc::new(server_tls));

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|e| format!("bind: {e}"))?;
    let addr = listener.local_addr().map_err(|e| format!("local_addr: {e}"))?;

    let (ready_tx, ready_rx) = oneshot::channel::<()>();
    let server = tokio::spawn(async move {
        let _ = ready_tx.send(());
        let (tcp, _) = listener
            .accept()
            .await
            .map_err(|e| format!("accept: {e}"))?;
        let tls = acceptor
            .accept(tcp)
            .await
            .map_err(|e| format!("tls accept: {e}"))?;
        let negotiated = tls
            .get_ref()
            .1
            .alpn_protocol()
            .map(|p| String::from_utf8_lossy(p).into_owned());
        let io = TokioIo::new(tls);
        // Client closing after the response is normal; hyper may report a
        // connection error — treat any post-ALPN outcome as success for the spike.
        let _ = AutoBuilder::new(TokioExecutor::new())
            .serve_connection(
                io,
                service_fn(|_req: Request<Incoming>| async move {
                    Ok::<_, Infallible>(Response::new(Full::new(Bytes::from_static(b"h2-ok"))))
                }),
            )
            .await;
        Ok::<_, String>(negotiated)
    });

    ready_rx
        .await
        .map_err(|_| "h2 server dropped".to_string())?;

    let body = timeout(Duration::from_secs(5), h2_get(addr))
        .await
        .map_err(|_| "h2 client timeout".to_string())??;

    let alpn = server.await.map_err(|e| format!("join: {e}"))??;

    if body != b"h2-ok" {
        return Err(format!("unexpected body: {body:?}"));
    }

    Ok(vec![
        format!("HTTP/2 GET / → 200 body=h2-ok on {addr}"),
        format!("server negotiated ALPN={alpn:?}"),
        "stack: hyper 1 (server,http1,http2) + hyper-util (tokio,server-auto) + tokio-rustls ring".into(),
    ])
}

async fn h2_get(addr: SocketAddr) -> Result<Vec<u8>, String> {
    let mut client_tls = RustlsClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(TrustAny))
        .with_no_client_auth();
    client_tls.alpn_protocols = vec![b"h2".to_vec()];
    let connector = TlsConnector::from(Arc::new(client_tls));

    let tcp = TcpStream::connect(addr)
        .await
        .map_err(|e| format!("connect: {e}"))?;
    let server_name = ServerName::try_from("localhost").map_err(|e| format!("sni: {e}"))?;
    let tls = connector
        .connect(server_name, tcp)
        .await
        .map_err(|e| format!("tls: {e}"))?;
    let io = TokioIo::new(tls);

    let (mut sender, conn) = hyper::client::conn::http2::Builder::new(TokioExecutor::new())
        .handshake(io)
        .await
        .map_err(|e| format!("h2 handshake: {e}"))?;
    tokio::spawn(async move {
        let _ = conn.await;
    });

    let req = Request::builder()
        .uri("https://localhost/")
        .body(Full::new(Bytes::new()))
        .map_err(|e| format!("req: {e}"))?;
    let resp = sender
        .send_request(req)
        .await
        .map_err(|e| format!("send: {e}"))?;
    if resp.status() != StatusCode::OK {
        return Err(format!("status {}", resp.status()));
    }
    let collected = resp
        .into_body()
        .collect()
        .await
        .map_err(|e| format!("body: {e}"))?;
    Ok(collected.to_bytes().to_vec())
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
