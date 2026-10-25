//! [`instant_acme::HttpClient`] over the workspace reqwest client (rustls + ring).
//!
//! Prefer this over instant-acme's `hyper-rustls` feature so the crate keeps a
//! single HTTP/TLS stack and root store (same as filtering's fetcher).

use std::future::Future;
use std::pin::Pin;

use bytes::Bytes;
use http::{Request, Response};
use http_body_util::{BodyExt, Full};
use instant_acme::{BodyWrapper, BytesResponse, Error as AcmeError, HttpClient};
use reqwest::Client;

use crate::error::TlsError;

/// Reqwest-backed ACME HTTP client.
#[derive(Clone, Debug)]
pub struct ReqwestHttpClient {
    client: Client,
}

impl ReqwestHttpClient {
    /// Builds a client that trusts the webpki root set (production / staging).
    pub fn new() -> Result<Self, TlsError> {
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .connect_timeout(std::time::Duration::from_secs(10))
            .build()
            .map_err(|e| TlsError::AcmeAccount {
                message: format!("build HTTP client: {e}"),
            })?;
        Ok(Self { client })
    }

    /// Builds a client that also trusts the given PEM root(s).
    ///
    /// Used by the ignored Pebble test so the local ACME CA is accepted without
    /// disabling certificate verification globally.
    pub fn with_extra_roots(root_pem: &[u8]) -> Result<Self, TlsError> {
        let cert = reqwest::Certificate::from_pem(root_pem).map_err(|e| TlsError::AcmeAccount {
            message: format!("parse ACME test root PEM: {e}"),
        })?;
        let client = Client::builder()
            .add_root_certificate(cert)
            .timeout(std::time::Duration::from_secs(30))
            .connect_timeout(std::time::Duration::from_secs(10))
            .build()
            .map_err(|e| TlsError::AcmeAccount {
                message: format!("build HTTP client with test root: {e}"),
            })?;
        Ok(Self { client })
    }

    /// Exposes the underlying reqwest client (for tests / diagnostics).
    pub fn inner(&self) -> &Client {
        &self.client
    }
}

impl HttpClient for ReqwestHttpClient {
    fn request(
        &self,
        req: Request<BodyWrapper<Bytes>>,
    ) -> Pin<Box<dyn Future<Output = Result<BytesResponse, AcmeError>> + Send>> {
        let client = self.client.clone();
        Box::pin(async move {
            let (parts, body) = req.into_parts();
            let body_bytes = match body.collect().await {
                Ok(c) => c.to_bytes(),
                Err(e) => match e {},
            };

            let mut builder = client.request(parts.method, parts.uri.to_string());
            for (name, value) in parts.headers.iter() {
                builder = builder.header(name.as_str(), value.as_bytes());
            }
            if !body_bytes.is_empty() {
                builder = builder.body(body_bytes.to_vec());
            }

            let rsp = builder
                .send()
                .await
                .map_err(|e| AcmeError::Other(Box::new(e)))?;
            let status = rsp.status();
            let headers = rsp.headers().clone();
            let bytes = rsp
                .bytes()
                .await
                .map_err(|e| AcmeError::Other(Box::new(e)))?;

            let mut http_rsp = Response::builder().status(status.as_u16());
            for (name, value) in headers.iter() {
                http_rsp = http_rsp.header(name, value);
            }
            let http_rsp = http_rsp
                .body(Full::new(bytes))
                .map_err(|e| AcmeError::Other(Box::new(e)))?;
            Ok(BytesResponse::from(http_rsp))
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use http::Method;
    use instant_acme::HttpClient;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    #[test]
    fn builds_default_and_rejects_bad_root_pem() {
        let c = ReqwestHttpClient::new().expect("webpki client");
        assert!(c.inner().get("https://example.com").build().is_ok());
        let err = ReqwestHttpClient::with_extra_roots(
            b"-----BEGIN CERTIFICATE-----\nbm90LWEtY2VydA==\n-----END CERTIFICATE-----\n",
        )
        .expect_err("bad pem");
        assert_eq!(err.code(), "tls.acme.account");
    }

    #[tokio::test]
    async fn http_client_round_trips_loopback() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 1024];
            let _ = sock.read(&mut buf).await;
            let body = b"{\"ok\":true}";
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                std::str::from_utf8(body).unwrap()
            );
            let _ = sock.write_all(resp.as_bytes()).await;
        });

        let client = ReqwestHttpClient::new().unwrap();
        let req = Request::builder()
            .method(Method::GET)
            .uri(format!("http://{addr}/dir"))
            .body(BodyWrapper::from(Vec::<u8>::new()))
            .unwrap();
        let rsp = HttpClient::request(&client, req)
            .await
            .expect("loopback GET");
        assert_eq!(rsp.parts.status, 200);
    }
}
