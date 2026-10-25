//! [`instant_acme::HttpClient`] over the workspace reqwest client (rustls + ring).
//!
//! Prefer this over instant-acme's `hyper-rustls` feature so the crate keeps a
//! single HTTP/TLS stack and root store (same as filtering's fetcher).
//!
//! Also records `Retry-After` from the last HTTP 429. instant-acme 0.8.5 drops
//! that header when surfacing `Error::Api(Problem)`, so [`crate::acme`] reads
//! it back via [`ReqwestHttpClient::take_last_retry_after`] when mapping rate
//! limits.

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use http::{Request, Response};
use http_body_util::{BodyExt, Full};
use instant_acme::{BodyWrapper, BytesResponse, Error as AcmeError, HttpClient};
use reqwest::Client;

use crate::error::{TlsError, parse_retry_after_header};

/// Reqwest-backed ACME HTTP client.
#[derive(Clone, Debug)]
pub struct ReqwestHttpClient {
    client: Client,
    /// `Retry-After` from the most recent HTTP 429 response, if any.
    last_retry_after: Arc<Mutex<Option<Duration>>>,
}

impl ReqwestHttpClient {
    /// Builds a client that trusts the webpki root set (production / staging).
    pub fn new() -> Result<Self, TlsError> {
        let tls = crate::http_tls::client_config(&[]).map_err(|e| TlsError::AcmeAccount {
            message: format!("build TLS config: {e}"),
        })?;
        let client = Client::builder()
            .use_preconfigured_tls(tls)
            .timeout(std::time::Duration::from_secs(30))
            .connect_timeout(std::time::Duration::from_secs(10))
            .build()
            .map_err(|e| TlsError::AcmeAccount {
                message: format!("build HTTP client: {e}"),
            })?;
        Ok(Self {
            client,
            last_retry_after: Arc::new(Mutex::new(None)),
        })
    }

    /// Builds a client that also trusts the given PEM root(s).
    ///
    /// Used by the ignored Pebble test so the local ACME CA is accepted without
    /// disabling certificate verification globally.
    pub fn with_extra_roots(root_pem: &[u8]) -> Result<Self, TlsError> {
        let certs =
            crate::pem_util::parse_cert_chain(root_pem).map_err(|e| TlsError::AcmeAccount {
                message: format!("parse ACME test root PEM: {e}"),
            })?;
        let tls = crate::http_tls::client_config(&certs).map_err(|e| TlsError::AcmeAccount {
            message: format!("build TLS config with test root: {e}"),
        })?;
        let client = Client::builder()
            .use_preconfigured_tls(tls)
            .timeout(std::time::Duration::from_secs(30))
            .connect_timeout(std::time::Duration::from_secs(10))
            .build()
            .map_err(|e| TlsError::AcmeAccount {
                message: format!("build HTTP client with test root: {e}"),
            })?;
        Ok(Self {
            client,
            last_retry_after: Arc::new(Mutex::new(None)),
        })
    }

    /// Exposes the underlying reqwest client (for tests / diagnostics).
    pub fn inner(&self) -> &Client {
        &self.client
    }

    /// Takes the `Retry-After` recorded from the last HTTP 429, if any.
    pub fn take_last_retry_after(&self) -> Option<Duration> {
        self.last_retry_after
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
    }
}

impl HttpClient for ReqwestHttpClient {
    fn request(
        &self,
        req: Request<BodyWrapper<Bytes>>,
    ) -> Pin<Box<dyn Future<Output = Result<BytesResponse, AcmeError>> + Send>> {
        let client = self.client.clone();
        let last_retry_after = Arc::clone(&self.last_retry_after);
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

            // Always rewrite the slot so a stale 429 hint cannot attach to a
            // later, unrelated rate-limit mapping (e.g. account then order).
            let delay = if status.as_u16() == 429 {
                headers
                    .get(reqwest::header::RETRY_AFTER)
                    .and_then(|v| v.to_str().ok())
                    .and_then(parse_retry_after_header)
            } else {
                None
            };
            if let Ok(mut slot) = last_retry_after.lock() {
                *slot = delay;
            }

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

    #[tokio::test]
    async fn records_retry_after_on_429_delta_seconds() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 1024];
            let _ = sock.read(&mut buf).await;
            let body = b"{\"type\":\"urn:ietf:params:acme:error:rateLimited\"}";
            let resp = format!(
                "HTTP/1.1 429 Too Many Requests\r\nRetry-After: 42\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                std::str::from_utf8(body).unwrap()
            );
            let _ = sock.write_all(resp.as_bytes()).await;
        });

        let client = ReqwestHttpClient::new().unwrap();
        let req = Request::builder()
            .method(Method::GET)
            .uri(format!("http://{addr}/new-order"))
            .body(BodyWrapper::from(Vec::<u8>::new()))
            .unwrap();
        let rsp = HttpClient::request(&client, req).await.expect("429");
        assert_eq!(rsp.parts.status, 429);
        assert_eq!(
            client.take_last_retry_after(),
            Some(Duration::from_secs(42))
        );
        assert_eq!(client.take_last_retry_after(), None);
    }

    #[tokio::test]
    async fn records_retry_after_on_429_http_date() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        // Far-future IMF-fixdate so the parsed delay is clearly positive.
        let http_date = "Wed, 01 Jan 2098 00:00:00 GMT";
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 1024];
            let _ = sock.read(&mut buf).await;
            let body = b"{}";
            let resp = format!(
                "HTTP/1.1 429 Too Many Requests\r\nRetry-After: {http_date}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                std::str::from_utf8(body).unwrap()
            );
            let _ = sock.write_all(resp.as_bytes()).await;
        });

        let client = ReqwestHttpClient::new().unwrap();
        let req = Request::builder()
            .method(Method::GET)
            .uri(format!("http://{addr}/new-order"))
            .body(BodyWrapper::from(Vec::<u8>::new()))
            .unwrap();
        let _ = HttpClient::request(&client, req).await.expect("429");
        let delay = client
            .take_last_retry_after()
            .expect("http-date retry-after");
        assert!(
            delay > Duration::from_secs(3600),
            "expected multi-hour delay from 2098 date, got {delay:?}"
        );
    }

    #[tokio::test]
    async fn non_429_response_clears_stale_retry_after() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let hits = Arc::new(std::sync::atomic::AtomicU32::new(0));
        let hits2 = hits.clone();
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    return;
                };
                let n = hits2.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let mut buf = [0u8; 1024];
                let _ = sock.read(&mut buf).await;
                let resp = if n == 0 {
                    "HTTP/1.1 429 Too Many Requests\r\nRetry-After: 99\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}"
                        .to_owned()
                } else {
                    "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}".to_owned()
                };
                let _ = sock.write_all(resp.as_bytes()).await;
            }
        });

        let client = ReqwestHttpClient::new().unwrap();
        let get = |path: &str| {
            Request::builder()
                .method(Method::GET)
                .uri(format!("http://{addr}{path}"))
                .body(BodyWrapper::from(Vec::<u8>::new()))
                .unwrap()
        };
        let _ = HttpClient::request(&client, get("/first"))
            .await
            .expect("429");
        // Do not take() — leave the stale hint in the slot, then a 200 must clear it.
        let _ = HttpClient::request(&client, get("/second"))
            .await
            .expect("200");
        assert_eq!(
            client.take_last_retry_after(),
            None,
            "200 must clear a prior 429 Retry-After"
        );
    }
}
