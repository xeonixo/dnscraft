//! HTTPS client for the UniFi OS gateway (Integration + classic surfaces).
//!
//! Defaults: `X-API-KEY` header, 30 s timeout, 8 MiB streamed body cap, no
//! redirects. The API key never appears in error messages or `Debug`.

use std::error::Error as StdError;
use std::fmt;
use std::time::Duration;

use reqwest::Client;
use reqwest::redirect::Policy;
use rustls::Error as RustlsError;

use crate::config::UnifiConfig;
use crate::error::ClientsError;
use crate::secret::Secret;
use crate::tls::build_client_config;

const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Maximum response body size per request (SPEC-clients.md).
pub const MAX_BODY_BYTES: usize = 8 * 1024 * 1024;

const API_KEY_HEADER: &str = "X-API-KEY";

/// HTTP client bound to one gateway base URL and TLS trust mode.
pub struct GatewayClient {
    http: Client,
    base_url: String,
    api_key: Secret,
}

impl fmt::Debug for GatewayClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GatewayClient")
            .field("base_url", &self.base_url)
            .field("api_key", &self.api_key)
            .finish()
    }
}

impl GatewayClient {
    /// Builds a client from UniFi config and an already-loaded API key.
    pub fn new(cfg: &UnifiConfig, api_key: Secret) -> Result<Self, ClientsError> {
        let tls = build_client_config(&cfg.tls)?;
        let http = Client::builder()
            .use_preconfigured_tls(tls)
            .timeout(REQUEST_TIMEOUT)
            .connect_timeout(CONNECT_TIMEOUT)
            .redirect(Policy::none())
            .build()
            .map_err(|e| ClientsError::Connect {
                message: format!("build HTTP client: {e}"),
            })?;
        let base_url = cfg.base_url.trim_end_matches('/').to_owned();
        if base_url.is_empty() {
            return Err(ClientsError::config("unifi.base_url is empty"));
        }
        Ok(Self {
            http,
            base_url,
            api_key,
        })
    }

    /// Gateway origin without a trailing slash (e.g. `https://192.0.2.1`).
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// `GET {base}{path}` and return the response body (status must be 2xx).
    ///
    /// `path` should begin with `/` (e.g. `/proxy/network/integration/v1/sites`).
    pub async fn get(&self, path: &str) -> Result<Vec<u8>, ClientsError> {
        let url = format!("{}{path}", self.base_url);
        let key = self.api_key.expose();
        let response = self
            .http
            .get(&url)
            .header(API_KEY_HEADER, key)
            .send()
            .await
            .map_err(|e| map_transport(e, key))?;

        let status = response.status();
        let body = read_capped(response, key).await?;
        if !status.is_success() {
            return Err(ClientsError::HttpStatus {
                status: status.as_u16(),
                message: redact(&format!("HTTP {status} from {path}"), key),
            });
        }
        Ok(body)
    }
}

async fn read_capped(mut response: reqwest::Response, key: &str) -> Result<Vec<u8>, ClientsError> {
    if let Some(len) = response.content_length()
        && len > MAX_BODY_BYTES as u64
    {
        return Err(ClientsError::HttpBody {
            message: format!("Content-Length {len} exceeds {MAX_BODY_BYTES} cap"),
        });
    }
    let mut body = Vec::new();
    loop {
        match response.chunk().await {
            Ok(Some(chunk)) => {
                if body.len().saturating_add(chunk.len()) > MAX_BODY_BYTES {
                    return Err(ClientsError::HttpBody {
                        message: format!(
                            "response body exceeds {MAX_BODY_BYTES} cap ({} bytes so far)",
                            body.len() + chunk.len()
                        ),
                    });
                }
                body.extend_from_slice(&chunk);
            }
            Ok(None) => break,
            Err(e) => {
                return Err(ClientsError::HttpBody {
                    message: redact(&format!("read body: {e}"), key),
                });
            }
        }
    }
    Ok(body)
}

fn map_transport(err: reqwest::Error, key: &str) -> ClientsError {
    let msg = redact(&error_chain(&err), key);
    match classify_tls(&err) {
        Some(TlsClass::Untrusted) => ClientsError::TlsUntrusted { message: msg },
        Some(TlsClass::Handshake) => ClientsError::TlsHandshake { message: msg },
        None => ClientsError::Connect { message: msg },
    }
}

enum TlsClass {
    Untrusted,
    Handshake,
}

fn classify_rustls(re: &RustlsError) -> TlsClass {
    match re {
        RustlsError::InvalidCertificate(_) => TlsClass::Untrusted,
        _ => TlsClass::Handshake,
    }
}

/// Walk the `std::error::Error` source chain and unwrap nested [`std::io::Error`]
/// payloads to find a [`RustlsError`].
///
/// hyper-rustls often wraps `rustls::Error` as `io::Error::new(InvalidData, err)`,
/// then another `io::Error` layer — so a plain `source()` walk never sees the
/// typed rustls value without opening `get_ref()`.
fn classify_tls(err: &reqwest::Error) -> Option<TlsClass> {
    let mut cur: Option<&(dyn StdError + 'static)> = Some(err);
    while let Some(e) = cur {
        if let Some(c) = classify_error_node(e) {
            return Some(c);
        }
        cur = e.source();
    }
    None
}

fn classify_error_node(e: &(dyn StdError + 'static)) -> Option<TlsClass> {
    if let Some(re) = e.downcast_ref::<RustlsError>() {
        return Some(classify_rustls(re));
    }
    if let Some(ioe) = e.downcast_ref::<std::io::Error>()
        && let Some(inner) = ioe.get_ref()
    {
        return classify_error_node(inner);
    }
    None
}

fn error_chain(err: &reqwest::Error) -> String {
    let mut parts = vec![err.to_string()];
    let mut cur: Option<&(dyn StdError + 'static)> = err.source();
    while let Some(e) = cur {
        parts.push(e.to_string());
        cur = e.source();
    }
    parts.join(": ")
}

fn redact(text: &str, key: &str) -> String {
    if key.is_empty() {
        text.to_owned()
    } else {
        text.replace(key, "[redacted]")
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn classify_nested_io_rustls_untrusted() {
        let rustls_err = RustlsError::InvalidCertificate(rustls::CertificateError::UnknownIssuer);
        let inner = std::io::Error::new(std::io::ErrorKind::InvalidData, rustls_err);
        let outer = std::io::Error::other(inner);
        assert!(matches!(
            classify_error_node(&outer),
            Some(TlsClass::Untrusted)
        ));
    }

    #[test]
    fn classify_nested_io_rustls_handshake() {
        let rustls_err = RustlsError::DecryptError;
        let inner = std::io::Error::new(std::io::ErrorKind::InvalidData, rustls_err);
        assert!(matches!(
            classify_error_node(&inner),
            Some(TlsClass::Handshake)
        ));
    }
}
