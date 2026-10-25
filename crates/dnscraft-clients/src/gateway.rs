//! HTTPS client for the UniFi OS gateway (Integration + classic surfaces).
//!
//! Defaults: `X-API-KEY` header, 30 s timeout, 8 MiB streamed body cap, no
//! redirects. The API key never appears in error messages or `Debug`.

use std::fmt;
use std::time::Duration;

use reqwest::Client;
use reqwest::redirect::Policy;

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
    // reqwest's Display is often just "error sending request for url (…)";
    // the rustls / certificate detail lives in the `source` chain.
    let raw = error_chain(&err);
    let msg = redact(&raw, key);
    if is_tls_untrusted(&raw) {
        return ClientsError::TlsUntrusted { message: msg };
    }
    if is_tls_handshake(&raw) {
        return ClientsError::TlsHandshake { message: msg };
    }
    if err.is_connect() || err.is_timeout() {
        return ClientsError::Connect { message: msg };
    }
    ClientsError::Connect { message: msg }
}

fn error_chain(err: &reqwest::Error) -> String {
    use std::error::Error as _;
    let mut parts = vec![err.to_string()];
    let mut cur: Option<&(dyn std::error::Error + 'static)> = err.source();
    while let Some(e) = cur {
        parts.push(e.to_string());
        cur = e.source();
    }
    parts.join(": ")
}

fn is_tls_untrusted(msg: &str) -> bool {
    let lower = msg.to_ascii_lowercase();
    lower.contains("applicationverificationfailure")
        || lower.contains("unknownissuer")
        || lower.contains("unknown ca")
        || lower.contains("invalidcertificate")
        || lower.contains("invalid peer certificate")
        || (lower.contains("certificate")
            && (lower.contains("invalid")
                || lower.contains("untrusted")
                || lower.contains("unknown")
                || lower.contains("not valid")))
}

fn is_tls_handshake(msg: &str) -> bool {
    let lower = msg.to_ascii_lowercase();
    (lower.contains("handshake") || lower.contains("tls") || lower.contains("ssl"))
        && !is_tls_untrusted(msg)
}

fn redact(text: &str, key: &str) -> String {
    if key.is_empty() {
        text.to_owned()
    } else {
        text.replace(key, "[redacted]")
    }
}
