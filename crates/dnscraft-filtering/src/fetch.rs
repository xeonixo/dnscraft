//! Downloads filter lists with conditional GET, a streaming size cap and a
//! strict redirect policy.
//!
//! The [`Fetcher`] never writes to the store on its own; [`Fetcher::fetch`]
//! returns a [`FetchOutcome`] and [`Fetcher::fetch_and_store`] persists it.
//! After any failure the last good body stays in the store: only the metadata
//! (attempt time, error) is rewritten.
//!
//! ## Rules
//!
//! - Total timeout 30 s (body included), connect timeout 10 s, at most 5
//!   redirects, and a redirect to anything but `https://` is refused.
//! - The body is read in chunks and aborted as soon as it exceeds the cap.
//!   With `gzip`, the cap applies to the **decompressed** bytes (reqwest
//!   decodes transparently, we count what comes out of it).
//! - Text only: a body with NUL bytes, or with more than 5 % replacement
//!   characters after lossy UTF-8 conversion, is rejected as `not_text`.
//! - `File` sources are read through [`ListStore::read_file_source`]. Change
//!   detection uses an in-memory (length, hash) per list id, so the first
//!   fetch after a restart reports `Updated` once.
//!
//! ## Error codes
//!
//! | Variant | Code |
//! |---|---|
//! | [`FetchError::Timeout`] | `filter_fetch.timeout` |
//! | [`FetchError::Connect`] | `filter_fetch.connect` |
//! | [`FetchError::HttpStatus`] | `filter_fetch.http_status` (param `status`) |
//! | [`FetchError::TooLarge`] | `filter_fetch.too_large` (param `max`) |
//! | [`FetchError::RedirectRefused`] | `filter_fetch.redirect_refused` |
//! | [`FetchError::TooManyRedirects`] | `filter_fetch.too_many_redirects` |
//! | [`FetchError::NotText`] | `filter_fetch.not_text` |
//! | [`FetchError::Tls`] | `filter_fetch.tls` |
//! | [`FetchError::Io`] | `filter_fetch.io` |

use std::collections::hash_map::DefaultHasher;
use std::collections::{BTreeMap, HashMap};
use std::hash::{Hash, Hasher};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use reqwest::header::{
    CONTENT_LENGTH, ETAG, HeaderMap, IF_MODIFIED_SINCE, IF_NONE_MATCH, LAST_MODIFIED,
};
use reqwest::redirect::Policy;
use reqwest::{StatusCode, Url};

use crate::store::{ListMeta, ListSourceSpec, ListStore, MetaError, StoreError};
use crate::types::ListId;

/// Maximum number of redirects followed.
pub const MAX_REDIRECTS: usize = 5;

/// Code stored in the metadata of a services file rejected by validation.
pub(crate) const MALFORMED_SERVICES_CODE: &str = "filter_services.malformed";

/// Share of replacement characters above which a body counts as binary.
const MAX_REPLACEMENT_RATIO: f64 = 0.05;

/// rustls client config with the ring provider and the Mozilla (webpki) roots.
///
/// reqwest 0.13 has no webpki-roots feature and defaults to the platform
/// verifier and aws-lc; this keeps the ring-only, bundled-roots behaviour.
fn webpki_tls_config() -> Result<rustls::ClientConfig, rustls::Error> {
    let roots = rustls::RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    Ok(rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .with_root_certificates(roots)
        .with_no_client_auth())
}

/// A fetch attempt failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum FetchError {
    /// The request did not finish within the total timeout.
    #[error("request timed out")]
    Timeout,
    /// The server could not be reached.
    #[error("connection failed: {0}")]
    Connect(String),
    /// The server answered with a status other than 200 or 304.
    #[error("unexpected HTTP status {0}")]
    HttpStatus(u16),
    /// The body is larger than the cap.
    #[error("body exceeds the size limit of {max} bytes")]
    TooLarge {
        /// The configured cap in bytes.
        max: u64,
    },
    /// A redirect to a non-https (or otherwise disallowed) target.
    #[error("redirect to {target} refused")]
    RedirectRefused {
        /// The refused target URL.
        target: String,
    },
    /// More than [`MAX_REDIRECTS`] redirects.
    #[error("too many redirects")]
    TooManyRedirects,
    /// The body is not text (NUL bytes or mostly invalid UTF-8).
    #[error("body is not text")]
    NotText,
    /// TLS handshake or certificate problem.
    #[error("TLS error: {0}")]
    Tls(String),
    /// Reading a local file, the response stream, or the source failed.
    #[error("I/O error: {0}")]
    Io(String),
}

impl FetchError {
    /// Stable, locale-neutral code exposed through the API.
    pub fn code(&self) -> &'static str {
        match self {
            Self::Timeout => "filter_fetch.timeout",
            Self::Connect(_) => "filter_fetch.connect",
            Self::HttpStatus(_) => "filter_fetch.http_status",
            Self::TooLarge { .. } => "filter_fetch.too_large",
            Self::RedirectRefused { .. } => "filter_fetch.redirect_refused",
            Self::TooManyRedirects => "filter_fetch.too_many_redirects",
            Self::NotText => "filter_fetch.not_text",
            Self::Tls(_) => "filter_fetch.tls",
            Self::Io(_) => "filter_fetch.io",
        }
    }

    /// The form stored in [`ListMeta::last_error`].
    pub fn to_meta_error(&self) -> MetaError {
        let mut params = BTreeMap::new();
        match self {
            Self::HttpStatus(s) => {
                params.insert("status".to_owned(), s.to_string());
            }
            Self::TooLarge { max } => {
                params.insert("max".to_owned(), max.to_string());
            }
            Self::RedirectRefused { target } => {
                params.insert("target".to_owned(), target.clone());
            }
            Self::Connect(d) | Self::Tls(d) | Self::Io(d) => {
                params.insert("detail".to_owned(), d.clone());
            }
            Self::Timeout | Self::TooManyRedirects | Self::NotText => {}
        }
        MetaError {
            code: self.code().to_owned(),
            params,
        }
    }
}

impl From<StoreError> for FetchError {
    fn from(e: StoreError) -> Self {
        match e {
            StoreError::TooLarge { max, .. } => Self::TooLarge { max },
            other => Self::Io(other.to_string()),
        }
    }
}

/// Result of one fetch attempt. `meta` always carries the new attempt time.
#[derive(Debug)]
pub enum FetchOutcome {
    /// New content.
    Updated {
        /// The list text.
        body: String,
        /// Metadata to store with it.
        meta: ListMeta,
    },
    /// The source reported no change; keep the stored body.
    NotModified {
        /// Metadata with refreshed times.
        meta: ListMeta,
    },
    /// The attempt failed; keep the stored body.
    Failed {
        /// Previous metadata with the attempt time and error set.
        meta: ListMeta,
        /// What went wrong.
        error: FetchError,
    },
}

impl FetchOutcome {
    /// The metadata of this outcome.
    pub fn meta(&self) -> &ListMeta {
        match self {
            Self::Updated { meta, .. } | Self::NotModified { meta } | Self::Failed { meta, .. } => {
                meta
            }
        }
    }
}

/// Fetcher settings.
#[derive(Clone, Debug)]
pub struct FetcherConfig {
    /// Total time for a request including the body.
    pub timeout: Duration,
    /// Time to establish the connection.
    pub connect_timeout: Duration,
    /// `User-Agent` header.
    pub user_agent: String,
}

impl Default for FetcherConfig {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(30),
            connect_timeout: Duration::from_secs(10),
            user_agent: format!(
                "DNScraft/{} (+https://github.com/xeonixo/dnscraft)",
                env!("CARGO_PKG_VERSION")
            ),
        }
    }
}

/// Async list downloader. Cheap to clone.
#[derive(Clone, Debug)]
pub struct Fetcher {
    client: reqwest::Client,
    store: ListStore,
    max_body: u64,
    file_state: Arc<Mutex<HashMap<ListId, (usize, u64)>>>,
}

impl Fetcher {
    /// Creates a fetcher with default settings. Size cap, test hatch and
    /// clock come from `store`.
    pub fn new(store: &ListStore) -> Result<Self, FetchError> {
        Self::with_config(store, FetcherConfig::default())
    }

    /// Creates a fetcher with explicit settings.
    pub fn with_config(store: &ListStore, config: FetcherConfig) -> Result<Self, FetchError> {
        let allow_http = store.config().allow_http_for_tests;
        let tls = webpki_tls_config()
            .map_err(|e| FetchError::Io(format!("cannot build TLS config: {e}")))?;
        let client = reqwest::Client::builder()
            .use_preconfigured_tls(tls)
            .user_agent(config.user_agent)
            .timeout(config.timeout)
            .connect_timeout(config.connect_timeout)
            .redirect(redirect_policy(allow_http))
            .gzip(true)
            .build()
            .map_err(|e| FetchError::Io(format!("cannot build HTTP client: {e}")))?;
        Ok(Self {
            client,
            store: store.clone(),
            max_body: store.config().max_body_bytes,
            file_state: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    /// Fetches one list. Never panics and never touches the store.
    pub async fn fetch(
        &self,
        id: &ListId,
        source: &ListSourceSpec,
        prev: Option<&ListMeta>,
    ) -> FetchOutcome {
        self.fetch_capped(id, source, prev, self.max_body).await
    }

    /// [`Self::fetch`] with an explicit size cap for URL bodies.
    async fn fetch_capped(
        &self,
        id: &ListId,
        source: &ListSourceSpec,
        prev: Option<&ListMeta>,
        max_body: u64,
    ) -> FetchOutcome {
        let now = self.store.now_unix();
        let mut meta = prev.cloned().unwrap_or_default();
        meta.last_attempt = Some(now);
        meta.source = Some(match source {
            ListSourceSpec::Url(u) => u.clone(),
            ListSourceSpec::File(p) => p.display().to_string(),
        });
        if let Err(e) = source.validate(self.store.config()) {
            return failed(meta, FetchError::Io(e.to_string()), None);
        }
        match source {
            ListSourceSpec::Url(url) => self.fetch_url(url, prev, meta, now, max_body).await,
            ListSourceSpec::File(path) => self.fetch_file(id, path, meta, now).await,
        }
    }

    /// Fetches a URL into the services catalog cache (`services_dir/{stem}.json`).
    ///
    /// Same conditional GET and last-good rules as list bodies, with its own
    /// size cap `max_body`. Used for `services.json` / `services_i18n.json`.
    ///
    /// A new body is passed to `validate` **before** anything is written. If
    /// it is rejected, the old body *and* the old metadata (including the
    /// ETag) stay on disk; only the attempt time and a
    /// `filter_services.malformed` error are recorded, and the outcome is
    /// [`FetchOutcome::Failed`].
    pub async fn fetch_and_store_services(
        &self,
        store: &ListStore,
        stem: &str,
        url: &str,
        max_body: u64,
        validate: &(dyn Fn(&str) -> Result<(), String> + Sync),
    ) -> FetchOutcome {
        let prev = match store.read_services_meta(stem) {
            Ok(m) => m,
            Err(e) => {
                tracing::warn!(file = stem, error = %e, "cannot read services metadata");
                None
            }
        };
        let source = ListSourceSpec::Url(url.to_owned());
        // Synthetic id for file-fingerprint bookkeeping only (URL path).
        let id = match ListId::new(&stem.replace('_', "-")) {
            Ok(id) => id,
            Err(_) => {
                let mut meta = prev.unwrap_or_default();
                meta.last_attempt = Some(store.now_unix());
                return failed(
                    meta,
                    FetchError::Io("invalid services cache stem".into()),
                    None,
                );
            }
        };
        let outcome = self
            .fetch_capped(&id, &source, prev.as_ref(), max_body)
            .await;
        let outcome = match outcome {
            FetchOutcome::Updated { body, meta } => match validate(&body) {
                Ok(()) => FetchOutcome::Updated { body, meta },
                Err(detail) => {
                    // Keep the old body and old validators (ETag etc.).
                    let mut kept = prev.clone().unwrap_or_default();
                    kept.last_attempt = meta.last_attempt;
                    kept.http_status = meta.http_status;
                    let mut params = BTreeMap::new();
                    params.insert("detail".to_owned(), detail.clone());
                    kept.last_error = Some(MetaError {
                        code: MALFORMED_SERVICES_CODE.to_owned(),
                        params,
                    });
                    FetchOutcome::Failed {
                        meta: kept,
                        error: FetchError::Io(format!("services file rejected: {detail}")),
                    }
                }
            },
            other => other,
        };
        let (result, outcome) = match outcome {
            FetchOutcome::Updated { body, meta } => {
                let r = store.write_services_body(stem, &body, &meta);
                match r {
                    Ok(()) => (Ok(()), FetchOutcome::Updated { body, meta }),
                    Err(e) => {
                        let error = FetchError::from(e);
                        let mut meta = meta;
                        meta.last_error = Some(error.to_meta_error());
                        (Ok(()), FetchOutcome::Failed { meta, error })
                    }
                }
            }
            other => (store.write_services_meta(stem, other.meta()), other),
        };
        if let Err(e) = result {
            tracing::warn!(file = stem, error = %e, "cannot write services metadata");
        }
        outcome
    }

    /// Fetches and persists: body and metadata on `Updated`, metadata only
    /// otherwise (the last good body stays). A store write failure on
    /// `Updated` turns into `Failed` so the caller does not use the new body
    /// as if it were saved.
    pub async fn fetch_and_store(
        &self,
        store: &ListStore,
        id: &ListId,
        source: &ListSourceSpec,
    ) -> FetchOutcome {
        let prev = match store.read_meta(id) {
            Ok(m) => m,
            Err(e) => {
                tracing::warn!(list = %id, error = %e, "cannot read list metadata");
                None
            }
        };
        let outcome = self.fetch(id, source, prev.as_ref()).await;
        let (result, outcome) = match outcome {
            FetchOutcome::Updated { body, meta } => {
                let r = store.write_body(id, &body, &meta);
                match r {
                    Ok(()) => (Ok(()), FetchOutcome::Updated { body, meta }),
                    Err(e) => {
                        let error = FetchError::from(e);
                        let mut meta = meta;
                        meta.last_error = Some(error.to_meta_error());
                        (Ok(()), FetchOutcome::Failed { meta, error })
                    }
                }
            }
            other => (store.write_meta(id, other.meta()), other),
        };
        if let Err(e) = result {
            tracing::warn!(list = %id, error = %e, "cannot write list metadata");
        }
        outcome
    }

    async fn fetch_url(
        &self,
        url: &str,
        prev: Option<&ListMeta>,
        mut meta: ListMeta,
        now: u64,
        max_body: u64,
    ) -> FetchOutcome {
        let mut req = self.client.get(url);
        if let Some(prev) = prev {
            if let Some(etag) = &prev.etag {
                req = req.header(IF_NONE_MATCH, etag);
            }
            if let Some(lm) = &prev.last_modified {
                req = req.header(IF_MODIFIED_SINCE, lm);
            }
        }
        let mut resp = match req.send().await {
            Ok(r) => r,
            Err(e) => return failed(meta, classify(&e), None),
        };
        let status = resp.status();
        meta.http_status = Some(status.as_u16());
        if status == StatusCode::NOT_MODIFIED {
            meta.last_success = Some(now);
            meta.last_error = None;
            return FetchOutcome::NotModified { meta };
        }
        if status != StatusCode::OK {
            return failed(meta, FetchError::HttpStatus(status.as_u16()), Some(status));
        }
        if declared_length(resp.headers()).is_some_and(|n| n > max_body) {
            return failed(meta, FetchError::TooLarge { max: max_body }, Some(status));
        }
        let etag = header_string(resp.headers(), &ETAG);
        let last_modified = header_string(resp.headers(), &LAST_MODIFIED);

        let mut bytes: Vec<u8> = Vec::new();
        loop {
            match resp.chunk().await {
                Ok(Some(chunk)) => {
                    if (bytes.len() as u64).saturating_add(chunk.len() as u64) > max_body {
                        // Dropping `resp` closes the connection.
                        return failed(meta, FetchError::TooLarge { max: max_body }, Some(status));
                    }
                    bytes.extend_from_slice(&chunk);
                }
                Ok(None) => break,
                Err(e) => return failed(meta, classify(&e), Some(status)),
            }
        }
        match decode_text(bytes) {
            Ok(body) => {
                meta.etag = etag;
                meta.last_modified = last_modified;
                meta.last_success = Some(now);
                meta.last_error = None;
                FetchOutcome::Updated { body, meta }
            }
            Err(e) => failed(meta, e, Some(status)),
        }
    }

    async fn fetch_file(
        &self,
        id: &ListId,
        path: &std::path::Path,
        mut meta: ListMeta,
        now: u64,
    ) -> FetchOutcome {
        let store = self.store.clone();
        let path = path.to_path_buf();
        let read = tokio::task::spawn_blocking(move || store.read_file_source(&path)).await;
        let text = match read {
            Ok(Ok(t)) => t,
            Ok(Err(e)) => return failed(meta, e.into(), None),
            Err(e) => return failed(meta, FetchError::Io(format!("read task failed: {e}")), None),
        };
        if let Err(e) = check_text(&text) {
            return failed(meta, e, None);
        }
        meta.http_status = None;
        meta.etag = None;
        meta.last_modified = None;
        meta.last_success = Some(now);
        meta.last_error = None;
        let fingerprint = (text.len(), hash_of(&text));
        let changed = {
            let mut state = self
                .file_state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            state.insert(id.clone(), fingerprint) != Some(fingerprint)
        };
        if changed {
            FetchOutcome::Updated { body: text, meta }
        } else {
            FetchOutcome::NotModified { meta }
        }
    }
}

fn failed(mut meta: ListMeta, error: FetchError, status: Option<StatusCode>) -> FetchOutcome {
    meta.last_error = Some(error.to_meta_error());
    meta.http_status = status.map(|s| s.as_u16());
    FetchOutcome::Failed { meta, error }
}

fn header_string(headers: &HeaderMap, name: &reqwest::header::HeaderName) -> Option<String> {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned)
}

/// `Content-Length`, which for a compressed response is the compressed size
/// (a lower bound of the decoded size only in practice; the stream count is
/// authoritative).
fn declared_length(headers: &HeaderMap) -> Option<u64> {
    headers
        .get(CONTENT_LENGTH)?
        .to_str()
        .ok()?
        .trim()
        .parse()
        .ok()
}

fn hash_of(text: &str) -> u64 {
    let mut h = DefaultHasher::new();
    text.hash(&mut h);
    h.finish()
}

/// Marker errors raised by the redirect policy.
#[derive(Debug)]
enum RedirectFailure {
    Refused(String),
    TooMany,
}

impl std::fmt::Display for RedirectFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Refused(t) => write!(f, "redirect to {t} refused"),
            Self::TooMany => write!(f, "too many redirects"),
        }
    }
}

impl std::error::Error for RedirectFailure {}

fn redirect_policy(allow_http_for_tests: bool) -> Policy {
    Policy::custom(move |attempt| {
        // `previous` holds the URLs visited so far; the first redirect sees 1.
        if attempt.previous().len() > MAX_REDIRECTS {
            return attempt.error(RedirectFailure::TooMany);
        }
        let target = attempt.url();
        let allowed = match target.scheme() {
            "https" => true,
            "http" => allow_http_for_tests && is_loopback_host(target),
            _ => false,
        };
        if allowed {
            attempt.follow()
        } else {
            let shown = target.to_string();
            attempt.error(RedirectFailure::Refused(shown))
        }
    })
}

fn is_loopback_host(url: &Url) -> bool {
    let Some(host) = url.host_str() else {
        return false;
    };
    let host = host.trim_start_matches('[').trim_end_matches(']');
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())
}

/// True when `err` or any of its sources is a [`rustls::Error`], including when
/// nested inside [`std::io::Error::get_ref`].
fn chain_contains_rustls(err: &(dyn std::error::Error + 'static)) -> bool {
    let mut source = Some(err);
    while let Some(e) = source {
        if e.downcast_ref::<rustls::Error>().is_some() {
            return true;
        }
        if let Some(io) = e.downcast_ref::<std::io::Error>()
            && let Some(inner) = io.get_ref()
            && (inner.downcast_ref::<rustls::Error>().is_some() || chain_contains_rustls(inner))
        {
            return true;
        }
        source = e.source();
    }
    false
}

/// Maps a reqwest error to a stable [`FetchError`].
///
/// Walks [`std::error::Error::source`] and downcasts to [`rustls::Error`] /
/// I/O kinds instead of matching message text.
fn classify(err: &reqwest::Error) -> FetchError {
    let mut source: Option<&(dyn std::error::Error + 'static)> = Some(err);
    let mut chain = String::new();
    while let Some(e) = source {
        if let Some(r) = e.downcast_ref::<RedirectFailure>() {
            return match r {
                RedirectFailure::Refused(t) => FetchError::RedirectRefused { target: t.clone() },
                RedirectFailure::TooMany => FetchError::TooManyRedirects,
            };
        }
        if !chain.is_empty() {
            chain.push_str(": ");
        }
        chain.push_str(&e.to_string());
        source = e.source();
    }
    if err.is_timeout() {
        return FetchError::Timeout;
    }
    if chain_contains_rustls(err) {
        return FetchError::Tls(chain);
    }
    if err.is_connect() {
        return FetchError::Connect(chain);
    }
    if err.is_redirect() {
        return FetchError::TooManyRedirects;
    }
    FetchError::Io(chain)
}

/// Converts a downloaded body to text, rejecting binary garbage.
fn decode_text(bytes: Vec<u8>) -> Result<String, FetchError> {
    if bytes.contains(&0) {
        return Err(FetchError::NotText);
    }
    match String::from_utf8(bytes) {
        Ok(s) => Ok(s),
        Err(e) => {
            let text = String::from_utf8_lossy(e.as_bytes()).into_owned();
            let replaced = replacement_count(&text);
            check_text(&text)?;
            tracing::warn!(replaced, "list body is not valid UTF-8, converted lossily");
            Ok(text)
        }
    }
}

fn replacement_count(text: &str) -> usize {
    text.chars().filter(|&c| c == '\u{FFFD}').count()
}

/// NUL bytes or too many replacement characters mean "not a text list".
fn check_text(text: &str) -> Result<(), FetchError> {
    if text.contains('\0') {
        return Err(FetchError::NotText);
    }
    let total = text.chars().count();
    if total > 0 && (replacement_count(text) as f64) / (total as f64) > MAX_REPLACEMENT_RATIO {
        return Err(FetchError::NotText);
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn fetch_error_codes_are_unique_and_prefixed() {
        let errs = [
            FetchError::Timeout,
            FetchError::Connect("c".into()),
            FetchError::HttpStatus(404),
            FetchError::TooLarge { max: 1 },
            FetchError::RedirectRefused { target: "t".into() },
            FetchError::TooManyRedirects,
            FetchError::NotText,
            FetchError::Tls("t".into()),
            FetchError::Io("i".into()),
        ];
        let mut seen = std::collections::HashSet::new();
        for e in &errs {
            assert!(e.code().starts_with("filter_fetch."));
            assert!(seen.insert(e.code()), "duplicate {}", e.code());
            assert!(!e.to_string().is_empty());
            assert_eq!(e.to_meta_error().code, e.code());
        }
        assert_eq!(
            FetchError::HttpStatus(503).to_meta_error().params["status"],
            "503"
        );
    }

    #[test]
    fn decode_text_rules() {
        assert_eq!(decode_text(b"ok\n".to_vec()).unwrap(), "ok\n");
        assert_eq!(decode_text(b"a\0b".to_vec()), Err(FetchError::NotText));
        // One stray byte in a long text is tolerated.
        let mut ok = vec![b'a'; 100];
        ok.push(0xff);
        assert!(decode_text(ok).unwrap().contains('\u{FFFD}'));
        // Mostly invalid bytes are garbage.
        assert_eq!(decode_text(vec![0xff; 100]), Err(FetchError::NotText));
    }
}
