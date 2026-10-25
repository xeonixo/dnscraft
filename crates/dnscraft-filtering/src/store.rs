//! On-disk store for filter list bodies and their metadata.
//!
//! Layout below the data directory:
//!
//! ```text
//! <data_dir>/filtering/lists/<list_id>.txt        list body
//! <data_dir>/filtering/lists/<list_id>.meta.json  versioned metadata
//! <data_dir>/filtering/services/                  blocked-services catalog (Task L4)
//! ```
//!
//! The store is **synchronous**; async callers run it on a blocking thread.
//!
//! ## Crash safety
//!
//! `write_body` / `write_meta` write to a temporary file in the same
//! directory, `fsync` it, `rename` it over the target and `fsync` the
//! directory (unix). A crash or I/O failure at any point leaves either the old
//! or the new file, never a torn one. The body is written before the metadata;
//! if only the metadata write fails, the new body is paired with the old
//! metadata, which at worst causes a redundant conditional re-fetch.
//!
//! ## Recovery
//!
//! Metadata that is not valid JSON or has an unknown `version` is treated as
//! absent (`Ok(None)` plus a `tracing` warning) so the caller can schedule a
//! re-fetch. It is never a panic or a startup failure.
//!
//! ## Error codes
//!
//! | Variant | Code |
//! |---|---|
//! | [`StoreError::Io`] | `filter_store.io` |
//! | [`StoreError::TooLarge`] | `filter_store.too_large` |
//! | [`StoreError::InvalidSource`] | `filter_store.invalid_source` |
//! | [`StoreError::Serialize`] | `filter_store.serialize` |

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::fs;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};
use std::time::UNIX_EPOCH;

use serde::{Deserialize, Serialize};

use crate::clock::{Clock, SystemClock};
use crate::set::ListBodies;
use crate::types::ListId;

/// Entries kept in the on-disk rule-line LRU.
const LINE_LRU_CAP: usize = 64;

/// Default maximum size of a list body: 64 MiB.
pub const DEFAULT_MAX_BODY_BYTES: u64 = 64 * 1024 * 1024;

/// Current metadata format version.
pub const META_VERSION: u32 = 1;

/// A store operation failed.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum StoreError {
    /// A filesystem operation failed.
    #[error("{op} {path}: {source}")]
    Io {
        /// What was attempted.
        op: &'static str,
        /// The path involved.
        path: PathBuf,
        /// The underlying error.
        #[source]
        source: io::Error,
    },
    /// A body is larger than the configured cap.
    #[error("{path} exceeds the size limit of {max} bytes")]
    TooLarge {
        /// The offending path.
        path: PathBuf,
        /// The configured cap in bytes.
        max: u64,
    },
    /// A list source is neither an allowed URL nor a usable file path.
    #[error("invalid list source: {reason}")]
    InvalidSource {
        /// Why it was rejected.
        reason: &'static str,
    },
    /// Metadata could not be serialized.
    #[error("cannot serialize metadata: {0}")]
    Serialize(#[from] serde_json::Error),
}

impl StoreError {
    /// Stable, locale-neutral code exposed through the API.
    pub fn code(&self) -> &'static str {
        match self {
            Self::Io { .. } => "filter_store.io",
            Self::TooLarge { .. } => "filter_store.too_large",
            Self::InvalidSource { .. } => "filter_store.invalid_source",
            Self::Serialize(_) => "filter_store.serialize",
        }
    }

    fn io(op: &'static str, path: &Path, source: io::Error) -> Self {
        Self::Io {
            op,
            path: path.to_path_buf(),
            source,
        }
    }
}

/// Store configuration.
#[derive(Clone, Debug)]
pub struct StoreConfig {
    /// Maximum accepted body size in bytes (store files and local file lists).
    pub max_body_bytes: u64,
    /// Accept `http://` URLs. Only for the local test server of the fetcher.
    #[doc(hidden)]
    pub allow_http_for_tests: bool,
}

impl Default for StoreConfig {
    fn default() -> Self {
        Self {
            max_body_bytes: DEFAULT_MAX_BODY_BYTES,
            allow_http_for_tests: false,
        }
    }
}

/// Where a list comes from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ListSourceSpec {
    /// An `https://` URL, fetched and cached in the store.
    Url(String),
    /// A local file, read directly and never copied into the store.
    File(PathBuf),
}

impl ListSourceSpec {
    /// Validates the source against `config`.
    pub fn validate(&self, config: &StoreConfig) -> Result<(), StoreError> {
        match self {
            Self::Url(url) => {
                let lower = url.to_ascii_lowercase();
                let rest = if let Some(r) = lower.strip_prefix("https://") {
                    r
                } else if config.allow_http_for_tests {
                    lower
                        .strip_prefix("http://")
                        .ok_or(StoreError::InvalidSource {
                            reason: "url must start with https://",
                        })?
                } else {
                    return Err(StoreError::InvalidSource {
                        reason: "url must start with https://",
                    });
                };
                if rest.is_empty() || rest.starts_with('/') || rest.chars().any(char::is_whitespace)
                {
                    return Err(StoreError::InvalidSource {
                        reason: "url has no valid host",
                    });
                }
                Ok(())
            }
            Self::File(path) => {
                if path.as_os_str().is_empty() {
                    return Err(StoreError::InvalidSource {
                        reason: "file path is empty",
                    });
                }
                Ok(())
            }
        }
    }
}

/// Error recorded in the metadata: stable code plus parameters.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MetaError {
    /// Stable error code, e.g. `filter_fetch.timeout`.
    pub code: String,
    /// Parameters for the localized message.
    #[serde(default)]
    pub params: BTreeMap<String, String>,
}

/// Metadata stored next to a list body. Times are unix seconds.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListMeta {
    /// Format version; see [`META_VERSION`].
    pub version: u32,
    /// URL or file path the list was loaded from.
    #[serde(default)]
    pub source: Option<String>,
    /// `ETag` response header of the last successful download.
    #[serde(default)]
    pub etag: Option<String>,
    /// `Last-Modified` response header of the last successful download.
    #[serde(default)]
    pub last_modified: Option<String>,
    /// Time of the last update attempt.
    #[serde(default)]
    pub last_attempt: Option<u64>,
    /// Time of the last successful update.
    #[serde(default)]
    pub last_success: Option<u64>,
    /// Error of the last attempt, if it failed.
    #[serde(default)]
    pub last_error: Option<MetaError>,
    /// HTTP status of the last attempt.
    #[serde(default)]
    pub http_status: Option<u16>,
    /// Rules accepted by the parser.
    #[serde(default)]
    pub rules_parsed: u64,
    /// Rules skipped by the parser.
    #[serde(default)]
    pub rules_skipped: u64,
}

impl Default for ListMeta {
    fn default() -> Self {
        Self {
            version: META_VERSION,
            source: None,
            etag: None,
            last_modified: None,
            last_attempt: None,
            last_success: None,
            last_error: None,
            http_status: None,
            rules_parsed: 0,
            rules_skipped: 0,
        }
    }
}

/// Handle to the filtering directory below a data directory.
#[derive(Clone, Debug)]
pub struct ListStore {
    lists_dir: PathBuf,
    services_dir: PathBuf,
    config: StoreConfig,
    clock: Arc<dyn Clock>,
}

impl ListStore {
    /// Opens (and creates) the store below `data_dir` with default config and
    /// the system clock.
    pub fn open(data_dir: &Path) -> Result<Self, StoreError> {
        Self::open_with(data_dir, StoreConfig::default(), Arc::new(SystemClock))
    }

    /// Opens the store with explicit config and clock.
    pub fn open_with(
        data_dir: &Path,
        config: StoreConfig,
        clock: Arc<dyn Clock>,
    ) -> Result<Self, StoreError> {
        let root = data_dir.join("filtering");
        let lists_dir = root.join("lists");
        let services_dir = root.join("services");
        create_private_dir(&lists_dir)?;
        create_private_dir(&services_dir)?;
        Ok(Self {
            lists_dir,
            services_dir,
            config,
            clock,
        })
    }

    /// Directory for the blocked-services catalog (used by Task L4).
    pub fn services_dir(&self) -> &Path {
        &self.services_dir
    }

    /// Path of a cached services-catalog body (`{stem}.json`).
    pub fn services_body_path(&self, stem: &str) -> PathBuf {
        self.services_dir.join(format!("{stem}.json"))
    }

    fn services_meta_path(&self, stem: &str) -> PathBuf {
        self.services_dir.join(format!("{stem}.meta.json"))
    }

    /// Reads a cached services-catalog body (`None` if absent).
    pub fn read_services_body(&self, stem: &str) -> Result<Option<String>, StoreError> {
        crate::services::validate_stem(stem)?;
        read_capped(&self.services_body_path(stem), self.config.max_body_bytes)
    }

    /// Atomically replaces a services-catalog body, then its metadata.
    pub fn write_services_body(
        &self,
        stem: &str,
        body: &str,
        meta: &ListMeta,
    ) -> Result<(), StoreError> {
        crate::services::validate_stem(stem)?;
        if body.len() as u64 > self.config.max_body_bytes {
            return Err(StoreError::TooLarge {
                path: self.services_body_path(stem),
                max: self.config.max_body_bytes,
            });
        }
        atomic_write(&self.services_body_path(stem), body.as_bytes())?;
        self.write_services_meta(stem, meta)
    }

    /// Atomically replaces services-catalog metadata only.
    pub fn write_services_meta(&self, stem: &str, meta: &ListMeta) -> Result<(), StoreError> {
        crate::services::validate_stem(stem)?;
        let json = serde_json::to_vec_pretty(meta)?;
        atomic_write(&self.services_meta_path(stem), &json)
    }

    /// Reads services-catalog metadata (corrupt → `Ok(None)` + warn).
    pub fn read_services_meta(&self, stem: &str) -> Result<Option<ListMeta>, StoreError> {
        crate::services::validate_stem(stem)?;
        let path = self.services_meta_path(stem);
        let text = match read_capped(&path, 1024 * 1024) {
            Ok(Some(t)) => t,
            Ok(None) => return Ok(None),
            Err(StoreError::TooLarge { .. }) => {
                tracing::warn!(file = stem, "services metadata too large, ignoring");
                return Ok(None);
            }
            Err(e) => return Err(e),
        };
        match serde_json::from_str::<ListMeta>(&text) {
            Ok(meta) if meta.version == META_VERSION => Ok(Some(meta)),
            Ok(meta) => {
                tracing::warn!(
                    file = stem,
                    version = meta.version,
                    "unsupported services metadata version, ignoring"
                );
                Ok(None)
            }
            Err(e) => {
                tracing::warn!(file = stem, error = %e, "corrupt services metadata, ignoring");
                Ok(None)
            }
        }
    }

    /// The configuration in effect.
    pub fn config(&self) -> &StoreConfig {
        &self.config
    }

    /// Current time in unix seconds, from the injected clock.
    pub fn now_unix(&self) -> u64 {
        self.clock
            .now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs())
    }

    /// Path of the cached body file (may not exist yet).
    pub fn body_path(&self, id: &ListId) -> PathBuf {
        self.lists_dir.join(format!("{id}.txt"))
    }

    fn meta_path(&self, id: &ListId) -> PathBuf {
        self.lists_dir.join(format!("{id}.meta.json"))
    }

    /// Reads the cached body, `None` if there is none. Files above the size
    /// cap are refused with [`StoreError::TooLarge`].
    pub fn read_body(&self, id: &ListId) -> Result<Option<String>, StoreError> {
        read_capped(&self.body_path(id), self.config.max_body_bytes)
    }

    /// Seeks to `offset` in the cached body and returns `(1-based line, text)`.
    ///
    /// Counts newlines from the start of the file up to `offset`. Missing or
    /// unreadable files yield `None` (never an error).
    pub fn read_rule_at(&self, id: &ListId, offset: u32) -> Option<(u32, Arc<str>)> {
        read_rule_at_path(&self.body_path(id), offset)
    }

    /// Reads a local file list directly (same size cap, never copied).
    pub fn read_file_source(&self, path: &Path) -> Result<String, StoreError> {
        read_capped(path, self.config.max_body_bytes)?.ok_or_else(|| {
            StoreError::io(
                "read",
                path,
                io::Error::new(io::ErrorKind::NotFound, "file not found"),
            )
        })
    }

    /// Atomically replaces the body, then the metadata.
    pub fn write_body(&self, id: &ListId, body: &str, meta: &ListMeta) -> Result<(), StoreError> {
        if body.len() as u64 > self.config.max_body_bytes {
            return Err(StoreError::TooLarge {
                path: self.body_path(id),
                max: self.config.max_body_bytes,
            });
        }
        atomic_write(&self.body_path(id), body.as_bytes())?;
        self.write_meta(id, meta)
    }

    /// Atomically replaces the metadata only (e.g. after a failed attempt).
    pub fn write_meta(&self, id: &ListId, meta: &ListMeta) -> Result<(), StoreError> {
        let json = serde_json::to_vec_pretty(meta)?;
        atomic_write(&self.meta_path(id), &json)
    }

    /// Reads the metadata. Missing, corrupt, oversized or future-version
    /// metadata yields `Ok(None)` (the latter three with a warning).
    pub fn read_meta(&self, id: &ListId) -> Result<Option<ListMeta>, StoreError> {
        let path = self.meta_path(id);
        // Metadata is small; a tampered huge file counts as corrupt.
        let text = match read_capped(&path, 1024 * 1024) {
            Ok(Some(t)) => t,
            Ok(None) => return Ok(None),
            Err(StoreError::TooLarge { .. }) => {
                tracing::warn!(list = %id, "list metadata too large, ignoring");
                return Ok(None);
            }
            Err(e) => return Err(e),
        };
        match serde_json::from_str::<ListMeta>(&text) {
            Ok(meta) if meta.version == META_VERSION => Ok(Some(meta)),
            Ok(meta) => {
                tracing::warn!(list = %id, version = meta.version, "unsupported list metadata version, ignoring");
                Ok(None)
            }
            Err(e) => {
                tracing::warn!(list = %id, error = %e, "corrupt list metadata, ignoring");
                Ok(None)
            }
        }
    }

    /// Removes body and metadata; missing files are fine.
    pub fn remove(&self, id: &ListId) -> Result<(), StoreError> {
        for path in [self.body_path(id), self.meta_path(id)] {
            match fs::remove_file(&path) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(StoreError::io("remove", &path, e)),
            }
        }
        sync_dir(&self.lists_dir);
        Ok(())
    }

    /// Ids that have a body or metadata in the store, sorted. Files with
    /// names that are not valid ids are ignored.
    pub fn list_ids(&self) -> Result<Vec<ListId>, StoreError> {
        let rd = fs::read_dir(&self.lists_dir)
            .map_err(|e| StoreError::io("read_dir", &self.lists_dir, e))?;
        let mut ids = std::collections::BTreeSet::new();
        for entry in rd {
            let entry = entry.map_err(|e| StoreError::io("read_dir", &self.lists_dir, e))?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            let stem = name
                .strip_suffix(".meta.json")
                .or_else(|| name.strip_suffix(".txt"));
            if let Some(id) = stem.and_then(|s| ListId::new(s).ok()) {
                ids.insert(id);
            }
        }
        Ok(ids.into_iter().collect())
    }
}

/// [`ListBodies`] over a [`ListStore`], with optional local-file fallbacks and
/// a small LRU of recently read rule lines (seek/pread, never the whole file
/// for Reasons).
#[derive(Debug)]
pub struct StoreListBodies {
    store: ListStore,
    /// Local file paths for lists whose body is not yet cached (File sources).
    files: RwLock<HashMap<ListId, PathBuf>>,
    line_cache: Mutex<LineLru>,
}

impl StoreListBodies {
    /// Bodies from `store`, falling back to `files` when the cache is empty.
    pub fn new(store: ListStore, files: HashMap<ListId, PathBuf>) -> Self {
        Self {
            store,
            files: RwLock::new(files),
            line_cache: Mutex::new(LineLru::new(LINE_LRU_CAP)),
        }
    }

    /// The underlying store.
    pub fn store(&self) -> &ListStore {
        &self.store
    }

    /// Rebuilds the file-fallback map from list configs.
    pub fn set_files(&self, files: HashMap<ListId, PathBuf>) {
        *self
            .files
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = files;
    }

    fn path_for(&self, id: &ListId) -> Option<PathBuf> {
        let cached = self.store.body_path(id);
        if cached.is_file() {
            return Some(cached);
        }
        self.files
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(id)
            .cloned()
            .filter(|p| p.is_file())
    }
}

impl ListBodies for StoreListBodies {
    fn body(&self, id: &ListId) -> Option<Arc<str>> {
        match self.store.read_body(id) {
            Ok(Some(s)) => return Some(Arc::from(s)),
            Ok(None) => {}
            Err(e) => {
                tracing::warn!(list = %id, error = %e, "cannot read cached list body");
            }
        }
        let path = {
            let files = self
                .files
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            files.get(id).cloned()
        }?;
        match self.store.read_file_source(&path) {
            Ok(s) => Some(Arc::from(s)),
            Err(e) => {
                tracing::warn!(list = %id, path = %path.display(), error = %e, "cannot read file list");
                None
            }
        }
    }

    fn rule_at(&self, id: &ListId, offset: u32) -> Option<(u32, Arc<str>)> {
        {
            let mut cache = self
                .line_cache
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Some(hit) = cache.get(id, offset) {
                return Some(hit);
            }
        }
        let path = self.path_for(id)?;
        let got = read_rule_at_path(&path, offset)?;
        let mut cache = self
            .line_cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        cache.insert(id.clone(), offset, got.clone());
        Some(got)
    }
}

#[derive(Debug)]
struct LineLru {
    cap: usize,
    order: VecDeque<(ListId, u32)>,
    map: HashMap<(ListId, u32), (u32, Arc<str>)>,
}

impl LineLru {
    fn new(cap: usize) -> Self {
        Self {
            cap: cap.max(1),
            order: VecDeque::new(),
            map: HashMap::new(),
        }
    }

    fn get(&mut self, id: &ListId, offset: u32) -> Option<(u32, Arc<str>)> {
        let key = (id.clone(), offset);
        let val = self.map.get(&key)?.clone();
        if let Some(pos) = self.order.iter().position(|k| k == &key) {
            self.order.remove(pos);
        }
        self.order.push_back(key);
        Some(val)
    }

    fn insert(&mut self, id: ListId, offset: u32, val: (u32, Arc<str>)) {
        let key = (id, offset);
        if self.map.insert(key.clone(), val).is_some() {
            if let Some(pos) = self.order.iter().position(|k| k == &key) {
                self.order.remove(pos);
            }
        }
        self.order.push_back(key);
        while self.order.len() > self.cap {
            if let Some(old) = self.order.pop_front() {
                self.map.remove(&old);
            }
        }
    }
}

/// Seeks to `offset` in `path`, counts newlines before it, reads one line.
fn read_rule_at_path(path: &Path, offset: u32) -> Option<(u32, Arc<str>)> {
    let mut file = fs::File::open(path).ok()?;
    let mut remaining = offset as u64;
    let mut newlines: u32 = 0;
    let mut buf = [0u8; 8192];
    while remaining > 0 {
        let chunk = remaining.min(buf.len() as u64) as usize;
        let n = file.read(&mut buf[..chunk]).ok()?;
        if n == 0 {
            return None;
        }
        newlines += buf[..n].iter().filter(|&&b| b == b'\n').count() as u32;
        remaining -= n as u64;
    }
    // Position is already at `offset` after the sequential read.
    let _ = file.seek(SeekFrom::Start(u64::from(offset))).ok()?;
    let mut line_buf: Vec<u8> = Vec::new();
    let mut one = [0u8; 1];
    loop {
        match file.read(&mut one) {
            Ok(0) => break,
            Ok(_) if one[0] == b'\n' => break,
            Ok(_) => line_buf.push(one[0]),
            Err(_) => return None,
        }
        if line_buf.len() > 4096 {
            break;
        }
    }
    let text = match String::from_utf8(line_buf) {
        Ok(s) => s,
        Err(e) => String::from_utf8_lossy(e.as_bytes()).into_owned(),
    };
    let text = text.trim_end_matches([' ', '\t', '\r']);
    Some((newlines.saturating_add(1), Arc::from(text)))
}

/// Reads `path` as text, refusing more than `max` bytes. `None` if missing.
/// Invalid UTF-8 is replaced lossily so one stray byte does not lose a list.
fn read_capped(path: &Path, max: u64) -> Result<Option<String>, StoreError> {
    let file = match fs::File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(StoreError::io("open", path, e)),
    };
    let too_large = || StoreError::TooLarge {
        path: path.to_path_buf(),
        max,
    };
    if let Ok(md) = file.metadata() {
        if md.len() > max {
            return Err(too_large());
        }
    }
    // The length check above can race with a growing file; cap the read too.
    let mut buf = Vec::new();
    file.take(max + 1)
        .read_to_end(&mut buf)
        .map_err(|e| StoreError::io("read", path, e))?;
    if buf.len() as u64 > max {
        return Err(too_large());
    }
    Ok(Some(match String::from_utf8(buf) {
        Ok(s) => s,
        Err(e) => String::from_utf8_lossy(e.as_bytes()).into_owned(),
    }))
}

/// Temporary sibling path used by [`atomic_write`].
fn tmp_path(path: &Path) -> PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(".tmp");
    path.with_file_name(name)
}

/// Writes `data` to a temp file, fsyncs, renames over `path`, fsyncs the dir.
/// On failure the temp file is removed and `path` is untouched.
fn atomic_write(path: &Path, data: &[u8]) -> Result<(), StoreError> {
    let tmp = tmp_path(path);
    let result = (|| {
        let mut file = fs::File::create(&tmp).map_err(|e| StoreError::io("create", &tmp, e))?;
        file.write_all(data)
            .map_err(|e| StoreError::io("write", &tmp, e))?;
        file.sync_all()
            .map_err(|e| StoreError::io("fsync", &tmp, e))?;
        drop(file);
        fs::rename(&tmp, path).map_err(|e| StoreError::io("rename", path, e))
    })();
    match result {
        Ok(()) => {
            if let Some(dir) = path.parent() {
                sync_dir(dir);
            }
            Ok(())
        }
        Err(e) => {
            let _ = fs::remove_file(&tmp);
            Err(e)
        }
    }
}

/// Best-effort directory fsync so a rename survives power loss (unix only).
fn sync_dir(dir: &Path) {
    #[cfg(unix)]
    if let Ok(d) = fs::File::open(dir) {
        let _ = d.sync_all();
    }
    #[cfg(not(unix))]
    let _ = dir;
}

/// Creates `dir` and missing parents; new directories get mode 0o700 on unix.
fn create_private_dir(dir: &Path) -> Result<(), StoreError> {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder
        .create(dir)
        .map_err(|e| StoreError::io("create_dir", dir, e))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn store_error_codes_are_unique_and_prefixed() {
        let errs = [
            StoreError::io("x", Path::new("p"), io::Error::other("e")),
            StoreError::TooLarge {
                path: "p".into(),
                max: 1,
            },
            StoreError::InvalidSource { reason: "r" },
            StoreError::Serialize(serde_json::from_str::<u8>("x").unwrap_err()),
        ];
        let mut seen = std::collections::HashSet::new();
        for e in &errs {
            assert!(e.code().starts_with("filter_store."));
            assert!(seen.insert(e.code()));
            assert!(!e.to_string().is_empty());
        }
    }
}
