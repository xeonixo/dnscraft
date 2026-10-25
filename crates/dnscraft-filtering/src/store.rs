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

use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::clock::{Clock, SystemClock};
use crate::set::{ListBodies, ListText, OpenedList};
use crate::types::ListId;

/// Spacing of the newline checkpoints of a pinned list body: the line number
/// of any offset needs at most one block of bytes after a checkpoint.
const TEXT_BLOCK: usize = 4096;

/// Longest rule text read from disk; longer lines are cut.
const LINE_TEXT_MAX: usize = 4096;

/// Rule texts cached per pinned list body.
const TEXT_CACHE_CAP: usize = 4096;

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

    /// Reads the line at `offset` in the cached body and returns
    /// `(1-based line, text)`.
    ///
    /// Counts newlines from the start of the file up to `offset` (in large
    /// positional reads), so the cost grows with `offset`; snapshots use the
    /// pinned, checkpointed reader of [`StoreListBodies::open`] instead.
    /// Missing or unreadable files yield `None` (never an error).
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

/// [`ListBodies`] over a [`ListStore`], with optional local-file fallbacks.
///
/// [`ListBodies::open`] returns the body together with a reader that keeps the
/// file handle open and records a newline checkpoint every [`TEXT_BLOCK`]
/// bytes, so rule text for a `Reason` costs one small positional read no
/// matter where the rule sits, and always comes from the bytes the snapshot
/// was built from (an atomic rename of a newer body leaves the old inode
/// readable through the handle).
#[derive(Debug)]
pub struct StoreListBodies {
    store: ListStore,
    /// Local file paths for lists whose body is not yet cached (File sources).
    files: RwLock<HashMap<ListId, PathBuf>>,
}

impl StoreListBodies {
    /// Bodies from `store`, falling back to `files` when the cache is empty.
    pub fn new(store: ListStore, files: HashMap<ListId, PathBuf>) -> Self {
        Self {
            store,
            files: RwLock::new(files),
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

    fn open(&self, id: &ListId) -> Option<OpenedList> {
        let max = self.store.config.max_body_bytes;
        match open_pinned(&self.store.body_path(id), max) {
            Ok(Some(opened)) => return Some(opened),
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
        match open_pinned(&path, max) {
            Ok(opened) => opened,
            Err(e) => {
                tracing::warn!(list = %id, path = %path.display(), error = %e, "cannot read file list");
                None
            }
        }
    }

    /// Unpinned lookup in whatever body is on disk now (O(offset) scan).
    fn rule_at(&self, id: &ListId, offset: u32) -> Option<(u32, Arc<str>)> {
        read_rule_at_path(&self.path_for(id)?, offset)
    }
}

/// Opens `path`, reads it (capped) and pins a [`ListText`] to the handle.
fn open_pinned(path: &Path, max: u64) -> Result<Option<OpenedList>, StoreError> {
    let Some((file, bytes)) = open_capped(path, max)? else {
        return Ok(None);
    };
    let lines = FileLines::pin(file, &bytes);
    Ok(Some(match String::from_utf8(bytes) {
        Ok(s) => OpenedList {
            body: Arc::from(s),
            text: lines.map(|l| Arc::new(l) as Arc<dyn ListText>),
        },
        Err(e) => {
            // Offsets refer to the lossily converted text, not to the file,
            // so keep that text for the (rare) invalid-UTF-8 list.
            let body: Arc<str> = Arc::from(String::from_utf8_lossy(e.as_bytes()).into_owned());
            OpenedList {
                text: Some(Arc::new(MemoryLines(Arc::clone(&body)))),
                body,
            }
        }
    }))
}

/// Number of newline bytes before each [`TEXT_BLOCK`]-aligned offset.
fn newline_checkpoints(bytes: &[u8]) -> Vec<u32> {
    let mut out = Vec::with_capacity(bytes.len() / TEXT_BLOCK + 1);
    let mut total = 0u32;
    for chunk in bytes.chunks(TEXT_BLOCK) {
        out.push(total);
        total = total.saturating_add(count_newlines(chunk));
    }
    if out.is_empty() {
        out.push(0);
    }
    out
}

fn count_newlines(bytes: &[u8]) -> u32 {
    u32::try_from(bytes.iter().filter(|&&b| b == b'\n').count()).unwrap_or(u32::MAX)
}

/// Rule text of an invalid-UTF-8 list, served from memory.
#[derive(Debug)]
struct MemoryLines(Arc<str>);

impl ListText for MemoryLines {
    fn rule_at(&self, offset: u32) -> Option<(u32, Arc<str>)> {
        crate::index::rule_at_body(&self.0, offset).map(|(line, text)| (line, Arc::from(text)))
    }
}

/// A list body on disk, read through an open handle.
#[derive(Debug)]
struct FileLines {
    file: fs::File,
    /// Length of the body when it was parsed.
    len: u64,
    /// Modification time when it was parsed (detects in-place edits).
    modified: Option<SystemTime>,
    /// `newlines_before[k]` = newlines before byte `k * TEXT_BLOCK`.
    newlines_before: Vec<u32>,
    cache: Mutex<TextCache>,
    /// Bytes fetched from disk (tests prove reads stay small).
    #[cfg(test)]
    bytes_read: AtomicU64,
}

impl ListText for FileLines {
    fn rule_at(&self, offset: u32) -> Option<(u32, Arc<str>)> {
        {
            let mut cache = self
                .cache
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Some(hit) = cache.get(offset) {
                return Some(hit);
            }
        }
        let got = self.read_line(offset)?;
        self.cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(offset, got.clone());
        Some(got)
    }
}

impl FileLines {
    /// Pins `file`, whose content `bytes` was just read from it. `None` if the
    /// file changed while it was read (its offsets cannot be trusted).
    fn pin(file: fs::File, bytes: &[u8]) -> Option<Self> {
        let meta = file.metadata().ok()?;
        if meta.len() != bytes.len() as u64 {
            return None;
        }
        Some(Self {
            file,
            len: bytes.len() as u64,
            modified: meta.modified().ok(),
            newlines_before: newline_checkpoints(bytes),
            cache: Mutex::new(TextCache::new(TEXT_CACHE_CAP)),
            #[cfg(test)]
            bytes_read: AtomicU64::new(0),
        })
    }

    /// One positional read of the block containing `offset` up to the end of
    /// the line (at most `TEXT_BLOCK + LINE_TEXT_MAX` bytes).
    fn read_line(&self, offset: u32) -> Option<(u32, Arc<str>)> {
        let off = offset as usize;
        if u64::from(offset) >= self.len {
            return None;
        }
        // An in-place edit invalidates every offset; refuse rather than lie.
        let meta = self.file.metadata().ok()?;
        if meta.len() != self.len || meta.modified().ok() != self.modified {
            return None;
        }
        let block = off / TEXT_BLOCK;
        let base = block * TEXT_BLOCK;
        let before = *self.newlines_before.get(block)?;
        let end = off
            .saturating_add(LINE_TEXT_MAX + 1)
            .min(usize::try_from(self.len).ok()?);
        let mut buf = vec![0u8; end.checked_sub(base)?];
        let n = read_full_at(&self.file, &mut buf, base as u64).ok()?;
        #[cfg(test)]
        self.bytes_read.fetch_add(n as u64, Ordering::Relaxed);
        if n != buf.len() {
            return None;
        }
        let line = before
            .saturating_add(count_newlines(buf.get(..off - base)?))
            .saturating_add(1);
        let rest = buf.get(off - base..)?;
        let cut = rest
            .iter()
            .position(|&b| b == b'\n')
            .unwrap_or(rest.len())
            .min(LINE_TEXT_MAX);
        let text = String::from_utf8_lossy(rest.get(..cut)?);
        Some((line, Arc::from(text.trim_end_matches(crate::parser::is_ws))))
    }
}

/// Bounded least-recently-used cache of rule texts, keyed by byte offset.
#[derive(Debug)]
struct TextCache {
    cap: usize,
    tick: u64,
    map: HashMap<u32, (u64, u32, Arc<str>)>,
}

impl TextCache {
    fn new(cap: usize) -> Self {
        Self {
            cap: cap.max(8),
            tick: 0,
            map: HashMap::new(),
        }
    }

    fn get(&mut self, offset: u32) -> Option<(u32, Arc<str>)> {
        let e = self.map.get_mut(&offset)?;
        self.tick += 1;
        e.0 = self.tick;
        Some((e.1, Arc::clone(&e.2)))
    }

    fn insert(&mut self, offset: u32, val: (u32, Arc<str>)) {
        if self.map.len() >= self.cap && !self.map.contains_key(&offset) {
            // Drop the least recently used eighth in one pass (amortised O(1)).
            let mut stamps: Vec<u64> = self.map.values().map(|e| e.0).collect();
            let k = (self.cap / 8).clamp(1, stamps.len());
            let (_, kth, _) = stamps.select_nth_unstable(k - 1);
            let limit = *kth;
            self.map.retain(|_, e| e.0 > limit);
        }
        self.tick += 1;
        self.map.insert(offset, (self.tick, val.0, val.1));
    }
}

/// Fills `buf` from `offset` with positional reads; returns the bytes read
/// (less than `buf.len()` only at end of file).
fn read_full_at(file: &fs::File, buf: &mut [u8], offset: u64) -> io::Result<usize> {
    let mut done = 0usize;
    while done < buf.len() {
        let rest = buf.get_mut(done..).unwrap_or(&mut []);
        let n = read_at(file, rest, offset + done as u64)?;
        if n == 0 {
            break;
        }
        done += n;
    }
    Ok(done)
}

#[cfg(unix)]
fn read_at(file: &fs::File, buf: &mut [u8], offset: u64) -> io::Result<usize> {
    std::os::unix::fs::FileExt::read_at(file, buf, offset)
}

#[cfg(windows)]
fn read_at(file: &fs::File, buf: &mut [u8], offset: u64) -> io::Result<usize> {
    std::os::windows::fs::FileExt::seek_read(file, buf, offset)
}

#[cfg(not(any(unix, windows)))]
fn read_at(_file: &fs::File, _buf: &mut [u8], _offset: u64) -> io::Result<usize> {
    Err(io::Error::from(io::ErrorKind::Unsupported))
}

/// Unpinned lookup: counts newlines before `offset` from the file start in
/// 64 KiB positional reads, then reads the line.
fn read_rule_at_path(path: &Path, offset: u32) -> Option<(u32, Arc<str>)> {
    let file = fs::File::open(path).ok()?;
    let mut newlines: u32 = 0;
    let mut buf = vec![0u8; 64 * 1024];
    let mut pos = 0u64;
    let target = u64::from(offset);
    while pos < target {
        let want = usize::try_from((target - pos).min(buf.len() as u64)).ok()?;
        let n = read_full_at(&file, buf.get_mut(..want)?, pos).ok()?;
        if n != want {
            return None;
        }
        newlines = newlines.saturating_add(count_newlines(buf.get(..n)?));
        pos += n as u64;
    }
    let mut line_buf = vec![0u8; LINE_TEXT_MAX];
    let n = read_full_at(&file, &mut line_buf, target).ok()?;
    let line_buf = line_buf.get(..n)?;
    let cut = line_buf.iter().position(|&b| b == b'\n').unwrap_or(n);
    let text = String::from_utf8_lossy(line_buf.get(..cut)?);
    Some((
        newlines.saturating_add(1),
        Arc::from(text.trim_end_matches(crate::parser::is_ws)),
    ))
}

/// Opens `path` and reads it, refusing more than `max` bytes. `None` if
/// missing. The returned handle stays valid for positional reads even if the
/// path is later replaced.
fn open_capped(path: &Path, max: u64) -> Result<Option<(fs::File, Vec<u8>)>, StoreError> {
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
    (&file)
        .take(max + 1)
        .read_to_end(&mut buf)
        .map_err(|e| StoreError::io("read", path, e))?;
    if buf.len() as u64 > max {
        return Err(too_large());
    }
    Ok(Some((file, buf)))
}

/// Reads `path` as text, refusing more than `max` bytes. `None` if missing.
/// Invalid UTF-8 is replaced lossily so one stray byte does not lose a list.
fn read_capped(path: &Path, max: u64) -> Result<Option<String>, StoreError> {
    Ok(
        open_capped(path, max)?.map(|(_, buf)| match String::from_utf8(buf) {
            Ok(s) => s,
            Err(e) => String::from_utf8_lossy(e.as_bytes()).into_owned(),
        }),
    )
}

/// Distinguishes concurrent temp files of one process.
static TMP_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Fresh temporary sibling path used by [`atomic_write`]: hidden, and unique
/// per process and call so it never collides with (or follows a symlink at)
/// a path an attacker or an earlier crash left behind.
fn tmp_path(path: &Path) -> PathBuf {
    let n = TMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let mut name = std::ffi::OsString::from(".");
    name.push(path.file_name().unwrap_or_default());
    name.push(format!(".{}.{n}.tmp", std::process::id()));
    path.with_file_name(name)
}

/// Creates a new file exclusively (`create_new`), mode 0o600 on unix.
fn create_private_new(path: &Path) -> io::Result<fs::File> {
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    opts.open(path)
}

/// Writes `data` to a temp file, fsyncs, renames over `path`, fsyncs the dir.
/// On failure the temp file is removed and `path` is untouched.
fn atomic_write(path: &Path, data: &[u8]) -> Result<(), StoreError> {
    let tmp = tmp_path(path);
    let result = (|| {
        let mut file = create_private_new(&tmp).map_err(|e| StoreError::io("create", &tmp, e))?;
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

    /// A rule near the end of a big body is found with reads that are bounded
    /// by one block plus one line, never by the distance from the file start.
    #[test]
    fn rule_text_reads_are_bounded_and_not_from_file_start() {
        let dir = std::env::temp_dir().join(format!("dnscraft-store-unit-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("big.txt");
        let line_len = "||host0000000.example^\n".len();
        let lines = 300_000usize; // about 6.9 MB
        let mut body = String::with_capacity(lines * line_len);
        for i in 0..lines {
            body.push_str(&format!("||host{i:07}.example^\n"));
        }
        fs::write(&path, &body).unwrap();
        let (file, bytes) = open_capped(&path, u64::MAX / 2).unwrap().unwrap();
        let pinned = FileLines::pin(file, &bytes).unwrap();
        assert!(pinned.newlines_before.len() < bytes.len() / TEXT_BLOCK + 2);

        let bound = (TEXT_BLOCK + LINE_TEXT_MAX + 1) as u64;
        for i in [lines - 1, lines - 2, lines / 2, 1, 0] {
            let before = pinned.bytes_read.load(Ordering::Relaxed);
            let (line, text) = pinned.rule_at((i * line_len) as u32).unwrap();
            let used = pinned.bytes_read.load(Ordering::Relaxed) - before;
            assert_eq!(line as usize, i + 1);
            assert_eq!(&*text, format!("||host{i:07}.example^"));
            assert!(used <= bound, "read {used} bytes for line {i}");
        }
        // A repeat is served from the cache without touching the disk.
        let before = pinned.bytes_read.load(Ordering::Relaxed);
        pinned.rule_at(((lines - 1) * line_len) as u32).unwrap();
        assert_eq!(pinned.bytes_read.load(Ordering::Relaxed), before);

        // Offsets outside the body are refused.
        assert!(
            pinned
                .rule_at(u32::try_from(bytes.len()).unwrap())
                .is_none()
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn text_cache_is_bounded_and_keeps_recent_entries() {
        let mut c = TextCache::new(64);
        for i in 0..64u32 {
            c.insert(i, (i, Arc::from("x")));
        }
        assert!(c.get(0).is_some()); // refresh the oldest
        for i in 64..200u32 {
            c.insert(i, (i, Arc::from("x")));
            assert!(c.map.len() <= 64);
        }
        assert!(c.get(199).is_some());
        assert!(c.get(1).is_none());
    }

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
