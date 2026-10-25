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

use std::collections::BTreeMap;
use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::UNIX_EPOCH;

use serde::{Deserialize, Serialize};

use crate::clock::{Clock, SystemClock};
use crate::types::ListId;

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

    fn body_path(&self, id: &ListId) -> PathBuf {
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
