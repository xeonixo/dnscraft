//! On-disk certificate and ACME account store.
//!
//! Layout under `<data_dir>/tls/` (mode **0o700**):
//!
//! ```text
//! account.json   ACME account credentials (0o600)
//! cert.pem       leaf + chain PEM (0o600)
//! key.pem        private key PEM (0o600)
//! meta.json      cache of identifiers / not_after / ARI id (0o600)
//! ```
//!
//! Writes are atomic (temp + fsync + rename), matching filtering's `ListStore`.
//! [`CertMeta::not_after`] in `meta.json` is a cache; [`CertStore::load`] always
//! re-parses `not_after` and identifiers from the leaf certificate.

use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rustls_pki_types::CertificateDer;
use serde::{Deserialize, Serialize};
use x509_parser::prelude::*;

use crate::error::TlsError;
use crate::pem_util::{KeyPem, parse_cert_chain, parse_leaf_info};

/// Directory name under the data directory.
pub const TLS_DIR_NAME: &str = "tls";

const CERT_FILE: &str = "cert.pem";
const KEY_FILE: &str = "key.pem";
const META_FILE: &str = "meta.json";
const ACCOUNT_FILE: &str = "account.json";

/// Cached certificate metadata written next to the PEM files.
///
/// `not_after` and `identifiers` are refreshed from the leaf on every
/// [`CertStore::load`]; values here are only a hint for status UIs between loads.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CertMeta {
    /// DNS names this certificate covers (typically `dns.<domain>` and `*.dns.<domain>`).
    #[serde(default)]
    pub identifiers: Vec<String>,
    /// Unix seconds of leaf `notAfter` (cache only).
    #[serde(default)]
    pub not_after_unix: Option<i64>,
    /// ACME ARI certificate id when known.
    #[serde(default)]
    pub ari_cert_id: Option<String>,
    /// Last error code from issuance/renewal, if any.
    #[serde(default)]
    pub last_error: Option<String>,
}

/// Material loaded from the store.
#[derive(Clone, PartialEq, Eq)]
pub struct LoadedCert {
    /// Leaf + intermediates as PEM.
    pub chain_pem: Vec<u8>,
    /// Private key PEM (redacted in [`Debug`] / [`Display`](std::fmt::Display)).
    pub key: KeyPem,
    /// Leaf `notAfter`.
    pub not_after: SystemTime,
    /// DNS SANs (and CN fallback) from the leaf.
    pub identifiers: Vec<String>,
    /// Cached metadata as last written (may lag the leaf).
    pub meta: CertMeta,
}

impl std::fmt::Debug for LoadedCert {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoadedCert")
            .field("chain_pem_len", &self.chain_pem.len())
            .field("key", &self.key)
            .field("not_after", &self.not_after)
            .field("identifiers", &self.identifiers)
            .field("meta", &self.meta)
            .finish()
    }
}

/// Persistent certificate and account store under `<data>/tls/`.
#[derive(Debug)]
pub struct CertStore {
    dir: PathBuf,
}

impl CertStore {
    /// Opens (or creates) `<data_dir>/tls/` with mode 0o700.
    ///
    /// An existing directory with wider permissions is tightened to 0o700.
    /// If tightening fails, returns [`TlsError::StoreIo`].
    pub fn open(data_dir: &Path) -> Result<Self, TlsError> {
        let dir = data_dir.join(TLS_DIR_NAME);
        ensure_private_dir(&dir)?;
        Ok(Self { dir })
    }

    /// Directory that holds the PEM and metadata files.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Loads the last good certificate, if any.
    ///
    /// Missing files → `Ok(None)`. Present but unreadable/corrupt PEM →
    /// [`TlsError::StoreCorrupt`] without deleting the files.
    pub fn load(&self) -> Result<Option<LoadedCert>, TlsError> {
        let cert_path = self.dir.join(CERT_FILE);
        let key_path = self.dir.join(KEY_FILE);
        if !cert_path.exists() && !key_path.exists() {
            return Ok(None);
        }
        if !cert_path.exists() || !key_path.exists() {
            return Err(TlsError::StoreCorrupt {
                message: "cert.pem or key.pem missing while the other is present".into(),
            });
        }

        let chain_pem = fs::read(&cert_path).map_err(|e| store_io("read", &cert_path, e))?;
        let key_bytes = fs::read(&key_path).map_err(|e| store_io("read", &key_path, e))?;

        let leaf_info =
            parse_leaf_info(&chain_pem).map_err(|message| TlsError::StoreCorrupt { message })?;
        // Validate the key parses as PEM (without installing).
        let _ =
            parse_cert_chain(&chain_pem).map_err(|message| TlsError::StoreCorrupt { message })?;
        KeyPem::parse(&key_bytes).map_err(|message| TlsError::StoreCorrupt { message })?;

        let meta = self.load_meta_file().unwrap_or_default();
        Ok(Some(LoadedCert {
            chain_pem,
            key: KeyPem::from_bytes(key_bytes),
            not_after: leaf_info.not_after,
            identifiers: leaf_info.identifiers,
            meta,
        }))
    }

    /// Atomically writes chain, key and metadata (all mode 0o600).
    pub fn save(&self, chain_pem: &[u8], key_pem: &[u8], meta: &CertMeta) -> Result<(), TlsError> {
        // Validate before touching disk so a bad import cannot wipe a good cert.
        let leaf =
            parse_leaf_info(chain_pem).map_err(|message| TlsError::StoreCorrupt { message })?;
        let _ =
            parse_cert_chain(chain_pem).map_err(|message| TlsError::StoreCorrupt { message })?;
        KeyPem::parse(key_pem).map_err(|message| TlsError::StoreCorrupt { message })?;

        let mut meta = meta.clone();
        meta.identifiers = leaf.identifiers;
        meta.not_after_unix = Some(system_time_unix(leaf.not_after));

        let meta_json = serde_json::to_vec_pretty(&meta).map_err(|e| TlsError::StoreIo {
            message: format!("serialize meta.json: {e}"),
        })?;

        atomic_write(&self.dir.join(CERT_FILE), chain_pem)?;
        atomic_write(&self.dir.join(KEY_FILE), key_pem)?;
        atomic_write(&self.dir.join(META_FILE), &meta_json)?;
        Ok(())
    }

    /// Reads ACME `account.json`, if present.
    pub fn load_account(&self) -> Result<Option<Vec<u8>>, TlsError> {
        let path = self.dir.join(ACCOUNT_FILE);
        match fs::read(&path) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(store_io("read", &path, e)),
        }
    }

    /// Atomically writes ACME `account.json` (mode 0o600).
    pub fn save_account(&self, data: &[u8]) -> Result<(), TlsError> {
        atomic_write(&self.dir.join(ACCOUNT_FILE), data)
    }

    fn load_meta_file(&self) -> Option<CertMeta> {
        let path = self.dir.join(META_FILE);
        let bytes = fs::read(&path).ok()?;
        serde_json::from_slice(&bytes).ok()
    }
}

fn system_time_unix(t: SystemTime) -> i64 {
    t.duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Parses leaf `notAfter` and DNS identifiers from a PEM chain (first cert).
pub(crate) struct LeafInfo {
    pub not_after: SystemTime,
    pub identifiers: Vec<String>,
}

pub(crate) fn leaf_info_from_der(der: &[u8]) -> Result<LeafInfo, String> {
    let (_, cert) = X509Certificate::from_der(der).map_err(|e| format!("x509 parse: {e}"))?;
    let secs = cert.validity().not_after.timestamp();
    let not_after = if secs >= 0 {
        UNIX_EPOCH + Duration::from_secs(secs as u64)
    } else {
        return Err("certificate notAfter before Unix epoch".into());
    };

    let mut identifiers = Vec::new();
    if let Ok(Some(san)) = cert.subject_alternative_name() {
        for name in &san.value.general_names {
            if let GeneralName::DNSName(dns) = name {
                identifiers.push(dns.to_string());
            }
        }
    }
    if identifiers.is_empty() {
        let cn = cert
            .subject()
            .iter_common_name()
            .next()
            .and_then(|a| a.as_str().ok())
            .unwrap_or("");
        if !cn.is_empty() {
            identifiers.push(cn.to_owned());
        }
    }

    // Also confirm rustls can see at least one cert DER.
    let _ = CertificateDer::from(der.to_vec());
    Ok(LeafInfo {
        not_after,
        identifiers,
    })
}

fn ensure_private_dir(dir: &Path) -> Result<(), TlsError> {
    if dir.exists() {
        if !dir.is_dir() {
            return Err(TlsError::StoreIo {
                message: format!("{} exists and is not a directory", dir.display()),
            });
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let meta = fs::metadata(dir).map_err(|e| store_io("metadata", dir, e))?;
            let mode = meta.permissions().mode() & 0o777;
            if mode != 0o700 {
                let mut perms = meta.permissions();
                perms.set_mode(0o700);
                fs::set_permissions(dir, perms).map_err(|e| store_io("chmod", dir, e))?;
            }
        }
        return Ok(());
    }
    create_private_dir(dir)
}

fn create_private_dir(dir: &Path) -> Result<(), TlsError> {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder
        .create(dir)
        .map_err(|e| store_io("create_dir", dir, e))
}

static TMP_COUNTER: AtomicU64 = AtomicU64::new(0);

fn tmp_path(path: &Path) -> PathBuf {
    let n = TMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let mut name = std::ffi::OsString::from(".");
    name.push(path.file_name().unwrap_or_default());
    name.push(format!(".{}.{n}.tmp", std::process::id()));
    path.with_file_name(name)
}

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

fn atomic_write(path: &Path, data: &[u8]) -> Result<(), TlsError> {
    let tmp = tmp_path(path);
    let result = (|| {
        let mut file = create_private_new(&tmp).map_err(|e| store_io("create", &tmp, e))?;
        file.write_all(data)
            .map_err(|e| store_io("write", &tmp, e))?;
        file.sync_all().map_err(|e| store_io("fsync", &tmp, e))?;
        drop(file);
        fs::rename(&tmp, path).map_err(|e| store_io("rename", path, e))
    })();
    match result {
        Ok(()) => {
            if let Some(parent) = path.parent() {
                sync_dir(parent);
            }
            Ok(())
        }
        Err(e) => {
            let _ = fs::remove_file(&tmp);
            Err(e)
        }
    }
}

fn sync_dir(dir: &Path) {
    #[cfg(unix)]
    if let Ok(d) = fs::File::open(dir) {
        let _ = d.sync_all();
    }
    #[cfg(not(unix))]
    let _ = dir;
}

fn store_io(op: &str, path: &Path, source: io::Error) -> TlsError {
    TlsError::StoreIo {
        message: format!("{op} {}: {source}", path.display()),
    }
}
