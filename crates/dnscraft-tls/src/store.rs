//! On-disk certificate and ACME account store.
//!
//! Layout under `<data_dir>/tls/` (mode **0o700**):
//!
//! ```text
//! account.json   ACME account credentials (0o600)
//! cert.pem       leaf + chain PEM (0o600)
//! key.pem        private key PEM (0o600)
//! meta.json      cache of identifiers / not_after / ARI id (0o600)
//! state.json     last issue/renew outcome, independent of any cert (0o600)
//! ```
//!
//! `state.json` (not `meta.json`) carries `last_error` / `last_issue` /
//! `last_renew_attempt`: it must be writable when the very first issuance
//! fails and no certificate exists yet, and a failed renewal must not rewrite
//! the files that describe the last good cert.
//!
//! Writes are atomic (temp + fsync + rename), matching filtering's `ListStore`.
//! [`CertMeta::not_after`] in `meta.json` is a cache; [`CertStore::load`] always
//! re-parses `not_after` and identifiers from the leaf certificate.

use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use x509_parser::prelude::*;

use crate::error::TlsError;
use crate::pem_util::{KeyPem, certified_key_from_pem, parse_leaf_info};
use crate::status::{CertDetail, CertSource, DynDnsAuditEntry, IssueRecord, StoreHealth};

/// Directory name under the data directory.
pub const TLS_DIR_NAME: &str = "tls";

/// Maximum number of issue/renew history entries kept in `state.json`.
pub const HISTORY_LIMIT: usize = 10;

/// Maximum number of DynDNS audit entries kept in `state.json`.
pub const DYNDNS_AUDIT_LIMIT: usize = 50;

const CERT_FILE: &str = "cert.pem";
const KEY_FILE: &str = "key.pem";
const META_FILE: &str = "meta.json";
const ACCOUNT_FILE: &str = "account.json";
const STATE_FILE: &str = "state.json";

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
    /// ACME ARI certificate id (`<aki>.<serial>`) of the stored leaf, when known.
    #[serde(default)]
    pub ari_cert_id: Option<String>,
    /// Where the stored certificate came from.
    #[serde(default)]
    pub source: CertSource,
}

/// Outcome of the most recent issue/renew attempts (`state.json`).
///
/// Written even when no certificate exists. `last_error` is always a stable
/// `tls.*` code ([`TlsError::code`]), never an error message.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct IssueState {
    /// Stable code of the last failed attempt; cleared on success.
    #[serde(default)]
    pub last_error: Option<String>,
    /// Unix seconds of the last successful issue/renew.
    #[serde(default)]
    pub last_issue_unix: Option<i64>,
    /// Unix seconds of the last attempt (success or failure).
    #[serde(default)]
    pub last_renew_attempt_unix: Option<i64>,
    /// Bounded (last [`HISTORY_LIMIT`]) issue/renew history, oldest first.
    #[serde(default)]
    pub history: Vec<IssueRecord>,
    /// `true` when the stored certificate was revoked locally.
    #[serde(default)]
    pub revoked: bool,
    /// Revocation reason as supplied by the operator.
    #[serde(default)]
    pub revoked_reason: Option<String>,
    /// Bounded (last [`DYNDNS_AUDIT_LIMIT`]) DynDNS write audit trail.
    #[serde(default)]
    pub dyndns_audit: Vec<DynDnsAuditEntry>,
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
    /// Parsed leaf detail (cert-only, never key material).
    pub detail: CertDetail,
}

impl std::fmt::Debug for LoadedCert {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoadedCert")
            .field("chain_pem_len", &self.chain_pem.len())
            .field("key", &self.key)
            .field("not_after", &self.not_after)
            .field("identifiers", &self.identifiers)
            .field("meta", &self.meta)
            .field("detail", &self.detail)
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

        ensure_secret_file_mode(&key_path, KEY_FILE)?;

        let chain_pem = fs::read(&cert_path).map_err(|e| store_io("read", &cert_path, e))?;
        let key_bytes = fs::read(&key_path).map_err(|e| store_io("read", &key_path, e))?;

        let leaf_info =
            parse_leaf_info(&chain_pem).map_err(|message| TlsError::StoreCorrupt { message })?;
        // Key must parse and match the leaf (a crash mid-save can leave a mismatched pair).
        certified_key_from_pem(&chain_pem, &key_bytes)
            .map_err(|message| TlsError::StoreCorrupt { message })?;

        let meta = self.load_meta_file().unwrap_or_default();
        Ok(Some(LoadedCert {
            chain_pem,
            key: KeyPem::from_bytes(key_bytes),
            not_after: leaf_info.not_after,
            identifiers: leaf_info.identifiers,
            meta,
            detail: leaf_info.detail,
        }))
    }

    /// Atomically writes chain, key and metadata (all mode 0o600).
    pub fn save(&self, chain_pem: &[u8], key_pem: &[u8], meta: &CertMeta) -> Result<(), TlsError> {
        // Validate before touching disk so a bad import cannot wipe a good cert.
        let leaf =
            parse_leaf_info(chain_pem).map_err(|message| TlsError::StoreCorrupt { message })?;
        certified_key_from_pem(chain_pem, key_pem)
            .map_err(|message| TlsError::StoreCorrupt { message })?;

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
    ///
    /// Rejects group/other-readable modes with [`TlsError::StorePermissions`]
    /// (same policy as `key.pem`).
    pub fn load_account(&self) -> Result<Option<Vec<u8>>, TlsError> {
        let path = self.dir.join(ACCOUNT_FILE);
        if !path.exists() {
            return Ok(None);
        }
        ensure_secret_file_mode(&path, ACCOUNT_FILE)?;
        match fs::read(&path) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(store_io("read", &path, e)),
        }
    }

    /// Soft permission probe for engine open: checks `account.json` when present.
    ///
    /// Does not read file contents. Used so [`crate::TlsEngine::open`] can
    /// surface [`TlsError::StorePermissions`] in status without failing open.
    pub fn check_account_permissions(&self) -> Result<(), TlsError> {
        let path = self.dir.join(ACCOUNT_FILE);
        if !path.exists() {
            return Ok(());
        }
        ensure_secret_file_mode(&path, ACCOUNT_FILE)
    }

    /// Atomically writes ACME `account.json` (mode 0o600).
    pub fn save_account(&self, data: &[u8]) -> Result<(), TlsError> {
        atomic_write(&self.dir.join(ACCOUNT_FILE), data)
    }

    /// Reads `state.json`; missing or unparseable → default (no history).
    pub fn load_state(&self) -> IssueState {
        fs::read(self.dir.join(STATE_FILE))
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default()
    }

    /// Atomically writes `state.json` (mode 0o600). Does not touch cert/key/meta.
    pub fn save_state(&self, state: &IssueState) -> Result<(), TlsError> {
        let json = serde_json::to_vec_pretty(state).map_err(|e| TlsError::StoreIo {
            message: format!("serialize state.json: {e}"),
        })?;
        atomic_write(&self.dir.join(STATE_FILE), &json)
    }

    /// Removes `account.json` after an account deactivation.
    ///
    /// Missing file is not an error.
    pub fn clear_account(&self) -> Result<(), TlsError> {
        let path = self.dir.join(ACCOUNT_FILE);
        match fs::remove_file(&path) {
            Ok(()) => {
                sync_dir(&self.dir);
                Ok(())
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(store_io("remove", &path, e)),
        }
    }

    /// Probes store health: writability, last write time, and corrupt PEM.
    ///
    /// The write probe creates and removes a private temp file in the TLS
    /// directory; it never touches the certificate, key, or metadata.
    pub fn health(&self) -> StoreHealth {
        let last_write = [CERT_FILE, STATE_FILE]
            .iter()
            .filter_map(|name| fs::metadata(self.dir.join(name)).ok()?.modified().ok())
            .max();
        let corrupt = matches!(
            self.load(),
            Err(TlsError::StoreCorrupt { .. } | TlsError::StorePermissions { .. })
        );
        StoreHealth {
            path: self.dir.display().to_string(),
            writable: probe_writable(&self.dir),
            last_write,
            corrupt,
        }
    }

    fn load_meta_file(&self) -> Option<CertMeta> {
        let path = self.dir.join(META_FILE);
        let bytes = fs::read(&path).ok()?;
        serde_json::from_slice(&bytes).ok()
    }
}

/// Appends one issue record, keeping only the last [`HISTORY_LIMIT`].
pub fn push_history(state: &mut IssueState, record: IssueRecord) {
    state.history.push(record);
    let excess = state.history.len().saturating_sub(HISTORY_LIMIT);
    if excess > 0 {
        state.history.drain(..excess);
    }
}

/// Appends DynDNS audit entries, keeping only the last [`DYNDNS_AUDIT_LIMIT`].
pub fn push_dyndns_audit(
    state: &mut IssueState,
    entries: impl IntoIterator<Item = DynDnsAuditEntry>,
) {
    state.dyndns_audit.extend(entries);
    let excess = state.dyndns_audit.len().saturating_sub(DYNDNS_AUDIT_LIMIT);
    if excess > 0 {
        state.dyndns_audit.drain(..excess);
    }
}

fn probe_writable(dir: &Path) -> bool {
    let path = tmp_path(&dir.join("health"));
    match create_private_new(&path) {
        Ok(file) => {
            drop(file);
            let _ = fs::remove_file(&path);
            true
        }
        Err(_) => false,
    }
}

fn system_time_unix(t: SystemTime) -> i64 {
    t.duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Parses leaf `notAfter`, DNS identifiers and cert detail from a DER cert.
pub(crate) struct LeafInfo {
    pub not_after: SystemTime,
    pub identifiers: Vec<String>,
    pub detail: CertDetail,
}

pub(crate) fn leaf_info_from_der(der: &[u8]) -> Result<LeafInfo, String> {
    let (_, cert) = X509Certificate::from_der(der).map_err(|e| format!("x509 parse: {e}"))?;
    let not_after = cert_time(cert.validity().not_after.timestamp())
        .ok_or_else(|| "certificate notAfter before Unix epoch".to_owned())?;
    let not_before = cert_time(cert.validity().not_before.timestamp());

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

    let detail = CertDetail {
        not_before,
        issuer: Some(cert.issuer().to_string()),
        subject: Some(cert.subject().to_string()),
        serial: Some(colon_hex(cert.raw_serial())),
        signature_algorithm: Some(signature_algorithm_name(&cert)),
        key_usage: key_usage_names(&cert),
        chain: Vec::new(),
    };

    Ok(LeafInfo {
        not_after,
        identifiers,
        detail,
    })
}

fn cert_time(secs: i64) -> Option<SystemTime> {
    (secs >= 0).then(|| UNIX_EPOCH + Duration::from_secs(secs as u64))
}

/// Serial as colon-separated upper-case hex (OpenSSL style).
fn colon_hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// Maps the leaf signature OID to a stable short name.
fn signature_algorithm_name(cert: &X509Certificate<'_>) -> String {
    let oid = cert.signature_algorithm.algorithm.to_id_string();
    match oid.as_str() {
        "1.2.840.10045.4.3.2" => "ecdsa-with-SHA256".into(),
        "1.2.840.10045.4.3.3" => "ecdsa-with-SHA384".into(),
        "1.2.840.10045.4.3.4" => "ecdsa-with-SHA512".into(),
        "1.2.840.113549.1.1.11" => "sha256WithRSAEncryption".into(),
        "1.2.840.113549.1.1.12" => "sha384WithRSAEncryption".into(),
        "1.2.840.113549.1.1.13" => "sha512WithRSAEncryption".into(),
        "1.2.840.113549.1.1.5" => "sha1WithRSAEncryption".into(),
        "1.3.101.112" => "Ed25519".into(),
        _ => oid,
    }
}

fn key_usage_names(cert: &X509Certificate<'_>) -> Vec<String> {
    let Ok(Some(ku)) = cert.key_usage() else {
        return Vec::new();
    };
    let ku = ku.value;
    let mut names = Vec::new();
    for (set, name) in [
        (ku.digital_signature(), "digitalSignature"),
        (ku.non_repudiation(), "nonRepudiation"),
        (ku.key_encipherment(), "keyEncipherment"),
        (ku.data_encipherment(), "dataEncipherment"),
        (ku.key_agreement(), "keyAgreement"),
        (ku.key_cert_sign(), "keyCertSign"),
        (ku.crl_sign(), "cRLSign"),
        (ku.encipher_only(), "encipherOnly"),
        (ku.decipher_only(), "decipherOnly"),
    ] {
        if set {
            names.push(name.to_owned());
        }
    }
    names
}

/// Rejects a secret store file that is readable by group/other (must be `0600`).
///
/// Does not rewrite the mode: a too-open file is a hard error so the operator
/// notices. Files are left in place ([`TlsError::StorePermissions`]).
///
/// `file_name` is the basename used in the error (`key.pem` / `account.json`).
fn ensure_secret_file_mode(path: &Path, file_name: &str) -> Result<(), TlsError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let meta = fs::metadata(path).map_err(|e| store_io("metadata", path, e))?;
        let mode = meta.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            return Err(TlsError::StorePermissions {
                file: file_name.to_owned(),
                mode,
            });
        }
    }
    let _ = (path, file_name);
    Ok(())
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::status::{IssueOutcome, IssueRecord};

    fn temp_dir(label: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "dnscraft-tls-store-unit-{label}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn history_and_dyndns_audit_are_bounded() {
        let mut state = IssueState::default();
        for i in 0..(HISTORY_LIMIT + 5) as u64 {
            push_history(
                &mut state,
                IssueRecord {
                    timestamp: UNIX_EPOCH + Duration::from_secs(i),
                    outcome: IssueOutcome::Renewed,
                    error: None,
                    serial: Some(i.to_string()),
                },
            );
        }
        assert_eq!(state.history.len(), HISTORY_LIMIT);
        assert_eq!(state.history.first().unwrap().serial.as_deref(), Some("5"));

        let entries = (0..(DYNDNS_AUDIT_LIMIT + 3)).map(|i| DynDnsAuditEntry {
            timestamp: UNIX_EPOCH,
            name: format!("n{i}"),
            record_type: "A".into(),
            content: "203.0.113.1".into(),
        });
        push_dyndns_audit(&mut state, entries);
        assert_eq!(state.dyndns_audit.len(), DYNDNS_AUDIT_LIMIT);
        assert_eq!(state.dyndns_audit.first().unwrap().name, "n3");
    }

    #[test]
    fn health_reports_writable_and_corrupt() {
        let dir = temp_dir("health");
        let store = CertStore::open(&dir).unwrap();
        let health = store.health();
        assert!(health.writable, "{health:?}");
        assert!(!health.corrupt);
        assert!(health.path.ends_with(TLS_DIR_NAME));

        fs::write(store.dir().join(CERT_FILE), b"NOT PEM").unwrap();
        fs::write(store.dir().join(KEY_FILE), b"NOT PEM").unwrap();
        assert!(store.health().corrupt);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn meta_source_and_cert_detail_round_trip() {
        let dir = temp_dir("roundtrip");
        let store = CertStore::open(&dir).unwrap();
        let certified = rcgen::generate_simple_self_signed(vec!["dns.example.com".into()]).unwrap();
        let chain = certified.cert.pem();
        let key = certified.signing_key.serialize_pem();
        store
            .save(
                chain.as_bytes(),
                key.as_bytes(),
                &CertMeta {
                    source: CertSource::Manual,
                    ..CertMeta::default()
                },
            )
            .unwrap();

        let loaded = store.load().unwrap().unwrap();
        assert_eq!(loaded.meta.source, CertSource::Manual);
        assert!(loaded.detail.not_before.is_some());
        assert!(loaded.detail.serial.is_some());
        assert_eq!(loaded.detail.chain.len(), 1);
        assert!(!loaded.detail.chain[0].contains("PRIVATE KEY"));

        store.save_account(b"{}").unwrap();
        assert!(store.load_account().unwrap().is_some());
        store.clear_account().unwrap();
        assert!(store.load_account().unwrap().is_none());
        let _ = fs::remove_dir_all(&dir);
    }
}
