//! Master-side cluster CA: one dedicated signing identity per cluster.
//!
//! The private key lives next to the certificate (`ca.pem` → `ca.key`), is
//! created with mode `0600`, and is held in a [`Secret`] so it cannot appear in
//! `Debug`, `Serialize`, or logs. Node certificates are issued under this CA in
//! the enrollment slice (`rcgen`, ring-only; ADR-0002).

use std::fmt;
use std::fs;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use dnscraft_common::secret::Secret;
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DnType, IsCa, Issuer, KeyPair,
    KeyUsagePurpose, PKCS_ECDSA_P256_SHA256, PublicKey,
};

use crate::error::ClusterError;

/// The master's dedicated cluster certificate authority.
///
/// The CA certificate is public; the key is private and never exported. Both
/// are persisted under the data directory, and loading an existing pair reuses
/// the same identity across restarts.
pub struct ClusterCa {
    cert_pem: String,
    key: KeyPair,
    cert_path: PathBuf,
    key_path: PathBuf,
}

impl ClusterCa {
    /// Loads the CA at `cert_path` (key derived as `<stem>.key`), or creates a
    /// new self-signed CA when neither file exists.
    ///
    /// A partially present pair (only the cert or only the key) is an error: it
    /// is never silently overwritten.
    pub fn load_or_generate(cert_path: &Path) -> Result<Self, ClusterError> {
        let key_path = key_path_for(cert_path);
        match (cert_path.exists(), key_path.exists()) {
            (true, true) => Self::load(cert_path, &key_path),
            (false, false) => Self::generate(cert_path, &key_path),
            _ => Err(ClusterError::Internal {
                message: format!(
                    "incomplete cluster CA state at {} (cert present: {}, key present: {})",
                    cert_path.display(),
                    cert_path.exists(),
                    key_path.exists()
                ),
            }),
        }
    }

    /// The CA certificate in PEM (public).
    pub fn cert_pem(&self) -> &str {
        &self.cert_pem
    }

    /// The CA certificate path.
    pub fn cert_path(&self) -> &Path {
        &self.cert_path
    }

    /// Signs `params` (carrying `public_key`) under this CA.
    pub(crate) fn sign(
        &self,
        params: &CertificateParams,
        public_key: &PublicKey,
    ) -> Result<Certificate, ClusterError> {
        let issuer = Issuer::from_ca_cert_pem(&self.cert_pem, &self.key).map_err(|error| {
            ClusterError::Internal {
                message: format!("cluster CA issuer: {error}"),
            }
        })?;
        params
            .signed_by(public_key, &issuer)
            .map_err(|error| ClusterError::Internal {
                message: format!("node certificate signing: {error}"),
            })
    }

    fn load(cert_path: &Path, key_path: &Path) -> Result<Self, ClusterError> {
        let cert_pem = fs::read_to_string(cert_path).map_err(io_error)?;
        let key_pem = Secret::new(fs::read_to_string(key_path).map_err(io_error)?);
        // Reject a corrupt key now rather than at first signing.
        let key = KeyPair::from_pem(key_pem.expose()).map_err(|error| ClusterError::Internal {
            message: format!("invalid cluster CA key: {error}"),
        })?;
        tighten_key_permissions(key_path)?;
        Ok(Self {
            cert_pem,
            key,
            cert_path: cert_path.to_owned(),
            key_path: key_path.to_owned(),
        })
    }

    fn generate(cert_path: &Path, key_path: &Path) -> Result<Self, ClusterError> {
        prepare_parent(cert_path)?;

        let mut params =
            CertificateParams::new(Vec::new()).map_err(|error| ClusterError::Internal {
                message: format!("cluster CA params: {error}"),
            })?;
        params
            .distinguished_name
            .push(DnType::CommonName, "DNScraft Cluster CA");
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];

        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).map_err(|error| {
            ClusterError::Internal {
                message: format!("cluster CA key generation: {error}"),
            }
        })?;
        let cert = params
            .self_signed(&key)
            .map_err(|error| ClusterError::Internal {
                message: format!("cluster CA certificate generation: {error}"),
            })?;

        let cert_pem = cert.pem();
        let key_pem = Secret::new(key.serialize_pem());
        write_key_0600(key_path, key_pem.expose().as_bytes())?;
        fs::write(cert_path, cert_pem.as_bytes()).map_err(io_error)?;

        Ok(Self {
            cert_pem,
            key,
            cert_path: cert_path.to_owned(),
            key_path: key_path.to_owned(),
        })
    }
}

impl fmt::Debug for ClusterCa {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClusterCa")
            .field("cert_path", &self.cert_path)
            .field("key_path", &self.key_path)
            .field("key", &"[redacted]")
            .finish()
    }
}

/// SHA-256 fingerprint (lowercase hex) of a DER-encoded certificate.
pub fn cert_fingerprint(der: &[u8]) -> String {
    crate::sha256_hex(der)
}

fn key_path_for(cert_path: &Path) -> PathBuf {
    cert_path.with_extension("key")
}

pub(crate) fn io_error(error: std::io::Error) -> ClusterError {
    ClusterError::Internal {
        message: error.to_string(),
    }
}

/// Creates the certificate's parent directory with mode 0700 when it does not
/// exist; a pre-existing directory is left untouched.
pub(crate) fn prepare_parent(path: &Path) -> Result<(), ClusterError> {
    if let Some(parent) = path.parent().filter(|dir| !dir.as_os_str().is_empty())
        && !parent.exists()
    {
        fs::create_dir_all(parent).map_err(io_error)?;
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700)).map_err(io_error)?;
    }
    Ok(())
}

/// Creates the key file with mode 0600 before writing any material.
pub(crate) fn write_key_0600(path: &Path, key_pem: &[u8]) -> Result<(), ClusterError> {
    use std::io::Write;

    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(io_error)?;
    file.write_all(key_pem).map_err(io_error)?;
    Ok(())
}

/// Forces an existing key file back to 0600 (for example after a manual copy).
pub(crate) fn tighten_key_permissions(path: &Path) -> Result<(), ClusterError> {
    let current = fs::metadata(path).map_err(io_error)?.permissions().mode() & 0o777;
    if current != 0o600 {
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).map_err(io_error)?;
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;

    fn temp_dir(name: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "dnscraft-cluster-{name}-{}-{nanos}",
            std::process::id()
        ))
    }

    #[test]
    fn ca_key_is_0600_and_never_in_debug() {
        let dir = temp_dir("ca");
        let cert_path = dir.join("ca.pem");
        let ca = ClusterCa::load_or_generate(&cert_path).unwrap();

        let key_path = dir.join("ca.key");
        let mode = fs::metadata(&key_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "cluster CA key must be mode 0600");

        let key_pem = fs::read_to_string(&key_path).unwrap();
        let debug = format!("{ca:?}");
        assert!(!debug.contains("PRIVATE KEY"), "{debug}");
        assert!(!debug.contains(key_pem.trim()), "{debug}");
        assert!(debug.contains("[redacted]"));

        assert!(ca.cert_pem().starts_with("-----BEGIN CERTIFICATE-----"));
        let cert_mode = fs::metadata(&cert_path).unwrap().permissions().mode() & 0o777;
        assert_ne!(cert_mode & 0o077, 0, "test expects a normal cert mode");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn ca_is_reused_across_restarts() {
        let dir = temp_dir("ca-reuse");
        let cert_path = dir.join("ca.pem");
        let first = ClusterCa::load_or_generate(&cert_path).unwrap();
        let second = ClusterCa::load_or_generate(&cert_path).unwrap();
        assert_eq!(first.cert_pem(), second.cert_pem());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn incomplete_ca_state_is_an_error() {
        let dir = temp_dir("ca-partial");
        fs::create_dir_all(&dir).unwrap();
        let cert_path = dir.join("ca.pem");
        fs::write(&cert_path, "not a ca").unwrap();
        let error = ClusterCa::load_or_generate(&cert_path).unwrap_err();
        assert_eq!(error.code(), "cluster.internal");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn fingerprint_is_sha256_hex() {
        // NIST test vector for "abc".
        assert_eq!(
            cert_fingerprint(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
