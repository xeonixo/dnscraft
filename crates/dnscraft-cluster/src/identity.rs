//! Sub-node identity: key + CSR generation, and durable storage of the
//! certificates received at enrollment.
//!
//! The private key is generated locally and never travels. It is written only
//! to the configured key path with mode `0600`, is held in a [`KeyPair`] whose
//! `Debug` output is redacted, and is never serialized into logs.

use std::fmt;
use std::fs;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use dnscraft_common::secret::Secret;
use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, PKCS_ECDSA_P256_SHA256};
use rustls_pki_types::CertificateDer;
use rustls_pki_types::pem::PemObject;
use x509_parser::prelude::{FromDer, X509Certificate};

use crate::ca::{
    io_error, node_id_from_der, prepare_parent, tighten_key_permissions, write_key_0600,
};
use crate::config::{TlsPaths, validate_node_id};
use crate::enroll::{EnrollRequest, EnrollResponse};
use crate::error::ClusterError;

/// A freshly generated node key and CSR, waiting for enrollment.
pub struct PendingNodeIdentity {
    node_id: String,
    key: KeyPair,
    csr_pem: String,
}

impl PendingNodeIdentity {
    /// Generates a ring-backed key pair and a CSR with `node_id` in both the
    /// subject Common Name and the single DNS SAN.
    pub fn generate(node_id: &str) -> Result<Self, ClusterError> {
        validate_node_id(node_id)?;

        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).map_err(|error| {
            ClusterError::Internal {
                message: format!("node key generation: {error}"),
            }
        })?;
        let csr_pem = csr_pem_for(node_id, &key)?;

        Ok(Self {
            node_id: node_id.to_owned(),
            key,
            csr_pem,
        })
    }

    /// The `node_id` this identity was generated for.
    pub fn node_id(&self) -> &str {
        &self.node_id
    }

    /// The PEM-encoded CSR to present to the master.
    pub fn csr_pem(&self) -> &str {
        &self.csr_pem
    }

    /// Builds the enroll request carrying the one-time `join_token`.
    pub fn request(&self, join_token: Secret) -> EnrollRequest {
        EnrollRequest::new(self.node_id.clone(), join_token, self.csr_pem.clone())
    }

    /// Persists the received CA and node certificates and this node's key under
    /// `paths`. The key file is created with mode `0600` and is never
    /// overwritten.
    pub fn persist(
        self,
        response: &EnrollResponse,
        paths: &TlsPaths,
    ) -> Result<NodeIdentity, ClusterError> {
        prepare_parent(&paths.ca_cert)?;
        fs::write(&paths.ca_cert, response.ca_cert_pem.as_bytes()).map_err(io_error)?;
        prepare_parent(&paths.node_cert)?;
        fs::write(&paths.node_cert, response.node_cert_pem.as_bytes()).map_err(io_error)?;
        prepare_parent(&paths.node_key)?;
        let key_pem = Secret::new(self.key.serialize_pem());
        write_key_0600(&paths.node_key, key_pem.expose().as_bytes())?;

        Ok(NodeIdentity {
            ca_cert_pem: response.ca_cert_pem.clone(),
            node_cert_pem: response.node_cert_pem.clone(),
            key: self.key,
        })
    }
}

/// PEM CSR for `node_id` signed with `key`; `node_id` is both the Common Name
/// and the single DNS SAN.
fn csr_pem_for(node_id: &str, key: &KeyPair) -> Result<String, ClusterError> {
    let mut params = CertificateParams::new(vec![node_id.to_owned()]).map_err(|error| {
        ClusterError::Internal {
            message: format!("node CSR params: {error}"),
        }
    })?;
    // `CertificateParams::new` keeps rcgen's placeholder CN; replace it.
    params.distinguished_name = DistinguishedName::new();
    params.distinguished_name.push(DnType::CommonName, node_id);

    let csr = params
        .serialize_request(key)
        .map_err(|error| ClusterError::Internal {
            message: format!("node CSR generation: {error}"),
        })?;
    csr.pem().map_err(|error| ClusterError::Internal {
        message: format!("node CSR encoding: {error}"),
    })
}

/// Parses the validity window of a PEM certificate and its node identity.
fn certificate_facts(cert_pem: &str) -> Result<(SystemTime, SystemTime, String), ClusterError> {
    let der = CertificateDer::from_pem_slice(cert_pem.as_bytes()).map_err(|error| {
        ClusterError::TransportTls {
            message: format!("node certificate PEM: {error}"),
        }
    })?;
    let (_, cert) =
        X509Certificate::from_der(der.as_ref()).map_err(|error| ClusterError::TransportTls {
            message: format!("node certificate DER: {error}"),
        })?;
    let validity = cert.validity();
    let not_before = unix_to_system_time(validity.not_before.timestamp());
    let not_after = unix_to_system_time(validity.not_after.timestamp());
    let node_id = node_id_from_der(der.as_ref()).ok_or(ClusterError::TransportTls {
        message: "node certificate has no node_id DNS SAN".to_owned(),
    })?;
    Ok((not_before, not_after, node_id))
}

fn unix_to_system_time(seconds: i64) -> SystemTime {
    match u64::try_from(seconds) {
        Ok(seconds) => UNIX_EPOCH + Duration::from_secs(seconds),
        Err(_) => UNIX_EPOCH,
    }
}

impl fmt::Debug for PendingNodeIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PendingNodeIdentity")
            .field("node_id", &self.node_id)
            .field("key", &"[redacted]")
            .field("csr_pem", &self.csr_pem)
            .finish()
    }
}

/// A loaded node identity: cluster CA, node certificate and private key.
pub struct NodeIdentity {
    ca_cert_pem: String,
    node_cert_pem: String,
    key: KeyPair,
}

impl NodeIdentity {
    /// Loads a previously persisted identity from `paths`, tightening the key
    /// file to mode `0600`.
    pub fn load(paths: &TlsPaths) -> Result<Self, ClusterError> {
        let ca_cert_pem = fs::read_to_string(&paths.ca_cert).map_err(io_error)?;
        let node_cert_pem = fs::read_to_string(&paths.node_cert).map_err(io_error)?;
        // Tighten before reading so the private key is never read with a mode
        // wider than 0600.
        tighten_key_permissions(&paths.node_key)?;
        let key_pem = Secret::new(fs::read_to_string(&paths.node_key).map_err(io_error)?);
        let key = KeyPair::from_pem(key_pem.expose()).map_err(|error| ClusterError::Internal {
            message: format!("invalid node key: {error}"),
        })?;
        Ok(Self {
            ca_cert_pem,
            node_cert_pem,
            key,
        })
    }

    /// The cluster CA certificate (PEM).
    pub fn ca_cert_pem(&self) -> &str {
        &self.ca_cert_pem
    }

    /// This node's certificate (PEM).
    pub fn node_cert_pem(&self) -> &str {
        &self.node_cert_pem
    }

    /// The private key for configuring the mTLS stack.
    ///
    /// Its `Debug` output is redacted. Never log, serialize, or persist it
    /// anywhere except the `0600` key file.
    pub fn key(&self) -> &KeyPair {
        &self.key
    }
}

impl NodeIdentity {
    /// Whether the node certificate has used two thirds of its lifetime at
    /// `now`, so a renewal should start.
    pub fn renewal_due(&self, now: SystemTime) -> Result<bool, ClusterError> {
        let (not_before, not_after, _) = certificate_facts(&self.node_cert_pem)?;
        let lifetime = not_after
            .duration_since(not_before)
            .unwrap_or(Duration::ZERO);
        Ok(now >= not_before + lifetime * 2 / 3)
    }

    /// A CSR for the node's current key and identity. Renewal keeps the key:
    /// only the certificate changes, so one file swap is atomic on disk.
    pub fn renewal_csr_pem(&self) -> Result<String, ClusterError> {
        let (_, _, node_id) = certificate_facts(&self.node_cert_pem)?;
        csr_pem_for(&node_id, &self.key)
    }

    /// Replaces the node certificate with `node_cert_pem` on disk.
    ///
    /// The new certificate must carry this node's key and identity. The file is
    /// written to a temporary sibling and renamed over the old one, so a crash
    /// leaves either the old or the new certificate, never a partial file.
    pub fn persist_renewed(
        &self,
        node_cert_pem: &str,
        paths: &TlsPaths,
    ) -> Result<(), ClusterError> {
        let (_, _, node_id) = certificate_facts(node_cert_pem)?;
        let der = CertificateDer::from_pem_slice(node_cert_pem.as_bytes()).map_err(|error| {
            ClusterError::TransportTls {
                message: format!("node certificate PEM: {error}"),
            }
        })?;
        let (_, cert) = X509Certificate::from_der(der.as_ref()).map_err(|error| {
            ClusterError::TransportTls {
                message: format!("node certificate DER: {error}"),
            }
        })?;
        if cert.public_key().subject_public_key.data.as_ref() != self.key.public_key_raw() {
            return Err(ClusterError::TransportTls {
                message: "renewed certificate does not match the node key".to_owned(),
            });
        }
        if node_id != self.certified_node_id()? {
            return Err(ClusterError::TransportTls {
                message: "renewed certificate names another node".to_owned(),
            });
        }
        let tmp = paths.node_cert.with_extension("pem.tmp");
        fs::write(&tmp, node_cert_pem.as_bytes()).map_err(io_error)?;
        fs::rename(&tmp, &paths.node_cert).map_err(io_error)
    }

    /// The `node_id` carried by this identity's certificate.
    fn certified_node_id(&self) -> Result<String, ClusterError> {
        let (_, _, node_id) = certificate_facts(&self.node_cert_pem)?;
        Ok(node_id)
    }
}

impl fmt::Debug for NodeIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NodeIdentity")
            .field("ca_cert_pem", &self.ca_cert_pem)
            .field("node_cert_pem", &self.node_cert_pem)
            .field("key", &"[redacted]")
            .finish()
    }
}
