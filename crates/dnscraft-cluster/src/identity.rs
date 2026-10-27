//! Sub-node identity: key + CSR generation, and durable storage of the
//! certificates received at enrollment.
//!
//! The private key is generated locally and never travels. It is written only
//! to the configured key path with mode `0600`, is held in a [`KeyPair`] whose
//! `Debug` output is redacted, and is never serialized into logs.

use std::fmt;
use std::fs;

use dnscraft_common::secret::Secret;
use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, PKCS_ECDSA_P256_SHA256};

use crate::ca::{io_error, prepare_parent, tighten_key_permissions, write_key_0600};
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
        let mut params = CertificateParams::new(vec![node_id.to_owned()]).map_err(|error| {
            ClusterError::Internal {
                message: format!("node CSR params: {error}"),
            }
        })?;
        // `CertificateParams::new` keeps rcgen's placeholder CN; replace it.
        params.distinguished_name = DistinguishedName::new();
        params.distinguished_name.push(DnType::CommonName, node_id);

        let csr = params
            .serialize_request(&key)
            .map_err(|error| ClusterError::Internal {
                message: format!("node CSR generation: {error}"),
            })?;
        let csr_pem = csr.pem().map_err(|error| ClusterError::Internal {
            message: format!("node CSR encoding: {error}"),
        })?;

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

impl fmt::Debug for NodeIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NodeIdentity")
            .field("ca_cert_pem", &self.ca_cert_pem)
            .field("node_cert_pem", &self.node_cert_pem)
            .field("key", &"[redacted]")
            .finish()
    }
}
