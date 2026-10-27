//! The in-process enroll protocol: a sub-node presents a one-time join token
//! and a CSR, and the master returns the cluster CA and a signed node
//! certificate.
//!
//! No socket is opened here. [`enroll`] is the master-side logic the transport
//! slice will call after decoding `POST /cluster/v1/enroll`; the request and
//! response types are its wire shape.

use std::fmt;
use std::time::Duration;

use dnscraft_common::clock::Clock;
use dnscraft_common::secret::Secret;
use rcgen::{
    CertificateParams, CertificateSigningRequestParams, DnType, DnValue, ExtendedKeyUsagePurpose,
    IsCa, KeyUsagePurpose, SanType,
};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use time::OffsetDateTime;

use crate::ca::{ClusterCa, cert_fingerprint};
use crate::config::validate_node_id;
use crate::error::ClusterError;
use crate::store::ClusterStore;

/// Cluster enroll protocol version.
pub const PROTOCOL_VERSION: u32 = 1;

/// A sub-node's enrollment request (`POST /cluster/v1/enroll` body).
///
/// The one-time join token is a credential that exists to travel over this
/// message. It is held in a [`Secret`] so [`Debug`] and logs redact it; the
/// encoded request must never be logged.
#[derive(Clone, PartialEq, Eq)]
pub struct EnrollRequest {
    /// Protocol version; must equal [`PROTOCOL_VERSION`].
    pub protocol: u32,
    /// The identity this node is claiming (also expected in the CSR SAN).
    pub node_id: String,
    /// One-time token minted by the master for `node_id`.
    pub join_token: Secret,
    /// PEM-encoded PKCS #10 certificate signing request.
    pub csr_pem: String,
}

impl EnrollRequest {
    /// Builds a request at the current [`PROTOCOL_VERSION`].
    pub fn new(node_id: impl Into<String>, join_token: Secret, csr_pem: impl Into<String>) -> Self {
        Self {
            protocol: PROTOCOL_VERSION,
            node_id: node_id.into(),
            join_token,
            csr_pem: csr_pem.into(),
        }
    }

    /// Rejects a request from an incompatible cluster protocol version.
    pub fn check_protocol(&self) -> Result<(), ClusterError> {
        if self.protocol == PROTOCOL_VERSION {
            Ok(())
        } else {
            Err(ClusterError::ProtocolVersion)
        }
    }
}

impl fmt::Debug for EnrollRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EnrollRequest")
            .field("protocol", &self.protocol)
            .field("node_id", &self.node_id)
            .field("join_token", &"[redacted]")
            .field("csr_pem", &self.csr_pem)
            .finish()
    }
}

impl Serialize for EnrollRequest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        use serde::ser::SerializeStruct;

        let mut request = serializer.serialize_struct("EnrollRequest", 4)?;
        request.serialize_field("protocol", &self.protocol)?;
        request.serialize_field("node_id", &self.node_id)?;
        // This is the wire encoding: the token must reach the master. Never
        // log the encoded request.
        request.serialize_field("join_token", self.join_token.expose())?;
        request.serialize_field("csr_pem", &self.csr_pem)?;
        request.end()
    }
}

impl<'de> Deserialize<'de> for EnrollRequest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Wire {
            protocol: u32,
            node_id: String,
            join_token: String,
            csr_pem: String,
        }

        let wire = Wire::deserialize(deserializer)?;
        Ok(Self {
            protocol: wire.protocol,
            node_id: wire.node_id,
            join_token: Secret::new(wire.join_token),
            csr_pem: wire.csr_pem,
        })
    }
}

/// The master's answer: the cluster CA and this node's signed certificate.
///
/// Both are public certificates; the node's private key never leaves the node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnrollResponse {
    /// Cluster CA certificate (PEM).
    pub ca_cert_pem: String,
    /// The node certificate signed by the cluster CA (PEM).
    pub node_cert_pem: String,
}

/// Master-side enrollment.
///
/// Verifies the protocol version, the CSR's `node_id` binding, and the one-time
/// join token; signs a node certificate with `ca`; and consumes the token while
/// registering the node's certificate fingerprint atomically. `node_cert_ttl`
/// is the issued certificate lifetime (`[cluster.join] node_cert_ttl`).
pub async fn enroll(
    ca: &ClusterCa,
    store: &ClusterStore,
    clock: &dyn Clock,
    node_cert_ttl: Duration,
    request: EnrollRequest,
) -> Result<EnrollResponse, ClusterError> {
    request.check_protocol()?;
    validate_node_id(&request.node_id)?;

    let csr = CertificateSigningRequestParams::from_pem(&request.csr_pem).map_err(|error| {
        ClusterError::Internal {
            message: format!("invalid node CSR: {error}"),
        }
    })?;
    verify_node_binding(&csr.params, &request.node_id)?;

    // The master, not the CSR, decides what the certificate may authorize.
    let CertificateSigningRequestParams {
        mut params,
        public_key,
    } = csr;
    params.is_ca = IsCa::NoCa;
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![
        ExtendedKeyUsagePurpose::ClientAuth,
        ExtendedKeyUsagePurpose::ServerAuth,
    ];
    params.not_before = OffsetDateTime::from(clock.now());
    let ttl = time::Duration::try_from(node_cert_ttl).map_err(|_| ClusterError::Internal {
        message: "node certificate lifetime is out of range".to_owned(),
    })?;
    params.not_after =
        params
            .not_before
            .checked_add(ttl)
            .ok_or_else(|| ClusterError::Internal {
                message: "node certificate lifetime overflows".to_owned(),
            })?;
    params.use_authority_key_identifier_extension = true;

    let node_cert = ca.sign(&params, &public_key)?;
    let fingerprint = cert_fingerprint(node_cert.der());

    store
        .redeem_join_token_and_register(request.join_token.expose(), &request.node_id, &fingerprint)
        .await?;

    Ok(EnrollResponse {
        ca_cert_pem: ca.cert_pem().to_owned(),
        node_cert_pem: node_cert.pem(),
    })
}

/// Requires the CSR to name exactly the requesting `node_id`: one DNS SAN equal
/// to it, and a Common Name (when present) equal to it too.
fn verify_node_binding(params: &CertificateParams, node_id: &str) -> Result<(), ClusterError> {
    let san_matches = params.subject_alt_names.len() == 1
        && matches!(
            params.subject_alt_names.first(),
            Some(SanType::DnsName(name)) if name.as_str() == node_id
        );
    let cn_matches = params
        .distinguished_name
        .get(&DnType::CommonName)
        .is_none_or(|value| dn_value_str(value) == Some(node_id));

    if san_matches && cn_matches {
        Ok(())
    } else {
        // The CSR is not for the node the token was minted for.
        Err(ClusterError::JoinTokenInvalid)
    }
}

fn dn_value_str(value: &DnValue) -> Option<&str> {
    match value {
        DnValue::Utf8String(value) => Some(value.as_str()),
        DnValue::Ia5String(value) => Some(value.as_str()),
        DnValue::PrintableString(value) => Some(value.as_str()),
        DnValue::TeletexString(value) => Some(value.as_str()),
        _ => None,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};
    use std::sync::Arc;
    use std::time::{SystemTime, UNIX_EPOCH};

    use dnscraft_common::clock::ManualClock;
    use rustls_pki_types::CertificateDer;
    use rustls_pki_types::pem::PemObject;

    use super::*;
    use crate::config::{DEFAULT_NODE_CERT_TTL, TlsPaths};
    use crate::identity::{NodeIdentity, PendingNodeIdentity};
    use crate::store::MintedJoinToken;

    const TOKEN_TTL: Duration = Duration::from_secs(15 * 60);

    fn temp_dir(name: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "dnscraft-cluster-enroll-{name}-{}-{nanos}",
            std::process::id()
        ))
    }

    fn clock() -> Arc<ManualClock> {
        Arc::new(ManualClock::new(
            UNIX_EPOCH + Duration::from_secs(1_700_000_000),
        ))
    }

    async fn store(clock: Arc<ManualClock>) -> ClusterStore {
        ClusterStore::open_in_memory(clock, TOKEN_TTL)
            .await
            .unwrap()
    }

    fn ca(dir: &Path) -> ClusterCa {
        ClusterCa::load_or_generate(&dir.join("ca.pem")).unwrap()
    }

    fn request_for(
        store_token: &MintedJoinToken,
        claimed_node_id: &str,
        csr_node_id: &str,
    ) -> (EnrollRequest, PendingNodeIdentity) {
        let pending = PendingNodeIdentity::generate(csr_node_id).unwrap();
        let request = EnrollRequest::new(
            claimed_node_id,
            Secret::new(store_token.expose()),
            pending.csr_pem(),
        );
        (request, pending)
    }

    #[tokio::test]
    async fn happy_path_returns_ca_and_node_cert_and_registers_fingerprint() {
        let dir = temp_dir("happy");
        let ca = ca(&dir);
        let clock = clock();
        let store = store(Arc::clone(&clock)).await;
        let minted = store.mint_join_token("node-a").await.unwrap();
        let (request, pending) = request_for(&minted, "node-a", "node-a");

        let debug = format!("{request:?}");
        assert!(!debug.contains(minted.expose()), "{debug}");
        assert!(debug.contains("[redacted]"));

        let response = enroll(&ca, &store, clock.as_ref(), DEFAULT_NODE_CERT_TTL, request)
            .await
            .unwrap();

        assert_eq!(response.ca_cert_pem, ca.cert_pem());
        assert!(
            response
                .node_cert_pem
                .starts_with("-----BEGIN CERTIFICATE-----")
        );

        let der = CertificateDer::from_pem_slice(response.node_cert_pem.as_bytes()).unwrap();
        let node = store.get_node("node-a").await.unwrap().unwrap();
        assert_eq!(node.fingerprint, cert_fingerprint(der.as_ref()));
        assert_eq!(node.last_seen, Some(1_700_000_000));

        // Persist and reload the local half of the identity.
        let paths = TlsPaths {
            ca_cert: dir.join("ca.pem"),
            node_cert: dir.join("node.pem"),
            node_key: dir.join("node.key"),
        };
        let identity = pending.persist(&response, &paths).unwrap();
        let mode = fs::metadata(&paths.node_key).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "node key must be mode 0600");
        let key_pem = fs::read_to_string(&paths.node_key).unwrap();
        assert!(key_pem.contains("PRIVATE KEY"));
        let debug = format!("{identity:?}");
        assert!(!debug.contains(key_pem.trim()), "{debug}");
        assert!(!debug.contains("PRIVATE KEY"), "{debug}");
        assert!(debug.contains("[redacted]"));

        let loaded = NodeIdentity::load(&paths).unwrap();
        assert_eq!(loaded.ca_cert_pem(), response.ca_cert_pem);
        assert_eq!(loaded.node_cert_pem(), response.node_cert_pem);
        assert_eq!(loaded.key().serialize_pem(), key_pem);

        let _ = fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn unknown_or_replayed_token_is_invalid() {
        let dir = temp_dir("replay");
        let ca = ca(&dir);
        let clock = clock();
        let store = store(Arc::clone(&clock)).await;

        let (request, _) = request_for(
            &store.mint_join_token("node-a").await.unwrap(),
            "node-a",
            "node-a",
        );
        let unknown = EnrollRequest::new(
            "node-a",
            Secret::new("not-a-real-token"),
            request.csr_pem.clone(),
        );
        let error = enroll(&ca, &store, clock.as_ref(), DEFAULT_NODE_CERT_TTL, unknown)
            .await
            .unwrap_err();
        assert_eq!(error.code(), "cluster.join.token_invalid");
        assert!(store.get_node("node-a").await.unwrap().is_none());

        let minted = store.mint_join_token("node-a").await.unwrap();
        let (first, _) = request_for(&minted, "node-a", "node-a");
        enroll(&ca, &store, clock.as_ref(), DEFAULT_NODE_CERT_TTL, first)
            .await
            .unwrap();

        // Replaying the same token with a fresh CSR fails: the token is gone.
        let (second, _) = request_for(&minted, "node-a", "node-a");
        let error = enroll(&ca, &store, clock.as_ref(), DEFAULT_NODE_CERT_TTL, second)
            .await
            .unwrap_err();
        assert_eq!(error.code(), "cluster.join.token_invalid");

        let _ = fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn expired_token_is_rejected_and_not_registered() {
        let dir = temp_dir("expired");
        let ca = ca(&dir);
        let clock = clock();
        let store = store(Arc::clone(&clock)).await;
        let minted = store.mint_join_token("node-a").await.unwrap();
        let (request, _) = request_for(&minted, "node-a", "node-a");

        clock.advance(TOKEN_TTL);
        let error = enroll(&ca, &store, clock.as_ref(), DEFAULT_NODE_CERT_TTL, request)
            .await
            .unwrap_err();
        assert_eq!(error.code(), "cluster.join.token_expired");
        assert!(store.get_node("node-a").await.unwrap().is_none());

        let _ = fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn token_bound_to_another_node_id_is_rejected_and_survives() {
        let dir = temp_dir("bound");
        let ca = ca(&dir);
        let clock = clock();
        let store = store(Arc::clone(&clock)).await;
        let minted = store.mint_join_token("node-a").await.unwrap();

        let (request, _) = request_for(&minted, "node-b", "node-b");
        let error = enroll(&ca, &store, clock.as_ref(), DEFAULT_NODE_CERT_TTL, request)
            .await
            .unwrap_err();
        assert_eq!(error.code(), "cluster.join.token_invalid");
        assert!(store.get_node("node-b").await.unwrap().is_none());

        // The token was not consumed: it still enrolls its intended node.
        let (request, _) = request_for(&minted, "node-a", "node-a");
        enroll(&ca, &store, clock.as_ref(), DEFAULT_NODE_CERT_TTL, request)
            .await
            .unwrap();
        assert!(store.get_node("node-a").await.unwrap().is_some());

        let _ = fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn csr_naming_another_node_is_rejected_and_token_survives() {
        let dir = temp_dir("csr-mismatch");
        let ca = ca(&dir);
        let clock = clock();
        let store = store(Arc::clone(&clock)).await;
        let minted = store.mint_join_token("node-a").await.unwrap();

        // Claims node-a but presents node-b's CSR.
        let (request, _) = request_for(&minted, "node-a", "node-b");
        let error = enroll(&ca, &store, clock.as_ref(), DEFAULT_NODE_CERT_TTL, request)
            .await
            .unwrap_err();
        assert_eq!(error.code(), "cluster.join.token_invalid");
        assert!(store.get_node("node-a").await.unwrap().is_none());

        let (request, _) = request_for(&minted, "node-a", "node-a");
        enroll(&ca, &store, clock.as_ref(), DEFAULT_NODE_CERT_TTL, request)
            .await
            .unwrap();

        let _ = fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn already_joined_node_is_rejected() {
        let dir = temp_dir("joined");
        let ca = ca(&dir);
        let clock = clock();
        let store = store(Arc::clone(&clock)).await;
        let minted = store.mint_join_token("node-a").await.unwrap();
        store.register_node("node-a", "existing").await.unwrap();
        let (request, _) = request_for(&minted, "node-a", "node-a");

        let error = enroll(&ca, &store, clock.as_ref(), DEFAULT_NODE_CERT_TTL, request)
            .await
            .unwrap_err();
        assert_eq!(error.code(), "cluster.node.already_joined");
        assert_eq!(
            store.get_node("node-a").await.unwrap().unwrap().fingerprint,
            "existing"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn protocol_version_and_malformed_csr_are_rejected() {
        let dir = temp_dir("version");
        let ca = ca(&dir);
        let clock = clock();
        let store = store(Arc::clone(&clock)).await;
        let minted = store.mint_join_token("node-a").await.unwrap();

        let (mut request, _) = request_for(&minted, "node-a", "node-a");
        request.protocol = PROTOCOL_VERSION + 1;
        let error = enroll(&ca, &store, clock.as_ref(), DEFAULT_NODE_CERT_TTL, request)
            .await
            .unwrap_err();
        assert_eq!(error.code(), "cluster.protocol.version");

        let bad = EnrollRequest::new("node-a", Secret::new(minted.expose()), "not a csr");
        let error = enroll(&ca, &store, clock.as_ref(), DEFAULT_NODE_CERT_TTL, bad)
            .await
            .unwrap_err();
        assert_eq!(error.code(), "cluster.internal");

        let _ = fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn request_round_trips_without_leaking_in_debug() {
        let request = EnrollRequest::new(
            "node-a",
            Secret::new("one-time-token"),
            "csr-pem-placeholder",
        );
        let json = serde_json::to_string(&request).unwrap();
        let decoded: EnrollRequest = serde_json::from_str(&json).unwrap();

        assert_eq!(decoded.protocol, PROTOCOL_VERSION);
        assert_eq!(decoded.node_id, "node-a");
        assert_eq!(decoded.join_token.expose(), "one-time-token");
        assert!(!format!("{request:?}").contains("one-time-token"));
    }
}
