//! Loopback end-to-end proof of the cluster join slice:
//! enroll → mTLS connect → `hello` → heartbeat, plus the rejection matrix
//! (wrong CA, missing client certificate, unregistered fingerprint, revoked
//! node). Real sockets on `127.0.0.1:0`, generated CA/certs via `rcgen`, an
//! injectable [`ManualClock`], and no wall-clock waits.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::fs;
use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use dnscraft_cluster::{
    ClusterCa, ClusterClient, ClusterError, ClusterServer, ClusterServerConfig, ClusterStore,
    ListenConfig, LogIngest, LogRecord, NodeIdentity, PROTOCOL_VERSION, PendingNodeIdentity,
    QuotaConfig, RelayResponse, RelayedActor, TlsPaths, WriteExecutor,
};
use dnscraft_common::clock::{Clock, ManualClock};
use dnscraft_common::secret::Secret;
use rcgen::{
    BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose, PKCS_ECDSA_P256_SHA256,
};
use reqwest::Client;
use rustls::RootCertStore;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use serde_json::Value;

const NODE_CERT_TTL: Duration = Duration::from_secs(90 * 24 * 3600);
const TOKEN_TTL: Duration = Duration::from_secs(15 * 60);

/// Write relay is not exercised here.
struct NoWrites;

#[async_trait]
impl WriteExecutor for NoWrites {
    async fn execute(
        &self,
        _node_id: &str,
        _request_id: &str,
        _actor: RelayedActor,
        _method: String,
        _path: String,
        _body: Value,
        _if_match: Option<String>,
        _idempotency_key: Option<String>,
    ) -> Result<RelayResponse, ClusterError> {
        Err(ClusterError::Internal {
            message: "write relay not used in this test".to_owned(),
        })
    }
}

/// Log ingest is not exercised here.
struct NoLogs;

#[async_trait]
impl LogIngest for NoLogs {
    async fn ingest(
        &self,
        _node_id: &str,
        _first_seq: u64,
        _last_seq: u64,
        _records: &[LogRecord],
    ) -> Result<u64, ClusterError> {
        Err(ClusterError::Internal {
            message: "log ingest not used in this test".to_owned(),
        })
    }

    async fn highest_seq(&self, _node_id: &str) -> Result<u64, ClusterError> {
        Ok(0)
    }
}

/// A unique, self-cleaning temporary directory.
struct TestDir(PathBuf);

impl TestDir {
    fn new(name: &str) -> Self {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let id = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "dnscraft-cluster-join-{name}-{}-{id}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).unwrap();
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// A real master listening on loopback.
struct Master {
    server: ClusterServer,
    store: ClusterStore,
    clock: Arc<ManualClock>,
    dir: TestDir,
    url: String,
}

async fn start_master(name: &str) -> Master {
    // Explicit ring provider for every rustls/reqwest client in this test.
    let _ = rustls::crypto::ring::default_provider().install_default();

    let dir = TestDir::new(name);
    // Real wall-clock start keeps the freshly issued certificates valid for
    // rustls, which verifies against the system clock; time still only moves
    // when the test advances it.
    let clock = Arc::new(ManualClock::new(SystemTime::now()));
    let ca = ClusterCa::load_or_generate(&dir.path().join("ca.pem")).unwrap();
    let store = ClusterStore::open_in_memory(clock.clone(), TOKEN_TTL)
        .await
        .unwrap();
    let server = ClusterServer::start(
        ClusterServerConfig {
            listen: ListenConfig {
                bind: IpAddr::V4(Ipv4Addr::LOCALHOST),
                port: 0,
            },
            server_name: "127.0.0.1".to_owned(),
            node_cert_ttl: NODE_CERT_TTL,
            quota: QuotaConfig::default(),
        },
        ca,
        store.clone(),
        clock.clone(),
        Arc::new(NoWrites),
        Arc::new(NoLogs),
        None,
    )
    .await
    .unwrap();
    let url = format!("https://{}", server.addr());
    Master {
        server,
        store,
        clock,
        dir,
        url,
    }
}

/// Mints a token, enrolls `node_id` over the pinned bootstrap channel and
/// persists the returned identity.
async fn enroll_node(master: &Master, node_id: &str) -> NodeIdentity {
    let token = master.store.mint_join_token(node_id).await.unwrap();
    let pending = PendingNodeIdentity::generate(node_id).unwrap();
    let response = ClusterClient::enroll(
        &master.url,
        master.server.server_cert_pem(),
        pending.request(Secret::new(token.expose())),
    )
    .await
    .unwrap();
    let paths = TlsPaths {
        ca_cert: master.dir.path().join(format!("{node_id}-ca.pem")),
        node_cert: master.dir.path().join(format!("{node_id}.pem")),
        node_key: master.dir.path().join(format!("{node_id}.key")),
    };
    pending.persist(&response, &paths).unwrap()
}

/// reqwest HTTP/2 client trusting `ca_pem`, optionally presenting a client
/// certificate (`cert_pem`, PKCS #8 DER key).
fn http_client(ca_pem: &str, identity: Option<(&str, &[u8])>) -> Client {
    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from_pem_slice(ca_pem.as_bytes()).unwrap())
        .unwrap();
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(roots);
    let mut tls = match identity {
        Some((cert_pem, key_der)) => {
            let certs = CertificateDer::pem_slice_iter(cert_pem.as_bytes())
                .collect::<Result<Vec<_>, _>>()
                .unwrap();
            let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_der.to_vec()));
            builder.with_client_auth_cert(certs, key).unwrap()
        }
        None => builder.with_no_client_auth(),
    };
    tls.alpn_protocols = vec![b"h2".to_vec()];
    Client::builder()
        .use_preconfigured_tls(tls)
        .build()
        .unwrap()
}

async fn open_stream(client: &Client, master_url: &str) -> reqwest::Response {
    client
        .get(format!("{master_url}/cluster/v1/stream"))
        .header("x-cluster-protocol", PROTOCOL_VERSION.to_string())
        .send()
        .await
        .unwrap()
}

/// Reads a JSON error response as `(status, code)`.
async fn error_code(response: reqwest::Response) -> (u16, String) {
    let status = response.status().as_u16();
    let text = response.text().await.unwrap();
    let body: Value = serde_json::from_str(&text).unwrap();
    let code = body["error"]["code"].as_str().unwrap().to_owned();
    (status, code)
}

/// Generates a client certificate for `node_id` signed by the master's real
/// cluster CA, without enrolling it in the registry.
fn unregistered_cert(dir: &Path, node_id: &str) -> (String, Vec<u8>) {
    let ca_pem = fs::read_to_string(dir.join("ca.pem")).unwrap();
    let ca_key_pem = fs::read_to_string(dir.join("ca.key")).unwrap();
    let ca_key = KeyPair::from_pem(&ca_key_pem).unwrap();
    let issuer = Issuer::from_ca_cert_pem(&ca_pem, ca_key).unwrap();
    sign_leaf(&issuer, node_id)
}

/// Generates a self-signed foreign CA and a leaf under it.
fn foreign_leaf(node_id: &str) -> (String, Vec<u8>) {
    let ca_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let mut params = CertificateParams::new(Vec::new()).unwrap();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    let ca_cert = params.self_signed(&ca_key).unwrap();
    let issuer = Issuer::from_ca_cert_pem(&ca_cert.pem(), ca_key).unwrap();
    sign_leaf(&issuer, node_id)
}

fn sign_leaf(issuer: &Issuer<'_, KeyPair>, node_id: &str) -> (String, Vec<u8>) {
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let mut params = CertificateParams::new(vec![node_id.to_owned()]).unwrap();
    params.is_ca = IsCa::NoCa;
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![
        ExtendedKeyUsagePurpose::ClientAuth,
        ExtendedKeyUsagePurpose::ServerAuth,
    ];
    let cert = params.signed_by(&key, issuer).unwrap();
    (cert.pem(), key.serialize_der())
}

fn unix_now(clock: &ManualClock) -> i64 {
    clock.now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64
}

#[tokio::test]
async fn enroll_connect_hello_and_heartbeat() {
    let master = start_master("happy").await;
    let identity = enroll_node(&master, "node-a").await;

    let client = ClusterClient::new(&master.url, &identity, master.clock.clone()).unwrap();
    assert_eq!(client.node_id(), "node-a");

    let stream = client.open_stream().await.unwrap();
    assert_eq!(stream.node_id(), "node-a");
    assert_eq!(stream.protocol(), PROTOCOL_VERSION);

    let heartbeat = client.heartbeat(Some(3), 0).await.unwrap();
    assert!(heartbeat.ok);
    assert!(!heartbeat.received_at.is_empty());

    let node = master.store.get_node("node-a").await.unwrap().unwrap();
    assert_eq!(node.applied_config_version, Some(3));
    assert_eq!(node.last_seen, Some(unix_now(&master.clock)));

    // A payload `node_id` is ignored: the master uses the certificate identity.
    let der = identity.key().serialize_der();
    let raw = http_client(
        master.server.ca_cert_pem(),
        Some((identity.node_cert_pem(), &der)),
    );
    let response = raw
        .post(format!("{}/cluster/v1/heartbeat", master.url))
        .header("content-type", "application/json")
        .body(r#"{"protocol":1,"applied_version":9,"queue_depth":0,"node_id":"node-b"}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 200);
    let node = master.store.get_node("node-a").await.unwrap().unwrap();
    assert_eq!(node.applied_config_version, Some(9));
    assert!(master.store.get_node("node-b").await.unwrap().is_none());

    // A protocol mismatch ends the stream with the documented error record.
    let mismatch = raw
        .get(format!("{}/cluster/v1/stream", master.url))
        .header("x-cluster-protocol", "2")
        .send()
        .await
        .unwrap();
    assert_eq!(mismatch.status().as_u16(), 200);
    let text = mismatch.text().await.unwrap();
    let record: Value = serde_json::from_str(text.trim()).unwrap();
    assert_eq!(record["type"], "error");
    assert_eq!(record["error"]["code"], "cluster.protocol.version");

    drop(stream);
    master.server.shutdown().await;
}

#[tokio::test]
async fn missing_unregistered_revoked_and_wrong_ca_are_rejected() {
    let master = start_master("reject").await;

    // Missing client certificate.
    let anonymous = http_client(master.server.ca_cert_pem(), None);
    let response = open_stream(&anonymous, &master.url).await;
    assert_eq!(
        error_code(response).await,
        (403, "cluster.transport.tls".to_owned())
    );

    // A certificate that chains to the cluster CA but was never registered.
    let (cert, key) = unregistered_cert(master.dir.path(), "node-z");
    let stranger = http_client(master.server.ca_cert_pem(), Some((&cert, &key)));
    let response = open_stream(&stranger, &master.url).await;
    assert_eq!(
        error_code(response).await,
        (403, "cluster.node.unknown".to_owned())
    );

    // A registered node that was revoked.
    let revoked_identity = enroll_node(&master, "node-b").await;
    master.store.revoke("node-b").await.unwrap();
    let der = revoked_identity.key().serialize_der();
    let revoked = http_client(
        master.server.ca_cert_pem(),
        Some((revoked_identity.node_cert_pem(), &der)),
    );
    let response = open_stream(&revoked, &master.url).await;
    assert_eq!(
        error_code(response).await,
        (403, "cluster.node.revoked".to_owned())
    );

    // A client certificate signed by another CA: rustls rejects the mTLS
    // handshake, so the documented `cluster.transport.tls` failure happens
    // before any HTTP response can carry a body.
    let (foreign_cert, foreign_key) = foreign_leaf("node-w");
    let wrong_ca = http_client(
        master.server.ca_cert_pem(),
        Some((&foreign_cert, &foreign_key)),
    );
    let result = wrong_ca
        .get(format!("{}/cluster/v1/stream", master.url))
        .header("x-cluster-protocol", PROTOCOL_VERSION.to_string())
        .send()
        .await;
    assert!(result.is_err(), "wrong-CA client certificate was accepted");

    master.server.shutdown().await;
}
