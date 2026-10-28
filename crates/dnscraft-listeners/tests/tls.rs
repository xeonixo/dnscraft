//! N6: TLS server configs, SNI admission, hot reload.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod support;

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, SystemTime};

use dnscraft_listeners::{
    AcceptEncrypted, Admission, ClientIdState, Exposure, Limits, ListenerCertResolver, ManualClock,
    PolicyClientIds, PublicConfig, PublicSniOutcome, SniGate, SniRejectKind, SystemClock,
    TlsPolicy, TlsStats, accept_encrypted, apply_sni_strike, client_id_state_local,
    inspect_public_sni, quic_server_config, tcp_server_config,
};
use dnscraft_policy::{ClientId, PolicyConfig};
use dnscraft_tls::{CertResolver, ClientIdRegistry, ReservedLabels};
use rustls::ClientConfig;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::ring::default_provider;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, Error as RustlsError, SignatureScheme};
use support::certs::{example_dns_cert, example_dns_cert_b};
use support::{policy_engine_with_client_ids, poll_until};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsConnector;

const DOMAIN: &str = "example.com";
const HANDSHAKE: Duration = Duration::from_secs(5);

fn gate(registry: Arc<dyn dnscraft_tls::ClientIdRegistry>) -> SniGate {
    SniGate {
        public_domain: DOMAIN.into(),
        reserved: Arc::new(std::sync::RwLock::new(ReservedLabels::new(
            ["node1".into()],
        ))),
        registry,
    }
}

fn install_ring() {
    let _ = default_provider().install_default();
}

#[derive(Debug)]
struct AcceptAllVerifier {
    seen_leaf: Arc<AtomicUsize>,
    leaves: Arc<Vec<Vec<u8>>>,
}

impl ServerCertVerifier for AcceptAllVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        let der = end_entity.as_ref();
        if let Some(idx) = self.leaves.iter().position(|l| l.as_slice() == der) {
            self.seen_leaf.store(idx + 1, Ordering::SeqCst);
        } else {
            self.seen_leaf.store(99, Ordering::SeqCst);
        }
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

fn client_connector(
    leaves: Arc<Vec<Vec<u8>>>,
    seen: Arc<AtomicUsize>,
    alpn: &[u8],
) -> TlsConnector {
    let verifier = Arc::new(AcceptAllVerifier {
        seen_leaf: seen,
        leaves,
    });
    let mut cfg = ClientConfig::builder_with_provider(Arc::new(default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    cfg.alpn_protocols = vec![alpn.to_vec()];
    cfg.resumption = rustls::client::Resumption::disabled();
    TlsConnector::from(Arc::new(cfg))
}

async fn handshake_as_client(
    addr: SocketAddr,
    sni: Option<&str>,
    leaves: Arc<Vec<Vec<u8>>>,
) -> Result<(), String> {
    let seen = Arc::new(AtomicUsize::new(0));
    let connector = client_connector(leaves, seen, b"dot");
    let tcp = TcpStream::connect(addr).await.map_err(|e| e.to_string())?;
    let name = match sni {
        Some(s) => ServerName::try_from(s.to_owned()).map_err(|e| e.to_string())?,
        None => {
            // rustls requires a ServerName for the connector; use a placeholder IP
            // name and omit DNS SNI via… not possible with TlsConnector easily.
            // Tests that need missing SNI use inspect_public_sni unit checks.
            ServerName::try_from("missing.invalid").map_err(|e| e.to_string())?
        }
    };
    let mut tls = connector
        .connect(name, tcp)
        .await
        .map_err(|e| e.to_string())?;
    tls.write_all(b"ping").await.map_err(|e| e.to_string())?;
    let mut buf = [0u8; 4];
    tls.read_exact(&mut buf).await.map_err(|e| e.to_string())?;
    if &buf != b"pong" {
        return Err(format!("bad echo {buf:?}"));
    }
    Ok(())
}

struct ServerHarness {
    addr: SocketAddr,
    join: tokio::task::JoinHandle<()>,
    stats: Arc<TlsStats>,
    certs: Arc<CertResolver>,
}

impl ServerHarness {
    async fn spawn(
        exposure: Exposure,
        gate: SniGate,
        certs: Arc<CertResolver>,
        resolver: Arc<ListenerCertResolver>,
    ) -> Self {
        let stats = Arc::clone(resolver.stats());
        let config = tcp_server_config(
            resolver,
            &[dnscraft_listeners::ALPN_DOT],
            &TlsPolicy::default(),
        );
        let admission = if exposure == Exposure::Public {
            support::public_test_admission(&Limits::default(), &PublicConfig::default())
        } else {
            support::admission_for(&Limits::default(), &PublicConfig::default())
        };
        let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();
        let adm = Arc::clone(&admission);
        let gate = Arc::new(gate);
        let certs_c = Arc::clone(&certs);
        let stats_c = Arc::clone(&stats);
        let clock = Arc::new(SystemClock);
        let join = tokio::spawn(async move {
            loop {
                let Ok((tcp, peer)) = listener.accept().await else {
                    break;
                };
                let config = Arc::clone(&config);
                let gate = Arc::clone(&gate);
                let adm = Arc::clone(&adm);
                let certs = Arc::clone(&certs_c);
                let stats = Arc::clone(&stats_c);
                let clock = Arc::clone(&clock);
                tokio::spawn(async move {
                    if let Ok(acc) = accept_encrypted(
                        tcp,
                        AcceptEncrypted {
                            config,
                            exposure,
                            gate: gate.as_ref(),
                            certs: certs.as_ref(),
                            admission: adm.as_ref(),
                            peer: peer.ip(),
                            clock: clock.as_ref(),
                            handshake_timeout: HANDSHAKE,
                            stats: stats.as_ref(),
                        },
                    )
                    .await
                    {
                        let mut stream = acc.stream;
                        let mut buf = [0u8; 4];
                        if stream.read_exact(&mut buf).await.is_ok() && &buf == b"ping" {
                            let _ = stream.write_all(b"pong").await;
                        }
                    }
                });
            }
        });
        Self {
            addr,
            join,
            stats,
            certs,
        }
    }

    async fn stop(self) {
        self.join.abort();
        let _ = self.join.await;
    }
}

#[tokio::test]
async fn policy_client_ids_follows_apply_config_and_lowercases() {
    install_ring();
    let engine = policy_engine_with_client_ids(&["phone"]).await;
    let reg = PolicyClientIds(Arc::clone(&engine));
    assert!(reg.is_registered("phone"));
    assert!(reg.is_registered("PHONE"), "adapter must lower-case");
    assert!(!reg.is_registered("unknown"));

    let without = PolicyConfig {
        client_ids: Vec::new(),
        records: Vec::new(),
        views: vec![dnscraft_policy::ViewConfig {
            id: dnscraft_policy::ViewId::new("default").unwrap(),
            is_default: true,
            subnets: Vec::new(),
            nodes: Vec::new(),
            profile: dnscraft_policy::ProfileId::new("default").unwrap(),
        }],
        profiles: vec![dnscraft_policy::ProfileConfig {
            id: dnscraft_policy::ProfileId::new("default").unwrap(),
            filter_set: dnscraft_filtering::SetId::new("default").unwrap(),
            suppress_aaaa: false,
            firefox_canary: false,
            icloud_private_relay: false,
            rebind: Some(false),
            rebind_exceptions: Vec::new(),
            forward_zones: None,
            safesearch: dnscraft_policy::SafeSearchConfig::default(),
            schedules: Vec::new(),
        }],
        ..PolicyConfig::default()
    };
    engine.apply_config(without).await.unwrap();
    assert!(!reg.is_registered("phone"));
}

#[test]
fn inspect_public_sni_matrix() {
    install_ring();
    let reg = Arc::new(SetReg(vec!["phone".into()]));
    let g = gate(reg);

    assert!(matches!(
        inspect_public_sni(Some("phone.dns.example.com"), &g),
        PublicSniOutcome::Accept { .. }
    ));
    assert!(matches!(
        inspect_public_sni(Some("PHONE.dns.example.com"), &g),
        PublicSniOutcome::Accept { .. }
    ));
    assert_eq!(
        inspect_public_sni(Some("unknown.dns.example.com"), &g),
        PublicSniOutcome::Reject {
            strike: true,
            kind: SniRejectKind::UnknownClientId
        }
    );
    assert_eq!(
        inspect_public_sni(None, &g),
        PublicSniOutcome::Reject {
            strike: true,
            kind: SniRejectKind::Missing
        }
    );
    assert_eq!(
        inspect_public_sni(Some("node1.dns.example.com"), &g),
        PublicSniOutcome::Reject {
            strike: false,
            kind: SniRejectKind::NodeHostname
        }
    );
    assert_eq!(
        inspect_public_sni(Some("dns.example.com"), &g),
        PublicSniOutcome::Reject {
            strike: false,
            kind: SniRejectKind::Apex
        }
    );

    // Strikes only for missing / unknown; public peer records them.
    let mut adm = Admission::new(
        &Limits::default(),
        &PublicConfig {
            ban_strikes: 2,
            ..PublicConfig::default()
        },
    );
    let public_peer: IpAddr = "203.0.113.50".parse().unwrap();
    let now = SystemTime::UNIX_EPOCH + Duration::from_secs(100);
    let unknown = inspect_public_sni(Some("unknown.dns.example.com"), &g);
    apply_sni_strike(&mut adm, public_peer, &unknown, now);
    apply_sni_strike(&mut adm, public_peer, &unknown, now);
    // After 2 strikes → banned.
    let decision = adm.check(
        &dnscraft_listeners::ListenerConfig {
            node_id: None,
            id: dnscraft_policy::ListenerId::new("t").unwrap(),
            protocol: dnscraft_listeners::Protocol::Dot,
            address: SocketAddr::from((Ipv4Addr::LOCALHOST, 853)),
            exposure: Exposure::Public,
            h3: false,
            tls_policy: None,
        },
        public_peer,
        &ClientIdState::Absent,
        now,
    );
    assert!(matches!(
        decision,
        dnscraft_listeners::AdmitDecision::Drop {
            code: "listeners.banned"
        }
    ));
}

#[test]
fn local_unknown_sni_ignored() {
    let reg = Arc::new(SetReg(vec!["phone".into()]));
    let g = gate(reg);
    assert_eq!(
        client_id_state_local(Some("unknown.dns.example.com"), &g),
        ClientIdState::Absent
    );
    assert_eq!(
        client_id_state_local(Some("phone.dns.example.com"), &g),
        ClientIdState::Registered(ClientId::new("phone").unwrap())
    );
    assert_eq!(
        client_id_state_local(Some("PHONE.dns.example.com"), &g),
        ClientIdState::Registered(ClientId::new("phone").unwrap())
    );
}

#[tokio::test]
async fn handshake_matrix_local_and_public() {
    install_ring();
    let engine = policy_engine_with_client_ids(&["phone"]).await;
    let reg: Arc<dyn dnscraft_tls::ClientIdRegistry> = Arc::new(PolicyClientIds(engine));
    let g = gate(Arc::clone(&reg));
    let (pem, key, der) = example_dns_cert();
    let leaves = Arc::new(vec![der]);

    // --- Local ---
    let certs = Arc::new(CertResolver::new());
    certs.install(&pem, &key).unwrap();
    let stats = Arc::new(TlsStats::default());
    let resolver = ListenerCertResolver::local(Arc::clone(&certs), Arc::clone(&stats));
    let local =
        ServerHarness::spawn(Exposure::Local, g.clone(), Arc::clone(&certs), resolver).await;

    handshake_as_client(
        local.addr,
        Some("phone.dns.example.com"),
        Arc::clone(&leaves),
    )
    .await
    .expect("local registered");
    handshake_as_client(
        local.addr,
        Some("PHONE.dns.example.com"),
        Arc::clone(&leaves),
    )
    .await
    .expect("local upper-case registered");
    handshake_as_client(
        local.addr,
        Some("unknown.dns.example.com"),
        Arc::clone(&leaves),
    )
    .await
    .expect("local unknown ignored");
    handshake_as_client(
        local.addr,
        Some("node1.dns.example.com"),
        Arc::clone(&leaves),
    )
    .await
    .expect("local node ignored");
    handshake_as_client(local.addr, Some("dns.example.com"), Arc::clone(&leaves))
        .await
        .expect("local apex ignored");
    local.stop().await;

    // --- Public ---
    let certs = Arc::new(CertResolver::new());
    certs.install(&pem, &key).unwrap();
    let stats = Arc::new(TlsStats::default());
    let resolver = ListenerCertResolver::local(Arc::clone(&certs), Arc::clone(&stats));
    let public =
        ServerHarness::spawn(Exposure::Public, g.clone(), Arc::clone(&certs), resolver).await;

    handshake_as_client(
        public.addr,
        Some("phone.dns.example.com"),
        Arc::clone(&leaves),
    )
    .await
    .expect("public registered");
    handshake_as_client(
        public.addr,
        Some("PHONE.dns.example.com"),
        Arc::clone(&leaves),
    )
    .await
    .expect("public upper-case registered");

    assert!(
        handshake_as_client(
            public.addr,
            Some("unknown.dns.example.com"),
            Arc::clone(&leaves),
        )
        .await
        .is_err(),
        "public unknown must fail"
    );
    poll_until(
        || public.stats.sni_reject_strike.load(Ordering::Relaxed) >= 1,
        Duration::from_secs(2),
    )
    .await;

    assert!(
        handshake_as_client(
            public.addr,
            Some("node1.dns.example.com"),
            Arc::clone(&leaves)
        )
        .await
        .is_err(),
        "public node must fail"
    );
    poll_until(
        || public.stats.sni_reject_no_strike.load(Ordering::Relaxed) >= 1,
        Duration::from_secs(2),
    )
    .await;

    assert!(
        handshake_as_client(public.addr, Some("dns.example.com"), Arc::clone(&leaves))
            .await
            .is_err(),
        "public apex must fail"
    );

    // Missing SNI: unit-level (connector always sends a name); strike path covered above.
    let missing = inspect_public_sni(None, &g);
    assert!(missing.should_strike());

    public.stop().await;
}

#[tokio::test]
async fn cert_hot_reload_keeps_open_connection() {
    install_ring();
    let engine = policy_engine_with_client_ids(&["phone"]).await;
    let reg: Arc<dyn dnscraft_tls::ClientIdRegistry> = Arc::new(PolicyClientIds(engine));
    let g = gate(reg);

    let (pem_a, key_a, der_a) = example_dns_cert();
    let (pem_b, key_b, der_b) = example_dns_cert_b();
    assert_ne!(der_a, der_b);

    let certs = Arc::new(CertResolver::new());
    certs.install(&pem_a, &key_a).unwrap();
    let stats = Arc::new(TlsStats::default());
    let resolver = ListenerCertResolver::local(Arc::clone(&certs), stats);
    let config = tcp_server_config(
        resolver,
        &[dnscraft_listeners::ALPN_DOT],
        &TlsPolicy::default(),
    );

    let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .await
        .unwrap();
    let addr = listener.local_addr().unwrap();
    let admission = Arc::new(Mutex::new(Admission::new(
        &Limits::default(),
        &PublicConfig::default(),
    )));
    let gate = Arc::new(g);
    let certs_c = Arc::clone(&certs);
    let adm = Arc::clone(&admission);
    let stats = Arc::new(TlsStats::default());

    let server = tokio::spawn(async move {
        let clock = SystemClock;
        // Conn 1 — keep open across reload.
        let (tcp1, peer1) = listener.accept().await.unwrap();
        let acc1 = accept_encrypted(
            tcp1,
            AcceptEncrypted {
                config: Arc::clone(&config),
                exposure: Exposure::Local,
                gate: gate.as_ref(),
                certs: certs_c.as_ref(),
                admission: adm.as_ref(),
                peer: peer1.ip(),
                clock: &clock,
                handshake_timeout: HANDSHAKE,
                stats: stats.as_ref(),
            },
        )
        .await
        .unwrap();
        let mut tls1 = acc1.stream;
        let mut buf = [0u8; 4];
        tls1.read_exact(&mut buf).await.unwrap();
        tls1.write_all(b"pong").await.unwrap();

        // Conn 2 after cert B.
        let (tcp2, peer2) = listener.accept().await.unwrap();
        let acc2 = accept_encrypted(
            tcp2,
            AcceptEncrypted {
                config: Arc::clone(&config),
                exposure: Exposure::Local,
                gate: gate.as_ref(),
                certs: certs_c.as_ref(),
                admission: adm.as_ref(),
                peer: peer2.ip(),
                clock: &clock,
                handshake_timeout: HANDSHAKE,
                stats: stats.as_ref(),
            },
        )
        .await
        .unwrap();
        let mut tls2 = acc2.stream;
        tls2.read_exact(&mut buf).await.unwrap();
        tls2.write_all(b"pong").await.unwrap();

        // First connection still works.
        tls1.write_all(b"live").await.unwrap();
        (tls1, tls2)
    });

    let leaves = Arc::new(vec![der_a, der_b]);
    let seen = Arc::new(AtomicUsize::new(0));
    let connector = client_connector(Arc::clone(&leaves), Arc::clone(&seen), b"dot");

    let tcp = TcpStream::connect(addr).await.unwrap();
    let name = ServerName::try_from("phone.dns.example.com").unwrap();
    let mut c1 = connector.connect(name.clone(), tcp).await.unwrap();
    assert_eq!(seen.load(Ordering::SeqCst), 1);
    c1.write_all(b"ping").await.unwrap();
    let mut buf = [0u8; 4];
    c1.read_exact(&mut buf).await.unwrap();

    certs.install(&pem_b, &key_b).unwrap();
    seen.store(0, Ordering::SeqCst);

    let tcp2 = TcpStream::connect(addr).await.unwrap();
    let mut c2 = connector.connect(name, tcp2).await.unwrap();
    assert_eq!(seen.load(Ordering::SeqCst), 2);
    c2.write_all(b"ping").await.unwrap();
    c2.read_exact(&mut buf).await.unwrap();

    let (_s1, _s2) = tokio::time::timeout(Duration::from_secs(5), server)
        .await
        .expect("server")
        .unwrap();
}

#[tokio::test]
async fn no_cert_then_install_next_handshake_ok() {
    install_ring();
    let engine = policy_engine_with_client_ids(&["phone"]).await;
    let reg: Arc<dyn dnscraft_tls::ClientIdRegistry> = Arc::new(PolicyClientIds(engine));
    let g = gate(reg);
    let (pem, key, der) = example_dns_cert();
    let leaves = Arc::new(vec![der]);

    let certs = Arc::new(CertResolver::new());
    let stats = Arc::new(TlsStats::default());
    let resolver = ListenerCertResolver::local(Arc::clone(&certs), Arc::clone(&stats));
    let h = ServerHarness::spawn(Exposure::Local, g, Arc::clone(&certs), resolver).await;

    assert!(
        handshake_as_client(h.addr, Some("phone.dns.example.com"), Arc::clone(&leaves))
            .await
            .is_err(),
        "empty resolver must fail"
    );
    poll_until(
        || h.stats.no_cert.load(Ordering::Relaxed) >= 1,
        Duration::from_secs(2),
    )
    .await;

    h.certs.install(&pem, &key).unwrap();
    handshake_as_client(h.addr, Some("phone.dns.example.com"), leaves)
        .await
        .expect("after install");
    h.stop().await;
}

#[test]
fn quic_config_has_zero_early_data_and_tls13_alpn() {
    install_ring();
    let certs = Arc::new(CertResolver::new());
    let stats = Arc::new(TlsStats::default());
    let resolver = ListenerCertResolver::local(certs, stats);
    let cfg = quic_server_config(resolver, &TlsPolicy::default());
    assert_eq!(cfg.max_early_data_size, 0);
    assert!(cfg.alpn_protocols.iter().any(|p| p == b"doq"));
    assert!(cfg.alpn_protocols.iter().any(|p| p == b"h3"));
}

#[test]
fn tcp_config_alpn_is_per_protocol_family() {
    install_ring();
    let certs = Arc::new(CertResolver::new());
    let stats = Arc::new(TlsStats::default());
    let dot = tcp_server_config(
        ListenerCertResolver::local(Arc::clone(&certs), Arc::clone(&stats)),
        &[dnscraft_listeners::ALPN_DOT],
        &TlsPolicy::default(),
    );
    assert_eq!(dot.alpn_protocols, vec![b"dot".to_vec()]);

    let doh = tcp_server_config(
        ListenerCertResolver::local(certs, stats),
        &[
            dnscraft_listeners::ALPN_H2,
            dnscraft_listeners::ALPN_HTTP_1_1,
        ],
        &TlsPolicy::default(),
    );
    assert_eq!(
        doh.alpn_protocols,
        vec![b"h2".to_vec(), b"http/1.1".to_vec()]
    );
}

/// Simple in-test registry (avoids spinning PolicyEngine for pure SNI unit tests).
struct SetReg(Vec<String>);

impl dnscraft_tls::ClientIdRegistry for SetReg {
    fn is_registered(&self, client_id: &str) -> bool {
        let lower = client_id.to_ascii_lowercase();
        self.0.iter().any(|id| id == &lower)
    }
}

// Silence unused import in some cfgs.
#[allow(dead_code)]
fn _clock() -> ManualClock {
    ManualClock::new(SystemTime::UNIX_EPOCH)
}
