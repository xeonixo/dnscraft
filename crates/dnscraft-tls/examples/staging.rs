//! Manual Let's Encrypt **staging** acceptance runner (Checkpoint C).
//!
//! Never put real domains, e-mails, tokens, or IPs in the repo. Configure via
//! environment variables and a token file **outside** the tree:
//!
//! ```text
//! export DNSCRAFT_DATA_DIR=$HOME/.local/share/dnscraft-staging
//! export DNSCRAFT_PUBLIC_DOMAIN=…          # owner zone apex
//! export DNSCRAFT_ACME_EMAIL=…             # ACME contact
//! export DNSCRAFT_NODE_HOSTNAME=node1.dns.…
//! export DNSCRAFT_RESERVED_LABELS=node1    # comma-separated
//! export DNSCRAFT_CLOUDFLARE_API_TOKEN_FILE=$HOME/.config/dnscraft-staging/cf-token
//! # optional: DNSCRAFT_DYNDNS=1  DNSCRAFT_PUBLIC_ENTRY=1
//!
//! cargo run -p dnscraft-tls --example staging -- issue
//! cargo run -p dnscraft-tls --example staging -- status
//! cargo run -p dnscraft-tls --example staging -- renew
//! cargo run -p dnscraft-tls --example staging -- handshake phone
//! cargo run -p dnscraft-tls --example staging -- sni-check
//! cargo run -p dnscraft-tls --example staging -- dyndns
//! ```
//!
//! ACME directory is hard-wired to Let's Encrypt **staging**. The token is
//! never printed.

#![allow(clippy::print_stdout, clippy::print_stderr, clippy::unwrap_used)]

use std::collections::HashSet;
use std::env;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use dnscraft_tls::{
    AcmeConfig, AcmeDirectoryKind, CertStore, ClientIdRegistry, CloudflareConfig, DynDnsConfig,
    KeyType, ReservedLabels, SystemClock, TlsConfig, TlsEngine, TlsStatus, accept_public_sni,
    parse_client_id_sni,
};
use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::server::ResolvesServerCert;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::client::TlsStream as ClientTlsStream;
use tokio_rustls::{TlsAcceptor, TlsConnector};

fn usage() -> ! {
    eprintln!(
        "usage: staging <issue|renew|status|handshake [client-id]|sni-check|dyndns>\n\
         see crates/dnscraft-tls/examples/staging.rs for required env vars"
    );
    std::process::exit(2);
}

fn require_env(name: &str) -> String {
    env::var(name).unwrap_or_else(|_| {
        eprintln!("missing required env {name}");
        std::process::exit(2);
    })
}

fn data_dir() -> PathBuf {
    PathBuf::from(require_env("DNSCRAFT_DATA_DIR"))
}

fn csv_env(name: &str, default: &str) -> Vec<String> {
    env::var(name)
        .unwrap_or_else(|_| default.to_owned())
        .split(',')
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
        .collect()
}

fn build_config() -> TlsConfig {
    let public_domain = require_env("DNSCRAFT_PUBLIC_DOMAIN");
    let email = require_env("DNSCRAFT_ACME_EMAIL");
    let hostname = require_env("DNSCRAFT_NODE_HOSTNAME");
    let default_label = hostname.split('.').next().unwrap_or("node1");
    let reserved = csv_env("DNSCRAFT_RESERVED_LABELS", default_label);
    let dyndns = env::var("DNSCRAFT_DYNDNS").ok().as_deref() == Some("1");
    let public_entry = env::var("DNSCRAFT_PUBLIC_ENTRY").ok().as_deref() == Some("1");

    TlsConfig {
        public_domain,
        key_type: KeyType::EcdsaP256,
        acme: AcmeConfig {
            enabled: true,
            directory: AcmeDirectoryKind::Staging,
            email,
            propagation_timeout: std::time::Duration::from_secs(180),
            propagation_poll: std::time::Duration::from_secs(5),
        },
        cloudflare: CloudflareConfig { zone_id: None },
        dyndns: DynDnsConfig {
            enabled: dyndns,
            hostname,
            public_entry,
            reserved_labels: reserved,
            proxied: false,
            ..DynDnsConfig::default()
        },
        ..TlsConfig::default()
    }
}

fn print_status(s: &TlsStatus) {
    println!("acme_directory={}", s.acme_directory);
    println!("acme_enabled={}", s.acme_enabled);
    println!("identifiers={:?}", s.identifiers);
    println!(
        "days_to_expiry={}",
        s.days_to_expiry
            .map(|d| d.to_string())
            .unwrap_or_else(|| "-".into())
    );
    println!(
        "last_issue={}",
        s.last_issue
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map(|d| d.as_secs().to_string())
            .unwrap_or_else(|| "-".into())
    );
    println!(
        "last_renew_attempt={}",
        s.last_renew_attempt
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map(|d| d.as_secs().to_string())
            .unwrap_or_else(|| "-".into())
    );
    println!("last_error={}", s.last_error.as_deref().unwrap_or("-"));
    println!(
        "cert_expiring={} cert_expired={}",
        s.cert_expiring, s.cert_expired
    );
    println!(
        "dyndns_ipv4={} dyndns_ipv6={}",
        s.dyndns_ipv4.as_deref().unwrap_or("-"),
        s.dyndns_ipv6.as_deref().unwrap_or("-")
    );
}

fn inspect_store(dir: &std::path::Path, public_domain: &str) {
    use std::os::unix::fs::PermissionsExt;

    let tls = dir.join("tls");
    let meta = std::fs::metadata(&tls).expect("tls dir");
    let mode = meta.permissions().mode() & 0o777;
    println!("tls_dir_mode={mode:04o} (expect 0700)");

    for name in [
        "cert.pem",
        "key.pem",
        "account.json",
        "state.json",
        "meta.json",
    ] {
        let p = tls.join(name);
        if !p.exists() {
            println!("{name}=missing");
            continue;
        }
        let m = std::fs::metadata(&p).unwrap().permissions().mode() & 0o777;
        println!("{name}_mode={m:04o}");
    }

    let store = CertStore::open(dir).expect("open store");
    let loaded = store.load().expect("load").expect("cert present");
    println!("leaf_identifiers={:?}", loaded.identifiers);
    for w in [
        format!("dns.{public_domain}"),
        format!("*.dns.{public_domain}"),
    ] {
        let ok = loaded.identifiers.iter().any(|i| i == &w);
        println!("san_{w}={}", if ok { "ok" } else { "MISSING" });
    }

    // Staging intermediates / roots advertise "(STAGING)" in the subject.
    let chain = String::from_utf8_lossy(&loaded.chain_pem);
    let staging_marker = chain.contains("(STAGING)") || chain.contains("Staging");
    println!("chain_contains_STAGING_marker={staging_marker}");

    let state = store.load_state();
    println!(
        "state_last_issue={:?} state_last_error={:?}",
        state.last_issue_unix, state.last_error
    );
}

struct SetReg(HashSet<String>);
impl ClientIdRegistry for SetReg {
    fn is_registered(&self, id: &str) -> bool {
        self.0.contains(id)
    }
}

fn sni_check(domain: &str, reserved_labels: &[String]) {
    let reserved = ReservedLabels::new(reserved_labels.iter().cloned());
    let reg = SetReg(HashSet::from(["phone".into()]));
    let node = reserved_labels
        .first()
        .cloned()
        .unwrap_or_else(|| "node1".into());
    let checks: [(&str, Option<String>); 5] = [
        ("apex", Some(format!("dns.{domain}"))),
        ("node_hostname", Some(format!("{node}.dns.{domain}"))),
        ("unknown_client_id", Some(format!("unknown.dns.{domain}"))),
        ("registered_client_id", Some(format!("phone.dns.{domain}"))),
        ("missing_sni", None),
    ];
    for (label, sni) in checks {
        let kind = sni
            .as_deref()
            .map(|s| parse_client_id_sni(s, domain, &reserved));
        let accept = accept_public_sni(sni.as_deref(), domain, &reserved, &reg);
        println!("sni_{label}: kind={kind:?} accept_public={accept}");
    }
}

async fn open_engine() -> TlsEngine {
    let mut cfg = build_config();
    cfg.validate().expect("config validate");
    assert_eq!(
        cfg.acme.directory.url(),
        "https://acme-staging-v02.api.letsencrypt.org/directory",
        "example must never use production ACME"
    );
    let dir = data_dir();
    std::fs::create_dir_all(&dir).expect("data dir");
    TlsEngine::open(cfg, &dir, Arc::new(SystemClock)).expect("TlsEngine::open")
}

/// Local TLS handshake against [`dnscraft_tls::CertResolver`] (loopback only).
async fn handshake(client_id: &str) {
    let engine = open_engine().await;
    let domain = require_env("DNSCRAFT_PUBLIC_DOMAIN");
    let sni = format!("{client_id}.dns.{domain}");
    let resolver = engine.resolver();
    assert!(
        resolver.has_cert(),
        "resolver has no cert — run issue first"
    );

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut server_cfg = ServerConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .expect("protocols")
        .with_no_client_auth()
        .with_cert_resolver(resolver as Arc<dyn ResolvesServerCert>);
    server_cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    let acceptor = TlsAcceptor::from(Arc::new(server_cfg));

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (sock, _) = listener.accept().await.expect("accept");
        let mut tls = acceptor.accept(sock).await.expect("server handshake");
        let _ = tls.write_all(b"ok").await;
        let _ = tls.shutdown().await;
    });

    // Client skips chain verify (LE staging roots); we only exercise SNI + serve.
    let mut client_cfg = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("protocols")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerify))
        .with_no_client_auth();
    client_cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    let connector = TlsConnector::from(Arc::new(client_cfg));
    let sock = TcpStream::connect(addr).await.expect("connect");
    let name = ServerName::try_from(sni.clone()).expect("sni");
    let mut tls: ClientTlsStream<TcpStream> = connector
        .connect(name, sock)
        .await
        .expect("client handshake");
    let mut buf = [0u8; 8];
    let n = tls.read(&mut buf).await.expect("read");
    println!(
        "handshake_ok sni={sni} peer_bytes={}",
        String::from_utf8_lossy(&buf[..n])
    );
    let _ = server.await;
}

#[derive(Debug)]
struct NoVerify;

impl rustls::client::danger::ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[tokio::main]
async fn main() {
    let mut args = env::args().skip(1);
    let cmd = args.next().unwrap_or_else(|| usage());

    if env::var("DNSCRAFT_CLOUDFLARE_API_TOKEN_FILE").is_err()
        && matches!(cmd.as_str(), "issue" | "renew" | "dyndns")
    {
        eprintln!("set DNSCRAFT_CLOUDFLARE_API_TOKEN_FILE to a 0600 file outside the repo");
        std::process::exit(2);
    }

    match cmd.as_str() {
        "status" => {
            let engine = open_engine().await;
            print_status(&engine.status_async().await);
            inspect_store(&data_dir(), &require_env("DNSCRAFT_PUBLIC_DOMAIN"));
        }
        "issue" | "renew" => {
            let t0 = SystemTime::now();
            let engine = open_engine().await;
            println!("starting renew_now (staging)…");
            match engine.renew_now().await {
                Ok(()) => {
                    let elapsed = t0.elapsed().unwrap_or_default();
                    println!("renew_now=ok elapsed_secs={}", elapsed.as_secs());
                }
                Err(e) => {
                    println!("renew_now=err code={} msg={e}", e.code());
                }
            }
            print_status(&engine.status_async().await);
            inspect_store(&data_dir(), &require_env("DNSCRAFT_PUBLIC_DOMAIN"));
        }
        "dyndns" => {
            let engine = open_engine().await;
            match engine.dyndns_now().await {
                Ok(r) => println!(
                    "dyndns=ok changed={} ipv4={:?} ipv6={:?}",
                    r.changed, r.ipv4, r.ipv6
                ),
                Err(e) => println!("dyndns=err code={} msg={e}", e.code()),
            }
            print_status(&engine.status_async().await);
        }
        "handshake" => {
            let id = args.next().unwrap_or_else(|| "phone".into());
            handshake(&id).await;
        }
        "sni-check" => {
            let domain = require_env("DNSCRAFT_PUBLIC_DOMAIN");
            let hostname = env::var("DNSCRAFT_NODE_HOSTNAME").unwrap_or_default();
            let default_label = hostname.split('.').next().unwrap_or("node1");
            let reserved = csv_env("DNSCRAFT_RESERVED_LABELS", default_label);
            sni_check(&domain, &reserved);
        }
        _ => usage(),
    }
}
