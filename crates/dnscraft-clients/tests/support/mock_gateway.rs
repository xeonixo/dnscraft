//! Hand-written HTTPS UniFi gateway mock (tokio-rustls + rcgen).
//!
//! Serves Integration (C6) and classic (C7) API routes.

#![allow(dead_code, clippy::unwrap_used, clippy::expect_used)]

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use rcgen::{BasicConstraints, CertificateParams, CertifiedIssuer, DnType, IsCa, KeyPair, SanType};
use rustls::ServerConfig;
use rustls::crypto::ring::default_provider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use tokio_rustls::TlsAcceptor;

/// One recorded request.
#[derive(Clone, Debug)]
pub struct RecordedRequest {
    pub method: String,
    pub path: String,
    pub headers: HashMap<String, String>,
}

/// How the mock signs its leaf certificate.
#[derive(Clone, Copy, Debug)]
pub enum CertKind {
    SelfSigned,
    CaSigned,
}

/// Oversized body variants for the 8 MiB cap tests.
#[derive(Clone, Copy, Debug)]
pub enum OversizeBody {
    DeclaredOnly,
    Streamed,
}

/// In-memory Integration API fixture.
#[derive(Clone, Debug, Default)]
pub struct IntegrationFixture {
    pub sites: Vec<Value>,
    pub networks: HashMap<String, Vec<Value>>,
    pub network_details: HashMap<String, Value>,
    pub clients: HashMap<String, Vec<Value>>,
    /// When set, the clients page at this offset returns HTTP 500.
    pub clients_fail_offset: Option<usize>,
    /// When set, clients response body is truncated garbage.
    pub clients_truncated_at_offset: Option<usize>,
}

/// In-memory classic controller API fixture (`/proxy/network/api/…`).
#[derive(Clone, Debug, Default)]
pub struct ClassicFixture {
    /// `/api/self/sites` `data` rows (`name` is the classic site key).
    pub sites: Vec<Value>,
    /// `stat/sta` rows keyed by classic site name.
    pub sta: HashMap<String, Vec<Value>>,
    /// `rest/user` rows keyed by classic site name.
    pub users: HashMap<String, Vec<Value>>,
    /// `rest/networkconf` rows keyed by classic site name.
    pub networkconf: HashMap<String, Vec<Value>>,
    /// When true, `stat/sta` returns HTTP 500.
    pub sta_fail: bool,
    /// When true, `rest/networkconf` returns HTTP 500.
    pub networkconf_fail: bool,
}

struct State {
    expected_key: String,
    force_status: Option<u16>,
    force_oversize: Option<OversizeBody>,
    /// Artificial per-request delay (tests: apply_config during slow sync).
    response_delay: Option<Duration>,
    ok_body: Vec<u8>,
    integration: IntegrationFixture,
    classic: ClassicFixture,
}

/// Loopback HTTPS gateway mock.
#[derive(Clone)]
pub struct MockGateway {
    addr: SocketAddr,
    state: Arc<Mutex<State>>,
    log: Arc<Mutex<Vec<RecordedRequest>>>,
    pub leaf_der: Vec<u8>,
    pub leaf_pem: String,
    pub ca_pem: String,
}

impl MockGateway {
    pub async fn start(api_key: &str, kind: CertKind) -> Self {
        let _ = default_provider().install_default();
        let (leaf_der, leaf_pem, key_der, ca_pem) = mint_certs(kind);

        let certs = vec![CertificateDer::from(leaf_der.clone())];
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_der));
        let server_config = ServerConfig::builder_with_provider(Arc::new(default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(server_config));

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let state = Arc::new(Mutex::new(State {
            expected_key: api_key.to_owned(),
            force_status: None,
            force_oversize: None,
            response_delay: None,
            ok_body: br#"{"ok":true}"#.to_vec(),
            integration: IntegrationFixture::default(),
            classic: ClassicFixture::default(),
        }));
        let log = Arc::new(Mutex::new(Vec::new()));
        let (s, l, a) = (state.clone(), log.clone(), acceptor);
        tokio::spawn(async move {
            loop {
                let Ok((sock, _)) = listener.accept().await else {
                    return;
                };
                let acc = a.clone();
                let st = s.clone();
                let lg = l.clone();
                tokio::spawn(async move {
                    let Ok(tls) = acc.accept(sock).await else {
                        return;
                    };
                    let _ = serve(tls, st, lg).await;
                });
            }
        });

        Self {
            addr,
            state,
            log,
            leaf_der,
            leaf_pem,
            ca_pem,
        }
    }

    pub fn base_url(&self) -> String {
        format!("https://{}", self.addr)
    }

    pub async fn set_integration(&self, fixture: IntegrationFixture) {
        self.state.lock().await.integration = fixture;
    }

    pub async fn set_classic(&self, fixture: ClassicFixture) {
        self.state.lock().await.classic = fixture;
    }

    pub async fn force_status(&self, status: u16) {
        self.state.lock().await.force_status = Some(status);
    }

    pub async fn clear_force_status(&self) {
        self.state.lock().await.force_status = None;
    }

    pub async fn force_oversize(&self, kind: OversizeBody) {
        self.state.lock().await.force_oversize = Some(kind);
    }

    /// Sleep this long before answering each request (`None` clears the delay).
    pub async fn set_response_delay(&self, delay: Option<Duration>) {
        self.state.lock().await.response_delay = delay;
    }

    pub async fn take_log(&self) -> Vec<RecordedRequest> {
        std::mem::take(&mut *self.log.lock().await)
    }
}

fn mint_certs(kind: CertKind) -> (Vec<u8>, String, Vec<u8>, String) {
    match kind {
        CertKind::SelfSigned => {
            let key = KeyPair::generate().unwrap();
            let mut params = CertificateParams::new(vec!["127.0.0.1".into()]).unwrap();
            params.subject_alt_names = vec![SanType::IpAddress(IpAddr::V4(Ipv4Addr::LOCALHOST))];
            params
                .distinguished_name
                .push(DnType::CommonName, "dnscraft-mock-gw");
            let cert = params.self_signed(&key).unwrap();
            (
                cert.der().as_ref().to_vec(),
                cert.pem(),
                key.serialize_der(),
                String::new(),
            )
        }
        CertKind::CaSigned => {
            let ca_key = KeyPair::generate().unwrap();
            let mut ca_params = CertificateParams::default();
            ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
            ca_params
                .distinguished_name
                .push(DnType::CommonName, "dnscraft-mock-ca");
            let ca = CertifiedIssuer::self_signed(ca_params, ca_key).unwrap();
            let ca_pem = ca.pem();

            let server_key = KeyPair::generate().unwrap();
            let mut server_params = CertificateParams::new(vec!["127.0.0.1".into()]).unwrap();
            server_params.subject_alt_names =
                vec![SanType::IpAddress(IpAddr::V4(Ipv4Addr::LOCALHOST))];
            server_params
                .distinguished_name
                .push(DnType::CommonName, "dnscraft-mock-gw");
            let cert = server_params.signed_by(&server_key, &ca).unwrap();
            (
                cert.der().as_ref().to_vec(),
                cert.pem(),
                server_key.serialize_der(),
                ca_pem,
            )
        }
    }
}

async fn serve(
    mut tls: tokio_rustls::server::TlsStream<TcpStream>,
    state: Arc<Mutex<State>>,
    log: Arc<Mutex<Vec<RecordedRequest>>>,
) -> std::io::Result<()> {
    let mut buf = vec![0u8; 64 * 1024];
    let n = tls.read(&mut buf).await?;
    if n == 0 {
        return Ok(());
    }
    let req_text = String::from_utf8_lossy(&buf[..n]);
    let mut lines = req_text.lines();
    let request_line = lines.next().unwrap_or("");
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("").to_owned();
    let path_q = parts.next().unwrap_or("/").to_owned();
    let (path, query) = match path_q.split_once('?') {
        Some((p, q)) => (p.to_owned(), q.to_owned()),
        None => (path_q.clone(), String::new()),
    };

    let mut headers = HashMap::new();
    for line in lines {
        if line.is_empty() {
            break;
        }
        if let Some((k, v)) = line.split_once(':') {
            headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_owned());
        }
    }
    log.lock().await.push(RecordedRequest {
        method: method.clone(),
        path: path_q.clone(),
        headers: headers.clone(),
    });

    // Snapshot the response *before* sleeping so a delayed request keeps the
    // fixture as it was when the request arrived (out-of-order install tests).
    enum Pending {
        Oversize(OversizeBody),
        Http(u16, Vec<u8>),
        Raw(Vec<u8>),
    }
    let (delay, pending) = {
        let st = state.lock().await;
        let delay = st.response_delay;
        let key_ok = headers
            .get("x-api-key")
            .is_some_and(|v| v == &st.expected_key);

        if let Some(over) = st.force_oversize {
            (delay, Pending::Oversize(over))
        } else if let Some(code) = st.force_status {
            let body = format!(r#"{{"error":"{code}"}}"#).into_bytes();
            (delay, Pending::Http(code, body))
        } else if !key_ok {
            (delay, Pending::Http(401, br#"{"error":"401"}"#.to_vec()))
        } else if let Some(resp) = integration_response(&st.integration, &path, &query) {
            (
                delay,
                match resp {
                    MockResp::Ok(body) => Pending::Http(200, body),
                    MockResp::Status(code, body) => Pending::Http(code, body),
                    MockResp::Raw(raw) => Pending::Raw(raw),
                },
            )
        } else if let Some(resp) = classic_response(&st.classic, &path) {
            (
                delay,
                match resp {
                    MockResp::Ok(body) => Pending::Http(200, body),
                    MockResp::Status(code, body) => Pending::Http(code, body),
                    MockResp::Raw(raw) => Pending::Raw(raw),
                },
            )
        } else {
            (delay, Pending::Http(200, st.ok_body.clone()))
        }
    };

    if let Some(d) = delay {
        tokio::time::sleep(d).await;
    }

    match pending {
        Pending::Oversize(over) => write_oversize(&mut tls, over).await,
        Pending::Http(code, body) => write_http(&mut tls, code, &body).await,
        Pending::Raw(raw) => {
            tls.write_all(&raw).await?;
            Ok(())
        }
    }
}

enum MockResp {
    Ok(Vec<u8>),
    Status(u16, Vec<u8>),
    Raw(Vec<u8>),
}

fn integration_response(fx: &IntegrationFixture, path: &str, query: &str) -> Option<MockResp> {
    const PFX: &str = "/proxy/network/integration/v1";
    if !path.starts_with(PFX) {
        return None;
    }
    let rest = &path[PFX.len()..];

    if rest == "/sites" {
        return Some(MockResp::Ok(
            json!({ "data": fx.sites }).to_string().into_bytes(),
        ));
    }

    // /sites/{site}/networks/{nid}
    if let Some(caps) = match_networks_detail(rest) {
        let key = format!("{}/{}", caps.0, caps.1);
        if let Some(detail) = fx.network_details.get(&key) {
            return Some(MockResp::Ok(detail.to_string().into_bytes()));
        }
        return Some(MockResp::Status(404, br#"{"error":"not found"}"#.to_vec()));
    }

    // /sites/{site}/networks
    if let Some(site) = match_networks_list(rest) {
        let list = fx.networks.get(site).cloned().unwrap_or_default();
        return Some(MockResp::Ok(
            json!({ "data": list }).to_string().into_bytes(),
        ));
    }

    // /sites/{site}/clients
    if let Some(site) = match_clients(rest) {
        let offset = query_param(query, "offset").unwrap_or(0);
        let limit = query_param(query, "limit").unwrap_or(25);

        if fx.clients_fail_offset == Some(offset) {
            return Some(MockResp::Status(500, br#"{"error":"boom"}"#.to_vec()));
        }
        if fx.clients_truncated_at_offset == Some(offset) {
            // Truncated JSON — Content-Length lies short / body cut mid-object.
            let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 40\r\nConnection: close\r\n\r\n{\"data\":[{\"id\":";
            return Some(MockResp::Raw(raw.to_vec()));
        }

        let all = fx.clients.get(site).cloned().unwrap_or_default();
        let slice: Vec<Value> = all.into_iter().skip(offset).take(limit).collect();
        return Some(MockResp::Ok(
            json!({
                "offset": offset,
                "limit": limit,
                "count": slice.len(),
                "data": slice,
            })
            .to_string()
            .into_bytes(),
        ));
    }

    None
}

fn classic_response(fx: &ClassicFixture, path: &str) -> Option<MockResp> {
    const PFX: &str = "/proxy/network/api";
    if !path.starts_with(PFX) {
        return None;
    }
    let rest = &path[PFX.len()..];

    if rest == "/self/sites" {
        return Some(MockResp::Ok(
            json!({ "meta": { "rc": "ok" }, "data": fx.sites })
                .to_string()
                .into_bytes(),
        ));
    }

    // /s/{site}/stat/sta | rest/user | rest/networkconf
    let rest = rest.strip_prefix("/s/")?;
    let (site, tail) = rest.split_once('/')?;

    match tail {
        "stat/sta" => {
            if fx.sta_fail {
                return Some(MockResp::Status(500, br#"{"error":"sta down"}"#.to_vec()));
            }
            let data = fx.sta.get(site).cloned().unwrap_or_default();
            Some(MockResp::Ok(
                json!({ "meta": { "rc": "ok" }, "data": data })
                    .to_string()
                    .into_bytes(),
            ))
        }
        "rest/user" => {
            let data = fx.users.get(site).cloned().unwrap_or_default();
            Some(MockResp::Ok(
                json!({ "meta": { "rc": "ok" }, "data": data })
                    .to_string()
                    .into_bytes(),
            ))
        }
        "rest/networkconf" => {
            if fx.networkconf_fail {
                return Some(MockResp::Status(
                    500,
                    br#"{"error":"networkconf down"}"#.to_vec(),
                ));
            }
            let data = fx.networkconf.get(site).cloned().unwrap_or_default();
            Some(MockResp::Ok(
                json!({ "meta": { "rc": "ok" }, "data": data })
                    .to_string()
                    .into_bytes(),
            ))
        }
        _ => Some(MockResp::Status(404, br#"{"error":"not found"}"#.to_vec())),
    }
}

fn match_networks_list(rest: &str) -> Option<&str> {
    // /sites/{site}/networks
    let rest = rest.strip_prefix("/sites/")?;
    let (site, tail) = rest.split_once('/')?;
    if tail == "networks" { Some(site) } else { None }
}

fn match_networks_detail(rest: &str) -> Option<(&str, &str)> {
    // /sites/{site}/networks/{nid}
    let rest = rest.strip_prefix("/sites/")?;
    let (site, tail) = rest.split_once('/')?;
    let tail = tail.strip_prefix("networks/")?;
    if tail.is_empty() || tail.contains('/') {
        None
    } else {
        Some((site, tail))
    }
}

fn match_clients(rest: &str) -> Option<&str> {
    let rest = rest.strip_prefix("/sites/")?;
    let (site, tail) = rest.split_once('/')?;
    if tail == "clients" { Some(site) } else { None }
}

fn query_param(query: &str, name: &str) -> Option<usize> {
    for part in query.split('&') {
        if let Some((k, v)) = part.split_once('=')
            && k == name
        {
            return v.parse().ok();
        }
    }
    None
}

async fn write_http(
    tls: &mut tokio_rustls::server::TlsStream<TcpStream>,
    status: u16,
    body: &[u8],
) -> std::io::Result<()> {
    let reason = match status {
        200 => "OK",
        401 => "Unauthorized",
        404 => "Not Found",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        _ => "Error",
    };
    let resp = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    tls.write_all(resp.as_bytes()).await?;
    tls.write_all(body).await?;
    Ok(())
}

async fn write_oversize(
    tls: &mut tokio_rustls::server::TlsStream<TcpStream>,
    over: OversizeBody,
) -> std::io::Result<()> {
    match over {
        OversizeBody::DeclaredOnly => {
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\nok",
                9 * 1024 * 1024
            );
            tls.write_all(resp.as_bytes()).await?;
        }
        OversizeBody::Streamed => {
            tls.write_all(b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n")
                .await?;
            let chunk = vec![b'x'; 64 * 1024];
            let mut sent = 0usize;
            while sent < 9 * 1024 * 1024 {
                tls.write_all(&chunk).await?;
                sent += chunk.len();
            }
        }
    }
    Ok(())
}
