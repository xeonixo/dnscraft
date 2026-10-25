//! ACME DNS-01 propagation check against authoritative nameservers.
//!
//! After writing `_acme-challenge` TXT records, poll each Cloudflare NS over
//! UDP until **all** expected values are present at **every** nameserver, or
//! until the timeout → [`TlsError::AcmePropagation`].

use std::collections::HashSet;
use std::net::SocketAddr;
use std::time::Duration;

use dnscraft_proto::{Message, Name, RData, RecordType};
use rand::Rng;
use tokio::net::UdpSocket;

use crate::clock::{Clock, wait_until};
use crate::error::TlsError;

/// Per-query UDP receive timeout (one poll round against one NS).
const QUERY_TIMEOUT: Duration = Duration::from_secs(3);

/// Resolves nameserver hostnames to UDP addresses on port 53.
///
/// Used once per issuance with the zone's `name_servers` from Cloudflare.
pub async fn resolve_nameservers(names: &[String]) -> Result<Vec<SocketAddr>, TlsError> {
    let mut out = Vec::new();
    for name in names {
        let host = name.trim_end_matches('.');
        let mut any = false;
        let addrs =
            tokio::net::lookup_host((host, 53))
                .await
                .map_err(|e| TlsError::CloudflareHttp {
                    message: format!("resolve NS {host}: {e}"),
                })?;
        for addr in addrs {
            out.push(addr);
            any = true;
        }
        if !any {
            return Err(TlsError::CloudflareHttp {
                message: format!("resolve NS {host}: no addresses"),
            });
        }
    }
    Ok(out)
}

/// Polls `nameservers` for TXT at `name` until every `expected` value is
/// present at every server, or `timeout` elapses.
///
/// `poll` is the wait between rounds (default 5 s). The first round runs
/// immediately. Time advances via [`Clock`] so tests use [`crate::ManualClock`].
pub async fn wait_for_txt(
    name: &str,
    expected: &[String],
    nameservers: &[SocketAddr],
    poll: Duration,
    timeout: Duration,
    clock: &dyn Clock,
) -> Result<(), TlsError> {
    if expected.is_empty() {
        return Ok(());
    }
    if nameservers.is_empty() {
        return Err(TlsError::AcmePropagation);
    }
    let qname = Name::from_ascii(&ensure_dot(name)).map_err(|_| TlsError::AcmePropagation)?;
    let deadline = clock.now() + timeout;
    let want: HashSet<&str> = expected.iter().map(String::as_str).collect();

    loop {
        if all_ns_have_all(&qname, nameservers, &want).await {
            return Ok(());
        }
        if clock.now() >= deadline {
            return Err(TlsError::AcmePropagation);
        }
        let next = clock.now() + poll;
        let wait_to = if next < deadline { next } else { deadline };
        wait_until(clock, wait_to).await;
        if clock.now() >= deadline && !all_ns_have_all(&qname, nameservers, &want).await {
            return Err(TlsError::AcmePropagation);
        }
    }
}

fn ensure_dot(name: &str) -> String {
    if name.ends_with('.') {
        name.to_owned()
    } else {
        format!("{name}.")
    }
}

async fn all_ns_have_all(qname: &Name, nameservers: &[SocketAddr], want: &HashSet<&str>) -> bool {
    for ns in nameservers {
        match query_txt(qname, *ns).await {
            Some(got) => {
                let have: HashSet<&str> = got.iter().map(String::as_str).collect();
                if !want.is_subset(&have) {
                    return false;
                }
            }
            None => return false,
        }
    }
    true
}

/// One authoritative TXT query. Returns `None` on transport/decode problems,
/// mismatched query id, truncated responses, or non-answers — never panics.
async fn query_txt(qname: &Name, ns: SocketAddr) -> Option<Vec<String>> {
    let id: u16 = rand::rng().random();
    let mut msg = Message::query(id, qname.clone(), RecordType::TXT);
    msg.header.rd = false;
    let bytes = msg.encode().ok()?;

    let sock = UdpSocket::bind("0.0.0.0:0").await.ok()?;
    sock.send_to(&bytes, ns).await.ok()?;

    let mut buf = vec![0u8; 4096];
    let (n, _) = tokio::time::timeout(QUERY_TIMEOUT, sock.recv_from(&mut buf))
        .await
        .ok()?
        .ok()?;
    let resp = Message::decode(&buf[..n]).ok()?;

    if resp.header.id != id {
        return None;
    }
    if !resp.header.qr || resp.header.tc {
        return None;
    }

    let mut values = Vec::new();
    for rr in &resp.answers {
        if rr.rtype() != RecordType::TXT {
            continue;
        }
        if let Some(s) = txt_rdata_utf8(&rr.rdata) {
            values.push(s);
        }
    }
    Some(values)
}

fn txt_rdata_utf8(rdata: &RData) -> Option<String> {
    match rdata {
        RData::TXT(parts) => {
            let mut bytes = Vec::new();
            for p in parts {
                bytes.extend_from_slice(p);
            }
            String::from_utf8(bytes).ok()
        }
        _ => None,
    }
}
