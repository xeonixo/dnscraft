//! ACME DNS-01 propagation check against authoritative nameservers.
//!
//! After writing `_acme-challenge` TXT records, poll each Cloudflare NS over
//! UDP until **all** expected values are present at **every** nameserver (at
//! least one address per nameserver, IPv4 or IPv6), or until the timeout →
//! [`TlsError::AcmePropagation`].

use std::collections::HashSet;
use std::net::SocketAddr;
use std::time::Duration;

use dnscraft_proto::{Message, Name, RData, RecordType};
use rand::Rng;
use tokio::net::UdpSocket;
use tracing::warn;

use crate::clock::{Clock, wait_until};
use crate::error::TlsError;

/// Per-query UDP receive timeout (one poll round against one NS address).
const QUERY_TIMEOUT: Duration = Duration::from_secs(3);

/// Resolves nameserver hostnames to UDP addresses on port 53, grouped by
/// nameserver.
///
/// Each element of the result holds **all** addresses (IPv4 and IPv6) of one
/// nameserver. A nameserver is considered propagated when at least one of its
/// addresses serves every expected value (see [`wait_for_txt`]); dual-stack
/// hosts therefore do not fail on hosts without IPv6 connectivity.
///
/// A value that already parses as [`SocketAddr`] (e.g. `127.0.0.1:5353` in
/// tests) forms a single-address group. A name that fails to resolve or has no
/// addresses is logged and skipped as long as at least one other nameserver
/// resolves; if none resolves, the result is [`TlsError::AcmePropagation`]
/// (we cannot verify propagation, so the order must not proceed).
pub async fn resolve_nameservers(names: &[String]) -> Result<Vec<Vec<SocketAddr>>, TlsError> {
    let mut out: Vec<Vec<SocketAddr>> = Vec::new();
    for name in names {
        let host = name.trim_end_matches('.');
        if let Ok(addr) = host.parse::<SocketAddr>() {
            out.push(vec![addr]);
            continue;
        }
        match tokio::net::lookup_host((host, 53)).await {
            Ok(addrs) => {
                let group: Vec<SocketAddr> = addrs.collect();
                if group.is_empty() {
                    warn!(ns = host, "nameserver resolved to no addresses; skipping");
                } else {
                    out.push(group);
                }
            }
            Err(e) => warn!(ns = host, "nameserver lookup failed; skipping: {e}"),
        }
    }
    if out.is_empty() {
        return Err(TlsError::AcmePropagation);
    }
    Ok(out)
}

/// Polls `nameservers` for TXT at `name` until every `expected` value is
/// present at every nameserver, or `timeout` elapses.
///
/// `nameservers` is grouped by nameserver (see [`resolve_nameservers`]): a
/// group passes when **at least one** of its addresses returns all expected
/// values; every group must pass.
///
/// `poll` is the wait between rounds (default 5 s). The first round runs
/// immediately. Time advances via [`Clock`] so tests use [`crate::ManualClock`].
pub async fn wait_for_txt(
    name: &str,
    expected: &[String],
    nameservers: &[Vec<SocketAddr>],
    poll: Duration,
    timeout: Duration,
    clock: &dyn Clock,
) -> Result<(), TlsError> {
    wait_for_txt_with_query_timeout(
        name,
        expected,
        nameservers,
        poll,
        timeout,
        QUERY_TIMEOUT,
        clock,
    )
    .await
}

/// [`wait_for_txt`] with an explicit per-query UDP receive timeout.
///
/// Exists so tests can exercise unreachable addresses without waiting the
/// default 3 s per query.
#[doc(hidden)]
pub async fn wait_for_txt_with_query_timeout(
    name: &str,
    expected: &[String],
    nameservers: &[Vec<SocketAddr>],
    poll: Duration,
    timeout: Duration,
    query_timeout: Duration,
    clock: &dyn Clock,
) -> Result<(), TlsError> {
    if expected.is_empty() {
        return Ok(());
    }
    if nameservers.iter().all(Vec::is_empty) {
        return Err(TlsError::AcmePropagation);
    }
    let qname = Name::from_ascii(&ensure_dot(name)).map_err(|_| TlsError::AcmePropagation)?;
    let deadline = clock.now() + timeout;
    let want: HashSet<&str> = expected.iter().map(String::as_str).collect();

    loop {
        if all_ns_have_all(&qname, nameservers, &want, query_timeout).await {
            return Ok(());
        }
        if clock.now() >= deadline {
            return Err(TlsError::AcmePropagation);
        }
        let next = clock.now() + poll;
        let wait_to = if next < deadline { next } else { deadline };
        wait_until(clock, wait_to).await;
        if clock.now() >= deadline
            && !all_ns_have_all(&qname, nameservers, &want, query_timeout).await
        {
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

async fn all_ns_have_all(
    qname: &Name,
    nameservers: &[Vec<SocketAddr>],
    want: &HashSet<&str>,
    query_timeout: Duration,
) -> bool {
    for group in nameservers {
        if group.is_empty() {
            continue;
        }
        let mut passed = false;
        for addr in group {
            if let Some(got) = query_txt(qname, *addr, query_timeout).await {
                let have: HashSet<&str> = got.iter().map(String::as_str).collect();
                if want.is_subset(&have) {
                    passed = true;
                    break;
                }
            }
        }
        if !passed {
            return false;
        }
    }
    true
}

/// One authoritative TXT query. Returns `None` on transport/decode problems,
/// mismatched query id, truncated responses, or non-answers — never panics.
///
/// The socket is bound to the address family of `ns`. Datagrams from any other
/// source address are ignored (the receive loop continues until `query_timeout`).
async fn query_txt(qname: &Name, ns: SocketAddr, query_timeout: Duration) -> Option<Vec<String>> {
    let id: u16 = rand::rng().random();
    let mut msg = Message::query(id, qname.clone(), RecordType::TXT);
    msg.header.rd = false;
    let bytes = msg.encode().ok()?;

    let local = if ns.is_ipv6() { "[::]:0" } else { "0.0.0.0:0" };
    let sock = UdpSocket::bind(local).await.ok()?;
    sock.send_to(&bytes, ns).await.ok()?;

    let recv = async {
        let mut buf = vec![0u8; 4096];
        loop {
            let (n, from) = sock.recv_from(&mut buf).await.ok()?;
            if from == ns {
                return Some(buf[..n].to_vec());
            }
        }
    };
    let datagram = tokio::time::timeout(query_timeout, recv).await.ok()??;
    let resp = Message::decode(&datagram).ok()?;

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
