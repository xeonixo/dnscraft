//! Outgoing transport: one UDP exchange with response matching and a timeout.
//!
//! Task 6 extends this module (TCP fallback, retries, server selection).

use std::net::SocketAddr;
use std::time::Duration;

use dnscraft_proto::{Edns, Message, Name, ProtoError, RecordType};
use tokio::net::UdpSocket;
use tokio::time::Instant;

/// EDNS UDP payload size advertised to authoritative servers.
pub(crate) const EDNS_PAYLOAD: u16 = 1232;

/// Why an exchange produced no usable response.
#[derive(Debug, thiserror::Error)]
pub(crate) enum TransportError {
    #[error("no matching response within the timeout")]
    Timeout,
    #[error("socket error: {0}")]
    Io(#[from] std::io::Error),
    #[error("cannot encode query: {0}")]
    Encode(#[from] ProtoError),
}

/// Builds a non-recursive query with EDNS (1232 bytes, DO set) and a random id.
pub(crate) fn build_query(name: &Name, qtype: RecordType) -> Message {
    let mut msg = Message::query(rand::random::<u16>(), name.clone(), qtype);
    msg.header.rd = false;
    let mut edns = Edns::new(EDNS_PAYLOAD);
    edns.dnssec_ok = true;
    msg.edns = Some(edns);
    msg
}

/// Sends `query` over UDP to `server` and waits for a matching response.
///
/// The socket is connected to `server` (the kernel drops datagrams from other
/// sources) and bound to an OS-chosen random source port. Datagrams that do
/// not decode, are not responses, or differ in id or question are ignored.
pub(crate) async fn exchange(
    server: SocketAddr,
    query: &Message,
    timeout: Duration,
) -> Result<Message, TransportError> {
    let bind: SocketAddr = if server.is_ipv4() {
        SocketAddr::from(([0, 0, 0, 0], 0))
    } else {
        SocketAddr::from(([0u16; 8], 0))
    };
    let socket = UdpSocket::bind(bind).await?;
    socket.connect(server).await?;
    socket.send(&query.encode()?).await?;
    let deadline = Instant::now() + timeout;
    let mut buf = vec![0u8; 4096];
    loop {
        let len = match tokio::time::timeout_at(deadline, socket.recv(&mut buf)).await {
            Err(_) => return Err(TransportError::Timeout),
            Ok(result) => result?,
        };
        match Message::decode(&buf[..len]) {
            Ok(resp) if matches_query(query, &resp) => return Ok(resp),
            Ok(_) | Err(_) => {
                tracing::debug!(%server, "ignoring unmatched or malformed datagram");
            }
        }
    }
}

fn matches_query(query: &Message, resp: &Message) -> bool {
    resp.header.qr && resp.header.id == query.header.id && resp.questions == query.questions
}
