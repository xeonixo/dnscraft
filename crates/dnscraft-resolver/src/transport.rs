//! Outgoing transport: UDP exchange with strict response matching, TCP
//! fallback on truncation, and multi-server querying with server selection.
//!
//! Source ports: every UDP exchange binds a fresh socket to port 0, so the OS
//! picks an ephemeral source port per query (randomised on Linux, BSD and
//! Windows). Together with the random 16-bit id this gives the usual
//! anti-spoofing entropy; we do not manage our own port pool.

use std::net::SocketAddr;
use std::time::Duration;

use crate::server_selection::ServerStats;

use dnscraft_proto::{Edns, Message, Name, ProtoError, RecordType};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::Instant;

/// EDNS UDP payload size advertised to authoritative servers.
pub const EDNS_PAYLOAD: u16 = 1232;

/// Why an exchange produced no usable response.
#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    #[error("no matching response within the timeout")]
    Timeout,
    #[error("socket error: {0}")]
    Io(#[from] std::io::Error),
    #[error("cannot encode query: {0}")]
    Encode(#[from] ProtoError),
    #[error("invalid response: {0}")]
    BadResponse(&'static str),
    #[error("no candidate servers")]
    NoServers,
}

/// Builds a non-recursive query with EDNS (1232 bytes, DO set) and a random id.
pub fn build_query(name: &Name, qtype: RecordType) -> Message {
    let mut msg = Message::query(rand::random::<u16>(), name.clone(), qtype);
    msg.header.rd = false;
    let mut edns = Edns::new(EDNS_PAYLOAD);
    edns.dnssec_ok = true;
    msg.edns = Some(edns);
    msg
}

/// Sends `query` over UDP to `server` and waits for a matching response;
/// a truncated (TC=1) response is retried over TCP.
///
/// The UDP socket is connected to `server` (the kernel drops datagrams from
/// other sources) and bound to an OS-chosen ephemeral source port. Datagrams
/// that do not decode or do not match (id, QR, opcode, question) are ignored
/// until `timeout` expires. The TCP retry gets its own `timeout` for connect,
/// write and read.
pub async fn exchange(
    server: SocketAddr,
    query: &Message,
    timeout: Duration,
) -> Result<Message, TransportError> {
    let resp = exchange_udp(server, query, timeout).await?;
    if resp.header.tc {
        tracing::debug!(%server, "truncated response, retrying over TCP");
        return exchange_tcp(server, query, timeout).await;
    }
    Ok(resp)
}

async fn exchange_udp(
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
    let mut buf = vec![0u8; 65535];
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

/// One query over a fresh TCP connection (RFC 7766 framing).
pub async fn exchange_tcp(
    server: SocketAddr,
    query: &Message,
    timeout: Duration,
) -> Result<Message, TransportError> {
    let wire = query.encode()?;
    let frame_len =
        u16::try_from(wire.len()).map_err(|_| TransportError::BadResponse("query too large"))?;
    let work = async {
        let mut stream = TcpStream::connect(server).await?;
        let mut framed = Vec::with_capacity(wire.len() + 2);
        framed.extend_from_slice(&frame_len.to_be_bytes());
        framed.extend_from_slice(&wire);
        stream.write_all(&framed).await?;
        let mut len = [0u8; 2];
        stream.read_exact(&mut len).await?;
        let mut buf = vec![0u8; usize::from(u16::from_be_bytes(len))];
        stream.read_exact(&mut buf).await?;
        Ok::<_, std::io::Error>(buf)
    };
    let buf = match tokio::time::timeout(timeout, work).await {
        Err(_) => return Err(TransportError::Timeout),
        Ok(r) => r?,
    };
    let resp =
        Message::decode(&buf).map_err(|_| TransportError::BadResponse("undecodable TCP reply"))?;
    if matches_query(query, &resp) {
        Ok(resp)
    } else {
        Err(TransportError::BadResponse(
            "TCP reply does not match query",
        ))
    }
}

/// A response together with the server that produced it.
#[derive(Debug)]
pub struct ServerResponse {
    /// The server that answered.
    pub server: SocketAddr,
    /// The response message.
    pub message: Message,
    /// Round-trip time of the successful exchange (including a TCP retry).
    pub rtt: Duration,
    /// `true` only when every server answered but the caller's `accept`
    /// predicate rejected all answers; `message` is then the last rejected one.
    pub lame: bool,
}

/// Tries `candidates` in the order given by `stats` until one gives a valid
/// response. See [`query_servers_with`]; every valid response is accepted
/// (REFUSED, SERVFAIL etc. are returned to the caller, who decides).
pub async fn query_servers(
    candidates: &[SocketAddr],
    query: &Message,
    timeout: Duration,
    stats: &ServerStats,
) -> Result<ServerResponse, TransportError> {
    query_servers_with(candidates, query, timeout, stats, |_| true).await
}

/// Tries `candidates` in `stats.order` until one gives a response accepted by
/// `accept`.
///
/// Contract: a timeout, network error or malformed/mismatching response moves
/// on to the next server (and is penalised in `stats`). A valid response
/// updates the server's smoothed RTT; if `accept` returns `false` (lame:
/// REFUSED, SERVFAIL, non-authoritative, ...) the next server is tried, and if
/// all servers were lame the last lame response is returned with
/// `lame = true`. If no server produced any valid response, the last error is
/// returned (`NoServers` for an empty list).
pub async fn query_servers_with(
    candidates: &[SocketAddr],
    query: &Message,
    timeout: Duration,
    stats: &ServerStats,
    accept: impl Fn(&Message) -> bool,
) -> Result<ServerResponse, TransportError> {
    let mut last_err = TransportError::NoServers;
    let mut lame: Option<ServerResponse> = None;
    for server in stats.order(candidates) {
        let start = Instant::now();
        match exchange(server, query, timeout).await {
            Ok(message) => {
                let rtt = start.elapsed();
                stats.record_success(server, rtt);
                let resp = ServerResponse {
                    server,
                    message,
                    rtt,
                    lame: false,
                };
                if accept(&resp.message) {
                    return Ok(resp);
                }
                tracing::debug!(%server, "lame response, trying next server");
                lame = Some(ServerResponse { lame: true, ..resp });
            }
            Err(e) => {
                match &e {
                    TransportError::Io(io) => stats.record_io_error(server, io),
                    _ => stats.record_failure(server),
                }
                tracing::debug!(%server, error = %e, "server failed, trying next");
                last_err = e;
            }
        }
    }
    lame.ok_or(last_err)
}

fn matches_query(query: &Message, resp: &Message) -> bool {
    resp.header.qr
        && resp.header.id == query.header.id
        && resp.header.opcode == query.header.opcode
        && resp.questions == query.questions
}
