use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex, PoisonError};

use hickory_proto::op::Message;
use hickory_proto::rr::rdata::opt::{EdnsCode, EdnsOption};
use hickory_proto::rr::{Name, RecordType};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::Mutex as AsyncMutex;
use tokio::task::{JoinHandle, JoinSet};

use crate::TestkitError;
use crate::responder::respond;
use crate::zone::Zone;

/// Maximum number of attempts to find a port free for both UDP and TCP.
const BIND_ATTEMPTS: usize = 32;

/// Transport a query arrived on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Transport {
    /// UDP datagram.
    Udp,
    /// TCP stream (RFC 7766 length-prefixed framing).
    Tcp,
}

/// A query received by a fake server.
#[derive(Clone, Debug)]
pub struct ReceivedQuery {
    /// Query name as sent by the client.
    pub name: Name,
    /// Query type.
    pub query_type: RecordType,
    /// Transport the query arrived on.
    pub transport: Transport,
    /// Whether the query carried an EDNS OPT record.
    pub edns_present: bool,
    /// The DNSSEC OK bit from the OPT record (`false` without EDNS).
    pub dnssec_ok: bool,
    /// Raw EDNS options as received (empty without EDNS). Tests can assert
    /// that no client-subnet (ECS) option was sent.
    pub edns_options: Vec<(EdnsCode, EdnsOption)>,
}

/// State shared between a handle and its socket tasks.
struct Shared {
    zone: Zone,
    log: Mutex<Vec<ReceivedQuery>>,
}

struct Running {
    udp: JoinHandle<()>,
    tcp: JoinHandle<()>,
}

struct Inner {
    shared: Arc<Shared>,
    addr: SocketAddr,
    running: AsyncMutex<Option<Running>>,
}

impl Drop for Inner {
    fn drop(&mut self) {
        if let Some(running) = self.running.get_mut().take() {
            running.udp.abort();
            running.tcp.abort();
        }
    }
}

/// Handle to one fake authoritative server. Cheap to clone; the server stops
/// when the last handle is dropped.
#[derive(Clone)]
pub struct ServerHandle {
    inner: Arc<Inner>,
}

impl std::fmt::Debug for ServerHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServerHandle")
            .field("zone", self.inner.shared.zone.origin())
            .field("addr", &self.inner.addr)
            .finish()
    }
}

impl ServerHandle {
    /// Binds UDP and TCP on the same OS-assigned loopback port and starts serving.
    pub(crate) async fn spawn(zone: Zone) -> Result<Self, TestkitError> {
        let (udp, tcp) = bind_any_port().await?;
        let addr = udp.local_addr().map_err(|source| TestkitError::Bind {
            addr: SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
            source,
        })?;
        let shared = Arc::new(Shared {
            zone,
            log: Mutex::new(Vec::new()),
        });
        let running = run(&shared, udp, tcp);
        tracing::debug!(zone = %shared.zone.origin(), %addr, "fake server started");
        Ok(Self {
            inner: Arc::new(Inner {
                shared,
                addr,
                running: AsyncMutex::new(Some(running)),
            }),
        })
    }

    /// The zone origin this server is authoritative for.
    pub fn zone(&self) -> &Name {
        self.inner.shared.zone.origin()
    }

    /// The loopback address (UDP and TCP) of the server. Stable across
    /// [`stop`](Self::stop) / [`start`](Self::start).
    pub fn addr(&self) -> SocketAddr {
        self.inner.addr
    }

    /// Stops the server: both sockets are closed before this returns, so
    /// queries time out (UDP) or are refused (TCP). No-op if already stopped.
    pub async fn stop(&self) {
        let running = self.inner.running.lock().await.take();
        if let Some(running) = running {
            running.udp.abort();
            running.tcp.abort();
            // Wait for the tasks to drop their sockets; a cancellation error is expected.
            let _ = running.udp.await;
            let _ = running.tcp.await;
            tracing::debug!(zone = %self.zone(), addr = %self.addr(), "fake server stopped");
        }
    }

    /// Restarts a stopped server on the same port. No-op if already running.
    pub async fn start(&self) -> Result<(), TestkitError> {
        let mut guard = self.inner.running.lock().await;
        if guard.is_some() {
            return Ok(());
        }
        let addr = self.inner.addr;
        let udp = UdpSocket::bind(addr)
            .await
            .map_err(|source| TestkitError::Bind { addr, source })?;
        let tcp = TcpListener::bind(addr)
            .await
            .map_err(|source| TestkitError::Bind { addr, source })?;
        *guard = Some(run(&self.inner.shared, udp, tcp));
        tracing::debug!(zone = %self.zone(), %addr, "fake server restarted");
        Ok(())
    }

    /// Queries received so far, in arrival order (across restarts).
    pub fn queries(&self) -> Vec<ReceivedQuery> {
        self.inner
            .shared
            .log
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Clears the query log.
    pub fn clear_queries(&self) {
        self.inner
            .shared
            .log
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clear();
    }
}

/// Binds a UDP socket on port 0 and a TCP listener on the same port.
async fn bind_any_port() -> Result<(UdpSocket, TcpListener), TestkitError> {
    let any = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
    let mut last_error = None;
    for _ in 0..BIND_ATTEMPTS {
        let udp = UdpSocket::bind(any)
            .await
            .map_err(|source| TestkitError::Bind { addr: any, source })?;
        let port = udp
            .local_addr()
            .map_err(|source| TestkitError::Bind { addr: any, source })?
            .port();
        let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
        match TcpListener::bind(addr).await {
            Ok(tcp) => return Ok((udp, tcp)),
            Err(source) => last_error = Some(TestkitError::Bind { addr, source }),
        }
    }
    Err(last_error.unwrap_or(TestkitError::Bind {
        addr: any,
        source: std::io::Error::other("no free port"),
    }))
}

fn run(shared: &Arc<Shared>, udp: UdpSocket, tcp: TcpListener) -> Running {
    Running {
        udp: tokio::spawn(udp_loop(Arc::clone(shared), udp)),
        tcp: tokio::spawn(tcp_loop(Arc::clone(shared), tcp)),
    }
}

/// Parses, logs and answers one request; `None` if it is not a parsable message.
fn handle(shared: &Shared, bytes: &[u8], transport: Transport) -> Option<(Message, Message)> {
    let req = match Message::from_vec(bytes) {
        Ok(req) => req,
        Err(error) => {
            tracing::debug!(%error, "ignoring unparsable datagram");
            return None;
        }
    };
    if let Some(query) = req.queries.first() {
        let received = ReceivedQuery {
            name: query.name().clone(),
            query_type: query.query_type(),
            transport,
            edns_present: req.edns.is_some(),
            dnssec_ok: req.edns.as_ref().is_some_and(|e| e.flags().dnssec_ok),
            edns_options: req
                .edns
                .as_ref()
                .map(|e| e.options().options.clone())
                .unwrap_or_default(),
        };
        shared
            .log
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(received);
    }
    let resp = respond(&shared.zone, &req);
    Some((req, resp))
}

async fn udp_loop(shared: Arc<Shared>, socket: UdpSocket) {
    let mut buf = vec![0u8; 4096];
    loop {
        let Ok((len, peer)) = socket.recv_from(&mut buf).await else {
            continue;
        };
        let Some((req, resp)) = handle(&shared, &buf[..len], Transport::Udp) else {
            continue;
        };
        let limit = usize::from(req.max_payload().max(512));
        let encoded = match resp.to_vec() {
            Ok(bytes) if bytes.len() > limit => resp.truncate().to_vec(),
            other => other,
        };
        match encoded {
            Ok(bytes) => {
                if let Err(error) = socket.send_to(&bytes, peer).await {
                    tracing::debug!(%error, %peer, "udp send failed");
                }
            }
            Err(error) => tracing::debug!(%error, "failed to encode response"),
        }
    }
}

async fn tcp_loop(shared: Arc<Shared>, listener: TcpListener) {
    // Dropping the set (when this task is aborted) aborts all connections.
    let mut connections = JoinSet::new();
    loop {
        let Ok((stream, _peer)) = listener.accept().await else {
            continue;
        };
        while connections.try_join_next().is_some() {}
        connections.spawn(tcp_connection(Arc::clone(&shared), stream));
    }
}

async fn tcp_connection(shared: Arc<Shared>, mut stream: TcpStream) {
    loop {
        let Ok(len) = stream.read_u16().await else {
            return;
        };
        let mut buf = vec![0u8; usize::from(len)];
        if stream.read_exact(&mut buf).await.is_err() {
            return;
        }
        let Some((_, resp)) = handle(&shared, &buf, Transport::Tcp) else {
            return;
        };
        let Ok(bytes) = resp.to_vec() else {
            return;
        };
        let Ok(framed_len) = u16::try_from(bytes.len()) else {
            return;
        };
        if stream.write_u16(framed_len).await.is_err() || stream.write_all(&bytes).await.is_err() {
            return;
        }
    }
}
