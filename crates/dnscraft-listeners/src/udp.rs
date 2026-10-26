//! Do53 UDP listener (concrete tokio socket or wildcard `quinn-udp`).

use std::io::{self, IoSliceMut};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime};

use dnscraft_policy::DnsProtocol;
use dnscraft_proto::Message;
use quinn_udp::{RecvMeta, Transmit, UdpSocketState};
use tokio::io::Interest;
use tokio::net::UdpSocket as TokioUdpSocket;
use tokio::sync::{Notify, Semaphore, oneshot, watch};

use crate::admission::{Admission, AdmitDecision, ClientIdState};
use crate::clock::{Clock, wait_until};
use crate::config::{Limits, ListenerConfig, PublicConfig};
use crate::core::{QueryMeta, handle_wire};
use crate::error::ListenersError;
use crate::handler::QueryHandler;
use crate::socket::bind_udp;

/// Classic DNS UDP size when the query has no OPT.
pub const CLASSIC_UDP_LIMIT: usize = 512;

/// Counters for one UDP listener (status / tests).
#[derive(Debug, Default)]
pub struct UdpStats {
    /// Datagrams accepted into processing (after a successful recv).
    pub received: AtomicU64,
    /// Answers successfully sent.
    pub answered: AtomicU64,
    /// Dropped because the source was public on Do53.
    pub dropped_public: AtomicU64,
    /// Dropped by other admission decisions (rate / ban).
    pub dropped_admission: AtomicU64,
    /// Dropped because the in-flight cap was full.
    pub dropped_inflight: AtomicU64,
    /// Dropped because [`Limits::query_timeout`] expired.
    pub dropped_timeout: AtomicU64,
    /// `handle_wire` returned `None` (no reply).
    pub dropped_silent: AtomicU64,
}

impl UdpStats {
    fn bump(field: &AtomicU64) {
        field.fetch_add(1, Ordering::Relaxed);
    }
}

/// Shared state for the recv loop and in-flight reply tasks.
struct UdpShared<H: ?Sized> {
    listener: ListenerConfig,
    limits: Limits,
    handler: Arc<H>,
    admission: Mutex<Admission>,
    clock: Arc<dyn Clock>,
    stats: Arc<UdpStats>,
    inflight: Arc<Semaphore>,
    sock: Arc<TokioUdpSocket>,
    /// Present when bound to an unspecified address (pktinfo path).
    state: Option<Arc<UdpSocketState>>,
}

/// Inputs for [`serve_udp`].
pub struct UdpServeParams<H: ?Sized> {
    /// Listener id / bind / exposure.
    pub listener: ListenerConfig,
    /// Shared limits (rates, timeouts, in-flight cap).
    pub limits: Limits,
    /// Public ban / tracking settings (rates still apply when public is off).
    pub public: PublicConfig,
    /// Policy or test handler.
    pub handler: Arc<H>,
    /// Wall clock (injectable for tests).
    pub clock: Arc<dyn Clock>,
    /// Counters for this listener.
    pub stats: Arc<UdpStats>,
    /// Receives the bound address once (useful when the config used port 0).
    pub bound: oneshot::Sender<SocketAddr>,
    /// Set to `true` to stop the accept loop.
    pub shutdown: watch::Receiver<bool>,
}

/// Runs one Do53 UDP listener until `params.shutdown` becomes `true`.
///
/// Concrete binds use tokio `recv_from` / `send_to`. Wildcard binds
/// (`0.0.0.0` / `::`) use [`UdpSocketState`] so replies leave from the
/// datagram's destination address.
pub async fn serve_udp<H>(params: UdpServeParams<H>) -> Result<(), ListenersError>
where
    H: QueryHandler + 'static,
{
    let UdpServeParams {
        listener,
        limits,
        public,
        handler,
        clock,
        stats,
        bound,
        mut shutdown,
    } = params;

    let std_sock = bind_udp(listener.address)?;
    let local = std_sock
        .local_addr()
        .map_err(|e| ListenersError::bind(listener.address, e))?;
    let wildcard = is_unspecified(local.ip());
    let state = if wildcard {
        Some(Arc::new(UdpSocketState::new((&std_sock).into()).map_err(
            |e| ListenersError::bind(listener.address, format!("UdpSocketState: {e}")),
        )?))
    } else {
        None
    };
    let sock = Arc::new(
        TokioUdpSocket::from_std(std_sock)
            .map_err(|e| ListenersError::bind(listener.address, e))?,
    );
    let _ = bound.send(local);

    let inflight = Arc::new(Semaphore::new(
        limits.max_inflight_per_listener.max(1) as usize
    ));
    let shared = Arc::new(UdpShared {
        admission: Mutex::new(Admission::new(&limits, &public)),
        listener,
        limits,
        handler,
        clock,
        stats,
        inflight,
        sock,
        state,
    });

    loop {
        tokio::select! {
            biased;
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    return Ok(());
                }
            }
            ready = shared.sock.readable() => {
                if ready.is_err() {
                    continue;
                }
                let _ = recv_batch(&shared).await;
            }
        }
    }
}

fn is_unspecified(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => v.is_unspecified(),
        IpAddr::V6(v) => v.is_unspecified(),
    }
}

/// UDP response size limit from the wire query (SPEC / N4).
pub fn udp_size_limit(wire: &[u8], udp_payload_max: u16) -> usize {
    match Message::decode(wire) {
        Ok(msg) => match msg.edns.as_ref() {
            Some(edns) => usize::from(edns.udp_payload.min(udp_payload_max)),
            None => CLASSIC_UDP_LIMIT,
        },
        Err(_) => CLASSIC_UDP_LIMIT,
    }
}

async fn recv_batch<H>(shared: &Arc<UdpShared<H>>) -> io::Result<()>
where
    H: QueryHandler + 'static,
{
    if let Some(state) = shared.state.as_ref() {
        let mut buf = [0u8; 65535];
        let mut meta = [RecvMeta::default()];
        let n = {
            let sock = Arc::clone(&shared.sock);
            let state = Arc::clone(state);
            shared.sock.try_io(Interest::READABLE, || {
                let mut iov = [IoSliceMut::new(&mut buf)];
                state.recv((&*sock).into(), &mut iov, &mut meta)
            })?
        };
        if n == 0 {
            return Ok(());
        }
        let m = meta[0];
        let mut offset = 0;
        while offset < m.len {
            let end = (offset + m.stride.max(1)).min(m.len);
            let datagram = buf[offset..end].to_vec();
            offset = end;
            if datagram.is_empty() {
                continue;
            }
            spawn_query(Arc::clone(shared), m.addr, m.dst_ip, datagram);
        }
        Ok(())
    } else {
        let mut buf = [0u8; 65535];
        let (n, peer) = shared
            .sock
            .try_io(Interest::READABLE, || shared.sock.try_recv_from(&mut buf))?;
        if n == 0 {
            return Ok(());
        }
        spawn_query(Arc::clone(shared), peer, None, buf[..n].to_vec());
        Ok(())
    }
}

fn spawn_query<H>(
    shared: Arc<UdpShared<H>>,
    peer: SocketAddr,
    dst_ip: Option<IpAddr>,
    datagram: Vec<u8>,
) where
    H: QueryHandler + 'static,
{
    UdpStats::bump(&shared.stats.received);

    let now = shared.clock.now();
    let decision = {
        let mut adm = shared
            .admission
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        adm.check(&shared.listener, peer.ip(), &ClientIdState::Absent, now)
    };
    match decision {
        AdmitDecision::Admit => {}
        AdmitDecision::Drop { code } | AdmitDecision::Refuse { code } => {
            record_admission_drop(&shared.stats, code);
            return;
        }
    }

    let permit = match shared.inflight.clone().try_acquire_owned() {
        Ok(p) => p,
        Err(_) => {
            UdpStats::bump(&shared.stats.dropped_inflight);
            return;
        }
    };

    tokio::spawn(async move {
        let _permit = permit;
        let size_limit = udp_size_limit(&datagram, shared.limits.udp_payload_max);
        let meta = QueryMeta {
            protocol: DnsProtocol::Udp53,
            listener_id: shared.listener.id.clone(),
            source: peer.ip(),
            client_id: None,
            size_limit,
            pad: false,
            udp_payload_max: shared.limits.udp_payload_max,
        };
        let deadline = add_duration(shared.clock.now(), shared.limits.query_timeout);
        let wake = Notify::new();

        enum Outcome {
            Answer(Vec<u8>),
            Silent,
            Timeout,
        }

        let outcome = tokio::select! {
            result = handle_wire(&datagram, meta, &shared.handler) => {
                match result {
                    Some(r) => Outcome::Answer(r.bytes),
                    None => Outcome::Silent,
                }
            }
            () = wait_until(shared.clock.as_ref(), deadline, &wake) => Outcome::Timeout,
        };

        match outcome {
            Outcome::Timeout => {
                UdpStats::bump(&shared.stats.dropped_timeout);
            }
            Outcome::Silent => {
                UdpStats::bump(&shared.stats.dropped_silent);
            }
            Outcome::Answer(bytes) => {
                if send_reply(&shared, peer, dst_ip, &bytes).await.is_ok() {
                    UdpStats::bump(&shared.stats.answered);
                }
            }
        }
    });
}

async fn send_reply<H>(
    shared: &UdpShared<H>,
    peer: SocketAddr,
    dst_ip: Option<IpAddr>,
    bytes: &[u8],
) -> io::Result<()> {
    if let Some(state) = shared.state.as_ref() {
        let transmit = Transmit {
            destination: peer,
            ecn: None,
            contents: bytes,
            segment_size: None,
            src_ip: dst_ip,
        };
        loop {
            shared.sock.writable().await?;
            match shared.sock.try_io(Interest::WRITABLE, || {
                state.try_send((&*shared.sock).into(), &transmit)
            }) {
                Ok(()) => return Ok(()),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                Err(e) => return Err(e),
            }
        }
    } else {
        shared.sock.send_to(bytes, peer).await.map(|_| ())
    }
}

fn add_duration(now: SystemTime, d: Duration) -> SystemTime {
    now.checked_add(d).unwrap_or(SystemTime::UNIX_EPOCH)
}

fn record_admission_drop(stats: &UdpStats, code: &str) {
    if code == "listeners.admission.public_do53" {
        UdpStats::bump(&stats.dropped_public);
    } else {
        UdpStats::bump(&stats.dropped_admission);
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn public_drop_code_increments_dropped_public() {
        let stats = UdpStats::default();
        record_admission_drop(&stats, "listeners.admission.public_do53");
        assert_eq!(stats.dropped_public.load(Ordering::Relaxed), 1);
        record_admission_drop(&stats, "listeners.rate_limited");
        assert_eq!(stats.dropped_admission.load(Ordering::Relaxed), 1);
    }
}
