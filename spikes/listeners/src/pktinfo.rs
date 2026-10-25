//! quinn-udp: wildcard bind learns destination IP and replies FROM it.

use std::io::{self, IoSliceMut};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::time::Duration;

use quinn_udp::{RecvMeta, Transmit, UdpSocketState};

const MAGIC: &[u8] = b"dnscraft-pktinfo";

pub fn run() -> Result<Vec<String>, String> {
    let mut report = Vec::new();

    // Linux treats all of 127.0.0.0/8 as loopback; 127.0.0.2 needs no extra address.
    let v4 = probe_v4(&[
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)),
    ])?;
    report.extend(v4);

    let v6 = probe_v6(IpAddr::V6(Ipv6Addr::LOCALHOST))?;
    report.extend(v6);

    // ULA on a dummy interface needs CAP_NET_ADMIN / root — not available here.
    report.push(
        "ULA on dummy interface: SKIPPED (ip link add type dummy → Operation not permitted; uid≠0)"
            .into(),
    );

    Ok(report)
}

fn probe_v4(dests: &[IpAddr]) -> Result<Vec<String>, String> {
    let server = UdpSocket::bind(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)))
        .map_err(|e| format!("bind 0.0.0.0:0: {e}"))?;
    server
        .set_nonblocking(true)
        .map_err(|e| format!("nonblocking: {e}"))?;
    let server_port = server
        .local_addr()
        .map_err(|e| format!("local_addr: {e}"))?
        .port();
    let state = UdpSocketState::new((&server).into()).map_err(|e| format!("UdpSocketState: {e}"))?;

    let mut lines = Vec::new();
    for &dest_ip in dests {
        let client = UdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .map_err(|e| format!("client bind: {e}"))?;
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .map_err(|e| format!("client timeout: {e}"))?;
        let dest = SocketAddr::new(dest_ip, server_port);
        client
            .send_to(MAGIC, dest)
            .map_err(|e| format!("send_to {dest}: {e}"))?;

        // Drain until our datagram arrives (ignore unrelated noise).
        let (peer, learned_dst, reply_src) = recv_and_reply(&server, &state, MAGIC)?;
        let _ = peer;

        let mut buf = [0u8; 64];
        let (n, from) = client
            .recv_from(&mut buf)
            .map_err(|e| format!("client recv (dest={dest_ip}): {e}"))?;
        if &buf[..n] != MAGIC {
            return Err(format!("bad reply payload from {from}"));
        }

        lines.push(format!(
            "IPv4 dest={dest_ip}: RecvMeta.dst_ip={learned_dst:?}, reply from={from}, Transmit.src_ip={reply_src:?}"
        ));

        if learned_dst != Some(dest_ip) {
            return Err(format!(
                "expected dst_ip={dest_ip}, got {learned_dst:?} (wildcard 0.0.0.0:{server_port})"
            ));
        }
        if from.ip() != dest_ip {
            return Err(format!(
                "reply source {} != destination {dest_ip} (pktinfo send failed)",
                from.ip()
            ));
        }
        if reply_src != Some(dest_ip) {
            return Err(format!("Transmit.src_ip={reply_src:?}, expected {dest_ip}"));
        }
    }
    Ok(lines)
}

fn probe_v6(dest_ip: IpAddr) -> Result<Vec<String>, String> {
    let server = UdpSocket::bind(SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0)))
        .map_err(|e| format!("bind [::]:0: {e}"))?;
    server
        .set_nonblocking(true)
        .map_err(|e| format!("nonblocking v6: {e}"))?;
    let server_port = server
        .local_addr()
        .map_err(|e| format!("local_addr v6: {e}"))?
        .port();
    let state = UdpSocketState::new((&server).into())
        .map_err(|e| format!("UdpSocketState v6: {e}"))?;

    let client = UdpSocket::bind(SocketAddr::from((Ipv6Addr::LOCALHOST, 0)))
        .map_err(|e| format!("client v6 bind: {e}"))?;
    client
        .set_read_timeout(Some(Duration::from_secs(2)))
        .map_err(|e| format!("client v6 timeout: {e}"))?;
    let dest = SocketAddr::new(dest_ip, server_port);
    client
        .send_to(MAGIC, dest)
        .map_err(|e| format!("send_to {dest}: {e}"))?;

    let (_peer, learned_dst, reply_src) = recv_and_reply(&server, &state, MAGIC)?;

    let mut buf = [0u8; 64];
    let (n, from) = client
        .recv_from(&mut buf)
        .map_err(|e| format!("client v6 recv: {e}"))?;
    if &buf[..n] != MAGIC {
        return Err(format!("bad v6 reply payload from {from}"));
    }

    let line = format!(
        "IPv6 dest={dest_ip}: RecvMeta.dst_ip={learned_dst:?}, reply from={from}, Transmit.src_ip={reply_src:?}"
    );

    if learned_dst != Some(dest_ip) {
        return Err(format!(
            "expected dst_ip={dest_ip}, got {learned_dst:?} (wildcard [::]:{server_port})"
        ));
    }
    if from.ip() != dest_ip {
        return Err(format!(
            "v6 reply source {} != destination {dest_ip}",
            from.ip()
        ));
    }
    Ok(vec![line])
}

fn recv_and_reply(
    server: &UdpSocket,
    state: &UdpSocketState,
    expect: &[u8],
) -> Result<(SocketAddr, Option<IpAddr>, Option<IpAddr>), String> {
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    loop {
        if std::time::Instant::now() > deadline {
            return Err("server recv timed out".into());
        }
        let mut buf = [0u8; 2048];
        let mut meta = [RecvMeta::default()];
        let mut iov = [IoSliceMut::new(&mut buf)];
        match state.recv(server.into(), &mut iov, &mut meta) {
            Ok(0) => {
                std::thread::sleep(Duration::from_millis(5));
                continue;
            }
            Ok(_) => {
                let m = meta[0];
                if m.len < expect.len() || &buf[..expect.len()] != expect {
                    continue;
                }
                let src_ip = m.dst_ip;
                let transmit = Transmit {
                    destination: m.addr,
                    ecn: None,
                    contents: expect,
                    segment_size: None,
                    src_ip,
                };
                // Spin on WouldBlock briefly.
                let send_deadline = std::time::Instant::now() + Duration::from_secs(1);
                loop {
                    match state.try_send(server.into(), &transmit) {
                        Ok(()) => break,
                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                            if std::time::Instant::now() > send_deadline {
                                return Err(format!("try_send WouldBlock until timeout: {e}"));
                            }
                            std::thread::sleep(Duration::from_millis(1));
                        }
                        Err(e) => return Err(format!("try_send: {e}")),
                    }
                }
                return Ok((m.addr, m.dst_ip, src_ip));
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(e) => return Err(format!("recv: {e}")),
        }
    }
}
