//! Shared bind helpers: `socket2` with `IPV6_V6ONLY` before bind (Checkpoint A).

use std::net::{SocketAddr, TcpListener, UdpSocket};

use socket2::{Domain, Protocol, Socket, Type};

use crate::error::ListenersError;

/// Binds a non-blocking UDP socket on `addr`.
///
/// For IPv6 addresses, sets `IPV6_V6ONLY` **before** bind so `0.0.0.0:p` and
/// `[::]:p` can coexist on Linux.
pub fn bind_udp(addr: SocketAddr) -> Result<UdpSocket, ListenersError> {
    let socket = create_socket(addr, Type::DGRAM, Protocol::UDP, false)?;
    socket
        .bind(&addr.into())
        .map_err(|e| ListenersError::bind(addr, e))?;
    Ok(socket.into())
}

/// Binds a non-blocking TCP listener on `addr` (`SO_REUSEADDR`, backlog 1024).
///
/// For IPv6 addresses, sets `IPV6_V6ONLY` **before** bind so `0.0.0.0:p` and
/// `[::]:p` can coexist on Linux.
pub fn bind_tcp(addr: SocketAddr) -> Result<TcpListener, ListenersError> {
    let socket = create_socket(addr, Type::STREAM, Protocol::TCP, true)?;
    socket
        .bind(&addr.into())
        .map_err(|e| ListenersError::bind(addr, e))?;
    socket
        .listen(1024)
        .map_err(|e| ListenersError::bind(addr, e))?;
    Ok(socket.into())
}

fn create_socket(
    addr: SocketAddr,
    ty: Type,
    protocol: Protocol,
    reuseaddr: bool,
) -> Result<Socket, ListenersError> {
    let domain = Domain::for_address(addr);
    let socket =
        Socket::new(domain, ty, Some(protocol)).map_err(|e| ListenersError::bind(addr, e))?;
    if reuseaddr {
        socket
            .set_reuse_address(true)
            .map_err(|e| ListenersError::bind(addr, e))?;
    }
    if addr.is_ipv6() {
        // Must run before bind (Checkpoint A: dual-stack [::] otherwise claims IPv4 too).
        socket
            .set_only_v6(true)
            .map_err(|e| ListenersError::bind(addr, e))?;
    }
    socket
        .set_nonblocking(true)
        .map_err(|e| ListenersError::bind(addr, e))?;
    Ok(socket)
}
