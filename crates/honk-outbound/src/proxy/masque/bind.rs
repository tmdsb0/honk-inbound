//! Binding flows to a MASQUE TUN device.
//!
//! A MASQUE endpoint hands us an IP address, not a proxy for a destination.
//! To send a flow through the tunnel we therefore let the kernel open the
//! connection normally, but pin the socket to the tunnel:
//!
//! * `SO_BINDTODEVICE` forces egress through the TUN device;
//! * binding the source address to the one from ADDRESS_ASSIGN makes the
//!   kernel pick the tunnel route and use the right source.
//!
//! Everything else — handshake, congestion control, retransmits — stays in
//! the kernel, so a tunnel flow behaves like any other socket.

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;

use crate::proxy::AsyncReadWrite;
use crate::proxy::PacketTransport;
use super::userspace::UserspaceDevice;

/// Open a TCP connection whose packets leave through `tun` using `source` as
/// the source address.
pub async fn connect_via_tun(
    tun: &str,
    source: IpAddr,
    target: SocketAddr,
    connect_timeout: Duration,
) -> io::Result<TcpStream> {
    if source.is_ipv4() != target.is_ipv4() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "masque tunnel source and target address families differ",
        ));
    }
    let socket = new_socket(target)?;
    bind_tunnel(&socket, tun, source)?;

    match socket.connect(&target.into()) {
        Ok(()) => TcpStream::from_std(socket.into()),
        Err(error)
            if error.kind() == io::ErrorKind::WouldBlock
                || error.raw_os_error() == Some(libc::EINPROGRESS) =>
        {
            let stream = TcpStream::from_std(socket.into())?;
            tokio::time::timeout(connect_timeout, stream.writable())
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "connect timeout"))??;
            if let Some(error) = stream.take_error()? {
                return Err(error);
            }
            Ok(stream)
        }
        Err(error) => Err(error),
    }
}

/// Create a UDP socket bound to the tunnel, for flows that need a fixed
/// source address.
pub fn udp_via_tun(tun: &str, source: IpAddr) -> io::Result<std::net::UdpSocket> {
    let domain = if source.is_ipv4() {
        socket2::Domain::IPV4
    } else {
        socket2::Domain::IPV6
    };
    let socket = socket2::Socket::new(domain, socket2::Type::DGRAM, None)?;
    socket.set_nonblocking(true)?;
    mark_control_plane(&socket)?;
    bind_tunnel(&socket, tun, source)?;
    Ok(socket.into())
}

fn new_socket(target: SocketAddr) -> io::Result<socket2::Socket> {
    let domain = if target.is_ipv4() {
        socket2::Domain::IPV4
    } else {
        socket2::Domain::IPV6
    };
    let socket = socket2::Socket::new(domain, socket2::Type::STREAM, None)?;
    socket.set_nonblocking(true)?;
    socket.set_tcp_nodelay(true)?;
    socket.set_keepalive(true)?;
    mark_control_plane(&socket)?;
    Ok(socket)
}

/// Carry the control-plane mark, like every other socket honk originates.
///
/// The packets themselves leave through the TUN device rather than the WAN
/// interface, but the mark still protects against any eBPF hook that
/// classifies by socket mark instead of by device.
#[cfg(target_os = "linux")]
fn mark_control_plane(socket: &socket2::Socket) -> io::Result<()> {
    crate::util::set_mark_best_effort(socket, crate::util::bypass_mark())
}

#[cfg(not(target_os = "linux"))]
fn mark_control_plane(_socket: &socket2::Socket) -> io::Result<()> {
    Ok(())
}

#[cfg(target_os = "linux")]
fn bind_tunnel(socket: &socket2::Socket, tun: &str, source: IpAddr) -> io::Result<()> {
    socket.bind_device(Some(tun.as_bytes()))?;
    socket.bind(&SocketAddr::new(source, 0).into())
}

#[cfg(not(target_os = "linux"))]
fn bind_tunnel(_socket: &socket2::Socket, _tun: &str, _source: IpAddr) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "MASQUE tunnels require SO_BINDTODEVICE, which is Linux-only",
    ))
}

/// Open a TCP connection through the in-process smoltcp stack backing the
/// `userspace` tunnel backend. The kernel is never involved: smoltcp owns the
/// connection and hands it back as a stream that behaves like any other.
pub async fn connect_via_userspace(
    device: &Arc<UserspaceDevice>,
    source: IpAddr,
    target: SocketAddr,
    connect_timeout: Duration,
) -> io::Result<Box<dyn AsyncReadWrite>> {
    if source.is_ipv4() != target.is_ipv4() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "masque tunnel source and target address families differ",
        ));
    }
    let connection = device.tcp_connect(source, target, connect_timeout).await.map_err(
        |error| {
            io::Error::new(
                io::ErrorKind::ConnectionRefused,
                format!("masque userspace connect to {target} failed: {error}"),
            )
        },
    )?;
    Ok(Box::new(connection) as Box<dyn AsyncReadWrite>)
}

/// Bind a UDP socket inside the in-process smoltcp stack backing the
/// `userspace` tunnel backend.
pub async fn udp_via_userspace(
    device: &Arc<UserspaceDevice>,
    source: IpAddr,
    target: SocketAddr,
    connect_timeout: Duration,
) -> io::Result<Arc<dyn PacketTransport>> {
    if source.is_ipv4() != target.is_ipv4() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "masque tunnel source and target address families differ",
        ));
    }
    let socket = device.udp_bind(source, target, connect_timeout).await.map_err(
        |error| {
            io::Error::new(
                io::ErrorKind::AddrInUse,
                format!("masque userspace udp bind for {target} failed: {error}"),
            )
        },
    )?;
    Ok(Arc::new(socket) as Arc<dyn PacketTransport>)
}
