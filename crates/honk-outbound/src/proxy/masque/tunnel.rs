//! Shared MASQUE tunnel state: a packet device plus the liveness of its
//! carrier.
//!
//! Both carriers (HTTP/2 and HTTP/3) end up with the same thing: a packet
//! device fed by a pair of shuttle tasks, and a flag that says whether the
//! carrier behind those tasks is still there. Keeping the state here means the
//! runtime in [`super`] caches one type whichever `network` a node picked, and
//! neither carrier has to know about the other's transport.
//!
//! The packet device ([`TunnelDevice`]) is backend-agnostic: the kernel
//! backend pins kernel sockets to a TUN device, the userspace backend opens
//! smoltcp sockets. The tunnel resolves the source address and dispatches the
//! dial, so the carriers and the dial side never branch on the backend.

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::sync::watch;

use super::bind;
use super::device::TunnelDevice;
use crate::proxy::AsyncReadWrite;
use crate::proxy::PacketTransport;
use crate::proxy::UdpSocketTransport;

/// Clears a tunnel's liveness flag when the task owning it exits, whichever
/// way it exits.
pub(super) struct LivenessGuard(pub(super) Arc<AtomicBool>);

impl LivenessGuard {
    pub(super) fn new(flag: Arc<AtomicBool>) -> Self {
        Self(flag)
    }
}

impl Drop for LivenessGuard {
    fn drop(&mut self) {
        self.store_dead();
    }
}

impl LivenessGuard {
    fn store_dead(&self) {
        self.0.store(false, Ordering::Relaxed);
    }
}

/// An established IP tunnel: a packet device fed by a MASQUE carrier.
pub struct MasqueTunnel {
    pub(super) device: TunnelDevice,
    /// Source addresses the endpoint (or the configuration) gave us.
    pub(super) addresses: Vec<IpAddr>,
    /// Cleared by whichever direction notices the carrier is gone, so the
    /// runtime can rebuild the tunnel instead of handing out a dead one.
    pub(super) alive: Arc<AtomicBool>,
    /// Releases the shuttle tasks. Both of them wait on the carrier or on the
    /// packet device, and neither would notice on its own that the tunnel is
    /// over.
    pub(super) shutdown: watch::Sender<bool>,
}

impl Drop for MasqueTunnel {
    fn drop(&mut self) {
        let _ = self.shutdown.send(true);
    }
}

impl MasqueTunnel {
    /// Assemble the shared state after a carrier has connected and configured
    /// the packet device.
    pub(super) fn new(
        device: TunnelDevice,
        addresses: Vec<IpAddr>,
        alive: Arc<AtomicBool>,
        shutdown: watch::Sender<bool>,
    ) -> Self {
        Self {
            device,
            addresses,
            alive,
            shutdown,
        }
    }

    /// Fresh liveness state for a carrier that is about to connect.
    pub(super) fn liveness() -> (Arc<AtomicBool>, watch::Sender<bool>, watch::Receiver<bool>) {
        let alive = Arc::new(AtomicBool::new(true));
        let (shutdown, receiver) = watch::channel(false);
        (alive, shutdown, receiver)
    }

    /// Whether the carrier is still running. A tunnel whose carrier died is
    /// unusable: the runtime replaces it rather than dialling through a device
    /// that no longer forwards packets.
    pub fn is_alive(&self) -> bool {
        self.alive.load(Ordering::Relaxed)
    }

    /// A stable label for logs and errors (the TUN name, or a synthetic id for
    /// the userspace backend).
    pub fn label(&self) -> String {
        self.device.label()
    }

    /// Source address of the same family as `target`, which dialled sockets
    /// must bind: the endpoint routes by source, so a mismatched family is a
    /// dead flow.
    pub fn source_for(&self, target: SocketAddr) -> Option<IpAddr> {
        self.addresses
            .iter()
            .copied()
            .find(|address| address.is_ipv4() == target.is_ipv4())
    }

    /// Open a TCP connection through the tunnel to `target`.
    ///
    /// The backend decides how: the kernel binds a real socket to the TUN
    /// device; the userspace backend opens the connection inside smoltcp and
    /// hands back a stream. Both return the same `Box<dyn AsyncReadWrite>`,
    /// so everything above this point is backend-agnostic.
    pub async fn dial(
        &self,
        target: SocketAddr,
        connect_timeout: Duration,
    ) -> io::Result<Box<dyn AsyncReadWrite>> {
        let source = self.source_for(target).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "masque tunnel {} has no {} source address for {target}",
                    self.label(),
                    if target.is_ipv4() { "IPv4" } else { "IPv6" },
                ),
            )
        })?;
        match &self.device {
            TunnelDevice::Kernel(tun) => bind::connect_via_tun(tun.name(), source, target, connect_timeout)
                .await
                .map(|stream| Box::new(stream) as Box<dyn AsyncReadWrite>),
            TunnelDevice::Userspace(device) => {
                bind::connect_via_userspace(device, source, target, connect_timeout).await
            }
        }
    }

    /// Open a UDP socket through the tunnel to `target`.
    pub async fn dial_udp(
        &self,
        target: SocketAddr,
        connect_timeout: Duration,
    ) -> io::Result<Arc<dyn PacketTransport>> {
        let source = self.source_for(target).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "masque tunnel {} has no {} source address for UDP {target}",
                    self.label(),
                    if target.is_ipv4() { "IPv4" } else { "IPv6" },
                ),
            )
        })?;
        match &self.device {
            TunnelDevice::Kernel(tun) => {
                let socket = bind::udp_via_tun(tun.name(), source)?;
                let socket = UdpSocket::from_std(socket)?;
                socket.connect(target).await?;
                Ok(Arc::new(UdpSocketTransport::new(Arc::new(socket), target)))
            }
            TunnelDevice::Userspace(device) => {
                bind::udp_via_userspace(device, source, target, connect_timeout).await
            }
        }
    }
}
