//! Shared MASQUE tunnel state: a TUN device plus the liveness of its carrier.
//!
//! Both carriers (HTTP/2 and HTTP/3) end up with the same thing: a TUN device
//! fed by a pair of shuttle tasks, and a flag that says whether the carrier
//! behind those tasks is still there. Keeping the state here means the runtime
//! in [`super`] caches one type whichever `network` a node picked, and neither
//! carrier has to know about the other's transport.

use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use tokio::sync::watch;

use super::tun::TunDevice;

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

/// An established IP tunnel: a TUN device fed by a MASQUE carrier.
pub struct MasqueTunnel {
    pub(super) tun: Arc<TunDevice>,
    /// Source addresses the kernel may use: as many of IPv4 and IPv6 as the
    /// endpoint (or the configuration) gave us.
    pub(super) addresses: Vec<IpAddr>,
    /// Cleared by whichever direction notices the carrier is gone, so the
    /// runtime can rebuild the tunnel instead of handing out a dead one.
    pub(super) alive: Arc<AtomicBool>,
    /// Releases the shuttle tasks. Both of them wait on the carrier or on the
    /// TUN device, and neither would notice on its own that the tunnel is
    /// over: a device whose reader never returns keeps its name, and the next
    /// tunnel for the same node then fails to create it with `EBUSY`.
    ///
    /// A watch rather than a `Notify`: waking only the waiters loses the
    /// wakeup for whichever task was mid-packet at that moment, and that
    /// task then holds its TUN device forever.
    pub(super) shutdown: watch::Sender<bool>,
}

impl Drop for MasqueTunnel {
    fn drop(&mut self) {
        let _ = self.shutdown.send(true);
    }
}

impl MasqueTunnel {
    /// Assemble the shared state after a carrier has connected and configured
    /// the TUN device.
    pub(super) fn new(
        tun: Arc<TunDevice>,
        addresses: Vec<IpAddr>,
        alive: Arc<AtomicBool>,
        shutdown: watch::Sender<bool>,
    ) -> Self {
        Self {
            tun,
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
    /// unusable: the runtime replaces it rather than dialling through a TUN
    /// device that no longer forwards packets.
    pub fn is_alive(&self) -> bool {
        self.alive.load(Ordering::Relaxed)
    }

    /// Interface name of the TUN device backing this tunnel.
    pub fn tun_name(&self) -> &str {
        self.tun.name()
    }

    /// Source address of the same family as `target`, which dialled sockets
    /// must bind: the endpoint routes by source, so a mismatched family is a
    /// dead flow.
    pub fn source_for(&self, target: std::net::SocketAddr) -> Option<IpAddr> {
        self.addresses
            .iter()
            .copied()
            .find(|address| address.is_ipv4() == target.is_ipv4())
    }
}
