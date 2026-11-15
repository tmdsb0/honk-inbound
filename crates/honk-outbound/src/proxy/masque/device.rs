//! MASQUE tunnel backend selection and the packet-device abstraction.
//!
//! Both carriers (HTTP/2 and HTTP/3) shuttle raw IP packets between the
//! MASQUE stream and a *packet device*. The device is the only thing that
//! differs between backends:
//!
//! * [`TunnelBackend::Kernel`] hands packets to a kernel TUN interface
//!   ([`TunDevice`]); the kernel then owns TCP/UDP via `SO_BINDTODEVICE`.
//! * [`TunnelBackend::Userspace`] hands packets to an in-process smoltcp
//!   stack ([`UserspaceDevice`]), which owns TCP/UDP itself — no TUN device,
//!   no `ip` calls, no extra capabilities.
//!
//! The carriers and the dial side are written against [`TunnelDevice`] and
//! never branch on the concrete backend, so the two backends share one
//! shuttle and one dial path instead of each getting a copy.

use std::io;
use std::net::IpAddr;
use std::sync::Arc;

use super::tun::TunDevice;
use super::userspace::UserspaceDevice;

/// Which packet device backs a MASQUE tunnel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TunnelBackend {
    /// Kernel TUN device + `SO_BINDTODEVICE`. The default; requires
    /// `/dev/net/tun`, `iproute2` and `CAP_NET_ADMIN`.
    Kernel,
    /// In-process smoltcp IP stack. No TUN device, no `ip` calls, no extra
    /// capabilities beyond what honk already holds.
    Userspace,
}

impl TunnelBackend {
    /// Parse the `global.masque_tunnel_mode` string. Anything unrecognised
    /// falls back to [`TunnelBackend::Kernel`] so a typo never silently
    /// disables the tunnel.
    pub fn parse(mode: &str) -> Self {
        match mode {
            "userspace" => Self::Userspace,
            _ => Self::Kernel,
        }
    }
}

/// The backend tunnels should use, derived from `global.masque_tunnel_mode`
/// and set once at startup. Read on every tunnel open, so it is a
/// process-global boot setting: a reload rebuilds tunnels but keeps the
/// backend chosen at boot.
static SELECTED_BACKEND: std::sync::OnceLock<TunnelBackend> = std::sync::OnceLock::new();

/// Record the backend chosen from `global.masque_tunnel_mode`.
///
/// A second, differing call is ignored — the first boot wins, as documented
/// for the setting.
pub fn set_masque_tunnel_backend(backend: TunnelBackend) {
    let _ = SELECTED_BACKEND.set(backend);
}

/// The backend tunnels should use. Defaults to [`TunnelBackend::Kernel`] until
/// [`set_masque_tunnel_backend`] runs, which keeps tests and any path that
/// opens a tunnel before config load on the historical kernel path.
pub fn masque_tunnel_backend() -> TunnelBackend {
    SELECTED_BACKEND
        .get()
        .copied()
        .unwrap_or(TunnelBackend::Kernel)
}

/// A packet device a carrier shuttle reads IP packets from and writes them to.
///
/// [`TunnelDevice::Kernel`] and [`TunnelDevice::Userspace`] implement the same
/// two operations; the carriers (and the dial side) call them through this
/// enum and stay backend-agnostic.
#[derive(Clone)]
pub enum TunnelDevice {
    Kernel(Arc<TunDevice>),
    Userspace(Arc<UserspaceDevice>),
}

impl TunnelDevice {
    /// Build the device for `backend`, configuring it with `addresses` (the
    /// tunnel source addresses) and `mtu`. `tun_name` and `slot` are used by
    /// the kernel backend to name and route the TUN device.
    pub fn create(
        backend: TunnelBackend,
        tun_name: &str,
        addresses: &[IpAddr],
        mtu: u32,
        slot: usize,
    ) -> io::Result<Self> {
        match backend {
            TunnelBackend::Kernel => {
                let tun = Arc::new(TunDevice::create(tun_name)?);
                tun.configure(addresses, mtu, slot)?;
                Ok(Self::Kernel(tun))
            }
            TunnelBackend::Userspace => {
                let device = Arc::new(UserspaceDevice::create(addresses, mtu, slot)?);
                Ok(Self::Userspace(device))
            }
        }
    }

    /// Read one IP packet destined for the MASQUE endpoint.
    pub async fn recv_packet(&self, buffer: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Kernel(tun) => tun.recv(buffer).await,
            Self::Userspace(device) => device.recv_packet(buffer).await,
        }
    }

    /// Write one IP packet received from the MASQUE endpoint.
    pub async fn send_packet(&self, packet: &[u8]) -> io::Result<usize> {
        match self {
            Self::Kernel(tun) => tun.send(packet).await,
            Self::Userspace(device) => device.send_packet(packet).await,
        }
    }

    /// A stable label for logs and errors: the TUN name, or a synthetic id.
    pub fn label(&self) -> String {
        match self {
            Self::Kernel(tun) => tun.name().to_string(),
            Self::Userspace(device) => device.label(),
        }
    }
}
