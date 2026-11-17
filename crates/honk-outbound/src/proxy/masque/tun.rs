//! TUN device plumbing for the MASQUE IP tunnel.
//!
//! The endpoint gives us IP packets; the kernel already knows how to turn
//! those into TCP and UDP far better than any userspace stack. So instead of
//! reimplementing TCP we hand the tunnel to the kernel as a network interface:
//!
//! ```text
//! app socket --(SO_BINDTODEVICE + source address)--> TUN --> tunnel task --> endpoint
//! ```
//!
//! Linux lets a socket be pinned to an interface with `SO_BINDTODEVICE`, and
//! binding the source address to the one the endpoint assigned makes the
//! kernel route that socket's packets out through the TUN device. Everything
//! above IP — handshake, congestion control, retransmits — stays in the kernel.

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::mem;
use std::net::IpAddr;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::io::AsRawFd;
use std::process::Command;
use tokio::io::unix::AsyncFd;

const TUN_PATH: &str = "/dev/net/tun";

/// Metric for the tunnel's default route. Far above any real default route
/// (LAN/WAN metrics are typically 0-600), so only `SO_BINDTODEVICE` sockets —
/// whose lookup is constrained to the tunnel — ever select it.
const TUN_ROUTE_METRIC: u32 = 20_000;

/// A TUN device carrying IP packets (no packet information header).
pub struct TunDevice {
    inner: AsyncFd<File>,
    name: String,
}

impl TunDevice {
    /// Create a TUN device. `name` may contain `%d`, which the kernel replaces
    /// with the next free index; the resolved name is returned by
    /// [`TunDevice::name`].
    pub fn create(name: &str) -> io::Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(TUN_PATH)?;

        match attach(&file, name) {
            Ok(resolved) => Self::finish(file, resolved),
            // The name is still held for an instant when the previous
            // generation of the same node is being torn down. Take the next
            // free index rather than failing the tunnel.
            Err(error) if error.raw_os_error() == Some(libc::EBUSY) => {
                let template = format!("{name}%d");
                let resolved = attach(&file, &template)?;
                Self::finish(file, resolved)
            }
            Err(error) => Err(error),
        }
    }

    fn finish(file: File, name: String) -> io::Result<Self> {
        Ok(Self {
            // SAFETY: `file` is the freshly opened TUN descriptor; nothing else
            // has a handle to it and it stays owned by the AsyncFd until drop.
            inner: unsafe { AsyncFd::register(file)? },
            name,
        })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    /// Assign the tunnel addresses, set the MTU, bring the interface up, and
    /// install a last-resort default route through it for each family.
    ///
    /// The default route is what makes arbitrary destinations reachable from a
    /// socket pinned with `SO_BINDTODEVICE`: the kernel still performs a route
    /// lookup for such a socket, constrained to the bound device. Its metric is
    /// deliberately enormous so it never outranks the system's real default
    /// route — only sockets bound to this device pick it.
    ///
    /// `slot` separates one node's tunnels from each other. A node may carry
    /// more than one path — its own, and one a group asked for — and each
    /// needs a default route of its own: `replace` with a shared metric would
    /// have the second tunnel overwrite the first's, leaving sockets pinned
    /// to the first device with nowhere to go. Distinct metrics let the
    /// lookup, which is already constrained to one device, find that
    /// device's route.
    pub fn configure(&self, addresses: &[IpAddr], mtu: u32, slot: usize) -> io::Result<()> {
        let mtu = mtu.to_string();
        let step = u32::try_from(slot).unwrap_or(0);
        let metric = TUN_ROUTE_METRIC.saturating_add(step).to_string();
        ip(&["link", "set", "dev", &self.name, "mtu", &mtu])?;
        for address in addresses {
            // A host route is all the tunnel needs: it is a source address the
            // endpoint already knows, not an on-link network.
            let prefix = if address.is_ipv4() { 32 } else { 128 };
            let address = format!("{address}/{prefix}");
            ip(&["addr", "add", &address, "dev", &self.name])?;
        }
        ip(&["link", "set", "dev", &self.name, "up"])?;
        for family in families(addresses) {
            // `replace` keeps a reconfigured device from failing on a route
            // the previous generation left behind.
            ip(&[
                family, "route", "replace", "default", "dev", &self.name, "metric", &metric,
            ])?;
        }
        Ok(())
    }

    /// Read one IP packet. Resolves when the device becomes readable.
    pub async fn recv(&self, buffer: &mut [u8]) -> io::Result<usize> {
        loop {
            let mut guard = self.inner.readable().await?;
            match guard.try_io(|inner| {
                let mut file = inner.get_ref();
                file.read(buffer)
            }) {
                Ok(result) => return result,
                Err(_would_block) => continue,
            }
        }
    }

    /// Write one IP packet.
    pub async fn send(&self, packet: &[u8]) -> io::Result<usize> {
        loop {
            let mut guard = self.inner.writable().await?;
            match guard.try_io(|inner| {
                let mut file = inner.get_ref();
                let written = file.write(packet)?;
                // A TUN write is normally atomic, but a short write would put
                // a truncated IP packet on the wire. Fail loudly instead of
                // silently corrupting the tunnel.
                if written != packet.len() {
                    return Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "masque TUN write was truncated",
                    ));
                }
                Ok(written)
            }) {
                Ok(result) => return result,
                Err(_would_block) => continue,
            }
        }
    }
}

/// Attach `file` to the device called `name`, returning the name the kernel
/// resolved (it expands a `%d` template to the next free index).
fn attach(file: &File, name: &str) -> io::Result<String> {
    let mut request: libc::ifreq = unsafe { mem::zeroed() };
    // Check before copying: `ifr_name` has to keep one byte for the NUL
    // terminator, and writing a full-length name would leave none.
    if name.len() >= request.ifr_name.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("TUN name {name:?} exceeds IFNAMSIZ"),
        ));
    }
    for (slot, byte) in request.ifr_name.iter_mut().zip(name.bytes()) {
        *slot = byte as libc::c_char;
    }
    request.ifr_ifru.ifru_flags = (libc::IFF_TUN | libc::IFF_NO_PI) as libc::c_short;

    if unsafe { libc::ioctl(file.as_raw_fd(), libc::TUNSETIFF, &request) } != 0 {
        return Err(io::Error::last_os_error());
    }

    Ok(request
        .ifr_name
        .iter()
        .take_while(|&&byte| byte != 0)
        .map(|&byte| byte as u8 as char)
        .collect::<String>())
}

/// The `ip` family selectors for the routes this device needs: `-4`, `-6`, or
/// both. A family without an address gets no route — adding one would fail on
/// kernels with that family disabled.
fn families(addresses: &[IpAddr]) -> Vec<&'static str> {
    let mut families = Vec::new();
    if addresses.iter().any(IpAddr::is_ipv4) {
        families.push("-4");
    }
    if addresses.iter().any(|address| address.is_ipv6()) {
        families.push("-6");
    }
    families
}

impl Drop for TunDevice {
    fn drop(&mut self) {
        // A TUN device disappears with the owning fd, but dropping the link
        // explicitly keeps `ip link` output clean while nodes churn.
        let _ = ip(&["link", "del", &self.name]);
    }
}

/// Run `ip` and turn a failure into an io::Error carrying its stderr.
fn ip(args: &[&str]) -> io::Result<()> {
    let output = Command::new("ip").args(args).output().map_err(|error| {
        io::Error::new(
            io::ErrorKind::NotFound,
            format!("cannot run `ip {}` : {error}", args.join(" ")),
        )
    })?;
    if output.status.success() {
        return Ok(());
    }
    Err(io::Error::other(format!(
        "ip {} failed: {}",
        args.join(" "),
        String::from_utf8_lossy(&output.stderr).trim()
    )))
}
