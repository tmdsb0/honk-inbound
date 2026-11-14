//! MASQUE connect-ip outbound (RFC 9484).
//!
//! A MASQUE endpoint does not proxy a destination for us — it hands us an IP
//! interface. The tunnel therefore carries *IP packets*, not streams, which
//! makes it structurally different from every other outbound in honk:
//!
//! * we open an extended CONNECT with `:protocol = connect-ip`;
//! * the endpoint replies with ADDRESS_ASSIGN, telling us which source address
//!   our packets must use;
//! * IP packets travel inside DATAGRAM capsules (HTTP/2) or QUIC DATAGRAMs
//!   (HTTP/3).
//!
//! Two backends carry those packets, chosen once at boot by
//! `global.masque_tunnel_mode`:
//!
//! * `tun` (default) exposes the tunnel as a kernel TUN device and lets the
//!   kernel own TCP/UDP. A dialled socket is bound to the device
//!   (`SO_BINDTODEVICE`) and to the assigned source address, so the kernel
//!   routes it with full BBR, window scaling and retransmit behaviour. See
//!   [`tun`] and [`bind`].
//! * `userspace` hands packets to an in-process smoltcp stack that owns
//!   TCP/UDP itself — no TUN device, no `ip` calls, no extra capabilities.
//!   See [`userspace`].
//!
//! Carriers, shuttles and dial paths are written against
//! [`device::TunnelDevice`] and never branch on the backend, so the default
//! kernel path is unchanged.

pub mod bind;
pub mod capsule;
pub mod carrier;
pub mod device;
pub mod http2;
pub mod http3;
pub mod tun;
pub mod tunnel;
pub mod userspace;
pub mod warp;

/// Set the MASQUE tunnel backend chosen from `global.masque_tunnel_mode`.
///
/// Re-exported so the boot path can record the setting once, before any
/// tunnel opens; the value is then read on every tunnel open.
pub use device::{set_masque_tunnel_backend, TunnelBackend};

use async_trait::async_trait;
use honk_config::node::Node;
use std::fmt;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tokio::sync::Mutex;

/// Slots a generation's own tunnel (0) and the detour paths it carries (1, 2, …)
/// occupy. Ephemeral runtimes — probes and one-shot dials — open their own
/// tunnel rather than share the generation's, so their slots live in a high
/// range that can never overlap and is unique per ephemeral runtime.
const EPHEMERAL_MASQUE_BASE: usize = 0x8000;
const EPHEMERAL_MASQUE_SPAN: usize = 0x7000;

/// Monotonically handed out to ephemeral MASQUE tunnels so two probes of the
/// same node never ask the kernel for the same TUN device name. Wraps within
/// [`EPHEMERAL_MASQUE_SPAN`]; a slot is only reused once every prior holder has
/// been torn down, and teardown deletes the device first.
static NEXT_EPHEMERAL_MASQUE_SLOT: AtomicUsize = AtomicUsize::new(EPHEMERAL_MASQUE_BASE);

use super::{
    PacketOutbound, PacketTransport, ProbeableOutbound, ProxyStream, RuntimeOwnedIo, TcpOutbound,
    WarmRequirement, WarmableOutbound,
};
use crate::runtime::{NodeRuntime, ProtocolRuntime};

/// MASQUE outbound handler. Stateless: the tunnel itself lives in the node's
/// generation runtime ([`MasqueRuntime`]) so a reload tears down the old TUN
/// device instead of leaking it.
#[derive(Default)]
pub struct MasqueHandler;

impl MasqueHandler {
    pub fn new() -> Self {
        Self
    }
}

/// Generation-owned MASQUE state: one IP tunnel per path.
///
/// Every flow on the node shares the tunnel for the path it takes — a MASQUE
/// endpoint assigns one address per CONNECT, and each dialled socket simply
/// binds it as its source. Establishing it lazily keeps a node that never
/// carries traffic from owning a TUN device.
///
/// One per path rather than one per node, because the tunnel *is* the path:
/// its carrier is the connection to the endpoint, and a carrier opened over
/// the node's own path is not one a flow that was told to ride a detour may
/// use. Each path therefore gets its own TUN device and its own default-route
/// metric, which is what stops the two from covering each other.
pub struct MasqueRuntime {
    tunnels: Mutex<std::collections::HashMap<Option<String>, TunnelSlot>>,
}

/// A live tunnel and the device slot it holds.
///
/// The slot is kept so a name and a route metric are never handed out twice
/// while a live tunnel still answers to them.
struct TunnelSlot {
    slot: usize,
    tunnel: Arc<tunnel::MasqueTunnel>,
    /// The front node the carrier was opened over. A group can switch its
    /// member while the tunnel is still alive; the cache must then rebuild
    /// instead of handing every new flow the old front's connection.
    carrier: Option<uuid::Uuid>,
}

impl Default for MasqueRuntime {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for MasqueRuntime {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let established = self.tunnel_count().is_some_and(|count| count != 0);
        formatter
            .debug_struct("MasqueRuntime")
            .field("established", &established)
            .finish()
    }
}

impl MasqueRuntime {
    pub fn new() -> Self {
        Self {
            tunnels: Mutex::new(std::collections::HashMap::new()),
        }
    }

    /// The node's own tunnel, opening it on first use.
    ///
    /// The detour is read from the node's runtime rather than kept here: the
    /// generation binds it in one place, so a carrier can only ever take the
    /// path once.
    pub async fn tunnel(
        &self,
        runtime: &NodeRuntime,
        connect_timeout: Duration,
    ) -> anyhow::Result<Arc<tunnel::MasqueTunnel>> {
        let detour = runtime.detour();
        self.tunnel_for(runtime, connect_timeout, detour.as_deref())
            .await
    }

    /// The tunnel for a path the caller names, which is how a group's detour
    /// reaches a MASQUE member.
    ///
    /// Callers on the same path share one CONNECT. Callers on different paths
    /// get different tunnels, each with its own TUN device and route metric.
    pub async fn tunnel_for(
        &self,
        runtime: &NodeRuntime,
        connect_timeout: Duration,
        detour: Option<&crate::proxy::detour::DetourPath>,
    ) -> anyhow::Result<Arc<tunnel::MasqueTunnel>> {
        let key = detour.map(|path| path.key());
        let carrier = detour.and_then(|path| path.carrier_id());
        let mut guard = self.tunnels.lock().await;
        // Reclaim dead tunnels even when their path is never dialled again:
        // their TUN devices and default routes live in the kernel, not in this
        // map, and would otherwise stay behind until a restart.
        guard.retain(|_, entry| entry.tunnel.is_alive());
        if guard
            .get(&key)
            .is_some_and(|entry| entry.carrier == carrier)
        {
            return Ok(Arc::clone(&guard[&key].tunnel));
        }
        // The carrier died or the front changed: drop the tunnel so its TUN
        // device goes with it, then rebuild over the current path.
        guard.remove(&key);
        // A generation's own tunnel is slot 0 and the detours it carries are the
        // small slots 1, 2, …; those names and route metrics must stay free for
        // the traffic that actually rides them. An ephemeral runtime (a probe or
        // a one-shot dial) owns nothing in the generation, so it takes a slot
        // from a high range that is unique per call — otherwise its TUN device
        // or default route would collide with the generation's and either fail
        // to open or silently steal the generation's route.
        let slot = if runtime.is_ephemeral() {
            let raw = NEXT_EPHEMERAL_MASQUE_SLOT.fetch_add(1, Ordering::Relaxed);
            EPHEMERAL_MASQUE_BASE + (raw % EPHEMERAL_MASQUE_SPAN)
        } else {
            // The lowest slot nobody is holding.
            (0..=guard.len())
                .find(|candidate| !guard.values().any(|entry| entry.slot == *candidate))
                .unwrap_or(guard.len())
        };
        let tunnel = Arc::new(
            carrier::open_tunnel(
                runtime.node.as_ref(),
                connect_timeout,
                detour,
                slot,
                device::masque_tunnel_backend(),
            )
            .await?,
        );
        guard.insert(
            key,
            TunnelSlot {
                slot,
                tunnel: Arc::clone(&tunnel),
                carrier,
            },
        );
        Ok(tunnel)
    }

    /// How many tunnels are up, and `None` while another task is mid-CONNECT.
    pub fn tunnel_count(&self) -> Option<usize> {
        let guard = self.tunnels.try_lock().ok()?;
        Some(
            guard
                .values()
                .filter(|entry| entry.tunnel.is_alive())
                .count(),
        )
    }

    /// Drop the tunnels, deleting their TUN devices.
    pub async fn close(&self) {
        self.tunnels.lock().await.clear();
    }

    /// Reclaim tunnels that this generation no longer uses.
    ///
    /// A tunnel is generation-level state: its carrier was opened over the
    /// detour that generation bound. A reload rebinds detours on *reused*
    /// runtimes, and a node the new config stops dialling keeps its runtime —
    /// so the map can still hold a live tunnel whose path no longer exists.
    /// `tunnel_for` only runs `retain` when a flow asks for the path, which
    /// for such a node never happens again; nothing then drops the tunnel and
    /// its TUN device and default route stay in the kernel until a restart.
    ///
    /// Each dial clones the tunnel's Arc into the flow's I/O owner (see
    /// `RuntimeOwnedIo` in the dial paths), so a live flow keeps the count
    /// above one and is left alone.
    pub async fn prune_idle(&self) {
        let mut guard = self.tunnels.lock().await;
        guard.retain(|_, entry| {
            keep_tunnel(entry.tunnel.is_alive(), Arc::strong_count(&entry.tunnel))
        });
    }
}

/// Whether a cached tunnel is still worth keeping. Kept separate from the
/// lock so the ownership rule can be checked without a real TUN device (which
/// needs root and is therefore out of reach of unit tests).
fn keep_tunnel(is_alive: bool, owners: usize) -> bool {
    is_alive && owners > 1
}

/// Resolve the node's MASQUE runtime, so both dial paths share one message
/// when a node is dispatched without its generation.
fn masque_runtime(runtime: &NodeRuntime) -> anyhow::Result<&MasqueRuntime> {
    match &runtime.runtime {
        ProtocolRuntime::Masque(runtime) => Ok(runtime),
        _ => anyhow::bail!(
            "masque node {} has no masque runtime; it cannot be dialled without its generation",
            runtime.node.name
        ),
    }
}

#[async_trait]
impl TcpOutbound for MasqueHandler {
    async fn dial(
        &self,
        node: &Node,
        target: SocketAddr,
        _target_domain: Option<&str>,
        _connect_timeout: Duration,
    ) -> anyhow::Result<ProxyStream> {
        anyhow::bail!(
            "masque node {} needs a generation runtime to own its tunnel; target {target} not dialled",
            node.name
        )
    }

    /// TCP through the tunnel: the backend decides how. The kernel backend
    /// binds a real socket to the TUN device; the userspace backend opens the
    /// connection inside smoltcp. Both return the same stream, so this stays
    /// backend-agnostic.
    async fn dial_runtime(
        &self,
        runtime: Arc<NodeRuntime>,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: Duration,
    ) -> anyhow::Result<ProxyStream> {
        let masque = masque_runtime(runtime.as_ref())?;
        let tunnel = masque.tunnel(runtime.as_ref(), connect_timeout).await?;
        let stream = tunnel.dial(target, connect_timeout).await.map_err(|error| {
            anyhow::anyhow!(
                "masque node {} cannot reach {target} through {}: {error}",
                runtime.node.name,
                tunnel.label()
            )
        })?;
        crate::runtime::flow_observation::milestone(
            crate::runtime::flow_observation::Milestone::TransportReady,
        );
        // The flow owns a reference to the tunnel: while its socket rides the
        // tunnel (a bound kernel socket or a smoltcp flow), pruning must not
        // pull the device out from under it. Once the flow ends, the map is
        // the only owner again.
        Ok(ProxyStream {
            stream: Box::new(RuntimeOwnedIo::new(stream, Arc::clone(&tunnel))),
            target_addr: target,
            target_domain: target_domain.map(str::to_string),
        })
    }

    /// The same dial over a detour the caller names.
    ///
    /// The tunnel *is* the path — its carrier is the one connection to the
    /// endpoint that every flow on the node shares — so a flow that was told
    /// to ride a detour cannot use the tunnel that was opened over the
    /// node's own path. It gets the tunnel for *this* path, which the node
    /// opens on its own device if it does not have one yet.
    async fn dial_runtime_detoured(
        &self,
        runtime: Arc<NodeRuntime>,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: Duration,
        detour: &Arc<crate::proxy::detour::DetourPath>,
    ) -> anyhow::Result<ProxyStream> {
        let masque = masque_runtime(runtime.as_ref())?;
        let tunnel = masque
            .tunnel_for(runtime.as_ref(), connect_timeout, Some(detour.as_ref()))
            .await?;
        let stream = tunnel.dial(target, connect_timeout).await.map_err(|error| {
            anyhow::anyhow!(
                "masque node {} cannot reach {target} through {}: {error}",
                runtime.node.name,
                tunnel.label()
            )
        })?;
        crate::runtime::flow_observation::milestone(
            crate::runtime::flow_observation::Milestone::TransportReady,
        );
        // The flow owns a reference to the tunnel: while its socket rides the
        // tunnel (a bound kernel socket or a smoltcp flow), pruning must not
        // pull the device out from under it. Once the flow ends, the map is
        // the only owner again.
        Ok(ProxyStream {
            stream: Box::new(RuntimeOwnedIo::new(stream, Arc::clone(&tunnel))),
            target_addr: target,
            target_domain: target_domain.map(str::to_string),
        })
    }
}

impl MasqueHandler {
    /// Bind a UDP socket to the tunnel carrying this flow's path, and keep the
    /// tunnel alive as long as the socket exists. `prune_idle()` reclaims a
    /// tunnel nobody holds, so the socket itself has to count as a holder —
    /// otherwise the TUN device disappears from under a live UDP flow.
    async fn dial_udp_via_tunnel(
        &self,
        runtime: Arc<NodeRuntime>,
        target: SocketAddr,
        connect_timeout: Duration,
        detour: Option<&crate::proxy::detour::DetourPath>,
    ) -> anyhow::Result<Arc<dyn PacketTransport>> {
        let masque = masque_runtime(runtime.as_ref())?;
        let tunnel = match detour {
            Some(detour) => {
                masque
                    .tunnel_for(runtime.as_ref(), connect_timeout, Some(detour))
                    .await?
            }
            None => masque.tunnel(runtime.as_ref(), connect_timeout).await?,
        };
        let transport = tunnel
            .dial_udp(target, connect_timeout)
            .await
            .map_err(|error| {
                anyhow::anyhow!(
                    "masque node {} cannot reach UDP {target} through {}: {error}",
                    runtime.node.name,
                    tunnel.label()
                )
            })?;
        Ok(crate::proxy::packet_transport_with_owner(
            transport,
            Arc::clone(&tunnel),
        ))
    }
}

#[async_trait]
impl PacketOutbound for MasqueHandler {
    async fn dial_udp_transport(
        &self,
        node: &Node,
        target: SocketAddr,
        _target_domain: Option<&str>,
        _connect_timeout: Duration,
    ) -> anyhow::Result<Arc<dyn PacketTransport>> {
        anyhow::bail!(
            "masque node {} needs a generation runtime to own its tunnel; UDP {target} not dialled",
            node.name
        )
    }

    async fn dial_udp_transport_runtime(
        &self,
        runtime: Arc<NodeRuntime>,
        target: SocketAddr,
        _target_domain: Option<&str>,
        connect_timeout: Duration,
    ) -> anyhow::Result<Arc<dyn PacketTransport>> {
        self.dial_udp_via_tunnel(runtime, target, connect_timeout, None)
            .await
    }

    async fn dial_udp_transport_runtime_detoured(
        &self,
        runtime: Arc<NodeRuntime>,
        target: SocketAddr,
        _target_domain: Option<&str>,
        connect_timeout: Duration,
        detour: &Arc<crate::proxy::detour::DetourPath>,
    ) -> anyhow::Result<Arc<dyn PacketTransport>> {
        // The tunnel *is* the path for MASQUE: every flow on a node shares one
        // carrier, so a detoured flow cannot join the generation's own tunnel.
        self.dial_udp_via_tunnel(runtime, target, connect_timeout, Some(detour.as_ref()))
            .await
    }
}

#[async_trait]
impl WarmableOutbound for MasqueHandler {
    /// Establish the tunnel ahead of the first flow. UDP needs nothing extra:
    /// whichever backend owns the packet device owns UDP too.
    async fn warm(
        &self,
        runtime: Arc<NodeRuntime>,
        connect_timeout: Duration,
        _requirement: WarmRequirement,
    ) -> anyhow::Result<()> {
        let masque = masque_runtime(runtime.as_ref())?;
        masque.tunnel(runtime.as_ref(), connect_timeout).await?;
        Ok(())
    }
}

impl ProbeableOutbound for MasqueHandler {}

#[cfg(test)]
mod tests {
    use super::*;

    /// A tunnel nobody holds is the leak: it has a live carrier, so the old
    /// `retain(is_alive)` would have kept it forever. A flow's owner clone is
    /// what separates it from a tunnel that is merely cached.
    #[test]
    fn only_a_held_and_live_tunnel_survives_pruning() {
        assert!(keep_tunnel(true, 2), "a flow is holding this tunnel");
        assert!(
            !keep_tunnel(true, 1),
            "an idle tunnel with a live carrier is exactly what leaked"
        );
        assert!(!keep_tunnel(false, 2), "a dead carrier is never reusable");
        assert!(!keep_tunnel(false, 1));
    }

    #[tokio::test]
    async fn pruning_an_empty_runtime_is_a_no_op() {
        let runtime = MasqueRuntime::new();
        runtime.prune_idle().await;
        assert_eq!(runtime.tunnel_count(), Some(0));
    }
}
