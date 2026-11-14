//! Carrier setup: how a MASQUE node's IP tunnel reaches its endpoint.
//!
//! `network: h2`    -> TCP + WARP TLS + HTTP/2 CONNECT-IP.
//! `network: quic`  -> QUIC + WARP TLS + HTTP/3 CONNECT-IP. WARP's H3 shape
//!                     is not RFC 9484: it uses `:protocol = cf-connect-ip`
//!                     and QUIC DATAGRAMs rather than DATAGRAM capsules. See
//!                     [`super::http3`].

use honk_config::node::Node;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use super::device::TunnelBackend;
use super::http3;
use super::tunnel::MasqueTunnel;
use super::warp::WarpIdentity;
use crate::proxy::AsyncReadWrite;
use crate::proxy::detour::DetourPath;

/// Default tunnel MTU. IPv6 requires >= 1280 and every MASQUE endpoint we
/// know advertises WARP-sized packets, so 1280 is the safe floor.
pub const DEFAULT_MTU: u32 = 1280;

/// Open the node's IP tunnel over its configured carrier.
///
/// `detour` carries the connection to the endpoint through another node when
/// the node names one; the generation supplies it, since only it can reach
/// that node's runtime.
pub async fn open_tunnel(
    node: &Node,
    connect_timeout: Duration,
    detour: Option<&DetourPath>,
    slot: usize,
    backend: TunnelBackend,
) -> anyhow::Result<MasqueTunnel> {
    let config = node
        .masque()
        .ok_or_else(|| anyhow::anyhow!("masque node {} has no masque config", node.name))?;
    // `MasqueConfig::network()` has already collapsed `h3`/`http3`/`quic`
    // into one value and defaults an absent setting to `h2`.
    match config.network() {
        "h2" => open_h2(node, connect_timeout, detour, slot, backend).await,
        "quic" => open_quic(node, connect_timeout, detour, slot, backend).await,
        other => anyhow::bail!("masque node {}: unsupported network {other:?}", node.name),
    }
}

/// QUIC + WARP TLS + HTTP/3 CONNECT-IP.
///
/// A detour supplies a TCP stream, but QUIC needs a UDP socket, so a detoured
/// h3 node cannot reuse the h2 detour path. Reject it explicitly rather than
/// silently dialling direct and bypassing the front node.
async fn open_quic(
    node: &Node,
    connect_timeout: Duration,
    detour: Option<&DetourPath>,
    slot: usize,
    backend: TunnelBackend,
) -> anyhow::Result<MasqueTunnel> {
    if detour.is_some() {
        anyhow::bail!(
            "masque node {}: `network: quic` does not support a detour yet; \
             use `network: h2` for detoured MASQUE nodes",
            node.name
        );
    }
    if let Some(name) = node.detour_name() {
        anyhow::bail!(
            "masque node {}: `network: quic` does not support detour {name:?} yet; \
             use `network: h2` for detoured MASQUE nodes",
            node.name
        );
    }
    let config = node
        .masque()
        .ok_or_else(|| anyhow::anyhow!("masque node {} has no masque config", node.name))?;
    let address = endpoint_address(node);
    let endpoint = resolve_endpoint(&address).await?;
    let mtu = config.mtu.map(u32::from).unwrap_or(DEFAULT_MTU);
    let tun_name = tun_name(node, slot);
    let preferred = tunnel_addresses(node);
    tracing::debug!(
        "masque: opening connect-ip tunnel to {address} via h3 on {tun_name} \
         (mtu {mtu}, addresses {preferred:?})"
    );
    http3::open_h3(
        node,
        endpoint,
        connect_timeout,
        mtu,
        &tun_name,
        &preferred,
        slot,
        backend,
    )
    .await
}

/// TCP + WARP TLS + HTTP/2 CONNECT-IP.
async fn open_h2(
    node: &Node,
    connect_timeout: Duration,
    detour: Option<&DetourPath>,
    slot: usize,
    backend: TunnelBackend,
) -> anyhow::Result<MasqueTunnel> {
    let config = node
        .masque()
        .ok_or_else(|| anyhow::anyhow!("masque node {} has no masque config", node.name))?;
    let address = endpoint_address(node);
    // The caller's detour wins over the node's, and it counts even when the
    // node names none. Matching `(None, _)` here used to dial direct, which
    // quietly dropped a detour a group had asked for — the one outcome this
    // is meant to make impossible.
    let tcp = match detour {
        Some(dialer) => {
            let endpoint = resolve_endpoint(&address).await?;
            dialer
                .connect(endpoint, connect_timeout)
                .await
                .map_err(|error| {
                    anyhow::anyhow!(
                        "masque node {}: detour could not reach {address}: {error}",
                        node.name
                    )
                })?
        }
        None => match node.detour_name() {
            Some(name) => anyhow::bail!(
                "masque node {}: detour {name:?} is not bound in this generation",
                node.name
            ),
            None => Box::new(crate::util::connect_outbound(&address, connect_timeout).await?)
                as Box<dyn AsyncReadWrite>,
        },
    };
    let identity = WarpIdentity::build(node)?;
    let tls = identity.connect(tcp, connect_timeout).await?;
    tracing::debug!(
        "masque: TLS to {address} established (sni {})",
        identity.sni()
    );
    let io = crate::tls::BatchRead::new(tls);

    let mtu = config.mtu.map(u32::from).unwrap_or(DEFAULT_MTU);
    let tun_name = tun_name(node, slot);
    let preferred = tunnel_addresses(node);
    tracing::debug!(
        "masque: opening connect-ip tunnel to {address} via h2 on {tun_name} \
         (mtu {mtu}, addresses {preferred:?})"
    );
    MasqueTunnel::open_h2(io, mtu, &tun_name, &preferred, slot, backend).await
}

/// Resolve the endpoint literal to an address a detour can dial.
///
/// Server hostnames resolve through the bootstrap resolver, the same path
/// direct server dials take; libc NSS resolution is deliberately not used.
async fn resolve_endpoint(address: &str) -> anyhow::Result<SocketAddr> {
    let (host, port) = address
        .rsplit_once(':')
        .ok_or_else(|| anyhow::anyhow!("masque endpoint {address} is not a host:port pair"))?;
    let port: u16 = port
        .parse()
        .map_err(|_| anyhow::anyhow!("masque endpoint {address} has a bad port"))?;
    let resolution = Box::pin(crate::bootstrap::resolve(host));
    let ip = resolution
        .await?
        .into_iter()
        .next()
        .ok_or_else(|| anyhow::anyhow!("masque endpoint {address} resolved to nothing"))?;
    Ok(SocketAddr::new(ip, port))
}

/// The node's `host:port`, bracketed when the endpoint is an IPv6 literal.
fn endpoint_address(node: &Node) -> String {
    let host = node.host();
    if host.contains(':') {
        format!("[{host}]:{}", node.port)
    } else {
        format!("{host}:{}", node.port)
    }
}

/// The addresses the node expects the tunnel to carry, from its `ip` and
/// `ipv6` settings. Both may carry a CIDR suffix (`172.16.0.2/32`), which is
/// what subscriptions emit; only the address part is needed here because the
/// TUN gets a host route.
fn tunnel_addresses(node: &Node) -> Vec<IpAddr> {
    let config = match node.masque() {
        Some(config) => config,
        None => return Vec::new(),
    };
    [&config.local_ipv4, &config.local_ipv6]
        .iter()
        .filter_map(|value| value.as_deref())
        .filter_map(|value| value.split('/').next())
        .filter_map(|value| value.parse().ok())
        .collect()
}

/// Interface name for one of a node's TUN devices. `IFNAMSIZ` is 16
/// including the terminator, so the suffix is trimmed to fit.
///
/// A node carries one device per path, not one device in total: the tunnel
/// over its own path and the one a group asked for are different carriers to
/// the same endpoint, and each needs a device of its own. Slot 0 keeps the
/// name the node has always had, so a node with a single path is unchanged.
fn tun_name(node: &Node, slot: usize) -> String {
    let suffix = node.id.as_u128() & 0xffff;
    match slot {
        0 => format!("masq{suffix:04x}"),
        other => format!("masq{suffix:04x}{other}"),
    }
}
