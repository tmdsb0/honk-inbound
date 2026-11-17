//! Wiring a node's detour to the node or group it names.
//!
//! A server the direct path out cannot reach is often reachable from another
//! node, so a node may name one — or a group, whose current member carries it.
//! Turning that name into a dial needs the node set, the groups and the proxy
//! registry, none of which the outbound layer owns, so the binding happens
//! here — once per generation, at startup and on every reload.

use honk_config::group::Group;
use honk_config::node::Node;
use honk_config::types::NodeProtocol;
use honk_outbound::group::GroupManager;
use honk_outbound::proxy::ProxyRegistry;
use honk_outbound::proxy::detour::DetourPath;
use honk_outbound::runtime::OutboundRuntimeRegistry;
use std::sync::Arc;

/// Bind every node that names a detour to the path it names.
///
/// A node-level detour is bound once here and read from `NodeRuntime::detour()`.
/// A **group-level** detour is different: it is built fresh on each dial by
/// [`group_detour`] and passed to the protocol handler, and when present it
/// **wins over** the node's own `dialer-proxy` (the dial path returns early).
/// Both eventually feed the same `DetourPath` resolution, but they are two
/// mechanisms with that precedence, not one binding read twice.
///
/// Unknown names, and a MASQUE node whose detour is another MASQUE node, are
/// reported and skipped rather than failing the generation: one unreachable
/// node should not take down the rest.
///
/// The name may be a node or a group. A group is resolved on each dial, so the
/// front follows the group's current choice instead of whichever node happened
/// to be selected when the generation was built.
///
/// This runs again on every reload. A node whose own config did not change
/// reuses its runtime, so rebinding (and clearing a binding the new config no
/// longer names) is what makes a switched front take effect without a restart.
pub(crate) fn bind_node_detours(
    registry: &Arc<OutboundRuntimeRegistry>,
    nodes: &[Node],
    proxies: &Arc<ProxyRegistry>,
    groups: &[Group],
    manager: &Arc<GroupManager>,
) {
    tracing::info!(
        nodes = nodes.len(),
        groups = groups.len(),
        "binding node detours"
    );
    for node in nodes {
        let Some(name) = node.detour_name() else {
            registry.clear_detour(node.id);
            continue;
        };
        let path = match (
            nodes.iter().find(|candidate| candidate.name == name),
            groups.iter().find(|group| group.name == name),
        ) {
            (Some(target), _) => {
                if node.protocol() == NodeProtocol::Masque
                    && target.protocol() == NodeProtocol::Masque
                {
                    tracing::warn!(
                        "masque node {}: detour {name:?} is itself a MASQUE node, which would \
                         nest tunnels; ignored",
                        node.name
                    );
                    registry.clear_detour(node.id);
                    continue;
                }
                tracing::info!(node = %node.name, detour = %name, "detour bound to node");
                DetourPath::new(Arc::clone(proxies), Arc::clone(registry), target.id)
            }
            (None, Some(_)) => {
                tracing::info!(node = %node.name, detour = %name, "detour bound to group");
                DetourPath::to_group(
                    Arc::clone(proxies),
                    Arc::clone(registry),
                    name,
                    Arc::clone(manager),
                    node.protocol(),
                )
            }
            (None, None) => {
                tracing::warn!(
                    "node {}: detour {name:?} is neither a node nor a group in this \
                     configuration",
                    node.name
                );
                registry.clear_detour(node.id);
                continue;
            }
        };
        if !registry.bind_detour(node.id, Arc::new(path)) {
            tracing::warn!(
                "node {}: detour {name:?} could not be bound to its runtime (id {})",
                node.name,
                node.id
            );
        }
    }
}

/// The detour that applies to a group, following the nested groups it draws
/// its members from.
///
/// `filter: group(X)` is a reference edge, not a copied node list: the group
/// borrows X's current selection. It is meant to borrow the way that selection
/// leaves the machine too, so a group naming no detour of its own inherits the
/// first one found in a breadth-first walk of its upstream groups, in
/// declaration order. An explicit `detour:`, including `direct`, wins and
/// stops the walk. `visited` makes a
/// cycle in the group graph harmless — the graph itself is only checked when
/// the outbound registry is built, which is later than a flow's lookup.
fn effective_group_detour<'a>(
    config: &'a honk_config::Config,
    group_name: &str,
) -> Option<&'a str> {
    let start = config
        .groups
        .iter()
        .find(|group| group.name == group_name)?;
    if let Some(detour) = start.detour.as_deref() {
        return Some(detour);
    }
    let mut visited = vec![start.name.as_str()];
    let mut pending: std::collections::VecDeque<_> =
        start.groups.iter().map(String::as_str).collect();
    while let Some(name) = pending.pop_front() {
        if visited.contains(&name) {
            continue;
        }
        visited.push(name);
        let Some(group) = config.groups.iter().find(|group| group.name == name) else {
            continue;
        };
        if let Some(detour) = group.detour.as_deref() {
            return Some(detour);
        }
        pending.extend(group.groups.iter().map(String::as_str));
    }
    None
}

/// The path a group asks its members to leave through, when one applies.
///
/// A group resolves to a node only once a flow arrives, so its detour cannot
/// be bound to that node the way a node's own is: which member carries the
/// flow is decided per flow, and the name is resolved here and handed to the
/// dial that needs it. A group that names no detour of its own inherits one
/// from the nested groups it draws its members from — see the
/// `effective_group_detour` helper below.
///
/// `None` means no detour applies — not that a named one is broken.
/// A name that resolves to nothing leaves the flow on the node's own path
/// rather than failing it, because the configuration was rejected at load
/// before it could reach this point.
pub(crate) fn group_detour(
    config: &honk_config::Config,
    proxies: &Arc<ProxyRegistry>,
    generation: &Arc<OutboundRuntimeRegistry>,
    manager: &Arc<GroupManager>,
    group_name: &str,
    rider: NodeProtocol,
) -> Option<Arc<DetourPath>> {
    let name = effective_group_detour(config, group_name)?;
    if matches!(name, honk_config::Config::BUILTIN_DIRECT_NODE) {
        let node = config.builtin_node(name)?;
        return Some(Arc::new(DetourPath::new(
            Arc::clone(proxies),
            Arc::clone(generation),
            node.id,
        )));
    }
    if let Some(node) = config.nodes.iter().find(|node| node.name == name) {
        return Some(Arc::new(DetourPath::new(
            Arc::clone(proxies),
            Arc::clone(generation),
            node.id,
        )));
    }
    if config.groups.iter().any(|group| group.name == name) {
        return Some(Arc::new(DetourPath::to_group(
            Arc::clone(proxies),
            Arc::clone(generation),
            name,
            Arc::clone(manager),
            rider,
        )));
    }
    None
}

/// Resolve the detour for one dial, trying the routing group first and the
/// selection chain's owning group second.
///
/// When a candidate came through a group's `final:` fallback the routing group
/// (e.g. `Final`) names no `detour:` of its own and is not linked to the
/// fallback group by a member edge, so looking the detour up by that name
/// returns nothing. The chain records the real owning group as its
/// second-to-last element; falling back to it keeps the front — and anything
/// it inherits — applied to the dial. TCP and UDP dials used to spell this
/// `.or_else` out independently.
pub(crate) fn group_detour_for_chain(
    config: &honk_config::Config,
    proxies: &Arc<ProxyRegistry>,
    generation: &Arc<OutboundRuntimeRegistry>,
    manager: &Arc<GroupManager>,
    group_name: &str,
    owning_group: Option<&str>,
    rider: NodeProtocol,
) -> Option<Arc<DetourPath>> {
    group_detour(config, proxies, generation, manager, group_name, rider).or_else(|| {
        owning_group.and_then(|via| group_detour(config, proxies, generation, manager, via, rider))
    })
}

#[cfg(test)]
mod tests {
    //! Chain verification over loopback.
    //!
    //! A SOCKS5 relay stands in for the front hop, a Trojan relay for the
    //! chained node's own server, and an echo server for the far side. Each
    //! relay records every target it is asked to reach, so a test can name the
    //! hop that carried a leg instead of only that bytes arrived: a node on a
    //! detour shows up as a request at the front for the chained node's own
    //! server, and never at that server directly.
    //!
    //! The chained node is deliberately Trojan and not SOCKS5. Only the
    //! protocols that dial through the shared transport consult the detour, so
    //! a test built on one that does not would pass whatever the chain did.

    use super::*;
    use honk_config::node::{OutboundConfig, TrojanConfig};
    use honk_config::types::{NodeProtocol, SubscriptionType};
    use honk_outbound::group::GroupManager;
    use honk_outbound::proxy::ProtocolEntry;
    use honk_outbound::proxy::socks5::Socks5Handler;
    use honk_outbound::proxy::trojan::TrojanHandler;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::Mutex;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    const TIMEOUT: Duration = Duration::from_secs(5);
    const PASSWORD: &str = "chain-secret";

    /// A relay that records every target it is asked to reach.
    struct Relay {
        address: SocketAddr,
        requested: Arc<Mutex<Vec<SocketAddr>>>,
    }

    impl Relay {
        fn targets(&self) -> Vec<SocketAddr> {
            self.requested.lock().unwrap().clone()
        }
    }

    async fn spawn_relay(trojan: bool) -> Relay {
        let requested = Arc::new(Mutex::new(Vec::new()));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let sink = Arc::clone(&requested);
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let sink = Arc::clone(&sink);
                tokio::spawn(async move {
                    let served = if trojan {
                        serve_trojan(&mut stream, &sink).await
                    } else {
                        serve_socks5(&mut stream, &sink).await
                    };
                    let _ = served;
                });
            }
        });
        Relay { address, requested }
    }

    async fn serve_socks5(
        stream: &mut TcpStream,
        sink: &Mutex<Vec<SocketAddr>>,
    ) -> anyhow::Result<()> {
        let mut greeting = [0_u8; 2];
        stream.read_exact(&mut greeting).await?;
        let mut methods = vec![0_u8; greeting[1] as usize];
        stream.read_exact(&mut methods).await?;
        stream.write_all(&[0x05, 0x00]).await?;

        let mut head = [0_u8; 4];
        stream.read_exact(&mut head).await?;
        if head[1] != 0x01 {
            anyhow::bail!("only CONNECT is supported");
        }
        let target = read_address(stream, head[3]).await?;
        sink.lock().unwrap().push(target);
        // Success, bound to an unspecified address: the client reads the reply
        // and starts sending, so the bound fields are not consulted.
        stream
            .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await?;
        relay_to(stream, target).await
    }

    /// Serve one Trojan connection: `hex(sha224(password)) CRLF cmd addr CRLF`
    /// and then the payload. The password is not checked, because which hop
    /// carried the leg is what is under test here, not authentication.
    async fn serve_trojan(
        stream: &mut TcpStream,
        sink: &Mutex<Vec<SocketAddr>>,
    ) -> anyhow::Result<()> {
        let mut hash = [0_u8; 56];
        stream.read_exact(&mut hash).await?;
        let mut crlf = [0_u8; 2];
        stream.read_exact(&mut crlf).await?;
        let mut command = [0_u8; 1];
        stream.read_exact(&mut command).await?;
        let mut address_type = [0_u8; 1];
        stream.read_exact(&mut address_type).await?;
        let target = read_address(stream, address_type[0]).await?;
        stream.read_exact(&mut crlf).await?;
        sink.lock().unwrap().push(target);
        relay_to(stream, target).await
    }

    /// The SOCKS5-style address both hops write: a type byte, the host, a port.
    async fn read_address(stream: &mut TcpStream, address_type: u8) -> anyhow::Result<SocketAddr> {
        let port = |bytes: [u8; 2]| u16::from_be_bytes(bytes);
        match address_type {
            0x01 => {
                let mut rest = [0_u8; 6];
                stream.read_exact(&mut rest).await?;
                Ok(SocketAddr::new(
                    IpAddr::V4(Ipv4Addr::new(rest[0], rest[1], rest[2], rest[3])),
                    port([rest[4], rest[5]]),
                ))
            }
            0x04 => {
                let mut rest = [0_u8; 18];
                stream.read_exact(&mut rest).await?;
                let mut octets = [0_u8; 16];
                octets.copy_from_slice(&rest[..16]);
                Ok(SocketAddr::new(
                    IpAddr::V6(std::net::Ipv6Addr::from(octets)),
                    port([rest[16], rest[17]]),
                ))
            }
            0x03 => {
                let mut length = [0_u8; 1];
                stream.read_exact(&mut length).await?;
                let mut host = vec![0_u8; length[0] as usize];
                stream.read_exact(&mut host).await?;
                let mut bytes = [0_u8; 2];
                stream.read_exact(&mut bytes).await?;
                let name = String::from_utf8_lossy(&host).into_owned();
                let address = tokio::net::lookup_host((name.as_str(), port(bytes)))
                    .await?
                    .next();
                address.ok_or_else(|| anyhow::anyhow!("{name} resolved to nothing"))
            }
            other => anyhow::bail!("unknown address type {other}"),
        }
    }

    async fn relay_to(stream: &mut TcpStream, target: SocketAddr) -> anyhow::Result<()> {
        let mut upstream = TcpStream::connect(target).await?;
        tokio::io::copy_bidirectional(stream, &mut upstream).await?;
        Ok(())
    }

    /// The far side: whatever it is sent comes straight back.
    async fn spawn_echo() -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let (mut reader, mut writer) = stream.split();
                    let _ = tokio::io::copy(&mut reader, &mut writer).await;
                });
            }
        });
        address
    }

    fn node_named(name: &str, server: SocketAddr, outbound: OutboundConfig) -> Node {
        let mut node = Node {
            name: name.to_owned(),
            address: server.to_string(),
            host: server.ip().to_string(),
            port: server.port(),
            outbound,
            ..Default::default()
        };
        node.id = node.derive_id();
        node
    }

    fn socks5_node(name: &str, server: SocketAddr) -> Node {
        node_named(
            name,
            server,
            OutboundConfig::from_protocol(NodeProtocol::Socks5),
        )
    }

    fn trojan_node(name: &str, server: SocketAddr) -> Node {
        node_named(
            name,
            server,
            OutboundConfig::Trojan(TrojanConfig {
                password: Some(PASSWORD.into()),
                ..Default::default()
            }),
        )
    }

    /// A generation that can dial either hop, with detours bound the way the
    /// control plane binds them. The group manager is what lets a detour name a
    /// group, so it is built from the same node set the runtimes are.
    fn registries(
        nodes: &[Node],
        groups: &[honk_config::group::Group],
    ) -> (Arc<OutboundRuntimeRegistry>, Arc<ProxyRegistry>) {
        let (registry, _) = OutboundRuntimeRegistry::build_reusing(nodes, 4, None).unwrap();
        let mut proxies = ProxyRegistry::new();
        proxies.register(ProtocolEntry::new(
            NodeProtocol::Socks5,
            Arc::new(Socks5Handler::new()),
        ));
        proxies.register(ProtocolEntry::new(
            NodeProtocol::Trojan,
            Arc::new(TrojanHandler::new()),
        ));
        let registry = Arc::new(registry);
        let proxies = Arc::new(proxies);
        let manager = Arc::new(GroupManager::new(groups, nodes));
        bind_node_detours(&registry, nodes, &proxies, groups, &manager);
        (registry, proxies)
    }

    /// Send a sentinel and require it back, so a stream that was accepted but
    /// carries nothing does not count as a working chain.
    async fn say_ping(stream: &mut Box<dyn honk_outbound::proxy::AsyncReadWrite>) {
        stream.write_all(b"ping").await.unwrap();
        let mut reply = [0_u8; 4];
        stream.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply, b"ping", "the bytes must travel every hop");
    }

    /// The chain, end to end: the front is asked for the chained node's own
    /// server, and the far side is only ever asked of the chained node.
    #[tokio::test]
    async fn a_chained_node_reaches_its_server_through_the_front() {
        let front = spawn_relay(false).await;
        let back = spawn_relay(true).await;
        let echo = spawn_echo().await;

        let front_node = socks5_node("front", front.address);
        let mut back_node = trojan_node("back", back.address);
        back_node.detour = Some("front".into());
        back_node.id = back_node.derive_id();

        let nodes = [front_node, back_node.clone()];
        let (registry, proxies) = registries(&nodes, &[]);

        let mut stream = proxies
            .dial_runtime(Arc::clone(&registry), back_node.id, echo, None, TIMEOUT)
            .await
            .expect("a chained node must dial through its front")
            .stream;
        say_ping(&mut stream).await;

        assert_eq!(
            front.targets(),
            vec![back.address],
            "the front must be asked to reach the chained node's own server"
        );
        assert_eq!(
            back.targets(),
            vec![echo],
            "the chained node must be asked for the far side"
        );
    }

    /// The control: an identical node that names no detour leaves on its own
    /// path, and the front that carries nothing sees nothing.
    #[tokio::test]
    async fn a_node_without_a_detour_never_touches_the_front() {
        let front = spawn_relay(false).await;
        let solo = spawn_relay(true).await;
        let echo = spawn_echo().await;

        let front_node = socks5_node("front", front.address);
        let solo_node = trojan_node("solo", solo.address);
        let nodes = [front_node, solo_node.clone()];
        let (registry, proxies) = registries(&nodes, &[]);

        let mut stream = proxies
            .dial_runtime(Arc::clone(&registry), solo_node.id, echo, None, TIMEOUT)
            .await
            .expect("a node on its own path must dial")
            .stream;
        say_ping(&mut stream).await;

        assert_eq!(
            solo.targets(),
            vec![echo],
            "the node must reach the far side itself"
        );
        assert!(
            front.targets().is_empty(),
            "a node it does not carry must never appear at the front"
        );
    }

    /// The chain is mandatory. A front that cannot be dialled fails the node
    /// rather than letting it leave through the real interface, which would
    /// look exactly like an ordinary connection.
    #[tokio::test]
    async fn a_chained_node_fails_when_its_front_is_unreachable() {
        let closed = {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            listener.local_addr().unwrap()
        };
        let back = spawn_relay(true).await;
        let echo = spawn_echo().await;

        let front_node = socks5_node("front", closed);
        let mut back_node = trojan_node("back", back.address);
        back_node.detour = Some("front".into());
        back_node.id = back_node.derive_id();

        let nodes = [front_node, back_node.clone()];
        let (registry, proxies) = registries(&nodes, &[]);

        let error = proxies
            .dial_runtime(Arc::clone(&registry), back_node.id, echo, None, TIMEOUT)
            .await
            .expect_err("a dead front must fail the chained node");
        assert!(
            !format!("{error:#}").is_empty(),
            "a refusal must carry a cause"
        );
        assert!(
            back.targets().is_empty(),
            "the chained node's own server must not be dialled directly"
        );
    }

    /// The subscription path, whole: the body a provider serves is parsed, the
    /// generation binds what it named, and the dial is carried by the node the
    /// subscription pointed at.
    #[tokio::test]
    async fn a_subscription_dialer_proxy_carries_the_node_through_the_front() {
        // Both proxies in the body are SOCKS5, so both relays have to be.
        // A relay speaking the wrong protocol waits for a header that never
        // arrives and the dial fails as a timeout, which names nothing.
        let front = spawn_relay(false).await;
        let back = spawn_relay(false).await;
        let echo = spawn_echo().await;

        let subscription = honk_config::subscription::Subscription {
            name: "chain".into(),
            url: "https://example.test/chain.yaml".into(),
            sub_type: SubscriptionType::Clash,
            ..Default::default()
        };
        // Flow mappings keep the body flat, so no indentation carries a meaning
        // the reader has to work out before the assertions.
        let body = [
            "proxies:".to_string(),
            format!(
                "  - {{name: front, type: socks5, server: {}, port: {}}}",
                front.address.ip(),
                front.address.port()
            ),
            format!(
                "  - {{name: back, type: socks5, server: {}, port: {}, dialer-proxy: front}}",
                back.address.ip(),
                back.address.port()
            ),
            String::new(),
        ]
        .join("\n");

        let nodes = crate::subscription::parse_subscription_content(&subscription, &body)
            .expect("a Clash subscription naming a dialer-proxy must parse");
        let back_node = nodes
            .iter()
            .find(|node| node.name == "back")
            .expect("the chained proxy must import");
        assert_eq!(
            back_node.detour_name(),
            Some("front"),
            "the detour must survive parsing"
        );

        let (registry, proxies) = registries(&nodes, &[]);
        let mut stream = proxies
            .dial_runtime(Arc::clone(&registry), back_node.id, echo, None, TIMEOUT)
            .await
            .expect("the chained node must dial through its front")
            .stream;
        say_ping(&mut stream).await;

        assert_eq!(
            front.targets(),
            vec![back.address],
            "the front named in the subscription must carry the chained node's server"
        );
        assert_eq!(
            back.targets(),
            vec![echo],
            "only the chained node is asked for the far side"
        );
    }

    /// A group names a front as a node does. The bind resolves it on the dial,
    /// so the member the group then carries is the hop that carries the leg:
    /// re-pointing the group moves the chain without a reload, which is the
    /// point of naming a group at all.
    #[tokio::test]
    async fn a_node_detoured_through_a_group_is_carried_by_its_member() {
        let front = spawn_relay(false).await;
        let spare = spawn_relay(false).await;
        let back = spawn_relay(true).await;
        let echo = spawn_echo().await;

        let front_node = socks5_node("front", front.address);
        let spare_node = socks5_node("spare", spare.address);
        let mut back_node = trojan_node("back", back.address);
        back_node.detour = Some("fronts".into());
        back_node.id = back_node.derive_id();

        let groups = [honk_config::group::Group {
            name: "fronts".into(),
            policy: honk_config::group::GroupPolicy::Selector,
            nodes: vec![front_node.id],
            ..Default::default()
        }];
        let nodes = [front_node, spare_node, back_node.clone()];
        let (registry, proxies) = registries(&nodes, &groups);

        let mut stream = proxies
            .dial_runtime(Arc::clone(&registry), back_node.id, echo, None, TIMEOUT)
            .await
            .expect("a group detour must dial through the group's member")
            .stream;
        say_ping(&mut stream).await;

        assert_eq!(
            front.targets(),
            vec![back.address],
            "the group's member must carry the chained node's server"
        );
        assert!(
            spare.targets().is_empty(),
            "a node the group does not contain must not be touched"
        );
        assert_eq!(
            back.targets(),
            vec![echo],
            "the far side is the back node's"
        );
    }

    /// The chain is mandatory whatever it names. A group that can produce no
    /// node fails the dial rather than letting the traffic leave on its own
    /// path, which would look like an ordinary connection.
    #[tokio::test]
    async fn a_group_with_nothing_to_select_fails_the_dial() {
        let back = spawn_relay(true).await;
        let echo = spawn_echo().await;

        let mut back_node = trojan_node("back", back.address);
        back_node.detour = Some("empty".into());
        back_node.id = back_node.derive_id();

        let groups = [honk_config::group::Group {
            name: "empty".into(),
            policy: honk_config::group::GroupPolicy::Selector,
            ..Default::default()
        }];
        let nodes = [back_node.clone()];
        let (registry, proxies) = registries(&nodes, &groups);

        proxies
            .dial_runtime(Arc::clone(&registry), back_node.id, echo, None, TIMEOUT)
            .await
            .expect_err("a group with no member must fail the chained node");
        assert!(
            back.targets().is_empty(),
            "the chained node must not reach its own server directly"
        );
    }

    fn group_named(name: &str, detour: Option<&str>) -> honk_config::Config {
        let mut config = honk_config::Config::default();
        config
            .nodes
            .push(socks5_node("front", "127.0.0.1:1".parse().unwrap()));
        config.groups.push(honk_config::group::Group {
            name: name.into(),
            policy: honk_config::group::GroupPolicy::Selector,
            detour: detour.map(str::to_string),
            ..Default::default()
        });
        config
    }

    fn detour_of_group(config: &honk_config::Config, group: &str) -> Option<Arc<DetourPath>> {
        let (generation, _) =
            OutboundRuntimeRegistry::build_reusing(&config.nodes, 4, None).unwrap();
        let manager = Arc::new(GroupManager::new(&config.groups, &config.nodes));
        group_detour(
            config,
            &Arc::new(ProxyRegistry::new()),
            &Arc::new(generation),
            &manager,
            group,
            NodeProtocol::Trojan,
        )
    }

    /// A group's detour names a node the same way a node's does, and resolves
    /// to it for the flow that came through the group.
    #[test]
    fn a_group_detour_naming_a_node_resolves_to_that_node() {
        let config = group_named("wallet", Some("front"));
        let front_id = config.nodes[0].id;
        let path = detour_of_group(&config, "wallet").expect("a node name must resolve");
        assert!(
            format!("{path:?}").contains(&front_id.to_string()),
            "the path must name the node the group pointed at: {path:?}"
        );
    }

    /// `direct` is a node like any other, so a group may name it.
    #[test]
    fn a_group_detour_may_name_direct() {
        let config = group_named("wallet", Some("direct"));
        assert!(
            detour_of_group(&config, "wallet").is_some(),
            "direct must resolve to the built-in node"
        );
    }

    /// A group that names nothing keeps its members on their own paths. This is
    /// the common case, and it must not cost a lookup that can fail.
    #[test]
    fn a_group_naming_no_detour_has_none_to_apply() {
        let config = group_named("wallet", None);
        assert!(
            detour_of_group(&config, "wallet").is_none(),
            "no name means no detour, not a broken one"
        );
    }

    /// A detour on a group with no reference edge to this one does not reach
    /// it: inheritance follows `filter: group(X)` edges, not mere coexistence.
    #[test]
    fn an_unrelated_groups_detour_is_not_applied() {
        let mut config = group_named("wallet", None);
        config.groups.push(honk_config::group::Group {
            name: "other".into(),
            policy: honk_config::group::GroupPolicy::Selector,
            detour: Some("front".into()),
            ..Default::default()
        });
        assert!(
            detour_of_group(&config, "wallet").is_none(),
            "a group is carried by its own detour, not a neighbour's"
        );
    }

    /// `filter: group(X)` is a reference edge: the group borrows X's current
    /// selection, so it also borrows how that selection leaves the machine.
    #[test]
    fn a_group_inherits_the_detour_of_the_group_it_references() {
        let mut config = group_named("wallet", None);
        config.groups[0].groups = vec!["upstream".into()];
        config.groups.push(honk_config::group::Group {
            name: "upstream".into(),
            policy: honk_config::group::GroupPolicy::Selector,
            detour: Some("front".into()),
            ..Default::default()
        });
        let front_id = config.nodes[0].id;
        let path = detour_of_group(&config, "wallet").expect("an inherited detour must resolve");
        assert!(
            format!("{path:?}").contains(&front_id.to_string()),
            "the inherited path must name the upstream detour node: {path:?}"
        );
    }

    /// Inheritance follows the whole chain, not just one hop.
    #[test]
    fn inheritance_follows_a_chain_of_nested_groups() {
        let mut config = group_named("wallet", None);
        config.groups[0].groups = vec!["mid".into()];
        config.groups.push(honk_config::group::Group {
            name: "mid".into(),
            groups: vec!["upstream".into()],
            policy: honk_config::group::GroupPolicy::Selector,
            ..Default::default()
        });
        config.groups.push(honk_config::group::Group {
            name: "upstream".into(),
            policy: honk_config::group::GroupPolicy::Selector,
            detour: Some("front".into()),
            ..Default::default()
        });
        let front_id = config.nodes[0].id;
        let path = detour_of_group(&config, "wallet").expect("a chained detour must resolve");
        assert!(
            format!("{path:?}").contains(&front_id.to_string()),
            "the chain must reach the upstream detour node: {path:?}"
        );
    }

    /// An explicit `detour:` on the group wins over one it would otherwise
    /// inherit from a nested group.
    #[test]
    fn an_explicit_detour_overrides_an_inherited_one() {
        let mut config = group_named("wallet", Some("front"));
        let inherited_id = config.nodes[0].id;
        config
            .nodes
            .push(socks5_node("own-front", "127.0.0.1:2".parse().unwrap()));
        let own_id = config.nodes[1].id;
        config.groups[0].detour = Some("own-front".into());
        config.groups[0].groups = vec!["upstream".into()];
        config.groups.push(honk_config::group::Group {
            name: "upstream".into(),
            policy: honk_config::group::GroupPolicy::Selector,
            detour: Some("front".into()),
            ..Default::default()
        });
        let path = detour_of_group(&config, "wallet").expect("the group's own detour must resolve");
        let rendered = format!("{path:?}");
        assert!(
            rendered.contains(&own_id.to_string()),
            "the group's own detour must win: {rendered}"
        );
        assert!(
            !rendered.contains(&inherited_id.to_string()),
            "the upstream detour must not be inherited: {rendered}"
        );
    }

    /// A cycle in the nested-group graph must not hang the lookup.
    #[test]
    fn inheritance_walks_a_cycle_only_once() {
        let mut config = group_named("wallet", None);
        config.groups[0].groups = vec!["b".into()];
        config.groups.push(honk_config::group::Group {
            name: "b".into(),
            groups: vec!["wallet".into()],
            policy: honk_config::group::GroupPolicy::Selector,
            ..Default::default()
        });
        assert!(detour_of_group(&config, "wallet").is_none());
    }
}
