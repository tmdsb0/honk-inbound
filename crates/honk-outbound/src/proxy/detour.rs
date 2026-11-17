//! The path a node takes out when it names a detour.
//!
//! A server the direct path out cannot reach is often reachable from another
//! node, so a node may name one — or a group, whose current member carries it.
//! Turning that name into a dial needs the node set, the groups and the proxy
//! registry, so the generation resolves it once and hands the node a
//! [`DetourPath`]. A group is the one part that cannot be resolved that early,
//! and it is resolved again on every dial instead.
//!
//! There are two callers: a node's own `dialer-proxy` is bound once per
//! generation, while a group's `detour` is resolved into a fresh path on each
//! dial and takes precedence over the node's binding.
//!
//! A dial through it yields the same byte stream a socket would, and for UDP
//! the same framed transport, so the protocol above does not have to know
//! which path it is on.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use honk_config::node::Node;
use honk_config::types::NodeProtocol;

use crate::alive::{IpVersion, ProbeDomain};
use crate::group::GroupManager;
use crate::proxy::{AsyncReadWrite, PacketTransport, ProxyRegistry};
use crate::runtime::OutboundRuntimeRegistry;

/// Refuse a dial for a node that names a detour this generation has not bound.
///
/// A node on a detour has to ride it. Dialling the direct path because the
/// binding is missing would send its traffic out of the real interface while
/// looking like a perfectly ordinary connection.
pub fn ensure_bound(node: &Node, detour: Option<&DetourPath>) -> anyhow::Result<()> {
    if detour.is_none()
        && let Some(name) = node.detour_name()
    {
        anyhow::bail!(
            "node {}: detour {name:?} is not bound in this generation",
            node.name
        );
    }
    Ok(())
}

/// Error context shared by every fronted QUIC dial. Keeping the wording in one
/// place means a `QuicClient` handshake and a MASQUE h3 tunnel report the same
/// failure identically, and there is a single place to change it.
pub(crate) fn udp_carry_context(addr: impl std::fmt::Display) -> String {
    format!("detour could not carry UDP to {addr}")
}

pub(crate) fn quic_endpoint_context(addr: impl std::fmt::Display) -> String {
    format!("QUIC endpoint over the detour to {addr}")
}

pub(crate) fn transport_error_context(cause: impl std::fmt::Display) -> String {
    format!("QUIC transport error: {cause}")
}

/// Which group member carries a detour, on each network a MASQUE tunnel can be
/// dialled on. The tunnel cache compares the whole signature.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CarrierSignature {
    pub tcp: Option<uuid::Uuid>,
    pub udp: Option<uuid::Uuid>,
}

/// Read a group's current carrier without advancing its selection state.
fn peek_carrier(manager: &GroupManager, name: &str, domain: ProbeDomain) -> Option<uuid::Uuid> {
    manager
        .peek_selection_plan_for_domain(name, domain, IpVersion::V4)
        .nodes
        .first()
        .map(|node| node.id)
}

/// Resolve a `host:port` pair to every address a detour can dial, in answer order.
///
/// The detour is dialled by address, so the name has to be resolved here
/// rather than inside the detour node: only this end knows which host the
/// node's traffic is actually for.
///
/// The lookup goes through the bootstrap resolver, the same path every
/// direct server dial takes (`connect_marked`): libc NSS resolution is
/// deliberately not used anywhere in the control plane, and a detoured
/// node's hostname must not resolve differently from an undetoured one.
///
/// Every address comes back so the caller can race them the way a direct dial
/// does: betting the whole dial on the first answer strands the node when
/// that one address is dead while a later one answers.
pub async fn resolve_endpoints(address: &str) -> anyhow::Result<Vec<SocketAddr>> {
    let (host, port) = address
        .rsplit_once(':')
        .ok_or_else(|| anyhow::anyhow!("endpoint {address} is not a host:port pair"))?;
    let port: u16 = port
        .parse()
        .map_err(|_| anyhow::anyhow!("endpoint {address} has a bad port"))?;
    // The resolver future is large; box it so callers that compose this dial
    // into deep async stacks do not blow the crate recursion limit while the
    // compiler computes nested future layouts (same trick `connect_marked`
    // uses for its flow-observed resolution).
    let resolution = Box::pin(crate::bootstrap::resolve(host));
    let ips = resolution.await?;
    if ips.is_empty() {
        anyhow::bail!("endpoint {address} resolved to nothing");
    }
    Ok(ips
        .into_iter()
        .map(|ip| SocketAddr::new(ip, port))
        .collect())
}

/// What the operator named: one node, or a group that picks one.
///
/// A group is resolved at dial time rather than at bind time. That is the
/// point of naming one — the front follows the group's current choice, so a
/// selector the operator has just switched, or a fallback that has failed over
/// since the last reload, carries the next dial without a reload of its own.
enum DetourTarget {
    Node(uuid::Uuid),
    Group {
        name: String,
        manager: Arc<GroupManager>,
    },
}

/// The node this one dials through, pinned to the generation that built it.
///
/// Dials stay inside that generation: a retired one refuses them, and the node
/// is rebuilt with the next.
pub struct DetourPath {
    proxies: Arc<ProxyRegistry>,
    generation: Arc<OutboundRuntimeRegistry>,
    target: DetourTarget,
    /// Whether the node riding this path is itself MASQUE. Only a group
    /// reaches this field: a node target is judged when it is bound, but a
    /// group gives no answer until the dial asks.
    rider_is_masque: bool,
}

impl std::fmt::Debug for DetourPath {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut debug = formatter.debug_struct("DetourPath");
        match &self.target {
            DetourTarget::Node(node_id) => debug.field("node_id", node_id),
            DetourTarget::Group { name, .. } => debug.field("group", name),
        };
        debug.finish_non_exhaustive()
    }
}

impl DetourPath {
    /// Pin a detour to the generation whose node set named it.
    pub fn new(
        proxies: Arc<ProxyRegistry>,
        generation: Arc<OutboundRuntimeRegistry>,
        node_id: uuid::Uuid,
    ) -> Self {
        Self {
            proxies,
            generation,
            target: DetourTarget::Node(node_id),
            rider_is_masque: false,
        }
    }

    /// Pin a detour to a group, resolved on each dial to whichever node the
    /// group then picks for that network.
    ///
    /// The rider's protocol comes along because the pair cannot be judged
    /// before the group answers.
    pub fn to_group(
        proxies: Arc<ProxyRegistry>,
        generation: Arc<OutboundRuntimeRegistry>,
        name: &str,
        manager: Arc<GroupManager>,
        rider: NodeProtocol,
    ) -> Self {
        Self {
            proxies,
            generation,
            target: DetourTarget::Group {
                name: name.to_string(),
                manager,
            },
            rider_is_masque: rider == NodeProtocol::Masque,
        }
    }

    /// A stable name for the logical path this detour takes.
    ///
    /// Something a node owns one of — a MASQUE tunnel, say — has to be one
    /// per path rather than one per node, because the one that was opened
    /// over this path is not the one a flow on another path may use. A group
    /// is keyed by name: which member carries it is resolved per dial, so the
    /// owner of a long-lived resource compares `carrier_id` as well before
    /// reusing the one it built for a previous member.
    pub(crate) fn key(&self) -> String {
        match &self.target {
            DetourTarget::Node(node_id) => format!("node:{node_id}"),
            DetourTarget::Group { name, .. } => format!("group:{name}"),
        }
    }

    /// The member carrying this path on each network, read without advancing
    /// group state (round-robin cursors, URLTest caches, marks).
    ///
    /// A MASQUE tunnel is not like an ordinary stream: it dials its server
    /// once and every later flow rides that same carrier. A group's current
    /// member can therefore change while the tunnel is still alive, and the
    /// cache must notice that the tunnel belongs to the old front.
    /// `connect_udp` selects with `ProbeDomain::DataUdp` while a TCP dial uses
    /// `Tcp`, so both have to take part in that comparison.
    pub(crate) fn carrier_signature(&self) -> CarrierSignature {
        match &self.target {
            DetourTarget::Node(node_id) => CarrierSignature {
                tcp: Some(*node_id),
                udp: Some(*node_id),
            },
            DetourTarget::Group { name, manager } => CarrierSignature {
                tcp: peek_carrier(manager, name, ProbeDomain::Tcp),
                udp: peek_carrier(manager, name, ProbeDomain::DataUdp),
            },
        }
    }

    /// The node that carries this dial, for this network.
    ///
    /// A group is selected once per dial, not once per attempted address:
    /// callers racing addresses resolve first and dial every attempt
    /// through the node that came back, so one dial is one selection.
    pub(crate) fn resolve(&self, domain: ProbeDomain) -> anyhow::Result<uuid::Uuid> {
        match &self.target {
            DetourTarget::Node(node_id) => Ok(*node_id),
            DetourTarget::Group { name, manager } => {
                let node = manager
                    .select_node_for_domain(name, domain, IpVersion::V4)
                    .ok_or_else(|| {
                        anyhow::anyhow!(
                            "detour group {name:?} has no node that can carry this dial"
                        )
                    })?;
                if self.rider_is_masque && node.protocol() == NodeProtocol::Masque {
                    anyhow::bail!(
                        "detour group {name:?} selected {:?}, which is MASQUE and would nest \
                         tunnels",
                        node.name
                    );
                }
                Ok(node.id)
            }
        }
    }

    /// Open a stream to `target` through the detour node.
    ///
    /// A detour that cannot carry the stream fails the dial. Falling back to
    /// the direct path would send traffic out of the real interface without
    /// saying so, which is worse than a node that is simply down.
    pub async fn connect(
        &self,
        target: SocketAddr,
        timeout: Duration,
    ) -> anyhow::Result<Box<dyn AsyncReadWrite>> {
        let node_id = self.resolve(ProbeDomain::Tcp)?;
        self.connect_via(node_id, target, timeout).await
    }

    /// Open a stream to `target` through the already-resolved front node.
    pub(crate) async fn connect_via(
        &self,
        node_id: uuid::Uuid,
        target: SocketAddr,
        timeout: Duration,
    ) -> anyhow::Result<Box<dyn AsyncReadWrite>> {
        let stream = self
            .proxies
            .dial_runtime(Arc::clone(&self.generation), node_id, target, None, timeout)
            .await?;
        Ok(stream.stream)
    }

    /// Open a stream through the detour to the first of `endpoints` that
    /// answers, racing them the way a direct dial races resolved addresses.
    /// The winning address comes back with the stream: a caller that has to
    /// re-dial the same peer (REALITY) must reuse it, not resolve again and
    /// risk landing on a different first answer.
    ///
    /// The front is resolved once for the whole race: a group front selected
    /// per attempt would burn one round-robin turn per address tried, and
    /// the attempts could ride different fronts.
    pub(crate) async fn connect_raced(
        &self,
        endpoints: &[SocketAddr],
        timeout: Duration,
    ) -> anyhow::Result<(Box<dyn AsyncReadWrite>, SocketAddr)> {
        let node_id = self.resolve(ProbeDomain::Tcp)?;
        crate::address_race::race_resolved_addrs(endpoints, |endpoint| {
            let this = self;
            async move {
                this.connect_via(node_id, endpoint, timeout)
                    .await
                    .map(|stream| (stream, endpoint))
            }
        })
        .await
        .ok_or_else(|| anyhow::anyhow!("no resolved address to dial"))?
    }

    /// Open a framed UDP transport to `target` through the detour node.
    pub async fn connect_udp(
        &self,
        target: SocketAddr,
        target_domain: Option<&str>,
        timeout: Duration,
    ) -> anyhow::Result<Arc<dyn PacketTransport>> {
        let node_id = self.resolve(ProbeDomain::DataUdp)?;
        self.connect_udp_via(node_id, target, target_domain, timeout)
            .await
    }

    /// Open a framed UDP transport to `target` through the already-resolved
    /// front node. Callers racing addresses resolve the front once and hand
    /// it here, so one dial is one group selection.
    pub(crate) async fn connect_udp_via(
        &self,
        node_id: uuid::Uuid,
        target: SocketAddr,
        target_domain: Option<&str>,
        timeout: Duration,
    ) -> anyhow::Result<Arc<dyn PacketTransport>> {
        self.proxies
            .dial_udp_transport_runtime(
                Arc::clone(&self.generation),
                node_id,
                target,
                target_domain,
                timeout,
            )
            .await
    }
}

/// Open the connection to a node's own server: through its detour when the
/// node names one, and to the real network when it does not.
///
/// Every protocol that reaches its server over a socket of its own has to come
/// through here rather than connecting directly. One that connects directly
/// ignores a detour the operator configured and sends the node's traffic out
/// of the real interface, which looks exactly like an ordinary connection —
/// the one outcome this feature exists to prevent.
pub(crate) async fn connect_server(
    node: &Node,
    detour: Option<&DetourPath>,
    connect_timeout: Duration,
) -> anyhow::Result<crate::transport_quality::tcp::Carrier> {
    ensure_bound(node, detour)?;
    let address = crate::proxy::transport::endpoint_address(node);
    let Some(path) = detour else {
        return Ok(crate::transport_quality::tcp::Carrier::Socket(
            crate::util::connect_outbound(&address, connect_timeout).await?,
        ));
    };
    let endpoints = resolve_endpoints(&address).await?;
    let (stream, _) = path
        .connect_raced(&endpoints, connect_timeout)
        .await
        .map_err(|error| {
            anyhow::anyhow!(
                "node {}: detour could not reach {address}: {error}",
                node.name
            )
        })?;
    Ok(crate::transport_quality::tcp::Carrier::Chained(stream))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn node_named(name: &str) -> Node {
        Node {
            name: name.to_string(),
            host: "example.com".to_string(),
            address: "example.com:443".to_string(),
            port: 443,
            ..Default::default()
        }
    }

    /// A node that names a detour it does not have must fail its dial rather
    /// than quietly take the direct path: the operator asked for the traffic to
    /// leave through another node.
    #[test]
    fn a_named_detour_without_a_binding_refuses_the_dial() {
        let mut node = node_named("back");
        node.detour = Some("front".into());
        let error = ensure_bound(&node, None).unwrap_err().to_string();
        assert!(
            error.contains("is not bound in this generation") && error.contains("back"),
            "{error}"
        );
    }

    #[test]
    fn a_node_on_its_own_path_needs_no_binding() {
        ensure_bound(&node_named("plain"), None).unwrap();
    }

    /// The check is about the binding, not the name: with one bound the dial
    /// proceeds however it was named.
    #[test]
    fn a_bound_detour_satisfies_the_check() {
        let generation = Arc::new(OutboundRuntimeRegistry::build(&[]).unwrap());
        let path = DetourPath::new(
            Arc::new(ProxyRegistry::new()),
            Arc::clone(&generation),
            uuid::Uuid::new_v4(),
        );
        let mut node = node_named("back");
        node.detour = Some("front".into());
        ensure_bound(&node, Some(&path)).unwrap();
    }

    /// The registry carries no group: nothing on the dial path can resolve one,
    /// which is why configuration drops those names before they get this far.
    #[test]
    fn the_path_is_pinned_to_one_node() {
        let generation = Arc::new(OutboundRuntimeRegistry::build(&[]).unwrap());
        let node_id = uuid::Uuid::new_v4();
        let path = DetourPath::new(Arc::new(ProxyRegistry::new()), generation, node_id);
        assert!(
            format!("{path:?}").contains(&node_id.to_string()),
            "the debug form names the node it rides: {path:?}"
        );
    }

    fn group_path(name: &str) -> DetourPath {
        DetourPath::to_group(
            Arc::new(ProxyRegistry::new()),
            Arc::new(OutboundRuntimeRegistry::build(&[]).unwrap()),
            name,
            Arc::new(GroupManager::new(&[], &[])),
            NodeProtocol::Trojan,
        )
    }

    /// A group detour has no node to name, so it names the group instead.
    #[test]
    fn a_group_detour_names_the_group_it_resolves() {
        let path = group_path("fronts");
        assert!(
            format!("{path:?}").contains("fronts"),
            "the debug form names the group: {path:?}"
        );
    }

    /// A group that can produce nothing refuses the dial. Sending it on its own
    /// path would be indistinguishable from a node with no detour at all.
    #[test]
    fn a_group_with_no_member_refuses_to_carry_the_dial() {
        let path = group_path("empty");
        let error = path
            .resolve(ProbeDomain::Tcp)
            .expect_err("an empty group carries nothing")
            .to_string();
        assert!(error.contains("empty"), "{error}");
    }

    /// A MASQUE tunnel is a long-lived carrier, so its owner must see the
    /// front it was opened over change. Keying the tunnel by group name alone
    /// used to hand every later flow the old member's connection until a full
    /// restart — even after a reload had already switched the front.
    #[test]
    fn a_switched_front_changes_the_reported_carrier() {
        use honk_config::node::{Group, GroupPolicy};

        let first = uuid::Uuid::new_v4();
        let second = uuid::Uuid::new_v4();
        let nodes = vec![
            Node {
                id: first,
                name: "front-a".into(),
                ..Default::default()
            },
            Node {
                id: second,
                name: "front-b".into(),
                ..Default::default()
            },
        ];
        let group = Group {
            name: "fronts".into(),
            policy: GroupPolicy::Selector,
            nodes: vec![first, second],
            ..Default::default()
        };
        let manager = Arc::new(GroupManager::new(&[group], &nodes));
        let path = DetourPath::to_group(
            Arc::new(ProxyRegistry::new()),
            Arc::new(OutboundRuntimeRegistry::build(&[]).unwrap()),
            "fronts",
            Arc::clone(&manager),
            NodeProtocol::Trojan,
        );

        assert_eq!(path.carrier_signature().tcp, Some(first));
        manager
            .set_selector_choice("fronts", "front-b", crate::group::SelectorNetworks::Both)
            .unwrap();
        assert_eq!(path.carrier_signature().tcp, Some(second));
    }

    /// Fake DNS wire reply: echo the query, answer with `ips` in the queried family.
    fn fake_dns_response(query: &[u8], ips: &[IpAddr]) -> Vec<u8> {
        let qtype = u16::from_be_bytes([query[query.len() - 4], query[query.len() - 3]]);
        let mut resp = query.to_vec();
        resp[2] = 0x81;
        resp[3] = 0x80;
        let mut count = 0u16;
        for ip in ips {
            let rdata = match (qtype, ip) {
                (1, IpAddr::V4(ip)) => ip.octets().to_vec(),
                (28, IpAddr::V6(ip)) => ip.octets().to_vec(),
                _ => continue,
            };
            resp.extend_from_slice(&[0xC0, 0x0C]);
            resp.extend_from_slice(&qtype.to_be_bytes());
            resp.extend_from_slice(&1u16.to_be_bytes());
            resp.extend_from_slice(&60u32.to_be_bytes());
            resp.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
            resp.extend_from_slice(&rdata);
            count += 1;
        }
        resp[6..8].copy_from_slice(&count.to_be_bytes());
        resp
    }

    /// Loopback TCP DNS stub: A answers `[dead, live]` in that order, AAAA
    /// answers nothing. UDP is unusable in this sandbox, so the stub speaks
    /// DNS over TCP (length-prefixed messages).
    async fn spawn_tcp_dns_stub(dead: Ipv4Addr, live: Ipv4Addr) -> SocketAddr {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                tokio::spawn(async move {
                    loop {
                        let mut len_buf = [0u8; 2];
                        if stream.read_exact(&mut len_buf).await.is_err() {
                            break;
                        }
                        let len = u16::from_be_bytes(len_buf) as usize;
                        let mut query = vec![0u8; len];
                        if stream.read_exact(&mut query).await.is_err() {
                            break;
                        }
                        let reply =
                            fake_dns_response(&query, &[IpAddr::V4(dead), IpAddr::V4(live)]);
                        if stream
                            .write_all(&(reply.len() as u16).to_be_bytes())
                            .await
                            .is_err()
                        {
                            break;
                        }
                        if stream.write_all(&reply).await.is_err() {
                            break;
                        }
                    }
                });
            }
        });
        addr
    }

    /// The builtin direct node is the only Direct node the config accepts:
    /// name `direct`, the builtin id, no host or address.
    fn direct_node() -> Node {
        honk_config::config::Config::builtin_direct_node()
    }

    /// A SOCKS5 node dialing the fake server at `server`.
    fn socks5_node(name: &str, server: SocketAddr) -> Node {
        Node {
            name: name.to_string(),
            host: server.ip().to_string(),
            address: server.ip().to_string(),
            port: server.port(),
            outbound: honk_config::node::OutboundConfig::Socks5(Default::default()),
            ..Default::default()
        }
    }

    /// Minimal SOCKS5 server: no-auth greeting, then a CONNECT it proxies
    /// through to the requested address, so a SOCKS5 front can carry a dial
    /// to a loopback listener in tests.
    async fn spawn_fake_socks5() -> SocketAddr {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::{TcpListener, TcpStream};

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                tokio::spawn(async move {
                    let mut greeting = [0u8; 2];
                    if stream.read_exact(&mut greeting).await.is_err() {
                        return;
                    }
                    let mut methods = vec![0u8; greeting[1] as usize];
                    if stream.read_exact(&mut methods).await.is_err() {
                        return;
                    }
                    if stream.write_all(&[5, 0]).await.is_err() {
                        return;
                    }
                    let mut head = [0u8; 4];
                    if stream.read_exact(&mut head).await.is_err() {
                        return;
                    }
                    let target = match head[3] {
                        1 => {
                            let mut buf = [0u8; 6];
                            if stream.read_exact(&mut buf).await.is_err() {
                                return;
                            }
                            SocketAddr::new(
                                IpAddr::V4(Ipv4Addr::new(buf[0], buf[1], buf[2], buf[3])),
                                u16::from_be_bytes([buf[4], buf[5]]),
                            )
                        }
                        _ => return,
                    };
                    match TcpStream::connect(target).await {
                        Ok(mut upstream) => {
                            if stream
                                .write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0])
                                .await
                                .is_err()
                            {
                                return;
                            }
                            let _ = tokio::io::copy_bidirectional(&mut stream, &mut upstream).await;
                        }
                        Err(_) => {
                            let _ = stream.write_all(&[5, 5, 0, 1, 0, 0, 0, 0, 0, 0]).await;
                        }
                    }
                });
            }
        });
        addr
    }

    /// Resolution returns every address in answer order: the dial race needs
    /// the whole set, not just the first answer.
    #[tokio::test]
    async fn resolve_endpoints_returns_every_address_in_answer_order() {
        if crate::bootstrap::run_global_test_in_child(
            "proxy::detour::tests::resolve_endpoints_returns_every_address_in_answer_order",
        ) {
            return;
        }
        let dead = Ipv4Addr::new(127, 0, 0, 2);
        let live = Ipv4Addr::new(127, 0, 0, 1);
        let stub = spawn_tcp_dns_stub(dead, live).await;
        crate::bootstrap::set_global(crate::bootstrap::BootstrapResolver::parse(&format!(
            "tcp://{stub}"
        )));
        let endpoints = resolve_endpoints("back.invalid:8443").await.unwrap();
        crate::bootstrap::set_global(None);
        assert_eq!(
            endpoints,
            vec![
                SocketAddr::new(dead.into(), 8443),
                SocketAddr::new(live.into(), 8443),
            ]
        );
    }

    /// A detour dial must reach a server whose first resolved address refuses
    /// the connection: the dial races every resolved address the way a direct
    /// dial does, instead of betting the whole dial on the first one.
    #[tokio::test]
    async fn detour_dial_races_resolved_addresses() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        if crate::bootstrap::run_global_test_in_child(
            "proxy::detour::tests::detour_dial_races_resolved_addresses",
        ) {
            return;
        }
        let dead = Ipv4Addr::new(127, 0, 0, 2);
        let live = Ipv4Addr::new(127, 0, 0, 1);
        let stub = spawn_tcp_dns_stub(dead, live).await;
        crate::bootstrap::set_global(crate::bootstrap::BootstrapResolver::parse(&format!(
            "tcp://{stub}"
        )));

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let accepted = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 4];
            stream.read_exact(&mut buf).await.unwrap();
            buf
        });

        let front = direct_node();
        let generation =
            Arc::new(OutboundRuntimeRegistry::build(std::slice::from_ref(&front)).unwrap());
        let path = DetourPath::new(
            Arc::new(ProxyRegistry::default_resolver().unwrap()),
            Arc::clone(&generation),
            front.id,
        );
        let mut back = node_named("back");
        back.host = "back.invalid".to_string();
        back.address = format!("back.invalid:{port}");
        back.port = port;
        back.detour = Some("direct".into());
        back.id = back.derive_id();

        let dialed = connect_server(&back, Some(&path), Duration::from_secs(5)).await;
        crate::bootstrap::set_global(None);
        let mut carrier = dialed
            .expect("detour dial reaches the live address although the first resolved one refuses");
        carrier.write_all(b"ping").await.unwrap();
        assert_eq!(accepted.await.unwrap(), *b"ping");
    }

    /// One raced dial is one group selection: a LoadBalance front must be
    /// picked once for the whole race, not once per attempted address.
    /// Picking per attempt burns two round-robin turns for one dial, and the
    /// attempts can ride different fronts.
    #[tokio::test]
    async fn detour_group_front_is_selected_once_per_raced_dial() {
        use honk_config::node::{Group, GroupPolicy};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        if crate::bootstrap::run_global_test_in_child(
            "proxy::detour::tests::detour_group_front_is_selected_once_per_raced_dial",
        ) {
            return;
        }
        let dead = Ipv4Addr::new(127, 0, 0, 2);
        let live = Ipv4Addr::new(127, 0, 0, 1);
        let stub = spawn_tcp_dns_stub(dead, live).await;
        crate::bootstrap::set_global(crate::bootstrap::BootstrapResolver::parse(&format!(
            "tcp://{stub}"
        )));

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let accepted = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 4];
            stream.read_exact(&mut buf).await.unwrap();
            buf
        });

        // Two SOCKS5 fronts in a LoadBalance group: the round-robin cursor
        // is the observable for how many selections one dial consumed.
        // A Direct front cannot be duplicated — the runtime registry only
        // accepts the one builtin `direct` node — so the fronts are SOCKS5
        // nodes, each served by its own fake server that proxies CONNECTs
        // through. The servers must listen on different ports: a node's
        // derived id covers protocol, host and port, so two fronts on one
        // server would be the same node.
        let socks_a = spawn_fake_socks5().await;
        let socks_b = spawn_fake_socks5().await;
        let mut front_a = socks5_node("socks-a", socks_a);
        front_a.id = front_a.derive_id();
        let mut front_b = socks5_node("socks-b", socks_b);
        front_b.id = front_b.derive_id();
        let fronts = [front_a, front_b];
        let group = Group {
            name: "front".into(),
            policy: GroupPolicy::LoadBalance,
            nodes: fronts.iter().map(|node| node.id).collect(),
            tolerance: 50,
            ..Default::default()
        };
        let manager = Arc::new(GroupManager::new(std::slice::from_ref(&group), &fronts));
        let generation = Arc::new(OutboundRuntimeRegistry::build(&fronts).unwrap());
        let mut back = node_named("back");
        back.host = "back.invalid".to_string();
        back.address = format!("back.invalid:{port}");
        back.port = port;
        back.detour = Some("front".into());
        back.id = back.derive_id();
        let path = DetourPath::to_group(
            Arc::new(ProxyRegistry::default_resolver().unwrap()),
            Arc::clone(&generation),
            "front",
            Arc::clone(&manager),
            back.protocol(),
        );

        let dialed = connect_server(&back, Some(&path), Duration::from_secs(5)).await;
        crate::bootstrap::set_global(None);
        let mut carrier = dialed.expect(
            "detour dial through a group front reaches the live address although the first resolved one refuses",
        );
        carrier.write_all(b"ping").await.unwrap();
        assert_eq!(accepted.await.unwrap(), *b"ping");
        // The race tried two addresses but the group was selected once: the
        // next pick is the second member, not the first one again.
        assert_eq!(manager.select_node("front").unwrap().name, "socks-b");
    }
}
