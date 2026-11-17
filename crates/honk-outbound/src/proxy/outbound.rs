use async_trait::async_trait;
use honk_config::node::Node;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use super::{DirectMark, MultiTargetTransport, PacketTransport, PreparedUdpTransport, ProxyStream};

/// Result of requesting reusable protocol state. `Ready` means the state is
/// usable after the call; `NotApplicable` means the protocol owns no
/// generation-scoped session or client.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WarmOutcome {
    Ready,
    NotApplicable,
}

/// TCP flow dialing. Every protocol implements this.
#[async_trait]
pub trait TcpOutbound: Send + Sync {
    async fn dial(
        &self,
        node: &Node,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: Duration,
    ) -> anyhow::Result<ProxyStream>;

    /// The provided `tcp` stream is already connected to the proxy
    /// server. Handlers that support connection pooling override this to
    /// skip `TcpStream::connect()`; the default ignores `tcp` and delegates
    /// to [`Self::dial`].
    async fn dial_with_tcp(
        &self,
        node: &Node,
        target: SocketAddr,
        target_domain: Option<&str>,
        tcp: tokio::net::TcpStream,
        connect_timeout: Duration,
    ) -> anyhow::Result<ProxyStream> {
        let _ = tcp;
        self.dial(node, target, target_domain, connect_timeout)
            .await
    }

    /// Dial through an explicitly captured runtime generation. Stateless
    /// handlers delegate to [`Self::dial`]; session-owning handlers override
    /// this to avoid consulting the mutable current-generation registry.
    async fn dial_runtime(
        &self,
        runtime: Arc<crate::runtime::NodeRuntime>,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: Duration,
    ) -> anyhow::Result<ProxyStream> {
        self.dial(
            runtime.node.as_ref(),
            target,
            target_domain,
            connect_timeout,
        )
        .await
    }

    /// Dial inside a generation, carried by a detour the caller names rather
    /// than by the node's own.
    ///
    /// This is how a group's detour reaches the member it picked. A group
    /// resolves to a node only once a flow arrives, so the front it names
    /// could never have been bound to that node: the same node is reachable
    /// directly, or through another group, and keeps its own path out in both
    /// cases. The caller is therefore the only thing that knows.
    ///
    /// The default refuses. Honouring this means opening the node's own server
    /// connection over the detour, which only the protocols that dial through
    /// the shared transport do; dialling regardless would send the flow out of
    /// the real interface while looking like an ordinary connection, which is
    /// the one outcome a detour exists to rule out. QUIC outbounds (Hysteria2,
    /// TUIC, Juicity) share the `crate::quic::fronted_quic_dial!` template so
    /// none of them can accidentally reuse a cached client from another path.
    async fn dial_runtime_detoured(
        &self,
        _runtime: Arc<crate::runtime::NodeRuntime>,
        _target: SocketAddr,
        _target_domain: Option<&str>,
        _connect_timeout: Duration,
        detour: &Arc<crate::proxy::detour::DetourPath>,
    ) -> anyhow::Result<ProxyStream> {
        let _ = detour;
        anyhow::bail!("this protocol cannot be carried by a detour a group names")
    }

    /// Dial a routed direct flow with a nonzero mark. Outbounds that do not
    /// own the flow's socket cannot apply it and refuse the dial.
    async fn dial_runtime_marked(
        &self,
        _runtime: Arc<crate::runtime::NodeRuntime>,
        _target: SocketAddr,
        _target_domain: Option<&str>,
        _connect_timeout: Duration,
        mark: DirectMark,
    ) -> anyhow::Result<ProxyStream> {
        anyhow::bail!("outbound cannot carry direct mark {:#x}", mark.get())
    }
}

/// Framed UDP transports — only protocols with UDP capability (see
/// [`crate::descriptor::ProtocolDescriptor::supports_udp`]).
#[async_trait]
pub trait PacketOutbound: Send + Sync {
    async fn dial_udp_transport(
        &self,
        node: &Node,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: Duration,
    ) -> anyhow::Result<Arc<dyn PacketTransport>>;

    /// Open a framed UDP transport using an explicitly captured runtime
    /// generation. Session-owning handlers override this so an authoritative
    /// flow reuses the same warmed generation-local client.
    async fn dial_udp_transport_runtime(
        &self,
        runtime: Arc<crate::runtime::NodeRuntime>,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: Duration,
    ) -> anyhow::Result<Arc<dyn PacketTransport>> {
        self.dial_udp_transport(
            runtime.node.as_ref(),
            target,
            target_domain,
            connect_timeout,
        )
        .await
    }

    /// UDP counterpart of [`TcpOutbound::dial_runtime_detoured`].
    ///
    /// A group's detour names the path this one flow must take, independent of
    /// whatever detour the node itself carries. Reusing a session, QUIC client
    /// or shared-source carrier opened over the node's own path would send the
    /// packets out of that other path while looking like an ordinary flow, so
    /// this dial must build one over the named detour instead.
    ///
    /// The default refuses. Silently dialling the node's own path is exactly
    /// the leak a detour exists to rule out, so only protocols that dial
    /// through the shared transport override this.
    async fn dial_udp_transport_runtime_detoured(
        &self,
        _runtime: Arc<crate::runtime::NodeRuntime>,
        _target: SocketAddr,
        _target_domain: Option<&str>,
        _connect_timeout: Duration,
        detour: &Arc<crate::proxy::detour::DetourPath>,
    ) -> anyhow::Result<Arc<dyn PacketTransport>> {
        let _ = detour;
        anyhow::bail!("this protocol cannot carry a detour a group names on UDP")
    }

    /// UDP counterpart of [`TcpOutbound::dial_runtime_marked`].
    async fn dial_udp_transport_runtime_marked(
        &self,
        _runtime: Arc<crate::runtime::NodeRuntime>,
        _target: SocketAddr,
        _target_domain: Option<&str>,
        _connect_timeout: Duration,
        mark: DirectMark,
    ) -> anyhow::Result<Arc<dyn PacketTransport>> {
        anyhow::bail!("outbound cannot carry direct mark {:#x}", mark.get())
    }

    /// Generation-pinned speculative preparation. The default wraps the
    /// authoritative runtime transport; session handlers override this when
    /// loser cancellation must avoid publishing reusable state.
    async fn dial_udp_transport_speculative_runtime(
        &self,
        runtime: Arc<crate::runtime::NodeRuntime>,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: Duration,
    ) -> anyhow::Result<PreparedUdpTransport> {
        self.dial_udp_transport_runtime(runtime, target, target_domain, connect_timeout)
            .await
            .map(PreparedUdpTransport::ready)
    }
}

/// One association carrying every destination of a client source (the core
/// `Shared` source transport). Registered only by protocols whose
/// [`PacketOutbound`] slot also exists; `speculative` preparations must not
/// publish carrier state until committed.
#[async_trait]
pub trait SharedSourceOutbound: Send + Sync {
    async fn prepare_shared_source(
        &self,
        runtime: Arc<crate::runtime::NodeRuntime>,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: Duration,
        speculative: bool,
    ) -> anyhow::Result<PreparedUdpTransport<dyn MultiTargetTransport>>;
}

/// Which property a warm request must establish. Selector ownership needs
/// the shared session; UDP top-N ownership additionally validates that the
/// server admitted UDP on protocols where that is negotiated separately.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WarmRequirement {
    Session,
    Udp,
}

#[async_trait]
pub trait WarmableOutbound: Send + Sync {
    async fn warm(
        &self,
        runtime: Arc<crate::runtime::NodeRuntime>,
        connect_timeout: Duration,
        requirement: WarmRequirement,
    ) -> anyhow::Result<()>;
}

/// Raw server reachability checks.
#[async_trait]
pub trait ProbeableOutbound: Send + Sync {
    async fn test_connectivity(&self, node: &Node) -> bool {
        let addr = format!("{}:{}", node.host(), node.port);
        match crate::util::connect_outbound(&addr, std::time::Duration::from_secs(3)).await {
            Ok(_stream) => true,
            Err(e) => {
                tracing::debug!(
                    "{} connectivity test failed for {}: {}",
                    node.protocol().as_str(),
                    node.name,
                    e
                );
                false
            }
        }
    }
}
