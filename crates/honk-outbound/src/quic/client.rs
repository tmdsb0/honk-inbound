use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Weak};
use std::time::Duration;

use anyhow::{Context as _, anyhow};
use quinn::{ClientConfig, Connection, Endpoint, VarInt};
use tokio::sync::Mutex;

use crate::proxy::detour::DetourPath;
use crate::transport_quality::TransportQuality;

use super::endpoint::{clamp_quic_payload_size, client_endpoint_with_mtu};
use super::metrics::{QuicClientConnectionMonitor, spawn_quic_client_connection_monitor};
use super::{
    AdaptiveFlowProfiles, DialEndpoint, FRONTED_UDP_PAYLOAD_SIZE, QUIC_SAMPLE_INTERVAL,
    QuicClient, QuicConnState, State, TrackedConnection,
};

impl<C> State<C> {
    fn prune_connections(&mut self) {
        self.connections.retain(|tracked| {
            if tracked.state.upgrade().is_some() {
                return true;
            }
            if tracked.connection.close_reason().is_none() {
                tracked
                    .connection
                    .close(VarInt::from_u32(0), b"state dropped");
            }
            false
        });
    }
}

fn spawn_tracked_connection_cleanup<C: Send + Sync + 'static>(
    state: Weak<Mutex<State<C>>>,
    id: u64,
    connection: Connection,
    owner: Weak<C>,
    monitor: Arc<QuicClientConnectionMonitor>,
) {
    let _ = crate::runtime::spawn_owned(async move {
        let _monitor = monitor;
        let mut removed = false;
        loop {
            if owner.upgrade().is_none() {
                if connection.close_reason().is_none() {
                    connection.close(VarInt::from_u32(0), b"state dropped");
                }
                break;
            }
            tokio::select! {
                _ = connection.closed(), if !removed => {
                    if let Some(state) = state.upgrade() {
                        let mut state = state.lock().await;
                        state.connections.retain(|tracked| tracked.id != id);
                    }
                    removed = true;
                }
                _ = tokio::time::sleep(QUIC_SAMPLE_INTERVAL) => {}
            }
        }
        if !removed && let Some(state) = state.upgrade() {
            let mut state = state.lock().await;
            state.connections.retain(|tracked| tracked.id != id);
        }
    });
}

struct ConnectionCloseGuard(Option<Connection>);

impl ConnectionCloseGuard {
    fn new(conn: Connection) -> Self {
        Self(Some(conn))
    }

    fn disarm(&mut self) {
        self.0 = None;
    }
}

impl Drop for ConnectionCloseGuard {
    fn drop(&mut self) {
        if let Some(conn) = self.0.take() {
            conn.close(VarInt::from_u32(0), b"connection setup cancelled");
        }
    }
}

impl<C: Send + Sync + 'static> QuicClient<C> {
    pub fn new(
        server_host: impl Into<String>,
        server_port: u16,
        server_name: impl Into<String>,
        config: ClientConfig,
    ) -> Self {
        Self {
            server_host: server_host.into(),
            server_port,
            server_name: server_name.into(),
            config,
            endpoint_factory: None,
            detour: None,
            detour_transform: None,
            mtu: 1252,
            flow_control_profiles: Arc::new(AdaptiveFlowProfiles::default()),
            task_scope: crate::runtime::TaskScope::capture(),
            state: Arc::new(Mutex::new(State {
                dial_endpoint: None,
                conn: None,
                connections: Vec::new(),
                next_connection_id: 1,
                quality: None,
                closed: false,
            })),
        }
    }

    pub(crate) fn with_flow_control_profiles(
        mut self,
        profiles: Option<Arc<AdaptiveFlowProfiles>>,
    ) -> Self {
        if let Some(profiles) = profiles {
            self.flow_control_profiles = profiles;
        }
        self
    }

    /// Ride out through another node instead of binding a socket here.
    ///
    /// The detour is dialled once per handshake, so a redial also gets a fresh
    /// path; unlike a socket it cannot be built by the synchronous
    /// [`Self::with_endpoint_factory`], and it takes precedence over it.
    pub(crate) fn with_detour(mut self, detour: Option<Arc<DetourPath>>) -> Self {
        self.detour = detour;
        self
    }

    /// Apply a protocol-specific wrapper to the UDP transport a detour hands
    /// back. Only used on detoured dials; a direct dial builds its own socket
    /// and needs no wrapper.
    pub(crate) fn with_detour_transform(
        mut self,
        transform: Option<super::DetourTransportTransform>,
    ) -> Self {
        self.detour_transform = transform;
        self
    }

    /// Advertise a larger `max_udp_payload_size` on paths known to carry it
    /// (anything but PMTU-black-holed last miles — see [`super::client_endpoint`]).
    /// Larger datagrams directly lower the per-packet processing cost that
    /// caps single-connection QUIC throughput (~180k pps at 1252B).
    pub fn with_max_udp_payload_size(mut self, mtu: u16) -> Self {
        self.mtu = clamp_quic_payload_size(mtu);
        self
    }

    /// Use a custom endpoint constructor instead of [`super::client_endpoint`] (see
    /// the field docs). The factory runs for every dial and must return a fresh
    /// socket.
    pub fn with_endpoint_factory(
        mut self,
        factory: impl Fn(bool) -> io::Result<Endpoint> + Send + Sync + 'static,
    ) -> Self {
        self.endpoint_factory = Some(Arc::new(factory));
        self
    }
    pub(crate) async fn enable_metrics(&self, quality: Arc<TransportQuality>)
    where
        C: QuicConnState,
    {
        let mut state = self.state.lock().await;
        state.quality = Some(Arc::clone(&quality));
        for tracked in &state.connections {
            tracked.monitor.enable_metrics(Arc::clone(&quality));
            if let Some(ctx) = tracked.state.upgrade() {
                ctx.enable_telemetry();
            }
        }
    }

    /// Return the shared connection (plus its protocol state), dialing and
    /// running `setup` first when there is no live connection.
    ///
    /// Resolved server addresses are raced until one completes the QUIC
    /// handshake; protocol setup runs exactly once for that winner.
    pub async fn connection_with<F, Fut>(
        &self,
        connect_timeout: Duration,
        setup: F,
    ) -> anyhow::Result<(Connection, Arc<C>)>
    where
        F: FnOnce(Connection) -> Fut,
        Fut: Future<Output = anyhow::Result<C>>,
    {
        self.task_scope
            .scope(self.connection_with_inner(connect_timeout, setup, |_, _| {}))
            .await
    }

    pub(crate) async fn connection_with_metrics<F, Fut>(
        &self,
        connect_timeout: Duration,
        setup: F,
    ) -> anyhow::Result<(Connection, Arc<C>)>
    where
        C: QuicConnState,
        F: FnOnce(Connection) -> Fut,
        Fut: Future<Output = anyhow::Result<C>>,
    {
        self.task_scope
            .scope(
                self.connection_with_inner(connect_timeout, setup, |ctx, _| {
                    ctx.enable_telemetry();
                }),
            )
            .await
    }

    async fn connection_with_inner<F, Fut, H>(
        &self,
        connect_timeout: Duration,
        setup: F,
        mut on_publish: H,
    ) -> anyhow::Result<(Connection, Arc<C>)>
    where
        F: FnOnce(Connection) -> Fut,
        Fut: Future<Output = anyhow::Result<C>>,
        H: FnMut(&C, &Connection),
    {
        let mut state = self.state.lock().await;
        if state.closed {
            anyhow::bail!("QUIC client is closed");
        }
        state.prune_connections();
        if let Some((conn, ctx)) = &state.conn
            && conn.close_reason().is_none()
        {
            let conn = conn.clone();
            let ctx = Arc::clone(ctx);
            let metrics_enabled = state.quality.is_some();
            drop(state);
            // The QUIC connection is already admitted and reusable; time the
            // logical stream before its protocol open can block or cancel.
            crate::runtime::start_scoped_dial();
            if let Some(observer) = crate::runtime::flow_observation::current() {
                observer.publish(
                    crate::runtime::flow_observation::FlowEvent::TransportAttached {
                        server_addr: Some(conn.remote_address()),
                        resolution_location:
                            crate::runtime::flow_observation::ResolutionLocation::Unknown,
                    },
                );
            }
            if metrics_enabled {
                on_publish(ctx.as_ref(), &conn);
            }
            return Ok((conn, ctx));
        }
        state.conn = None;

        let host = format!("{}:{}", self.server_host, self.server_port);
        let resolution = crate::bootstrap::resolve(&self.server_host);
        let (resolved, selection) =
            crate::runtime::flow_observation::observe_resolution(resolution).await;
        let addrs: Vec<SocketAddr> = resolved
            .with_context(|| format!("resolve {host}"))?
            .into_iter()
            .map(|ip| SocketAddr::new(ip, self.server_port))
            .collect();
        if addrs.is_empty() {
            anyhow::bail!("resolve {host}: no addresses");
        }

        // A detour is dialled to one address and hands back a transport pinned
        // to it, so it replaces the address race rather than joining it: there
        // is no set of local paths to try, just the one the detour carries.
        let (conn, dial_endpoint, ipv6) = match self.detour.as_deref() {
            Some(path) => {
                let server_addr = *addrs.first().expect("address list checked non-empty");
                self.detour_handshake(path, server_addr, selection.as_ref(), connect_timeout)
                    .await?
            }
            None => {
                let raced = crate::address_race::race_resolved_addrs(&addrs, |server_addr| {
                    let ipv6 = server_addr.is_ipv6();
                    let selection = selection.as_ref();
                    async move {
                        // Every dial binds a fresh socket, so a redial does not inherit the
                        // local port of a black-holed flow: middleboxes keep dropping its NAT
                        // mapping for later connections.
                        let endpoint = crate::runtime::new_owned_quic_endpoint(|| {
                            match &self.endpoint_factory {
                                Some(factory) => factory(ipv6),
                                None => client_endpoint_with_mtu(ipv6, self.mtu),
                            }
                        })
                        .with_context(|| format!("create QUIC endpoint (ipv6={ipv6})"))?;
                        if let Some(selection) = selection {
                            selection.selected_ip(server_addr.ip());
                        }
                        let conn = self
                            .handshake(&endpoint, server_addr, connect_timeout)
                            .await?;
                        // The race infers its error type from this block, and
                        // nothing else here names one; say `anyhow::Error` so
                        // the `?` conversions above have a single answer.
                        Ok::<_, anyhow::Error>((conn, endpoint, ipv6))
                    }
                })
                .await;
                let (conn, endpoint, ipv6) = match raced {
                    Some(result) => result?,
                    None => anyhow::bail!("resolve {host}: no addresses"),
                };
                (conn, DialEndpoint::Direct(endpoint), ipv6)
            }
        };
        state.dial_endpoint = Some(dial_endpoint.clone());
        let mut close_guard = ConnectionCloseGuard::new(conn.clone());
        let ctx = match setup(conn.clone()).await {
            Ok(ctx) => ctx,
            Err(error) => {
                close_guard.disarm();
                conn.close(VarInt::from_u32(0), b"setup failed");
                return Err(crate::proxy::quic_carrier_error(error));
            }
        };
        crate::runtime::flow_observation::milestone(
            crate::runtime::flow_observation::Milestone::TransportReady,
        );
        let ctx = Arc::new(ctx);
        if state.quality.is_some() {
            on_publish(ctx.as_ref(), &conn);
        }
        close_guard.disarm();
        let id = state.next_connection_id;
        state.next_connection_id = state.next_connection_id.wrapping_add(1).max(1);
        let owner = Arc::downgrade(&ctx);
        let monitor = Arc::new(spawn_quic_client_connection_monitor(
            conn.clone(),
            Arc::clone(&self.flow_control_profiles),
            ipv6,
            owner.clone(),
            state.quality.clone(),
        ));
        // The endpoint's driver tasks have to live as long as any connection
        // that reads through them, so a tracked connection takes its own claim.
        state.connections.push(TrackedConnection {
            id,
            connection: conn.clone(),
            _dial_endpoint: dial_endpoint.clone(),
            state: owner.clone(),
            monitor: Arc::clone(&monitor),
        });
        spawn_tracked_connection_cleanup(
            Arc::downgrade(&self.state),
            id,
            conn.clone(),
            owner,
            monitor,
        );
        state.conn = Some((conn.clone(), Arc::clone(&ctx)));
        Ok((conn, ctx))
    }

    /// Complete the QUIC handshake on an endpoint already pointed at
    /// `server_addr`.
    ///
    /// Retries stay inside one address job: the shared scheduler races
    /// addresses for this node, never protocol attempts or nodes.
    async fn handshake(
        &self,
        endpoint: &Endpoint,
        server_addr: SocketAddr,
        connect_timeout: Duration,
    ) -> anyhow::Result<Connection> {
        let mut last_error = None;
        for attempt in 1..=3u8 {
            let mut observation = crate::runtime::flow_observation::TransportAttempt::start(
                Some(server_addr),
                crate::runtime::flow_observation::ResolutionLocation::Unknown,
            );
            let connecting =
                match endpoint.connect_with(self.config.clone(), server_addr, &self.server_name) {
                    Ok(connecting) => connecting,
                    Err(error) => {
                        if let Some(observation) = observation.as_mut() {
                            observation.finish(
                            crate::runtime::flow_observation::TransportStatus::Failed,
                            Some(
                                crate::runtime::flow_observation::TransportError::QuicConnectFailed,
                            ),
                        );
                        }
                        return Err(error.into());
                    }
                };
            match tokio::time::timeout(connect_timeout, connecting).await {
                Err(_) => {
                    if let Some(observation) = observation.as_mut() {
                        observation.finish(crate::runtime::flow_observation::TransportStatus::Failed, Some(crate::runtime::flow_observation::TransportError::QuicConnectTimeout));
                    }
                    last_error = Some(anyhow!(
                        "QUIC connect to {server_addr} timed out (attempt {attempt})"
                    ));
                }
                Ok(Err(error)) => {
                    if let Some(observation) = observation.as_mut() {
                        observation.finish(
                            crate::runtime::flow_observation::TransportStatus::Failed,
                            Some(
                                crate::runtime::flow_observation::TransportError::QuicConnectFailed,
                            ),
                        );
                    }
                    last_error =
                        Some(
                            crate::proxy::NodeFailure(anyhow::Error::new(error).context(format!(
                                "QUIC connect to {server_addr} (attempt {attempt})"
                            )))
                            .into(),
                        );
                }
                Ok(Ok(connection)) => {
                    if let Some(observation) = observation.as_mut() {
                        observation.finish(
                            crate::runtime::flow_observation::TransportStatus::Succeeded,
                            None,
                        );
                    }
                    return Ok(connection);
                }
            }
        }
        Err(last_error.unwrap_or_else(|| anyhow!("QUIC connect to {server_addr} failed")))
    }

    /// Run QUIC over the framed UDP transport a detour hands back for
    /// `server_addr`.
    ///
    /// The transport is pinned to that one address and owned by the endpoint
    /// built on it. [`DialEndpoint::Fronted`] keeps that owner — and the
    /// adapter workers the socket reads and writes through — alive for as long
    /// as any connection uses it, and gives `force_close` one teardown path.
    ///
    /// The endpoint advertises [`FRONTED_UDP_PAYLOAD_SIZE`] rather than the
    /// conservative 1252-byte default. A detour hands back whole UDP
    /// datagrams inside the front node's *stream* transport (the stream is
    /// segmented by TCP, so the datagram itself is not shrunk), and real
    /// peers answer a 1200-byte Initial with a 1280-byte handshake flight.
    /// At 1252 the adapter has to drop that reply and the handshake stalls
    /// until its deadline. 1350 matches the cap MASQUE h3 detours already use.
    async fn detour_handshake(
        &self,
        detour: &crate::proxy::detour::DetourPath,
        server_addr: SocketAddr,
        selection: Option<&crate::runtime::flow_observation::LookupSelection>,
        connect_timeout: Duration,
    ) -> anyhow::Result<(Connection, DialEndpoint, bool)> {
        if let Some(selection) = selection {
            selection.selected_ip(server_addr.ip());
        }
        let transport = detour
            .connect_udp(
                server_addr,
                Some(self.server_host.as_str()),
                connect_timeout,
            )
            .await
            .with_context(|| crate::proxy::detour::udp_carry_context(server_addr))?;
        let transport = match &self.detour_transform {
            Some(transform) => transform(transport),
            None => transport,
        };
        let packet = Arc::new(
            crate::quic::packet_transport_endpoint_with_mtu(
                transport,
                server_addr,
                FRONTED_UDP_PAYLOAD_SIZE,
            )
            .with_context(|| crate::proxy::detour::quic_endpoint_context(server_addr))?,
        );
        // quinn reports `EndpointStopping` / a bare timeout when the adapter
        // workers die, hiding the datagram-level cause. Attach it here the
        // same way `quic_handshake_probe` does, while `packet` is alive.
        let conn = match self
            .handshake(packet.endpoint(), server_addr, connect_timeout)
            .await
        {
            Ok(conn) => conn,
            Err(error) => {
                return Err(match packet.terminal_error() {
                    Some(cause) => error
                        .context(crate::proxy::detour::transport_error_context(cause)),
                    None => error,
                });
            }
        };
        Ok((conn, DialEndpoint::Fronted(packet), server_addr.is_ipv6()))
    }

    /// Drop the cached connection if it is `conn`, forcing the next
    /// [`connection_with`](Self::connection_with) call to re-dial. Used when a
    /// stream operation fails on a half-dead connection.
    pub async fn invalidate(&self, conn: &Connection) {
        let mut state = self.state.lock().await;
        if let Some((cached, _)) = &state.conn
            && cached.stable_id() == conn.stable_id()
        {
            state.conn = None;
        }
        state.prune_connections();
    }

    /// Release the reusable holder without closing flows that already own
    /// connection/state clones. A later dial may rebuild this client.
    pub async fn release_cached(&self) {
        let mut state = self.state.lock().await;
        state.conn = None;
        state.dial_endpoint = None;
        state.prune_connections();
    }

    /// Close the cached connection and the latest dial's endpoint, terminating every flow that
    /// still owns a connection clone, and reject future dials. Awaits an
    /// in-flight dial's single-flight section so its late connection is also
    /// closed; a try-lock skip would leak that connection and endpoint driver.
    pub async fn force_close(&self) {
        let dial_endpoint = {
            let mut state = self.state.lock().await;
            state.closed = true;
            state.conn = None;
            for tracked in state.connections.drain(..) {
                tracked
                    .connection
                    .close(VarInt::from_u32(0), b"generation shutdown");
            }
            state.dial_endpoint.take()
        };
        // One owner, one teardown: a fronted endpoint belongs to the
        // `PacketTransportEndpoint`, a direct one to its `RuntimeEndpoint`.
        match dial_endpoint {
            Some(DialEndpoint::Fronted(packet)) => {
                // `close` reports whether the adapter drivers joined cleanly;
                // at zero grace it only signals quinn, so discard the flag.
                let _ = packet.close(Duration::ZERO).await;
            }
            Some(DialEndpoint::Direct(endpoint)) => {
                endpoint.close(VarInt::from_u32(0), b"generation shutdown")
            }
            None => {}
        }
    }
}
