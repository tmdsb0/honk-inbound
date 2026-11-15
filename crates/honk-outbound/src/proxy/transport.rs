//! Shared stream-transport helpers for proxy handlers.
//!
//! Trojan, VMess and VLESS all wrap their connections in the same order:
//!
//! ```text
//! TCP -> (TLS/REALITY) -> (WebSocket | gRPC | XHTTP) -> protocol header
//! ```
//!
//! This module provides the reusable pieces so each handler only implements
//! its own protocol handshake:
//!
//! - [`wrap_transport`]: cold or supplied TCP/TLS wrapping, including one-shot XHTTP,
//! - [`wrap_transport_runtime`]: XHTTP physical reuse owned by the node generation,
//! - [`maybe_tls_wrap`]: just the TCP/TLS step, preserving the same setup budget.
//! - [`grpc`]: gRPC gun framing over a connection-owned HTTP/2 client.
//! - [`xhttp`]: raw XHTTP bodies over bounded node-owned HTTP/2 carriers.

use futures_util::{SinkExt, StreamExt};
use honk_config::node::Node;
use percent_encoding::{AsciiSet, CONTROLS, PercentEncode, utf8_percent_encode};
use tokio::net::TcpStream;

use crate::proxy::transport::grpc::wrap_grpc;

use super::AsyncReadWrite;
use crate::proxy::detour::DetourPath;
use crate::transport_quality::tcp::{Carrier, ObservedTcp};

/// The node's server as a `host:port` literal, bracketed when it is IPv6.
pub(crate) fn endpoint_address(node: &Node) -> String {
    let host = node.host();
    if host.contains(':') {
        format!("[{host}]:{}", node.port)
    } else {
        format!("{}:{}", host, node.port)
    }
}

pub(crate) struct TransportPreparation(Option<xhttp::XhttpPreparation>);

impl TransportPreparation {
    pub(crate) fn none() -> Self {
        Self(None)
    }

    pub(crate) fn commit(self) -> anyhow::Result<()> {
        self.0.map_or(Ok(()), xhttp::XhttpPreparation::commit)
    }
}

pub(crate) async fn write_request<W: tokio::io::AsyncWrite + Unpin + ?Sized>(
    stream: &mut W,
    request: &[u8],
) -> std::io::Result<()> {
    use tokio::io::AsyncWriteExt;
    let write = async {
        stream.write_all(request).await?;
        stream.flush().await
    };
    crate::runtime::flow_observation::request_write(std::pin::pin!(write)).await
}

/// Connect if needed, then apply TLS and `node.transport` wrapping.
pub(crate) async fn wrap_transport(
    node: &Node,
    tcp: Option<TcpStream>,
    connect_timeout: std::time::Duration,
    detour: Option<&DetourPath>,
) -> anyhow::Result<Box<dyn AsyncReadWrite>> {
    if node.is_xhttp() {
        let owner = crate::runtime::NodeRuntime::try_ephemeral_guarded(node)?;
        let runtime = owner.runtime();
        let stream = wrap_transport_runtime(&runtime, tcp, connect_timeout, detour).await?;
        return Ok(Box::new(crate::proxy::RuntimeOwnedIo {
            inner: stream,
            _owner: owner,
        }));
    }
    let stream = maybe_tls_wrap(node, tcp, connect_timeout, detour).await?;
    wrap_after_tls(node, stream).await
}

/// Reuse the node-owned physical H2 pool, not a pool of logical protocol streams.
pub(crate) async fn wrap_transport_runtime(
    runtime: &std::sync::Arc<crate::runtime::NodeRuntime>,
    tcp: Option<TcpStream>,
    connect_timeout: std::time::Duration,
    detour: Option<&DetourPath>,
) -> anyhow::Result<Box<dyn AsyncReadWrite>> {
    let (stream, preparation) =
        prepare_transport_runtime(runtime, tcp, connect_timeout, detour).await?;
    preparation.commit()?;
    Ok(stream)
}

/// Caller-owned preparation: unpublished XHTTP carriers roll back unless the
/// selected UDP candidate commits them through its existing preparation fence.
pub(crate) async fn prepare_transport_runtime(
    runtime: &std::sync::Arc<crate::runtime::NodeRuntime>,
    tcp: Option<TcpStream>,
    connect_timeout: std::time::Duration,
    detour: Option<&DetourPath>,
) -> anyhow::Result<(Box<dyn AsyncReadWrite>, TransportPreparation)> {
    if let Some(xhttp) = &runtime.xhttp {
        let (stream, preparation) = xhttp.prepare(runtime, tcp, connect_timeout).await?;
        return Ok((stream, TransportPreparation(Some(preparation))));
    }
    let stream = maybe_tls_wrap(&runtime.node, tcp, connect_timeout, detour).await?;
    Ok((
        wrap_after_tls(&runtime.node, stream).await?,
        TransportPreparation::none(),
    ))
}

pub(crate) async fn wrap_after_tls(
    node: &Node,
    stream: Box<dyn AsyncReadWrite>,
) -> anyhow::Result<Box<dyn AsyncReadWrite>> {
    match node.transport().unwrap().transport.as_str() {
        "" | "tcp" => Ok(stream), // raw TCP/TLS
        "ws" => wrap_ws(node, stream).await,
        "grpc" => wrap_grpc(node, stream).await,
        // Unknown transport must not silently degrade to raw TCP — a
        // mistyped transport means a different protocol than intended.
        other => anyhow::bail!(
            "node '{}': unsupported transport '{}' (expected tcp/ws/grpc; xhttp requires its runtime)",
            node.name,
            other
        ),
    }
}

/// Connect if needed and apply TLS or authenticated REALITY. `None` identifies
/// a cold dial whose admission may be reused after dropping its failed socket;
/// a supplied socket always needs fresh admission for a replacement.
///
/// `detour` carries the connection through another node when the node names
/// one. It wins over a supplied socket: a node on a detour has no business
/// holding a socket of its own.
pub(crate) async fn maybe_tls_wrap(
    node: &Node,
    tcp: Option<TcpStream>,
    connect_timeout: std::time::Duration,
    detour: Option<&DetourPath>,
) -> anyhow::Result<Box<dyn AsyncReadWrite>> {
    match maybe_tls_wrap_concrete(node, tcp, connect_timeout, detour).await? {
        MaybeTls::Tls(stream) => Ok(Box::new(crate::tls::BatchRead::new(stream))),
        MaybeTls::Plain(stream) => Ok(stream),
    }
}

/// [`maybe_tls_wrap`] without erasing the concrete stream type: the XTLS
/// Vision direct-copy switch must reach the raw TCP socket under the TLS
/// stream once the server abandons the outer TLS session.
pub(crate) enum MaybeTls {
    Tls(crate::tls::TlsStream<ObservedTcp>),
    Plain(Box<ObservedTcp>),
}

pub(crate) async fn maybe_tls_wrap_concrete(
    node: &Node,
    tcp: Option<TcpStream>,
    connect_timeout: std::time::Duration,
    detour: Option<&DetourPath>,
) -> anyhow::Result<MaybeTls> {
    let tls = node.tls().unwrap();
    if !tls.alpn.is_empty() {
        node.validate_protocol()?;
    }
    let cold = tcp.is_none();
    // A node that names a detour must ride it. Dialling the direct path
    // because the binding is missing would send its traffic out of the real
    // interface while looking like a normal connection.
    crate::proxy::detour::ensure_bound(node, detour)?;
    let address = endpoint_address(node);
    let initial_tcp = async {
        if let Some(path) = detour {
            let endpoint = crate::proxy::detour::resolve_endpoint(&address).await?;
            let stream = path
                .connect(endpoint, connect_timeout)
                .await
                .map_err(|error| {
                    anyhow::anyhow!(
                        "node {}: detour could not reach {address}: {error}",
                        node.name
                    )
                })?;
            // The block's error type has to be pinned here: the detour dial
            // returns before the surrounding `?` conversions have anything to
            // unify against.
            return Ok::<_, anyhow::Error>(Carrier::Chained(stream));
        }
        match tcp {
            Some(tcp) => {
                if let Some(observer) = crate::runtime::flow_observation::current() {
                    observer.publish(
                        crate::runtime::flow_observation::FlowEvent::TransportAttached {
                            server_addr: tcp.peer_addr().ok(),
                            resolution_location:
                                crate::runtime::flow_observation::ResolutionLocation::Unknown,
                        },
                    );
                }
                Ok(Carrier::Socket(tcp))
            }
            None => Ok(Carrier::Socket(
                crate::util::connect_outbound(&address, connect_timeout).await?,
            )),
        }
    };
    if let Some(reality) = crate::reality::parse_reality_config(node)? {
        let deadline = tokio::time::Instant::now() + connect_timeout * 3;
        let alpn = node.is_xhttp().then_some(b"\x02h2".as_slice());
        let setup = async {
            let tcp = initial_tcp.await?;
            // A detour hands back a chained carrier (a byte stream), not a
            // socket, so `peer_addr()` cannot answer. The re-dial target is
            // the endpoint `initial_tcp` already resolved and dialled; using
            // it keeps the replacement handshake on exactly the same fronted
            // path instead of leaking out of the real interface.
            let peer = if detour.is_some() {
                crate::proxy::detour::resolve_endpoint(&address).await?
            } else {
                tcp.peer_addr()?
            };
            let tcp = ObservedTcp::new_carrier(tcp);
            let chrome = crate::tls::chrome_mode();
            let mut tls_stream = match crate::reality::reality_connect_with_key_shares(
                tcp, &reality, chrome, true, alpn,
            )
            .await
            {
                Ok(stream) => stream,
                Err(error) if error.is::<crate::reality::RealityMaskCertificate>() => {
                    // The failed handshake has dropped its SSL/TCP before admission
                    // transfers. Supplied sockets cannot spend another dial's credit.
                    let replacement = async {
                        let remaining =
                            deadline.saturating_duration_since(tokio::time::Instant::now());
                        if remaining.is_zero() {
                            return Err(std::io::Error::new(
                                std::io::ErrorKind::TimedOut,
                                "REALITY setup timeout",
                            )
                            .into());
                        }
                        let budget = connect_timeout.min(remaining);
                        // The re-dial is the same peer over the same path.
                        // With a detour that means through the detour: a
                        // direct socket here would be the leak the detour
                        // exists to prevent, and it would happen exactly when
                        // the handshake looks most suspicious.
                        let tcp = match detour {
                            Some(path) => ObservedTcp::new_carrier(
                                crate::transport_quality::tcp::Carrier::Chained(
                                    path.connect(peer, budget).await.map_err(|error| {
                                        std::io::Error::other(format!(
                                            "node {}: detour could not re-dial {peer}: {error}",
                                            node.name
                                        ))
                                    })?,
                                ),
                            ),
                            None => ObservedTcp::new(
                                crate::util::connect_marked_addr(
                                    peer,
                                    Some(crate::util::bypass_mark()),
                                    budget,
                                )
                                .await?,
                            ),
                        };
                        crate::reality::reality_connect_with_key_shares(
                            tcp, &reality, chrome, false, alpn,
                        )
                        .await
                    };
                    crate::runtime::admit_replacement_dial(replacement, cold).await?
                }
                Err(error) => return Err(error),
            };
            // Xray REALITY omits server ALPN; XHTTP selects H2 after authentication.
            tls_stream.get_mut().activate();
            crate::runtime::flow_observation::milestone(
                crate::runtime::flow_observation::Milestone::TransportReady,
            );
            Ok(MaybeTls::Tls(tls_stream))
        };
        return tokio::time::timeout_at(deadline, setup)
            .await
            .map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::TimedOut, "REALITY setup timeout")
            })?;
    }
    let mut tcp = ObservedTcp::new_carrier(initial_tcp.await?);
    if tls.enabled {
        let connector = crate::tls::build_connector(node)?;
        let server_name = tls.sni.clone().unwrap_or_else(|| node.host().to_string());
        let mut tls_stream = connector.connect(&server_name, tcp).await?;
        if node.is_xhttp() {
            anyhow::ensure!(
                tls_stream.ssl().selected_alpn_protocol() == Some(b"h2"),
                "XHTTP requires negotiated h2 ALPN"
            );
        }
        tls_stream.get_mut().activate();
        crate::runtime::flow_observation::milestone(
            crate::runtime::flow_observation::Milestone::TransportReady,
        );
        return Ok(MaybeTls::Tls(tls_stream));
    }
    tcp.activate();
    crate::runtime::flow_observation::milestone(
        crate::runtime::flow_observation::Milestone::TransportReady,
    );
    Ok(MaybeTls::Plain(Box::new(tcp)))
}

fn encode_uri_path(path: &str) -> PercentEncode<'_> {
    // Paths may already contain escapes and query delimiters; preserve both.
    const ENCODE_SET: &AsciiSet = &CONTROLS
        .add(b' ')
        .add(b'"')
        .add(b'<')
        .add(b'>')
        .add(b'`')
        .add(b'{')
        .add(b'}')
        .add(b'|')
        .add(b'\\')
        .add(b'^');
    utf8_percent_encode(path, ENCODE_SET)
}

/// Upgrade an already-connected (optionally TLS-wrapped) stream to
/// WebSocket, then bridge through a duplex so the caller gets a
/// plain `AsyncRead + AsyncWrite` handle.
async fn wrap_ws(
    node: &Node,
    stream: Box<dyn AsyncReadWrite>,
) -> anyhow::Result<Box<dyn AsyncReadWrite>> {
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;

    let transport = node.transport().unwrap();
    let ws_path = transport.ws_path.as_deref().unwrap_or("/");

    // Build the request from the URI so tungstenite generates the full
    // handshake header set (Sec-WebSocket-Key, Upgrade, ...); a bare
    // `http::Request` passed to `client_async` is sent as-is and real
    // servers reject the missing key. A bare IPv6 literal must be
    // bracketed in the authority, or the URI parses as an invalid host.
    // Strip any brackets first: share links parse through `url::Url`,
    // which already returns bare literals, but a hand-written config or
    // another provider may carry them.
    let host = node.host().trim_start_matches('[').trim_end_matches(']');
    let authority = if host.contains(':') {
        format!("[{host}]:{}", node.port)
    } else {
        format!("{host}:{}", node.port)
    };
    let uri = format!("ws://{authority}{}", encode_uri_path(ws_path));
    let mut request = uri
        .into_client_request()
        .map_err(|e| anyhow::anyhow!("WebSocket request build failed: {}", e))?;
    // The handshake Host is the endpoint host (no port) unless the operator
    // configured an explicit ws host; a bare IPv6 literal must be bracketed
    // here too, or the header value is an invalid authority.
    let ws_host = transport
        .ws_host
        .as_deref()
        .map(|h| h.trim_start_matches('[').trim_end_matches(']').to_string())
        .unwrap_or_else(|| host.to_string());
    let ws_host = if ws_host.contains(':') {
        format!("[{ws_host}]")
    } else {
        ws_host
    };
    request.headers_mut().insert(
        tokio_tungstenite::tungstenite::http::header::HOST,
        ws_host
            .parse()
            .map_err(|e| anyhow::anyhow!("invalid WebSocket host header: {}", e))?,
    );

    let (ws_stream, _response) = tokio_tungstenite::client_async(request, stream)
        .await
        .map_err(|e| anyhow::anyhow!("WebSocket upgrade failed: {}", e))?;

    // The duplex half is a genuine in-flight buffer: the bridge writer drains
    // it while the relay keeps filling it, so `capacity / RTT` does bound a
    // single flow here. That is unlike the relay copy chunk, which is a serial
    // read/write loop and gains nothing from being larger than one frame.
    let capacity = honk_config::tuning::relay_buf_size();
    let (client_half, server_half) = tokio::io::duplex(capacity);
    let progress = crate::runtime::flow_observation::current()
        .map(|_| std::sync::Arc::new(parking_lot::Mutex::new(WsWriteProgress::default())));

    let _ = crate::runtime::spawn_owned(ws_bridge_relay(ws_stream, server_half, progress.clone()));

    if let Some(progress) = progress {
        return Ok(Box::new(ObservedWs {
            inner: client_half,
            progress,
        }));
    }
    Ok(Box::new(client_half))
}

#[derive(Debug, Default)]
struct WsWriteProgress {
    accepted: u64,
    flushed: u64,
    request: Option<(crate::runtime::flow_observation::RequestWrite, u64)>,
}

#[derive(Debug)]
struct ObservedWs {
    inner: tokio::io::DuplexStream,
    progress: std::sync::Arc<parking_lot::Mutex<WsWriteProgress>>,
}

impl tokio::io::AsyncRead for ObservedWs {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl tokio::io::AsyncWrite for ObservedWs {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        let mut progress = this.progress.lock();
        let result = std::pin::Pin::new(&mut this.inner).poll_write(cx, buf);
        if let std::task::Poll::Ready(Ok(size)) = result {
            progress.accepted += size as u64;
            if size != 0
                && let Some(request) = crate::runtime::flow_observation::RequestWrite::current()
            {
                request.defer(progress.accepted);
                progress.request = Some((request, progress.accepted));
            }
        }
        result
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Background task that bridges a WebSocket stream to a duplex half.
/// Reads binary/text messages from the WebSocket and writes them to
/// the duplex; reads from the duplex and sends as binary WebSocket
/// messages.
async fn ws_bridge_relay(
    ws: tokio_tungstenite::WebSocketStream<Box<dyn AsyncReadWrite>>,
    server: tokio::io::DuplexStream,
    progress: Option<std::sync::Arc<parking_lot::Mutex<WsWriteProgress>>>,
) {
    let (mut ws_sink, mut ws_stream) = ws.split();
    let (mut server_read, mut server_write) = tokio::io::split(server);

    // server → ws
    let s2w = async {
        // One frame per read: this buffer is copied again into the outgoing
        // `Message`, so keeping it at one protocol frame bounds both the
        // per-flow allocation and the copy volume.
        let mut buf = vec![0u8; honk_config::tuning::relay_copy_chunk()];
        loop {
            use tokio::io::AsyncReadExt;
            let n = server_read
                .read(&mut buf)
                .await
                .map_err(|e| anyhow::anyhow!("ws bridge server read: {}", e))?;
            if n == 0 {
                break;
            }
            ws_sink
                .send(tokio_tungstenite::tungstenite::Message::Binary(
                    buf[..n].to_vec().into(),
                ))
                .await
                .map_err(|e| anyhow::anyhow!("ws bridge send: {}", e))?;
            if let Some(progress) = &progress {
                let delivered = {
                    let mut progress = progress.lock();
                    progress.flushed += n as u64;
                    progress
                        .request
                        .as_ref()
                        .filter(|(_, end)| *end <= progress.flushed)
                        .map(|(request, _)| (request.clone(), progress.flushed))
                };
                if let Some((request, position)) = delivered {
                    request.delivered(position);
                }
            }
        }
        let _ = ws_sink.close().await;
        Ok::<_, anyhow::Error>(())
    };

    // ws → server
    let w2s = async {
        loop {
            let msg = ws_stream.next().await;
            match msg {
                Some(Ok(tokio_tungstenite::tungstenite::Message::Binary(data))) => {
                    use tokio::io::AsyncWriteExt;
                    server_write.write_all(&data).await?;
                }
                Some(Ok(tokio_tungstenite::tungstenite::Message::Text(data))) => {
                    use tokio::io::AsyncWriteExt;
                    server_write.write_all(data.as_bytes()).await?;
                }
                Some(Ok(
                    tokio_tungstenite::tungstenite::Message::Close(_)
                    | tokio_tungstenite::tungstenite::Message::Ping(_)
                    | tokio_tungstenite::tungstenite::Message::Pong(_),
                )) => {}
                Some(Ok(tokio_tungstenite::tungstenite::Message::Frame(_))) => {}
                Some(Err(e)) => {
                    tracing::debug!("ws bridge recv error: {}", e);
                    break;
                }
                None => break,
            }
        }
        Ok::<_, anyhow::Error>(())
    };

    tokio::select! {
        r = s2w => { let _ = r; },
        r = w2s => { let _ = r; },
    }
}

mod grpc;
mod h2_io;
#[cfg(test)]
mod tests;
pub(crate) mod xhttp;
