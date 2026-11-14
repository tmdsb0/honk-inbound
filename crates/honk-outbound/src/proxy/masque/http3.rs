//! MASQUE connect-ip carrier over HTTP/3 (Cloudflare WARP / Zero Trust).
//!
//! WARP does **not** implement RFC 9484 verbatim. The differences that matter
//! here are all dictated by the deployed endpoints and mirrored by `usque` and
//! mihomo:
//!
//! * the extended CONNECT uses `:protocol = cf-connect-ip`, not the standard
//!   `connect-ip` (the latter is answered with 400), and goes to
//!   `https://cloudflareaccess.com/` rather than a well-known MASQUE path;
//! * the TLS handshake skips PKI: the SNI is a decoy, the device authenticates
//!   with a self-signed client certificate, and the edge is authenticated by
//!   pinning its public key;
//! * the edge sends neither ADDRESS_ASSIGN nor ROUTE_ADVERTISEMENT — waiting
//!   for one stalls forever, so the tunnel addresses come from the node's
//!   `ip` / `ipv6` settings;
//! * IP packets ride in QUIC DATAGRAM frames as
//!   `varint(Quarter Stream ID) || varint(Context ID = 0) || IP packet`.
//!   There is no DATAGRAM capsule here; that framing is the HTTP/2 carrier's.
//!
//! A WARP QUIC DATAGRAM's leading `0x00` is the Context ID, while an HTTP/2
//! DATAGRAM capsule's leading `0x00` is the capsule type. They are unrelated.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use boring::pkey::PKey;
use bytes::{Bytes, BytesMut};
use h3::client::SendRequest;
use h3::ext::Protocol;
use h3_quinn::Connection as H3QuinnConnection;
use honk_config::node::Node;
use quinn::{ClientConfig, TransportConfig, VarInt};

use crate::quic::boring::{BoringQuicClientConfig, BoringQuicOptions};

use super::capsule::{put_varint, read_varint};
use super::device::{TunnelBackend, TunnelDevice};
use super::tunnel::{LivenessGuard, MasqueTunnel};
use super::warp::{self, DEFAULT_SNI};

/// Authority of the WARP CONNECT-IP request. The edge answers on its Access
/// host regardless of which anycast address handled the QUIC connection.
const CONNECT_AUTHORITY: &str = "cloudflareaccess.com";

/// WARP's private extended CONNECT protocol identifier.
const WARP_PROTOCOL: Protocol = Protocol::CF_CONNECT_IP;

/// ALPN wire format for a single `h3` protocol.
const ALPN_H3_WIRE: &[u8] = b"\x02h3";

/// UDP payload size advertised to the edge. WARP endpoints carry 1280-byte IP
/// packets plus QUIC/H3 overhead, so quinn's conservative 1252 default would
/// cap path MTU growth below the tunnel MTU.
const MAX_UDP_PAYLOAD_SIZE: u16 = 1350;

/// DATAGRAM receive buffer. quinn advertises this as
/// `max_datagram_frame_size`, capped at `u16::MAX`.
const DATAGRAM_BUFFER_SIZE: usize = 1024 * 1024;

/// QUIC DATAGRAM context ID reserved for IP payloads (RFC 9484 section 5).
const IP_CONTEXT_ID: u64 = 0;

/// The CONNECT stream is the connection's first client-initiated bidirectional
/// stream: HTTP/3 control and QPACK streams are unidirectional, so its stream
/// ID is 0 and the Quarter Stream ID (`stream_id / 4`) is also 0.
const CONNECT_FLOW_ID: u64 = 0;

/// Open a WARP connect-ip tunnel over HTTP/3.
///
/// `endpoint` is already resolved by the caller. WARP's QUIC carrier has no
/// detour support yet: a QUIC endpoint needs a UDP socket, while `DetourPath`
/// hands out a TCP stream, so the caller rejects a detoured h3 node instead of
/// silently dialling direct.
pub async fn open_h3(
    node: &Node,
    endpoint: SocketAddr,
    connect_timeout: Duration,
    mtu: u32,
    tun_name: &str,
    preferred: &[IpAddr],
    slot: usize,
    backend: TunnelBackend,
) -> anyhow::Result<MasqueTunnel> {
    let config = node
        .masque()
        .ok_or_else(|| anyhow::anyhow!("masque node {} has no masque config", node.name))?;

    // WARP never assigns addresses, so a node without `ip` / `ipv6` cannot
    // build a usable tunnel. Failing here is better than a tunnel that comes
    // up with no source address and drops every packet.
    if preferred.is_empty() {
        anyhow::bail!(
            "masque node {}: HTTP/3 WARP endpoints do not send ADDRESS_ASSIGN; \
             configure `ip` or `ipv6`",
            node.name
        );
    }

    let (alive, shutdown, shutdown_signal) = MasqueTunnel::liveness();
    let tun_label = tun_name.to_string();

    let client = build_client_config(node)?;
    let quinn_endpoint =
        crate::quic::client_endpoint_with_mtu(endpoint.is_ipv6(), MAX_UDP_PAYLOAD_SIZE)?;
    let sni = config
        .tls
        .sni
        .clone()
        .unwrap_or_else(|| DEFAULT_SNI.to_string());
    let connecting = quinn_endpoint
        .connect_with(client, endpoint, &sni)
        .map_err(|error| anyhow::anyhow!("masque node {}: QUIC connect failed: {error}", node.name))?;
    let connection = tokio::time::timeout(connect_timeout, connecting)
        .await
        .map_err(|_| {
            anyhow::anyhow!(
                "masque node {}: QUIC handshake to {endpoint} timed out after {connect_timeout:?}",
                node.name
            )
        })??;
    tracing::debug!(
        "masque: QUIC to {endpoint} established (sni {sni}) on {tun_name}"
    );

    // WARP's edge does not advertise SETTINGS_ENABLE_CONNECT_PROTOCOL, so the
    // client has to enable both settings itself and not gate on the peer's.
    let mut builder = h3::client::builder();
    builder.enable_extended_connect(true);
    builder.enable_datagram(true);
    let (mut driver, mut sender): (_, SendRequest<h3_quinn::OpenStreams, Bytes>) = builder
        .build(H3QuinnConnection::new(connection.clone()))
        .await
        .map_err(|error| {
            anyhow::anyhow!("masque node {}: HTTP/3 handshake failed: {error}", node.name)
        })?;

    let mut request = http::Request::builder()
        .method(http::Method::CONNECT)
        .uri(format!("https://{CONNECT_AUTHORITY}/"))
        .header("capsule-protocol", "?1")
        .header("user-agent", "")
        .body(())?;
    // h3 reads the `:protocol` pseudo-header from the request's extensions.
    request.extensions_mut().insert(WARP_PROTOCOL);
    let mut request_stream = sender.send_request(request).await.map_err(|error| {
        anyhow::anyhow!("masque node {}: CONNECT-IP request failed: {error}", node.name)
    })?;
    let response = request_stream.recv_response().await.map_err(|error| {
        anyhow::anyhow!("masque node {}: CONNECT-IP response failed: {error}", node.name)
    })?;
    let status = response.status();
    tracing::debug!("masque: connect-ip on {tun_name} answered {status} over h3");
    if !status.is_success() {
        anyhow::bail!(
            "masque node {}: endpoint rejected cf-connect-ip with status {status}",
            node.name
        );
    }

    let device = TunnelDevice::create(backend, tun_name, preferred, mtu, slot)?;

    // TUN -> endpoint. Each IP packet becomes one QUIC DATAGRAM.
    let upstream_tun = device.clone();
    let upstream_conn = connection.clone();
    let upstream_alive = LivenessGuard::new(Arc::clone(&alive));
    let upstream_shutdown = shutdown.clone();
    let mut upstream_signal = shutdown_signal.clone();
    let upstream_label = tun_label.clone();
    tokio::spawn(async move {
        let _alive = upstream_alive;
        let mut packet = vec![0u8; mtu as usize];
        let mut packets = 0usize;
        loop {
            let outcome = {
                let read = upstream_tun.recv_packet(&mut packet);
                tokio::pin!(read);
                tokio::select! {
                    result = &mut read => result,
                    _ = upstream_signal.changed() => break,
                }
            };
            match outcome {
                Ok(0) => break,
                Ok(length) => {
                    packets += 1;
                    if packets == 1 {
                        tracing::debug!(
                            "masque: first packet to {upstream_label}: {length} bytes (h3)"
                        );
                    }
                    let datagram = encode_ip_datagram(&packet[..length]);
                    if let Err(error) = upstream_conn.send_datagram(datagram) {
                        tracing::debug!("masque h3 datagram send failed: {error}");
                        break;
                    }
                }
                Err(error) => {
                    tracing::debug!("masque packet device read failed: {error}");
                    break;
                }
            }
        }
        let _ = upstream_shutdown.send(true);
    });

    // Endpoint -> TUN. QUIC DATAGRAMs arrive whole, so unlike the HTTP/2
    // carrier there is no stream buffer and no flow control to release.
    let downstream_tun = device.clone();
    let downstream_conn = connection.clone();
    let downstream_alive = LivenessGuard::new(Arc::clone(&alive));
    let downstream_shutdown = shutdown.clone();
    let mut downstream_signal = shutdown_signal.clone();
    let downstream_label = tun_label.clone();
    tokio::spawn(async move {
        let _alive = downstream_alive;
        let mut packets = 0usize;
        loop {
            let next = downstream_conn.read_datagram();
            tokio::pin!(next);
            let datagram = tokio::select! {
                result = &mut next => result,
                _ = downstream_signal.changed() => break,
            };
            let datagram = match datagram {
                Ok(datagram) => datagram,
                Err(error) => {
                    tracing::debug!("masque h3 datagram read failed: {error}");
                    break;
                }
            };
            let Some(packet) = decode_ip_datagram(datagram) else {
                continue;
            };
            packets += 1;
            if packets == 1 {
                tracing::debug!(
                    "masque: first packet from {downstream_label}: {} bytes (h3)",
                    packet.len()
                );
            }
            if let Err(error) = downstream_tun.send_packet(&packet).await {
                tracing::debug!("masque packet device write failed: {error}");
                let _ = downstream_shutdown.send(true);
                return;
            }
        }
        let _ = downstream_shutdown.send(true);
    });

    // The HTTP/3 driver, the QUIC endpoint, the request handle and the CONNECT
    // stream all have to outlive the tunnel: dropping the endpoint closes the
    // connection, and dropping the CONNECT stream resets the tunnel. Park them
    // in one task that also runs the driver to completion.
    let park_alive = Arc::clone(&alive);
    let park_shutdown = shutdown.clone();
    let mut park_signal = shutdown_signal.clone();
    tokio::spawn(async move {
        let _endpoint = quinn_endpoint;
        let _sender = sender;
        let _request_stream = request_stream;
        let driver_closed = async {
            let error = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
            tracing::debug!("masque h3 connection closed: {error}");
        };
        tokio::select! {
            _ = driver_closed => {}
            _ = park_signal.changed() => {}
        }
        park_alive.store(false, Ordering::Relaxed);
        let _ = park_shutdown.send(true);
    });

    Ok(MasqueTunnel::new(
        device,
        preferred.to_vec(),
        alive,
        shutdown,
    ))
}

/// Assemble the QUIC TLS config WARP expects: ALPN `h3`, the device client
/// certificate, and a public-key pin instead of PKI verification.
fn build_client_config(node: &Node) -> anyhow::Result<ClientConfig> {
    let config = node
        .masque()
        .ok_or_else(|| anyhow::anyhow!("masque node {} has no masque config", node.name))?;
    let private_key = config.private_key.as_deref().ok_or_else(|| {
        anyhow::anyhow!(
            "masque node {} has no private-key; WARP authenticates the device with a \
             client certificate",
            node.name
        )
    })?;
    let device = PKey::private_key_from_der(&warp::decode_base64(private_key, "private-key")?)?;
    let certificate = warp::self_signed(&device)?;
    let pinned = match config.endpoint_public_key.as_deref() {
        Some(key) => Some(PKey::public_key_from_der(&warp::decode_base64(key, "public-key")?)?),
        None => {
            tracing::warn!(
                "masque node {}: no public-key, so the QUIC endpoint is not pinned",
                node.name
            );
            None
        }
    };

    let crypto = BoringQuicClientConfig::new(BoringQuicOptions {
        alpn_wire: ALPN_H3_WIRE.to_vec(),
        // With a pin, the custom verify callback replaces PKI. Without one the
        // SNI is still a decoy, so certificate verification has to be skipped.
        skip_cert_verify: pinned.is_none(),
        chrome: false,
        ech_config_list: None,
        pin_sha256: None,
        client_certificate: Some(certificate),
        client_private_key: Some(device),
        endpoint_public_key: pinned,
        // A pinned endpoint must never resume: a PSK would skip the pin.
        ticket_key: None,
    })?;
    let mut client = ClientConfig::new(Arc::new(crypto));
    let mut transport = TransportConfig::default();
    transport.datagram_receive_buffer_size(Some(DATAGRAM_BUFFER_SIZE));
    transport.max_concurrent_uni_streams(VarInt::from_u32(3));
    transport.keep_alive_interval(Some(Duration::from_secs(15)));
    client.transport_config(Arc::new(transport));
    Ok(client)
}

/// Wrap an IP packet in an HTTP/3 DATAGRAM payload:
/// `varint(Quarter Stream ID) || varint(Context ID = 0) || IP packet`.
fn encode_ip_datagram(packet: &[u8]) -> Bytes {
    let mut buf = BytesMut::with_capacity(packet.len() + 4);
    put_varint(&mut buf, CONNECT_FLOW_ID);
    put_varint(&mut buf, IP_CONTEXT_ID);
    buf.extend_from_slice(packet);
    buf.freeze()
}

/// Unwrap one HTTP/3 DATAGRAM, checking both identifiers before handing the
/// remaining bytes to the TUN device. Datagrams for another flow or context
/// are dropped, not treated as IP packets.
fn decode_ip_datagram(datagram: Bytes) -> Option<Bytes> {
    let mut cursor: &[u8] = &datagram;
    let flow_id = read_varint(&mut cursor)?;
    if flow_id != CONNECT_FLOW_ID {
        tracing::trace!("masque h3: dropping datagram for flow {flow_id}");
        return None;
    }
    let context_id = read_varint(&mut cursor)?;
    if context_id != IP_CONTEXT_ID {
        tracing::trace!("masque h3: dropping datagram for context {context_id}");
        return None;
    }
    if cursor.is_empty() {
        return None;
    }
    // quinn already hands us a refcounted buffer. Slice the two IDs off the
    // front instead of copying the whole IP packet a second time on the
    // downstream path of every datagram.
    let header_len = datagram.len() - cursor.len();
    Some(datagram.slice(header_len..))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ip_datagram_round_trips_with_both_ids() {
        let packet: Vec<u8> = b"\x45\x00\x00\x14test-payload".to_vec();
        let encoded = encode_ip_datagram(&packet);
        // flow id 0, context id 0, then the packet verbatim.
        assert_eq!(&encoded[..2], b"\x00\x00");
        assert_eq!(
            decode_ip_datagram(encoded.clone()).unwrap().as_ref(),
            packet.as_slice()
        );
    }

    #[test]
    fn datagram_without_capsule_wrapper() {
        // The HTTP/2 carrier wraps packets in a DATAGRAM capsule. HTTP/3 must
        // not: there is no type/length header, only the two IDs.
        let packet = b"\x45\x00\x00\x14";
        let encoded = encode_ip_datagram(packet);
        assert_eq!(&encoded[..], b"\x00\x00\x45\x00\x00\x14");
    }

    #[test]
    fn foreign_flow_or_context_is_dropped() {
        let mut wrong_flow = BytesMut::new();
        put_varint(&mut wrong_flow, 1);
        put_varint(&mut wrong_flow, 0);
        wrong_flow.extend_from_slice(b"\x45\x00");
        assert!(decode_ip_datagram(wrong_flow.freeze()).is_none());

        let mut wrong_context = BytesMut::new();
        put_varint(&mut wrong_context, 0);
        put_varint(&mut wrong_context, 7);
        wrong_context.extend_from_slice(b"\x45\x00");
        assert!(decode_ip_datagram(wrong_context.freeze()).is_none());
    }

    #[test]
    fn truncated_datagrams_are_dropped() {
        assert!(decode_ip_datagram(Bytes::from_static(b"")).is_none());
        assert!(decode_ip_datagram(Bytes::from_static(b"\x00")).is_none());
        assert!(decode_ip_datagram(Bytes::from_static(b"\x00\x00")).is_none());
    }

    #[test]
    fn warps_protocol_value_is_cf_connect_ip() {
        assert_eq!(WARP_PROTOCOL.as_str(), "cf-connect-ip");
        assert_ne!(WARP_PROTOCOL.as_str(), "connect-ip");
    }
}
