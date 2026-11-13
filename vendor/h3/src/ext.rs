//! Extensions for the HTTP/3 protocol.

use std::str::FromStr;

/// Describes the `:protocol` pseudo-header for extended connect
///
/// See: <https://www.rfc-editor.org/rfc/rfc8441#section-4>
#[derive(Copy, PartialEq, Debug, Clone)]
pub struct Protocol(ProtocolInner);

impl Protocol {
    /// WebTransport protocol
    pub const WEB_TRANSPORT: Protocol = Protocol(ProtocolInner::WebTransport);
    /// RFC 9298 protocol
    pub const CONNECT_UDP: Protocol = Protocol(ProtocolInner::ConnectUdp);
    /// Cloudflare WARP / Zero Trust MASQUE connect-ip carrier.
    ///
    /// WARP does not implement RFC 9484's `connect-ip`: it answers 400 to that
    /// value and only accepts this private identifier. See honk's
    /// `proxy/masque/http3.rs`. Kept here because `Protocol`'s tuple field is
    /// private, so a downstream crate cannot construct the value itself.
    pub const CF_CONNECT_IP: Protocol = Protocol(ProtocolInner::CfConnectIp);

    /// Return a &str representation of the `:protocol` pseudo-header value
    #[inline]
    pub fn as_str(&self) -> &str {
        match self.0 {
            ProtocolInner::WebTransport => "webtransport",
            ProtocolInner::ConnectUdp => "connect-udp",
            ProtocolInner::CfConnectIp => "cf-connect-ip",
        }
    }
}

#[derive(Copy, PartialEq, Debug, Clone)]
enum ProtocolInner {
    WebTransport,
    ConnectUdp,
    CfConnectIp,
}

/// Error when parsing the protocol
pub struct InvalidProtocol;

impl FromStr for Protocol {
    type Err = InvalidProtocol;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "webtransport" => Ok(Self(ProtocolInner::WebTransport)),
            "connect-udp" => Ok(Self(ProtocolInner::ConnectUdp)),
            "cf-connect-ip" => Ok(Self(ProtocolInner::CfConnectIp)),
            _ => Err(InvalidProtocol),
        }
    }
}
