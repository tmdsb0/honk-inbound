//! MASQUE capsule framing.
//!
//! In an IP tunnel the peer hands us a byte stream (HTTP/2 DATA frames) or a
//! sequence of datagrams (HTTP/3). Both carry *capsules* as defined by
//! RFC 9297, with the IP-tunnel capsules of RFC 9484 on top:
//!
//! ```text
//! Capsule {
//!   Capsule Type (i),
//!   Length (i),
//!   Value (..),
//! }
//! ```
//!
//! Type and Length use QUIC variable-length integers, so a capsule header is
//! between 3 and 24 bytes. A reader must therefore buffer partial capsules
//! rather than assuming one read equals one capsule.
//!
//! The Context ID of RFC 9484 lives inside the value of an HTTP/3 datagram,
//! not in the capsule header — and the connect-ip endpoints deployed today
//! omit it from HTTP/2 capsules entirely, carrying the IP packet as the whole
//! value. A capsule that puts a Context ID before Length is read back as a
//! zero-length datagram followed by garbage, which is why the endpoint resets
//! the tunnel instead of forwarding anything.

use bytes::{Buf, BufMut, Bytes, BytesMut};

pub const CAPSULE_DATAGRAM: u64 = 0x00;
pub const CAPSULE_ADDRESS_ASSIGN: u64 = 0x01;
pub const CAPSULE_ADDRESS_REQUEST: u64 = 0x02;
pub const CAPSULE_ROUTE_ADVERTISEMENT: u64 = 0x03;

/// A capsule value we understand. Anything else is reported as
/// [`Capsule::Unknown`] so callers can skip it instead of failing the tunnel:
/// RFC 9297 says unknown capsule types must be silently skipped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Capsule {
    /// An IP packet destined for (or received from) the tunnel.
    ///
    /// Over HTTP/2 the capsule value is the packet itself, so `context_id` is
    /// always 0. Over HTTP/3 the packet would ride in a QUIC DATAGRAM, whose
    /// Context ID is the one recorded here.
    Datagram {
        context_id: u64,
        payload: Bytes,
    },
    /// The endpoint assigned us addresses. `prefix_len` is in bits.
    AddressAssign {
        addresses: Vec<AssignedAddress>,
    },
    /// The endpoint advertised routes it will carry for us.
    RouteAdvertisement {
        ranges: Vec<AddressRange>,
    },
    Unknown {
        kind: u64,
        payload: Bytes,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AssignedAddress {
    pub ip: IpAddress,
    pub prefix_len: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AddressRange {
    pub start_ip: IpAddress,
    pub end_ip: IpAddress,
    pub ip_protocol: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpAddress {
    V4([u8; 4]),
    V6([u8; 16]),
}

impl IpAddress {
    pub fn to_std(self) -> std::net::IpAddr {
        match self {
            IpAddress::V4(a) => std::net::IpAddr::V4(std::net::Ipv4Addr::from(a)),
            IpAddress::V6(a) => std::net::IpAddr::V6(std::net::Ipv6Addr::from(a)),
        }
    }
}

/// Error produced while decoding a capsule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CapsuleError {
    /// Not enough bytes yet; the caller should buffer more and retry.
    Incomplete,
    Malformed(&'static str),
}

impl std::fmt::Display for CapsuleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CapsuleError::Incomplete => f.write_str("capsule framing is incomplete"),
            CapsuleError::Malformed(reason) => write!(f, "malformed capsule: {reason}"),
        }
    }
}

impl std::error::Error for CapsuleError {}

/// Encode a QUIC variable-length integer into `buf`.
pub fn put_varint(buf: &mut BytesMut, value: u64) {
    match value {
        0..=0x3F => buf.put_u8(value as u8),
        0x40..=0x3FFF => {
            buf.put_u16(0x4000 | value as u16);
        }
        0x4000..=0x3FFF_FFFF => {
            buf.put_u32(0x8000_0000 | value as u32);
        }
        _ => {
            buf.put_u64(0xC000_0000_0000_0000 | value);
        }
    }
}

/// Decode a QUIC variable-length integer, returning `None` when `buf` holds an
/// incomplete (or oversized) encoding.
pub fn read_varint(buf: &mut impl Buf) -> Option<u64> {
    if !buf.has_remaining() {
        return None;
    }
    let first = buf.chunk()[0];
    let length = 1usize << (first >> 6);
    if buf.remaining() < length {
        return None;
    }
    let value = match length {
        1 => {
            // The single-byte form still has to consume its byte, or a caller
            // decoding a sequence would read the same one repeatedly.
            buf.advance(1);
            u64::from(first & 0x3F)
        }
        2 => u64::from(u16::from_be_bytes(safe_2(buf)?) & 0x3FFF),
        4 => u64::from(u32::from_be_bytes(safe_4(buf)?) & 0x3FFF_FFFF),
        8 => u64::from_be_bytes(safe_8(buf)?) & 0x3FFF_FFFF_FFFF_FFFF,
        _ => return None,
    };
    Some(value)
}

fn safe_2(buf: &mut impl Buf) -> Option<[u8; 2]> {
    let mut out = [0u8; 2];
    buf.copy_to_slice(&mut out);
    Some(out)
}

fn safe_4(buf: &mut impl Buf) -> Option<[u8; 4]> {
    let mut out = [0u8; 4];
    buf.copy_to_slice(&mut out);
    Some(out)
}

fn safe_8(buf: &mut impl Buf) -> Option<[u8; 8]> {
    let mut out = [0u8; 8];
    buf.copy_to_slice(&mut out);
    Some(out)
}

/// Encode a DATAGRAM capsule wrapping `payload` (an IP packet).
///
/// The packet is the whole capsule value: `Type, Length, Packet`. Endpoints
/// that speak Cloudflare's connect-ip read it that way, so a Context ID in
/// front of Length would be parsed as a zero-length value and the rest of the
/// bytes as a second, malformed capsule.
pub fn encode_datagram(payload: &[u8]) -> BytesMut {
    // Reserve the whole frame up front. Starting from an empty `BytesMut`
    // reallocates — and copies the small header — as soon as the payload is
    // appended, which happens once per IP packet on the upstream path.
    // 1 byte of type plus at most 8 bytes of length is the worst-case header.
    let mut buf = BytesMut::with_capacity(payload.len() + 9);
    put_varint(&mut buf, CAPSULE_DATAGRAM);
    put_varint(&mut buf, payload.len() as u64);
    buf.put_slice(payload);
    buf
}

/// Decode one capsule from the front of `buf`.
///
/// On success the consumed bytes are advanced past. On
/// [`CapsuleError::Incomplete`] `buf` is left untouched so the caller can retry
/// after appending more data.
pub fn decode(buf: &mut BytesMut) -> Result<Capsule, CapsuleError> {
    let mut cursor = std::io::Cursor::new(&buf[..]);
    let kind = read_varint(&mut cursor).ok_or(CapsuleError::Incomplete)?;
    let length = read_varint(&mut cursor).ok_or(CapsuleError::Incomplete)?;
    let length =
        usize::try_from(length).map_err(|_| CapsuleError::Malformed("capsule too large"))?;
    let header_len = cursor.position() as usize;
    if buf.len() < header_len + length {
        return Err(CapsuleError::Incomplete);
    }
    let payload = buf.split_to(header_len + length).freeze();
    let value = payload.slice(header_len..);

    let capsule = match kind {
        CAPSULE_DATAGRAM => Capsule::Datagram {
            context_id: 0,
            payload: value,
        },
        CAPSULE_ADDRESS_ASSIGN => Capsule::AddressAssign {
            addresses: parse_address_assign(&value)?,
        },
        CAPSULE_ROUTE_ADVERTISEMENT => Capsule::RouteAdvertisement {
            ranges: parse_route_advertisement(&value)?,
        },
        other => Capsule::Unknown {
            kind: other,
            payload: value,
        },
    };
    Ok(capsule)
}

fn parse_address_assign(mut value: &[u8]) -> Result<Vec<AssignedAddress>, CapsuleError> {
    let mut out = Vec::new();
    while !value.is_empty() {
        let family = *value
            .first()
            .ok_or(CapsuleError::Malformed("truncated family"))?;
        let (ip, prefix_len) = match family {
            0x02 => {
                if value.len() < 6 {
                    return Err(CapsuleError::Malformed("truncated IPv4 assignment"));
                }
                let mut a = [0u8; 4];
                a.copy_from_slice(&value[1..5]);
                let prefix_len = value[5];
                value = &value[6..];
                (IpAddress::V4(a), prefix_len)
            }
            0x03 => {
                if value.len() < 18 {
                    return Err(CapsuleError::Malformed("truncated IPv6 assignment"));
                }
                let mut a = [0u8; 16];
                a.copy_from_slice(&value[1..17]);
                let prefix_len = value[17];
                value = &value[18..];
                (IpAddress::V6(a), prefix_len)
            }
            _ => return Err(CapsuleError::Malformed("unknown address family")),
        };
        out.push(AssignedAddress { ip, prefix_len });
    }
    Ok(out)
}

fn parse_route_advertisement(_value: &[u8]) -> Result<Vec<AddressRange>, CapsuleError> {
    // Route advertisements are advisory: the endpoint tells us which prefixes
    // it can carry. honk binds sockets to the TUN device directly, so it does
    // not need to install routes from this capsule.
    Ok(Vec::new())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varint_round_trips_across_all_widths() {
        for value in [0u64, 1, 63, 64, 16383, 16384, 1 << 30, u64::MAX >> 2] {
            let mut buf = BytesMut::new();
            put_varint(&mut buf, value);
            let mut slice = &buf[..];
            assert_eq!(read_varint(&mut slice), Some(value), "value {value}");
        }
    }

    #[test]
    fn datagram_capsule_survives_a_round_trip() {
        let packet = b"\x45\x00\x00\x14";
        // Type, Length, packet — no Context ID in front of the length.
        assert_eq!(&encode_datagram(packet)[..], b"\x00\x04\x45\x00\x00\x14");
        let mut buf = encode_datagram(packet);
        let capsule = decode(&mut buf).expect("decodes");
        match capsule {
            Capsule::Datagram {
                context_id,
                payload,
            } => {
                assert_eq!(context_id, 0);
                assert_eq!(&payload[..], &packet[..]);
            }
            other => panic!("unexpected capsule {other:?}"),
        }
    }

    #[test]
    fn partial_capsule_reports_incomplete_without_consuming() {
        let mut buf = encode_datagram(&[0u8; 40]);
        let full = buf.len();
        buf.truncate(full - 5);
        let mut probe = buf.clone();
        assert_eq!(decode(&mut probe), Err(CapsuleError::Incomplete));
        assert_eq!(probe.len(), full - 5, "buffer must be left intact");
    }

    #[test]
    fn unknown_capsule_types_are_skipped() {
        let mut buf = BytesMut::new();
        put_varint(&mut buf, 0x4F5A);
        put_varint(&mut buf, 2);
        buf.put_slice(b"hi");
        let capsule = decode(&mut buf).expect("decodes");
        assert!(matches!(capsule, Capsule::Unknown { .. }));
    }
}
