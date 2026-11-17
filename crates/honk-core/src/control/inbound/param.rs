//! Protocol-layer primitives shared by the HTTP and SOCKS5 frontends.
//!
//! Two ideas are borrowed deliberately:
//!
//! * 3proxy's `struct clientparam`: protocol parsers only fill one uniform
//!   description of the connection; policy (routing, dial, accounting) never
//!   reaches back into protocol details.
//! * Xray's `ProcessWithFirstbyte` / `io.MultiReader`: bytes read while
//!   peeking are **not** consumed. [`ReadBuffer`] keeps a cursor so CONNECT
//!   and mixed-protocol dispatch can hand the exact pre-read bytes back.
//!
//! Timeouts are *total* deadlines around a whole handshake/request, not a
//! per-read timer that a slow drip can renew forever (3proxy's
//! `conf.timeouts[SINGLEBYTE_*]` is per-operation; we deliberately go one
//! stricter by bounding the whole phase).

use std::net::{IpAddr, SocketAddr};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::Instant;

/// Target as supplied by the client. A domain is kept as a domain: resolving
/// it is a routing decision (qname rules / follow), not a protocol detail.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(super) enum InboundTarget {
    Ip(IpAddr),
    Domain(String),
}

/// Uniform connection description. Mirrors 3proxy `clientparam`: every
/// protocol handler fills this and the dial/route/accounting layer consumes
/// only this.
#[derive(Clone, Debug)]
pub(super) struct ClientParam {
    /// Inbound tag: the listener name used by `inbound(name)` routing rules.
    pub listener: String,
    /// Authenticated user, if the listener requires credentials. Usable by a
    /// future `inbound_user()` rule without changing the protocol layer.
    pub user: Option<String>,
    pub client_addr: SocketAddr,
    pub target: InboundTarget,
    pub target_port: u16,
}

#[derive(Debug, thiserror::Error)]
pub(super) enum ProtoError {
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
    #[error("handshake/request timed out")]
    Timeout,
    #[error("peer closed before the request completed")]
    Closed,
    #[error("request head exceeded the configured limit")]
    TooLarge,
    #[error("malformed request: {0}")]
    Malformed(&'static str),
    #[error("authentication required or failed")]
    Auth,
    #[error("unsupported protocol feature: {0}")]
    Unsupported(&'static str),
}

/// A stream plus the bytes already read from it.
///
/// `pos` is the read cursor into `buf`; `peek` advances nothing, so the first
/// byte used for mixed-protocol dispatch is still delivered to the selected
/// protocol parser. `drain_buffered` returns everything past the cursor for
/// CONNECT tunnels that already carry a TLS ClientHello.
pub(super) struct ReadBuffer<S> {
    stream: S,
    buf: Vec<u8>,
    pos: usize,
    max: usize,
}

impl<S: AsyncRead + AsyncWrite + Unpin> ReadBuffer<S> {
    pub(super) fn new(stream: S, max: usize) -> Self {
        Self {
            stream,
            buf: Vec::with_capacity(256),
            pos: 0,
            max,
        }
    }

    pub(super) fn stream_mut(&mut self) -> &mut S {
        &mut self.stream
    }

    fn compact(&mut self) {
        if self.pos > 0 {
            self.buf.drain(..self.pos);
            self.pos = 0;
        }
    }

    async fn pull(&mut self, deadline: Instant) -> Result<(), ProtoError> {
        self.compact();
        if self.buf.len() >= self.max {
            return Err(ProtoError::TooLarge);
        }
        let mut chunk = [0u8; 1024];
        let read = tokio::time::timeout_at(deadline, self.stream.read(&mut chunk))
            .await
            .map_err(|_| ProtoError::Timeout)??;
        if read == 0 {
            return Err(ProtoError::Closed);
        }
        self.buf.extend_from_slice(&chunk[..read]);
        if self.buf.len() > self.max {
            return Err(ProtoError::TooLarge);
        }
        Ok(())
    }

    /// Peek one byte without consuming it (Xray `MultiReader` semantics).
    pub(super) async fn peek_u8(&mut self, deadline: Instant) -> Result<u8, ProtoError> {
        while self.buf.len() <= self.pos {
            self.pull(deadline).await?;
        }
        Ok(self.buf[self.pos])
    }

    /// Consume exactly `count` bytes, preferring already buffered ones.
    pub(super) async fn read_exact_buffered(
        &mut self,
        count: usize,
        deadline: Instant,
    ) -> Result<Vec<u8>, ProtoError> {
        while self.buf.len() - self.pos < count {
            self.pull(deadline).await?;
        }
        let end = self.pos + count;
        let out = self.buf[self.pos..end].to_vec();
        self.pos = end;
        Ok(out)
    }

    /// Read one HTTP head through `\r\n\r\n`, leaving everything after it
    /// buffered. A single total deadline covers the whole head.
    pub(super) async fn read_head(&mut self, deadline: Instant) -> Result<Vec<u8>, ProtoError> {
        loop {
            let window = &self.buf[self.pos..];
            if window.len() >= 4
                && let Some(index) = window.windows(4).position(|w| w == b"\r\n\r\n")
            {
                let end = self.pos + index + 4;
                let head = self.buf[self.pos..end].to_vec();
                self.pos = end;
                return Ok(head);
            }
            self.pull(deadline).await?;
        }
    }

    /// Everything read but not yet consumed. Used after CONNECT so a
    /// pipelined ClientHello is not silently dropped.
    pub(super) fn drain_buffered(&mut self) -> Vec<u8> {
        let rest = self.buf[self.pos..].to_vec();
        self.buf.clear();
        self.pos = 0;
        rest
    }

    pub(super) async fn write_all(&mut self, bytes: &[u8]) -> Result<(), ProtoError> {
        self.stream.write_all(bytes).await?;
        Ok(())
    }
}

/// Every error reply closes the connection. Reusing a connection after a
/// protocol error is how clients end up talking to the wrong upstream.
pub(super) async fn http_error<S: AsyncRead + AsyncWrite + Unpin>(
    rb: &mut ReadBuffer<S>,
    status: u16,
    reason: &str,
) {
    let body =
        format!("HTTP/1.1 {status} {reason}\r\nConnection: close\r\nContent-Length: 0\r\n\r\n");
    let _ = rb.write_all(body.as_bytes()).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn deadline() -> Instant {
        Instant::now() + std::time::Duration::from_secs(2)
    }

    #[tokio::test]
    async fn peek_does_not_consume_first_byte() {
        let (mut client, server) = tokio::io::duplex(1024);
        let mut rb = ReadBuffer::new(server, 4096);
        client.write_all(b"\x05rest").await.unwrap();
        assert_eq!(rb.peek_u8(deadline()).await.unwrap(), 0x05);
        assert_eq!(
            rb.read_exact_buffered(5, deadline()).await.unwrap(),
            b"\x05rest".to_vec()
        );
    }

    #[tokio::test]
    async fn read_head_keeps_pipelined_bytes() {
        let (mut client, server) = tokio::io::duplex(4096);
        let mut rb = ReadBuffer::new(server, 64 * 1024);
        client
            .write_all(b"GET / HTTP/1.1\r\nHost: a\r\n\r\nCLIENTHELLO")
            .await
            .unwrap();
        let head = rb.read_head(deadline()).await.unwrap();
        assert!(head.ends_with(b"\r\n\r\n"));
        assert_eq!(rb.drain_buffered(), b"CLIENTHELLO".to_vec());
    }

    #[tokio::test]
    async fn head_split_across_reads_is_reassembled() {
        let (mut client, server) = tokio::io::duplex(4096);
        let mut rb = ReadBuffer::new(server, 64 * 1024);
        client.write_all(b"GET / HTTP/1.1\r\n").await.unwrap();
        client.flush().await.unwrap();
        let handle = tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            client.write_all(b"Host: b\r\n\r\n").await.unwrap();
        });
        let head = rb.read_head(deadline()).await.unwrap();
        assert!(head.windows(4).any(|w| w == b"\r\n\r\n"));
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn oversized_head_is_rejected() {
        let (mut client, server) = tokio::io::duplex(4096);
        let mut rb = ReadBuffer::new(server, 32);
        client.write_all(&[b'x'; 64]).await.unwrap();
        assert!(matches!(
            rb.read_head(deadline()).await,
            Err(ProtoError::TooLarge)
        ));
    }

    #[tokio::test]
    async fn deadline_is_not_renewed_by_slow_drip() {
        let (mut client, server) = tokio::io::duplex(4096);
        let mut rb = ReadBuffer::new(server, 64 * 1024);
        let start = Instant::now() + std::time::Duration::from_millis(60);
        client.write_all(b"G").await.unwrap();
        assert!(matches!(
            rb.read_head(start).await,
            Err(ProtoError::Timeout)
        ));
    }
}
