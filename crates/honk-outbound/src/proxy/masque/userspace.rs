//! In-process MASQUE IP stack (smoltcp) for the `userspace` tunnel backend.
//!
//! The kernel backend ([`super::tun`]) hands IP packets to a TUN device and
//! lets the kernel own TCP/UDP. This backend keeps them in-process: a smoltcp
//! [`Interface`] owns TCP/UDP, and the carriers ([`super::http2`],
//! [`super::http3`]) shuttle IP packets between that interface and the MASQUE
//! stream. No TUN device, no `ip` calls, no extra capabilities.
//!
//! A single poll loop drives the interface on smoltcp's own schedule: after
//! each `poll()` it asks for `poll_delay()` and sleeps exactly until the next
//! TCP timer, waking early only when ingress, a write or a socket change pokes
//! it. There is no fixed polling interval and no timer-based fallback in the
//! receive paths -- every waiter registers a waker before checking its
//! condition, so a wakeup cannot be lost.
//!
//! The connection handles ([`TcpConnection`], [`UdpConnection`]) read and
//! write their smoltcp socket **directly** under a short synchronous lock:
//! there is no channel to copy into, no unbounded queue to fill, and smoltcp's
//! own receive buffer acts as the TCP receive window, so a slow reader applies
//! back pressure all the way to the peer.

use std::collections::HashMap;
use std::collections::VecDeque;
use std::future::poll_fn;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU16, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use async_trait::async_trait;
use futures_util::task::AtomicWaker;
use smoltcp::iface::{Config, Interface, PollResult, SocketHandle, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::tcp::{
    CongestionControl, RecvError as TcpRecvError, Socket as TcpSocket, State as TcpState,
};
use smoltcp::socket::udp::{self, RecvError as UdpRecvError, Socket as UdpSocket};
use smoltcp::time::Instant as SmolInstant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, IpEndpoint, IpListenEndpoint};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::Notify;

use crate::proxy::PacketTransport;

/// TCP receive buffer, in bytes. smoltcp derives the advertised receive window
/// and its RFC 1323 window-scale shift from this capacity (`log2(cap) - 16`),
/// so throughput is bounded by roughly `window / RTT`. A 64 KiB buffer means
/// an unscaled 64 KiB window, i.e. ~640 KiB/s on a 100 ms path. 512 KiB offers
/// a scaled 512 KiB window (shift 3) and keeps per-connection memory bounded.
const TCP_RX_BUFFER: usize = 512 * 1024;
/// TCP transmit buffer, in bytes. A peer advertising a large window must not
/// find us limited by our own send buffer on the upload side.
const TCP_TX_BUFFER: usize = 256 * 1024;
/// Number of UDP datagram slots the receive/transmit buffers hold.
const UDP_SLOTS: usize = 64;
/// UDP payload storage, in bytes (`UDP_SLOTS` packets of ~1.5 KiB).
const UDP_PAYLOAD: usize = UDP_SLOTS * 1500;
/// First ephemeral source port handed out to tunnel sockets.
const FIRST_PORT: u16 = 32_768;
/// Upper bound on an idle wait when smoltcp reports no pending timers. Every
/// real wakeup is event-driven; this only bounds a completely idle sleep.
const MAX_IDLE: Duration = Duration::from_secs(60);

/// The raw queues a smoltcp [`Device`] reads ingress from and writes egress to.
///
/// Kept separate from [`Inner`] so the device (owned by the poll loop's stack)
/// does not form a reference cycle back into [`Inner`].
struct DeviceQueues {
    /// Packets decoded from the MASQUE stream, waiting for smoltcp as ingress.
    ingress: std::sync::Mutex<VecDeque<Vec<u8>>>,
    /// IP packets smoltcp produced as egress, waiting for a carrier.
    egress: std::sync::Mutex<VecDeque<Vec<u8>>>,
    /// Wakes the poll loop after ingress arrives or a socket wants to send.
    /// `notify_one` stores a permit, so a wakeup is never lost while the loop
    /// is busy polling.
    poll_notify: Notify,
    /// Wakes a carrier's [`UserspaceDevice::recv_packet`] once egress is ready.
    carrier_recv_notify: Notify,
}

/// The smoltcp-facing half of the device: a point-to-point IP device whose
/// ingress/egress are the [`DeviceQueues`].
struct SmolDevice {
    queues: Arc<DeviceQueues>,
    mtu: usize,
}

impl Device for SmolDevice {
    type RxToken<'a> = SmolRxToken where Self: 'a;
    type TxToken<'a> = SmolTxToken<'a> where Self: 'a;

    fn receive(&mut self, _timestamp: SmolInstant) -> Option<(SmolRxToken, SmolTxToken<'_>)> {
        let packet = self.queues.ingress.lock().unwrap().pop_front()?;
        // The paired transmit token is how smoltcp sends an immediate reply
        // to this very packet (ICMP error/echo, TCP RST). It must push egress
        // just like `transmit` does, or those replies are silently dropped.
        Some((SmolRxToken { packet }, SmolTxToken { device: self }))
    }

    fn transmit(&mut self, _timestamp: SmolInstant) -> Option<SmolTxToken<'_>> {
        Some(SmolTxToken { device: self })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = self.mtu;
        caps
    }
}

struct SmolRxToken {
    packet: Vec<u8>,
}

impl RxToken for SmolRxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.packet[..])
    }
}

struct SmolTxToken<'a> {
    device: &'a mut SmolDevice,
}

impl TxToken for SmolTxToken<'_> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buffer = vec![0u8; len];
        let result = f(&mut buffer);
        self.device
            .queues
            .egress
            .lock()
            .unwrap()
            .push_back(buffer);
        self.device.queues.carrier_recv_notify.notify_one();
        result
    }
}

/// Wakers and lifecycle flags shared between the poll loop and one connection
/// handle. `Arc` so a dropped handle can be noticed without taking any lock.
#[derive(Default)]
struct SocketState {
    read: AtomicWaker,
    write: AtomicWaker,
    /// Wakes a `tcp_connect` waiter when the handshake settles.
    connect_wake: AtomicWaker,
    /// The connection handle was dropped; the poll loop reclaims the socket.
    dropped: AtomicBool,
    /// TCP connect outcome, published by the poll loop: 0 pending,
    /// 1 established, 2 failed/closed before establishment.
    connect: AtomicU8,
}

#[derive(Clone, Copy)]
enum SocketKind {
    Tcp,
    Udp,
}

struct SocketEntry {
    state: Arc<SocketState>,
    kind: SocketKind,
}

/// Shared, process-global state for one userspace tunnel.
struct Inner {
    /// All stack and socket operations are synchronous and short, so a plain
    /// mutex is enough. No guard is ever held across an `.await`.
    stack: std::sync::Mutex<Stack>,
    sockets: std::sync::Mutex<HashMap<SocketHandle, SocketEntry>>,
    shutdown: AtomicBool,
    next_port: AtomicU16,
    queues: Arc<DeviceQueues>,
    label: String,
}

struct Stack {
    iface: Interface,
    sockets: SocketSet<'static>,
    device: SmolDevice,
}

impl Inner {
    /// Allocate an ephemeral source port for a tunnel socket.
    fn alloc_port(&self) -> u16 {
        let port = self.next_port.fetch_add(1, Ordering::Relaxed);
        if port == 0 { 1 } else { port }
    }
}

/// A MASQUE tunnel backed by an in-process smoltcp stack.
pub struct UserspaceDevice {
    inner: Arc<Inner>,
    poll_task: std::sync::Mutex<Option<tokio::task::JoinHandle<()>>>,
}

impl UserspaceDevice {
    /// Build the interface, configure its addresses and default routes, and
    /// start the poll loop.
    pub fn create(addresses: &[IpAddr], mtu: u32, slot: usize) -> io::Result<Self> {
        let queues = Arc::new(DeviceQueues {
            ingress: std::sync::Mutex::new(VecDeque::new()),
            egress: std::sync::Mutex::new(VecDeque::new()),
            poll_notify: Notify::new(),
            carrier_recv_notify: Notify::new(),
        });

        let mut device = SmolDevice {
            queues: Arc::clone(&queues),
            mtu: mtu as usize,
        };

        // smoltcp strongly recommends a per-boot seed: with a fixed one, TCP
        // initial sequence numbers repeat and a stale segment from an earlier
        // run can be accepted by a new connection.
        let mut config = Config::new(HardwareAddress::Ip);
        config.random_seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|elapsed| elapsed.as_nanos() as u64 ^ (slot as u64).rotate_left(32))
            .unwrap_or(0x9e37_79b9_7f4a_7c15);
        let mut iface = Interface::new(config, &mut device, SmolInstant::now());
        iface.update_ip_addrs(|addrs| {
            for address in addresses {
                let addr: IpAddress = (*address).into();
                let prefix = if address.is_ipv4() { 32 } else { 128 };
                let _ = addrs.push(IpCidr::new(addr, prefix));
            }
        });
        // A point-to-point medium needs no neighbour resolution, so the gateway
        // is only used to pick this interface; the local address itself
        // satisfies that. `has_neighbor` is unconditionally true for Medium::Ip,
        // which is what lets socket egress proceed without an ARP cache.
        {
            let routes = iface.routes_mut();
            if let Some(gateway) = addresses.iter().find(|a| a.is_ipv4()).copied() {
                if let IpAddress::Ipv4(gw) = IpAddress::from(gateway) {
                    let _ = routes.add_default_ipv4_route(gw);
                }
            }
            if let Some(gateway) = addresses.iter().find(|a| a.is_ipv6()).copied() {
                if let IpAddress::Ipv6(gw) = IpAddress::from(gateway) {
                    let _ = routes.add_default_ipv6_route(gw);
                }
            }
        }

        let stack = Stack {
            iface,
            sockets: SocketSet::new(vec![]),
            device,
        };

        let inner = Arc::new(Inner {
            stack: std::sync::Mutex::new(stack),
            sockets: std::sync::Mutex::new(HashMap::new()),
            shutdown: AtomicBool::new(false),
            next_port: AtomicU16::new(FIRST_PORT),
            queues,
            label: format!("masque-userspace-{slot}"),
        });

        let poll_task = tokio::spawn(poll_loop(Arc::clone(&inner)));
        Ok(Self {
            inner,
            poll_task: std::sync::Mutex::new(Some(poll_task)),
        })
    }

    /// Read one egress IP packet the stack wants to send down the MASQUE
    /// stream. Blocks until the stack produces one.
    pub async fn recv_packet(&self, buffer: &mut [u8]) -> io::Result<usize> {
        loop {
            {
                let mut egress = self.inner.queues.egress.lock().unwrap();
                if let Some(packet) = egress.pop_front() {
                    let length = packet.len().min(buffer.len());
                    buffer[..length].copy_from_slice(&packet[..length]);
                    return Ok(length);
                }
            }
            // `notify_one` stores a permit, so a packet arriving between the
            // pop above and this await still wakes us immediately. No timeout
            // fallback is needed.
            self.inner.queues.carrier_recv_notify.notified().await;
        }
    }

    /// Inject one ingress IP packet decoded from the MASQUE stream, then wake
    /// the poll loop so smoltcp processes it.
    pub async fn send_packet(&self, packet: &[u8]) -> io::Result<usize> {
        self.inner
            .queues
            .ingress
            .lock()
            .unwrap()
            .push_back(packet.to_vec());
        self.inner.queues.poll_notify.notify_one();
        Ok(packet.len())
    }

    /// A stable label for logs and errors.
    pub fn label(&self) -> String {
        self.inner.label.clone()
    }

    /// Open a TCP connection through the tunnel to `target`, bound to the
    /// tunnel `source` address. The poll loop reports when the handshake
    /// completes, so this never races with socket reclamation.
    pub async fn tcp_connect(
        &self,
        source: IpAddr,
        target: SocketAddr,
        connect_timeout: Duration,
    ) -> io::Result<TcpConnection> {
        let state = Arc::new(SocketState::default());
        let handle = {
            let mut stack = self.inner.stack.lock().unwrap();
            let mut socket = TcpSocket::new(
                smoltcp::storage::RingBuffer::new(vec![0u8; TCP_RX_BUFFER]),
                smoltcp::storage::RingBuffer::new(vec![0u8; TCP_TX_BUFFER]),
            );
            // `bind::new_socket` sets TCP_NODELAY on every kernel-backend
            // tunnel socket. smoltcp enables Nagle by default, which combined
            // with a peer's delayed ACK stalls small request/response exchanges
            // for 40-200ms. Keep both backends on the same footing, and ACK
            // immediately instead of smoltcp's 10ms delayed ACK.
            socket.set_nagle_enabled(false);
            socket.set_ack_delay(None);
            socket.set_congestion_control(CongestionControl::Cubic);
            let local = IpListenEndpoint {
                addr: Some(source.into()),
                port: self.inner.alloc_port(),
            };
            socket
                .connect(stack.iface.context(), target, local)
                .map_err(|error| {
                    io::Error::new(
                        io::ErrorKind::ConnectionRefused,
                        format!("masque userspace tcp connect: {error:?}"),
                    )
                })?;
            stack.sockets.add(socket)
        };
        self.inner.sockets.lock().unwrap().insert(
            handle,
            SocketEntry {
                state: Arc::clone(&state),
                kind: SocketKind::Tcp,
            },
        );
        self.inner.queues.poll_notify.notify_one();

        let outcome = tokio::time::timeout(connect_timeout, async {
            // Register before checking, so a handshake settling between the
            // check and the await cannot be missed.
            poll_fn(|cx| {
                state.connect_wake.register(cx.waker());
                match state.connect.load(Ordering::Acquire) {
                    0 => Poll::Pending,
                    _ => Poll::Ready(()),
                }
            })
            .await;
            match state.connect.load(Ordering::Acquire) {
                1 => Ok(()),
                _ => Err(io::Error::new(
                    io::ErrorKind::ConnectionRefused,
                    "masque userspace tcp connect failed",
                )),
            }
        })
        .await;

        match outcome {
            Ok(Ok(())) => Ok(TcpConnection {
                inner: Arc::clone(&self.inner),
                handle,
                state,
            }),
            Ok(Err(error)) => {
                self.abandon(&state);
                Err(error)
            }
            Err(_) => {
                self.abandon(&state);
                Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "masque userspace tcp connect timeout",
                ))
            }
        }
    }

    /// Bind a UDP socket to the tunnel `source` address for traffic to
    /// `target`.
    pub async fn udp_bind(
        &self,
        source: IpAddr,
        target: SocketAddr,
        _connect_timeout: Duration,
    ) -> io::Result<UdpConnection> {
        let state = Arc::new(SocketState::default());
        let handle = {
            let mut stack = self.inner.stack.lock().unwrap();
            let rx = udp::PacketBuffer::new(
                vec![udp::PacketMetadata::EMPTY; UDP_SLOTS],
                vec![0u8; UDP_PAYLOAD],
            );
            let tx = udp::PacketBuffer::new(
                vec![udp::PacketMetadata::EMPTY; UDP_SLOTS],
                vec![0u8; UDP_PAYLOAD],
            );
            let mut socket = UdpSocket::new(rx, tx);
            let local = IpListenEndpoint {
                addr: Some(source.into()),
                port: self.inner.alloc_port(),
            };
            socket.bind(local).map_err(|error| {
                io::Error::new(
                    io::ErrorKind::AddrInUse,
                    format!("masque userspace udp bind: {error:?}"),
                )
            })?;
            stack.sockets.add(socket)
        };
        self.inner.sockets.lock().unwrap().insert(
            handle,
            SocketEntry {
                state: Arc::clone(&state),
                kind: SocketKind::Udp,
            },
        );
        self.inner.queues.poll_notify.notify_one();

        Ok(UdpConnection {
            inner: Arc::clone(&self.inner),
            handle,
            state,
            target,
        })
    }

    /// Mark a socket for reclamation by the poll loop.
    fn abandon(&self, state: &Arc<SocketState>) {
        state.dropped.store(true, Ordering::Relaxed);
        self.inner.queues.poll_notify.notify_one();
    }
}

impl Drop for UserspaceDevice {
    fn drop(&mut self) {
        self.inner.shutdown.store(true, Ordering::Relaxed);
        if let Some(task) = self.poll_task.lock().unwrap().take() {
            task.abort();
        }
    }
}

/// Drive the interface on smoltcp's own schedule until shutdown.
///
/// `poll()` drains ingress and egress and reports whether any socket state
/// changed; `poll_delay()` then gives the exact time of the next TCP timer. We
/// sleep for that long and wake early only when something pokes the queues.
/// No guard is held across the await.
async fn poll_loop(inner: Arc<Inner>) {
    // `poll()` folds `poll_maintenance()`'s result away, so `PollResult::None`
    // does not prove that a TCP timer left every socket unchanged. Remember
    // why we woke: a timer expiry has to service sockets even when `poll()`
    // reports no state change, or a writer waiting on `can_send()` could hang.
    let mut timer_fired = false;
    loop {
        if inner.shutdown.load(Ordering::Relaxed) {
            break;
        }
        let delay = {
            let mut stack = inner.stack.lock().unwrap();
            let mut entries = inner.sockets.lock().unwrap();
            // Destructure first: `Interface::poll` needs the device and socket
            // set that live beside it in `Stack` as disjoint borrows.
            let Stack {
                iface,
                sockets,
                device,
            } = &mut *stack;
            let now = SmolInstant::now();
            let result = iface.poll(now, &mut *device, &mut *sockets);
            service_sockets(sockets, &mut entries, result, timer_fired);
            iface.poll_delay(now, sockets)
        };
        // smoltcp has its own `Duration`; normalise once so the timer and the
        // idle fallback share `std::time::Duration`.
        let wait: Duration = delay.map(Into::into).unwrap_or(MAX_IDLE);
        timer_fired = tokio::select! {
            _ = tokio::time::sleep(wait) => true,
            _ = inner.queues.poll_notify.notified() => false,
        };
    }
}

/// Reclaim dropped sockets, publish TCP connect outcomes and wake readers or
/// writers whose socket changed readiness.
///
/// `PollResult::None` only covers ingress/egress; timer-driven changes are
/// folded away by `poll()`, so `timer_fired` also forces a service pass.
fn service_sockets(
    sockets: &mut SocketSet<'static>,
    entries: &mut HashMap<SocketHandle, SocketEntry>,
    result: PollResult,
    timer_fired: bool,
) {
    let changed = matches!(result, PollResult::SocketStateChanged) || timer_fired;
    let handles: Vec<SocketHandle> = entries.keys().copied().collect();
    for handle in handles {
        // Clone the shared bits out of the map so reclaiming an entry below
        // does not conflict with an outstanding borrow of it.
        let Some((kind, state)) = entries
            .get(&handle)
            .map(|entry| (entry.kind, Arc::clone(&entry.state)))
        else {
            continue;
        };
        if state.dropped.load(Ordering::Relaxed) {
            entries.remove(&handle);
            sockets.remove(handle);
            continue;
        }
        // Only TCP sockets have a connect outcome to publish.
        let pending_connect =
            matches!(kind, SocketKind::Tcp) && state.connect.load(Ordering::Relaxed) == 0;
        if !changed && !pending_connect {
            continue;
        }
        match kind {
            SocketKind::Tcp => {
                let socket = sockets.get_mut::<TcpSocket>(handle);
                if pending_connect {
                    match socket.state() {
                        TcpState::Established => {
                            state.connect.store(1, Ordering::Release);
                            state.connect_wake.wake();
                        }
                        TcpState::Closed | TcpState::TimeWait => {
                            state.connect.store(2, Ordering::Release);
                            state.connect_wake.wake();
                        }
                        _ => {}
                    }
                }
                if socket.can_recv() {
                    state.read.wake();
                }
                if socket.can_send() {
                    state.write.wake();
                }
            }
            SocketKind::Udp => {
                let socket = sockets.get_mut::<UdpSocket>(handle);
                if socket.can_recv() {
                    state.read.wake();
                }
                if socket.can_send() {
                    state.write.wake();
                }
            }
        }
    }
}

/// Convert a smoltcp endpoint back into a std `SocketAddr`.
fn endpoint_to_socketaddr(endpoint: IpEndpoint) -> SocketAddr {
    SocketAddr::new(endpoint.addr.into(), endpoint.port)
}

/// A TCP connection inside the userspace tunnel, bridging smoltcp to
/// `AsyncRead` / `AsyncWrite`. Reads go straight into the caller's buffer, so
/// a short read leaves the rest in smoltcp's receive window instead of
/// discarding it.
pub struct TcpConnection {
    inner: Arc<Inner>,
    handle: SocketHandle,
    state: Arc<SocketState>,
}

impl std::fmt::Debug for TcpConnection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("TcpConnection").field(&self.handle).finish()
    }
}

impl Drop for TcpConnection {
    fn drop(&mut self) {
        self.state.dropped.store(true, Ordering::Relaxed);
        self.inner.queues.poll_notify.notify_one();
    }
}

impl AsyncRead for TcpConnection {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        let mut stack = this.inner.stack.lock().unwrap();
        let socket = stack.sockets.get_mut::<TcpSocket>(this.handle);
        // The closure consumes only as many bytes as fit; the rest stays in
        // smoltcp's rx buffer for the next read.
        match socket.recv(|data| {
            let length = data.len().min(buf.remaining());
            buf.put_slice(&data[..length]);
            (length, length)
        }) {
            Ok(0) => {
                this.state.read.register(cx.waker());
                Poll::Pending
            }
            Ok(_) => Poll::Ready(Ok(())),
            // FIN received: the peer closed, which reads as EOF.
            Err(TcpRecvError::Finished) => Poll::Ready(Ok(())),
            Err(TcpRecvError::InvalidState) => {
                this.state.read.register(cx.waker());
                Poll::Pending
            }
        }
    }
}

impl AsyncWrite for TcpConnection {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let mut stack = this.inner.stack.lock().unwrap();
        let socket = stack.sockets.get_mut::<TcpSocket>(this.handle);
        if !socket.can_send() {
            this.state.write.register(cx.waker());
            return Poll::Pending;
        }
        match socket.send_slice(buf) {
            Ok(written) => {
                drop(stack);
                this.inner.queues.poll_notify.notify_one();
                Poll::Ready(Ok(written))
            }
            Err(error) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                format!("masque userspace tcp send: {error:?}"),
            ))),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.inner.queues.poll_notify.notify_one();
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        {
            let mut stack = this.inner.stack.lock().unwrap();
            stack.sockets.get_mut::<TcpSocket>(this.handle).close();
        }
        this.inner.queues.poll_notify.notify_one();
        Poll::Ready(Ok(()))
    }
}

/// A UDP association inside the userspace tunnel, bridging smoltcp to
/// `PacketTransport`.
pub struct UdpConnection {
    inner: Arc<Inner>,
    handle: SocketHandle,
    state: Arc<SocketState>,
    target: SocketAddr,
}

impl std::fmt::Debug for UdpConnection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("UdpConnection").field(&self.handle).finish()
    }
}

impl Drop for UdpConnection {
    fn drop(&mut self) {
        self.state.dropped.store(true, Ordering::Relaxed);
        self.inner.queues.poll_notify.notify_one();
    }
}

impl UdpConnection {
    /// Register before checking, so a packet arriving between the caller's
    /// failed `recv()` and this wait cannot be missed. The condition lives on
    /// the smoltcp socket itself, so there is no channel and no lost wakeup.
    fn wait_readable(&self) -> impl std::future::Future<Output = ()> + '_ {
        poll_fn(move |cx| {
            self.state.read.register(cx.waker());
            let mut stack = self.inner.stack.lock().unwrap();
            let socket = stack.sockets.get_mut::<UdpSocket>(self.handle);
            if socket.can_recv() {
                Poll::Ready(())
            } else {
                Poll::Pending
            }
        })
    }

    fn wait_writable(&self) -> impl std::future::Future<Output = ()> + '_ {
        poll_fn(move |cx| {
            self.state.write.register(cx.waker());
            let mut stack = self.inner.stack.lock().unwrap();
            let socket = stack.sockets.get_mut::<UdpSocket>(self.handle);
            if socket.can_send() {
                Poll::Ready(())
            } else {
                Poll::Pending
            }
        })
    }
}

#[async_trait]
impl PacketTransport for UdpConnection {
    fn relay_addr(&self) -> SocketAddr {
        self.target
    }

    async fn send_packet(&self, data: &[u8]) -> io::Result<()> {
        let remote: IpEndpoint = self.target.into();
        loop {
            if self.inner.shutdown.load(Ordering::Relaxed) {
                return Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "masque userspace tunnel closed",
                ));
            }
            {
                let mut stack = self.inner.stack.lock().unwrap();
                let socket = stack.sockets.get_mut::<UdpSocket>(self.handle);
                if socket.can_send() {
                    socket.send_slice(data, remote).map_err(|error| {
                        io::Error::new(
                            io::ErrorKind::BrokenPipe,
                            format!("masque userspace udp send: {error:?}"),
                        )
                    })?;
                    drop(stack);
                    self.inner.queues.poll_notify.notify_one();
                    return Ok(());
                }
            }
            self.wait_writable().await;
        }
    }

    async fn recv_packet(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        loop {
            if self.inner.shutdown.load(Ordering::Relaxed) {
                return Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "masque userspace tunnel closed",
                ));
            }
            {
                let mut stack = self.inner.stack.lock().unwrap();
                let socket = stack.sockets.get_mut::<UdpSocket>(self.handle);
                match socket.recv() {
                    Ok((payload, meta)) => {
                        let length = payload.len().min(buf.len());
                        buf[..length].copy_from_slice(&payload[..length]);
                        return Ok((length, endpoint_to_socketaddr(meta.endpoint)));
                    }
                    Err(UdpRecvError::Exhausted) | Err(UdpRecvError::Truncated) => {}
                }
            }
            self.wait_readable().await;
        }
    }
}
