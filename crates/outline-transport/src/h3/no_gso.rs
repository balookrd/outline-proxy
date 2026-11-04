//! QUIC client socket that never asks the kernel for UDP GSO.
//!
//! quinn sizes every outgoing batch by [`AsyncUdpSocket::max_transmit_segments`]
//! of its socket; the stock Tokio socket reports what `quinn-udp` probed at bind
//! time (`UDP_SEGMENT` support of the *host*), not of the egress device the
//! datagrams actually leave through. Behind a policy route onto a device without
//! TX checksum offload — a VLAN on a NIC whose driver exposes no
//! `vlan_features` is the case seen in the field — the kernel answers every
//! segmented `sendmsg` with `EIO`. `quinn-udp` then halts GSO on that socket,
//! but only after the batch is lost, and since each dial binds a fresh socket,
//! every new QUIC connection drops its first handshake flight and pays a full
//! PTO (~1 s) before it comes up.
//!
//! Wrapping the socket and reporting a single segment keeps quinn on one
//! datagram per `sendmsg` from the first packet. Everything else is delegated
//! unchanged, including receive-side GRO.

use std::fmt;
use std::io::{self, IoSliceMut};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use quinn::udp::{RecvMeta, Transmit};
use quinn::{AsyncUdpSocket, UdpPoller};

/// [`AsyncUdpSocket`] that forwards to `inner` but caps transmit batches at one
/// datagram, so no `UDP_SEGMENT` (GSO) send is ever issued.
pub(crate) struct NoGsoUdpSocket {
    inner: Arc<dyn AsyncUdpSocket>,
}

impl NoGsoUdpSocket {
    pub(crate) fn new(inner: Arc<dyn AsyncUdpSocket>) -> Self {
        Self { inner }
    }
}

impl fmt::Debug for NoGsoUdpSocket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NoGsoUdpSocket").field("inner", &self.inner).finish()
    }
}

impl AsyncUdpSocket for NoGsoUdpSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Arc::clone(&self.inner).create_io_poller()
    }

    fn try_send(&self, transmit: &Transmit) -> io::Result<()> {
        self.inner.try_send(transmit)
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        self.inner.poll_recv(cx, bufs, meta)
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    fn max_transmit_segments(&self) -> usize {
        1
    }

    fn max_receive_segments(&self) -> usize {
        self.inner.max_receive_segments()
    }

    fn may_fragment(&self) -> bool {
        self.inner.may_fragment()
    }
}

#[cfg(test)]
#[path = "tests/no_gso.rs"]
mod tests;
