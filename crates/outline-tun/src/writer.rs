//! Shared writer handle for the TUN device.
//!
//! Wraps the TUN fd (`AsyncFd` in production, a blocking `File` behind a
//! mutex in tests) and exposes async `write_packet` that parks on kernel
//! writability. Each `write(2)` delivers exactly one IP packet on TUN, so
//! concurrent writers don't need a user-space lock in the async case.

use std::io::{IoSlice, Write as _};
use std::sync::Arc;

use anyhow::{Context, Result};
use bytes::Bytes;
use tokio::io::Interest;
use tokio::io::unix::AsyncFd;

use outline_metrics as metrics;

use crate::vnet::VirtioNetHdr;

/// A cheaply-cloneable handle for writing IP packets to a TUN device.
///
/// Production path wraps the TUN fd (set to `O_NONBLOCK`) in
/// [`tokio::io::unix::AsyncFd`], so `write_packet` integrates with the tokio
/// reactor: when the kernel tx queue is full, the task parks on writability
/// instead of blocking the runtime thread. Each `write(2)` is atomic per
/// packet on TUN, so no mutex is needed between concurrent writers — the
/// kernel serialises them.
///
/// The `#[cfg(test)]` blocking variant keeps tests backed by a regular file
/// working, since regular files can't be registered with epoll/kqueue.
#[derive(Clone)]
pub(crate) struct SharedTunWriter {
    inner: SharedTunWriterInner,
    /// When `true` the TUN fd was opened with `IFF_VNET_HDR`, so every write
    /// must be prefixed with a `virtio_net_hdr`: `GSO_NONE` for a single packet,
    /// or a real GSO descriptor for a downlink TSO super-segment.
    gso_enabled: bool,
}

#[derive(Clone)]
enum SharedTunWriterInner {
    Async(Arc<AsyncFd<std::fs::File>>),
    #[cfg(test)]
    Blocking(Arc<parking_lot::Mutex<std::fs::File>>),
}

impl SharedTunWriter {
    pub(crate) fn from_async_fd(fd: Arc<AsyncFd<std::fs::File>>, gso_enabled: bool) -> Self {
        Self {
            inner: SharedTunWriterInner::Async(fd),
            gso_enabled,
        }
    }

    #[cfg(test)]
    pub(crate) fn new(file: std::fs::File) -> Self {
        Self {
            inner: SharedTunWriterInner::Blocking(Arc::new(parking_lot::Mutex::new(file))),
            gso_enabled: false,
        }
    }

    /// Write one IP packet to the TUN device.
    ///
    /// On the production (`AsyncFd`) path, this parks the task on
    /// writability if the kernel tx queue is full, so it only suspends under
    /// device backpressure — the common case is a single non-blocking
    /// `write(2)` that returns immediately. Each `write(2)` delivers exactly
    /// one IP packet to the kernel.
    pub(crate) async fn write_packet(&self, packet: &[u8]) -> Result<()> {
        // Single IP packet: GSO_NONE header when the fd carries a vnet header,
        // otherwise a bare write.
        let vnet = self.gso_enabled.then_some(VirtioNetHdr::NONE);
        match &self.inner {
            SharedTunWriterInner::Async(fd) => fd
                .async_io(Interest::WRITABLE, |f| write_tun_packet(f, packet, vnet))
                .await
                .context("failed to write packet to TUN"),
            #[cfg(test)]
            SharedTunWriterInner::Blocking(mutex) => mutex
                .lock()
                .write_all(packet)
                .context("failed to write packet to TUN"),
        }
    }

    /// Write a TCP super-segment for kernel TSO: the `header` carries the GSO
    /// type, MSS (`gso_size`) and checksum offset, and `packet` is one large
    /// IP/TCP packet the kernel splits into MSS segments. Only meaningful when
    /// the fd carries a vnet header (`config.gso`); the caller (`flush`)
    /// guarantees that.
    pub(crate) async fn write_gso_segment(
        &self,
        packet: &[u8],
        header: VirtioNetHdr,
    ) -> Result<()> {
        // Downlink TSO signal: one super-segment the kernel splits per MSS —
        // how often the write path actually coalesced server→client data.
        metrics::record_tun_packet("down", ip_family_str(packet), "tso_supersegment");
        match &self.inner {
            SharedTunWriterInner::Async(fd) => fd
                .async_io(Interest::WRITABLE, |f| write_tun_packet(f, packet, Some(header)))
                .await
                .context("failed to write GSO segment to TUN"),
            #[cfg(test)]
            SharedTunWriterInner::Blocking(mutex) => mutex
                .lock()
                .write_all(packet)
                .context("failed to write GSO segment to TUN"),
        }
    }

    /// Write one downlink data packet whose IP/TCP `header` and `payload` chunks
    /// live in separate buffers, gathering them (and any vnet header) into one
    /// `writev` so the payload — owned `Bytes` shared with the retransmit
    /// scoreboard — is never copied into a contiguous packet buffer. `payload`
    /// carries one chunk on the fast path and several when a TSO super-segment
    /// coalesces multiple upstream reads.
    ///
    /// `gso` is `Some` for a TSO super-segment; `None` for a single IP packet, in
    /// which case a `GSO_NONE` vnet header is prepended when the fd carries one.
    pub(crate) async fn write_data_packet(
        &self,
        header: &[u8],
        payload: &[Bytes],
        gso: Option<VirtioNetHdr>,
    ) -> Result<()> {
        let vnet = match gso {
            Some(vnet) => {
                // Downlink TSO signal: one super-segment the kernel splits per
                // MSS — how often the write path coalesced server→client data.
                metrics::record_tun_packet("down", ip_family_str(header), "tso_supersegment");
                Some(vnet)
            },
            None => self.gso_enabled.then_some(VirtioNetHdr::NONE),
        };
        match &self.inner {
            SharedTunWriterInner::Async(fd) => fd
                .async_io(Interest::WRITABLE, |f| write_tun_data_packet(f, header, payload, vnet))
                .await
                .context("failed to write data packet to TUN"),
            #[cfg(test)]
            SharedTunWriterInner::Blocking(mutex) => {
                let mut file = mutex.lock();
                file.write_all(header)
                    .context("failed to write data packet header to TUN")?;
                for chunk in payload {
                    file.write_all(chunk)
                        .context("failed to write data packet payload to TUN")?;
                }
                Ok(())
            },
        }
    }

    /// Write a batch of IP packets to the TUN device, one `write(2)` per packet.
    pub(crate) async fn write_packets(&self, packets: &[Vec<u8>]) -> Result<()> {
        for packet in packets {
            self.write_packet(packet).await?;
        }
        Ok(())
    }
}

/// Prometheus IP-family label from the leading IP version nibble.
fn ip_family_str(packet: &[u8]) -> &'static str {
    match packet.first().map(|b| b >> 4) {
        Some(4) => "ipv4",
        Some(6) => "ipv6",
        _ => "unknown",
    }
}

fn write_tun_packet(
    file: &std::fs::File,
    packet: &[u8],
    vnet: Option<VirtioNetHdr>,
) -> std::io::Result<()> {
    let mut w: &std::fs::File = file;
    let Some(header) = vnet else {
        let written = w.write(packet)?;
        if written != packet.len() {
            return Err(std::io::Error::other(format!(
                "short TUN write: {written}/{} bytes",
                packet.len()
            )));
        }
        return Ok(());
    };

    // vnet path: one write(2) must atomically deliver [virtio_net_hdr | packet].
    // `writev` keeps the (potentially large) payload copy-free. The header is
    // GSO_NONE for a single packet or a TSO descriptor for a super-segment.
    let header = header.encode();
    let expected = header.len() + packet.len();
    let written = w.write_vectored(&[IoSlice::new(&header), IoSlice::new(packet)])?;
    if written != expected {
        return Err(std::io::Error::other(format!(
            "short TUN vnet write: {written}/{expected} bytes"
        )));
    }
    Ok(())
}

/// Write one IP packet whose IP/TCP header and payload chunks are separate
/// buffers, gathering them (with an optional `virtio_net_hdr`) into a single
/// `writev` so the payload is delivered copy-free. One `write(2)` atomically
/// delivers the whole packet on TUN, exactly as the single-buffer paths do. The
/// `iovec` is `[vnet?, header, chunk0, …]`; the caller bounds the chunk count
/// well below `IOV_MAX`.
fn write_tun_data_packet(
    file: &std::fs::File,
    header: &[u8],
    payload: &[Bytes],
    vnet: Option<VirtioNetHdr>,
) -> std::io::Result<()> {
    let mut w: &std::fs::File = file;
    let vnet = vnet.map(|vnet| vnet.encode());
    let mut iovecs: Vec<IoSlice<'_>> = Vec::with_capacity(2 + payload.len());
    let mut expected = header.len();
    if let Some(vnet) = vnet.as_ref() {
        iovecs.push(IoSlice::new(vnet));
        expected += vnet.len();
    }
    iovecs.push(IoSlice::new(header));
    for chunk in payload {
        iovecs.push(IoSlice::new(chunk));
        expected += chunk.len();
    }
    let written = w.write_vectored(&iovecs)?;
    if written != expected {
        return Err(std::io::Error::other(format!(
            "short TUN data write: {written}/{expected} bytes"
        )));
    }
    Ok(())
}
