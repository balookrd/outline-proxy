//! Shared writer handle for the TUN device.
//!
//! Wraps the TUN fd (`AsyncFd` in production, a blocking `File` behind a
//! mutex in tests) and exposes async `write_packet` that parks on kernel
//! writability. Each `write(2)` delivers exactly one IP packet on TUN, so
//! concurrent writers don't need a user-space lock in the async case.

use std::io::{IoSlice, Write as _};
use std::sync::Arc;

use anyhow::{Context, Result};
use tokio::io::Interest;
use tokio::io::unix::AsyncFd;

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

    /// Write a batch of IP packets to the TUN device, one `write(2)` per packet.
    pub(crate) async fn write_packets(&self, packets: &[Vec<u8>]) -> Result<()> {
        for packet in packets {
            self.write_packet(packet).await?;
        }
        Ok(())
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
