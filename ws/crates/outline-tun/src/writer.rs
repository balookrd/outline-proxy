//! Shared writer handle for the TUN device.
//!
//! Wraps the TUN fd (`AsyncFd` in production, a blocking `File` behind a
//! mutex in tests) and exposes async `write_packet` that parks on kernel
//! writability. Each `write(2)` delivers exactly one IP packet on TUN, so
//! concurrent writers don't need a user-space lock in the async case.

use std::io::Write as _;
use std::sync::Arc;

use anyhow::{Context, Result};
use tokio::io::Interest;
use tokio::io::unix::AsyncFd;

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
}

#[derive(Clone)]
enum SharedTunWriterInner {
    Async(Arc<AsyncFd<std::fs::File>>),
    #[cfg(test)]
    Blocking(Arc<parking_lot::Mutex<std::fs::File>>),
}

impl SharedTunWriter {
    pub(crate) fn from_async_fd(fd: Arc<AsyncFd<std::fs::File>>) -> Self {
        Self { inner: SharedTunWriterInner::Async(fd) }
    }

    #[cfg(test)]
    pub(crate) fn new(file: std::fs::File) -> Self {
        Self {
            inner: SharedTunWriterInner::Blocking(Arc::new(parking_lot::Mutex::new(file))),
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
        match &self.inner {
            SharedTunWriterInner::Async(fd) => {
                fd.async_io(Interest::WRITABLE, |f| write_tun_packet(f, packet))
                    .await
                    .context("failed to write packet to TUN")
            },
            #[cfg(test)]
            SharedTunWriterInner::Blocking(mutex) => mutex
                .lock()
                .write_all(packet)
                .context("failed to write packet to TUN"),
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

fn write_tun_packet(file: &std::fs::File, packet: &[u8]) -> std::io::Result<()> {
    let mut w: &std::fs::File = file;
    let written = w.write(packet)?;
    if written != packet.len() {
        return Err(std::io::Error::other(format!(
            "short TUN write: {written}/{} bytes",
            packet.len()
        )));
    }
    Ok(())
}
