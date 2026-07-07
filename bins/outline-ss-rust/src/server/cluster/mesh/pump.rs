//! Bidirectional relay pump between a client carrier and a mesh stream.
//!
//! Mirrors the shape of the direct relay (`server::relay`): exactly one writer
//! per direction and no intermediate queue beyond a copy buffer, so
//! backpressure is honest — it rides the QUIC stream flow-control window rather
//! than an unbounded in-memory buffer. This is the failure class that bit the
//! TUN pump, so there is deliberately no blind coalescing here: each direction
//! is a straight `copy` that reads then fully writes before reading again.
//!
//! The uplink copies carrier→mesh; the downlink copies mesh→carrier. On EOF a
//! direction shuts its writer down (FIN) so the peer observes a clean close.
//! The pump returns once both directions have completed (full duplex) or one
//! errors.

use anyhow::{Context, Result};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

/// Splices a client `carrier` to a mesh stream's `mesh_send`/`mesh_recv`
/// halves. Generic over the byte streams so it is exercised over in-memory
/// duplexes in tests and over `quinn` streams in production.
pub(in crate::server) async fn pump<C, S, R>(
    carrier: C,
    mut mesh_send: S,
    mut mesh_recv: R,
) -> Result<()>
where
    C: AsyncRead + AsyncWrite + Unpin + Send,
    S: AsyncWrite + Unpin + Send,
    R: AsyncRead + Unpin + Send,
{
    let (mut carrier_read, mut carrier_write) = tokio::io::split(carrier);

    // Uplink: the ONLY writer to `mesh_send`.
    let uplink = async {
        tokio::io::copy(&mut carrier_read, &mut mesh_send).await?;
        mesh_send.shutdown().await?;
        Ok::<(), std::io::Error>(())
    };
    // Downlink: the ONLY writer to `carrier_write`.
    let downlink = async {
        tokio::io::copy(&mut mesh_recv, &mut carrier_write).await?;
        carrier_write.shutdown().await?;
        Ok::<(), std::io::Error>(())
    };

    tokio::try_join!(uplink, downlink).context("mesh relay pump")?;
    Ok(())
}

#[cfg(test)]
#[path = "tests/pump.rs"]
mod tests;
