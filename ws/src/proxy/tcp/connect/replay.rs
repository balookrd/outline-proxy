use anyhow::{Context, Result};
use bytes::BytesMut;

use outline_transport::TcpWriter;

use super::super::failover::MAX_CHUNK0_FAILOVER_BUF;

/// Accumulates client→upstream bytes during the chunk-0 failover window so
/// they can be replayed verbatim to a replacement uplink if the first one
/// fails before returning any response data.
///
/// Once the total buffered size exceeds [`MAX_CHUNK0_FAILOVER_BUF`],
/// `overflow` is set and cross-uplink failover is disabled — the upstream is
/// given the full `upstream_response` window instead of the aggressive
/// chunk-0 timeout, and no replay attempt is made on any subsequent uplink.
pub(super) struct ReplayBufState {
    /// All chunk bytes stored contiguously; avoids one heap allocation per chunk.
    buf: BytesMut,
    /// End offset of each logical chunk within `buf`.
    splits: Vec<usize>,
    total: usize,
    pub(super) overflow: bool,
}

impl ReplayBufState {
    pub(super) fn new() -> Self {
        Self {
            buf: BytesMut::new(),
            splits: Vec::with_capacity(8),
            total: 0,
            overflow: false,
        }
    }

    /// Attempts to buffer `chunk`.
    ///
    /// Returns `true` if this call caused `overflow` to be set for the
    /// **first time** — the caller should promote `attempt_timeout` to the
    /// full `upstream_response` window immediately.  Returns `false` either
    /// when the chunk was buffered successfully or when overflow was already
    /// set on a prior call (no-op).
    pub(super) fn push(&mut self, chunk: &[u8]) -> bool {
        if self.overflow {
            return false;
        }
        if self.total + chunk.len() <= MAX_CHUNK0_FAILOVER_BUF {
            self.buf.extend_from_slice(chunk);
            self.total += chunk.len();
            self.splits.push(self.total);
            false
        } else {
            self.overflow = true;
            true // overflow just triggered
        }
    }

    /// Sends every buffered chunk to `writer` in order.  Wraps errors with
    /// the supplied `context` string before propagating.
    pub(super) async fn replay_to(
        &self,
        writer: &mut TcpWriter,
        context: &'static str,
    ) -> Result<()> {
        let bytes = &self.buf[..];
        let mut start = 0;
        for &end in &self.splits {
            writer.send_chunk(&bytes[start..end]).await.context(context)?;
            start = end;
        }
        Ok(())
    }
}
