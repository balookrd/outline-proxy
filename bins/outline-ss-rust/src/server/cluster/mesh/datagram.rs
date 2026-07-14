//! Length-delimited datagram framing over a mesh QUIC bi-stream.
//!
//! TCP-shaped carriers (`SsTcp` / `VlessTcp` / their `*Xhttp` variants) relay
//! as a transparent byte stream — chunk boundaries are irrelevant because the
//! home's padding decoder and AEAD are stream-oriented (see [`super::frame`]).
//! SS-UDP is different: one WebSocket `Binary` frame carries **exactly one**
//! AEAD-sealed SS-UDP packet with no length prefix, so a datagram boundary is
//! semantically load-bearing. Splicing SS-UDP as a raw byte stream would let
//! QUIC coalesce or split packets, and the home's per-packet AEAD open would
//! then fail on a mis-boundaried buffer.
//!
//! So an `SsUdp` relayed stream frames each datagram as `u32 BE length |
//! payload` over the same QUIC bi-stream. The stream is reliable and ordered,
//! which changes the mesh hop's semantics (no loss between edge and home) — an
//! acceptable, arguably better trade: the client↔target UDP path is still
//! best-effort over the last mile, and the mesh hop no longer drops packets.
//!
//! A `u32` prefix (not `u16`) is deliberate: a UDP payload maxes at 65507 bytes
//! but Shadowsocks-2022 framing plus carrier padding — whose padding segments
//! are each capped at `u16::MAX` and may be emitted several per datagram — push
//! the on-mesh datagram past 64 KiB, which would overflow a `u16` length.

use anyhow::{Context, Result, bail};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Hard upper bound on a single relayed UDP datagram. Comfortably above the
/// largest legitimate SS-UDP-plus-padding packet (a 65507-byte UDP payload plus
/// SS-2022 headers plus padding) while still rejecting a forged or corrupt
/// length prefix before it drives an unbounded allocation — a bounded-resource
/// guard on the relay read path.
pub(in crate::server) const MAX_UDP_DATAGRAM: usize = 128 * 1024;

/// Length prefix width in bytes (`u32` big-endian).
const LEN_PREFIX: usize = 4;

/// Writes one datagram as `u32 BE length | payload`. One call writes exactly one
/// datagram, so the reader reconstructs the identical boundary and SS-UDP's
/// one-frame-per-packet atomicity survives the mesh hop. Rejects a payload
/// larger than [`MAX_UDP_DATAGRAM`] rather than emitting an unreadable frame.
pub(in crate::server) async fn write_datagram<W>(writer: &mut W, payload: &[u8]) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    if payload.len() > MAX_UDP_DATAGRAM {
        bail!("mesh UDP datagram too large: {} bytes (max {MAX_UDP_DATAGRAM})", payload.len());
    }
    let len = payload.len() as u32;
    writer
        .write_all(&len.to_be_bytes())
        .await
        .context("writing mesh datagram length")?;
    writer
        .write_all(payload)
        .await
        .context("writing mesh datagram payload")?;
    Ok(())
}

/// Reads one datagram into `buf` (cleared, then refilled with exactly the
/// datagram's bytes — `buf.len()` equals the returned length on success).
///
/// Returns `Ok(None)` on a clean stream end **at a frame boundary** (the peer
/// finished the stream with no partial length prefix pending), `Ok(Some(len))`
/// with the datagram in `buf[..len]`, or an error on a truncated frame or a
/// length prefix exceeding [`MAX_UDP_DATAGRAM`].
pub(in crate::server) async fn read_datagram<R>(
    reader: &mut R,
    buf: &mut Vec<u8>,
) -> Result<Option<usize>>
where
    R: AsyncRead + Unpin,
{
    // Read the length prefix by hand so a clean EOF at the boundary (zero bytes
    // read) is distinguished from a truncated prefix (one to three bytes read).
    let mut len_buf = [0u8; LEN_PREFIX];
    let mut got = 0;
    while got < LEN_PREFIX {
        match reader
            .read(&mut len_buf[got..])
            .await
            .context("reading mesh datagram length")?
        {
            0 if got == 0 => return Ok(None),
            0 => bail!("truncated mesh datagram length prefix: {got} of {LEN_PREFIX} bytes"),
            n => got += n,
        }
    }

    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_UDP_DATAGRAM {
        bail!("mesh UDP datagram length {len} exceeds max {MAX_UDP_DATAGRAM}");
    }
    buf.clear();
    buf.reserve(len);
    // Fill the vector's spare capacity directly instead of `resize(len, 0)` +
    // `read_exact`: the resize memsets up to `MAX_UDP_DATAGRAM` bytes to zero on
    // every datagram, only for the read to overwrite them immediately. Reading
    // through a `take`-limited `read_to_end` writes into uninitialised spare
    // capacity, so the datagram lands with no zero-fill pass. A short read means
    // the peer ended the stream mid-payload — the same truncation `read_exact`
    // reported, surfaced with the frame's own diagnostics.
    let read = (&mut *reader)
        .take(len as u64)
        .read_to_end(buf)
        .await
        .context("reading mesh datagram payload")?;
    if read != len {
        bail!("truncated mesh datagram payload: {read} of {len} bytes");
    }
    Ok(Some(len))
}

#[cfg(test)]
#[path = "tests/datagram.rs"]
mod tests;
