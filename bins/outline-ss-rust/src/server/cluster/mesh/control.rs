//! Mesh control datagrams: out-of-band signals between cluster members that ride
//! QUIC datagrams on the mesh connection, separate from the relay stream.
//!
//! A relay stream is an OPEN header followed by a raw byte stream (or
//! length-framed datagrams for SS-UDP) — there is no room for mid-stream control
//! framing without corrupting the relayed carrier. Control signals therefore
//! travel as QUIC datagrams on the same connection, keyed by the relayed
//! session's id so the home can route them to the right relay task.
//!
//! Currently the only signal is `THROTTLE_HINT`: an edge that detects the
//! *client* segment is throttled (its write toward the client stalls while the
//! home keeps feeding it) tells the home, which injects an `OCTL` cover frame
//! into the relayed downlink so the client backs off. It is best-effort — a lost
//! datagram is re-sent on the next detection window, and the client-side
//! cooldown is idempotent, so QUIC datagrams (unreliable, unordered) fit.

use anyhow::{Result, bail};

/// Datagram type tag (first byte). Room for more control kinds later.
const KIND_THROTTLE_HINT: u8 = 1;

/// Wire length of a THROTTLE_HINT datagram: `kind(1) | session_id(16)`.
const THROTTLE_HINT_LEN: usize = 1 + 16;

/// A parsed mesh control datagram.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::server) enum ControlDatagram {
    /// The edge detected a throttled client segment for this relayed session;
    /// the home should nudge the client (inject an `OCTL` cover frame).
    ThrottleHint { session_id: [u8; 16] },
}

/// Encodes a THROTTLE_HINT datagram: `KIND_THROTTLE_HINT | session_id`.
pub(in crate::server) fn encode_throttle_hint(session_id: &[u8; 16]) -> Vec<u8> {
    let mut out = Vec::with_capacity(THROTTLE_HINT_LEN);
    out.push(KIND_THROTTLE_HINT);
    out.extend_from_slice(session_id);
    out
}

/// Parses a mesh control datagram. Total and side-effect-free: an unknown kind,
/// an empty datagram or a wrong length is an error the receiver logs and drops
/// (control datagrams are best-effort, so a bad one is never fatal).
pub(in crate::server) fn parse_control_datagram(bytes: &[u8]) -> Result<ControlDatagram> {
    match bytes.first() {
        Some(&KIND_THROTTLE_HINT) => {
            if bytes.len() != THROTTLE_HINT_LEN {
                bail!(
                    "throttle hint datagram wrong length: {} (want {THROTTLE_HINT_LEN})",
                    bytes.len()
                );
            }
            let mut session_id = [0u8; 16];
            session_id.copy_from_slice(&bytes[1..THROTTLE_HINT_LEN]);
            Ok(ControlDatagram::ThrottleHint { session_id })
        },
        Some(&other) => bail!("unknown mesh control datagram kind {other}"),
        None => bail!("empty mesh control datagram"),
    }
}

#[cfg(test)]
#[path = "tests/control.rs"]
mod tests;
