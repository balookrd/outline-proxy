//! Per-flow resume accounting for TUN TCP flows.
//!
//! A TUN TCP flow rides a *shared* carrier (one H3/H2/H1 connection multiplexes
//! many flows). When that carrier dies, every flow on it dies with it — even
//! though the server still holds each flow's upstream socket parked under the
//! Session ID it minted for that flow (see
//! `bins/outline-ss-rust/docs/SESSION-RESUMPTION.md`). Re-attaching the parked
//! upstream on a fresh carrier is byte-exact only if the client can answer two
//! questions at redial time:
//!
//!   1. *Which* parked upstream is mine? → the flow's own [`SessionId`].
//!   2. Which uplink bytes must be replayed, and from which offset? → the
//!      [`ClientUpstreamRingBuffer`] (uplink tail) plus `client_acked_offset`
//!      (the v2 `X-Outline-Resume-Down-Acked` value the server needs to compute
//!      its downlink replay slice).
//!
//! This module holds exactly that state and nothing else. **It only records.**
//! Nothing here dials, redials, or changes what happens when a carrier dies —
//! the migration itself is a separate change. Mirrors the accounting the SOCKS5
//! pinned relay already does inline
//! (`bins/outline-ws-rust/src/proxy/tcp/connect/pinned_relay.rs`).

use outline_transport::SessionId;
use outline_transport::uplink_replay::{ClientUpstreamRingBuffer, PushError};

/// Byte cap of one flow's uplink replay ring.
///
/// This is a **ceiling, not a preallocation**: [`ClientUpstreamRingBuffer::new`]
/// allocates nothing, and the ring only ever grows with the bytes the flow
/// actually sends upstream (FIFO-evicting once it reaches the cap). A flow that
/// never sends — an idle flow, or a pure download — holds zero bytes here.
///
/// Memory budget (AGENTS.md bounded-resources guardrail): worst case is
/// `max_flows × TUN_UPLINK_REPLAY_RING_BYTES`, reached only if *every* flow in
/// the table is simultaneously mid-upload; the steady state is far below that.
/// 64 KiB per flow also comfortably exceeds the largest single chunk the uplink
/// pump can hand us (one client segment, ≤ 65535 B of IP payload), so the
/// oversized-chunk path below is a guardrail rather than an expected event.
pub(in crate::tcp) const TUN_UPLINK_REPLAY_RING_BYTES: usize = 64 * 1024;

/// What a future carrier migration needs to re-attach this flow's parked
/// upstream on a new carrier without losing or duplicating a byte.
///
/// A flow is *resumable* while it holds a replay ring. It stops being resumable
/// the moment the ring can no longer reconstruct the uplink byte stream
/// exactly — see [`Self::record_uplink_chunk`]. That is a downgrade of a future
/// capability, never a reason to disturb the live flow.
pub(in crate::tcp) struct FlowResume {
    /// The Session ID the server minted for **this flow** on its carrier
    /// (`None` on a direct flow, or against a server without resumption).
    ///
    /// It is the flow's own id and must never be presented by another flow: on
    /// a resume hit the server ignores the handshake target and re-attaches
    /// whatever upstream is parked under the id, so a shared id would splice one
    /// flow onto another flow's destination.
    ///
    /// Recorded but not yet read outside tests: the only consumer is the redial
    /// that migrates the flow, which does not exist yet. It is captured now so
    /// that when it does, the id is the one this flow was actually issued rather
    /// than whatever happened to be cached for the uplink.
    #[allow(dead_code)]
    pub(in crate::tcp) session_id: Option<SessionId>,
    /// Bounded tail of the bytes this flow sent upstream, addressed by absolute
    /// offset. `None` once the flow is no longer replayable (never armed, or
    /// downgraded by an oversized chunk).
    replay: Option<ClientUpstreamRingBuffer>,
    /// Cumulative downstream *payload* bytes this flow has accepted from the
    /// server — the v2 `X-Outline-Resume-Down-Acked` value.
    ///
    /// A plain `u64` rather than the SOCKS relay's `Arc<AtomicU64>`: there the
    /// counter is shared by two independently-spawned relay closures and must
    /// survive them, whereas here both writers (the uplink pump and the downlink
    /// reader) already hold the flow mutex when they touch it, and the state
    /// outlives every per-flow task. An `Arc` would buy nothing but an
    /// allocation per flow.
    client_acked_offset: u64,
}

impl FlowResume {
    /// State for a flow that cannot be resumed: no id, no ring. This is what a
    /// flow is born with (no carrier yet) and what a direct flow keeps for life
    /// (a direct socket has no carrier to migrate off).
    pub(in crate::tcp) const fn disarmed() -> Self {
        Self {
            session_id: None,
            replay: None,
            client_acked_offset: 0,
        }
    }

    /// State for a freshly-connected tunneled flow: records `session_id` and
    /// arms a [`TUN_UPLINK_REPLAY_RING_BYTES`] replay ring.
    pub(in crate::tcp) fn armed(session_id: Option<SessionId>) -> Self {
        Self::armed_with_capacity(session_id, TUN_UPLINK_REPLAY_RING_BYTES)
    }

    /// [`Self::armed`] with an explicit ring cap. Production always takes the
    /// default; the cap is a parameter so tests can drive the overflow path
    /// without pushing 64 KiB through a flow.
    pub(in crate::tcp) fn armed_with_capacity(
        session_id: Option<SessionId>,
        capacity_bytes: usize,
    ) -> Self {
        Self {
            session_id,
            replay: Some(ClientUpstreamRingBuffer::new(capacity_bytes)),
            client_acked_offset: 0,
        }
    }

    /// Whether a byte-exact replay of this flow's uplink is still possible.
    pub(in crate::tcp) fn is_resumable(&self) -> bool {
        self.replay.is_some()
    }

    /// The replay ring, for callers that need its offsets (`total_sent`,
    /// `oldest_offset`) or its tail. `None` once the flow is no longer
    /// resumable.
    ///
    /// Read by tests today; the migration redial is what will read it in
    /// anger (`replay_from(server_acked_offset)`).
    #[allow(dead_code)]
    pub(in crate::tcp) fn replay(&self) -> Option<&ClientUpstreamRingBuffer> {
        self.replay.as_ref()
    }

    /// Cumulative downstream payload bytes accepted from the server — what the
    /// migration redial will send as `X-Outline-Resume-Down-Acked`. Read by
    /// tests today; there is no redial to send it yet.
    #[allow(dead_code)]
    pub(in crate::tcp) fn client_acked_offset(&self) -> u64 {
        self.client_acked_offset
    }

    /// Records a payload chunk handed to the upstream writer. Called with
    /// exactly the bytes, in exactly the order, that go out on the wire, so the
    /// ring's `total_sent()` tracks the server's view of this flow's uplink.
    ///
    /// A chunk larger than the ring cap cannot be held whole, and a ring that
    /// cannot hold it whole can never replay it — so the flow is downgraded to
    /// non-resumable (the ring is dropped, freeing what it held) and the error
    /// is handed back for the caller to log/count. **The chunk is still sent**:
    /// losing the ability to replay a future carrier death says nothing about
    /// the flow that is working right now, and turning this into a FIN/RST would
    /// break a live connection to protect a hypothetical one.
    pub(in crate::tcp) fn record_uplink_chunk(&mut self, chunk: &[u8]) -> Result<(), PushError> {
        let Some(ring) = self.replay.as_mut() else {
            return Ok(());
        };
        match ring.push(chunk) {
            Ok(()) => Ok(()),
            Err(error) => {
                self.replay = None;
                Err(error)
            },
        }
    }

    /// Records downstream payload bytes accepted from the server.
    ///
    /// "Accepted" is the moment the bytes land in this flow's downlink buffer,
    /// not the moment the TUN client ACKs them: from that point our own TCP
    /// state machine owns their delivery (and retransmission), so a resume must
    /// not ask the server to replay them a second time.
    ///
    /// Kept up to date even after the flow stops being resumable, so the counter
    /// stays a truthful "bytes taken from the server" for the whole flow.
    pub(in crate::tcp) fn record_downlink_payload(&mut self, len: usize) {
        self.client_acked_offset = self.client_acked_offset.saturating_add(len as u64);
    }
}

#[cfg(test)]
#[path = "tests/resume.rs"]
mod tests;
