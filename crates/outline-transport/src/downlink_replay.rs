//! Client-side surface of the Ack-Prefix Protocol v2 (Symmetric
//! Downlink Replay) control frame.
//!
//! The byte layout — constants, header builder, parser — lives in
//! [`outline_wire::resume::downlink_replay`], shared with the server's
//! resume-emit paths so the two sides cannot drift; this module
//! re-exports that vocabulary for the readers in this crate and keeps
//! only the transport-level [`DownlinkReplayOutcome`]. The
//! protocol-level contract is specified in
//! `bins/outline-ss-rust/docs/SESSION-RESUMPTION.md` § Symmetric
//! Downlink Replay (v2).
//!
//! Used by the SOCKS-side mid-session retry path: after the v1
//! 14-byte `"ORSM"` frame is consumed (see `outline_wire::resume`),
//! and when both sides advertised the v2 capability, the next bytes
//! on the wire form the v2 `"ORDR"` frame — a 14-byte header
//! followed by `replay_len` payload bytes that the client must flush
//! to its SOCKS5 client BEFORE any subsequent fresh-upstream bytes.
//!
//! The parser handles the header only. The payload is read by the
//! reader's `consume_downlink_replay_with_timeout` helper, which
//! accumulates AEAD chunks until the full `header + replay_len`
//! plaintext is available.

pub use outline_wire::resume::downlink_replay::{
    FLAG_KNOWN_MASK, FLAG_REPLAY_TRUNCATED, FLAGS_NONE, FRAME_HEADER_LEN_V1, MAGIC, ParseResult,
    VERSION_V1, parse_v1,
};

/// Outcome of [`crate::tcp_transport::TcpReader::consume_downlink_replay_with_timeout`]
/// — and the matching method on the VLESS reader. Surfaces the
/// orchestrator-relevant distinction between "server replayed N bytes"
/// (the happy path; flush them to SOCKS5 before fresh upstream bytes)
/// and "server signalled truncation" (the client's reported offset is
/// outside the retained ring window; orchestrator decides session
/// policy per `tcp_mid_session_retry_overflow_policy`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DownlinkReplayOutcome {
    /// Server emitted `payload` plaintext bytes that the client must
    /// flush to its SOCKS5 client BEFORE any subsequent fresh-upstream
    /// bytes flow. Always `Vec<u8>` even on a 0-byte replay (legitimate
    /// when the client's offset already matches `total_sent_downlink`).
    Replay(Vec<u8>),
    /// Server signalled `REPLAY_TRUNCATED` — the requested replay slice
    /// is partially or fully outside the retained ring window. The
    /// downstream byte stream has an irrecoverable gap; the
    /// orchestrator handles per overflow policy.
    Truncated,
}
