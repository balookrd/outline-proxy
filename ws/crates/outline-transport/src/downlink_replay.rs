//! Wire-format parser for the Ack-Prefix Protocol v2 (Symmetric
//! Downlink Replay) control frame.
//!
//! Mirror of the server-side `outline-ss-rust`'s relay-side emit logic
//! in `server::resumption::downlink_ring` and the WS upgrade response
//! header `X-Outline-Resume-Symmetric-Replay`. The byte layout is
//! shared between the two repos and lives in
//! `docs/SESSION-RESUMPTION.md` § Symmetric Downlink Replay (v2) of
//! the server repo.
//!
//! Used by the SOCKS-side mid-session retry path: after the v1
//! 14-byte `"ORSM"` frame is consumed (see [`crate::ack_prefix`]),
//! and when both sides advertised the v2 capability, the next bytes
//! on the wire form the v2 `"ORDR"` frame — a 14-byte header
//! followed by `replay_len` payload bytes that the client must flush
//! to its SOCKS5 client BEFORE any subsequent fresh-upstream bytes.
//!
//! The parser handles the header only. The payload is read by the
//! reader's `consume_downlink_replay_with_timeout` helper, which
//! accumulates AEAD chunks until the full `header + replay_len`
//! plaintext is available.

/// ASCII magic identifying the v2 control frame. Distinguishes it
/// from the v1 `"ORSM"` frame and from accidental upstream bytes.
pub const MAGIC: [u8; 4] = *b"ORDR";

/// Wire-format version. Receivers that see a higher byte MUST drop
/// the session.
pub const VERSION_V1: u8 = 0x01;

/// `flags` bit 0: the server's downlink ring rolled past the
/// client-reported offset and the requested replay slice cannot be
/// reconstructed. When set, `replay_len` MUST be `0` and the client
/// observes an irrecoverable downstream gap (handled per
/// `tcp_mid_session_retry_overflow_policy`).
pub const FLAG_REPLAY_TRUNCATED: u8 = 0x01;

/// All flag bits this version of the parser knows about. A non-zero
/// bit outside this mask indicates a future protocol extension and
/// MUST cause the session to be dropped.
pub const FLAG_KNOWN_MASK: u8 = FLAG_REPLAY_TRUNCATED;

/// Total wire size of the v2 control-frame header, in bytes. Payload
/// of `replay_len` bytes follows immediately after.
pub const FRAME_HEADER_LEN_V1: usize = 14;

/// Outcome of a [`parse_v1`] attempt on the 14-byte header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseResult {
    /// The header is a valid v2 control frame. Carries the parsed
    /// `flags` byte (so callers can inspect [`FLAG_REPLAY_TRUNCATED`])
    /// and the `replay_len` declared by the server.
    Valid { flags: u8, replay_len: u64 },
    /// Buffer is shorter than [`FRAME_HEADER_LEN_V1`].
    TooShort,
    /// Magic does not match `"ORDR"` — drop session.
    BadMagic,
    /// Unrecognised version — drop session.
    UnsupportedVersion(u8),
    /// Reserved flag bits (outside [`FLAG_KNOWN_MASK`]) were set —
    /// drop session.
    ReservedFlagsSet(u8),
}

/// Parse the first 14 bytes of the v2 frame.
///
/// Layout:
///
/// ```text
///   +0  : magic        "ORDR"      4 bytes  ASCII
///   +4  : version      0x01        1 byte
///   +5  : flags        bitfield    1 byte   bit 0 = REPLAY_TRUNCATED
///   +6  : replay_len   u64 BE      8 bytes  payload bytes that follow
///   +14 : (header end)
/// ```
///
/// On `Valid` the caller continues to read exactly `replay_len` bytes
/// from the transport; those bytes are the server's downstream replay
/// payload. On any error variant the session MUST be dropped per spec.
pub fn parse_v1(buf: &[u8]) -> ParseResult {
    if buf.len() < FRAME_HEADER_LEN_V1 {
        return ParseResult::TooShort;
    }
    if buf[0..4] != MAGIC {
        return ParseResult::BadMagic;
    }
    if buf[4] != VERSION_V1 {
        return ParseResult::UnsupportedVersion(buf[4]);
    }
    let flags = buf[5];
    if flags & !FLAG_KNOWN_MASK != 0 {
        return ParseResult::ReservedFlagsSet(flags);
    }
    let replay_len = u64::from_be_bytes(
        buf[6..14]
            .try_into()
            .expect("FRAME_HEADER_LEN_V1 guarantees 8 bytes here"),
    );
    ParseResult::Valid { flags, replay_len }
}

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

#[cfg(test)]
#[path = "tests/downlink_replay.rs"]
mod tests;
