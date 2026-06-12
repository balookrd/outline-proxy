//! Session-resumption wire vocabulary shared by the server and the client.
//!
//! Owns the `X-Outline-*` header names negotiated on every WS upgrade /
//! CONNECT / XHTTP request and the byte layout of the Ack-Prefix Protocol
//! v1 control frame, so the two sides of the wire cannot drift. The
//! protocol-level contract lives in `docs/SESSION-RESUMPTION.md`; the
//! server's negotiation gates and the client's dial plumbing stay in
//! their respective crates — only the format-level vocabulary is here.

/// Lower-cased name of the request header carrying the Session ID a
/// client wishes to resume.
pub const RESUME_REQUEST_HEADER: &str = "x-outline-resume";

/// Lower-cased name of the request header advertising client support
/// for session resumption. Sent on every connect for as long as the
/// client wishes to receive future Session IDs.
pub const RESUME_CAPABLE_HEADER: &str = "x-outline-resume-capable";

/// Lower-cased name of the response header carrying the Session ID
/// the server has assigned to the just-established session.
pub const SESSION_RESPONSE_HEADER: &str = "x-outline-session";

/// Lower-cased name of the request **and** response header used to
/// negotiate the Ack-Prefix Protocol (v1). Client sets `1` to advertise
/// support; server echoes `1` to confirm. When both sides set the
/// header AND the resume hits, the server emits the
/// [`FRAME_LEN_V1`]-byte control frame ahead of the upstream→client
/// relay. See `docs/SESSION-RESUMPTION.md` § Ack-Prefix Protocol (v1).
pub const ACK_PREFIX_HEADER: &str = "x-outline-resume-ack-prefix";

/// Lower-cased name of the request **and** response header used to
/// negotiate the Symmetric Downlink Replay (v2) capability. Client
/// sets `1` to advertise support; server echoes `1` to confirm — but
/// only when v1 was also negotiated AND the server-side ring is
/// enabled (`downlink_buffer_bytes > 0`). See
/// `docs/SESSION-RESUMPTION.md` § Symmetric Downlink Replay (v2).
pub const SYMMETRIC_REPLAY_HEADER: &str = "x-outline-resume-symmetric-replay";

/// Lower-cased name of the request-only header carrying the client's
/// last-acked downstream offset on a v2 resume request. Decimal `u64`,
/// max `2^63 − 1`; absent or malformed values are treated as `0` per
/// spec. See `docs/SESSION-RESUMPTION.md` § Symmetric Downlink Replay
/// (v2).
pub const DOWN_ACKED_HEADER: &str = "x-outline-resume-down-acked";

/// ASCII signature distinguishing the v1 control frame from accidental
/// upstream bytes that happen to start with the same prefix. No
/// application-level upstream protocol is expected to begin with
/// `"ORSM"` (Outline Resume Sync Message) at the very first byte of a
/// resumed session, and the version + flags checks give a second layer
/// of defence.
pub const MAGIC: [u8; 4] = *b"ORSM";

/// Wire-format version. Future revisions bump this byte; receivers
/// that do not recognise a version MUST drop the session rather than
/// risk upstream byte corruption from a misaligned parse.
pub const VERSION_V1: u8 = 0x01;

/// Reserved flags byte. Must be `0` in v1; non-zero bits indicate a
/// future protocol extension the receiver does not understand.
pub const FLAGS_NONE: u8 = 0x00;

/// Total wire size of the v1 control-frame plaintext payload, in bytes.
/// Layout:
///
/// ```text
///   +0  : magic        "ORSM"      4 bytes  ASCII
///   +4  : version      0x01        1 byte
///   +5  : flags        0x00        1 byte   reserved
///   +6  : up_acked     u64 BE      8 bytes
///   +14 : (end)
/// ```
pub const FRAME_LEN_V1: usize = 14;

/// Serialise the v1 control frame plaintext (server side).
///
/// `up_acked` is the cumulative byte count the server has successfully
/// forwarded to the upstream `TcpStream` over the lifetime of the
/// session being resumed. The frame is plaintext at this layer —
/// callers feed it through the relay's normal AEAD encryption + WS
/// framing chain, identical to any other data chunk on the session.
pub fn build_v1_payload(up_acked: u64) -> [u8; FRAME_LEN_V1] {
    let mut buf = [0u8; FRAME_LEN_V1];
    buf[0..4].copy_from_slice(&MAGIC);
    buf[4] = VERSION_V1;
    buf[5] = FLAGS_NONE;
    buf[6..14].copy_from_slice(&up_acked.to_be_bytes());
    buf
}

/// Outcome of a [`parse_v1`] attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseResult {
    /// The bytes are a valid v1 control frame; carries the `up_acked`
    /// counter from the server.
    Valid { up_acked: u64 },
    /// The buffer is shorter than [`FRAME_LEN_V1`] — caller may need
    /// to wait for more bytes if it is still streaming the first
    /// decrypted chunk. (The server's emit always sends the full 14
    /// bytes in a single AEAD chunk, so receivers that decrypt one
    /// chunk at a time should not normally see this outcome.)
    TooShort,
    /// Magic does not match `"ORSM"`. Receiver should drop the session
    /// — the prefix is unrecognised and continuing would risk upstream
    /// byte corruption from misinterpreting these bytes as data.
    BadMagic,
    /// Wire-format version is not v1. Same handling as `BadMagic`:
    /// drop and reconnect without the capability.
    UnsupportedVersion(u8),
    /// Reserved flags byte was non-zero — indicates a future protocol
    /// extension this receiver does not understand.
    ReservedFlagsSet(u8),
}

/// Parse the first decrypted frame of a resumed session as a v1
/// control frame (client side).
///
/// On success returns `Valid { up_acked }`; the caller uses the offset
/// as the start position for replay from its outbound ring buffer. On
/// any validation failure the caller MUST drop the session and
/// reconnect without advertising the Ack-Prefix capability — see the
/// strict-handling rules in the spec.
pub fn parse_v1(buf: &[u8]) -> ParseResult {
    if buf.len() < FRAME_LEN_V1 {
        return ParseResult::TooShort;
    }
    if buf[0..4] != MAGIC {
        return ParseResult::BadMagic;
    }
    if buf[4] != VERSION_V1 {
        return ParseResult::UnsupportedVersion(buf[4]);
    }
    if buf[5] != 0 {
        return ParseResult::ReservedFlagsSet(buf[5]);
    }
    let up_acked =
        u64::from_be_bytes(buf[6..14].try_into().expect("FRAME_LEN_V1 guarantees 8 bytes here"));
    ParseResult::Valid { up_acked }
}

#[cfg(test)]
#[path = "tests/resume.rs"]
mod tests;
