//! Wire-format parser for the Ack-Prefix Protocol v1 control frame.
//!
//! Mirror of the server-side serializer in `outline-ss-rust`'s
//! `server::resumption::ack_prefix` module: the byte layout is shared
//! between the two repos and lives in
//! `docs/SESSION-RESUMPTION.md` § Ack-Prefix Protocol (v1) of the
//! server repo.
//!
//! Used by the SOCKS-side mid-session retry path: when a client dials
//! with both `X-Outline-Resume: <id>` and
//! `X-Outline-Resume-Ack-Prefix: 1`, and the server response carries
//! the same capability header, the first decrypted SS-WS / VLESS-WS
//! data frame on the new transport is treated as a control frame.
//! [`parse_v1`] validates the magic / version / flags and returns the
//! `up_acked` byte offset; the caller uses that as the start position
//! for replay from its outbound ring buffer.

/// ASCII magic identifying the v1 control frame. Distinguishes it from
/// accidental upstream bytes that happen to start with the same prefix.
pub const MAGIC: [u8; 4] = *b"ORSM";

/// Wire-format version. Receivers that see a higher byte MUST drop the
/// session rather than risk upstream byte corruption from a misaligned
/// parse.
pub const VERSION_V1: u8 = 0x01;

/// Total wire size of the v1 control-frame payload, in bytes.
pub const FRAME_LEN_V1: usize = 14;

/// Outcome of a [`parse_v1`] attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseResult {
    /// The bytes are a valid v1 control frame; carries the `up_acked`
    /// counter from the server.
    Valid { up_acked: u64 },
    /// The buffer is shorter than [`FRAME_LEN_V1`] — caller may need
    /// to wait for more bytes if it is still streaming the first
    /// decrypted chunk. (Server's emit always sends the full 14 bytes
    /// in a single AEAD chunk, so receivers that decrypt one chunk at
    /// a time should not normally see this outcome.)
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

/// Parse the first decrypted frame as a v1 control frame.
///
/// Layout:
///
/// ```text
///   +0  : magic        "ORSM"      4 bytes  ASCII
///   +4  : version      0x01        1 byte
///   +5  : flags        0x00        1 byte   reserved (must be 0)
///   +6  : up_acked     u64 BE      8 bytes
///   +14 : (end)
/// ```
///
/// On success returns `Valid { up_acked }`. On any validation failure
/// the caller MUST drop the session and reconnect without advertising
/// the Ack-Prefix capability — see the strict-handling rules in the
/// spec.
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
#[path = "tests/ack_prefix.rs"]
mod tests;
