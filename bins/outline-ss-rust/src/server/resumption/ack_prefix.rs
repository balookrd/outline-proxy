//! Wire format for the Ack-Prefix Protocol v1 control frame.
//!
//! See `docs/SESSION-RESUMPTION.md` § Ack-Prefix Protocol (v1) for the
//! protocol-level description; this module owns the byte layout and a
//! small serializer used by the server-side resume-hit branch in
//! `src/server/transport/tcp.rs`.
//!
//! The frame is **plaintext** at this layer — callers feed the 14-byte
//! payload returned by [`build_v1_payload`] through the SS-WS / VLESS-WS
//! relay's normal AEAD encryption + WS framing chain, identical to any
//! other data chunk on the same session. The client's receive path
//! decrypts the first frame after a resume request, validates the
//! magic / version / flags, then reads `up_acked` and uses it as the
//! offset into its replay buffer.

/// ASCII signature distinguishing the control frame from accidental
/// upstream bytes that happen to start with the same prefix. No
/// application-level upstream protocol is expected to begin with
/// `"ORSM"` (Outline Resume Sync Message) at the very first byte of a
/// resumed session, and the version + flags checks below give a second
/// layer of defence.
pub(crate) const MAGIC: [u8; 4] = *b"ORSM";

/// Wire-format version. Future revisions bump this byte; clients that
/// do not recognise a version MUST drop the session rather than risk
/// upstream byte corruption from a misaligned parse.
pub(crate) const VERSION_V1: u8 = 0x01;

/// Reserved flags byte. Must be `0` in v1; non-zero bits indicate a
/// future protocol extension the receiver does not understand.
pub(crate) const FLAGS_NONE: u8 = 0x00;

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
pub(crate) const FRAME_LEN_V1: usize = 14;

/// Serialise the v1 control frame plaintext.
///
/// `up_acked` is the cumulative byte count the server has successfully
/// forwarded to the upstream `TcpStream` over the lifetime of this
/// session. Callers read it from
/// [`super::parked::ParkedTcp::upstream_bytes_acked`] (loaded with
/// `Ordering::Relaxed`) right before emitting the frame.
pub(crate) fn build_v1_payload(up_acked: u64) -> [u8; FRAME_LEN_V1] {
    let mut buf = [0u8; FRAME_LEN_V1];
    buf[0..4].copy_from_slice(&MAGIC);
    buf[4] = VERSION_V1;
    buf[5] = FLAGS_NONE;
    buf[6..14].copy_from_slice(&up_acked.to_be_bytes());
    buf
}

#[cfg(test)]
#[path = "tests/ack_prefix.rs"]
mod tests;
