//! Shadowsocks-2022 protocol types shared across outline crates.
//!
//! This crate owns the typed error enum produced by SS2022 framing/replay
//! logic. The codec itself lives in `outline-transport` (tightly coupled to
//! the WS/socket reader wrappers); consumers such as `outline-uplink`
//! classify the error without pulling in the full transport dependency tree.

use std::fmt;

/// Typed marker for Shadowsocks-2022 framing and replay errors. Placed in the
/// `anyhow` error chain (as a `bail!` value or `.context` layer) so that
/// classifiers can match by variant via `downcast_ref` instead of grepping
/// formatted strings.
#[derive(Debug)]
pub enum Ss2022Error {
    InvalidResponseHeaderLength(usize),
    InvalidResponseHeaderType(u8),
    RequestSaltMismatch,
    InvalidInitialTargetHeader,
    DuplicateOrOutOfOrderUdpPacket,
    OversizedUdpUplink,
}

impl fmt::Display for Ss2022Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Ss2022Error::InvalidResponseHeaderLength(len) => {
                write!(f, "invalid ss2022 response header length: {len}")
            },
            Ss2022Error::InvalidResponseHeaderType(ty) => {
                write!(f, "invalid ss2022 response header type: {ty}")
            },
            Ss2022Error::RequestSaltMismatch => {
                write!(f, "ss2022 response header request salt mismatch")
            },
            Ss2022Error::InvalidInitialTargetHeader => {
                write!(f, "invalid ss2022 initial target header")
            },
            Ss2022Error::DuplicateOrOutOfOrderUdpPacket => {
                write!(f, "duplicate or out-of-order ss2022 UDP packet")
            },
            Ss2022Error::OversizedUdpUplink => {
                write!(f, "oversized UDP packet dropped before uplink send")
            },
        }
    }
}

impl std::error::Error for Ss2022Error {}
