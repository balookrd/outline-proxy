use std::io;

/// Typed error returned by SOCKS5 parsing, negotiation, and reassembly.
///
/// Variants are grouped by concern:
///
/// * [`Socks5Error::Io`] wraps a raw `std::io::Error` with a short static
///   context string so callers get a breadcrumb without allocating.
/// * Every other variant corresponds to a specific protocol violation or
///   unsupported field value, so callers can match on them rather than
///   parsing error strings.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Socks5Error {
    #[error("{context}")]
    Io {
        context: &'static str,
        #[source]
        source: io::Error,
    },

    #[error("unsupported SOCKS version: {0}")]
    UnsupportedVersion(u8),

    #[error("unsupported SOCKS command: {0}")]
    UnsupportedCommand(u8),

    #[error("unsupported SOCKS auth method (no acceptable method advertised by client)")]
    UnsupportedAuthMethod,

    #[error("unsupported username/password auth version: {0}")]
    UnsupportedAuthVersion(u8),

    #[error("invalid SOCKS5 username/password credentials")]
    InvalidCredentials,

    #[error("invalid request version: {0}")]
    InvalidRequestVersion(u8),

    #[error("reserved byte is not zero")]
    ReservedByteNonZero,

    #[error("UDP packet is too short")]
    UdpPacketTooShort,

    #[error("invalid UDP reserved bytes")]
    InvalidUdpReservedBytes,

    #[error("invalid fragmented UDP packet with fragment number 0")]
    InvalidUdpFragmentZero,

    #[error("out-of-order or duplicate UDP fragment: {0}")]
    OutOfOrderUdpFragment(u8),

    #[error("fragment target changed within UDP fragment sequence")]
    FragmentTargetChanged,

    #[error("UDP fragment sequence exceeded reassembly byte cap ({projected} > {limit})")]
    ReassemblyCapExceeded { projected: usize, limit: usize },

    #[error("invalid UDP-in-TCP header length: {0}")]
    InvalidUdpInTcpHeaderLen(u16),

    #[error("UDP-in-TCP header length mismatch")]
    UdpInTcpHeaderMismatch,

    #[error("UDP-in-TCP {field} exceeds u16 framing limit")]
    UdpInTcpFrameTooLarge { field: &'static str },

    #[error("unsupported address type: {0}")]
    UnsupportedAddressType(u8),

    #[error("short {kind} address")]
    ShortAddress { kind: &'static str },

    #[error("domain name is too long for SOCKS5")]
    DomainTooLong,

    #[error("domain is not valid UTF-8")]
    DomainNotUtf8,

    #[error("empty address buffer")]
    EmptyAddressBuffer,
}

impl Socks5Error {
    /// Wrap an `std::io::Error` with a static context string.
    /// Usage: `stream.read_exact(&mut buf).await.map_err(Socks5Error::io("reading header"))?`.
    pub fn io(context: &'static str) -> impl FnOnce(io::Error) -> Self {
        move |source| Socks5Error::Io { context, source }
    }
}

pub type Result<T> = std::result::Result<T, Socks5Error>;
