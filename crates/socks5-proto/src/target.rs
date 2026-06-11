//! Target address type shared with the server side via `outline-wire`.
//!
//! Re-exported here so SOCKS5 consumers keep importing it from
//! `socks5_proto`; the codec itself (SOCKS5 ATYP wire shape) lives in the
//! shared crate. Address parse/encode errors surface as
//! [`TargetAddrError`](outline_wire::TargetAddrError) and convert into
//! [`Socks5Error`](crate::Socks5Error) via `?`.

pub use outline_wire::target::{
    SOCKS_ATYP_DOMAIN, SOCKS_ATYP_IPV4, SOCKS_ATYP_IPV6, TargetAddr, socket_addr_to_target,
};
