// `CipherKind` lives in the `shadowsocks-crypto` workspace crate; re-exported
// here so existing `crate::types::CipherKind` imports keep working.
pub use shadowsocks_crypto::CipherKind;
// SOCKS5 address primitives live in the `socks5-proto` workspace crate;
// re-exported for the same reason.
pub use socks5_proto::{
    SOCKS_ATYP_DOMAIN, SOCKS_ATYP_IPV4, SOCKS_ATYP_IPV6, TargetAddr, socket_addr_to_target,
};
// Transport address + mode types live in the `outline-transport` workspace
// crate; re-exported for the same reason.
pub use outline_transport::{ServerAddr, WsTransportMode};
// Uplink transport enum lives in the `outline-uplink` workspace crate;
// re-exported for the same reason.
pub use outline_uplink::UplinkTransport;
