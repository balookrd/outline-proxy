use std::fmt;

use anyhow::{Result, bail};
use serde::Deserialize;

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

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
#[derive(Default)]
pub enum UplinkTransport {
    #[default]
    Websocket,
    Shadowsocks,
}

impl std::str::FromStr for UplinkTransport {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        match s {
            "websocket" => Ok(Self::Websocket),
            "shadowsocks" => Ok(Self::Shadowsocks),
            _ => bail!("unsupported uplink transport: {s}"),
        }
    }
}

impl fmt::Display for UplinkTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value = match self {
            Self::Websocket => "websocket",
            Self::Shadowsocks => "shadowsocks",
        };
        f.write_str(value)
    }
}
