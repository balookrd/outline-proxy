//! VLESS protocol constants + request/response header (de)serialization.
//!
//! The wire layout itself lives in `outline-wire` (shared with the server);
//! this module keeps the historical client-facing names.

pub(super) use outline_wire::vless::build_request_header;
#[cfg(test)]
pub(super) use outline_wire::vless::{
    ATYP_DOMAIN as VLESS_ATYP_DOMAIN, ATYP_IPV4 as VLESS_ATYP_IPV4,
};
pub(super) use outline_wire::vless::{
    COMMAND_TCP as VLESS_CMD_TCP, COMMAND_UDP as VLESS_CMD_UDP, VERSION as VLESS_VERSION,
};

pub(super) const MAX_VLESS_UDP_PAYLOAD: usize = 64 * 1024;
