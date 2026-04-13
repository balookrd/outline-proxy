use std::net::IpAddr;
use std::time::Duration;

use anyhow::Result;

use crate::tun_wire::IpVersion;
use crate::types::TargetAddr;

mod engine;
mod lifecycle;
mod types;
mod wire;

#[cfg(test)]
mod tests;

pub use self::engine::TunUdpEngine;
#[cfg(test)]
pub(crate) use self::wire::build_ipv4_udp_packet;
pub(crate) use self::wire::parse_udp_packet;

use self::types::{UdpFlowKey, UdpFlowState};

const TUN_FLOW_CLEANUP_INTERVAL: Duration = Duration::from_secs(30);

pub(crate) fn classify_tun_udp_forward_error(error: &anyhow::Error) -> &'static str {
    crate::error_text::classify_tun_udp_forward_error(error)
}

fn build_udp_payload(target: &TargetAddr, payload: &[u8]) -> Result<Vec<u8>> {
    let mut out = target.to_wire_bytes()?;
    out.extend_from_slice(payload);
    Ok(out)
}

fn ip_to_target(ip: IpAddr, port: u16) -> TargetAddr {
    match ip {
        IpAddr::V4(ip) => TargetAddr::IpV4(ip, port),
        IpAddr::V6(ip) => TargetAddr::IpV6(ip, port),
    }
}

fn ip_family_from_version(version: IpVersion) -> &'static str {
    match version {
        IpVersion::V4 => "ipv4",
        IpVersion::V6 => "ipv6",
    }
}
