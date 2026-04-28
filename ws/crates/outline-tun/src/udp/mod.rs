use std::fmt;
use std::time::Duration;

use anyhow::Result;

use crate::wire::{ip_family_from_version, ip_to_target};
use outline_metrics as metrics;
use outline_uplink::{TransportKind, UplinkManager};
use socks5_proto::TargetAddr;

mod engine;
mod lifecycle;
mod types;
mod wire;

/// Typed marker placed in the error chain when every UDP uplink candidate
/// failed during TUN flow setup. Classifiers match this via downcast instead
/// of substring-matching the formatted error string.
#[derive(Debug)]
pub(crate) struct AllUdpUplinksFailed;

impl fmt::Display for AllUdpUplinksFailed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "all UDP uplinks failed")
    }
}

impl std::error::Error for AllUdpUplinksFailed {}

#[cfg(test)]
mod tests;

pub use self::engine::TunUdpEngine;
#[cfg(test)]
pub(crate) use self::wire::build_ipv4_udp_packet;
pub(crate) use self::wire::parse_udp_packet;

use self::types::{UdpFlowKey, UdpFlowState};

const TUN_FLOW_CLEANUP_INTERVAL: Duration = Duration::from_secs(30);

pub(crate) fn classify_tun_udp_forward_error(error: &anyhow::Error) -> &'static str {
    crate::error_classify::classify_tun_udp_forward_error(error)
}

fn build_udp_payload(target: &TargetAddr, payload: &[u8]) -> Result<Vec<u8>> {
    let mut out = target.to_wire_bytes()?;
    out.extend_from_slice(payload);
    Ok(out)
}

/// Record a UDP datagram and its byte count in one call. Every site that
/// emits `add_udp_datagram` also emits the matching `add_bytes("udp", ...)`,
/// so collapsing them removes the risk of one getting out of sync.
pub(super) fn record_udp_xfer(
    direction: &'static str,
    group: &str,
    uplink: &str,
    bytes: usize,
) {
    metrics::add_udp_datagram(direction, group, uplink);
    metrics::add_bytes("udp", direction, group, uplink, bytes);
}

/// Returns `true` when a flow bound to `flow_index` must be torn down
/// because its group is in strict-active-uplink mode and has repointed to a
/// different uplink.
pub(super) async fn should_migrate_flow(
    manager: &UplinkManager,
    flow_index: usize,
) -> bool {
    if !manager.strict_active_uplink_for(TransportKind::Udp) {
        return false;
    }
    manager
        .active_uplink_index_for_transport(TransportKind::Udp)
        .await
        .is_some_and(|active| active != flow_index)
}
