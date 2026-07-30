use std::fmt;
use std::time::Duration;

use anyhow::Result;

use crate::wire::{ip_family_from_version, ip_to_target};
use outline_uplink::{TransportKind, UplinkManager};
use socks5_proto::TargetAddr;

mod drop_cache;
mod engine;
mod eviction;
mod lifecycle;
mod sni_cache;
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
pub(crate) use self::engine::{should_emit_ptb_for_limit, should_emit_ptb_now};
#[cfg(test)]
pub(crate) use self::wire::build_ipv4_udp_packet;
pub(crate) use self::wire::parse_udp_packet;
pub(crate) use self::wire::resegment_udp_gso;

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

/// What a strict-`active_passive` group's active-uplink pointer says about a UDP
/// flow bound to `flow_index`. The UDP twin of the TCP engine's
/// `ActiveUplinkVerdict`, and deliberately the same three-way shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum UdpActiveUplinkVerdict {
    /// Leave the flow alone: the group is not strict, the flow is still on the
    /// active uplink, or it has not been bound to one yet.
    Stay,
    /// The pointer moved off this flow's uplink on a switch that means to
    /// abandon it (an operator drain), or off a group with no shared resume
    /// scope to migrate into. Tear the flow down, exactly as this group always
    /// has.
    Abort,
    /// The pointer moved on a switch that is not a decision to abandon the flow
    /// — an operator soft switch, or any machine-driven repoint. Carry it over
    /// to `target` instead of tearing it down.
    Migrate { target: usize },
}

/// Policy predicate for a UDP flow; see [`UdpActiveUplinkVerdict`].
///
/// Reads the published `ActiveUplinksSnapshot` rather than the manager's async
/// `active_uplinks` lock. That lock never carried the switch intent at all,
/// which is why every repoint — an operator soft switch included — read here as
/// a teardown. It also keeps this off an async lock, and it is consulted once
/// per datagram in a strict scope.
///
/// `usize::MAX` marks a flow whose dial has not resolved an uplink yet; it has
/// no carrier to migrate and nothing to tear down, so it is never disturbed.
pub(super) fn udp_active_uplink_verdict(
    manager: &UplinkManager,
    flow_index: usize,
) -> UdpActiveUplinkVerdict {
    if flow_index == usize::MAX || !manager.strict_active_uplink_for(TransportKind::Udp) {
        return UdpActiveUplinkVerdict::Stay;
    }
    let snapshot = manager.active_uplinks_snapshot();
    let Some(active) = snapshot.udp_for(manager.strict_global_active_uplink()) else {
        return UdpActiveUplinkVerdict::Stay;
    };
    if active == flow_index {
        return UdpActiveUplinkVerdict::Stay;
    }
    if snapshot.intent.migrates_live_flows(manager.shared_resume()) {
        UdpActiveUplinkVerdict::Migrate { target: active }
    } else {
        UdpActiveUplinkVerdict::Abort
    }
}
