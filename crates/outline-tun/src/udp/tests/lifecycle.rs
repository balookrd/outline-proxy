//! Tests for the UDP flow-reader's clean-close classification.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use anyhow::anyhow;
use outline_transport::WsClosed;
use socks5_proto::TargetAddr;

use super::is_clean_ws_close;
use crate::udp::UdpFlowKey;
use crate::wire::IpVersion;

#[test]
fn bare_ws_closed_is_clean() {
    let err = anyhow::Error::from(WsClosed);
    assert!(
        is_clean_ws_close(&err),
        "a bare WsClosed marker must classify as a clean close, not a runtime failure",
    );
}

#[test]
fn ws_closed_under_context_is_clean() {
    // The reader propagates the read error up through `?`, which can layer
    // additional context on top of the typed marker. The chain walk must still
    // find `WsClosed` underneath — otherwise a routine close would be charged
    // as a data-plane failure the moment any context is added.
    let err = anyhow::Error::from(WsClosed).context("reading UDP downlink packet");
    assert!(
        is_clean_ws_close(&err),
        "WsClosed beneath a context layer must still classify as a clean close",
    );
}

#[test]
fn dirty_read_error_is_not_clean() {
    // A real transport error (e.g. the 1013 "front alive, back dead" close)
    // carries no WsClosed marker and MUST still escalate as a runtime failure.
    let err = anyhow!("websocket read failed: IO error: Invalid close code: 1013");
    assert!(
        !is_clean_ws_close(&err),
        "a genuine read error must NOT be suppressed as a clean close",
    );
}

#[test]
fn udp_response_sources_from_client_dialled_addr_across_family_mismatch() {
    // Regression: with QUIC/UDP destination override the exit can resolve the
    // sniffed domain to a *different family* than the client's flow. The exit
    // then tags its response with that (here IPv6) address. The reader must
    // still build the client reply from the IPv4 address the client dialled —
    // not bail with "unexpected response address family" and tear the flow down
    // (which killed QUIC video once IPv6 was disabled and everything fell to v4).
    let exit_v6 = TargetAddr::IpV6(Ipv6Addr::new(0x2a00, 0x1450, 0, 0, 0, 0, 0, 0x200e), 443);
    let mut payload = exit_v6.to_wire_bytes().unwrap();
    payload.extend_from_slice(b"VIDEO");

    let key = UdpFlowKey {
        version: IpVersion::V4,
        local_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        local_port: 50000,
        remote_ip: IpAddr::V4(Ipv4Addr::new(142, 250, 1, 14)),
        remote_port: 443,
    };

    // Building straight from the exit's IPv6 address on an IPv4 flow is exactly
    // the bail the old reader hit.
    assert!(
        super::super::wire::build_response_packet(
            key.version,
            &exit_v6,
            key.local_ip,
            key.local_port,
            b"VIDEO",
        )
        .is_err(),
        "echoing the exit's mismatched-family address must fail to build",
    );

    // The fix sources the reply from the client-dialled IPv4 address, so the
    // packet builds and carries the payload regardless of the exit's family.
    let pkt = super::build_client_response_packet(&key, &payload).unwrap();
    assert_eq!(pkt[0] >> 4, 4, "must be an IPv4 packet (client's family)");
    assert!(pkt.ends_with(b"VIDEO"), "payload must follow the rewritten header");
}
