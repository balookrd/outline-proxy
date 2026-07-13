//! Tests for the pre-resolved byte / datagram counter handles: the resolved
//! handle must write into exactly the same series the per-call `add_bytes` /
//! `add_udp_datagram` path did.

use crate::{
    DIRECT_GROUP_LABEL, DIRECT_UPLINK_LABEL, direct_tcp_bytes, direct_udp_counters,
    flow_bytes_counter, udp_flow_counters,
};

fn bytes_series(protocol: &str, direction: &str, group: &str, uplink: &str) -> u64 {
    crate::METRICS
        .bytes_total
        .with_label_values(&[protocol, direction, group, uplink])
        .get()
}

fn datagram_series(direction: &str, group: &str, uplink: &str) -> u64 {
    crate::METRICS
        .udp_datagrams_total
        .with_label_values(&[direction, group, uplink])
        .get()
}

#[test]
fn flow_bytes_counter_writes_the_labelled_series() {
    // Unique labels keep this series independent of every other test.
    let (group, uplink) = ("flow_bytes_grp", "flow_bytes_up");

    flow_bytes_counter("tcp", "up", group, uplink).add(1500);
    flow_bytes_counter("tcp", "up", group, uplink).add(500);

    assert_eq!(bytes_series("tcp", "up", group, uplink), 2000);
    // A different direction is an independent series and stays untouched.
    assert_eq!(bytes_series("tcp", "down", group, uplink), 0);
}

#[test]
fn udp_flow_counters_bump_both_datagram_and_byte_series() {
    let (group, uplink) = ("udp_ctr_grp", "udp_ctr_up");

    let counters = udp_flow_counters("down", group, uplink);
    counters.record(200);
    counters.record(300);

    assert_eq!(datagram_series("down", group, uplink), 2);
    // `bytes_total` for UDP carries the fixed `protocol="udp"` label.
    assert_eq!(bytes_series("udp", "down", group, uplink), 500);
}

#[test]
fn direct_helpers_target_the_direct_labels() {
    // Direct series are shared, so assert on deltas rather than absolutes.
    let tcp_before = bytes_series("tcp", "up", DIRECT_GROUP_LABEL, DIRECT_UPLINK_LABEL);
    direct_tcp_bytes("up").add(64);
    assert_eq!(
        bytes_series("tcp", "up", DIRECT_GROUP_LABEL, DIRECT_UPLINK_LABEL),
        tcp_before + 64
    );

    let dg_before = datagram_series("down", DIRECT_GROUP_LABEL, DIRECT_UPLINK_LABEL);
    let by_before = bytes_series("udp", "down", DIRECT_GROUP_LABEL, DIRECT_UPLINK_LABEL);
    direct_udp_counters("down").record(128);
    assert_eq!(datagram_series("down", DIRECT_GROUP_LABEL, DIRECT_UPLINK_LABEL), dg_before + 1);
    assert_eq!(
        bytes_series("udp", "down", DIRECT_GROUP_LABEL, DIRECT_UPLINK_LABEL),
        by_before + 128
    );
}
