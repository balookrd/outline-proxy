//! Byte-level tests for `build_icmpv4_frag_needed` and
//! `build_icmpv6_packet_too_big` — the PMTUD signals emitted on the TUN UDP
//! oversize-drop path.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::{Duration, Instant};

use crate::{
    IPV4_HEADER_LEN, IPV4_MIN_PATH_MTU, IPV6_HEADER_LEN, IPV6_MIN_PATH_MTU, IpVersion,
    build_icmpv4_frag_needed, build_icmpv6_packet_too_big, checksum16, icmpv6_checksum,
    should_emit_ptb_for_limit, should_emit_ptb_now,
};

const ICMPV4_PROTOCOL: u8 = 1;
const ICMPV6_NEXT_HEADER: u8 = 58;

fn synth_ipv4_udp(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    sport: u16,
    dport: u16,
    payload_len: u16,
) -> Vec<u8> {
    let mut p = vec![0u8; IPV4_HEADER_LEN + 8];
    p[0] = 0x45;
    let total_len = (p.len() as u16) + payload_len;
    p[2..4].copy_from_slice(&total_len.to_be_bytes());
    p[8] = 64;
    p[9] = 17; // UDP
    p[12..16].copy_from_slice(&src.octets());
    p[16..20].copy_from_slice(&dst.octets());
    p[20..22].copy_from_slice(&sport.to_be_bytes());
    p[22..24].copy_from_slice(&dport.to_be_bytes());
    let udp_len = 8u16 + payload_len;
    p[24..26].copy_from_slice(&udp_len.to_be_bytes());
    p
}

fn synth_ipv6_udp(
    src: Ipv6Addr,
    dst: Ipv6Addr,
    sport: u16,
    dport: u16,
    payload_len: u16,
) -> Vec<u8> {
    let mut p = vec![0u8; IPV6_HEADER_LEN + 8];
    p[0] = 0x60;
    let payload_total: u16 = 8 + payload_len;
    p[4..6].copy_from_slice(&payload_total.to_be_bytes());
    p[6] = 17; // UDP
    p[7] = 64;
    p[8..24].copy_from_slice(&src.octets());
    p[24..40].copy_from_slice(&dst.octets());
    p[40..42].copy_from_slice(&sport.to_be_bytes());
    p[42..44].copy_from_slice(&dport.to_be_bytes());
    let udp_len: u16 = 8 + payload_len;
    p[44..46].copy_from_slice(&udp_len.to_be_bytes());
    p
}

#[test]
fn icmpv4_frag_needed_swaps_addresses_and_quotes_offending_packet() {
    let client = Ipv4Addr::new(10, 0, 0, 5);
    let remote = Ipv4Addr::new(8, 8, 8, 8);
    let original = synth_ipv4_udp(client, remote, 40000, 4500, 0);
    let mtu: u16 = 1400;

    let icmp = build_icmpv4_frag_needed(mtu, &original).expect("build ICMPv4 Frag Needed");

    assert_eq!(icmp[0] >> 4, 4, "outer IPv4");
    assert_eq!(icmp[9], ICMPV4_PROTOCOL, "protocol = ICMP");
    // Source of the ICMP reply is the destination of the original packet
    // (the proxy/tunnel itself), destination is the original sender.
    assert_eq!(&icmp[12..16], &remote.octets(), "ICMP source = original dst");
    assert_eq!(&icmp[16..20], &client.octets(), "ICMP destination = original src");

    let icmp_off = IPV4_HEADER_LEN;
    assert_eq!(icmp[icmp_off], 3, "type = Destination Unreachable");
    assert_eq!(icmp[icmp_off + 1], 4, "code = Fragmentation Needed");
    let advertised_mtu = u16::from_be_bytes([icmp[icmp_off + 6], icmp[icmp_off + 7]]);
    assert_eq!(advertised_mtu, mtu);

    let quoted = &icmp[icmp_off + 8..icmp_off + 8 + IPV4_HEADER_LEN + 8];
    assert_eq!(quoted, &original[..IPV4_HEADER_LEN + 8], "quoted IP + UDP header matches");

    // The ICMP header checksum must verify (one's-complement sum over the
    // ICMP body has to be zero when the embedded checksum is included).
    let total_len = u16::from_be_bytes([icmp[2], icmp[3]]) as usize;
    assert_eq!(checksum16(&icmp[icmp_off..total_len]), 0, "ICMP checksum");
    assert_eq!(checksum16(&icmp[..IPV4_HEADER_LEN]), 0, "outer IP checksum");
}

#[test]
fn icmpv4_frag_needed_clamps_advertised_mtu_to_protocol_minimum() {
    let original = synth_ipv4_udp(Ipv4Addr::new(10, 0, 0, 5), Ipv4Addr::new(8, 8, 8, 8), 1, 1, 0);
    let icmp = build_icmpv4_frag_needed(100, &original).unwrap();
    let icmp_off = IPV4_HEADER_LEN;
    let advertised = u16::from_be_bytes([icmp[icmp_off + 6], icmp[icmp_off + 7]]);
    assert_eq!(advertised, IPV4_MIN_PATH_MTU, "below-minimum MTU is clamped");
}

#[test]
fn icmpv6_packet_too_big_swaps_addresses_and_advertises_mtu() {
    let client: Ipv6Addr = "2001:db8::5".parse().unwrap();
    let remote: Ipv6Addr = "2001:db8::4500".parse().unwrap();
    let original = synth_ipv6_udp(client, remote, 40000, 4500, 0);
    let mtu: u32 = 1400;

    let icmp = build_icmpv6_packet_too_big(mtu, &original).expect("build ICMPv6 PTB");

    assert_eq!(icmp[0] >> 4, 6, "outer IPv6");
    assert_eq!(icmp[6], ICMPV6_NEXT_HEADER, "next header = ICMPv6");
    assert_eq!(&icmp[8..24], &remote.octets(), "ICMP source = original dst");
    assert_eq!(&icmp[24..40], &client.octets(), "ICMP destination = original src");

    let icmp_off = IPV6_HEADER_LEN;
    assert_eq!(icmp[icmp_off], 2, "type = Packet Too Big");
    assert_eq!(icmp[icmp_off + 1], 0, "code = 0");
    let advertised = u32::from_be_bytes([
        icmp[icmp_off + 4],
        icmp[icmp_off + 5],
        icmp[icmp_off + 6],
        icmp[icmp_off + 7],
    ]);
    assert_eq!(advertised, mtu);

    let body_len = u16::from_be_bytes([icmp[4], icmp[5]]) as usize;
    let body = &icmp[icmp_off..icmp_off + body_len];
    // A correct one's-complement checksum makes the verification sum
    // (computed over the message with the embedded checksum included) wrap
    // back to zero.
    assert_eq!(icmpv6_checksum(remote, client, body), 0, "ICMPv6 checksum verifies");
    // Recomputing with the checksum field zeroed must reproduce the
    // embedded value byte-for-byte.
    let mut zeroed = body.to_vec();
    let embedded = u16::from_be_bytes([zeroed[2], zeroed[3]]);
    zeroed[2] = 0;
    zeroed[3] = 0;
    assert_eq!(icmpv6_checksum(remote, client, &zeroed), embedded, "checksum recomputes");
}

#[test]
fn icmpv6_packet_too_big_clamps_to_protocol_minimum() {
    let client: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let remote: Ipv6Addr = "2001:db8::2".parse().unwrap();
    let original = synth_ipv6_udp(client, remote, 1, 1, 0);
    let icmp = build_icmpv6_packet_too_big(800, &original).unwrap();
    let icmp_off = IPV6_HEADER_LEN;
    let advertised = u32::from_be_bytes([
        icmp[icmp_off + 4],
        icmp[icmp_off + 5],
        icmp[icmp_off + 6],
        icmp[icmp_off + 7],
    ]);
    assert_eq!(advertised, IPV6_MIN_PATH_MTU as u32, "below-minimum MTU is clamped");
}

#[test]
fn ptb_throttle_lets_first_emission_through() {
    let now = Instant::now();
    assert!(should_emit_ptb_now(None, now, Duration::from_secs(1)));
}

#[test]
fn ptb_throttle_suppresses_within_window() {
    let earlier = Instant::now();
    let now = earlier + Duration::from_millis(500);
    assert!(!should_emit_ptb_now(Some(earlier), now, Duration::from_secs(1)));
}

#[test]
fn ptb_throttle_releases_after_interval() {
    let earlier = Instant::now();
    let now = earlier + Duration::from_millis(1_100);
    assert!(should_emit_ptb_now(Some(earlier), now, Duration::from_secs(1)));
}

#[test]
fn ptb_throttle_handles_non_monotonic_clock_safely() {
    // Some test or paused-time setups may compute `now` earlier than the
    // recorded `previous`. `saturating_duration_since` keeps the duration
    // at zero rather than overflowing, so the call should always suppress
    // (not panic).
    let later = Instant::now() + Duration::from_secs(10);
    let now = Instant::now();
    assert!(!should_emit_ptb_now(Some(later), now, Duration::from_secs(1)));
}

#[test]
fn ptb_suppression_blocks_below_v4_quic_initial_minimum() {
    // QUIC v1 requires Initial datagrams to be at least 1200 bytes
    // (RFC 9000 §14.1). A QUIC-over-WS transport whose datagram budget
    // sits at ~1180 — typical for SS-UDP over a 1200-byte QUIC datagram
    // channel — would otherwise produce a PTB advertising 1180 and push
    // compliant QUIC clients off UDP onto a TCP fallback.
    assert!(!should_emit_ptb_for_limit(Some(1180), IpVersion::V4, false));
    assert!(!should_emit_ptb_for_limit(Some(800), IpVersion::V4, false));
}

#[test]
fn ptb_suppression_allows_v4_real_pmtud_range() {
    // Legitimate path-MTU drops sit in the ~1300-1450 range (VoWiFi
    // IKE_AUTH with certificates, GRE, IPsec encapsulation). Those
    // remain eligible for a PTB even with the default suppression on.
    assert!(should_emit_ptb_for_limit(Some(1200), IpVersion::V4, false));
    assert!(should_emit_ptb_for_limit(Some(1400), IpVersion::V4, false));
    assert!(should_emit_ptb_for_limit(Some(4096), IpVersion::V4, false));
}

#[test]
fn ptb_suppression_blocks_below_v6_minimum_link_mtu() {
    // IPv6 endpoints follow the 1280-byte minimum link MTU; QUIC v6
    // initials never go below that, so PTBs claiming a smaller path are
    // suppressed for the same reason as v4.
    assert!(!should_emit_ptb_for_limit(Some(1200), IpVersion::V6, false));
    assert!(!should_emit_ptb_for_limit(Some(1279), IpVersion::V6, false));
}

#[test]
fn ptb_suppression_allows_v6_at_minimum_link_mtu() {
    assert!(should_emit_ptb_for_limit(Some(1280), IpVersion::V6, false));
    assert!(should_emit_ptb_for_limit(Some(1400), IpVersion::V6, false));
}

#[test]
fn ptb_unspecified_limit_is_always_permissive() {
    // When the transport surfaces no explicit limit we cannot prove the
    // QUIC initial minimum is violated; suppressing in that case would
    // silence legitimate PMTUD signals on transports that simply don't
    // report a size. The opt-out flag does not change this branch —
    // None is always permissive.
    assert!(should_emit_ptb_for_limit(None, IpVersion::V4, false));
    assert!(should_emit_ptb_for_limit(None, IpVersion::V6, false));
    assert!(should_emit_ptb_for_limit(None, IpVersion::V4, true));
    assert!(should_emit_ptb_for_limit(None, IpVersion::V6, true));
}

#[test]
fn ptb_opt_in_emits_below_quic_initial_minimum() {
    // tun.pmtud_emit_below_quic_initial = true restores the
    // unconditional PTB behaviour for operators that prefer explicit
    // PMTUD over QUIC protection (VoWiFi / IKE-only deployments). All
    // sub-minimum limits that the default would suppress become
    // eligible for a PTB again.
    assert!(should_emit_ptb_for_limit(Some(1180), IpVersion::V4, true));
    assert!(should_emit_ptb_for_limit(Some(800), IpVersion::V4, true));
    assert!(should_emit_ptb_for_limit(Some(1200), IpVersion::V6, true));
    assert!(should_emit_ptb_for_limit(Some(1279), IpVersion::V6, true));
}

#[test]
fn ptb_opt_in_preserves_above_minimum_behaviour() {
    // Enabling sub-minimum emission must not regress the above-minimum
    // branch: these limits are eligible under both settings.
    assert!(should_emit_ptb_for_limit(Some(1400), IpVersion::V4, true));
    assert!(should_emit_ptb_for_limit(Some(1400), IpVersion::V6, true));
}

#[test]
fn icmpv6_packet_too_big_does_not_exceed_minimum_link_mtu() {
    let client: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let remote: Ipv6Addr = "2001:db8::2".parse().unwrap();
    // 2000-byte original — larger than IPv6 minimum path MTU — must be
    // truncated by the builder so the final ICMPv6 packet fits in 1280.
    let mut original = synth_ipv6_udp(client, remote, 1, 1, 0);
    original.extend(std::iter::repeat_n(0xAB, 2000));

    let icmp = build_icmpv6_packet_too_big(1280, &original).unwrap();
    assert!(icmp.len() <= IPV6_MIN_PATH_MTU, "ICMPv6 PTB must fit in 1280 bytes");
}
