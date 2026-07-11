mod sniff;

use super::parse_udp_packet;
use super::resegment_udp_gso;
use super::wire::{build_gso_udp_packet, build_ipv4_udp_packet, build_ipv6_udp_packet};
use crate::wire::test_utils::{
    IP_PROTOCOL_UDP, assert_ipv4_header_checksum_valid, assert_transport_checksum_valid,
    corrupt_ip_length_field, corrupt_udp_length_field, random_payload, seeded_rng,
};
use crate::wire::{IPV4_HEADER_LEN, IPV6_HEADER_LEN, IpVersion, checksum16};
use bytes::Bytes;
use rand::Rng;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[test]
fn ipv4_udp_roundtrip() {
    let packet = build_ipv4_udp_packet(
        Ipv4Addr::new(8, 8, 8, 8),
        Ipv4Addr::new(10, 0, 0, 2),
        53,
        40000,
        b"hello",
    )
    .unwrap();

    let parsed = parse_udp_packet(&packet).unwrap();
    assert_eq!(parsed.version, IpVersion::V4);
    assert_eq!(parsed.source_ip, IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)));
    assert_eq!(parsed.destination_ip, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)));
    assert_eq!(parsed.source_port, 53);
    assert_eq!(parsed.destination_port, 40000);
    assert_eq!(parsed.payload, b"hello");
}

#[test]
fn ipv6_udp_roundtrip() {
    let packet = build_ipv6_udp_packet(
        Ipv6Addr::LOCALHOST,
        Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2),
        5353,
        41000,
        b"world",
    )
    .unwrap();

    let parsed = parse_udp_packet(&packet).unwrap();
    assert_eq!(parsed.version, IpVersion::V6);
    assert_eq!(parsed.source_ip, IpAddr::V6(Ipv6Addr::LOCALHOST));
    assert_eq!(parsed.destination_ip, IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2)));
    assert_eq!(parsed.source_port, 5353);
    assert_eq!(parsed.destination_port, 41000);
    assert_eq!(parsed.payload, b"world");
}

#[test]
fn ipv6_udp_roundtrip_with_destination_options() {
    let source_ip = Ipv6Addr::LOCALHOST;
    let destination_ip = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2);
    let payload = b"world";
    let udp_len = 8 + payload.len();
    let extension_len = 8usize;
    let total_len = crate::wire::IPV6_HEADER_LEN + extension_len + udp_len;
    let mut packet = vec![0u8; total_len];
    packet[0] = 0x60;
    packet[4..6].copy_from_slice(&((extension_len + udp_len) as u16).to_be_bytes());
    packet[6] = crate::wire::IPV6_NEXT_HEADER_DESTINATION_OPTIONS;
    packet[7] = 64;
    packet[8..24].copy_from_slice(&source_ip.octets());
    packet[24..40].copy_from_slice(&destination_ip.octets());
    packet[40] = IP_PROTOCOL_UDP;
    packet[48..50].copy_from_slice(&5353u16.to_be_bytes());
    packet[50..52].copy_from_slice(&41000u16.to_be_bytes());
    packet[52..54].copy_from_slice(&(udp_len as u16).to_be_bytes());
    packet[56..].copy_from_slice(payload);
    let checksum = crate::wire::ipv6_payload_checksum(
        source_ip,
        destination_ip,
        IP_PROTOCOL_UDP,
        &packet[48..],
    );
    packet[54..56].copy_from_slice(&checksum.to_be_bytes());

    let parsed = parse_udp_packet(&packet).unwrap();
    assert_eq!(parsed.version, IpVersion::V6);
    assert_eq!(parsed.source_ip, IpAddr::V6(source_ip));
    assert_eq!(parsed.destination_ip, IpAddr::V6(destination_ip));
    assert_eq!(parsed.source_port, 5353);
    assert_eq!(parsed.destination_port, 41000);
    assert_eq!(parsed.payload, payload);
}

#[test]
fn randomized_udp_packet_roundtrip_and_mutation_smoke() {
    let mut rng = seeded_rng(0x5eed_4eed);
    for _ in 0..128 {
        let payload = random_payload(&mut rng, 63);
        let source_port = rng.random_range(1..=65000);
        let destination_port = rng.random_range(1..=65000);

        if rng.random_bool(0.5) {
            let source_ip = Ipv4Addr::new(8, 8, 4, rng.random_range(1..=250));
            let destination_ip = Ipv4Addr::new(10, 0, 0, rng.random_range(2..=250));
            let packet = build_ipv4_udp_packet(
                source_ip,
                destination_ip,
                source_port,
                destination_port,
                &payload,
            )
            .unwrap();

            assert_ipv4_header_checksum_valid(&packet);
            assert_transport_checksum_valid(&packet, IP_PROTOCOL_UDP);

            let parsed = parse_udp_packet(&packet).unwrap();
            assert_eq!(parsed.version, IpVersion::V4);
            assert_eq!(parsed.source_ip, IpAddr::V4(source_ip));
            assert_eq!(parsed.destination_ip, IpAddr::V4(destination_ip));
            assert_eq!(parsed.source_port, source_port);
            assert_eq!(parsed.destination_port, destination_port);
            assert_eq!(parsed.payload, payload);

            assert!(parse_udp_packet(&corrupt_ip_length_field(&packet)).is_err());
            assert!(parse_udp_packet(&corrupt_udp_length_field(&packet)).is_err());
        } else {
            let source_ip = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, rng.random_range(2..=250));
            let destination_ip = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, rng.random_range(2..=250));
            let packet = build_ipv6_udp_packet(
                source_ip,
                destination_ip,
                source_port,
                destination_port,
                &payload,
            )
            .unwrap();

            assert_transport_checksum_valid(&packet, IP_PROTOCOL_UDP);

            let parsed = parse_udp_packet(&packet).unwrap();
            assert_eq!(parsed.version, IpVersion::V6);
            assert_eq!(parsed.source_ip, IpAddr::V6(source_ip));
            assert_eq!(parsed.destination_ip, IpAddr::V6(destination_ip));
            assert_eq!(parsed.source_port, source_port);
            assert_eq!(parsed.destination_port, destination_port);
            assert_eq!(parsed.payload, payload);

            assert!(parse_udp_packet(&corrupt_ip_length_field(&packet)).is_err());
            assert!(parse_udp_packet(&corrupt_udp_length_field(&packet)).is_err());
        }
    }
}

// A UDP GRO super-packet is a single IP packet carrying one UDP header whose
// `len` spans the WHOLE aggregate, followed by N gso_size-sized datagrams.
// `build_ipv4/ipv6_udp_packet` with a multi-datagram payload produces exactly
// that shape (one header, uh->len = 8 + full payload), so it doubles as a
// super-packet fixture. `resegment_udp_gso` must cut it back into datagrams
// using the IP total length — never the WHOLE `uh->len`.

#[test]
fn resegment_udp_gso_splits_ipv4_into_datagrams() {
    let gso_size = 100u16;
    // 3 full datagrams + a short 50-byte tail.
    let payload: Vec<u8> = (0..350u32).map(|i| (i % 251) as u8).collect();
    let packet = build_ipv4_udp_packet(
        Ipv4Addr::new(8, 8, 8, 8),
        Ipv4Addr::new(10, 0, 0, 2),
        443,
        50000,
        &payload,
    )
    .unwrap();

    let datagrams = resegment_udp_gso(&packet, gso_size).unwrap();
    assert_eq!(datagrams.len(), 4);
    for d in &datagrams {
        assert_eq!(d.version, IpVersion::V4);
        assert_eq!(d.source_ip, IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)));
        assert_eq!(d.destination_ip, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)));
        assert_eq!(d.source_port, 443);
        assert_eq!(d.destination_port, 50000);
    }
    assert_eq!(datagrams[0].payload.len(), 100);
    assert_eq!(datagrams[3].payload.len(), 50);
    // Front-to-back order preserved; concatenation is byte-identical.
    let reassembled: Vec<u8> = datagrams.iter().flat_map(|d| d.payload.clone()).collect();
    assert_eq!(reassembled, payload);
}

#[test]
fn resegment_udp_gso_splits_ipv6_into_datagrams() {
    let gso_size = 200u16;
    let payload: Vec<u8> = (0..500u32).map(|i| (i % 251) as u8).collect();
    let packet = build_ipv6_udp_packet(
        Ipv6Addr::LOCALHOST,
        Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2),
        5353,
        41000,
        &payload,
    )
    .unwrap();

    let datagrams = resegment_udp_gso(&packet, gso_size).unwrap();
    assert_eq!(datagrams.len(), 3); // 200 + 200 + 100
    for d in &datagrams {
        assert_eq!(d.version, IpVersion::V6);
        assert_eq!(d.source_port, 5353);
        assert_eq!(d.destination_port, 41000);
    }
    let reassembled: Vec<u8> = datagrams.iter().flat_map(|d| d.payload.clone()).collect();
    assert_eq!(reassembled, payload);
}

#[test]
fn resegment_udp_gso_single_datagram_matches_parse() {
    // payload <= gso_size → one datagram, identical to the per-packet parse.
    let packet = build_ipv4_udp_packet(
        Ipv4Addr::new(8, 8, 8, 8),
        Ipv4Addr::new(10, 0, 0, 2),
        443,
        50000,
        b"single",
    )
    .unwrap();
    let via_parse = parse_udp_packet(&packet).unwrap();
    let via_reseg = resegment_udp_gso(&packet, 1400).unwrap();
    assert_eq!(via_reseg.len(), 1);
    assert_eq!(via_reseg[0].payload, via_parse.payload);
    assert_eq!(via_reseg[0].source_port, via_parse.source_port);
    assert_eq!(via_reseg[0].destination_port, via_parse.destination_port);
}

#[test]
fn resegment_udp_gso_rejects_zero_gso_size() {
    let packet = build_ipv4_udp_packet(
        Ipv4Addr::new(8, 8, 8, 8),
        Ipv4Addr::new(10, 0, 0, 2),
        443,
        50000,
        b"data",
    )
    .unwrap();
    assert!(resegment_udp_gso(&packet, 0).is_err());
}

#[test]
fn resegment_udp_gso_rejects_too_many_segments() {
    // gso_size = 1 over a 200-byte aggregate → 200 datagrams > MAX (128): drop whole.
    let payload = vec![0xabu8; 200];
    let packet = build_ipv4_udp_packet(
        Ipv4Addr::new(8, 8, 8, 8),
        Ipv4Addr::new(10, 0, 0, 2),
        443,
        50000,
        &payload,
    )
    .unwrap();
    assert!(resegment_udp_gso(&packet, 1).is_err());
}

// A USO super-packet carries a *partial* (pseudo-header) UDP checksum; the
// kernel finalises each split segment by adding the L4 byte checksum and
// complementing. For a single (un-split) datagram that finalisation is exactly
// `checksum16` over the UDP bytes, and it must equal the full checksum the
// per-datagram builder computes for the same datagram. `uh->len` spans the
// whole aggregate (WHOLE-super) — a wrong length here silently corrupts every
// segment (the prior UDP-GSO bug).

#[test]
fn gso_udp_partial_checksum_finalizes_to_full_ipv4() {
    let src = Ipv4Addr::new(8, 8, 8, 8);
    let dst = Ipv4Addr::new(10, 0, 0, 2);
    let payload = b"the quick brown fox jumps over the lazy udp gso datagram twice";

    let full = build_ipv4_udp_packet(src, dst, 443, 50000, payload).unwrap();
    let full_udp = &full[IPV4_HEADER_LEN..];
    let full_csum = u16::from_be_bytes([full_udp[6], full_udp[7]]);

    let (gso, vnet) = build_gso_udp_packet(
        IpVersion::V4,
        IpAddr::V4(src),
        IpAddr::V4(dst),
        443,
        50000,
        payload.len() as u16,
        &[Bytes::copy_from_slice(payload)],
    )
    .unwrap();
    assert_eq!(vnet.gso_type, 5); // VIRTIO_NET_HDR_GSO_UDP_L4
    assert_eq!(vnet.csum_offset, 6);
    assert_eq!(vnet.gso_size, payload.len() as u16);

    let gso_udp = &gso[IPV4_HEADER_LEN..];
    assert_eq!(
        checksum16(gso_udp),
        full_csum,
        "kernel-finalised partial UDP checksum must equal the full checksum"
    );
    // IPv4 header checksum stays valid.
    assert_eq!(checksum16(&gso[..IPV4_HEADER_LEN]), 0);
}

#[test]
fn gso_udp_partial_checksum_finalizes_to_full_ipv6() {
    let src = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
    let dst = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2);
    let payload = b"an odd-length payload to exercise the udp gso checksum folding path!";

    let full = build_ipv6_udp_packet(src, dst, 5353, 41000, payload).unwrap();
    let full_udp = &full[IPV6_HEADER_LEN..];
    let full_csum = u16::from_be_bytes([full_udp[6], full_udp[7]]);

    let (gso, vnet) = build_gso_udp_packet(
        IpVersion::V6,
        IpAddr::V6(src),
        IpAddr::V6(dst),
        5353,
        41000,
        payload.len() as u16,
        &[Bytes::copy_from_slice(payload)],
    )
    .unwrap();
    assert_eq!(vnet.gso_type, 5);

    let gso_udp = &gso[IPV6_HEADER_LEN..];
    assert_eq!(
        checksum16(gso_udp),
        full_csum,
        "kernel-finalised partial UDP checksum must equal the full checksum (v6)"
    );
}

#[test]
fn gso_udp_assembles_multiple_segments_contiguously() {
    let src = Ipv4Addr::new(9, 9, 9, 9);
    let dst = Ipv4Addr::new(10, 0, 0, 5);
    // USO coalesces equal-sized datagrams; use three of the same length.
    let d0 = Bytes::from_static(b"segment-zero-payload-0");
    let d1 = Bytes::from_static(b"segment-one--payload-1");
    let d2 = Bytes::from_static(b"segment-two--payload-2");
    assert_eq!(d0.len(), d1.len());
    assert_eq!(d1.len(), d2.len());
    let segments = [d0.clone(), d1.clone(), d2.clone()];

    let mut concat = Vec::new();
    concat.extend_from_slice(&d0);
    concat.extend_from_slice(&d1);
    concat.extend_from_slice(&d2);

    let (gso, vnet) = build_gso_udp_packet(
        IpVersion::V4,
        IpAddr::V4(src),
        IpAddr::V4(dst),
        443,
        50000,
        d0.len() as u16,
        &segments,
    )
    .unwrap();
    assert_eq!(vnet.gso_size, d0.len() as u16);

    // The builder must assemble the batch's datagrams contiguously — the
    // payload region equals their exact concatenation (UDP header is 8 bytes).
    let payload_region = &gso[IPV4_HEADER_LEN + 8..];
    assert_eq!(payload_region, concat.as_slice());

    // Partial checksum still finalises to the full checksum over the whole payload.
    let full = build_ipv4_udp_packet(src, dst, 443, 50000, &concat).unwrap();
    let full_udp = &full[IPV4_HEADER_LEN..];
    let full_csum = u16::from_be_bytes([full_udp[6], full_udp[7]]);
    assert_eq!(checksum16(&gso[IPV4_HEADER_LEN..]), full_csum);
}

/// Eviction-selection logic shared by the tunnelled and direct UDP flow
/// tables. `oldest_flow_key` is generic over [`FlowStamp`], so the direct
/// flow cap added alongside the tunnelled one reuses exactly this routine;
/// it is exercised here with a minimal stand-in flow type.
mod eviction {
    use crate::udp::lifecycle::oldest_flow_key;
    use crate::udp::types::FlowStamp;
    use std::collections::HashMap;
    use std::sync::Arc;
    use std::time::{Duration, Instant};
    use tokio::sync::Mutex;

    struct StampFlow {
        id: u64,
        last_seen: Instant,
    }

    impl FlowStamp for StampFlow {
        fn id(&self) -> u64 {
            self.id
        }
        fn last_seen(&self) -> Instant {
            self.last_seen
        }
        fn set_last_seen(&mut self, now: Instant) {
            self.last_seen = now;
        }
    }

    fn flow(id: u64, last_seen: Instant) -> Arc<Mutex<StampFlow>> {
        Arc::new(Mutex::new(StampFlow { id, last_seen }))
    }

    #[tokio::test]
    async fn selects_least_recently_seen_key() {
        let base = Instant::now();
        let mut flows: HashMap<u32, Arc<Mutex<StampFlow>>> = HashMap::new();
        flows.insert(1, flow(1, base + Duration::from_secs(60)));
        flows.insert(2, flow(2, base)); // least-recently-seen → evicted first
        flows.insert(3, flow(3, base + Duration::from_secs(5)));

        assert_eq!(oldest_flow_key(&flows).await, Some(2));
    }

    #[tokio::test]
    async fn empty_table_has_no_oldest_key() {
        let flows: HashMap<u32, Arc<Mutex<StampFlow>>> = HashMap::new();
        assert_eq!(oldest_flow_key(&flows).await, None);
    }
}
