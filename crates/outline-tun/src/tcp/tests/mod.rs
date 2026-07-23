use std::collections::VecDeque;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;

use super::{
    BufferedClientSegment, ClientSegmentView, IPV4_HEADER_LEN, IPV6_HEADER_LEN, ParsedTcpPacket,
    TCP_FLAG_ACK, TCP_FLAG_FIN, TCP_FLAG_RST, TCP_FLAG_SYN, TrimmedSegment, build_reset_response,
    drain_ready_buffered_segments, normalize_client_segment, queue_future_segment,
};
use crate::config::TunTcpConfig;
use crate::tcp::state_machine::SequenceRange;
use crate::wire::test_utils::{
    IP_PROTOCOL_TCP, assert_ipv4_header_checksum_valid, assert_transport_checksum_valid,
    flip_packet_byte, random_payload, seeded_rng, transport_offset,
};
use futures_util::StreamExt;
use outline_transport::{TcpShadowsocksWriter, TransportStream};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng, seq::SliceRandom};
use shadowsocks_crypto::CipherKind;
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use tokio_tungstenite::{accept_async, connect_async};

fn parse_action_response(packet: &[u8]) -> Vec<u8> {
    match handle_stateless_packet(packet).unwrap() {
        Some(response) => response,
        None => panic!("expected response"),
    }
}

fn handle_stateless_packet(packet: &[u8]) -> Result<Option<Vec<u8>>, anyhow::Error> {
    let parsed = super::parse_tcp_packet_unverified(packet)?;
    if (parsed.flags & TCP_FLAG_RST) != 0 {
        return Ok(None);
    }
    Ok(Some(build_reset_response(&parsed)?))
}
#[test]
fn ipv4_syn_generates_rst_ack() {
    let packet = build_client_packet(
        Ipv4Addr::new(10, 0, 0, 2),
        Ipv4Addr::new(8, 8, 8, 8),
        40000,
        80,
        1,
        0,
        0x4000,
        TCP_FLAG_SYN,
        &[],
    );
    let response = parse_action_response(&packet);
    assert_eq!(response[9], 6);
    assert_eq!(response[IPV4_HEADER_LEN + 13], TCP_FLAG_RST | TCP_FLAG_ACK);
}

#[test]
fn ipv6_ack_generates_rst() {
    let packet = build_client_ipv6_packet_with_options(
        Ipv6Addr::LOCALHOST,
        Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2),
        40000,
        80,
        1,
        5,
        0x4000,
        TCP_FLAG_ACK,
        &[],
        &[],
    );
    let response = parse_action_response(&packet);
    assert_eq!(response[6], 6);
    assert_eq!(response[IPV6_HEADER_LEN + 13], TCP_FLAG_RST);
}

#[test]
fn rst_packets_are_ignored() {
    let packet = build_client_packet(
        Ipv4Addr::new(10, 0, 0, 2),
        Ipv4Addr::new(8, 8, 8, 8),
        40000,
        80,
        1,
        5,
        0x4000,
        TCP_FLAG_RST | TCP_FLAG_ACK,
        &[],
    );
    assert!(handle_stateless_packet(&packet).unwrap().is_none());
}

#[test]
fn parsed_tcp_packet_keeps_payload() {
    let packet = build_client_packet(
        Ipv4Addr::new(10, 0, 0, 2),
        Ipv4Addr::new(8, 8, 8, 8),
        40000,
        80,
        1,
        5,
        0x4000,
        TCP_FLAG_ACK,
        b"abc",
    );
    let parsed: ParsedTcpPacket = super::parse_tcp_packet_unverified(&packet).unwrap();
    assert_eq!(parsed.flags, TCP_FLAG_ACK);
    assert_eq!(parsed.payload, b"abc"[..]);
    assert_eq!(parsed.sequence_number, 1);
    assert_eq!(parsed.acknowledgement_number, 5);
}

#[test]
fn normalize_client_segment_trims_retransmitted_prefix() {
    let packet = ParsedTcpPacket {
        version: super::IpVersion::V4,
        source_ip: "10.0.0.1".parse().unwrap(),
        destination_ip: "8.8.8.8".parse().unwrap(),
        source_port: 12345,
        destination_port: 80,
        sequence_number: 100,
        acknowledgement_number: 0,
        window_size: 4096,
        max_segment_size: None,
        window_scale: None,
        sack_permitted: false,
        sack_blocks: Vec::new(),
        timestamp_value: None,
        timestamp_echo_reply: None,
        flags: TCP_FLAG_ACK,
        payload: Bytes::from_static(b"abcdef"),
    };

    let segment = normalize_client_segment(&packet, 103);
    assert_eq!(segment.payload.as_ref(), b"def");
    assert!(!segment.fin);
}

#[test]
fn normalize_client_segment_keeps_new_fin_after_duplicate_payload() {
    let packet = ParsedTcpPacket {
        version: super::IpVersion::V4,
        source_ip: "10.0.0.1".parse().unwrap(),
        destination_ip: "8.8.8.8".parse().unwrap(),
        source_port: 12345,
        destination_port: 80,
        sequence_number: 100,
        acknowledgement_number: 0,
        window_size: 4096,
        max_segment_size: None,
        window_scale: None,
        sack_permitted: false,
        sack_blocks: Vec::new(),
        timestamp_value: None,
        timestamp_echo_reply: None,
        flags: TCP_FLAG_ACK | TCP_FLAG_FIN,
        payload: Bytes::from_static(b"abc"),
    };

    let segment: ClientSegmentView = normalize_client_segment(&packet, 103);
    assert!(segment.payload.is_empty());
    assert!(segment.fin);
}

#[test]
fn normalize_client_segment_drops_fully_duplicate_fin() {
    let packet = ParsedTcpPacket {
        version: super::IpVersion::V4,
        source_ip: "10.0.0.1".parse().unwrap(),
        destination_ip: "8.8.8.8".parse().unwrap(),
        source_port: 12345,
        destination_port: 80,
        sequence_number: 100,
        acknowledgement_number: 0,
        window_size: 4096,
        max_segment_size: None,
        window_scale: None,
        sack_permitted: false,
        sack_blocks: Vec::new(),
        timestamp_value: None,
        timestamp_echo_reply: None,
        flags: TCP_FLAG_ACK | TCP_FLAG_FIN,
        payload: Bytes::from_static(b"abc"),
    };

    let segment: ClientSegmentView = normalize_client_segment(&packet, 104);
    assert!(segment.payload.is_empty());
    assert!(!segment.fin);
}

#[test]
fn duplicate_syn_is_detected() {
    let packet = ParsedTcpPacket {
        version: super::IpVersion::V4,
        source_ip: "10.0.0.1".parse().unwrap(),
        destination_ip: "8.8.8.8".parse().unwrap(),
        source_port: 12345,
        destination_port: 80,
        sequence_number: 41,
        acknowledgement_number: 0,
        window_size: 4096,
        max_segment_size: None,
        window_scale: Some(4),
        sack_permitted: true,
        sack_blocks: Vec::new(),
        timestamp_value: None,
        timestamp_echo_reply: None,
        flags: TCP_FLAG_SYN,
        payload: Bytes::new(),
    };
    assert!(super::is_duplicate_syn(&packet, 42));
}

#[test]
fn queue_future_segment_deduplicates_identical_packet() {
    let seg = TrimmedSegment {
        sequence_number: 200,
        flags: TCP_FLAG_ACK,
        payload: Bytes::from_static(b"later"),
    };
    let mut pending = VecDeque::new();

    queue_future_segment(&mut pending, &seg, 100);
    queue_future_segment(&mut pending, &seg, 100);

    assert_eq!(pending.len(), 1);
}

/// A segment that straddles several already-buffered ones must be split into
/// exactly the holes between them: the buffered bytes win, the new segment only
/// fills the gaps (including the leading and trailing ones). This is the path
/// that inserts into the queue while walking it — the reason the walk used to
/// run over a full clone of the queue.
#[test]
fn queue_future_segment_fills_every_hole_between_buffered_segments() {
    let mut pending = VecDeque::new();
    let expected_seq = 100;
    for (sequence_number, payload) in
        [(110u32, Bytes::from_static(b"DDD")), (120, Bytes::from_static(b"III"))]
    {
        queue_future_segment(
            &mut pending,
            &TrimmedSegment {
                sequence_number,
                flags: TCP_FLAG_ACK,
                payload,
            },
            expected_seq,
        );
    }

    // [105, 125): overlaps both buffered segments and leaves three holes —
    // before, between, and after them.
    let straddling: Vec<u8> = (0..20u8).map(|index| b'a' + index).collect();
    queue_future_segment(
        &mut pending,
        &TrimmedSegment {
            sequence_number: 105,
            flags: TCP_FLAG_ACK,
            payload: Bytes::from(straddling),
        },
        expected_seq,
    );

    let queued: Vec<(u32, &[u8])> = pending
        .iter()
        .map(|segment| (segment.sequence_number, &segment.payload[..]))
        .collect();
    assert_eq!(
        queued,
        vec![
            (105, b"abcde".as_slice()),
            (110, b"DDD".as_slice()),
            (113, b"ijklmno".as_slice()),
            (120, b"III".as_slice()),
            (123, b"st".as_slice()),
        ],
        "buffered bytes must survive; only the holes come from the new segment"
    );

    // And the whole thing reassembles into one contiguous stream.
    queue_future_segment(
        &mut pending,
        &TrimmedSegment {
            sequence_number: 100,
            flags: TCP_FLAG_ACK,
            payload: Bytes::from_static(b"AAAAA"),
        },
        expected_seq,
    );
    let mut sequence = expected_seq;
    let mut payload = Vec::new();
    assert!(!drain_ready_buffered_segments(&mut sequence, &mut pending, &mut payload));
    assert_eq!(sequence, 125);
    assert_eq!(payload.concat(), b"AAAAAabcdeDDDijklmnoIIIst");
    assert!(pending.is_empty());
}

#[test]
fn drain_ready_buffered_segments_reassembles_contiguous_tail() {
    let mut expected_seq = 103;
    let mut pending = VecDeque::new();
    let first = TrimmedSegment {
        sequence_number: 106,
        flags: TCP_FLAG_ACK,
        payload: Bytes::from_static(b"ghi"),
    };
    let second = TrimmedSegment {
        sequence_number: 103,
        flags: TCP_FLAG_ACK,
        payload: Bytes::from_static(b"def"),
    };
    queue_future_segment(&mut pending, &first, expected_seq);
    queue_future_segment(&mut pending, &second, expected_seq);
    let mut payload = Vec::new();

    let closed = drain_ready_buffered_segments(&mut expected_seq, &mut pending, &mut payload);

    assert!(!closed);
    assert_eq!(expected_seq, 109);
    assert_eq!(payload.concat(), b"defghi");
    assert!(pending.is_empty());
}

#[test]
fn drain_ready_buffered_segments_stops_on_gap() {
    let mut expected_seq = 103;
    let mut pending = VecDeque::from([BufferedClientSegment {
        sequence_number: 106,
        flags: TCP_FLAG_ACK,
        payload: b"ghi".to_vec().into(),
    }]);
    let mut payload = Vec::new();

    let closed = drain_ready_buffered_segments(&mut expected_seq, &mut pending, &mut payload);

    assert!(!closed);
    assert_eq!(expected_seq, 103);
    assert!(payload.is_empty());
    assert_eq!(pending.len(), 1);
}

#[test]
fn drain_ready_buffered_segments_closes_on_buffered_fin() {
    let mut expected_seq = 103;
    let mut pending = VecDeque::from([BufferedClientSegment {
        sequence_number: 103,
        flags: TCP_FLAG_ACK | TCP_FLAG_FIN,
        payload: b"def".to_vec().into(),
    }]);
    let mut payload = Vec::new();

    let closed = drain_ready_buffered_segments(&mut expected_seq, &mut pending, &mut payload);

    assert!(closed);
    assert_eq!(expected_seq, 107);
    assert_eq!(payload.concat(), b"def");
    assert!(pending.is_empty());
}

#[test]
fn parse_tcp_packet_extracts_window_scale_and_sack_blocks() {
    let packet = build_client_packet_with_options(
        Ipv4Addr::new(10, 0, 0, 2),
        Ipv4Addr::new(8, 8, 8, 8),
        40004,
        443,
        10,
        100,
        2048,
        TCP_FLAG_ACK,
        &[3, 3, 7, 4, 2, 1, 1, 5, 10, 0, 0, 0, 120, 0, 0, 0, 140, 1, 1, 1],
        &[],
    );
    let parsed = super::parse_tcp_packet_unverified(&packet).unwrap();
    assert_eq!(parsed.window_scale, Some(7));
    assert!(parsed.sack_permitted);
    assert_eq!(parsed.sack_blocks, vec![(120, 140)]);
}

#[test]
fn parse_tcp_packet_extracts_mss_and_timestamps() {
    let packet = build_client_packet_with_options(
        Ipv4Addr::new(10, 0, 0, 2),
        Ipv4Addr::new(8, 8, 8, 8),
        40004,
        443,
        10,
        100,
        2048,
        TCP_FLAG_ACK,
        &[2, 4, 0x05, 0xb4, 8, 10, 0, 0, 0, 9, 0, 0, 0, 7, 1, 1],
        &[],
    );
    let parsed = super::parse_tcp_packet_unverified(&packet).unwrap();
    assert_eq!(parsed.max_segment_size, Some(1460));
    assert_eq!(parsed.timestamp_value, Some(9));
    assert_eq!(parsed.timestamp_echo_reply, Some(7));
}

#[test]
fn parse_tcp_packet_rejects_invalid_ipv4_header_checksum() {
    let mut packet = build_client_packet(
        Ipv4Addr::new(10, 0, 0, 2),
        Ipv4Addr::new(8, 8, 8, 8),
        40004,
        443,
        10,
        100,
        2048,
        TCP_FLAG_ACK,
        b"hello",
    );
    packet[12] ^= 0x01;
    let error = super::parse_tcp_packet_unverified(&packet).unwrap_err();
    assert!(error.to_string().contains("invalid IPv4 header checksum"));
}

#[test]
fn parse_tcp_packet_rejects_invalid_tcp_checksum_ipv4() {
    let mut packet = build_client_packet(
        Ipv4Addr::new(10, 0, 0, 2),
        Ipv4Addr::new(8, 8, 8, 8),
        40004,
        443,
        10,
        100,
        2048,
        TCP_FLAG_ACK,
        b"hello",
    );
    packet[IPV4_HEADER_LEN + 7] ^= 0x01;
    let error = super::parse_tcp_packet_unverified(&packet).unwrap_err();
    assert!(error.to_string().contains("invalid TCP checksum"));
}

#[test]
fn parse_tcp_packet_rejects_invalid_tcp_checksum_ipv6() {
    let client_ip = Ipv6Addr::LOCALHOST;
    let remote_ip = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2);
    let mut packet = build_client_ipv6_packet_with_options(
        client_ip,
        remote_ip,
        40004,
        443,
        10,
        100,
        2048,
        TCP_FLAG_ACK,
        &[],
        b"hello",
    );
    packet[IPV6_HEADER_LEN + 5] ^= 0x01;
    let error = super::parse_tcp_packet_unverified(&packet).unwrap_err();
    assert!(error.to_string().contains("invalid TCP checksum"));
}

#[test]
fn parse_tcp_packet_accepts_ipv6_destination_options_before_tcp() {
    let client_ip = Ipv6Addr::LOCALHOST;
    let remote_ip = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2);
    let packet = build_client_ipv6_packet_with_extension_headers(
        client_ip,
        remote_ip,
        40004,
        443,
        10,
        100,
        2048,
        TCP_FLAG_ACK,
        &[vec![super::wire::IPV6_NEXT_HEADER_DESTINATION_OPTIONS, 0, 0, 0, 0, 0, 0, 0]],
        &tcp_option_pad(vec![2, 4, 0x05, 0xb4]),
        b"hello",
    );
    let parsed = super::parse_tcp_packet_unverified(&packet).unwrap();
    assert_eq!(parsed.version, super::IpVersion::V6);
    assert_eq!(parsed.source_port, 40004);
    assert_eq!(parsed.destination_port, 443);
    assert_eq!(parsed.max_segment_size, Some(1460));
    assert_eq!(parsed.payload, b"hello"[..]);
}

#[test]
fn parse_tcp_packet_rejects_ipv6_fragment_header() {
    let client_ip = Ipv6Addr::LOCALHOST;
    let remote_ip = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2);
    let packet = build_client_ipv6_packet_with_extension_headers(
        client_ip,
        remote_ip,
        40004,
        443,
        10,
        100,
        2048,
        TCP_FLAG_ACK,
        &[vec![super::wire::IPV6_NEXT_HEADER_FRAGMENT, 0, 0, 0, 0, 0, 0, 0]],
        &[],
        b"hello",
    );
    let error = super::parse_tcp_packet_unverified(&packet).unwrap_err();
    assert!(error.to_string().contains("IPv6 fragments are not supported"));
}

#[test]
fn randomized_tcp_packet_round_trip_and_mutation_smoke() {
    let mut rng = seeded_rng(0x5eed_7a11);
    for _ in 0..128 {
        let payload = random_payload(&mut rng, 47);
        let flags = [
            TCP_FLAG_ACK,
            TCP_FLAG_ACK | super::TCP_FLAG_PSH,
            TCP_FLAG_ACK | TCP_FLAG_FIN,
            TCP_FLAG_SYN,
            TCP_FLAG_SYN | TCP_FLAG_ACK,
        ][rng.random_range(0..5)];
        let payload = if (flags & TCP_FLAG_SYN) != 0 {
            Vec::new()
        } else {
            payload
        };
        let options = match rng.random_range(0..4) {
            0 => Vec::new(),
            1 => tcp_option_pad(vec![2, 4, 0x05, 0xb4]),
            2 => tcp_option_pad(vec![1, 3, 3, 7]),
            _ => tcp_option_pad(vec![8, 10, 0, 0, 0, 9, 0, 0, 0, 7]),
        };
        let sequence_number = rng.random::<u32>();
        let acknowledgement_number = rng.random::<u32>();
        let window_size = rng.random_range(1..=u16::MAX);

        if rng.random_bool(0.5) {
            let client_ip = Ipv4Addr::new(10, 0, 0, rng.random_range(2..=250));
            let remote_ip = Ipv4Addr::new(8, 8, 4, rng.random_range(1..=250));
            let packet = build_client_packet_with_options(
                client_ip,
                remote_ip,
                rng.random_range(1024..=65000),
                rng.random_range(1..=65000),
                sequence_number,
                acknowledgement_number,
                window_size,
                flags,
                &options,
                &payload,
            );
            assert_ipv4_header_checksum_valid(&packet);
            assert_transport_checksum_valid(&packet, IP_PROTOCOL_TCP);
            let parsed = super::parse_tcp_packet_unverified(&packet).unwrap();
            assert_eq!(parsed.version, super::IpVersion::V4);
            assert_eq!(parsed.sequence_number, sequence_number);
            assert_eq!(parsed.acknowledgement_number, acknowledgement_number);
            assert_eq!(parsed.flags, flags);
            assert_eq!(parsed.payload, payload);

            let mutated = flip_packet_byte(&packet, transport_offset(&packet) + 4);
            assert!(super::parse_tcp_packet_unverified(&mutated).is_err());
        } else {
            let client_ip = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, rng.random_range(2..=250));
            let remote_ip = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, rng.random_range(2..=250));
            let packet = build_client_ipv6_packet_with_options(
                client_ip,
                remote_ip,
                rng.random_range(1024..=65000),
                rng.random_range(1..=65000),
                sequence_number,
                acknowledgement_number,
                window_size,
                flags,
                &options,
                &payload,
            );
            assert_transport_checksum_valid(&packet, IP_PROTOCOL_TCP);
            let parsed = super::parse_tcp_packet_unverified(&packet).unwrap();
            assert_eq!(parsed.version, super::IpVersion::V6);
            assert_eq!(parsed.sequence_number, sequence_number);
            assert_eq!(parsed.acknowledgement_number, acknowledgement_number);
            assert_eq!(parsed.flags, flags);
            assert_eq!(parsed.payload, payload);

            let mutated = flip_packet_byte(&packet, transport_offset(&packet) + 4);
            assert!(super::parse_tcp_packet_unverified(&mutated).is_err());
        }
    }
}

#[test]
fn randomized_out_of_order_reassembly_smoke() {
    let mut rng = StdRng::seed_from_u64(0x51ce_2026);
    for _ in 0..64 {
        let sequence_start = rng.random_range(10_000..50_000);
        let total_len = rng.random_range(12..96);
        let mut original = vec![0u8; total_len];
        rng.fill(original.as_mut_slice());

        let mut segments = Vec::new();
        let mut cursor = 0usize;
        while cursor < total_len {
            let len = rng.random_range(1..=(total_len - cursor).min(16));
            segments
                .push((sequence_start + cursor as u32, original[cursor..cursor + len].to_vec()));
            if cursor > 0 && rng.random_bool(0.35) {
                let overlap_start = cursor.saturating_sub(rng.random_range(1..=cursor.min(4)));
                segments.push((
                    sequence_start + overlap_start as u32,
                    original[overlap_start..cursor + len].to_vec(),
                ));
            }
            cursor += len;
        }
        segments.shuffle(&mut rng);

        let mut pending = VecDeque::new();
        for (sequence_number, payload) in segments {
            let seg = TrimmedSegment {
                sequence_number,
                flags: TCP_FLAG_ACK,
                payload: Bytes::from(payload),
            };
            queue_future_segment(&mut pending, &seg, sequence_start);
        }

        let mut expected_seq = sequence_start;
        let mut reassembled = Vec::new();
        let closed =
            drain_ready_buffered_segments(&mut expected_seq, &mut pending, &mut reassembled);
        assert!(!closed);
        assert_eq!(expected_seq, sequence_start + total_len as u32);
        assert_eq!(reassembled.concat(), original);
    }
}

#[tokio::test]
async fn build_flow_syn_ack_advertises_mss_and_timestamps() {
    let mut state = tcp_flow_state_for_tests().await;
    state.client_sack_permitted = true;
    state.timestamps_enabled = true;
    state.recent_client_timestamp = Some(1234);
    state.server_timestamp_offset = 7;

    let packet = super::build_flow_syn_ack_packet(&state, 900, 101).unwrap();
    let parsed = super::parse_tcp_packet_unverified(&packet).unwrap();
    assert_eq!(parsed.flags, TCP_FLAG_SYN | TCP_FLAG_ACK);
    assert_eq!(parsed.max_segment_size, Some(super::MAX_SERVER_SEGMENT_PAYLOAD as u16));
    assert!(parsed.sack_permitted);
    assert_eq!(parsed.timestamp_echo_reply, Some(1234));
    assert!(parsed.timestamp_value.unwrap_or_default() >= 7);
}

#[cfg(feature = "metrics")]
#[tokio::test]
async fn bbr_metrics_export_loss_cap_gauges_and_episode_counter() {
    let mut state = tcp_flow_state_for_tests().await;
    // Labels unique to this test: the series below are asserted by absolute
    // value, and other tests in this binary sync flows concurrently under the
    // helper's shared "test" labels.
    state.routing.group_name = Arc::from("bbr_metrics_grp");
    state.routing.uplink_name = Arc::from("bbr_metrics_up");
    state.bbr.btlbw_bps = 10_000_000;
    state.bbr.min_rtt = Duration::from_millis(20);
    state.bbr.pacing_gain = 1.0;

    // Two RTO loss episodes drive the exported counter. The cap is then set
    // directly: it is a per-round quantity adapted against a *measured loss
    // rate* and floored at what the link delivered (see the `bbr` unit tests),
    // not something an episode moves on its own — an episode says loss happened,
    // not how much. What this test pins down is what reaches Prometheus.
    super::state_machine::note_congestion_event(&mut state, true);
    super::state_machine::note_congestion_event(&mut state, true);
    assert_eq!(state.bbr.loss_episodes, 2);
    state.bbr.loss_cap_bps = 7_225_000;

    super::state_machine::sync_flow_metrics(&mut state);
    let rendered = outline_metrics::render_prometheus(&[]).expect("render metrics");
    let labels = "{group=\"bbr_metrics_grp\",uplink=\"bbr_metrics_up\"}";
    for expected in [
        format!("outline_ws_tun_tcp_bbr_btlbw_bytes_per_second{labels} 10000000"),
        format!("outline_ws_tun_tcp_bbr_pacing_rate_bytes_per_second{labels} 7225000"),
        format!("outline_ws_tun_tcp_bbr_loss_cap_bytes_per_second{labels} 7225000"),
        format!("outline_ws_tun_tcp_bbr_loss_capped_flows{labels} 1"),
        format!("outline_ws_tun_tcp_bbr_min_rtt_seconds{labels} 0.02"),
        format!("outline_ws_tun_tcp_bbr_loss_episodes_total{labels} 2"),
    ] {
        assert!(rendered.contains(&expected), "missing `{expected}` in:\n{rendered}");
    }

    // Closing the flow unwinds the gauges to zero, but the counter is monotonic:
    // it must keep the two episodes this flow contributed.
    super::state_machine::clear_flow_metrics(&mut state);
    let after_close = outline_metrics::render_prometheus(&[]).expect("render metrics");
    for expected in [
        format!("outline_ws_tun_tcp_bbr_loss_cap_bytes_per_second{labels} 0"),
        format!("outline_ws_tun_tcp_bbr_loss_capped_flows{labels} 0"),
        format!("outline_ws_tun_tcp_bbr_pacing_rate_bytes_per_second{labels} 0"),
        format!("outline_ws_tun_tcp_bbr_loss_episodes_total{labels} 2"),
    ] {
        assert!(
            after_close.contains(&expected),
            "missing `{expected}` after close in:\n{after_close}"
        );
    }
}

#[tokio::test]
async fn flush_server_data_emits_gso_super_segment_tracked_per_mss() {
    let mut state = tcp_flow_state_for_tests().await;
    state.gso_enabled = true;
    state.client_max_segment_size = None;
    state.server_seq = 1000;
    state.rcv_nxt = 500;
    state.client_window = 100_000;
    state.client_window_end = state.server_seq.wrapping_add(100_000);

    let mss = super::MAX_SERVER_SEGMENT_PAYLOAD;
    let payload_len = mss * 4 + 200; // 5000 bytes: spans 5 MSS segments (4×MSS + 200)
    state.pending_server_data = std::collections::VecDeque::from([vec![7u8; payload_len].into()]);
    state.pending_server_bytes_total = state.pending_server_data.iter().map(|c| c.len()).sum();

    let flush = super::state_machine::flush_server_output(&mut state).unwrap();

    // One physical write (a TSO super-segment) instead of five MSS packets.
    assert_eq!(flush.data_packets.len(), 1);
    let packet = &flush.data_packets[0];
    let vnet = packet.vnet.expect("TSO super-segment carries a virtio_net_hdr");
    assert_eq!(vnet.gso_size as usize, mss);
    assert_eq!(vnet.gso_type, crate::vnet::VIRTIO_NET_HDR_GSO_TCPV4);
    assert_eq!(vnet.flags, crate::vnet::VIRTIO_NET_HDR_F_NEEDS_CSUM);
    // IPv4 total_len covers the whole coalesced payload: header + payload bytes,
    // even though the payload is carried as zero-copy chunks never copied into
    // `header`.
    let payload_bytes: usize = packet.payload.iter().map(|c| c.len()).sum();
    let total_len = u16::from_be_bytes([packet.header[2], packet.header[3]]) as usize;
    assert_eq!(total_len, packet.header.len() + payload_bytes);
    assert!(total_len > mss);

    // The retransmit scoreboard is still per-MSS so a loss inside the
    // super-segment recovers at MSS granularity.
    assert_eq!(state.unacked_server_segments.len(), 5);
    let sequence_numbers: Vec<u32> = state
        .unacked_server_segments
        .iter()
        .map(|segment| segment.sequence_number)
        .collect();
    assert_eq!(
        sequence_numbers,
        vec![
            1000,
            1000 + mss as u32,
            1000 + 2 * mss as u32,
            1000 + 3 * mss as u32,
            1000 + 4 * mss as u32,
        ]
    );
    assert_eq!(state.unacked_server_segments.back().unwrap().payload.len(), 200);
    assert_eq!(state.server_seq, 1000 + payload_len as u32);
}

#[tokio::test]
async fn flush_super_segment_from_multiple_chunks_is_byte_exact() {
    let mut state = tcp_flow_state_for_tests().await;
    state.gso_enabled = true;
    state.client_max_segment_size = None;
    state.server_seq = 1000;
    state.rcv_nxt = 500;
    state.client_window = 100_000;
    state.client_window_end = state.server_seq.wrapping_add(100_000);

    let mss = super::MAX_SERVER_SEGMENT_PAYLOAD; // 1200
    // Chunk boundaries (every 1000 B) deliberately misalign with MSS boundaries
    // (every 1200 B) so every MSS segment straddles a chunk boundary — this is
    // the copy path in `slice_chunks`, which must stay byte-exact.
    let chunk_len = 1000usize;
    let chunk_count = 5usize;
    let total = chunk_len * chunk_count; // 5000
    let stream: Vec<u8> = (0..total).map(|i| (i % 251) as u8).collect();
    let mut queue = std::collections::VecDeque::new();
    for c in 0..chunk_count {
        let start = c * chunk_len;
        queue.push_back(stream[start..start + chunk_len].to_vec().into());
    }
    state.pending_server_data = queue;
    state.pending_server_bytes_total = total;

    let flush = super::state_machine::flush_server_output(&mut state).unwrap();

    assert_eq!(flush.data_packets.len(), 1);
    let packet = &flush.data_packets[0];
    assert!(packet.vnet.is_some(), "TSO super-segment");
    // The multi-chunk payload is carried without coalescing into one buffer.
    assert!(packet.payload.len() > 1, "payload kept as separate chunks");

    // The vectored payload chunks reconstruct the original stream exactly.
    let mut written = Vec::new();
    for chunk in &packet.payload {
        written.extend_from_slice(chunk);
    }
    assert_eq!(written, stream, "writev payload must equal the source stream");

    // Every scoreboard segment holds the byte-exact MSS slice of the stream,
    // including the segments copied across chunk boundaries.
    assert_eq!(state.unacked_server_segments.len(), total.div_ceil(mss));
    let mut offset = 0usize;
    for segment in &state.unacked_server_segments {
        let end = (offset + mss).min(total);
        assert_eq!(
            segment.payload.as_ref(),
            &stream[offset..end],
            "segment [{offset}, {end}) must be byte-exact"
        );
        offset = end;
    }
    assert_eq!(state.server_seq, 1000 + total as u32);
}

/// Canonical `tcp_rate_skb_delivered` records the send time of the most recently
/// ACKed packet in `first_tx_mstamp`; the next segments snapshot it and measure
/// their send-phase interval from it, so that interval spans one flight.
///
/// `tcp_rate_skb_sent` also seeds the anchor, but only when the pipe is empty —
/// and that used to be the only site here. A bulk transfer never empties its
/// pipe, so every segment snapshotted the instant the flow's first byte went out
/// and its send interval became the flow's *age*. The rate interval is
/// `max(ack_interval, send_interval)`, so a stale anchor divides each sample by
/// that age: seconds instead of milliseconds, reading kilobytes/s on a path
/// carrying tens of MB/s.
#[tokio::test]
async fn ack_advances_first_tx_mstamp_so_the_send_interval_spans_one_flight() {
    const MSS: usize = 4;
    const STEP: Duration = Duration::from_millis(2);

    fn send_segment(state: &mut super::TcpFlowState, sequence_number: u32, at: Instant) {
        state.unacked_server_segments.push_back(super::ServerSegment {
            sequence_number,
            acknowledgement_number: 500,
            flags: TCP_FLAG_ACK | super::TCP_FLAG_PSH,
            payload: vec![0u8; MSS].into(),
            last_sent: at,
            first_sent: at,
            retransmits: 0,
            rto_retransmits: 0,
            fast_retransmit_epoch: 0,
            delivered_snapshot: 0,
            delivered_at_snapshot: at,
            // What `push_unacked_segments` snapshots: the flight anchor as it
            // stands when this segment goes out.
            first_tx_snapshot: state.first_tx_mstamp,
            app_limited: false,
        });
        super::rebuild_unacked_accounting(state);
    }

    let mut state = tcp_flow_state_for_tests().await;
    let t0 = Instant::now();
    state.first_tx_mstamp = t0;
    state.last_client_ack = 1000;
    state.server_seq = 1000;
    state.client_window = 65535;
    state.client_window_end = 1000u32.wrapping_add(65535);

    // Prime the pipe with two segments, so ACKing one never drains it and the
    // `tcp_rate_skb_sent` reseed never fires — exactly the bulk-transfer case.
    let mut next_seq = 1000u32;
    let mut sent_at = t0;
    send_segment(&mut state, next_seq, sent_at);
    next_seq += MSS as u32;
    sent_at += STEP;
    send_segment(&mut state, next_seq, sent_at);
    next_seq += MSS as u32;

    let mut send_interval = Duration::ZERO;
    for _ in 0..100 {
        let oldest = state.unacked_server_segments.front().expect("pipe is never empty");
        let ack = oldest.sequence_number.wrapping_add(MSS as u32);
        let effect = super::process_server_ack(&mut state, ack, &[]);
        send_interval = effect
            .rate_sample
            .expect("a cleanly ACKed segment yields a rate sample")
            .send_interval;
        // Send one more before the next ACK, so the pipe stays occupied.
        sent_at += STEP;
        send_segment(&mut state, next_seq, sent_at);
        next_seq += MSS as u32;
    }

    // The flow is ~200 ms old by now, while one flight spans two `STEP`s. The
    // send interval must measure the flight, not the flow.
    let flow_age = sent_at.saturating_duration_since(t0);
    assert!(flow_age >= Duration::from_millis(190), "flow_age={flow_age:?}");
    assert!(
        send_interval <= STEP * 3,
        "send interval must span one flight, not the flow's age: \
         send_interval={send_interval:?}, flow_age={flow_age:?}"
    );
}

/// The anchor tracks the newest ACKed segment, never walks backwards, and is not
/// dragged back by an older segment ACKed later (a retransmitted hole closing
/// after the segments above it).
#[tokio::test]
async fn first_tx_mstamp_tracks_the_newest_acked_segment_and_never_recedes() {
    let mut state = tcp_flow_state_for_tests().await;
    let t0 = Instant::now();
    state.first_tx_mstamp = t0;
    state.last_client_ack = 1000;
    state.server_seq = 1008;
    state.client_window = 65535;
    state.client_window_end = 1000u32.wrapping_add(65535);
    state.unacked_server_segments = VecDeque::from([
        super::ServerSegment {
            sequence_number: 1000,
            acknowledgement_number: 500,
            flags: TCP_FLAG_ACK | super::TCP_FLAG_PSH,
            payload: b"AAAA".to_vec().into(),
            last_sent: t0 + Duration::from_millis(5),
            first_sent: t0 + Duration::from_millis(5),
            retransmits: 0,
            rto_retransmits: 0,
            fast_retransmit_epoch: 0,
            delivered_snapshot: 0,
            delivered_at_snapshot: t0,
            first_tx_snapshot: t0,
            app_limited: false,
        },
        super::ServerSegment {
            sequence_number: 1004,
            acknowledgement_number: 500,
            flags: TCP_FLAG_ACK | super::TCP_FLAG_PSH,
            payload: b"BBBB".to_vec().into(),
            last_sent: t0 + Duration::from_millis(9),
            first_sent: t0 + Duration::from_millis(9),
            retransmits: 0,
            rto_retransmits: 0,
            fast_retransmit_epoch: 0,
            delivered_snapshot: 0,
            delivered_at_snapshot: t0,
            first_tx_snapshot: t0,
            app_limited: false,
        },
    ]);
    super::rebuild_unacked_accounting(&mut state);

    super::process_server_ack(&mut state, 1008, &[]);
    assert_eq!(
        state.first_tx_mstamp,
        t0 + Duration::from_millis(9),
        "anchor must reach the newest ACKed segment's send instant"
    );

    // An older send instant arriving later must not drag the anchor back.
    state.unacked_server_segments.push_back(super::ServerSegment {
        sequence_number: 1008,
        acknowledgement_number: 500,
        flags: TCP_FLAG_ACK | super::TCP_FLAG_PSH,
        payload: b"CCCC".to_vec().into(),
        last_sent: t0 + Duration::from_millis(7),
        first_sent: t0 + Duration::from_millis(7),
        retransmits: 0,
        rto_retransmits: 0,
        fast_retransmit_epoch: 0,
        delivered_snapshot: 0,
        delivered_at_snapshot: t0,
        first_tx_snapshot: t0,
        app_limited: false,
    });
    super::rebuild_unacked_accounting(&mut state);
    super::process_server_ack(&mut state, 1012, &[]);
    assert_eq!(state.first_tx_mstamp, t0 + Duration::from_millis(9), "anchor must not recede");
}

#[tokio::test]
async fn process_server_ack_marks_sacked_segments_without_cumulative_ack() {
    let mut state = tcp_flow_state_for_tests().await;
    state.last_client_ack = 1000;
    state.server_seq = 1012;
    state.client_window = 8192;
    state.client_window_end = 9192;
    state.unacked_server_segments = VecDeque::from([
        super::ServerSegment {
            sequence_number: 1000,
            acknowledgement_number: 500,
            flags: TCP_FLAG_ACK | super::TCP_FLAG_PSH,
            payload: b"AAAA".to_vec().into(),
            last_sent: Instant::now(),
            first_sent: Instant::now(),
            retransmits: 0,
            rto_retransmits: 0,
            fast_retransmit_epoch: 0,
            delivered_snapshot: 0,
            delivered_at_snapshot: Instant::now(),
            first_tx_snapshot: Instant::now(),
            app_limited: false,
        },
        super::ServerSegment {
            sequence_number: 1004,
            acknowledgement_number: 500,
            flags: TCP_FLAG_ACK | super::TCP_FLAG_PSH,
            payload: b"BBBB".to_vec().into(),
            last_sent: Instant::now(),
            first_sent: Instant::now(),
            retransmits: 0,
            rto_retransmits: 0,
            fast_retransmit_epoch: 0,
            delivered_snapshot: 0,
            delivered_at_snapshot: Instant::now(),
            first_tx_snapshot: Instant::now(),
            app_limited: false,
        },
    ]);

    super::rebuild_unacked_accounting(&mut state);

    let effect = super::process_server_ack(&mut state, 1000, &[(1004, 1008)]);
    assert_eq!(effect.bytes_acked, 0);
    assert!(!effect.retransmit_now);
    assert_eq!(state.sack_scoreboard, vec![SequenceRange { start: 1004, end: 1008 }]);
}

#[tokio::test]
async fn process_server_ack_partial_ack_in_fast_recovery_requests_next_retransmit() {
    let mut state = tcp_flow_state_for_tests().await;
    state.last_client_ack = 1000;
    state.server_seq = 1016;
    state.fast_recovery_end = Some(1016);
    state.recovery_epoch = 1;
    state.sack_scoreboard = vec![SequenceRange { start: 1008, end: 1012 }];
    state.unacked_server_segments = VecDeque::from([
        super::ServerSegment {
            sequence_number: 1000,
            acknowledgement_number: 500,
            flags: TCP_FLAG_ACK | super::TCP_FLAG_PSH,
            payload: b"AAAA".to_vec().into(),
            last_sent: Instant::now() - Duration::from_secs(2),
            first_sent: Instant::now() - Duration::from_millis(200),
            retransmits: 0,
            rto_retransmits: 0,
            fast_retransmit_epoch: 0,
            delivered_snapshot: 0,
            delivered_at_snapshot: Instant::now(),
            first_tx_snapshot: Instant::now(),
            app_limited: false,
        },
        super::ServerSegment {
            sequence_number: 1004,
            acknowledgement_number: 500,
            flags: TCP_FLAG_ACK | super::TCP_FLAG_PSH,
            payload: b"BBBB".to_vec().into(),
            last_sent: Instant::now() - Duration::from_secs(2),
            first_sent: Instant::now() - Duration::from_secs(2),
            retransmits: 1,
            rto_retransmits: 0,
            fast_retransmit_epoch: 0,
            delivered_snapshot: 0,
            delivered_at_snapshot: Instant::now(),
            first_tx_snapshot: Instant::now(),
            app_limited: false,
        },
        super::ServerSegment {
            sequence_number: 1008,
            acknowledgement_number: 500,
            flags: TCP_FLAG_ACK | super::TCP_FLAG_PSH,
            payload: b"CCCC".to_vec().into(),
            last_sent: Instant::now() - Duration::from_secs(2),
            first_sent: Instant::now() - Duration::from_secs(2),
            retransmits: 0,
            rto_retransmits: 0,
            fast_retransmit_epoch: 0,
            delivered_snapshot: 0,
            delivered_at_snapshot: Instant::now(),
            first_tx_snapshot: Instant::now(),
            app_limited: false,
        },
        super::ServerSegment {
            sequence_number: 1012,
            acknowledgement_number: 500,
            flags: TCP_FLAG_ACK | super::TCP_FLAG_PSH,
            payload: b"DDDD".to_vec().into(),
            last_sent: Instant::now() - Duration::from_secs(2),
            first_sent: Instant::now() - Duration::from_secs(2),
            retransmits: 0,
            rto_retransmits: 0,
            fast_retransmit_epoch: 0,
            delivered_snapshot: 0,
            delivered_at_snapshot: Instant::now(),
            first_tx_snapshot: Instant::now(),
            app_limited: false,
        },
    ]);

    super::rebuild_unacked_accounting(&mut state);

    let effect = super::process_server_ack(&mut state, 1004, &[(1008, 1012)]);
    assert_eq!(effect.bytes_acked, 4);
    assert!(!effect.grow_congestion_window);
    assert!(effect.retransmit_now);
    assert_eq!(state.fast_recovery_end, Some(1016));
}

#[tokio::test]
async fn process_server_ack_exits_fast_recovery_once_recovery_point_is_acked() {
    let mut state = tcp_flow_state_for_tests().await;
    state.last_client_ack = 1000;
    state.server_seq = 1016;
    state.fast_recovery_end = Some(1016);
    state.unacked_server_segments = VecDeque::from([
        super::ServerSegment {
            sequence_number: 1000,
            acknowledgement_number: 500,
            flags: TCP_FLAG_ACK | super::TCP_FLAG_PSH,
            payload: b"AAAA".to_vec().into(),
            last_sent: Instant::now() - Duration::from_secs(2),
            first_sent: Instant::now() - Duration::from_millis(200),
            retransmits: 1,
            rto_retransmits: 0,
            fast_retransmit_epoch: 0,
            delivered_snapshot: 0,
            delivered_at_snapshot: Instant::now(),
            first_tx_snapshot: Instant::now(),
            app_limited: false,
        },
        super::ServerSegment {
            sequence_number: 1004,
            acknowledgement_number: 500,
            flags: TCP_FLAG_ACK | super::TCP_FLAG_PSH,
            payload: b"BBBB".to_vec().into(),
            last_sent: Instant::now() - Duration::from_secs(2),
            first_sent: Instant::now() - Duration::from_secs(2),
            retransmits: 1,
            rto_retransmits: 0,
            fast_retransmit_epoch: 0,
            delivered_snapshot: 0,
            delivered_at_snapshot: Instant::now(),
            first_tx_snapshot: Instant::now(),
            app_limited: false,
        },
    ]);

    super::rebuild_unacked_accounting(&mut state);

    let effect = super::process_server_ack(&mut state, 1008, &[]);
    assert_eq!(effect.bytes_acked, 8);
    assert!(!effect.grow_congestion_window);
    assert!(!effect.retransmit_now);
    assert!(state.fast_recovery_end.is_none());
}

// --- SACK fast-retransmit budget (regression: Kinopoisk direct-video RST) ---
//
// A burst-loss on the downlink makes the client send many duplicate ACKs whose
// SACK islands keep growing. The old code fast-retransmitted the *same* hole on
// every such partial SACK and counted each against `max_retransmits`, so a live
// flow was reaped with `retransmit_budget_exhausted` in ~100 ms. These pin the
// fix: a hole is fast-retransmitted at most once per recovery episode, and the
// budget keys off RTO-driven retransmits only.

fn unacked_segment(seq: u32, payload: &'static [u8]) -> super::ServerSegment {
    super::ServerSegment {
        sequence_number: seq,
        acknowledgement_number: 500,
        flags: TCP_FLAG_ACK | super::TCP_FLAG_PSH,
        payload: payload.to_vec().into(),
        last_sent: Instant::now(),
        first_sent: Instant::now(),
        retransmits: 0,
        rto_retransmits: 0,
        fast_retransmit_epoch: 0,
        delivered_snapshot: 0,
        delivered_at_snapshot: Instant::now(),
        first_tx_snapshot: Instant::now(),
        app_limited: false,
    }
}

#[tokio::test]
async fn fast_retransmit_resends_a_hole_at_most_once_per_episode() {
    let mut state = tcp_flow_state_for_tests().await;
    state.last_client_ack = 1000;
    state.server_seq = 1020;
    // One hole at 1000; everything above it gets SACKed incrementally.
    state.unacked_server_segments = VecDeque::from([
        unacked_segment(1000, b"AAAA"),
        unacked_segment(1004, b"BBBB"),
        unacked_segment(1008, b"CCCC"),
        unacked_segment(1012, b"DDDD"),
        unacked_segment(1016, b"EEEE"),
    ]);
    super::rebuild_unacked_accounting(&mut state);

    // Three dup-ACKs (cum=1000) with SACK covering 1004..1012 enter fast
    // recovery and request the first (and only) retransmit of the hole.
    super::process_server_ack(&mut state, 1000, &[(1004, 1012)]);
    super::process_server_ack(&mut state, 1000, &[(1004, 1012)]);
    let third = super::process_server_ack(&mut state, 1000, &[(1004, 1012)]);
    assert!(third.retransmit_now, "3rd dup-ACK enters recovery and retransmits the hole");

    let sdp = super::retransmit_oldest_unacked_packet(&mut state).unwrap().unwrap();
    let mut pkt = sdp.header.clone();
    for chunk in &sdp.payload {
        pkt.extend_from_slice(chunk);
    }
    assert_eq!(super::parse_tcp_packet_unverified(&pkt).unwrap().sequence_number, 1000);
    let hole = &state.unacked_server_segments[0];
    assert_eq!(hole.sequence_number, 1000);
    assert_eq!(hole.retransmits, 1, "Karn counter bumps on every wire put-back");
    assert_eq!(hole.rto_retransmits, 0, "fast-retransmit is not an RTO event");

    // A 4th dup-ACK whose SACK now also covers 1012..1016 advances the
    // scoreboard, leaving 1000 the only remaining hole — already resent this
    // episode, so it must NOT be fast-retransmitted again.
    let fourth = super::process_server_ack(&mut state, 1000, &[(1004, 1016)]);
    assert!(
        !fourth.retransmit_now,
        "same hole must not be re-fast-retransmitted on a follow-up partial SACK"
    );
    assert!(super::retransmit_oldest_unacked_packet(&mut state).unwrap().is_none());
    assert_eq!(state.unacked_server_segments[0].retransmits, 1);
}

#[tokio::test]
async fn budget_keys_off_rto_retransmits_not_fast_retransmits() {
    let config = TunTcpConfig {
        max_retransmits: 3,
        downlink_max_rate_bps: 0,
        ..test_tun_tcp_config()
    };
    let mut state = tcp_flow_state_for_tests().await;
    let mut segment = unacked_segment(1000, b"AAAA");
    // A storm of SACK-driven fast-retransmits must not look like a dead path.
    segment.retransmits = 100;
    segment.rto_retransmits = 0;
    state.unacked_server_segments = VecDeque::from([segment]);
    assert!(
        !super::retransmit_budget_exhausted(&state, &config),
        "fast-retransmits alone never exhaust the budget"
    );

    // Only genuine RTO-driven resends count toward the dead-path budget.
    state.unacked_server_segments[0].rto_retransmits = 3;
    assert!(super::retransmit_budget_exhausted(&state, &config));
}

#[tokio::test]
async fn rto_retransmit_bumps_the_rto_counter() {
    let mut state = tcp_flow_state_for_tests().await;
    state.retransmission_timeout = Duration::from_millis(200);
    let mut segment = unacked_segment(1000, b"AAAA");
    segment.last_sent = Instant::now() - Duration::from_secs(2);
    state.unacked_server_segments = VecDeque::from([segment]);

    let _ = super::retransmit_due_segment(&mut state).unwrap().unwrap();
    let seg = &state.unacked_server_segments[0];
    assert_eq!(seg.rto_retransmits, 1, "RTO resend is the dead-path signal");
    assert_eq!(seg.retransmits, 1);
}

// --- Incremental in-flight (pipe) accounting equivalence ------------------
//
// `pipe_bytes` / `pipe_segments` / `earliest_unsacked_sent` are maintained
// incrementally at every push / ACK / SACK / retransmit site so the hot-path
// reads are O(1). These pin that the running counters stay bit-for-bit equal to
// a full scan of the unacked queue through every mutation shape — a drift would
// silently skew the congestion window.

fn scan_pipe_accounting(state: &super::TcpFlowState) -> (usize, usize, Option<Instant>) {
    let mut bytes = 0usize;
    let mut segments = 0usize;
    let mut earliest: Option<Instant> = None;
    for segment in &state.unacked_server_segments {
        if !super::server_segment_is_sacked(state, segment) {
            bytes += super::server_segment_len(segment);
            segments += 1;
            earliest = Some(match earliest {
                Some(current) => current.min(segment.last_sent),
                None => segment.last_sent,
            });
        }
    }
    (bytes, segments, earliest)
}

#[track_caller]
fn assert_accounting_matches(state: &super::TcpFlowState, context: &str) {
    let (bytes, segments, earliest) = scan_pipe_accounting(state);
    assert_eq!(state.pipe_bytes, bytes, "pipe_bytes drifted after {context}");
    assert_eq!(state.pipe_segments, segments, "pipe_segments drifted after {context}");
    assert_eq!(
        state.earliest_unsacked_sent, earliest,
        "earliest_unsacked_sent drifted after {context}"
    );
}

#[tokio::test]
async fn incremental_pipe_accounting_matches_scan_through_ack_sack_retransmit() {
    let mut state = tcp_flow_state_for_tests().await;
    state.last_client_ack = 1000;
    state.server_seq = 1024;
    state.recovery_epoch = 1;
    state.client_window = 65535;
    state.client_window_end = 1024u32.wrapping_add(65535);
    state.retransmission_timeout = Duration::from_millis(200);

    // Six 4-byte segments (1000..1024) with strictly increasing send instants.
    let base = Instant::now() - Duration::from_secs(1);
    let mut queue = VecDeque::new();
    for index in 0..6u32 {
        let mut segment = unacked_segment(1000 + index * 4, b"DATA");
        segment.last_sent = base + Duration::from_millis(index as u64);
        segment.first_sent = segment.last_sent;
        queue.push_back(segment);
    }
    state.unacked_server_segments = queue;
    super::rebuild_unacked_accounting(&mut state);
    assert_accounting_matches(&state, "manual build");
    assert_eq!((state.pipe_bytes, state.pipe_segments), (24, 6));

    // Partial cumulative ACK frees the first two segments (1000, 1004).
    super::process_server_ack(&mut state, 1008, &[]);
    assert_accounting_matches(&state, "partial cumulative ACK");
    assert_eq!((state.pipe_bytes, state.pipe_segments), (16, 4));

    // A dup ACK (cum unchanged) carrying a SACK block pulls 1012..1020 (the
    // 1012 and 1016 segments) out of the pipe, leaving 1008 and 1020 un-SACKed.
    super::process_server_ack(&mut state, 1008, &[(1012, 1020)]);
    assert_accounting_matches(&state, "SACK block");
    assert_eq!((state.pipe_bytes, state.pipe_segments), (8, 2));

    // Fast-retransmit the 1008 hole: its send instant is rewritten to now,
    // reordering the queue — the earliest cache must fall back to the exact min.
    let sdp = super::retransmit_oldest_unacked_packet(&mut state).unwrap().unwrap();
    let mut packet = sdp.header.clone();
    for chunk in &sdp.payload {
        packet.extend_from_slice(chunk);
    }
    assert_eq!(super::parse_tcp_packet_unverified(&packet).unwrap().sequence_number, 1008);
    assert!(state.unacked_reordered, "a retransmit past the tail reorders send instants");
    assert_accounting_matches(&state, "fast retransmit");
    assert_eq!((state.pipe_bytes, state.pipe_segments), (8, 2));

    // An RTO resend of the still-old 1020 segment (also un-SACKed) keeps books.
    let _ = super::retransmit_due_segment(&mut state).unwrap().unwrap();
    assert_accounting_matches(&state, "RTO retransmit");

    // Cumulative ACK past everything drains the queue: pipe empty, cache cleared.
    super::process_server_ack(&mut state, 1024, &[]);
    assert_accounting_matches(&state, "final drain");
    assert_eq!((state.pipe_bytes, state.pipe_segments), (0, 0));
    assert_eq!(state.earliest_unsacked_sent, None);
    assert!(!state.unacked_reordered);
}

/// `app_limited` must mean "our supply ended the flight", not "the queue is
/// empty right now". A bulk transfer whose flush was stopped by the send window
/// is congestion-limited: its delivery-rate sample measures the path and must
/// stay eligible to lower BtlBw. Marking it app-limited is what let BtlBw drift
/// upward unchecked — the stack then offers the last hop more than it can drain,
/// and the loss cap collapses onto its floor (the 3d0d495 regression).
#[tokio::test]
async fn a_flight_the_window_cut_short_is_not_app_limited() {
    let mut state = tcp_flow_state_for_tests().await;
    let mss = super::MAX_SERVER_SEGMENT_PAYLOAD;
    state.server_seq = 1000;
    // Exactly 2 MSS of window, and exactly 2 MSS queued: the window and the
    // queue run out on the very same write. The queue being empty afterwards is
    // incidental — the window is what bounded the flight.
    let window = (mss * 2) as u32;
    state.client_window = window;
    state.client_window_end = 1000u32.wrapping_add(window);
    state.pending_server_data = VecDeque::from([vec![7u8; mss * 2].into()]);
    state.pending_server_bytes_total = mss * 2;

    super::state_machine::flush_server_output(&mut state).unwrap();

    assert!(state.pending_server_data.is_empty(), "the queue did drain");
    assert!(
        state
            .unacked_server_segments
            .iter()
            .all(|segment| !segment.app_limited),
        "a flight the window cut short is congestion-limited, not app-limited",
    );
}

/// The other side of the same rule: nothing left to send while window remains is
/// genuinely app-limited, and that sample must not be allowed to lower BtlBw.
#[tokio::test]
async fn a_flight_that_ran_out_of_data_with_window_to_spare_is_app_limited() {
    let mut state = tcp_flow_state_for_tests().await;
    let mss = super::MAX_SERVER_SEGMENT_PAYLOAD;
    state.server_seq = 1000;
    // Plenty of window, one MSS queued: our supply is what ends the flight.
    let window = (mss * 10) as u32;
    state.client_window = window;
    state.client_window_end = 1000u32.wrapping_add(window);
    state.pending_server_data = VecDeque::from([vec![7u8; mss].into()]);
    state.pending_server_bytes_total = mss;

    super::state_machine::flush_server_output(&mut state).unwrap();

    assert!(
        state
            .unacked_server_segments
            .iter()
            .all(|segment| segment.app_limited),
        "queue dry with window to spare is app-limited",
    );
}

#[tokio::test]
async fn flush_fills_exactly_the_send_window_and_tracks_pipe() {
    // The flush loop decrements `available_window` per write instead of
    // recomputing it; this pins that it still emits exactly one window's worth
    // and that the incremental pipe accounting equals the emitted total.
    let mut state = tcp_flow_state_for_tests().await;
    let mss = super::MAX_SERVER_SEGMENT_PAYLOAD;
    // cwnd is generous so the peer receive window is the binding limit.
    state.server_seq = 1000;
    // Advertise exactly 5 MSS + 100 bytes of send window.
    let window = (mss * 5 + 100) as u32;
    state.client_window = window;
    state.client_window_end = 1000u32.wrapping_add(window);
    // Queue far more than the window so the window is what caps the flush.
    state.pending_server_data = VecDeque::from([vec![7u8; mss * 20].into()]);
    state.pending_server_bytes_total = mss * 20;

    let flush = super::state_machine::flush_server_output(&mut state).unwrap();
    let emitted: usize = flush
        .data_packets
        .iter()
        .map(|packet| packet.payload.iter().map(|chunk| chunk.len()).sum::<usize>())
        .sum();
    assert_eq!(emitted, window as usize, "flush emits exactly the send window");
    assert_eq!(state.pipe_bytes, window as usize);
    assert_eq!(state.server_seq, 1000u32.wrapping_add(window));
    assert_accounting_matches(&state, "windowed flush");
    // 5 full MSS segments + 1 short (100-byte) segment.
    assert_eq!(state.pipe_segments, 6);
}

/// Random SACK blocks within `[low, high)`, each a valid non-empty range. The
/// blocks are deliberately allowed to straddle segment boundaries and overlap —
/// the point is to stress the scoreboard/pipe bookkeeping with shapes the
/// hand-written equivalence test never reaches.
fn random_sack_blocks(rng: &mut StdRng, low: u32, high: u32) -> Vec<(u32, u32)> {
    let span = high.wrapping_sub(low);
    if span == 0 {
        return Vec::new();
    }
    let count = rng.random_range(0..=3);
    let mut blocks = Vec::with_capacity(count);
    for _ in 0..count {
        let a = low.wrapping_add(rng.random_range(0..=span));
        let b = low.wrapping_add(rng.random_range(0..=span));
        let (start, end) = if a <= b { (a, b) } else { (b, a) };
        if end > start {
            blocks.push((start, end));
        }
    }
    blocks
}

/// Property test — the executable stand-in for the release assert-build that the
/// perf runbook called for. The debug cross-check that guards the incremental
/// `pipe_bytes` / `pipe_segments` / `earliest_unsacked_sent` against a missed
/// update site is compiled out of release (`#[cfg(debug_assertions)]`), so a
/// drift would silently skew the congestion window on the live gateway and only
/// show up as throughput decay weeks later. This drives thousands of randomized
/// push / ACK / SACK / fast-retransmit steps across several seeds and asserts
/// the running counters equal a full scan after *every* mutation — covering the
/// ACK×SACK×retransmit interleavings the single deterministic sequence above
/// cannot enumerate. Tests run with debug_assertions on, so the internal
/// cross-check fires here too; this adds an independent scan and exercises the
/// real mutation sites through their public entry points.
#[tokio::test]
async fn incremental_pipe_accounting_survives_randomized_ack_sack_retransmit() {
    let mss = super::MAX_SERVER_SEGMENT_PAYLOAD;
    for seed in [0x1u64, 0xdead_beef, 0x5eed_face, 0xf00d_cafe, 42, 0xa5a5_a5a5] {
        let mut rng = seeded_rng(seed);
        let mut state = tcp_flow_state_for_tests().await;
        // Generous windows so the flush path can actually push new segments;
        // congestion growth/back-off during the run still varies burst sizes.

        for step in 0..600u32 {
            match rng.random_range(0..100u32) {
                // Push new data through the real flush path (push_unacked_segments).
                0..=34 => {
                    let window = (mss * 40) as u32;
                    state.client_window = window;
                    state.client_window_end = state.server_seq.wrapping_add(window);
                    let len = rng.random_range(1..=mss * 6);
                    state.pending_server_data.push_back(vec![0xABu8; len].into());
                    state.pending_server_bytes_total += len;
                    let _ = super::state_machine::flush_server_output(&mut state).unwrap();
                },
                // Cumulative ACK (possibly carrying SACK blocks): pops a prefix
                // and, on a new SACK block, rebuilds the accounting.
                35..=74 => {
                    let span = state.server_seq.wrapping_sub(state.last_client_ack);
                    if span > 0 {
                        let ack = state.last_client_ack.wrapping_add(rng.random_range(0..=span));
                        let sacks =
                            random_sack_blocks(&mut rng, state.last_client_ack, state.server_seq);
                        super::process_server_ack(&mut state, ack, &sacks);
                    }
                },
                // Pure duplicate ACK carrying SACK blocks (no cumulative advance).
                75..=89 => {
                    let sacks =
                        random_sack_blocks(&mut rng, state.last_client_ack, state.server_seq);
                    let ack = state.last_client_ack;
                    if !sacks.is_empty() {
                        super::process_server_ack(&mut state, ack, &sacks);
                    }
                },
                // Fast-retransmit the oldest hole: rewrites a segment's send
                // instant (reordering the queue) and rebuilds the earliest cache.
                // Bump the recovery epoch first so the hole is fresh for resend.
                _ => {
                    if !state.unacked_server_segments.is_empty() {
                        state.recovery_epoch = state.recovery_epoch.wrapping_add(1);
                        let _ = super::retransmit_oldest_unacked_packet(&mut state).unwrap();
                    }
                },
            }
            assert_accounting_matches(&state, &format!("seed {seed:#x} step {step}"));
        }

        // Drain everything: the queue empties, the counters bottom out at zero,
        // and the earliest/reordered caches clear.
        let final_ack = state.server_seq;
        super::process_server_ack(&mut state, final_ack, &[]);
        assert_accounting_matches(&state, &format!("seed {seed:#x} final drain"));
        assert_eq!((state.pipe_bytes, state.pipe_segments), (0, 0));
        assert_eq!(state.earliest_unsacked_sent, None);
        assert!(!state.unacked_reordered);
    }
}

#[tokio::test]
async fn advertised_window_collapses_when_uplink_buffer_fills_and_reopens_on_drain() {
    // Uplink back-pressure runs through the advertised receive window: as the
    // pump-fed buffer fills, the window shrinks to 0 and the client stalls.
    // The proactive window-update in the pump keys off exactly this transition
    // (was 0, drain reopened it) to wake the client without waiting for its
    // back-off-delayed zero-window probe — which had throttled uplink badly.
    let mut state = tcp_flow_state_for_tests().await;
    state.receive_window_capacity = 4096;
    state.pending_client_data.clear();
    state.pending_client_segments.clear();
    assert!(
        super::advertised_receive_window(&state) > 0,
        "empty buffer advertises an open window"
    );

    state.pending_client_data.push_back(vec![0u8; 4096].into());
    assert_eq!(
        super::advertised_receive_window(&state),
        0,
        "a full uplink buffer must collapse the advertised window to 0",
    );

    state.pending_client_data.clear();
    assert!(
        super::advertised_receive_window(&state) > 0,
        "draining the buffer must reopen the window (the proactive-update trigger)",
    );
}

#[tokio::test]
async fn delayed_ack_defers_lone_in_order_segment_then_acks_the_second() {
    use crate::tcp::state_machine::apply_inbound_and_flush;
    let mut state = tcp_flow_state_for_tests().await;

    let first = TrimmedSegment {
        sequence_number: state.rcv_nxt,
        flags: TCP_FLAG_ACK,
        payload: Bytes::from_static(b"hello"),
    };
    let out = apply_inbound_and_flush(&mut state, &first).unwrap();
    assert!(out.pending_ack.is_none(), "a lone in-order segment defers its ACK");
    assert!(state.delayed_ack_deadline.is_some(), "the delayed-ACK timer is armed");
    assert_eq!(state.unacked_in_order_segments, 1);

    let second = TrimmedSegment {
        sequence_number: state.rcv_nxt,
        flags: TCP_FLAG_ACK,
        payload: Bytes::from_static(b"world"),
    };
    let out = apply_inbound_and_flush(&mut state, &second).unwrap();
    assert!(
        out.pending_ack.is_some(),
        "the 2nd in-order segment ACKs immediately (RFC 5681)"
    );
    assert!(state.delayed_ack_deadline.is_none(), "the delay is cleared once acked");
    assert_eq!(state.unacked_in_order_segments, 0);
}

#[tokio::test]
async fn delayed_ack_is_immediate_for_a_fin() {
    use crate::tcp::state_machine::apply_inbound_and_flush;
    let mut state = tcp_flow_state_for_tests().await;
    let fin = TrimmedSegment {
        sequence_number: state.rcv_nxt,
        flags: TCP_FLAG_ACK | TCP_FLAG_FIN,
        payload: Bytes::new(),
    };
    let out = apply_inbound_and_flush(&mut state, &fin).unwrap();
    assert!(out.pending_ack.is_some(), "a FIN must be acked immediately, never deferred");
    assert!(state.delayed_ack_deadline.is_none());
}

#[tokio::test]
async fn delayed_ack_is_immediate_while_a_reassembly_hole_is_buffered() {
    use crate::tcp::state_machine::apply_inbound_and_flush;
    let mut state = tcp_flow_state_for_tests().await;
    // An out-of-order segment sits buffered ahead of rcv_nxt (a SACK hole): the
    // peer needs a prompt ACK carrying SACK, so delaying is not allowed.
    state.pending_client_segments.push_back(BufferedClientSegment {
        sequence_number: state.rcv_nxt.wrapping_add(100),
        flags: TCP_FLAG_ACK,
        payload: b"future".to_vec().into(),
    });
    let seg = TrimmedSegment {
        sequence_number: state.rcv_nxt,
        flags: TCP_FLAG_ACK,
        payload: Bytes::from_static(b"now"),
    };
    let out = apply_inbound_and_flush(&mut state, &seg).unwrap();
    assert!(
        out.pending_ack.is_some(),
        "with a buffered hole, ACK immediately so the peer's SACK path sees progress",
    );
    assert!(state.delayed_ack_deadline.is_none());
}

#[tokio::test]
async fn delayed_ack_timer_flushes_the_deferred_ack() {
    use crate::tcp::maintenance::{FlowMaintenancePlan, plan_flow_maintenance};
    use crate::tcp::state_machine::apply_inbound_and_flush;
    let config = test_tun_tcp_config();
    let mut state = tcp_flow_state_for_tests().await;

    let seg = TrimmedSegment {
        sequence_number: state.rcv_nxt,
        flags: TCP_FLAG_ACK,
        payload: Bytes::from_static(b"data"),
    };
    let out = apply_inbound_and_flush(&mut state, &seg).unwrap();
    assert!(out.pending_ack.is_none(), "the lone segment deferred its ACK");
    let deadline = state.delayed_ack_deadline.expect("timer armed");

    // Fire maintenance exactly at the deadline: the deferred ACK must go out.
    let plan = plan_flow_maintenance(&mut state, &config, Duration::from_secs(300), deadline)
        .expect("plan");
    match plan {
        FlowMaintenancePlan::SendPacket { event, .. } => {
            assert_eq!(event, "delayed_ack", "the fired timer emits the deferred ACK");
        },
        _ => panic!("expected a delayed_ack SendPacket from the fired timer"),
    }
    assert!(state.delayed_ack_deadline.is_none(), "timer state cleared after firing");
    assert_eq!(state.unacked_in_order_segments, 0);
}

#[tokio::test]
async fn update_client_send_window_uses_rfc_precedence_rules() {
    let mut state = tcp_flow_state_for_tests().await;
    state.client_window = 4096;
    state.client_window_end = 5096;
    state.client_window_update_seq = 100;
    state.client_window_update_ack = 1000;

    let stale = ParsedTcpPacket {
        version: super::IpVersion::V4,
        source_ip: "10.0.0.2".parse().unwrap(),
        destination_ip: "8.8.8.8".parse().unwrap(),
        source_port: 40000,
        destination_port: 443,
        sequence_number: 99,
        acknowledgement_number: 1000,
        window_size: 1,
        max_segment_size: None,
        window_scale: None,
        sack_permitted: false,
        sack_blocks: Vec::new(),
        timestamp_value: None,
        timestamp_echo_reply: None,
        flags: TCP_FLAG_ACK,
        payload: Bytes::new(),
    };
    super::update_client_send_window(&mut state, &stale);
    assert_eq!(state.client_window, 4096);
    assert_eq!(state.client_window_end, 5096);

    let newer = ParsedTcpPacket {
        sequence_number: 101,
        window_size: 2,
        ..stale
    };
    super::update_client_send_window(&mut state, &newer);
    assert_eq!(state.client_window, 2);
    assert_eq!(state.client_window_end, 1002);
    assert_eq!(state.client_window_update_seq, 101);
    assert_eq!(state.client_window_update_ack, 1000);
}

#[tokio::test]
async fn zero_window_persist_backoff_doubles_until_cap() {
    let mut state = tcp_flow_state_for_tests().await;
    state.client_window = 0;
    state.client_window_end = state.server_seq;
    state.pending_server_data.push_back(b"ABC".to_vec().into());
    state.pending_server_bytes_total = state.pending_server_data.iter().map(|c| c.len()).sum();

    let first = super::maybe_emit_zero_window_probe(&mut state).unwrap();
    assert!(first.is_some());
    assert_eq!(
        state.zero_window_probe_backoff,
        super::TCP_ZERO_WINDOW_PROBE_BASE_INTERVAL.saturating_mul(2)
    );
    let first_deadline = state.next_zero_window_probe_at.unwrap();

    state.next_zero_window_probe_at = Some(Instant::now() - Duration::from_millis(1));
    let second = super::maybe_emit_zero_window_probe(&mut state).unwrap();
    assert!(second.is_some());
    assert!(state.next_zero_window_probe_at.unwrap() > first_deadline);

    super::reset_zero_window_persist(&mut state);
    assert_eq!(state.zero_window_probe_backoff, super::TCP_ZERO_WINDOW_PROBE_BASE_INTERVAL);
    assert!(state.next_zero_window_probe_at.is_none());
}

#[tokio::test]
async fn build_flow_ack_packet_advertises_sack_blocks_for_buffered_segments() {
    let mut state = tcp_flow_state_for_tests().await;
    state.client_sack_permitted = true;
    state.pending_client_segments = VecDeque::from([
        BufferedClientSegment {
            sequence_number: 120,
            flags: TCP_FLAG_ACK,
            payload: b"efgh".to_vec().into(),
        },
        BufferedClientSegment {
            sequence_number: 112,
            flags: TCP_FLAG_ACK,
            payload: b"abcd".to_vec().into(),
        },
    ]);
    let packet =
        super::build_flow_ack_packet(&state, state.server_seq, state.rcv_nxt, TCP_FLAG_ACK)
            .unwrap();
    let parsed = super::parse_tcp_packet_unverified(&packet).unwrap();
    assert_eq!(parsed.sack_blocks, vec![(112, 116), (120, 124)]);
}

#[tokio::test]
async fn build_flow_ack_packet_limits_sack_blocks_when_timestamps_are_enabled() {
    let mut state = tcp_flow_state_for_tests().await;
    state.client_sack_permitted = true;
    state.timestamps_enabled = true;
    state.recent_client_timestamp = Some(55);
    state.pending_client_segments = VecDeque::from([
        BufferedClientSegment {
            sequence_number: 112,
            flags: TCP_FLAG_ACK,
            payload: b"aaaa".to_vec().into(),
        },
        BufferedClientSegment {
            sequence_number: 120,
            flags: TCP_FLAG_ACK,
            payload: b"bbbb".to_vec().into(),
        },
        BufferedClientSegment {
            sequence_number: 128,
            flags: TCP_FLAG_ACK,
            payload: b"cccc".to_vec().into(),
        },
        BufferedClientSegment {
            sequence_number: 136,
            flags: TCP_FLAG_ACK,
            payload: b"dddd".to_vec().into(),
        },
    ]);

    let packet =
        super::build_flow_ack_packet(&state, state.server_seq, state.rcv_nxt, TCP_FLAG_ACK)
            .unwrap();
    let parsed = super::parse_tcp_packet_unverified(&packet).unwrap();
    assert_eq!(parsed.sack_blocks, vec![(112, 116), (120, 124), (128, 132)]);
    assert_eq!(parsed.timestamp_echo_reply, Some(55));
}

#[tokio::test]
async fn retransmit_prefers_unsacked_hole_before_sacked_tail() {
    let mut state = tcp_flow_state_for_tests().await;
    state.rcv_nxt = 500;
    state.recovery_epoch = 1;
    state.sack_scoreboard = vec![SequenceRange { start: 1004, end: 1008 }];
    state.unacked_server_segments = VecDeque::from([
        super::ServerSegment {
            sequence_number: 1000,
            acknowledgement_number: 500,
            flags: TCP_FLAG_ACK | super::TCP_FLAG_PSH,
            payload: b"AAAA".to_vec().into(),
            last_sent: Instant::now() - Duration::from_secs(2),
            first_sent: Instant::now() - Duration::from_secs(2),
            retransmits: 0,
            rto_retransmits: 0,
            fast_retransmit_epoch: 0,
            delivered_snapshot: 0,
            delivered_at_snapshot: Instant::now(),
            first_tx_snapshot: Instant::now(),
            app_limited: false,
        },
        super::ServerSegment {
            sequence_number: 1004,
            acknowledgement_number: 500,
            flags: TCP_FLAG_ACK | super::TCP_FLAG_PSH,
            payload: b"BBBB".to_vec().into(),
            last_sent: Instant::now() - Duration::from_secs(2),
            first_sent: Instant::now() - Duration::from_secs(2),
            retransmits: 0,
            rto_retransmits: 0,
            fast_retransmit_epoch: 0,
            delivered_snapshot: 0,
            delivered_at_snapshot: Instant::now(),
            first_tx_snapshot: Instant::now(),
            app_limited: false,
        },
        super::ServerSegment {
            sequence_number: 1008,
            acknowledgement_number: 500,
            flags: TCP_FLAG_ACK | super::TCP_FLAG_PSH,
            payload: b"CCCC".to_vec().into(),
            last_sent: Instant::now() - Duration::from_secs(2),
            first_sent: Instant::now() - Duration::from_secs(2),
            retransmits: 0,
            rto_retransmits: 0,
            fast_retransmit_epoch: 0,
            delivered_snapshot: 0,
            delivered_at_snapshot: Instant::now(),
            first_tx_snapshot: Instant::now(),
            app_limited: false,
        },
    ]);

    let sdp = super::retransmit_oldest_unacked_packet(&mut state).unwrap().unwrap();
    let mut packet = sdp.header.clone();
    for chunk in &sdp.payload {
        packet.extend_from_slice(chunk);
    }
    let parsed = super::parse_tcp_packet_unverified(&packet).unwrap();
    assert_eq!(parsed.sequence_number, 1000);
    assert_eq!(parsed.payload, b"AAAA"[..]);
}

#[tokio::test]
async fn ack_progress_updates_rtt_estimate() {
    let mut state = tcp_flow_state_for_tests().await;

    // The Reno window growth is gone (BBRv2 in-flight ceilings govern); an ACK
    // still folds an RTT sample into the estimator and the RTO derived from it.
    super::note_ack_progress(&mut state, 600, Some(Duration::from_millis(120)), true, None);
    assert_eq!(state.smoothed_rtt, Some(Duration::from_millis(120)));
    assert!(state.retransmission_timeout >= Duration::from_millis(200));
}

#[tokio::test]
async fn timeout_congestion_event_backs_off_the_rto() {
    let mut state = tcp_flow_state_for_tests().await;
    state.retransmission_timeout = Duration::from_millis(800);
    state.unacked_server_segments = VecDeque::from([super::ServerSegment {
        sequence_number: 1000,
        acknowledgement_number: 500,
        flags: TCP_FLAG_ACK | super::TCP_FLAG_PSH,
        payload: b"AAAA".to_vec().into(),
        last_sent: Instant::now() - Duration::from_secs(2),
        first_sent: Instant::now() - Duration::from_secs(2),
        retransmits: 0,
        rto_retransmits: 0,
        fast_retransmit_epoch: 0,
        delivered_snapshot: 0,
        delivered_at_snapshot: Instant::now(),
        first_tx_snapshot: Instant::now(),
        app_limited: false,
    }]);
    super::rebuild_unacked_accounting(&mut state);

    super::note_congestion_event(&mut state, true);
    // An RTO doubles the retransmission timeout (capped at TCP_MAX_RTO_BACKOFF).
    // The window is no longer touched here — the BBRv2 in-flight ceilings and the
    // measured loss rate govern how much may be in flight.
    assert_eq!(state.retransmission_timeout, Duration::from_millis(1600));
}

#[tokio::test]
async fn reassembly_limits_trigger_for_segment_and_byte_pressure() {
    let mut state = tcp_flow_state_for_tests().await;
    state.pending_client_segments = VecDeque::from([
        super::BufferedClientSegment {
            sequence_number: 150,
            flags: TCP_FLAG_ACK,
            payload: vec![1; 32].into(),
        },
        super::BufferedClientSegment {
            sequence_number: 182,
            flags: TCP_FLAG_ACK,
            payload: vec![2; 32].into(),
        },
    ]);
    let config = TunTcpConfig {
        max_buffered_client_segments: 1,
        max_buffered_client_bytes: 48,
        ..test_tun_tcp_config()
    };
    assert!(super::exceeds_client_reassembly_limits(&state, &config));
}

#[tokio::test]
async fn queue_future_segment_rejects_oversized_without_inserting() {
    // Pre-check semantics: a segment that would push the reassembly queue
    // past its byte cap must be rejected before mutation, not after. This
    // closes the DoS vector where a single oversized out-of-order segment
    // transiently spikes memory above the configured limit.
    let mut state = tcp_flow_state_for_tests().await;
    state.pending_client_segments = VecDeque::from([super::BufferedClientSegment {
        sequence_number: 150,
        flags: TCP_FLAG_ACK,
        payload: vec![1; 32].into(),
    }]);
    let existing_snapshot: Vec<_> = state.pending_client_segments.iter().cloned().collect();
    let config = TunTcpConfig {
        max_buffered_client_segments: 16,
        max_buffered_client_bytes: 48,
        ..test_tun_tcp_config()
    };
    // Oversized future segment (64 bytes) well within the receive window
    // but with only 16 bytes of headroom left (48 cap - 32 already queued).
    let packet = ParsedTcpPacket {
        version: super::IpVersion::V4,
        source_ip: "10.0.0.2".parse().unwrap(),
        destination_ip: "8.8.8.8".parse().unwrap(),
        source_port: 40000,
        destination_port: 443,
        sequence_number: 200,
        acknowledgement_number: 1000,
        window_size: 4096,
        max_segment_size: None,
        window_scale: None,
        sack_permitted: false,
        sack_blocks: Vec::new(),
        timestamp_value: None,
        timestamp_echo_reply: None,
        flags: TCP_FLAG_ACK,
        payload: Bytes::from(vec![9u8; 64]),
    };
    let outcome = super::queue_future_segment_with_recv_window(&mut state, &config, &packet);
    assert_eq!(outcome, super::QueueFutureSegmentOutcome::WouldExceedLimits);
    // The queue must be unchanged — no partial insertion before the check.
    assert_eq!(state.pending_client_segments.len(), existing_snapshot.len());
    for (actual, expected) in state.pending_client_segments.iter().zip(existing_snapshot.iter()) {
        assert_eq!(actual.sequence_number, expected.sequence_number);
        assert_eq!(actual.flags, expected.flags);
        assert_eq!(actual.payload, expected.payload);
    }
}

#[tokio::test]
async fn queue_future_segment_accepts_within_limits() {
    let mut state = tcp_flow_state_for_tests().await;
    let config = TunTcpConfig {
        max_buffered_client_segments: 16,
        max_buffered_client_bytes: 1024,
        ..test_tun_tcp_config()
    };
    let packet = ParsedTcpPacket {
        version: super::IpVersion::V4,
        source_ip: "10.0.0.2".parse().unwrap(),
        destination_ip: "8.8.8.8".parse().unwrap(),
        source_port: 40000,
        destination_port: 443,
        sequence_number: 200,
        acknowledgement_number: 1000,
        window_size: 4096,
        max_segment_size: None,
        window_scale: None,
        sack_permitted: false,
        sack_blocks: Vec::new(),
        timestamp_value: None,
        timestamp_echo_reply: None,
        flags: TCP_FLAG_ACK,
        payload: Bytes::from(vec![9u8; 64]),
    };
    let outcome = super::queue_future_segment_with_recv_window(&mut state, &config, &packet);
    assert_eq!(outcome, super::QueueFutureSegmentOutcome::Queued);
    assert_eq!(state.pending_client_segments.len(), 1);
    assert_eq!(state.pending_client_segments[0].payload.len(), 64);
}

#[tokio::test]
async fn server_backlog_limit_detects_pending_bytes() {
    let mut state = tcp_flow_state_for_tests().await;
    state.pending_server_data = VecDeque::from([vec![1; 128].into(), vec![2; 128].into()]);
    state.pending_server_bytes_total = state.pending_server_data.iter().map(|c| c.len()).sum();
    let config = TunTcpConfig {
        max_pending_server_bytes: 200,
        ..test_tun_tcp_config()
    };
    let pressure =
        super::assess_server_backlog_pressure(&mut state, &config, Instant::now(), false);
    assert!(pressure.exceeded);
}

#[tokio::test]
async fn server_backlog_pressure_allows_brief_window_stall() {
    let mut state = tcp_flow_state_for_tests().await;
    state.client_window = 0;
    state.client_window_end = state.server_seq;
    state.pending_server_data = VecDeque::from([vec![1; 256].into()]);
    state.pending_server_bytes_total = state.pending_server_data.iter().map(|c| c.len()).sum();
    let config = TunTcpConfig {
        max_pending_server_bytes: 200,
        ..test_tun_tcp_config()
    };

    let pressure = super::assess_server_backlog_pressure(&mut state, &config, Instant::now(), true);

    assert!(pressure.exceeded);
    assert!(!pressure.should_abort);
    assert!(state.backlog_limit_exceeded_since.is_some());
}

#[tokio::test]
async fn server_backlog_pressure_does_not_abort_throttled_flow_over_grace() {
    // A merely slow flow — over the soft limit for longer than the (now
    // informational) grace, but with the client window open and ACK progress
    // fresh — must NOT be aborted. Downlink backpressure parks the reader on
    // exactly this flow for the whole transfer; the dropped grace arm used to
    // reap such a healthy large download after a few seconds.
    let mut state = tcp_flow_state_for_tests().await;
    state.pending_server_data = VecDeque::from([vec![1; 256].into()]);
    state.pending_server_bytes_total = state.pending_server_data.iter().map(|c| c.len()).sum();
    let config = TunTcpConfig {
        max_pending_server_bytes: 200,
        ..test_tun_tcp_config()
    };
    state.backlog_limit_exceeded_since = Some(Instant::now() - config.backlog_abort_grace);

    let pressure =
        super::assess_server_backlog_pressure(&mut state, &config, Instant::now(), false);

    assert!(pressure.exceeded);
    assert!(!pressure.should_abort);
}

#[tokio::test]
async fn server_backlog_pressure_does_not_abort_stalled_flow_with_fresh_ack() {
    // Window shut but the client is still making ACK progress (no_progress has
    // not reached backlog_no_progress_abort): a brief stall, not a dead flow,
    // so grace alone must not abort it — only a sustained no-progress stall does.
    let mut state = tcp_flow_state_for_tests().await;
    state.client_window = 0;
    state.client_window_end = state.server_seq;
    state.pending_server_data = VecDeque::from([vec![1; 256].into()]);
    state.pending_server_bytes_total = state.pending_server_data.iter().map(|c| c.len()).sum();
    let config = TunTcpConfig {
        max_pending_server_bytes: 200,
        ..test_tun_tcp_config()
    };
    state.backlog_limit_exceeded_since = Some(Instant::now() - config.backlog_abort_grace);

    let pressure = super::assess_server_backlog_pressure(&mut state, &config, Instant::now(), true);

    assert!(pressure.exceeded);
    assert!(!pressure.should_abort);
}

#[tokio::test]
async fn server_backlog_pressure_aborts_after_no_ack_progress_timeout() {
    let mut state = tcp_flow_state_for_tests().await;
    state.client_window = 0;
    state.client_window_end = state.server_seq;
    state.pending_server_data = VecDeque::from([vec![1; 256].into()]);
    state.pending_server_bytes_total = state.pending_server_data.iter().map(|c| c.len()).sum();
    let config = TunTcpConfig {
        max_pending_server_bytes: 200,
        backlog_abort_grace: Duration::from_secs(60),
        backlog_no_progress_abort: Duration::from_secs(2),
        ..test_tun_tcp_config()
    };
    state.last_ack_progress_at = Instant::now() - config.backlog_no_progress_abort;

    let pressure = super::assess_server_backlog_pressure(&mut state, &config, Instant::now(), true);

    assert!(pressure.exceeded);
    assert!(pressure.should_abort);
    assert!(
        pressure.no_progress_ms.unwrap_or_default() >= config.backlog_no_progress_abort.as_millis()
    );
}

#[tokio::test]
async fn server_backlog_pressure_aborts_immediately_above_hard_limit() {
    let mut state = tcp_flow_state_for_tests().await;
    state.pending_server_data = VecDeque::from([vec![1; 512].into()]);
    state.pending_server_bytes_total = state.pending_server_data.iter().map(|c| c.len()).sum();
    let config = TunTcpConfig {
        max_pending_server_bytes: 200,
        ..test_tun_tcp_config()
    };

    let pressure =
        super::assess_server_backlog_pressure(&mut state, &config, Instant::now(), false);

    assert!(pressure.exceeded);
    assert!(pressure.should_abort);
}
// --- ISN wraparound: sequence-space arithmetic near u32::MAX ---
//
// TCP sequence numbers are a u32 that wraps; comparisons must use modular
// arithmetic (RFC 1323, "Protection Against Wrapped Sequences"). These
// tests pin the invariants at the wrap point that normal-range tests
// never exercise.

#[test]
fn seq_comparisons_handle_u32_wraparound() {
    use crate::tcp::state_machine::{seq_ge, seq_gt, seq_lt};
    assert!(seq_lt(u32::MAX, 0));
    assert!(seq_gt(0, u32::MAX));
    assert!(seq_ge(0, u32::MAX));
    assert!(!seq_lt(0, u32::MAX));
    assert!(seq_lt(u32::MAX - 10, 5));
    assert!(seq_gt(5, u32::MAX - 10));
    assert!(!seq_lt(42, 42));
    assert!(!seq_gt(42, 42));
    assert!(seq_ge(42, 42));
}

#[test]
fn packet_sequence_len_counts_syn_and_fin_near_wrap() {
    use crate::tcp::state_machine::packet_sequence_len;
    let mut packet = ParsedTcpPacket {
        version: super::IpVersion::V4,
        source_ip: "10.0.0.1".parse().unwrap(),
        destination_ip: "8.8.8.8".parse().unwrap(),
        source_port: 1,
        destination_port: 2,
        sequence_number: u32::MAX,
        acknowledgement_number: 0,
        window_size: 0,
        max_segment_size: None,
        window_scale: None,
        sack_permitted: false,
        sack_blocks: Vec::new(),
        timestamp_value: None,
        timestamp_echo_reply: None,
        flags: TCP_FLAG_SYN,
        payload: Bytes::new(),
    };
    assert_eq!(packet_sequence_len(&packet), 1);
    packet.flags = TCP_FLAG_ACK | TCP_FLAG_FIN;
    packet.payload = Bytes::from_static(b"abc");
    assert_eq!(packet_sequence_len(&packet), 4);
}

#[test]
fn normalize_client_segment_trims_prefix_across_isn_wraparound() {
    // 6-byte payload starting at u32::MAX - 2 covers seqs
    // [MAX-2, MAX-1, MAX, 0, 1, 2]. expected_seq = 1 -> drop first 4 bytes.
    let start = u32::MAX.wrapping_sub(2);
    let packet = ParsedTcpPacket {
        version: super::IpVersion::V4,
        source_ip: "10.0.0.1".parse().unwrap(),
        destination_ip: "8.8.8.8".parse().unwrap(),
        source_port: 1,
        destination_port: 2,
        sequence_number: start,
        acknowledgement_number: 0,
        window_size: 0,
        max_segment_size: None,
        window_scale: None,
        sack_permitted: false,
        sack_blocks: Vec::new(),
        timestamp_value: None,
        timestamp_echo_reply: None,
        flags: TCP_FLAG_ACK,
        payload: Bytes::from_static(b"ABCDEF"),
    };
    let segment = normalize_client_segment(&packet, 1);
    assert_eq!(segment.payload.as_ref(), b"EF");
    assert!(!segment.fin);
}

#[test]
fn queue_future_segment_reassembles_across_isn_wraparound() {
    // Three 4-byte segments starting at u32::MAX - 3 wrap past zero.
    let start = u32::MAX.wrapping_sub(3);
    let mut expected_seq = start;
    let mut pending = VecDeque::new();

    let first = TrimmedSegment {
        sequence_number: start,
        flags: TCP_FLAG_ACK,
        payload: Bytes::from_static(b"ABCD"),
    };
    let second = TrimmedSegment {
        sequence_number: start.wrapping_add(4),
        flags: TCP_FLAG_ACK,
        payload: Bytes::from_static(b"EFGH"),
    };
    let third = TrimmedSegment {
        sequence_number: start.wrapping_add(8),
        flags: TCP_FLAG_ACK,
        payload: Bytes::from_static(b"IJKL"),
    };
    queue_future_segment(&mut pending, &third, expected_seq);
    queue_future_segment(&mut pending, &second, expected_seq);
    queue_future_segment(&mut pending, &first, expected_seq);

    let mut payload = Vec::new();
    let closed = drain_ready_buffered_segments(&mut expected_seq, &mut pending, &mut payload);
    assert!(!closed);
    assert_eq!(payload.concat(), b"ABCDEFGHIJKL");
    assert_eq!(expected_seq, start.wrapping_add(12));
    assert!(pending.is_empty());
}

#[test]
fn is_duplicate_syn_recognised_when_expected_seq_just_wrapped() {
    // Scenario: server ISN was u32::MAX, rcv_nxt wrapped to 0.
    // A retransmitted SYN with seq == u32::MAX must still be a dup.
    let packet = ParsedTcpPacket {
        version: super::IpVersion::V4,
        source_ip: "10.0.0.1".parse().unwrap(),
        destination_ip: "8.8.8.8".parse().unwrap(),
        source_port: 1,
        destination_port: 2,
        sequence_number: u32::MAX,
        acknowledgement_number: 0,
        window_size: 0,
        max_segment_size: None,
        window_scale: None,
        sack_permitted: false,
        sack_blocks: Vec::new(),
        timestamp_value: None,
        timestamp_echo_reply: None,
        flags: TCP_FLAG_SYN,
        payload: Bytes::new(),
    };
    assert!(super::is_duplicate_syn(&packet, 0));
}

#[tokio::test]
async fn process_server_ack_handles_snd_nxt_wrap() {
    // Server has two 4-byte segments that straddle the wrap point.
    // A cumulative ACK past u32::MAX must free both, not be treated
    // as a stale (backwards) ACK.
    let mut state = tcp_flow_state_for_tests().await;
    let base = u32::MAX.wrapping_sub(3);
    state.last_client_ack = base;
    state.server_seq = base.wrapping_add(8);
    state.client_window = 8192;
    state.client_window_end = state.server_seq.wrapping_add(8192);
    state.unacked_server_segments = VecDeque::from([
        super::ServerSegment {
            sequence_number: base,
            acknowledgement_number: 500,
            flags: TCP_FLAG_ACK | super::TCP_FLAG_PSH,
            payload: b"AAAA".to_vec().into(),
            last_sent: Instant::now(),
            first_sent: Instant::now(),
            retransmits: 0,
            rto_retransmits: 0,
            fast_retransmit_epoch: 0,
            delivered_snapshot: 0,
            delivered_at_snapshot: Instant::now(),
            first_tx_snapshot: Instant::now(),
            app_limited: false,
        },
        super::ServerSegment {
            sequence_number: base.wrapping_add(4),
            acknowledgement_number: 500,
            flags: TCP_FLAG_ACK | super::TCP_FLAG_PSH,
            payload: b"BBBB".to_vec().into(),
            last_sent: Instant::now(),
            first_sent: Instant::now(),
            retransmits: 0,
            rto_retransmits: 0,
            fast_retransmit_epoch: 0,
            delivered_snapshot: 0,
            delivered_at_snapshot: Instant::now(),
            first_tx_snapshot: Instant::now(),
            app_limited: false,
        },
    ]);
    super::rebuild_unacked_accounting(&mut state);

    let ack = base.wrapping_add(8);
    let effect = super::process_server_ack(&mut state, ack, &[]);
    assert_eq!(effect.bytes_acked, 8);
    assert!(state.unacked_server_segments.is_empty());
    assert_eq!(state.last_client_ack, ack);
}

#[tokio::test]
async fn process_server_ack_stale_ack_across_wrap_is_rejected() {
    // Inverse of the above: an ACK for an older value that wrapped past
    // the current cumulative must be treated as a stale duplicate, not
    // as progress. Here last_client_ack = 10 (just past wrap) and an
    // attacker-supplied ACK of u32::MAX - 5 (before the wrap) must not
    // free segments or advance last_client_ack.
    let mut state = tcp_flow_state_for_tests().await;
    state.last_client_ack = 10;
    state.server_seq = 20;
    state.unacked_server_segments = VecDeque::from([super::ServerSegment {
        sequence_number: 10,
        acknowledgement_number: 500,
        flags: TCP_FLAG_ACK | super::TCP_FLAG_PSH,
        payload: b"AAAA".to_vec().into(),
        last_sent: Instant::now(),
        first_sent: Instant::now(),
        retransmits: 0,
        rto_retransmits: 0,
        fast_retransmit_epoch: 0,
        delivered_snapshot: 0,
        delivered_at_snapshot: Instant::now(),
        first_tx_snapshot: Instant::now(),
        app_limited: false,
    }]);

    let stale = u32::MAX.wrapping_sub(5);
    let effect = super::process_server_ack(&mut state, stale, &[]);
    assert_eq!(effect.bytes_acked, 0);
    assert_eq!(state.unacked_server_segments.len(), 1);
    assert_eq!(state.last_client_ack, 10);
}

// --- PAWS (RFC 7323): timestamp-based stale-segment rejection ---
//
// The engine-level test covers the happy path end-to-end; these cases
// pin the per-branch decisions in the validator and the TS.Recent
// bookkeeping helper, including behavior across a 2^32 timestamp wrap.

fn paws_packet(
    sequence_number: u32,
    timestamp_value: Option<u32>,
    flags: u8,
    payload: &'static [u8],
) -> ParsedTcpPacket {
    ParsedTcpPacket {
        version: super::IpVersion::V4,
        source_ip: "10.0.0.2".parse().unwrap(),
        destination_ip: "8.8.8.8".parse().unwrap(),
        source_port: 40000,
        destination_port: 443,
        sequence_number,
        acknowledgement_number: 1000,
        window_size: 4096,
        max_segment_size: None,
        window_scale: None,
        sack_permitted: false,
        sack_blocks: Vec::new(),
        timestamp_value,
        timestamp_echo_reply: None,
        flags,
        payload: Bytes::from_static(payload),
    }
}

fn matches_challenge_ack(
    validation: crate::tcp::validation::PacketValidation,
    expected_reason: &'static str,
) -> bool {
    matches!(
        validation,
        crate::tcp::validation::PacketValidation::ChallengeAck(reason) if reason == expected_reason,
    )
}

#[test]
fn timestamp_lt_handles_wraparound() {
    use crate::tcp::state_machine::timestamp_lt;
    assert!(timestamp_lt(u32::MAX, 0));
    assert!(!timestamp_lt(0, u32::MAX));
    assert!(timestamp_lt(u32::MAX - 10, 5));
    assert!(!timestamp_lt(5, u32::MAX - 10));
    assert!(!timestamp_lt(42, 42));
}

#[tokio::test]
async fn validate_existing_packet_accepts_when_timestamps_disabled() {
    let mut state = tcp_flow_state_for_tests().await;
    state.timestamps_enabled = false;
    state.recent_client_timestamp = None;
    let packet = paws_packet(state.rcv_nxt, None, TCP_FLAG_ACK, b"abc");

    let validation = crate::tcp::validation::validate_existing_packet(&state, &packet);
    assert!(matches!(validation, crate::tcp::validation::PacketValidation::Accept));
}

#[tokio::test]
async fn validate_existing_packet_paws_rejects_stale_timestamp_within_window() {
    let mut state = tcp_flow_state_for_tests().await;
    state.timestamps_enabled = true;
    state.recent_client_timestamp = Some(100);
    let packet = paws_packet(state.rcv_nxt, Some(50), TCP_FLAG_ACK, b"abc");

    let validation = crate::tcp::validation::validate_existing_packet(&state, &packet);
    assert!(matches_challenge_ack(validation, "paws_reject"));
}

#[tokio::test]
async fn validate_existing_packet_paws_ignores_stale_timestamp_outside_window() {
    // A stale TS on a segment outside the receive window must be silently
    // dropped (PacketValidation::Ignore) rather than triggering a challenge
    // ACK; otherwise we give an off-path attacker a reflection primitive
    // for arbitrary sequence numbers.
    let mut state = tcp_flow_state_for_tests().await;
    state.timestamps_enabled = true;
    state.recent_client_timestamp = Some(100);
    // Place the segment far outside the receive window.
    let far_seq = state.rcv_nxt.wrapping_add(1 << 30);
    let packet = paws_packet(far_seq, Some(50), TCP_FLAG_ACK, b"abc");

    let validation = crate::tcp::validation::validate_existing_packet(&state, &packet);
    assert!(matches!(validation, crate::tcp::validation::PacketValidation::Ignore));
}

#[tokio::test]
async fn validate_existing_packet_challenges_missing_timestamp_within_window() {
    // Once timestamps are negotiated the peer must include TSopt on every
    // non-RST segment (RFC 7323 §3.2). A missing TS inside the window is
    // either a protocol violation or a forged segment; answer with a
    // challenge ACK rather than silently accepting.
    let mut state = tcp_flow_state_for_tests().await;
    state.timestamps_enabled = true;
    state.recent_client_timestamp = Some(100);
    let packet = paws_packet(state.rcv_nxt, None, TCP_FLAG_ACK, b"abc");

    let validation = crate::tcp::validation::validate_existing_packet(&state, &packet);
    assert!(matches_challenge_ack(validation, "missing_timestamp"));
}

#[tokio::test]
async fn validate_existing_packet_accepts_equal_or_newer_timestamp() {
    // PAWS uses strict-less-than: TSval == TS.Recent must still be accepted
    // (RFC 7323 §5.3) — retransmitted segments legitimately carry the same
    // TSval as the previously accepted one.
    let mut state = tcp_flow_state_for_tests().await;
    state.timestamps_enabled = true;
    state.recent_client_timestamp = Some(100);

    let equal = paws_packet(state.rcv_nxt, Some(100), TCP_FLAG_ACK, b"abc");
    let newer = paws_packet(state.rcv_nxt, Some(101), TCP_FLAG_ACK, b"abc");

    assert!(matches!(
        crate::tcp::validation::validate_existing_packet(&state, &equal),
        crate::tcp::validation::PacketValidation::Accept,
    ));
    assert!(matches!(
        crate::tcp::validation::validate_existing_packet(&state, &newer),
        crate::tcp::validation::PacketValidation::Accept,
    ));
}

#[tokio::test]
async fn validate_existing_packet_paws_accepts_timestamp_across_wrap() {
    // TSval wraps modulo 2^32 just like sequence numbers. When TS.Recent
    // is near u32::MAX, a TSval that wrapped past zero is "newer" and
    // must be accepted.
    let mut state = tcp_flow_state_for_tests().await;
    state.timestamps_enabled = true;
    state.recent_client_timestamp = Some(u32::MAX - 10);
    let newer_wrapped = paws_packet(state.rcv_nxt, Some(5), TCP_FLAG_ACK, b"abc");

    let validation = crate::tcp::validation::validate_existing_packet(&state, &newer_wrapped);
    assert!(matches!(validation, crate::tcp::validation::PacketValidation::Accept));
}

#[tokio::test]
async fn validate_existing_packet_rst_bypasses_paws_check() {
    // RST handling runs before PAWS; a valid RST with a stale (or missing)
    // timestamp must close the flow, not trigger a PAWS challenge.
    let mut state = tcp_flow_state_for_tests().await;
    state.timestamps_enabled = true;
    state.recent_client_timestamp = Some(100);
    let packet = paws_packet(state.rcv_nxt, Some(1), TCP_FLAG_RST, b"");

    let validation = crate::tcp::validation::validate_existing_packet(&state, &packet);
    assert!(matches!(
        validation,
        crate::tcp::validation::PacketValidation::CloseFlow("client_rst"),
    ));
}

#[tokio::test]
async fn note_recent_client_timestamp_is_noop_when_feature_disabled() {
    let mut state = tcp_flow_state_for_tests().await;
    state.timestamps_enabled = false;
    state.recent_client_timestamp = None;

    super::state_machine::note_recent_client_timestamp(&mut state, Some(42));
    assert_eq!(state.recent_client_timestamp, None);
}

#[tokio::test]
async fn note_recent_client_timestamp_records_when_enabled() {
    let mut state = tcp_flow_state_for_tests().await;
    state.timestamps_enabled = true;
    state.recent_client_timestamp = Some(50);

    super::state_machine::note_recent_client_timestamp(&mut state, Some(100));
    assert_eq!(state.recent_client_timestamp, Some(100));

    // None must leave the existing value untouched.
    super::state_machine::note_recent_client_timestamp(&mut state, None);
    assert_eq!(state.recent_client_timestamp, Some(100));
}

// --- Maintenance rescheduling ----------------------------------------------
//
// `reschedule_flow` pushes a scheduler entry only when the deadline moves
// *earlier*; a later deadline (the common case — committing new data pushes the
// RTO out) rides on the entry that is already on the heap, and does not even
// wake the maintenance loop, whose sleep target is the unchanged heap minimum.
// The whole construction rests on one invariant: a live flow whose canonical
// deadline is `Some(d)` always has a heap entry at or before `d`, which the
// loop's `scheduled_at <= d` filter turns into a re-plan that re-arms the flow.
// Losing that is what `2ec72b5` fixed (the flow fell off the scheduler and its
// RTO retransmit never fired); `tun_tcp_retransmits_after_partial_ack_moves_
// deadline_later` guards the end-to-end symptom, this one guards the invariant.

#[tokio::test]
async fn later_deadline_keeps_the_flow_covered_by_the_existing_heap_entry() {
    let mut state = tcp_flow_state_for_tests().await;
    let tcp = test_tun_tcp_config();
    let scheduler = Arc::clone(&state.signals.scheduler);

    super::maintenance::commit_flow_changes(&mut state, &tcp);
    let first = state
        .next_scheduled_deadline
        .expect("a live flow always has a deadline");
    let entries = scheduler.entries_for_tests();
    assert_eq!(entries.len(), 1, "the first deadline is always pushed");
    assert_eq!(entries[0].0, first);
    assert_eq!(entries[0].1, state.key);

    // Fresh traffic on the flow: `last_seen` advances, so the idle deadline —
    // and with it the flow's canonical deadline — recedes.
    state.timestamps.last_seen = Instant::now() + Duration::from_secs(5);
    super::maintenance::commit_flow_changes(&mut state, &tcp);
    let later = state.next_scheduled_deadline.expect("still live");
    assert!(later > first, "the new deadline must be later than the pushed one");

    // Heap-growth guard: no entry is pushed for a later deadline...
    let entries = scheduler.entries_for_tests();
    assert_eq!(entries.len(), 1, "a later deadline must not grow the heap");
    // ...and none is needed. The entry already on the heap fires at or before the
    // canonical deadline, so the maintenance loop pops it, re-plans, and re-arms
    // the flow at its current deadline. The flow can never be lost.
    assert!(
        entries[0].0 <= later,
        "flow left uncovered: heap entry {:?} fires after its deadline {:?}",
        entries[0].0,
        later,
    );

    // An *earlier* deadline is the case that genuinely needs a new entry (nothing
    // on the heap would fire in time), and it gets one.
    state.delayed_ack_deadline = Some(Instant::now());
    super::maintenance::commit_flow_changes(&mut state, &tcp);
    let earlier = state.next_scheduled_deadline.expect("still live");
    assert!(earlier < later);
    let entries = scheduler.entries_for_tests();
    assert_eq!(entries.len(), 2, "an earlier deadline is pushed");
    assert!(entries.iter().any(|(deadline, _)| *deadline == earlier));
}

// --- Per-flow queue capacity ------------------------------------------------

#[tokio::test]
async fn reclaim_returns_idle_queue_capacity_without_touching_the_accounting() {
    let mut state = tcp_flow_state_for_tests().await;
    let burst = 1024usize;

    // A transfer's worth of queued data on every per-flow queue.
    for index in 0..burst {
        state.pending_server_data.push_back(Bytes::from_static(b"DATA"));
        state.pending_server_bytes_total += 4;
        state.pending_client_data.push_back(Bytes::from_static(b"DATA"));
        state.pending_client_segments.push_back(BufferedClientSegment {
            sequence_number: 5000 + index as u32 * 4,
            flags: TCP_FLAG_ACK,
            payload: Bytes::from_static(b"DATA"),
        });
        state
            .unacked_server_segments
            .push_back(unacked_segment(1000 + index as u32 * 4, b"DATA"));
    }
    super::rebuild_unacked_accounting(&mut state);
    assert_accounting_matches(&state, "queued burst");
    assert!(state.pending_server_data.capacity() >= burst);

    // The transfer completes: the queues drain, but `pop_front` / `clear` keep
    // the peak allocation, which is what an idle flow used to hold forever.
    state.pending_server_data.clear();
    state.pending_server_bytes_total = 0;
    state.pending_client_data.clear();
    state.pending_client_segments.clear();
    state.unacked_server_segments.clear();
    super::rebuild_unacked_accounting(&mut state);
    assert!(
        state.pending_server_data.capacity() >= burst,
        "a drained deque keeps its capacity — that is the leak being reclaimed",
    );

    super::state_machine::reclaim_flow_queue_capacity(&mut state);

    assert!(state.pending_server_data.capacity() < burst, "downlink queue not reclaimed");
    assert!(state.pending_client_data.capacity() < burst, "uplink queue not reclaimed");
    assert!(state.unacked_server_segments.capacity() < burst, "unacked queue not reclaimed");
    assert!(
        state.pending_client_segments.capacity() < burst,
        "reassembly queue not reclaimed"
    );

    // Capacity only: the running counters track contents and must be untouched.
    assert_eq!(state.pending_server_bytes_total, 0);
    assert_eq!((state.pipe_bytes, state.pipe_segments), (0, 0));
    assert_accounting_matches(&state, "capacity reclaim");
}

#[tokio::test]
async fn reclaim_leaves_a_still_loaded_queue_alone() {
    let mut state = tcp_flow_state_for_tests().await;

    // A flow that is quiet but still holds a full downlink backlog (a stalled
    // client, say) must not have its queue shrunk out from under the data.
    for _ in 0..1024 {
        state.pending_server_data.push_back(Bytes::from_static(b"DATA"));
        state.pending_server_bytes_total += 4;
    }
    let capacity = state.pending_server_data.capacity();

    super::state_machine::reclaim_flow_queue_capacity(&mut state);

    assert_eq!(state.pending_server_data.len(), 1024, "reclaim must not drop data");
    assert_eq!(state.pending_server_data.capacity(), capacity, "a loaded queue is left alone");
    assert_eq!(state.pending_server_bytes_total, 4096);
}

#[tokio::test]
async fn receive_window_grows_with_drained_bytes_and_saturates_at_the_cap() {
    let mut state = tcp_flow_state_for_tests().await;
    state.receive_window_capacity = 16_384;

    state.grow_receive_window(4_096, 32_768);
    assert_eq!(state.receive_window_capacity, 20_480, "growth must track drained bytes");

    state.grow_receive_window(1 << 20, 32_768);
    assert_eq!(state.receive_window_capacity, 32_768, "growth must clamp at the cap");

    state.grow_receive_window(4_096, 32_768);
    assert_eq!(
        state.receive_window_capacity, 32_768,
        "a full window must not grow past the cap"
    );

    // A cap lowered below the current capacity (not reachable via config, but
    // the invariant matters: TCP forbids shrinking an advertised window).
    state.grow_receive_window(4_096, 16_384);
    assert_eq!(state.receive_window_capacity, 32_768, "the window must never shrink");
}

#[test]
fn initial_receive_window_clamps_to_the_buffer_cap() {
    let config = TunTcpConfig {
        initial_receive_window_bytes: 65_536,
        max_buffered_client_bytes: 2_097_152,
        ..test_tun_tcp_config()
    };
    assert_eq!(config.initial_receive_window(), 65_536);

    let disabled = TunTcpConfig {
        initial_receive_window_bytes: 0,
        ..config.clone()
    };
    assert_eq!(
        disabled.initial_receive_window(),
        2_097_152,
        "0 must disable auto-tuning: flows start at the full window"
    );

    let oversized = TunTcpConfig {
        initial_receive_window_bytes: 8 << 20,
        ..config
    };
    assert_eq!(
        oversized.initial_receive_window(),
        2_097_152,
        "an initial window above the cap must clamp to it"
    );
}

#[tokio::test]
async fn pending_budget_charge_discharge_and_drop_settle_the_global_counter() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    let mut state = tcp_flow_state_for_tests().await;
    let global = std::sync::Arc::new(AtomicUsize::new(0));
    state.pending_budget_global = Some(std::sync::Arc::clone(&global));

    state.charge_pending_server(1500);
    state.charge_pending_server(500);
    assert_eq!(state.pending_server_bytes_total, 2000);
    assert_eq!(
        global.load(Ordering::SeqCst),
        2000,
        "charges must mirror into the shared counter"
    );

    state.discharge_pending_server(700);
    assert_eq!(state.pending_server_bytes_total, 1300);
    assert_eq!(global.load(Ordering::SeqCst), 1300);

    // Whatever is still charged when the flow dies must come back with it.
    drop(state);
    assert_eq!(global.load(Ordering::SeqCst), 0, "drop must return the flow's remaining charge");
}

pub(super) fn test_tun_tcp_config() -> TunTcpConfig {
    TunTcpConfig {
        connect_timeout: Duration::from_secs(5),
        handshake_timeout: Duration::from_secs(5),
        half_close_timeout: Duration::from_secs(15),
        max_pending_server_bytes: 1_048_576,
        pending_server_budget_bytes: 0,
        // Legacy full-window start: the state-machine tests below drive uplink
        // scenarios without a pump to grow the window, so auto-tuning is
        // exercised by its own dedicated tests instead.
        initial_receive_window_bytes: 0,
        backlog_abort_grace: Duration::from_secs(3),
        backlog_hard_limit_multiplier: 2,
        backlog_no_progress_abort: Duration::from_secs(8),
        max_buffered_client_segments: 4096,
        max_buffered_client_bytes: 262_144,
        max_retransmits: 12,
        downlink_max_rate_bps: 0,
        keepalive_idle: None,
        keepalive_interval: Duration::from_secs(30),
        keepalive_max_probes: 6,
        sniffing: true,
        sniff_timeout: Duration::from_millis(300),
        sniff_override_exclude: Vec::new().into(),
        sniff_direct_reresolve: false,
        route_by_sni: false,
        carrier_migration: true,
    }
}
// --- L4-checksum provenance (skipping the redundant validation pass) --------
//
// Under IFF_VNET_HDR the kernel hands us packets with an un-finalised L4
// checksum (`F_NEEDS_CSUM`); the read loop folds the segment itself to produce
// the real checksum. Validating that checksum afterwards walks the whole
// payload a second time only to confirm our own arithmetic, so the parser skips
// it — but only for a checksum the read loop actually produced.

/// The kernel's CHECKSUM_PARTIAL hand-off: the L4 checksum field does not hold
/// a valid checksum yet. Modelled by blanking it, as `recompute_*` expects.
fn offload_checksum_field(packet: &mut [u8], l4_offset: usize) {
    packet[l4_offset + 16..l4_offset + 18].fill(0);
}

fn payload_of_len(len: usize) -> Vec<u8> {
    (0..len).map(|index| (index % 251) as u8).collect()
}

/// Skipping validation must not change *anything* the parser produces: for every
/// payload size — empty (pure ACK), 1 byte, the MSS boundary either side, and a
/// GRO-sized super-segment — and with TCP options present (they move the payload
/// offset), the recomputed parse equals the validated parse field for field.
#[test]
fn recomputed_parse_matches_validated_parse_ipv4() {
    let option_sets: [&[u8]; 2] = [&[], &[2, 4, 0x05, 0xb4, 8, 10, 0, 0, 0, 9, 0, 0, 0, 7, 1, 1]];
    for payload_len in [0usize, 1, 536, 1447, 1448, 1449, 16_384] {
        for options in option_sets {
            let payload = payload_of_len(payload_len);
            let packet = build_client_packet_with_options(
                Ipv4Addr::new(10, 0, 0, 2),
                Ipv4Addr::new(8, 8, 8, 8),
                40004,
                443,
                10,
                100,
                2048,
                TCP_FLAG_ACK,
                options,
                &payload,
            );
            let validated = super::parse_tcp_packet_unverified(&packet).unwrap();

            let mut offloaded = packet.clone();
            offload_checksum_field(&mut offloaded, IPV4_HEADER_LEN);
            assert_eq!(
                crate::wire::recompute_transport_checksum(&mut offloaded),
                crate::wire::L4Checksum::Recomputed
            );
            let recomputed =
                super::wire::parse_tcp_packet(&offloaded, crate::wire::L4Checksum::Recomputed)
                    .unwrap();

            assert_eq!(recomputed, validated, "payload_len={payload_len} options={options:?}");
            assert_eq!(recomputed.payload.len(), payload_len);
            assert_eq!(&recomputed.payload[..], &payload[..], "payload must arrive intact");
        }
    }
}

#[test]
fn recomputed_parse_matches_validated_parse_ipv6() {
    for payload_len in [0usize, 1, 1448, 16_384] {
        let payload = payload_of_len(payload_len);
        let packet = build_client_ipv6_packet_with_options(
            Ipv6Addr::LOCALHOST,
            Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2),
            40004,
            443,
            10,
            100,
            2048,
            TCP_FLAG_ACK,
            &[],
            &payload,
        );
        let validated = super::parse_tcp_packet_unverified(&packet).unwrap();

        let mut offloaded = packet.clone();
        offload_checksum_field(&mut offloaded, IPV6_HEADER_LEN);
        assert_eq!(
            crate::wire::recompute_transport_checksum(&mut offloaded),
            crate::wire::L4Checksum::Recomputed
        );
        let recomputed =
            super::wire::parse_tcp_packet(&offloaded, crate::wire::L4Checksum::Recomputed).unwrap();

        assert_eq!(recomputed, validated, "payload_len={payload_len}");
        assert_eq!(&recomputed.payload[..], &payload[..]);
    }
}

/// The skip is an optimisation, not a relaxation: a packet is only ever parsed
/// with validation skipped *after* the read loop repaired its checksum, and the
/// repaired packet still passes the full validation it no longer runs.
#[test]
fn recompute_repairs_the_offloaded_checksum_the_parser_then_trusts() {
    let payload = payload_of_len(1448);
    let packet = build_client_packet(
        Ipv4Addr::new(10, 0, 0, 2),
        Ipv4Addr::new(8, 8, 8, 8),
        40004,
        443,
        10,
        100,
        2048,
        TCP_FLAG_ACK,
        &payload,
    );

    // As the kernel delivers it: the checksum field is not valid yet, so the
    // plain (no-vnet) path would reject the packet outright.
    let mut offloaded = packet.clone();
    offload_checksum_field(&mut offloaded, IPV4_HEADER_LEN);
    let error = super::parse_tcp_packet_unverified(&offloaded).unwrap_err();
    assert!(error.to_string().contains("invalid TCP checksum"));

    // The read loop's recompute is what makes it valid …
    assert_eq!(
        crate::wire::recompute_transport_checksum(&mut offloaded),
        crate::wire::L4Checksum::Recomputed
    );
    let parsed =
        super::wire::parse_tcp_packet(&offloaded, crate::wire::L4Checksum::Recomputed).unwrap();
    assert_eq!(&parsed.payload[..], &payload[..]);

    // … and the repaired packet also passes the validation the parser skipped,
    // producing the identical result. Skipping it costs no correctness.
    assert_eq!(super::parse_tcp_packet_unverified(&offloaded).unwrap(), parsed);
}

/// A corrupt checksum is still rejected on every path where the read loop did
/// not produce it — the guard against the skip being applied too widely.
#[test]
fn corrupt_checksum_is_still_rejected_without_recompute() {
    let mut packet = build_client_packet(
        Ipv4Addr::new(10, 0, 0, 2),
        Ipv4Addr::new(8, 8, 8, 8),
        40004,
        443,
        10,
        100,
        2048,
        TCP_FLAG_ACK,
        b"payload",
    );
    packet[IPV4_HEADER_LEN + 16] ^= 0x01;

    let error = super::parse_tcp_packet_unverified(&packet).unwrap_err();
    assert!(error.to_string().contains("invalid TCP checksum"));
}

#[allow(clippy::too_many_arguments)]
pub(super) fn build_client_packet(
    client_ip: Ipv4Addr,
    remote_ip: Ipv4Addr,
    client_port: u16,
    remote_port: u16,
    sequence_number: u32,
    acknowledgement_number: u32,
    window_size: u16,
    flags: u8,
    payload: &[u8],
) -> Vec<u8> {
    build_client_packet_with_options(
        client_ip,
        remote_ip,
        client_port,
        remote_port,
        sequence_number,
        acknowledgement_number,
        window_size,
        flags,
        &[],
        payload,
    )
}

#[allow(clippy::too_many_arguments)]
pub(super) fn build_client_packet_with_options(
    client_ip: Ipv4Addr,
    remote_ip: Ipv4Addr,
    client_port: u16,
    remote_port: u16,
    sequence_number: u32,
    acknowledgement_number: u32,
    window_size: u16,
    flags: u8,
    options: &[u8],
    payload: &[u8],
) -> Vec<u8> {
    super::build_response_packet_custom(
        super::IpVersion::V4,
        client_ip.into(),
        remote_ip.into(),
        client_port,
        remote_port,
        sequence_number,
        acknowledgement_number,
        flags,
        window_size,
        options,
        payload,
    )
    .unwrap()
}

#[allow(clippy::too_many_arguments)]
fn build_client_ipv6_packet_with_options(
    client_ip: Ipv6Addr,
    remote_ip: Ipv6Addr,
    client_port: u16,
    remote_port: u16,
    sequence_number: u32,
    acknowledgement_number: u32,
    window_size: u16,
    flags: u8,
    options: &[u8],
    payload: &[u8],
) -> Vec<u8> {
    super::build_response_packet_custom(
        super::IpVersion::V6,
        client_ip.into(),
        remote_ip.into(),
        client_port,
        remote_port,
        sequence_number,
        acknowledgement_number,
        flags,
        window_size,
        options,
        payload,
    )
    .unwrap()
}

fn tcp_option_pad(mut options: Vec<u8>) -> Vec<u8> {
    while !options.len().is_multiple_of(4) {
        options.push(1);
    }
    options
}

#[allow(clippy::too_many_arguments)]
fn build_client_ipv6_packet_with_extension_headers(
    client_ip: Ipv6Addr,
    remote_ip: Ipv6Addr,
    client_port: u16,
    remote_port: u16,
    sequence_number: u32,
    acknowledgement_number: u32,
    window_size: u16,
    flags: u8,
    extension_headers: &[Vec<u8>],
    options: &[u8],
    payload: &[u8],
) -> Vec<u8> {
    let tcp_packet = build_client_ipv6_packet_with_options(
        client_ip,
        remote_ip,
        client_port,
        remote_port,
        sequence_number,
        acknowledgement_number,
        window_size,
        flags,
        options,
        payload,
    );

    let tcp_segment = &tcp_packet[IPV6_HEADER_LEN..];
    let extension_len: usize = extension_headers.iter().map(Vec::len).sum();
    let total_len = IPV6_HEADER_LEN + extension_len + tcp_segment.len();
    let mut packet = vec![0u8; total_len];
    packet[0] = 0x60;
    packet[4..6].copy_from_slice(&((extension_len + tcp_segment.len()) as u16).to_be_bytes());
    packet[6] = extension_headers
        .first()
        .and_then(|header| header.first().copied())
        .unwrap_or(super::wire::IPV6_NEXT_HEADER_TCP);
    packet[7] = 64;
    packet[8..24].copy_from_slice(&client_ip.octets());
    packet[24..40].copy_from_slice(&remote_ip.octets());

    let mut offset = IPV6_HEADER_LEN;
    for (index, header) in extension_headers.iter().enumerate() {
        let mut encoded = header.clone();
        let next = if index + 1 < extension_headers.len() {
            extension_headers[index + 1][0]
        } else {
            super::wire::IPV6_NEXT_HEADER_TCP
        };
        encoded[0] = next;
        packet[offset..offset + encoded.len()].copy_from_slice(&encoded);
        offset += encoded.len();
    }
    packet[offset..].copy_from_slice(tcp_segment);
    packet
}
pub(in crate::tcp) async fn tcp_flow_state_for_tests() -> super::TcpFlowState {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut ws = accept_async(stream).await.unwrap();
        while ws.next().await.is_some() {}
    });

    let (ws_stream, _) = connect_async(format!("ws://{addr}/")).await.unwrap();
    let ws = TransportStream::new_http1(ws_stream);
    let (sink, _stream) = ws.split();
    let cipher = CipherKind::Chacha20IetfPoly1305;
    let master_key = cipher.derive_master_key("Secret0").unwrap();
    let (close_signal, _close_rx) = tokio::sync::watch::channel(false);
    super::TcpFlowState {
        id: 1,
        gso_enabled: false,
        key: super::TcpFlowKey {
            version: super::IpVersion::V4,
            client_ip: "10.0.0.2".parse().unwrap(),
            client_port: 40000,
            remote_ip: "8.8.8.8".parse().unwrap(),
            remote_port: 443,
        },
        routing: super::state_machine::FlowRouting {
            uplink_index: 0,
            uplink_name: Arc::from("test"),
            group_name: Arc::from("test"),
            manager: super::engine::tests::build_test_manager("ws://127.0.0.1:1/".parse().unwrap())
                .await,
            route: crate::TunRoute::Group {
                name: "test".into(),
                manager: super::engine::tests::build_test_manager(
                    "ws://127.0.0.1:1/".parse().unwrap(),
                )
                .await,
            },
            target: socks5_proto::TargetAddr::IpV4("8.8.8.8".parse().unwrap(), 443),
            upstream_carrier: Some(Arc::new(Mutex::new(crate::tcp::UpstreamCarrier::new(
                crate::tcp::UpstreamWriter::TunneledWs({
                    let (writer, _ctrl_tx) = TcpShadowsocksWriter::connect(
                        sink,
                        cipher,
                        &master_key,
                        super::UpstreamTransportGuard::new("test", "tcp"),
                    )
                    .await
                    .unwrap();
                    writer
                }),
            )))),
        },
        resume: super::state_machine::FlowResume::armed(None),
        signals: super::state_machine::FlowControlSignals {
            close_signal,
            upstream_pump: Arc::new(tokio::sync::Notify::new()),
            carrier_migration: Arc::new(tokio::sync::Notify::new()),
            server_drain: Arc::new(tokio::sync::Notify::new()),
            scheduler: Arc::new(super::engine::scheduler::FlowScheduler::new()),
            idle_timeout: std::time::Duration::from_secs(60),
        },
        status: super::TcpFlowStatus::Established,
        rcv_nxt: 100,
        client_window_scale: 0,
        client_sack_permitted: false,
        client_max_segment_size: None,
        timestamps_enabled: false,
        recent_client_timestamp: None,
        server_timestamp_offset: 0,
        client_window: 4096,
        client_window_end: 5096,
        client_window_update_seq: 100,
        client_window_update_ack: 1000,
        server_seq: 1000,
        last_client_ack: 1000,
        duplicate_ack_count: 0,
        fast_recovery_end: None,
        recovery_epoch: 0,
        receive_window_capacity: 262_144,
        smoothed_rtt: None,
        rttvar: super::TCP_INITIAL_RTO / 2,
        retransmission_timeout: super::TCP_INITIAL_RTO,
        bbr: super::BbrState::new(Instant::now(), 0),
        pending_server_data: VecDeque::new(),
        pending_server_bytes_total: 0,
        pending_budget_global: None,
        backlog_limit_exceeded_since: None,
        last_ack_progress_at: Instant::now(),
        pending_client_data: VecDeque::new(),
        unacked_server_segments: VecDeque::new(),
        sack_scoreboard: Vec::new(),
        pipe_bytes: 0,
        pipe_segments: 0,
        first_tx_mstamp: Instant::now(),
        earliest_unsacked_sent: None,
        unacked_reordered: false,
        pending_client_segments: VecDeque::new(),
        server_fin_pending: false,
        zero_window_probe_backoff: super::TCP_ZERO_WINDOW_PROBE_BASE_INTERVAL,
        next_zero_window_probe_at: None,
        unacked_in_order_segments: 0,
        delayed_ack_deadline: None,
        keepalive_probes_sent: 0,
        last_keepalive_probe_at: None,
        reported: super::state_machine::ReportedFlowMetrics::default(),
        flow_gauges: None,
        timestamps: super::state_machine::FlowTimestamps {
            created_at: Instant::now(),
            status_since: Instant::now(),
            last_seen: Instant::now(),
        },
        eviction_indexed_at: Instant::now(),
        next_scheduled_deadline: None,
    }
}

/// Put `bytes` of real unacked segments in the pipe, keeping the running
/// accounting in step with the scan (the debug cross-check asserts on it).
fn fill_pipe_for_tests(state: &mut super::TcpFlowState, bytes: usize) {
    let mss = super::MAX_SERVER_SEGMENT_PAYLOAD;
    let now = Instant::now();
    let mut left = bytes;
    while left > 0 {
        let len = left.min(mss);
        state.unacked_server_segments.push_back(super::ServerSegment {
            sequence_number: state.server_seq,
            acknowledgement_number: 500,
            flags: TCP_FLAG_ACK,
            payload: vec![7u8; len].into(),
            last_sent: now,
            first_sent: now,
            retransmits: 0,
            rto_retransmits: 0,
            fast_retransmit_epoch: 0,
            delivered_snapshot: 0,
            delivered_at_snapshot: now,
            first_tx_snapshot: now,
            app_limited: false,
        });
        state.server_seq = state.server_seq.wrapping_add(len as u32);
        left -= len;
    }
    // Let the production rebuild derive pipe_bytes / segments / earliest-unsacked,
    // so the debug cross-check against a full scan stays satisfied.
    super::rebuild_unacked_accounting(state);
}

/// Canonical BBR retires the probe-up phase on `is_full_length && inflight >=
/// gain x BDP`, not on the timer alone — "this may take more than min_rtt if
/// min_rtt is small". Our cycle used wall clock only, so on a path whose ACKs
/// return slower than its own minimum the 1.25 phase expired before the ACKs it
/// provoked came back: the sample landed in the next phase, was divided by that
/// phase's interval, and the probe's extra bandwidth never reached BtlBw. A
/// Wi-Fi client on the field gateway sat at 3.57 MB/s of a 33 MB/s link with the
/// cycle spinning through all eight phases and the estimate frozen.
#[tokio::test]
async fn probe_up_holds_until_the_pipe_reaches_the_gain_it_probes_for() {
    let mut state = tcp_flow_state_for_tests().await;
    let now = Instant::now();
    state.bbr.mode = super::state_machine::BbrMode::ProbeBw;
    state.bbr.probe_bw_phase = 0;
    state.bbr.pacing_gain = 1.25;
    state.bbr.btlbw_bps = 9_000_000;
    state.bbr.min_rtt = Duration::from_micros(1_983);
    state.bbr.min_rtt_stamp = now;
    // Already past the min-RTT slice: the timer alone would retire the phase.
    state.bbr.cycle_stamp = now - Duration::from_millis(50);
    state.bbr.loss_in_round = false;
    // The pipe is nearly empty: the probe has achieved nothing yet, because the
    // ACKs it provoked are still out on a path that answers slower than its own
    // minimum.
    fill_pipe_for_tests(&mut state, 1_200);

    super::state_machine::bbr_on_ack_for_tests(&mut state, 0, None, None, now);

    assert_eq!(
        state.bbr.pacing_gain, 1.25,
        "probe-up must persist until the pipe holds gain x BDP; retiring it on the \
         timer alone is what froze BtlBw on the jittery path",
    );
    assert_eq!(state.bbr.probe_bw_phase, 0);
}

/// The other side: once the pipe really holds `gain x BDP` the probe has done its
/// job, and the cycle must move on rather than keep inflating the queue.
#[tokio::test]
async fn probe_up_advances_once_the_pipe_has_filled() {
    let mut state = tcp_flow_state_for_tests().await;
    let now = Instant::now();
    state.bbr.mode = super::state_machine::BbrMode::ProbeBw;
    state.bbr.probe_bw_phase = 0;
    state.bbr.pacing_gain = 1.25;
    state.bbr.btlbw_bps = 9_000_000;
    state.bbr.min_rtt = Duration::from_micros(1_983);
    state.bbr.min_rtt_stamp = now;
    state.bbr.cycle_stamp = now - Duration::from_millis(50);
    state.bbr.loss_in_round = false;
    // Well past 1.25 x BDP (BDP is ~17.8 KB at these estimates).
    fill_pipe_for_tests(&mut state, 200_000);

    super::state_machine::bbr_on_ack_for_tests(&mut state, 0, None, None, now);

    assert_ne!(
        state.bbr.pacing_gain, 1.25,
        "a probe that reached gain x BDP must hand over to the next phase",
    );
}
