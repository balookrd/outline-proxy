use std::collections::VecDeque;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;

use super::{
    BufferedClientSegment, ClientSegmentView, IPV4_HEADER_LEN, IPV6_HEADER_LEN, ParsedTcpPacket,
    TCP_FLAG_ACK, TCP_FLAG_FIN, TCP_FLAG_RST, TCP_FLAG_SYN, build_reset_response,
    drain_ready_buffered_segments, normalize_client_segment, queue_future_segment,
};
use crate::config::TunTcpConfig;
use crate::transport::{AnyWsStream, TcpShadowsocksWriter};
use crate::tun_tcp::state_machine::SequenceRange;
use crate::tun_wire::test_utils::{
    IP_PROTOCOL_TCP, assert_ipv4_header_checksum_valid, assert_transport_checksum_valid,
    flip_packet_byte, random_payload, seeded_rng, transport_offset,
};
use crate::types::CipherKind;
use futures_util::StreamExt;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng, seq::SliceRandom};
use tokio::net::TcpListener;
use tokio::sync::{Mutex, Notify};
use tokio_tungstenite::{accept_async, connect_async};

fn parse_action_response(packet: &[u8]) -> Vec<u8> {
    match handle_stateless_packet(packet).unwrap() {
        Some(response) => response,
        None => panic!("expected response"),
    }
}

fn handle_stateless_packet(packet: &[u8]) -> Result<Option<Vec<u8>>, anyhow::Error> {
    let parsed = super::parse_tcp_packet(packet)?;
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
    let parsed: ParsedTcpPacket = super::parse_tcp_packet(&packet).unwrap();
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
    let packet = ParsedTcpPacket {
        version: super::IpVersion::V4,
        source_ip: "10.0.0.1".parse().unwrap(),
        destination_ip: "8.8.8.8".parse().unwrap(),
        source_port: 12345,
        destination_port: 80,
        sequence_number: 200,
        acknowledgement_number: 0,
        window_size: 4096,
        max_segment_size: None,
        window_scale: None,
        sack_permitted: false,
        sack_blocks: Vec::new(),
        timestamp_value: None,
        timestamp_echo_reply: None,
        flags: TCP_FLAG_ACK,
        payload: Bytes::from_static(b"later"),
    };
    let mut pending = VecDeque::new();

    queue_future_segment(&mut pending, &packet, 100);
    queue_future_segment(&mut pending, &packet, 100);

    assert_eq!(pending.len(), 1);
}

#[test]
fn drain_ready_buffered_segments_reassembles_contiguous_tail() {
    let mut expected_seq = 103;
    let mut pending = VecDeque::new();
    let first = ParsedTcpPacket {
        version: super::IpVersion::V4,
        source_ip: "10.0.0.1".parse().unwrap(),
        destination_ip: "8.8.8.8".parse().unwrap(),
        source_port: 12345,
        destination_port: 80,
        sequence_number: 106,
        acknowledgement_number: 0,
        window_size: 4096,
        max_segment_size: None,
        window_scale: None,
        sack_permitted: false,
        sack_blocks: Vec::new(),
        timestamp_value: None,
        timestamp_echo_reply: None,
        flags: TCP_FLAG_ACK,
        payload: Bytes::from_static(b"ghi"),
    };
    let second = ParsedTcpPacket {
        sequence_number: 103,
        payload: Bytes::from_static(b"def"),
        ..first.clone()
    };
    queue_future_segment(&mut pending, &first, expected_seq);
    queue_future_segment(&mut pending, &second, expected_seq);
    let mut payload = Vec::new();

    let closed = drain_ready_buffered_segments(&mut expected_seq, &mut pending, &mut payload);

    assert!(!closed);
    assert_eq!(expected_seq, 109);
    assert_eq!(payload, b"defghi");
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
    assert_eq!(payload, b"def");
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
    let parsed = super::parse_tcp_packet(&packet).unwrap();
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
    let parsed = super::parse_tcp_packet(&packet).unwrap();
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
    let error = super::parse_tcp_packet(&packet).unwrap_err();
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
    let error = super::parse_tcp_packet(&packet).unwrap_err();
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
    let error = super::parse_tcp_packet(&packet).unwrap_err();
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
    let parsed = super::parse_tcp_packet(&packet).unwrap();
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
    let error = super::parse_tcp_packet(&packet).unwrap_err();
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
        ][rng.gen_range(0..5)];
        let payload = if (flags & TCP_FLAG_SYN) != 0 {
            Vec::new()
        } else {
            payload
        };
        let options = match rng.gen_range(0..4) {
            0 => Vec::new(),
            1 => tcp_option_pad(vec![2, 4, 0x05, 0xb4]),
            2 => tcp_option_pad(vec![1, 3, 3, 7]),
            _ => tcp_option_pad(vec![8, 10, 0, 0, 0, 9, 0, 0, 0, 7]),
        };
        let sequence_number = rng.r#gen::<u32>();
        let acknowledgement_number = rng.r#gen::<u32>();
        let window_size = rng.gen_range(1..=u16::MAX);

        if rng.gen_bool(0.5) {
            let client_ip = Ipv4Addr::new(10, 0, 0, rng.gen_range(2..=250));
            let remote_ip = Ipv4Addr::new(8, 8, 4, rng.gen_range(1..=250));
            let packet = build_client_packet_with_options(
                client_ip,
                remote_ip,
                rng.gen_range(1024..=65000),
                rng.gen_range(1..=65000),
                sequence_number,
                acknowledgement_number,
                window_size,
                flags,
                &options,
                &payload,
            );
            assert_ipv4_header_checksum_valid(&packet);
            assert_transport_checksum_valid(&packet, IP_PROTOCOL_TCP);
            let parsed = super::parse_tcp_packet(&packet).unwrap();
            assert_eq!(parsed.version, super::IpVersion::V4);
            assert_eq!(parsed.sequence_number, sequence_number);
            assert_eq!(parsed.acknowledgement_number, acknowledgement_number);
            assert_eq!(parsed.flags, flags);
            assert_eq!(parsed.payload, payload);

            let mutated = flip_packet_byte(&packet, transport_offset(&packet) + 4);
            assert!(super::parse_tcp_packet(&mutated).is_err());
        } else {
            let client_ip = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, rng.gen_range(2..=250));
            let remote_ip = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, rng.gen_range(2..=250));
            let packet = build_client_ipv6_packet_with_options(
                client_ip,
                remote_ip,
                rng.gen_range(1024..=65000),
                rng.gen_range(1..=65000),
                sequence_number,
                acknowledgement_number,
                window_size,
                flags,
                &options,
                &payload,
            );
            assert_transport_checksum_valid(&packet, IP_PROTOCOL_TCP);
            let parsed = super::parse_tcp_packet(&packet).unwrap();
            assert_eq!(parsed.version, super::IpVersion::V6);
            assert_eq!(parsed.sequence_number, sequence_number);
            assert_eq!(parsed.acknowledgement_number, acknowledgement_number);
            assert_eq!(parsed.flags, flags);
            assert_eq!(parsed.payload, payload);

            let mutated = flip_packet_byte(&packet, transport_offset(&packet) + 4);
            assert!(super::parse_tcp_packet(&mutated).is_err());
        }
    }
}

#[test]
fn randomized_out_of_order_reassembly_smoke() {
    let mut rng = StdRng::seed_from_u64(0x51ce_2026);
    for _ in 0..64 {
        let sequence_start = rng.gen_range(10_000..50_000);
        let total_len = rng.gen_range(12..96);
        let mut original = vec![0u8; total_len];
        rng.fill(original.as_mut_slice());

        let mut segments = Vec::new();
        let mut cursor = 0usize;
        while cursor < total_len {
            let len = rng.gen_range(1..=(total_len - cursor).min(16));
            segments
                .push((sequence_start + cursor as u32, original[cursor..cursor + len].to_vec()));
            if cursor > 0 && rng.gen_bool(0.35) {
                let overlap_start = cursor.saturating_sub(rng.gen_range(1..=cursor.min(4)));
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
            let packet = ParsedTcpPacket {
                version: super::IpVersion::V4,
                source_ip: "10.0.0.1".parse().unwrap(),
                destination_ip: "8.8.8.8".parse().unwrap(),
                source_port: 12345,
                destination_port: 80,
                sequence_number,
                acknowledgement_number: 0,
                window_size: 4096,
                max_segment_size: None,
                window_scale: None,
                sack_permitted: false,
                sack_blocks: Vec::new(),
                timestamp_value: None,
                timestamp_echo_reply: None,
                flags: TCP_FLAG_ACK,
                payload: Bytes::from(payload),
            };
            queue_future_segment(&mut pending, &packet, sequence_start);
        }

        let mut expected_seq = sequence_start;
        let mut reassembled = Vec::new();
        let closed =
            drain_ready_buffered_segments(&mut expected_seq, &mut pending, &mut reassembled);
        assert!(!closed);
        assert_eq!(expected_seq, sequence_start + total_len as u32);
        assert_eq!(reassembled, original);
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
    let parsed = super::parse_tcp_packet(&packet).unwrap();
    assert_eq!(parsed.flags, TCP_FLAG_SYN | TCP_FLAG_ACK);
    assert_eq!(parsed.max_segment_size, Some(super::MAX_SERVER_SEGMENT_PAYLOAD as u16));
    assert!(parsed.sack_permitted);
    assert_eq!(parsed.timestamp_echo_reply, Some(1234));
    assert!(parsed.timestamp_value.unwrap_or_default() >= 7);
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
        },
        super::ServerSegment {
            sequence_number: 1004,
            acknowledgement_number: 500,
            flags: TCP_FLAG_ACK | super::TCP_FLAG_PSH,
            payload: b"BBBB".to_vec().into(),
            last_sent: Instant::now(),
            first_sent: Instant::now(),
            retransmits: 0,
        },
    ]);

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
    state.slow_start_threshold = 2400;
    state.congestion_window = 4000;
    state.fast_recovery_end = Some(1016);
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
        },
        super::ServerSegment {
            sequence_number: 1004,
            acknowledgement_number: 500,
            flags: TCP_FLAG_ACK | super::TCP_FLAG_PSH,
            payload: b"BBBB".to_vec().into(),
            last_sent: Instant::now() - Duration::from_secs(2),
            first_sent: Instant::now() - Duration::from_secs(2),
            retransmits: 1,
        },
        super::ServerSegment {
            sequence_number: 1008,
            acknowledgement_number: 500,
            flags: TCP_FLAG_ACK | super::TCP_FLAG_PSH,
            payload: b"CCCC".to_vec().into(),
            last_sent: Instant::now() - Duration::from_secs(2),
            first_sent: Instant::now() - Duration::from_secs(2),
            retransmits: 0,
        },
        super::ServerSegment {
            sequence_number: 1012,
            acknowledgement_number: 500,
            flags: TCP_FLAG_ACK | super::TCP_FLAG_PSH,
            payload: b"DDDD".to_vec().into(),
            last_sent: Instant::now() - Duration::from_secs(2),
            first_sent: Instant::now() - Duration::from_secs(2),
            retransmits: 0,
        },
    ]);

    let effect = super::process_server_ack(&mut state, 1004, &[(1008, 1012)]);
    assert_eq!(effect.bytes_acked, 4);
    assert!(!effect.grow_congestion_window);
    assert!(effect.retransmit_now);
    assert_eq!(
        state.congestion_window,
        state.slow_start_threshold + super::MAX_SERVER_SEGMENT_PAYLOAD
    );
    assert_eq!(state.fast_recovery_end, Some(1016));
}

#[tokio::test]
async fn process_server_ack_exits_fast_recovery_once_recovery_point_is_acked() {
    let mut state = tcp_flow_state_for_tests().await;
    state.last_client_ack = 1000;
    state.server_seq = 1016;
    state.slow_start_threshold = 2400;
    state.congestion_window = 4000;
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
        },
        super::ServerSegment {
            sequence_number: 1004,
            acknowledgement_number: 500,
            flags: TCP_FLAG_ACK | super::TCP_FLAG_PSH,
            payload: b"BBBB".to_vec().into(),
            last_sent: Instant::now() - Duration::from_secs(2),
            first_sent: Instant::now() - Duration::from_secs(2),
            retransmits: 1,
        },
    ]);

    let effect = super::process_server_ack(&mut state, 1008, &[]);
    assert_eq!(effect.bytes_acked, 8);
    assert!(!effect.grow_congestion_window);
    assert!(!effect.retransmit_now);
    assert!(state.fast_recovery_end.is_none());
    assert_eq!(state.congestion_window, state.slow_start_threshold);
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
        super::build_flow_ack_packet(&state, state.server_seq, state.client_next_seq, TCP_FLAG_ACK)
            .unwrap();
    let parsed = super::parse_tcp_packet(&packet).unwrap();
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
        super::build_flow_ack_packet(&state, state.server_seq, state.client_next_seq, TCP_FLAG_ACK)
            .unwrap();
    let parsed = super::parse_tcp_packet(&packet).unwrap();
    assert_eq!(parsed.sack_blocks, vec![(112, 116), (120, 124), (128, 132)]);
    assert_eq!(parsed.timestamp_echo_reply, Some(55));
}

#[tokio::test]
async fn retransmit_prefers_unsacked_hole_before_sacked_tail() {
    let mut state = tcp_flow_state_for_tests().await;
    state.client_next_seq = 500;
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
        },
        super::ServerSegment {
            sequence_number: 1004,
            acknowledgement_number: 500,
            flags: TCP_FLAG_ACK | super::TCP_FLAG_PSH,
            payload: b"BBBB".to_vec().into(),
            last_sent: Instant::now() - Duration::from_secs(2),
            first_sent: Instant::now() - Duration::from_secs(2),
            retransmits: 0,
        },
        super::ServerSegment {
            sequence_number: 1008,
            acknowledgement_number: 500,
            flags: TCP_FLAG_ACK | super::TCP_FLAG_PSH,
            payload: b"CCCC".to_vec().into(),
            last_sent: Instant::now() - Duration::from_secs(2),
            first_sent: Instant::now() - Duration::from_secs(2),
            retransmits: 0,
        },
    ]);

    let packet = super::retransmit_oldest_unacked_packet(&mut state).unwrap().unwrap();
    let parsed = super::parse_tcp_packet(&packet).unwrap();
    assert_eq!(parsed.sequence_number, 1000);
    assert_eq!(parsed.payload, b"AAAA"[..]);
}

#[tokio::test]
async fn ack_progress_updates_rtt_and_grows_congestion_window() {
    let mut state = tcp_flow_state_for_tests().await;
    state.congestion_window = super::MAX_SERVER_SEGMENT_PAYLOAD;
    state.slow_start_threshold = super::TCP_SERVER_RECV_WINDOW_CAPACITY;

    super::note_ack_progress(&mut state, 600, Some(Duration::from_millis(120)), true);
    assert_eq!(state.smoothed_rtt, Some(Duration::from_millis(120)));
    assert!(state.retransmission_timeout >= Duration::from_millis(200));
    assert_eq!(state.congestion_window, super::MAX_SERVER_SEGMENT_PAYLOAD + 600);
}

#[tokio::test]
async fn timeout_congestion_event_reduces_cwnd_and_backs_off_rto() {
    let mut state = tcp_flow_state_for_tests().await;
    state.congestion_window = super::MAX_SERVER_SEGMENT_PAYLOAD * 8;
    state.slow_start_threshold = super::MAX_SERVER_SEGMENT_PAYLOAD * 8;
    state.retransmission_timeout = Duration::from_millis(800);
    state.unacked_server_segments = VecDeque::from([super::ServerSegment {
        sequence_number: 1000,
        acknowledgement_number: 500,
        flags: TCP_FLAG_ACK | super::TCP_FLAG_PSH,
        payload: b"AAAA".to_vec().into(),
        last_sent: Instant::now() - Duration::from_secs(2),
        first_sent: Instant::now() - Duration::from_secs(2),
        retransmits: 0,
    }]);

    super::note_congestion_event(&mut state, true);
    assert_eq!(state.congestion_window, super::MAX_SERVER_SEGMENT_PAYLOAD);
    assert!(state.slow_start_threshold >= super::TCP_MIN_SSTHRESH);
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
async fn server_backlog_pressure_aborts_after_grace_even_without_window_stall() {
    let mut state = tcp_flow_state_for_tests().await;
    state.pending_server_data = VecDeque::from([vec![1; 256].into()]);
    let config = TunTcpConfig {
        max_pending_server_bytes: 200,
        ..test_tun_tcp_config()
    };
    state.backlog_limit_exceeded_since = Some(Instant::now() - config.backlog_abort_grace);

    let pressure =
        super::assess_server_backlog_pressure(&mut state, &config, Instant::now(), false);

    assert!(pressure.exceeded);
    assert!(pressure.should_abort);
}

#[tokio::test]
async fn server_backlog_pressure_aborts_after_grace_when_stalled() {
    let mut state = tcp_flow_state_for_tests().await;
    state.client_window = 0;
    state.client_window_end = state.server_seq;
    state.pending_server_data = VecDeque::from([vec![1; 256].into()]);
    let config = TunTcpConfig {
        max_pending_server_bytes: 200,
        ..test_tun_tcp_config()
    };
    state.backlog_limit_exceeded_since = Some(Instant::now() - config.backlog_abort_grace);

    let pressure = super::assess_server_backlog_pressure(&mut state, &config, Instant::now(), true);

    assert!(pressure.exceeded);
    assert!(pressure.should_abort);
}

#[tokio::test]
async fn server_backlog_pressure_aborts_after_no_ack_progress_timeout() {
    let mut state = tcp_flow_state_for_tests().await;
    state.client_window = 0;
    state.client_window_end = state.server_seq;
    state.pending_server_data = VecDeque::from([vec![1; 256].into()]);
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
    let config = TunTcpConfig {
        max_pending_server_bytes: 200,
        ..test_tun_tcp_config()
    };

    let pressure =
        super::assess_server_backlog_pressure(&mut state, &config, Instant::now(), false);

    assert!(pressure.exceeded);
    assert!(pressure.should_abort);
}
pub(super) fn test_tun_tcp_config() -> TunTcpConfig {
    TunTcpConfig {
        connect_timeout: Duration::from_secs(5),
        handshake_timeout: Duration::from_secs(5),
        half_close_timeout: Duration::from_secs(15),
        max_pending_server_bytes: 1_048_576,
        backlog_abort_grace: Duration::from_secs(3),
        backlog_hard_limit_multiplier: 2,
        backlog_no_progress_abort: Duration::from_secs(8),
        max_buffered_client_segments: 4096,
        max_buffered_client_bytes: 262_144,
        max_retransmits: 12,
    }
}
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
    while options.len() % 4 != 0 {
        options.push(1);
    }
    options
}

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
async fn tcp_flow_state_for_tests() -> super::TcpFlowState {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut ws = accept_async(stream).await.unwrap();
        while ws.next().await.is_some() {}
    });

    let (ws_stream, _) = connect_async(format!("ws://{addr}/")).await.unwrap();
    let ws = AnyWsStream::Http1 { inner: ws_stream };
    let (sink, _stream) = ws.split();
    let cipher = CipherKind::Chacha20IetfPoly1305;
    let master_key = cipher.derive_master_key("Secret0").unwrap();
    let (close_signal, _close_rx) = tokio::sync::watch::channel(false);
    super::TcpFlowState {
        id: 1,
        key: super::TcpFlowKey {
            version: super::IpVersion::V4,
            client_ip: "10.0.0.2".parse().unwrap(),
            client_port: 40000,
            remote_ip: "8.8.8.8".parse().unwrap(),
            remote_port: 443,
        },
        uplink_index: 0,
        uplink_name: Arc::from("test"),
        group_name: Arc::from("test"),
        manager: super::engine::tests::build_test_manager("ws://127.0.0.1:1/".parse().unwrap())
            .await,
        route: crate::tun::TunRoute::Group {
            name: "test".to_string(),
            manager: super::engine::tests::build_test_manager(
                "ws://127.0.0.1:1/".parse().unwrap(),
            )
            .await,
        },
        upstream_writer: Some(Arc::new(Mutex::new(crate::tun_tcp::TunTcpUpstreamWriter::Tunneled({
            let (writer, _ctrl_tx) = TcpShadowsocksWriter::connect(
                sink,
                cipher,
                &master_key,
                super::UpstreamTransportGuard::new("test", "tcp"),
            )
            .await
            .unwrap();
            writer
        })))),
        close_signal,
        maintenance_notify: Arc::new(Notify::new()),
        status: super::TcpFlowStatus::Established,
        client_next_seq: 100,
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
        receive_window_capacity: 262_144,
        smoothed_rtt: None,
        rttvar: super::TCP_INITIAL_RTO / 2,
        retransmission_timeout: super::TCP_INITIAL_RTO,
        congestion_window: super::MAX_SERVER_SEGMENT_PAYLOAD * super::TCP_INITIAL_CWND_SEGMENTS,
        slow_start_threshold: super::TCP_SERVER_RECV_WINDOW_CAPACITY,
        pending_server_data: VecDeque::new(),
        backlog_limit_exceeded_since: None,
        last_ack_progress_at: Instant::now(),
        pending_client_data: VecDeque::new(),
        unacked_server_segments: VecDeque::new(),
        sack_scoreboard: Vec::new(),
        pending_client_segments: VecDeque::new(),
        server_fin_pending: false,
        zero_window_probe_backoff: super::TCP_ZERO_WINDOW_PROBE_BASE_INTERVAL,
        next_zero_window_probe_at: None,
        reported: super::state_machine::ReportedFlowMetrics::default(),
        created_at: Instant::now(),
        status_since: Instant::now(),
        last_seen: Instant::now(),
    }
}
