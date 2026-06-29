use std::net::{Ipv4Addr, Ipv6Addr};

use super::*;

const UUID: &str = "550e8400-e29b-41d4-a716-446655440000";

fn request_prefix(command: u8) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.push(VERSION);
    bytes.extend_from_slice(&parse_uuid(UUID).unwrap());
    bytes.push(0);
    bytes.push(command);
    bytes
}

#[test]
fn parse_vless_ipv4_tcp_request() {
    let mut bytes = request_prefix(COMMAND_TCP);
    bytes.extend_from_slice(&443_u16.to_be_bytes());
    bytes.push(0x01);
    bytes.extend_from_slice(&[127, 0, 0, 1]);

    let parsed = parse_request(&bytes).unwrap().unwrap();
    assert_eq!(parsed.user_id, parse_uuid(UUID).unwrap());
    assert_eq!(parsed.target, TargetAddr::IpV4(Ipv4Addr::new(127, 0, 0, 1), 443));
    assert_eq!(parsed.consumed, bytes.len());
}

#[test]
fn parse_vless_domain_tcp_request() {
    let mut bytes = request_prefix(COMMAND_TCP);
    bytes.extend_from_slice(&80_u16.to_be_bytes());
    bytes.push(0x02);
    bytes.push(11);
    bytes.extend_from_slice(b"example.com");

    let parsed = parse_request(&bytes).unwrap().unwrap();
    assert_eq!(parsed.target, TargetAddr::Domain("example.com".to_owned(), 80));
    assert_eq!(parsed.consumed, bytes.len());
}

#[test]
fn parse_vless_ipv6_tcp_request() {
    let mut bytes = request_prefix(COMMAND_TCP);
    bytes.extend_from_slice(&8443_u16.to_be_bytes());
    bytes.push(0x03);
    let ip = Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1);
    bytes.extend_from_slice(&ip.octets());

    let parsed = parse_request(&bytes).unwrap().unwrap();
    assert_eq!(parsed.target, TargetAddr::IpV6(ip, 8443));
    assert_eq!(parsed.consumed, bytes.len());
}

#[test]
fn parse_vless_udp_request() {
    let mut bytes = request_prefix(COMMAND_UDP);
    bytes.extend_from_slice(&53_u16.to_be_bytes());
    bytes.push(0x01);
    bytes.extend_from_slice(&[1, 1, 1, 1]);

    let parsed = parse_request(&bytes).unwrap().unwrap();
    assert_eq!(parsed.command, VlessCommand::Udp);
    assert_eq!(parsed.target, TargetAddr::IpV4(Ipv4Addr::new(1, 1, 1, 1), 53));
    assert_eq!(parsed.consumed, bytes.len());
}

#[test]
fn reject_unknown_command() {
    let mut bytes = request_prefix(0x04);
    bytes.extend_from_slice(&53_u16.to_be_bytes());
    bytes.push(0x01);
    bytes.extend_from_slice(&[1, 1, 1, 1]);

    assert_eq!(parse_request(&bytes).unwrap_err(), VlessError::UnsupportedCommand(0x04));
}

#[test]
fn parse_vless_mux_request_has_no_address() {
    // Both Xray-core and sing-box omit the port/atyp/address for the Mux
    // command and begin the mux frame stream immediately after the
    // command byte. The parser must consume only the fixed header and
    // leave the frame bytes untouched. The leading 0x00 of the tail is
    // exactly the byte that the old address-parsing path mis-read as
    // `atyp` and rejected as `UnsupportedAddressType(0x0)`.
    let mut bytes = request_prefix(COMMAND_MUX);
    let mux_frame_tail = [0x00, 0x04, 0xde, 0xad, 0xbe, 0xef];
    bytes.extend_from_slice(&mux_frame_tail);

    let parsed = parse_request(&bytes).unwrap().unwrap();
    assert_eq!(parsed.command, VlessCommand::Mux);
    // version(1) | uuid(16) | opt_len(1) | command(1) = 19 bytes.
    assert_eq!(parsed.consumed, 19);
    assert_eq!(&bytes[parsed.consumed..], &mux_frame_tail);
}

#[test]
fn parse_vless_mux_request_header_only() {
    // A Mux carrier whose first WS frame carries only the VLESS header
    // (the mux frames arrive in a later frame) must still parse, not
    // stall waiting for a non-existent address.
    let bytes = request_prefix(COMMAND_MUX);
    let parsed = parse_request(&bytes).unwrap().unwrap();
    assert_eq!(parsed.command, VlessCommand::Mux);
    assert_eq!(parsed.consumed, bytes.len());
}

#[test]
fn reject_invalid_version() {
    let mut bytes = request_prefix(COMMAND_TCP);
    bytes[0] = 0x01;
    bytes.extend_from_slice(&443_u16.to_be_bytes());
    bytes.push(0x01);
    bytes.extend_from_slice(&[127, 0, 0, 1]);

    assert_eq!(parse_request(&bytes).unwrap_err(), VlessError::InvalidVersion(0x01));
}

#[test]
fn returns_none_for_truncated_request() {
    let mut bytes = request_prefix(COMMAND_TCP);
    bytes.extend_from_slice(&443_u16.to_be_bytes());
    bytes.push(0x02);
    bytes.push(11);
    bytes.extend_from_slice(b"examp");

    assert_eq!(parse_request(&bytes).unwrap(), None);
}

// Client build → server parse round-trips: both halves now live in one
// place, so encode/decode must agree byte-for-byte.

#[test]
fn build_parse_roundtrip_tcp() {
    let uuid = parse_uuid(UUID).unwrap();
    let target = TargetAddr::Domain("example.com".to_owned(), 443);
    let header = build_request_header(&uuid, COMMAND_TCP, &target, &[]);

    let parsed = parse_request(&header).unwrap().unwrap();
    assert_eq!(parsed.user_id, uuid);
    assert_eq!(parsed.command, VlessCommand::Tcp);
    assert_eq!(parsed.target, target);
    assert_eq!(parsed.consumed, header.len());
    assert_eq!(parsed.addons, VlessRequestAddons::default());
}

#[test]
fn build_parse_roundtrip_with_resume_addons() {
    let uuid = parse_uuid(UUID).unwrap();
    let target = TargetAddr::IpV6(Ipv6Addr::LOCALHOST, 8443);
    let resume_id = [0x5A; 16];
    let addons = encode_request_addons(true, Some(&resume_id));
    let header = build_request_header(&uuid, COMMAND_TCP, &target, &addons);

    let parsed = parse_request(&header).unwrap().unwrap();
    assert_eq!(parsed.target, target);
    assert!(parsed.addons.resume_capable);
    assert_eq!(parsed.addons.resume_id, Some(resume_id));
}

#[test]
fn response_addons_roundtrip() {
    let session_id = [0x77; 16];
    let block = encode_response_addons(Some(&session_id), Some(AddonResumeResult::Hit));
    assert_eq!(parse_response_addons_session_id(&block), Some(session_id));

    assert_eq!(parse_response_addons_session_id(&[]), None);
    let result_only = encode_response_addons(None, Some(AddonResumeResult::MissUnknown));
    assert_eq!(parse_response_addons_session_id(&result_only), None);
}

#[test]
fn parse_uuid_accepts_dashed_and_plain() {
    let dashed = parse_uuid(UUID).unwrap();
    let plain = parse_uuid("550e8400e29b41d4a716446655440000").unwrap();
    let upper = parse_uuid("550E8400-E29B-41D4-A716-446655440000").unwrap();
    assert_eq!(dashed, plain);
    assert_eq!(dashed, upper);
    assert_eq!(dashed[0], 0x55);
    assert_eq!(dashed[15], 0x00);
}

#[test]
fn parse_uuid_rejects_invalid() {
    assert_eq!(parse_uuid("not-a-uuid"), Err(VlessError::InvalidUuid));
    assert_eq!(parse_uuid("550e8400e29b41d4a71644665544000"), Err(VlessError::InvalidUuid));
    assert_eq!(parse_uuid("550e8400e29b41d4a7164466554400001"), Err(VlessError::InvalidUuid));
}

#[test]
fn mask_uuid_keeps_first_four_bytes() {
    let id = parse_uuid(UUID).unwrap();
    assert_eq!(mask_uuid(&id), "550e8400-...");
}
