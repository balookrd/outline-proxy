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
    assert_eq!(
        parsed.target,
        TargetAddr::Socket(SocketAddr::from((Ipv4Addr::new(127, 0, 0, 1), 443)))
    );
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
    assert_eq!(parsed.target, TargetAddr::Socket(SocketAddr::from((ip, 8443))));
    assert_eq!(parsed.consumed, bytes.len());
}

#[test]
fn reject_unknown_uuid() {
    let known = VlessUser::new(UUID.to_owned(), None).unwrap();
    let unknown = parse_uuid("650e8400-e29b-41d4-a716-446655440000").unwrap();
    assert!(find_user(&[known], &unknown).is_none());
}

#[test]
fn parse_vless_udp_request() {
    let mut bytes = request_prefix(COMMAND_UDP);
    bytes.extend_from_slice(&53_u16.to_be_bytes());
    bytes.push(0x01);
    bytes.extend_from_slice(&[1, 1, 1, 1]);

    let parsed = parse_request(&bytes).unwrap().unwrap();
    assert_eq!(parsed.command, VlessCommand::Udp);
    assert_eq!(
        parsed.target,
        TargetAddr::Socket(SocketAddr::from((Ipv4Addr::new(1, 1, 1, 1), 53)))
    );
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
fn parse_vless_mux_request() {
    let mut bytes = request_prefix(COMMAND_MUX);
    bytes.extend_from_slice(&666_u16.to_be_bytes());
    bytes.push(0x02);
    let domain = b"v1.mux.cool";
    bytes.push(domain.len() as u8);
    bytes.extend_from_slice(domain);

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
