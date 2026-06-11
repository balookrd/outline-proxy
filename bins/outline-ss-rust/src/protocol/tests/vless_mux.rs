use super::*;

fn ipv4_target(a: u8, b: u8, c: u8, d: u8, port: u16) -> TargetAddr {
    TargetAddr::Socket(SocketAddr::from((Ipv4Addr::new(a, b, c, d), port)))
}

#[test]
fn parses_new_tcp_frame() {
    let mut out = BytesMut::new();
    encode_frame(
        &mut out,
        7,
        SessionStatus::New,
        OPTION_DATA,
        Some(Network::Tcp),
        Some(&ipv4_target(1, 2, 3, 4, 80)),
        Some(b"hello"),
    );

    let parsed = parse_frame(&out).unwrap().unwrap();
    assert_eq!(parsed.meta.session_id, 7);
    assert_eq!(parsed.meta.status, SessionStatus::New);
    assert_eq!(parsed.meta.network, Some(Network::Tcp));
    assert_eq!(parsed.meta.target, Some(ipv4_target(1, 2, 3, 4, 80)));
    assert_eq!(parsed.meta.global_id, None);
    assert_eq!(parsed.data, Some(b"hello".as_ref()));
    assert_eq!(parsed.consumed, out.len());
}

#[test]
fn parses_new_udp_with_global_id() {
    let mut out = BytesMut::new();
    let mut meta = BytesMut::new();
    meta.put_u16(3);
    meta.put_u8(SESSION_STATUS_NEW);
    meta.put_u8(OPTION_DATA);
    meta.put_u16(53);
    meta.put_u8((NETWORK_UDP << 4) | ATYP_IPV4);
    meta.extend_from_slice(&[1, 1, 1, 1]);
    meta.extend_from_slice(&[0xAA; GLOBAL_ID_LEN]);
    out.put_u16(meta.len() as u16);
    out.extend_from_slice(&meta);
    out.put_u16(4);
    out.extend_from_slice(b"ping");

    let parsed = parse_frame(&out).unwrap().unwrap();
    assert_eq!(parsed.meta.network, Some(Network::Udp));
    assert_eq!(parsed.meta.global_id, Some([0xAA; GLOBAL_ID_LEN]));
    assert_eq!(parsed.meta.target, Some(ipv4_target(1, 1, 1, 1, 53)));
    assert_eq!(parsed.data, Some(b"ping".as_ref()));
}

#[test]
fn parses_keep_without_address() {
    let mut out = BytesMut::new();
    encode_frame(&mut out, 9, SessionStatus::Keep, OPTION_DATA, None, None, Some(b"abc"));

    let parsed = parse_frame(&out).unwrap().unwrap();
    assert_eq!(parsed.meta.status, SessionStatus::Keep);
    assert_eq!(parsed.meta.target, None);
    assert_eq!(parsed.data, Some(b"abc".as_ref()));
}

#[test]
fn parses_keep_with_xudp_address() {
    let mut out = BytesMut::new();
    encode_frame(
        &mut out,
        4,
        SessionStatus::Keep,
        OPTION_DATA,
        Some(Network::Udp),
        Some(&ipv4_target(8, 8, 8, 8, 53)),
        Some(b"q"),
    );

    let parsed = parse_frame(&out).unwrap().unwrap();
    assert_eq!(parsed.meta.target, Some(ipv4_target(8, 8, 8, 8, 53)));
    assert_eq!(parsed.data, Some(b"q".as_ref()));
}

#[test]
fn parses_end_frame_without_data() {
    let mut out = BytesMut::new();
    encode_frame(&mut out, 12, SessionStatus::End, 0, None, None, None);

    let parsed = parse_frame(&out).unwrap().unwrap();
    assert_eq!(parsed.meta.status, SessionStatus::End);
    assert_eq!(parsed.data, None);
    assert_eq!(parsed.consumed, out.len());
}

#[test]
fn returns_none_for_partial() {
    let input = [0x00, 0x04, 0x00, 0x01];
    assert!(parse_frame(&input).unwrap().is_none());
}

#[test]
fn returns_none_for_partial_data() {
    let mut out = BytesMut::new();
    encode_frame(&mut out, 1, SessionStatus::Keep, OPTION_DATA, None, None, Some(b"abcdef"));
    let truncated = &out[..out.len() - 2];
    assert!(parse_frame(truncated).unwrap().is_none());
}

#[test]
fn rejects_short_meta() {
    let input = [0x00, 0x00];
    assert!(matches!(parse_frame(&input), Err(MuxError::MetaTooShort)));
}

#[test]
fn parses_domain_target() {
    let mut out = BytesMut::new();
    let addr = TargetAddr::Domain("example.com".to_owned(), 443);
    encode_frame(
        &mut out,
        2,
        SessionStatus::New,
        OPTION_DATA,
        Some(Network::Tcp),
        Some(&addr),
        Some(b"."),
    );
    let parsed = parse_frame(&out).unwrap().unwrap();
    assert_eq!(parsed.meta.target, Some(addr));
}
