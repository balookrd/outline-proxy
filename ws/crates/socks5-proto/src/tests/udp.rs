use std::net::Ipv4Addr;

use super::*;

#[test]
fn socks5_udp_packet_round_trip() {
    let target = TargetAddr::IpV4(Ipv4Addr::new(1, 1, 1, 1), 53);
    let packet = build_udp_packet(&target, b"hello").unwrap();
    let parsed = parse_udp_request(&packet).unwrap();
    assert_eq!(parsed.fragment, 0);
    assert_eq!(parsed.target, target);
    assert_eq!(parsed.payload, b"hello");
}

#[tokio::test]
async fn socks5_udp_in_tcp_packet_round_trip() {
    let (mut writer, mut reader) = tokio::io::duplex(128);
    let target = TargetAddr::Domain("example.com".to_string(), 53);

    let send = tokio::spawn(async move {
        write_udp_tcp_packet(&mut writer, &target, b"hello").await.unwrap();
    });

    let packet = read_udp_tcp_packet(&mut reader).await.unwrap().unwrap();
    send.await.unwrap();
    assert_eq!(packet.target, TargetAddr::Domain("example.com".to_string(), 53));
    assert_eq!(packet.payload, b"hello");
}
