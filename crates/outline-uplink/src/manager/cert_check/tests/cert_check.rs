//! Endpoint-extraction tests for the cert-check loop.

use url::Url;

use super::{CertEndpoint, uplink_tls_endpoints};
use crate::config::{CipherKind, FallbackTransport, TransportMode, UplinkConfig, UplinkTransport};

fn ws_uplink(name: &str, tcp_url: &str, udp_url: &str) -> UplinkConfig {
    UplinkConfig {
        name: name.to_string(),
        transport: UplinkTransport::Ws,
        tcp_ws_url: Some(Url::parse(tcp_url).unwrap()),
        tcp_mode: TransportMode::WsH1,
        udp_ws_url: Some(Url::parse(udp_url).unwrap()),
        udp_mode: TransportMode::WsH1,
        vless_ws_url: None,
        vless_xhttp_url: None,
        vless_mode: TransportMode::WsH1,
        tcp_addr: None,
        udp_addr: None,
        cipher: CipherKind::Chacha20IetfPoly1305,
        password: "secret".to_string(),
        weight: 1.0,
        fwmark: None,
        ipv6_first: false,
        vless_id: None,
        fingerprint_profile: None,
        fallbacks: Vec::new(),
        shuffle_wires: false,
        carrier_downgrade: true,
        shuffle_timer: None,
    }
}

fn vless_xhttp_uplink(name: &str, xhttp_url: &str) -> UplinkConfig {
    let mut u = ws_uplink(name, "wss://unused/tcp", "wss://unused/udp");
    u.transport = UplinkTransport::Vless;
    u.tcp_ws_url = None;
    u.udp_ws_url = None;
    u.vless_xhttp_url = Some(Url::parse(xhttp_url).unwrap());
    u.vless_mode = TransportMode::XhttpH3;
    u.vless_id = Some([0u8; 16]);
    u
}

/// VLESS-over-WS fallback wire pointing at `host` (port 443 unless the URL
/// carries one). Mirrors the real `[[outline.uplinks.fallbacks]]` shape.
fn vless_ws_fallback(host: &str) -> FallbackTransport {
    FallbackTransport {
        transport: UplinkTransport::Vless,
        tcp_ws_url: None,
        tcp_mode: TransportMode::WsH3,
        udp_ws_url: None,
        udp_mode: TransportMode::WsH3,
        vless_ws_url: Some(Url::parse(&format!("wss://{host}/vless")).unwrap()),
        vless_xhttp_url: None,
        vless_mode: TransportMode::WsH3,
        vless_id: Some([0u8; 16]),
        tcp_addr: None,
        udp_addr: None,
        cipher: CipherKind::Chacha20IetfPoly1305,
        password: String::new(),
        fwmark: None,
        ipv6_first: false,
        fingerprint_profile: None,
    }
}

fn endpoint(host: &str, port: u16) -> CertEndpoint {
    CertEndpoint {
        host: host.to_string(),
        port,
        fwmark: None,
        ipv6_first: false,
    }
}

#[test]
fn ws_tcp_and_udp_on_same_host_dedupe_to_one_endpoint() {
    let u = ws_uplink("a", "wss://edge.example/tcp", "wss://edge.example/udp");
    assert_eq!(uplink_tls_endpoints(&u), vec![endpoint("edge.example", 443)]);
}

#[test]
fn explicit_port_is_preserved() {
    let u = ws_uplink("a", "wss://edge.example:8443/tcp", "wss://edge.example:8443/udp");
    assert_eq!(uplink_tls_endpoints(&u), vec![endpoint("edge.example", 8443)]);
}

#[test]
fn plain_ws_carries_no_tls_endpoint() {
    let u = ws_uplink("a", "ws://edge.example/tcp", "ws://edge.example/udp");
    assert!(uplink_tls_endpoints(&u).is_empty());
}

#[test]
fn vless_xhttp_collapses_tcp_and_udp_to_one_https_endpoint() {
    let u = vless_xhttp_uplink("a", "https://edge.example/xhttp?mode=stream-one");
    assert_eq!(uplink_tls_endpoints(&u), vec![endpoint("edge.example", 443)]);
}

#[test]
fn shadowsocks_uplink_has_no_tls_endpoints() {
    let mut u = ws_uplink("a", "wss://x/tcp", "wss://x/udp");
    u.transport = UplinkTransport::Shadowsocks;
    u.tcp_ws_url = None;
    u.udp_ws_url = None;
    assert!(uplink_tls_endpoints(&u).is_empty());
}

#[test]
fn fallback_on_a_different_host_adds_a_second_endpoint() {
    let mut u = vless_xhttp_uplink("a", "https://primary.example/xhttp");
    u.fallbacks = vec![vless_ws_fallback("fallback.example")];
    assert_eq!(
        uplink_tls_endpoints(&u),
        vec![endpoint("primary.example", 443), endpoint("fallback.example", 443)],
    );
}

#[test]
fn fallback_sharing_primary_host_is_deduped() {
    let mut u = vless_xhttp_uplink("a", "https://same.example/xhttp");
    u.fallbacks = vec![vless_ws_fallback("same.example")];
    assert_eq!(uplink_tls_endpoints(&u), vec![endpoint("same.example", 443)]);
}
