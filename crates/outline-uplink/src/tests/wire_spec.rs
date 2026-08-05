use url::Url;

use crate::config::{SsPathKind, TransportMode, UplinkTransport};
use crate::tests::sample_uplink_config;
use crate::wire_spec::{Plane, WireSpec};

#[test]
fn from_uplink_projects_the_primary_wire() {
    let uplink = sample_uplink_config();
    let spec = WireSpec::from_uplink(&uplink);

    assert_eq!(spec.wire, 0, "the primary wire is always index 0");
    assert_eq!(spec.name, uplink.name, "a wire reports its parent's name");
    assert_eq!(spec.transport, UplinkTransport::Vless);
    assert_eq!(spec.dial_mode(Plane::Tcp), uplink.tcp_dial_mode());
    assert_eq!(spec.dial_url(Plane::Tcp), uplink.tcp_dial_url());
}

#[test]
fn from_fallback_projects_the_fallback_wire_but_keeps_the_parent_name() {
    let mut uplink = sample_uplink_config();
    let fallback = crate::config::FallbackTransport {
        transport: UplinkTransport::Ss,
        tcp_ws_url: Some(Url::parse("wss://example.test/ss").unwrap()),
        tcp_xhttp_url: None,
        tcp_mode: TransportMode::WsH3,
        udp_ws_url: Some(Url::parse("wss://example.test/ssu").unwrap()),
        udp_xhttp_url: None,
        udp_mode: TransportMode::WsH3,
        vless_ws_url: None,
        vless_xhttp_url: None,
        vless_mode: TransportMode::WsH3,
        ss_ws_url: None,
        ss_xhttp_url: None,
        ss_mode: None,
        vless_id: None,
        cipher: uplink.cipher,
        password: "fallback-secret".to_string(),
        fwmark: Some(42),
        ipv6_first: true,
        fingerprint_profile: None,
    };
    uplink.fallbacks.push(fallback);

    let spec = WireSpec::from_fallback(&uplink.name, 1, &uplink.fallbacks[0]);

    assert_eq!(spec.wire, 1);
    assert_eq!(spec.name, uplink.name, "a fallback shares its parent's identity");
    assert_eq!(spec.transport, UplinkTransport::Ss, "but dials its own family");
    assert_eq!(spec.password, "fallback-secret", "and its own credentials");
    assert_eq!(spec.fwmark, Some(42));
    assert!(spec.ipv6_first);
    assert!(spec.supports_udp());
}

#[test]
fn combined_ss_discriminator_comes_from_the_wire_not_the_parent() {
    let mut uplink = sample_uplink_config();
    uplink.ss_ws_url = Some(Url::parse("wss://example.test/combined").unwrap());
    uplink.ss_mode = Some(TransportMode::WsH3);
    uplink.transport = UplinkTransport::Ss;
    uplink.fallbacks.push(crate::config::FallbackTransport {
        transport: UplinkTransport::Ss,
        tcp_ws_url: Some(Url::parse("wss://example.test/split-tcp").unwrap()),
        tcp_xhttp_url: None,
        tcp_mode: TransportMode::WsH3,
        udp_ws_url: Some(Url::parse("wss://example.test/split-udp").unwrap()),
        udp_xhttp_url: None,
        udp_mode: TransportMode::WsH3,
        vless_ws_url: None,
        vless_xhttp_url: None,
        vless_mode: TransportMode::WsH3,
        ss_ws_url: None,
        ss_xhttp_url: None,
        ss_mode: None,
        vless_id: None,
        cipher: uplink.cipher,
        password: "split".to_string(),
        fwmark: None,
        ipv6_first: false,
        fingerprint_profile: None,
    });

    let primary = WireSpec::from_uplink(&uplink);
    let fallback = WireSpec::from_fallback(&uplink.name, 1, &uplink.fallbacks[0]);

    assert_eq!(
        primary.combined_ss_kind(SsPathKind::Udp),
        Some(SsPathKind::Udp),
        "the parent is combined-SS, so its legs carry the discriminator"
    );
    assert_eq!(
        fallback.combined_ss_kind(SsPathKind::Udp),
        None,
        "the fallback uses split paths — a pool filled with the wrong leg drops every \
         reused datagram"
    );
}
