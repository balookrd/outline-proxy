use super::super::endpoint::EndpointKind;
use super::super::file::EndpointSection;

#[test]
fn kind_parses_snake_case_and_reports_family() {
    let s: EndpointSection = toml::from_str(
        r#"path = "/pss"
kind = "ws_ss"
padded = true"#,
    )
    .unwrap();
    assert_eq!(s.path, "/pss");
    assert_eq!(s.kind, EndpointKind::WsSs);
    assert!(s.padded);
    assert!(s.kind.is_ss() && s.kind.is_combined() && !s.kind.is_vless());
}

#[test]
fn padded_defaults_to_false() {
    let s: EndpointSection = toml::from_str(
        r#"path = "/tcp"
kind = "ws_ss_tcp""#,
    )
    .unwrap();
    assert!(!s.padded);
    assert!(!s.kind.is_combined());
}

#[test]
fn unknown_field_is_rejected() {
    let err = toml::from_str::<EndpointSection>(
        r#"path = "/x"
kind = "ws_vless"
padde = true"#,
    )
    .unwrap_err();
    assert!(err.to_string().contains("padde") || err.to_string().contains("unknown"));
}

#[test]
fn all_eight_kinds_round_trip() {
    for (s, k) in [
        ("ws_ss", EndpointKind::WsSs),
        ("ws_ss_tcp", EndpointKind::WsSsTcp),
        ("ws_ss_udp", EndpointKind::WsSsUdp),
        ("ws_vless", EndpointKind::WsVless),
        ("xhttp_ss", EndpointKind::XhttpSs),
        ("xhttp_ss_tcp", EndpointKind::XhttpSsTcp),
        ("xhttp_ss_udp", EndpointKind::XhttpSsUdp),
        ("xhttp_vless", EndpointKind::XhttpVless),
    ] {
        let parsed: EndpointSection =
            toml::from_str(&format!("path = \"/p\"\nkind = \"{s}\"")).unwrap();
        assert_eq!(parsed.kind, k, "kind {s}");
    }
}
