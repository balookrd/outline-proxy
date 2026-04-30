use crate::share_link::VlessShareLink;
use outline_transport::TransportMode;

const UUID: &str = "11111111-2222-3333-4444-555555555555";

fn parse(uri: &str) -> VlessShareLink {
    VlessShareLink::parse(uri).expect("valid vless share link")
}

#[test]
fn parses_ws_tls_h3_into_wss_url() {
    let link = parse(&format!(
        "vless://{UUID}@vless.example.com:443?type=ws&security=tls&path=%2Fsecret%2Fvless&alpn=h3&encryption=none#edge"
    ));
    assert_eq!(link.uuid, UUID);
    assert_eq!(link.mode, TransportMode::WsH3);
    assert_eq!(link.name.as_deref(), Some("edge"));
    assert!(link.vless_xhttp_url.is_none());
    let url = link.vless_ws_url.expect("ws url present");
    assert_eq!(url.scheme(), "wss");
    assert_eq!(url.host_str(), Some("vless.example.com"));
    assert_eq!(url.port_or_known_default(), Some(443));
    assert_eq!(url.path(), "/secret/vless");
}

#[test]
fn ws_without_security_uses_plain_ws_scheme() {
    let link = parse(&format!("vless://{UUID}@host:80?type=ws"));
    let url = link.vless_ws_url.expect("ws url present");
    assert_eq!(url.scheme(), "ws");
    assert_eq!(link.mode, TransportMode::WsH1);
}

#[test]
fn ws_alpn_h2_picks_ws_h2_mode() {
    let link = parse(&format!("vless://{UUID}@host:443?type=ws&security=tls&alpn=h2"));
    assert_eq!(link.mode, TransportMode::WsH2);
}

#[test]
fn ws_alpn_first_token_wins_for_comma_lists() {
    let link = parse(&format!(
        "vless://{UUID}@host:443?type=ws&security=tls&alpn=h3%2Ch2"
    ));
    assert_eq!(link.mode, TransportMode::WsH3);
}

#[test]
fn xhttp_default_mode_is_h2() {
    let link = parse(&format!("vless://{UUID}@host:443?type=xhttp&security=tls"));
    assert!(link.vless_ws_url.is_none());
    let url = link.vless_xhttp_url.expect("xhttp url");
    assert_eq!(url.scheme(), "https");
    assert_eq!(link.mode, TransportMode::XhttpH2);
}

#[test]
fn xhttp_alpn_h3_picks_xhttp_h3_mode() {
    let link = parse(&format!(
        "vless://{UUID}@host:443?type=xhttp&security=tls&alpn=h3"
    ));
    assert_eq!(link.mode, TransportMode::XhttpH3);
    assert!(link.vless_xhttp_url.is_some());
}

#[test]
fn xhttp_submode_preserved_as_query_string() {
    let link = parse(&format!(
        "vless://{UUID}@host:443?type=xhttp&security=tls&path=%2Fxhttp&mode=stream-one"
    ));
    let url = link.vless_xhttp_url.expect("xhttp url");
    assert_eq!(url.path(), "/xhttp");
    assert_eq!(url.query(), Some("mode=stream-one"));
}

#[test]
fn quic_security_tls_yields_https_scheme_and_quic_mode() {
    let link = parse(&format!("vless://{UUID}@host:443?type=quic&security=tls"));
    assert_eq!(link.mode, TransportMode::Quic);
    let url = link.vless_ws_url.expect("dial url present for quic");
    assert_eq!(url.scheme(), "https");
}

#[test]
fn fragment_is_percent_decoded_into_name() {
    let link = parse(&format!(
        "vless://{UUID}@host:443?type=ws&security=tls#edge%20one"
    ));
    assert_eq!(link.name.as_deref(), Some("edge one"));
}

#[test]
fn missing_uuid_is_rejected() {
    let err = VlessShareLink::parse("vless://host:443?type=ws").unwrap_err();
    assert!(format!("{err:#}").contains("UUID"));
}

#[test]
fn malformed_uuid_is_rejected() {
    let err = VlessShareLink::parse("vless://not-a-uuid@host:443?type=ws").unwrap_err();
    assert!(format!("{err:#}").to_lowercase().contains("uuid"));
}

#[test]
fn missing_port_is_rejected() {
    let err = VlessShareLink::parse(&format!("vless://{UUID}@host?type=ws")).unwrap_err();
    assert!(format!("{err:#}").contains(":port"));
}

#[test]
fn non_none_encryption_is_rejected() {
    let err =
        VlessShareLink::parse(&format!("vless://{UUID}@host:443?type=ws&encryption=aes-128-gcm"))
            .unwrap_err();
    assert!(format!("{err:#}").contains("encryption"));
}

#[test]
fn xtls_flow_is_rejected() {
    let err = VlessShareLink::parse(&format!(
        "vless://{UUID}@host:443?type=ws&flow=xtls-rprx-vision"
    ))
    .unwrap_err();
    assert!(format!("{err:#}").contains("flow"));
}

#[test]
fn empty_flow_is_accepted() {
    parse(&format!("vless://{UUID}@host:443?type=ws&security=tls&flow="));
}

#[test]
fn divergent_sni_is_rejected() {
    let err = VlessShareLink::parse(&format!(
        "vless://{UUID}@host:443?type=ws&security=tls&sni=other.example.com"
    ))
    .unwrap_err();
    assert!(format!("{err:#}").contains("sni"));
}

#[test]
fn divergent_host_header_is_rejected() {
    let err = VlessShareLink::parse(&format!(
        "vless://{UUID}@host:443?type=ws&security=tls&host=other.example.com"
    ))
    .unwrap_err();
    assert!(format!("{err:#}").contains("host"));
}

#[test]
fn matching_sni_is_accepted() {
    parse(&format!(
        "vless://{UUID}@host:443?type=ws&security=tls&sni=host&host=host"
    ));
}

#[test]
fn type_tcp_is_rejected_with_clear_message() {
    let err = VlessShareLink::parse(&format!("vless://{UUID}@host:443?type=tcp")).unwrap_err();
    assert!(format!("{err:#}").contains("type=tcp"));
}

#[test]
fn unknown_type_is_rejected() {
    let err =
        VlessShareLink::parse(&format!("vless://{UUID}@host:443?type=splice")).unwrap_err();
    assert!(format!("{err:#}").contains("splice"));
}

#[test]
fn security_reality_maps_to_tls_scheme() {
    let link = parse(&format!("vless://{UUID}@host:443?type=ws&security=reality"));
    let url = link.vless_ws_url.expect("ws url");
    assert_eq!(url.scheme(), "wss");
}

#[test]
fn link_without_scheme_is_rejected() {
    let err = VlessShareLink::parse(&format!("{UUID}@host:443?type=ws")).unwrap_err();
    assert!(format!("{err:#}").contains("vless://"));
}

#[test]
fn percent_encoded_path_is_decoded_into_url_path() {
    let link = parse(&format!(
        "vless://{UUID}@host:443?type=ws&security=tls&path=%2Fa%2Fb%2Fc"
    ));
    assert_eq!(link.vless_ws_url.unwrap().path(), "/a/b/c");
}

#[test]
fn path_without_leading_slash_is_normalised() {
    let link = parse(&format!(
        "vless://{UUID}@host:443?type=ws&security=tls&path=secret%2Fvless"
    ));
    assert_eq!(link.vless_ws_url.unwrap().path(), "/secret/vless");
}

#[test]
fn path_falls_back_to_uri_path_when_query_missing() {
    let link = parse(&format!("vless://{UUID}@host:443/legacy/path?type=ws&security=tls"));
    assert_eq!(link.vless_ws_url.unwrap().path(), "/legacy/path");
}

#[test]
fn empty_fragment_does_not_become_name() {
    let link = parse(&format!("vless://{UUID}@host:443?type=ws&security=tls#"));
    assert!(link.name.is_none());
}
