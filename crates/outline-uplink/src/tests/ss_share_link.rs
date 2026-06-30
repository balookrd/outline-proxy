use base64::Engine;

use crate::config::CipherKind;
use crate::ss_share_link::SsShareLink;
use outline_transport::TransportMode;

const METHOD: &str = "chacha20-ietf-poly1305";
const PASSWORD: &str = "Secret0";

/// SIP002 url-safe base64 (no padding) of `method:password`.
fn userinfo(method: &str, password: &str) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(format!("{method}:{password}"))
}

fn link(query: &str) -> String {
    format!("ss://{}@ss.example.com:443?{query}", userinfo(METHOD, PASSWORD))
}

fn parse(uri: &str) -> SsShareLink {
    SsShareLink::parse(uri).expect("valid ss share link")
}

#[test]
fn parses_ws_tls_h3_into_wss_combined_url() {
    let l = parse(&link("type=ws&security=tls&path=%2Fsecret%2Fss&alpn=h3#edge"));
    assert_eq!(l.cipher, CipherKind::Chacha20IetfPoly1305);
    assert_eq!(l.password, PASSWORD);
    assert_eq!(l.mode, TransportMode::WsH3);
    assert_eq!(l.name.as_deref(), Some("edge"));
    assert!(l.ss_xhttp_url.is_none());
    let url = l.ss_ws_url.expect("ws url present");
    assert_eq!(url.scheme(), "wss");
    assert_eq!(url.host_str(), Some("ss.example.com"));
    assert_eq!(url.port_or_known_default(), Some(443));
    assert_eq!(url.path(), "/secret/ss");
}

#[test]
fn type_defaults_to_ws() {
    let l = parse(&link("security=tls"));
    assert!(l.ss_ws_url.is_some());
    assert_eq!(l.mode, TransportMode::WsH1);
}

#[test]
fn ws_without_security_uses_plain_ws_scheme() {
    let l = parse(&format!("ss://{}@host:80?type=ws", userinfo(METHOD, PASSWORD)));
    let url = l.ss_ws_url.expect("ws url present");
    assert_eq!(url.scheme(), "ws");
    assert_eq!(l.mode, TransportMode::WsH1);
}

#[test]
fn ws_alpn_h2_picks_ws_h2_mode() {
    let l = parse(&link("type=ws&security=tls&alpn=h2"));
    assert_eq!(l.mode, TransportMode::WsH2);
}

#[test]
fn ws_alpn_first_token_wins_for_comma_lists() {
    let l = parse(&link("type=ws&security=tls&alpn=h3%2Ch2"));
    assert_eq!(l.mode, TransportMode::WsH3);
}

#[test]
fn xhttp_default_mode_is_h2() {
    let l = parse(&link("type=xhttp&security=tls"));
    assert!(l.ss_ws_url.is_none());
    let url = l.ss_xhttp_url.expect("xhttp url");
    assert_eq!(url.scheme(), "https");
    assert_eq!(l.mode, TransportMode::XhttpH2);
}

#[test]
fn xhttp_alpn_h3_picks_xhttp_h3_mode() {
    let l = parse(&link("type=xhttp&security=tls&alpn=h3"));
    assert_eq!(l.mode, TransportMode::XhttpH3);
    assert!(l.ss_xhttp_url.is_some());
}

#[test]
fn xhttp_alpn_h1_picks_xhttp_h1_mode() {
    let l = parse(&link("type=xhttp&security=tls&alpn=h1"));
    assert_eq!(l.mode, TransportMode::XhttpH1);

    let l = parse(&link("type=xhttp&security=tls&alpn=http%2F1.1"));
    assert_eq!(l.mode, TransportMode::XhttpH1);
}

#[test]
fn xhttp_submode_preserved_as_query_string() {
    let l = parse(&link("type=xhttp&security=tls&path=%2Fxhttp&mode=stream-one"));
    let url = l.ss_xhttp_url.expect("xhttp url");
    assert_eq!(url.path(), "/xhttp");
    assert_eq!(url.query(), Some("mode=stream-one"));
}

#[test]
fn aes_256_gcm_method_decodes() {
    let l = parse(&format!("ss://{}@host:443?type=ws&security=tls", userinfo("aes-256-gcm", "pw")));
    assert_eq!(l.cipher, CipherKind::Aes256Gcm);
    assert_eq!(l.password, "pw");
}

#[test]
fn ss2022_method_decodes() {
    let l = parse(&format!(
        "ss://{}@host:443?type=ws&security=tls",
        userinfo("2022-blake3-aes-256-gcm", "AAAAAAAAAAAAAAAAAAAAAA==")
    ));
    assert_eq!(l.cipher, CipherKind::Aes256Gcm2022);
}

#[test]
fn standard_base64_userinfo_is_accepted() {
    // Some encoders emit standard (non-url-safe) base64. With a `:` in the
    // payload there are no `+`/`/` chars here, so it round-trips either way.
    let standard =
        base64::engine::general_purpose::STANDARD_NO_PAD.encode(format!("{METHOD}:{PASSWORD}"));
    let l = parse(&format!("ss://{standard}@host:443?type=ws&security=tls"));
    assert_eq!(l.cipher, CipherKind::Chacha20IetfPoly1305);
    assert_eq!(l.password, PASSWORD);
}

#[test]
fn fragment_is_percent_decoded_into_name() {
    let l = parse(&link("type=ws&security=tls#edge%20one"));
    assert_eq!(l.name.as_deref(), Some("edge one"));
}

#[test]
fn empty_fragment_does_not_become_name() {
    let l = parse(&link("type=ws&security=tls#"));
    assert!(l.name.is_none());
}

#[test]
fn missing_userinfo_is_rejected() {
    let err = SsShareLink::parse("ss://host:443?type=ws").unwrap_err();
    assert!(format!("{err:#}").contains("userinfo"));
}

#[test]
fn plaintext_method_password_pair_is_rejected() {
    // Legacy `ss://method:password@host` (a `:` in authority) is not SIP002.
    let err =
        SsShareLink::parse("ss://chacha20-ietf-poly1305:Secret0@host:443?type=ws").unwrap_err();
    assert!(format!("{err:#}").to_lowercase().contains("base64"));
}

#[test]
fn unsupported_method_is_rejected() {
    let err = SsShareLink::parse(&format!("ss://{}@host:443?type=ws", userinfo("rc4-md5", "pw")))
        .unwrap_err();
    assert!(format!("{err:#}").contains("cipher"));
}

#[test]
fn invalid_base64_userinfo_is_rejected() {
    let err = SsShareLink::parse("ss://!!!notbase64!!!@host:443?type=ws").unwrap_err();
    assert!(format!("{err:#}").to_lowercase().contains("base64"));
}

#[test]
fn empty_password_is_rejected() {
    let err =
        SsShareLink::parse(&format!("ss://{}@host:443?type=ws", userinfo(METHOD, ""))).unwrap_err();
    assert!(format!("{err:#}").contains("password"));
}

#[test]
fn missing_port_is_rejected() {
    let err = SsShareLink::parse(&format!("ss://{}@host?type=ws", userinfo(METHOD, PASSWORD)))
        .unwrap_err();
    assert!(format!("{err:#}").contains(":port"));
}

#[test]
fn type_quic_is_rejected_with_clear_message() {
    let err = SsShareLink::parse(&link("type=quic&security=tls")).unwrap_err();
    assert!(format!("{err:#}").contains("type=quic"));
}

#[test]
fn type_tcp_is_rejected() {
    let err = SsShareLink::parse(&link("type=tcp")).unwrap_err();
    assert!(format!("{err:#}").contains("type=tcp"));
}

#[test]
fn unknown_type_is_rejected() {
    let err = SsShareLink::parse(&link("type=splice")).unwrap_err();
    assert!(format!("{err:#}").contains("splice"));
}

#[test]
fn security_reality_maps_to_tls_scheme() {
    let l = parse(&link("type=ws&security=reality"));
    assert_eq!(l.ss_ws_url.unwrap().scheme(), "wss");
}

#[test]
fn divergent_sni_is_rejected() {
    let err = SsShareLink::parse(&link("type=ws&security=tls&sni=other.example.com")).unwrap_err();
    assert!(format!("{err:#}").contains("sni"));
}

#[test]
fn matching_sni_is_accepted() {
    parse(&format!(
        "ss://{}@host:443?type=ws&security=tls&sni=host&host=host",
        userinfo(METHOD, PASSWORD)
    ));
}

#[test]
fn link_without_scheme_is_rejected() {
    let err = SsShareLink::parse(&format!("{}@host:443?type=ws", userinfo(METHOD, PASSWORD)))
        .unwrap_err();
    assert!(format!("{err:#}").contains("ss://"));
}

#[test]
fn path_without_leading_slash_is_normalised() {
    let l = parse(&link("type=ws&security=tls&path=secret%2Fss"));
    assert_eq!(l.ss_ws_url.unwrap().path(), "/secret/ss");
}

#[test]
fn path_falls_back_to_uri_path_when_query_missing() {
    let l = parse(&format!(
        "ss://{}@host:443/legacy/path?type=ws&security=tls",
        userinfo(METHOD, PASSWORD)
    ));
    assert_eq!(l.ss_ws_url.unwrap().path(), "/legacy/path");
}
