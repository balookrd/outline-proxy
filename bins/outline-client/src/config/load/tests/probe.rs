use super::*;

#[test]
fn parse_tls_target_accepts_full_https_url() {
    let t = parse_tls_target("https://www.youtube.com/").unwrap();
    assert_eq!(t.host, "www.youtube.com");
    assert_eq!(t.port, 443);
}

#[test]
fn parse_tls_target_accepts_https_url_with_explicit_port() {
    let t = parse_tls_target("https://www.youtube.com:8443/some/path").unwrap();
    assert_eq!(t.host, "www.youtube.com");
    assert_eq!(t.port, 8443);
}

#[test]
fn parse_tls_target_accepts_bare_host() {
    let t = parse_tls_target("www.youtube.com").unwrap();
    assert_eq!(t.host, "www.youtube.com");
    assert_eq!(t.port, 443);
}

#[test]
fn parse_tls_target_accepts_host_port() {
    let t = parse_tls_target("www.youtube.com:8443").unwrap();
    assert_eq!(t.host, "www.youtube.com");
    assert_eq!(t.port, 8443);
}

#[test]
fn parse_tls_target_accepts_bracketed_ipv6() {
    let t = parse_tls_target("[::1]:8443").unwrap();
    assert_eq!(t.host, "::1");
    assert_eq!(t.port, 8443);
}

#[test]
fn parse_tls_target_rejects_http_scheme() {
    let err = parse_tls_target("http://example.com/").unwrap_err();
    let msg = format!("{err:#}");
    assert!(
        msg.contains("scheme must be https") && msg.contains("[outline.probe.http]"),
        "expected error to point at [outline.probe.http]; got: {msg}"
    );
}
