//! Unit tests for the cert-expiry parser and accept-any TLS config.

use std::sync::Arc;

use super::{accept_any_client_config_for, leaf_not_after_unix_ms};
use crate::fingerprint_profile::TlsFingerprint;
use crate::tests::client_hello::{
    alpn_protocols, capture_tcp_hello, handshake, ja4, ja4_without_grease_sigalgs, server_config,
};

/// DER of a self-signed P-256 certificate (`CN=cert-check-fixture.test`)
/// generated with a fixed validity window:
///
/// ```text
/// openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
///   -nodes -days 36500 -subj "/CN=cert-check-fixture.test" | \
/// openssl x509 -outform DER -out fixture_cert.der
/// ```
///
/// notAfter = 2126-05-09 15:45:52 UTC = 4_934_015_152 s.
const FIXTURE_DER: &[u8] = include_bytes!("fixture_cert.der");
const FIXTURE_NOT_AFTER_MS: u64 = 4_934_015_152_000;

#[test]
fn parses_not_after_from_fixture() {
    let ms = leaf_not_after_unix_ms(FIXTURE_DER).expect("fixture must parse");
    assert_eq!(ms, FIXTURE_NOT_AFTER_MS);
}

#[test]
fn rejects_non_certificate_bytes() {
    assert!(leaf_not_after_unix_ms(b"not a certificate at all").is_err());
    assert!(leaf_not_after_unix_ms(&[]).is_err());
}

#[test]
fn accept_any_config_builds() {
    // Building the accept-any client config must not panic: the profile provider,
    // TLS 1.3 only, and the custom verifier wired in.
    let cfg = accept_any_client_config_for(None);
    assert!(!cfg.alpn_protocols.iter().any(|p| p.is_empty()));
}

#[test]
fn cert_check_hello_is_browser_shaped() {
    // No fingerprint = Chromium, as for the carrier dials.
    let hello = capture_tcp_hello(accept_any_client_config_for(None), "localtest.me");
    let stable = ja4_without_grease_sigalgs(&hello);
    println!("cert_check chromium: ja4 {} / without GREASE sigalgs {stable}", ja4(&hello));
    assert_eq!(stable, "t13d1517h2_8daaf6152771_cb7bf5808d99");
    assert_eq!(alpn_protocols(&hello), vec![b"h2".to_vec(), b"http/1.1".to_vec()]);

    let hello = capture_tcp_hello(
        accept_any_client_config_for(Some(TlsFingerprint::Firefox)),
        "localtest.me",
    );
    println!("cert_check firefox: ja4 {}", ja4(&hello));
    assert_eq!(ja4(&hello), "t13d1517h2_8daaf6152771_3cbfd9057e0d");

    let hello = capture_tcp_hello(
        accept_any_client_config_for(Some(TlsFingerprint::Safari)),
        "localtest.me",
    );
    println!("cert_check safari: ja4 {}", ja4(&hello));
    assert_eq!(ja4(&hello), "t13d2013h2_a09f3c656075_7f0f34a4126d");
}

#[test]
fn cert_check_accepts_an_expired_certificate() {
    // A self-signed certificate that expired in 2020: the handshake still completes
    // under the browser hello and the leaf's notAfter is readable.
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let mut params = rcgen::CertificateParams::new(vec!["localhost".into()]).unwrap();
    params.not_before = rcgen::date_time_ymd(2019, 1, 1);
    params.not_after = rcgen::date_time_ymd(2020, 1, 1);
    let cert = params.self_signed(&key).unwrap();
    let der = cert.der().clone();

    for fp in [None, Some(TlsFingerprint::Firefox), Some(TlsFingerprint::Safari)] {
        let mut server =
            server_config(&[&rustls::version::TLS13], None, der.clone(), key.serialize_der());
        server.alpn_protocols = vec![b"h2".to_vec()];
        let (client, _) = handshake(accept_any_client_config_for(fp), server)
            .unwrap_or_else(|e| panic!("{fp:?}: {e:?}"));
        let leaf = client.peer_certificates().unwrap()[0].as_ref().to_vec();
        assert_eq!(leaf_not_after_unix_ms(&leaf).unwrap(), 1_577_836_800_000, "{fp:?}");
        assert_eq!(client.alpn_protocol(), Some(&b"h2"[..]), "{fp:?}");
    }
}

/// Moves everything `from` has to say into `to`.
fn pump(from: &mut rustls::Connection, to: &mut rustls::Connection) {
    let mut buf = Vec::new();
    while from.wants_write() {
        from.write_tls(&mut buf).unwrap();
    }
    let mut rd = std::io::Cursor::new(buf);
    while (rd.position() as usize) < rd.get_ref().len() {
        to.read_tls(&mut rd).unwrap();
        to.process_new_packets().unwrap();
    }
}

#[test]
fn cert_check_configs_do_not_resume() {
    // A resumed handshake carries no Certificate, so a cached config that resumed would
    // report a renewed certificate's old notAfter. Same server config (and ticket
    // store) for both handshakes; both must be full.
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let cert = rcgen::CertificateParams::new(vec!["localhost".into()])
        .unwrap()
        .self_signed(&key)
        .unwrap();
    let server_cfg = Arc::new(server_config(
        &[&rustls::version::TLS13],
        None,
        cert.der().clone(),
        key.serialize_der(),
    ));
    let client_cfg = accept_any_client_config_for(None);
    for round in 0..2 {
        let name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
        let mut client: rustls::Connection =
            rustls::ClientConnection::new(Arc::clone(&client_cfg), name)
                .unwrap()
                .into();
        let mut server: rustls::Connection =
            rustls::ServerConnection::new(Arc::clone(&server_cfg)).unwrap().into();
        for _ in 0..8 {
            pump(&mut client, &mut server);
            pump(&mut server, &mut client);
        }
        assert!(!client.is_handshaking(), "round {round}");
        let rustls::Connection::Client(c) = &client else { unreachable!() };
        assert_eq!(c.handshake_kind(), Some(rustls::HandshakeKind::Full), "round {round}");
    }
}
