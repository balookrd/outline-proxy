//! The client config, and the session-ticket store inside it, live for the
//! whole process: a server is resumed for as long as its tickets are valid.

use std::sync::Arc;

use rustls::client::WebPkiServerVerifier;

use super::*;
use crate::tests::client_hello::server_config;
use crate::tls_hello::{BrowserVerifier, build_shaped_client_config};

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

/// One full exchange between a fresh client and server connection built from
/// the shared configs; returns how the client's handshake went.
fn handshake_kind(
    client: &Arc<ClientConfig>,
    server: &Arc<rustls::ServerConfig>,
) -> rustls::HandshakeKind {
    let name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
    let mut client: rustls::Connection = rustls::ClientConnection::new(Arc::clone(client), name)
        .unwrap()
        .into();
    let mut server: rustls::Connection =
        rustls::ServerConnection::new(Arc::clone(server)).unwrap().into();
    // Enough rounds for the handshake and for the tickets that follow it.
    for _ in 0..8 {
        pump(&mut client, &mut server);
        pump(&mut server, &mut client);
    }
    assert!(!client.is_handshaking());
    let rustls::Connection::Client(client) = &client else { unreachable!() };
    client.handshake_kind().expect("handshake finished")
}

/// The same `(fingerprint, ALPN)` yields the same config object — and so the
/// same ticket store — on every call. The ALPN values are unique to this test
/// so no other test shares the cache entries.
#[test]
fn a_client_config_is_built_once_per_key() {
    let alpn: &[&[u8]] = &[b"tls-cache-test"];
    for fp in [None, Some(TlsFingerprint::Firefox)] {
        let first = build_client_config_for(fp, alpn);
        assert!(Arc::ptr_eq(&first, &build_client_config_for(fp, alpn)), "tcp, {fp:?}");
        #[cfg(feature = "quic")]
        {
            let first = build_quic_client_config(fp, alpn);
            assert!(Arc::ptr_eq(&first, &build_quic_client_config(fp, alpn)), "quic, {fp:?}");
        }
    }
    // A different key is a different config.
    let other = build_client_config_for(None, &[b"tls-cache-test-other"]);
    assert!(!Arc::ptr_eq(&other, &build_client_config_for(None, alpn)));
}

/// What keeping the config buys: the second connection to a server resumes
/// the first one's session instead of running a full handshake. Uses a config
/// shaped like the dial path's, with its own trust root so the test does not
/// depend on the process-wide test-root override.
#[test]
fn a_kept_config_resumes_the_second_handshake() {
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let cert = rcgen::CertificateParams::new(vec!["localhost".into()])
        .unwrap()
        .self_signed(&key)
        .unwrap();
    let server = Arc::new(server_config(
        &[&rustls::version::TLS13],
        None,
        cert.der().clone(),
        key.serialize_der(),
    ));

    for fp in [None, Some(TlsFingerprint::Firefox)] {
        let profile = crate::tcp_tls_profile::for_fingerprint(fp);
        let mut roots = RootCertStore::empty();
        roots.add(cert.der().clone()).unwrap();
        let inner = WebPkiServerVerifier::builder_with_provider(
            Arc::new(roots),
            Arc::new(profile.provider()),
        )
        .build()
        .unwrap();
        let verifier = Arc::new(BrowserVerifier::new(inner, profile.sig_schemes));
        let client = build_shaped_client_config(profile, &[b"h2"], verifier);

        assert_eq!(handshake_kind(&client, &server), rustls::HandshakeKind::Full, "{fp:?}");
        assert_eq!(handshake_kind(&client, &server), rustls::HandshakeKind::Resumed, "{fp:?}");
    }
}
