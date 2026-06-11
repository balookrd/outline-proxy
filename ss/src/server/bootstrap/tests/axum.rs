use super::{TlsHandshakeFailReason, classify_tls_handshake_error};

#[test]
fn tls_handshake_unexpected_eof_is_closed_early() {
    let error = std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "tls handshake eof");
    assert!(matches!(
        classify_tls_handshake_error(&error),
        TlsHandshakeFailReason::ClosedEarly
    ));
}

#[test]
fn tls_handshake_protocol_failure_is_not_closed_early() {
    let error = std::io::Error::other("received corrupt message");
    assert!(!matches!(
        classify_tls_handshake_error(&error),
        TlsHandshakeFailReason::ClosedEarly
    ));
}

#[test]
fn no_cert_chain_resolved_is_classified() {
    // rustls wraps `Error::General(...)` with `io::ErrorKind::InvalidData`
    // when `ResolvesServerCert::resolve` returns `None`. Verify the
    // classifier still picks it up — if upstream rustls rephrases the
    // string this test fails loudly and the bucket falls back to
    // `protocol_error` until the matcher is updated.
    let inner = rustls::Error::General("no server certificate chain resolved".to_owned());
    let error = std::io::Error::new(std::io::ErrorKind::InvalidData, inner);
    assert!(matches!(
        classify_tls_handshake_error(&error),
        TlsHandshakeFailReason::NoCertChain
    ));
}

#[test]
fn other_invalid_data_is_protocol_error() {
    let inner = rustls::Error::General("some other rustls failure".to_owned());
    let error = std::io::Error::new(std::io::ErrorKind::InvalidData, inner);
    assert!(matches!(
        classify_tls_handshake_error(&error),
        TlsHandshakeFailReason::ProtocolError
    ));
}
