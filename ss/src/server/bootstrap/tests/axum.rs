use super::is_benign_tls_handshake_error;

#[test]
fn tls_handshake_unexpected_eof_is_benign() {
    let error = std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "tls handshake eof");
    assert!(is_benign_tls_handshake_error(&error));
}

#[test]
fn tls_handshake_protocol_failure_is_not_benign() {
    let error = std::io::Error::other("received corrupt message");
    assert!(!is_benign_tls_handshake_error(&error));
}
