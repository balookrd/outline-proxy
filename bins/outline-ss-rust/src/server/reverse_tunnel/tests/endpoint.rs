use quinn::{ConnectionClose, ConnectionError, TransportErrorCode};

use super::*;

#[test]
fn crypto_code_range_bounds() {
    // QUIC maps TLS alerts to transport error codes 0x0100..0x0200.
    assert!(!is_crypto_code(0x0ff));
    assert!(is_crypto_code(0x100));
    assert!(is_crypto_code(0x12a)); // crypto(42) = bad_certificate
    assert!(is_crypto_code(0x1ff));
    assert!(!is_crypto_code(0x200));
    assert!(!is_crypto_code(0)); // NO_ERROR
}

#[test]
fn auth_failure_detects_crypto_range_close() {
    // A CONNECTION_CLOSE carrying a TLS alert (here certificate_unknown = 46)
    // is what `ws` sends when it rejects our client cert under mTLS.
    let close = ConnectionClose {
        error_code: TransportErrorCode::crypto(46),
        frame_type: None,
        reason: Default::default(),
    };
    assert!(is_auth_failure(&ConnectionError::ConnectionClosed(close)));
}

#[test]
fn auth_failure_ignores_non_crypto_conditions() {
    // Idle timeout / reset / local close are transient or benign, never auth.
    assert!(!is_auth_failure(&ConnectionError::TimedOut));
    assert!(!is_auth_failure(&ConnectionError::Reset));
    assert!(!is_auth_failure(&ConnectionError::LocallyClosed));
}
