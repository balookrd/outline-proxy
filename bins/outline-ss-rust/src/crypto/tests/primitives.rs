use super::super::error::CryptoError;
use super::super::primitives::{MAX_NONCE_COUNTER, next_stream_nonce};

#[test]
fn next_stream_nonce_rejects_after_threshold() {
    let mut counter = MAX_NONCE_COUNTER - 1;
    assert!(next_stream_nonce(&mut counter).is_ok());
    assert_eq!(counter, MAX_NONCE_COUNTER);
    assert!(matches!(next_stream_nonce(&mut counter), Err(CryptoError::NonceExhausted)));
    // Counter must not advance past the limit on subsequent calls.
    assert_eq!(counter, MAX_NONCE_COUNTER);
    assert!(matches!(next_stream_nonce(&mut counter), Err(CryptoError::NonceExhausted)));
}
