use super::super::error::CryptoError;
use super::super::primitives::{MAX_NONCE_COUNTER, derive_subkey, next_stream_nonce};
use crate::config::CipherKind;

// The ring-path session subkey is derived per stream into a stack buffer.
// It must carry zeroize-on-drop semantics so the key does not survive in a
// reclaimed stack frame (core dump, swap, memory disclosure).
#[test]
fn derive_subkey_returns_zeroizing_key_material() {
    let subkey = derive_subkey(CipherKind::Aes256Gcm, &[7u8; 32], &[9u8; 32]).unwrap();
    let ty = std::any::type_name_of_val(&subkey);
    assert!(
        ty.contains("zeroize::Zeroizing<"),
        "session subkey must be wrapped in Zeroizing, got `{ty}`"
    );
    assert_ne!(subkey[..CipherKind::Aes256Gcm.key_len()], [0u8; 32]);
}

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
