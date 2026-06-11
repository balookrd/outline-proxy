use crate::config::CipherKind;
use crate::crypto::{CryptoError, UserKey};

#[test]
fn rejects_bad_ss2022_psk_length() {
    let error = UserKey::new("alice", "c2hvcnQ=", None, CipherKind::Aes256Gcm2022).unwrap_err();
    assert!(matches!(error, CryptoError::InvalidPskLength { .. }));
}
