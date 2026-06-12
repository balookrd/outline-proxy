use crate::config::CipherKind;
use crate::crypto::{CryptoError, UserKey};

#[test]
fn rejects_bad_ss2022_psk_length() {
    let error = UserKey::new("alice", "c2hvcnQ=", None, CipherKind::Aes256Gcm2022).unwrap_err();
    assert!(matches!(error, CryptoError::InvalidPskLength { .. }));
}

#[test]
fn rejects_bad_ss2022_psk_base64() {
    let error = UserKey::new("alice", "not base64!", None, CipherKind::Aes256Gcm2022).unwrap_err();
    assert!(matches!(error, CryptoError::InvalidBase64Key));
}

#[test]
fn rejects_empty_classic_password() {
    let error = UserKey::new("alice", "", None, CipherKind::Aes256Gcm).unwrap_err();
    assert!(matches!(error, CryptoError::EmptyPassword));
}

#[test]
fn classic_password_round_trips_through_matches_password() {
    let key = UserKey::new("alice", "foobar", None, CipherKind::Aes256Gcm).unwrap();
    assert!(key.matches_password("foobar").unwrap());
    assert!(!key.matches_password("other").unwrap());
    assert!(key.matches_password("").is_err());
}
