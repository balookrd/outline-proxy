use std::sync::Arc;

use outline_net::IpAliasTable;

use crate::config::CipherKind;
use crate::crypto::{CryptoError, UserKey};

#[test]
fn rejects_bad_ss2022_psk_length() {
    let error =
        UserKey::new("alice", "c2hvcnQ=", None, CipherKind::Aes256Gcm2022, None).unwrap_err();
    assert!(matches!(error, CryptoError::InvalidPskLength { .. }));
}

#[test]
fn rejects_bad_ss2022_psk_base64() {
    let error =
        UserKey::new("alice", "not base64!", None, CipherKind::Aes256Gcm2022, None).unwrap_err();
    assert!(matches!(error, CryptoError::InvalidBase64Key));
}

#[test]
fn rejects_empty_classic_password() {
    let error = UserKey::new("alice", "", None, CipherKind::Aes256Gcm, None).unwrap_err();
    assert!(matches!(error, CryptoError::EmptyPassword));
}

#[test]
fn classic_password_round_trips_through_matches_password() {
    let key = UserKey::new("alice", "foobar", None, CipherKind::Aes256Gcm, None).unwrap();
    assert!(key.matches_password("foobar").unwrap());
    assert!(!key.matches_password("other").unwrap());
    assert!(key.matches_password("").is_err());
}

#[test]
fn effective_label_picks_alias_by_source_ip() {
    let cidrs = ["192.0.2.0/24".to_string()];
    let table = IpAliasTable::build([("office", cidrs.as_slice())]).unwrap();
    let key =
        UserKey::new("base", "foobar", None, CipherKind::Aes256Gcm, Some(Arc::new(table))).unwrap();
    // In-subnet source IP relabels to the alias.
    assert_eq!(&*key.effective_label(Some("192.0.2.7".parse().unwrap())), "office");
    // Out-of-subnet falls back to the base id.
    assert_eq!(&*key.effective_label(Some("198.51.100.1".parse().unwrap())), "base");
    // Absent peer falls back to the base id.
    assert_eq!(&*key.effective_label(None), "base");
}

#[test]
fn effective_label_without_aliases_is_base_id() {
    let key = UserKey::new("base", "foobar", None, CipherKind::Aes256Gcm, None).unwrap();
    assert_eq!(&*key.effective_label(Some("192.0.2.7".parse().unwrap())), "base");
}
