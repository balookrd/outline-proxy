use std::str::FromStr;

use super::*;

const ALL: [CipherKind; 6] = [
    CipherKind::Aes128Gcm,
    CipherKind::Aes256Gcm,
    CipherKind::Chacha20IetfPoly1305,
    CipherKind::Aes128Gcm2022,
    CipherKind::Aes256Gcm2022,
    CipherKind::Chacha20Poly13052022,
];

#[test]
fn str_roundtrip_all_kinds() {
    for kind in ALL {
        assert_eq!(CipherKind::from_str(kind.as_str()).unwrap(), kind);
        assert_eq!(kind.to_string(), kind.as_str());
    }
}

#[test]
fn rejects_unknown_method_string() {
    let err = CipherKind::from_str("rc4-md5").unwrap_err();
    assert_eq!(err, UnknownCipherError("rc4-md5".to_string()));
}

#[test]
fn key_and_salt_lengths() {
    assert_eq!(CipherKind::Aes128Gcm.key_len(), 16);
    assert_eq!(CipherKind::Aes128Gcm2022.key_len(), 16);
    assert_eq!(CipherKind::Aes256Gcm.key_len(), 32);
    assert_eq!(CipherKind::Chacha20IetfPoly1305.key_len(), 32);
    assert_eq!(CipherKind::Aes256Gcm2022.key_len(), 32);
    assert_eq!(CipherKind::Chacha20Poly13052022.key_len(), 32);
    for kind in ALL {
        assert_eq!(kind.salt_len(), kind.key_len());
    }
}

#[test]
fn ss2022_classification() {
    assert!(!CipherKind::Aes128Gcm.is_ss2022());
    assert!(!CipherKind::Aes256Gcm.is_ss2022());
    assert!(!CipherKind::Chacha20IetfPoly1305.is_ss2022());
    assert!(CipherKind::Aes128Gcm2022.is_ss2022());
    assert!(CipherKind::Aes256Gcm2022.is_ss2022());
    assert!(CipherKind::Chacha20Poly13052022.is_ss2022());

    assert!(CipherKind::Aes128Gcm2022.is_ss2022_aes());
    assert!(CipherKind::Aes256Gcm2022.is_ss2022_aes());
    assert!(!CipherKind::Chacha20Poly13052022.is_ss2022_aes());
    assert!(CipherKind::Chacha20Poly13052022.is_ss2022_chacha());
    assert!(!CipherKind::Aes128Gcm2022.is_ss2022_chacha());
}

#[test]
fn max_payload_lengths() {
    assert_eq!(CipherKind::Aes256Gcm.max_payload_len(), 0x3fff);
    assert_eq!(CipherKind::Aes256Gcm2022.max_payload_len(), 0xffff);
}

#[test]
fn serde_uses_canonical_method_names() {
    for kind in ALL {
        let json = format!("\"{}\"", kind.as_str());
        let parsed: CipherKind = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, kind);
        assert_eq!(serde_json::to_string(&kind).unwrap(), json);
    }
}

#[test]
fn serde_accepts_legacy_aliases() {
    let parsed: CipherKind = serde_json::from_str("\"aes128-gcm\"").unwrap();
    assert_eq!(parsed, CipherKind::Aes128Gcm);
    let parsed: CipherKind = serde_json::from_str("\"aes256-gcm\"").unwrap();
    assert_eq!(parsed, CipherKind::Aes256Gcm);
}
