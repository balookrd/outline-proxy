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

// Reference vectors computed independently with Python's hashlib
// (EVP_BytesToKey, MD5, no salt, one hash round).
#[test]
fn evp_bytes_to_key_matches_reference_vectors() {
    let key16 = evp_bytes_to_key(b"foobar", 16);
    assert_eq!(hex(&key16), "3858f62230ac3c915f300c664312c63f");
    let key32 = evp_bytes_to_key(b"foobar", 32);
    assert_eq!(hex(&key32), "3858f62230ac3c915f300c664312c63f568378529614d22ddb49237d2f60bfdf");
}

#[test]
fn derive_master_key_stretches_classic_passwords() {
    let key = CipherKind::Aes256Gcm.derive_master_key("foobar").unwrap();
    assert_eq!(hex(&key), "3858f62230ac3c915f300c664312c63f568378529614d22ddb49237d2f60bfdf");
}

#[test]
fn derive_master_key_decodes_ss2022_psk() {
    use base64::Engine;
    let psk = [7u8; 32];
    let encoded = base64::engine::general_purpose::STANDARD.encode(psk);
    let key = CipherKind::Aes256Gcm2022.derive_master_key(&encoded).unwrap();
    assert_eq!(key[..], psk[..]);

    let err = CipherKind::Aes256Gcm2022
        .derive_master_key("not base64!")
        .unwrap_err();
    assert!(matches!(err, MasterKeyError::InvalidBase64Psk(_)));

    let err = CipherKind::Aes256Gcm2022.derive_master_key("c2hvcnQ=").unwrap_err();
    assert!(matches!(err, MasterKeyError::PskLengthMismatch { got: 5, expected: 32 }));
}

// Master keys (the classic EVP stretch and the decoded SS2022 PSK alike)
// outlive the call that derives them and are copied into transports and
// user tables. They must carry zeroize-on-drop semantics so freed pages
// cannot leak them into a core dump or swap.
#[test]
fn evp_bytes_to_key_returns_zeroizing_key_material() {
    assert_zeroizing(&evp_bytes_to_key(b"foobar", 16), "EVP_BytesToKey output");
    assert_zeroizing(&evp_bytes_to_key(b"foobar", 32), "EVP_BytesToKey output");
}

// Zeroizing only wipes the buffer it still owns: a reallocation part-way
// through the stretch would drop an unwiped copy of the key blocks written
// so far. The output buffer must therefore be sized to whole MD5 blocks up
// front, for any requested length — not just the 16/32 the ciphers ask for.
#[test]
fn evp_bytes_to_key_never_reallocates_mid_stretch() {
    for key_len in 1..=64 {
        let key = evp_bytes_to_key(b"foobar", key_len);
        assert_eq!(key.len(), key_len);
        // Exactly the whole-block size means the buffer was allocated once,
        // up front. A grow part-way through would leave the amortized
        // doubled capacity instead — and an unwiped copy of the earlier
        // blocks in the freed allocation.
        assert_eq!(
            key.capacity(),
            key_len.div_ceil(16) * 16,
            "key_len {key_len}: capacity indicates a mid-stretch realloc"
        );
    }
}

#[test]
fn derive_master_key_returns_zeroizing_key_material() {
    use base64::Engine;

    let classic = CipherKind::Aes256Gcm.derive_master_key("foobar").unwrap();
    assert_zeroizing(&classic, "classic master key");

    let encoded = base64::engine::general_purpose::STANDARD.encode([7u8; 32]);
    let psk = CipherKind::Aes256Gcm2022.derive_master_key(&encoded).unwrap();
    assert_zeroizing(&psk, "ss2022 master key");
}

/// Type-level contract check: the value must be a `zeroize::Zeroizing`
/// wrapper, not a bare `Vec`/array. Asserting on the type name keeps this a
/// runtime assertion (a compile-time bound would turn a missing wrapper into
/// a build error instead of a test failure).
fn assert_zeroizing<T>(value: &T, what: &str) {
    let ty = std::any::type_name_of_val(value);
    assert!(
        ty.contains("zeroize::Zeroizing<"),
        "{what} must be wrapped in Zeroizing, got `{ty}`"
    );
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
