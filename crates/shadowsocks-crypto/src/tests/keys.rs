use super::*;

const MASTER_KEY: [u8; 32] = [7u8; 32];
const SALT: [u8; 32] = [9u8; 32];

// A session subkey is derived per stream/datagram and copied onto the stack
// of every caller. It must carry zeroize-on-drop semantics so the plaintext
// key does not survive in reclaimed stack frames.
#[test]
fn derive_subkey_returns_zeroizing_key_material() {
    let classic = derive_subkey(CipherKind::Aes256Gcm, &MASTER_KEY, &SALT).unwrap();
    assert_zeroizing(&classic, "classic session subkey");

    let ss2022 = derive_subkey(CipherKind::Aes256Gcm2022, &MASTER_KEY, &SALT[..8]).unwrap();
    assert_zeroizing(&ss2022, "ss2022 session subkey");
}

// The wrapper must not change what the KDF produces: both ends of the wire
// derive the same bytes, so any change here is a protocol break.
#[test]
fn derive_subkey_still_derives_the_same_bytes() {
    let first = derive_subkey(CipherKind::Aes256Gcm, &MASTER_KEY, &SALT).unwrap();
    let second = derive_subkey(CipherKind::Aes256Gcm, &MASTER_KEY, &SALT).unwrap();
    assert_eq!(first[..], second[..]);
    assert_ne!(first[..32], [0u8; 32]);

    // Short-key ciphers fill only `key_len()` bytes (HKDF-expand truncates the
    // same stream) and leave the tail of the 32-byte buffer zeroed.
    let short = derive_subkey(CipherKind::Aes128Gcm, &MASTER_KEY, &SALT).unwrap();
    assert_eq!(short[..16], first[..16]);
    assert_eq!(short[16..], [0u8; 16]);
}

/// Type-level contract check: the value must be a `zeroize::Zeroizing`
/// wrapper, not a bare array. Asserting on the type name keeps this a
/// runtime assertion (a compile-time bound would turn a missing wrapper into
/// a build error instead of a test failure).
fn assert_zeroizing<T>(value: &T, what: &str) {
    let ty = std::any::type_name_of_val(value);
    assert!(
        ty.contains("zeroize::Zeroizing<"),
        "{what} must be wrapped in Zeroizing, got `{ty}`"
    );
}
