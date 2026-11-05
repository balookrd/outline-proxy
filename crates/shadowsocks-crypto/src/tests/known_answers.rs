//! Known-answer tests pinning the bytes on the wire.
//!
//! The expected values were captured with the previous RustCrypto line
//! (aes 0.8 / aes-gcm 0.10 / chacha20poly1305 0.10 / hkdf 0.12 / sha1 0.10)
//! before the bump to 0.11. Round-trip tests cannot catch a change both sides
//! make the same way, and the fleet always runs a mix of old and new builds
//! while a rollout is in progress, so the ciphertext itself is pinned here.
//! Long outputs are pinned by their BLAKE3 digest to keep the table short.

use crate::cipher_kind::CipherKind;
use crate::ss2022_udp::seal_xchacha_packet;
use crate::{AeadCipher, decrypt_udp_separate_header, derive_subkey, encrypt_udp_separate_header};

/// Deterministic test bytes: `i * 7 + seed`, wrapping.
fn pattern(len: usize, seed: u8) -> Vec<u8> {
    (0..len)
        .map(|i| (i as u8).wrapping_mul(7).wrapping_add(seed))
        .collect()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Full hex for short outputs, `b3:<digest>` for long ones.
fn fingerprint(bytes: &[u8]) -> String {
    if bytes.len() <= 64 {
        hex(bytes)
    } else {
        format!("b3:{}", blake3::hash(bytes).to_hex())
    }
}

const AEAD_CASES: &[(CipherKind, usize, &str)] = &[
    (CipherKind::Chacha20IetfPoly1305, 0, "eae97e2e5487879285819bfc7fa50f5f"),
    (CipherKind::Chacha20IetfPoly1305, 1, "3df3b815efdf1ea2c69429d334cd8d7dd5"),
    (
        CipherKind::Chacha20IetfPoly1305,
        15,
        "3d19e91cce729f178b21ac6845646bcbf3cd1e500700d04d6a13b19faa6404",
    ),
    (
        CipherKind::Chacha20IetfPoly1305,
        16,
        "3d19e91cce729f178b21ac6845646b192ff08c15ed8445cf29ce027d5994c683",
    ),
    (
        CipherKind::Chacha20IetfPoly1305,
        33,
        "3d19e91cce729f178b21ac6845646b19a3fef1284545f8d94ce3da541d80bacc222b97c7433f5abad16c82bb305abe5566",
    ),
    (
        CipherKind::Chacha20IetfPoly1305,
        1400,
        "b3:20624d3463099432254d72d0a6c45686884281c2d48d9445d09d7643be5453b1",
    ),
    (
        CipherKind::Chacha20IetfPoly1305,
        16384,
        "b3:6852d07d829440611b9e6925287170cd5491d72dad42876458c85d752cce9cf1",
    ),
    (CipherKind::Aes128Gcm, 0, "bb5dc43c6a232107527ce7126c1bc15c"),
    (CipherKind::Aes128Gcm, 1, "56b500e06e0cee28c4822f57f1223b7295"),
    (
        CipherKind::Aes128Gcm,
        15,
        "56e1ceb7cd14ae8abe28c0b140cfaec4a551561cb0501d3b37c932a78d6c71",
    ),
    (
        CipherKind::Aes128Gcm,
        16,
        "56e1ceb7cd14ae8abe28c0b140cfae9d203a03216f0ab0aafe929eb95b2087c7",
    ),
    (
        CipherKind::Aes128Gcm,
        33,
        "56e1ceb7cd14ae8abe28c0b140cfae9d806a01ad16a3fe0c4daed414f2b3fd10bb8ab264132fe679f878a47b8498df2db5",
    ),
    (
        CipherKind::Aes128Gcm,
        1400,
        "b3:41b72d00a4d508cfd370854a35b31e279573b080ce8b9a6ef9ce4d8756afafe5",
    ),
    (
        CipherKind::Aes128Gcm,
        16384,
        "b3:260527bf3a3a8422e28541cd1c62984ad7f88eef224be29825bf85719949748d",
    ),
    (CipherKind::Aes256Gcm, 0, "6117d9fd1e39065d3146a6dc2fa8b9cd"),
    (CipherKind::Aes256Gcm, 1, "1a8fa62a6d85fbc06312e225140c42b5a9"),
    (
        CipherKind::Aes256Gcm,
        15,
        "1aa9cdc915450c963ccdbb941e301f83e0ded2ca6dbb68aa24c973706a1b00",
    ),
    (
        CipherKind::Aes256Gcm,
        16,
        "1aa9cdc915450c963ccdbb941e301f4f278a7ffa1a27a3d6b98e6ca16c072c59",
    ),
    (
        CipherKind::Aes256Gcm,
        33,
        "1aa9cdc915450c963ccdbb941e301f4feb5296e06534c6acefd6252f8a2dd46f15fc54f568eed8e8df584749e804e76700",
    ),
    (
        CipherKind::Aes256Gcm,
        1400,
        "b3:d3fcfc3fc82ee8f961bf18864d64b2b3be092a545baa03ea56ba66afec65d06d",
    ),
    (
        CipherKind::Aes256Gcm,
        16384,
        "b3:68c0ce03bbc79882014203e9812379c69c10d2df5dd1bb9142901e57cb1d6477",
    ),
];

const SUBKEY_CASES: &[(CipherKind, &str)] = &[
    (
        CipherKind::Chacha20IetfPoly1305,
        "d98bfbd6161b47e05cfb491c1cc03ff4975bfe0f127903022a14c75dc3c3db59",
    ),
    (CipherKind::Aes128Gcm, "1ad72746697e852ffcaab46260f4e4d4"),
    (
        CipherKind::Aes256Gcm,
        "d98bfbd6161b47e05cfb491c1cc03ff4975bfe0f127903022a14c75dc3c3db59",
    ),
    (CipherKind::Aes128Gcm2022, "fef1a7efb5c274661453b6a8abbb5763"),
    (
        CipherKind::Aes256Gcm2022,
        "c791b0de907fe80ec88b0c5b1654686c9e23ee7ff4e0d3c5c14d733d4ac7013a",
    ),
    (
        CipherKind::Chacha20Poly13052022,
        "c791b0de907fe80ec88b0c5b1654686c9e23ee7ff4e0d3c5c14d733d4ac7013a",
    ),
];

const SEPARATE_HEADER_CASES: &[(CipherKind, &str)] = &[
    (CipherKind::Aes128Gcm2022, "d6e0008976e5e9e462ea36b6d30c4a15"),
    (CipherKind::Aes256Gcm2022, "9ca83d75310a3eaf4bb81df2c08981ce"),
];

const XCHACHA_CASES: &[(usize, &str)] = &[
    (
        0,
        "0910171e252c333a41484f565d646b727980878e959ca3aac5d5853e3fb8afc0313cf907466e8716",
    ),
    (
        1,
        "0910171e252c333a41484f565d646b727980878e959ca3aa07a767883cca244b6fff438089e223b9c9",
    ),
    (33, "b3:93bb0763dd96ee00fe6be206053310c247ea3593b8b7fc42d5dfc085bc89e9c7"),
    (1400, "b3:8e328b5dbfd754236c7740a0a90881e6dece6aeca3974f2e8d26ecc1da24d271"),
];

fn aead_case(cipher: CipherKind, len: usize) -> (Vec<u8>, Vec<u8>, String) {
    let key = pattern(cipher.key_len(), 0x11);
    let nonce: [u8; 12] = pattern(12, 0x5a).try_into().unwrap();
    let plaintext = pattern(len, 0x33);
    let aead = AeadCipher::new(cipher, &key).unwrap();
    let ciphertext = aead.encrypt(&nonce, &plaintext).unwrap();
    let mut into = b"prefix".to_vec();
    aead.encrypt_into(&nonce, &plaintext, &mut into).unwrap();
    assert_eq!(&into[6..], &ciphertext[..], "encrypt_into must match encrypt");
    let fp = fingerprint(&ciphertext);
    (plaintext, ciphertext, fp)
}

#[test]
fn aead_ciphertext_matches_the_pinned_bytes() {
    for &(cipher, len, want) in AEAD_CASES {
        let (plaintext, ciphertext, fp) = aead_case(cipher, len);
        assert_eq!(fp, want, "{cipher:?} len={len}");
        let key = pattern(cipher.key_len(), 0x11);
        let nonce: [u8; 12] = pattern(12, 0x5a).try_into().unwrap();
        let aead = AeadCipher::new(cipher, &key).unwrap();
        assert_eq!(aead.decrypt(&nonce, &ciphertext).unwrap(), plaintext, "{cipher:?} len={len}");
        let mut tampered = ciphertext.clone();
        *tampered.last_mut().unwrap() ^= 1;
        assert!(
            aead.decrypt(&nonce, &tampered).is_err(),
            "{cipher:?} len={len}: bad tag accepted"
        );
    }
}

#[test]
fn session_subkeys_match_the_pinned_bytes() {
    for &(cipher, want) in SUBKEY_CASES {
        let master = pattern(cipher.key_len(), 0x21);
        let salt = pattern(cipher.salt_len(), 0x42);
        let subkey = derive_subkey(cipher, &master, &salt).unwrap();
        assert_eq!(hex(&subkey[..cipher.key_len()]), want, "{cipher:?}");
    }
}

#[test]
fn ss2022_separate_header_matches_the_pinned_bytes() {
    for &(cipher, want) in SEPARATE_HEADER_CASES {
        let master = pattern(cipher.key_len(), 0x21);
        let header: [u8; 16] = pattern(16, 0x70).try_into().unwrap();
        let enc = encrypt_udp_separate_header(cipher, &master, &header).unwrap();
        assert_eq!(hex(&enc), want, "{cipher:?}");
        assert_eq!(decrypt_udp_separate_header(cipher, &master, &enc).unwrap(), header);
    }
}

#[test]
fn ss2022_xchacha_packet_matches_the_pinned_bytes() {
    for &(len, want) in XCHACHA_CASES {
        let master = pattern(32, 0x21);
        let nonce: [u8; 24] = pattern(24, 0x09).try_into().unwrap();
        let packet = seal_xchacha_packet(&master, &nonce, &pattern(len, 0x33)).unwrap();
        assert_eq!(fingerprint(&packet), want, "len={len}");
    }
}

#[test]
#[ignore = "prints the table; run with --ignored to regenerate"]
fn print_known_answers() {
    let ciphers = [CipherKind::Chacha20IetfPoly1305, CipherKind::Aes128Gcm, CipherKind::Aes256Gcm];
    for cipher in ciphers {
        for len in [0usize, 1, 15, 16, 33, 1400, 16384] {
            let (_, _, fp) = aead_case(cipher, len);
            println!("    (CipherKind::{cipher:?}, {len}, \"{fp}\"),");
        }
    }
    for cipher in all_ciphers() {
        let master = pattern(cipher.key_len(), 0x21);
        let salt = pattern(cipher.salt_len(), 0x42);
        let subkey = derive_subkey(cipher, &master, &salt).unwrap();
        println!("    (CipherKind::{cipher:?}, \"{}\"),", hex(&subkey[..cipher.key_len()]));
    }
    for cipher in [CipherKind::Aes128Gcm2022, CipherKind::Aes256Gcm2022] {
        let master = pattern(cipher.key_len(), 0x21);
        let header: [u8; 16] = pattern(16, 0x70).try_into().unwrap();
        let enc = encrypt_udp_separate_header(cipher, &master, &header).unwrap();
        println!("    (CipherKind::{cipher:?}, \"{}\"),", hex(&enc));
    }
    for len in [0usize, 1, 33, 1400] {
        let master = pattern(32, 0x21);
        let nonce: [u8; 24] = pattern(24, 0x09).try_into().unwrap();
        let packet = seal_xchacha_packet(&master, &nonce, &pattern(len, 0x33)).unwrap();
        println!("    ({len}, \"{}\"),", fingerprint(&packet));
    }
}

fn all_ciphers() -> [CipherKind; 6] {
    [
        CipherKind::Chacha20IetfPoly1305,
        CipherKind::Aes128Gcm,
        CipherKind::Aes256Gcm,
        CipherKind::Aes128Gcm2022,
        CipherKind::Aes256Gcm2022,
        CipherKind::Chacha20Poly13052022,
    ]
}
