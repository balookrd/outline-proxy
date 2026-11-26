# Дедупликация `shadowsocks-crypto` на `aws-lc-rs`, потоковый кодек и удаление `ring` (M3 — Подпроект 2) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Перевести `crates/shadowsocks-crypto` на единый C/ASM-движок `aws-lc-rs` (уже залинкованный во все бинари ради `rustls`/`quinn`), вынести в него общий потоковый чанковый/SS2022 кодек (`stream`), `StreamNonce` (`2^32`), `AesHeaderCipher` и `XChaChaCipher`, перевести `outline-server`, `outline-transport`, `outline-ui` и `outline-windows` с `ring` и полностью удалить крейт `ring` из монорепо.

**Architecture:** В корневой `Cargo.toml` добавляются `aws-lc-rs = { version = "1.19", default-features = false, features = ["aws-lc-sys", "alloc"] }` и `sha2 = "0.11"`, а `ring = "0.17"` удаляется после миграции всех четырёх потребителей. `shadowsocks-crypto` становится truly-shared крейтом: `AeadCipher` оборачивает `aws_lc_rs::aead::LessSafeKey` (`Send + Sync`), `derive_subkey` использует `aws_lc_rs::hkdf::HKDF_SHA1_FOR_LEGACY_USE_ONLY`, модуль `stream` реализует in-place упаковку/распаковку AEAD-чанков поверх `SealBuf` (`Vec<u8>` и `BytesMut`), а `ss2022_udp` экспортирует переиспользуемые `AesHeaderCipher` и `XChaChaCipher`. На сервере остаются только `UserKey`, `SessionKeyCache<Arc<AeadCipher>>`, multi-user перебор первого пакета/чанка и `diagnose`.

**Tech Stack:** Rust (Edition 2024), `aws-lc-rs` 1.19, `aes`, `chacha20poly1305` (`XChaCha20Poly1305`), `bytes`, `sha2`, `outline-wire`.

## Global Constraints

- Wire-формат пакетов и потоков (Shadowsocks Legacy + SS2022 TCP/UDP) остаётся побайтово неизменным; все зашитые векторы в `crates/shadowsocks-crypto/src/tests/known_answers.rs` обязаны проходить без изменений.
- По завершении плана `cargo tree --workspace --exclude sockudo-ws --exclude outline-windows -i ring` возвращает пустой вывод, а `ring` отсутствует в корневом `Cargo.toml` и всех `Cargo.toml` workspace.
- Лимит вызовов потокового AEAD на один ключ закреплён на `MAX_STREAM_NONCE_COUNTER = 1 << 32` (NIST SP 800-38D) одинаково на сервере и клиенте.
- После проверок и тестов на каждом шаге удалять `target/debug` (`rm -rf target/debug`).
- Все комментарии в Rust-коде — на английском языке; документация EN/RU обновляется синхронно парой.

---

## Карта файлов

- **Создаваемые файлы:**
  - `crates/shadowsocks-crypto/src/stream.rs` — `SealBuf`, `seal_payload_chunk`, `seal_legacy_chunks`, `seal_ss2022_response_first_frame`, `open_length_block`, `open_payload_in_place`, `drain_chunk_from_bytes`.
  - `crates/shadowsocks-crypto/src/tests/stream.rs` — unit-тесты потокового кодека для `Vec<u8>`, `BytesMut`, SS2022 response и лимитов размера/nonce.
- **Модифицируемые файлы в `shadowsocks-crypto` и `outline-transport`:**
  - `Cargo.toml` — добавление `aws-lc-rs`, `sha2`; удаление `ring` (на Task 3).
  - `crates/shadowsocks-crypto/Cargo.toml` — замена `aes-gcm`, `hkdf`, `sha1`, `md5` на `aws-lc-rs` и `bytes`.
  - `crates/shadowsocks-crypto/src/{lib.rs,error.rs,aead.rs,keys.rs,ss2022_udp.rs}` — миграция на `aws-lc-rs`, добавление `StreamNonce`, `AesHeaderCipher`, `XChaChaCipher`, `InvalidLengthHeader`, `InvalidChunkSize`, `InvalidHeaderLength`.
  - `crates/outline-transport/src/tcp_transport/{writer/mod.rs,reader/mod.rs}` — перевод на `StreamNonce` и `shadowsocks_crypto::stream`.
  - `crates/outline-transport/Cargo.toml`, `src/quic/tests/tls_config.rs`, `src/tests/client_hello.rs` — замена dev-зависимости `ring` на `aws-lc-rs`.
- **Модифицируемые / удаляемые файлы в `outline-server`, `outline-ui`, `outline-windows` и документации:**
  - Удаляются: `bins/outline-server/src/crypto/primitives.rs`, `bins/outline-server/src/crypto/tests/primitives.rs`.
  - `bins/outline-server/Cargo.toml`, `src/crypto/{mod.rs,error.rs,user_key.rs,session_cache.rs,ss2022_header.rs,stream.rs,udp.rs,diagnose.rs}` и `src/crypto/tests/{session_cache.rs,stream.rs}`, `src/server/bootstrap/cert_pin.rs`, `src/outbound.rs`, `src/server/nat/entry.rs`, `src/server/transport/xhttp/mod.rs`, `src/server/tests/resumption/cluster.rs`.
  - `bins/outline-ui/Cargo.toml`, `bins/outline-ui/src/auth.rs` — замена `ring::digest` на `aws_lc_rs::digest`.
  - `bins/outline-windows/Cargo.toml`, `bins/outline-windows/src/updater.rs`, `bins/outline-windows/README.md`, `bins/outline-windows/README.ru.md` — замена `ring::digest` на `sha2::Sha256` (+ синхронизация `crates/outline-tun/Cargo.toml` с `sha2 = { workspace = true }`).
  - `AGENTS.md`, `.github/workflows/ci.yml`, `bins/outline-server/docs/SESSION-RESUMPTION.md`, `bins/outline-server/docs/SESSION-RESUMPTION.ru.md`.

---

### Task 1: Перевод `shadowsocks-crypto` на `aws-lc-rs`, `StreamNonce`, `AesHeaderCipher` и `XChaChaCipher`

**Files:**
- Modify: `Cargo.toml`
- Modify: `crates/outline-tun/Cargo.toml`
- Modify: `crates/shadowsocks-crypto/Cargo.toml`
- Modify: `crates/shadowsocks-crypto/src/lib.rs`
- Modify: `crates/shadowsocks-crypto/src/error.rs`
- Modify: `crates/shadowsocks-crypto/src/aead.rs`
- Modify: `crates/shadowsocks-crypto/src/keys.rs`
- Modify: `crates/shadowsocks-crypto/src/ss2022_udp.rs`
- Modify: `crates/shadowsocks-crypto/src/tests/mod.rs`

**Interfaces:**
- Produces:
  - `shadowsocks_crypto::{AeadCipher, AesHeaderCipher, XChaChaCipher, StreamNonce, MAX_STREAM_NONCE_COUNTER, LEGACY_MAX_PAYLOAD_LEN, SHADOWSOCKS_NONCE_LEN, SHADOWSOCKS_XNONCE_LEN}`
  - Варианты `CryptoError::{InvalidLengthHeader, InvalidChunkSize(usize), InvalidHeaderLength}`
  - Временно сохраняет `pub fn increment_nonce(nonce: &mut [u8; 12]) -> Result<()>` (удаляется в Task 2 после миграции `outline-transport`), чтобы весь workspace собирался после Task 1.

- [ ] **Step 1: Добавить тесты `StreamNonce`, `AesHeaderCipher` и `XChaChaCipher` в `crates/shadowsocks-crypto/src/tests/mod.rs`**

В `crates/shadowsocks-crypto/src/tests/mod.rs` добавить тесты:

```rust
#[test]
fn stream_nonce_advances_little_endian_and_caps_at_2_pow_32() {
    let mut n = crate::StreamNonce::new();
    assert_eq!(n.next().unwrap(), [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    assert_eq!(n.next().unwrap(), [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);

    let mut near = crate::StreamNonce::from_counter(crate::MAX_STREAM_NONCE_COUNTER - 1);
    let last = near.next().unwrap();
    assert_eq!(&last[..4], &[0xff, 0xff, 0xff, 0xff]);
    assert_eq!(&last[4..], &[0; 8]);
    assert!(matches!(near.next(), Err(crate::CryptoError::NonceOverflow)));
}

#[test]
fn aes_header_and_xchacha_ciphers_round_trip() {
    let key32 = [0x42u8; 32];
    let hdr_cipher = crate::AesHeaderCipher::new(crate::CipherKind::Aes256Gcm2022, &key32).unwrap();
    let block = [0xABu8; 16];
    let enc = hdr_cipher.encrypt_header(&block);
    assert_ne!(enc, block);
    assert_eq!(hdr_cipher.decrypt_header(&enc).unwrap(), block);

    let xcipher = crate::XChaChaCipher::new(&key32).unwrap();
    let nonce = [0x11u8; 24];
    let mut buf = b"hello xchacha".to_vec();
    let tag = xcipher.seal_in_place_separate_tag(&nonce, &mut buf).unwrap();
    buf.extend_from_slice(&tag);
    let len = xcipher.decrypt_detached_in_place(&nonce, &mut buf).unwrap();
    assert_eq!(&buf[..len], b"hello xchacha");
}
```

- [ ] **Step 2: Запустить тест и убедиться, что он падает до реализации**

Run: `cargo test -p shadowsocks-crypto stream_nonce_`
Expected: FAIL (`cannot find struct StreamNonce`).

- [ ] **Step 3: Обновить `Cargo.toml` и перевести `shadowsocks-crypto` на `aws-lc-rs`**

1. В корневом `Cargo.toml` в `[workspace.dependencies]` добавить:
   ```toml
   aws-lc-rs = { version = "1.19", default-features = false, features = ["aws-lc-sys", "alloc"] }
   sha2 = "0.11"
   ```
   (и в `crates/outline-tun/Cargo.toml` заменить `sha2 = "0.11"` на `sha2 = { workspace = true }`).
2. В `crates/shadowsocks-crypto/Cargo.toml` заменить `[dependencies]`:
   ```toml
   [dependencies]
   aes = { workspace = true }
   aws-lc-rs = { workspace = true }
   base64 = { workspace = true, features = ["std"] }
   blake3 = { workspace = true }
   bytes = { workspace = true }
   chacha20poly1305 = { workspace = true }
   outline-wire = { path = "../outline-wire" }
   rand = { workspace = true }
   serde = { workspace = true, features = ["derive"] }
   thiserror = { workspace = true }
   zeroize = { workspace = true }
   ```
3. В `crates/shadowsocks-crypto/src/error.rs` добавить варианты:
   ```rust
   #[error("invalid encrypted length header")]
   InvalidLengthHeader,

   #[error("unsupported chunk size {0}")]
   InvalidChunkSize(usize),

   #[error("decrypted fixed header length mismatch")]
   InvalidHeaderLength,
   ```
4. В `crates/shadowsocks-crypto/src/keys.rs` заменить `hkdf`+`sha1` на `aws_lc_rs::hkdf`:
   ```rust
   use aws_lc_rs::hkdf;
   use zeroize::Zeroizing;

   use crate::cipher_kind::CipherKind;
   use crate::error::{CryptoError, Result};

   pub use outline_wire::SS_SUBKEY_INFO as SHADOWSOCKS_INFO;
   pub use outline_wire::evp_bytes_to_key;
   pub use outline_wire::ss2022::SS2022_SUBKEY_CONTEXT as SHADOWSOCKS_2022_INFO;

   struct HkdfLen(usize);

   impl hkdf::KeyType for HkdfLen {
       fn len(&self) -> usize {
           self.0
       }
   }

   pub fn derive_subkey(
       cipher: CipherKind,
       master_key: &[u8],
       salt: &[u8],
   ) -> Result<Zeroizing<[u8; 32]>> {
       let mut subkey = Zeroizing::new([0u8; 32]);
       let key_len = cipher.key_len();
       if cipher.is_ss2022() {
           outline_wire::ss2022::ss2022_session_subkey_into(master_key, salt, &mut subkey[..key_len]);
       } else {
           let salt = hkdf::Salt::new(hkdf::HKDF_SHA1_FOR_LEGACY_USE_ONLY, salt);
           let prk = salt.extract(master_key);
           let okm = prk
               .expand(&[SHADOWSOCKS_INFO], HkdfLen(key_len))
               .map_err(|_| CryptoError::HkdfExpandFailed)?;
           okm.fill(&mut subkey[..key_len])
               .map_err(|_| CryptoError::HkdfExpandFailed)?;
       }
       Ok(subkey)
   }
   ```
5. В `crates/shadowsocks-crypto/src/aead.rs` переписать `AeadCipher` на `aws_lc_rs::aead::{AES_128_GCM, AES_256_GCM, Aad, CHACHA20_POLY1305, LessSafeKey, Nonce, UnboundKey}` и добавить `StreamNonce`, `MAX_STREAM_NONCE_COUNTER`, `LEGACY_MAX_PAYLOAD_LEN`, `SHADOWSOCKS_NONCE_LEN`, `SHADOWSOCKS_XNONCE_LEN`, `from_master_and_salt`, `seal_in_place_separate_tag`, `open_fixed_in_place` (оставив `increment_nonce` до Task 2):
   ```rust
   use aws_lc_rs::aead::{
       AES_128_GCM, AES_256_GCM, Aad, Algorithm, CHACHA20_POLY1305, LessSafeKey, Nonce, UnboundKey,
   };

   use crate::cipher_kind::CipherKind;
   use crate::error::{CryptoError, Result};
   use crate::keys::derive_subkey;

   pub const SHADOWSOCKS_TAG_LEN: usize = 16;
   pub const SHADOWSOCKS_NONCE_LEN: usize = 12;
   pub const SHADOWSOCKS_XNONCE_LEN: usize = 24;
   pub const LEGACY_MAX_PAYLOAD_LEN: usize = 0x3fff;
   pub const SHADOWSOCKS_MAX_PAYLOAD: usize = 0xffff;
   pub const MAX_STREAM_NONCE_COUNTER: u64 = 1 << 32;

   const CIPHER_CHACHA: &str = "chacha20-poly1305";
   const CIPHER_AES_128: &str = "aes-128-gcm";
   const CIPHER_AES_256: &str = "aes-256-gcm";

   pub struct AeadCipher {
       key: LessSafeKey,
       cipher_name: &'static str,
   }

   impl AeadCipher {
       pub fn new(cipher: CipherKind, key: &[u8]) -> Result<Self> {
           let (alg, cipher_name): (&'static Algorithm, &'static str) = match cipher {
               CipherKind::Chacha20IetfPoly1305 | CipherKind::Chacha20Poly13052022 => {
                   (&CHACHA20_POLY1305, CIPHER_CHACHA)
               },
               CipherKind::Aes128Gcm | CipherKind::Aes128Gcm2022 => (&AES_128_GCM, CIPHER_AES_128),
               CipherKind::Aes256Gcm | CipherKind::Aes256Gcm2022 => (&AES_256_GCM, CIPHER_AES_256),
           };
           let unbound = UnboundKey::new(alg, key)
               .map_err(|_| CryptoError::InvalidKey { cipher: cipher_name })?;
           Ok(Self { key: LessSafeKey::new(unbound), cipher_name })
       }

       pub fn from_master_and_salt(
           cipher: CipherKind,
           master_key: &[u8],
           salt: &[u8],
       ) -> Result<Self> {
           let subkey = derive_subkey(cipher, master_key, salt)?;
           Self::new(cipher, &subkey[..cipher.key_len()])
       }

       pub fn seal_in_place_separate_tag(
           &self,
           nonce: &[u8; 12],
           in_out: &mut [u8],
       ) -> Result<[u8; SHADOWSOCKS_TAG_LEN]> {
           let tag = self
               .key
               .seal_in_place_separate_tag(
                   Nonce::assume_unique_for_key(*nonce),
                   Aad::empty(),
                   in_out,
               )
               .map_err(|_| CryptoError::EncryptFailed { cipher: self.cipher_name })?;
           let mut out = [0u8; SHADOWSOCKS_TAG_LEN];
           out.copy_from_slice(tag.as_ref());
           Ok(out)
       }

       pub fn encrypt(&self, nonce: &[u8; 12], payload: &[u8]) -> Result<Vec<u8>> {
           let mut buffer = Vec::with_capacity(payload.len() + SHADOWSOCKS_TAG_LEN);
           self.encrypt_into(nonce, payload, &mut buffer)?;
           Ok(buffer)
       }

       pub fn encrypt_into(
           &self,
           nonce: &[u8; 12],
           payload: &[u8],
           out: &mut Vec<u8>,
       ) -> Result<()> {
           out.reserve(payload.len() + SHADOWSOCKS_TAG_LEN);
           let start = out.len();
           out.extend_from_slice(payload);
           let tag = self.seal_in_place_separate_tag(nonce, &mut out[start..])?;
           out.extend_from_slice(&tag);
           Ok(())
       }

       pub fn decrypt(&self, nonce: &[u8; 12], payload: &[u8]) -> Result<Vec<u8>> {
           let mut buf = payload.to_vec();
           self.decrypt_in_place(nonce, &mut buf)?;
           Ok(buf)
       }

       pub fn decrypt_detached_in_place(&self, nonce: &[u8; 12], buf: &mut [u8]) -> Result<usize> {
           if buf.len() < SHADOWSOCKS_TAG_LEN {
               return Err(CryptoError::ShortCiphertext);
           }
           let plaintext = self
               .key
               .open_in_place(Nonce::assume_unique_for_key(*nonce), Aad::empty(), buf)
               .map_err(|_| CryptoError::DecryptFailed { cipher: self.cipher_name })?;
           Ok(plaintext.len())
       }

       pub fn decrypt_in_place(&self, nonce: &[u8; 12], buf: &mut Vec<u8>) -> Result<()> {
           let plaintext_len = self.decrypt_detached_in_place(nonce, buf)?;
           buf.truncate(plaintext_len);
           Ok(())
       }

       pub fn open_fixed_in_place<'a>(
           &self,
           nonce: &[u8; 12],
           ciphertext: &'a mut [u8],
           expected_plaintext_len: usize,
       ) -> Result<&'a [u8]> {
           let plaintext = self
               .key
               .open_in_place(Nonce::assume_unique_for_key(*nonce), Aad::empty(), ciphertext)
               .map_err(|_| CryptoError::DecryptFailed { cipher: self.cipher_name })?;
           if plaintext.len() != expected_plaintext_len {
               return Err(CryptoError::InvalidHeaderLength);
           }
           Ok(plaintext)
       }
   }

   #[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
   pub struct StreamNonce(u64);

   impl StreamNonce {
       pub const fn new() -> Self {
           Self(0)
       }

       pub const fn from_counter(counter: u64) -> Self {
           Self(counter)
       }

       pub const fn counter(&self) -> u64 {
           self.0
       }

       pub fn next(&mut self) -> Result<[u8; SHADOWSOCKS_NONCE_LEN]> {
           let current = self.0;
           if current >= MAX_STREAM_NONCE_COUNTER {
               return Err(CryptoError::NonceOverflow);
           }
           self.0 = current + 1;
           let mut nonce = [0u8; SHADOWSOCKS_NONCE_LEN];
           nonce[..8].copy_from_slice(&current.to_le_bytes());
           Ok(nonce)
       }
   }
   ```
6. В `crates/shadowsocks-crypto/src/ss2022_udp.rs` добавить публичные `AesHeaderCipher` и `XChaChaCipher`, переписать `encrypt_udp_separate_header`, `decrypt_udp_separate_header`, `seal_xchacha_packet` и `decrypt_udp_packet_2022_chacha` поверх них, и реэкспортировать все новые типы в `crates/shadowsocks-crypto/src/lib.rs`.

- [ ] **Step 4: Прогнать тесты (включая `known_answers`), линтер, очистить `target/debug` и закоммитить**

Run:
```bash
cargo fmt --check -p shadowsocks-crypto -p outline-tun && \
cargo clippy -p shadowsocks-crypto -p outline-tun --all-targets --no-deps -- -D warnings && \
cargo test -p shadowsocks-crypto && \
rm -rf target/debug
```
Expected: PASS (все `known_answers` и новые тесты проходят побайтово).

Commit:
```bash
git add Cargo.toml Cargo.lock crates/outline-tun/Cargo.toml crates/shadowsocks-crypto
git commit -m "refactor(crypto): migrate shadowsocks-crypto to aws-lc-rs and add StreamNonce/SS2022 helpers"
```

---

### Task 2: Потоковый кодек `shadowsocks_crypto::stream` и миграция `outline-transport`

**Files:**
- Create: `crates/shadowsocks-crypto/src/stream.rs`
- Create: `crates/shadowsocks-crypto/src/tests/stream.rs`
- Modify: `crates/shadowsocks-crypto/src/lib.rs`
- Modify: `crates/shadowsocks-crypto/src/aead.rs`
- Modify: `crates/shadowsocks-crypto/src/tests/mod.rs`
- Modify: `crates/outline-transport/src/tcp_transport/writer/mod.rs`
- Modify: `crates/outline-transport/src/tcp_transport/reader/mod.rs`
- Modify: `crates/outline-transport/Cargo.toml`
- Modify: `crates/outline-transport/src/quic/tests/tls_config.rs`
- Modify: `crates/outline-transport/src/tests/client_hello.rs`

**Interfaces:**
- Consumes: `AeadCipher`, `StreamNonce`, `LEGACY_MAX_PAYLOAD_LEN`, `SHADOWSOCKS_MAX_PAYLOAD`
- Produces: `shadowsocks_crypto::stream::{SealBuf, seal_payload_chunk, seal_legacy_chunks, seal_ss2022_response_first_frame, open_length_block, open_payload_in_place, drain_chunk_from_bytes}`

- [ ] **Step 1: Создать `crates/shadowsocks-crypto/src/tests/stream.rs` с unit-тестами потокового кодека**

```rust
use bytes::BytesMut;

use crate::stream::{
    drain_chunk_from_bytes, open_length_block, open_payload_in_place, seal_legacy_chunks,
    seal_payload_chunk, seal_ss2022_response_first_frame,
};
use crate::{AeadCipher, CipherKind, CryptoError, LEGACY_MAX_PAYLOAD_LEN, SHADOWSOCKS_TAG_LEN, StreamNonce};

#[test]
fn seal_legacy_chunks_and_drain_round_trip_across_vec_and_bytes_mut() {
    let cipher = AeadCipher::new(CipherKind::Aes128Gcm, &[0x24; 16]).unwrap();
    let salt = [0x99u8; 16];
    let payload = vec![0x5Au8; LEGACY_MAX_PAYLOAD_LEN * 2 + 123];

    let mut seal_nonce = StreamNonce::new();
    let mut sent_salt = false;
    let mut wire = BytesMut::new();
    seal_legacy_chunks(&cipher, &mut seal_nonce, &salt, &mut sent_salt, &payload, &mut wire)
        .unwrap();
    assert!(sent_salt);
    assert_eq!(&wire[..16], &salt);

    let mut body = wire.split_off(16);
    let mut open_nonce = StreamNonce::new();
    let mut pending = None;
    let mut out = Vec::new();
    while drain_chunk_from_bytes(
        &mut body,
        &cipher,
        &mut open_nonce,
        &mut pending,
        LEGACY_MAX_PAYLOAD_LEN,
        &mut out,
    )
    .unwrap()
    {}
    assert!(body.is_empty());
    assert_eq!(out, payload);
}

#[test]
fn open_length_block_rejects_bad_tag_and_oversized_chunk() {
    let cipher = AeadCipher::new(CipherKind::Chacha20IetfPoly1305, &[0x77; 32]).unwrap();
    let mut bad = [0u8; 2 + SHADOWSOCKS_TAG_LEN];
    let mut n = StreamNonce::new();
    assert!(matches!(
        open_length_block(&cipher, &mut n, LEGACY_MAX_PAYLOAD_LEN, &mut bad),
        Err(CryptoError::InvalidLengthHeader)
    ));

    // Encrypt an oversized length header (0x4000 > 0x3fff) manually.
    let mut seal_n = StreamNonce::new();
    let mut oversized = Vec::new();
    cipher
        .encrypt_into(&seal_n.next().unwrap(), &0x4000u16.to_be_bytes(), &mut oversized)
        .unwrap();
    let mut open_n = StreamNonce::new();
    assert!(matches!(
        open_length_block(&cipher, &mut open_n, LEGACY_MAX_PAYLOAD_LEN, &mut oversized),
        Err(CryptoError::InvalidChunkSize(0x4000))
    ));
}

#[test]
fn ss2022_response_first_frame_round_trips() {
    let cipher = AeadCipher::new(CipherKind::Aes128Gcm2022, &[0x33; 16]).unwrap();
    let resp_salt = [0xAA; 16];
    let req_salt = [0xBB; 16];
    let mut seal_n = StreamNonce::new();
    let mut wire = Vec::new();
    seal_ss2022_response_first_frame(
        &cipher,
        &mut seal_n,
        &resp_salt,
        &req_salt,
        1_700_000_000,
        b"first-bytes",
        &mut wire,
    )
    .unwrap();
    assert_eq!(&wire[..16], &resp_salt);

    let mut open_n = StreamNonce::new();
    let hdr_ct_len = 1 + 8 + 16 + 2 + SHADOWSOCKS_TAG_LEN;
    let mut hdr_buf = wire[16..16 + hdr_ct_len].to_vec();
    let hdr_pt = open_payload_in_place(&cipher, &mut open_n, &mut hdr_buf).unwrap();
    let len = outline_wire::ss2022::parse_response_header(
        CipherKind::Aes128Gcm2022,
        &req_salt,
        &hdr_buf[..hdr_pt],
        1_700_000_000,
    )
    .unwrap();
    assert_eq!(len, b"first-bytes".len());

    let mut pay_buf = wire[16 + hdr_ct_len..].to_vec();
    let pay_pt = open_payload_in_place(&cipher, &mut open_n, &mut pay_buf).unwrap();
    assert_eq!(&pay_buf[..pay_pt], b"first-bytes");
}
```

- [ ] **Step 2: Подключить `pub mod stream;` в `crates/shadowsocks-crypto/src/lib.rs` и убедиться, что тест падает**

Run: `cargo test -p shadowsocks-crypto stream`
Expected: FAIL (`file not found for module stream`).

- [ ] **Step 3: Реализовать `crates/shadowsocks-crypto/src/stream.rs` и перевести `outline-transport` (включая замену dev-зависимости `ring` на `aws-lc-rs`)**

1. Создать `crates/shadowsocks-crypto/src/stream.rs`:
   ```rust
   //! Synchronous Shadowsocks AEAD stream chunk sealer and opener shared by the
   //! client and the server.

   use bytes::BytesMut;
   use outline_wire::ss2022::SS2022_TCP_RESPONSE_TYPE;

   use crate::aead::{AeadCipher, LEGACY_MAX_PAYLOAD_LEN, SHADOWSOCKS_TAG_LEN, StreamNonce};
   use crate::error::{CryptoError, Result};

   pub trait SealBuf {
       fn len(&self) -> usize;
       fn is_empty(&self) -> bool {
           self.len() == 0
       }
       fn reserve(&mut self, additional: usize);
       fn extend_from_slice(&mut self, src: &[u8]);
       fn slice_mut(&mut self, start: usize, end: usize) -> &mut [u8];
   }

   impl SealBuf for Vec<u8> {
       fn len(&self) -> usize {
           Vec::len(self)
       }
       fn reserve(&mut self, additional: usize) {
           Vec::reserve(self, additional);
       }
       fn extend_from_slice(&mut self, src: &[u8]) {
           Vec::extend_from_slice(self, src);
       }
       fn slice_mut(&mut self, start: usize, end: usize) -> &mut [u8] {
           &mut self[start..end]
       }
   }

   impl SealBuf for BytesMut {
       fn len(&self) -> usize {
           BytesMut::len(self)
       }
       fn reserve(&mut self, additional: usize) {
           BytesMut::reserve(self, additional);
       }
       fn extend_from_slice(&mut self, src: &[u8]) {
           BytesMut::extend_from_slice(self, src);
       }
       fn slice_mut(&mut self, start: usize, end: usize) -> &mut [u8] {
           &mut self[start..end]
       }
   }

   fn seal_block<B: SealBuf>(
       cipher: &AeadCipher,
       nonce: &mut StreamNonce,
       plaintext: &[u8],
       out: &mut B,
   ) -> Result<()> {
       let n = nonce.next()?;
       let start = out.len();
       out.extend_from_slice(plaintext);
       let end = out.len();
       let tag = cipher.seal_in_place_separate_tag(&n, out.slice_mut(start, end))?;
       out.extend_from_slice(&tag);
       Ok(())
   }

   pub fn seal_payload_chunk<B: SealBuf>(
       cipher: &AeadCipher,
       nonce: &mut StreamNonce,
       max_chunk_size: usize,
       pending_salt: Option<&[u8]>,
       payload: &[u8],
       out: &mut B,
   ) -> Result<()> {
       if payload.len() > max_chunk_size {
           return Err(CryptoError::InvalidChunkSize(payload.len()));
       }
       let salt_len = pending_salt.map_or(0, <[u8]>::len);
       out.reserve(salt_len + 2 + SHADOWSOCKS_TAG_LEN + payload.len() + SHADOWSOCKS_TAG_LEN);
       if let Some(salt) = pending_salt {
           out.extend_from_slice(salt);
       }
       let length = u16::try_from(payload.len())
           .map_err(|_| CryptoError::InvalidChunkSize(payload.len()))?
           .to_be_bytes();
       seal_block(cipher, nonce, &length, out)?;
       seal_block(cipher, nonce, payload, out)
   }

   pub fn seal_legacy_chunks<B: SealBuf>(
       cipher: &AeadCipher,
       nonce: &mut StreamNonce,
       salt: &[u8],
       sent_salt: &mut bool,
       plaintext: &[u8],
       out: &mut B,
   ) -> Result<()> {
       let chunk_count = plaintext.len().div_ceil(LEGACY_MAX_PAYLOAD_LEN).max(1);
       out.reserve(
           usize::from(!*sent_salt) * salt.len()
               + plaintext.len()
               + chunk_count * (2 + 2 * SHADOWSOCKS_TAG_LEN),
       );
       for chunk in plaintext.chunks(LEGACY_MAX_PAYLOAD_LEN) {
           let prefix = if *sent_salt {
               None
           } else {
               *sent_salt = true;
               Some(salt)
           };
           seal_payload_chunk(cipher, nonce, LEGACY_MAX_PAYLOAD_LEN, prefix, chunk, out)?;
       }
       Ok(())
   }

   pub fn seal_ss2022_response_first_frame<B: SealBuf>(
       cipher: &AeadCipher,
       nonce: &mut StreamNonce,
       salt: &[u8],
       request_salt: &[u8],
       now_secs: u64,
       initial_payload: &[u8],
       out: &mut B,
   ) -> Result<()> {
       let length = u16::try_from(initial_payload.len())
           .map_err(|_| CryptoError::InvalidChunkSize(initial_payload.len()))?
           .to_be_bytes();
       let header_pt_len = 1 + 8 + request_salt.len() + 2;
       out.reserve(
           salt.len()
               + header_pt_len
               + SHADOWSOCKS_TAG_LEN
               + initial_payload.len()
               + SHADOWSOCKS_TAG_LEN,
       );
       out.extend_from_slice(salt);
       let hdr_nonce = nonce.next()?;
       let hdr_start = out.len();
       out.extend_from_slice(&[SS2022_TCP_RESPONSE_TYPE]);
       out.extend_from_slice(&now_secs.to_be_bytes());
       out.extend_from_slice(request_salt);
       out.extend_from_slice(&length);
       let hdr_end = out.len();
       let hdr_tag = cipher.seal_in_place_separate_tag(&hdr_nonce, out.slice_mut(hdr_start, hdr_end))?;
       out.extend_from_slice(&hdr_tag);

       seal_block(cipher, nonce, initial_payload, out)
   }

   pub fn open_length_block(
       cipher: &AeadCipher,
       nonce: &mut StreamNonce,
       max_chunk_size: usize,
       block: &mut [u8],
   ) -> Result<usize> {
       if block.len() != 2 + SHADOWSOCKS_TAG_LEN {
           return Err(CryptoError::InvalidLengthHeader);
       }
       let n = nonce.next()?;
       let pt = cipher
           .open_fixed_in_place(&n, block, 2)
           .map_err(|_| CryptoError::InvalidLengthHeader)?;
       let chunk_len = u16::from_be_bytes([pt[0], pt[1]]) as usize;
       if chunk_len > max_chunk_size {
           return Err(CryptoError::InvalidChunkSize(chunk_len));
       }
       Ok(chunk_len)
   }

   pub fn open_payload_in_place(
       cipher: &AeadCipher,
       nonce: &mut StreamNonce,
       buf: &mut [u8],
   ) -> Result<usize> {
       let n = nonce.next()?;
       cipher.decrypt_detached_in_place(&n, buf)
   }

   pub fn drain_chunk_from_bytes(
       buffer: &mut BytesMut,
       cipher: &AeadCipher,
       nonce: &mut StreamNonce,
       pending_chunk_len: &mut Option<usize>,
       max_chunk_size: usize,
       output: &mut Vec<u8>,
   ) -> Result<bool> {
       if pending_chunk_len.is_none() {
           if buffer.len() < 2 + SHADOWSOCKS_TAG_LEN {
               return Ok(false);
           }
           let mut len_block = buffer.split_to(2 + SHADOWSOCKS_TAG_LEN);
           *pending_chunk_len = Some(open_length_block(
               cipher,
               nonce,
               max_chunk_size,
               &mut len_block,
           )?);
       }
       let chunk_len = pending_chunk_len.expect("set above");
       if buffer.len() < chunk_len + SHADOWSOCKS_TAG_LEN {
           return Ok(false);
       }
       let mut encrypted_payload = buffer.split_to(chunk_len + SHADOWSOCKS_TAG_LEN);
       let pt_len = open_payload_in_place(cipher, nonce, &mut encrypted_payload)?;
       output.extend_from_slice(&encrypted_payload[..pt_len]);
       *pending_chunk_len = None;
       Ok(true)
   }

   #[cfg(test)]
   #[path = "tests/stream.rs"]
   mod tests;
   ```
2. Удалить устаревший `increment_nonce` из `crates/shadowsocks-crypto/src/aead.rs` и `lib.rs` (и его старые 2 теста в `tests/mod.rs`, заменённые тестами `StreamNonce`).
3. В `crates/outline-transport/src/tcp_transport/writer/mod.rs`:
   - заменить `nonce: [u8; 12]` на `nonce: StreamNonce` (`StreamNonce::new()`);
   - в `send_chunk` (ветка SS2022 header) использовать `self.cipher_state.encrypt_into(&self.nonce.next()?, &fixed_header, &mut frame)?` и то же для `variable_header`;
   - в `encrypt_payload_frame_into` вызывать `shadowsocks_crypto::stream::seal_payload_chunk(&self.cipher_state, &mut self.nonce, self.cipher.max_payload_len(), salt_slice, payload, frame)?`.
4. В `crates/outline-transport/src/tcp_transport/reader/mod.rs`:
   - заменить `nonce: [u8; 12]` на `nonce: StreamNonce` (`StreamNonce::new()`);
   - использовать `open_length_block` и `open_payload_in_place` (+ `truncate`) в `read_one_decrypted_chunk`.
5. В `crates/outline-transport/Cargo.toml` в `[dev-dependencies]` заменить `ring = { workspace = true }` на `aws-lc-rs = { workspace = true }`, в `src/quic/tests/tls_config.rs:18` заменить `use ring::{aead, hmac};` на `use aws_lc_rs::{aead, hmac};`, а в `src/tests/client_hello.rs:218` заменить `ring::digest::digest(&ring::digest::SHA256, ...)` на `aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, ...)`.

- [ ] **Step 4: Прогнать тесты, линтер, очистить `target/debug` и закоммитить**

Run:
```bash
cargo fmt --check -p shadowsocks-crypto -p outline-transport && \
cargo clippy -p shadowsocks-crypto -p outline-transport --all-targets --no-deps -- -D warnings && \
cargo test -p shadowsocks-crypto -p outline-transport && \
rm -rf target/debug
```
Expected: PASS (exit code 0).

Commit:
```bash
git add crates/shadowsocks-crypto crates/outline-transport
git commit -m "refactor(crypto,transport): add shared stream chunk codec and migrate client off ring"
```

---

### Task 3: Перевод `outline-server`, `outline-ui`, `outline-windows` и полное удаление `ring`

**Files:**
- Modify: `Cargo.toml`
- Modify: `bins/outline-server/Cargo.toml`
- Delete: `bins/outline-server/src/crypto/primitives.rs`
- Delete: `bins/outline-server/src/crypto/tests/primitives.rs`
- Modify: `bins/outline-server/src/crypto/mod.rs`
- Modify: `bins/outline-server/src/crypto/error.rs`
- Modify: `bins/outline-server/src/crypto/user_key.rs`
- Modify: `bins/outline-server/src/crypto/session_cache.rs`
- Modify: `bins/outline-server/src/crypto/ss2022_header.rs`
- Modify: `bins/outline-server/src/crypto/stream.rs`
- Modify: `bins/outline-server/src/crypto/udp.rs`
- Modify: `bins/outline-server/src/crypto/diagnose.rs`
- Modify: `bins/outline-server/src/crypto/tests/mod.rs`
- Modify: `bins/outline-server/src/crypto/tests/session_cache.rs`
- Modify: `bins/outline-server/src/crypto/tests/stream.rs`
- Modify: `bins/outline-server/src/server/bootstrap/cert_pin.rs`
- Modify: `bins/outline-server/src/outbound.rs`
- Modify: `bins/outline-server/src/server/nat/entry.rs`
- Modify: `bins/outline-server/src/server/transport/xhttp/mod.rs`
- Modify: `bins/outline-server/src/server/tests/resumption/cluster.rs`
- Modify: `bins/outline-ui/Cargo.toml`
- Modify: `bins/outline-ui/src/auth.rs`
- Modify: `bins/outline-windows/Cargo.toml`
- Modify: `bins/outline-windows/src/updater.rs`

**Interfaces:**
- Consumes: `shadowsocks_crypto::{AeadCipher, AesHeaderCipher, XChaChaCipher, StreamNonce, stream::*, derive_subkey, LEGACY_MAX_PAYLOAD_LEN, SHADOWSOCKS_MAX_PAYLOAD, SHADOWSOCKS_TAG_LEN, SHADOWSOCKS_XNONCE_LEN}`, `aws_lc_rs::digest`, `sha2::Sha256`
- Produces: workspace без единой активной зависимости на крейт `ring`.

- [ ] **Step 1: Перевести `outline-ui` и `outline-windows` с `ring`**

1. В `bins/outline-ui/Cargo.toml` заменить `ring = { workspace = true }` на `aws-lc-rs = { workspace = true }`. В `bins/outline-ui/src/auth.rs` заменить два вызова `ring::digest::digest(&ring::digest::SHA256, ...)` на `aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, ...)`.
2. В `bins/outline-windows/Cargo.toml` заменить `ring = { workspace = true }` на `sha2 = { workspace = true }`. В `bins/outline-windows/src/updater.rs` заменить:
   ```rust
   use sha2::{Digest as _, Sha256};
   let mut hasher = Sha256::new();
   // в цикле скачивания:
   hasher.update(&chunk);
   // после flush:
   let digest = hasher.finalize();
   let calculated_hash = to_hex(&digest);
   ```

- [ ] **Step 2: Перевести `bins/outline-server` на `shadowsocks-crypto` + `aws-lc-rs` и удалить `ring` из корневого `Cargo.toml`**

1. В `bins/outline-server/Cargo.toml`: удалить `ring`, `aes`, `chacha20poly1305`; добавить `aws-lc-rs = { workspace = true }` и `shadowsocks-crypto = { path = "../../crates/shadowsocks-crypto" }`.
2. В корневом `Cargo.toml`: удалить `ring = "0.17"`.
3. Удалить `bins/outline-server/src/crypto/primitives.rs` и `bins/outline-server/src/crypto/tests/primitives.rs` (убрать `mod primitives;` из `crypto/mod.rs` и `crypto/tests/mod.rs`, реэкспортировать `pub use shadowsocks_crypto::SHADOWSOCKS_MAX_PAYLOAD as MAX_CHUNK_SIZE;`).
4. В `bins/outline-server/src/crypto/error.rs`: заменить `From<ring::error::Unspecified>` на `From<shadowsocks_crypto::CryptoError>`:
   ```rust
   impl From<shadowsocks_crypto::CryptoError> for CryptoError {
       fn from(err: shadowsocks_crypto::CryptoError) -> Self {
           use shadowsocks_crypto::CryptoError as Sc;
           match err {
               Sc::InvalidLengthHeader => Self::InvalidLengthHeader,
               Sc::InvalidChunkSize(n) => Self::InvalidChunkSize(n),
               Sc::InvalidHeaderLength => Self::InvalidHeader,
               Sc::NonceOverflow => Self::NonceExhausted,
               Sc::HkdfExpandFailed => Self::KeyDerivation,
               _ => Self::Cipher,
           }
       }
   }
   ```
5. В `user_key.rs`: заменить локальные `AesHeaderCipher` и `XChaCha20Poly1305` на `shadowsocks_crypto::{AesHeaderCipher, XChaChaCipher}`.
6. В `session_cache.rs` (и `tests/session_cache.rs`): заменить `ring::aead::LessSafeKey` на `shadowsocks_crypto::AeadCipher` (`LruCache<CacheKey, Arc<AeadCipher>>`).
7. В `ss2022_header.rs`: убрать `ring::aead::Nonce`; возвращать чистый `[u8; 12]` из `outline_wire::ss2022::udp_nonce_from_separate_header`.
8. В `stream.rs` (и `tests/stream.rs`):
   - заменить `LessSafeKey` на `AeadCipher` (`AeadCipher::from_master_and_salt`), `nonce_counter: u64` на `nonce: StreamNonce`, `SystemRandom` на `rand::rng().fill_bytes(...)`;
   - заменить локальные `drain_length_header`, `drain_payload`, `encrypt_legacy_chunks`, `encrypt_legacy_chunk`, `encrypt_ss2022_chunk` вызовами `shadowsocks_crypto::stream::{drain_chunk_from_bytes, seal_legacy_chunks, seal_payload_chunk, seal_ss2022_response_first_frame}`.
9. В `udp.rs` и `diagnose.rs`: заменить `LessSafeKey` на `AeadCipher`, `AesHeaderCipher` / `XChaCha20Poly1305` на методы `shadowsocks_crypto::{AesHeaderCipher, XChaChaCipher}`, `SystemRandom` на `rand::rng().fill_bytes(...)`.
10. В `server/bootstrap/cert_pin.rs` и `server/tests/resumption/cluster.rs`: заменить `ring::digest` на `aws_lc_rs::digest`.
11. В `outbound.rs`, `server/nat/entry.rs` и `server/transport/xhttp/mod.rs`: заменить `ring::rand::SystemRandom` на `rand::rng().fill_bytes(...)`.

- [ ] **Step 3: Проверить полное отсутствие `ring` в графе зависимостей и прогнать тесты**

Run:
```bash
test -z "$(cargo tree --workspace --exclude sockudo-ws --exclude outline-windows -i ring 2>/dev/null)" && \
cargo fmt --check -p outline-server -p outline-ui -p shadowsocks-crypto && \
cargo clippy --workspace --exclude sockudo-ws --exclude outline-windows --all-targets --no-deps -- -D warnings && \
cargo test -p shadowsocks-crypto -p outline-server -p outline-ui && \
rm -rf target/debug
```
Expected: PASS (`cargo tree ... -i ring` возвращает пустую строку, все тесты и clippy зелёные).

- [ ] **Step 4: Закоммитить**

```bash
git add -A Cargo.toml Cargo.lock bins/outline-server bins/outline-ui bins/outline-windows
git commit -m "refactor(server,crypto): share shadowsocks-crypto on server and remove ring crate"
```

---

### Task 4: Актуализация документации, усиление CI-инварианта и финальный CI-гейт

**Files:**
- Modify: `AGENTS.md`
- Modify: `.github/workflows/ci.yml`
- Modify: `bins/outline-server/docs/SESSION-RESUMPTION.md`
- Modify: `bins/outline-server/docs/SESSION-RESUMPTION.ru.md`
- Modify: `bins/outline-windows/README.md`
- Modify: `bins/outline-windows/README.ru.md`
- Modify: `android/rust/Cargo.lock` (если изменится при проверке `android/rust`)

**Interfaces:**
- Produces: синхронизированная EN/RU документация, усиленный CI-гейт на запрет `ring` во всём графе workspace и зелёный прогон всех проверок.

- [ ] **Step 1: Обновить документацию и CI-инвариант**

1. В `AGENTS.md`:
   - В разделе «Структура» (`crates/`): указать, что truly-shared (обе стороны) — `outline-wire` и `shadowsocks-crypto` (единый AEAD / SS2022 / потоковый кодек поверх `aws-lc-rs`), убрать устаревшую фразу про раздельные бэкенды `ring` и RustCrypto.
   - В разделе «Монорепо-инварианты» (`rustls — только aws-lc-rs`): заменить предложение «`ring`-крейт остаётся только для SS-AEAD/SHA-256...» на «Крейт `ring` полностью удалён из графа зависимостей workspace; для AEAD/HKDF/SHA-256 везде используется `aws-lc-rs` (или `sha2` в GUI)».
2. В `.github/workflows/ci.yml` (шаг `invariant — aws-lc-rs only, no ring`): усилить проверку так, чтобы падала при появлении любого `ring` в `cargo tree --workspace --exclude sockudo-ws --exclude outline-windows -i ring`:
   ```yaml
      - name: invariant — aws-lc-rs only, no ring in workspace
        run: |
          if [ -n "$(cargo tree --workspace --exclude sockudo-ws --exclude outline-windows -i ring 2>/dev/null)" ]; then
            echo "::error::the ring crate re-entered the workspace dependency graph; stay on aws-lc-rs"
            cargo tree --workspace --exclude sockudo-ws --exclude outline-windows -i ring
            exit 1
          fi
          echo "ok: no ring in workspace graph (aws-lc-rs only)"
   ```
3. В `bins/outline-server/docs/SESSION-RESUMPTION.md` и `SESSION-RESUMPTION.ru.md` (строка 38): заменить `(`ring::rand::SystemRandom`)` на `(`rand::rng()`, ChaCha12 CSPRNG)`.
4. В `bins/outline-windows/README.md` и `README.ru.md` (строки 86 / 89-90): заменить `ring` (`ring::digest::SHA256`) на `sha2` (`sha2::Sha256`).

- [ ] **Step 2: Прогнать полный локальный CI-гейт монорепо (включая `e2e_*` и `android/rust`) и очистить `target/debug`**

Run:
```bash
cargo fmt --check -p outline-server -p outline-client -p outline-ui \
  -p outline-metrics -p outline-net -p outline-routing -p outline-transport \
  -p outline-tun -p outline-uplink -p outline-wire \
  -p shadowsocks-crypto -p socks5-proto && \
cargo clippy --workspace --exclude sockudo-ws --exclude outline-windows --all-targets --no-deps -- -D warnings && \
cargo test --workspace --exclude sockudo-ws --exclude outline-windows && \
RUN_E2E_FAILOVER=1 cargo test -p outline-client --features test-tls --test 'e2e_*' -- --test-threads=1 && \
(cd android/rust && cargo fmt --check && cargo clippy --no-deps -- -D warnings) && \
test -z "$(cargo tree --workspace --exclude sockudo-ws --exclude outline-windows -i ring 2>/dev/null)" && \
rm -rf target/debug
```
Expected: PASS (exit code 0).

- [ ] **Step 3: Закоммитить документацию и CI-инвариант**

```bash
git add AGENTS.md .github/workflows/ci.yml bins/outline-server/docs/SESSION-RESUMPTION.md bins/outline-server/docs/SESSION-RESUMPTION.ru.md bins/outline-windows/README.md bins/outline-windows/README.ru.md android/rust/Cargo.lock
git commit -m "docs,ci: document unified shadowsocks-crypto and enforce zero-ring invariant"
```
