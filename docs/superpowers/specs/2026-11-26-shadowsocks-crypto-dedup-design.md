# Единый крипто-слой `shadowsocks-crypto` на `aws-lc-rs`, потоковый кодек и удаление `ring` (M3 — Подпроект 2)

**Дата:** 2026-11-26
**Статус:** На ревью
**Затронутые пакеты:** `shadowsocks-crypto`, `outline-transport`, `outline-server` (+ корневой `Cargo.toml`, `AGENTS.md`)

---

## 1. Контекст и мотивация

После Подпроекта 1 (вынос чистых примитивов и заголовков в `outline-wire`) следующий уровень дублирования между `outline-server` и `outline-client` — криптографический слой Shadowsocks AEAD и потоковый/UDP кодек поверх него:

1. **Дублирование крипто-движков в бинаре сервера:** во все бинари монорепо (`outline-server`, `outline-client`, `outline-android`) уже безусловно залинкован C/ASM-движок `aws-lc-rs = "1.19.0"` (единственный провайдер `rustls` и `quinn`). При этом в `outline-server` исторически оставался крейт `ring` (второй форк BoringSSL) исключительно ради `src/crypto/*`, одного вызова SHA-256 в `cert_pin.rs` и нескольких вызовов `SystemRandom`.
2. **Дублирование потокового чанкового кодека и SS2022-примитивов:** упаковка и распаковка чанков `[2B len + 16B tag][payload + 16B tag]`, вывод сессионного субключа (`derive_subkey`), 16-байтный AES-ECB шифр заголовка SS2022 UDP (`AesHeaderCipher`) и XChaCha20-Poly1305 шифр SS2022 ChaCha UDP реализованы дважды — в `bins/outline-server/src/crypto/*` и в `crates/shadowsocks-crypto` + `crates/outline-transport/src/tcp_transport/*`.
3. **Расхождение по лимиту nonce (NIST SP 800-38D):** сервер принудительно ограничивает число вызовов AEAD на один ключ константой `MAX_NONCE_COUNTER = 1 << 32`, тогда как клиентский `increment_nonce` считает до `2^96`.

---

## 2. Цели и границы Подпроекта 2

### Цели
1. Перевести `crates/shadowsocks-crypto` с RustCrypto `aes-gcm`/`hkdf`/`sha1` на `aws-lc-rs` (оставив лёгкие `aes` для 16-байтного блочного заголовка SS2022 и `chacha20poly1305` только для `XChaCha20Poly1305` с 24-байтным nonce) и подключить `shadowsocks-crypto` к `outline-server` как общий truly-shared крейт.
2. Полностью удалить зависимость `ring` из корневого `Cargo.toml` и `bins/outline-server` (`cert_pin.rs` переходит на `aws_lc_rs::digest::SHA256`, генерация случайных байт — на `rand::rng()`).
3. Унифицировать счётчик потокового nonce (`StreamNonce` с лимитом `MAX_STREAM_NONCE_COUNTER = 1 << 32`) на клиенте и сервере.
4. Вынести без-IO потоковый чанковый и SS2022-ответный кодек в новый модуль `shadowsocks_crypto::stream` с поддержкой zero-copy записи как в `Vec<u8>`, так и в `BytesMut`.
5. Вынести переиспользуемые `Send + Sync` обёртки `AesHeaderCipher` и `XChaChaCipher` в `shadowsocks-crypto`, убрав их дубликаты из серверных `user_key.rs` и `udp.rs`.

### Границы (что остаётся на сторонах)
- На **сервере** (`bins/outline-server/src/crypto/`): multi-tenant сущность `UserKey` (`fwmark`, `IpAliasTable`, `OnceLock<AesHeaderCipher>`, `OnceLock<XChaChaCipher>`), шардированный `SessionKeyCache` (хранящий `Arc<shadowsocks_crypto::AeadCipher>`), multi-user перебор первого чанка/пакета с `user_hint` и модуль диагностики `diagnose.rs`.
- На **клиенте** (`crates/outline-transport/src/tcp_transport/`): асинхронные обёртки чтения/записи (`ReadTransport::read_exact`, `WriteTransport`), батчинг `send_chunks` и перехват управляющих фреймов сессионного резюма (`ORSM` / `ORDR`).

---

## 3. Архитектура и публичный API `shadowsocks-crypto`

### 3.1. Зависимости

- **Корневой `Cargo.toml`:**
  - Добавляется `aws-lc-rs = { version = "1.19", default-features = false, features = ["aws-lc-sys", "alloc"] }` (совпадает с версией и набором фич, уже присутствующими в `Cargo.lock` и `android/rust/Cargo.lock`).
  - Удаляется `ring = "0.17"`.
- **`crates/shadowsocks-crypto/Cargo.toml`:**
  - Удаляются `aes-gcm`, `hkdf`, `sha1`, `md5`.
  - Добавляются `aws-lc-rs = { workspace = true }` и `bytes = { workspace = true }`.
  - Сохраняется `chacha20poly1305` (ради `XChaCha20Poly1305`) и `aes` (ради `Aes128`/`Aes256` single-block encrypt/decrypt для SS2022 UDP separate header).
- **`bins/outline-server/Cargo.toml`:**
  - Удаляются `ring`, `aes`, `chacha20poly1305`.
  - Добавляются `shadowsocks-crypto = { path = "../../crates/shadowsocks-crypto" }` и `aws-lc-rs = { workspace = true }`.

---

### 3.2. `AeadCipher`, `derive_subkey` и `StreamNonce`

```rust
pub const SHADOWSOCKS_TAG_LEN: usize = 16;
pub const SHADOWSOCKS_NONCE_LEN: usize = 12;
pub const SHADOWSOCKS_XNONCE_LEN: usize = 24;
pub const LEGACY_MAX_PAYLOAD_LEN: usize = 0x3fff;
pub const SHADOWSOCKS_MAX_PAYLOAD: usize = 0xffff;

/// Per-key invocation ceiling matching NIST SP 800-38D (< 2^32 blocks/invocations for AES-GCM).
pub const MAX_STREAM_NONCE_COUNTER: u64 = 1 << 32;

/// Thread-safe pre-expanded AEAD session key backed by `aws_lc_rs::aead::LessSafeKey`.
pub struct AeadCipher {
    key: aws_lc_rs::aead::LessSafeKey,
    cipher_name: &'static str,
}

impl AeadCipher {
    pub fn new(cipher: CipherKind, subkey: &[u8]) -> Result<Self>;
    pub fn from_master_and_salt(cipher: CipherKind, master_key: &[u8], salt: &[u8]) -> Result<Self>;

    pub fn seal_in_place_separate_tag(
        &self,
        nonce: &[u8; 12],
        in_out: &mut [u8],
    ) -> Result<[u8; SHADOWSOCKS_TAG_LEN]>;

    pub fn encrypt(&self, nonce: &[u8; 12], payload: &[u8]) -> Result<Vec<u8>>;
    pub fn encrypt_into(&self, nonce: &[u8; 12], payload: &[u8], out: &mut Vec<u8>) -> Result<()>;

    pub fn decrypt(&self, nonce: &[u8; 12], payload: &[u8]) -> Result<Vec<u8>>;
    pub fn decrypt_in_place(&self, nonce: &[u8; 12], buf: &mut Vec<u8>) -> Result<()>;
    pub fn decrypt_detached_in_place(&self, nonce: &[u8; 12], buf: &mut [u8]) -> Result<usize>;

    /// Opens `ciphertext` in place and verifies that the resulting plaintext length
    /// equals `expected_plaintext_len` (`CryptoError::InvalidHeaderLength` on mismatch).
    pub fn open_fixed_in_place<'a>(
        &self,
        nonce: &[u8; 12],
        ciphertext: &'a mut [u8],
        expected_plaintext_len: usize,
    ) -> Result<&'a [u8]>;
}

/// Monotonic little-endian 96-bit stream nonce counter capped at `MAX_STREAM_NONCE_COUNTER`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct StreamNonce(u64);

impl StreamNonce {
    pub const fn new() -> Self;
    pub const fn from_counter(counter: u64) -> Self;
    pub const fn counter(&self) -> u64;

    /// Returns the current 12-byte little-endian nonce and advances the counter,
    /// or `Err(CryptoError::NonceOverflow)` once `counter >= MAX_STREAM_NONCE_COUNTER`.
    pub fn next(&mut self) -> Result<[u8; 12]>;
}
```

- `derive_subkey(cipher: CipherKind, master_key: &[u8], salt: &[u8]) -> Result<Zeroizing<[u8; 32]>>` использует `aws_lc_rs::hkdf::Salt::new(HKDF_SHA1_FOR_LEGACY_USE_ONLY, salt)` для классических шифров и `outline_wire::ss2022::ss2022_session_subkey_into` для SS2022. Серверный модуль `bins/outline-server/src/crypto/primitives.rs` и его тесты удаляются (тесты объединяются в `shadowsocks-crypto`).

---

### 3.3. Потоковый чанковый кодек (`shadowsocks_crypto::stream`)

Новый модуль `crates/shadowsocks-crypto/src/stream.rs` предоставляет синхронные операции кадрирования поверх `AeadCipher` и `StreamNonce`:

```rust
/// Buffer abstraction implemented for `Vec<u8>` and `bytes::BytesMut` so both
/// client and server encrypt chunks in place without intermediate copies.
pub trait SealBuf {
    fn len(&self) -> usize;
    fn is_empty(&self) -> bool { self.len() == 0 }
    fn reserve(&mut self, additional: usize);
    fn extend_from_slice(&mut self, src: &[u8]);
    fn slice_mut(&mut self, start: usize, end: usize) -> &mut [u8];
}

/// Appends `[optional salt][encrypted 2B BE length + tag][encrypted payload + tag]` into `out`.
pub fn seal_payload_chunk<B: SealBuf>(
    cipher: &AeadCipher,
    nonce: &mut StreamNonce,
    max_chunk_size: usize,
    pending_salt: Option<&[u8]>,
    payload: &[u8],
    out: &mut B,
) -> Result<()>;

/// Splits `plaintext` into chunks of at most `LEGACY_MAX_PAYLOAD_LEN` (`0x3fff`)
/// and seals each into `out` (emitting `salt` ahead of the first chunk if `!sent_salt`).
pub fn seal_legacy_chunks<B: SealBuf>(
    cipher: &AeadCipher,
    nonce: &mut StreamNonce,
    salt: &[u8],
    sent_salt: &mut bool,
    plaintext: &[u8],
    out: &mut B,
) -> Result<()>;

/// Seals the very first SS2022 TCP response frame:
/// `salt || AEAD(type=1 || now_secs_be || request_salt || len_be) || AEAD(initial_payload)`.
pub fn seal_ss2022_response_first_frame<B: SealBuf>(
    cipher: &AeadCipher,
    nonce: &mut StreamNonce,
    salt: &[u8],
    request_salt: &[u8],
    now_secs: u64,
    initial_payload: &[u8],
    out: &mut B,
) -> Result<()>;

/// Opens a `2 + SHADOWSOCKS_TAG_LEN` length block in place and validates `len <= max_chunk_size`.
pub fn open_length_block(
    cipher: &AeadCipher,
    nonce: &mut StreamNonce,
    max_chunk_size: usize,
    block: &mut [u8],
) -> Result<usize>;

/// Opens a `chunk_len + SHADOWSOCKS_TAG_LEN` payload block in place, returning `chunk_len`.
pub fn open_payload_in_place(
    cipher: &AeadCipher,
    nonce: &mut StreamNonce,
    buf: &mut [u8],
) -> Result<usize>;

/// Buffered push-mode chunk drainer (used by server `AeadStreamDecryptor`):
/// consumes one complete `[len + tag][payload + tag]` pair from `buffer` into `output`
/// when enough bytes have arrived, returning `Ok(true)` if a chunk was produced.
pub fn drain_chunk_from_bytes(
    buffer: &mut bytes::BytesMut,
    cipher: &AeadCipher,
    nonce: &mut StreamNonce,
    pending_chunk_len: &mut Option<usize>,
    max_chunk_size: usize,
    output: &mut Vec<u8>,
) -> Result<bool>;
```

- Изменения у потребителей:
  - Клиентский `TcpShadowsocksWriter` заменяет `nonce: [u8; 12]` на `nonce: StreamNonce` и делегирует `encrypt_payload_frame_into` (и отправку SS2022 request header) в `seal_payload_chunk` / `AeadCipher`.
  - Клиентский `TcpShadowsocksReader` заменяет `nonce: [u8; 12]` на `nonce: StreamNonce` и использует `open_length_block` / `open_payload_in_place` в `read_one_decrypted_chunk`.
  - Серверный `bins/outline-server/src/crypto/stream.rs` удаляет локальные `drain_length_header`, `drain_payload`, `encrypt_legacy_chunks`, `encrypt_legacy_chunk`, `encrypt_ss2022_chunk` и делегирует в `shadowsocks_crypto::stream::*`, сохраняя только multi-user выбор ключа `ensure_session_key` / `try_user`.

---

### 3.4. `AesHeaderCipher` и `XChaChaCipher` для SS2022 UDP

В `crates/shadowsocks-crypto/src/ss2022_udp.rs` экспортируются переиспользуемые шифры (потокобезопасные `Send + Sync`), чтобы сервер кэшировал их в `UserKey` без прямых зависимостей на `aes` и `chacha20poly1305`:

```rust
pub struct AesHeaderCipher { /* Aes128 | Aes256 */ }

impl AesHeaderCipher {
    pub fn new(cipher: CipherKind, master_key: &[u8]) -> Result<Self>;
    pub fn encrypt_header(&self, header: &[u8; 16]) -> [u8; 16];
    pub fn decrypt_header(&self, encrypted: &[u8]) -> Result<[u8; 16]>;
}

pub struct XChaChaCipher(chacha20poly1305::XChaCha20Poly1305);

impl XChaChaCipher {
    pub fn new(master_key: &[u8]) -> Result<Self>;
    pub fn seal_in_place_separate_tag(&self, nonce: &[u8; 24], in_out: &mut [u8]) -> Result<[u8; 16]>;
    pub fn decrypt_detached_in_place(&self, nonce: &[u8; 24], buf: &mut [u8]) -> Result<usize>;
}
```

- Функции `encrypt_udp_separate_header`, `decrypt_udp_separate_header` и ChaCha20-2022 UDP в `shadowsocks-crypto` переписываются поверх `AesHeaderCipher` и `XChaChaCipher`.
- В серверных `user_key.rs`, `udp.rs` и `diagnose.rs` локальные `AesHeaderCipher`, `XChaCha20Poly1305` и `encrypt/decrypt_ss2022_separate_header` заменяются на типы из `shadowsocks-crypto`.

---

## 4. Обработка ошибок и диагностика

1. В `shadowsocks_crypto::CryptoError` добавляются варианты `InvalidChunkSize(usize)` и `InvalidHeaderLength`, чтобы серверный `bins/outline-server/src/crypto/error.rs` через `From<shadowsocks_crypto::CryptoError>` без потерь сохранял диагностические категории в `diagnose.rs` (`invalid_header_len`, `auth_failed`, `subkey_error`) и метриках.
2. По достижении `MAX_STREAM_NONCE_COUNTER` (`1 << 32`) `StreamNonce::next()` возвращает `Err(CryptoError::NonceOverflow)` (маппится в `NonceExhausted` на сервере и ошибку потока на клиенте), предотвращая повторное использование пары `(key, nonce)` в AES-GCM.

---

## 5. План тестирования и актуализации документации

1. **Регрессионные known-answer тесты (`crates/shadowsocks-crypto/src/tests/known_answers.rs`):** обязаны пройти без изменения зашитых байтовых констант, доказывая побайтовую эквивалентность `aws-lc-rs` прежнему стеку на всех 6 шифрах (`aes-128-gcm`, `aes-256-gcm`, `chacha20-ietf-poly1305` и три шифра SS2022).
2. **Unit-тесты `shadowsocks_crypto::stream`:**
   - round-trip `seal_legacy_chunks` + `drain_chunk_from_bytes` и `open_length_block`/`open_payload_in_place` как на `Vec<u8>`, так и на `BytesMut`;
   - round-trip `seal_ss2022_response_first_frame`;
   - проверка отклонения `chunk_len > max_chunk_size` и срабатывания `MAX_STREAM_NONCE_COUNTER` (`StreamNonce::from_counter((1 << 32) - 1)`).
3. **Проверка графа зависимостей:**
   - `cargo tree --workspace --exclude sockudo-ws --exclude outline-windows -i ring` — пустой вывод;
   - `cargo tree -i 'rustls@0.23' -e features | grep 'rustls feature "ring"'` — пустой вывод.
4. **Актуализация документации (по правилам синхронизации EN/RU):**
   - `AGENTS.md`: обновить описание `crates/` (`shadowsocks-crypto` теперь truly-shared между сервером и клиентом) и пункт про `ring` (крейт `ring` полностью удалён из workspace, единый крипто-движок — `aws-lc-rs`);
   - `bins/outline-server/docs/SESSION-RESUMPTION.md` и `SESSION-RESUMPTION.ru.md` (строка 38: актуализировать упоминание CSPRNG вместо `ring::rand::SystemRandom`).
5. **Полный локальный CI-гейт:** `fmt`, `clippy`, `cargo test --workspace`, `RUN_E2E_FAILOVER=1 ... e2e_*` и `android/rust`.
