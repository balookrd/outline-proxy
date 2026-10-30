# ClientHello в QUIC Initial как у браузеров — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** TLS ClientHello внутри QUIC Initial у H3-клиента совпадает с Chrome 156 / Apple URLSession (Safari) / Firefox 159 по набору и порядку расширений, cipher suites, группам, key_share, подписям, сжатию сертификата, GREASE и ECH GREASE, а JA4 каждого профиля равен JA4 браузера. Плюс размер первого Initial-датаграммы как у браузера.

**Architecture:** rustls 0.23.40 вендорится в `vendor/rustls` (как quinn-proto) с одним логическим патчем «client-hello-shape»: opt-in `ClientConfig::client_hello_shape` (по умолчанию `None` — побайтово upstream, и сервер, и TCP-клиент не затронуты) управляет GREASE, лишними и сырыми расширениями, порядком, дополнительными key_share; плюс группа `secp521r1` в aws-lc-rs-провайдере. Всё, что rustls даёт публично (только TLS 1.3, порядок подписей через обёртку верификатора, `cert_decompressors`, `EchMode::Grease`), делается в нашем крейте. Профили — новый модуль `crates/outline-transport/src/quic/tls_profile.rs`, применяются только к QUIC-конфигу H3; патч-API rustls — только через гейт-модуль `crates/outline-transport/src/tls_vendored.rs`.

**Tech Stack:** Rust 2024, rustls 0.23.40 (vendored, aws-lc-rs), quinn 0.11.9 / vendored quinn-proto 0.11.15, `brotli-decompressor`, `ruzstd`, `flate2` (уже в дереве), tshark 4.6.

**Предыстория:** QUIC TP уже как у браузеров (`a3854e5f`…`c279db00`). Замер ClientHello — память проекта `quic-tls-clienthello-vs-browsers`, захваты в scratchpad `chello.bcEH/`.

## Global Constraints

- Комментарии в коде, commit-сообщения и PR — на английском; план и чат — на русском. Термины: «носитель» (не «карьер»), «гейт» (не «ворота»/«врата»).
- Никогда не добавлять трейлер `Co-Authored-By: Claude` и футер «Generated with Claude Code».
- Коммит — только по явной команде владельца; **никогда не `git push`** без отдельной команды. Работать в `main`, веток не создавать. Исполнители задач НЕ коммитят: одобренное складывается в индекс, следующая задача ревьюится по незастейдженному diff.
- Тесты наших крейтов — в `tests/` рядом с модулем; inline `mod tests {}` запрещены. `vendor/rustls` — upstream-стиль, не форматировать и не линтовать; его inline-тесты только чинить до компиляции.
- Гейт (ровно эти команды):
  ```bash
  cargo fmt --check -p outline-ss-rust -p outline-ws-rust -p outline-ui \
    -p outline-metrics -p outline-net -p outline-routing -p outline-transport \
    -p outline-tun -p outline-uplink -p outline-wire \
    -p shadowsocks-crypto -p socks5-proto
  cargo clippy --workspace --exclude sockudo-ws --all-targets --no-deps -- -D warnings
  cargo test --workspace --exclude sockudo-ws
  (cd android/rust && cargo fmt --check && cargo clippy --no-deps -- -D warnings)
  ```
  Известный посторонний флейк: `outline-tun health_recovery::tun_downlink_traffic_restores_uplink_health_without_probe` — при единственном падении перезапустить и указать оба прогона.
- **Никогда `cargo fmt --all`** (переформатирует `vendor/`); format-only diff в `vendor/` откатывать.
- rustls — только aws-lc-rs: никаких `ring`-фич у rustls/quinn/webpki; фичи rustls `brotli`/`zlib` **не включать** (иначе при совместной сборке у сервера появятся компрессоры и он начнёт сжимать сертификат — смена серверного поведения).
- Патч rustls: при `client_hello_shape = None` ClientHello, ServerHello-обработка и порядок расхода случайности **побайтово как у upstream**; сервер (`outline-ss-rust`), TCP-клиент (`tokio-rustls`), probe и mesh не трогают новую опцию.
- Патч-API rustls в production-коде — только через `crates/outline-transport/src/tls_vendored.rs`; в `.github/workflows/ci.yml` добавляется инвариант по образцу quinn-proto (`client_hello_shape\|ClientHelloShape\|ExtensionOrder\|kx_group::SECP521R1`), тестовые модули освобождены.
- `PATCHES.md`/`PATCHES.ru.md`, `CHANGELOG.md`/`CHANGELOG.ru.md` — парой; `rustls-0.23.40.patch` генерируется тем же способом, что `quinn-proto-0.11.15.patch` (временный git-репозиторий с чистым крейтом в новом уникальном каталоге scratchpad), round-trip (`patch -p1` к чистому crates.io 0.23.40 → `diff -r` пусто). Никаких `rm -rf` с переменными.
- Выкатка — только по команде владельца, по одному узлу.

## Замеры (2026-10-29, хост `localtest.me` → 127.0.0.1, SNI уходит)

| | Chrome 156 | Apple (macOS 27, URLSession) | Firefox 159 |
|---|---|---|---|
| JA4 | `q13d0312h3_55b375c5d22e_178839b6cec1` | `q13d0311h3_55b375c5d22e_f2a83c8e78ae` | `q13d0315h3_55b375c5d22e_dc5437974b47` |
| Расширения (набор) | 0, 10, 13, 16, 27, 43, 45, 51, 57, 17613, 51764, 65037 | GREASE, 0, 5, 10, 13, 16, 18, 27, 43, 45, 51, 57, GREASE | 0, 5, 10, 13, 16, 23, 27, 28, 34, 43, 45, 51, 57, 65037, 65281 |
| Порядок | случайный, ECH тоже в перемешке | фиксированный `GREASE,0,10,16,5,13,18,51,45,43,57,27,GREASE` | случайный, ECH последним |
| cipher_suites | 1301, 1302, 1303 | GREASE, 1302, 1303, 1301 | 1301, 1303, 1302 |
| supported_groups | 11ec, 1d, 17, 18 | GREASE, 11ec, 1d, 17, 18, 19 | 11ec, 1d, 17, 18, 19 |
| key_share | 11ec, 1d | GREASE (1 байт `00`), 11ec, 1d | 11ec, 1d, 17 |
| supported_versions | 0304 | GREASE, 0304 | 0304 |
| signature_algorithms | 0403,0804,0401,0503,0805,0501,0806,0601,0201 | 0403,0804,0401,0503,0805,0805,0501,0806,0601,0201 (0805 дважды) | 0403,0503,0603,0203,0804,0805,0806,0401,0501,0601,0201 |
| compress_certificate | brotli | zlib | zlib, zstd, brotli |
| ECH GREASE | kdf 1 / aead 1, enc 32, payload 176/208/240 (длина расширения 218–282) | нет | kdf 1 / aead 1, enc 32, payload 240 (282) |
| Сырые расширения | 17613 ALPS = `0003026833`; 51764 = 186 байт (ниже) | 18 SCT = пусто; GREASE: первый пустой, последний `00` | 28 = `4001`; 34 = `0008040305030603 0203`; 65281 = `00` |
| UDP Initial | 1250 | 1200 | 1252 |

Chrome 0xca34 (51764), одинаков во всех захватах (186 байт):
```
00b80582df1302010582df1302060582df13020d0582df13020e0582df13020f0582df1302120582df1302130582df13021408839a648c9b2d010708839a648c9b2d010808839a648c9b2d010908839a648c9b2d010a08839a648c9b2d010b08839a648c9b2d010c08839a648c9b2d010d08839a648c9b2d011208839a648c9b2d011304d679090104d679090404d679090504d679090604d679090704d679090804d679090a04d679090b04d679090c04d679090d04d679090f
```
Firefox 34 (delegated_credentials), 10 байт: `0008 0403 0503 0603 0203`.

Наш клиент сейчас (все профили один JA4 `q13d0312h3_…_16aff4c164e8`): расширения 0, 5, 10, 11, 13, 16, 23, 35, 43, 45, 51, 57; подписи 0503,0403,0603,0807,0806,0805,0804,0601,0501,0401; нет 27; UDP 1200.

## Решения

1. **Вендорим rustls 0.23.40** (версия корневого `Cargo.lock`); Android (сейчас 0.23.43) сводится на неё через `[patch.crates-io]`, как было с quinn-proto. Если какой-то крейт Android требует ≥ 0.23.41 — STOP и вопрос владельцу (вендорить 0.23.43 и поднять корень).
2. **Опция патча — `ClientConfig::client_hello_shape: Option<Arc<ClientHelloShape>>`**, по умолчанию `None`. Внутри:
   - `omit_extended_master_secret`, `omit_ec_point_formats`, `omit_status_request: bool`;
   - `extra_extensions: Vec<(u16, Vec<u8>)>` — пишутся как есть, участвуют в порядке наравне со штатными;
   - `grease: bool` — GREASE в стиле BoringSSL (RFC 8701): случайные значения `0x?A?A` на соединение; первый элемент cipher_suites, supported_groups, supported_versions; первая запись key_share с 1-байтным ключом `00`; расширение-GREASE первым (пустое) и последним (`00`), значения двух GREASE-расширений различны;
   - `extension_order: ExtensionOrder` — `Upstream` (rustls: перемешано, ECH и PSK в конце), `ShuffledWithEch` (ECH тоже в перемешке, PSK последним), `Fixed(Vec<u16>)` (ровно этот порядок; не перечисленные — после списка в порядке upstream; GREASE-расширения при `grease` — первым и последним; PSK всегда в самом конце, ECH/ECH-outer — по списку, если перечислены, иначе перед PSK);
   - `extra_key_share_groups: Vec<NamedGroup>` — дополнительные key_share после штатных (Firefox: secp256r1). Клиент хранит их ключи и, если ServerHello выбрал такую группу, завершает обмен с ней.
   При HRR форма сохраняется (тот же seed, те же GREASE-значения), как rustls уже делает для порядка.
3. **`kx_group::SECP521R1`** в `crypto/aws_lc_rs` (по образцу `SECP384R1`, через `agreement::ECDH_P521`); в `DEFAULT_KX_GROUPS`/`ALL_KX_GROUPS` не добавляется — дефолты не меняются.
4. **Подписи** — публичным API: обёртка `BrowserVerifier` над `WebPkiServerVerifier`, отдаёт `supported_verify_schemes()` = список браузера (с дублями и 0201/0203 — проверка их не встретит: TLS 1.3 сервер такие в CertificateVerify не выберет, а сертификаты с SHA-1 webpki и так отвергает), всё остальное делегирует.
5. **Сжатие сертификата** — публичный `ClientConfig::cert_decompressors` с собственными декомпрессорами в нашем крейте (zlib — `flate2`, brotli — `brotli-decompressor`, zstd — `ruzstd`), без фич rustls. Наш сервер компрессоров не имеет и сжимать не станет; декомпрессоры нужны, чтобы сторонний сервер/CDN не порвал рукопожатие.
6. **ECH GREASE** — публичный `EchMode::Grease(EchGreaseConfig::new(DH_KEM_X25519_HKDF_SHA256_AES_128, placeholder))` (enc 32, kdf 1, aead 1 — как у Chrome/Firefox); placeholder — 32 случайных байта на сборку конфига. Длину payload rustls выводит из внутреннего hello с выравниванием; если она не попадает в {176, 208, 240} (Chrome) / не равна 240 (Firefox) — STOP с цифрами, решение о патче паддинга — отдельно.
7. **Только TLS 1.3 для QUIC-конфига** — убирает 35 (`session_ticket` идёт от TLS 1.2-резюмпции). 11 и 23, 5 убираются флагами патча там, где браузер их не шлёт.
8. **Профили — только для QUIC.** TCP-ClientHello (h1/h2 поверх TCP) у браузеров другой (у Chrome там GREASE, padding и пр.) — не трогаем: `crate::tls::build_client_config` остаётся как есть, QUIC получает свой `build_quic_client_config`.
9. **Размер Initial — НЕ подгоняется (решение владельца при выполнении Task 3).** Initial остаётся 1200 у всех профилей: 1250/1252 по IPv6 дают 1298/1300 байт IP-пакета при минимальном MTU 1280. Тема переносится в план дробления CRYPTO; IPv6-размеры браузеров не замерены.
10. **Вне этого плана** (отдельные планы): дробление CRYPTO в Initial (Chrome «chaos protection», neqo split) — патч quinn-proto; TCP ClientHello; резюмпция (PSK/0-RTT в ClientHello) — проверяется только первый ClientHello.

## File Structure

| Файл | Что меняется | Задача |
|---|---|---|
| `vendor/rustls/**` | крейт 0.23.40 как есть (dev-deps убраны) | 1 |
| `Cargo.toml`, `android/rust/Cargo.toml`, `android/rust/Cargo.lock` | `[patch.crates-io] rustls` | 1 |
| `vendor/rustls/src/client/client_conn.rs` | поле `client_hello_shape`, типы `ClientHelloShape`, `ExtensionOrder` | 2 |
| `vendor/rustls/src/client/hs.rs` | omit-флаги, GREASE, extra key shares, сырые расширения | 2 |
| `vendor/rustls/src/msgs/handshake.rs` | кодирование сырых и GREASE-расширений, режимы порядка | 2 |
| `vendor/rustls/src/client/tls13.rs` | завершение обмена по extra key share | 2 |
| `vendor/rustls/src/crypto/aws_lc_rs/kx.rs` (+ `mod.rs` реэкспорт) | `SECP521R1` | 2 |
| `vendor/rustls/src/lib.rs` | реэкспорт новых типов | 2 |
| `crates/outline-transport/src/tls_vendored.rs` | гейт к патч-API rustls | 2 |
| `crates/outline-transport/Cargo.toml` | `brotli-decompressor`, `ruzstd`, `flate2` | 3 |
| `crates/outline-transport/src/quic/tls_profile.rs` | `QuicTlsProfile` для трёх семейств, декомпрессоры, `BrowserVerifier` | 3 |
| `crates/outline-transport/src/tls.rs` | `build_quic_client_config(fp, alpn)` | 3 |
| `crates/outline-transport/src/quic/tls_config.rs` | QUIC-конфиг через новый билдер | 3 |
| `crates/outline-transport/src/quic/tests/{tls_config,tls_profile}.rs` | JA4-хелпер, wire-тесты, loopback-рукопожатия | 2, 3 |
| `.github/workflows/ci.yml` | инвариант rustls-гейта | 2 |
| `rustls-0.23.40.patch`, `PATCHES*.md`, `AGENTS.md`, `bins/outline-ws-rust/CHANGELOG*.md` | документация | 1, 4 |

---

### Task 1: Вендоринг rustls 0.23.40 без изменений

**Files:**
- Create: `vendor/rustls/` (копия `~/.cargo/registry/src/*/rustls-0.23.40`)
- Modify: `Cargo.toml` (корень), `android/rust/Cargo.toml`, `android/rust/Cargo.lock`, `PATCHES.md`, `PATCHES.ru.md`, `AGENTS.md`

**Interfaces:**
- Produces: `rustls` во всём дереве (корень и Android) — один экземпляр из `vendor/rustls`.

- [ ] **Step 1: Скопировать крейт.** `cp -R ~/.cargo/registry/src/index.crates.io-*/rustls-0.23.40 vendor/rustls` (каталог назначения не должен существовать; проверить `ls vendor`). Удалить `.cargo-ok`/`.cargo_vcs_info.json`, если есть, по образцу `vendor/quinn-proto`. В `vendor/rustls/Cargo.toml` убрать секции `[dev-dependencies]` (и `[[bench]]`/`[[example]]`, если ссылаются на отсутствующие файлы) — ровно как сделано для quinn-proto (сравнить `vendor/quinn-proto/Cargo.toml` с `Cargo.toml.orig`).
- [ ] **Step 2: Патч-секции.** В корневом `Cargo.toml` в `[patch.crates-io]` рядом с `quinn-proto`: `rustls = { path = "vendor/rustls" }`. В `android/rust/Cargo.toml` — `rustls = { path = "../../vendor/rustls" }` рядом с его записью quinn-proto.
- [ ] **Step 3: Одна версия.** `cargo tree -i rustls --workspace -e normal` и `(cd android/rust && cargo tree -i rustls -e normal)` → один `rustls v0.23.40 (…/vendor/rustls)`. Если Android не сводится на 0.23.40 из-за требования зависимости ≥ 0.23.41 — STOP, NEEDS_CONTEXT с выводом `cargo tree`.
- [ ] **Step 4: Документация.** `PATCHES.md`/`PATCHES.ru.md`: таблица артефактов — строка `rustls-0.23.40.patch` (все отличия `vendor/rustls` от crates.io `rustls 0.23.40`); новый раздел `## rustls (0.23.40)` с baseline и единственным пунктом «Vendoring trim (`Cargo.toml`) — dev-dependencies removed». `AGENTS.md`: в абзаце о vendored-крейтах добавить `vendor/rustls`. Сгенерировать `rustls-0.23.40.patch` (пока только `Cargo.toml`) тем же способом, что quinn-proto, round-trip пустой.
- [ ] **Step 5: Полный гейт** → зелёный. Не коммитить.

---

### Task 2: Патч rustls «client-hello-shape» и гейт

**Files:**
- Modify: `vendor/rustls/src/client/client_conn.rs`, `vendor/rustls/src/client/hs.rs`, `vendor/rustls/src/client/tls13.rs`, `vendor/rustls/src/msgs/handshake.rs`, `vendor/rustls/src/crypto/aws_lc_rs/kx.rs`, `vendor/rustls/src/crypto/aws_lc_rs/mod.rs`, `vendor/rustls/src/lib.rs`
- Create: `crates/outline-transport/src/tls_vendored.rs` (подключить в `lib.rs` под той же фичей, что `quic`)
- Modify: `.github/workflows/ci.yml`
- Test: `crates/outline-transport/src/quic/tests/tls_config.rs`

**Interfaces:**
- Produces (rustls, `pub`):
  ```rust
  // rustls::client
  #[derive(Debug, Clone, Default)]
  pub struct ClientHelloShape {
      pub omit_extended_master_secret: bool,
      pub omit_ec_point_formats: bool,
      pub omit_status_request: bool,
      pub extra_extensions: Vec<(u16, Vec<u8>)>,
      pub grease: bool,
      pub extension_order: ExtensionOrder,
      pub extra_key_share_groups: Vec<NamedGroup>,
  }
  #[derive(Debug, Clone, Default, PartialEq, Eq)]
  pub enum ExtensionOrder { #[default] Upstream, ShuffledWithEch, Fixed(Vec<u16>) }
  // ClientConfig: pub client_hello_shape: Option<Arc<ClientHelloShape>>  (None by default)
  // rustls::crypto::aws_lc_rs::kx_group::SECP521R1: &dyn SupportedKxGroup
  ```
- Produces (гейт `tls_vendored.rs`):
  ```rust
  pub(crate) use rustls::client::{ClientHelloShape, ExtensionOrder};
  pub(crate) fn set_client_hello_shape(config: &mut rustls::ClientConfig, shape: ClientHelloShape);
  pub(crate) fn secp521r1() -> &'static dyn rustls::crypto::SupportedKxGroup;
  ```

- [ ] **Step 1: Тестовые хелперы и failing-тесты** в `crates/outline-transport/src/quic/tests/tls_config.rs`. JA4 (FoxIO, QUIC-вариант) по захваченному ClientHello — разбор уже есть (`clienthello_extension`, `transport_param_ids_from_clienthello`); добавить:

  ```rust
  fn is_grease_u16(v: u16) -> bool {
      v & 0x0f0f == 0x0a0a && (v >> 8) == (v & 0xff)
  }

  /// Extension types of a ClientHello in wire order.
  fn extension_types(ch: &[u8]) -> Vec<u16> { /* walk the same layout as clienthello_extension */ }
  /// Cipher suites in offer order.
  fn cipher_suites(ch: &[u8]) -> Vec<u16> { /* same layout */ }
  /// u16 list inside an extension whose body is <u16 len><u16...> (groups 10, sig algs 13).
  fn u16_list_ext(ch: &[u8], ext: u16) -> Vec<u16> { /* … */ }

  /// JA4 for a QUIC ClientHello (FoxIO spec): q + "13" + d/i + 2-digit ciphers + 2-digit
  /// extensions (GREASE excluded, SNI and ALPN counted) + ALPN first/last char, then
  /// sha256[..12] of sorted ciphers, then sha256[..12] of sorted extensions without
  /// SNI/ALPN joined with "_" and the signature algorithms in offer order.
  fn ja4(ch: &[u8]) -> String { /* … */ }

  #[test]
  fn ja4_helper_reproduces_measured_chrome_hash() {
      // JA4_r of the Chrome 156 capture -> its JA4 c-part.
      let c = "000a,000d,001b,002b,002d,0033,0039,44cd,ca34,fe0d_0403,0804,0401,0503,0805,0501,0806,0601,0201";
      assert_eq!(sha256_hex12(c), "178839b6cec1");
      assert_eq!(sha256_hex12("1301,1302,1303"), "55b375c5d22e");
  }
  ```

  SHA-256 — тем же крейтом, что уже использует `hmac_sha256` в этом файле (`hmac`/`digest` из ring или aws-lc-rs — смотреть импорт). Тесты на сам патч (через гейт, конфиг собирается вручную, профили — в Task 3):

  ```rust
  /// Capture the Initial ClientHello of a QUIC client config built from `tls`.
  fn capture_with_tls(tls: rustls::ClientConfig, seed: u8) -> Vec<u8> {
      let quic = quinn::crypto::rustls::QuicClientConfig::try_from(tls).unwrap();
      capture_clienthello(quinn::ClientConfig::new(Arc::new(quic)), quinn::EndpointConfig::default(), [seed; 32])
  }

  fn tls13_config() -> rustls::ClientConfig { /* builder_with_provider(aws-lc-rs default).with_protocol_versions(&[&TLS13]), test roots, no client auth, alpn h3 */ }

  #[tokio::test]
  async fn default_shape_keeps_upstream_extensions() {
      let ch = capture_with_tls(tls13_config(), 1);
      let mut ids = extension_types(&ch); ids.sort();
      assert_eq!(ids, [0, 5, 10, 11, 13, 16, 23, 43, 45, 51, 57]);
  }

  #[tokio::test]
  async fn shape_omits_adds_and_greases() {
      use crate::tls_vendored::{ClientHelloShape, ExtensionOrder, set_client_hello_shape};
      let mut tls = tls13_config();
      set_client_hello_shape(&mut tls, ClientHelloShape {
          omit_extended_master_secret: true,
          omit_ec_point_formats: true,
          omit_status_request: false,
          extra_extensions: vec![(18, vec![])],
          grease: true,
          extension_order: ExtensionOrder::Fixed(vec![0, 10, 16, 5, 13, 18, 51, 45, 43, 57]),
          extra_key_share_groups: vec![],
      });
      for seed in 0..8u8 {
          let ch = capture_with_tls(tls.clone(), seed);
          let ids = extension_types(&ch);
          assert!(is_grease_u16(ids[0]) && is_grease_u16(*ids.last().unwrap()));
          assert_ne!(ids[0], *ids.last().unwrap(), "two distinct GREASE extensions");
          assert_eq!(ids[1..ids.len() - 1], [0, 10, 16, 5, 13, 18, 51, 45, 43, 57]);
          assert!(is_grease_u16(cipher_suites(&ch)[0]));
          assert!(is_grease_u16(u16_list_ext(&ch, 10)[0]));
          // key_share: GREASE entry with a 1-byte key first; supported_versions: GREASE first.
      }
  }

  #[tokio::test]
  async fn extra_key_share_and_shuffled_ech() { /* extra_key_share_groups = [secp256r1]: key_share groups 11ec,1d,17; ShuffledWithEch + EchMode::Grease: over 16 seeds 0xfe0d is not always last */ }
  ```

  Плюс loopback-тест рукопожатия (сервер — `loopback::Loopback`, его rustls-сервер; клиент — `tls13_config()` с полной формой и `extra_key_share_groups = [secp256r1]`): рукопожатие проходит, echo работает. Отдельный loopback-тест, где сервер ограничен группой `secp256r1` (собрать `ServerConfig` с провайдером, у которого `kx_groups = [SECP256R1]`) — клиент завершает обмен по extra key share **без HRR** (проверить `conn.handshake_data()`/статистику: один Initial-раунд; если API не даёт — проверить, что рукопожатие успешно и в логе rustls нет HRR, и описать в отчёте).

- [ ] **Step 2: Убедиться, что не собирается** (`tls_vendored` нет).
- [ ] **Step 3: Тип и поле.** В `client_conn.rs` — `ClientHelloShape`, `ExtensionOrder` (документация на каждое поле — смысл из «Решения» п. 2), поле `ClientConfig::client_hello_shape` (в builder — `None`, в ручном `Debug`, если есть). Реэкспорт из `rustls::client` и в `lib.rs` там, где экспортируются остальные client-типы.
- [ ] **Step 4: Сборка расширений (`hs.rs::emit_client_hello_for_retry`).** При `Some(shape)`:
  - `omit_extended_master_secret` → `exts.extended_master_secret_request = None`; `omit_status_request` → `exts.certificate_status_request = None`; `omit_ec_point_formats` → не выставлять `ec_point_formats`;
  - `extra_key_share_groups`: для каждой группы, найденной `config.find_kx_group(g, TLSv1_3)` и ещё не присутствующей в `shares`, `start()` ключ, добавить `KeyShareEntry` после штатных, сохранить `Box<dyn ActiveKeyExchange>` в состоянии рукопожатия (рядом с основным `key_share`, переносится в `ExpectServerHello`);
  - `grease`: значения из `config.provider.secure_random` один раз на ClientHello, сохраняются в `input.hello` для HRR; GREASE в cipher_suites (первым), named_groups (первым), supported_versions (первым), key_shares (первым, ключ `[0]`), два GREASE-расширения (первое пустое, последнее `[0]`, значения различны).
  `None` — код идёт ровно прежним путём (никаких лишних вызовов `secure_random`).
- [ ] **Step 5: Кодирование и порядок (`msgs/handshake.rs`).** `ClientExtensions` получает поля для сырых расширений (`extra: Vec<(ExtensionType, Vec<u8>)>`, GREASE-первый/последний) и режим порядка. `used_extensions_in_encoding_order`: `Upstream` — прежний код; `ShuffledWithEch` — ECH-расширения входят в перемешиваемое множество, PSK последним; `Fixed(list)` — по списку, остальные после в порядке upstream, GREASE первым/последним, PSK в самом конце. Сырые расширения кодируются как `type | u16 len | bytes`. Проверить, что серверная сторона и разбор чужих ClientHello (сервер rustls читает `ClientExtensions`) не изменились: новые поля только у исходящего клиентского hello.
- [ ] **Step 6: ServerHello с extra key share (`client/tls13.rs`).** Там, где сверяется группа `their_key_share` с нашим `key_share` (и гибридным компонентом), добавить ветку: группа совпала с одним из extra — `complete` его ключом. Иначе — прежнее поведение (включая HRR).
- [ ] **Step 7: `SECP521R1`.** В `crypto/aws_lc_rs/kx.rs` по образцу `SECP384R1` (`agreement::ECDH_P521`, `NamedGroup::secp521r1`), реэкспорт в `kx_group`; `DEFAULT_KX_GROUPS`/`ALL_KX_GROUPS` не трогать.
- [ ] **Step 8: Гейт `crates/outline-transport/src/tls_vendored.rs`.**

  ```rust
  //! Gate for the patched `rustls` API (see PATCHES.md). Production code reaches the
  //! patch only through this module, so a rebase of the vendored crate touches one file.

  use std::sync::Arc;

  pub(crate) use rustls::client::{ClientHelloShape, ExtensionOrder};

  /// Shape the QUIC ClientHello like a browser (client-only; `None` keeps upstream rustls).
  pub(crate) fn set_client_hello_shape(config: &mut rustls::ClientConfig, shape: ClientHelloShape) {
      config.client_hello_shape = Some(Arc::new(shape));
  }

  /// `secp521r1` key exchange (aws-lc-rs), offered by Safari and Firefox.
  pub(crate) fn secp521r1() -> &'static dyn rustls::crypto::SupportedKxGroup {
      rustls::crypto::aws_lc_rs::kx_group::SECP521R1
  }
  ```

  Пока production его не вызывает — `#[cfg_attr(not(test), expect(dead_code, reason = "used by the QUIC TLS profiles (next task)"))]` на элементах.
- [ ] **Step 9: CI-инвариант.** В `.github/workflows/ci.yml` новый шаг по образцу quinn-proto: `grep -rn 'client_hello_shape\|ClientHelloShape\|ExtensionOrder\|kx_group::SECP521R1' bins/*/src crates/*/src --include='*.rs' | grep -v '/tests/' | grep -v '^crates/outline-transport/src/tls_vendored\.rs:'` → пусто, иначе ошибка.
- [ ] **Step 10: Тесты** `cargo test -p outline-transport --features h3 quic::` → новые и прежние PASS. Upstream-тесты rustls прогнать в копии крейта в scratchpad с исходным манифестом (как делали с quinn-proto) — все PASS, приложить счёт.
- [ ] **Step 11: Полный гейт** → зелёный. Не коммитить.

---

### Task 3: TLS-профили браузеров для QUIC

**Files:**
- Create: `crates/outline-transport/src/quic/tls_profile.rs`
- Modify: `crates/outline-transport/Cargo.toml`, `crates/outline-transport/src/tls.rs`, `crates/outline-transport/src/quic/tls_config.rs`, `crates/outline-transport/src/quic/tp_profile.rs`, `crates/outline-transport/src/quic/mod.rs`
- Test: `crates/outline-transport/src/quic/tests/tls_config.rs`, `crates/outline-transport/src/quic/tests/tls_profile.rs`

**Interfaces:**
- Consumes: гейт Task 2.
- Produces:
  ```rust
  // quic/tls_profile.rs
  pub(crate) struct QuicTlsProfile {
      pub(crate) cipher_suites: &'static [rustls::CipherSuite],     // offer order
      pub(crate) kx_groups: &'static [rustls::NamedGroup],          // offer order, real groups only
      pub(crate) sig_schemes: &'static [rustls::SignatureScheme],   // verbatim, duplicates kept
      pub(crate) cert_compression: &'static [rustls::CertificateCompressionAlgorithm],
      pub(crate) ech_grease: bool,
      pub(crate) omit_extended_master_secret: bool,
      pub(crate) omit_status_request: bool,
      pub(crate) extra_extensions: &'static [(u16, &'static [u8])],
      pub(crate) grease: bool,
      pub(crate) order: ShapeOrder,                                 // Shuffled | ShuffledWithEch | Fixed(&'static [u16])
      pub(crate) extra_key_shares: &'static [rustls::NamedGroup],
  }
  pub(crate) fn for_fingerprint(fp: Option<TlsFingerprint>) -> &'static QuicTlsProfile;
  // tls.rs
  pub(crate) fn build_quic_client_config(fp: Option<TlsFingerprint>, alpn: &[&[u8]]) -> Arc<rustls::ClientConfig>;
  ```

- [ ] **Step 1: Failing-тесты** (`tests/tls_config.rs`), по одному на семейство, на двух–шестнадцати seed'ах:

  ```rust
  #[tokio::test]
  async fn h3_chromium_clienthello_matches_chrome_156() {
      use crate::fingerprint_profile::{TlsFingerprint, with_dial_fingerprint};
      for seed in 0..8u8 {
          let ch = with_dial_fingerprint(Some(TlsFingerprint::Chromium), async move {
              capture_clienthello(super::h3_quic_client_config(), super::h3_endpoint_config(), [seed; 32])
          }).await;
          assert_eq!(ja4(&ch), "q13d0312h3_55b375c5d22e_178839b6cec1");
          assert_eq!(cipher_suites(&ch), [0x1301, 0x1302, 0x1303]);
          assert_eq!(u16_list_ext(&ch, 10), [0x11ec, 0x1d, 0x17, 0x18]);
          assert_eq!(clienthello_extension(&ch, 17613), Some(&[0x00, 0x03, 0x02, b'h', b'3'][..]));
          assert_eq!(clienthello_extension(&ch, 51764).map(<[u8]>::len), Some(186));
          // ECH GREASE: enc 32, payload in {176, 208, 240}
      }
      // over the seeds the ECH extension is not always last
  }

  #[tokio::test]
  async fn h3_safari_clienthello_matches_apple() {
      // JA4 q13d0311h3_55b375c5d22e_f2a83c8e78ae; order GREASE,0,10,16,5,13,18,51,45,43,57,27,GREASE;
      // ciphers GREASE,1302,1303,1301; groups GREASE,11ec,1d,17,18,19; key_share GREASE(1 byte),11ec,1d;
      // supported_versions GREASE,0304; sig algs with 0805 twice; compress_certificate [zlib].
  }

  #[tokio::test]
  async fn h3_firefox_clienthello_matches_firefox_159() {
      // JA4 q13d0315h3_55b375c5d22e_dc5437974b47; ECH last; ciphers 1301,1303,1302;
      // groups 11ec,1d,17,18,19; key_share 11ec,1d,17; compress [zlib,zstd,brotli];
      // 28 = 4001, 34 = 0008040305030603 0203, 65281 = 00.
  }

  #[tokio::test]
  async fn h3_initial_datagram_size_follows_profile() {
      // first Initial datagram length: 1200 for every profile (decision 9)
  }
  ```

  Ожидаемые значения — ровно из таблицы «Замеры»; утверждения в комментариях раскрыть в настоящие `assert_eq!`. В `tests/tls_profile.rs` — loopback-рукопожатия по всем трём профилям против нашего quinn/rustls-сервера (`loopback::Loopback`; корни клиента — тестовый override, тот же механизм, что у `build_client_config`), echo по bidi-потоку, `close_reason() == None`; и unit-тест декомпрессоров: zlib/brotli/zstd-сжатый образец → исходные байты (образцы сжать в тесте теми же крейтами, где есть компрессор: `flate2` пишет zlib; для brotli/zstd — маленькие заранее сжатые константы с исходником в комментарии).

- [ ] **Step 2: Убедиться, что падают.**
- [ ] **Step 3: Зависимости.** `crates/outline-transport/Cargo.toml` под фичей `quic`: `brotli-decompressor` и `ruzstd` (последние стабильные версии, `default-features` по смыслу — только декодер), `flate2` (уже в дереве — та же версия). Проверить `cargo tree -i rustls` (по-прежнему один) и что фичи `brotli`/`zlib` у rustls не включились (`cargo tree -e features -i rustls`).
- [ ] **Step 4: `quic/tls_profile.rs`.** Константы трёх профилей по таблице:
  - Chromium: ciphers `1301,1302,1303`; groups `X25519MLKEM768, X25519, SECP256R1, SECP384R1`; sig `0403,0804,0401,0503,0805,0501,0806,0601,0201`; compression `[Brotli]`; `ech_grease: true`; omit EMS и status_request; extra `[(17613, &[0,3,2,b'h',b'3']), (51764, &CHROME_TRUST_ANCHORS)]` (186 байт из «Замеров», константа с комментарием «Chrome 156 trust-anchor ids, constant across captures»); `grease: false`; order `ShuffledWithEch`; extra key shares нет.
  - Safari: ciphers `1302,1303,1301`; groups `X25519MLKEM768, X25519, SECP256R1, SECP384R1, SECP521R1`; sig `0403,0804,0401,0503,0805,0805,0501,0806,0601,0201`; compression `[Zlib]`; `ech_grease: false`; omit EMS; status_request оставить; extra `[(18, &[])]`; `grease: true`; order `Fixed(&[0, 10, 16, 5, 13, 18, 51, 45, 43, 57, 27])`.
  - Firefox: ciphers `1301,1303,1302`; groups `X25519MLKEM768, X25519, SECP256R1, SECP384R1, SECP521R1`; sig `0403,0503,0603,0203,0804,0805,0806,0401,0501,0601,0201`; compression `[Zlib, Zstd, Brotli]`; `ech_grease: true`; EMS и status_request оставить; extra `[(28, &[0x40, 0x01]), (34, &[0,8,4,3,5,3,6,3,2,3]), (65281, &[0])]`; `grease: false`; order `Shuffled` (ECH в конце — поведение upstream); extra key shares `[SECP256R1]`.
  - `ec_point_formats` опускается во всех трёх (`omit_ec_point_formats: true` выставляет билдер).
  - Декомпрессоры: три `impl rustls::compress::CertDecompressor` (zlib — `flate2::read::ZlibDecoder`, brotli — `brotli_decompressor::Decompressor`, zstd — `ruzstd::decoding::StreamingDecoder`), каждый пишет ровно в `output` и возвращает `DecompressionFailed` при несовпадении длины.
  - `BrowserVerifier`: оборачивает `Arc<WebPkiServerVerifier>`, `supported_verify_schemes()` → `sig_schemes.to_vec()`, остальное делегирует.
  - Модуль-док: что совпадает с браузером, что нет (дробление CRYPTO — отдельный план; резюмпция не выравнивалась).
- [ ] **Step 5: `tls.rs::build_quic_client_config`.** Провайдер: `default_provider()` с `cipher_suites`/`kx_groups` из профиля (группы мапятся на `kx_group::*`, `SECP521R1` — через гейт); корни — как в `build_client_config_uncached` (test override или webpki); `ClientConfig::builder_with_provider(p)` → при `ech_grease` `.with_ech(EchMode::Grease(EchGreaseConfig::new(hpke::DH_KEM_X25519_HKDF_SHA256_AES_128, HpkePublicKey(random 32 bytes))))`, иначе `.with_protocol_versions(&[&rustls::version::TLS13])`; `.dangerous().with_custom_certificate_verifier(BrowserVerifier)` → `.with_no_client_auth()`; `alpn_protocols`, `cert_decompressors`, `resumption` — как у существующего билдера (тот же ticket store и ротация); затем `tls_vendored::set_client_hello_shape(...)`. Кэш — по `(fp, alpn)` с той же `SESSION_TICKET_ROTATION_INTERVAL`. `fp = None` → профиль Chromium (как `tp_profile::for_fingerprint(None)`).
- [ ] **Step 6: Подключить.** `h3_quic_client_config` берёт `crate::tls::build_quic_client_config(fp, &[b"h3"])` вместо `build_client_config`. Снять `expect(dead_code)` с элементов гейта, которые теперь используются.
- [ ] **Step 7: Тесты** `cargo test -p outline-transport --features h3 quic::` → PASS (новые и все прежние, включая TP-тесты). Если ECH payload не попадает в ожидаемые значения — STOP (см. «Решения» п. 6).
- [ ] **Step 8: Полный гейт** → зелёный. Не коммитить.

---

### Task 4: Документация, патч-артефакт, проверка на проводе

**Files:**
- Modify: `rustls-0.23.40.patch`, `PATCHES.md`, `PATCHES.ru.md`, `AGENTS.md`, `bins/outline-ws-rust/CHANGELOG.md`, `bins/outline-ws-rust/CHANGELOG.ru.md`, `crates/outline-transport/src/tls_fingerprint.rs` (модуль-док)

- [ ] **Step 1: PATCHES (EN/RU), раздел rustls.** Пункт 1 **client-hello-shape** (`client_conn.rs`, `hs.rs`, `tls13.rs`, `msgs/handshake.rs`, `lib.rs`): поля `ClientHelloShape`, режимы `ExtensionOrder`, правила GREASE, extra key shares и завершение обмена по ним; при `None` — upstream побайтово, сервер не затронут. Пункт 2 **secp521r1** (`crypto/aws_lc_rs/kx.rs`, `mod.rs`): новая группа, дефолтные списки не меняются. Пункт 3 — vendoring trim. Раздел гейт-модулей: добавить `crates/outline-transport/src/tls_vendored.rs` и CI-проверку.
- [ ] **Step 2: `AGENTS.md`** — vendored rustls, его гейт, запрет фич `brotli`/`zlib` у rustls (почему — сервер начал бы сжимать сертификат).
- [ ] **Step 3: `tls_fingerprint.rs`** — модуль-док больше не утверждает, что расширения rustls недоступны: для QUIC это делает `quic/tls_profile.rs`, TCP по-прежнему только порядок ciphers/групп.
- [ ] **Step 4: CHANGELOG (EN/RU), `[Unreleased]`:** ClientHello H3-носителя теперь как у Chrome 156 / Safari / Firefox 159 (JA4 совпадает), размер первого Initial как у браузера; rustls вендорится; ограничения — CRYPTO не дробится, TCP ClientHello прежний, резюмпция не выравнивалась.
- [ ] **Step 5: Патч-артефакт** `rustls-0.23.40.patch` — перегенерировать, round-trip пустой (команды и вывод — в отчёт).
- [ ] **Step 6: Проверка на проводе.** Релизная сборка `outline-ws-rust`, `scripts/quic-initial-sink.py 4433`, конфиг с `tcp_ws_url = "wss://localtest.me:4433/x/tcp"`, `tcp_mode = "h3"`, `fingerprint_profile = "random"`, 8–12 запусков; профиль опознаётся по порядку TP. tshark: `-Y tls.handshake.type==1 -T fields -e tls.handshake.ja4 -e tls.handshake.extension.type -e udp.length`. Ожидаемо: три разных JA4, равных браузерным; UDP 1200 у всех (решение 9). Вывод — в отчёт.
- [ ] **Step 7: Полный гейт** → зелёный. Показать владельцу `git status` и `git diff --stat`. Не коммитить.

---

## После выполнения

- Обновить память `quic-tls-clienthello-vs-browsers`: JA4 совпадает, что осталось (CRYPTO, TCP, резюмпция).
- Следующие планы: дробление CRYPTO в Initial (quinn-proto), затем TCP ClientHello.
