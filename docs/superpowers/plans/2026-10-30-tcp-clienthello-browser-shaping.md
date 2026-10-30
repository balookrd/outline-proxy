# ClientHello по TCP (h1/h2) как у браузеров — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** TLS ClientHello TCP-носителей (ws_h1, ws_h2, xhttp_h1, xhttp_h2), проверки сертификата (`cert_check`) и HTTPS-пробы совпадает с Chrome 156 / Apple URLSession (Safari) / Firefox 159 по набору и порядку расширений, шифрам, группам, key_share, подписям, сжатию сертификата, GREASE и ECH GREASE; JA4 каждого профиля равен JA4 браузера для той же ALPN.

**Architecture:** Расширяем существующий патч vendored rustls «client-hello-shape» тремя opt-in полями (`wire_cipher_suites`, `advertise_tls12`, `grease_signature_algorithms`). Реальный TCP-конфиг — только TLS 1.3 (как QUIC: это даёт GREASE ECH, который rustls допускает лишь при TLS 1.3), а TLS 1.2, его шифры и его расширения (11, 23, 35, 65281) только объявляются. Общие части QUIC-профилей (структура профиля, `BrowserVerifier`, декомпрессоры, `NoKxHintStore`) выносятся в негейтированный модуль `tls_hello.rs`; TCP-профили — в новый `tcp_tls_profile.rs`; `crate::tls::build_client_config` строит браузерный hello для всех TCP-дозвонов. Старый модуль `tls_fingerprint.rs` (перестановка шифров в провайдере) удаляется.

**Tech Stack:** Rust 2024, vendored rustls 0.23.40 (aws-lc-rs), tokio-rustls 0.26, `brotli-decompressor`, `ruzstd`, `flate2`, tshark 4.6.

**Предыстория:** QUIC ClientHello уже как у браузеров (`c45d726b`, план `2026-10-29-quic-clienthello-browser-shaping.md`). Замер TCP — память проекта `tcp-tls-clienthello-vs-browsers`; захваты и инструменты — scratchpad `tcpch/` (приёмник `tls-hello-sink.py`, разбор `exts.py`, `ch.sh`, `sum.sh`, сырые hello в `tcpch/fixtures/*.bin`).

## Global Constraints

- Комментарии в коде, commit-сообщения и PR — на английском; план и чат — на русском. Термины: «носитель» (не «карьер»), «гейт» (не «ворота»/«врата»).
- Никогда не добавлять трейлер `Co-Authored-By: Claude` и футер «Generated with Claude Code».
- Коммит — только по явной команде владельца; **никогда не `git push`** без отдельной команды. Работать в `main`, веток не создавать. Исполнители задач НЕ коммитят: одобренное складывается в индекс, следующая задача ревьюится по незастейдженному diff.
- Тесты наших крейтов — в `tests/` рядом с модулем; inline `mod tests {}` запрещены. `vendor/rustls` — upstream-стиль, не форматировать и не линтовать; новые тесты патча — в нашем крейте (`crates/outline-transport/src/tests/…`), не в `vendor/`.
- Гейт (ровно эти команды):
  ```bash
  cargo fmt --check -p outline-ss-rust -p outline-ws-rust -p outline-ui \
    -p outline-metrics -p outline-net -p outline-routing -p outline-transport \
    -p outline-tun -p outline-uplink -p outline-wire \
    -p shadowsocks-crypto -p socks5-proto
  cargo clippy --workspace --exclude sockudo-ws --all-targets --no-deps -- -D warnings
  cargo test --workspace --exclude sockudo-ws
  RUN_E2E_FAILOVER=1 cargo test -p outline-ws-rust --features test-tls --test 'e2e_*' -- --test-threads=1
  (cd android/rust && cargo fmt --check && cargo clippy --no-deps -- -D warnings)
  ```
  Плюс `cargo check -p outline-ws-rust --no-default-features` и `cargo check -p outline-ss-rust --no-default-features` (job `features-and-invariants`). Известные посторонние флейки: `outline-tun health_recovery::tun_downlink_traffic_restores_uplink_health_without_probe`, `outline-uplink loss::tests::a_vanished_carrier_contributes_no_window` (linux) — при единственном падении перезапустить и указать оба прогона.
- **Никогда `cargo fmt --all`** (переформатирует `vendor/`); format-only diff в `vendor/` откатывать.
- rustls — только aws-lc-rs; фичи rustls `brotli`/`zlib` **не включать** (у сервера появились бы компрессоры сертификата).
- Патч rustls: при `client_hello_shape = None` ClientHello, обработка ServerHello и расход случайности **побайтово как у upstream**; при `Some(shape)` с новыми полями по умолчанию (`wire_cipher_suites` пуст, оба bool `false`) — побайтово как до этого плана (QUIC-профили не меняются на проводе). Сервер `outline-ss-rust` и cluster mesh новую опцию не трогают.
- Патч-API rustls в production-коде — только через `crates/outline-transport/src/tls_vendored.rs` (инвариант в `.github/workflows/ci.yml` уже есть; тестовые модули освобождены).
- `PATCHES.md`/`PATCHES.ru.md`, `bins/outline-ws-rust/CHANGELOG.md`/`CHANGELOG.ru.md` — парой. `rustls-0.23.40.patch` перегенерировать тем же способом, что раньше (временный git-репозиторий с чистым crates.io 0.23.40 в новом уникальном каталоге scratchpad), round-trip (`patch -p1` к чистому крейту → `diff -r` с `vendor/rustls` пусто). Никаких `rm -rf` с переменными.
- Выкатка — только по команде владельца, по одному узлу.

## Замеры (2026-10-30, хост `localtest.me` → 127.0.0.1)

Сырые ClientHello (handshake-сообщение целиком, с 4-байтовым заголовком) лежат в scratchpad `tcpch/fixtures/`: `chrome156_h2.bin` (страница, ALPN h2,http/1.1), `chrome156_h1.bin` (WebSocket, ALPN http/1.1), `apple_h2.bin`, `apple_h1.bin`, `firefox159_h2.bin` (у Firefox WebSocket идёт тем же hello). Firefox и Apple после разрыва повторяют hello (Firefox без 27, Apple с `TLS_FALLBACK_SCSV` 0x5600) — это не эталон, эталон только первый hello.

| | Chrome 156 | Apple URLSession (macOS 27) | Firefox 159 | наш сейчас |
|---|---|---|---|---|
| JA4 (страница) | `t13d1517h2_8daaf6152771_*` (c-часть плавает: tshark считает GREASE в подписях) | `t13d2013h2_a09f3c656075_7f0f34a4126d` | `t13d1517h2_8daaf6152771_3cbfd9057e0d` | `t13d1011h2_61a7ad8aa9b6_f9531d972513` у всех профилей |
| JA4 (ALPN http/1.1) | `t13d1516h1_…` (без ALPS) | `t13d2013h1_…` | — (браузер шлёт h2,http/1.1) | `t13d1011h1_…` |
| cipher_suites | GREASE, 1301, 1302, 1303, c02b, c02f, c02c, c030, cca9, cca8, c013, c014, 009c, 009d, 002f, 0035 | GREASE, 1302, 1303, 1301, c02c, c02b, cca9, c030, c02f, cca8, c00a, c009, c014, c013, 009d, 009c, 0035, 002f, c008, c012, 000a | 1301, 1303, 1302, c02b, c02f, cca9, cca8, c02c, c030, c013, c014, 009c, 009d, 002f, 0035 | 9 шифров + 00ff |
| supported_versions | GREASE, 0304, 0303 | GREASE, 0304, 0303 | 0304, 0303 | 0304, 0303 |
| supported_groups | GREASE, 11ec, 1d, 17, 18 | GREASE, 11ec, 1d, 17, 18, 19 | 11ec, 1d, 17, 18, 19 | 11ec, 1d, 17, 18 |
| key_share | GREASE (`00`), 11ec, 1d | GREASE (`00`), 11ec, 1d | 11ec, 1d, 17 | 11ec, 1d |
| signature_algorithms | GREASE, 0904, 0905, 0906, 0403, 0804, 0401, 0503, 0805, 0501, 0806, 0601 | 0403, 0804, 0401, 0503, 0805, 0805, 0501, 0806, 0601, 0201 | 0403, 0503, 0603, 0804, 0805, 0806, 0401, 0501, 0601, 0203, 0201 | 0503, 0403, 0603, 0807, 0806, 0805, 0804, 0601, 0501, 0401 |
| compress_certificate | brotli (`020002`) | zlib (`020001`) | zlib, brotli, zstd (`06000100020003`) | нет |
| ECH GREASE | payload 144/176/208/240 (длина расширения 186/218/250/282) | нет | payload 240 (282) | нет |
| Набор расширений | 0, 5, 10, 11, 13, 16, 18, 23, 27, 35, 43, 45, 51, 17613*, 51764, 65037, 65281 + 2 GREASE | 0, 5, 10, 11, 13, 16, 18, 23, 27, 43, 45, 51, 65281 + 2 GREASE | 0, 5, 10, 11, 13, 16, 18, 23, 27, 28, 34, 35, 43, 45, 51, 65037, 65281 | 0, 5, 10, 11, 13, 16, 23, 35, 43, 45, 51 |
| Порядок | случайный, ECH тоже в перемешке; GREASE первым (пустой) и последним (`00`) | фиксированный: GREASE, 0, 23, 65281, 10, 11, 16, 5, 13, 18, 51, 45, 43, 27, GREASE | фиксированный: 0, 23, 65281, 10, 11, 35, 16, 5, 34, 18, 51, 43, 13, 45, 28, 27, 65037 | случайный |

\* 17613 (ALPS, тело `0003026832` = «h2») Chrome шлёт только при `h2` в ALPN.

Тела расширений (одинаковы у всех, кто шлёт): 11 = `0100`; 23 = пусто; 35 = пусто (без билета); 18 = пусто; 65281 = `00`; 5 = `0100000000`; 45 = `0101`; 28 = `4001`; 34 = `0008 0403 0503 0603 0203`; 51764 — те же 186 байт, что `CHROME_TRUST_ANCHORS` в `quic/tls_profile.rs` (сверено побайтово).

**QUIC-hello Chrome тем же днём не изменился** (`q13d0312h3_55b375c5d22e_178839b6cec1`, без ML-DSA) — подписи ML-DSA и GREASE в подписях Chrome шлёт только по TCP. QUIC-профили в этом плане не меняются.

Вторая утечка: `outline_transport::cert_check` (прямой дозвон к своему же узлу, виден DPI) и HTTPS-проба через туннель (`outline_uplink::probe::tls`) строят стандартный rustls-hello: 234 байта, без ALPN, без PQ-доли (`t13d101000_…`).

## Решения

1. **Шифры, которых rustls не умеет, объявляются (решение владельца).** На провод идёт полный список браузера (CBC, RSA-обмен, у Apple 3DES); реально согласуются только TLS 1.3-наборы провайдера. Сервер, выбравший объявленный, но нереализованный набор, получает чистую ошибку рукопожатия (не панику).
2. **Реальный TCP-конфиг — только TLS 1.3; TLS 1.2 объявляется.** `supported_versions` = (GREASE,) 0304, 0303. Из расширений TLS 1.2 rustls и в TLS 1.3-only конфиге сам строит 11 `ec_point_formats` (`0100`) и 23 `extended_master_secret` (пусто) — флаги `omit_*` для TCP выключены; 35 `session_ticket` (rustls строит его только при включённом TLS 1.2) и 65281 `renegotiation_info` пишутся как сырые `extra_extensions`. Причина: `ConfigBuilder::with_ech` в rustls оставляет только TLS 1.3, а GREASE ECH нужен Chrome и Firefox. Следствие: сервер только с TLS 1.2 рукопожатие не пройдёт (чистая ошибка «версия выключена»). TLS для TCP-носителей на узлах завершает сам `outline-ss-rust` — только TLS 1.3 (ответ владельца), так что парк не затронут. Это продолжение решения 1: владелец уже принял отказ TLS 1.2-серверов, выбирающих объявленный CBC.
3. **ALPN по носителю (решение владельца).** h1-носители (ws_h1, xhttp_h1, fallback на h1) шлют `http/1.1`, h2-носители — `h2, http/1.1`, у всех профилей. У Chrome ALPS (17613) — только когда в ALPN есть `h2`. У профиля Firefox на h1-носителе отличается только ALPN (`t13d1517h1` вместо `t13d1517h2`) — принято владельцем.
4. **Пробы — профилем процесса (решение владельца).** `cert_check` и HTTPS-проба выбирают профиль тем же `fingerprint_profile::select(url)`, что и дозвон носителя (url = `https://host:port`), и строят тот же браузерный hello; `cert_check` дополнительно объявляет ALPN `h2, http/1.1` (как загрузка страницы) и сохраняет свой верификатор «принять любой сертификат».
5. **Нет профиля (`Strategy::None`, дефолт) → Chromium**, как у QUIC (`quic::tls_profile::for_fingerprint`). Это меняет hello у всех TCP-дозвонов по умолчанию — ровно цель плана; прежний «стандартный rustls при None» был отличимым отпечатком.
6. **Расширение патча** (три поля `ClientHelloShape`, по умолчанию нейтральны):
   - `wire_cipher_suites: Vec<CipherSuite>` — пусто: как сейчас (провайдер + SCSV при TLS 1.2). Непусто: в `cipher_suites` уходит ровно этот список (после GREASE, если `grease`), `TLS_EMPTY_RENEGOTIATION_INFO_SCSV` не добавляется. Список обязан содержать все TLS 1.3-наборы провайдера (иначе их нельзя было бы выбрать) — проверка в нашем крейте (`tls_hello`), не в патче.
   - `advertise_tls12: bool` — в `supported_versions` на проводе после 0304 добавляется 0303, даже если конфиг только TLS 1.3. Внутренняя логика rustls (выбор шифров, SCSV, EMS, тикеты, проверка ServerHello) по-прежнему видит реальные версии конфига.
   - `grease_signature_algorithms: bool` — при `grease` первым элементом `signature_algorithms` идёт отдельное GREASE-значение `0x?A?A` (свой случайный байт; при HRR не меняется). Без `grease` поле игнорируется.
7. **Подписи** — как в QUIC, `BrowserVerifier` с `supported_verify_schemes()` = список браузера. ML-DSA (`ML_DSA_44/65/87` уже есть в `SignatureScheme` rustls 0.23.40) объявляется, проверка его не встретит: WebPKI-сертификатов ML-DSA нет, а сервер, выбравший его, даст чистую ошибку верификатора.
8. **Сжатие сертификата, NoKxHintStore, ECH GREASE** — те же механизмы, что в QUIC. Декомпрессоры и их зависимости (`flate2`, `brotli-decompressor`, `ruzstd`) перестают быть опциональными (TCP есть в каждой сборке клиента); фича `quic` их больше не тянет. Сервер их не использует (у сервера нет `cert_decompressors`), фичи rustls `zlib`/`brotli` не включаются.
9. **`tls_fingerprint.rs` удаляется** вместе с `src/tests/tls_fingerprint.rs`: перестановка шифров в провайдере теряет смысл, порядок на проводе задаёт `wire_cipher_suites`.
10. **Вне плана:** h2 SETTINGS/WINDOW_UPDATE/порядок псевдозаголовков (Akamai h2 fingerprint) — следующий слой отпечатка h2-носителей, отдельный план; резюмпция и 0-RTT (`early_data`); TCP-уровень (опции SYN, окно) — ОС.

## File Structure

| Файл | Действие | Ответственность |
|---|---|---|
| `vendor/rustls/src/client/client_conn.rs` | изменить | три новых поля `ClientHelloShape` + rustdoc |
| `vendor/rustls/src/client/hs.rs` | изменить | wire-список шифров, 0303 в `supported_versions`, GREASE в подписях |
| `vendor/rustls/src/client/common.rs` | изменить | `GreaseValues::signature_algorithm` |
| `vendor/rustls/src/msgs/handshake.rs` | изменить при необходимости | кодирование GREASE в `signature_algorithms`, если `ClientExtensions` не даёт вставить его иначе |
| `rustls-0.23.40.patch`, `PATCHES.md`, `PATCHES.ru.md` | изменить | патч-артефакт и описание |
| `crates/outline-transport/src/tls_vendored.rs` | изменить | `apply_tls_hello_profile` (общий для QUIC и TCP) + новые поля |
| `crates/outline-transport/src/tls_hello.rs` | создать | `HelloProfile`, `ShapeOrder`, `BrowserVerifier`, декомпрессоры, `NoKxHintStore`, `provider()`, `build_shaped_client_config(profile, alpn, verifier)` |
| `crates/outline-transport/src/quic/tls_profile.rs` | изменить | только QUIC-константы `CHROMIUM`/`SAFARI`/`FIREFOX` типа `HelloProfile` и `for_fingerprint` |
| `crates/outline-transport/src/tcp_tls_profile.rs` | создать | TCP-константы трёх браузеров и `for_fingerprint` |
| `crates/outline-transport/src/tls.rs` | изменить | `build_client_config` → браузерный hello; `build_quic_client_config` → через `tls_hello`; новая сигнатура `build_https_probe_client_config(url, alpn)` |
| `crates/outline-transport/src/cert_check.rs` | изменить | браузерный hello с верификатором «принять любой» |
| `crates/outline-uplink/src/probe/tls.rs` | изменить | вызов новой `build_https_probe_client_config` |
| `crates/outline-transport/src/tls_fingerprint.rs`, `src/tests/tls_fingerprint.rs` | удалить | заменены `wire_cipher_suites` |
| `crates/outline-transport/src/lib.rs` | изменить | модули `tls_hello`, `tcp_tls_profile`; убрать `tls_fingerprint` |
| `crates/outline-transport/Cargo.toml` | изменить | декомпрессоры не опциональны |
| `crates/outline-transport/src/tests/client_hello.rs` | создать | общий тестовый разбор ClientHello и `ja4()` (вынести из `quic/tests/tls_config.rs`) |
| `crates/outline-transport/src/tests/fixtures/tcp_client_hello/*.bin` | создать | 5 эталонных hello из scratchpad `tcpch/fixtures/` |
| `crates/outline-transport/src/tests/tls_vendored.rs` | создать | тесты трёх новых полей патча |
| `crates/outline-transport/src/tests/tcp_tls_profile.rs` | создать | JA4/набор/порядок/рукопожатия TCP-профилей |
| `crates/outline-transport/src/tests/cert_check.rs` (или существующий тестовый модуль cert_check) | изменить | hello `cert_check` браузерный |
| `crates/outline-transport/src/fingerprint_profile.rs` | изменить | rustdoc «What this module does NOT do» |
| `bins/outline-ws-rust/CHANGELOG.md`, `CHANGELOG.ru.md` | изменить | запись в Unreleased |

---

### Task 1: Расширение патча rustls и гейт

**Files:**
- Modify: `vendor/rustls/src/client/client_conn.rs` (`ClientHelloShape`), `vendor/rustls/src/client/hs.rs`, `vendor/rustls/src/client/common.rs`, при необходимости `vendor/rustls/src/msgs/handshake.rs`
- Modify: `crates/outline-transport/src/tls_vendored.rs`
- Create: `crates/outline-transport/src/tests/tls_vendored.rs` (подключить в `src/tests/mod.rs`)

**Interfaces:**
- Produces (rustls): `ClientHelloShape { …, wire_cipher_suites: Vec<CipherSuite>, advertise_tls12: bool, grease_signature_algorithms: bool }` (все `Default`-нейтральны; если у структуры нет `Default`, добавить поля во все места построения).
- Produces (наш крейт): `tls_vendored::apply_quic_tls_profile` получает три новых поля из профиля (в Task 2 переименуется), сейчас — константами `Vec::new()/false/false`, чтобы QUIC на проводе не изменился.

- [ ] **Step 1: Тесты (падают).** В `src/tests/tls_vendored.rs` построить TLS 1.3-only `ClientConfig` (aws-lc-rs, только `TLS13_AES_128_GCM_SHA256`, `X25519`), выставить форму через `tls_vendored::set_client_hello_shape` и снять ClientHello из `rustls::ClientConnection::new(...).write_tls(&mut Vec)` (разбор — существующие функции из `quic/tests/tls_config.rs`, на этом шаге их можно временно скопировать в тест; в Task 2 они переедут в `tests/client_hello.rs`). Тесты:
  1. `wire_cipher_suites_replace_the_offered_list` — форма с `wire_cipher_suites = [1301, c02b, 002f, 000a]` → в hello ровно `1301, c02b, 002f, 000a`, без `00ff`.
  2. `wire_cipher_suites_follow_grease` — то же + `grease = true` → первый шифр GREASE `0x?A?A`, дальше список.
  3. `empty_wire_list_keeps_the_provider_list` — `wire_cipher_suites` пуст, конфиг TLS 1.2+1.3 → список провайдера + `00ff` (как upstream).
  4. `advertise_tls12_appends_0303` — TLS 1.3-only конфиг, `advertise_tls12 = true` → `supported_versions` = `0304, 0303`; с `grease` → `GREASE, 0304, 0303`; без поля → `0304`.
  5. `grease_signature_algorithms_prepends_one_value` — `grease = true`, `grease_signature_algorithms = true` → первый элемент `signature_algorithms` — GREASE, остальное = `supported_verify_schemes()` верификатора; при `grease = false` поле ничего не меняет.
  6. `defaults_keep_the_hello_byte_identical` — форма с прежними полями (как Apple-профиль QUIC) и новыми по умолчанию: hello до и после патча совпадает по набору/порядку шифров, версий, подписей (сравнение с ожидаемыми списками).
  7. `server_selecting_tls12_fails_cleanly` — in-memory рукопожатие: клиент TLS 1.3-only с `advertise_tls12`, сервер rustls только TLS 1.2 (`ServerConfig::builder_with_protocol_versions(&[&TLS12])`, самоподписанный сертификат `rcgen`, клиенту — верификатор, доверяющий ему) → `Err`, без паники.
  8. `server_selecting_an_unimplemented_suite_fails_cleanly` — серверу TLS 1.2 выдать только `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`, клиенту TLS 1.3-only с `wire_cipher_suites`, содержащим этот набор → `Err`, без паники. (Если rustls раньше отвергает версию — тест проверяет то же, что 7; оставить, он фиксирует контракт для решения 1.)
  9. `handshake_completes_with_all_three_fields` — сервер rustls TLS 1.3 → рукопожатие завершается, согласован `TLS13_AES_128_GCM_SHA256`.

  Run: `cargo test -p outline-transport --lib tls_vendored` — тесты 1, 2, 4, 5 FAIL (нет полей), остальные компилируются только после Step 2.
- [ ] **Step 2: Патч.** В `ClientHelloShape` добавить три поля с rustdoc (английский, в стиле соседних полей): что меняется на проводе и что НЕ меняется во внутренней логике. В `common.rs` `GreaseValues` — поле `signature_algorithm`, отдельный случайный байт (seed 6 байт; значение берётся только при `grease_signature_algorithms`). В `hs.rs`:
  - после сборки `cipher_suites` (сейчас: провайдер → `00ff` при tls12 → GREASE): если `shape.wire_cipher_suites` непуст — заменить список им ДО вставки GREASE, `00ff` не добавлять;
  - `supported_versions` в `ClientExtensions`: при `advertise_tls12` — копия с `tls12 = true` только для расширения; локальная `supported_versions` (по которой rustls фильтрует шифры, ставит SCSV/EMS/тикеты и проверяет ServerHello) не меняется. Проверить порядок кодирования: на проводе должно быть `0304, 0303` (после GREASE);
  - `signature_schemes`: при `grease && grease_signature_algorithms` вставить `SignatureScheme::from(grease.signature_algorithm)` первым. При HRR — тот же `GreaseValues` (уже хранится в `input.hello.grease`).
  Ни при `client_hello_shape = None`, ни при нейтральных полях расход случайности и байты не меняются (кроме случая `grease = true`: seed стал 6 байт вместо 5 — допустимо, но тогда тест 6 сравнивает списки, а не байты случайных полей).
- [ ] **Step 3:** `tls_vendored::apply_quic_tls_profile` заполняет новые поля нейтрально. Run: `cargo test -p outline-transport --lib tls_vendored` — PASS; `cargo test -p outline-transport --features h3 quic::` — PASS (QUIC JA4-тесты не тронуты); upstream-тесты vendored rustls: `cargo test --manifest-path vendor/rustls/Cargo.toml --lib` (как в прошлом плане; если в workspace так не запускается — тем же способом, что в Task 2 плана 2026-10-29) — PASS.
- [ ] **Step 4:** Гейт целиком. Отчёт: списки из тестов 1–5 дословно.

### Task 2: Общий модуль `tls_hello`, TCP-профили, браузерный `build_client_config`

**Files:**
- Create: `crates/outline-transport/src/tls_hello.rs`, `crates/outline-transport/src/tcp_tls_profile.rs`, `crates/outline-transport/src/tests/client_hello.rs`, `crates/outline-transport/src/tests/tcp_tls_profile.rs`, `crates/outline-transport/src/tests/fixtures/tcp_client_hello/{chrome156_h2,chrome156_h1,apple_h2,apple_h1,firefox159_h2}.bin` (скопировать из `/private/tmp/claude-501/-Users-mvmalykh-IdeaProjects-outline-proxy/9485f03f-e16e-46f6-8398-2e54ca9d2af0/scratchpad/tcpch/fixtures/`)
- Modify: `crates/outline-transport/src/quic/tls_profile.rs`, `crates/outline-transport/src/quic/tests/tls_config.rs` (+ `quic/tests/tls_profile.rs`), `crates/outline-transport/src/tls.rs`, `crates/outline-transport/src/tls_vendored.rs`, `crates/outline-transport/src/lib.rs`, `crates/outline-transport/Cargo.toml`
- Delete: `crates/outline-transport/src/tls_fingerprint.rs`, `crates/outline-transport/src/tests/tls_fingerprint.rs`

**Interfaces:**
- Consumes: три поля патча из Task 1.
- Produces:
  - `tls_hello::HelloProfile` — нынешний `QuicTlsProfile` + поля `wire_cipher_suites: &'static [CipherSuite]` (пусто = не трогать), `advertise_tls12: bool`, `grease_signature_algorithms: bool`, `alps_h2: bool` (добавить `(17613, [0x00,0x03,0x02,b'h',b'2'])`, если в ALPN есть `h2`). `cipher_suites` остаётся «реализованные TLS 1.3-наборы, порядок предложения» (для `provider()`).
  - `tls_hello::{ShapeOrder, BrowserVerifier, NoKxHintStore, ZLIB, BROTLI, ZSTD}` — перенесены из `quic/tls_profile.rs` без изменения поведения.
  - `tls_hello::build_shaped_client_config(profile: &HelloProfile, alpn: &[&[u8]], verifier: Arc<dyn ServerCertVerifier>) -> Arc<ClientConfig>` — TLS 1.3-only (через `with_ech` при `ech_grease`, иначе `with_protocol_versions(&[&TLS13])`), `cert_decompressors`, `resumption = NoKxHintStore`, ALPN, форма через `tls_vendored::apply_tls_hello_profile(&mut config, profile, alpn)`. Проверяет (debug_assert + `expect` при построении констант в тесте), что непустой `wire_cipher_suites` содержит все `cipher_suites`.
  - `tls_hello::webpki_verifier(profile) -> Arc<dyn ServerCertVerifier>` — `BrowserVerifier` над `WebPkiServerVerifier` с `roots()` (test-override учитывается).
  - `tcp_tls_profile::{CHROMIUM, SAFARI, FIREFOX}: HelloProfile`, `tcp_tls_profile::for_fingerprint(Option<TlsFingerprint>) -> &'static HelloProfile` (`None` → Chromium).
  - `tls::build_client_config(alpn)` — сигнатура прежняя; внутри `tcp_tls_profile::for_fingerprint(current_dial_fingerprint())` → `build_shaped_client_config`. Кэш и ротация (`SESSION_TICKET_ROTATION_INTERVAL`) — прежние.
  - `tests::client_hello::{parse_client_hello, ja4, ja4_without_grease_sigalgs}` — `pub(crate)`, для QUIC (`q`) и TCP (`t`).

TCP-профили (точные значения; порядок — порядок предложения):

```rust
// Chrome 156 over TCP.
pub(crate) const CHROMIUM: HelloProfile = HelloProfile {
    name: "chromium",
    cipher_suites: &[TLS13_AES_128_GCM_SHA256, TLS13_AES_256_GCM_SHA384, TLS13_CHACHA20_POLY1305_SHA256],
    wire_cipher_suites: &[/* 1301,1302,1303,c02b,c02f,c02c,c030,cca9,cca8,c013,c014,009c,009d,002f,0035 */],
    kx_groups: &[X25519MLKEM768, X25519, secp256r1, secp384r1],
    sig_schemes: &[ML_DSA_44, ML_DSA_65, ML_DSA_87, ECDSA_NISTP256_SHA256, RSA_PSS_SHA256, RSA_PKCS1_SHA256,
                   ECDSA_NISTP384_SHA384, RSA_PSS_SHA384, RSA_PKCS1_SHA384, RSA_PSS_SHA512, RSA_PKCS1_SHA512],
    cert_compression: &[Brotli],
    ech_grease: true,
    omit_extended_master_secret: false, // rustls builds 23 (empty) and 11 (`0100`) even TLS 1.3-only
    omit_status_request: false,         // 5 = 0100000000, as Chrome
    extra_extensions: &[(35, &[]), (18, &[]), (65281, &[0x00]), (51764, &CHROME_TRUST_ANCHORS)],
    alps_h2: true,
    grease: true,
    grease_signature_algorithms: true,
    advertise_tls12: true,
    order: ShapeOrder::ShuffledWithEch,
    extra_key_shares: &[],
    ech_grease_payload_lengths: &[144, 176, 208, 240],
};

// Apple URLSession / Network.framework over TCP.
pub(crate) const SAFARI: HelloProfile = HelloProfile {
    name: "safari",
    cipher_suites: &[TLS13_AES_256_GCM_SHA384, TLS13_CHACHA20_POLY1305_SHA256, TLS13_AES_128_GCM_SHA256],
    wire_cipher_suites: &[/* 1302,1303,1301,c02c,c02b,cca9,c030,c02f,cca8,c00a,c009,c014,c013,009d,009c,0035,002f,c008,c012,000a */],
    kx_groups: &[X25519MLKEM768, X25519, secp256r1, secp384r1, secp521r1],
    sig_schemes: /* как quic SAFARI: 0403,0804,0401,0503,0805,0805,0501,0806,0601,0201 */,
    cert_compression: &[Zlib],
    ech_grease: false,
    omit_extended_master_secret: false,
    omit_status_request: false,
    extra_extensions: &[(65281, &[0x00]), (18, &[])],
    alps_h2: false,
    grease: true,
    grease_signature_algorithms: false,
    advertise_tls12: true,
    order: ShapeOrder::Fixed(&[0, 23, 65281, 10, 11, 16, 5, 13, 18, 51, 45, 43, 27]),
    extra_key_shares: &[],
    ech_grease_payload_lengths: &[],
};

// Firefox 159 over TCP.
pub(crate) const FIREFOX: HelloProfile = HelloProfile {
    name: "firefox",
    cipher_suites: &[TLS13_AES_128_GCM_SHA256, TLS13_CHACHA20_POLY1305_SHA256, TLS13_AES_256_GCM_SHA384],
    wire_cipher_suites: &[/* 1301,1303,1302,c02b,c02f,cca9,cca8,c02c,c030,c013,c014,009c,009d,002f,0035 */],
    kx_groups: &[X25519MLKEM768, X25519, secp256r1, secp384r1, secp521r1],
    sig_schemes: &[ECDSA_NISTP256_SHA256, ECDSA_NISTP384_SHA384, ECDSA_NISTP521_SHA512, RSA_PSS_SHA256,
                   RSA_PSS_SHA384, RSA_PSS_SHA512, RSA_PKCS1_SHA256, RSA_PKCS1_SHA384, RSA_PKCS1_SHA512,
                   ECDSA_SHA1_Legacy, RSA_PKCS1_SHA1],
    cert_compression: &[Zlib, Brotli, Zstd], // TCP order differs from QUIC (zlib, zstd, brotli)
    ech_grease: true,
    omit_extended_master_secret: false,
    omit_status_request: false,
    extra_extensions: &[(65281, &[0x00]), (35, &[]),
                        (34, &[0x00, 0x08, 0x04, 0x03, 0x05, 0x03, 0x06, 0x03, 0x02, 0x03]),
                        (18, &[]), (28, &[0x40, 0x01])],
    alps_h2: false,
    grease: false,
    grease_signature_algorithms: false,
    advertise_tls12: true,
    order: ShapeOrder::Fixed(&[0, 23, 65281, 10, 11, 35, 16, 5, 34, 18, 51, 43, 13, 45, 28, 27, 65037]),
    extra_key_shares: &[secp256r1],
    ech_grease_payload_lengths: &[240],
};
```

Шифры в `wire_cipher_suites` записывать константами `CipherSuite::…` (у rustls есть имена для всех: `TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA` = c013, `TLS_RSA_WITH_AES_128_GCM_SHA256` = 009c, `TLS_RSA_WITH_3DES_EDE_CBC_SHA` = 000a и т.д.; при отсутствии имени — `CipherSuite::from(0x….)` с комментарием). Порядок `ShapeOrder::Fixed` и место ECH в нём (Firefox: 65037 последним) — проверить, что патч ставит ECH по списку; если нет — STOP с фактическим порядком.

- [ ] **Step 1: Перенос без изменения поведения.** Создать `tls_hello.rs`, перенести туда `ShapeOrder`, структуру профиля (переименовать `QuicTlsProfile` → `HelloProfile`, добавить 4 поля; QUIC-константы получают `wire_cipher_suites: &[]`, `advertise_tls12: false`, `grease_signature_algorithms: false`, `alps_h2: false`), `provider()`, `cert_decompressors()`, декомпрессоры, `BrowserVerifier`, `NoKxHintStore`. `tls_vendored::apply_quic_tls_profile` → `apply_tls_hello_profile(config, profile, alpn)`. В `Cargo.toml` `flate2`, `brotli-decompressor`, `ruzstd` — обычные зависимости, убрать их из фичи `quic`, комментарий над ними поправить («browser-shaped TLS ClientHello, TCP and QUIC»). Вынести разбор ClientHello и `ja4` из `quic/tests/tls_config.rs` в `src/tests/client_hello.rs` (`pub(crate)`), QUIC-тесты переключить на него. Run: `cargo test -p outline-transport --features h3 quic::` и `cargo check -p outline-ws-rust --no-default-features` — PASS, ни один QUIC-тест не изменён по ожиданиям.
- [ ] **Step 2: Тесты TCP-профилей (падают).** В `src/tests/tcp_tls_profile.rs`, hello снимается как в Task 1 (`ClientConnection::new` + `write_tls`, SNI `localtest.me` — длина SNI влияет только на длину hello, не на JA4):
  1. `ja4_helper_reproduces_fixtures` — `ja4()` на `apple_h2.bin` = `t13d2013h2_a09f3c656075_7f0f34a4126d`, на `firefox159_h2.bin` = `t13d1517h2_8daaf6152771_3cbfd9057e0d` (значения tshark); для Chrome — `ja4_without_grease_sigalgs()` детерминирован на двух разных хендшейках из фикстур (`chrome156_h2.bin`, `chrome156_h1.bin` дают свои стабильные значения).
  2. `{chromium,safari,firefox}_h2_matches_the_browser` — JA4 нашего hello (ALPN `h2, http/1.1`) == JA4 фикстуры (Chrome — через `ja4_without_grease_sigalgs` на обеих сторонах).
  3. `{chromium,safari}_h1_matches_the_browser` — то же для ALPN `http/1.1` против `chrome156_h1.bin` / `apple_h1.bin`; `firefox_h1_differs_only_in_alpn` — JA4 = фикстура Firefox с `h2` → `h1` в a-части.
  4. `wire_lists_match_the_fixture` — для каждого профиля и ALPN: cipher_suites, supported_groups, key_share-группы, supported_versions, signature_algorithms, ALPN, compress_certificate, psk_ke_modes и ТЕЛА расширений 5, 11, 18, 23, 28, 34, 35, 65281, 17613, 51764 побайтово равны фикстуре (GREASE-позиции сравнивать как «есть GREASE на этом месте», значения — любые `0x?A?A`).
  5. `fixed_orders_match` — Safari и Firefox: порядок типов расширений == фикстуре (GREASE как маркер); `chromium_order_is_shuffled` — из 8 hello Chrome хотя бы два с разным порядком, у всех GREASE первым и последним.
  6. `ech_grease_lengths` — Chrome: длина payload ∈ {144, 176, 208, 240}; Firefox: 240; Safari: расширения 65037 нет.
  7. `handshake_completes_over_tcp_profiles` — для каждого профиля × ALPN (`h2,http/1.1`, `http/1.1`) — in-memory рукопожатие с rustls-сервером TLS 1.3 (самоподписанный сертификат через `install_test_tls_root`-механизм или собственный верификатор теста), ALPN сервера `h2, http/1.1` → согласован `h2` для h2-ALPN и `http/1.1` для h1-ALPN.
  8. `none_fingerprint_is_chromium` — `tcp_tls_profile::for_fingerprint(None)` == `&CHROMIUM`.
  Run: `cargo test -p outline-transport --lib tcp_tls_profile` — FAIL (нет модуля/констант).
- [ ] **Step 3: Реализация.** `tcp_tls_profile.rs` с константами выше; `build_shaped_client_config` и `webpki_verifier` в `tls_hello.rs`; `tls::build_client_config_uncached(fp, alpn)` → `build_shaped_client_config(tcp_tls_profile::for_fingerprint(fp), alpn, webpki_verifier(profile))`; `build_quic_client_config_uncached` → тот же путь с QUIC-профилем (поведение QUIC не меняется). Удалить `tls_fingerprint.rs`, его тесты и упоминания (`tls.rs`, `lib.rs`, rustdoc). Шапку `tls.rs` переписать: оба билдера браузерные, TCP — TLS 1.3 с объявленным 1.2. Run: Step 2 тесты — PASS; `cargo test -p outline-transport --features h3` — PASS.
- [ ] **Step 4:** Гейт целиком (включая e2e — `e2e_tls_carriers` гоняет wss h2 и failover на TLS). Отчёт: JA4 каждого профиля × ALPN дословно.

### Task 3: `cert_check` и HTTPS-проба — профилем процесса

**Files:**
- Modify: `crates/outline-transport/src/tls.rs` (`build_https_probe_client_config`), `crates/outline-transport/src/cert_check.rs`, `crates/outline-uplink/src/probe/tls.rs`
- Test: тестовый модуль `cert_check` в `crates/outline-transport/src/tests/` (найти существующий; если нет — создать `src/tests/cert_check.rs`), `crates/outline-uplink/src/probe/tests/…` (существующие тесты пробы — должны остаться зелёными)

**Interfaces:**
- Consumes: `tls_hello::build_shaped_client_config`, `tcp_tls_profile::for_fingerprint`, `fingerprint_profile::select`.
- Produces: `pub fn build_https_probe_client_config(url: &Url, alpn: &[&[u8]]) -> Arc<ClientConfig>` — профиль `fingerprint_profile::select(url).map(|p| p.tls)`, кэш как у `build_client_config` (ключ `(fp, alpn)`); `cert_check::fetch_leaf_cert_not_after_unix_ms` — hello профиля `select(https://host:port)`, ALPN `h2, http/1.1`, верификатор `AcceptAnyServerCert`, но `supported_verify_schemes()` = список профиля (обернуть: `BrowserVerifier`-подобная обёртка над accept-any, либо параметризовать `BrowserVerifier` любым внутренним верификатором). Кэш accept-any-конфигов — по `TlsFingerprint` (три штуки) вместо одного `OnceLock`.

- [ ] **Step 1: Тесты (падают).** (а) `cert_check_hello_is_browser_shaped` — построить конфиг `cert_check` для `None` и снять hello: JA4 == JA4 Chrome-профиля для `h2` (`t13d1517h2_…`), ALPN `h2, http/1.1`. (б) `cert_check_accepts_an_expired_certificate` — существующий тест (или новый: rustls-сервер с просроченным самоподписанным сертификатом → `notAfter` прочитан) остаётся зелёным с браузерным hello. (в) `probe_config_follows_the_url_profile` — `build_https_probe_client_config(&url, &[b"h2", b"http/1.1"])` при стратегии по умолчанию даёт hello Chrome; для явного `TlsFingerprint::Firefox` через `with_dial_fingerprint`/параметр — hello Firefox (выбрать способ, не трогающий глобальный `OnceLock` стратегии: `select_with_strategy` или внутренняя `build_https_probe_client_config_for(fp, alpn)`, которую тестировать напрямую).
- [ ] **Step 2: Реализация.** Изменить `build_https_probe_client_config` и вызов в `outline-uplink/src/probe/tls.rs` (url пробы = `https://{sni}:443`, порт — тот, что проба реально использует, если он есть в коде). `cert_check.rs`: заменить `accept_any_client_config()` на браузерный конфиг по профилю. Обновить rustdoc модуля `cert_check` (hello теперь как у браузера дозвона).
- [ ] **Step 3:** Run: `cargo test -p outline-transport --features cert-check` и `cargo test -p outline-uplink` — PASS. Гейт целиком.

### Task 4: Документация, патч-артефакт, проверка на проводе

**Files:**
- Modify: `PATCHES.md`, `PATCHES.ru.md`, `rustls-0.23.40.patch`, `bins/outline-ws-rust/CHANGELOG.md`, `bins/outline-ws-rust/CHANGELOG.ru.md`, `crates/outline-transport/src/fingerprint_profile.rs` (rustdoc), `AGENTS.md` (только если там описан `tls_fingerprint.rs`/TCP-hello — проверить `grep`)

- [ ] **Step 1:** `PATCHES.md`/`.ru.md` — раздел патча «client-hello-shape» дополнить тремя полями (что на проводе, что внутри не меняется, нейтральность по умолчанию). Перегенерировать `rustls-0.23.40.patch` и сделать round-trip.
- [ ] **Step 2:** CHANGELOG ws-rust (Unreleased, EN и RU парой): TCP-носители, `cert_check` и HTTPS-проба шлют ClientHello Chrome/Safari/Firefox (JA4 браузера); реальный TCP-TLS теперь только 1.3 (сервер только с TLS 1.2 не пройдёт рукопожатие); объявляются шифры, которых клиент не умеет; профиль Firefox на h1-носителях отличается от браузера только ALPN; без `fingerprint_profile` — Chromium. Упомянуть удаление перестановки шифров (`tls_fingerprint`).
- [ ] **Step 3:** `fingerprint_profile.rs` — раздел «What this module does NOT do»: TLS ClientHello теперь формируют `tcp_tls_profile` / `quic::tls_profile` (не «нужен uTLS»); HTTP/2 SETTINGS по-прежнему не трогаются.
- [ ] **Step 4: Провод.** Собрать `outline-ws-rust` (debug), для каждого `tcp_mode` из `ws_h1, ws_h2, xhttp_h1, xhttp_h2` и `fingerprint_profile = "random"` снять hello приёмником `scratchpad/tcpch/tls-hello-sink.py` (как при замере; конфиги `tcpch/ours-*.toml`), сравнить JA4 с таблицей «Замеры» через `tcpch/sum.sh`. Отдельно: hello `cert_check` (появляется в том же захвате, сейчас `t13d101000`) — должен стать `t13d1517h2_…`. Ожидание: каждое соединение — JA4 одного из трёх браузеров для своей ALPN; ни одного `t13d1011` и `t13d101000`.
- [ ] **Step 5:** Гейт целиком; `cargo build` для `x86_64-apple-darwin` (как в прошлом плане) и Android `(cd android/rust && cargo clippy --no-deps -- -D warnings)`. Linux: прогон `cargo test -p outline-transport` в docker `rust:bookworm` (память `repro-linux-ci-failure-in-docker`, target — в docker-томе, не bind-mount).

## После выполнения

- Финальное ревью всей серии (самая сильная модель): патч rustls нейтрален по умолчанию, сервер не затронут, QUIC JA4 не изменился.
- Владелец решает о коммите (предложение: два коммита — `feat(rustls-patch): …` и `feat(transport): shape the TCP TLS ClientHello like Chrome, Safari and Firefox`) и о выкатке: клиенты `.102`, `.104`, `cloud1`, `cloud2` по одному через `ops/deploy/deploy-binary.sh`; после каждого — journalctl на ошибки `tls handshake`/`cert-check`, метрики дозвонов. Android/macOS получают изменение со следующей сборкой.
- Память: `tcp-tls-clienthello-vs-browsers` — отметить «СДЕЛАНО, коммит …, НЕ раскатан».
