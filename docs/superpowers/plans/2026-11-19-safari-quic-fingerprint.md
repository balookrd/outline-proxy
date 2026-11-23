# План реализации: Завершение эмуляции Safari QUIC / HTTP/3 (Initial DCID и Spin Bit)

## 1. Контекст и результаты исследований

В рамках задачи маскировки и точной эмуляции браузеров на QUIC/H3 ранее оставался открытым вопрос из аудита 2026-11-10:
> «DCID и spin bit для Safari — нет ни захвата, ни исходника (отложено).»

В кодовой базе (`crates/outline-transport/src/quic/tp_profile.rs`) для профиля `SAFARI` стояло временное предположение:
- `initial_dcid_len: InitialDcidLen::Fixed(MAX_CID_LEN)` (20 байт, дефолт quinn);
- `spin_bit: SpinBit::Spinning` (не было подтверждено замером).

### Результаты свежих замеров на macOS 27.2.1 (Apple Network.framework / Safari)
1. **Initial Destination CID Length**:
   - Ровно **8 байт** (в точности как у Chromium).
   - Source CID Length: **0 байт** (empty SCID в Initial).
2. **Spin Bit (RFC 9000 section 17.4)**:
   - При реальном H3-обмене с сервером `nuxt2.fleet.example` зафиксирован переворот Spin Bit (бит 0x20 в первом байте short header) на каждом RTT: `False -> True -> True -> ...`.
   - Поведение полностью соответствует **`SpinBit::Spinning`**.
3. **Hello Layout**:
   - ClientHello передаётся строго последовательно: один CRYPTO frame на Initial packet (Frame #1: 0..999 + PADDING до 1200 байт; Frame #2: 999..1490 + PADDING до 1200 байт).
   - Текущий `HelloLayout::Contiguous` в quinn полностью соответствует поведению стека Apple.
4. **Transport Parameters**:
   - Все 8 параметров (`0x04: 16777216`, `0x05: 2097152`, `0x06: 2097152`, `0x07: 2097152`, `0x09: 8`, `0x0e: 64`, `0x0f: empty`, `0xff080808: [0x09]`), порядок ротации и отсутствие 0x20 (datagram) в точности совпадают с профилем `SAFARI`.

---

## 2. Цели изменений

1. В [`crates/outline-transport/src/quic/tp_profile.rs`](../../crates/outline-transport/src/quic/tp_profile.rs):
   - Переключить `initial_dcid_len` профиля `SAFARI` с `Fixed(MAX_CID_LEN)` на `Fixed(8)`.
   - Обновить комментарии к `SAFARI`, зафиксировав результаты замеров на macOS 27.
2. В [`crates/outline-transport/src/quic/tests/tls_config.rs`](../../crates/outline-transport/src/quic/tests/tls_config.rs):
   - Расширить тест `h3_initial_dcid_length_follows_the_browser`, добавив проверку Safari: `(8, 0)`.
3. В [`crates/outline-transport/src/quic/tests/tp_profile.rs`](../../crates/outline-transport/src/quic/tests/tp_profile.rs):
   - Добавить тест `safari_profile_spins_the_spin_bit`, проверяющий переворот spin bit на последовательных RTT.
4. Актуализация документации и памяти проекта:
   - Обновить заметки памяти: `~/.claude/projects/<project-slug>/memory/quic-transport-params-vs-browsers.md` и `audit-2026-11-10-masking-backlog.md`.
   - Обновить сопутствующие проектные документы (EN/RU).

---

## 3. План реализации по шагам

### Шаг 1. Правка кода `crates/outline-transport`
- Обновить `crates/outline-transport/src/quic/tp_profile.rs`:
  - `initial_dcid_len: InitialDcidLen::Fixed(8)`.
  - Обновить комментарии.

### Шаг 2. Добавление unit-тестов
- В `crates/outline-transport/src/quic/tests/tls_config.rs`:
  - Добавить проверку Safari в `h3_initial_dcid_length_follows_the_browser`.
- В `crates/outline-transport/src/quic/tests/tp_profile.rs`:
  - Добавить тест `safari_profile_spins_the_spin_bit`.

### Шаг 3. Локальная верификация
- Запустить `cargo test -p outline-transport`.
- Запустить полный локальный CI-гейт согласно `AGENTS.md`:
  - `cargo fmt --check ...`
  - `cargo clippy --workspace --exclude sockudo-ws --all-targets --no-deps -- -D warnings`
  - `cargo test --workspace --exclude sockudo-ws`
  - `(cd android/rust && cargo fmt --check && cargo clippy --no-deps -- -D warnings)`
  - `scripts/audit-vendored.sh`

### Шаг 4. Актуализация документации и памяти
- Обновить файлы в Claude memory.
- Обновить `docs/` при наличии связанных файлов.

### Шаг 5. Коммит в ветку `safari-fingerprint`
- Создать атомарный коммит с четким описанием изменений.
