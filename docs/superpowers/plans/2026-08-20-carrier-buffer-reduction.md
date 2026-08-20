# Снижение per-flow RSS: буферы носителя — план реализации

> **Для агентных исполнителей:** ОБЯЗАТЕЛЬНЫЙ СУБ-СКИЛЛ: используйте
> superpowers:subagent-driven-development (рекомендуется) или
> superpowers:executing-plans для выполнения плана задача за задачей. Шаги
> размечены чекбоксами (`- [ ]`).

**Цель:** убрать эагерный резерв буферов WS-носителя, который платится на каждой
сессии (включая простаивающие), чтобы снизить RSS на туннельный флоу.

**Архитектура:** два независимых изменения значений констант. Первое — в нашем
коде (`ws_client_config()` для tungstenite-путей h1/h2), покрывается unit-тестом
по TDD. Второе — четвёртый логический патч в vendored `sockudo-ws` (h3-путь), в
уже патченном файле; vendored исключён из тестов и clippy в CI, поэтому там
верификация иная: сборка, сверка с upstream и регенерация патч-артефакта.

**Технологии:** Rust 2024, tokio-tungstenite/tungstenite 0.29, vendored
sockudo-ws 1.7.5, cargo workspace.

**Спека:** `docs/superpowers/specs/2026-08-20-carrier-buffer-reduction-design.md`

## Глобальные ограничения

- **Значения:** tungstenite `read_buffer_size = 32 * 1024`, `write_buffer_size =
  0`; sockudo `BytesMut::with_capacity(32 * 1024)` вместо `64 * 1024`.
- **`max_write_buffer_size` НЕ трогать** — остаётся `usize::MAX`.
- **В sockudo патчить только `from_h3_client` и `from_h3_server`.** `from_h2` и
  `from_quic` остаются upstream-vanilla: data plane их не инстанцирует.
- **CI-гейт гонять целиком и в этом порядке** (`fmt` падает первым и маскирует
  clippy):
  ```
  cargo fmt --check -p outline-ss-rust -p outline-ws-rust -p outline-ui \
    -p outline-metrics -p outline-net -p outline-routing -p outline-transport \
    -p outline-tun -p outline-uplink -p outline-wire \
    -p shadowsocks-crypto -p socks5-proto
  cargo clippy --workspace --exclude sockudo-ws --all-targets --no-deps -- -D warnings
  cargo test --workspace --exclude sockudo-ws
  ```
- **`cargo fmt --all` НЕ запускать** — он переформатирует `vendor/*` под
  проектный стиль и молча рассинхронизирует дерево с патч-артефактом. Только
  явный список пакетов, как выше. После форматирования проверять
  `git status --short vendor` и откатывать format-only diff.
- **Документация парами EN/RU** в одном изменении: `PATCHES.md` +
  `PATCHES.ru.md`, `CHANGELOG.md` + `CHANGELOG.ru.md` каждого затронутого бинаря.
- **`git commit` — только по явной команде владельца.** Шаги «коммит» ниже
  означают: показать `git diff --stat` и дождаться команды. Ветки не создавать,
  работать в `main`.
- **Прод не трогать.** Раскатка — отдельно, по явному согласию владельца.
- **Трейлеры `Co-Authored-By` и подписи Claude в коммиты/тексты не добавлять.**

---

### Task 1: буферы tungstenite (h1 / h2)

**Файлы:**
- Изменить: `crates/outline-transport/src/lib.rs:356-360` (`ws_client_config`)
- Тест: `crates/outline-transport/src/tests/mod.rs` (модуль `ws_message_cap`,
  рядом с `caps_message_and_frame_size_to_one_mib` на строке ~1059)
- Изменить: `bins/outline-ws-rust/CHANGELOG.md`, `bins/outline-ws-rust/CHANGELOG.ru.md`

**Интерфейсы:**
- Потребляет: ничего от других задач.
- Производит: ничего для других задач. `ws_client_config()` сохраняет текущую
  сигнатуру `pub(crate) fn ws_client_config() -> WebSocketConfig`.

- [ ] **Шаг 1: Написать падающий тест**

В `crates/outline-transport/src/tests/mod.rs`, внутрь `mod ws_message_cap`,
сразу после теста `caps_message_and_frame_size_to_one_mib`:

```rust
    /// tungstenite defaults reserve a 128 KiB read buffer eagerly on every
    /// session and let the write buffer grow to another 128 KiB. Each tunnelled
    /// flow carries its own carrier, so that reserve is paid per flow — on a
    /// 700 MiB budget with peaks around 574 concurrent sessions it is the
    /// difference between surviving a burst and being OOM-killed. The write
    /// buffer is dropped entirely (the SS/VLESS writers already coalesce up to
    /// `FRAME_SOFT_CAP`), mirroring the server's `write_buffer_size(0)`.
    #[test]
    fn shrinks_carrier_read_and_write_buffers() {
        let cfg = ws_client_config();
        assert_eq!(cfg.read_buffer_size, 32 * 1024);
        assert_eq!(cfg.write_buffer_size, 0);
        // Deliberately left at the tungstenite default: capping it would turn a
        // congested carrier from "buffer grows" into `WriteBufferFull` and a torn
        // session, and `carrier_queue` already applies backpressure upstream.
        assert_eq!(cfg.max_write_buffer_size, usize::MAX);
    }
```

- [ ] **Шаг 2: Запустить тест — убедиться, что падает**

```bash
cargo test -p outline-transport shrinks_carrier_read_and_write_buffers
```

Ожидается: FAIL, `assertion `left == right` failed: left: 131072, right: 32768`
(текущий дефолт 128 KiB).

- [ ] **Шаг 3: Минимальная реализация**

В `crates/outline-transport/src/lib.rs` заменить тело `ws_client_config`
(строки 356-360) на:

```rust
pub(crate) fn ws_client_config() -> tokio_tungstenite::tungstenite::protocol::WebSocketConfig {
    tokio_tungstenite::tungstenite::protocol::WebSocketConfig::default()
        .max_message_size(Some(WS_MAX_MESSAGE_SIZE))
        .max_frame_size(Some(WS_MAX_MESSAGE_SIZE))
        // Every tunnelled flow dials its own carrier, so tungstenite's default
        // 128 KiB read buffer is reserved eagerly once per flow and the write
        // buffer grows to another 128 KiB on top. 32 KiB still covers a typical
        // frame in one read, and the buffer is a starting capacity, not a
        // ceiling. `write_buffer_size(0)` mirrors the server
        // (`bins/outline-ss-rust/src/server/transport/mod.rs`): the SS/VLESS
        // writers already coalesce up to `FRAME_SOFT_CAP`, so buffering the
        // coalesced frame a second time only costs residency.
        .read_buffer_size(32 * 1024)
        .write_buffer_size(0)
}
```

Также обновить doc-комментарий над функцией (строки 349-355): добавить
предложение о буферах, сохранив существующий текст про cap сообщения.

- [ ] **Шаг 4: Запустить тест — убедиться, что проходит**

```bash
cargo test -p outline-transport shrinks_carrier_read_and_write_buffers
```

Ожидается: `test result: ok. 1 passed`.

- [ ] **Шаг 5: Прогнать соседние тесты носителя (регрессия)**

```bash
cargo test -p outline-transport ws_message_cap
```

Ожидается: все тесты модуля проходят, включая
`rejects_inbound_message_larger_than_cap` — `write_buffer_size(0)` не должен
ломать отправку, а `read_buffer_size` не должен влиять на отбраковку по
заголовку кадра.

- [ ] **Шаг 6: Записать в CHANGELOG (EN)**

В `bins/outline-ws-rust/CHANGELOG.md`, в секцию `## [Unreleased]` → `### Changed`
(создать подзаголовок, если его нет, — он идёт после `### Added`):

```markdown
- **WebSocket carriers no longer reserve 128 KiB per session up front.** Every tunnelled flow dials its own carrier, so tungstenite's default read buffer (128 KiB, allocated eagerly) and write buffer (a further 128 KiB, grown lazily) were paid once per flow: on a 964 MiB box under a 700 MiB cgroup cap, with bursts reaching ~574 concurrent sessions, that reserve alone accounted for up to ~125 MiB and the process was OOM-killed at peaks of 639 MiB. The client now asks for a 32 KiB read buffer and no write buffer, the latter matching what the server already does — the Shadowsocks/VLESS writers coalesce up to `FRAME_SOFT_CAP` before handing a frame over, so buffering it again only cost residency. Buffer sizes are starting capacities rather than ceilings, so a large message still grows the buffer on demand; the trade is more `read()` calls on large frames.
```

- [ ] **Шаг 7: Записать в CHANGELOG (RU)**

В `bins/outline-ws-rust/CHANGELOG.ru.md`, в ту же секцию:

```markdown
- **WebSocket-носители больше не резервируют по 128 KiB на сессию заранее.** Каждый туннельный флоу дозванивается своим носителем, поэтому дефолтный буфер чтения tungstenite (128 KiB, аллоцируется эагерно) и буфер записи (ещё 128 KiB, растёт лениво) платились по разу на флоу: на плате 964 MiB под cgroup-лимитом 700 MiB, при всплесках до ~574 одновременных сессий, один только этот резерв давал до ~125 MiB, и процесс убивал OOM на пиках 639 MiB. Теперь клиент просит буфер чтения 32 KiB и не просит буфер записи вовсе — последнее повторяет то, что сервер уже делает у себя: writer'ы Shadowsocks/VLESS коалесцируют запись до `FRAME_SOFT_CAP` перед передачей кадра, так что вторая буферизация стоила только резидентности. Размеры буферов — начальная ёмкость, а не потолок, поэтому крупное сообщение по-прежнему растит буфер по мере надобности; плата — больше вызовов `read()` на крупных кадрах.
```

- [ ] **Шаг 8: Прогнать CI-гейт целиком**

```bash
cargo fmt --check -p outline-ss-rust -p outline-ws-rust -p outline-ui \
  -p outline-metrics -p outline-net -p outline-routing -p outline-transport \
  -p outline-tun -p outline-uplink -p outline-wire \
  -p shadowsocks-crypto -p socks5-proto
cargo clippy --workspace --exclude sockudo-ws --all-targets --no-deps -- -D warnings
cargo test --workspace --exclude sockudo-ws
```

Ожидается: все три шага зелёные. `vendor/` не тронут:
`git status --short vendor` пустой.

- [ ] **Шаг 9: Показать diff и дождаться команды на коммит**

```bash
git status --short && git diff --stat
```

Коммит выполнять ТОЛЬКО по явной команде владельца. Заготовка сообщения:

```
perf(transport): shrink per-carrier WebSocket buffers

Each tunnelled flow dials its own carrier, so tungstenite's default
128 KiB read buffer was reserved once per flow. Ask for 32 KiB and drop
the write buffer entirely, matching the server, which already sets
write_buffer_size(0) on its side.
```

---

### Task 2: четвёртый патч vendored sockudo-ws (h3)

**Файлы:**
- Изменить: `vendor/sockudo-ws/src/stream/transport_stream.rs` (две строки: в
  `from_h3_server` ~460 и `from_h3_client` ~478)
- Изменить: `sockudo-ws-1.7.5.patch` (регенерация)
- Изменить: `PATCHES.md`, `PATCHES.ru.md` (четвёртый пункт в списке)
- Изменить: `AGENTS.md` (корневой, раздел «Монорепо-инварианты»)
- Изменить: `bins/outline-ss-rust/CHANGELOG.md`, `bins/outline-ss-rust/CHANGELOG.ru.md`

**Интерфейсы:**
- Потребляет: ничего от Task 1 (задачи независимы).
- Производит: ничего. Публичные сигнатуры `Stream::<Http3>::from_h3_client` и
  `from_h3_server` не меняются — меняется только начальная ёмкость внутреннего
  `read_buf`.

**Почему здесь нет TDD:** vendored-крейт исключён из `cargo test` и `cargo
clippy` в CI (`--exclude sockudo-ws`), собственных тестов на эти конструкторы
нет, а тип `Http3StreamInner` приватен — снаружи ёмкость `read_buf` не
наблюдаема. Верификация: сборка + побайтовая сверка с upstream через
регенерацию патча (шаги 2-6).

- [ ] **Шаг 1: Восстановить upstream-дерево обратным применением патча**

GitHub из этой среды недоступен, поэтому upstream получаем из самого vendored
дерева. Это попутно доказывает, что vendored = upstream + патч (нет дрейфа).

```bash
WORK=/private/tmp/claude-501/-Users-mvmalykh-IdeaProjects-outline-proxy/e78fe053-0908-475d-89c8-e080dbf3cdaf/scratchpad/sockudo
REPO=/Users/mvmalykh/IdeaProjects/outline-proxy
rm -rf "$WORK" && mkdir -p "$WORK/base"
cp -R "$REPO/vendor/sockudo-ws/src" "$WORK/base/src"
cd "$WORK/base" && git apply -R -p1 "$REPO/sockudo-ws-1.7.5.patch" && echo "REVERSE-APPLY OK"
```

Ожидается: `REVERSE-APPLY OK`. Если `git apply` ругается — vendored уже разошёлся
с патчем, СТОП: чинить расхождение отдельно, не смешивая с этой задачей.

- [ ] **Шаг 2: Зафиксировать upstream как git-baseline**

```bash
WORK=/private/tmp/claude-501/-Users-mvmalykh-IdeaProjects-outline-proxy/e78fe053-0908-475d-89c8-e080dbf3cdaf/scratchpad/sockudo
cd "$WORK/base" && git init -q . && git add -A && \
  git -c user.email=b@b -c user.name=b commit -qm upstream && echo "BASELINE OK"
```

Ожидается: `BASELINE OK`.

- [ ] **Шаг 3: Внести изменение в vendored-исходник**

В `vendor/sockudo-ws/src/stream/transport_stream.rs` — ДВЕ правки.

В `from_h3_server` (`Http3StreamInner::Server`, ~строка 460):

```rust
                read_buf: BytesMut::with_capacity(32 * 1024),
```

В `from_h3_client` (`Http3StreamInner::Client`, ~строка 478):

```rust
                read_buf: BytesMut::with_capacity(32 * 1024),
```

`from_h2` (~190, `recv_buf`) и `from_quic` (~439, `recv_buf`) НЕ трогать —
остаются `64 * 1024`.

Проверка, что изменены ровно две строки и ровно те:

```bash
grep -n "with_capacity(32 \* 1024)\|with_capacity(64 \* 1024)" \
  vendor/sockudo-ws/src/stream/transport_stream.rs
```

Ожидается: две строки с `32 * 1024` (в `Server` и `Client` вариантах) и две с
`64 * 1024` (в `from_h2` и `from_quic`).

- [ ] **Шаг 4: Убедиться, что собирается**

```bash
cargo check -p outline-ws-rust && cargo check -p outline-ss-rust
```

Ожидается: обе команды зелёные.

- [ ] **Шаг 5: Регенерировать патч-артефакт**

```bash
WORK=/private/tmp/claude-501/-Users-mvmalykh-IdeaProjects-outline-proxy/e78fe053-0908-475d-89c8-e080dbf3cdaf/scratchpad/sockudo
REPO=/Users/mvmalykh/IdeaProjects/outline-proxy
rm -rf "$WORK/base/src" && cp -R "$REPO/vendor/sockudo-ws/src" "$WORK/base/src"
cd "$WORK/base" && git add -A && git diff --cached > "$REPO/sockudo-ws-1.7.5.patch"
grep -c "^diff --git" "$REPO/sockudo-ws-1.7.5.patch"
```

Ожидается: `3` (те же три файла: `error.rs`, `server.rs`,
`transport_stream.rs` — новых файлов патч не добавляет).

- [ ] **Шаг 6: Проверить, что патч воспроизводит vendored побайтово**

```bash
WORK=/private/tmp/claude-501/-Users-mvmalykh-IdeaProjects-outline-proxy/e78fe053-0908-475d-89c8-e080dbf3cdaf/scratchpad/sockudo
REPO=/Users/mvmalykh/IdeaProjects/outline-proxy
rm -rf "$WORK/verify" && mkdir -p "$WORK/verify"
# вернуть base/src к upstream-состоянию (снимает и индекс, и рабочее дерево)
cd "$WORK/base" && git reset --hard -q HEAD && cp -R "$WORK/base/src" "$WORK/verify/src"
cd "$WORK/verify" && git apply -p1 "$REPO/sockudo-ws-1.7.5.patch" && \
  diff -r "$WORK/verify/src" "$REPO/vendor/sockudo-ws/src" && echo "PATCH ROUNDTRIP OK"
```

Ожидается: `PATCH ROUNDTRIP OK` без строк различий.

- [ ] **Шаг 7: Обновить PATCHES.ru.md**

В `PATCHES.ru.md`, раздел `## sockudo-ws (1.7.5)`, в нумерованный список
логических изменений добавить четвёртым пунктом:

```markdown
4. **h3-read-buf-capacity** (`src/stream/transport_stream.rs`) — начальная
   ёмкость `read_buf` у живых H3 WebSocket-стримов снижена с 64 KiB до 32 KiB в
   `from_h3_client` и `from_h3_server` (`Http3StreamInner::{Client,Server}` — те
   же два конструктора, что правит `fix-h3-poll-write`). Буфер аллоцируется
   эагерно на КАЖДЫЙ стрим, а каждый туннельный флоу несёт свой носитель, так
   что резерв платился по разу на флоу; на `.104` под cgroup-лимитом 700 MiB это
   часть той памяти, из-за которой процесс убивал OOM. `BytesMut::with_capacity`
   задаёт начальную ёмкость, а не потолок, поэтому крупное сообщение по-прежнему
   растит буфер сам — меняется только объём эагерного резерва. `from_h2` и
   `from_quic` намеренно оставлены upstream-vanilla: data plane их не
   инстанцирует (тот же принцип, по которому `fix-h3-poll-write` живёт только в
   двух живых типах стрима).
```

- [ ] **Шаг 8: Обновить PATCHES.md (EN)**

В `PATCHES.md`, в соответствующий список раздела sockudo-ws, добавить
четвёртым пунктом:

```markdown
4. **h3-read-buf-capacity** (`src/stream/transport_stream.rs`) — the initial
   `read_buf` capacity on the live H3 WebSocket streams drops from 64 KiB to
   32 KiB in `from_h3_client` and `from_h3_server`
   (`Http3StreamInner::{Client,Server}` — the same two constructors
   `fix-h3-poll-write` patches). The buffer is allocated eagerly per stream and
   every tunnelled flow carries its own carrier, so the reserve was paid once
   per flow; on `.104`, under a 700 MiB cgroup cap, it is part of what got the
   process OOM-killed. `BytesMut::with_capacity` sets a starting capacity rather
   than a ceiling, so a large message still grows the buffer on demand — only
   the eager reserve changes. `from_h2` and `from_quic` are deliberately left
   upstream-vanilla: the data plane never instantiates them (the same rule that
   keeps `fix-h3-poll-write` confined to the two live stream types).
```

- [ ] **Шаг 9: Обновить корневой AGENTS.md**

В `AGENTS.md`, раздел «Монорепо-инварианты», в пункте «**Единый `vendor/`.**»:
заменить «ровно три логических патча» на «ровно четыре логических патча», а в
перечислении файлов дополнить описание `src/stream/transport_stream.rs`, где
сейчас указан только `fix-h3-poll-write`:

```
`src/stream/transport_stream.rs` (fix-h3-poll-write: машина состояний
`queue_send`/`poll_drain`/`queue_grease`/`poll_quic_finish`, она же даёт FIN
вместо RESET_STREAM на закрытии — иначе `H3_INTERNAL_ERROR` рвёт всё
QUIC-соединение; плюс h3-read-buf-capacity: эагерный `read_buf` живых H3-стримов
64 KiB → 32 KiB)
```

Формулировку «и все они живут в трёх файлах» оставить без изменений — файлов
по-прежнему три.

- [ ] **Шаг 10: Записать в CHANGELOG ss-rust (EN + RU)**

Серверный бинарь меняется только через vendored-патч (`from_h3_server`), его
собственный код не тронут.

В `bins/outline-ss-rust/CHANGELOG.md`, секция `## [Unreleased]` → `### Changed`:

```markdown
- **HTTP/3 WebSocket streams no longer reserve 64 KiB per stream up front.** The vendored `sockudo-ws` allocated its `read_buf` eagerly at 64 KiB for every live H3 stream; it now starts at 32 KiB. The capacity is a starting size rather than a ceiling, so a large message still grows the buffer on demand. Client and server share the vendored crate, so both sides get the smaller reserve.
```

В `bins/outline-ss-rust/CHANGELOG.ru.md`:

```markdown
- **HTTP/3 WebSocket-стримы больше не резервируют по 64 KiB на стрим заранее.** Vendored `sockudo-ws` аллоцировал `read_buf` эагерно по 64 KiB на каждый живой H3-стрим; теперь начальная ёмкость 32 KiB. Ёмкость — стартовый размер, а не потолок, поэтому крупное сообщение по-прежнему растит буфер по мере надобности. Клиент и сервер делят vendored-крейт, поэтому меньший резерв достаётся обеим сторонам.
```

- [ ] **Шаг 11: Прогнать CI-гейт целиком**

```bash
cargo fmt --check -p outline-ss-rust -p outline-ws-rust -p outline-ui \
  -p outline-metrics -p outline-net -p outline-routing -p outline-transport \
  -p outline-tun -p outline-uplink -p outline-wire \
  -p shadowsocks-crypto -p socks5-proto
cargo clippy --workspace --exclude sockudo-ws --all-targets --no-deps -- -D warnings
cargo test --workspace --exclude sockudo-ws
```

Ожидается: все три зелёные. Дополнительно убедиться, что в `vendor/` изменён
ровно один файл и ровно две строки:

```bash
git diff --stat vendor/
```

Ожидается: `vendor/sockudo-ws/src/stream/transport_stream.rs | 4 ++--`.

- [ ] **Шаг 12: Показать diff и дождаться команды на коммит**

```bash
git status --short && git diff --stat
```

Коммит — ТОЛЬКО по явной команде владельца. Заготовка сообщения:

```
perf(vendor): shrink eager H3 stream read buffer to 32 KiB

sockudo-ws allocated read_buf eagerly at 64 KiB per live H3 stream, and
every tunnelled flow carries its own carrier, so the reserve was paid per
flow. from_h2 and from_quic stay upstream-vanilla: the data plane never
instantiates them.
```

---

## Проверка результата (после обеих задач)

- [ ] **Шаг 1: Убедиться, что оба изменения на месте**

```bash
cargo test -p outline-transport ws_message_cap
git diff --stat vendor/ sockudo-ws-1.7.5.patch
```

Ожидается: тесты зелёные; в diff — `transport_stream.rs` и обновлённый артефакт.

- [ ] **Шаг 2: Свериться со спекой**

Проверить по таблице «Затрагиваемые файлы» в
`docs/superpowers/specs/2026-08-20-carrier-buffer-reduction-design.md`, что
тронуты все перечисленные файлы и ни один лишний.

**Раскатка на прод в этот план НЕ входит.** Она делается отдельно, по явному
согласию владельца, через `ops/deploy/deploy-binary.sh`, по одному узлу, с
верификацией по разделу «Верификация на проде» из спеки.
