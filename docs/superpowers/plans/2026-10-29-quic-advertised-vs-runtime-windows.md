# Объявленное vs рабочее окно QUIC — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** H3-клиент объявляет в QUIC Initial окна приёма браузера (Safari: 2 MiB на поток / 16 MiB на соединение; Chrome: 6 / 15 MiB), а после рукопожатия работает с прежними окнами 8 / 64 MiB (или из `[quic]`), так что мимикрия не стоит пропускной способности.

**Architecture:** Пассивный наблюдатель видит только transport parameters в Initial; последующие `MAX_DATA` / `MAX_STREAM_DATA` идут в зашифрованных 1-RTT пакетах. Окно соединения поднимается штатным `quinn::Connection::set_receive_window` сразу после рукопожатия. Окно потока quinn 0.11 задаёт один раз и использует и как объявленное, и как рабочее — поэтому вендорим `quinn-proto 0.11.15` с минимальным патчем: новое поле `TransportConfig::initial_stream_receive_window` уходит в TP и в начальный кредит потока, а `stream_receive_window` остаётся рабочим окном, до которого поток расширяется на первом чтении. Доступ к патч-API — только через модуль-врата `crates/outline-transport/src/quic/vendored.rs`.

**Tech Stack:** Rust 2024, quinn 0.11.9, quinn-proto 0.11.15 (vendored), rustls 0.23 (aws-lc-rs).

**Предыстория:** фаза A (`a3854e5f`, план `2026-10-29-quic-tp-browser-shaping.md`) сделала объявленные окна браузерными, но рабочие окна стали теми же числами: у Safari-профиля поток ограничен 2 MiB ÷ RTT (≈7 МБ/с при 300 мс). Этот план снимает ограничение.

## Global Constraints

- Комментарии в коде, commit-сообщения и PR — на английском; план и чат — на русском.
- Никогда не добавлять трейлер `Co-Authored-By: Claude` и футер «Generated with Claude Code».
- Коммит — только по явной команде владельца; **никогда не `git push`** без отдельной команды. Работать в `main`, веток не создавать.
- Тесты наших крейтов — в `tests/` рядом с модулем; inline `mod tests {}` запрещены. В `vendor/quinn-proto` — upstream-стиль, его не форматируем и не линтуем.
- Гейт (из `AGENTS.md`, ровно эти команды):
  ```bash
  cargo fmt --check -p outline-ss-rust -p outline-ws-rust -p outline-ui \
    -p outline-metrics -p outline-net -p outline-routing -p outline-transport \
    -p outline-tun -p outline-uplink -p outline-wire \
    -p shadowsocks-crypto -p socks5-proto
  cargo clippy --workspace --exclude sockudo-ws --all-targets --no-deps -- -D warnings
  cargo test --workspace --exclude sockudo-ws
  (cd android/rust && cargo fmt --check && cargo clippy --no-deps -- -D warnings)
  ```
- **Никогда `cargo fmt --all`** — он переформатирует `vendor/`. Любой format-only diff в `vendor/` откатывать.
- rustls — только `aws-lc-rs`: `cargo tree -i 'rustls@0.23' -e features | grep 'rustls feature "ring"'` — пусто (и в корне, и в `android/rust`).
- Патч обязан быть **поведенчески нейтральным при `initial_stream_receive_window = None`** (дефолт): серверный `outline-ss-rust` тоже собирается с vendored quinn-proto и не должен измениться.
- Production-код обращается к патч-API quinn-proto только через `crates/outline-transport/src/quic/vendored.rs` (CI-инвариант, Task 2).
- `PATCHES.md` / `PATCHES.ru.md` и `CHANGELOG.md` / `CHANGELOG.ru.md` обновляются парой.
- Выкатка — только по команде владельца, по одному узлу (`ops/deploy/deploy-binary.sh`).

## Что меняется по смыслу

| | Объявлено в Initial (TP) | Рабочее окно после рукопожатия |
|---|---|---|
| Поток, Chromium | 6_291_456 | 8 MiB (или `[quic] stream_receive_window`) |
| Поток, Safari | 2_097_152 | 8 MiB (или `[quic] stream_receive_window`) |
| Соединение, Chromium | 15_728_640 | 64 MiB (или `[quic] receive_window`) |
| Соединение, Safari | 16_777_216 | 64 MiB (или `[quic] receive_window`) |

Рабочее окно никогда не меньше объявленного (`max(рабочее, объявленное)`). `[quic] stream_receive_window` / `receive_window` снова означают рабочие окна с дефолтами 8 / 64 MiB, как до фазы A, и **больше не влияют на Initial** — мимикрию не ломают.

Как растёт окно потока: `Recv` стартует с `sent_max_stream_data = объявленное`; на первом чтении приложением `max_stream_data(рабочее)` даёт `read + 8 MiB`, разница ≥ `8 MiB / 8`, и `MAX_STREAM_DATA` уходит сразу. Отправитель ждёт не больше одного RTT после первых данных.

## File Structure

| Файл | Что меняется |
|---|---|
| `vendor/quinn-proto/` | **Новый.** Копия crates.io `quinn-proto 0.11.15` + патч (Task 2) |
| `quinn-proto-0.11.15.patch` | **Новый.** Все отличия `vendor/quinn-proto` от upstream |
| `Cargo.toml` (корень) | `[patch.crates-io] quinn-proto = { path = "vendor/quinn-proto" }` |
| `android/rust/Cargo.toml` | То же — detached workspace повторяет патч (как уже делает для `h3`) |
| `PATCHES.md`, `PATCHES.ru.md` | Раздел `quinn-proto (0.11.15)` |
| `AGENTS.md` | «Единый `vendor/`» и модули-врата — упомянуть quinn-proto |
| `.github/workflows/ci.yml` | Инвариант: патч-API quinn-proto только во вратах |
| `crates/outline-transport/src/quic/vendored.rs` | **Новый.** Врата: `set_advertised_stream_receive_window` |
| `crates/outline-transport/src/quic/mod.rs` | `mod vendored;`, реэкспорт `raise_h3_receive_window` |
| `crates/outline-transport/src/quic/tls_config.rs` | `RuntimeWindows`, `build_h3_transport`, `raise_h3_receive_window`; дефолты 8 / 64 MiB |
| `crates/outline-transport/src/h3/shared.rs`, `xhttp/h3_pool.rs` | Вызов `raise_h3_receive_window` после рукопожатия |
| `crates/outline-transport/src/quic/tests/loopback.rs` | **Новый.** Общий loopback-сервер для тестов `quic/` |
| `crates/outline-transport/src/quic/tests/tls_config.rs` | Тесты: wire не зависит от рабочих окон; поток и соединение растут |
| `crates/outline-transport/src/quic/tests/tp_profile.rs` | Rebind-тест переходит на `loopback.rs` |
| `bins/outline-ws-rust/src/config/types.rs` | Doc-комментарии `QuicConfig`: рабочие окна, дефолт 8 / 64 MiB |
| `bins/outline-ws-rust/CHANGELOG.md`, `CHANGELOG.ru.md` | Запись в `[Unreleased]` |

---

### Task 1: Вендоринг quinn-proto 0.11.15 без изменений

**Files:**
- Create: `vendor/quinn-proto/` (копия)
- Modify: `Cargo.toml` (корень, `[patch.crates-io]`), `android/rust/Cargo.toml` (`[patch.crates-io]`), `Cargo.lock`, `android/rust/Cargo.lock`

**Interfaces:** Produces: путь `vendor/quinn-proto`, через который обе сборки берут quinn-proto.

- [ ] **Step 1: Скопировать upstream**

```bash
SRC=$(ls -d ~/.cargo/registry/src/*/quinn-proto-0.11.15 | head -1)
mkdir -p vendor/quinn-proto
cp -R "$SRC"/. vendor/quinn-proto/
rm -f vendor/quinn-proto/Cargo.lock vendor/quinn-proto/.cargo_vcs_info.json vendor/quinn-proto/.cargo-ok
diff -r "$SRC/src" vendor/quinn-proto/src && echo SRC_IDENTICAL
```
Expected: `SRC_IDENTICAL`. Если в registry нет 0.11.15 — `cargo fetch` в корне (версия зафиксирована в `Cargo.lock`).

- [ ] **Step 2: Vendoring-trim `Cargo.toml`** — как у `vendor/h3`: удалить все секции `[dev-dependencies.*]` из `vendor/quinn-proto/Cargo.toml` (upstream dev-deps тянут `rcgen` с дефолтным `ring` — инвариант aws-lc-rs). Больше ничего в манифесте не трогать. Файл `Cargo.toml.orig` оставить как есть (справочный).

- [ ] **Step 3: Подключить патч** — корневой `Cargo.toml`:

```toml
[patch.crates-io]
h3 = { path = "vendor/h3" }
quinn-proto = { path = "vendor/quinn-proto" }
sockudo-ws = { path = "vendor/sockudo-ws" }
```

`android/rust/Cargo.toml` — в существующую секцию, с комментарием:

```toml
[patch.crates-io]
h3 = { path = "../../vendor/h3" }
# outline-transport sets the patched quinn-proto API (see PATCHES.md), so the
# detached workspace must repeat this patch as well.
quinn-proto = { path = "../../vendor/quinn-proto" }
```

- [ ] **Step 4: Проверить, что граф не изменился, кроме источника quinn-proto**

Run: `cargo check --workspace --exclude sockudo-ws` и `(cd android/rust && cargo check)`
Run: `git diff Cargo.lock android/rust/Cargo.lock`
Expected: сборка зелёная; в lock-файлах у `quinn-proto 0.11.15` исчезли `source`/`checksum` (path-зависимость), других изменений версий нет. Инвариант rustls (Global Constraints) — пусто в обоих workspace.

- [ ] **Step 5: Полный гейт.** Expected: зелёный (поведение не менялось).

- [ ] **Step 6: Commit** (по команде владельца)

```bash
git add vendor/quinn-proto Cargo.toml Cargo.lock android/rust/Cargo.toml android/rust/Cargo.lock
git commit -m "build(vendor): vendor quinn-proto 0.11.15 verbatim"
```

Отдельный коммит «как есть» нужен, чтобы патч в Task 2 читался чистым diff'ом.

### Task 2: Патч quinn-proto, врата и документация патча

**Files:**
- Modify: `vendor/quinn-proto/src/config/transport.rs`, `src/transport_parameters.rs`, `src/connection/mod.rs`, `src/connection/streams/state.rs`, `src/connection/streams/mod.rs`, `src/connection/streams/recv.rs`
- Create: `quinn-proto-0.11.15.patch`, `crates/outline-transport/src/quic/vendored.rs`
- Modify: `crates/outline-transport/src/quic/mod.rs`, `PATCHES.md`, `PATCHES.ru.md`, `AGENTS.md`, `.github/workflows/ci.yml`

**Interfaces:**
- Produces (vendored): `quinn::TransportConfig::initial_stream_receive_window(&mut self, value: Option<VarInt>) -> &mut Self`
- Produces (врата): `pub(crate) fn set_advertised_stream_receive_window(transport: &mut quinn::TransportConfig, advertised: u32)`

- [ ] **Step 1: `config/transport.rs`**
  - В `struct TransportConfig` сразу после `pub(crate) stream_receive_window: VarInt,`:
    ```rust
    pub(crate) initial_stream_receive_window: Option<VarInt>,
    ```
  - В `impl Default for TransportConfig` рядом с `stream_receive_window: STREAM_RWND.into(),`:
    ```rust
    initial_stream_receive_window: None,
    ```
  - В `impl fmt::Debug for TransportConfig`: добавить `initial_stream_receive_window,` в деструктуризацию `let Self { .. } = self;` и `.field("initial_stream_receive_window", initial_stream_receive_window)` после `stream_receive_window`.
  - Сеттер и геттер сразу после `pub fn stream_receive_window(..)`:
    ```rust
    /// Per-stream receive window advertised in the transport parameters, when it should
    /// differ from the window granted once the application reads (`stream_receive_window`).
    ///
    /// The peer starts with this much credit per stream; the first read extends it to
    /// `stream_receive_window`. `None` (the default) advertises `stream_receive_window`.
    pub fn initial_stream_receive_window(&mut self, value: Option<VarInt>) -> &mut Self {
        self.initial_stream_receive_window = value;
        self
    }

    pub(crate) fn advertised_stream_receive_window(&self) -> VarInt {
        self.initial_stream_receive_window.unwrap_or(self.stream_receive_window)
    }
    ```

- [ ] **Step 2: `transport_parameters.rs:158-160`** — три поля берут объявленное окно:
    ```rust
    initial_max_stream_data_bidi_local: config.advertised_stream_receive_window(),
    initial_max_stream_data_bidi_remote: config.advertised_stream_receive_window(),
    initial_max_stream_data_uni: config.advertised_stream_receive_window(),
    ```

- [ ] **Step 3: `connection/streams/state.rs`**
  - Поле рядом с `stream_receive_window`:
    ```rust
    /// Per-stream credit the peer was told about in the transport parameters; a new
    /// receive stream starts from it before the first read widens it.
    pub(super) initial_stream_receive_window: u64,
    ```
  - `StreamsState::new` — новый последний параметр `initial_stream_receive_window: VarInt`, инициализация `initial_stream_receive_window: initial_stream_receive_window.into(),`. Обновить **все** вызовы `StreamsState::new` в `vendor/quinn-proto/src` (`grep -rn "StreamsState::new" vendor/quinn-proto/src`), включая `#[cfg(test)]`: в тестах передавать тот же аргумент, что идёт как `stream_receive_window`.
  - Начальный кредит/переиспользование потока — на объявленное окно: в `get_or_insert_recv(self.stream_receive_window)` (около строк 266 и 319) и в `recv.free(self.stream_receive_window)` (около 946) заменить `self.stream_receive_window` на `self.initial_stream_receive_window`.
  - Вызовы `rs.max_stream_data(self.stream_receive_window)` (около 507) **не трогать** — это рабочее окно.
- [ ] **Step 4: `connection/streams/mod.rs:141`** — `get_or_insert_recv(self.state.stream_receive_window)` → `get_or_insert_recv(self.state.initial_stream_receive_window)`. **`recv.rs:269`** — `get_or_insert_recv(streams.stream_receive_window)` → `get_or_insert_recv(streams.initial_stream_receive_window)`. `recv.rs:365` (`max_stream_data(...)`) не трогать.
- [ ] **Step 5: `recv.rs::max_stream_data`** — защита на случай рабочего окна меньше объявленного (тогда `read + window` может оказаться ниже уже объявленного кредита):
    ```rust
    let diff = max_stream_data.saturating_sub(self.sent_max_stream_data);
    ```
- [ ] **Step 6: `connection/mod.rs:344-351`** — `StreamsState::new(..)` получает последним аргументом `config.advertised_stream_receive_window()`.
- [ ] **Step 7: Проверить, что больше нигде объявленное окно не нужно**

Run: `grep -rn "stream_receive_window" vendor/quinn-proto/src | grep -v "initial_stream_receive_window\|advertised_stream_receive_window"`
Expected: остались только чтения в `max_stream_data(...)`, поля/сеттер/Default/Debug в `transport.rs`, документация. Каждое оставшееся место разобрать: начальный кредит → объявленное, расширение → рабочее.

- [ ] **Step 8: Врата `crates/outline-transport/src/quic/vendored.rs`** — файл создаётся в **Task 3 Step 2** вместе с первым вызовом (иначе clippy `-D warnings` упадёт на dead code). Здесь только зафиксировать его содержимое для PATCHES-документации:

```rust
//! Gate for the patched `quinn-proto` API (see PATCHES.md). Production code reaches the
//! patch only through this module, so a rebase of the vendored crate touches one file.

/// Advertise `advertised` bytes of per-stream credit in the transport parameters while
/// `TransportConfig::stream_receive_window` stays the window granted after the first read.
pub(crate) fn set_advertised_stream_receive_window(
    transport: &mut quinn::TransportConfig,
    advertised: u32,
) {
    transport.initial_stream_receive_window(Some(quinn::VarInt::from_u32(advertised)));
}
```

- [ ] **Step 9: Патч-артефакт**

```bash
SRC=$(ls -d ~/.cargo/registry/src/*/quinn-proto-0.11.15 | head -1)
diff -ruN "$SRC/src" vendor/quinn-proto/src > quinn-proto-0.11.15.patch; true
diff -u "$SRC/Cargo.toml" vendor/quinn-proto/Cargo.toml >> quinn-proto-0.11.15.patch; true
```
Заменить абсолютные пути registry в заголовках патча на `a/` и `vendor/quinn-proto/` → `b/` (как в `h3-0.0.8.patch`; свериться с его заголовками). Проверка: в чистой копии `cp -R "$SRC" /tmp/qp && cd /tmp/qp && patch -p1 < .../quinn-proto-0.11.15.patch` и `diff -r /tmp/qp/src vendor/quinn-proto/src` — пусто. Временные копии делать в scratchpad-каталоге сессии, а не в `/tmp`, если он есть.

- [ ] **Step 10: `PATCHES.md` и `PATCHES.ru.md`** — в таблицу артефактов строку `quinn-proto-0.11.15.patch`; в «Модули-врата» — `crates/outline-transport/src/quic/vendored.rs` (клиент, `initial_stream_receive_window`); новый раздел (RU-версия; EN — тот же смысл):

```markdown
## quinn-proto (0.11.15)

Baseline — crates.io `quinn-proto 0.11.15`. Логические изменения в
`quinn-proto-0.11.15.patch`:

1. **advertised-stream-window** (`src/config/transport.rs`,
   `src/transport_parameters.rs`, `src/connection/mod.rs`,
   `src/connection/streams/{state,mod,recv}.rs`) — новое
   `TransportConfig::initial_stream_receive_window(Option<VarInt>)`. Это значение
   уходит в `initial_max_stream_data_*` transport parameters и служит начальным
   кредитом каждого входящего потока; `stream_receive_window` остаётся окном, до
   которого поток расширяется на первом чтении (`MAX_STREAM_DATA`). Нужно, чтобы
   H3-клиент объявлял в Initial окно браузера (видно пассивному DPI), а работал с
   большим (последующие `MAX_STREAM_DATA` зашифрованы). `None` (дефолт) — поведение
   upstream; сервер патч не использует. `max_stream_data` считает разницу через
   `saturating_sub`, чтобы рабочее окно меньше объявленного не паниковало.
2. **Vendoring-trim** (`Cargo.toml`) — убраны dev-dependencies (upstream `rcgen` с
   дефолтным `ring` нарушил бы инвариант aws-lc-rs).

Проверка соответствия: применить патч к чистой копии crates.io 0.11.15 и сравнить
`diff -r src/` — совпадение побайтово.
```

- [ ] **Step 11: `AGENTS.md`** — в пункте «Единый `vendor/`» добавить предложение: `vendor/quinn-proto` = upstream 0.11.15 + один логический патч (advertised-stream-window) и vendoring-trim, описано в `PATCHES*.md`. В разделе «Vendored patches» к списку модулей-врат добавить `crates/outline-transport/src/quic/vendored.rs` (quinn-proto). В «Монорепо-инварианты» ничего больше не менять.

- [ ] **Step 12: CI-инвариант** в `.github/workflows/ci.yml` рядом с шагом «invariant — vendored sockudo-ws API only behind gate modules» (тот же стиль):

```yaml
      - name: invariant — patched quinn-proto API only behind the gate module
        run: |
          leaked=$(grep -rn 'initial_stream_receive_window' bins/*/src crates/*/src --include='*.rs' \
            | grep -v '/tests/' \
            | grep -v '^crates/outline-transport/src/quic/vendored\.rs:' || true)
          if [ -n "$leaked" ]; then
            echo "::error::patched quinn-proto API referenced outside the gate module:"
            echo "$leaked"
            exit 1
          fi
```

Проверить локально той же командой — пусто.

- [ ] **Step 13: Нейтральность патча.** Полный гейт; плюс `cargo test -p outline-ss-rust` отдельно (сервер на патченом quinn-proto с дефолтом `None`). Существующие wire-тесты `quic::tests::*` — зелёные без изменений (новое API ещё нигде не вызывается).
- [ ] **Step 14: Commit** (по команде владельца): `build(vendor): patch quinn-proto to advertise a separate initial stream window`.

### Task 3: Рабочие окна в H3-клиенте

**Files:**
- Modify: `crates/outline-transport/src/quic/tls_config.rs`, `crates/outline-transport/src/quic/mod.rs`
- Modify: `crates/outline-transport/src/h3/shared.rs` (после `connecting.await` в `connect_h3_connection`), `crates/outline-transport/src/xhttp/h3_pool.rs` (после рукопожатия в `dial`)
- Create: `crates/outline-transport/src/quic/tests/loopback.rs`
- Modify: `crates/outline-transport/src/quic/tests/tls_config.rs`, `crates/outline-transport/src/quic/tests/tp_profile.rs`
- Modify: `bins/outline-ws-rust/src/config/types.rs` (doc-комментарии `QuicConfig`)

**Interfaces:**
- Consumes: `super::vendored::set_advertised_stream_receive_window`, `super::tp_profile::{QuicTpProfile, for_fingerprint}`
- Produces:
  - `#[derive(Debug, Clone, Copy, PartialEq, Eq)] pub(crate) struct RuntimeWindows { pub(crate) stream: u32, pub(crate) connection: u32 }`
  - `impl RuntimeWindows { pub(crate) fn current(tp: &QuicTpProfile) -> Self }`
  - `pub(crate) fn build_h3_transport(tp: &QuicTpProfile, runtime: RuntimeWindows) -> quinn::TransportConfig`
  - `pub(crate) fn raise_receive_window(connection: &quinn::Connection, runtime: RuntimeWindows)`
  - `pub(crate) fn raise_h3_receive_window(connection: &quinn::Connection)` (реэкспорт из `quic`)
  - тестовый `loopback::Loopback` (см. Step 5)

- [ ] **Step 1: Дефолты рабочих окон** в `tls_config.rs` рядом со статиками `QUIC_*_RECEIVE_WINDOW`:

```rust
// Windows granted once streams are read. The Initial advertises the browser's values
// (see `tp_profile`); these keep a long-RTT carrier stream throughput-bound by the link,
// not the window: at ~1 s tunnel RTT a 2 MiB window caps one flow near 16 Mbit.
// `[quic] stream_receive_window` / `receive_window` override them.
const DEFAULT_RUNTIME_STREAM_WINDOW: u32 = 8 * 1024 * 1024;
const DEFAULT_RUNTIME_CONNECTION_WINDOW: u32 = 64 * 1024 * 1024;
```

- [ ] **Step 2: `RuntimeWindows` и сборка транспорта**

```rust
/// Receive windows the client grants after the handshake; never below what the
/// Initial advertised.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RuntimeWindows {
    pub(crate) stream: u32,
    pub(crate) connection: u32,
}

impl RuntimeWindows {
    pub(crate) fn current(tp: &super::tp_profile::QuicTpProfile) -> Self {
        Self {
            stream: QUIC_STREAM_RECEIVE_WINDOW
                .get()
                .copied()
                .unwrap_or(DEFAULT_RUNTIME_STREAM_WINDOW)
                .max(tp.stream_receive_window),
            connection: QUIC_RECEIVE_WINDOW
                .get()
                .copied()
                .unwrap_or(DEFAULT_RUNTIME_CONNECTION_WINDOW)
                .max(tp.receive_window),
        }
    }
}
```

Создать врата `crates/outline-transport/src/quic/vendored.rs` с содержимым из Task 2 Step 8 и подключить `mod vendored;` в `quic/mod.rs`.

`apply_tp_profile` заменить на `build_h3_transport`, которая собирает весь `TransportConfig` H3-клиента (keep-alive, профиль, BBR, датаграммы off) — тело переносится из `h3_quic_client_config`:

```rust
/// Full H3 client transport: browser-shaped transport parameters, runtime windows
/// granted after the handshake, keep-alive PING jitter and BBR.
pub(crate) fn build_h3_transport(
    tp: &super::tp_profile::QuicTpProfile,
    runtime: RuntimeWindows,
) -> quinn::TransportConfig {
    let mut transport = quinn::TransportConfig::default();
    apply_quic_keepalive(&mut transport);
    let idle = QUIC_CUSTOM_IDLE_TIMEOUT.get().copied().unwrap_or(tp.idle_timeout);
    transport.max_idle_timeout(Some(idle.try_into().expect("valid client idle timeout")));
    // The connection window is advertised as the browser's and raised to `runtime` right
    // after the handshake (`raise_h3_receive_window`); the stream window is split by the
    // vendored quinn-proto patch.
    transport.receive_window(quinn::VarInt::from_u32(tp.receive_window));
    transport.stream_receive_window(quinn::VarInt::from_u32(runtime.stream));
    super::vendored::set_advertised_stream_receive_window(&mut transport, tp.stream_receive_window);
    transport.max_concurrent_bidi_streams(quinn::VarInt::from_u32(tp.max_bidi_streams));
    transport.max_concurrent_uni_streams(quinn::VarInt::from_u32(tp.max_uni_streams));
    apply_quic_carrier_tuning(&mut transport);
    // quinn can only advertise `max_datagram_frame_size` up to 65535 while Chrome sends
    // 65536, so the parameter stays off until it can be sent exactly.
    transport.datagram_receive_buffer_size(None);
    transport
}
```

Существующее предупреждение `keepalive >= idle` (с `Once`) сохранить там, где оно сейчас, считая idle так же. В `h3_quic_client_config()` вызывать `build_h3_transport(tp, RuntimeWindows::current(tp))`.

- [ ] **Step 3: Подъём окна соединения**

```rust
/// Raise the connection receive window from the browser's advertised value to the
/// runtime one. Sends `MAX_DATA` inside 1-RTT packets, invisible to a passive observer.
pub(crate) fn raise_receive_window(connection: &quinn::Connection, runtime: RuntimeWindows) {
    connection.set_receive_window(quinn::VarInt::from_u32(runtime.connection));
}

/// [`raise_receive_window`] for the active dial fingerprint; call right after the H3
/// handshake, inside the same fingerprint scope as [`h3_quic_client_config`].
pub(crate) fn raise_h3_receive_window(connection: &quinn::Connection) {
    let fp = crate::fingerprint_profile::current_dial_fingerprint();
    raise_receive_window(connection, RuntimeWindows::current(super::tp_profile::for_fingerprint(fp)));
}
```

`quic/mod.rs`: `pub(crate) use tls_config::raise_h3_receive_window;`

Вызовы: `h3/shared.rs::connect_h3_connection` — сразу после `let connection = connecting.await...?;` (до `h3::client::new`): `crate::quic::raise_h3_receive_window(&connection);`. `xhttp/h3_pool.rs::dial` — сразу после получения `quinn::Connection` из `connect_with(..).await`, тем же вызовом. Оба места выполняются в той же функции и той же задаче, что и `h3_quic_client_config()`, без `spawn` между ними — fingerprint-scope общий (проверить и зафиксировать в отчёте).

- [ ] **Step 4: Doc-комментарии `QuicConfig`** (`bins/outline-ws-rust/src/config/types.rs`):

```rust
    /// Per-stream QUIC receive window granted after the handshake, in bytes (default
    /// 8 MiB). The Initial always advertises the dial's browser value instead.
    pub stream_receive_window: Option<u32>,
    /// Per-connection QUIC receive window granted after the handshake, in bytes
    /// (default 64 MiB). The Initial always advertises the browser value instead.
    pub receive_window: Option<u32>,
```

- [ ] **Step 5: Общий loopback для тестов `quic/tests/loopback.rs`** — вынести из rebind-теста в `tests/tp_profile.rs` поднятие сервера (rcgen-сертификат, rustls server/client config с ALPN `h3`, `quinn::Endpoint::server` на `127.0.0.1:0`):

```rust
//! Loopback QUIC server shared by the `quic` tests.

use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::Arc;

use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

pub(super) struct Loopback {
    pub(super) server: quinn::Endpoint,
    pub(super) addr: SocketAddr,
    client_tls: Arc<quinn::crypto::rustls::QuicClientConfig>,
}

impl Loopback {
    pub(super) fn new() -> Self { /* body moved from the rebind test */ }

    /// Connects a fresh client endpoint (with `endpoint_config`) using `transport`.
    pub(super) async fn connect(
        &self,
        endpoint_config: quinn::EndpointConfig,
        transport: quinn::TransportConfig,
    ) -> (quinn::Endpoint, quinn::Connection) { /* bind 127.0.0.1:0, Endpoint::new, connect_with */ }
}

pub(super) fn loopback() -> SocketAddr {
    (Ipv4Addr::LOCALHOST, 0).into()
}
```

Подключение в обоих тестовых файлах: `#[path = "loopback.rs"] mod loopback;` (путь относительно `quic/tests/`). Rebind-тест переписать на `Loopback` без изменения его проверок.

- [ ] **Step 6: Тест «рабочие окна не видны в Initial»** (`tests/tls_config.rs`):

```rust
/// Runtime windows never reach the Initial: with 32 MiB / 256 MiB granted after the
/// handshake, the Safari profile still advertises Apple's 2 MiB / 16 MiB.
#[tokio::test]
async fn runtime_windows_do_not_change_advertised_parameters() {
    use crate::fingerprint_profile::{TlsFingerprint, with_dial_fingerprint};
    use std::sync::Arc;

    let runtime = super::RuntimeWindows { stream: 32 << 20, connection: 256 << 20 };
    let ch = with_dial_fingerprint(Some(TlsFingerprint::Safari), async {
        let mut config = super::h3_quic_client_config();
        config.transport_config(Arc::new(super::build_h3_transport(
            &super::super::tp_profile::SAFARI,
            runtime,
        )));
        capture_clienthello(config, super::h3_endpoint_config())
    })
    .await;
    let tp = transport_params_from_clienthello(&ch);
    let int = |id| tp_value(&tp, id).map(varint_value);
    assert_eq!(int(0x04), Some(16_777_216), "initial_max_data");
    for id in [0x05, 0x06, 0x07] {
        assert_eq!(int(id), Some(2_097_152), "initial_max_stream_data {id:#x}");
    }
}
```

(Путь к `SAFARI` подобрать по видимости: тесты — модуль `quic::tls_config::tests`, так что `super::super::tp_profile::SAFARI` = `crate::quic::tp_profile::SAFARI`.)

- [ ] **Step 7: Тест «окно потока растёт на первом чтении» с контролем**

```rust
/// Bytes the server manages to write on one client-opened stream while the client
/// has read a single byte and then stalls for 300 ms.
async fn written_before_stall(lb: &loopback::Loopback, transport: quinn::TransportConfig) -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;

    let written = Arc::new(AtomicU64::new(0));
    let server_written = Arc::clone(&written);
    let server = lb.server.clone();
    let task = tokio::spawn(async move {
        let conn = server.accept().await.unwrap().await.unwrap();
        let (mut send, mut recv) = conn.accept_bi().await.unwrap();
        let mut hello = [0u8; 1];
        recv.read_exact(&mut hello).await.unwrap();
        let chunk = vec![0u8; 64 * 1024];
        loop {
            if send.write_all(&chunk).await.is_err() {
                break;
            }
            server_written.fetch_add(chunk.len() as u64, Ordering::Relaxed);
        }
    });

    let (_ep, conn) = lb.connect(quinn::EndpointConfig::default(), transport).await;
    let (mut send, mut recv) = conn.open_bi().await.unwrap();
    send.write_all(b"h").await.unwrap();
    let mut first = [0u8; 1];
    recv.read_exact(&mut first).await.unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    let total = written.load(std::sync::atomic::Ordering::Relaxed);
    conn.close(0u32.into(), b"done");
    task.abort();
    total
}

#[tokio::test]
async fn stream_window_grows_past_advertised_after_first_read() {
    let lb = loopback::Loopback::new();
    let advertised = 2u32 << 20;

    let mut split = quinn::TransportConfig::default();
    split.stream_receive_window(quinn::VarInt::from_u32(8 << 20));
    super::super::vendored::set_advertised_stream_receive_window(&mut split, advertised);
    split.receive_window(quinn::VarInt::from_u32(64 << 20));
    let grown = written_before_stall(&lb, split).await;
    assert!(grown > 6 << 20, "runtime window not granted: {grown} bytes");

    let mut same = quinn::TransportConfig::default();
    same.stream_receive_window(quinn::VarInt::from_u32(advertised));
    same.receive_window(quinn::VarInt::from_u32(64 << 20));
    let capped = written_before_stall(&lb, same).await;
    assert!(capped <= u64::from(advertised) + (64 << 10), "control not capped: {capped} bytes");
}
```

(`Loopback::new()` поднимает один сервер; два последовательных `connect` к нему допустимы — сервер принимает соединения в задачах `written_before_stall`.)

- [ ] **Step 8: Тест «окно соединения поднимается после рукопожатия» с контролем** — по образцу Step 7: клиентский транспорт `receive_window = 16 MiB`, `stream_receive_window = 8 MiB` (без раздельного объявленного окна, чтобы мерить только соединение); клиент открывает 3 bidi-потока, на каждом шлёт 1 байт; сервер на каждом пишет до упора, считая общий счётчик; клиент читает по 1 байту с каждого и ждёт 300 мс.
  - С вызовом `super::raise_receive_window(&conn, super::RuntimeWindows { stream: 8 << 20, connection: 64 << 20 })` сразу после `connect`: `total > 18 << 20`.
  - Без вызова (контроль): `total <= (16 << 20) + (64 << 10)`.

- [ ] **Step 9: Прогон**

Run: `cargo test -p outline-transport --features h3 quic::`
Expected: все PASS, включая wire-тесты фазы A без изменений, rebind-тест и три новых.

- [ ] **Step 10: Полный гейт + CI-инвариант** (команда из Task 2 Step 12 — пусто).

- [ ] **Step 11: Commit** (по команде владельца): `feat(transport): grant runtime QUIC windows after advertising the browser's`.

### Task 4: CHANGELOG и проверка на проводе

**Files:** `bins/outline-ws-rust/CHANGELOG.md`, `bins/outline-ws-rust/CHANGELOG.ru.md`

- [ ] **Step 1: CHANGELOG EN/RU** — в `[Unreleased]` в записи про browser-shaped transport parameters заменить фразы о цене мимикрии (явные `[quic]`-окна «ломают маскировку»; потолок Safari ~7 МБ/с при 300 мс; совет задать `stream_receive_window` ради скорости) на (EN; RU — тот же смысл):

```markdown
The Initial advertises the browser's receive windows, but right after the handshake the client grants its runtime windows — 8 MiB per stream and 64 MiB per connection by default, or `[quic] stream_receive_window` / `receive_window` — through `MAX_STREAM_DATA` / `MAX_DATA` in encrypted 1-RTT packets, so mimicry no longer caps throughput and the `[quic]` window settings no longer affect the Initial. This relies on a vendored `quinn-proto` 0.11.15 patch (see `PATCHES.md`).
```

Остальные части записи (idle, SCID, `grease_quic_bit`, перечень невыровненных параметров) не трогать.

- [ ] **Step 2: Проверка на проводе** — `cargo build --release -p outline-ws-rust`, захват `scripts/quic-initial-sink.py` (как в фазе A: конфиг с `tcp_ws_url = "wss://127.0.0.1:4433/x/tcp"`, `tcp_mode = "h3"`, `fingerprint_profile = "random"`, несколько прогонов до Chromium- и Safari-захвата). Expected: значения 0x04–0x07 ровно как в таблице «Что меняется по смыслу» (объявленные), а не 8 / 64 MiB.

- [ ] **Step 3: Полный гейт.** Commit (по команде владельца): `docs(ws): runtime QUIC windows no longer trade throughput for mimicry`.

---

## Порядок выкатки

Меняется только клиент. Сервер собирается с vendored quinn-proto, но патч-API не вызывает — поведение прежнее (подтверждает `cargo test -p outline-ss-rust` в Task 2). Выкатка по команде владельца через `ops/deploy/deploy-binary.sh`, по одному клиентскому узлу; на каждом сравнить пропускную способность H3-носителей по метрикам (QUIC PathStats, байты носителя) с периодом до фазы A — не замером скорости через туннель. Android и macOS получают изменение со следующим релизом.

## Self-review

- Покрытие: объявленное окно потока (Task 2 + wire-тест Task 3 Step 6), рабочее окно потока (Step 7 с контролем), окно соединения (Step 8 с контролем), `[quic]` = рабочие окна (Step 2, Step 4, CHANGELOG), нейтральность для сервера (Task 2 Step 13), Android-сборка (Task 1 Step 3–4), врата и CI (Task 2 Steps 8, 12), документация патча (Steps 9–11).
- Сигнатуры: `initial_stream_receive_window(Option<VarInt>)`, `set_advertised_stream_receive_window(&mut TransportConfig, u32)`, `RuntimeWindows { stream, connection }`, `build_h3_transport(&QuicTpProfile, RuntimeWindows)`, `raise_receive_window(&Connection, RuntimeWindows)`, `raise_h3_receive_window(&Connection)` согласованы между задачами.
- Врата создаются в Task 3 вместе с первым вызовом, чтобы Task 2 не оставлял dead code под `-D warnings`.
- `xhttp/h3_pool.rs::dial`: точка вызова — сразу после `let connection = connecting.await...?;` внутри `timeout(fresh_connect_timeout(), async { .. })`, до `h3::client::new` (там же, в той же задаче, вызывается `h3_quic_client_config()` строкой выше).
