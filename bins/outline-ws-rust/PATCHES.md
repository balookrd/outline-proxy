# Local Patches

Этот файл фиксирует локальные патчи на vendored зависимости, чтобы их было проще сопровождать при обновлениях.

## h3 0.0.8

- Upstream crate: `h3`
- Vendored path: [`vendor/h3`](/Users/mvmalykh/IdeaProjects/outline-ws-rust/vendor/h3)
- Patch file: [`h3-0.0.8-git.patch`](/Users/mvmalykh/IdeaProjects/outline-ws-rust/h3-0.0.8-git.patch)

### Purpose

Локальный patch нужен для поддержки `ws-over-http3`:

- добавляет `Protocol::WEBSOCKET` в `h3::ext::Protocol`
- разрешает значение `:protocol = "websocket"` для RFC 9220
- подавляет шумные warnings в vendored crate, чтобы сборка и тесты были чище

### Files changed relative to upstream

- [`vendor/h3/src/ext.rs`](/Users/mvmalykh/IdeaProjects/outline-ws-rust/vendor/h3/src/ext.rs)
- [`vendor/h3/src/lib.rs`](/Users/mvmalykh/IdeaProjects/outline-ws-rust/vendor/h3/src/lib.rs)

### Source of truth

Источником правды для локальных отличий считается [`h3-0.0.8-git.patch`](/Users/mvmalykh/IdeaProjects/outline-ws-rust/h3-0.0.8-git.patch).

Если `vendor/h3` нужно пересобрать из чистого upstream checkout:

```bash
git apply /Users/mvmalykh/IdeaProjects/outline-ws-rust/h3-0.0.8-git.patch
```

### Maintenance note

При обновлении `h3` лучше:

1. взять чистый upstream crate нужной версии
2. попробовать применить [`h3-0.0.8-git.patch`](/Users/mvmalykh/IdeaProjects/outline-ws-rust/h3-0.0.8-git.patch) вручную или адаптировать его
3. после переноса изменений обновить patch-файл в корне проекта

## sockudo-ws 1.7.5

- Upstream crate: `sockudo-ws`
- Vendored path: [`vendor/sockudo-ws`](/Users/mvmalykh/IdeaProjects/outline-ws-rust/vendor/sockudo-ws)
- Patch file: [`sockudo-ws-mips.patch`](/Users/mvmalykh/IdeaProjects/outline-ws-rust/sockudo-ws-mips.patch)

### Purpose

Локальный patch нужен для legacy MIPS router-сборок:

- отключает `tokio-rustls` default features, чтобы `release-router` не тащил `aws-lc-sys`
- добавляет fallback для targets без `AtomicU64`, чтобы `pubsub` собирался на MIPS32

### Files changed relative to upstream

- [`vendor/sockudo-ws/Cargo.toml`](/Users/mvmalykh/IdeaProjects/outline-ws-rust/vendor/sockudo-ws/Cargo.toml)
- [`vendor/sockudo-ws/src/pubsub.rs`](/Users/mvmalykh/IdeaProjects/outline-ws-rust/vendor/sockudo-ws/src/pubsub.rs)

### Source of truth

Источником правды для локальных отличий считается [`sockudo-ws-mips.patch`](/Users/mvmalykh/IdeaProjects/outline-ws-rust/sockudo-ws-mips.patch).

Если `vendor/sockudo-ws` нужно пересобрать из чистого upstream checkout:

```bash
git apply /Users/mvmalykh/IdeaProjects/outline-ws-rust/sockudo-ws-mips.patch
```

### Maintenance note

При обновлении `sockudo-ws` лучше:

1. взять чистый upstream crate нужной версии
2. попробовать применить [`sockudo-ws-mips.patch`](/Users/mvmalykh/IdeaProjects/outline-ws-rust/sockudo-ws-mips.patch) вручную или адаптировать его
3. после переноса изменений обновить patch-файл в корне проекта

## fix-h3-poll-write (h3 + sockudo-ws)

- Patch file: [`fix-h3-poll-write.patch`](/Users/mvmalykh/IdeaProjects/outline-ws-rust/fix-h3-poll-write.patch)
- Затрагивает: `vendor/h3` и `vendor/sockudo-ws`

### Purpose

Исправляет некорректные реализации `AsyncWrite::poll_write` и `poll_shutdown` для H3-стримов.

**Проблема `poll_write`:** старая реализация вызывала `stream.send_data(data)` и пиновала полученный `Future` прямо внутри `poll_write`. При повторном вызове `poll_write` (пока QUIC-буфер занят) создавался новый `Future`, предыдущие данные терялись, а `waker` не регистрировался корректно.

**Проблема `poll_shutdown`:** старая реализация аналогично пиновала `stream.finish()` заново при каждом повторном вызове, что приводило к повторному вызову `send_data` для GREASE-фрейма и к `H3_INTERNAL_ERROR` при занятом `writing`-буфере.

Новая реализация добавляет в `h3::connection::RequestStream` четыре метода:

| Метод | Описание |
|---|---|
| `queue_send(buf)` | Синхронно кладёт DATA-фрейм в QUIC send-буфер, не блокируясь |
| `poll_drain(cx)` | Поллит `poll_ready` транспорта до завершения флаша |
| `queue_grease()` | Синхронно кладёт GREASE-фрейм ровно один раз (no-op если отключён) |
| `poll_quic_finish(cx)` | Поллит `poll_finish` транспорта до отправки QUIC FIN |

Публичные делегаты этих методов добавлены в `h3::client::stream` и `h3::server::stream`.

Стримы sockudo-ws переписаны:

- **`poll_write`** — хранит `write_queued: Option<usize>`; при `Pending` повторный вызов пропускает `queue_send` и сразу вызывает `poll_drain`
- **`poll_shutdown`** — трёхфазный: `queue_grease` (ровно один раз, охраняется `shutdown_started: bool`) → `poll_drain` → `poll_quic_finish`

### Files changed

- [`vendor/h3/src/connection.rs`](/Users/mvmalykh/IdeaProjects/outline-ws-rust/vendor/h3/src/connection.rs) — `queue_send`, `poll_drain`, `queue_grease`, `poll_quic_finish`
- [`vendor/h3/src/client/stream.rs`](/Users/mvmalykh/IdeaProjects/outline-ws-rust/vendor/h3/src/client/stream.rs) — публичные делегаты всех четырёх методов
- [`vendor/h3/src/server/stream.rs`](/Users/mvmalykh/IdeaProjects/outline-ws-rust/vendor/h3/src/server/stream.rs) — публичные делегаты всех четырёх методов
- [`vendor/sockudo-ws/src/http3/stream.rs`](/Users/mvmalykh/IdeaProjects/outline-ws-rust/vendor/sockudo-ws/src/http3/stream.rs) — `Http3ServerStream` + `Http3ClientStream`: поля `write_queued`, `shutdown_started`; фикс `poll_write` и `poll_shutdown`
- [`vendor/sockudo-ws/src/stream/transport_stream.rs`](/Users/mvmalykh/IdeaProjects/outline-ws-rust/vendor/sockudo-ws/src/stream/transport_stream.rs) — `Stream<Http3>`: то же самое

### Source of truth

Источником правды считается [`fix-h3-poll-write.patch`](/Users/mvmalykh/IdeaProjects/outline-ws-rust/fix-h3-poll-write.patch).

Чтобы воспроизвести изменения поверх чистых checkout'ов обоих крейтов:

```bash
git apply fix-h3-poll-write.patch
```

### Maintenance note

При обновлении любого из затронутых крейтов:

1. взять чистые upstream версии `h3` и `sockudo-ws`
2. применить остальные патчи (`h3-0.0.8-git.patch`, `sockudo-ws-mips.patch`)
3. применить или адаптировать `fix-h3-poll-write.patch`
4. обновить patch-файл в корне проекта: `git diff HEAD vendor/h3 vendor/sockudo-ws > fix-h3-poll-write.patch`
