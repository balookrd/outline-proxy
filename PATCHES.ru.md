# Локальные патчи

Единый источник истины по локальным патчам на vendored-крейты.
*English version: [PATCHES.md](PATCHES.md).*

Монорепо vendor'ит и патчит два upstream-крейта, чтобы HTTP/3 WebSocket-путь
был практичен. Пропатченные копии лежат в `vendor/h3` и `vendor/sockudo-ws`,
подключены через `[patch.crates-io]` в корневом `Cargo.toml`. Файлы `.patch` в
этом каталоге — review- и maintenance-артефакты; сами сборки используют
vendored-копии.

Регенерированы против:

- **h3** — crates.io `h3 0.0.8`.
- **sockudo-ws** — GitHub-тег `v1.7.5`, нормализованный rustfmt'ом к
  формату публикации крейта (см. примечание ниже).

## Артефакты-патчи

| Файл | Что покрывает |
|------|---------------|
| [`h3-0.0.8.patch`](h3-0.0.8.patch) | все отличия `vendor/h3` от upstream `h3 0.0.8` |
| [`sockudo-ws-1.7.5.patch`](sockudo-ws-1.7.5.patch) | все отличия `vendor/sockudo-ws/src` (однострочное изменение `Cargo.toml` описано ниже, в патч не входит) |

## h3 (0.0.8)

Логические изменения в `h3-0.0.8.patch`:

1. **RFC 9220 WebSocket** (`src/ext.rs`, `src/lib.rs`) — добавляет
   `Protocol::WEBSOCKET` и парсит/сериализует `:protocol = websocket`.
   Upstream `h3 0.0.8` его не распознаёт, а Extended CONNECT WebSocket поверх
   HTTP/3 требует этого значения псевдо-заголовка.
2. **fix-h3-poll-write** (`src/connection.rs`, `src/client/stream.rs`,
   `src/server/stream.rs`) — добавляет `queue_send` / `poll_drain` /
   `queue_grease` / `poll_quic_finish`, чтобы `AsyncWrite::poll_write` и
   `poll_shutdown` не пересоздавали `send_data`-future на каждый poll. Старый
   код делал двойную запись при заполненном QUIC send-буфере; h3-quinn
   репортит это как `H3_INTERNAL_ERROR`, что закрывает всё QUIC-соединение и
   рвёт все мультиплексированные сессии на нём.
3. **Vendoring-trim** (`Cargo.toml`) — убраны dev-dependencies, чтобы
   workspace их не тянул.

## sockudo-ws (1.7.5)

> **Примечание — crate yanked.** `sockudo-ws 1.7.5` снят (yanked) с crates.io
> (скачивание возвращает `403 AccessDenied`), поэтому патч регенерирован
> против GitHub-тега `v1.7.5` после нормализации rustfmt'ом к формату
> публикации крейта — git-дерево отличается лишь whitespace / порядком
> импортов и вырезанными `[[bin]]` / bench-таргетами. Источником истины
> остаётся сама vendored-копия `vendor/sockudo-ws`.

Логические изменения в `sockudo-ws-1.7.5.patch`:

1. **h3-noerror** (`src/server.rs`) — трактует `ApplicationClose: H3_NO_ERROR`
   как нормальное закрытие и подавляет ложные `eprintln!` `HTTP/3 accept
   error` / `HTTP/3 connection error` при чистом shutdown. Также
   восстанавливает `WebSocketServer::into_parts`, нужный серверному
   accept-циклу `outline-ss-rust`.
2. **MIPS-fallback** (`src/pubsub.rs`) — `CounterU64` откатывается на
   `Mutex<u64>` на таргетах без `target_has_atomic = "64"`, чтобы `pubsub`
   собирался на MIPS32 (сборка `release-router`).
3. **fix-h3-poll-write** (`src/http3/stream.rs`,
   `src/stream/transport_stream.rs`) — sockudo-половина poll-write-фикса:
   машины состояний `write_queued` / `shutdown_started`, дёргающие h3-методы
   `queue_send` / `poll_drain` / `queue_grease` / `poll_quic_finish` ровно
   один раз на логическую запись / shutdown.

**`Cargo.toml`** (одна строка, в патч не входит): `tokio-rustls` выставлен в
`default-features = false, features = ["ring", "tls12"]`, чтобы сборка
`release-router` не тянула `aws-lc-sys` — это держит весь workspace на `ring`
(см. инвариант ring-only в корневом `AGENTS.md`).

## Регенерация

Чтобы пересобрать артефакты-патчи после правки vendored-исходников:

- **h3** — сравнить vendored-копию с чистым upstream-checkout'ом: взять
  свежий `h3 0.0.8` с crates.io (например через одноразовый git-baseline) и
  сделать `git diff vendor/h3` по изменённым файлам.
- **sockudo-ws** — нормализовать чистый GitHub-checkout `v1.7.5` rustfmt'ом с
  workspace-овским `rustfmt.toml`, затем сделать diff его `src/` против
  `vendor/sockudo-ws/src`.

Не поднимай upstream-версии и не убирай `[patch.crates-io]` без явной
причины: HTTP/3 WebSocket-путь зависит от этих патчей.
