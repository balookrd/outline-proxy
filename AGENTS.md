# AGENTS.md

## Область действия

Корневой файл монорепо `outline-proxy`. Действует на весь репозиторий. Для
бинарь-специфичных правил дополнительно читай:

- [`bins/outline-ss-rust/AGENTS.md`](bins/outline-ss-rust/AGENTS.md) — server data plane.
- [`bins/outline-ws-rust/AGENTS.md`](bins/outline-ws-rust/AGENTS.md) — client (SOCKS5/TUN ingress).

При конфликте корневые монорепо-правила имеют приоритет над тем, что в
per-bin файлах относится к старой раздельной раскладке репозиториев.

## Что это

`outline-proxy` — единый Cargo workspace, объединивший ранее раздельные
`outline-ss-rust` (сервер) и `outline-ws-rust` (клиент). Они делят общий
wire-protocol (Shadowsocks AEAD / VLESS поверх WebSocket / XHTTP / HTTP3 /
raw QUIC), поэтому живут в одном дереве с общими крейтами и vendored-копиями.

Цель консолидации — убрать дублирование wire-protocol и подготовить
симметричный transport для reverse-tunnel (сервер за NAT звонит наружу,
клиент слушает; топология A). См. план в истории и памяти проекта.

## Структура

- `bins/outline-ss-rust/` — серверный бинарь: listeners, accept, relay, NAT,
  outbound, control/dashboard. Edition 2024.
- `bins/outline-ws-rust/` — клиентский бинарь: SOCKS5/TUN ingress, uplink LB,
  routing, dial. Edition 2024, имеет router-сборку для MIPS/armv7.
- `crates/` — общие крейты. Truly-shared (обе стороны): `outline-wire` —
  wire-protocol примитивы (`CipherKind` + master-key KDF, `TargetAddr`,
  SS2022-заголовки, VLESS/mux-кодек; чистая логика, без tokio и без
  AEAD-backend'ов). Ныне в основном client-side: `outline-transport`,
  `outline-uplink`, `outline-tun`, `outline-metrics`, `outline-net`,
  `outline-routing`, `outline-ss2022`, `shadowsocks-crypto`, `socks5-proto`.
- `vendor/h3`, `vendor/sockudo-ws` — пропатченные крейты, подключены через
  корневой `[patch.crates-io]`. ОДНА копия каждого на весь workspace.

## Команды

Workspace целиком:

```bash
cargo check --workspace
cargo test --workspace
cargo fmt --all          # затрагивает и vendor/* — откатывай format-only diff в vendor
```

Один бинарь / router-сборка / cross-build (через корневые `.cargo` aliases):

```bash
cargo check -p outline-ss-rust
cargo check -p outline-ws-rust
cargo check -p outline-ws-rust --no-default-features --features router
cargo ss-release-musl-x86_64       # zigbuild server, нужен cargo-zigbuild + zig
cargo ws-release-router-musl-armv7 # stripped router build
```

## Монорепо-инварианты (специфичны для слияния)

- **rustls — только `ring`.** Никакого `aws_lc_rs` в графе: два
  CryptoProvider'а ломают `rustls` default-provider (паника
  «exactly one of aws-lc-rs and ring»). Любая зависимость, тянущая rustls
  (`tokio-rustls`, `rcgen`, `quinn`, `tokio-tungstenite`), должна быть на ring:
  `default-features = false` + явный `ring`. Проверка:
  `cargo tree -i aws-lc-rs` должна давать «did not match any packages».
- **Единый `vendor/`.** `vendor/sockudo-ws` = upstream 1.7.5 + два наложенных
  патча: MIPS `AtomicU64`→`Mutex` fallback (router) и h3-noerror (protocol —
  `writer.shutdown()` в WebSocket `close()`: FIN вместо RESET_STREAM, иначе
  `H3_INTERNAL_ERROR` рвёт всё QUIC-соединение; плюс `is_normal_h3_shutdown`).
  Также restored `WebSocketServer::into_parts` (нужен серверному accept-loop).
  Не плоди вторые копии vendored и не поднимай версии без явной причины.
- **Router-изоляция.** `outline-ws-rust --no-default-features --features router`
  НЕ должен тянуть `outline-ss-rust`, `mimalloc`, Prometheus metrics, H3/QUIC,
  `aws-lc-rs`. Проверка: `cargo tree -e features -p outline-ws-rust
  --no-default-features --features router` без этих зависимостей.
- **Единый профиль.** `[profile.release]` (lto=fat, panic=abort) и
  `[profile.release-router]` (opt-level=z) — только в корневом `Cargo.toml`.
  Package-манифесты в `bins/*` тонкие, без `[workspace]`/`[profile]`/`[patch]`.

## Общие рабочие правила

- Начинай с `git status --short`. Не трогай `target/`, `.idea/`, `.claude/`,
  `*.iml` без явной просьбы.
- Общение с владельцем и рассуждения — на русском; имена кода, команды, логи,
  протоколы — на их естественном языке. Git-коммиты, PR и комментарии в коде —
  на английском.
- Тесты держи в подкаталогах `tests/` рядом с модулем (`<dir>/tests/<basename>.rs`),
  без inline `#[cfg(test)] mod tests {}`.
- User-facing документация ведётся в EN и RU параллельно (`*.md` / `*.ru.md`) —
  обновляй обе стороны в одном изменении.
- Не логируй secrets/PSK/UUID/tokens; держи metrics labels low-cardinality.
- `cargo fmt` использует общий `rustfmt.toml` (100 колонок). Не форматируй
  `vendor/*` без явной цели.

## Протокольные guardrails (критично — не регрессировать)

- **H3-keepalive.** На H3-carrier НЕ слать server→client WS `Ping` и не делать
  pong-deadline reaping: клиентские keepalive проглатываются split-reader'ом,
  живость держит QUIC keep-alive, а reactive Pong доставляется таймерным
  `WsSocket::flush`. Подробности — в `bins/outline-ss-rust/AGENTS.md` и
  `bins/outline-ws-rust/AGENTS.md` (SS-UDP/TCP/VLESS-over-WS, H3-aware).
- **Bounded resources.** UDP/NAT/session/resumption и любые новые
  долгоживущие socket/task/buffer должны иметь явный лимит/eviction/
  cancellation/shutdown.
- **Transport fallback / resume.** Сохраняй `h3→h2→http1`, `xhttp_h3→h2→h1`,
  per-uplink fallback wires и cross-transport resume (`X-Outline-Resume*`),
  если задача явно не нацелена на них.

## Vendored patches

Корневые patch-файлы и `PATCHES.md` в `bins/*` документируют отличия vendored
копий от upstream. Меняешь поведение vendored — обнови vendored source и
patch-документацию в том же изменении. HTTP/3 WebSocket path зависит от этих
патчей; не удаляй `[patch.crates-io]`.
