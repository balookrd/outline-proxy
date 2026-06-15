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
  routing, dial. Edition 2024.
- `crates/` — общие крейты. Truly-shared (обе стороны): `outline-wire` —
  wire-protocol примитивы (`CipherKind` + master-key/subkey KDF, `TargetAddr`,
  SS2022-заголовки и UDP-раскладки обеих половин, VLESS/mux-кодек; чистая
  логика, без tokio и без AEAD-backend'ов — AEAD seal/open остаётся по
  сторонам: `ring` на сервере, RustCrypto на клиенте). Ныне в основном
  client-side: `outline-transport`,
  `outline-uplink`, `outline-tun`, `outline-metrics`, `outline-net`,
  `outline-routing`, `shadowsocks-crypto`, `socks5-proto`.
- `vendor/h3`, `vendor/sockudo-ws` — пропатченные крейты, подключены через
  корневой `[patch.crates-io]`. ОДНА копия каждого на весь workspace.

## Команды

Workspace целиком:

```bash
cargo check --workspace
cargo test --workspace
cargo fmt --all          # затрагивает и vendor/* — откатывай format-only diff в vendor
```

Один бинарь / cross-build (через корневые `.cargo` aliases):

```bash
cargo check -p outline-ss-rust
cargo check -p outline-ws-rust
cargo ss-release-musl-x86_64       # zigbuild server, нужен cargo-zigbuild + zig
cargo ws-release-musl-aarch64      # zigbuild client
```

## Монорепо-инварианты (специфичны для слияния)

- **rustls — только `aws-lc-rs`.** Ровно один CryptoProvider в графе: два
  (`ring` + `aws_lc_rs`) ломают `rustls` default-provider (паника
  «exactly one of aws-lc-rs and ring»). Любая зависимость, тянущая rustls
  (`tokio-rustls`, `rcgen`, `quinn`, `tokio-tungstenite`, `sockudo-ws`), должна
  быть на aws-lc-rs: `default-features = false` + явный `aws_lc_rs`
  (`rustls-aws-lc-rs` у quinn). Проверка: `cargo tree -i 'rustls@0.23' -e features
  | grep 'rustls feature "ring"'` — пусто. `ring`-крейт остаётся только для
  SS-AEAD/SHA-256, не как rustls-провайдер. aws-lc-sys требует cmake при сборке.
- **Единый `vendor/`.** `vendor/sockudo-ws` = upstream 1.7.5 + наложенные
  патчи h3-noerror и poll-write (protocol —
  `writer.shutdown()` в WebSocket `close()`: FIN вместо RESET_STREAM, иначе
  `H3_INTERNAL_ERROR` рвёт всё QUIC-соединение; плюс `is_normal_h3_shutdown`).
  Также restored `WebSocketServer::into_parts` (нужен серверному accept-loop).
  Не плоди вторые копии vendored и не поднимай версии без явной причины.
- **Единый профиль.** `[profile.release]` (lto=fat, panic=abort) — только в
  корневом `Cargo.toml`. Package-манифесты в `bins/*` тонкие, без
  `[workspace]`/`[profile]`/`[patch]`.

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

Корневые [`PATCHES.md`](PATCHES.md) / [`PATCHES.ru.md`](PATCHES.ru.md) и
patch-артефакты (`h3-0.0.8.patch`, `sockudo-ws-1.7.5.patch`) — единый источник
истины по отличиям vendored копий от upstream (per-bin `PATCHES.md` —
указатели на корневой). Меняешь поведение vendored — обнови vendored source и
корневую patch-документацию в том же изменении. HTTP/3 WebSocket path зависит
от этих патчей; не удаляй `[patch.crates-io]`.

Production-код не обращается к `h3`-патч-API и `sockudo_ws` напрямую — только
через модули-врата `crates/outline-transport/src/h3/vendored.rs` (клиент) и
`bins/outline-ss-rust/src/server/h3/vendored.rs` (сервер); CI это проверяет
(тесты — исключение). Новые обращения к vendored-API добавляй во врата, а не
в потребителей.
