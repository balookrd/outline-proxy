# outline-proxy

`outline-proxy` — это Cargo workspace (монорепозиторий), в котором живут обе
половины Outline-совместимой прокси-системы на базе Shadowsocks AEAD и VLESS
поверх WebSocket / XHTTP / HTTP/3 / raw QUIC.

- **[`outline-ss-rust`](bins/outline-ss-rust/)** — **серверный** data plane.
  Принимает Shadowsocks AEAD или VLESS поверх WebSocket (HTTP/1.1, RFC 8441 H2,
  RFC 9220 H3), XHTTP и raw QUIC и релеит на произвольные TCP/UDP назначения.
  Multi-user с per-user политиками, Prometheus-метрики, опциональные встроенные
  TLS- и QUIC/H3-listener'ы.
- **[`outline-ws-rust`](bins/outline-ws-rust/)** — **клиент**. Принимает
  локальный SOCKS5 (и опциональный TUN) трафик и отправляет его через
  соответствующие транспорты, с multi-uplink failover, балансировкой нагрузки,
  health-пробами и урезанной **router-сборкой** для устройств с ограниченной
  памятью (MIPS / armv7).

Клиент дайлит сервер; обе стороны говорят на одном wire-протоколе и делят набор
общих крейтов — поэтому они в одном репозитории.

Режим **обратного туннеля** (топология A) инвертирует несущую, чтобы сервер мог
работать за NAT без публичного IP: он сам дозванивается *наружу* к публичному
клиенту, который слушает и маршрутизирует трафик пользователей обратно через
него. См. [docs/REVERSE-TUNNEL.ru.md](docs/REVERSE-TUNNEL.ru.md).

*English version: [README.md](README.md)*

## Структура

```
outline-proxy/
├── bins/
│   ├── outline-ss-rust/   # серверный бинарь  (+ его README, CHANGELOG, docs/)
│   └── outline-ws-rust/   # клиентский бинарь  (+ его README, CHANGELOG, docs/)
├── crates/                # общие крейты (wire-протокол, transport, uplink, tun, crypto, routing, …)
├── vendor/                # пропатченные h3 + sockudo-ws (одна копия, на уровне workspace)
├── .cargo/config.toml     # cross-build алиасы (ss-* / ws-*)
├── .github/workflows/     # CI: per-binary release / nightly / tag пайплайны
├── AGENTS.md              # правила для контрибьюторов + монорепо-инварианты
└── Cargo.toml             # корень workspace: members, профили, [patch.crates-io]
```

Документация по каждому бинарю лежит рядом с ним —
[README сервера](bins/outline-ss-rust/README.md) ·
[README клиента](bins/outline-ws-rust/README.md) — а более детальные материалы
под каждым `bins/*/docs/` (архитектура, session resumption, настройка uplink'ов,
TUN PMTUD).

## Сборка

Оба бинаря — Rust edition 2024.

```bash
# весь workspace
cargo build --release
cargo test --workspace

# один бинарь
cargo build --release -p outline-ss-rust
cargo build --release -p outline-ws-rust

# router-сборка клиента (урезанная, под ограниченную память)
cargo build --profile release-router --no-default-features --features router -p outline-ws-rust

# musl cross-сборки через алиасы cargo-zigbuild (нужны cargo-zigbuild + zig)
cargo ss-release-musl-x86_64
cargo ws-release-router-musl-armv7
```

`rustls` во всём workspace закреплён на провайдере `ring`, а HTTP/3 WebSocket
path зависит от пропатченных `vendor/h3` и `vendor/sockudo-ws`. Полный набор
монорепо-инвариантов — в [`AGENTS.md`](AGENTS.md).

## Релизы

Каждый бинарь версионируется и релизится независимо через префиксные теги:

- `ss-v<x.y.z>` → собирает и публикует **сервер** (workflow *Tag Release (server)*)
- `ws-v<x.y.z>` → собирает и публикует **клиент** (workflow *Tag Release (client)*)

Push'и в `main` публикуют rolling-предрелизы `ss-nightly` / `ws-nightly`
(с path-фильтром — пересобирается только затронутый бинарь). Ручные workflow
*Release (server|client)* поднимают версию в соответствующем `bins/*/Cargo.toml`
и запускают процесс тегирования.

## Лицензия

GPL-3.0 — см. [LICENSE](LICENSE).
