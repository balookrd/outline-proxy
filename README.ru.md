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

## Поддерживаемые протоколы и транспорты

Две независимые оси: **протокол полезной нагрузки (payload)** — что едет внутри —
и **транспорт-носитель (carrier)** — как он доставляется. Клиент и сервер
согласуют пару из обоих на каждый uplink.

| Payload \ Carrier | WebSocket (h1/h2/h3) | XHTTP (h1/h2/h3) | raw QUIC |
|---|:---:|:---:|:---:|
| **Shadowsocks** (AEAD / SS2022) | ✅ | — | ✅ |
| **VLESS** | ✅ | ✅ | ✅ |

XHTTP — это VLESS-only протокол `packet-up` / `stream-one`; у Shadowsocks
XHTTP-носителя нет. Все остальные ячейки поддерживаются в обе стороны.

Клиент выбирает пару `transport` + `mode` на каждый uplink:

| `transport` | допустимые значения `*_mode` | поле URL для dial |
|---|---|---|
| `ss` (алиас `shadowsocks`; deprecated `ws` / `websocket`) | `ws_h1` · `ws_h2` · `ws_h3` · `quic` | `tcp_ws_url` / `udp_ws_url` |
| `vless` | `ws_h1` · `ws_h2` · `ws_h3` · `quic` · `xhttp_h1` · `xhttp_h2` · `xhttp_h3` | `vless_ws_url` (ws / quic) · `vless_xhttp_url` (xhttp) |

Алиасы носителей: `h1` / `http1` → `ws_h1`, `h2` → `ws_h2`, `h3` → `ws_h3`.

**Носители (carrier)**

- **WebSocket h1 / h2 / h3** — RFC 6455, RFC 8441 (H2 Extended CONNECT), RFC 9220
  (H3 Extended CONNECT). Базовый путь для обоих payload'ов.
- **XHTTP** (только VLESS) — два sub-режима: `packet-up` (каждый пакет — отдельный
  запрос, работает на h1 / h2 / h3) и `stream-one` (один bidi-POST, нужен
  мультиплекс — только h2 / h3; на h1 сервер отдаёт 505).
- **raw QUIC** — без WebSocket / HTTP-обёртки, ALPN `outline-quic`. Несёт и
  Shadowsocks, и VLESS. TCP-подобные сессии едут по свежему bidi-стриму,
  UDP-подобные — по QUIC-датаграммам (RFC 9221). Требует feature `quic` при сборке.

**Автоматический fallback** (per-uplink, в том числе mid-session): WebSocket
деградирует `h3 → h2 → h1`, XHTTP — `xhttp_h3 → xhttp_h2 → xhttp_h1`, а raw QUIC
при неудаче dial'а откатывается на WebSocket-over-H2.

> **Совместимость с Outline:** Shadowsocks-over-WebSocket — это путь, на котором
> говорят приложения Outline: сервер выдаёт для него Outline-ключ доступа
> (`$type: websocket`, TCP + UDP). Shadowsocks-over-QUIC — standalone-режим
> только для встроенного клиента `outline-ws-rust`, наружу как Outline-ключ не
> отдаётся. VLESS отдаётся как share-link `vless://…` (`ws` / `xhttp` / `quic`).

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
