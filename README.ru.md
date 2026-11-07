<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/logo-dark.png">
    <img src="docs/logo-light.png" alt="outline-proxy logo" width="100%">
  </picture>
</p>

# outline-proxy

`outline-proxy` — Cargo workspace (монорепозиторий) с Outline-совместимым
прокси на базе Shadowsocks AEAD и VLESS поверх WebSocket / XHTTP / HTTP/3. В нём
сервер, клиент, агрегирующий dashboard-UI, Android-VPN-клиент и клиент для
строки меню macOS.

- [`outline-ss-rust`](bins/outline-ss-rust/) — серверный data plane.
  Принимает Shadowsocks AEAD или VLESS поверх WebSocket (HTTP/1.1, RFC 8441 H2,
  RFC 9220 H3) и XHTTP и релеит на произвольные TCP/UDP-назначения. У каждого
  пользователя свои `method`, `fwmark`, флаг `enabled` и IP-`aliases`; сервер
  отдаёт Prometheus-метрики, умеет встроенные TLS- и QUIC/H3-listener'ы и
  mesh-кластер между узлами.
- [`outline-ws-rust`](bins/outline-ws-rust/) — клиент. Принимает локальный
  SOCKS5 (и, опционально, TUN) трафик и отправляет его через те же носители, с
  multi-uplink failover, балансировкой нагрузки и health-пробами.
- [`outline-ui`](bins/outline-ui/) — отдаёт оба дашборда, серверный и
  клиентский, из одного бинаря (`/ss` и `/ws`). Своего data plane нет, он только
  опрашивает control API каждого узла.
- [`android/`](android/) — Android-VPN-клиент. Запускает uplink-стек
  `outline-ws-rust` без изменений под слоем `VpnService` + Compose-UI.
- [`macos/`](macos/) — клиент для строки меню macOS. Переключает режимы SOCKS5
  (системный прокси без root) и TUN (L3 VPN через ядровый интерфейс `utun`),
  управляет профилями серверов и показывает журнал; платный аккаунт Apple
  Developer не нужен. Universal DMG собирают `./macos/scripts/package-dmg.sh` и
  GitHub Actions.

Клиент дозванивается до сервера; обе стороны говорят на одном wire-протоколе и
делят набор общих крейтов, поэтому они в одном репозитории.

*English version: [README.md](README.md)*

## Поддерживаемые протоколы и транспорты

Осей две, и они независимы: протокол полезной нагрузки (payload) — что едет
внутри — и носитель (carrier) — как он доставляется. Клиент и сервер
договариваются об одной паре на каждый uplink.

| Payload \ Carrier | WebSocket (h1/h2/h3) | XHTTP (h1/h2/h3) |
|---|:---:|:---:|
| Shadowsocks (AEAD / SS2022) | да | да |
| VLESS | да | да |

XHTTP — протокол `packet-up` / `stream-one`. VLESS ходит по нему для TCP + UDP
на одном пути; Shadowsocks — на forward-пути (client→server) и для TCP, и для
UDP. По умолчанию TCP и UDP идут через раздельные серверные эндпоинты
(`[[endpoint]] kind = "xhttp_ss_tcp"` / `"xhttp_ss_udp"`, то же разделение, что
`ws_ss_tcp` / `ws_ss_udp` у WebSocket). Опционально их можно свести на один
общий эндпоинт (серверный `kind = "xhttp_ss"`, клиентские `ss_xhttp_url` +
`ss_mode`); тогда разделение TCP/UDP несёт скрытый дискриминатор в session id, и
цензор видит один эндпоинт вместо двух. У WebSocket есть тот же combined-вариант
(серверный `kind = "ws_ss"`, клиентский `ss_ws_url`). Все остальные ячейки
поддерживаются в обе стороны.

Клиент выбирает пару `transport` + `mode` на каждый uplink:

| `transport` | режим | допустимые значения `*_mode` | поле URL для dial |
|---|---|---|---|
| `ss` (алиас `shadowsocks`; deprecated `ws` / `websocket`) | split | `ws_h1` · `ws_h2` · `ws_h3` · `xhttp_h1` · `xhttp_h2` · `xhttp_h3` | `tcp_ws_url` / `udp_ws_url` (ws) · `tcp_xhttp_url` / `udp_xhttp_url` (xhttp) |
| `ss` | combined | `ws_h1` · `ws_h2` · `ws_h3` · `xhttp_h1` · `xhttp_h2` · `xhttp_h3` | `ss_ws_url` или `ss_xhttp_url` + `ss_mode` |
| `vless` | — | `ws_h1` · `ws_h2` · `ws_h3` · `xhttp_h1` · `xhttp_h2` · `xhttp_h3` | `vless_ws_url` (ws) · `vless_xhttp_url` (xhttp) |

Алиасы режимов: `h1` / `http1` → `ws_h1`, `h2` → `ws_h2`, `h3` → `ws_h3`.

### Носители

- WebSocket h1 / h2 / h3: RFC 6455, RFC 8441 (H2 Extended CONNECT), RFC 9220
  (H3 Extended CONNECT). Несёт оба payload'а.
- У XHTTP два sub-режима: `packet-up` (каждый пакет — отдельный запрос, работает
  на h1 / h2 / h3) и `stream-one` (один двунаправленный POST; нужен
  мультиплекс, поэтому только h2 / h3, на h1 сервер отвечает 505). Несёт VLESS
  (TCP + UDP) и Shadowsocks (forward-путь TCP + UDP).

Автоматический fallback работает per-uplink, в том числе посреди сессии:
WebSocket спускается `h3 → h2 → h1`, XHTTP — `xhttp_h3 → xhttp_h2 → xhttp_h1`.

### Совместимость с Outline

Shadowsocks поверх WebSocket — путь, на котором говорят приложения Outline.
Генератор ключей [`ops/access-keys`](ops/access-keys/) выдаёт пользователю
Outline-ключ доступа (`$type: websocket`, TCP + UDP), если на сервере есть пара
раздельных эндпоинтов `ws_ss_tcp` / `ws_ss_udp`. Shadowsocks поверх XHTTP
работает только со встроенным клиентом `outline-ws-rust`, Outline-ключа для
него нет; вместо этого на каждый combined-эндпоинт (`ws_ss` / `xhttp_ss`)
генератор выдаёт share-link `ss://…` (SIP002 userinfo) для этого клиента.
VLESS-эндпоинты (`ws_vless` / `xhttp_vless`) получают share-link `vless://…`.

## Структура

```
outline-proxy/
├── bins/
│   ├── outline-ss-rust/   # серверный бинарь  (+ его README, CHANGELOG, docs/)
│   ├── outline-ws-rust/   # клиентский бинарь  (+ его README, CHANGELOG, docs/)
│   └── outline-ui/        # агрегирующий dashboard-UI (+ его README)
├── android/               # Android-VPN-клиент (отдельный workspace: Rust-ядро + Gradle/Kotlin-приложение)
├── macos/                 # клиент для строки меню macOS (Swift/AppKit)
├── crates/                # общие крейты (wire-протокол, transport, uplink, tun, crypto, routing, …)
├── vendor/                # пропатченные h3, sockudo-ws, quinn-proto, rustls, hyper (одна копия, на уровне workspace)
├── .cargo/config.toml     # cross-build алиасы (ss-* / ws-* / ui-*)
├── .github/workflows/     # CI: lint/test-гейт, release / nightly / tag пайплайны по компонентам
├── AGENTS.md              # правила для контрибьюторов + монорепо-инварианты
├── PATCHES.md             # что меняет каждый vendored-крейт относительно upstream
└── Cargo.toml             # корень workspace: members, профили, [patch.crates-io]
```

Документация по каждому компоненту лежит рядом с ним:
[README сервера](bins/outline-ss-rust/README.ru.md) ·
[README клиента](bins/outline-ws-rust/README.ru.md) ·
[README dashboard-UI](bins/outline-ui/README.ru.md) ·
[README Android-клиента](android/README.ru.md) ·
[README клиента macOS](macos/README.ru.md). Подробности — в `bins/*/docs/`:
архитектура сервера и session resumption, конфигурации uplink'ов клиента, TUN
PMTUD и TUN GSO.

Сквозные темы в [`docs/`](docs/):
[carrier-padding](docs/PADDING.ru.md) ·
[фрейминг записей SS-UDP поверх XHTTP](docs/XHTTP-UDP-RECORDS.ru.md) ·
[выбор исходящего IPv6](docs/OUTBOUND-IPV6.ru.md) ·
[mesh-кластер серверов](docs/CLUSTER.ru.md) ·
[развёртывание кластера](docs/CLUSTER-DEPLOY.ru.md).

[`scripts/code-index.py`](scripts/code-index.py) генерирует локальную
структурную карту workspace (пакеты, файлы, верхнеуровневые элементы);
использование описано в [`docs/CODE-INDEX.ru.md`](docs/CODE-INDEX.ru.md).

## Сборка

Оба бинаря — Rust edition 2024.

```bash
# весь workspace
cargo build --release
cargo test --workspace --exclude sockudo-ws

# один бинарь
cargo build --release -p outline-ss-rust
cargo build --release -p outline-ws-rust

# musl cross-сборки через алиасы cargo-zigbuild (нужны cargo-zigbuild + zig)
cargo ss-release-musl-x86_64
cargo ws-release-musl-aarch64
cargo ui-release-musl-aarch64
```

`sockudo-ws` — явный member workspace, поэтому голый `--workspace` его
захватывает; CI его исключает, команда тестов выше тоже.

`rustls` во всём workspace использует провайдер `aws-lc-rs`. HTTP/3
WebSocket-путь зависит от пропатченных `vendor/h3` и `vendor/sockudo-ws`; патчи
всех пяти vendored-крейтов описаны в [`PATCHES.ru.md`](PATCHES.ru.md).
Монорепо-инварианты и точные команды CI-гейта — в [`AGENTS.md`](AGENTS.md).

Android-клиент живёт в [`android/`](android/) как отдельный Cargo workspace
(корневой `cargo build --workspace` его не видит) плюс Gradle/Kotlin-приложение;
собирается оттуда, см. [его README](android/README.ru.md).

## Релизы

Каждый компонент версионируется и релизится независимо через префиксные теги:

| Тег | Что собирает и публикует | Workflow |
|---|---|---|
| `ss-v<x.y.z>` | сервер | *Tag Release (server)* |
| `ws-v<x.y.z>` | клиент | *Tag Release (client)* |
| `ui-v<x.y.z>` | dashboard-UI | *Tag Release (ui)* |
| `android-v<x.y.z>` | Android-приложение | *Tag Release (android)* |
| `macos-v<x.y.z>` | приложение macOS | *Tag Release (macos)* |

Push'и в `main` публикуют скользящие предрелизы `ss-nightly` / `ws-nightly` /
`ui-nightly` / `android-nightly` / `macos-nightly`. У каждого nightly-workflow
есть path-фильтр, поэтому пересобирается только затронутый компонент; фильтры
Android и macOS дополнительно покрывают клиент, общие и vendored-крейты, которые
линкует их нативный код.

Ручные workflow *Release (server|client|ui|android|macos)* принимают серию
`MAJOR.MINOR`, вычисляют следующую patch-версию по существующим тегам,
записывают её в файл версии компонента (`bins/*/Cargo.toml` для трёх бинарей,
`android/rust/Cargo.toml` для Android, `macos/Resources/Info.plist` для macOS),
пушат в `main` коммит `release: cut <tag>` и печатают команду `git tag -s <tag>`
для локального запуска. Push этого подписанного тега запускает соответствующий
*Tag Release*.

### Установка Android-приложения

Приложения нет ни в одном сторе. К каждому релизу на GitHub приложен
подписанный APK (`outline-proxy-<версия>-arm64-v8a.apk`, а на скользящем теге —
`outline-proxy-nightly-<sha>-arm64-v8a.apk`): скачайте его и откройте, чтобы
установить. Установленная сборка умеет обновляться: тап по метке версии внизу
главного экрана проверяет тот канал, из которого она собрана, качает APK в
«Загрузки» и передаёт его системному установщику. Само приложение ничего не
устанавливает, поэтому разрешения на установку не запрашивает.

## Лицензия

GPL-3.0, см. [LICENSE](LICENSE).
