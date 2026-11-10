<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/logo-dark.png">
    <img src="docs/logo-light.png" alt="outline-proxy logo" width="100%">
  </picture>
</p>

# outline-ws-rust

`outline-ws-rust` — клиентский бинарь монорепо `outline-proxy`. Он принимает локальный SOCKS5-трафик и, опционально, пакеты с существующего TUN-устройства и отправляет их на сервер `outline-ss-rust` (или другой Outline-совместимый / VLESS-сервер) по WebSocket поверх HTTP/1.1, HTTP/2 или HTTP/3 либо по XHTTP поверх тех же трёх версий HTTP.

Документ описывает сборку, настройку и запуск клиента на Linux. Серверная сторона описана в [`bins/outline-ss-rust/README.ru.md`](../outline-ss-rust/README.ru.md), справочник по формам аплинков — [docs/UPLINK-CONFIGURATIONS.ru.md](docs/UPLINK-CONFIGURATIONS.ru.md).

Поддерживает:

- SOCKS5 `CONNECT`
- SOCKS5 `UDP ASSOCIATE` и `hev-socks5` `UDP-in-TCP` (`CMD=0x05`)
- несколько аплинков с failover и балансировкой
- WebSocket поверх HTTP/1.1, RFC 8441 (`ws-over-h2`) и RFC 9220 (`ws-over-h3`)
- XHTTP (`xhttp_h1` / `xhttp_h2` / `xhttp_h3`) для Shadowsocks и VLESS
- VLESS-аплинки (UUID-аутентификация, per-destination UDP session-mux)
- конфигурацию аплинка одной строкой из share-link URI `vless://…` или `ss://…` (TOML `link = "..."`, CLI `--vless-link`, поле `link` в control-plane payload)
- метрики Prometheus и дашборды Grafana; multi-instance UI оператора — отдельный сервис `outline-ui`
- существующее TUN-устройство: `tun2udp` и userspace-реле `tun2tcp`

---

*English version: [README.md](README.md)*

## Что делает процесс

1. Принимает локальный SOCKS5 и опциональный TUN-трафик.
2. Выбирает аплинк по health-пробам, EWMA RTT, sticky-маршрутизации, гистерезису, штрафам за сбои и warm standby.
3. Дозванивается до аплинка в заданном режиме носителя (`ws_h1` / `ws_h2` / `ws_h3` или `xhttp_h1` / `xhttp_h2` / `xhttp_h3`) и при неудаче дозвона откатывается на более старую версию HTTP.
4. Шифрует payload через Shadowsocks AEAD или формирует VLESS-кадры с UUID-аутентификацией перед отправкой в upstream.
5. Экспортирует метрики Prometheus по runtime, аплинкам, пробам, TUN и `tun2tcp`.

## Архитектура

```mermaid
flowchart LR
    subgraph LocalHost["Локальный хост"]
        C["SOCKS5-клиенты"]
        T["Существующий TUN"]
        P["outline-ws-rust"]
        M["/metrics endpoint"]
        C --> P
        T --> P
        P --> M
    end

    subgraph Runtime["Proxy runtime"]
        S["SOCKS5 TCP + UDP handlers"]
        U["Uplink manager"]
        LB["Скоринг и маршрутизация
EWMA RTT + weight + penalty
sticky + hysteresis"]
        WS["WS transport connectors
HTTP/1.1 / HTTP/2 / HTTP/3"]
        SS["Shadowsocks AEAD"]
        VL["VLESS framing
UUID auth"]
        TT["TUN engines
tun2udp + tun2tcp"]
    end

    P --> S
    P --> TT
    S --> U
    TT --> U
    U --> LB
    LB -->|"*_ws_mode = http1/h2/h3"| WS
    WS -->|"outline"| SS
    WS -->|"vless"| VL

    subgraph Upstream["Upstream аплинки"]
        O1["outline-over-ws (A/B)"]
        O4["vless-over-ws edge"]
    end

    SS --> O1
    VL --> O4

    subgraph Observability["Observability"]
        PR["Prometheus"]
        GD["Grafana dashboards"]
        AL["Alert rules"]
    end

    M --> PR
    PR --> GD
    PR --> AL
```

## Поддерживаемые возможности

### SOCKS5

- SOCKS5 без аутентификации
- опциональная аутентификация по логину и паролю (RFC 1929)
- TCP `CONNECT`
- UDP `ASSOCIATE`
- `hev-socks5` `FWD UDP` / `UDP-in-TCP` (`CMD=0x05`)
- pipelined SOCKS5-handshake из `hev-socks5-tunnel`
- сборка фрагментированных SOCKS5 UDP-датаграмм от клиента
- цели IPv4, IPv6 и доменные имена
- policy routing по CIDR назначения или доменному суффиксу: списки из файлов с перечитыванием по mtime, fallback на правило (`fallback_via` / `fallback_direct` / `fallback_drop`) и встроенные цели `direct` и `drop`
- байпасс туннеля на уровне группы (`bypass_when_down` у группы аплинков): пока в группе нет здорового аплинка, трафик в неё идёт `direct` вместо отказа и возвращается в туннель, как только любой аплинк восстановится

### Outline-транспорты

- `ws://` и `wss://`
- HTTP/1.1 Upgrade
- RFC 8441 WebSocket over HTTP/2
- RFC 9220 WebSocket over HTTP/3 / QUIC
- XHTTP (`xhttp_h1` / `xhttp_h2` / `xhttp_h3`) для SS (`tcp_xhttp_url` / `udp_xhttp_url`) и VLESS (`vless_xhttp_url`); парные эндпоинты — XHTTP-эндпоинты outline-ss-rust. Подрежим выбирает query-строка URL дозвона: голый URL или `?mode=packet-up` — GET плюс последовательные POST'ы, `?mode=stream-one` — один двунаправленный POST (только h2 / h3; h1-носитель поддерживает только packet-up и на stream-one завершается ошибкой). Используйте, когда WebSocket Upgrade режется на пути (CDN, captive-portal middlebox'ы).
- VLESS-аплинки (`transport = "vless"`, UUID-аутентификация, per-destination UDP session-mux с лимитом `vless_udp_max_sessions`)
- fallback носителя при неудаче дозвона:
  - `ws_h3 -> ws_h2 -> ws_h1`
  - `ws_h2 -> ws_h1`
  - `xhttp_h3 -> xhttp_h2 -> xhttp_h1` (только packet-up; stream-one останавливается на h2). Через каждую смену носителя переносится тот же токен `X-Outline-Resume`, поэтому сервер outline-ss-rust с включённым возобновлением сессий подхватывает запаркованный upstream вместо нового. Шаг h1 — для путей, режущих и QUIC, и ALPN h2; он открывает два keep-alive сокета на сессию (долгоживущий GET + сериализованные POST'ы), потому что h1 не мультиплексирует.
  - fallback-wire'ы на аплинк через `[[outline.uplinks.fallbacks]]`: аплинк может объявить дополнительные wire-формы (другой `transport` + URL), которые dial-цикл пробует после провала primary на этом аплинке, например `vless → ss` или `ss → vless`. После `probe.min_failures` подряд проваленных дозвонов активный wire остаётся на fallback на `mode_downgrade_secs`, и новые сессии стартуют с него; по истечении пина сессии возвращаются на primary. Resume-токены (`X-Outline-Resume`) переживают смену wire через identity-level resume-cache, поэтому сервер с включённым возобновлением подхватывает upstream и при переходе `vless ↔ ss`. Цикл chunk-0 failover пробует все остальные wire'ы того же аплинка, прежде чем перейти на другой аплинк. `shuffle_wires = true` перемешивает цепочку при старте процесса (перестановки без совпадений внутри `[[uplink_group]]`) и передаёт управление uplink-failover'у после одного полного прохода без успешного wire (любой успешный wire сбрасывает проход); `shuffle_timer = "1h"` перевыбирает `active_wire` с заданным интервалом (`30s` / `5m` / `1h30m` / `2d` / голые секунды) и подавляет probe-driven ранний возврат на primary, чтобы перевыбор действовал. `carrier_downgrade = false` отключает каскад носителей внутри wire: сбой сразу переводит на следующий wire (против DPI, который режет upstream независимо от версии HTTP). См. «Внутри-аплинковые fallback-транспорты» в [docs/UPLINK-CONFIGURATIONS.ru.md](docs/UPLINK-CONFIGURATIONS.ru.md).
- клиентское возобновление сессии между носителями: WebSocket Upgrade несёт `X-Outline-Resume-Capable: 1`; Session ID из ответа сервера (`X-Outline-Session`) кэшируется по аплинку (а внутри VLESS UDP mux — по паре (uplink, target)) и предъявляется как `X-Outline-Resume: <hex>` при следующем дозвоне, так что сервер outline-ss-rust с включённым возобновлением подхватывает запаркованный upstream и пропускает connect к цели. Покрытие: TCP поверх WS, SS-UDP поверх WS и VLESS поверх XHTTP (h1 / h2 / h3, packet-up и stream-one; токен возвращается в том ответе, что несёт первый downlink-чанк). Сервер без возобновления игнорирует заголовок, остальной wire не меняется.

### Шифрование

- `chacha20-ietf-poly1305`
- `aes-128-gcm`
- `aes-256-gcm`
- `2022-blake3-aes-128-gcm`
- `2022-blake3-aes-256-gcm`
- `2022-blake3-chacha20-poly1305`

### Управление аплинками

- несколько аплинков в группе
- режим выбора:
  - `active_active`: новые флоу могут идти через разные аплинки в зависимости от скора, sticky и failover
  - `active_passive`: держать выбранный аплинк, пока он не станет нездоровым или не уйдёт в cooldown. Когда ручное переключение через control plane или probe-driven failover уводит активный аплинк с идущей SOCKS5-сессии, эта TCP-сессия закрывается RST'ом (`SO_LINGER {l_onoff=1, l_linger=0}`), чтобы клиент переподключился через новый активный аплинк, а не выходил через ставший пассивным (другой source IP / ASN). UDP downlink-цикл просыпается от того же watch'а `subscribe_active_uplinks`. Счётчик: `outline_ws_socks_tcp_strict_aborts_total`. `active_active` это не затрагивает.
- область маршрутизации:
  - `per_flow`: решение принимается отдельно для каждого ключа маршрутизации / цели
  - `per_uplink`: один активный аплинк на транспорт (`tcp` и `udp`) на весь процесс. В `active_passive` закреплённые TCP и UDP аплинки не истекают по `sticky_ttl`; установленные SOCKS TCP-туннели остаются на аплинке, который завершил setup, а немигрируемые флоу, зависящие от старого активного аплинка, после переключения могут быть перевыбраны или закрыты. История штрафов в строгий per-transport скор не входит.
  - `per_client`: каждый входящий клиент закрепляется за одним выбранным балансировщиком аплинком по своему source IP (peer IP SOCKS5 или IP LAN-устройства за TUN-роутером) на `sticky_ttl`, с продлением, пока клиент активен. Разные клиенты распределяются по аплинкам, один клиент держит один выходной IP, с failover при деградации закреплённого аплинка. Только `active_active` — в `active_passive` ведёт себя как `per_flow`. Клиенты без определимого source IP делят один ключ.
  - `global`: один активный аплинк для всего нового трафика процесса, TCP и UDP. Ранжирование идёт по TCP-скору, но UDP-способный активный аплинк считается упавшим и тогда, когда UDP-проба помечает его нездоровым или действует его UDP runtime cooldown. Активный глобальный аплинк не истекает по `sticky_ttl`, история штрафов в строгий глобальный скор не входит, а TUN-флоу, оставшиеся на старом аплинке после глобального переключения, закрываются и переподключаются через новый.
- статический `weight` на аплинк
- EWMA RTT-скоринг
- штрафы за сбои с экспоненциальным затуханием
- sticky-маршрутизация с TTL
- гистерезис против переключений на малой разнице скоров
- runtime failover
- `auto_failback = false` по умолчанию: активный аплинк меняется только при сбое и сам на восстановившийся primary не возвращается
- warm-standby WebSocket-пулы для TCP и UDP
- сохранение выбора активного аплинка между рестартами (TOML state-файл, debounced async-запись)
- плановый взвешенный перевыбор строгого активного аплинка (только `active_passive`): слоты по часам `reselect_at` или фиксированный `reselect_interval`; ротация всегда исключает текущий активный и взвешивает кандидатов по здоровью/штрафу, как `health_weighted_selection`; `POST /control/reselect` запускает её вручную. См. «Плановый перевыбор» в [docs/UPLINK-CONFIGURATIONS.ru.md](docs/UPLINK-CONFIGURATIONS.ru.md).
- детерминированный вариант этой ротации (`reselect_sync = true`, требует `reselect_at`): порядок слота выводится из имени группы, имён аплинков, локального дня и индекса слота вместо случайного розыгрыша, поэтому независимые узлы с одинаковым конфигом группы выбирают один и тот же аплинк — один выходной адрес для клиентов, попадающих на любой из них, — без обмена сообщениями.

### Health-пробы

- WebSocket connectivity-пробы (handshake TCP + TLS + WS; без ping/pong — серверы редко отвечают на WebSocket ping control frames)
- HTTP-пробы через `websocket-stream`
- DNS-пробы через `websocket-packet`
- TLS-handshake-пробы к заданному SNI через туннель; ловят upstream-фильтрацию, которая молча режет `ServerHello` для отдельных SNI, — обычная HTTP-проба этого не видит
- ограничение параллельности проб
- отдельный лимит дозвонов для проб
- немедленное пробуждение пробы при runtime-сбое (не чаще раза в 15 с на аплинк)
- счётчик успехов подряд, по которому разрешается auto-failback

### TUN

- только существующее TUN-устройство (процесс его не создаёт)
- `tun2udp` с управлением жизненным циклом флоу, сборкой IPv4/IPv6-фрагментов и локальными ICMP echo reply
- userspace-реле `tun2tcp` с ретрансмитом, zero-window persist/backoff, SACK-aware приёмом и отправкой, adaptive RTO и ограниченными буферами

### Эксплуатация

- метрики Prometheus
- дашборды Grafana в [`grafana/`](grafana)
- контроль срока TLS-сертификатов аплинков: gauge `outline_ws_uplink_cert_expiry_timestamp_seconds` и поле `cert_not_after_unix_ms` у каждого аплинка в `GET /control/topology`
- systemd-юниты с песочницей (см. [systemd](#systemd))
- Linux `fwmark` / `SO_MARK`
- IPv6 для слушателей, upstream'ов, проб и SOCKS5-целей

## Текущие ограничения

- `tun2tcp` — userspace TCP-реле, не эквивалент ядерного TCP-стека.
- Не-echo ICMP на TUN не поддерживается.
- `probe.http` поддерживает только `http://`. Для HTTPS используйте `[outline.probe.tls]`: он выполняет TLS handshake (без HTTP-обмена) к заданному SNI. `probe.tcp` должен указывать на сервис, который первым отправляет данные (SSH, SMTP), а не на HTTP/HTTPS-порт.
- TCP failover на другой аплинк возможен только до начала полезного обмена. Установленный TCP-туннель между аплинками не переносится; миграция носителя в TUN (см. [Миграция носителя](#миграция-носителя-переживаем-смерть-носителя)) перезванивает в тот же аплинк.

## Структура репозитория

Пути указаны относительно `bins/outline-ws-rust/`; общие крейты лежат в корне workspace.

- [`config.toml`](config.toml) — пример конфигурации
- [`systemd/outline-ws-rust.service`](systemd/outline-ws-rust.service), [`systemd/outline-ws-rust@.service`](systemd/outline-ws-rust@.service) — systemd-юниты
- [`grafana/outline-ws-rust-dashboard.json`](grafana/outline-ws-rust-dashboard.json) — основной операционный дашборд
- [`grafana/outline-ws-rust-hang-diagnostics.json`](grafana/outline-ws-rust-hang-diagnostics.json) — диагностика зависаний
- [`src/bootstrap/`](src/bootstrap) — запуск: bind слушателей и хранилище состояния
- [`src/config/`](src/config) — схема CLI и конфига, загрузка, валидация
- [`src/proxy/`](src/proxy) — SOCKS5 TCP/UDP ingress (диспетчер, TCP failover, UDP-реле)
- [`src/http/`](src/http) — эндпоинт метрик и control plane
- [`../../crates/outline-uplink/`](../../crates/outline-uplink) — выбор аплинка, пробы, failover, standby-пулы
- [`../../crates/outline-transport/`](../../crates/outline-transport) — транспорты WebSocket / HTTP/2 / HTTP/3 / XHTTP / VLESS и кросс-транспортный `ResumeCache`
- [`../../crates/outline-net/`](../../crates/outline-net) — DNS-кэш и сокетные хелперы (fwmark, keepalive, размеры буферов)
- [`../../crates/outline-tun/`](../../crates/outline-tun) — TUN-движки (TCP и UDP)
- [`../../crates/shadowsocks-crypto/`](../../crates/shadowsocks-crypto) — хелперы Shadowsocks AEAD
- [`../../crates/outline-wire/`](../../crates/outline-wire) — общий с сервером wire-кодек (`CipherKind`, `TargetAddr`, SS2022-заголовки, VLESS/mux)
- [`../../crates/outline-metrics/`](../../crates/outline-metrics) — регистрация Prometheus-метрик и session/transport snapshots
- [`../../crates/outline-routing/`](../../crates/outline-routing) — таблица маршрутизации по CIDR и доменам
- [`../../crates/socks5-proto/`](../../crates/socks5-proto) — примитивы протокола SOCKS5
- [`../../PATCHES.ru.md`](../../PATCHES.ru.md) — реестр патчей vendored-крейтов (один на весь workspace)

## Сборка

Все команды ниже выполняйте из корня workspace (`outline-proxy/`).

### Требования

- Rust toolchain (stable): `rustup update stable`
- для кросс-компиляции: [`cargo-zigbuild`](https://github.com/rust-cross/cargo-zigbuild) и Zig; zigbuild использует C-компилятор Zig как линкер, отдельный cross-toolchain под каждую платформу не нужен.

```bash
cargo install cargo-zigbuild
```

Установите Rust-таргеты:

```bash
rustup target add x86_64-unknown-linux-musl
rustup target add aarch64-unknown-linux-musl
```

Алиасы из корневого `.cargo/config.toml`:

```bash
cargo ws-release-musl-x86_64
cargo ws-release-musl-aarch64
```

### CI-релизы

Workflow'ы клиента — `.github/workflows/ws-*.yml`; теги клиента имеют префикс `ws-`.

- Push в `main`, затрагивающий `bins/outline-ws-rust/**`, `crates/**`, `vendor/**`, `Cargo.toml`, `Cargo.lock` или `.cargo/**`, запускает `Nightly Release (client)`. Он переносит rolling-тег `ws-nightly` на этот коммит и заново публикует prerelease `Client Nightly`.
- Nightly публикует `release`-сборки для `x86_64-unknown-linux-musl` и `aarch64-unknown-linux-musl` и `SHA256SUMS.txt`. Архивы называются `outline-ws-rust-nightly-<full-commit-sha>-<target>.tar.gz`.
- Для стабильного релиза запустите вручную workflow `Release (client)` с `major_minor`, например `1.7`. CI находит последний тег `ws-v1.7.*`, увеличивает patch, обновляет `Cargo.toml` и `Cargo.lock`, создаёт release-коммит и пушит его в `main`.
- После появления release-коммита в `main` создайте и отправьте подписанный тег локально (`git tag -s ws-vX.Y.Z -m ws-vX.Y.Z`). Push тега запускает `Tag Release (client)`, который собирает и публикует GitHub Release с теми же двумя таргетами.
- Ручной push тега `ws-v*` тоже запускает `Tag Release (client)`.

### Feature flags

| Фича | По умолчанию | Что делает |
|---|---|---|
| `h3` | да | HTTP/3-носители (`ws_h3`, `xhttp_h3`): quinn + sockudo-ws/http3 |
| `metrics` | да | эндпоинт Prometheus `/metrics` и метрики транспортного уровня (prometheus + serde_json) |
| `control` | да | аутентифицированный control-plane listener (`[control]`) |
| `socks5` | да | SOCKS5 ingress (`src/proxy`); в Android-сборке выключен |
| `tun` | да | TUN-движки (`tun2udp` + `tun2tcp`) |
| `jemalloc` | да | аллокатор jemalloc; метрики кучи отдают `heap_mode="exact"`, `GET /control/alloc` возвращает статистику аллокатора |
| `env-filter` | да | разбор `RUST_LOG`; без неё уровень логов зафиксирован на `WARN` (экономия ~300 КБ на MIPS) |
| `multi-thread` | да | work-stealing планировщик Tokio; без неё `current_thread` (экономия ~100–200 КБ на MIPS) |
| `mimalloc` | нет | прежний аллокатор, оставлен собираемым для сравнения; несовместим с `jemalloc` |
| `test-tls` | нет | только для e2e-тестов: доверяет самоподписанному корню из `OUTLINE_WS_TEST_TLS_CA_DER`. В боевых сборках не включать |

### Сборка бинаря

Нативная сборка под текущую машину:

```bash
cargo build --release -p outline-ws-rust
```

Статический бинарь x86-64 (без зависимости от glibc):

```bash
cargo zigbuild --release -p outline-ws-rust --target x86_64-unknown-linux-musl
# или
cargo ws-release-musl-x86_64
```

Статический бинарь AArch64:

```bash
cargo zigbuild --release -p outline-ws-rust --target aarch64-unknown-linux-musl
# или
cargo ws-release-musl-aarch64
```

Чтобы убрать одну фичу, отключите дефолтные и перечислите остальные. Пример без `metrics`:

```bash
cargo zigbuild --release -p outline-ws-rust --no-default-features \
  --features h3,control,socks5,tun,jemalloc,env-filter,multi-thread \
  --target x86_64-unknown-linux-musl
```

## Быстрый старт

`--config` по умолчанию — `config.toml` в текущем каталоге. Из корня workspace укажите путь к примеру:

```bash
cargo run --release -p outline-ws-rust -- --config bins/outline-ws-rust/config.toml
```

Разовый запуск с параметрами из CLI:

```bash
cargo run --release -p outline-ws-rust -- \
  --listen [::]:1080 \
  --tcp-ws-url wss://example.com/SECRET/tcp \
  --tcp-mode h3 \
  --udp-ws-url wss://example.com/SECRET/udp \
  --udp-mode h3 \
  --method chacha20-ietf-poly1305 \
  --password 'Secret0'
```

Настройки клиента для этого примера: SOCKS5-хост `::1` или `127.0.0.1`, порт `1080`.

`listen = "[::]:1080"` на большинстве систем создаёт dual-stack слушатель. Если ваша платформа не отображает IPv4 на IPv6-сокеты, добавьте отдельный IPv4-слушатель.

### Совместимость с `hev-socks5-tunnel`

`outline-ws-rust` принимает оба UDP-режима [`hev-socks5-tunnel`](https://github.com/heiher/hev-socks5-tunnel):

```yaml
socks5:
  address: '127.0.0.1'
  port: 1080
  udp: 'udp'      # стандартный SOCKS5 UDP ASSOCIATE
  # udp: 'tcp'    # hev FWD UDP / UDP-in-TCP (CMD=0x05)
  # pipeline: true
```

- `udp: 'udp'` — стандартный SOCKS5 `UDP ASSOCIATE`.
- `udp: 'tcp'` — UDP-реле `hev-socks5` поверх TCP (`CMD=0x05`).
- `pipeline: true` работает, в том числе с аутентификацией по логину и паролю.

## Конфигурация

Процесс читает файл из `--config` / `PROXY_CONFIG` (по умолчанию `config.toml`). Ниже — выдержка; полный пример с комментариями — [`config.toml`](config.toml).

```toml
[socks5]
# Опционально. Если секции или listen нет, SOCKS5 listener не поднимается.
listen = "[::]:1080"
# Опциональная локальная SOCKS5-аутентификация для клиентов.
#
# [[socks5.users]]
# username = "alice"
# password = "secret1"
#
# [[socks5.users]]
# username = "bob"
# password = "secret2"

[metrics]
listen = "[::1]:9090"

# Control plane (mutating endpoints, например /switch). Должен слушать
# на отдельном сокете от [metrics] и всегда защищён bearer-токеном.
# Без секции мутирующие эндпоинты недоступны.
# [control]
# listen = "127.0.0.1:9091"
# token = "long-random-secret"
# # Либо читать токен из соседнего файла (путь — относительно конфига).
# # Используйте, когда секрет нельзя хранить в самом конфиге.
# # token_file = "/etc/outline-ws/control.token"

# Multi-instance дашборд переехал в сервис outline-ui
# (см. bins/outline-ui/README.ru.md). Этот бинарь отдаёт только [metrics]
# и [control] ниже.

[tun]
# Путь к существующему TUN-устройству. Создание, IP-адреса и маршруты — вне приложения.
# Linux:
# path = "/dev/net/tun"
# name = "tun0"
# macOS / BSD:
# path = "/dev/tun0"
# mtu = 1500
# Лимит одновременных UDP-flow на таблицу. Применяется независимо к
# туннелируемым и к прямым (`via = "direct"`) flow; при переполнении таблицы
# из неё вытесняется least-recently-seen flow. По умолчанию 4096.
# max_flows = 4096
# Лимит на туннелируемые flow — те, что дайлят собственный носитель — сразу по
# ОБОИМ путям, TCP и UDP. Носитель стоит примерно в 28 раз дороже сокета прямого
# flow (замер: 0.279 МиБ против 0.010 МиБ на голом ws://-аплинке, с TLS/H3
# больше), поэтому на узле с лимитом памяти `max_flows` достигается уже после
# того, как память кончилась: всплеск 2026-08-08 держал ~1155 flow при лимите
# 4096, а его 419 носителей подняли RSS с 199 до 757 МиБ, и throttle cgroup'а по
# MemoryHigh заморозил рантайм. При переполнении вытесняется least-recently-seen
# туннелируемый flow того же протокола — ровно как у max_flows; прямые flow в
# этот лимит не считаются. Подбирать по
# `outline_ws_tun_carrier_flow_memory_estimate_bytes` и объёму памяти, который
# готовы отдать, а по `outline_ws_tun_carrier_flows_active` смотреть, упирается
# ли лимит. Не должен превышать max_flows. По умолчанию 0 (выключено).
#
# ВНИМАНИЕ: раньше лимит действовал только на UDP-пути, поэтому значение,
# подобранное до этого изменения, стало вдвое жёстче — вместе два пути доходили
# примерно до 2x от него (в бою наблюдались 256 UDP одновременно с 318 TCP).
# Пересмотреть значение при обновлении.
# max_carrier_flows = 0
# idle_timeout_secs = 300
# Общепроцессный лимит одновременных upstream-dial'ов, общий для TCP- и
# UDP-движков. Всплеск flow дайлит по одному carrier-handshake (TLS/WS/QUIC)
# на flow; сверх лимита connect-таски ждут пермит (он держится только на время
# dial'а, не жизни flow), и всплеск проходит handshake'и быстрыми волнами, а не
# все разом. На steady-state число одновременных flow не влияет. 0 — выключить.
# max_concurrent_upstream_dials = 32
# Встроенный bypass IKE / IPsec NAT-T — см. раздел «TUN-режим» ниже.
# ipsec_bypass = false
# Разрешить ICMP PTB с path MTU ниже QUIC Initial-datagram минимума
# (1200 v4 / 1280 v6) на TUN UDP oversize дропах. По умолчанию false
# защищает QUIC-клиентов от вытеснения в TCP; true для VoWiFi /
# IKE-only установок (`docs/TUN-PMTUD.ru.md`).
# pmtud_emit_below_quic_initial = false
# QUIC connection sniffing (как destOverride в Xray; по умолчанию включено).
# Достаёт SNI из ClientHello в QUIC Initial первой датаграммы и отправляет
# наружу домен (а не IP), чтобы его резолвил выходной узел. Зеркалит [tun.tcp]
# sniffing для QUIC.
# sniff_quic = true
# Домены включения в sniff-override (TCP + QUIC): когда задано и не пусто, ТОЛЬКО
# хосты, совпавшие с суффиксом, перезаписываются в домен (чтобы их резолвил exit);
# остальные сохраняют литеральный IP. По умолчанию пусто (override для всех, кроме исключений).
# sniff_override_include = ["youtube.com", "instagram.com"]
# sniff_override_include_file = "lists/override-include.lst"
# Домены-исключения из sniff-override (TCP + QUIC): sniff-хост, совпавший с
# суффиксом, оставляет литеральный IP вместо домена. Для сайтов, где DNS самого
# клиента лучше, чем ре-резолв на exit (гео-битый CDN edge). По умолчанию пусто.
# sniff_override_exclude = ["strava.com"]
# sniff_override_exclude_file = "lists/override-exclude.lst"
# file_poll_secs = 60 # Интервал опроса файлов доменов в секундах для автоперезагрузки по изменению mtime

# [tun.tcp]
# connect_timeout_secs = 10
# handshake_timeout_secs = 15
# half_close_timeout_secs = 60
# max_pending_server_bytes = 2097152
# backlog_abort_grace_secs = 3
# backlog_hard_limit_multiplier = 2
# backlog_no_progress_abort_secs = 8
# max_buffered_client_segments = 4096
# max_buffered_client_bytes = 2097152
# Авто-тюнинг uplink-окна приёма: новый flow рекламирует в SYN-ACK столько,
# а остаток до max_buffered_client_bytes «зарабатывает» по мере того, как его
# байты реально уходят в upstream — всплеск ещё дозванивающихся flow буферизует
# N x 64 KiB вместо N x 2 MiB. 0 — стартовать сразу с полного окна (старое
# поведение).
# initial_receive_window_bytes = 65536
# max_retransmits = 12
# Sniffing соединений (как destOverride в Xray; по умолчанию включено).
# Подсматривает первые байты клиента, достаёт хост из TLS SNI / HTTP Host и
# отправляет наружу домен (а не IP), чтобы его резолвил выходной узел. (QUIC —
# кноб [tun] sniff_quic; per-domain опт-ауты — [tun] sniff_override_exclude.)
# sniffing = true
# sniff_timeout_ms = 300
# SNI bypass для DIRECT-флоу: ре-резолв sniff-домена ЛОКАЛЬНЫМ резолвером ЭТОГО
# узла и коннект к его IP вместо литерального IP клиента — чинит bypass-домены,
# которые клиент зарезолвил в мёртвый/недостижимый IP. По умолчанию false.
# sniff_direct_reresolve = false
# Миграция носителя (по умолчанию включена): когда общий носитель, на котором
# едет туннельный флоу, умирает — переподключиться, дать серверу вернуть
# запаркованный upstream, доиграть байтовый разрыв в обе стороны и продолжить
# работу вместо сброса соединения приложения. Включается ТОЛЬКО при
# подтверждённом server-side resume hit, поэтому против сервера без resumption
# (дефолт на сервере) она инертна. См. раздел «TUN-режим».
# carrier_migration = true

# [outline.probe] — шаблон, наследуемый каждой [[uplink_group]];
# конкретные группы могут переопределить любое поле через [uplink_group.probe].
[outline.probe]
interval_secs = 30
timeout_secs = 10
max_concurrent = 4
max_dials = 2
min_failures = 1

[outline.probe.ws]
enabled = true

[outline.probe.http]
# Один URL:
#   url = "http://example.com/"
# Или список для ротации — один URL на один probe-вызов, по кругу.
# Размазывание нагрузки по нескольким эндпоинтам помогает заметить отказ
# отдельного сайта, а не маскировать его за единственной всегда-доступной
# точкой. Курсор общий на группу, так что подряд идущие probe-вызовы внутри
# цикла попадают в подряд идущие записи списка.
urls = [
    "http://example.com/",
    "http://www.iana.org/",
]

# `outline.probe.http` отправляет HTTP `HEAD`, а не `GET`, чтобы health-check
# не тянул тело ответа через uplink. Любой HTTP-статус в диапазоне `200..400`
# считается успехом — `301`/`302` редиректы тоже подходят.

# Опционально: TLS-handshake проба. Воспроизводит user-flow chunk-0 паттерн,
# когда upstream-фильтр тихо режет `ServerHello` для конкретных SNI — для
# `[outline.probe.http]` это невидимо, потому что plain HTTP TLS не делает.
# Взаимоисключается с `[outline.probe.http]` / `[outline.probe.tcp]`
# (приоритет: tls → http → tcp). Метрики идут под `probe="tls"`. См.
# docs/UPLINK-CONFIGURATIONS.ru.md «TLS-handshake проба data-path» по
# поводу выбора целей.
# [outline.probe.tls]
# targets = [
#   "www.youtube.com:443",
#   "www.instagram.com",  # bare host → порт 443
# ]

[outline.probe.dns]
server = "1.1.1.1"
port = 53
name = "example.com"

# Каждая группа — изолированный UplinkManager со своим probe loop, standby
# pool, sticky-routes, активным аплинком и LB-политикой.
# Обратите внимание: [[uplink_group]] остаётся на верхнем уровне, не под [outline].
[[uplink_group]]
name = "main"
mode = "active_active"
routing_scope = "per_flow"
warm_standby_tcp = 1
warm_standby_udp = 1
sticky_ttl_secs = 300
hysteresis_ms = 50
failure_cooldown_secs = 10
tcp_chunk0_failover_timeout_secs = 10
rtt_ewma_alpha = 0.3
rtt_ewma_halflife_secs = 300
failure_penalty_ms = 500
failure_penalty_max_ms = 30000
failure_penalty_halflife_secs = 60
h3_downgrade_secs = 60
# auto_failback = false
# Границы VLESS UDP session-mux (используются только аплинками transport = "vless").
# vless_udp_max_sessions = 256              # LRU-вытеснение свыше этого числа целей
# vless_udp_session_idle_secs = 60          # 0 отключает idle-эвикцию
# vless_udp_janitor_interval_secs = 15

# Аплинки живут под [outline]. Каждая запись [[outline.uplinks]] должна
# содержать `group = "..."`, совпадающее с [[uplink_group]].name выше.
[[outline.uplinks]]
name = "primary"
group = "main"
transport = "ss"
tcp_ws_url = "wss://example.com/SECRET/tcp"
weight = 1.0
tcp_mode = "h3"
# fwmark = 100
# disable_udp_gso = true
# ipv6_first = true
# ipv4_only = true
udp_ws_url = "wss://example.com/SECRET/udp"
udp_mode = "h3"
method = "chacha20-ietf-poly1305"
password = "Secret0"

[[outline.uplinks]]
name = "backup"
group = "main"
transport = "ss"
tcp_ws_url = "wss://backup.example.com/SECRET/tcp"
weight = 0.8
tcp_mode = "h2"
udp_ws_url = "wss://backup.example.com/SECRET/udp"
udp_mode = "h2"
method = "chacha20-ietf-poly1305"
password = "Secret0"

# VLESS-over-WebSocket аплинк. Использует тот же WSS-путь дозвона, что и
# transport = "ss"; `vless_id` заменяет Shadowsocks-овые cipher/password.
# Сервер VLESS открывает один WS-путь (`ws_path_vless`), общий для TCP и
# UDP, поэтому в клиентском конфиге задаётся одна пара
# `vless_ws_url`/`vless_mode` — поля `tcp_ws_url`/`udp_ws_url` для
# `transport = "vless"` запрещены и парсер отвергнет их с явной ошибкой.
[[outline.uplinks]]
name = "vless-edge"
group = "main"
transport = "vless"
vless_ws_url = "wss://vless.example.com/SECRET/vless"
vless_mode = "h2"
vless_id = "11111111-2222-3333-4444-555555555555"
weight = 0.5

# Тот же VLESS-аплинк, заданный одной share-link URI. Загрузчик
# разворачивает URI в тройку `vless_id` / `vless_*_url` / `vless_mode`
# на старте; смешивать `link` с явными полями нельзя. Поддерживаются
# стандартные query-параметры Xray / V2Ray (`type`, `security`, `path`,
# `alpn`, `mode`). Полная таблица параметров и ограничения — в
# docs/UPLINK-CONFIGURATIONS.ru.md «VLESS share-link URIs».
[[outline.uplinks]]
name = "vless-share"
group = "main"
link = "vless://11111111-2222-3333-4444-555555555555@vless.example.com:443?type=ws&security=tls&path=%2FSECRET%2Fvless&alpn=h2#vless-edge"
weight = 0.5

# Опциональный policy-routing: first-match-wins по CIDR назначения.
# `via` принимает имя группы или зарезервированные `direct` / `drop`.
# Если [[route]] отсутствует — весь трафик идёт через первую группу.
[[route]]
prefixes = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7"]
via = "direct"

[[route]]
default = true
via = "main"
```

### Поведение параметров конфигурации

- `transport` принимает `ss` (по умолчанию; алиас `shadowsocks`) или `vless`. `ws` / `websocket` — deprecated-алиасы `ss`, будут удалены. VLESS использует те же поля носителя, что и `ss` (`ipv6_first`, `fwmark`, …), но берёт собственную пару URL/режим — `vless_ws_url` или `vless_xhttp_url` плюс `vless_mode` — и аутентифицируется одним `vless_id` вместо Shadowsocks `method` + `password`; `tcp_ws_url` / `udp_ws_url` при `transport = "vless"` отвергаются на разборе. VLESS UDP открывает по сессии на каждое назначение внутри аплинка, не больше `vless_udp_max_sessions` (по умолчанию `256`, вытеснение LRU), с вытеснением простаивающих через `vless_udp_session_idle_secs` (по умолчанию `60`, `0` отключает), проверка каждые `vless_udp_janitor_interval_secs` (по умолчанию `15`). Эти три ключа задаются в `[outline.load_balancing]` или на каждой `[[uplink_group]]`.
- `link = "vless://UUID@HOST:PORT?type=...&security=...&alpn=...#NAME"` задаёт VLESS-аплинк одной share-link URI вместо `vless_id` / `vless_*_url` / `vless_mode`; `transport = "vless"` подставляется сам. Ссылка `ss://` (SIP002 userinfo) так же задаёт SS-аплинк. То же значение принимают `--vless-link` (алиас `--link`, env `OUTLINE_VLESS_LINK`) и payload `/control/uplinks` (`link`, алиас `share_link`). Смешивать `link` с явными полями нельзя — конфиг отвергается. Query-параметры и ограничения: [docs/UPLINK-CONFIGURATIONS.ru.md](docs/UPLINK-CONFIGURATIONS.ru.md#5-vless-share-link-uris).
- Нужен хотя бы один ingress: `--listen` / `[socks5].listen` и/или `[tun]`. Без них процесс завершается с ошибкой, а не слушает `127.0.0.1:1080`.
- `tcp_mode` / `udp_mode` (`transport = "ss"`) и `vless_mode` (`transport = "vless"`) выбирают носитель: `ws_h1` / `ws_h2` / `ws_h3` (WebSocket Upgrade) или `xhttp_h1` / `xhttp_h2` / `xhttp_h3` (XHTTP; SS берёт URL из `tcp_xhttp_url` / `udp_xhttp_url`, VLESS — из `vless_xhttp_url`). Старые значения `http1` / `h1`, `h2`, `h3` принимаются как алиасы `ws_h1`, `ws_h2`, `ws_h3`; `quic` отвергается (raw QUIC-аплинки удалены). Блоки конфига для каждой формы, цепочки fallback и поведение resume: [docs/UPLINK-CONFIGURATIONS.ru.md](docs/UPLINK-CONFIGURATIONS.ru.md).
- `ipv6_first` (по умолчанию `false`): аплинк предпочитает IPv6-адреса IPv4 для TCP, UDP, H1, H2 и H3.
- `ipv4_only` (по умолчанию `false`) отбрасывает AAAA-записи при резолве серверов аплинка. Включайте на хостах без IPv6-связности, где попытки по IPv6 падают с `NetworkUnreachable (OS 101)` и аплинк флапает. При `ipv4_only = true` `ipv6_first` игнорируется. Наследуется от `[outline]` в `[[outline.uplinks]]` и `[[outline.uplinks.fallbacks]]`, если не переопределён.
- `disable_udp_gso` (по умолчанию `false`, в `[[outline.uplinks]]` и `[[outline.uplinks.fallbacks]]`) отключает UDP GSO на QUIC-сокетах аплинка (`ws_h3` / `xhttp_h3`): quinn отправляет по одной датаграмме на `sendmsg`. Нужен аплинку, чей выход не принимает сегментированные отправки, — обычно тому, что `fwmark` уводит в VLAN сетевой карты без аппаратной контрольной суммы на TX: там каждая GSO-отправка падает с `EIO`, и каждое новое QUIC-соединение теряет первую пачку рукопожатия (~1 с лишняя на дозвон). TCP-носители не затрагиваются. Наследуется fallback'ами, если не переопределён. См. «Выход без UDP GSO» в [docs/UPLINK-CONFIGURATIONS.ru.md](docs/UPLINK-CONFIGURATIONS.ru.md).
- `method` принимает также `2022-blake3-aes-128-gcm`, `2022-blake3-aes-256-gcm` и `2022-blake3-chacha20-poly1305`; для них `password` — base64-кодированный PSK ровно длины ключа шифра.
- `[[socks5.users]]` включает локальную SOCKS5-аутентификацию для нескольких пользователей; в каждой записи нужны и `username`, и `password`. Одного пользователя задают `[socks5] username` + `password` или `--socks5-username` / `--socks5-password`.
- Один и тот же SOCKS5-слушатель принимает и стандартный `UDP ASSOCIATE`, и `hev-socks5` `UDP-in-TCP` (`CMD=0x05`); отдельный переключатель не нужен.
- `[outline.probe] min_failures` (по умолчанию `3`): сколько проб подряд должно провалиться, чтобы аплинк стал нездоровым. То же значение — порог успехов подряд для `auto_failback`. Поставьте `1`, чтобы уходить на failover после первой проваленной пробы.
- `[outline.probe] interval_secs` (по умолчанию `120`): период цикла проб. Значение меньше 60 с даёт предупреждение при старте: частые handshake'и проб могут упереться в rate limit upstream'а.
- `tcp_chunk0_failover_timeout_secs` (по умолчанию `10`, `[outline.load_balancing]` или на `[[uplink_group]]`): сколько ждать первых байтов ответа upstream'а после последней активности клиента, прежде чем разрешить TCP chunk-0 failover на другой аплинк. Увеличьте, если аплинки переключаются на медленных первых байтах ответа.
- `auto_failback` (по умолчанию `false`, `[outline.load_balancing]` или на `[[uplink_group]]`): возвращать ли трафик на восстановившийся аплинк с более высоким приоритетом.
  - `false`: активный аплинк меняется только при сбое. Перейдя на резервный, прокси остаётся на нём, пока не упадёт сам резервный. Так нет обрывов соединений, которые вызывает упреждающий возврат.
  - `true`: пока текущий активный здоров, а есть кандидат с более высоким `weight` (или равным weight и меньшим индексом в конфиге), трафик возвращается на кандидата после того, как он пройдёт `min_failures` циклов проб подряд. Приоритет — `weight`, а не EWMA RTT: под нагрузкой EWMA активного аплинка растёт, а простаивающий резервный выглядит быстрее, и сравнение по EWMA переключало бы на этом. Failback идёт только в сторону большего weight (`1.0 → 1.5 → 2.0`); переход на аплинк с меньшим weight требует подтверждённого пробой failover'а.
- `mode_downgrade_secs` (на группу, по умолчанию `60`, алиас `h3_downgrade_secs`): сколько аплинк после сбоя на «продвинутом» носителе (например, H3 application error вроде `H3_INTERNAL_ERROR`) остаётся на ранг ниже (`ws_h3 → ws_h2`, `xhttp_h3 → xhttp_h2`), прежде чем снова попробовать заданный носитель. Действует для `ss` и `vless`. `0` отключает даунгрейд.
- `carrier_degraded_failover_secs` (на группу, по умолчанию `3 × mode_downgrade_secs`): failover по качеству носителя для строгого выбора (`active_passive`). Аплинк, чьи пробы проходят по TCP-фоллбеку, считается здоровым, поэтому без этого параметра он держал бы активный слот, даже когда каждый дозвон ограничен ниже заданного носителя (`ws_h3 → ws_h2`, TCP поверх TCP). Если активный аплинк проработал ниже заданного носителя под одним непрерывным окном даунгрейда не меньше этого числа секунд, а в группе есть здоровый по пробам кандидат с равным или большим `weight`, чей носитель не деградирован и чья серия успешных проб достигла `min_failures`, выбор мягко переключается на этого кандидата. Одиночная вспышка сработать не может: одно окно истекает через `mode_downgrade_secs`, порог пересекают только сбои, которые продолжают продлевать окно. `0` отключает. Работает при любом `auto_failback`; кандидат с меньшим weight не забирает слот только за качество носителя.
- `state_path` (опционально): TOML-файл, где хранится выбор активного аплинка между рестартами. По умолчанию — путь к конфигу с расширением `.state.toml` (`config.toml` → `config.state.toml`). Если файл нельзя записать (например, конфиг в `/etc/` под `ProtectSystem=strict`), при старте пишется предупреждение и процесс работает без сохранения. Прилагаемые юниты задают `STATE_PATH=/var/lib/outline-ws-rust/_default/state.toml` (шаблон: `/var/lib/outline-ws-rust/<instance>/state.toml`). Сохраняется только имя активного аплинка; EWMA и штрафы восстанавливаются за один цикл проб после рестарта.
- У каждой `[[uplink_group]]` свой probe loop, standby-пул, sticky-routes, активный аплинк и политика балансировки; группы не делят runtime-состояние.
- `[outline.probe]` — шаблон: каждая группа его наследует, `[uplink_group.probe]` переопределяет отдельные поля. Подтаблицы проб (`ws` / `http` / `dns` / `tcp` / `tls`) заменяются целиком: если группа задаёт `[uplink_group.probe.http]`, шаблонный `[outline.probe.http]` для неё не действует. Application-level пробы (`http` / `tcp` / `tls`) взаимоисключающие: за цикл выполняется одна, приоритет `tls → http → tcp`.
- Имена аплинков должны быть уникальны по всем группам: лейбл Prometheus `uplink="..."` не содержит группы.
- Секция `[bypass]` удалена. Перенесите bypass-префиксы в `[[route]]` с `via = "direct"`; конфиг с `[bypass]` не загружается и выдаёт ошибку с указанием миграции.
- Аплинки, шаблон проб и настройки балансировки живут под `[outline]` (`[[outline.uplinks]]`, `[outline.probe]`, `[outline.load_balancing]`). Старая плоская форма (top-level `tcp_ws_url` / `[probe]` / `[[uplinks]]` / `[load_balancing]`) ещё загружается и пишет deprecation-предупреждение. Если аплинков не задано, top-level `tcp_ws_url` / `password` или CLI-флаги (`--tcp-ws-url`, `--password`, …) создают группу `default` с одним аплинком.
- Флаги CLI и переменные окружения переопределяют файл. `--metrics-listen` включает метрики без `[metrics]`; `--tun-path` включает TUN без `[tun]`; `--control-listen` + `--control-token` включают control plane без `[control]` — нужны оба, один без другого даёт ошибку старта.
- `direct_fwmark` (опционально, top-level): `SO_MARK` для TCP- и UDP-сокетов `direct`-соединений. Нужен, когда bypass-трафик надо пометить для policy routing, например чтобы bypass-маршрут не перехватывался снова TUN-интерфейсом.
- `[dial] timeout_secs` (по умолчанию `10`, ограничивается диапазоном `2..=120`): верхняя граница одного свежего дозвона носителя — TCP + TLS + HTTP upgrade для WS/XHTTP или QUIC + HTTP/3 handshake — и, в размере 70 % от неё, открытия стрима на установленном H3-соединении. 10 с хватает на broadband и LTE. На 2G один round trip близок к секунде, а одна цепочка сертификатов передаётся несколько секунд, поэтому бюджет в 10 с истекает посреди рукопожатия, каждая попытка засчитывается как runtime-сбой, а повторы съедают полосу, которой рукопожатию не хватило: аплинк числится поднятым и ничего не передаёт. Для таких каналов увеличьте значение. Цена — худшее время failover'а: именно эта граница не даёт дозвону в чёрную дыру держать цепочку `h3 → h2 → h1` весь бюджет SYN-ретрансмитов ОС (Linux ~127 с).
- `[tcp_timeouts]` ограничивает SOCKS5 TCP-сессии, значения в секундах:

  | Ключ | По умолчанию | Что делает |
  |---|---|---|
  | `socks_upstream_idle_secs` | `300` | закрыть туннелируемую SOCKS5-сессию, если столько времени не было payload ни в одну сторону; keepalive-кадры таймер не сбрасывают. Освобождает FD соединений, которые TUN-интерцепторы открывают и бросают без FIN |
  | `direct_idle_secs` | `120` | то же для `direct`-сессий |
  | `post_client_eof_downstream_secs` | `600` | сколько после полузакрытия со стороны клиента ждать, пока downstream доотдаст данные и пришлёт FIN. Нужно долгим запросам (большой upload, затем минуты работы сервера); прежние 30 с обрывали их посреди ответа |
  | `upstream_response_secs` | `15` | срок ответа chunk-0 на аплинк, когда кандидатов для failover не осталось |

### Флаги CLI и переменные окружения

| Флаг | Env | Что задаёт |
|---|---|---|
| `--config` | `PROXY_CONFIG` | путь к конфигу (по умолчанию `config.toml`) |
| `--listen` | `SOCKS5_LISTEN` | адрес SOCKS5-слушателя |
| `--socks5-username` | `SOCKS5_USERNAME` | единственный SOCKS5-пользователь |
| `--socks5-password` | `SOCKS5_PASSWORD` | пароль этого пользователя |
| `--transport` | `OUTLINE_TRANSPORT` | `ss` или `vless` |
| `--tcp-ws-url` | `OUTLINE_TCP_WS_URL` | WebSocket URL для SS TCP |
| `--tcp-xhttp-url` | `OUTLINE_TCP_XHTTP_URL` | базовый XHTTP URL для SS TCP |
| `--tcp-mode` | `OUTLINE_TCP_MODE` | носитель SS TCP |
| `--udp-ws-url` | `OUTLINE_UDP_WS_URL` | WebSocket URL для SS UDP |
| `--udp-xhttp-url` | `OUTLINE_UDP_XHTTP_URL` | базовый XHTTP URL для SS UDP |
| `--udp-mode` | `OUTLINE_UDP_MODE` | носитель SS UDP |
| `--vless-ws-url` | `OUTLINE_VLESS_WS_URL` | WebSocket URL для VLESS |
| `--vless-xhttp-url` | `OUTLINE_VLESS_XHTTP_URL` | базовый XHTTP URL для VLESS |
| `--vless-mode` | `OUTLINE_VLESS_MODE` | носитель VLESS |
| `--vless-link` (`--link`) | `OUTLINE_VLESS_LINK` | аплинк из share-link `vless://` или `ss://` |
| `--method` | `SHADOWSOCKS_METHOD` | шифр Shadowsocks |
| `--password` | `SHADOWSOCKS_PASSWORD` | пароль / PSK Shadowsocks |
| `--fwmark` | `OUTLINE_FWMARK` | `SO_MARK` аплинка |
| `--ipv6-first` | `OUTLINE_IPV6_FIRST` | предпочитать IPv6 для аплинка |
| `--ipv4-only` | `OUTLINE_IPV4_ONLY` | только IPv4 для аплинка |
| `--metrics-listen` | `METRICS_LISTEN` | адрес слушателя метрик |
| `--control-listen` | `CONTROL_LISTEN` | адрес control-plane слушателя |
| `--control-token` | `CONTROL_TOKEN` | bearer-токен control plane |
| `--tun-path` | `TUN_PATH` | путь к TUN-устройству |
| `--tun-name` | `TUN_NAME` | имя TUN-интерфейса |
| `--tun-mtu` | `TUN_MTU` | MTU TUN |
| `--worker-threads` | `WORKER_THREADS` | число worker-потоков Tokio (по умолчанию — число CPU) |
| `--thread-stack-size-kb` | `THREAD_STACK_SIZE_KB` | стек потока Tokio в КиБ (по умолчанию `2048`) |
| `--state-path` | `STATE_PATH` | файл состояния активного аплинка |
| `--fingerprint-profile` | `OUTLINE_FINGERPRINT_PROFILE` | стратегия браузерного отпечатка: `off`, `stable`, `per_host_stable`, `random` |

## Policy routing

Маршрутизация по назначению, правила проверяются по порядку до первого совпадения (first-match-wins), плюс одно явное правило `default = true`. Каждое правило выбирает цель через `via = "..."`:

- имя группы (одной из объявленных `[[uplink_group]]`): соединение идёт через uplink manager этой группы;
- `direct`: напрямую, мимо аплинков (то, что раньше делал `[bypass]`);
- `drop`: SOCKS5 `REP=0x02 (connection not allowed)` для TCP, тихий сброс для UDP.

IP-цели сравниваются с CIDR-префиксами правил. Доменные цели (SOCKS5-клиент передал hostname для удалённого резолва) с CIDR-префиксом не совпадают никогда; они сравниваются с доменными суффиксами `domains` и, если ни одно правило их не перечисляет, уходят в default. Прокси не резолвит домен локально ради маршрутизации: DNS-запрос ушёл бы мимо туннеля, а удалённый резолв сломался бы.

Правила можно менять на ходу через `/control/routes` и переупорядочивать через `/control/routes/reorder`; эндпоинты и ограничение hot-apply — в разделе [Control plane](#control-plane).

### Конфигурация маршрутов

```toml
# RFC 1918 / ULA / loopback — никогда через туннель.
[[route]]
prefixes = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7", "127.0.0.0/8", "::1/128"]
via = "direct"

# Страновой / GeoIP-список из файла, hot-reload по mtime.
[[route]]
file = "/etc/outline-ws-rust/geoip-cn.list"
file_poll_secs = 60
via = "backup"
fallback_via = "main"     # пробуем "main", если в "backup" нет healthy-аплинков

# Несколько файлов, объединённых в одно правило — например, IPv4 и IPv6
# списки из разных фидов. Все файлы отслеживаются независимо;
# inline `prefixes` при желании тоже можно добавить — всё смерджится.
[[route]]
files = [
    "/etc/outline-ws-rust/geoip-cn-v4.list",
    "/etc/outline-ws-rust/geoip-cn-v6.list",
]
file_poll_secs = 60
via = "backup"

# Заблокировать диапазон.
[[route]]
prefixes = ["198.51.100.0/24"]
via = "drop"

# Доменные цели (SOCKS5h-hostname): локальные зоны — напрямую…
[[route]]
domains = ["home.arpa", "corp.example"]
domain_file = "/etc/outline-ws-rust/bypass-domains.lst"
via = "direct"

# …все остальные домены — через туннель, а не в default.
[[route]]
domains = ["*"]
via = "main"

# Явный default — матчит всё, что не подошло выше.
[[route]]
default = true
via = "main"
fallback_direct = true    # или: fallback_drop = true / fallback_via = "backup"
```

Поля правила:

| Поле | По умолчанию | Значение |
|---|---|---|
| `prefixes` / `file` / `files` | — | inline-список CIDR и/или файлы с одним CIDR на строку (комментарии `#` и пустые строки пропускаются). Все источники объединяются в CIDR-набор правила; `file` — сокращение для `files` из одного элемента, их можно сочетать |
| `domains` / `domain_file` / `domain_files` | — | доменные суффиксы для доменных целей (тот же формат файлов, один суффикс на строку). `example.com` совпадает с самим доменом и любым поддоменом (`a.b.example.com`) по границе меток; регистр не важен, завершающая точка игнорируется, `.example.com` и `*.example.com` — то же самое. `"*"` совпадает с любым доменом — используйте как catch-all, чтобы доменные цели получили явный маршрут. Правило может сочетать CIDR и домены: IP сравниваются с CIDR, домены — с суффиксами |
| `file_poll_secs` | `60` | как часто делать `stat` каждого файла из `file` / `files` / `domain_file` / `domain_files`; содержимое перечитывается при смене mtime |
| `via` | — | цель для совпавшего трафика; обязательно, кроме правила `default = true`, где это цель по умолчанию |
| `fallback_via` / `fallback_direct` / `fallback_drop` | — | взаимоисключающие; применяются, когда `via` — группа без здоровых аплинков в момент диспатча |
| `invert` | `false` | правило совпадает с адресами вне своего набора префиксов. Только CIDR; с `domains` не сочетается (отвергается при загрузке — заведите отдельное доменное правило) |
| `default` | — | ровно одно правило должно иметь `default = true`; оно совпадает со всем, что не совпало выше, и не может иметь префиксов или доменов |

### Матчинг префиксов

Inline- и файловые префиксы правила объединяются в [`CidrSet`](../../crates/outline-routing/src/cidr.rs): отсортированные диапазоны `[start, end]` (IPv4 как `u32`, IPv6 как `u128`), пересекающиеся и смежные диапазоны слиты. Поиск — двоичный (`partition_point`), O(log n) на правило.

### Hot-reload

Каждое правило хотя бы с одним `file` / `files` / `domain_file` / `domain_files` получает фоновую задачу, которая раз в `file_poll_secs` проверяет mtime каждого файла. При изменении CIDR- и доменный наборы правила собираются заново из inline-записей и всех файлов и атомарно подменяются (`ArcSwap`); другие правила не затрагиваются. При ошибке чтения или разбора остаются прежние наборы, в лог пишется предупреждение.

### Idle timeout прямых соединений

`direct`-соединения закрываются после 120 с (`[tcp_timeouts] direct_idle_secs`) без байтов в обе стороны, их FD освобождаются. Иначе клиенты, которые открывают TCP-соединения (DNS-over-HTTPS, DNS-over-TLS) и бросают их без FIN, держали бы оба сокета открытыми. Любые данные в любую сторону сбрасывают таймер.

### Fallback-семантика

Если `via` указывает на группу без здоровых аплинков, используется fallback-цель правила (один уровень, без рекурсии). Здоровье читается в момент диспатча через `UplinkManager::has_any_healthy(transport)`, без построения списка кандидатов и без изменения sticky-routes. Когда основная группа восстанавливается, новые соединения снова идут через неё; fallback проверяется только при диспатче.

### Байпасс на уровне группы (`bypass_when_down`)

Вместо `fallback_direct = true` на каждом маршруте группа может задать `bypass_when_down = true` на своей `[[uplink_group]]`: пока в группе нет здорового аплинка, трафик в неё идёт `direct`, включая неявный диспатч «всё в группу по умолчанию», когда `[[route]]` не задан. Явный fallback маршрута имеет приоритет; байпасс тогда применяется (на один уровень) к группе, куда попал fallback. Решение пересчитывается на каждый дозвон / датаграмму / флоу, поэтому трафик возвращается в туннель, как только любой аплинк восстановится. На хостах, где TUN держит маршрут по умолчанию, задайте `direct_fwmark`, чтобы обходные сокеты не возвращались в TUN. См. «Байпасс полностью упавшей группы» в [docs/UPLINK-CONFIGURATIONS.ru.md](docs/UPLINK-CONFIGURATIONS.ru.md).

## Транспортные режимы

Четыре формы аплинка — Shadowsocks поверх WebSocket, Shadowsocks поверх XHTTP, VLESS поверх WebSocket и VLESS поверх XHTTP — описаны с TOML-примерами и цепочками fallback при дозвоне в [docs/UPLINK-CONFIGURATIONS.ru.md](docs/UPLINK-CONFIGURATIONS.ru.md). Здесь — runtime-детали, которых в том справочнике нет.

Выбор носителя:

- `ws_h1` проходит через любой reverse proxy, пропускающий WebSocket Upgrade;
- `ws_h2` требует reverse proxy и origin с поддержкой RFC 8441;
- `ws_h3` требует доступности сервера по QUIC (UDP);
- `xhttp_h2` / `xhttp_h3` — когда WebSocket Upgrade режется на пути; дозвон сам спускается до `xhttp_h1`, если режутся ещё и QUIC, и ALPN h2 (у h1 ниже пропускная способность, но URL тот же, что у xray).

QUIC-эндпоинты. Каждое H3-соединение (`ws_h3`, `xhttp_h3`) получает собственный QUIC-эндпоинт и UDP-сокет на новом локальном порту и живёт ровно столько, сколько соединение. Поэтому NAT-трансляция, застрявшая на мёртвом назначении, затрагивает одно соединение, а не все последующие дозвоны. Каждый эндпоинт выделяет ~2,9 МиБ приёмного буфера на Linux с GRO; gauge `outline_ws_h3_endpoints_active{kind}` считает живые эндпоинты. `fwmark` ставится на сокет до первого `sendmsg`.

Если на рукопожатие нет ответа через 1 с, начинается второй дозвон с нового локального порта, а через 3 с — третий; используется первый завершившийся. Некоторые пути выбрасывают UDP-поток целиком, поэтому повторы с того же порта не проходят, а новый порт — это новый поток. Здоровое рукопожатие завершается примерно за два RTT и второй дозвон не запускает. `outline_ws_quic_dial_hedges_total{kind,result}` считает дозвоны с гонкой: `result="won"` — первой завершилась дополнительная попытка, `result="lost"` — первая всё равно выиграла.

QUIC keep-alive PING уходят каждые 8–12 с (джиттер на процесс; `[quic] keepalive_secs` переопределяет), чтобы NAT-трансляции не истекали, а сервер замечал мёртвые соединения раньше idle timeout (`[quic] idle_timeout_secs`, по умолчанию 30 с из браузерного профиля).

Окно даунгрейда. После сбоя на «продвинутом» носителе (H3 / `xhttp_h3`) аплинк остаётся на ранг ниже на `mode_downgrade_secs` (по умолчанию 60 с; алиас `h3_downgrade_secs`; `0` отключает). То же окно открывают провалы TCP-проб на H3-аплинках; иначе в `active_passive + global` проба, чередующая успех и провал, вызывала бы failover каждый цикл. Два уровня (кэш на хост + окно на аплинк) описаны в [docs/UPLINK-CONFIGURATIONS.ru.md](docs/UPLINK-CONFIGURATIONS.ru.md#механика-окна-даунгрейда).

Скоринг во время окна даунгрейда (scope `per_flow`): пока окно открыто, к эффективной задержке аплинка поверх обычного штрафа добавляется `failure_penalty_max_ms`. Когда обычный штраф затухает, эта добавка не даёт флоу `active_active + per_flow` вернуться на primary, работающий на H2-фоллбеке, пока окно не закроется.

Warm-standby следует даунгрейду: пока аплинк ограничен с H3 до H2, новые standby-соединения открываются по H2.

Таймауты рукопожатия. У каждого пути подключения есть верхняя граница, чтобы сервер в чёрной дыре не задерживал новые сессии на минуты, пока аплинк числится здоровым:

| Ситуация | Граница (по умолчанию) | Без границы |
|---|---|---|
| Свежее подключение (TCP/QUIC + TLS + HTTP handshake), H1 / H2 / H3 | `[dial] timeout_secs`, 10 с | ретрансмиты SYN в Linux ~127 с (H1/H2); QUIC idle timeout (H3) |
| Новый стрим на общем H2-соединении | `[dial] timeout_secs`, 10 с | ожидание мёртвого соединения |
| Новая сессия на H3-соединении из пула | 8 × сглаженный RTT соединения, не меньше 3 с и не больше 70 % от `[dial] timeout_secs` (7 с); затем сессия перезванивает на новое соединение | ожидание, пока QUIC idle timeout закроет соединение |

Соединение из пула, чей путь умер (NAT rebinding, запоздавшее закрытие сервером, тихие потери), для клиентской библиотеки выглядит открытым; эти границы такие случаи ловят. Таймаут считается runtime-сбоем upstream'а: запись в пуле инвалидируется при следующем открытии, `report_runtime_failure` ставит cooldown и будит пробу. В `active_passive + global` активный аплинк меняется только после того, как проба подтвердит сбой на собственном свежем подключении, поэтому кратковременный сбой пула не меняет выходной IP, а восстановление при действительно недоступном primary занимает около одного цикла проб.

Переподключение общего соединения. Когда общее H2- или H3-соединение рвётся и N сессий одновременно пытаются переподключиться, выполняется одно новое рукопожатие. Медленный путь сериализуется `tokio::sync::Mutex<()>` на ключ сервера: первый ожидающий подключается и кладёт соединение в кэш, остальные находят его под блокировкой и переиспользуют вместо N TLS-рукопожатий к одному серверу.

Обрывы SOCKS5-согласования. Когда локальный SOCKS5-клиент (TUN-интерцептор вроде sing-box или Clash) закрывает соединение после greeting, но до или во время запроса CONNECT, ошибки `early eof` / `failed to read request header` пишутся на уровне `debug`, а не `warn`. TUN-интерцепторы так делают, когда сбрасывают пул соединений при переподключениях.

## UDP по HTTP/3 datagram

На `ws_h3` и `xhttp_h3` клиентский UDP (Shadowsocks / SS2022 и VLESS) может идти в HTTP/3 DATAGRAM-кадрах (RFC 9297), привязанных к request stream носителя, вместо самого стрима. Это убирает head-of-line blocking и двойную ретрансмиссию QUIC внутри QUIC. Правила по протоколам: [docs/UPLINK-CONFIGURATIONS.ru.md](docs/UPLINK-CONFIGURATIONS.ru.md#udp-по-http3-datagram).

```toml
[quic]
# Предлагать UDP по HTTP/3 datagram (по умолчанию true). false: не предлагать
# никогда, UDP остаётся в потоке, как раньше. Читается один раз при старте: действует после перезапуска.
# udp_datagrams = true
```

- Согласование. Клиент шлёт `x-outline-udp-datagram: 1`; сервер в знак согласия возвращает его (серверный ключ `[server.h3] udp_datagrams`, по умолчанию `true`). Без эха UDP остаётся в стриме байт в байт как раньше, поэтому любая сторона может быть старой версии.
- Где действует. Только `ws_h3` / `xhttp_h3`, только UDP-планы, никогда с отпечатком Safari (он не объявляет `max_datagram_frame_size`).
- Размеры. Выбор делается на каждый пакет по текущему `max_datagram_size()`; пакет, который не помещается, идёт по стриму. До PMTUD клиент начинает с MTU 1200, поэтому сразу после подключения большинство полноразмерных пакетов ещё идёт по стриму. Максимальный UDP payload сервера — 1452. Буферы датаграмм — 1 МиБ с каждой стороны.
- Выкатка. Сначала серверы, потом клиенты; безопасен любой порядок. Откат: `udp_datagrams = false` на стороне, которая сбоит, и перезапуск этого сервиса (без пересборки).

Кэш path MTU. Клиент запоминает path MTU, на котором остановился каждый H3-путь (ключ — сервер, порт, fwmark и хэш локального адреса источника, то есть сеть, в которой он находится), в файле рядом с state-файлом с расширением `.pmtu` (по умолчанию `<config>.state.pmtu`; с прилагаемым юнитом — `/var/lib/outline-ws-rust/_default/state.pmtu`). Следующий дозвон по тому же пути пробует этот размер первым: одна MTU-проба вместо лесенки 1326 → 1389 → 1420 → …, которую пассивный наблюдатель видел бы на каждом соединении.

| Значение в кэше | Срок жизни | Что происходит при следующем соединении |
|---|---|---|
| 1452 (верхняя граница H3) | 3 дня с момента, когда путь впервые на нём остановился | первая проба и, после подтверждения, потолок соединения |
| меньше 1452 | 1 час | то же; короткий срок не даёт поиску, остановившемуся низко из-за случайной потери пробы, ограничивать соединения сутками |
| истёкшее, не старше 30 дней | — | первая проба, которая только задаёт начало поиска: поиск продолжается выше, результат сохраняется заново |

Устаревшее значение (путь сузился) стоит одного отвергнутого размера пробы, дальше обычный поиск идёт ниже. Если поиск отверг какой-то размер, потолок соединения ставится на единицу ниже наименьшего отвергнутого, поэтому неизменный путь платит за отвергнутый размер один раз за соединение, а не при каждом повторном поиске раз в 10 минут. Initial остаётся 1200 байт.

Метрики (на `/metrics`):

| Метрика | Лейблы | Значение |
| --- | --- | --- |
| `outline_ws_udp_h3_datagrams_total` | `direction`, `transport`, `proto` | UDP-пакеты, ушедшие H3-датаграммами (`up` = отданы quinn, который при полном буфере отправки может выбросить самую старую) |
| `outline_ws_udp_h3_datagram_fallback_total` | `direction`, `transport`, `proto`, `reason` | пакеты / VLESS-записи согласованной сессии, ушедшие по стриму; `reason` для `up`: `unarmed` (VLESS, отправлено до первого ответа сервера), `too_large` (не влез в размер датаграммы), `send_failed` (quinn отказал по другой причине); для `down` всегда `stream` (причину показывает счётчик сервера) |
| `outline_ws_udp_h3_datagram_dropped_total` | `reason` | отброшенные входящие датаграммы: `unknown_stream`, `closed_stream` (стрим закрыт менее 10 с назад), `malformed`, `queue_full` (всплеск переполнил ограниченную очередь приёма стрима), `queue_stalled` (переполнилась, пока потребитель не читал 50 мс), `early` (VLESS, до заголовка ответа) |
| `outline_ws_udp_h3_datagram_sessions_total` | `transport`, `state` | предложения по итогу, `negotiated` / `declined`; считаются якорные стримы, включая пополнение standby-пула и дозвоны проб |
| `outline_ws_quic_path_mtu_bytes` | `transport` | гистограмма path MTU соединений с датаграммами, отсчёт раз в 10 с, а не при закрытии (соединение короче 10 с точки не даёт; чёрные дыры и потерянные пробы всё равно сбрасываются при закрытии); 1200 — минимум QUIC после чёрной дыры, тогда пакеты примерно от 1100 байт идут по стриму |
| `outline_ws_quic_black_holes_total` | `transport` | 10-секундные отсчёты, в которых соединение с датаграммами обнаружило MTU black hole (каждое обнаружение сбрасывает path MTU до 1200), не больше одного на отсчёт: умирающее соединение срабатывает детектором тысячи раз в минуту |
| `outline_ws_quic_mtu_probes_lost_total` | `transport` | потерянные DPLPMTUD-пробы на соединениях с датаграммами |

## Carrier-padding

Опциональный паддинг на уровне приложения для WebSocket- и XHTTP-дозвонов — клиентская половина серверного паддинга. Каждый Shadowsocks-чанк или VLESS-кадр оборачивается в кадр с длинами `real_len | pad_len | real | pad`, и размер внешней TLS-записи перестаёт следовать за размером payload. На этой корреляции размеров записей работают классификаторы TLS-in-TLS.

- Глобальное значение плюс переопределение на аплинке. `[padding]` задаёт параметры схемы и значение по умолчанию (`enabled`, по умолчанию `false`); каждый `[[outline.uplinks]]` может задать `padding = true` / `padding = false`. Дозвон берёт значение аплинка, если оно задано, иначе глобальное (та же схема, что у `fingerprint_profile` на аплинке). Либо оставьте глобальное выключенным и задайте `padding = true` на аплинках, ведущих на ваши padded-эндпоинты сервера, либо включите глобально и задайте `padding = false` на VLESS-аплинке к стороннему серверу (xray / sing-box). Padded-дозвон (SS и VLESS, TCP и UDP) должен идти на эндпоинты сервера, где паддинг тоже включён.
- Задаётся конфигом на обеих сторонах, не согласуется по сети. На outline-ss-rust у соответствующего `[[endpoint]]` должно быть `padded = true`; иначе padded-кадры попадут в обычный декодер и сессия упадёт.
- Cover-трафик. При `cover = true` простаивающее соединение шлёт кадры из одного паддинга со случайным интервалом (`cover_jitter_min_ms` … `cover_jitter_max_ms`, по умолчанию 250 / 1500).

Покрывает SS и VLESS поверх WebSocket (h1/h2/h3) и поверх XHTTP. UDP паддится по датаграммам на каждом WS-носителе — SS-UDP (split: укажите его путь; combined: общий базовый путь) и VLESS-UDP. Полное описание: [`docs/PADDING.ru.md`](../../docs/PADDING.ru.md); ключи перечислены в блоке `[padding]` в `config.toml`.

## Выбор аплинка и runtime-поведение

У каждого аплинка свои:

- TCP URL и режим
- UDP URL и режим
- шифр и пароль (или `vless_id`)
- опциональный Linux `fwmark`
- приоритет через `weight`. Среди здоровых кандидатов всегда выигрывает больший weight, независимо от EWMA; так помечают резервные аплинки, на которые failover и sticky не должны уходить. При равном weight порядок задаёт скор на основе EWMA, затем индекс в конфиге.

Конвейер выбора:

1. Health-пробы обновляют последний RTT и EWMA RTT.
2. Подтверждённые пробой сбои добавляют затухающий штраф. При включённых пробах runtime-сбой (например, сброс H3-соединения под нагрузкой) только ставит временный cooldown; штраф добавляется, когда проба подтверждает сбой (`consecutive_failures ≥ min_failures`). Поэтому кратковременные ошибки под нагрузкой не копят штрафы на здоровом аплинке.
3. Эффективная задержка = EWMA RTT + текущий штраф.
4. Кандидаты сортируются: сначала здоровые, затем по `weight` (больший первым), затем по `effective_latency / weight`, затем по индексу в конфиге. Скор ранжирует только аплинки с одинаковым weight.
5. Sticky-маршрутизация и гистерезис держат флоу на их аплинке, пока разница скоров не превысит `hysteresis_ms`.
6. Warm-standby пулы держат заранее установленные соединения, и новая сессия пропускает рукопожатие.

Лимит sticky-маршрутов: таблица хранит не более 100 000 per-flow записей. При больших NAT-пулах или множестве клиентов в scope `per_flow` новые записи сверх лимита не сохраняются, и флоу получает свежий выбор по задержке. Глобальные и per-transport закрепления (scope `global` и `per_uplink`) сохраняются всегда.

Область маршрутизации:

- `per_flow`: разные цели могут идти через разные аплинки.
- `per_uplink`: один выбранный аплинк на транспорт, TCP и UDP могут идти через разные аплинки. В `active_passive` каждый транспорт держит свой закреплённый аплинк до failover или явного перевыбора; штрафы не влияют на строгий per-transport скор.
- `global`: один выбранный аплинк для всего нового трафика до failover или явного перевыбора. Ранжирует TCP-скор, но UDP-способный активный аплинк должен держать и UDP здоровым: провал UDP-пробы или UDP runtime cooldown вызывает глобальный failover. Штрафы не влияют на строгий глобальный скор.

Auto-failback (`auto_failback`, по умолчанию `false`):

- `false`: активный аплинк меняется только при сбое (cooldown или потеря здоровья). Пока он здоров, он остаётся активным, даже если восстановился аплинк с большим приоритетом. Так нет обрывов соединений, которые вызывает упреждающий возврат на primary.
- `true`: пока текущий активный здоров, а есть здоровый по пробам кандидат с большим `weight` (или равным weight и меньшим индексом в конфиге), трафик возвращается на кандидата после `min_failures` успешных циклов проб подряд. Приоритет — `weight`, а не EWMA, потому что EWMA активного аплинка растёт под нагрузкой. Failback идёт только в сторону большего weight; переход на меньший weight требует подтверждённого пробой failover'а.

Плановый перевыбор: `reselect_at` (слоты по часам `"HH:MM"`, срабатывают в течение 90 с после заданного времени) или `reselect_interval` (фиксированный период) принудительно запускает взвешенно-случайную ротацию строгого активного аплинка в режиме `active_passive`. Текущий активный всегда исключается; победитель разыгрывается среди здоровых, включённых, не находящихся в cooldown кандидатов с весом `penalty_weight × weight` (с нижней границей `health_weight_floor`). Ключи взаимоисключающие, оба требуют `active_passive`. `POST /control/reselect` запускает ту же ротацию вручную. См. «Плановый перевыбор» в [docs/UPLINK-CONFIGURATIONS.ru.md](docs/UPLINK-CONFIGURATIONS.ru.md).

**Внимание:** при `auto_failback = true` розыгрыш может выпасть на аплинк с меньшим weight, и следующая серия здоровых проб аплинка с большим weight вернёт переключение через failback. Если плановый переход должен сохраняться, задайте группе одинаковый `weight` или оставьте `auto_failback = false` (по умолчанию).

Синхронный перевыбор: `reselect_sync = true` (требует `reselect_at`) заменяет случайный розыгрыш детерминированным. Порядок предпочтения в слоте выводится из имени группы, имён аплинков, локальной календарной даты и индекса слота; активным становится первый аплинк этого порядка, здоровый на данном узле. Независимые узлы с одинаковым конфигом группы выбирают один аплинк без обмена данными, и клиенты, попадающие на любой из них, сохраняют один выходной адрес. Здоровье, cooldown и административное состояние остаются локальными: узел, чей аплинк умер, сразу уходит на failover, а если сбой видит только один узел, пара остаётся разделённой до следующего слота. При старте решение слота перекрывает активный аплинк, восстановленный из state-файла, а `POST /control/reselect` в пределах слота идемпотентен. Все узлы одного sync-домена должны работать в одном часовом поясе. См. «Синхронный перевыбор» в [docs/UPLINK-CONFIGURATIONS.ru.md](docs/UPLINK-CONFIGURATIONS.ru.md).

Failover с учётом штрафов: когда активный аплинк уходит в cooldown, кандидаты на замену сортируются так: сначала здоровые → оставшийся cooldown → `weight` (больший первым) → скор со штрафом (`(EWMA + penalty) / weight`) → индекс в конфиге. Намеренно понижённый резервный аплинк не продвигается только за счёт лучшего RTT пробы; внутри одного weight слагаемое штрафа не даёт трём и более равным аплинкам переключаться по кругу (без него только что упавший primary, очищенный пробой, сразу выигрывал бы за счёт лучшего сырого EWMA).

Runtime failover:

- UDP может сменить аплинк внутри активной ассоциации после сбоя отправки или чтения.
- TCP может уйти на failover до установления рабочего туннеля.
- Установленные TCP-туннели на другой аплинк не переносятся.

## Health-пробы

Типы проб:

| Тип | Что проверяет |
|---|---|
| `ws` | рукопожатие TCP + TLS + WebSocket к аплинку. Без ping/pong-кадров (многие серверы на них не отвечают). Подтверждает, что новое соединение открывается; целостность data path проверяют `http` / `dns` |
| `http` | HTTP `HEAD` через `websocket-stream`; успех — статус `200..400` |
| `dns` | DNS-обмен через `websocket-packet`; проверяет UDP data path |
| `tcp` | подключение через туннель к TCP-сервису, который первым отправляет данные |
| `tls` | TLS handshake к заданному SNI через туннель, без HTTP-обмена |

Параметры проб (`[outline.probe]`):

| Ключ | По умолчанию | Значение |
|---|---|---|
| `interval_secs` | `120` | период цикла проб; верхняя граница — каждый цикл ждёт 70–100 % от него |
| `timeout_secs` | `10` | таймаут одной пробы |
| `max_concurrent` | `4` | параллельные задачи проб |
| `max_dials` | `2` | параллельные дозвоны проб |
| `min_failures` | `3` | провалов подряд до признания аплинка нездоровым; также серия успехов перед auto-failback |
| `attempts` | `1` | попыток на аплинк за цикл; каждая неудачная увеличивает счётчик провалов, успешная обнуляет его и увеличивает счётчик успехов. Значение больше 1 даёт предупреждение |
| `skip_when_active` | `true` | пропускать цикл для аплинка, по которому недавно шёл трафик (см. ниже) |
| `liveness_interval_secs` | `300` | при `skip_when_active` принудительно проводить цикл хотя бы так часто; `0` отключает |
| `endpoint_check` | `false` | проверка доступности эндпоинтов аплинка голым TCP (см. ниже) |
| `endpoint_check_timeout_ms` | `2000` | срок на эндпоинт для `endpoint_check`, включая резолв (минимум 100) |

`endpoint_check` параллельно подключается к каждому эндпоинту аплинка (primary + fallback'и, обе плоскости, без дублей по `host:port` и параметрам выхода). Он только ускоряет вердикт, к которому уже пришла обычная проба. Если ни один эндпоинт не принимает подключение и проба не прошла ни по одной плоскости, сбой считается сбоем хоста: аплинк помечается нездоровым после `min_failures` таких циклов без спуска по носителям (`h3 → h2 → h1`) и без ротации цепочки wire'ов, а список эндпоинтов попадает в `last_error`. Выключенный хост тогда обнаруживается за пару циклов вместо нескольких минут. Прошедшая проба перевешивает проверку: голый connect не отличает «сервера нет» от «новый TCP к нему отклоняют, пока трафик идёт по уже поднятому QUIC-носителю».

Проверка выполняется после пробы и только в циклах, где проба провалилась по всем плоскостям. Время обнаружения такое же, как при запуске первой, а здоровый аплинк не тратит лишнего подключения за цикл. На сервере каждая проверка — TCP-соединение, закрытое до ClientHello; при `interval_secs = 10` это было бы 8 640 в сутки на аплинк на клиента. На дашбордах `probe="endpoint"` в `outline_ws_probe_runs_total` / `outline_ws_probe_duration_seconds` в штатном режиме имеет почти нулевой rate; ненулевой rate значит, что аплинки проваливают пробы. Держите `endpoint_check_timeout_ms` заметно меньше `timeout_secs`: он платится поверх уже проваленного цикла, а мёртвый хост стоит полного срока, потому что на SYN в чёрную дыру RST не приходит.

Тайминг проб:

- Пробы идут по таймеру `interval_secs`.
- Когда runtime-сбой ставит новый cooldown, probe loop будится сразу (внутренний `Notify`, не чаще раза в 15 с на аплинк и транспорт), и failover подтверждается в пределах одного цикла, а не на следующем плановом.
- Пропуск проб при трафике (`skip_when_active = true`, все области маршрутизации): цикл для аплинка пропускается, если по нему за последние `interval_secs` был TCP-трафик, аплинк здоров по пробам и runtime cooldown не действует. Проба всё равно выполняется, если недавно был chunk-0 сбой (`chunk0_failure_window_secs`, по умолчанию 300) или с последнего полного цикла прошло `liveness_interval_secs`. Нездоровый аплинк пробуется всегда: только проба возвращает его в строй.

Проверка warm-standby: раз в 15 с standby-соединения проверяются неблокирующим чтением с таймаутом 1 мс. EOF, close frame или ошибка очищают слот и запускают пополнение; таймаут (нет данных за 1 мс) значит, что соединение открыто.

Включение проб:

- пробы работают только при заданных настройках проб;
- один `[outline.probe]` не включает ни одной проверки;
- нужен хотя бы один из `[outline.probe.ws]`, `.http`, `.dns`, `.tcp` или `.tls`.

Аплинки без `udp_ws_url` — только TCP: UDP-состояние здоровья и standby-слоты для них не создаются, исходы UDP-проб не влияют на их UDP-метрику здоровья.

## IPv6

Поддерживается:

- IPv6-цели SOCKS5
- upstream URL с IPv6-литералом, например `wss://[2001:db8::10]/SECRET/tcp`
- IPv6-пробы
- IPv6-слушатели
- IPv6 UDP-пакеты в TUN-режиме
- IPv6 upstream-транспорт для `h2` и `h3`

## TUN-режим

Процесс подключается к существующему TUN-устройству. Создание интерфейса, адреса, маршруты и policy routing настраиваются вне приложения.

### tun2udp

- пересылка UDP по IPv4 и IPv6
- сборка IPv4- и IPv6-фрагментов на входе с TUN
- локальные ICMP echo reply для IPv4 (`ping`)
- локальные ICMPv6 echo reply, с фрагментацией у источника до минимального MTU IPv6 при необходимости
- опциональная привязка этих ответов к здоровью группы (`tun_suppress_icmp_reply_when_down` у группы аплинков): ping'и, маршрутизируемые в группу, не получают ответа, пока в группе нет здорового аплинка, — внешний watchdog видит мёртвый туннель
- эта привязка требует ещё и свежести вердикта (`tun_icmp_liveness_window_secs`). Ответ генерируется локально — ping не покидает хост — и доказывает только то, что этот цикл работает, а флаг `healthy` сохраняет последнее значение, если probe loop умер. С окном нужно ещё, чтобы какой-то здоровый аплинк в его пределах пронёс трафик или завершил цикл проб; иначе ответ не отправляется и считается как `icmp_reply_suppressed_stale`. Без значения окно равно `max(3 × interval, liveness_interval + 60s, 60s)`; `0` — проверяется только флаг здоровья; у групп без проб проверка свежести не выполняется
- IPv6 UDP и ICMPv6 через поддерживаемые цепочки extension header'ов
- транспорт через аплинк на каждый флоу
- очистка простаивающих флоу (`[tun] idle_timeout_secs`, по умолчанию 300)
- лимит числа флоу (`max_flows`, по умолчанию 4096) с вытеснением давно не виденного флоу
- метрики флоу и исходов пакетов, включая локальные ICMP-ответы

### tun2tcp

- userspace TCP-реле через Outline TCP-аплинки
- обработка SYN / SYN-ACK / FIN / RST
- буферизация out-of-order сегментов
- соблюдение receive window
- SACK-aware приём и отправка
- adaptive RTO
- zero-window persist/backoff
- ограниченные буферы и бюджет ретрансмитов (`[tun.tcp] max_retransmits`, по умолчанию 12)
- завершение флоу по таймауту, переполнению или сбою реле
- транспортные ошибки идут в систему штрафов аплинка: резкие закрытия upstream'а (например, QUIC `APPLICATION_CLOSE` / `H3_INTERNAL_ERROR`) передаются в `report_runtime_failure`, поэтому даунгрейд H3→H2 и штраф действуют на TUN TCP-флоу так же, как на SOCKS5; чистые закрытия WebSocket (FIN или Close frame) сбоями не считаются

`tun2tcp` не эквивалентен ядерному TCP-стеку.

### Bypass IKE / IPsec NAT-T

`tun.ipsec_bypass = true` отправляет UDP-флоу с портом назначения 500 или 4500 в direct-путь (как `via = "direct"`) мимо policy routing. VoWiFi и другие IKEv2/IPsec-клиенты тогда достают свой шлюз через ESP-in-UDP; голый ESP (IP protocol 50) отбрасывается всегда, потому что TUN-классификатор пропускает только TCP/UDP/ICMP.

Bypass использует локальный сокет direct-пути. На хостах, где TUN держит маршрут по умолчанию, этот сокет вернулся бы в TUN: на Linux задайте `direct_fwmark` и добавьте `ip rule fwmark <mark> lookup <table>`, где `<mark>` — значение `direct_fwmark`, а `<table>` — таблица маршрутизации с физическим маршрутом по умолчанию. Без `direct_fwmark` при старте пишется предупреждение.

По умолчанию `false`. Порты матчатся вместе: IKEv2 переносит IKE_AUTH с 500 на 4500 посреди сессии через NAT_DETECTION, и bypass одного 4500 ломает рукопожатие.

### Миграция носителя (переживаем смерть носителя)

Туннелируемый TUN-флоу не владеет своим транспортом: он делит один носитель — одно H3/H2/H1-соединение — с остальными флоу этого аплинка. Когда носитель рушится (ошибка уровня H3-соединения разом обрывает всё, что на нём мультиплексировано), все флоу на нём теряют транспорт в один момент, и каждое приложение видит обрыв соединения.

Upstream-сокеты при этом живы. Сервер переносит каждый в реестр сирот под Session ID, выданным этому флоу, и держит 30 с ([`docs/SESSION-RESUMPTION.ru.md`](../outline-ss-rust/docs/SESSION-RESUMPTION.ru.md)). При `[tun.tcp] carrier_migration = true` (по умолчанию) флоу, чей носитель умер, дозванивается на новый, предъявляет свой Session ID, получает запаркованный upstream обратно и закрывает байтовый разрыв в обе стороны, прежде чем продолжить. Ack-Prefix Protocol (v1) сообщает клиенту, сколько uplink-байт сервер реально переслал, и клиент повторяет только хвост, потерянный в пути; Symmetric Downlink Replay (v2) возвращает downstream-байты, которые мёртвый носитель не доставил, и они отдаются приложению раньше всего, что пришлёт новый носитель. Приложение не видит обрыва: ни FIN, ни RST, ни дыры, ни дублированного байта.

Миграция срабатывает только при подтверждённом resume hit. Перезвон с ID может промахнуться — парковка истекла или у сервера выключено возобновление, — и при промахе сервер открывает к назначению новый upstream, байтовый поток которого начинается с нуля. Продолжить флоу на нём значило бы пришить новый поток к недочитанному и отдать приложению испорченные данные, похожие на корректные. Поэтому клиент мигрирует только тогда, когда сервер доказал подхват, прислав управляющий кадр v1, — а он шлёт его только после того, как забрал сироту. Capability-заголовок в ответе на upgrade доказательством не является: сервер возвращает его и при попадании, и при промахе. Всё остальное — промах, таймаут, неразбираемый кадр, повтор, который клиент уже не может воспроизвести байт в байт, обрезанный downstream-срез — уходит в обычное закрытие.

Следствия:

- Возобновление на сервере по умолчанию выключено (`[session_resumption] enabled` в outline-ss-rust). Сервер без него не выдаёт Session ID, его флоу к миграции не допускаются, и клиентская настройка там ни на что не влияет.
- Direct-флоу (`via = "direct"`) не мигрируют никогда: у них свой сокет до origin, носителя, с которого уходить, нет, и подхватывать нечего.
- Лимиты: не больше 2 попыток на флоу, ни одна не стартует позже 20 с после первой (TTL парковки на сервере — 30 с), кольцо повтора uplink ограничено 64 КиБ на флоу. Флоу, отправивший один чанк больше этого, теряет кольцо, не может доказать побайтовую точность и закрывается как раньше, а не возобновляется с дырой.
- Миграционный дозвон запрашивает заданный носитель аплинка, а не ограниченный. Смерть носителя, вызвавшая миграцию, сама засчитывается как runtime-сбой и опускает аплинк на ранг ниже (`ws_h3` → `ws_h2`) на `mode_downgrade_secs`. Если соблюдать это ограничение, каждый спасённый флоу до конца жизни ехал бы по TCP поверх TCP — живой флоу обратно наверх ничто не переносит, — и долгая загрузка, спасённая с мёртвого H3-носителя, ползла бы вместо переподключения на полной скорости. Если носитель действительно сломан, дозвон сам спускается `h3 → h2 → h1`. По той же причине миграция перезванивает в свой аплинк, а не в перевыбранный: смерть носителя могла отправить этот аплинк в cooldown.
- Счётчики в `outline_ws_tun_tcp_events_total{event=…}`: `carrier_migrated`, `carrier_migration_miss`, `carrier_migration_dial_failed`, `carrier_migration_replay_evicted`, `carrier_migration_replay_ahead`, `carrier_migration_downlink_truncated`, `carrier_migration_downlink_frame_invalid`, плюс по счётчику на каждую причину, по которой флоу оказался непригоден до всякого дозвона: `carrier_migration_disabled`, `carrier_migration_abandoned`, `carrier_migration_no_session_id`, `carrier_migration_no_replay_ring`, `carrier_migration_budget_spent`, `carrier_migration_deadline_passed`. Флоу, остановленный на предусловии, не дозванивается, поэтому без этих шести «миграция не пробовалась» выглядело бы так же, как «в этой сборке нет кода миграции».

`carrier_migration = false` возвращает прежнее поведение: мёртвый носитель сразу превращается в FIN/RST.

#### Операторский soft switch

Тот же механизм переносит живые TUN TCP-флоу через операторский soft switch: `POST /control/activate {"group":"…","uplink":"…","soft":true}` на группе с `mode = "active_passive"` и `shared_resume = true`.

В строгом `active_passive` у группы один активный аплинк, и флоу, оставшийся на другом, закрывается RST'ом (`event="global_switch"`). Soft switch заменяет это: reader upstream'а флоу закрывает старый носитель и затем дозванивается в новый активный аплинк со своим Session ID. Mesh-кластер делит один resume-scope, а ID несёт свой домашний шард, поэтому новый edge-узел ретранслирует на домашний узел, где запаркован upstream, и подхватывает его — то же правило подтверждённого попадания, тот же повтор v1/v2, тот же результат без FIN, RST, дыр и дублей. Всё, что не дотянуло до подтверждённого попадания, уходит в RST, который дал бы жёсткий switch.

Порядок «сначала закрыть, потом дозвониться» обязателен. В отличие от смерти носителя, здесь старый носитель здоров, а сервер паркует upstream только после закрытия этого носителя. Перезвон, пришедший первым, нашёл бы ID на живой сессии, получил бы `miss-unknown` и новый upstream — гарантированный промах. Закрытие носителя первым ставит флоу за барьер park-before-resume на сервере, который закрывает оставшуюся гонку. (По той же причине клиент шлёт `X-Xhttp-Fin` на XHTTP-носителях: собственного сигнала закрытия у них нет, а idle-проход для soft switch слишком поздний.)

- `soft` учитывается только на группе с `shared_resume`. В остальных случаях `/control/activate` превращает его в жёсткий switch и возвращает действующее значение в ответе.
- Счётчики в `outline_ws_tun_tcp_events_total{event=…}`: `soft_switch_migrated` и `soft_switch_migration_failed` (за последним следует обычное закрытие `global_switch`).

#### Какие перевыборы мигрируют, а какие бросают

Судьбу оставшегося флоу решает не то, кто сдвинул указатель, а то, собирается ли переключение его бросить. Публикуемый снимок несёт `SwitchIntent`:

| Intent | Кем выставляется | Живые флоу на старом аплинке |
| --- | --- | --- |
| `OperatorHard` | `/control/activate {"soft":false}`, жёсткий плановый перевыбор или любой soft-запрос, принудительно сделанный жёстким вне кластера | RST (`global_switch`) |
| `OperatorSoft` | `/control/activate {"soft":true}` на группе с `shared_resume` | миграция, при неудаче RST |
| `Failover` | failover по пробе, failover по runtime-сбою, auto-failback, failover по деградации носителя, failover по потерям, начальный выбор | миграция на группе с `shared_resume`, иначе RST |

Жёсткий switch бросает намеренно: в mesh-кластере мигрированная сессия ретранслируется обратно на домашний узел, а это и есть выводимый из работы узел, так что миграция сорвала бы вывод. При failover никто не решал, что сессии должны закончиться, а аплинк, с которого ушли, обычно и есть нездоровый — запаркованный upstream живёт на сервере, и mesh достаёт его с нового edge-узла без сломанного пути клиента. Вне кластера (`shared_resume = false`) ничего не мигрирует: подхватывать нечего, и дозвон только добавил бы задержку перед тем же закрытием.

#### TUN UDP-флоу

То же решение действует для туннелируемых UDP-флоу, с одним отличием: байтовой непрерывности нет, поэтому нет и правила подтверждённого попадания. Запаркованная UDP-сессия не хранит буфер пакетов в сторону upstream, и промах resume стоит нового исходящего порта на выходе — никогда не сшитого байтового потока, из-за которого TCP-путь требует доказательства.

Попадание сохраняет сессию: сервер переводит запаркованные NAT-записи флоу (SS-UDP) или подхватывает его закреплённый сокет (VLESS-UDP), поэтому выход сохраняет исходящий порт, а NAT-привязка, path validation и состояние по адресу у собеседника переживают переключение. Uplink-задача флоу закрывает старый носитель — сначала reader, затем носитель, затем перезвон — по той же причине park-before-resume, что и в TCP.

- Счётчики в `outline_ws_tun_udp_events_total{event=…}`: `soft_switch_migrated`, `soft_switch_migrated_no_resume_id` (флоу перенесён, но сервер не выдал ему Session ID, поэтому исходящий порт на выходе сменился), `soft_switch_migration_failed` (перезвон не удался, флоу закрыт как при жёстком switch), `soft_switch_target_invalid`.
- Каждый туннелируемый UDP-флоу и каждая SOCKS5 UDP-ассоциация держат собственный resume-слот. TUN дозванивается отдельным носителем на каждый флоу; с прежним общим на процесс слотом `<resume-scope>#udp` новый флоу предъявлял запаркованный ID предыдущего, и попадание по нему было попаданием в чужую сессию.

### TUN PMTUD safety gate

Когда upstream-транспорт отказывается принять слишком большую UDP-датаграмму на TUN-пути (SS-UDP, VLESS-UDP, SS-2022, …), движок шлёт исходному отправителю ICMP «Fragmentation Needed» (IPv4) или «Packet Too Big» (IPv6), чтобы его PMTUD отреагировал, не чаще одного PTB в секунду на флоу. `tun.pmtud_emit_below_quic_initial` решает, может ли такой PTB объявлять path MTU ниже минимума Initial-датаграммы QUIC v1 (1200 v4 / 1280 v6, RFC 9000 §14.1).

По умолчанию `false`: такие PTB подавляются. QUIC-стеки воспринимают PTB ниже минимума как «это назначение не может нести QUIC» и уходят на TCP; с гейтом QUIC-трафик (YouTube, сервисы Google) остаётся на UDP, даже когда бюджет датаграммы TUN-аплинка чуть ниже 1200 байт. Слишком большая датаграмма отбрасывается молча, отправитель подстраивается своими ретрансмитами и таймаутами.

`tun.pmtud_emit_below_quic_initial = true` шлёт PTB всегда. Включайте там, где уход QUIC на TCP не важен, а сигнал PMTUD на каждом отбросе важен, — например, на VoWiFi / IKEv2-концентраторе, где IKE_AUTH с сертификатами идёт через узкий аплинк и PTB — единственный способ для IKE узнать MTU туннеля. Полный контракт: [docs/TUN-PMTUD.ru.md](docs/TUN-PMTUD.ru.md).

## Linux fwmark

`fwmark` аплинка ставит `SO_MARK` на исходящие сокеты:

- TCP-сокеты WebSocket по HTTP/1.1
- TCP-сокеты WebSocket по HTTP/2
- UDP-сокеты QUIC для HTTP/3
- дозвоны проб
- warm-standby соединения

Требования:

- только Linux
- `CAP_NET_ADMIN`
- под systemd `PrivateUsers=no`: `setsockopt(SO_MARK)` проверяется против user namespace, которому принадлежит сетевой стек (init namespace). При `PrivateUsers=true` capability действует только внутри приватного namespace, и каждый помеченный дозвон падает с `EPERM`. Относится и к `fwmark` аплинка, и к top-level `direct_fwmark`.

## Метрики

Multi-instance дашборд не входит в этот бинарь. Его отдаёт сервис `outline-ui`, который собирает control API всех инстансов; см. [`bins/outline-ui/README.ru.md`](../outline-ui/README.ru.md). Этот бинарь отдаёт эндпоинт метрик только для чтения и аутентифицированный control plane.

При заданном `[metrics]` процесс отдаёт:

- `/metrics` — текстовый формат Prometheus

```bash
curl http://[::1]:9090/metrics
```

У слушателя метрик нет изменяющих эндпоинтов; `/switch` и остальные живут на отдельном аутентифицированном control-слушателе, поэтому доступ на чтение метрик не даёт права переключать активный аплинк.

Пример scrape-конфига Prometheus:

```yaml
scrape_configs:
  - job_name: outline-ws-rust
    metrics_path: /metrics
    static_configs:
      - targets:
          - "[::1]:9090"
```

Группы метрик:

- информация о сборке и старте
- gauge'и резидентной памяти и кучи процесса
- SOCKS5-запросы и активные сессии, включая `command="connect"`, `command="udp_associate"` и `command="udp_in_tcp"`
- гистограмма длительности сессий
- байты payload и UDP-датаграммы
- отбросы слишком больших UDP-пакетов в обе стороны
- здоровье аплинков, задержка, EWMA RTT, штрафы, скор, cooldown, готовность standby. `uplink_health` равен `1` (здоров) или `0` (нездоров) только после того, как проба подтвердила состояние; до первого цикла проб серии нет, и это значит «неизвестно», а не «нездоров».
- состояние policy routing и выбора активного аплинка
- результаты и задержка проб
- исходы получения и пополнения warm-standby
- метрики TUN-флоу и пакетов
- метрики `tun2tcp`: ретрансмиты, backlog, окно, RTT и RTO

На Linux сэмплер памяти процесса обновляет:

- `outline_ws_process_resident_memory_bytes`
- `outline_ws_process_virtual_memory_bytes`
- `outline_ws_process_heap_allocated_bytes`
- `outline_ws_process_heap_mode_info{mode}`
- `outline_ws_process_open_fds`
- `outline_ws_process_threads`

С фичей `jemalloc` (по умолчанию) значения кучи берутся из собственных счётчиков jemalloc (`stats.allocated` / `stats.resident`), и `heap_mode_info{mode="exact"}` равен `1`. Сборки без jemalloc оценивают кучу по `VmData` (`mode="estimated"`); сборки не под Linux отдают `mode="unavailable"`.

На Linux процесс также периодически пишет в лог опись дескрипторов `process fd snapshot`: число открытых FD и разбивку на сокеты, pipe'ы, anon inode, обычные файлы и прочее.

`outline_ws_selection_mode_info{mode}`, `outline_ws_routing_scope_info{scope}`, `outline_ws_global_active_uplink_info{uplink}` и `outline_ws_sticky_routes` показывают конфигурацию селектора и состояние активного аплинка.

`outline_ws_group_bypass_active{group, transport}` показывает состояние `bypass_when_down`: `1`, пока новые флоу этого транспорта идут direct, потому что в группе нет здорового аплинка, `0`, пока трафик идёт в туннель. Серия есть только у групп с `bypass_when_down = true`. Дашборд outline-ui показывает то же состояние чипом в заголовке группы (`bypass armed` / `bypass: direct`); в дашборде Grafana это панели «Direct Bypass (bypass_when_down)» и «Direct Bypass Timeline» в разделе Routing Policy.

Учёт открытых соединений по аплинкам — для соединений, утекающих в неактивный аплинк после переключения `global` / `per_uplink`:

- `outline_ws_uplink_open_connections{group, transport, uplink}` — gauge открытых upstream-транспортов по аплинку. После переключения новый активный аплинк набирает соединения, старый их сливает; серия, которая не опускается, — признак утечки.
- `outline_ws_uplink_connection_close_total{group, transport, uplink, classification}` — счётчик закрытий upstream-транспортов, классифицированных в момент закрытия: `active` (аплинк ещё был активным), `inactive` (указатель активного уже ушёл — сливается оставшаяся сессия) или `unknown` (scope `per_flow`, указателя нет). `rate(...{classification="inactive"}[5m])` — скорость слива после переключения; устойчиво ненулевое значение вне недавнего переключения указывает на устаревший sticky-маршрут или warm-standby пул.

Обе метрики выведены в строку Grafana «Inactive Uplink Leak (Global / Per-Uplink)» в `grafana/outline-ws-rust-dashboard.json`. Соединения проб не учитываются; метрики покрывают только дозвоны пользовательского трафика.

`outline_ws_carrier_writer_terminations_total{writer, reason}` считает writer-задачи WebSocket-носителя, остановившиеся из-за ошибки записи. `writer` — `ss` (SS поверх WS) или `frame` (writer VLESS-чанков / датаграмм); `reason` — `peer_closed`, если носитель уже был закрыт (штатно, лог на `debug`), или `error` для настоящей ошибки записи (лог на `warn`). Устойчивый rate `reason="error"` значит, что аплинк не может писать. Строка Grafana: «Carrier Writer Terminations».

Прочие счётчики:

- `outline_ws_tun_udp_forward_errors_total{reason}` — TUN UDP-пакеты, которые не удалось отправить в upstream: `all_uplinks_failed`, `transport_error`, `connect_failed`, `other`.
- `outline_ws_udp_oversized_dropped_total{direction="up|down", cause}` — слишком большие UDP-пакеты, отброшенные до отправки в аплинк (`up`) или до доставки клиенту (`down`); `cause` — `socks_client`, `socks_relay`, `socks_direct`, `socks_in_tcp`, `ss_socket`, `vless_udp` или `xhttp_records`.
- `outline_ws_udp_malformed_dropped_total{cause}` — клиентские датаграммы, которые SOCKS5 UDP ingress не может разобрать; отбрасываются поштучно, ассоциация продолжает работать: `parse` (испорченный SOCKS5 UDP-заголовок или неподдерживаемый тип адреса), `reassembly` (последовательность фрагментов не по порядку, со сменой цели или сверх лимита сборки).
- `outline_ws_uplink_payload_integrity_errors_total{transport, group, uplink, cause}` — downlink-датаграммы, не прошедшие проверку целостности payload: `decrypt_failed`, `packet_too_short`, `udp_out_of_order` (replay/reorder в SS2022). Отделён от `outline_ws_uplink_runtime_failures_total`: испорченный payload говорит о байтах, а не о носителе, поэтому не даёт cooldown, штрафа, серии runtime-сбоев и даунгрейда носителя (`xhttp_h3 → xhttp_h2`). Закрывается только затронутый флоу: на TUN UDP-пути — с причиной `payload_error` (пересоздаётся следующим пакетом); на SOCKS5 UDP downlink датаграмма отбрасывается, а ассоциация сохраняет транспорт. Когда такие ошибки списывались на носитель, боевой аплинк 69,6 % времени работал на UDP поверх TCP при доле испорченных датаграмм ~0,1 %. Растущий rate — всё равно дефект, но за носителем; смотрите его на отдельной панели, а не на графике failover.
- `outline_ws_tun_icmp_local_replies_total{ip_family}` — локальные ICMP echo reply.

На TUN UDP-пути отбросы слишком больших пакетов дополнительно порождают ICMP PTB отправителю; см. [TUN PMTUD safety gate](#tun-pmtud-safety-gate) и [docs/TUN-PMTUD.ru.md](docs/TUN-PMTUD.ru.md).

Дашборды Grafana (см. [`grafana/README.md`](grafana/README.md)):

- [`grafana/outline-ws-rust-dashboard.json`](grafana/outline-ws-rust-dashboard.json)
- [`grafana/outline-ws-rust-hang-diagnostics.json`](grafana/outline-ws-rust-hang-diagnostics.json)

## Control plane

При заданном `[control]` процесс отдаёт изменяющие эндпоинты на отдельном TCP-слушателе, который требует bearer-токен:

| Метод и путь | Назначение |
|---|---|
| `GET /control/topology` | топология инстанс / группа / аплинк для дашбордов |
| `GET /control/summary` | компактные счётчики здоровья групп и аплинков |
| `POST /control/activate` | JSON API активации (действия по клику в дашборде) |
| `POST /control/reselect` | взвешенно-случайный перевыбор строгого активного аплинка группы сейчас — та же ротация, что `reselect_at` / `reselect_interval` делают по расписанию. Тело `{"group":"main","soft":true}` (`soft` по умолчанию `true`) |
| `POST /control/uplink_enabled` | административно включить/выключить аплинк. Тело `{"group":"main","uplink":"backup","enabled":false}`. Выключенный аплинк исключается из проб, выбора кандидатов, failover и пополнения standby до повторного включения; если он был активным, трафик сразу уходит на включённый аплинк. Не сохраняется: после рестарта все аплинки включены. В дашборде outline-ui — кнопка питания у аплинка (Enable / Disable) |
| `GET` / `POST` / `PATCH` / `DELETE /control/uplinks`, `POST /control/uplinks/reorder` | подготовка правок `[[outline.uplinks]]` в файле конфига |
| `GET` / `POST` / `PATCH` / `DELETE /control/uplink_groups`, `POST /control/uplink_groups/reorder` | подготовка правок `[[uplink_group]]` в файле конфига (см. «`/control/uplink_groups` (CRUD)» в [docs/UPLINK-CONFIGURATIONS.ru.md](docs/UPLINK-CONFIGURATIONS.ru.md)) |
| `GET` / `POST` / `PATCH` / `DELETE /control/routes`, `POST /control/routes/reorder` | подготовка правок `[[route]]`; reorder перемещает правило в списке first-match-wins |
| `GET` / `PATCH /control/config` | чтение и изменение настроек подсистем клиента в файле конфига (`[probe]`, `[socks5]`, `[tun]`, `[dial]`, `[padding]`, `[quic]`, `[h2]`, `[tcp_timeouts]`, `fingerprint_profile`, `prefer_public_ipv6_src`, `direct_fwmark`). Возвращает `{ "status": "ok", "apply_required": true, "restart_required": bool }`. Перед записью `PATCH` загружает изменённый файл так же, как это делает старт; если он не загрузится (например, `tun.mtu` меньше 1280 или `dial.timeout_secs = 0`), запрос получает `400` с ошибкой загрузчика, а файл на диске остаётся прежним |
| `POST /control/apply` | применить без рестарта подготовленные правки аплинков и групп, а также маршрутов, если маршрутизация была настроена при старте |
| `GET /control/alloc` | статистика аллокатора (счётчики jemalloc в сборке по умолчанию) |
| `POST /switch` | ручное переопределение активного аплинка |

Запросы без совпадающего заголовка `Authorization: Bearer <token>` отклоняются с `401 Unauthorized` до чтения тела; анонимного доступа нет.

### Конфигурация

Задайте `listen` и токен в `[control]` либо передайте `--control-listen` (`CONTROL_LISTEN`) вместе с `--control-token` (`CONTROL_TOKEN`). Токен можно читать из файла через `token_file = "..."` (путь относительно файла конфига). Только одна из двух половин — ошибка старта.

Привязывайте control-слушатель к loopback или management VLAN; токен не заменяет сетевую изоляцию.

### Ручное переключение активного аплинка

`POST /switch` закрепляет активный аплинк группы `active_passive`, не дожидаясь probe loop. Выбор сохраняется через state store (если он настроен) и переживает рестарт.

Query-параметры:

- `uplink` (обязательный) — имя аплинка, который нужно активировать.
- `group` (опциональный) — целевая группа. Без него поиск идёт по всем группам (имена аплинков глобально уникальны).
- `transport` (опциональный) — `tcp`, `udp` или `both` (по умолчанию). Учитывается только при `routing_scope = per_uplink`; в `global` игнорируется.

```bash
TOKEN="long-random-secret"

# Переключить единственную группу на аплинк "backup"
# (оба транспорта в режиме per_uplink)
curl -XPOST -H "Authorization: Bearer $TOKEN" \
  'http://127.0.0.1:9091/switch?uplink=backup'

# В режиме per_uplink переключить только UDP
curl -XPOST -H "Authorization: Bearer $TOKEN" \
  'http://127.0.0.1:9091/switch?uplink=backup&transport=udp'

# Явно указать группу
curl -XPOST -H "Authorization: Bearer $TOKEN" \
  'http://127.0.0.1:9091/switch?group=main&uplink=backup'
```

Ответы: `200` при успехе; `400`, если аплинк или группа неизвестны или группа не в режиме `active_passive`; `401`, если bearer-токен отсутствует или неверен; `405` для методов кроме POST. Переопределение действует, пока выбранный аплинк здоров; когда probe loop пометит его нездоровым, работает обычный failover. При `auto_failback = true` цикл может вернуться на аплинк с большим приоритетом, когда тот стабилизируется.

### Control API для дашбордов

`GET /control/topology` возвращает группы и аплинки в JSON, включая булевы `active_global`, `active_tcp`, `active_udp` у каждого аплинка, для дашборда outline-ui или других клиентов control plane.

`GET /control/summary` возвращает счётчики: `groups_total`, `uplinks_total`, число здоровых/нездоровых по TCP/UDP и счётчики активного выбора.

`POST /control/activate` принимает JSON и использует ту же логику переключения, что `/switch`:

```json
{
  "group": "core",
  "uplink": "uplink-02",
  "transport": "tcp"
}
```

`POST /control/reselect` выполняет взвешенно-случайный перевыбор, который `reselect_at` / `reselect_interval` делают по расписанию, вне расписания. Применим к группе `active_passive` с одним строгим активным слотом (scope `global` или `per_uplink`); остальные группы возвращают `outcome: "skipped"`.

```json
{
  "group": "main",
  "soft": true
}
```

`soft` по умолчанию `true` и запрашивает переключение с сохранением сессий через cluster resume; на группе без `shared_resume` переключение становится жёстким, как в `/control/activate`. Ответ содержит действующее значение `soft` и имена аплинков `from` / `to`, если слот сдвинулся:

```json
{
  "group": "main",
  "outcome": "switched",
  "from": "uplink-01",
  "to": "uplink-02",
  "soft": true
}
```

`outcome` — `switched`, `no_candidate` (не осталось подходящего аплинка после исключения текущего активного и выключенных / нездоровых / находящихся в cooldown) или `skipped` (группа не `active_passive` или у неё нет одного строгого активного слота). В дашборде outline-ui это кнопка группы **Reselect**; в отличие от soft switch, она показывается независимо от `cluster_resume_enabled`.

`/control/uplinks` правит массив `[[outline.uplinks]]` в TOML-файле на диске. Ответы на изменения содержат `apply_required: true`, если `/control/apply` может активировать подготовленную правку; `restart_required` зарезервирован для правок, которые нельзя применить на ходу.

`/control/routes` правит массив `[[route]]` так же, но по индексу в массиве, а не по имени (у правила нет ключа идентичности), с оптимистичной проверкой `revision`: устаревший индекс от параллельной правки отвергается, а не сдвигает чужое правило. `POST /control/routes/reorder` переносит одно правило на новый индекс, потому что first-match-wins зависит от порядка. `POST /control/apply` применяет подготовленную правку маршрутов так же, как правку аплинков, но только если `[[route]]` был при старте процесса. Включение policy routing на узле, стартовавшем без него (всё через первую группу), требует рестарта: живой таблицы маршрутизации для подмены нет.

```bash
TOKEN="long-random-secret"

curl -H "Authorization: Bearer $TOKEN" \
  'http://127.0.0.1:9091/control/topology'

curl -H "Authorization: Bearer $TOKEN" \
  'http://127.0.0.1:9091/control/summary'

curl -XPOST -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"group":"core","uplink":"uplink-02","transport":"tcp"}' \
  'http://127.0.0.1:9091/control/activate'
```

## Production-эксплуатация

### `install-client.sh`

[install-client.sh](../../install-client.sh) устанавливает клиент на Linux x86-64 или AArch64 из GitHub-релизов. Запускайте от `root` на целевом хосте:

```bash
curl -fsSL https://raw.githubusercontent.com/balookrd/outline-proxy/main/install-client.sh -o install-client.sh
chmod +x install-client.sh
./install-client.sh --help
sudo ./install-client.sh
```

Режимы:

```bash
sudo ./install-client.sh                       # последний stable-релиз (новейший тег ws-v*)
sudo ./install-client.sh --force               # переустановить, даже если версия совпадает
sudo CHANNEL=nightly ./install-client.sh       # rolling prerelease ws-nightly
sudo VERSION=v1.2.3 ./install-client.sh        # закрепить stable-версию (тег ws-v1.2.3)
sudo ./install-client.sh --remove              # алиас --uninstall
sudo ./install-client.sh --purge
```

Что делает скрипт:

- выбирает артефакт релиза по `uname -m` (`x86_64`/`amd64` → `x86_64-unknown-linux-musl`, `aarch64`/`arm64` → `aarch64-unknown-linux-musl`); другие архитектуры отвергает
- не скачивает, если установленная версия совпадает с выбранным релизом (`--force` или `FORCE=1` отменяют проверку); для nightly отслеживает SHA коммита релиза в `/etc/outline-ws-rust/nightly-commit`
- ставит бинарь в `/usr/local/bin/outline-ws-rust`, предыдущий сохраняет как `<path>.bak.<timestamp>`
- ставит `outline-ws-rust.service` и `outline-ws-rust@.service` в `/etc/systemd/system`, взятые из того же релизного тега, что и бинарь
- создаёт системного пользователя и группу `outline-ws`, каталоги `/etc/outline-ws-rust` и `/var/lib/outline-ws-rust` и отдаёт каталог конфигурации `outline-ws` (`0750`, файлы `0640`), чтобы control API мог писать конфиг
- скачивает `config.toml` и `instances/example.toml`, только если их ещё нет
- перезапускает только те unit'ы `outline-ws-rust`, что были активны; новый сервис не включает и не запускает, остановленный остаётся остановленным

После первой установки:

1. Отредактируйте `/etc/outline-ws-rust/config.toml`.
2. Включите один из вариантов:
   - один инстанс: `sudo systemctl enable --now outline-ws-rust.service`
   - именованный инстанс (конфиг `/etc/outline-ws-rust/instances/<name>.toml`): `sudo systemctl enable --now outline-ws-rust@<name>.service`
3. Проверьте статус: `systemctl status outline-ws-rust --no-pager`.
4. Проверьте логи: `journalctl -u outline-ws-rust -e --no-pager`.

Для обновления запустите скрипт ещё раз; бинарь заменяется, только если выбранный релиз отличается от установленного.

Переменные окружения:

| Переменная | По умолчанию | Значение |
|---|---|---|
| `CHANNEL` | `stable` | `stable` или `nightly` |
| `VERSION` | последняя | stable: `1.2.3` или `v1.2.3`; при `CHANNEL=nightly` допустимо только `nightly` |
| `FORCE` | пусто | `1` — переустановить, даже если версия совпадает |
| `INSTALL_PATH` | `/usr/local/bin/outline-ws-rust` | полный путь устанавливаемого бинаря |
| `CONFIG_DIR` | `/etc/outline-ws-rust` | каталог конфигурации |
| `STATE_DIR` | `/var/lib/outline-ws-rust` | каталог состояния |
| `SERVICE_USER` / `SERVICE_GROUP` | `outline-ws` | системный пользователь и группа сервиса |
| `GITHUB_TOKEN` | пусто | GitHub-токен против rate limit API |

Удаление:

- `--remove` (алиас `--uninstall`): останавливает и отключает `outline-ws-rust.service` и все `outline-ws-rust@<name>.service`, удаляет оба unit-файла (с последующим `daemon-reload`), бинарь и его `.bak.*`. Оставляет `/etc/outline-ws-rust` (включая `instances/`), `/var/lib/outline-ws-rust` и пользователя/группу `outline-ws`, чтобы переустановка подхватила конфиг.
- `--purge`: всё, что делает `--remove`, плюс удаляет `/etc/outline-ws-rust`, `/var/lib/outline-ws-rust` и пользователя/группу `outline-ws`.

Оба режима идемпотентны: отсутствующие артефакты пропускаются.

#### Установка через HTTP(S) прокси

Если `github.com` или его CDN релизов (`objects.githubusercontent.com`) недоступны с хоста, запустите установку через HTTP- или SOCKS5-прокси с доступом к GitHub; `curl` в скрипте учитывает стандартные переменные прокси.

`sudo` по умолчанию сбрасывает `http_proxy` / `https_proxy`, поэтому передайте их явно:

```bash
sudo https_proxy=http://HOST:PORT http_proxy=http://HOST:PORT ./install-client.sh
```

либо экспортируйте и используйте `sudo -E`:

```bash
export https_proxy=http://HOST:PORT
export http_proxy=http://HOST:PORT
sudo -E ./install-client.sh
```

Для SOCKS5 (например, туннель `ssh -D 1080 user@vps`) используйте `ALL_PROXY=socks5h://HOST:PORT`. Прокси с аутентификацией: `http://USER:PASS@HOST:PORT` (спецсимволы в пароле — URL-encode).

Проверьте прокси перед запуском установщика:

```bash
curl -v --proxy http://HOST:PORT --max-time 20 https://github.com -o /dev/null
```

### systemd

Юниты:

- [`systemd/outline-ws-rust.service`](systemd/outline-ws-rust.service) — один инстанс, конфиг `/etc/outline-ws-rust/config.toml`, состояние в `/var/lib/outline-ws-rust/_default/`
- [`systemd/outline-ws-rust@.service`](systemd/outline-ws-rust@.service) — шаблон именованного инстанса, конфиг `/etc/outline-ws-rust/instances/<name>.toml`, состояние в `/var/lib/outline-ws-rust/<name>/`

Ручная установка (`install-client.sh` делает то же самое):

1. Установите бинарь в `/usr/local/bin/outline-ws-rust`.
2. Создайте пользователя и группу сервиса:
   `sudo groupadd --system outline-ws && sudo useradd --system --no-create-home --shell /usr/sbin/nologin --gid outline-ws outline-ws`
3. Положите конфигурацию в `/etc/outline-ws-rust/config.toml` и отдайте каталог пользователю сервиса:
   `sudo chown -R outline-ws:outline-ws /etc/outline-ws-rust && sudo chmod 0750 /etc/outline-ws-rust`
4. Скопируйте оба unit-файла в `/etc/systemd/system/`.
5. Перечитайте конфигурацию systemd и включите сервис:
   `sudo systemctl daemon-reload && sudo systemctl enable --now outline-ws-rust`

Что задают юниты:

- `Restart=on-failure`, `RestartSec=3s`
- `RUST_LOG=info`, логи в journald
- `LimitNOFILE=1048576`, `LimitSTACK=8M`, `TasksMax=infinity`
- `MemoryHigh=70%`, `MemoryMax=85%`: на хосте с малым объёмом RAM всплеск флоу может исчерпать память быстрее, чем ядро её освободит, и подвесить весь хост; с лимитами ядро убивает по OOM сервис, и systemd его перезапускает. Для фиксированных значений переопределите drop-in'ом
- `User=outline-ws` / `Group=outline-ws` и `StateDirectory=outline-ws-rust/_default` (шаблон: `outline-ws-rust/%i`), чтобы у файлов состояния был постоянный владелец
- `ReadWritePaths` включает `/etc/outline-ws-rust` (шаблон: `/etc/outline-ws-rust/instances`), чтобы правки через control API и миграция конфига могли записать файл
- `AmbientCapabilities=CAP_NET_ADMIN` для `fwmark`; уберите обе строки с capability, если `fwmark` / `direct_fwmark` не используются. Для них нужен ещё `PrivateUsers=no` в drop-in'е: юниты задают `PrivateUsers=true`, а `SO_MARK` внутри приватного user namespace падает с `EPERM` даже при наличии capability
- `PrivateDevices=false` для доступа к `/dev/net/tun` (TUN-режим)
- `ProtectSystem=strict`, `ProtectHome=true`, `NoNewPrivileges=true`, `RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX`, `SystemCallFilter=@system-service` и остальные опции `Protect*` / `Restrict*` в файле юнита

Стеки потоков: worker- и blocking-потоки Tokio по умолчанию получают стек 2048 КиБ, а не наследуют лимит стека хоста (`--thread-stack-size-kb` / `THREAD_STACK_SIZE_KB`). Юнит одного инстанса задаёт `THREAD_STACK_SIZE_KB=512`; если нативный резолвер или глубокий FFI-вызов его переполнит, процесс упадёт при старте — увеличьте значение.

### Логирование

Сервис пишет логи через `tracing`; прилагаемые юниты задают `RUST_LOG=info`. `debug` включайте только для диагностики: события жизненного цикла соединений и транспорта становятся заметно многословнее.

Строки жизненного цикла носителя пишутся в target `outline_transport::conn_life` парами: у каждой `… connection opened` ровно одна `… connection closed` того же уровня, с `id`, `peer`, `mode`, `age_secs`, `streams` и `class`. Соединение, закрытое локально (проба, отпущенная после замера, кэшированный носитель, у которого закончился последний стрим), отчитывается собственным drop guard'ом как `class=local_drop`: driver-задача, ждущая закрытия на уровне протокола, при drop отменяется и отчитаться не может. Поскольку пары сходятся, утечка дескрипторов видна как разница между двумя счётчиками. До появления пар `opened` против `closed` на нагруженном узле давали 34 515 против 0 и выглядели в точности как утечка.

Общие (кэшированные) носители пишут пару на `info`; соединения проб — один дозвон на замер, десятки тысяч в сутки — пишут её на `debug`.

Два штатных события пишутся ниже `warn`, потому что ни одно не говорит о проблеме в этом процессе: остановка WS writer-задачи из-за уже закрытого носителя (считается в `outline_ws_carrier_writer_terminations_total{reason="peer_closed"}`) и разрыв HTTP-клиентом соединения со слушателем метрик / control до завершения запроса (`request aborted by client`). Настоящие ошибки записи и ошибки запросов остаются на `warn`.

### Безопасность

- Не открывайте `metrics.listen` без контроля доступа.
- `control.listen` ограничьте ещё строже: привяжите к loopback или management-сети, обращайтесь с bearer-токеном как с учётными данными (ротируйте, храните вне конфига через `token_file`) и не используйте для него порт метрик. Control-слушатель — единственный путь, которым можно изменить выбор активного аплинка.
- Встроенные ограничения слушателей против slowloris и простаивающих соединений (вкомпилированы, не настраиваются):

  | Слушатель | Максимум одновременных соединений | Таймаут |
  |---|---|---|
  | SOCKS5 | 4096 | 10 с на SOCKS5 handshake |
  | `/metrics` | 64 | 5 с на чтение заголовков запроса |
  | control | 16 | 5 с на чтение заголовков запроса; проверка bearer-токена идёт только после получения заголовков, поэтому именно этот таймаут не даёт неаутентифицированным клиентам держать сокеты |

- HTTP/3-носителям нужна доступность порта сервера по UDP.
- `fwmark` работает только на Linux и требует `CAP_NET_ADMIN` или root; в песочнице systemd с приватным user namespace нужен ещё `PrivateUsers=no`.
- TUN-режиму нужен доступ к `/dev/net/tun` (`PrivateDevices=false`).

## Тестирование

Из корня workspace:

```bash
cargo check -p outline-ws-rust
cargo test -p outline-ws-rust
```

CI-гейт (fmt, clippy, тесты, feature matrix) описан в корневом [`AGENTS.md`](../../AGENTS.md). End-to-end тесты против настоящих процессов `outline-ss-rust` (`tests/e2e_*.rs`) запускаются только с `RUN_E2E_FAILOVER=1`, а набор TLS/H3-носителей требует фичи `test-tls`:

```bash
RUN_E2E_FAILOVER=1 cargo test -p outline-ws-rust --features test-tls --test 'e2e_*' -- --test-threads=1
```

Ручные тесты против реального сервера есть для HTTP/1.1, HTTP/2 и HTTP/3 (`real_server_h1`, `real_server_h2`, `real_server_h3`); каждый пропускается, если его переменная `RUN_REAL_SERVER_*` не равна `1`:

```bash
RUN_REAL_SERVER_H2=1 \
OUTLINE_TCP_WS_URL='wss://example.com/SECRET/tcp' \
OUTLINE_UDP_WS_URL='wss://example.com/SECRET/udp' \
SHADOWSOCKS_PASSWORD='Secret0' \
cargo test -p outline-ws-rust --test real_server_h2 -- --nocapture
```

```bash
RUN_REAL_SERVER_H3=1 \
OUTLINE_TCP_WS_URL='wss://example.com/SECRET/tcp' \
OUTLINE_UDP_WS_URL='wss://example.com/SECRET/udp' \
SHADOWSOCKS_PASSWORD='Secret0' \
cargo test -p outline-ws-rust --test real_server_h3 -- --nocapture
```

Изоляция групп, fallback и direct-диспатч:

```bash
cargo test -p outline-ws-rust --test group_routing -- --nocapture
```

Warm standby:

```bash
cargo test -p outline-ws-rust --test standby_validation -- --nocapture
```

## Ссылки на протоколы

- [Outline `outline-ss-server`](https://github.com/Jigsaw-Code/outline-ss-server)
- [`hev-socks5-core`](https://github.com/heiher/hev-socks5-core)
- [`hev-socks5-tunnel`](https://github.com/heiher/hev-socks5-tunnel)
- [Спецификация Shadowsocks AEAD](https://shadowsocks.org/doc/aead.html)
- [RFC 8441: Bootstrapping WebSockets with HTTP/2](https://datatracker.ietf.org/doc/html/rfc8441)
- [RFC 9220: Bootstrapping WebSockets with HTTP/3](https://datatracker.ietf.org/doc/html/rfc9220)

## Отслеживание локальных патчей

Патчи vendored-крейтов (`vendor/h3`, `vendor/sockudo-ws`, `vendor/quinn-proto`, `vendor/rustls`, `vendor/hyper`) перечислены в общем для workspace [`PATCHES.ru.md`](../../PATCHES.ru.md), включая патч `h3` для RFC 9220.
