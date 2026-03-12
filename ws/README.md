# outline-ws-rust

Локальный SOCKS5-прокси на Rust, который:

- принимает TCP `CONNECT` и пересылает трафик на `outline-ss-server` через `websocket-stream`
- принимает SOCKS5 `UDP ASSOCIATE` и пересылает UDP через `websocket-packet`
- умеет читать пакеты из уже созданного TUN-устройства и пересылать UDP через `websocket-packet`
- содержит начальный stateful TCP-over-TUN path поверх Outline TCP uplink

Сейчас реализовано:

- SOCKS5 без аутентификации
- TCP `CONNECT`
- UDP `ASSOCIATE`
- Shadowsocks AEAD: `chacha20-ietf-poly1305`, `aes-128-gcm`, `aes-256-gcm`
- Подключение к `ws://` и `wss://` endpoint'ам Outline WebSocket transport
- Режимы WebSocket transport: HTTP/1.1 upgrade, RFC 8441 WebSocket over HTTP/2 и RFC 9220 WebSocket over HTTP/3/QUIC
- Конфигурация через `config.toml` с override через CLI/env
- Автоматический fallback transport-режимов: `h3 -> h2 -> http1`, `h2 -> http1`
- Несколько uplink с background health probes и ordered failover
- Fastest-first load balancing, sticky routing и hysteresis
- Warm-standby WebSocket connections для TCP и UDP uplink
- Existing TUN device mode для UDP traffic
- начальный stateful TCP-over-TUN path

Не реализовано:

- Username/password auth
- Shadowsocks 2022
- production-grade TCP relay через TUN

## Сборка

```bash
cargo build --release
```

## Конфиг

По умолчанию приложение читает [`config.toml`](/Users/mmalykhin/Documents/Playground/config.toml):

```toml
[socks5]
listen = "[::]:1080"

[status]
listen = "[::1]:9090"

[tun]
# Existing TUN device path. Provisioning stays on the OS side.
# Linux:
# path = "/dev/net/tun"
# name = "tun0"
# macOS / BSD:
# path = "/dev/tun0"
# mtu = 1500

[outline.probe]
interval_secs = 30
timeout_secs = 10
max_concurrent = 4
max_dials = 2

[outline.probe.ws]
enabled = true

[outline.probe.http]
url = "http://example.com/"

[outline.probe.dns]
server = "1.1.1.1"
port = 53
name = "example.com"

[outline.load_balancing]
warm_standby_tcp = 1
warm_standby_udp = 1
sticky_ttl_secs = 300
hysteresis_ms = 50
failure_cooldown_secs = 10
failure_penalty_ms = 500
failure_penalty_max_ms = 30000
failure_penalty_halflife_secs = 60

[[outline.uplinks]]
name = "primary"
tcp_ws_url = "wss://example.com/SECRET/tcp"
tcp_ws_mode = "h3"
udp_ws_url = "wss://example.com/SECRET/udp"
udp_ws_mode = "h3"
method = "chacha20-ietf-poly1305"
password = "Secret0"

[[outline.uplinks]]
name = "backup"
tcp_ws_url = "wss://backup.example.com/SECRET/tcp"
tcp_ws_mode = "h2"
udp_ws_url = "wss://backup.example.com/SECRET/udp"
udp_ws_mode = "h2"
method = "chacha20-ietf-poly1305"
password = "Secret0"
```

`tcp_ws_mode` и `udp_ws_mode` принимают `http1`, `h2` или `h3`. Старый single-uplink формат `[outline] tcp_ws_url=...` тоже всё ещё поддержан. CLI-флаги `--tcp-ws-url`, `--udp-ws-url`, `--method`, `--password` по-прежнему работают и создают один runtime uplink поверх файла.

Рекомендация:

- оставляй `http1` как fallback по умолчанию
- включай `h2` только если upstream действительно поддерживает RFC 8441 Extended CONNECT для WebSocket
- включай `h3` только если upstream действительно поддерживает RFC 9220 поверх QUIC и до него открыт UDP
- если `h2` не поднимается, сначала переключись обратно на `http1`, затем проверяй поддержку RFC 8441 на балансировщике или origin-сервере
- если `h3` не поднимается, сначала проверь, что endpoint доступен по `wss://`, сервер advertises ALPN `h3`, а UDP/QUIC не режется на пути

Если выбран `h3`, клиент сначала пробует RFC 9220, затем автоматически откатывается на `h2`, а затем на обычный HTTP/1.1 upgrade. Если выбран `h2`, при неудаче клиент автоматически откатывается на HTTP/1.1.

## Несколько uplink и probes

Каждый uplink имеет собственные:

- `tcp_ws_url` / `tcp_ws_mode`
- `udp_ws_url` / `udp_ws_mode`
- `method`
- `password`
- опциональный `fwmark` для Linux policy routing

Логика выбора такая:

- базовый probe делает `WebSocket Ping -> Pong` на каждом `tcp_ws_url` и `udp_ws_url`
- background probe периодически проверяет каждый uplink
- `max_concurrent` ограничивает число одновременно исполняемых probe-задач
- `max_dials` ограничивает только probe websocket dials и изолирует их от пользовательского и warm-standby path
- для TCP probe используется реальный HTTP-запрос через `websocket-stream`
- для UDP probe используется реальный DNS-запрос через `websocket-packet`
- healthy uplink сортируются fastest-first по последней измеренной latency
- `warm_standby_tcp` и `warm_standby_udp` держат заранее открытые idle WebSocket-соединения на каждый uplink
- standby-соединение забирается первым, а пул пополняется в фоне
- failure penalty model добавляет штраф к latency после probe/runtime ошибок и плавно уменьшает его по `failure_penalty_halflife_secs`
- sticky routing закрепляет target за выбранным uplink на `sticky_ttl_secs`
- hysteresis не даёт переключаться на другой uplink, если он быстрее меньше чем на `hysteresis_ms`
- runtime failover сразу помечает упавший uplink unhealthy на `failure_cooldown_secs`
- при пользовательском запросе прокси сначала выбирает лучший healthy uplink
- если выбранный uplink не поднимается, запрос автоматически пробует следующий uplink по порядку
- для UDP runtime failover делает мгновенное переключение на следующий uplink при `send/read` ошибке

Текущее ограничение probes:

- probes вообще не запускаются, если секция `[outline.probe]` не настроена явно
- секция `[outline.probe]` сама по себе ничего не включает: должен быть явно настроен хотя бы один из `ws`, `http` или `dns`
- `ws` probe включается только через `[outline.probe.ws]` и проверяет только сам WebSocket transport, не прикладной маршрут Shadowsocks
- HTTP probe сейчас поддерживает только `http://` URL, не `https://`
- DNS probe требует `udp_ws_url`

Замечание по runtime failover:

- UDP переключается прозрачно в рамках живой association
- TCP можно безопасно переключать только до начала полезного обмена; уже установленный TCP tunnel нельзя бесшовно мигрировать на другой uplink без переподключения на стороне клиента

## IPv6

Поддерживаются:

- SOCKS5 target address `ATYP=IPv6`
- uplink URL с IPv6 literal, например `wss://[2001:db8::10]/SECRET/tcp`
- `h2` и `h3` transport к IPv6 upstream
- HTTP/DNS probes к IPv6 target/server
- IPv6 listen/bind, например `listen = "[::1]:1080"` или `listen = "[::]:1080"`
- IPv6 UDP packets from TUN mode

## TUN

Приложение умеет работать с уже существующим TUN-устройством. Создание интерфейса, назначение адресов и настройка маршрутов остаются на стороне ОС.

Пример конфига:

```toml
[tun]
path = "/dev/net/tun"
name = "tun0"
mtu = 1500
max_flows = 4096
idle_timeout_secs = 300
```

CLI override:

```bash
cargo run --release -- \
  --config ./config.toml \
  --tun-path /dev/net/tun \
  --tun-name tun0 \
  --tun-mtu 1500
```

Текущее поведение TUN path:

- поддерживаются IPv4 и IPv6 UDP пакеты
- для каждого UDP flow поднимается отдельный uplink transport с тем же runtime failover, что и у обычного UDP path
- ответы с uplink инкапсулируются обратно в IPv4/IPv6 UDP packets и пишутся в TUN
- idle flow автоматически очищаются по `idle_timeout_secs`
- число одновременно живых UDP flow ограничивается `max_flows`; при переполнении вытесняется самый старый flow
- TCP packets идут в отдельный `tun_tcp` path
- `tun_tcp` поднимает stateful userspace TCP relay: принимает `SYN`, создаёт uplink TCP tunnel, отвечает `SYN-ACK`, проксирует payload и закрывает flow через `FIN`/`RST`
- для `client -> upstream` path есть overlap trimming, out-of-order buffering, receive-window enforcement и SACK-aware ACK path
- для `upstream -> client` path есть send-window tracking, zero-window persist/backoff, deferred `FIN`, adaptive `RTO`, базовый congestion control (`cwnd`/`ssthresh`) и SACK-aware retransmit выбора дырки
- при ошибке установки uplink или runtime write/read ошибке `tun_tcp` возвращает `RST`, чтобы клиентский стек не зависал
- IPv4 fragments и IPv6 extension-header paths сейчас не поддержаны
- текущие ограничения `tun_tcp`: нет полноценного Reno/NewReno recovery, нет congestion avoidance уровня production TCP stack, нет SACK scoreboard уровня kernel TCP и нет поддержки IPv4 fragments / IPv6 extension headers

На Linux для attach к существующему persistent TUN нужны:

- `path = "/dev/net/tun"`
- `name = "tun0"` или другое имя интерфейса

На системах с device node style TUN достаточно пути вроде `/dev/tun0`.

## Linux fwmark

Для outbound uplink sockets можно указать `fwmark` на уровне uplink:

```toml
[[outline.uplinks]]
name = "primary"
tcp_ws_url = "wss://example.com/SECRET/tcp"
udp_ws_url = "wss://example.com/SECRET/udp"
method = "chacha20-ietf-poly1305"
password = "Secret0"
fwmark = 100
```

Это применяет `SO_MARK` к:

- HTTP/1.1 websocket TCP socket
- HTTP/2 websocket TCP socket
- HTTP/3 QUIC UDP socket
- probe и warm-standby соединениям этого uplink

Ограничения:

- работает только на Linux
- требует `CAP_NET_ADMIN`
- если `fwmark` задан не на Linux, процесс вернёт ошибку при попытке установить uplink connection

## Запуск

Через конфиг:

```bash
cargo run --release
```

С override:

```bash
cargo run --release -- \
  --config ./config.toml \
  --listen [::]:1080 \
  --tcp-ws-url wss://example.com/SECRET/tcp \
  --tcp-ws-mode h3 \
  --udp-ws-url wss://example.com/SECRET/udp \
  --udp-ws-mode h3 \
  --method chacha20-ietf-poly1305 \
  --password 'Secret0'
```

Пример настройки клиента:

- SOCKS5 host: `::1` или `127.0.0.1`
- SOCKS5 port: `1080`

Для шаблона `listen = "[::]:1080"` ОС обычно создаёт dual-stack listener. Если на твоей системе IPv4 не маппится в IPv6 socket, укажи отдельный IPv4 bind, например `127.0.0.1:1080`.

## Status и Metrics

Если настроена секция `[status]`, proxy поднимает лёгкий HTTP endpoint:

- `/status` — JSON snapshot по uplink, latency, cooldown и sticky routes
- `/status` также показывает `standby_tcp_ready` и `standby_udp_ready`
- `/status` также показывает `tcp_penalty_ms` / `udp_penalty_ms` и effective latency
- `/metrics` — Prometheus text format

Production-ready `/metrics` теперь включает:

- build/startup info
- active sessions, request rate и session duration histogram
- payload bytes и UDP datagrams
- uplink selection, runtime failures и failovers
- probe runs и probe latency histogram
- warm-standby hit/miss и refill success/error
- текущие uplink gauges: health, raw latency, failure penalty, effective latency, cooldown, standby size и sticky routes
- TUN/tun2udp metrics: active flows, flow create/close reasons, flow lifetime histogram и packet outcomes
- TUN/tun2tcp metrics: retransmit/zero-window/deferred-fin events, active TCP flows, in-flight server segments/bytes, pending server backlog, buffered client segments, zero-window flow count, congestion window, slow-start threshold, smoothed RTT и retransmission timeout
- `tun2tcp` gauges по `cwnd`, `ssthresh`, `SRTT` и `RTO` экспортируются как aggregated per-uplink значения; в Grafana для них показываются средние по активным TCP flows
- idle warm-standby websocket тоже валидируются ping/pong, пока не выданы в работу

Пример:

```toml
[status]
listen = "[::1]:9090"
```

Проверка:

```bash
curl http://[::1]:9090/status
curl http://[::1]:9090/metrics
```

Пример Prometheus scrape config:

```yaml
scrape_configs:
  - job_name: outline-ws-rust
    metrics_path: /metrics
    static_configs:
      - targets:
          - "[::1]:9090"
```

Готовый Grafana dashboard:

- [`/Users/mmalykhin/Documents/Playground/grafana/outline-ws-rust-dashboard.json`](/Users/mmalykhin/Documents/Playground/grafana/outline-ws-rust-dashboard.json)
- [`/Users/mmalykhin/Documents/Playground/grafana/outline-ws-rust-tun-tcp-dashboard.json`](/Users/mmalykhin/Documents/Playground/grafana/outline-ws-rust-tun-tcp-dashboard.json)
- dashboard включает отдельные панели `Failure Penalty` и `Effective Latency Inflation` для degraded-but-not-yet-unhealthy uplink
- dashboard включает отдельные TUN panels: `TUN Flow Pressure`, `TUN Idle Timeout and Evictions`, `TUN Read and Send Errors`, `TUN Packet Outcomes`
- отдельный `tun2tcp` dashboard включает панели `TUN TCP Retransmits`, `TUN TCP Window And FIN Events`, `TUN TCP In-Flight Segments`, `TUN TCP In-Flight Bytes`, `TUN TCP Pending Server Bytes`, `TUN TCP Buffered Client Segments`, `TUN TCP Zero-Window Flows`, `TUN TCP Active Flows`, `TUN TCP Congestion Window`, `TUN TCP RTT And RTO`

Готовые Prometheus alert rules:

- [`/Users/mmalykhin/Documents/Playground/prometheus/outline-ws-rust-alerts.yml`](/Users/mmalykhin/Documents/Playground/prometheus/outline-ws-rust-alerts.yml)
- rules включают `Socks5OutlineWsPenaltySaturation` и `Socks5OutlineWsEffectiveLatencyInflation`
- rules включают TUN alerts: `Socks5OutlineWsTunFlowPressureHigh`, `Socks5OutlineWsTunFlowEvictions`, `Socks5OutlineWsTunIdleTimeoutBurst`, `Socks5OutlineWsTunReadOrSendErrors`
- rules включают `tun2tcp` alerts: `Socks5OutlineWsTunTcpRetransmitRateHigh`, `Socks5OutlineWsTunTcpZeroWindowStalls`, `Socks5OutlineWsTunTcpBufferedClientBacklog`, `Socks5OutlineWsTunTcpPendingServerBacklog`

## Systemd

Готовый unit с hardening:

- [`/Users/mmalykhin/Documents/Playground/deploy/systemd/outline-ws-rust.service`](/Users/mmalykhin/Documents/Playground/deploy/systemd/outline-ws-rust.service)

Если используешь `fwmark`, оставь в unit:

- `AmbientCapabilities=CAP_NET_ADMIN`
- `CapabilityBoundingSet=CAP_NET_ADMIN`

Если используешь TUN через systemd:

- не включай `PrivateDevices=true`, иначе сервис может не видеть `/dev/net/tun`
- для текущего unit это уже выставлено как `PrivateDevices=false`
- на хосте должен существовать `/dev/net/tun`

Если `fwmark` не используешь, эти capability можно убрать.

Пример сервера Outline:

```yaml
web:
  servers:
    - id: my_web_server
      listen:
        - "0.0.0.0:8000"

services:
  - listeners:
      - type: websocket-stream
        web_server: my_web_server
        path: "/SECRET/tcp"
      - type: websocket-packet
        web_server: my_web_server
        path: "/SECRET/udp"
    keys:
      - id: user-0
        cipher: chacha20-ietf-poly1305
        secret: Secret0
```

Источники по протоколу:

- [Outline ss-server](https://github.com/Jigsaw-Code/outline-ss-server)
- [Shadowsocks AEAD spec](https://shadowsocks.org/doc/aead.html)
- [RFC 8441 WebSocket over HTTP/2 transport model](https://datatracker.ietf.org/doc/html/rfc8441)
- [RFC 9220 Bootstrapping WebSockets with HTTP/3](https://datatracker.ietf.org/doc/html/rfc9220)

Замечание по `websocket-packet`: отдельной публичной спецификации формата сообщения у Outline я не нашёл, поэтому реализация построена на их packet-oriented transport model: один UDP datagram передаётся как один бинарный WebSocket frame с Shadowsocks UDP AEAD payload внутри.

## Проверка `h2`

Для ручной проверки реального `ws-over-h2` добавлен отдельный integration test, который запускается только через env:

```bash
RUN_REAL_SERVER_H2=1 \
OUTLINE_TCP_WS_URL='wss://example.com/SECRET/tcp' \
OUTLINE_UDP_WS_URL='wss://example.com/SECRET/udp' \
SHADOWSOCKS_PASSWORD='Secret0' \
cargo test --test real_server_h2 -- --nocapture
```

Этот тестовый файл содержит два сценария:

- TCP `CONNECT` через реальный `h2` upstream
- UDP `ASSOCIATE` через реальный `h2` upstream с DNS-запросом наружу

Дополнительно можно переопределить:

- `SHADOWSOCKS_METHOD` (`chacha20-ietf-poly1305` по умолчанию)
- `H2_TEST_TARGET_HOST` (`example.com` по умолчанию)
- `H2_TEST_TARGET_PORT` (`80` по умолчанию)
- `H2_TEST_DNS_SERVER` (`1.1.1.1` по умолчанию)
- `H2_TEST_DNS_PORT` (`53` по умолчанию)
- `H2_TEST_DNS_NAME` (`example.com` по умолчанию)

Для ручной проверки реального `ws-over-h3` добавлен отдельный integration test:

```bash
RUN_REAL_SERVER_H3=1 \
OUTLINE_TCP_WS_URL='wss://example.com/SECRET/tcp' \
OUTLINE_UDP_WS_URL='wss://example.com/SECRET/udp' \
SHADOWSOCKS_PASSWORD='Secret0' \
cargo test --test real_server_h3 -- --nocapture
```

Дополнительно можно переопределить:

- `SHADOWSOCKS_METHOD` (`chacha20-ietf-poly1305` по умолчанию)
- `H3_TEST_TARGET_HOST` (`example.com` по умолчанию)
- `H3_TEST_TARGET_PORT` (`80` по умолчанию)
- `H3_TEST_DNS_SERVER` (`1.1.1.1` по умолчанию)
- `H3_TEST_DNS_PORT` (`53` по умолчанию)
- `H3_TEST_DNS_NAME` (`example.com` по умолчанию)

`ws-over-h3` проверен против реального upstream: ручные integration tests `real_server_h3` проходят и для TCP `CONNECT`, и для UDP `ASSOCIATE`.
