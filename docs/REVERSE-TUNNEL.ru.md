# Обратный туннель (топология A)

Этот документ описывает функцию обратного туннеля, которая позволяет серверу
`outline-ss-rust` работать **за NAT без публичного IP**, самостоятельно
дозваниваясь до публичного клиента `outline-ws-rust`, который его слушает.

*English version: [REVERSE-TUNNEL.md](REVERSE-TUNNEL.md)*

## Зачем

В обычном («прямом») развёртывании сервер публичен, а клиент дозванивается до
него. Иногда всё наоборот: машина с «чистым» egress-IP (тем, с которого должен
выходить трафик) стоит за NAT, а единственный публичный хост, которым вы
управляете, — это тот, к которому подключаются пользователи. Топология A это
решает:

- `outline-ss-rust` (**сервер** за NAT) дозванивается *наружу* по QUIC к
  публичному `outline-ws-rust`.
- `outline-ws-rust` (**клиент**, публичный VPS) **слушает**, принимает несущую
  и маршрутизирует пользовательский SOCKS5/TUN-трафик через неё.
- Трафик пользователей входит на `ws`; в интернет он выходит с egress-IP `ss`.

## Как это работает

Инвертируется только **направление несущей**. Stream-уровневый data plane не
меняется относительно прямого пути, потому что QUIC позволяет любому пиру
открывать двунаправленные стримы независимо от того, кто дозвонился:

| Роль | Прямое развёртывание | Обратное (топология A) |
|------|----------------------|------------------------|
| `ss` | QUIC-сервер (`accept`) | QUIC-**клиент** (`connect`), по-прежнему `accept_bi` |
| `ws` | QUIC-клиент (`connect`) | QUIC-**сервер** (`accept`), открывает `bi` на сессию |
| TLS  | `ss` предъявляет server cert | инвертируется: `ws` предъявляет server cert, `ss` — client cert (mTLS) |

Каждая пользовательская сессия — это один QUIC bidi-стрим, несущий «сырой»
Shadowsocks (SS-AEAD / SS-2022), ровно как прямой `ss`-ALPN raw-QUIC транспорт.
UDP едет в QUIC-датаграммах. Сервер `ss` переиспользует свой существующий
accept-цикл raw-SS без изменений — ему всё равно, что несущую дозвонили наружу.

### Аутентификация: mTLS + pinned-сертификаты

CDN-фронтинг к обратной несущей неприменим, поэтому ни одна из сторон не
использует публичное хранилище доверия webpki. Вместо этого обе стороны пинят
сертификат контрагента по **SHA-256 fingerprint**, и слушатель требует
клиентский сертификат (взаимный TLS):

- `ss` предъявляет **клиентский сертификат**; `ws` принимает несущую, только
  если fingerprint этого серта в его allow-list.
- `ws` предъявляет **серверный сертификат**; `ss` завершает handshake, только
  если fingerprint этого серта совпадает с настроенным пином.

Fingerprint клиентского серта пира также определяет, *какой* настроенный пир
подключился, а значит — какие Shadowsocks-креды (`method` / `password`)
слушатель использует для кадрирования стримов этого пира.

## Настройка

### 1. Сгенерировать пару сертификатов

Нужны два self-signed серта: один предъявляет слушатель `ws`, другой —
дозвонщик `ss`. Подойдёт любой инструмент; с OpenSSL:

```bash
# серверный сертификат ws (предъявляет публичный слушатель)
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
  -keyout ws-server.key -out ws-server.crt -days 3650 \
  -subj "/CN=reverse" -addext "subjectAltName=DNS:reverse"

# клиентский сертификат ss (предъявляет дозвонщик за NAT)
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
  -keyout ss-client.key -out ss-client.crt -days 3650 \
  -subj "/CN=reverse-ss" -addext "subjectAltName=DNS:reverse-ss"
```

Вычислите SHA-256 fingerprint каждого серта над его **DER**-кодировкой — это
строка пина, которую настраивает противоположная сторона (hex, опционально
через двоеточие, или base64 от 32 байт):

```bash
openssl x509 -in ws-server.crt -outform DER | openssl dgst -sha256
openssl x509 -in ss-client.crt -outform DER | openssl dgst -sha256
```

### 2. Настроить публичный слушатель `ws`

```toml
[reverse_listener]
enabled = true
# UDP-адрес, на который биндится QUIC server endpoint.
listen = "0.0.0.0:8443"
# Сертификат, который этот слушатель предъявляет дозвонщикам.
server_cert_path = "/etc/outline-ws/ws-server.crt"
server_key_path  = "/etc/outline-ws/ws-server.key"
# Uplink-группа, в которую сводятся reverse-пиры. Направьте трафик сюда через [[route]].
group = "reverse"
# true (по умолчанию) предлагает ss-mtu, затем ss (включает oversize-record fallback).
mtu = true
# Верхняя граница числа одновременно зарегистрированных пиров (по умолчанию 8).
max_peers = 8

# По одной записи на каждый ожидаемый пир ss. `client_cert_pin`
# аутентифицирует несущую (mTLS); method/password — это SS-креды для
# кадрирования стримов к этому пиру (должны совпадать с пользователем ss).
[[reverse_listener.peers]]
client_cert_pin = "aa:bb:cc:..."          # SHA-256 от ss-client.crt (DER)
method   = "2022-blake3-aes-256-gcm"
password = "<base64-psk-или-пароль>"
```

Направьте маршрутизацию на reverse-группу как на любую другую:

```toml
[[route]]
default = true
via = "reverse"
```

Когда пир не подключён, группа проваливается на свои настроенные uplink'и
(если есть) или роняет сессию ошибкой — но никогда не дропает молча.

### 3. Настроить дозвонщик `ss` (за NAT)

```toml
[reverse_tunnel]
enabled = true

[[reverse_tunnel.endpoints]]
# host:port публичного слушателя ws. host — DNS-имя или литеральный IP.
addr = "ws.example.com:8443"
# TLS SNI / server name. По умолчанию — host-часть `addr`.
server_name = "reverse"
# SHA-256 от ws-server.crt (DER) — пинит серт слушателя (без webpki).
server_cert_pin = "dd:ee:ff:..."
# Клиентский сертификат для mTLS (его пин в allow-list на ws).
client_cert_path = "/etc/outline-ss/ss-client.crt"
client_key_path  = "/etc/outline-ss/ss-client.key"
# true (по умолчанию) предлагает [ss-mtu, ss]; false — только [ss].
mtu = true
# Пол / потолок backoff'а переподключения в секундах (по умолчанию 1 / 60).
backoff_min_secs = 1
backoff_max_secs = 60
```

Shadowsocks-пользователь, кадрирующий трафик (`method` / `password` в записи
пира на `ws`), должен существовать в `[[users]]` сервера `ss`, чтобы прошёл
AEAD-handshake — mTLS-identity и SS-пользователь это независимые слои.

Каждый endpoint крутит свой цикл переподключения с ограниченным
джиттер-backoff'ом. Некорректный пин или нечитаемый сертификат отключает
только этот endpoint (с логом при старте), не роняя сервер.

## Наблюдаемость

| Метрика | Сторона | Смысл |
|---------|---------|-------|
| `outline_ss_reverse_tunnel_active_connections` | ss | Gauge установленных несущих. |
| `outline_ss_reverse_tunnel_connects_total{result}` | ss | Исходы дозвона (`success` / `failure`). |
| `outline_ws_rust_reverse_peers{group}` | ws | Gauge подключённых пиров по группам. |

Лейблы низко-кардинальны; fingerprint'ы сертификатов пиров никогда не
логируются и не экспортируются.

## Ограничения

- **Только «сырой» Shadowsocks** на обратной несущей (SS-TCP и SS-UDP). VLESS
  и HTTP/3-WebSocket в обратном режиме не несутся.
- **Без CDN-фронтинга** — несущая это прямое QUIC-соединение, аутентифицируемое
  pinned-сертификатами, а не frontable HTTPS-запрос.
- Пиры сводятся в **одну группу** с round-robin-балансировкой между живыми
  пирами; пир, чья несущая отвалилась, исключается при следующем выборе.
- QUIC keep-alive (10 с) на обоих концах держит NAT-mapping живым со стороны
  `ss` — это тот случай, ради которого функция и существует.
