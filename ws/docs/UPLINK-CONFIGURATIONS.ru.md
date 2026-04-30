# Конфигурации аплинков и поведение fallback

Описывает шесть поддерживаемых форм блока `[[outline.uplinks]]`: на
каждый — минимальный пример конфига и цепочка fallback на этапе дозвона.

Каждый шаг fallback включается только если предыдущий вернул ошибку на
этапе dial / handshake. После провала «продвинутого» режима (`ws_h3`,
`quic`, `xhttp_h3`) для аплинка открывается **окно даунгрейда**:
последующие дозвоны в этом окне полностью пропускают сломанный режим.
Окно закрывается, когда явная recovery-проба подтверждает, что
продвинутый режим снова доступен — после этого аплинк возвращается к
сконфигурированному режиму.

*English version: [UPLINK-CONFIGURATIONS.md](UPLINK-CONFIGURATIONS.md)*

---

## 1. Native Shadowsocks

Прямые TCP / UDP сокеты до SS-сервера. Без HTTP, WebSocket и QUIC.

```toml
[[outline.uplinks]]
name = "ss-native"
group = "main"
transport = "shadowsocks"
tcp_addr = "ss.example.com:8388"
udp_addr = "ss.example.com:8388"
method = "chacha20-ietf-poly1305"
password = "Secret0"
weight = 1.0
```

- **TCP fallback:** нет. Ошибка дозвона сразу приводит к ошибке аплинка.
- **UDP fallback:** нет.
- **Resume:** не используется (у SS поверх голых сокетов нет понятия
  session id).

## 2. Shadowsocks over raw QUIC

`tcp_mode = "quic"` выбирает raw-QUIC carrier (ALPN `ss`). Один QUIC
bidi на каждую SS-TCP сессию; SS-UDP едет по QUIC datagrams 1:1 с
SS-AEAD пакетами. Dial URL используется как QUIC dial target —
важны только `host:port`, scheme и path игнорируются.

```toml
[[outline.uplinks]]
name = "ss-quic"
group = "main"
transport = "ws"
tcp_ws_url = "https://ss.example.com:443"
udp_ws_url = "https://ss.example.com:443"
tcp_mode = "quic"
udp_mode = "quic"
method = "chacha20-ietf-poly1305"
password = "Secret0"
weight = 1.0
```

- **TCP fallback:** `quic → ws_h2 → ws_h1`.
  - QUIC handshake падает → `note_advanced_mode_dial_failure` открывает
    per-uplink окно даунгрейда; диспетчер проваливается в WS-путь, где
    `effective_tcp_mode` теперь возвращает `WsH2`.
  - h2 handshake падает на том же дозвоне →
    `connect_websocket_with_resume` инлайн опускается до `ws_h1`.
  - В пределах окна даунгрейда каждый новый TCP-дозвон полностью
    пропускает QUIC и стартует с H2.
- **UDP fallback:** `quic → ws_h2 → ws_h1`. Та же логика, что и у TCP.
  SS-UDP по WS использует WS-фрейминг датаграмм поверх H2/H1 потока.
- **Resume:** TCP и UDP получают по своему слоту в
  `global_resume_cache` (ключи `<uplink>#tcp` / `<uplink>#udp`).
  Session ID переживает смену carrier'а — припаркованный upstream
  переподключается через QUIC→WS пивот.

## 3. Shadowsocks over WebSocket (H3)

WebSocket-carrier на HTTP/1.1, /2 или /3. `ws_h3` (алиас `h3`) — лучший
выбор, когда сервер его поддерживает: H3-дозвон — это один 1-RTT QUIC
handshake, против TCP+TLS+HTTP для H2.

```toml
[[outline.uplinks]]
name = "ss-ws-h3"
group = "main"
transport = "ws"
tcp_ws_url = "wss://example.com/SECRET/tcp"
udp_ws_url = "wss://example.com/SECRET/udp"
tcp_mode = "h3"
udp_mode = "h3"
method = "chacha20-ietf-poly1305"
password = "Secret0"
weight = 1.0
```

- **TCP fallback:** `ws_h3 → ws_h2 → ws_h1`. Инлайн-fallback внутри
  `connect_websocket_with_resume`. Каждый шаг — это новый handshake на
  тот же `tcp_ws_url`. Провал `ws_h3` дополнительно записывает host-level
  cap в `ws_mode_cache`, поэтому последующие дозвоны в пределах TTL
  кэша пропускают H3 ещё до того, как сработает per-uplink окно
  даунгрейда.
- **UDP fallback:** `ws_h3 → ws_h2 → ws_h1`. Та же логика на UDP-WS пути.
- **Resume:** TCP и UDP получают по своему слоту в
  `global_resume_cache` (`<uplink>#tcp` / `<uplink>#udp`). Инлайн
  H3→H2→H1 fallback внутри `connect_websocket_with_resume` пробрасывает
  один и тот же `resume_request` через все три carrier'а.

## 4. VLESS over raw QUIC

`vless_mode = "quic"` выбирает raw QUIC с ALPN `vless`. Несколько TCP-
и UDP-сессий к разным таргетам разделяют одну QUIC-connection;
UDP-сессии демультиплексируются 4-байтовым session_id-префиксом,
который сервер выделяет на каждую датаграмму. URL берётся из
`vless_ws_url` (важны только `host:port` — как у SS-over-QUIC).

```toml
[[outline.uplinks]]
name = "vless-quic"
group = "main"
transport = "vless"
vless_ws_url = "https://vless.example.com:443"
vless_mode = "quic"
vless_id = "11111111-2222-3333-4444-555555555555"
weight = 1.0
```

- **TCP fallback:** `quic → ws_h2 → ws_h1`. Тот же путь диспетчера, что
  и у SS-over-QUIC. Cross-transport session resumption сохраняется при
  пивоте QUIC→WS — припаркованный upstream переподключается под тем же
  VLESS Session ID.
- **UDP fallback:** `quic → ws_h2 → ws_h1`. Реализован через
  `VlessUdpHybridMux`: мультиплексор стартует на QUIC и лениво
  переключается на WS, когда первый QUIC-дозвон сессии падает до того,
  как хоть одна сессия успела состояться. Если хотя бы одна QUIC-сессия
  уже отработала успешно — runtime-ошибки остаются на QUIC (это
  настоящий сбой сессии, а не недоступность QUIC-пира).
- **Resume:** TCP делит один слот `<uplink>#tcp` между QUIC и WS —
  сервер паркует обе ветки под одним `Parked::Tcp(Vless)`, поэтому
  один Session ID валиден через любой carrier. UDP в resume не
  участвует (hybrid mux пересоздаёт per-target сессии после пивота).

## 5. VLESS over WebSocket (H3)

WebSocket-carrier с VLESS-фреймингом. VLESS-сервер открывает один
WS-путь (`ws_path_vless`), общий для TCP и UDP — VLESS UDP едет по той
же WS-сессии, что и TCP, с mux.cool / XUDP фреймингом.

```toml
[[outline.uplinks]]
name = "vless-ws-h3"
group = "main"
transport = "vless"
vless_ws_url = "wss://vless.example.com/SECRET/vless"
vless_mode = "h3"
vless_id = "11111111-2222-3333-4444-555555555555"
weight = 1.0
```

- **TCP fallback:** `ws_h3 → ws_h2 → ws_h1`. Инлайн-fallback в
  `connect_websocket_with_resume`, аналогично SS-over-WS.
- **UDP fallback:** `ws_h3 → ws_h2 → ws_h1`. UDP мультиплексируется в
  той же WS-сессии, что и TCP, так что carrier общий, и маркер
  даунгрейда распространяется на оба направления.
- **Resume:** один слот `<uplink>#tcp` покрывает TCP. UDP едет по той
  же WS-сессии и неявно следует за переподключениями TCP (отдельного
  UDP-токена resume нет).

## 6. VLESS over XHTTP (H3)

`vless_mode = "xhttp_h3"` выбирает XHTTP packet-up поверх QUIC +
HTTP/3. Драйвер открывает один долгоживущий GET (downlink) и
пайплайнит POST'ы (uplink), упорядоченные через `X-Xhttp-Seq`. Базовый
URL пишется в `vless_xhttp_url` (НЕ `vless_ws_url`); session id
дописывается на этапе дозвона одним path-сегментом после базового
пути. Полезно, когда WebSocket Upgrade блокируется на сети (CDN-шлюзы,
captive-portal middleboxes).

```toml
[[outline.uplinks]]
name = "vless-xhttp-h3"
group = "main"
transport = "vless"
vless_xhttp_url = "https://vless.example.com/SECRET/xhttp"
vless_mode = "xhttp_h3"
vless_id = "11111111-2222-3333-4444-555555555555"
weight = 1.0
```

- **TCP fallback:** `xhttp_h3 → xhttp_h2`. Диспетчер переиспользует
  тот же `resume_request` при смене carrier'а, поэтому припаркованный
  upstream переподключается без создания новой VLESS-сессии. Глубже
  `xhttp_h2` fallback не идёт — XHTTP работает только на h2 / h3.
- **UDP fallback:** `xhttp_h3 → xhttp_h2`. XHTTP — это двусторонний
  packet-up драйвер на той же h2/h3 connection, поэтому UDP едет рядом
  с TCP в одном carrier'е и даунгрейдится синхронно.
- **Resume:** слот `<uplink>#tcp` переиспользуется при смене
  carrier'а `xhttp_h3 → xhttp_h2` — один и тот же `resume_request`
  предъявляется на любом carrier'е, и сервер переподключает
  припаркованный upstream вместо открытия новой сессии. UDP едет в
  том же XHTTP-carrier'е и наследует поведение реконнекта от TCP.

### Submode: packet-up vs stream-one

Wire-режим выбирается **только** через query-параметр `?mode=` в
`vless_xhttp_url` — отдельного конфиг-поля нет. `XhttpSubmode`
читается на каждом dial'е, так что менять можно прямо в URL.

| URL                                              | Submode                |
|--------------------------------------------------|------------------------|
| `https://host/path/xhttp`                        | `packet-up` (default)  |
| `https://host/path/xhttp?mode=packet-up`         | `packet-up` (явно)     |
| `https://host/path/xhttp?mode=stream-one`        | `stream-one`           |
| `https://host/path/xhttp?mode=stream_one`        | `stream-one` (alias)   |

- **packet-up** (default) — один долгоживущий GET (downlink) плюс
  pipeline POST'ов (uplink), упорядоченных через `X-Xhttp-Seq`. Каждый
  uplink-чанк — отдельный короткий запрос. Максимально устойчив к
  CDN'ам и middlebox'ам, которые буферизируют или закрывают
  long-running POST body. Начинать стоит с него.
- **stream-one** — один bidirectional POST: request body несёт
  uplink, response body — downlink. Меньше overhead'а на чанк и ниже
  latency на мелких пачках. Работает только на `xhttp_h2` / `xhttp_h3`
  и только если путь не буферизирует POST body — прокси, которые ждут
  end-of-request перед форвардом, застрянут на первом байте. На h3
  `RequestStream` разделяется через `split`, так что uplink/downlink
  половинки крутятся в отдельных tasks.

Оба submode'а идут через один и тот же `connect_xhttp` driver, так что
resume, fallback chain (`xhttp_h3 → xhttp_h2`) и механика окна
даунгрейда у них одинаковые.

---

## Сводка

| Конфигурация          | TCP цепочка               | UDP цепочка                              | TCP resume      | UDP resume                  |
|-----------------------|---------------------------|------------------------------------------|-----------------|-----------------------------|
| Native SS             | нет                       | нет                                      | —               | —                           |
| SS / WS / QUIC        | `quic → ws_h2 → ws_h1`    | `quic → ws_h2 → ws_h1`                   | да (`#tcp`)     | да (`#udp`)                 |
| SS / WS / H3          | `ws_h3 → ws_h2 → ws_h1`   | `ws_h3 → ws_h2 → ws_h1`                  | да (`#tcp`)     | да (`#udp`)                 |
| VLESS / QUIC          | `quic → ws_h2 → ws_h1`    | `quic → ws_h2 → ws_h1` (hybrid mux)      | да (`#tcp`)     | нет (сессии пересоздаются)  |
| VLESS / WS / H3       | `ws_h3 → ws_h2 → ws_h1`   | `ws_h3 → ws_h2 → ws_h1`                  | да (`#tcp`)     | вместе с TCP carrier'ом     |
| VLESS / XHTTP / H3    | `xhttp_h3 → xhttp_h2`     | `xhttp_h3 → xhttp_h2`                    | да (`#tcp`)     | вместе с TCP carrier'ом     |

## Механика окна даунгрейда

Записывается в двух слоях:

1. **Per-host `ws_mode_cache`** (короткий TTL). Выставляется при
   падении h3/h2 WS handshake. Последующие дозвоны к тому же хосту
   клампают запрошенный режим до записанного потолка. Переживает
   границы аплинков, делящих один и тот же хост.

2. **Per-uplink `mode_downgrade_until`**. Выставляется по
   `note_advanced_mode_dial_failure`. Пока окно открыто,
   `effective_tcp_mode` / `effective_udp_mode` возвращают `WsH2` —
   пробы, refill standby и прямые дозвоны перестают долбиться в
   сломанный продвинутый режим. Сбрасывается успешной H3-recovery
   пробой.

Когда оба слоя дают одно и то же ограничение, `effective_*_mode`
авторитетен для роутинга, а host-кэш управляет инлайн-клампом
`connect_websocket_with_resume`.

## Механика session resumption

`global_resume_cache` — process-wide map с ключами вида
`<имя_аплинка>#tcp` / `<имя_аплинка>#udp`. В слоте лежит последний
Session ID, который сервер выдал для этого аплинка + направления.

При дозвоне закэшированный ID (если он есть) предъявляется серверу как
`resume_request`:

- **WS-путь** — отправляется заголовком `X-Outline-Resume` вместе с
  `X-Outline-Resume-Capable: 1`. При инлайн-fallback (h3 → h2 → h1)
  тот же токен переиспользуется на каждом carrier'е.
- **VLESS-over-QUIC** — кладётся в VLESS Addons opcode `SESSION_ID`.
  Слот `#tcp` общий с VLESS-over-WS, поэтому закэшированный ID
  переподключает аплинк через любой carrier.
- **XHTTP-путь** — отправляется `X-Outline-Resume`; тот же токен
  переиспользуется при смене carrier'а `xhttp_h3 → xhttp_h2`.

Если сервер отвечает заголовком `X-Outline-Session: <hex>` (или
эквивалентом в VLESS-аддонах), новый ID асинхронно записывается обратно
в слот — он будет использован при следующем реконнекте.

UDP-слот отдельный: TCP-реконнект не должен подхватить UDP-side Session
ID и наоборот. В конфигурациях, где UDP едет по TCP-carrier'у
(VLESS/WS, VLESS/XHTTP), отдельный UDP-слот не поддерживается — UDP
следует за жизненным циклом TCP.
