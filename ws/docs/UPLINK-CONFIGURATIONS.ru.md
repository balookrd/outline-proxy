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

- **TCP fallback:** `xhttp_h3 → xhttp_h2 → xhttp_h1`. Диспетчер
  переиспользует тот же `resume_request` на каждом шаге смены
  carrier'а, поэтому припаркованный upstream переподключается без
  создания новой VLESS-сессии. h1-carrier — это фолбек последнего
  шанса для путей, где режутся и QUIC, и ALPN h2; throughput строго
  хуже (без мультиплексирования — см. «форма h1 carrier'а» ниже),
  зато wire-URL остаётся идентичным (`<base>/<session>/<seq>`), и
  тот же `xhttp_path_vless` listener обслуживает запросы.
- **UDP fallback:** `xhttp_h3 → xhttp_h2 → xhttp_h1`. XHTTP — это
  двусторонний packet-up драйвер на той же connection, поэтому UDP
  едет рядом с TCP в одном carrier'е и даунгрейдится синхронно.
- **Resume:** слот `<uplink>#tcp` переиспользуется на каждом шаге
  цепочки `xhttp_h3 → xhttp_h2 → xhttp_h1` — один и тот же
  `resume_request` предъявляется на любом carrier'е, и сервер
  переподключает припаркованный upstream вместо открытия новой
  сессии. UDP едет в том же XHTTP-carrier'е и наследует поведение
  реконнекта от TCP.

**Форма h1 carrier'а.** В отличие от h2 / h3, HTTP/1.1 не умеет
мультиплексировать стримящийся GET с одновременными POST'ами на
одной connection, поэтому h1-carrier открывает **два** keep-alive
сокета на сессию: один — под долгоживущий downlink GET (chunked
response body), второй — под строго сериализованные uplink POST'ы
(один in-flight запрос за раз). Pipelining сознательно не
используется — он слишком ненадёжен через CDN/proxy промежутки.
Следствия:

- Throughput ограничен round-trip-временем одного POST'а; ожидайте
  заметного отставания от h2 под нагрузкой.
- Падение единственного POST'а кладёт uplink-сокет, и драйвер
  выходит — upstream видит чистый разрыв сессии, а не частичную
  порчу. Следующий dial реаттачится через resume-токен.
- Stream-one на h1 **не пускается на провод** — h1 не умеет
  мультиплексировать streaming GET и streaming POST на одном
  соединении, поэтому `?mode=stream-one` с `vless_mode = xhttp_h1`
  (или цепочка, упавшая до h1) тихо приводится к packet-up на
  этапе dial'а. Wire-URL остаётся идентичным (`<base>/<session>/<seq>`).
  Защитный `packet-up only` bail во внутреннем h1-драйвере
  сохранён для прямых вызовов в обход публичного `connect_xhttp`.

## 7. VLESS share-link URIs

Пять VLESS форм выше (разделы 4–6 плюс варианты `ws_h2` / `ws_h1`
раздела 5) можно сконфигурировать одной строкой
`vless://UUID@HOST:PORT?...#NAME` — это share-link формат клиентов
Xray / V2Ray. Используйте поле `link` вместо ручного заполнения
тройки `vless_id` / `vless_*_url` / `vless_mode`:

```toml
[[outline.uplinks]]
name = "vless-share"
group = "main"
link = "vless://11111111-2222-3333-4444-555555555555@vless.example.com:443?type=ws&security=tls&path=%2Fsecret%2Fvless&alpn=h3&encryption=none#edge"
weight = 1.0
```

Загрузчик разворачивает URI в те же внутренние поля, которые
порождает длинная TOML-форма, так что поведение dial / fallback /
resume полностью совпадает с соответствующим разделом выше. Поле
`transport` указывать необязательно: `link` неявно подразумевает
`transport = "vless"`.

### Распознаваемые параметры

| Элемент / параметр URI             | Куда мапится                                       |
|------------------------------------|----------------------------------------------------|
| `UUID` (userinfo)                  | `vless_id`                                         |
| `HOST:PORT` (authority)            | host + port dial-URL (порт обязателен)             |
| `type=ws`                          | `vless_mode = ws_h1` (с `alpn`: `ws_h2`/`ws_h3`), URL → `vless_ws_url` |
| `type=xhttp`                       | `vless_mode = xhttp_h2` (с `alpn=h3`: `xhttp_h3`; с `alpn=h1` / `http/1.1`: `xhttp_h1`), URL → `vless_xhttp_url` |
| `type=quic`                        | `vless_mode = quic`, URL → `vless_ws_url` (только TLS) |
| `security=tls` / `reality`         | scheme URL → `wss://` (ws) или `https://` (xhttp/quic) |
| `security=none` (или отсутствует)  | scheme URL → `ws://` / `http://`                   |
| `path=...`                         | path URL (percent-decoded; ведущий `/` добавляется автоматически) |
| `alpn=h3` / `h2` / `h1` / `h2,h3`  | выбирает H1/H2/H3-вариант режима; учитывается первый токен |
| `mode=packet-up` / `stream-one`    | пробрасывается как `?mode=` в XHTTP dial-URL       |
| `encryption=none` (или отсутствует)| принимается (других режимов encryption у VLESS нет)|
| `#NAME`                            | имя аплинка (percent-decoded)                      |

### Ограничения и конфликты

- В URI обязателен явный `:port` — у схемы нет дефолта.
- `link` взаимно исключителен с `vless_id`, `vless_ws_url`,
  `vless_xhttp_url` и `vless_mode`. Смешение приводит к ошибке на
  этапе загрузки конфига; используйте либо URI, либо явные поля.
- `flow=...` (xtls-rprx-vision) и любые `encryption=`, отличные от
  `none`, отклоняются — на клиенте этих режимов нет.
- Параметры `sni=` и `host=` принимаются только если они совпадают с
  authority host. Текущий транспорт переиспользует host из URL и
  как SNI, и как HTTP-заголовок `Host`, поэтому расходящиеся значения
  иначе бы тихо терялись — загрузчик предпочитает ошибку.
- `type=tcp` / `type=grpc` / `type=h2` отклоняются — для них нет
  реализации carrier'а.
- Reality-параметры (`pbk`, `sid`, `spx`, `fp`) принимаются, но
  игнорируются; пока reality не реализован, считайте
  `security=reality` синонимом `security=tls`.

То же поле `link` принимается:

- CLI-флагом `--vless-link <URI>` / переменной окружения
  `OUTLINE_VLESS_LINK`.
- REST-эндпойнтами `/control/uplinks` — как `link` (алиас
  `share_link`) внутри JSON-объекта `uplink`.

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
  половинки крутятся в отдельных tasks. На `xhttp_h1` carrier
  тихо использует packet-up (у h1 нет аналогичной формы).

Оба submode'а идут через один и тот же `connect_xhttp` driver, так что
resume, цепочка по h-версии (`xhttp_h3 → xhttp_h2 → xhttp_h1`) и
механика окна даунгрейда у них одинаковые. У самого submode-а
есть собственный одношаговый fallback — см. ниже.

#### Fallback `stream-one → packet-up`

Stream-one — это один долгоживущий POST, и он чувствителен к
middlebox'ам, которые буферизируют или закрывают streaming
request body (CDN'ы, корпоративные прокси, часть мобильных NAT'ов).
Если на dial'е stream-one open падает на `xhttp_h2` / `xhttp_h3`,
carrier ретраит packet-up на **той же** TCP/TLS/h2 (или QUIC/h3)
connection и записывает фейл в per-host кэш XHTTP-submode'а.
Последующие dial'ы заранее пропускают stream-one на
`mode_downgrade_secs` и идут сразу в packet-up — обречённый
handshake не повторяется на каждом коннекте. Успешный stream-one
dial снимает блок раньше срока.

Оси submode и h-версии независимы: блок stream-one на хосте
не понижает cap по h-версии, а h-версионный даунгрейд не
обновляет stream-one блок.

Дашборд показывает реальный submode на protocol-pill'е —
для `stream-one` отображается `/S`, packet-up без суффикса,
а активный блок рендерится как `/S↘P`, чтобы было видно тихий
даунгрейд. Поля snapshot:

- `tcp_xhttp_submode` / `udp_xhttp_submode` — submode из
  dial-URL (`packet-up` / `stream-one`); `None` вне VLESS.
- `tcp_xhttp_submode_block_remaining_ms` /
  `udp_xhttp_submode_block_remaining_ms` — оставшийся TTL
  per-host блока stream-one; `None`, если блок истёк или
  не выставлялся.

---

## Сводка

| Конфигурация          | TCP цепочка               | UDP цепочка                              | TCP resume      | UDP resume                  |
|-----------------------|---------------------------|------------------------------------------|-----------------|-----------------------------|
| Native SS             | нет                       | нет                                      | —               | —                           |
| SS / WS / QUIC        | `quic → ws_h2 → ws_h1`    | `quic → ws_h2 → ws_h1`                   | да (`#tcp`)     | да (`#udp`)                 |
| SS / WS / H3          | `ws_h3 → ws_h2 → ws_h1`   | `ws_h3 → ws_h2 → ws_h1`                  | да (`#tcp`)     | да (`#udp`)                 |
| VLESS / QUIC          | `quic → ws_h2 → ws_h1`    | `quic → ws_h2 → ws_h1` (hybrid mux)      | да (`#tcp`)     | нет (сессии пересоздаются)  |
| VLESS / WS / H3       | `ws_h3 → ws_h2 → ws_h1`   | `ws_h3 → ws_h2 → ws_h1`                  | да (`#tcp`)     | вместе с TCP carrier'ом     |
| VLESS / XHTTP / H3    | `xhttp_h3 → xhttp_h2 → xhttp_h1` | `xhttp_h3 → xhttp_h2 → xhttp_h1` | да (`#tcp`) | вместе с TCP carrier'ом     |

## Механика окна даунгрейда

Записывается в двух слоях:

1. **Per-host кэши** (короткий TTL, по одному на ось).
   - `ws_mode_cache` — выставляется при падении h3/h2 WS handshake.
     Клампает последующие дозвоны к тому же хосту до записанного
     потолка (`WsH2` после падения `WsH3`, `WsH1` после падения
     `WsH2`).
   - `xhttp_mode_cache` — sibling-кэш для оси h-версии XHTTP.
     Выставляется при падении dial'а `xhttp_h3` или `xhttp_h2`;
     клампает последующие дозвоны до `XhttpH2` / `XhttpH1`
     соответственно. Независим от WS-кэша, чтобы `record_failure`
     одной цепочки не затирал cap другой, когда несколько аплинков
     делят один `(host, port)`, но используют разные транспорты.
   - `xhttp_submode_cache` — ортогональная ось: per-host
     отслеживание падений stream-one. Выставляется при падении
     dial'а `?mode=stream-one` на `xhttp_h2` / `xhttp_h3`; на
     время TTL клампает выбор submode'а до `packet-up`.
     Независим от h-версионного кэша — фейл stream-one не
     обновляет h-версионный cap и наоборот.

   Все три кэша ключатся по **назначению** `host:port` (dial-URL,
   не local interface), поэтому переживают границы аплинков,
   смотрящих на один и тот же upstream, и смену локального маршрута
   / `fwmark`. Общий knob `mode_downgrade_secs` управляет TTL для
   всех трёх.

2. **Per-uplink `mode_downgrade_until`** + family-aware
   `mode_downgrade_capped_to`. Выставляется по
   `note_advanced_mode_dial_failure` или
   `note_silent_transport_fallback`. Пока окно открыто,
   `effective_tcp_mode` / `effective_udp_mode` возвращают cap
   (а не configured режим) — пробы, refill standby и прямые дозвоны
   перестают долбиться в сломанный продвинутый режим. Family-aware:
   `WsH3` / `Quic` коллапсируют в `WsH2`, `XhttpH3` — в `XhttpH2`,
   `XhttpH2` — в `XhttpH1`. Многоступенчатые XHTTP-даунгрейды
   (`XhttpH3 → XhttpH2 → XhttpH1`) сходятся за несколько dial'ов —
   каждое наблюдение silent-fallback'а понижает cap на один rank
   внутри активного окна и никогда не повышает обратно.
   Сбрасывается успешной H3-recovery пробой (WS-путь) или
   естественным истечением TTL (XHTTP-путь — recovery пробы нет).
   Cap публикуется через snapshot (`tcp_mode_capped_to` /
   `udp_mode_capped_to`), так что колонки `tcp_mode_effective` /
   `udp_mode_effective` дашборда отражают реальный carrier, который
   выберет диспетчер.

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
  переиспользуется на каждом шаге смены carrier'а
  `xhttp_h3 → xhttp_h2 → xhttp_h1`.

Если сервер отвечает заголовком `X-Outline-Session: <hex>` (или
эквивалентом в VLESS-аддонах), новый ID асинхронно записывается обратно
в слот — он будет использован при следующем реконнекте.

UDP-слот отдельный: TCP-реконнект не должен подхватить UDP-side Session
ID и наоборот. В конфигурациях, где UDP едет по TCP-carrier'у
(VLESS/WS, VLESS/XHTTP), отдельный UDP-слот не поддерживается — UDP
следует за жизненным циклом TCP.

## Диверсификация браузерного фингерпринта

WS / XHTTP-дозвоны могут подмешивать браузерные заголовки
идентификации (`User-Agent`, `Accept-*`, семейство Sec-CH-UA,
Sec-Fetch-*), чтобы простое DPI-правило вида «WS-upgrade без
User-Agent» больше не отделяло клиент от реального браузерного
трафика. В пул входит шесть профилей: Chrome 130 (Windows + macOS),
Firefox 130 (Windows + macOS), Safari 17 (macOS), Edge 130 (Windows).
Под стратегией PerHostStable выбор детерминирован по `(host, port)`,
поэтому один пир видит одну идентичность через все реконнекты.

Тумблер opt-in. По умолчанию форма провода полностью совпадает с тем,
что было до этого изменения — никаких новых заголовков, кроме
`X-Outline-Resume-*`. Включается ключом верхнего уровня
`fingerprint_profile` в `config.toml`:

```toml
# верхний уровень — рядом с [socks5], [metrics], [outline], [[uplink_group]]
fingerprint_profile = "stable"
```

Допустимые значения:

- `"off"` / `"none"` / `"disabled"` / отсутствие ключа — по умолчанию,
  заголовки не добавляются.
- `"stable"` / `"per_host_stable"` / `"per-host-stable"` / `"per-host"` —
  одна идентичность на пару `(host, port)` на всё время жизни процесса.
- `"random"` — свежий профиль на каждый дозвон.

Для встроенных вызовов (тесты, кастомные бинарники) стратегию также
можно проставить прямо через Rust API; bootstrap-бинарь подхватывает
значение из конфига при старте:

```rust
use outline_transport::{
    init_fingerprint_profile_strategy, FingerprintProfileStrategy,
};

init_fingerprint_profile_strategy(FingerprintProfileStrategy::PerHostStable);
```

Что **не** покрыто (отдельная и дороже задача):

- TLS ClientHello / JA3 / JA4 — rustls не даёт настраивать порядок
  cipher suites / extensions / supported_groups, значит для реальной
  диверсификации нужен uTLS-подобный стек (например, `boring` /
  BoringSSL).
- Порядок ALPN — сейчас зафиксирован для каждого carrier'а
  (`h2`, `http/1.1`, `h3`, `vless`, `ss`). TLS-конфиги кэшируются
  по списку ALPN, поэтому per-host рандомизация потребует нового
  ключа кеша.
- Фингерпринт HTTP/2 `SETTINGS` (Akamai/JA4H2) — принадлежит крейту
  `h2` и почти закрыт для клиентской подстройки.
- Порядок transport-параметров QUIC — принадлежит `quinn`.
