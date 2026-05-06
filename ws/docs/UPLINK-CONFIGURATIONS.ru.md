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

## Структура секции `[outline]`

Таблица `[outline]` собирает всё, что относится к проксирующему движку —
транспорты, аплинки, пробинг, балансировку — отдельно от обвязки хоста
(`[socks5]`, `[metrics]`, `[control]`, `[dashboard]`, `[tcp_timeouts]`,
`[tun]`, `[[route]]`). Поддерживаются две формы конфигурации.

**1. Inline-стенограмма для одного аплинка.** Если поля `transport`,
`tcp_ws_url`, `udp_ws_url`, `vless_ws_url`, `vless_xhttp_url`,
`tcp_mode` / `udp_mode` / `vless_mode`, `link`, `tcp_addr`, `udp_addr`,
`method`, `password`, `fwmark`, `ipv6_first` написаны прямо под
`[outline]` (или, для обратной совместимости, на верхнем уровне) —
описан один неявный аплинк. CLI-флаги (`--tcp-ws-url`, `--password`, …)
работают именно с этой формой. Удобно для тривиальных деплойментов; не
сочетается с `[[outline.uplinks]]` / `[[uplink_group]]`.

```toml
[outline]
transport = "ws"                  # "ws" (по умолчанию; alias "websocket") | "shadowsocks" | "vless"
tcp_ws_url = "wss://example.com/SECRET/tcp"
udp_ws_url = "wss://example.com/SECRET/udp"
tcp_mode = "h3"
udp_mode = "h3"
method = "chacha20-ietf-poly1305"
password = "Secret0"
```

`outline.transport` принимает:

| значение      | форма канала                                                                       |
|---------------|------------------------------------------------------------------------------------|
| `ws`          | Shadowsocks AEAD-фрейминг внутри WebSocket-носителя (по умолчанию; alias `websocket`) |
| `shadowsocks` | «Голый» Shadowsocks поверх сырых TCP/UDP-сокетов — см. § 1                         |
| `vless`       | VLESS поверх WebSocket или XHTTP (h1/h2/h3) — см. §§ 4–7                           |

**2. Multi-uplink + группы (продакшен-форма).** `[[outline.uplinks]]`
объявляет аплинки; `[[uplink_group]]` (на верхнем уровне, *не* под
`[outline]`) объявляет группы; каждый аплинк указывает свою группу через
`group = "..."`. В этой форме у каждого аплинка собственное поле
`transport`, поэтому inline-`outline.transport` не используется.

## Справочник балансировки нагрузки

Две эквивалентные поверхности, выбирается по форме конфига:

- **`[outline.load_balancing]`** — применяется в inline-форме (когда
  `[[uplink_group]]` не объявлены). При загрузке сворачивается в
  неявную «default» группу
  ([groups.rs:21](src/config/load/groups.rs:21)).
- **Поля прямо под `[[uplink_group]]`** — применяются на каждой группе,
  если используются группы (блок `[outline.load_balancing]` в этой
  форме молча игнорируется;
  [groups.rs:171](src/config/load/groups.rs:171)).

Имена полей и значения по умолчанию идентичны на обеих поверхностях.
Все поля опциональны; пропущенные подставляются дефолтами из таблицы.

| поле                                 | дефолт             | ед.   | назначение                                                                                       |
|--------------------------------------|--------------------|-------|--------------------------------------------------------------------------------------------------|
| `mode`                               | `"active_active"`  | enum  | `active_active` распределяет нагрузку (per-flow / per-uplink); `active_passive` держит один активным, остальные — резерв |
| `routing_scope`                      | `"per_flow"`       | enum  | `per_flow` (выбор аплинка на сессию) / `per_uplink` (sticky по host:port) / `global` (один активный на весь инстанс) |
| `sticky_ttl_secs`                    | `300`              | с     | как долго `(host, port)` залипает за выбранным аплинком                                          |
| `hysteresis_ms`                      | `50`               | мс    | минимальный интервал между двумя сменами `active`; гасит флаппинг                                |
| `failure_cooldown_secs`              | `10`               | с     | как долго после провала аплинк исключается из выборки                                            |
| `tcp_chunk0_failover_timeout_secs`   | `10`               | с     | сколько ждать первого байта от origin'а перед тем, как уйти на следующий аплинк                  |
| `auto_failback`                      | `false`            | bool  | возвращаться на исходно-предпочтительный аплинк после восстановления                             |
| `warm_standby_tcp`                   | `0`                | int   | сколько прогретых TCP-соединений держать на резервных аплинках                                   |
| `warm_standby_udp`                   | `0`                | int   | то же для UDP                                                                                    |
| `warm_probe_keepalive_secs`          | `20`               | с     | период keepalive для кэшированных warm-probe-каналов (`0` отключает)                             |
| `rtt_ewma_alpha`                     | `0.3`              | (0,1] | коэффициент сглаживания EWMA для per-uplink RTT, используемого в скоринге выбора                 |
| `failure_penalty_ms`                 | `500`              | мс    | стартовый штраф к RTT при свежем runtime-провале                                                 |
| `failure_penalty_max_ms`             | `30000`            | мс    | потолок суммарного штрафа за провалы                                                             |
| `failure_penalty_halflife_secs`      | `60`               | с     | период полураспада экспоненциального затухания штрафа                                            |
| `runtime_failure_window_secs`        | `60`               | с     | окно, в котором подряд идущие data-plane провалы складываются к health flip; `0` = legacy без затухания |
| `mode_downgrade_secs`                | `60`               | с     | cooldown перед повтором настроенного «продвинутого» режима (H3 / QUIC / `xhttp_h{2,3}`) после фолбэка. Legacy alias: `h3_downgrade_secs` |
| `global_udp_strict_health`           | `false`            | bool  | в `routing_scope = "global"` дополнительно гейтить активный аплинк по UDP-здоровью; по умолчанию мягко — UDP-провалы информативные |
| `udp_ws_keepalive_secs`              | `60`               | с     | период WS Ping на простаивающих UDP-WS-сокетах (`0` отключает)                                   |
| `tcp_ws_keepalive_secs`              | `60`               | с     | период WS Ping на простаивающих VLESS-over-WS TCP-сессиях (`0` отключает; SS-over-WS игнорирует) |
| `tcp_ws_standby_keepalive_secs`      | `20`               | с     | период WS Ping на warm-standby TCP-сокетах (`0` отключает)                                       |
| `tcp_active_keepalive_secs`          | `20`               | с     | период SS2022 0-байтного keepalive на активных SOCKS TCP-сессиях (`0` отключает; SS1 игнорирует) |
| `vless_udp_max_sessions`             | `256`              | int   | жёсткий лимит на одновременные VLESS UDP-сессии (LRU-вытеснение при переполнении)                |
| `vless_udp_session_idle_secs`        | `60`               | с     | вытеснять VLESS UDP-сессии, простаивавшие дольше этого (`0` отключает вытеснение)                |
| `vless_udp_janitor_interval_secs`    | `15`               | с     | как часто janitor сканирует idle-сессии VLESS UDP                                                |

Источник дефолтов:
[`src/config/load/balancing.rs`](src/config/load/balancing.rs); запасные
значения для `vless_udp_*` — из
[`crates/outline-transport/src/vless/udp_mux.rs`](crates/outline-transport/src/vless/udp_mux.rs).

Шпаргалка по `routing_scope`:

- **`per_flow`** — рекомендуемый дефолт. Каждая новая SOCKS/TUN-сессия
  выбирает аплинк по весу, RTT EWMA и текущим штрафам; существующие
  сессии остаются на своём аплинке весь поток. Лучшая параллельность,
  минимальный blast radius.
- **`per_uplink`** — потоки с общим `(host, port)` назначаются на один
  аплинк на `sticky_ttl_secs`. Полезно, когда origin чувствителен к
  смене source IP (анти-фрод, sticky session cookies, привязанные к
  клиентскому IP).
- **`global`** — ровно один аплинк `active` на весь инстанс; failover
  гейтится `hysteresis_ms` + `failure_cooldown_secs`. Подходит для
  чистой дашборд-семантики на устройствах, которые «должны выглядеть»
  как одна точка egress (роутеры, узкоспециализированные домашние
  шлюзы).

Взаимодействие mode × scope:

- `active_active` + `per_flow` — единственная комбинация, реально
  использующая взвешенное распределение.
- `active_passive` + `global` — классический primary/backup: один
  аплинк несёт всё, остальные ждут.
- `active_passive` + `per_flow` допустимо, но смысл скуднее: пассивные
  аплинки работают только как failover-цели, не как взвешенные
  «соседи».

Пример — `[outline.load_balancing]` для inline-формы и те же поля,
вынесенные на группу:

```toml
# Inline-форма
[outline.load_balancing]
mode = "active_active"
routing_scope = "per_flow"
sticky_ttl_secs = 300
hysteresis_ms = 50
failure_cooldown_secs = 10
warm_standby_tcp = 1
warm_standby_udp = 1
rtt_ewma_alpha = 0.3
failure_penalty_ms = 500
failure_penalty_max_ms = 30000
failure_penalty_halflife_secs = 60
mode_downgrade_secs = 60
runtime_failure_window_secs = 60
global_udp_strict_health = false
auto_failback = false

# Эквивалент для multi-group формы — те же имена полей прямо на группе:
[[uplink_group]]
name = "main"
mode = "active_active"
routing_scope = "per_flow"
sticky_ttl_secs = 300
hysteresis_ms = 50
warm_standby_tcp = 1
# … и т.д.
```

## Переопределение проб для конкретной группы

`[outline.probe]` — шаблон, который наследует каждая `[[uplink_group]]`.
Любая группа может переопределить параметры проб через
`[uplink_group.probe]`. Эта таблица привязывается к **последней объявленной
выше** `[[uplink_group]]` — ставьте блок override сразу после нужной
группы и до объявления следующей `[[uplink_group]]`.

Правила слияния:

- **Скалярные поля** (`interval_secs`, `timeout_secs`, `max_concurrent`,
  `max_dials`, `min_failures`, `attempts`) мержатся пофилдово — поля,
  не указанные в override, наследуются из `[outline.probe]`.
- **Саб-таблицы** (`ws` / `http` / `dns` / `tcp`) заменяются целиком.
  Если группа задаёт `[uplink_group.probe.http]`, шаблонная
  `[outline.probe.http]` для этой группы отбрасывается полностью —
  все нужные поля надо повторить.
- **Чтобы пробы запустились**, в результирующей (после мержа)
  конфигурации должна остаться хотя бы одна из `ws` / `http` / `dns`,
  иначе probe-loop для группы не стартует.

Пример: группа `backup` пробит реже, использует свой HTTP-таргет, а WS
и DNS-саб-таблицы наследует из шаблона:

```toml
[outline.probe]
interval_secs  = 30
timeout_secs   = 10
max_concurrent = 4
max_dials      = 2

[outline.probe.ws]
enabled = true

[outline.probe.http]
url = "http://example.com/"

[outline.probe.dns]
server = "1.1.1.1"
port   = 53
name   = "example.com"


[[uplink_group]]
name = "main"
mode = "active_active"
# … наследует [outline.probe] без изменений …


[[uplink_group]]
name = "backup"
mode = "active_passive"
routing_scope = "global"

# Override относится к "backup" — последней объявленной выше [[uplink_group]]:
[uplink_group.probe]
interval_secs = 60   # резервный путь пробим реже
min_failures  = 2    # терпимее к одиночному фейлу

# Заменяет [outline.probe.http] целиком для этой группы:
[uplink_group.probe.http]
url = "http://backup-canary.example.net/"

# [uplink_group.probe.ws] / .dns не переопределены, так что группа
# наследует шаблонные саб-таблицы `ws` и `dns` без изменений.
```

**Выключение типа пробы для одной группы:**

- `ws`: задайте `[uplink_group.probe.ws] enabled = false` в override —
  у `WsProbeConfig` есть явное поле `enabled`.
- `http` / `dns` / `tcp`: выключить per-group нельзя. Мерж использует
  `override.or(template)` ([groups.rs:160](src/config/load/groups.rs:160)),
  поэтому пропущенная саб-таблица наследует значение из шаблона, и
  способа задать «явное None» нет. Если нужно, чтобы одна группа
  работала без какой-то из этих проб, а другая — с ней, уберите
  саб-таблицу из `[outline.probe]` и объявите её только в нужных
  группах через `[uplink_group.probe.<тип>]`.

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

### Per-uplink override

Каждый блок `[[outline.uplinks]]` может переопределить top-level
значение собственным ключом `fingerprint_profile`. Полезно, когда
один uplink должен оставаться байт-в-байт совместимым с xray-формой,
а соседи на тот же хост хотят PerHostStable-идентичность:

```toml
fingerprint_profile = "stable"  # по умолчанию для всех аплинков ниже

[[outline.uplinks]]
name = "cdn-fronted"
group = "main"
tcp_ws_url = "wss://cdn.example.com/secret/tcp"
# наследует "stable" с верхнего уровня

[[outline.uplinks]]
name = "xray-shaped"
group = "main"
tcp_ws_url = "wss://xray.example.com/secret/tcp"
fingerprint_profile = "off"      # явный opt-out ради byte-identity
```

Override прокидывается через per-dial task-local scope в
`outline-uplink::dial::dial_in_uplink_scope`, поэтому пробы,
прогревание warm-standby и live-диспетчер используют одно и то же
значение для конкретного аплинка. Scope снимается на возврате из
dial-future'а; спавненные post-handshake таски (драйверы, body-drain
loops) ничего не наследуют — это нормально, потому что единственный
`select` живёт в dial-entry-point.

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

## Внутри-аплинковые fallback-транспорты

Один `[[outline.uplinks]]` может нести упорядоченный список
**fallback-транспортов**, которые dial-loop пробует по порядку, если
primary-транспорт этого аплинка не смог дозвониться. Мотивирующий
сценарий: VLESS-эндпоинт блокируется на сетевом пути; вместо демоута
аплинка целиком и failover'а на другой аплинк в группе loop падает
на Shadowsocks- или WS-wire **этого же** аплинка, сохраняя
identity / weight / group-привязку оператора.

```toml
[[outline.uplinks]]
name        = "edge-1"
group       = "main"
weight      = 1.0
transport   = "vless"
vless_xhttp_url = "https://cdn.example.com/SECRET/xhttp"
vless_id        = "00000000-0000-0000-0000-000000000000"
vless_mode      = "xhttp_h3"
cipher          = "2022-blake3-aes-256-gcm"
password        = "BASE64=="

  [[outline.uplinks.fallbacks]]
  transport   = "ws"
  tcp_ws_url  = "wss://ws.example.com/tcp"
  udp_ws_url  = "wss://ws.example.com/udp"
  tcp_mode    = "ws_h2"
  udp_mode    = "ws_h1"
  # cipher / password / fwmark / ipv6_first / fingerprint_profile
  # наследуются от родительского аплинка, если не указаны явно.

  [[outline.uplinks.fallbacks]]
  transport   = "shadowsocks"
  tcp_addr    = "1.2.3.4:8388"
  udp_addr    = "1.2.3.4:8389"
```

### Поля

Каждая fallback-секция несёт собственные wire-поля, повторяющие схему
top-level `[[outline.uplinks]]` **минус** атрибуты идентичности, которые
принадлежат родителю (`name`, `weight`, `group`, `link`):

| Поле | Обязательно для | Заметки |
|---|---|---|
| `transport` | всегда | `ws` / `shadowsocks` / `vless`; должен отличаться от primary родителя; каждый транспорт может встречаться в списке fallback'ов одного аплинка не более одного раза. |
| `tcp_ws_url`, `udp_ws_url`, `tcp_mode`, `udp_mode` | `transport = "ws"` | `tcp_ws_url` обязателен; `udp_ws_url` опционален (UDP-fallback opt-in). |
| `vless_ws_url`, `vless_xhttp_url`, `vless_mode`, `vless_id` | `transport = "vless"` | URL должен соответствовать `vless_mode` (xhttp\_\* → `vless_xhttp_url`; ws/quic → `vless_ws_url`). `vless_id` per-wire и **не наследуется** от родителя — у разных VLESS-эндпоинтов разные uuid'ы. |
| `tcp_addr`, `udp_addr` | `transport = "shadowsocks"` | `tcp_addr` обязателен; `udp_addr` опционален. |
| `cipher`, `password` | наследуются | По умолчанию — значение родителя. Переопределите тут, если fallback использует другой shared secret. |
| `fwmark`, `ipv6_first`, `fingerprint_profile` | наследуются | То же самое: дефолтятся к родителю, можно переопределить per-fallback. |

### Поведение

- Dial-loop пробует `primary → fallbacks[0] → fallbacks[1] → …`
  для каждой сессии заново. Новая сессия снова стартует с primary —
  per-аплинковой памяти про «активный wire» в этой итерации нет
  (это фаза 2).
- Успешный fallback-дайл **невидим** для балансировщика, кроме тика
  метрики `outline_uplink_selected`. `report_runtime_failure` родителя
  инкрементируется только когда провалились **все** wire'ы аплинка —
  транзиентные сбои primary'а больше не демотят аплинк целиком, пока
  работает хоть один fallback.
- Probe в этой итерации продолжает дёргать **primary**. Probe-
  подтверждённый health-статус читается с primary-wire; флапающий
  primary, всегда восстанавливающийся через fallback, всё равно может
  показаться как `tcp_healthy = Some(false)` после `min_failures`
  подряд probe-failures. Маршрутизация probe на active-wire — фаза 2.
- Fallback-дайл обходит standby pool, mode-downgrade окно,
  cross-transport resume cache и RTT-EWMA — эти структуры приколочены
  к primary index/transport и принадлежат active-wire-aware
  механизму, который придёт в фазе 2. DNS-кэш и per-uplink fingerprint
  scope сохраняются.
- UDP-фильтр кандидатов (`supports_transport_for_scope`) теперь
  консультируется с `UplinkConfig::supports_udp_any()`, так что
  аплинк, у которого primary — TCP-only (например, SS без `udp_addr`),
  но fallback UDP-capable, всё равно попадает в UDP-выдачу.
- **Ограничение:** VLESS как *fallback-транспорт на UDP* в этой
  итерации возвращает понятную ошибку. QUIC-mux в
  `acquire_udp_standby_or_connect` приколочен хуками к
  `candidate.index`, и переиспользование этих хуков для fallback-wire
  требует active-wire плумбинга. Сегодня для UDP-fallback используйте
  SS или WS.

### Inline-стенограмма `[outline]`

Inline-форма (`tcp_ws_url` и т.п. прямо на `[outline]`) **не**
поддерживает fallback'и — для них объявите явный массив
`[[outline.uplinks]]`.
