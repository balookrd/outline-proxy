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
    `connect_transport` инлайн опускается до `ws_h1`.
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
  `connect_transport`. Каждый шаг — это новый handshake на
  тот же `tcp_ws_url`. Провал `ws_h3` дополнительно записывает host-level
  cap в `ws_mode_cache`, поэтому последующие дозвоны в пределах TTL
  кэша пропускают H3 ещё до того, как сработает per-uplink окно
  даунгрейда.
- **UDP fallback:** `ws_h3 → ws_h2 → ws_h1`. Та же логика на UDP-WS пути.
- **Resume:** TCP и UDP получают по своему слоту в
  `global_resume_cache` (`<uplink>#tcp` / `<uplink>#udp`). Инлайн
  H3→H2→H1 fallback внутри `connect_transport` пробрасывает
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
  `connect_transport`, аналогично SS-over-WS.
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
| `tcp_mid_session_retry_buffer_bytes` | `262144`           | bytes | размер ring-буфера на сессию для Ack-Prefix mid-session retry (`0` отключает retry; см. раздел «Mid-session retry» ниже) |
| `tcp_mid_session_retry_budget`       | `1`                | int   | максимум попыток redial mid-session на одну сессию (`0` отключает retry — эквивалент `tcp_mid_session_retry_buffer_bytes = 0`) |
| `tcp_mid_session_retry_overflow_policy` | `"soft"`        | enum  | поведение при чанке больше cap'а ring-буфера: `"soft"` (дефолт) держит сессию живой и отдаёт `failed_replay` на будущих ретраях; `"hard"` сразу обрывает сессию, чтобы гарантировать ретраебельность остальных |
| `tcp_mid_session_retry_consume_timeout_secs` | `5`            | с     | верхний предел ожидания v1 Ack-Prefix control frame от сервера при resume hit; защищает pinned relay от молчащего/сломанного сервера |
| `tcp_symmetric_replay_enabled`       | `true`             | bool  | opt-in в v2 Symmetric Downlink Replay протокол на retry-redial'ах; `false` подавляет v2-advertise без отключения v1.x retry (например, на время постепенного раскатывания серверной стороны) |
| `tcp_symmetric_replay_max_bytes`     | `1048576`          | байт  | жёсткий cap на принимаемый v2 `replay_len` от сервера; ответы выше этого валят сессию — защита от вредоносного пира, индуцирующего unbounded buffering |
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

Принудительная реселекция в `active_passive`:

При смене активного аплинка (probe-failover, ручной control-plane
switch, решение `auto_failback`) прокси гарантирует egress-
консистентность, разрывая сессии, привязанные к ставшему пассивным
аплинку — у разных аплинков обычно разные egress IP, и оставление
in-flight сессии на старом аплинке ломало бы любую source-IP-
зависимую логику на destination.

- **SOCKS5 TCP**: watcher pinned-relay видит switch и принудительно
  закрывает клиентский сокет с TCP RST (`SO_LINGER {l_onoff=1,
  l_linger=0}` + drop). Приложение видит hard reset и переподключается
  через новый активный аплинк. Счётчик:
  `outline_ws_rust_socks_tcp_strict_aborts_total{reason="global_switch"}`.
- **SOCKS5 UDP**: per-group downlink-loop подписан на тот же сигнал и
  атомарно подменяет transport на switch
  (`reconcile_global_udp_transport`); клиент не видит L4-close (у UDP
  его нет), но следующий датаграмма уже идёт через новый аплинк.
- **TUN TCP**: симметрично SOCKS5, но на L3 — TUN engine отправляет
  `RST+ACK` сегмент в kernel-TCP приложения. Метрика:
  `outline_ws_rust_tun_tcp_events_total{event="global_switch"}`.

Поведение включается фактом запуска в `active_passive` (любой scope);
`active_active` не затрагивается — там нет понятия «единственного
активного аплинка», от которого можно «отклониться», поэтому strict-
abort watcher не срабатывает. Кому нужна посессионная миграция без
abort — оставайтесь на `active_active` + `per_flow`.

Mid-session retry (Ack-Prefix Protocol v1):

- Когда у запинённой SOCKS TCP-сессии mid-stream обрывается upstream
  транспорт (H3 APPLICATION_CLOSE, NAT eviction, server-initiated
  reset и т.п.), relay может прозрачно сделать одну попытку
  re-dial на тот же SS-WS аплинк. Новый dial объявляет
  `X-Outline-Resume-Ack-Prefix: 1`; outline-ss-rust сервер с
  включённой фичей шлёт 14-байтный control-frame на resume-hit, в
  котором сообщает точный байтовый offset upstream-байт, которые
  он успел отправить наверх. Клиент replay'ит хвост из своего
  uplink-буфера от этого offset'а — upstream видит каждый байт
  ровно один раз.
- `tcp_mid_session_retry_buffer_bytes` задаёт лимит ring-буфера на
  сессию. Дефолт `262144` (256 KiB) — достаточно, чтобы вместить
  типичные HTTP request bodies и payload'ы идемпотентных RPC, и
  достаточно мало, чтобы держать N параллельных сессий не было
  заметно на фоне kernel socket buffers. `0` полностью отключает
  retry (буфер вообще не аллоцируется).
- `tcp_mid_session_retry_budget` ограничивает число попыток redial
  на сессию. Дефолт `1` — большинство retriable-сбоев восстанавли-
  ваются с первой попытки. Большие значения окупаются только на
  по-настоящему flaky-транспортах; каждая попытка стоит одного
  полного replay'а буфера даже при persistent failure. `0` полностью
  отключает retry (то же, что и `buffer_bytes = 0`).
- `tcp_mid_session_retry_overflow_policy` определяет, что
  происходит если один uplink-чанк больше
  `tcp_mid_session_retry_buffer_bytes`. Такой чанк сам по себе
  нельзя реплейнуть, и retry-контракт сессии с этого момента
  необратимо нарушен. `"soft"` (дефолт) — поднимет метрику
  `outcome="buffer_overflow"`, отправит чанк дальше и продолжит;
  будущие retry на этой сессии вернут `failed_replay`. `"hard"`
  сразу убивает сессию. Бери `"hard"` когда retry-корректность
  для всего деплоя важнее жизни одной outlier-сессии (например,
  интерактивные RPC, где порванный replay испортит state); бери
  `"soft"` (дефолт) для типичного веб-трафика, где живучесть
  сессии — пользовательски видимая метрика.
- `tcp_mid_session_retry_consume_timeout_secs` ограничивает время
  ожидания v1 Ack-Prefix control frame от сервера при успешном
  resume-hit. Сервер шлёт его сразу же; таймаут нужен, чтобы
  сломанная сетевая дорожка или misbehaving сервер не остановили
  pinned relay незаметно. Дефолт `5` — комфортно покрывает
  спутник + сотовую связь. Уменьшай на known-low-RTT деплоях;
  большие значения обычно маскируют проблемы с retry-поведением.
- v1 sweet spot — HTTP request bodies, идемпотентные RPC. НЕ для
  SSH-подобных downlink-heavy сессий *сама по себе*: v1 не
  replay'ит downlink-направление. Этот gap закрывает протокол v2
  Symmetric Downlink Replay (см. ниже).
- Ограничено WS-family carrier'ами — SS-WS (`transport = "ws"`) и
  VLESS-WS (`transport = "vless"`). Raw QUIC и direct-socket
  Shadowsocks для retry в v1 — no-op; relay падает в legacy-
  поведение «один shot, прокидываем ошибку наружу» без видимых
  изменений.
- Redial идёт на **wire, который менеджер сейчас считает активным**
  для этого транспорта (`active_wire`), а не безусловно на primary.
  Если ранее dial-loop уже сдвинул `active_wire` на fallback из-за
  поломки primary, retry дёргает именно этот fallback (с тем же
  Ack-Prefix / Symmetric Downlink Replay capability'и, что и primary),
  вместо того чтобы вслепую долбить мёртвый primary URL и накапливать
  runtime-failure стрик на родительский uplink. Сам fallback wire тоже
  должен быть SS-WS или VLESS-WS, иначе retry схлопывается в no-op и
  сессия завершается на исходной mid-stream-ошибке.
- Outcome'ы экспортируются в метрику
  `outline_ws_rust_uplink_mid_session_retries_total{outcome}` со
  значениями `outcome ∈ {success, failed_redial, failed_replay,
  buffer_overflow, downlink_truncated}`. Wire-формат — в
  `docs/SESSION-RESUMPTION.md` § Ack-Prefix Protocol (v1)
  репозитория outline-ss-rust.

Symmetric Downlink Replay (v2):

- Опциональное opt-in расширение поверх v1.x. Закрывает
  byte-loss gap в **downstream**-направлении (server→client),
  который v1 оставляет открытым: байты, которые сервер эмитнул
  в WebSocket, но клиент никогда не наблюдал до того как нижний
  TCP умер, replay'ятся на следующем resume-hit'е, в порядке,
  ДО того как пойдут свежие upstream-байты. Обязателен для SSH
  и других протоколов, рассматривающих байтовый поток как
  единый упорядоченный лог; для протоколов с собственным
  application-layer retry (HTTP request bodies, идемпотентные
  RPC) можно оставить выключенным и полагаться только на v1.
- Wire-side: клиент анонсирует
  `X-Outline-Resume-Symmetric-Replay: 1` И сообщает свой
  текущий `client_acked_offset` через
  `X-Outline-Resume-Down-Acked: <decimal>`. Сервер эмитит
  14-байтный control frame `"ORDR"` + replay payload (байты
  `[client_acked_offset, total_sent_downlink)`) сразу после v1
  кадра `"ORSM"` на resume-hit'е. Сервер гейтит v2 на
  (a) v1 тоже договорён и (b) его конфиг
  `[session_resumption].downlink_buffer_bytes > 0` (default `0`
  = выключено). Полная спека — в репозитории сервера в файле
  `docs/SESSION-RESUMPTION.md` § Symmetric Downlink Replay (v2).
- `tcp_symmetric_replay_enabled` (default `true`) —
  операторский переключатель. Capability активен в runtime
  только когда (a) v1.x retry включён
  (`tcp_mid_session_retry_buffer_bytes > 0` И
  `tcp_mid_session_retry_budget > 0`), (b) этот knob включён,
  (c) сервер эхо'ит обе capability'и. `false` подавляет
  v2-advertise без отключения v1.x.
- `tcp_symmetric_replay_max_bytes` (default `1048576` = 1 MiB) —
  жёсткий cap на v2 `replay_len`, который клиент примет от
  сервера. Ответы выше этого валят сессию — защита от
  вредоносного пира, индуцирующего unbounded buffering. Серверы
  в адекватной конфигурации ставят `downlink_buffer_bytes`
  сильно ниже этого cap'а (default 64 KiB на сервере), так что
  он срабатывает только против явно некорректного пира.
- Политика truncation: когда сервер выставляет
  `REPLAY_TRUNCATED` (его ring проехал за client-reported
  offset, например очень долгая парковка или очень маленький
  серверный буфер), клиент уважает
  `tcp_mid_session_retry_overflow_policy`: `"soft"` продолжает
  сессию под irrecoverable downstream gap и инкрементирует
  `outline_ws_rust_uplink_mid_session_retries_total{outcome="downlink_truncated"}`;
  `"hard"` обрывает сессию сразу. Используйте то же значение,
  что и для v1 buffer-overflow, чтобы политика была
  консистентной.
- Тот же eligibility-gate, что у v1 — SS-WS / VLESS-WS /
  VLESS-XHTTP carriers; raw QUIC и direct-socket Shadowsocks
  вне scope'а (нет HTTP-layer carrier'а для v2-negotiation).

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
- **Саб-таблицы** (`ws` / `http` / `dns` / `tcp` / `tls`) заменяются
  целиком. Если группа задаёт `[uplink_group.probe.http]`, шаблонная
  `[outline.probe.http]` для этой группы отбрасывается полностью —
  все нужные поля надо повторить.
- **Чтобы пробы запустились**, в результирующей (после мержа)
  конфигурации должна остаться хотя бы одна из `ws` / `http` / `dns` /
  `tcp` / `tls`, иначе probe-loop для группы не стартует.
- **Application-уровневые саб-пробы взаимоисключающие.** В одном цикле
  выполняется только одна из `tls` / `http` / `tcp` — это ограничивает
  количество handshake'ов за цикл. Приоритет: `tls` → `http` → `tcp`:
  если задана `[outline.probe.tls]`, саб-таблицы `http` и `tcp` молча
  пропускаются. `ws` и `dns` всегда работают параллельно с активной
  из трёх.

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
- `http` / `dns` / `tcp` / `tls`: выключить per-group нельзя. Мерж
  использует `override.or(template)`
  ([groups.rs:160](src/config/load/groups.rs:160)), поэтому пропущенная
  саб-таблица наследует значение из шаблона, и способа задать «явное
  None» нет. Если нужно, чтобы одна группа работала без какой-то из
  этих проб, а другая — с ней, уберите саб-таблицу из `[outline.probe]`
  и объявите её только в нужных группах через
  `[uplink_group.probe.<тип>]`.

## TLS-handshake проба data-path (`[outline.probe.tls]`)

Plain HTTP проба гонит `HEAD` через туннель к настроенному
`http://...`-URL — никакого TLS она не делает, так что upstream-фильтр,
тихо режущий `ServerHello` для конкретных SNI, для неё невидим.
User-flow паттерн `chunk0_timeout` (handshake к серверу-uplink прошёл,
ClientHello переслан upstream-цели, ответных байт не приходит) при этом
проходит мимо: `uplink_health` остаётся `1`, streak до
`probe.min_failures` не доходит, per-flow rescue гасит симптом.

`[outline.probe.tls]` закрывает этот пробел. Открывает тот же туннель,
что HTTP-проба, и поверх него гонит реальный `ClientHello →
ServerHello / Certificate → Finished → close_notify` к настроенной
паре `(SNI, port)`. Никакого HTTP-обмена после handshake — цель
воспроизвести точно тот же «жду ответных байт» паттерн, чтобы probe
падал на тех же условиях, что user-flow, и runtime-эскалация
(`probe-driven healthy=false → uplink выпадает из selection → global
active съезжает`) реально срабатывала.

```toml
[outline.probe.tls]
# Каждая цель — одна из форм:
#   - полный URL:         "https://www.youtube.com/"
#   - URL с портом:       "https://www.youtube.com:8443/"
#   - host:port:          "www.youtube.com:443"
#   - bare host:          "www.instagram.com"   # → порт 443
#   - IPv6 в скобках:     "[::1]:8443"
# URL-форма принимает только `https://` (TLS-handshake-only проба не
# имеет смысла поверх `http://`). Путь/query/fragment игнорируются —
# проба не шлёт HTTP-запрос, только TLS handshake.
# Probe ротирует список по одной записи за цикл — фильтрация по
# конкретному SNI всплывает наружу, а не маскируется одной
# всегда-доступной целью.
targets = [
  "https://www.youtube.com/",
  "www.instagram.com",
]
```

Как выбирать цели:

- Берите SNI, по которым реально ходит пользовательский трафик
  деплоймента, а не stub-origins типа `example.com`. Probe полезен
  только когда его цель чувствительна к тому же upstream-фильтру,
  что и user-flows.
- Двух-четырёх целей достаточно. Probe платит один свежий handshake
  на uplink за цикл, ротация по списку размывает cycle-load.
- Не включайте свой собственный uplink-host — outer transport уже
  покрывается WS sub-probe.

Метрики пишутся под label `probe="tls"`. Разделите его от `probe="http"`
/ `probe="ws"` на панели «Probe Runs (success/error, by sub-probe)»,
чтобы видеть новый сигнал отдельно. В эпизоде TLS-DPI серия
`probe="tls" result="error"` должна повторять форму
`runtime_failure_signatures_total{signature="chunk0_timeout"}`
у user-flow; если она остаётся плоской на пиках user-flow — выбранные
SNI не попадают под тот же фильтр, нужны другие.

Взаимоисключаются с `[outline.probe.http]` и `[outline.probe.tcp]`
в одном цикле (приоритет: `tls` → `http` → `tcp`). Можно оставить
`[outline.probe.http]` в шаблоне для групп, которые не объявляют
`tls` — цикл выберет блок с наивысшим приоритетом из заданных.

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
`connect_transport`.

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
трафика. В пул входит шесть профилей: Chrome 142 (Windows + macOS),
Firefox 150 (Windows + macOS), Safari 19 (macOS), Edge 142 (Windows).

Доступны две стабильные стратегии. **`process_stable`
(рекомендуемый дефолт)** выбирает одну идентичность на старте
процесса и использует её на каждом дозвоне независимо от того, какой
аплинк сработал — ровно так, как реальный пользователь с одним
браузером выглядит для on-path-наблюдателя: один source IP, один
User-Agent. Выбор сидируется из OS-уровня hostname (`gethostname(2)`
на Unix, `%COMPUTERNAME%` из process environment на Windows),
поэтому идентичность стабильна между рестартами на одной машине.
В контейнерах / sandbox-средах, запущенных без явного hostname
(`docker run --hostname=""`, `unshare --uts /bin/sh -c …` и проч.),
syscall не возвращает полезного значения и сид падает на `rand`
при старте процесса — всё ещё стабильно в пределах процесса, но
ротируется при рестарте. Если в контейнере нужна детерминированная
идентичность, оператор должен передать `--hostname` (Docker),
`Hostname=` (systemd) или эквивалентный runtime-knob; чтение
shell-переменной `$HOSTNAME` *не сработает*, потому что демоны её
не наследуют.

`per_host_stable` — это легаси-разрез по пирам: профиль хешится из
`(host, port)`, поэтому каждый пир видит одну консистентную
идентичность, но **разные** пиры видят **разные** идентичности
от того же source IP. Полезно только когда пиры полностью
развязаны между наблюдателями (разные AS, разные юрисдикции,
никакого глобального DPI на пути клиента). Для большинства
deployment'ов это сливает «автоматизированный мульти-pseudo-клиент»,
потому что глобальный наблюдатель коррелирует: один и тот же
source IP не должен производить четыре browser identity за 30
секунд против четырёх разных хостов. Предпочтительно
`process_stable`, если нет конкретной причины наоборот.

Тумблер opt-in. По умолчанию форма провода полностью совпадает с тем,
что было до этого изменения — никаких новых заголовков, кроме
`X-Outline-Resume-*`. Включается ключом верхнего уровня
`fingerprint_profile` в `config.toml`:

```toml
# верхний уровень — рядом с [socks5], [metrics], [outline], [[uplink_group]]
fingerprint_profile = "stable"   # алиас `process_stable` — рекомендуется
```

Допустимые значения:

- `"off"` / `"none"` / `"disabled"` / отсутствие ключа — по умолчанию,
  заголовки не добавляются.
- `"stable"` / `"process"` / `"process_stable"` / `"process-stable"` —
  **рекомендуется.** Одна идентичность на весь процесс; форма
  реального пользователя для любого наблюдателя.
- `"per_host_stable"` / `"per-host-stable"` / `"per-host"` — легаси
  per-peer split; см. оговорку выше.
- `"random"` — свежий профиль на каждый дозвон. Полезно для тестов
  или когда стабильная идентичность сама по себе нежелательна.

> Важное изменение: ранее короткий `stable` алиасился в
> `per_host_stable`. Теперь он резолвится в `process_stable`.
> Операторы со старыми конфигами с `stable` автоматически
> получают более безопасное поведение; те, кому нужен именно
> per-peer split, должны прописать `per_host_stable` полностью.

То же значение можно задать через CLI или переменную окружения —
это **переопределяет** top-level ключ из TOML (per-uplink override
по-прежнему побеждает поверх любого источника — приоритет такой же,
как у `--listen` / `--metrics-listen`):

```sh
outline-ws-rust --fingerprint-profile stable
# либо:
OUTLINE_FINGERPRINT_PROFILE=random outline-ws-rust
```

Принимает тот же набор алиасов, что и TOML-ключ. Полезно для
разовой проверки опт-ина на уже развёрнутой конфигурации без
редактирования файла.

Для встроенных вызовов (тесты, кастомные бинарники) стратегию также
можно проставить прямо через Rust API; bootstrap-бинарь подхватывает
значение из конфига при старте:

```rust
use outline_transport::{
    init_fingerprint_profile_strategy, FingerprintProfileStrategy,
};

init_fingerprint_profile_strategy(FingerprintProfileStrategy::ProcessStable);
```

### Наблюдаемость

`tracing::info!` пишет каждую тройку `(host, port, profile)` при
первом её наблюдении в процессе — удобно убедиться, что стратегия
действительно заехала после правки конфига.

В Prometheus метрика
`outline_ws_rust_uplink_fingerprint_profile_strategy_info` несёт
лейблы `group`, `uplink`, `strategy` (одно из `none`,
`per_host_stable`, `process_stable`, `random`). Gauge равен `1` на активной стратегии
и `0` на остальных, публикуется безусловно — отсутствующая серия
означает баг в snapshot-пайплайне, а не выключенную фичу.
Метрика отражает **эффективную** стратегию: per-uplink override
если задан, иначе глобальный дефолт. Та же строка доступна в JSON
с `/snapshot` как поле `fingerprint_profile_strategy` у каждого
аплинка — поле опускается из JSON, когда стратегия равна `none`,
поэтому старые snapshot-консьюмеры получают ту же форму, что и до
появления этого ключа.

В пакетной Grafana-дашборде есть stat-панель **«Fingerprint
Strategy»** в верхней строке статуса рядом с `Selection Mode`,
`Routing Scope` и `Active Uplink`. Каждая ячейка показывает, сколько
аплинков в выбранном фильтре `group` сейчас на каждой стратегии;
пустые ячейки серые, так что активное распределение видно сразу.

Встроенный HTML-дашборд control-plane'а рисует per-uplink чип
с **именем активного профиля** (например, `Chrome 142 macOS`)
рядом с протокол-pill в каждой строке аплинка, где эффективная
стратегия не равна `none`. Цвет — по семейству: синий для
стабильных профилей (Chrome / Firefox / Safari / Edge под
`process_stable` или `per_host_stable`) и фиолетовый для `Random` —
оператор сразу видит, идентичность приколота или ротируется.
Аплинки на `none` чипа не получают — типичный opt-out-deployment
визуально не меняется. Tooltip несёт и сырой id профиля, и стратегию
(`fingerprint_profile_name = chrome-142-macos · strategy = process_stable`),
чтобы отрисованный лейбл сразу сопоставлялся с Prometheus-лейблом
`strategy` и snapshot-полем без перевода между формами.

Активный профиль вычисляется в snapshot-билдере через
`select_with_strategy(primary_dial_url, effective_strategy)` —
сначала `tcp_dial_url()`, при его отсутствии — `udp_dial_url()`
(для UDP-only аплинков); для plain-Shadowsocks (нет URL) профиль
не считается. Поле в snapshot называется
`UplinkSnapshot::fingerprint_profile_name` и проходит через
topology JSON как `fingerprint_profile_name` (опускается, если
отсутствует).

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
| `transport` | всегда | `ws` / `shadowsocks` / `vless`. **Ограничений по уникальности нет** — same-transport-as-parent и duplicate-transport entries разрешены явно. Самая распространённая кросс-family форма: VLESS primary на `xhttp_h*` плюс VLESS fallback на `ws_h*` (тот же `transport = "vless"`, другая carrier-семья, другой dial URL); два SS fallback'а на разные хосты (belt-and-suspenders) тоже работают. Dial-loop и per-wire mode tracking трактуют каждый fallback как собственный wire независимо от `transport`. |
| `tcp_ws_url`, `udp_ws_url`, `tcp_mode`, `udp_mode` | `transport = "ws"` | `tcp_ws_url` обязателен; `udp_ws_url` опционален (UDP-fallback opt-in). |
| `vless_ws_url`, `vless_xhttp_url`, `vless_mode`, `vless_id` | `transport = "vless"` | URL должен соответствовать `vless_mode` (xhttp\_\* → `vless_xhttp_url`; ws/quic → `vless_ws_url`). `vless_id` per-wire и **не наследуется** от родителя — у разных VLESS-эндпоинтов разные uuid'ы. |
| `tcp_addr`, `udp_addr` | `transport = "shadowsocks"` | `tcp_addr` обязателен; `udp_addr` опционален. |
| `cipher`, `password` | наследуются | По умолчанию — значение родителя. Переопределите тут, если fallback использует другой shared secret. |
| `fwmark`, `ipv6_first`, `fingerprint_profile` | наследуются | То же самое: дефолтятся к родителю, можно переопределить per-fallback. |

### Поведение

#### Per-сессионный dial-loop

- Для каждой новой сессии dial-loop итерирует wire'ы по
  `wire_dial_order` — стартует с **активного wire'а** (изначально `0`
  = primary; продвигается state-машиной sticky-fallback ниже) и
  заворачивается через остальную цепочку, чтобы primary всё ещё был
  протестирован last-resort'ом, даже если активный приколот к
  fallback'у. Первый wire, который успешно дозвонился, несёт сессию.
- Успешный дайл **невидим** для балансировщика кроме тика метрики
  `outline_uplink_selected`. `report_runtime_failure` родителя
  инкрементируется только когда **все** wire'ы аплинка провалились в
  одной сессии — транзиентные сбои одного wire'а больше не демотят
  аплинк целиком, пока работает другой.
- Runtime-сбои, приписанные к **конкретному wire'у** (chunk-0
  failures, несущие индекс упавшего wire'а, и mid-session resets,
  несущие индекс текущего relay-wire'а), гейтятся той же проверкой
  active-wire, что и dial-loop: сбой, привязанный к wire'у, с
  которого менеджер уже ушёл, считается session-local fallback churn,
  пишется только как suppressed-метрика
  (`outline_ws_rust_uplink_runtime_failures_suppressed_total`) и
  **не** копится в penalty / cooldown /
  consecutive_runtime_failures родительского аплинка. Аплинки без
  fallback'ов (single-wire) ведут себя ровно как раньше — там нет
  «non-active wire», чтобы что-то suppress'ить.

#### Sticky fallback + auto-failback (active-wire state machine)

- После **`probe.min_failures` подряд провалов dial'а** wire'а, с
  которого новые сессии сейчас стартуют (`active_wire`), dial-loop
  продвигает `active_wire` на следующий wire в цепочке и пинит его
  на `LoadBalancingConfig::mode_downgrade_duration` (один knob, два
  применения — per-wire mode-downgrade и per-uplink active-wire
  pin). Последующие новые сессии стартуют со sticky-wire'а; primary
  всё ещё в конце dial-цепочки, так что recovered primary может
  обслуживать трафик, если все остальные wire'ы провалились.
- По истечении пина `active_wire` сбрасывается обратно на `0`
  (primary), и следующая сессия снова пробует первый-выбор оператора.
  Если primary всё ещё сломан, streak пересобирается — таймер это
  rate-limit на retry, а не one-shot.
- **Ранний failback через probe-recovery.** Probe (в этой итерации
  всё ещё primary-only) триггерит немедленный snap-back на primary,
  как только наберёт `probe.min_failures` подряд успехов — pin timer
  это не жёсткий wait. Если primary оправился за пару probe-циклов
  (типично 2 × `probe.interval_secs`), трафик возвращается к нему
  задолго до естественного истечения 60-секундного пина. Тот же knob
  `min_failures` это и failure-threshold, и success-stability (одна
  ментальная модель: N подряд probe-исходов перекидывают active wire
  в любую сторону).
- Состояние **per-transport**: TCP и UDP двигаются независимо
  (`PerTransportStatus::active_wire` разделено per-transport).
  Метрика `outline_ws_rust_uplink_active_wire_index{transport}`
  показывает текущий wire для дашбордов.

#### Случайная forward-only ротация (`shuffle_wires = true`)

Per-uplink опционально, заменяет операторскую упорядоченную цепочку
с бесконечной обёрткой на рандомизированную forward-only ротацию с
эскалацией uplink-failover после полного круга:

```toml
[[outline.uplinks]]
name        = "edge-shuffled"
group       = "main"
transport   = "vless"
vless_xhttp_url = "https://cdn-a.example.com/SECRET/xhttp"
vless_id        = "00000000-0000-0000-0000-000000000000"
vless_mode      = "xhttp_h3"
shuffle_wires   = true

  [[outline.uplinks.fallbacks]]
  transport       = "vless"
  vless_xhttp_url = "https://cdn-b.example.com/SECRET/xhttp"
  vless_id        = "11111111-1111-1111-1111-111111111111"
  vless_mode      = "xhttp_h3"

  [[outline.uplinks.fallbacks]]
  transport       = "vless"
  vless_xhttp_url = "https://cdn-c.example.com/SECRET/xhttp"
  vless_id        = "22222222-2222-2222-2222-222222222222"
  vless_mode      = "xhttp_h3"
```

Семантика:

- **На старте**: цепочка `[primary, fallbacks[0], …]` перемешивается
  единожды через `rand::thread_rng()`. Каждый перезапуск процесса
  даёт другой порядок — operator-primary может оказаться в любой
  позиции. Шафл сохраняет множество wires точно (ни одного
  потерянного, дублированного или испорченного) и parent-level
  идентичность (`name`, `weight`, `group`, `fingerprint_profile`)
  остаётся на аплинке независимо от того, какой wire оказался в
  слоте 0.
- **Collision-free внутри группы**: когда несколько аплинков в
  одной `group` включают `shuffle_wires`, loader выдаёт каждому
  такую перестановку wires, которая не совпадает ни с одной уже
  использованной в группе. У трёх 3-wire аплинков наивные
  независимые `rand::thread_rng()`-шафлы давали ≈ 44% шанс
  совпадения двух из них на старте — чистая статистика, но это
  ломает операторский intent «разные dial-порядки на разных
  аплинках». Проход `shuffle_wire_chains_per_group` в
  `load_uplinks` перешафливает до 32 раз при обнаружении
  коллизии, в пределах естественного потолка `N ≤ total_wires!`
  (нельзя получить больше уникальных перестановок чем физически
  существует). Группы изолированы: два аплинка из разных групп
  могут совпасть в перестановке — дедуп нацелен на распределение
  *внутри* группы, не по всему конфигу.
- **В runtime forward-ротация продвигается тремя источниками
  ошибок** через одну и ту же state machine `record_wire_outcome`:
  - **dial-провалы** (новая сессия не открылась на активном wire) —
    как у legacy-цепочки, через цикл dial'а;
  - **probe-провалы** (`process_probe_err` /
    `run_fallback_wire_probe`) — двигают `active_wire` на
    probe-пути и инкрементируют счётчик круга;
  - **runtime-провалы** (`report_runtime_failure*` — например,
    `ws upstream read idle for 300s on datagram channel`, mid-session
    transport resets, chunk-0 timeouts) — кормят per-wire streak,
    так что повторяющиеся ошибки уже установленной сессии на
    активном wire продвигают ротацию, а не только флипают
    uplink-level health.

  Без подачи runtime-провалов доминирующий production-кейс (idle
  WS read на установленной сессии) никогда бы не тикал
  `active_wire` и в дашборде не было бы видно ротации, хотя wire
  явно сломан.
- **Счётчик круга**: per-transport `wires_failed_in_round`
  инкрементируется при каждом продвижении active wire,
  независимо от того, какой источник его сдвинул. Когда счётчик
  достигает `total_wires` (каждый wire оказался активным в
  провальном круге со времени последнего успеха), аплинку
  принудительно ставится `healthy = Some(false)` и cooldown
  (`failure_cooldown`) — балансировщик берёт другой uplink для
  новых сессий.
- **Гейт на uplink-level healthy flip**: пока счётчик круга не
  достиг `total_wires`, *uplink-level* флип в `healthy = Some(false)`
  **подавляется** на этом аплинке — и на probe-пути
  (`record_transport_failure`), и на runtime-пути
  (`report_runtime_failure_inner`). Per-wire счётчики
  (`consecutive_failures`, `consecutive_runtime_failures`)
  продолжают накапливаться, но LB не убирает аплинк из кандидатов
  раньше времени — ротация по wires успевает пройти круг перед
  uplink-failover. После исчерпания круга гейт отпускается и флип
  срабатывает.
- **Вертикальный carrier-каскад до wire-rotation**: для WS-family
  и VLESS-XHTTP wires шаг wire-advance тоже гейтится на
  **effective mode активного wire** — пока активный wire не на дне
  своей family. Пока активный wire на `ws_h3` / `ws_h2` /
  `xhttp_h3` / `xhttp_h2`, runtime / probe / dial failures
  направляются в существующую машинерию `extend_mode_downgrade`
  (cap wire'а на ранг ниже: `ws_h3 → ws_h2 → ws_h1`,
  `xhttp_h3 → xhttp_h2 → xhttp_h1`), а не в per-wire advance
  counter. Только когда wire достигает `ws_h1` / `xhttp_h1`
  (или family без descent stack: Shadowsocks direct sockets, raw
  QUIC ALPN cases) — следующая ошибка на активном wire вызывает
  собственно wire-rotation step. Это даёт оператору
  `min_failures × carrier_ranks` бюджет на каждом wire перед
  переходом на следующий, что соответствует обещанному в общей
  доке каскаду `h3 → h2 → http1` на активном плече.
- **Recovery probe удерживает cap**: при `shuffle_wires = true`
  configured-carrier recovery probe в
  [`UplinkManager::note_recovery_probe_success`] **не сбрасывает**
  mode-downgrade cap даже после
  `RECOVERY_SUCCESS_STREAK_THRESHOLD` (2 подряд успеха). Cap всё
  ещё может истечь по своему `mode_downgrade_until` дедлайну
  (default 60 s). Обоснование: handshake-only recovery probe на
  `xhttp_h3` обычно успешен даже когда реальный data-plane трафик
  ещё фейлит (production кейс из лога, из-за которого и делалась
  эта итерация); сброс cap'а на этом сигнале возвращает трафик к
  сломанному configured carrier и снова триггерит тот же descent
  на следующей ошибке, оставляя цикл на верхнем ранге вместо
  спуска до floor.
- **Сброс на любом успехе wire**: успешный dial *любого* wire
  (primary или fallback) обнуляет счётчик круга и ставит штамп
  `last_any_wire_success`; успешный probe также обнуляет его
  (`record_transport_success`). Трафик, стабилизировавшийся на
  одном wire, перезапускает круг; следующий провал продолжит
  forward-ротацию с того wire, который только что работал, а не с
  фиксированного нуля.
- **Per-wire бюджеты**: при продвижении active wire (любым путём —
  dial / probe / runtime) `consecutive_failures` и
  `consecutive_runtime_failures` сбрасываются в `0`, так что
  новый wire получает свой `min_failures`-бюджет, прежде чем
  быть признанным сломанным.

Когда использовать:

- Есть несколько примерно эквивалентных fallback-эндпоинтов
  (несколько CDN, несколько SNI к одному upstream, зеркальные
  Shadowsocks-серверы) и хочется, чтобы разные перезапуски процесса
  или разные реплики распределяли нагрузку между ними, а не били
  всегда первой записью списка.
- Нужен явный «сдаюсь на этом uplink» после одного полного прохода
  по цепочке, а не legacy wrap-forever, чтобы балансировщик быстрее
  переключился на следующий uplink, когда все wire'ы текущего
  деградировали.

Когда **не** стоит:

- Есть чёткий предпочтительный primary (быстрый, дешёвый), а
  fallbacks — только аварийный резерв. Оставьте `shuffle_wires`
  выключенным, чтобы operator-ordered цепочка соблюдалась, а
  `auto_failback` возвращал трафик обратно на сконфигурированный
  primary.

По умолчанию `false` — существующие конфиги сохраняют операторский
порядок цепочки и wrap-forever state machine без изменений.

#### Отключение carrier-каскада на wire (`carrier_downgrade = false`)

Per-uplink opt-out для вертикального `h3 → h2 → h1` (и
`xhttp_h3 → xhttp_h2 → xhttp_h1`) каскада внутри WS / VLESS-XHTTP
wire:

```toml
[[outline.uplinks]]
name        = "edge-no-cascade"
group       = "main"
transport   = "vless"
vless_xhttp_url = "https://cdn.example.com/SECRET/xhttp"
vless_id        = "00000000-0000-0000-0000-000000000000"
vless_mode      = "xhttp_h3"
shuffle_wires   = true
carrier_downgrade = false
```

С отключённым флагом:

- `extend_mode_downgrade` no-op для этого аплинка: никакого
  `mode_downgrade_*` состояния не устанавливается, никаких `↘ ↘`
  стрелок на дашборде, никакого `mode_downgrade_secs` окна на ранг.
- `wire_is_at_carrier_floor` всегда true. При `shuffle_wires = true`
  это сворачивает per-wire каскад в прямой wire-to-wire переход —
  сбои сразу переходят на следующий wire по достижении
  `min_failures`, а не тратят окно downgrade на каждый промежуточный
  carrier.
- Без `shuffle_wires` старое sticky-поведение сохраняется, разница
  только в том, что dial-loop никогда не capping на нижний ранг.

Когда использовать:

- Оператор знает, что промежуточные ранги тоже мертвы — DPI режет
  весь upstream независимо от HTTP version, сервер не объявляет
  нижне-ранговые carrier'ы, окно cap добавляет чистую latency перед
  неизбежной ротацией wire.
- Вместе с `shuffle_wires = true` и несколькими примерно
  эквивалентными fallback'ами это даёт оператору политику «skip
  h2/h1, сразу следующий wire» — дешевле в обходе чем полный
  вертикальный каскад.

По умолчанию `true` — существующие конфиги сохраняют descent-контракт
без изменений.

#### Mid-session handover (chunk-0 wire-aware failover)

- Если у сессии чанк-0 застрял (нет первого байта от upstream'а в
  пределах `tcp_chunk0_failover_timeout`), цикл chunk-0 failover
  теперь сначала пробует все остальные wire'ы **этого же** аплинка
  (Phase A) перед прыжком на другой аплинк (Phase B). Токен
  X-Outline-Resume, выпущенный для провалившегося wire'а, едет в
  wire-handover dial через identity-level resume-cache (см. «Resume
  через wire-свитчи» ниже), так что handover-via-resume бесшовен на
  сервере outline-ss-rust с включённой фичей. События wire-handover
  пишутся на failover-счётчик с `transport="tcp_wire"`; cross-uplink
  failover'ы — `transport="tcp"`.

#### Resume через wire-свитчи

- Fallback TCP- и UDP-дайлы участвуют в
  `outline_transport::global_resume_cache()` под ключом
  `<uplink_name>#<transport>` — **тот же identity-level ключ**, что
  у primary. Primary VLESS-дайл, выпустивший session id, далее WS
  fallback-дайл после провала primary'а — токен предъявляется на
  fallback-дайле; server-side resume re-attach'ит upstream-сессию.
  Работает для любой комбинации, где оба wire'а несут WS-resume
  header (WS, VLESS-WS, VLESS-XHTTP). У Shadowsocks fallback'а нет
  WS-слоя, и он дайлит свежим — рестарт сессии там неизбежен.

#### Liveness override

- Без помощи probe-здоровье primary гейтило бы весь аплинк из выдачи
  (`selection_health` → `effective_health` → false), и fallback wire
  не получил бы шанса. Чтобы это предотвратить, аплинк хотя бы с
  одним сконфигурированным fallback'ом считается selectable, если
  **любой** wire — primary или fallback — недавно успешно дозвонился
  в окне `runtime_failure_window`. Single-wire аплинки сохраняют
  probe-only гейтинг (никаких false-positive liveness из устаревших
  primary-успехов).
- **Bootstrap pass-through.** Override по recent-success нуждается
  хотя бы в одном предыдущем wire-успехе, чтобы зацепиться. Если
  primary помечен probe'ом как unhealthy с самого первого цикла (или
  поднялся неработающим после рестарта) и `last_any_wire_success` ещё
  ни разу не штамповался, selection-слой всё равно пропускает аплинк
  в кандидаты — при условии, что fallbacks сконфигурированы и
  транспорт не в cooldown — чтобы dial-loop получил шанс попробовать
  fallback. Иначе dial-loop (раньше — единственный, кто штамповал
  `last_any_wire_success`) и фильтр кандидатов блокируют друг друга.
  Snapshot-side **effective health** этим bootstrap-проходом НЕ
  пользуется: fallback wire, который ещё ни разу не дозвонился, не
  должен светиться зелёным. Дашборд становится зелёным только после
  реально успешного fallback-дайла или валидации fallback-wire
  пробой (см. ниже).
- **Per-wire probe walks.** Когда primary в этом цикле упал И у
  аплинка есть fallback, шедулер делает дополнительный probe-проход
  по активному fallback wire — индекс `max(active_wire, 1)` — через
  синтетическое per-wire представление аплинка
  (`UplinkConfig::wire_view`). При успехе fallback-wire probe сам
  штампует `last_any_wire_success`, так что пассивные аплинки без
  клиентского трафика всё равно получают валидацию fallback'а и
  светятся `*_health_effective = true` на дашборде. Обходит
  warm-standby слоты (они приколочены к primary wire родителя) и не
  трогает penalty / cooldown родителя — этот scoring-state размечен
  под primary'ский трафик. Fallback-wire probe **кормит** свою
  собственную per-wire EWMA-слотину, так что cross-uplink скоринг
  ранжирует аплинк по реально работающему wire'у, а не по
  (возможно устаревшему) primary-сэмплу.
- Тот же any-wire-сигнал кормит **effective health** на snapshot /
  Prometheus / дашборде. `UplinkSnapshot::tcp_health_effective` (и
  соответствующая Prometheus-gauge
  `outline_ws_rust_uplink_health_effective`) отражает «доставляет ли
  аплинк трафик?»: probe-подтверждённое ИЛИ any-wire недавно работал.
  Legacy `tcp_healthy` / `outline_ws_rust_uplink_health` сохраняет
  probe-only верлдикт для дашбордов, которым нужно именно primary-
  здоровье. Tone строки в HTML-дашборде читает effective, так что
  аплинк с probe-мёртвым primary, но рабочим fallback'ом, рендерится
  зелёным, а не красным — визуализация совпадает с роутингом.

#### Список обходов

- Fallback-дайл обходит standby pool — пул сегодня приколочен к форме
  primary wire'а родителя, и переиспользование его для fallback wire
  выдало бы сокет неподходящего транспорта. Per-wire warm-standby
  pool — следующий шаг. Mode-downgrade окно, наоборот, уже per-wire
  (см. `fallback_mode_downgrades` и `effective_*_mode_for_wire`), так
  что fallback wire, наблюдающий собственный carrier-downgrade,
  закрывает только свой слот.
- DNS-кэш, per-uplink fingerprint scope и resume-cache **сохраняются**
  через wire-свитчи.
- RTT EWMA теперь **per-wire**. Primary живёт в существующем
  `rtt_ewma` слоте на `PerTransportStatus`; у каждого fallback wire'а
  свой слот в `fallback_rtt_ewma` (lazy-extend при первой записи,
  индекс `wire_index - 1`). Per-wire probe walk подкладывает
  латенси fallback-пробы в его собственный слот, а cross-uplink
  скоринг (`scoring_base_latency`) читает EWMA текущего active
  wire'а. Так что когда dial-loop перевёл `active_wire` на fallback,
  скоринг ранжирует аплинк против соседей по реально работающему
  wire'у, а не по primary (потенциально устаревшему или
  принадлежащему уже сломанному wire'у) значению. Холодный старт
  сразу после wire-flip'а — fallback-слот пустой — на один probe-
  цикл откатывается на primary EWMA, пока per-wire probe не
  заштампует свежий сэмпл.
- Две Prometheus-gauge'и отдают RTT EWMA на разных уровнях
  семантики. `outline_ws_rust_uplink_rtt_ewma_seconds{transport,uplink}`
  сохраняет legacy primary-only вердикт — пригодится для здоровья
  именно сконфигурированного primary независимо от того, какой wire
  сейчас тянет трафик. `outline_ws_rust_uplink_active_wire_rtt_ewma_seconds{transport,uplink}`
  отдаёт EWMA wire'а, реально несущего трафик; равен legacy gauge
  при `active_wire == 0`, иначе читает соответствующий
  `fallback_rtt_ewma` слот. Операторы, графящие user-visible
  latency / алертящие по real-traffic RTT, используют active-wire
  gauge; primary-health алерты остаются на legacy gauge.

#### UDP-кандидатура

- UDP-фильтр кандидатов (`supports_transport_for_scope`)
  консультируется с `UplinkConfig::supports_udp_any()`, так что
  аплинк, у которого primary — TCP-only (например, SS без
  `udp_addr`), но fallback UDP-capable, всё равно попадает в
  UDP-выдачу.

#### Поддерживаемые wire-формы VLESS-fallback'а

- **Все три формы работают как VLESS-fallback** теперь: `ws_h1` /
  `ws_h2` / `ws_h3` (WS-семейство), `xhttp_h1` / `xhttp_h2` /
  `xhttp_h3` (XHTTP-семейство) и `quic` (raw QUIC). QUIC-mode идёт
  через ту же машинерию `VlessUdpHybridMux`, что primary VLESS-UDP
  (QUIC-mux + WS-over-H2 fallback factory), но все per-uplink хуки
  привязаны к *слоту fallback wire'а* в per-wire mode-downgrade,
  а не к primary'и. Так что fallback-wire'овский `quic`-дайл,
  который провалился и переключился на WS-H2, записывает QUIC-провал
  в свой слот, и следующие дайлы того же fallback-wire'а пропускают
  QUIC сразу, пока окно даунгрейда wire'а не истечёт — точно
  отражая поведение primary, без загрязнения его mode-tracking'а.

### Inline-стенограмма `[outline]`

Inline-форма (`tcp_ws_url` и т.п. прямо на `[outline]`) **не**
поддерживает fallback'и — для них объявите явный массив
`[[outline.uplinks]]`.
