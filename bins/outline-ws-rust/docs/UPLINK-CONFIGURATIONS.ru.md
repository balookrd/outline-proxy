# Конфигурации аплинков и поведение fallback

Описывает четыре поддерживаемых формы блока `[[outline.uplinks]]`: на
каждую — минимальный пример конфига и цепочка fallback на этапе дозвона.

Каждый шаг fallback включается только если предыдущий вернул ошибку на
этапе dial / handshake. После провала «продвинутого» режима (`ws_h3`,
`xhttp_h3`) для аплинка открывается **окно даунгрейда**:
последующие дозвоны в этом окне полностью пропускают сломанный режим.
Окно закрывается, когда явная recovery-проба подтверждает, что
продвинутый режим снова доступен — после этого аплинк возвращается к
сконфигурированному режиму.

*English version: [UPLINK-CONFIGURATIONS.md](UPLINK-CONFIGURATIONS.md)*

---

## 1. Shadowsocks over WebSocket (H3)

WebSocket-carrier на HTTP/1.1, /2 или /3. `ws_h3` (алиас `h3`) — лучший
выбор, когда сервер его поддерживает: H3-дозвон — это один 1-RTT QUIC
handshake, против TCP+TLS+HTTP для H2.

```toml
[[outline.uplinks]]
name = "ss-ws-h3"
group = "main"
transport = "ss"
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
- **Resume:** TCP-шный Session ID принадлежит **сессии**, а не аплинку:
  свежий дозвон не предъявляет `X-Outline-Resume` вовсе — сервер выдаёт
  ему новый ID; предъявить ID может только редайл той же самой сессии
  (mid-session retry, кластерный soft-switch). У UDP остаётся свой слот
  в `global_resume_cache` (`<uplink>#udp`). Инлайн H3→H2→H1 fallback
  внутри `connect_transport` пробрасывает тот `resume_request`, с
  которым дозвон начался, через все три carrier'а.

## 2. Shadowsocks over XHTTP

`tcp_mode = "xhttp_h3"` (либо `xhttp_h2` / `xhttp_h1`) пускает
Shadowsocks-AEAD-поток по XHTTP-драйверу packet-up / stream-one вместо
WebSocket — тот же carrier, что у VLESS, но с SS-нагрузкой. Базовый URL
кладётся в `tcp_xhttp_url` (не `tcp_ws_url`); per-session id
дописывается при диале одним сегментом пути. Полезно, когда WebSocket
Upgrade режется на сети, но обычные HTTP POST/GET проходят (CDN-шлюзы,
captive-portal-мидлбоксы).

```toml
[[outline.uplinks]]
name = "ss-xhttp-h3"
group = "main"
transport = "ss"
tcp_xhttp_url = "https://ss.example.com/SECRET/xhttp"
tcp_mode = "xhttp_h3"
# Опционально: пустить и SS-UDP по XHTTP (отдельный base-путь на сервере).
udp_xhttp_url = "https://ss.example.com/SECRET/xhttp-udp"
udp_mode = "xhttp_h3"
method = "chacha20-ietf-poly1305"
password = "Secret0"
weight = 1.0
```

- **Carrier против URL:** `tcp_mode` выбирает семейство носителя;
  XHTTP-режим диалит `tcp_xhttp_url`, WS-режим — `tcp_ws_url`. Указание
  не того URL для режима (или обоих сразу) отвергается при загрузке
  конфига. Один wire несёт одно семейство — переключение WS↔XHTTP
  делается отдельным fallback-wire.
- **TCP fallback-цепочка:** `xhttp_h3 → xhttp_h2 → xhttp_h1`, идентично
  спуску VLESS-XHTTP (см. раздел 4). На h1-носителе stream-one
  принудительно сводится к packet-up — ровно как у VLESS.
- **Submode:** packet-up (по умолчанию) или stream-one, выбирается через
  `?mode=` в `tcp_xhttp_url` — правила те же, что в таблице submode для
  VLESS-XHTTP.
- **Сервер:** соответствующий серверный listener — `xhttp_path_ss`
  (отдельный от `xhttp_path_vless` — один базовый путь обслуживает один
  протокол).
- **UDP:** задайте `udp_xhttp_url` с `udp_mode = xhttp_h*`, чтобы пустить
  и SS-UDP-датаграммы по XHTTP. В отличие от VLESS (который мультиплексит
  TCP + UDP на одном пути), у SS TCP и UDP — на **разных** base-путях:
  сервер регистрирует `xhttp_path_ss_udp` под датаграммы, зеркаля
  разделение `ws_path_tcp` / `ws_path_udp`. TCP-only uplink'и просто
  оставляют UDP-поля пустыми.

### Combined-путь: один URL для TCP и UDP

Опционально TCP и UDP можно свести на **один** base-путь, чтобы цензор видел
один endpoint вместо двух. Задайте `ss_xhttp_url` (один URL на обе ноги) и
`ss_mode` вместо раздельных полей `tcp_*` / `udp_*` (а на сервере — combined
`xhttp_path_ss` вместо раздельных `xhttp_path_tcp` + `xhttp_path_udp`). Клиент тогда кодирует
TCP/UDP-дискриминатор в первый символ session-id — невидимо внутри TLS,
статистически неотличимо от случайного id — и сервер направляет каждый запрос
в нужный relay без второго пути.

```toml
[[outline.uplinks]]
name = "ss-xhttp-combined"
group = "main"
transport = "ss"
ss_xhttp_url = "https://ss.example.com/SECRET/xhttp"   # один URL для TCP + UDP
ss_mode = "xhttp_h2"
method = "chacha20-ietf-poly1305"
password = "Secret0"
weight = 1.0
```

Для WebSocket-носителя задайте вместо этого `ss_ws_url` + WS-`ss_mode`
(дискриминатор тогда поедет в `/{token}`-сегменте URL, который клиент
добавляет при дайле):

```toml
ss_ws_url = "wss://ss.example.com/SECRET/ws"
ss_mode = "ws_h2"
```

`ss_xhttp_url` и `ss_ws_url` взаимоисключающи, а `ss_mode` должен
соответствовать выбранному носителю (XHTTP-`ss_mode` для `ss_xhttp_url`,
WS — для `ss_ws_url`). Combined-поля также взаимоисключающи с раздельными
`tcp_*` / `udp_*` URL — загрузка конфига отвергает их смешивание.

### Share-link URI (`ss://`)

Combined-path SS-аплинк выше можно задать и одной строкой
`ss://BASE64(method:password)@HOST:PORT?...#NAME` — это SS-аналог VLESS
share-link (раздел 5). Вместо ручного заполнения полей `ss_*_url` / `ss_mode` /
`method` / `password` укажи поле `link`:

```toml
[[outline.uplinks]]
name = "ss-share"
group = "main"
link = "ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpTZWNyZXQw@ss.example.com:443?type=ws&security=tls&path=%2Fsecret%2Fss&alpn=h2#edge"
weight = 1.0
```

Userinfo задаётся в формате SIP002 — url-safe base64 от `method:password` (та же
кодировка, что выдают клиенты Outline / Shadowsocks). Загрузчик разворачивает
URI в combined-path поля, поэтому поведение dial / fallback / resume идентично
длинной TOML-форме выше. Поле `transport` указывать не обязательно — `ss://`
`link` подразумевает `transport = "ss"`.

#### Распознаваемые query-параметры

| Элемент URI / параметр             | Во что разворачивается                            |
|------------------------------------|--------------------------------------------------|
| `BASE64(method:password)` (userinfo) | `method` + `password` (SIP002 url-safe base64)  |
| `HOST:PORT` (authority)            | host + port dial-URL (port обязателен)           |
| `type=ws` (по умолчанию)           | `ss_mode = ws_h1` (с `alpn`: `ws_h2`/`ws_h3`), URL → `ss_ws_url` |
| `type=xhttp`                       | `ss_mode = xhttp_h2` (с `alpn=h3`: `xhttp_h3`; с `alpn=h1` / `http/1.1`: `xhttp_h1`), URL → `ss_xhttp_url` |
| `security=tls` / `reality`         | схема URL → `wss://` (ws) или `https://` (xhttp)  |
| `security=none` (или отсутствует)  | схема URL → `ws://` / `http://`                   |
| `path=...`                         | путь URL (percent-decoded; ведущий `/` добавляется) |
| `alpn=h3` / `h2` / `h1` / `h2,h3`  | выбирает вариант режима H1/H2/H3; берётся первый токен |
| `mode=packet-up` / `stream-one`    | пробрасывается как `?mode=` в XHTTP dial-URL      |
| `#NAME`                            | имя аплинка (percent-decoded)                     |

#### Как URI раскладывается по полям конфига (разбор примера)

Возьмём линк из примера выше:

```
ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpTZWNyZXQw@ss.example.com:443?type=ws&security=tls&path=%2Fsecret%2Fss&alpn=h2#edge
```

Он разбирается по частям:

| Часть URI | Декодированное значение | Превращается в |
|-----------|-------------------------|----------------|
| userinfo `Y2hh…cmV0MA` | base64url-decode → `chacha20-ietf-poly1305:Secret0`, split по первому `:` | `method = chacha20-ietf-poly1305`, `password = Secret0` |
| схема `ss://` | — | `transport = "ss"` (combined-path) |
| `type=ws` + `security=tls` | WS-носитель, TLS | схема dial-URL → `wss://`, URL → `ss_ws_url` |
| `alpn=h2` | первый токен | `ss_mode = ws_h2` |
| `ss.example.com:443` | authority | host + port dial-URL |
| `path=%2Fsecret%2Fss` | percent-decode → `/secret/ss` | путь dial-URL |
| `#edge` | percent-decode | `name = edge` |

Итоговый `UplinkConfig` (и **полностью эквивалентная** длинная TOML-форма):

```toml
[[outline.uplinks]]
name = "edge"
transport = "ss"
ss_ws_url = "wss://ss.example.com:443/secret/ss"   # type=ws → ss_ws_url (ss_xhttp_url остаётся пустым)
ss_mode = "ws_h2"
method = "chacha20-ietf-poly1305"
password = "Secret0"
```

XHTTP-линк (`…?type=xhttp&security=tls&path=%2Fxhttp&alpn=h3&mode=stream-one`)
кладёт URL в `ss_xhttp_url`, схема становится `https://`, а submode едет в query
dial-URL:

```toml
ss_xhttp_url = "https://ss.example.com:443/xhttp?mode=stream-one"   # type=xhttp → ss_xhttp_url
ss_mode = "xhttp_h3"
```

Отдельной dial-логики для линка нет — он просто заполняет те же combined-path
поля, которые затем проходят через ту же валидацию `combined_ss` и тот же путь
`resolve_primary_credentials`, что и аплинк, написанный руками в TOML.

#### Ограничения и конфликты

- В URI обязателен явный `:port` — дефолта по схеме нет.
- Userinfo должен быть SIP002 base64 от `method:password`; устаревшая форма
  с открытым текстом `ss://method:password@host` (буквальный `:` в authority)
  отвергается.
- `method` должен быть одним из поддерживаемых шифров
  (`chacha20-ietf-poly1305`, `aes-128-gcm`, `aes-256-gcm`, `2022-blake3-*`).
- `link` взаимоисключающ с `method`, `password`, всеми полями `ss_*` /
  `tcp_*` / `udp_*` и полями `vless_*`. Их смешивание — ошибка загрузки;
  используй либо URI, либо явные поля.
- `type=quic` не поддерживается — raw QUIC убран как носитель; используй
  носитель `ws` или `xhttp`.
- `sni=` и `host=` принимаются только если совпадают с host из authority
  (транспортный стек использует host из URL и для SNI, и для HTTP-заголовка
  `Host`) — как и в VLESS share-link.

Это же поле `link` принимают CLI-флаг (`--link` / `--vless-link` /
`OUTLINE_VLESS_LINK`) и REST-эндпоинты `/control/uplinks` (`link`, алиас
`share_link`) — схема (`ss://` против `vless://`) выбирает транспорт.

Для **раздельной** двухпутёвой раскладки SS (отдельные `tcp_*` и `udp_*` URL)
единой строки-ссылки нет — используй длинную TOML-форму выше.

## 3. VLESS over WebSocket (H3)

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
- **Resume:** TCP-шный Session ID — per-session (предъявляется только
  когда редайлится сама эта сессия). UDP едет по той же WS-сессии и
  неявно следует за переподключениями TCP (отдельного UDP-токена resume
  нет).

## 4. VLESS over XHTTP (H3)

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
- **Resume:** собственный токен редайлящейся сессии переиспользуется на
  каждом шаге цепочки `xhttp_h3 → xhttp_h2 → xhttp_h1` — один и тот же
  `resume_request` предъявляется на любом carrier'е, и сервер
  переподключает припаркованный upstream именно этой сессии вместо
  открытия новой. Первый дозвон не несёт токена вовсе. UDP едет в том же
  XHTTP-carrier'е и наследует поведение реконнекта от TCP.

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

## 5. VLESS share-link URIs

VLESS-формы выше (разделы 3–4, включая варианты носителя `ws_h1` /
`ws_h2` / `ws_h3`) можно сконфигурировать одной строкой
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
| `security=tls` / `reality`         | scheme URL → `wss://` (ws) или `https://` (xhttp) |
| `security=none` (или отсутствует)  | scheme URL → `ws://` / `http://`                   |
| `path=...`                         | path URL (percent-decoded; ведущий `/` добавляется автоматически) |
| `alpn=h3` / `h2` / `h1` / `h2,h3`  | выбирает H1/H2/H3-вариант режима; учитывается первый токен |
| `mode=packet-up` / `stream-one`    | пробрасывается как `?mode=` в XHTTP dial-URL       |
| `encryption=none` (или отсутствует)| принимается (других режимов encryption у VLESS нет)|
| `#NAME`                            | имя аплинка (percent-decoded)                      |

### Как URI раскладывается по полям конфига (разбор примера)

Возьмём линк из примера выше:

```
vless://11111111-2222-3333-4444-555555555555@vless.example.com:443?type=ws&security=tls&path=%2Fsecret%2Fvless&alpn=h3&encryption=none#edge
```

Он разбирается по частям:

| Часть URI | Декодированное значение | Превращается в |
|-----------|-------------------------|----------------|
| userinfo `11111111-…-555555555555` | проверенный UUID | `vless_id = 11111111-2222-3333-4444-555555555555` |
| схема `vless://` | — | `transport = "vless"` |
| `type=ws` + `security=tls` | WS-носитель, TLS | схема dial-URL → `wss://`, URL → `vless_ws_url` |
| `alpn=h3` | первый токен | `vless_mode = ws_h3` |
| `vless.example.com:443` | authority | host + port dial-URL |
| `path=%2Fsecret%2Fvless` | percent-decode → `/secret/vless` | путь dial-URL |
| `encryption=none` | — | принимается, поля нет (других режимов у VLESS нет) |
| `#edge` | percent-decode | `name = edge` |

Итоговый `UplinkConfig` (и **полностью эквивалентная** длинная TOML-форма):

```toml
[[outline.uplinks]]
name = "edge"
transport = "vless"
vless_ws_url = "wss://vless.example.com:443/secret/vless"   # type=ws → vless_ws_url (vless_xhttp_url остаётся пустым)
vless_mode = "ws_h3"
vless_id = "11111111-2222-3333-4444-555555555555"
```

XHTTP-линк (`…?type=xhttp&security=tls&path=%2Fxhttp&alpn=h3&mode=stream-one`)
кладёт URL в `vless_xhttp_url`, схема становится `https://`, а submode едет в
query dial-URL:

```toml
vless_xhttp_url = "https://vless.example.com:443/xhttp?mode=stream-one"   # type=xhttp → vless_xhttp_url
vless_mode = "xhttp_h3"
```

Отдельной dial-логики для линка нет — он просто заполняет те же поля `vless_*`,
которые затем проходят через ту же per-transport валидацию и тот же путь
`resolve_primary_credentials`, что и аплинк, написанный руками в TOML.

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

- CLI-флагом `--link <URI>` (алиас `--vless-link`) / переменной окружения
  `OUTLINE_VLESS_LINK`.
- REST-эндпойнтами `/control/uplinks` — как `link` (алиас
  `share_link`) внутри JSON-объекта `uplink`.

Поле `link` также принимает `ss://` Shadowsocks share-link — см.
«Share-link URI (`ss://`)» в разделе 2. Схема выбирает транспорт.

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

| Конфигурация          | TCP цепочка               | UDP цепочка                              | TCP resume        | UDP resume                  |
|-----------------------|---------------------------|------------------------------------------|-------------------|-----------------------------|
| Native SS             | нет                       | нет                                      | —                 | —                           |
| SS / WS / H3          | `ws_h3 → ws_h2 → ws_h1`   | `ws_h3 → ws_h2 → ws_h1`                  | да (per-session)  | да (`#udp`)                 |
| VLESS / WS / H3       | `ws_h3 → ws_h2 → ws_h1`   | `ws_h3 → ws_h2 → ws_h1`                  | да (per-session)  | вместе с TCP carrier'ом     |
| VLESS / XHTTP / H3    | `xhttp_h3 → xhttp_h2 → xhttp_h1` | `xhttp_h3 → xhttp_h2 → xhttp_h1` | да (per-session) | вместе с TCP carrier'ом     |

## Структура секции `[outline]`

Таблица `[outline]` собирает всё, что относится к проксирующему движку —
транспорты, аплинки, пробинг, балансировку — отдельно от обвязки хоста
(`[socks5]`, `[metrics]`, `[control]`, `[dashboard]`, `[tcp_timeouts]`,
`[tun]`, `[[route]]`). Поддерживаются две формы конфигурации.

**1. Inline-стенограмма для одного аплинка.** Если поля `transport`,
`tcp_ws_url`, `udp_ws_url`, `vless_ws_url`, `vless_xhttp_url`,
`tcp_mode` / `udp_mode` / `vless_mode`, `link`,
`method`, `password`, `fwmark`, `ipv6_first` написаны прямо под
`[outline]` (или, для обратной совместимости, на верхнем уровне) —
описан один неявный аплинк. CLI-флаги (`--tcp-ws-url`, `--password`, …)
работают именно с этой формой. Удобно для тривиальных деплойментов; не
сочетается с `[[outline.uplinks]]` / `[[uplink_group]]`.

```toml
[outline]
transport = "ss"                  # "ss" (по умолчанию; alias "shadowsocks"); "ws"/"websocket" deprecated | "vless"
tcp_ws_url = "wss://example.com/SECRET/tcp"
udp_ws_url = "wss://example.com/SECRET/udp"
tcp_mode = "h3"
udp_mode = "h3"
method = "chacha20-ietf-poly1305"
password = "Secret0"
```

`outline.transport` принимает:

| значение          | форма канала                                                                       |
|-------------------|------------------------------------------------------------------------------------|
| `ss`              | Shadowsocks AEAD-фрейминг внутри WebSocket-носителя (по умолчанию; alias `shadowsocks`) |
| `ws` / `websocket`| **Deprecated**-алиасы для `ss` — всё ещё принимаются, удалятся в следующем релизе  |
| `vless`           | VLESS поверх WebSocket или XHTTP (h1/h2/h3) — см. §§ 3–4                           |

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
| `routing_scope`                      | `"per_flow"`       | enum  | `per_flow` (выбор аплинка на сессию) / `per_uplink` (sticky по host:port) / `per_client` (sticky по source IP клиента, только `active_active`) / `global` (один активный на весь инстанс) |
| `sticky_ttl_secs`                    | `300`              | с     | как долго `(host, port)` залипает за выбранным аплинком                                          |
| `hysteresis_ms`                      | `50`               | мс    | минимальный интервал между двумя сменами `active`; гасит флаппинг                                |
| `failure_cooldown_secs`              | `10`               | с     | как долго после провала аплинк исключается из выборки                                            |
| `tcp_chunk0_failover_timeout_secs`   | `10`               | с     | сколько ждать первого байта от origin'а перед тем, как уйти на следующий аплинк                  |
| `auto_failback`                      | `false`            | bool  | возвращаться на исходно-предпочтительный аплинк после восстановления                             |
| `health_weighted_selection`          | `true`             | bool  | ранжировать выбор ноги (субаплинка) и семейства носителя (H3/H2/H1) по живучести — weighted-random с затухающим штрафом, так что нестабильный кандидат выбирается реже, но всё равно пробуется и со временем восстанавливается; `false` возвращает legacy: фиксированный циклический порядок ног + бинарный cap даунгрейда носителя |
| `health_weight_floor`                | `0.05`             | [0,1] | минимальный вес выбора при `health_weighted_selection`, чтобы у постоянно падающей ноги / носителя сохранялась небольшая вероятность ретрая, а анти-DPI реролл *никогда* не избегал ногу полностью |
| `warm_standby_tcp`                   | `0`                | int   | сколько прогретых TCP-соединений держать на резервных аплинках                                   |
| `warm_standby_udp`                   | `0`                | int   | то же для UDP                                                                                    |
| `warm_probe_keepalive_secs`          | `20`               | с     | период keepalive для кэшированных warm-probe-каналов (`0` отключает)                             |
| `rtt_ewma_alpha`                     | `0.3`              | (0,1] | коэффициент сглаживания EWMA для per-uplink RTT, используемого в скоринге выбора                 |
| `loss_latency_penalty_k`             | `0.0`              | ≥0    | сила инфляции латентности от carrier-loss (`latency × (1 + k · loss)`); `0.0` — измеряет, не действуя: выбор не меняется. См. «Потери носителя в выборе аплинка» ниже |
| `loss_latency_inflation_max`         | `4.0`              | [1,100] | потолок этого множителя — ограничивает, насколько одно плохое окно замера может опустить аплинк в ранжировании |
| `loss_sample_interval_secs`          | `10`               | с     | сетка сэмплирования счётчиков carrier-loss, независимая от `probe.interval`; `0` полностью отключает сэмплирование (носители по-прежнему регистрируют пробы, но их никогда не дифференцируют) |
| `loss_sample_min_packets`            | `200`              | int   | минимум пакетов, которые wire должен отправить за одно окно сэмплирования, чтобы окно засчиталось |
| `loss_ewma_alpha`                    | `0.2`              | (0,1] | коэффициент сглаживания EWMA для per-wire carrier-loss                                            |
| `loss_failover_ratio`                | `0.0`              | [0,1] | отношение потерь, выше которого закреплённый активный аплинк считается деградировавшим для loss-driven failover; `0.0` полностью отключает проверку — это единственная часть carrier-loss-фичи, которая двигает трафик без явной просьбы оператора. См. «Loss-driven failover для закреплённого активного аплинка» ниже |
| `loss_failover_secs`                 | не задано (выкл.)  | с     | сколько времени `loss_failover_ratio` должен превышаться **непрерывно**, прежде чем активный аплинк уступит чистому соседу равного или более высокого веса; один тик с отношением на уровне порога или ниже сбрасывает отсчёт. Не задано — проверка отключена независимо от `loss_failover_ratio`; `0` эквивалентен «не задано» |
| `failure_penalty_ms`                 | `500`              | мс    | стартовый штраф к RTT при свежем runtime-провале                                                 |
| `failure_penalty_max_ms`             | `30000`            | мс    | потолок суммарного штрафа за провалы                                                             |
| `failure_penalty_halflife_secs`      | `60`               | с     | период полураспада экспоненциального затухания штрафа                                            |
| `runtime_failure_window_secs`        | `60`               | с     | окно, в котором подряд идущие data-plane провалы складываются к health flip; `0` = legacy без затухания |
| `mode_downgrade_secs`                | `60`               | с     | cooldown перед повтором настроенного «продвинутого» режима (H3 / `xhttp_h{2,3}`) после фолбэка. Legacy alias: `h3_downgrade_secs` |
| `global_udp_strict_health`           | `false`            | bool  | в `routing_scope = "global"` дополнительно гейтить активный аплинк по UDP-здоровью; по умолчанию мягко — UDP-провалы информативные |
| `udp_ws_keepalive_secs`              | `60`               | с     | период WS Ping на простаивающих UDP-WS-сокетах (`0` отключает; на H3-carrier игнорируется — живость держит QUIC keep-alive, а WS Ping/Pong на тихом H3-datagram-стриме рискует `H3_INTERNAL_ERROR`) |
| `tcp_ws_keepalive_secs`              | `60`               | с     | период WS Ping на простаивающих VLESS-over-WS TCP-сессиях (`0` отключает; SS-over-WS игнорирует) |
| `tcp_ws_standby_keepalive_secs`      | `20`               | с     | период WS Ping на warm-standby TCP-сокетах (`0` отключает)                                       |
| `tcp_active_keepalive_secs`          | `20`               | с     | период SS2022 0-байтного keepalive на активных SOCKS TCP-сессиях (`0` отключает; SS1 игнорирует) |
| `tcp_mid_session_retry_buffer_bytes` | `262144`           | bytes | размер ring-буфера на сессию для Ack-Prefix mid-session retry (`0` отключает retry; см. раздел «Mid-session retry» ниже) |
| `tcp_mid_session_retry_budget`       | `1`                | int   | максимум попыток redial mid-session на одну сессию (`0` отключает retry — эквивалент `tcp_mid_session_retry_buffer_bytes = 0`) |
| `tcp_mid_session_retry_overflow_policy` | `"soft"`        | enum  | поведение при чанке больше cap'а ring-буфера: `"soft"` (дефолт) держит сессию живой и отдаёт `failed_replay` на будущих ретраях; `"hard"` сразу обрывает сессию, чтобы гарантировать ретраебельность остальных |
| `tcp_mid_session_retry_consume_timeout_secs` | `5`            | с     | верхний предел ожидания v1 Ack-Prefix control frame от сервера при resume hit; защищает pinned relay от молчащего/сломанного сервера |
| `tcp_symmetric_replay_enabled`       | `true`             | bool  | opt-in в v2 Symmetric Downlink Replay протокол на retry-redial'ах; `false` подавляет v2-advertise без отключения v1.x retry (например, на время постепенного раскатывания серверной стороны) |
| `tcp_symmetric_replay_max_bytes`     | `1048576`          | байт  | жёсткий cap на принимаемый v2 `replay_len` от сервера; ответы выше этого валят сессию — защита от вредоносного пира, индуцирующего unbounded buffering |
| `tun_suppress_icmp_reply_when_down`  | `false`            | bool  | перестать отвечать на ICMP echo (ping) на TUN для destination'ов, маршрутизируемых в эту группу, пока в группе нет ни одного здорового uplink'а ни по одному транспорту — превращает ping через туннель в liveness-сигнал для внешних watchdog'ов. Ответы также подавлены после старта, пока первая проба (или первый успешный flow) не подтвердит uplink |
| `bypass_when_down`                   | `false`            | bool  | байпасс туннеля, пока в группе нет ни одного здорового uplink'а: трафик, маршрутизируемый в эту группу, уходит `direct` (через сетевой стек хоста, с `direct_fwmark`) вместо отказа на мёртвой группе и возвращается в туннель, как только любой uplink оживает. См. «Байпасс полностью упавшей группы» ниже |
| `vless_udp_max_sessions`             | `256`              | int   | жёсткий лимит на одновременные VLESS UDP-сессии (LRU-вытеснение при переполнении)                |
| `vless_udp_session_idle_secs`        | `60`               | с     | вытеснять VLESS UDP-сессии, простаивавшие дольше этого (`0` отключает вытеснение)                |
| `vless_udp_janitor_interval_secs`    | `15`               | с     | как часто janitor сканирует idle-сессии VLESS UDP                                                |
| `reselect_at`                        | не задано (выкл.)  | list  | wall-clock слоты `"HH:MM"` локального времени для планового взвешенного перевыбора строгого активного аплинка (только `active_passive`); взаимоисключимо с `reselect_interval`. См. «Плановый перевыбор» ниже |
| `reselect_interval`                  | не задано (выкл.)  | duration | эквивалент `reselect_at` фиксированным периодом (`"90m"`, `"1h30m"`; целое число читается как секунды, но рекомендуется суффикс единицы); минимум `60s`; взаимоисключимо с `reselect_at` |

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
- **`per_client`** — закрепляет каждого входящего клиента за одним
  выбранным балансировщиком аплинком на `sticky_ttl_secs` (обновляется,
  пока клиент активен), ключуясь по source IP клиента: peer IP SOCKS5
  или IP LAN-устройства за TUN-роутером. Разные клиенты распределяются
  по аплинкам, но любой отдельный клиент держит стабильный egress, а не
  размазывается потоками по всем — аналог `per_flow`, только по source
  IP. При деградации закреплённого аплинка клиент уходит в failover на
  другой. Только `active_active` (в `active_passive` ведёт себя как
  `per_flow`). Клиенты без определимого source IP сводятся к одному
  общему ключу.
- **`global`** — ровно один аплинк `active` на весь инстанс; failover
  гейтится `hysteresis_ms` + `failure_cooldown_secs`. Подходит для
  чистой дашборд-семантики на устройствах, которые «должны выглядеть»
  как одна точка egress (роутеры, узкоспециализированные домашние
  шлюзы).

Взаимодействие mode × scope:

- `active_active` + `per_flow` — единственная комбинация, реально
  использующая взвешенное распределение на уровне отдельных сессий.
- `active_active` + `per_client` — то же взвешенное распределение, но на
  уровне клиентов: каждый клиент садится на один аплинк и остаётся на
  нём, поэтому его egress IP стабилен для всех его потоков.
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
  `outline_ws_socks_tcp_strict_aborts_total{reason="global_switch"}`.
- **SOCKS5 UDP**: per-group downlink-loop подписан на тот же сигнал и
  атомарно подменяет transport на switch
  (`reconcile_global_udp_transport`); клиент не видит L4-close (у UDP
  его нет), но следующий датаграмма уже идёт через новый аплинк.
- **TUN TCP**: симметрично SOCKS5, но на L3 — TUN engine отправляет
  `RST+ACK` сегмент в kernel-TCP приложения. Метрика:
  `outline_ws_tun_tcp_events_total{event="global_switch"}`.

Поведение включается фактом запуска в `active_passive` (любой scope);
`active_active` не затрагивается — там нет понятия «единственного
активного аплинка», от которого можно «отклониться», поэтому strict-
abort watcher не срабатывает. Кому нужна посессионная миграция без
abort — оставайтесь на `active_active` + `per_flow`.

**Soft switch (миграция вместо RST).** На кластерной группе
(`shared_resume = true`, т.е. аплинки — это edge'ы одного серверного
mesh-`[cluster]`) операторский *soft*-switch мигрирует живые SOCKS5
TCP-сессии на новый активный аплинк, а не рвёт их. Pinned-relay watcher
при переключении передайливает новый активный edge с групповым
`X-Outline-Resume` id и реплеит недоставленный uplink-хвост (а под v2 —
и downlink-суффикс), поэтому сессия продолжается без reset'а на стороне
клиента — сервер переприкрепляет припаркованный upstream через
mesh-релей. Откат к жёсткому RST-teardown выше — когда switch был
операторским *сливом*, группа не кластерная, mid-session retry выключен
(нет replay-ринга), новый активный аплинк не WS-семейства, либо
resume-редайл провалился.

Гейт — опубликованный `SwitchIntent` (`try_soft_switch_migrate` в
`pinned_relay.rs` читает `snapshot.intent`), а не то, какой механизм
вызвал переключение. Три значения:

| Намерение | Кем ставится | Живые сессии |
| --- | --- | --- |
| `OperatorHard` | `/control/activate {"soft":false}`, жёсткий плановый reselect, любой soft-запрос, зажатый вне кластера | RST |
| `OperatorSoft` | `/control/activate {"soft":true}` на кластерной группе | мигрируют |
| `Failover` | failover по пробе/runtime, auto-failback, carrier-degraded failover, loss-driven failover, начальный выбор | мигрируют на кластере |

Рвёт сессии только операторский **слив**, и по конкретной причине: под
mesh мигрировавшая сессия релеится обратно на свой *home* — на тот
самый узел, который сливают, — так что миграция сорвала бы слив.
Health-failover — не это решение: никто не выбирал завершать эти
сессии, а аплинк, с которого ушёл указатель, обычно как раз нездоров —
и именно тогда resume стоит попытки: запаркованный upstream живёт на
*сервере*, и mesh достаёт до него с нового edge, минуя сломанный путь
клиента к старому. (Пока значение было булевым, любой машинный
перевыбор публиковал `soft = false` и был неотличим от слива — поэтому
массовая смерть носителей сбрасывала все оставшиеся не у дел сессии,
опережая их собственную миграцию по смерти носителя.)
В dashboard рядом с **▶ Activate**
на кластерных группах есть кнопка **⇄ Soft switch** (показывается только при
`cluster_resume_enabled`); она шлёт `soft: true` в `/control/activate`, а поле
`soft` в ответе сообщает, была ли миграция реально применена или сведена к
жёсткому переключению.

**Cross-node миграция UDP.** При `shared_resume` UDP тоже делит групповой
resume-scope (раньше он был закреплён per-uplink, чтобы обойти тогда-сломанную
ветку релея). Поэтому soft-switch — и любая переселекция UDP-wire — удерживает
живой UDP-поток на его исходном home, а не переустанавливает его на новом edge:

- **SS-UDP** прогоняет все назначения через один id с ключом `<group>#udp`.
  Новый edge декодирует home-shard из id и релеит датаграммный носитель на
  home, который переприкрепляет припаркованную NAT-запись — один upstream
  source port переживает переключение.
- **VLESS-UDP** разворачивает один uplink в множество одно-назначенческих
  сессий, поэтому хранит durable per-target id с ключом `<group>#<target>`.
  Каждый target мигрирует независимо: свежий mux, который менеджер строит для
  нового edge, повторно предъявляет shard-несущий id этого target'а, и home
  ресумит припаркованный per-target сокет. На home VLESS-UDP едет по VLESS-TCP
  mesh-носителю, поэтому отдельного UDP-carrier kind нет.

Эти ключи именуют **слот**, и владелец слота важен не меньше самого ключа.
У каждого владельца носителя слот свой (`UdpResumeStore::Private`): один на
туннельный TUN UDP-флоу, один на SOCKS5 UDP-ассоциацию. Процессные кэши, в
которых слоты жили раньше, корректны только там, где на scope существует один
носитель, — SOCKS этому *почти* удовлетворяет, а TUN нет, потому что
дозванивается по одному носителю на флоу. Общий слот означал, что свежий флоу
предъявляет то, что запарковал последний закрывшийся, а попадание по нему —
это не промах resume, а попадание в **чужую сессию**: сервер перенаправляет
NAT-записи того флоу на этот носитель, а TUN-reader переисточивает каждый ответ
со своего собственного remote, и трафик пира одного флоу приезжал клиенту под
адресом другого.

Дозвону на обоих ingress'ах предшествует закрытие старого носителя. Сервер
паркует датаграммную сессию только после закрытия её стрима, поэтому дозвон,
ушедший раньше, искал бы id против ещё живой сессии, получил бы `miss-unknown`
и свежий upstream на свежем исходящем порту — весь смысл миграции терялся бы на
одном лишь порядке действий.

Вне кластера (`shared_resume = false`) UDP остаётся per-uplink, и каждый wire
резолвится локально — как и раньше: общий UDP-id между несвязанными home лишь
промахивался бы.

**Плановый перевыбор (`reselect_at` / `reselect_interval`).** Независимо
от failover, группа в режиме `active_passive` может по расписанию
ротировать свой строгий активный аплинк — уводя трафик с рабочего
аплинка по таймеру, а не только при сбое:

```toml
# reselect_at = ["03:00", "10:10"]   # wall-clock слоты, локальное время системы
# reselect_interval = "10h"          # ...или фиксированный период ("90m", "1h30m"); минимум 60s
```

- **`reselect_interval` использует тот же `parse_human_duration`, что и
  `shuffle_timer`**: целое число (например, `"300"`) по-прежнему читается
  как секунды, но для этого ключа рекомендуется суффикс единицы —
  опечатка на один символ (`"10"` вместо `"10h"`) это ровно тот случай,
  который ловит нижний порог 60 с ниже, а вот целое число, случайно
  оказавшееся выше порога (например, `"600"`, задуманное как `"600m"`),
  этот порог не поймает.
- **Взаимоисключимы**, и оба требуют `mode = "active_passive"` и
  `routing_scope = "global"` или `"per_uplink"` (загрузчик конфига отвергает
  любую другую комбинацию) — перевыбор двигает строгий активный слот,
  который существует только там.
- **Выбор — это принудительная ротация.** Текущий активный аплинк всегда
  исключается, поэтому каждый тик реально двигает слот (кроме исхода
  `no_candidate` ниже) — гарантированно, а не «может быть». Среди оставшихся
  аплинков, которые административно включены, здоровы и не в
  `failure_cooldown_secs`, один выбирается с вероятностью, пропорциональной
  `penalty_weight × weight` — тот же скор с затухающим штрафом за сбои,
  что использует `health_weighted_selection` в других местах, — с полом
  `health_weight_floor`, чтобы у оштрафованного сейчас аплинка сохранялась
  небольшая вероятность, а не постоянный пропуск. Если ни один кандидат не
  подходит (группа с одним аплинком, либо все остальные аплинки упали,
  выключены или в cooldown'е), тик — no-op (`outcome = "no_candidate"`).
- **`routing_scope = "per_uplink"` тянет TCP и UDP независимо** — слот
  каждого транспорта гейтится по здоровью/cooldown/штрафу именно этого
  транспорта и исключает только его собственный текущий активный аплинк,
  поэтому по итогам одного тика TCP и UDP законно могут оказаться на
  разных аплинках.
- **Расписание.** Записи `reselect_at` — это локальные слоты `"HH:MM"`,
  которые загрузчик конфига парсит, сортирует и дедуплицирует.
  Wall-clock цикл опрашивает состояние каждые 30 с и считает слот
  наступившим на протяжении примерно 90 с *после* настроенного времени —
  и никогда раньше; слот, полностью проспанный (suspend хоста, зависший
  процесс), при позднем обнаружении пропускается, а не срабатывает
  задним числом. Этот же цикл засеивает защиту «уже сработало сегодня»
  от часов в момент запуска, поэтому рестарт процесса или hot-apply,
  попавший внутрь окна допуска слота, считает этот слот уже обработанным
  вместо повторного срабатывания. У слота, настроенного в пределах этого
  ~90-секундного окна от локальной полуночи, эффективное окно усекается
  на границе суток вместо переноса в следующие — избегайте настраивать
  слоты так близко к полуночи, если важно полное окно. `reselect_interval`
  устроен иначе и проще: это обычный монотонный sleep-цикл, отсчитываемый
  от старта процесса (или последнего hot-apply через `/control/apply`),
  не связанный с wall-clock временем и без собственной защиты «уже
  сработало» — рестарт или hot-apply обнуляет отсчёт, поэтому следующий
  перевыбор всегда наступает ровно через полный `interval`, отсчитанный
  от момента самого рестарта, не раньше. По сравнению с расписанием,
  которое сложилось бы без рестарта, это может только отодвинуть
  срабатывание позже — на срок вплоть до почти целого лишнего
  `interval` (худший случай: рестарт происходит за миг до того, как
  должен был наступить тик невозмущённого расписания), — но никогда не
  приближает срабатывание.
- **Soft switch.** Плановая или ручная ротация запрашивает soft
  (сохраняющее resume) переключение — так же, как автоматический
  carrier-degraded failover; на группе без `shared_resume` оно клампится
  до жёсткого, как и `/control/activate`/`/control/reselect`. См. «Soft
  switch» выше.
- **Накопленное состояние не сбрасывается.** В отличие от чистого сброса,
  который выполняет ручной операторский switch через `/control/activate`,
  плановый или ручной перевыбор оставляет накопленное здоровье/RTT-EWMA/
  штраф-состояние каждого аплинка нетронутым — двигается только активный
  слот.
- **Ручной триггер.** `POST /control/reselect` выполняет тот же
  взвешенный выбор по требованию («reselect now»), вне расписания — форму
  запроса/ответа см. в справочнике control-plane README.
- **Взаимодействие с `auto_failback = true`.** `auto_failback` двигает
  активный слот только «вверх»: с probe-здорового активного на кандидата
  со строго большим `weight` (либо равным весом и меньшим индексом в
  конфиге), и только после того, как этот кандидат остаётся
  probe-здоровым `probe.min_failures` подряд успешных циклов пробы —
  иначе он no-op, пока активный остаётся здоровым. У планового перевыбора
  такого приоритетного правила нет: это чистый взвешенный выбор, поэтому
  он вполне может приземлиться на аплинк с *меньшим* весом, чем тот, что
  заменил. Если так и случилось, а `auto_failback = true`, следующая же
  серия подряд здоровых проб на более весомом аплинке запускает failback,
  который молча откатывает плановое перемещение — группа возвращается на
  более весомый аплинк по расписанию `auto_failback`, а не по
  расписанию, настроенному для планового перевыбора. Если плановый
  перевыбор должен реально удерживаться до следующего слота — задайте
  всем аплинкам группы одинаковый `weight`, либо держите `auto_failback`
  выключенным (дефолт), если полагаетесь на эту функцию.
- Метрика: `outline_ws_uplink_reselect_total{group,outcome}` —
  `outcome` равен `switched` (слот сдвинулся), `no_candidate` (кроме
  текущего активного ничего не подошло) либо `skipped` (группа не в
  `active_passive` или без единого строгого активного слота для
  ротации).

Байпасс полностью упавшей группы (`bypass_when_down`):

- При `bypass_when_down = true` на группе любой поток или датаграмма,
  чей маршрут резолвится в эту группу, диспатчится `direct` — через
  сетевой стек хоста, ровно как маршрут `via = "direct"` — пока в
  группе нет ни одного здорового uplink'а. Решение переоценивается
  вживую (на каждый TCP-dial, каждую UDP-датаграмму, каждый TUN-flow),
  поэтому трафик возвращается в туннель, как только любой uplink
  группы оживает.
- Критерий здоровья совпадает с существующим route-fallback-решением:
  на SOCKS5-пути он per-transport (`has_any_healthy` по TCP или UDP
  соответственно — группа со здоровым TCP продолжает туннелировать
  TCP, даже если её UDP-сторона полностью лежит), на TUN-пути группа
  должна лежать по **обоим** транспортам — так же, как у
  `tun_suppress_icmp_reply_when_down`.
- Приоритет: явный `fallback_via` / `fallback_direct` / `fallback_drop`
  на совпавшем правиле `[[route]]` выигрывает. Байпасс затем всё равно
  применяется к группе, в которую привёл fallback (на один уровень
  вглубь), если та тоже включила опцию и лежит. Маршруты без явного
  fallback'а — включая неявный диспатч «всё в дефолтную группу» при
  отсутствии `[[route]]` — получают байпасс напрямую.
- На TUN-хостах (и SOCKS5-хостах, где TUN держит default route)
  задайте `direct_fwmark` и парное `ip rule … lookup …`, чтобы
  байпасс-сокеты выходили из TUN routing loop; на Linux при
  отсутствующей комбинации старт пишет предупреждение. В сочетании с
  `tun_suppress_icmp_reply_when_down` ping'и продолжают отвечаться,
  пока байпасс активен — путь жив, просто не туннелирован.
- Замечание: сразу после старта у группы ещё нет вердикта проб, и она
  считается лежащей, поэтому первые мгновения трафик может идти
  direct, пока первая проба (или первый успешный flow) не подтвердит
  uplink. Байпасс-трафик виден в метриках под группой `direct`, как и
  любой policy-direct трафик.
- Наблюдаемость: встроенный dashboard рисует чип в заголовке группы —
  серый `Bypass: armed`, пока у каждого транспорта ещё есть здоровый
  uplink, и янтарный `Bypass: DIRECT (TCP + UDP)` с перечислением
  отведённых транспортов, пока байпасс активен. То же состояние
  экспортируется как `outline_ws_group_bypass_active{group,
  transport}` (`1` = идёт direct, `0` = туннелируется; серии есть
  только у opted-in групп) и едет через `/control/topology` полями
  группы `bypass_when_down` / `bypass_active_tcp` /
  `bypass_active_udp` (опускаются, пока `false`). В поставляемом
  Grafana-дашборде — парная stat-панель и таймлайн в секции Routing
  Policy. Пример алерта:
  `max by (group) (outline_ws_group_bypass_active) == 1`.

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
- Ограничено WS-family carrier'ами — SS-WS (`transport = "ss"`) и
  VLESS-WS (`transport = "vless"`).
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
  `outline_ws_uplink_mid_session_retries_total{outcome}` со
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
  `outline_ws_uplink_mid_session_retries_total{outcome="downlink_truncated"}`;
  `"hard"` обрывает сессию сразу. Используйте то же значение,
  что и для v1 buffer-overflow, чтобы политика была
  консистентной.
- Тот же eligibility-gate, что у v1 — SS-WS / VLESS-WS /
  VLESS-XHTTP carriers.

### Потери носителя в выборе аплинка

**Зачем это нужно.** Выбор ранжирует аплинки по RTT — а RTT сам по себе
слеп к потерям. 2026-08-02 шлюз просидел шесть с половиной часов на
аплинке, чей путь ронял пакеты, пока его RTT держался ровным EWMA
0.21–0.32 с, лучшим скором в группе, `health = 1` на каждом цикле пробы,
а счётчик runtime-провалов не сдвинулся ни разу. Ничего из того, на что
смотрел выбор, потерь не видело. Эта фича измеряет потери прямо на
носителе (carrier socket) и позволяет им умножать латентность, по
которой ранжирует выбор — по умолчанию **выключена**, потому что
принципиального коэффициента a priori не существует; см. «Выбор
`loss_latency_penalty_k`» ниже.

**Что измеряется и где.** Для wire, который сейчас несёт трафик
(primary либо активный fallback), менеджер сэмплирует OS-уровневые
счётчики потерь carrier-сокета по фиксированной сетке
(`loss_sample_interval_secs`, дефолт `10s`): QUIC `PathStats`
(lost/sent пакеты) на H3/QUIC-носителе, `TCP_INFO`
(retransmits/segments-out) на TCP-носителе. Это намеренно **не** LAN-нога
до локального SOCKS5/TUN-клиента и **не** соединение пробы — проба
дозванивается по своему короткоживущему сокету и никогда не несёт
пользовательский трафик. Сэмплирование идёт по своему таймеру,
независимому от `probe.interval`: циклы пробы штатно пропускаются для
аплинка, уже несущего реальный трафик (`probe.skip_when_active`), а
дифференцирование кумулятивных счётчиков ядра в отношение требует
ровной сетки сэмплирования вне зависимости от того, прошла ли проба.

**Пять ручек** живут под `[outline.load_balancing]` (либо
per-group-эквивалентом — дефолт каждой см. в строке справочной таблицы
выше):

- `loss_latency_penalty_k` (дефолт `0.0`) — сила инфляции.
- `loss_latency_inflation_max` (дефолт `4.0`, допустимый диапазон `[1.0,
  100.0]`) — потолок множителя.
- `loss_sample_interval_secs` (дефолт `10`) — сетка сэмплирования. `0` —
  документированный выключатель: `spawn_loss_sampler_loop` тогда вообще
  не запускает таймер, носители по-прежнему регистрируют пробы, но
  ничто не сводит их в вердикт — способ выкатить проводку проб без
  цены самого цикла сэмплирования, например при поэтапной раскатке
  фичи.
- `loss_sample_min_packets` (дефолт `200`) — минимальный объём на окно.
- `loss_ewma_alpha` (дефолт `0.2`) — сглаживание per-wire EWMA.

**Дефолт из поставки измеряет, ничего не меняя.**
`loss_latency_penalty_k = 0.0` даёт множитель ровно `1.0`
(`LossEwma::inflation`), поэтому включение фичи с дефолтами не меняет
ничего в том, какой аплинк выбирается — начинает публиковаться только
`outline_ws_uplink_carrier_loss_ratio`. Отношение сэмплируется и
публикуется безусловно, независимо от `loss_latency_penalty_k`;
превращение его в реальный сигнал failover — осознанный второй шаг,
когда вы уже знаете, какой уровень потерь видит именно ваш парк (ниже).

**Как читать метрики.** Два gauge, оба с лейблами `{group, transport,
uplink}`:

- `outline_ws_uplink_carrier_loss_ratio` — сглаженное отношение потерь
  (EWMA, `loss_ewma_alpha`) для wire, несущего трафик сейчас.
- `outline_ws_uplink_carrier_loss_observed_packets` — кумулятивное
  число пакетов, на которых основано это отношение. Всегда читайте его
  рядом с отношением: отношение, посчитанное по паре сотен пакетов
  сразу после открытия минимально-объёмного гейта, куда шумнее, чем
  построенное на дне ровного трафика.

**Отсутствие серии значит «не измерено» — никогда «потерь нет».**
Есть четыре разные причины, по которым у wire в конкретный момент может не
быть серии `carrier_loss_ratio`, и ни одна из них не означает «путь
чист»:

1. Он ещё не отправил `loss_sample_min_packets` (дефолт `200`) пакетов
   в пределах одного окна сэмплирования. Этот гейт намеренный: на
   почти простаивающем носителе один потерянный пакет из десяти — это
   не «10 % потерь», это шум округления, и скормить его в EWMA значило
   бы сделать тихий аплинк катастрофически лоссовым на вид. Сверяйтесь
   с `outline_ws_uplink_carrier_loss_observed_packets`, чтобы отличить
   «трафика ещё мало» от «измерено и чисто».
2. Wire — это `xhttp_h1`. Этот носитель дозванивается **двумя
   независимыми plain-сокетами** — долгоживущим downlink GET и
   сериализованным uplink-POST-сокетом — вместо одного общего
   соединения, поэтому нет единого носителя, к которому можно отнести
   потери. Это семейство носителей никогда не регистрирует loss-пробу —
   так устроено изначально.
3. Wire — это VLESS-UDP. `VlessUdpSessionMux` дозванивается свежим
   носителем лениво, по назначению, в момент первой необходимости — в
   точке, где обычно регистрируется loss-проба, носителя ещё просто
   не существует.
4. Все носители wire исчезли (retired локально, либо standby, который
   перестали дозванивать) и registry это заметил — либо потому что
   носитель реально закрылся, либо потому что он простоял без трафика
   достаточно долго, чтобы быть вытесненным как stale, даже оставаясь
   технически открытым. В любом случае, как только у wire не остаётся
   зарегистрированных носителей, его вердикт сбрасывается в
   «не измерено». Без этого отношение, измеренное пока wire нёс
   реальный трафик, иначе пережило бы его бесконечно — застрявший
   штраф ровно на том standby, на который оператор хотел бы
   переключиться.

Это структурные свойства или свойства жизненного цикла этих путей, а
не повод искать неисправность. Не читайте «серии нет» на `xhttp_h1`,
VLESS-UDP wire или wire, только что потерявшем последний носитель, как
«потерь нет» — для него просто не публикуется никакого вердикта.

**Выбор `loss_latency_penalty_k`.** Принципиального дефолта не
существует — `0.0` это не «маленькое значение», это «выключено».
Выводите значение из чисел собственного парка, а не угадывайте:

1. Соберите `outline_ws_uplink_carrier_loss_ratio` по аплинкам группы за
   представительный период — неделя покрывает большинство суточных и
   недельных колебаний. Сравните разброс между лучшим и худшим
   аплинками; путь из инцидента 2026-08-02 держал 2–3 % потерь на
   плохом отрезке, пока здоровый аплинк той же группы мерил около нуля.
2. `k` управляет тем, сколько потерь нужно, чтобы *инфлированная*
   латентность лоссового пути пересекла *обычную* латентность чистого
   кандидата: `inflated_latency = latency × (1 + k × loss)`, зажатая
   `loss_latency_inflation_max`.
3. Разбор примера — **сверяйте арифметику, прежде чем доверять
   прикидке, здесь легко ошибиться**: при `k = 20` путь с RTT `210 мс` и
   измеренными `2 %` потерь получает скор
   `210 мс × (1 + 20 × 0.02) = 210 мс × 1.4 = 294 мс` — он всё ещё
   *обгоняет* чистого кандидата на `300 мс`; одних `2 %` потерь при
   таком `k` недостаточно, чтобы его сдвинуть. Пересечение наступает
   при `3 %` потерь: `210 мс × (1 + 20 × 0.03) = 210 мс × 1.6 = 336 мс`
   — это уже *проигрывает* чистому пути на `300 мс`. Если `2 %` для вас
   уже тот уровень потерь, при котором вы хотите failover, `k = 20`
   для этой пары аплинков мал — поднимайте `k`, пока пересечение не
   ляжет туда, куда говорят ваши собственные цифры.
4. Прогоните эту арифметику заново на реальных RTT и измеренных
   отношениях потерь ваших аплинков, прежде чем фиксировать значение в
   `config.toml` — важен тот разброс, что в ваших метриках, а не тот,
   что в этом примере.

**`loss_latency_inflation_max` ограничивает вред одного плохого окна.**
Множитель `(1 + k × loss)` зажимается этим потолком (дефолт `4.0`,
проверяется при загрузке на `[1.0, 100.0]`) перед применением, поэтому
одно катастрофическое окно сэмплирования не может увести scoring-
латентность аплинка в абсурдное значение. `loss_latency_penalty_k`
**никогда не исключает** лоссовый аплинк из кандидатов — только
опускает его в ранжировании. Он может быть единственным живым путём в
группе, и жёсткое исключение вывело бы его из ротации целиком вместо
того, чтобы продолжать нести трафик с пониженным приоритетом.

**Опустить в ранге — не то же самое, что заставить уступить: это
`loss_failover_ratio` / `loss_failover_secs`, ниже.** В `mode =
"active_active"` пониженного ранга достаточно: балансировщик заново
ранжирует кандидатов на каждом выборе, поэтому лоссовый аплинк просто
проигрывает больше таких выборов своим более чистым соседям. Но
реальная форма парка — `mode = "active_passive"` с `auto_failback =
false`: один аплинк *закреплён* активным, и `strict_transport_candidates`
держит его, как только проба назовёт его здоровым — `score`, а значит
и `loss_latency_penalty_k` — вне зависимости от значения — на этом
пути вообще не читается
(`crates/outline-uplink/src/manager/candidates.rs`, функция
`strict_transport_candidates`). Именно это и произошло 2026-08-02:
здоровый по пробе, с ничем не примечательным RTT, но лоссовый активный
аплинк продержал закреплённый слот шесть с половиной часов, и никакое
значение `k` его бы не сдвинуло.

### Loss-driven failover для закреплённого активного аплинка

`loss_failover_ratio` (дефолт `0.0`, выключено) и `loss_failover_secs`
(дефолт не задано, выключено) — это механизм, который заставляет
закреплённый strict-активный аплинк реально уступить из-за потерь —
аналог `carrier_degraded_failover_secs` (который реагирует на тихий
даунгрейд носителя, например `ws_h3 → ws_h2`), но для сигнала потерь.
Оба параметра должны быть заданы, чтобы проверка заработала, и каждый
отключает её независимо: `loss_failover_ratio = 0.0` (дефолт)
полностью выключает проверку, и `loss_failover_secs` не заданный (или
`0`) делает то же самое вне зависимости от отношения. Это единственная
часть всей carrier-loss-фичи, которая двигает боевой трафик без
явной просьбы оператора, поэтому — как и любой другой knob в этом
разделе — она поставляется выключенной.

**Требует включённого сэмплирования.** `loss_sample_interval_secs = 0` —
документированный выключатель для самого таймера сэмплирования потерь
(см. выше) — вообще не запускает цикл сэмплирования, поэтому эпизод
«повышено с» никогда не поддерживается, и `loss_failover_ratio` /
`loss_failover_secs` молча остаются мертвы вне зависимости от
собственных значений. Если задаёте любой из этих параметров, держите
`loss_sample_interval_secs` на дефолте (`10`) или любом другом ненулевом
значении.

**Тоже требует включённых проб.** Планка устойчивости кандидата,
описанная ниже (`probe.min_failures` подряд успешных проб), считается
исключительно по исходам проб. Если у группы пробы выключены (не настроен ни `[probe.ws]`,
ни `[probe.http]`, ни `[probe.dns]`, ни `[probe.tcp]`, ни `[probe.tls]`),
`consecutive_successes` никогда не уходит от `0`, поэтому ни один
кандидат никогда не преодолеет планку streak'а, и loss-driven failover
никогда не сработает — что бы ни говорили `loss_failover_ratio` /
`loss_failover_secs`. Унаследовано от `carrier_degraded_failover_secs`,
у которого то же требование по той же причине.

**Как принимается решение.** На каждом тике сэмплирования carrier-loss
(`loss_sample_interval_secs`) менеджер заново сверяет отношение потерь
активного wire у strict-активного аплинка с `loss_failover_ratio` и
поддерживает для аплинка непрерывную метку «повышено с»: тик, чьё
отношение строго выше порога, стартует (или продлевает) эпизод; тик на
уровне порога или ниже сбрасывает эпизод. Это отношение — то же самое
значение, сглаженное `loss_ewma_alpha`, которым эта фича скорит везде в
остальных местах, а не сырое отношение одного окна — поэтому оно не
отражает мгновенно путь, который только что стал чистым. При дефолтном
`loss_ewma_alpha = 0.2`, начиная со сглаженного `0.9`, нужно порядка
десятка с лишним подряд *засчитавшихся* чистых окон, чтобы спуститься
под порог `0.05`, а не одно; пока сглаженное отношение само не
пересечёт порог снизу, каждый тик по-прежнему читается как «повышено»,
и эпизод продолжает стареть, даже когда путь уже восстановился. Тик
заново оценивается только на *свежем* отношении — последнее
*засчитавшееся* измерение wire (набравшее `loss_sample_min_packets`)
должно укладываться примерно в 3 тика сэмплирования. Без этой проверки
свежести wire, который один раз измерил высокие потери, а затем несёт
только лёгкий трафик ниже объёмного порога (редкие keepalive, ночное
затишье), бесконечно продолжал бы читать своё последнее, уже
неактуальное отношение как непрерывное доказательство. Эпизод «старел»
бы по измерению, которое давно перестали наблюдать, и реально
настроенная оператором длительность потерь
переставала бы значить то, что она обещает. Устаревшее или вовсе
отсутствующее отношение (например, `loss_sample_min_packets` так и не
набран) сбрасывает эпизод так же, как и сглаженно-чистый тик. Как только
этот эпизод непрерывно продержался не меньше `loss_failover_secs`,
активный уступает кандидату, который:

- здоров по пробе, равного или более высокого веса (приоритет оператора
  по-прежнему в силе — это failover, а не failback), и имеет
  `probe.min_failures` подряд успешных проб — та же планка
  устойчивости, что применяет проверка carrier-degraded. Этот пункт
  важнее, чем кажется: при `routing_scope = "global"` кандидат может
  быть «здоров» чисто по bootstrap-допуску (аплинк с настроенными
  `[[outline.uplinks.fallbacks]]`, который ни разу не подтвердил ни
  одного успешного дозвона, всё равно допускается в кандидатуру, чтобы
  dial-loop активного wire мог попробовать fallback — см. «Sticky
  fallback + auto-failback (active-wire state machine)» ниже). Без
  требования streak'а мёртвый standby именно в таком состоянии — проба
  ни разу не подтверждена, вердикта по потерям тоже нет (неизмеренное
  читается как чистое). Он забрал бы ногу у лоссового, но рабочего
  primary, тут же провалил бы проверку здоровья на следующем dispatch'е,
  откатился бы обратно на лоссовый primary — и на следующем тике сработал
  бы снова: переключение на каждое соединение.
- сам находится на уровне `loss_failover_ratio` или ниже. Кандидат
  **без** собственного вердикта по потерям считается чистым:
  отсутствие значит «не измерено», никогда не «потерь нет» и никогда
  не «измерено и лоссово» (см. четыре причины отсутствия серии выше)
  — отказ переключиться на неизмеренного кандидата оставил бы шлюз на
  лоссовом пути без всякой причины.

Если такого кандидата нет, активный аплинк **остаётся** — лоссовый
путь, всё ещё несущий трафик, лучше, чем никакой, а переключение между
двумя одинаково лоссовыми аплинками было бы churn'ом, а не
восстановлением. Переключение публикуется как `SwitchIntent::Failover`
(см. таблицу `SwitchIntent` выше), поэтому на кластерной группе живые
сессии мигрируют на новый активный вместо сброса — точно как при
carrier-degraded failover. И строка лога, и причина в ручном
переключении называют оба аплинка и измеренное отношение потерь,
поэтому решение читается само по себе, без сверки с метриками.

**Один непрерывный эпизод, а не накопительный.** Аплинк, дёргающийся
вокруг порога — один тик выше, один тик ниже, и по кругу — никогда не
пересечёт `loss_failover_secs`: самый первый чистый тик сбрасывает
эпизод в «не начат», та же дисциплина, которую
`carrier_degraded_failover_secs` применяет к спускающемуся окну
носителя.

**Не сочетается с `auto_failback = true`.** Эта проверка выполняется до
блока weight-driven auto-failback, поэтому может переставить активный
на соседа с тем же весом и более высоким индексом — а собственный
фильтр `auto_failback` не исключает ни лоссового, ни carrier-degraded
кандидата, так что на следующем же dispatch'е может откатиться прямо
обратно. Тот же пробел уже существует для
`carrier_degraded_failover_secs`; этот параметр лишь расширяет область,
где он может проявиться. На парке `auto_failback = false` (дефолт) это
не возникает — несостыковка важна, только если обе фичи включены
одновременно.

**Выбор значений.** Сначала найдите реальный разброс потерь своего
парка по «Выбор `loss_latency_penalty_k`» выше — `loss_failover_ratio`
стоит ставить на уровне или выше того уровня потерь, который вы уже
считаете неприемлемым, а не ниже (слишком низкий порог превращает
обычный шум в триггер failover'а). `loss_failover_secs` должен быть
достаточно большим, чтобы одно плохое окно сэмплирования не могло
сработать в одиночку: несколько `loss_sample_interval_secs` — разумный
пол, зеркалящий дефолт `3 × mode_downgrade_secs`, который
`carrier_degraded_failover_secs` использует по той же причине.

**Наблюдение до срабатывания.** Ещё две серии, вдобавок к описанным
выше:

- `outline_ws_uplink_loss_elevated_seconds{group, transport, uplink}` —
  сколько времени длится текущий эпизод. Отсутствует, пока эпизод не
  идёт (фича выключена, отношение сейчас не выше порога, либо последнее
  засчитавшееся измерение устарело). Сравнивайте с `loss_failover_secs`,
  чтобы увидеть, насколько близко аплинк подошёл к переключению, ещё до
  того, как оно случится.
- `outline_ws_uplink_loss_failovers_total{transport, group, from_uplink,
  to_uplink}` — считает каждое переключение, вызванное этой проверкой,
  отдельно от `outline_ws_uplink_failovers_total` (data-plane / runtime
  failover'ы, а не это strict-mode переключение активного слота).

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
   `mode_downgrade_capped_to`. Выставляется runtime-отказом
   (`report_runtime_failure_for_wire`), отказом пробы или дайлом, который
   тихо зафолбечился (`note_silent_transport_fallback`) — каждый
   атрибутируется тому wire, на котором произошёл. Пока окно открыто,
   `effective_tcp_mode` / `effective_udp_mode` возвращают cap
   (а не configured режим) — пробы, refill standby и прямые дозвоны
   перестают долбиться в сломанный продвинутый режим. Family-aware:
   `WsH3` коллапсирует в `WsH2`, `XhttpH3` — в `XhttpH2`,
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

Session ID **выдаётся сервером и принадлежит одной сессии**. На
resume-hit'е сервер игнорирует target из нового хендшейка — авторитетен
припаркованный target — и переприкрепляет тот upstream, который
припаркован под предъявленным ID. Поэтому предъявить ID вправе только та
сессия, которой он был выдан.

**TCP.** Каждый дозвон рекламирует `X-Outline-Resume-Capable: 1`, так что
сервер выдаёт ID и возвращает его в `X-Outline-Session: <hex>`. Клиент
читает этот ID прямо с носителя
(`TransportStream::issued_session_id()`) и хранит его *на сессии*:

- **Свежий дозвон не предъявляет `X-Outline-Resume`.** Это новая сессия,
  ресумить ей нечего. (Per-uplink кэша, из которого можно было бы взять
  токен, намеренно больше нет: один общий слот на аплинк означал, что
  свежий дозвон сессии B мог предъявить припаркованный ID сессии A и
  оказаться пришитым к её destination'у.)
- **Редайл существующей сессии предъявляет её собственный ID** — это путь
  mid-session retry (`redial_for_mid_session_retry`) и кластерная
  soft-switch-миграция. На hit'е сервер выдаёт новый ID, который
  заменяет старый на сессии.
- В пределах одного дозвона токен (какой бы ни был — `None` на свежем
  дозвоне) пробрасывается через инлайн-смену carrier'а: `h3 → h2 → h1`
  на WS-пути, `xhttp_h3 → xhttp_h2 → xhttp_h1` на XHTTP-пути.

`outline_ws_resume_lookup_total{transport="tcp",result}` считает `hit`
для редайла, который нёс ID, и `miss` для дозвона без него.

**UDP** ключует свои id как `<resume-scope>#udp` (плюс
`<resume-scope>#<target>` для VLESS-UDP), но слот, который эти ключи
именуют, принадлежит **владельцу одного носителя** — одному туннельному
TUN UDP-флоу, одной SOCKS5 UDP-ассоциации (`UdpResumeStore::Private`).
Процессные кэши, где эти ключи жили раньше, работают по принципу
last-write-wins, что корректно только там, где на scope существует один
носитель. TUN дозванивается по одному носителю на *флоу*, поэтому при
общем слоте свежий флоу предъявлял id, запаркованный предыдущим
закрывшимся, а попадание по нему переприкрепляет upstream **того** флоу —
сращивание чужих сессий, а не промах resume. В конфигурациях, где UDP едет
по TCP-carrier'у (VLESS/WS, VLESS/XHTTP), UDP-слота нет вовсе — UDP следует
за жизненным циклом TCP.

## Диверсификация браузерного фингерпринта

WS / XHTTP-дозвоны могут подмешивать браузерные заголовки
идентификации (`User-Agent`, `Accept-*`, семейство Sec-CH-UA,
Sec-Fetch-*), чтобы простое DPI-правило вида «WS-upgrade без
User-Agent» больше не отделяло клиент от реального браузерного
трафика. В пул входит шесть профилей: Chrome 151 (Windows + macOS),
Firefox 152 (Windows + macOS), Safari 26 (macOS), Edge 150 (Windows).

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
`outline_ws_uplink_fingerprint_profile_strategy_info` несёт
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
с **именем активного профиля** (например, `Chrome 151 macOS`)
рядом с протокол-pill в каждой строке аплинка, где эффективная
стратегия не равна `none`. Цвет — по семейству: синий для
стабильных профилей (Chrome / Firefox / Safari / Edge под
`process_stable` или `per_host_stable`) и фиолетовый для `Random` —
оператор сразу видит, идентичность приколота или ротируется.
Аплинки на `none` чипа не получают — типичный opt-out-deployment
визуально не меняется. Tooltip несёт и сырой id профиля, и стратегию
(`fingerprint_profile_name = chrome-151-macos · strategy = process_stable`),
чтобы отрисованный лейбл сразу сопоставлялся с Prometheus-лейблом
`strategy` и snapshot-полем без перевода между формами.

Активный профиль вычисляется в snapshot-билдере через
`select_with_strategy(primary_dial_url, effective_strategy)` —
сначала `tcp_dial_url()`, при его отсутствии — `udp_dial_url()`
(для UDP-only аплинков); для любого аплинка без dial URL (нет URL)
профиль не считается. Поле в snapshot называется
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
  (`h2`, `http/1.1`, `h3`). TLS-конфиги кэшируются
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
на WS- или VLESS-wire **этого же** аплинка, сохраняя
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
  transport   = "ss"
  tcp_ws_url  = "wss://ws.example.com/tcp"
  udp_ws_url  = "wss://ws.example.com/udp"
  tcp_mode    = "ws_h2"
  udp_mode    = "ws_h1"
  # cipher / password / fwmark / ipv6_first / fingerprint_profile
  # наследуются от родительского аплинка, если не указаны явно.

  [[outline.uplinks.fallbacks]]
  transport       = "vless"
  vless_ws_url    = "wss://vless.example.com/SECRET/vless"
  vless_mode      = "ws_h2"
  vless_id        = "11111111-2222-3333-4444-555555555555"
```

### Поля

Каждая fallback-секция несёт собственные wire-поля, повторяющие схему
top-level `[[outline.uplinks]]` **минус** атрибуты идентичности, которые
принадлежат родителю (`name`, `weight`, `group`, `link`):

| Поле | Обязательно для | Заметки |
|---|---|---|
| `transport` | всегда | `ss` / `vless` (`ss` также принимает deprecated-алиасы `ws` / `websocket`). **Ограничений по уникальности нет** — same-transport-as-parent и duplicate-transport entries разрешены явно. Самая распространённая кросс-family форма: VLESS primary на `xhttp_h*` плюс VLESS fallback на `ws_h*` (тот же `transport = "vless"`, другая carrier-семья, другой dial URL); два VLESS fallback'а на разные хосты (belt-and-suspenders) тоже работают. Dial-loop и per-wire mode tracking трактуют каждый fallback как собственный wire независимо от `transport`. |
| `tcp_ws_url`, `udp_ws_url`, `tcp_mode`, `udp_mode` | `transport = "ss"` | `tcp_ws_url` обязателен; `udp_ws_url` опционален (UDP-fallback opt-in). |
| `vless_ws_url`, `vless_xhttp_url`, `vless_mode`, `vless_id` | `transport = "vless"` | URL должен соответствовать `vless_mode` (xhttp\_\* → `vless_xhttp_url`; ws\_\* → `vless_ws_url`). `vless_id` per-wire и **не наследуется** от родителя — у разных VLESS-эндпоинтов разные uuid'ы. |
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
  (`outline_ws_uplink_runtime_failures_suppressed_total`) и
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
  Метрика `outline_ws_uplink_active_wire_index{transport}`
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

  **Ошибки целостности payload в этот список не входят.**
  Датаграмма, которую не удалось открыть AEAD, обрезанный пакет или
  отклонение SS2022 как дубль/переупорядоченный говорят о *байтах*,
  а не о носителе, который их доставил, поэтому
  `report_runtime_failure*` уводит их в
  `report_payload_integrity_failure`: они считаются в
  `outline_ws_uplink_payload_integrity_errors_total{cause}` и больше
  ни на что не влияют — ни cooldown, ни penalty, ни streak
  runtime-провалов, ни тик круга ротации, ни cap носителя. Рвётся
  только пострадавший flow (`payload_error` на TUN UDP-пути); на
  SOCKS5 UDP-downlink датаграмма дропается, транспорт остаётся.
  Полевой кейс, из-за которого это сделано: доля битых датаграмм
  ~0.1% открыла 682 окна `xhttp_h3 → xhttp_h2` за 16 часов на одном
  узле и держала его в UDP-поверх-TCP 69.6% времени. Это data-plane
  половина того же инварианта, который проба держит через
  `carrier_ok` против `transport_ok`: носитель спускается только по
  признакам самого носителя.
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
  counter. Только когда wire достигает `ws_h1` / `xhttp_h1` —
  следующая ошибка на активном wire вызывает
  собственно wire-rotation step. Это даёт оператору
  `min_failures × carrier_ranks` бюджет на каждом wire перед
  переходом на следующий, что соответствует обещанному в общей
  доке каскаду `h3 → h2 → http1` на активном плече.
  Каскад **per-wire**: кэп wire 0 живёт в primary-слоте descent
  (его читает `effective_tcp_mode`), кэп fallback-wire — в
  `fallback_mode_downgrades[wire - 1]` (его читает
  `effective_tcp_mode_for_wire`). Отказ на одном wire никогда не
  капает другой — в том числе runtime-отказ на активном fallback,
  который иначе зажимал бы носитель всем дайлам wire 0. Кэп каждого
  wire двигают только его собственные сигналы: реальный трафик по
  нему, дайл, который на нём зафолбечился, и — для активного
  fallback — fallback-wire-проба: она дайлит *effective* носитель
  этого wire и потому ведёт каскад вниз (и обратно вверх) ровно так
  же, как primary-проба для wire 0. Одна асимметрия, о которой стоит
  знать: recovery-проба по сконфигурированному носителю есть только у
  primary, поэтому кэп fallback-wire отыгрывается назад по одному
  рангу через walk-up, а последний шаг обратно на сконфигурированный
  носитель ждёт истечения окна `mode_downgrade_secs`.
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
  upstream-серверы) и хочется, чтобы разные перезапуски процесса
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

#### Периодический реролл active-wire (`shuffle_timer`)

Per-uplink интервал, по которому фоновая задача рерольнет
`active_wire` для обоих транспортов на случайный wire цепочки.
Принимает human-readable длительности:

```toml
[[outline.uplinks]]
shuffle_timer = "1h"      # каждый час
# shuffle_timer = "30s"   # каждые 30 секунд
# shuffle_timer = "1h30m" # составные длительности тоже работают
# shuffle_timer = "3600"  # голое число = секунды
```

Каждый тик:

* Выбирает случайный wire из `0..total_wires` независимо для TCP
  и UDP.
* Обнуляет `active_wire_streak`, `wires_failed_in_round`,
  `consecutive_failures`, `consecutive_runtime_failures`,
  `chunk0_consecutive_failures` — новый wire начинает со свежего
  бюджета, а не наследует streak предыдущего.
* Сбрасывает любой in-flight `mode_downgrade_*` cap (carrier-стек
  нового wire независим от старого; устаревший cap иначе
  исказил бы dial-time mode для нового wire).
* Пинит новый wire на `mode_downgrade_duration`, если только
  реролл не вернул на primary (совпадает с pin-политикой
  dial/probe пути).

Когда использовать:

* Защита от time-based DPI эвристик: даже uplink, стабильно
  работающий на одном wire часами, переключится на другой carrier
  shape по каждому тику — не будет выглядеть как long-lived
  stable flow на одном URL/mode.
* Принудительная диверсификация wires по расписанию (например,
  крутить три CDN edge каждые 30 минут в часы пик).

Независим от `shuffle_wires` (он только задаёт начальный порядок
цепочки при загрузке конфига) — можно комбинировать или ставить
независимо. No-op для аплинков без fallbacks.

Интервал виден в JSON snapshot как `shuffle_timer_secs:
Option<u64>`, а событие реролла пишется в метрику
`outline_ws_uplink_failover_total{transport="tcp_shuffle_timer"}`
(и UDP аналог).

**Probe-driven early-failback подавляется** пока
`shuffle_timer = Some(_)` активен. Дефолтное поведение
`record_transport_success` — снапать `active_wire` обратно на
primary как только primary probe успешно сработал
`probe.min_failures` раз подряд ("primary восстановлен, верни
трафик"); под `shuffle_timer` этот snap-back в следующем же
probe-цикле (~30 секунд при `min_failures = 2`) молча отменял
бы реролл, и ротация в UI выглядела как «ничего не меняется».
Поэтому реролл становится authoritative источником
`active_wire` до следующего тика, а probe-успех на primary
остаётся информационным сигналом (счётчики тикают, healthy
флипается обратно в true, recovery probe чистит cap), но
`active_wire` больше не трогает.

#### Mid-session handover (chunk-0 wire-aware failover)

- Если у сессии чанк-0 застрял (нет первого байта от upstream'а в
  пределах `tcp_chunk0_failover_timeout`), цикл chunk-0 failover
  теперь сначала пробует все остальные wire'ы **этого же** аплинка
  (Phase A) перед прыжком на другой аплинк (Phase B). Wire-handover dial
  — это **свежий** дозвон: он не предъявляет токен `X-Outline-Resume`, и
  новый wire открывает новый upstream-разговор (застрявший chunk-0
  означает, что байтов от upstream'а и не было). События wire-handover
  пишутся на failover-счётчик с `transport="tcp_wire"`; cross-uplink
  failover'ы — `transport="tcp"`.

#### Resume через wire-свитчи

- Resume следует за **сессией**, а не за wire'ом. Сессия, которую
  редайлят посреди потока (mid-session retry, кластерный soft-switch),
  предъявляет тот токен `X-Outline-Resume`, который выдали *ей* на
  умершем wire'е — на каком бы wire'е она ни оказалась. Поэтому сессия,
  установленная на primary VLESS-wire и переехавшая на fallback WS-wire,
  всё так же переприкрепляет свой припаркованный upstream на сервере.
  Работает для любой комбинации, где оба wire'а несут WS-resume header
  (WS, VLESS-WS, VLESS-XHTTP).
- Чего больше **не** шарится — так это самого токена: per-uplink слота
  resume нет, поэтому дозвон физически не может предъявить токен,
  выданный другой сессии (на hit'е это переприкрепило бы upstream той
  сессии и тихо увело бы эту на чужой destination).

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
  `outline_ws_uplink_health_effective`) отражает «доставляет ли
  аплинк трафик?»: probe-подтверждённое ИЛИ any-wire недавно работал.
  Legacy `tcp_healthy` / `outline_ws_uplink_health` сохраняет
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
- DNS-кэш и per-uplink fingerprint scope **сохраняются** через
  wire-свитчи; собственный resume-токен редайлящейся сессии — тоже (он
  едет с сессией, а не с wire'ом).
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
  семантики. `outline_ws_uplink_rtt_ewma_seconds{transport,uplink}`
  сохраняет legacy primary-only вердикт — пригодится для здоровья
  именно сконфигурированного primary независимо от того, какой wire
  сейчас тянет трафик. `outline_ws_uplink_active_wire_rtt_ewma_seconds{transport,uplink}`
  отдаёт EWMA wire'а, реально несущего трафик; равен legacy gauge
  при `active_wire == 0`, иначе читает соответствующий
  `fallback_rtt_ewma` слот. Операторы, графящие user-visible
  latency / алертящие по real-traffic RTT, используют active-wire
  gauge; primary-health алерты остаются на legacy gauge.

#### UDP-кандидатура

- UDP-фильтр кандидатов (`supports_transport_for_scope`)
  консультируется с `UplinkConfig::supports_udp_any()`, так что
  аплинк, у которого primary — TCP-only (например, WS-аплинк без
  `udp_ws_url`), но fallback UDP-capable, всё равно попадает в
  UDP-выдачу.

#### Поддерживаемые wire-формы VLESS-fallback'а

- **Обе формы работают как VLESS-fallback**: `ws_h1` /
  `ws_h2` / `ws_h3` (WS-семейство) и `xhttp_h1` / `xhttp_h2` /
  `xhttp_h3` (XHTTP-семейство). Каждый fallback-wire отслеживается
  независимо — его слот per-wire mode-downgrade отдельный от
  primary, поэтому carrier-даунгрейд fallback-wire'а кэпит только
  его слот, не загрязняя mode-tracking primary.

### Inline-стенограмма `[outline]`

Inline-форма (`tcp_ws_url` и т.п. прямо на `[outline]`) **не**
поддерживает fallback'и — для них объявите явный массив
`[[outline.uplinks]]`.

## Контроль срока TLS-сертификатов

Независимо от data-path проб прокси раз в 6 часов (плюс один раз при
старте и после перезагрузки конфига) выполняет фоновую проверку: открывает
прямое TLS-соединение к собственному endpoint'у каждого аплинка — ко
всем `wss://` / `https://` хостам по primary и fallback wire'ам,
дедуплицированным по `(host, port)` и с `fwmark` аплинка — и читает поле
`notAfter` листового сертификата. Соединение принимает сертификат
независимо от валидности (поэтому уже протухший серт всё равно
считывается) и сразу закрывается, не обмениваясь данными. Это **внешний**
сертификат самого сервера аплинка — в отличие от data-path пробы
`[outline.probe.tls]`, которая проверяет внешний SNI *через* туннель.

Ближайший `notAfter` среди endpoint'ов аплинка отдаётся двумя путями:

- **Prometheus**: `outline_ws_uplink_cert_expiry_timestamp_seconds{group,uplink}`
  — срок как Unix-таймстамп в секундах. Отсутствует до первой проверки и
  для аплинков без TLS-endpoint. Алерт настраивайте
  со своим порогом, например
  `outline_ws_uplink_cert_expiry_timestamp_seconds - time() < 14 * 86400`.
- **Дашборд**: в колонке Status аплинка появляется янтарный чип
  `⚠ cert Nd`, когда до истечения меньше 14 дней, и красный
  `⚠ cert expired`, когда серт уже протух; для здорового серта чип не
  показывается.

Включается через build-фичи `metrics` и `dashboard` (через их под-фичу
`cert-check`); урезанные `router`-сборки не тянут ни проверку, ни
X.509-парсер.
