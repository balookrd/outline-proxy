# История изменений

Все заметные изменения проекта собраны в этом файле.

Этот журнал покрывает стабильные git-теги `v1.0.0` … `v1.3.1`; последний стабильный релиз — `v1.3.1` (2026-04-30). В репозитории также используется тег `nightly` для публикации nightly-канала; соответствующие изменения сгруппированы под ближайшим стабильным релизом. Секция `## Unreleased` содержит изменения, попавшие после `v1.3.1`.

*English version: [CHANGELOG.md](CHANGELOG.md)*

## Unreleased

Изменения после `v1.3.1` (2026-04-30):

### Добавлено

- Динамический генератор access-key теперь выпускает второй URI VLESS-over-XHTTP на пользователя, когда `xhttp_path_vless` установлен: существующий `<user>-vless-xhttp.<ext>` сохраняет `?type=xhttp&mode=packet-up` (имя файла и фрагмент не меняются — уже разосланные `ssconf://`-ссылки продолжают работать), а новый `<user>-vless-xhttp-stream-one.<ext>` несёт `?type=xhttp&mode=stream-one` с фрагментом `<host-short>:<user>-xhttp-stream-one`. Сервер уже обслуживает оба wire-режима на одном base path, так что клиент сам подбирает тот, что проходит на его сети, без ручного редактирования URI.
- Добавлен L4 SNI fallback (маскировка). Новый блок `[sni_fallback]` подсматривает TLS ClientHello до handshake'а, и если SNI не попадает под `match_sni` — сплайсит сырое TCP-соединение (вместе с захваченным ClientHello) на внешний backend (haproxy, nginx, caddy, …), у которого свой собственный сертификат для чужих SNI. Сестра `[http_fallback]` на уровень ниже OSI: со стороны пассивного сканера наш листенер становится похож на SNI-маршрутизирующий haproxy frontend. Whitelist поддерживает nginx-style wildcards с одним лейблом слева (`*.api.example.com`); `allow_no_sni = false` (по умолчанию) отправляет коннекты без SNI на бэкенд; `proxy_protocol = "v1" | "v2"` настоятельно рекомендуется, иначе бэкенд видит `127.0.0.1` как peer для каждого спайса — логи / ACL / rate-limit становятся бесполезны. Throw-away `rustls::server::Acceptor` парсит ClientHello, захваченные байты возвращаются в наш TLS-терминатор через обёртку `PrependStream` (если SNI наш) или дописываются в начало бэкенд-соединения перед `tokio::io::copy_bidirectional` (если чужой). Малформированные handshake'ы (больше `max_client_hello_bytes`, по умолчанию 8 KiB) закрываются локально — junk не уходит на бэкенд и не засоряет его логи. Требует, чтобы основной TCP-листенер терминировал TLS; HTTP/3 SNI парсится quinn'ом до того, как наш код его видит, и в scope не входит. PROXY-protocol-кодер вынесен из `transport::fallback` в общий `transport::proxy_protocol`, чтобы оба fallback'а эмитили одинаковую wire-форму.
- Добавлен L7 HTTP fallback (маскировка). Новый блок `[http_fallback]` reverse-proxy'ит каждый запрос, который не попал ни в один существующий WebSocket / XHTTP / metrics / control / dashboard маршрут, на внешний upstream (haproxy, nginx, caddy, …) вместо `404`, чтобы листенер перестал отличаться от обычного веб-сервиса. Hop-by-hop заголовки (RFC 7230 §6.1 + всё перечисленное в `Connection:`) срезаются в обе стороны, тело стримится насквозь, `Host` заменяется на authority бэкенда (поведение nginx-овского `proxy_set_header Host $proxy_host;`). `X-Forwarded-For`, `X-Forwarded-Proto`, `X-Forwarded-Host` добавляются/выставляются по тумблерам; `X-Forwarded-Proto` отражает, терминировал ли входящий листенер TLS. Опциональный `proxy_protocol = "v1" | "v2"` добавляет HAProxy PROXY-protocol заголовок в начало TCP-соединения с бэкендом, чтобы тот логировал реальный IP клиента — адрес назначения берётся из bind-адреса входящего листенера (деградирует до UNKNOWN/UNSPEC при `0.0.0.0` / `[::]`). По одному upstream TCP-соединению на запрос (без пула); HTTPS-upstream, Unix-доменные сокеты и h3 fallback — вне MVP.
- Добавлен `backend_proto = "h1" | "h2"` в `[http_fallback]`, управляющий HTTP-версией, на которой листенер говорит с upstream-бэкендом. По умолчанию `"h1"` — поведение существующих развёртываний не меняется байт-в-байт; `"h2"` переключает upstream-клиент на prior-knowledge HTTP/2 (h2c, без ALPN), что полезно, когда бэкенд — это gRPC-gateway или envoy / caddy / nginx-upstream, настроенный на h2c. Независим от входящего протокола — клиент HTTP/1.1 на нашем листенере всё равно может быть проброшен на h2-бэкенд, и наоборот. На проводе к upstream только plain HTTP (HTTPS-upstream остаётся вне MVP); рассчитано на доверенные backends в приватной сети или на loopback'е, что согласуется с существующим ограничением `http://` для MVP. Заодно подготовка под будущий h3 fallback-адаптер, который разделит тот же тумблер `backend_proto`.
- Расширен `[http_fallback]` на HTTP/3-листенер через два новых тумблера: `apply_to_h1` (по умолчанию `true` — сохраняет прежнее TCP-only поведение) и `apply_to_h3` (по умолчанию `false`, opt-in). При `apply_to_h3 = true` каждый QUIC-запрос, не попавший ни в XHTTP base path, ни в WS-over-h3 CONNECT, ни в auth-root `/`, проксируется на тот же upstream — тот же `backend`, тот же `backend_proto = "h1" | "h2"`, та же стрипка hop-by-hop / `X-Forwarded-*`, что и на TCP-стороне. `X-Forwarded-Proto` всегда рапортует `https` (QUIC по спеке шифрован), независимо от того, был ли `tls_cert_path` выставлен на TCP-листенере. PROXY-protocol заголовки, эмитирующиеся в TCP-сокет к бэкенду, несут `Transport=DGRAM` (`0x12` / `0x22`), так что бэкенд видит, что origin был UDP/QUIC; v1 отвергается на старте при `apply_to_h3 = true` — у v1 на проводе нет UDP-формы. Тело запроса буферизуется целиком до форвардинга (fallback-трафик — это в основном мелкие пробы; разбивать `RequestStream` ради потоковости в обе стороны не имело смысла для 404-замены); тело ответа стримится chunk-ами обратно через QUIC — backend, отдающий большой файл или SSE-канал, проходит насквозь, не залипая в RAM. Трейлеры пробрасываются в обе стороны, если выбранный `backend_proto` их умеет. Auth-root challenge (`http_root.auth = true` для `/`) сохраняет приоритет над fallback'ом и на h3-пути — это симметрично тому, как axum-роутер пиннит `/` впереди wildcard-фолбэка на TCP-стороне.

### Исправлено

- XHTTP packet-up теперь распознаёт URL-формат, который шлют клиенты xray-семейства (`happ`, `hiddify`, `v2rayN` и пр.), и они перестают таймаутить на каждом тесте соединения. Раньше сервер регистрировал маршрут только в форме `<base>/<id>` и брал per-packet `seq` из заголовка `X-Xhttp-Seq` — это конвенция, под которую заточен `outline-ws-rust`. Клиенты xray по дефолту используют `PlacementPath` и для session, и для seq, и кладут `seq` прямо в URL, отправляя POST'ы на `<base>/<id>/<seq>`; без матчингового маршрута такие POST'ы тихо отдавали 404, и клиент бесконечно ретраил с новыми session id'ами, пока не сдавался. Теперь оба пути — axum-роутер (HTTP/1.1, HTTP/2) и HTTP/3-диспатчер — матчат любую из двух форм; path-based seq имеет приоритет над заголовочным, если клиент пришлёт оба сразу, чтобы будущий клиент с обоими формами получал детерминированный ответ, а не молчаливое расхождение. `<base>/<id>/<seq>` принимает только POST (GET в этой форме отвечает 400) и только при `?mode=packet-up` (у stream-one нет per-packet seq); не-числовой `<seq>` сегмент уходит в глобальный not-found хэндлер, чтобы опечатка не попала случайно в GET-ветку. Существующие клиенты `outline-ws-rust` продолжают использовать заголовочную форму без изменений.

### Изменено

- Восстановлен паритет EN/RU README. В RU вернули пропавший раздел "Чистый Shadowsocks-сокет" (deployment mode #3) и перепронумеровали SNI/HTTP-fallback'и под EN, перенесли блок "Настройка производительности HTTP/3" в его EN-позицию (после "Наблюдаемости", перед "Production-эксплуатацией"), обновили список Prometheus-метрик под актуальные эмиттеры (smaps virtual-mapping, thread count и т.д.) вместо устаревших упоминаний `[heap]` и legacy allocator-trim, и привели строку "VLESS поверх WebSocket" в feature-table к EN-варианту (доступно поверх h1/h2/h3). Количество секций, bullet'ов, таблиц и code-fence'ов теперь совпадают по всем пяти двуязычным докам (README, ARCHITECTURE, SESSION-RESUMPTION, PATCHES, CHANGELOG).
- Переписана шапка CHANGELOG и старый backlog `Unreleased` разнесён по фактическим тегам в отдельные секции (`## 1.3.1`, `## 1.3.0`, `## 1.2.0`, `## 1.1.0`) согласно тому, в какие стабильные релизы между `v1.0.2` и `v1.3.1` попали изменения. Раньше всё после `v1.0.2` лежало в `Unreleased`, что вводило в заблуждение — четыре стабильных релиза уже были выпущены. Теперь `Unreleased` несёт только работу, пришедшую после `v1.3.1`.

## 1.3.1 - 2026-04-30

### Добавлено

- Добавлено cross-repo покрытие SS-TCP поверх raw-QUIC — ячейка матрицы, отмеченная в handoff-брифе как пропущенная. Серверная сторона переиспользует `serve_h3_server` с `H3Alpn::Ss` и общий самоподписанный CA+leaf серт; клиент дёргает публичный `outline_transport::connect_ss_tcp_quic` через URL `https://` и тот же шифр `Chacha20IetfPoly1305` / master key `secret-b`, что и остальные SS-тесты. Resume-варианта нет — у SS-over-raw-QUIC нет места для resume-токена на проводе (HTTP-headers отсутствуют, а Addons-TLV — VLESS-only механизм).
- Расширено cross-repo покрытие на WS-h2 → WS-h1 fallback в диспетчере с end-to-end сохранением resume-токена. Два новых теста — VLESS-WS и SS-WS — поднимают plain-TCP h1-only axum-сервер с `OrphanRegistry`, получают токен `X-Outline-Session` через клиента A на `WsH1`, и направляют клиента B с `WsH2` на тот же `ws://` URL. Префикс h2 prior-knowledge падает на h1-кодеке hyper'а как malformed-h1, диспетчер фиксирует фейл и ретраит на h1 с тем же `X-Outline-Resume` — сервер переподключает припаркованный upstream, а `TransportStream::downgraded_from()` репортит изначальный `WsH2`. (XHTTP исключён — у диспетчера нет h1-fallback'а для XHTTP, минимум — h2.) Plain TCP убирает несоответствие tungstenite vs override-slot, которое возникло бы на h1 поверх TLS — tungstenite использует webpki для `wss://` и не консультирует наш cross-repo TLS-override.
- Расширено cross-repo покрытие на h3→h2 fallback в диспетчере с end-to-end сохранением resume-токена. Три новых теста — XHTTP, VLESS-WS, SS-WS — поднимают TLS-only axum-сервер с `OrphanRegistry`, получают токен `X-Outline-Session` через клиента A на h2, и направляют клиента B на тот же `https://`/`wss://` URL с запросом `XhttpH3` / `WsH3`. UDP-листенера на порту нет, h3 connect упирается в 10-с таймаут, диспетчер фолбэчит на h2 с тем же resume-заголовком — сервер переподключает припаркованный upstream, а `TransportStream::downgraded_from()` репортит изначальный h3-режим. По ходу написания этих тестов нашли и поправили шестилетний баг h2-диалера на клиенте (двойной слэш в `:path`); см. ws-rust коммит d268ce9.
- Расширено cross-repo покрытие session-resumption на h3-carrier'ы: XHTTP packet-up поверх h3 переподключается через ту же пару заголовков `X-Outline-Resume-Capable` / `X-Outline-Session`, что и h2-путь (uplink-EOF дрейвится через тест-only `XhttpRegistry::first_session` + `close_uplink`, поскольку у клиента нет FIN-сигнала), VLESS-TCP поверх WebSocket-h3 (RFC 9220) переподключается через graceful WS Close на QUIC bidi-стриме, и SS-TCP поверх WebSocket-h3 переподключается через Close в priority-канале writer'а с теми же 100 мс ожидания, что использует h2-путь, чтобы `AbortOnDrop` не убил спаунд writer-таску гонкой.
- Расширено cross-repo покрытие session-resumption за пределы XHTTP h2: VLESS-TCP поверх WebSocket-h2 переподключается к припаркованному upstream'у после graceful WS Close от клиента A, VLESS-TCP поверх raw QUIC переподключается через VLESS Addons opcode `RESUME_ID` (`0x11`), и SS-TCP поверх WebSocket-h2 переподключается через ту же пару заголовков `X-Outline-Session`, что эмитит продакшен-листенер. SS-WS-путь требует 100 мс ожидания между отправкой Close в priority-канал writer'а и дропом обёртки — иначе `AbortOnDrop` writer'а убьёт спаунд-таску до того, как Close-фрейм уйдёт на провод, и relay воспримет дисконнект как ошибку, а не как parkable shutdown.
- Расширена cross-repo матрица carrier'ов: добавлены WebSocket-h1 и WebSocket-h3 (RFC 9220) для VLESS и Shadowsocks. VLESS-сюита теперь покрывает packet-up h2/h3 + stream-one h2/h3 через XHTTP, плюс VLESS-TCP поверх WS-h1 / WS-h2 / WS-h3 / raw-QUIC. SS-сюита теперь покрывает SS-TCP plain плюс SS-TCP поверх WS-h1 / WS-h2 / WS-h3. h3-carrier'ы (XHTTP h3, WS-h3) шарят один самоподписанный серт, установленный один раз через `outline_transport::install_test_tls_root`; WS-h3 требует `wss://` URL'ов, WS-h1/h2 требует `ws://`.
- Добавлено cross-repo e2e-покрытие Shadowsocks: SS поверх plain TCP (серверный `serve_ss_tcp_listener`, клиент сплитит `TcpStream` и оборачивает в `TcpShadowsocksWriter::connect_socket` / `TcpShadowsocksReader::new_socket`) и SS поверх WebSocket-h2 (серверный дефолтный axum-роут `/tcp`, клиент сплитит `TransportStream` из `connect_websocket_with_resume` и оборачивает в WS-варианты конструкторов `connect` / `new`). Шифр — `Chacha20IetfPoly1305`, master key выводится на клиенте через `CipherKind::derive_master_key` (`CipherKind` ре-экспортирован из `shadowsocks-crypto` по тому же мотиву, что и `TargetAddr` ранее).
- Добавлено cross-repo e2e-покрытие VLESS поверх XHTTP-сюиты: VLESS-TCP поверх WebSocket-h2 (plain TCP, `ws://` URL) и VLESS-TCP поверх сырого QUIC (TLS+QUIC, ALPN `vless`, самоподписанный серт устанавливается на клиенте через `outline_transport::install_test_tls_root`). Оба теста дёргают публичный клиентский API (`connect_websocket_with_resume`, `connect_vless_tcp_quic_with_resume`) и гоняют настоящий VLESS-handshake к локальному TCP-эхо-апстриму.
- Добавлено end-to-end покрытие XHTTP между репозиториями: новый тест-модуль поднимает настоящий клиент из `outline-ws-rust` (соседний репо, подключён как dev-dep по относительному пути) и гоняет его против этого сервера в одном tokio-процессе. Пять кейсов — packet-up h2, stream-one h2 и h2 resume между двумя последовательными dial-ами с одним и тем же токеном `X-Outline-Session` поверх plain TCP, плюс packet-up h3 и stream-one h3 поверх самоподписанного TLS+QUIC-эндпоинта с сертом, установленным на клиенте через новую ручку `outline_transport::install_test_tls_root`. Кейс resume гонит uplink-EOF напрямую через `XhttpSession::close_uplink`, потому что у клиента пока нет FIN-сигнала; h3→h2 fallback с cross-carrier токеном отложен (10 с QUIC-таймаут на каждый упавший dial).
- Добавлены регрессионные тесты на контракт XHTTP downlink-кольца при обрыве GET: GET, дропнутый посреди стрима, не закрывает сессию, downlink-слот освобождается, а следующий GET с тем же path id читает байты, запушенные уже после обрыва.
- Расширен VLESS-over-XHTTP режимом `stream-one` рядом с существующим `packet-up`. Сервер выбирает carrier per-request из query URL'а: `?mode=stream-one` — это один bidirectional POST, у которого request body несёт uplink, а response body несёт downlink; отсутствие query (или `?mode=packet-up`) сохраняет поведение GET+POST. Stream-one отклоняет HTTP/1.1 с 505, потому что h1 не умеет full-duplex; на h3 bidi-стрим QUIC разделяется через `RequestStream::split` на send/recv половины на отдельных tasks. Один base path обслуживает оба режима — клиенты на том же `xhttp_path_vless` могут выбрать тот, который переживёт текущую сеть.
- Подключён cross-transport session resumption через XHTTP carrier. Когда `[session_resumption]` включён, XHTTP-handler читает `X-Outline-Resume-Capable` / `X-Outline-Resume` из первого GET или POST, который создаёт сессию, минтит `X-Outline-Session` ровно один раз на сессию, и кладёт токен в `XhttpSession::issued_resume_id` — так каждый последующий attach (переподключённый GET, поздний POST) возвращает то же значение клиенту. Сминтованный `ResumeContext` пробрасывается прямо в `run_vless_relay`, поэтому существующая per-protocol park-on-drop / take-on-resume логика просто работает — в том числе при смене carrier'а (клиент, у которого упал `xhttp_h3` dial, может откатиться на `xhttp_h2` с тем же токеном, и сервер переподключит припаркованный VLESS upstream вместо нового connect'а к таргету).
- Добавлен VLESS-over-XHTTP packet-up листенер для VLESS, использующий тот же VLESS-relay через новый `WsSocket`-адаптер, поэтому TCP, UDP, mux.cool/XUDP и session resumption работают поверх h1, h2 и h3 без дублирования логики. Wire-сторона: GET на `<base>/<id>` открывает long-lived downlink, POST'ы на тот же URL с `X-Xhttp-Seq` несут uplink. Reorder-буфер на сервере склеивает out-of-order POST'ы от h2-мультиплексированных клиентов; downlink-кольцо переживает обрыв GET'а в полёте (CDN ~100 c) — следующий GET с тем же id продолжает чтение с того места, где предыдущий остановился. Каждый ответ несёт случайный `X-Padding` (100–1024 байта URL-safe ASCII) плюс SSE-style маскировочные заголовки (`Content-Type: text/event-stream`, `Cache-Control: no-store, no-cache, must-revalidate`, `Pragma: no-cache`, `X-Accel-Buffering: no`), чтобы пассивный fingerprinting по размеру/форме первого ответа не цеплял XHTTP. Настраивается через `xhttp_path_vless` (top-level + per-user override); валидация запрещает пересечение с WS-/TCP-/UDP-путями. Динамический генератор access-key выпускает дополнительный `vless://...?type=xhttp&mode=packet-up&path=...` URI на пользователя, если поле задано — xray, sing-box, Hiddify, v2rayNG и Shadowrocket принимают этот URI как есть.

## 1.3.0 - 2026-04-29

### Изменено

- Флаги `tokio::sync::Mutex<bool>`, охранявшие состояние magic-префикса в oversize-record-стриме сырого QUIC, заменены на `AtomicBool`. Прежняя раскладка брала по два async-мьютекса на запись (`send` + `pending_magic` на send, `recv` + `expect_magic` на recv), добавляя по два лишних `.await` на горячий путь, хотя каждый флаг переключается с `true` на `false` ровно один раз, а доступ уже сериализован внешним `send`/`recv`. Датаграммы, которые не помещаются в `Connection::max_datagram_size()` и едут через этот fallback-канал, теперь делают на две task-yield меньше на каждый record.

## 1.2.0 - 2026-04-28

### Добавлено

- Добавлен `tuning.ws_data_channel_capacity` — настраиваемая ёмкость per-session bounded mpsc для WS-writer fan-in. Дефолты: `16` / `64` / `128` для профилей `small` / `medium` / `large`. Прежнее жёстко зашитое `16` было выбрано под memory-constrained multi-session деплои и не давало throughput'а для high-bandwidth single-tenant TUN-клиентов на bursty видео — кратковременные задержки WS-writer'а упирали upstream-чтение, плеер не успевал буферизовать, на экране были фризы. Дефолтный профиль (`large`) теперь возвращает запас по throughput; для memory-constrained деплоев override `16` восстанавливает прежнее поведение.
- Добавлено возобновление сессии между транспортами для SS-over-WebSocket, одиночного VLESS-over-WebSocket, одиночного VLESS-UDP поверх WebSocket, VLESS-mux поверх WebSocket, SS-UDP поверх WebSocket и **VLESS-TCP поверх сырого QUIC** (opt-in через `[session_resumption]`, по умолчанию выключено). При включении сервер генерирует 16-байтовый Session ID, возвращает его в заголовке ответа `X-Outline-Session` на WebSocket Upgrade (HTTP/1.1, HTTP/2, HTTP/3), и при разрыве паркует живой upstream в in-memory реестр осиротевших сессий вместо его закрытия. Последующий коннект по любому WebSocket-транспорту с заголовком `X-Outline-Resume: <hex>` после аутентификации того же пользователя пересаживается на припаркованный upstream, пропуская connect к таргету. Для VLESS-mux весь `MuxState` — каждое TCP и UDP под-соединение внутри — паркуется **атомарно**; UDP-sub-conn'ы переподключаются через shared `Arc<UdpSocket>` (без back-buffer'а, пакеты во время park-периода могут быть дропнуты, что соответствует loss-tolerance UDP). Одиночный VLESS-UDP работает так же: connected `UdpSocket` сохраняется через переподключение WS вместе с частично-распарсенным 2-byte-length-prefix буфером. SS-UDP-over-WS connectionless на уровне WebSocket — один стрим может регистрировать несколько NAT-entries `(user, fwmark, target)` — поэтому park снепшотит *список NAT-ключей*, owned'ом которых этот стрим был, и detach'ит свой sender в каждом (`detach_session_for_stream` мэтчится по stream-уникальному `u64`, чтобы одновременный reconnect не сбил slot); resume на первом аутентифицированном datagram'е переподключает каждую выжившую entry к новому sender'у без re-bind upstream-socket'ов. У сырого QUIC нет HTTP-заголовков, поэтому negotiation едет в VLESS request Addons TLV: тег `0x10 RESUME_CAPABLE`, тег `0x11 RESUME_ID`; ответ несёт `0x10 SESSION_ID` и `0x11 RESUME_RESULT`. Raw-QUIC TCP паркуется в том же `Parked::Tcp(Vless)` варианте, что и VLESS-over-WS, так что клиент, потерявший raw QUIC, может откатиться на VLESS-over-WS и продолжить тот же upstream прозрачно. Припаркованная запись запоминает, какой прокси-протокол аутентифицировал исходную сессию — попытки cross-protocol / cross-shape resume (SS↔VLESS, single↔mux, tcp↔udp, ss-udp↔vless-udp) отклоняются. Direct SS-UDP (без WebSocket-туннелирования) вне зоны охвата по спеке. Mismatch владельца внешне отчитывается как `unknown`, чтобы не давать oracle-подсказку о существовании ID. Лимиты per-user (`orphan_per_user_cap = 4`) и глобальный (`orphan_global_cap = 10000`) ограничивают память; периодический sweeper выселяет записи старше `orphan_ttl_tcp_secs` (по умолчанию 30 с). Новые метрики: `outline_ss_orphan_park_total{kind}`, `_resume_hit_total{kind}`, `_resume_miss_total{reason}`, `_evicted_total{kind,reason}`, `_current{kind}` — `kind` это `tcp`, `vless_udp_single`, `vless_mux` или `ss_udp_stream`. UDP-single и сырой QUIC вне зоны охвата; формат и план — в `docs/SESSION-RESUMPTION.md`.
- Добавлен сырой VLESS-over-QUIC и Shadowsocks-over-QUIC (без WebSocket, без HTTP/3 framing'а). Тот же QUIC-эндпоинт `h3_listen` мультиплексирует их по ALPN: новый список `[server.h3].alpn` (по умолчанию `["h3"]`) выбирает рекламируемые протоколы — `h3` оставляет существующий путь HTTP/3 + WebSocket-over-HTTP/3, `vless` передаёт один VLESS-запрос на bidi QUIC-стрим (TCP-таргет — двунаправленный сплайс на стриме; для UDP bidi-стрим работает как control/якорь времени жизни сессии, а пакеты идут QUIC datagram'ами с 4-байтным big-endian session_id'ом), `ss` передаёт одну SS-AEAD TCP-сессию на bidi-стрим и один SS-AEAD UDP-пакет на QUIC datagram (через ту же NAT-таблицу и replay store, что и обычный UDP-слушатель). Добавлена метка `quic` в существующих метриках протокола. Команда VLESS `mux.cool` на сыром QUIC отклоняется — вместо неё открывайте дополнительные QUIC-стримы.
- Добавлена поддержка VLESS mux.cool / XUDP поверх WebSocket: TCP- и UDP-под-соединения мультиплексируются в рамках одного VLESS-стрима (совместимо с xray / happ / hiddify), с per-packet адресацией в Keep-фреймах и лимитом 8 одновременных под-соединений на сессию. XUDP `GlobalID` парсится, но переиспользование UDP-сессий между реконнектами пока не реализовано.

### Безопасность

- HTTP/3-листенер огорожен двумя семафорами против DoS через неограниченный fan-out задач: приём соединений ограничен 4096 (как у TLS и shadowsocks), а обработчики WebSocket-стримов — глобальным лимитом 65536 суммарно по всем QUIC-соединениям. Ранее клиент мог открыть множество QUIC-соединений и умножить per-connection стрим-лимиты в неограниченный `tokio::spawn`.
- Стор SS-2022 anti-replay огранничен через `tuning.udp_replay_max_sessions` (дефолты по профилям 16k/64k/256k; `0` отключает cap). Ранее клиент с валидным ключом мог вращать `client_session_id` в каждом пакете и раздувать стор без ограничения до следующего прохода idle-eviction. Дропы при достижении cap экспонируются как `outline_ss_udp_replay_store_full_dropped_total{user,protocol}`.
- Запись конфигурации при мутациях control plane больше не блокирует tokio-воркер: мьютекс пользовательского списка переведён на `tokio::sync::Mutex`, а `persist_users` выполняется через `spawn_blocking` — медленная запись на диск (NFS, USB) не останавливает рантайм, пока удерживается лок.
- VLESS-over-WebSocket теперь отправляет корректный WebSocket Close фрейм при ошибке парсинга/аутентификации вместо тихого закрытия каналов. Раньше проба с неправильной версией VLESS или неизвестным UUID получала резкий FIN/RST без какого-либо Close по RFC 6455 — это была чёткая сигнатура, по которой active probes могли отличить VLESS от обычного WebSocket-эндпоинта и от SS-поверх-WS (где Close при auth-фейле уже отправлялся). Ошибки upstream TCP/UDP connect по-прежнему транслируются в Close 1013 (Try Again Later); ошибки парсера/аутентификации — в обычный Close, симметрично пути SS.
- Добавлен probe-resistance sink при отклонённом handshake для VLESS и Shadowsocks по всем транспортам — WebSocket, plain TCP и raw-QUIC. После отказа парсера/аутентификации соединение удерживается открытым, а входящий трафик дренируется в /dev/null до срабатывания существующего handshake-таймаута (`SS_TCP_HANDSHAKE_TIMEOUT_SECS = 30`) или лимита в 64 КиБ принятых байтов; только после этого приходит close. Это убирает сигнатуру по таймину close, по которой раньше можно было отличить VLESS (парсер бейлится на 18-м байте) от SS (AEAD-путь висит, пока не наберётся полный AEAD-блок) и от обычного эндпоинта. Сессии в sink-режиме отображаются в метриках как `disconnect_reason="handshake_rejected"` — отдельно от `error`, чтобы их длительный жизненный цикл не искажал статистику настоящих relay-ошибок.

### Изменено

- Поле `vless_ws_path` у `[[users]]` переименовано в `ws_path_vless` для единообразия с `ws_path_tcp` / `ws_path_udp`. JSON-поле control API и форма дашборда тоже используют новое имя. **Breaking change**: конфиги и API-клиенты со старым именем не проходят `deny_unknown_fields`.
- SS-2022 UDP session-key cache теперь шардируется на 16 независимых LRU-партиций по ключу FNV-1a от `(user_index, salt[..8])`. Прежний LRU под одним мьютексом сериализовал каждый UDP-датаграм по всем worker-тредам — на тысячах pps сам acquire лока проявлялся как джиттер на decrypt-пути, а подряд идущие попадания по несвязанным `(user, salt)` блокировали друг друга. Lookup и insert теперь касаются только одного шарда, floor конкуренции упал в 16× без изменений публичного API; настроенная суммарная ёмкость делится между шардами поровну (с округлением вверх).

### Исправлено

- Исправлен VLESS поверх HTTP/3: H3-роутер не проверял множество VLESS-путей, поэтому Extended CONNECT на любой сконфигурированный `vless_ws_path` получал 404. Теперь VLESS маршрутизируется в H3 наравне с Axum (TCP, UDP, mux.cool/XUDP).
- Исправлен drain-таймер HTTP-листенера, срабатывавший через 10 с после старта независимо от сигнала на завершение. Предыдущая попытка ограничить shutdown `axum::serve` оборачивала весь serve-future в `tokio::time::timeout`, и обычные HTTP/метрики-листенеры умирали при каждом запуске с записью `connections did not drain within shutdown timeout` в журнале. Теперь serve-future гонится с `shutdown.cancelled().then(sleep(10s))`, так что 10-секундный bound включается только после фактического `SIGTERM`/`SIGINT`.

## 1.1.0 - 2026-04-24

### Добавлено

- Добавлены настраиваемые профили ресурсных лимитов H2/H3 (`small`, `medium`, `large`) с опциональными полевыми оверрайдами через секцию `[tuning]`.
- Добавлен process-wide семафор `udp_max_concurrent_relay_tasks` для ограничения числа одновременных UDP relay задач.
- Добавлена панель Grafana для UDP relay drops с разбивкой по transport, protocol и причине дропа.
- Добавлено кооперативное корректное завершение работы по `SIGTERM` и `SIGINT`.
- В `install.sh` добавлены проверка версии и определение SHA коммита для nightly.
- Добавлены регрессионные тесты для переподключения UDP NAT через WebSocket и HTTP/3.
- Добавлен русский перевод `PATCHES.md`.
- Добавлен рандомизированный выбор исходящего IPv6-адреса из заданного префикса или интерфейса.
- Добавлен bounded TLS-листенер с корректным сливом соединений при завершении.
- Добавлен периодический WebSocket Ping (каждые 60 с) поверх TCP для поддержания клиентского `WS_READ_IDLE_TIMEOUT`.
- Добавлен singleflight в DNS для объединения одновременных промахов по одному host/port, с тестами на коалесцирование и восстановление после ошибок.
- Добавлена панель Grafana для UDP replay drops с разбивкой по пользователю и протоколу.

### Безопасность

- Добавлена защита от повторов (anti-replay) для Shadowsocks-2022 UDP: дубликаты `packet_id` в окне сессии отбрасываются скользящим битовым фильтром на 1024 бита с ключом по client session ID (повторы к другому таргету не обходят фильтр). Дропы экспонируются как `outline_ss_udp_replay_dropped_total{user,protocol}`.
- Усилена HTTP-аутентификация на корневом пути: сравнение пароля выполняется в constant-time, из горячего пути убран повторный derivation-шаг.
- Счётчик nonce для Shadowsocks stream AEAD ограничен 2^32 вызовами в каждом направлении, чтобы оставаться в пределах безопасных лимитов AEAD.

### Изменено

- Tuning-параметры (`client_active_ttl_secs`, `udp_nat_idle_timeout_secs`, `udp_max_concurrent_relay_tasks`) перенесены из топ-левела конфига в `TuningProfile` внутри секции `[tuning]`. **Breaking change**: конфиги со старыми топ-левел ключами не проходят `deny_unknown_fields`.
- Модуль метрик разбит на специализированные субмодули (`labels`, `registry`, `guards`, `sampler`, `render`).
- Lifecycle сессии и классификация ошибок транспорта вынесены в общие хелперы, устраняя дублирующиеся match-блоки для TCP/UDP и WS/H3 путей.
- Крупные модули server, transport, crypto и config разбиты на более мелкие субмодули для упрощения поддержки.
- Экспорт метрик переведён на `metrics` и `metrics-exporter-prometheus`.
- Внутренняя логика UDP NAT отвязана от транспортно-зависимой отправки ответов.
- Продолжена оптимизация горячих путей в DNS-кеше, crypto, route map и метках метрик для уменьшения аллокаций и конкуренции за блокировки, включая кешированные системные часы (общий атомик) и read-lock фаст-паты для lookup NAT-записей и проверки replay-окна.
- Частично унифицировано серверное логирование и внутренние имена сущностей.
- Таймаут TCP upstream connect снижен с 10 с до 5 с.
- Ослаблен systemd-песочница: разрешён `AF_NETLINK`, чтобы `getifaddrs` работал при выборе исходящего IPv6-интерфейса.
- Параметры outbound IPv6 (prefix/interface) задокументированы в русском README и примерах конфигов.

### Исправлено

- Исправлена тихая классификация внутренних ошибок H3 как клиентского отключения — теперь они попадают в `DisconnectReason::Error`.
- Исправлено зацикливание QUIC-соединений за счёт keep-alive ping со стороны сервера.
- Исправлены сценарии повторной записи в HTTP/3, которые могли приводить к `H3_INTERNAL_ERROR` при записи и завершении соединения.
- Исправлено переиспользование NAT-записи при переподключении клиентской сессии.
- Исправлено симметричное завершение TCP-over-H3 при закрытии соединения клиентом.
- Попытки расшифровки для неизвестного пользователя переведены в штатно обрабатываемый сценарий вместо серверной ошибки.
- Исправлена эвикция NAT: неинициализированные ячейки удаляются, метрика active-entries остаётся честной.
- Исправлен idle-таймер UDP NAT: обновляется только на доставленных ответах, что не даёт «зависшим» записям продлевать свою жизнь.
- Исправлен HTTP/3: при ошибке коннекта к upstream отправляется WebSocket Close 1013 (паритет с TCP).
- Исправлена валидация конфига: `h3_max_concurrent_uni_streams` должен быть ненулевым.
- Исправлен `outbound_ipv6_interface`: теперь биндится к реально назначенным адресам интерфейса вместо случайного хоста в их /64, поэтому обратный трафик возвращается при обычном SLAAC/DHCPv6 без AnyIP-маршрутов и NDP-прокси. В паре с kernel privacy extensions (`use_tempaddr=2`) даёт ротацию source по соединениям.

## 1.0.2 - 2026-04-12

### Добавлено

- Добавлена настраиваемая строка `realm` для HTTP-аутентификации на корневом пути.
- Добавлен вывод `install.sh --help`.

### Изменено

- Изменён текст `realm` по умолчанию для HTTP-аутентификации на `/`.
- Изменено поведение инсталлятора: сервис больше не запускается автоматически при новой установке.
- Обновление через инсталлятор теперь перезапускает уже активный сервис, когда это уместно.

### Исправлено

- Исправлен разбор URL релизных артефактов и защитная логика в `install.sh`.
- Исправлены сценарии, где `listen` и `h3_listen` используют один и тот же адрес.
- Исправлен сброс nightly-релиза перед публикацией артефактов.
- Исправлен WebSocket-слушатель для HTTP/2 поверх TLS.
- Исправлена обработка HTTP-аутентификации на корневом пути.
- Снижен шум от безобидных TLS EOF в handshake-логах.

## 1.0.1 - 2026-04-09

### Добавлено

- В инсталлятор добавлена поддержка release-каналов и закреплённых версий.
- Добавлена диагностика TCP-handshake для Shadowsocks.

### Изменено

- Переработана раскладка серверных модулей как подготовка к дальнейшему упрощению и повышению надёжности.

### Исправлено

- Исправлены временные ошибки слушателя, из-за которых раньше мог завершаться accept loop.
- Усилена надёжность при приёме Shadowsocks-соединений.

## 1.0.0 - 2026-04-06

Этот релиз суммирует историю проекта от первых коммитов 2026-03-12 до первого стабильного тега.

### Добавлено

- Добавлена исходная production-ориентированная Rust-реализация WebSocket-релея на базе Shadowsocks.
- Добавлена поддержка WebSocket-транспортов поверх HTTP/1.1, HTTP/2 (RFC 8441) и HTTP/3 (RFC 9220).
- Добавлены встроенный TLS для HTTP/1.1 и HTTP/2, а также QUIC/TLS для сценариев с HTTP/3.
- Добавлены многопользовательская маршрутизация, пути на пользователя, выбор шифра на пользователя и поддержка Linux `fwmark`.
- Добавлены метрики Prometheus, мониторинг памяти и готовый дашборд Grafana.
- Добавлены архитектурная документация и русский `README`.
- Добавлена генерация Outline-совместимых ключей доступа, включая раздельную генерацию клиентских конфигов.
- Добавлена поддержка Shadowsocks 2022 и отдельного plain Shadowsocks-слушателя.
- Добавлены регрессионные relay-тесты и кеширование метрик памяти процесса.
- Добавлены musl-алиасы сборки и релизный workflow для кроссплатформенных сборок.

### Изменено

- Листенеры сделаны опциональными, а модель их конфигурации стала явнее.
- Переработаны NAT-таблица и per-session cache, включая дедупликацию создания UDP NAT-записей.
- Добавлены DNS-кеш и несколько оптимизаций в тракте метрик.
- Пересобрана стратегия allocator и диагностики памяти, в итоге проект перешёл с jemalloc на mimalloc.
- Разделена логика library entrypoint и улучшена задержка UDP поверх HTTP/2.
- Улучшена релизная автоматизация, имена артефактов, pinning Zig и установка целевых toolchain.

### Исправлено

- Повышена пропускная способность QUIC и HTTP/3, уменьшены packet drops.
- Исправлена обработка крупных Shadowsocks-пакетов через корректное разбиение.
- Исправлена обработка переполнения stream nonce.
- Убраны лишние аллокации из горячего пути TCP-шифрования и lookup в DNS-кеше.
- Исправлены проблемы линковки allocator-зависимостей и части релизного workflow.
