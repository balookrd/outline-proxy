# Changelog

Все заметные изменения проекта собраны в этом файле.

Этот changelog подготовлен ретроспективно по git-тегам и истории коммитов репозитория. Он фиксирует пользовательские и эксплуатационные изменения, а не перечисляет каждый отдельный коммит.

В репозитории также есть rolling-тег `nightly`, но верхний раздел ниже описывает текущее состояние ветки после последнего теха-релиза, а не изменяемый тег.

---

*English version: [CHANGELOG.md](CHANGELOG.md)*

## [Unreleased] - изменения после `v1.3.1`

### Добавлено

- Per-host диверсификация браузерного фингерпринта для WS / XHTTP dial-путей. WS H1 / H2 / H3 upgrade'ы и XHTTP H1 / H2 / H3 GET / POST теперь могут подмешивать браузерные заголовки идентификации (`User-Agent`, `Accept`, `Accept-Language`, `Accept-Encoding`, семейство Sec-CH-UA и подходящий триплет `Sec-Fetch-{Site,Mode,Dest}` — `mode=websocket,dest=websocket` для WS-upgrade, `mode=cors,dest=empty` для XHTTP), чтобы простое DPI-правило вида «WS-upgrade без User-Agent» или «XHTTP POST без браузерных заголовков» больше не отделяло этот клиент от реального браузерного трафика. В пуле шесть представительных профилей — Chrome 130 (Windows + macOS), Firefox 130 (Windows + macOS), Safari 17 (macOS), Edge 130 (Windows) — подобраны так, чтобы под per-host-stable селектором ~⅔ пиров получили Chromium-идентичность, а оставшаяся ⅓ — Gecko / WebKit, что грубо соответствует реальному browser-share. Выбор детерминирован по `(host, port)` через `DefaultHasher` и фиксируется на всё время жизни процесса, поэтому один пир никогда не видит сессию, разделённую между двумя фингерпринтами. Тумблер opt-in через новый top-level ключ `fingerprint_profile` в конфиге — принимает `"off"` / `"none"` / `"disabled"` (по умолчанию — wire shape байт-в-байт совпадает с pre-knob билдами), `"stable"` / `"per_host_stable"` / `"per-host-stable"` / `"per-host"` (одна идентичность на host:port) или `"random"` (свежий профиль на каждый dial). Строки корректно проходят `serde::Deserialize`, поэтому значение читается прямо из `config.toml`. Bootstrap-бинарь однократно вызывает `init_fingerprint_profile_strategy` при старте, рядом с существующей проводкой `init_downgrade_ttl`; встроенные вызовы (тесты, кастомные бинарники) могут проставить стратегию напрямую через Rust API. Cross-transport заголовки сессионной resumption (`X-Outline-Resume-*`) вставляются независимо от профиля и едут поверх любой активной идентичности. Сознательно НЕ покрыто (отдельная и более дорогая работа): TLS ClientHello / JA3 / JA4 — rustls не даёт настраивать порядок cipher-suites / extensions / supported_groups, поэтому реальная диверсификация TLS требует uTLS-подобного стека (`boring` / BoringSSL); порядок ALPN — сейчас зафиксирован per-carrier, TLS-конфиги кэшируются по списку ALPN; фингерпринт HTTP/2 SETTINGS (Akamai / JA4H2) — принадлежит крейту `h2` и почти закрыт для клиентской подстройки; порядок transport-параметров QUIC — принадлежит `quinn`. Подробности — в `docs/UPLINK-CONFIGURATIONS.ru.md` «Диверсификация браузерного фингерпринта».
- Inline-fallback `stream-one → packet-up` для XHTTP carrier'а и per-host submode-кэш (`xhttp_submode_cache`). Когда dial `?mode=stream-one` падает на `xhttp_h2` / `xhttp_h3` уже после успешного carrier-handshake, dialer ретраит packet-up на **той же** TCP/TLS/h2 (или QUIC/h3) connection — без свежего handshake'а, просто другая форма запроса — и записывает фейл в per-host кэш по ключу destination `(host, port)`. Последующие dial'ы того же хоста заранее пропускают stream-one на `mode_downgrade_secs` и идут сразу в packet-up, не повторяя обречённый handshake на каждом коннекте. Кэш — ортогональный sibling `xhttp_mode_cache`: независимый слот, независимый TTL, независимая декейка, поэтому блок stream-one не понижает cap по h-версии, а h-версионный даунгрейд не обновляет stream-one блок. Снимается раньше срока успешным stream-one dial'ом. Carrier `xhttp_h1` тихо приводит stream-one к packet-up на публичной точке входа `connect_xhttp` (h1 не умеет мультиплексировать streaming GET со streaming POST на одной connection); внутренний h1-драйвер сохраняет защитный `packet-up only` bail для прямых вызовов в обход. Effective submode публикуется в snapshot (`tcp_xhttp_submode` / `udp_xhttp_submode` configured + `tcp_xhttp_submode_block_remaining_ms` / `udp_xhttp_submode_block_remaining_ms`) и рендерится на protocol-pill дашборда — `stream-one` показывается как `/S`, packet-up без суффикса, активный блок — как `/S↘P`, чтобы тихий даунгрейд был виден. Мотивация: middlebox'ы (CDN'ы, корпоративные прокси, idle-timeout мобильных NAT'ов) буферизируют или закрывают streaming POST body, но пропускают короткие POST'ы — stream-one там виснет, packet-up выживает, и кэш превращает per-dial-угадайку в выученную per-host форму.
- Per-host XHTTP downgrade cache (`xhttp_mode_cache`) — sibling существующего WS-only `ws_mode_cache`. Запоминает провалы `xhttp_h3` / `xhttp_h2` по ключу destination `(host, port)`, чтобы последующие dial'ы того же upstream из разных аплинков (например, несколько VLESS-UUID за одним CDN-хостом) пропускали doomed handshake, не ожидая, пока каждый аплинк наполнит своё per-uplink окно. У каждой цепочки свой слот — провал `WsH3` больше не идёт против XHTTP cap'а и наоборот, так что несколько транспортов на один `host:port` декейятся независимо. Шарит knob `mode_downgrade_secs` с WS-кэшем (один knob, два слота) и собирается мусором из того же `gc_shared_connections`. Сбрасывается ранним `record_success` при meets-or-exceeds dial'е — восстановленная reachability `xhttp_h3` сразу снимает cap, чтобы следующий dial реально упражнял h3, а не ждал истечения TTL.
- Per-uplink окно даунгрейда теперь покрывает XHTTP-семейство. Раньше gate открывался только на провалах `WsH3` / `Quic`; теперь он также открывается на провалах `XhttpH3` и `XhttpH2`, поэтому последующие dial'ы пропускают doomed handshake до истечения TTL (по умолчанию 60 с, управляется `mode_downgrade_secs`). Реализация переключает `effective_tcp_mode` / `effective_udp_mode` с хардкоженного возврата `WsH2` на family-aware ceiling, хранящийся в новом поле `PerTransportStatus::mode_downgrade_capped_to` — `WsH3` / `Quic` коллапсируют в `WsH2`, `XhttpH3` — в `XhttpH2`, `XhttpH2` — в `XhttpH1`. Многоступенчатые XHTTP-даунгрейды (`XhttpH3 → XhttpH2 → XhttpH1`) сходятся за несколько dial'ов: каждое наблюдение silent-fallback'а понижает cap на один rank внутри активного окна и никогда не повышает обратно. Cap публикуется через `UplinkSnapshot::tcp_mode_capped_to` / `udp_mode_capped_to`, так что колонки `tcp_mode_effective` / `udp_mode_effective` дашборда теперь показывают реальный carrier, который выберет диспетчер (вместо хардкоженной декорации `ws_h2` / `xhttp_h2`). Защитная логика: триггеры, которые подняли бы режим выше configured (например, шальной `WsH3`-fallback notice на `WsH2`-configured аплинке), или кросс-семейные (XHTTP-провал на WS-аплинке), пропускаются — это сигнал бага в upstream wiring, и они не должны мис-парковать аплинк.
- VLESS-over-XHTTP `xhttp_h1` packet-up carrier и цепочка фолбека `xhttp_h3 → xhttp_h2 → xhttp_h1`. Новый `vless_mode = "xhttp_h1"` напрямую выбирает HTTP/1.1 packet-up; существующие ветки `xhttp_h2` и `xhttp_h3` в `connect_websocket_with_resume` теперь проваливаются в него на провал h2-dial'а (вдобавок к существующему шагу `xhttp_h3 → xhttp_h2`). h1-carrier — фолбек последнего шанса для путей, режущих и QUIC, и ALPN h2; wire-URL остаётся идентичным (`<base>/<session>/<seq>`), поэтому тот же `xhttp_path_vless` listener обслуживает запросы. Так как HTTP/1.1 не умеет мультиплексировать стримящийся GET с одновременными POST'ами на одной connection, драйвер открывает **два** keep-alive сокета на сессию: один — под долгоживущий downlink GET (chunked response), второй — под строго сериализованные uplink POST'ы (без pipelining'а — слишком ненадёжно через CDN/proxy промежутки). Throughput ограничен round-trip-временем одного POST'а и ожидаемо заметно отстаёт от h2 под нагрузкой. Тот же `X-Outline-Resume` токен прокидывается через каждую смену carrier'а, поэтому припаркованный VLESS upstream переподключается через всю цепочку. Stream-one на h1 сознательно не реализован — `?mode=stream-one` в паре с `vless_mode = xhttp_h1` (или цепочка, упавшая до h1) отваливается на dial'е. VLESS share-link URI принимают `alpn=h1` / `alpn=http/1.1` для прямого пина h1-carrier'а. CLI / TOML / control-plane payload принимают `xhttp_h1` везде, где принимают `xhttp_h2` / `xhttp_h3`.
- Клиент VLESS-over-XHTTP packet-up. Доступны два режима:
  - `vless_mode = "xhttp_h2"` — XHTTP едет по одному shared TCP+TLS+h2 соединению на сессию.
  - `vless_mode = "xhttp_h3"` — XHTTP едет по QUIC + HTTP/3 (за feature-флагом `h3`, в дефолтном профиле включён). Парный листенер — тот же `xhttp_path_vless` в outline-ss-rust, доступный на QUIC-эндпоинте по ALPN `h3`.

  В обоих режимах на сессию генерируется случайный id и используется для обоих половин: driver открывает один long-lived GET (downlink) и пайплайнит POST'ы (uplink) с `X-Xhttp-Seq`. XHTTP-carrier выставлен через тот же `TransportStream` enum, что и WS-варианты, поэтому встраивается в текущий dial dispatch и в TUN / SOCKS-конвейеры без правок наверху. Новое поле uplink-конфига `vless_xhttp_url` несёт базовый URL — обязательно, когда `vless_mode` — один из `xhttp_*`. Полезен, когда WebSocket-апгрейд режется на сети (Cloudflare-style CDN, captive-portal middleboxes).

  Поверх того же dial path работают три дополнительные возможности:
    1. **Fallback `xhttp_h3 → xhttp_h2`.** При провале QUIC + HTTP/3 dial'а (handshake timeout, ALPN mismatch, заблокированный UDP) dispatcher прозрачно повторяет через h2, неся тот же `resume_request`, открывает существующее `mode-downgrade` окно — следующие dial'ы пропускают h3 до восстановления — и сообщает изначальный режим через `TransportStream::downgraded_from()` для записи в uplink-manager.
    2. **Cross-transport resumption** через XHTTP carrier. Dial рекламирует `X-Outline-Resume-Capable: 1` и (если есть) `X-Outline-Resume: <hex>`, синхронно ждёт response headers — токен `X-Outline-Session`, выданный сервером, забирается до старта drain'а. Токен ложится в существующий `ResumeCache` ровно как у WS-пути, поэтому припаркованный VLESS upstream переподключается через XHTTP reconnect — в том числе при смене carrier'а (h3-провалился-h2 несёт тот же токен end-to-end).
    3. **Stream-one carrier** выбирается чисто из URL-а dial'а. Прописываешь `?mode=stream-one` в `vless_xhttp_url` — и пара GET+POST заменяется на один bidirectional POST: request body несёт uplink, response body несёт downlink. Никакого нового конфиг-поля, никакого нового mode-варианта — `XhttpSubmode::from_url(&Url)` читает query во время dial'а и роутит на нужный driver. На h3 stream разделяется через `RequestStream::split` — uplink и downlink половинки на отдельных tasks. Packet-up driver остаётся по умолчанию для URL'ов без query (или с `?mode=packet-up`).
- VLESS share-link URI стали полноценной формой конфига. Одна строка `link = "vless://UUID@HOST:PORT?type=ws|xhttp|quic&...#NAME"` в `[[outline.uplinks]]` (или в top-level / inline `[outline]`) на этапе загрузки разворачивается в тройку `vless_id` / `vless_*_url` / `vless_mode`; `transport = "vless"` подставляется автоматически. Поддержанные query-параметры: `type` (`ws` / `xhttp` / `quic`), `security` (`none` / `tls` / `reality`), `path`, `alpn` (выбирает H1/H2/H3 вариант режима), `mode` (`packet-up` / `stream-one`, пробрасывается в XHTTP dial-URL), `encryption=none`. `flow=...`, `type=tcp|grpc|h2`, расходящиеся `sni=` / `host=` и любой `encryption`, кроме `none`, отклоняются. То же поле принимает CLI-флаг `--vless-link <URI>` (`OUTLINE_VLESS_LINK`) и REST-эндпойнты `/control/uplinks` (`link`, алиас `share_link`). См. docs/UPLINK-CONFIGURATIONS.ru.md «VLESS share-link URIs».

### Изменено

- **Ломающее переименование в конфиге / CLI / API.** Поля «режим транспорта» теперь везде называются `tcp_mode` / `udp_mode` / `vless_mode` — TOML (`tcp_mode = "h2"`), CLI (`--tcp-mode`, `--udp-mode`, `--vless-mode`), переменные окружения (`OUTLINE_TCP_MODE`, `OUTLINE_UDP_MODE`, `OUTLINE_VLESS_MODE`), JSON control-плана (`/control/topology`, `/control/uplinks`), payload дашборда и Rust API (`UplinkConfig::tcp_mode`, `effective_tcp_mode()`). Старые `*_ws_mode` имена удалены без алиасов — существующие TOML-файлы и скрипты придётся обновить вручную. Причина: после появления `xhttp_h2` / `xhttp_h3` / `quic`, которые уже не привязаны к WebSocket, инфикс `_ws_` стал вводить в заблуждение.
- Панель дашборда теперь корректно рисует даунгрейд `xhttp_h3` → `xhttp_h2` (раньше H3/QUIC-индикация срабатывала только на старых коротких именах режимов, и xhttp-аплинки визуально «зависали» на сконфигурированном режиме). VLESS-аплинки также публикуют `tcp_mode` / `udp_mode` для `xhttp_h2` / `xhttp_h3` — раньше поле выставлялось только при наличии `vless_ws_url`, поэтому чисто-XHTTP аплинк отображался дефолтным «VLESS/WS/H1».
- `outline_transport::install_test_tls_root(CertificateDer)` — тест-only ручка, пинающая кастомный самоподписанный root для XHTTP h2 / h3 dial-путей. Override-слот это `RwLock<Option<…>>` с дефолтом `None`, так что продакшен-вызывающие (которые её не трогают) сохраняют webpki-поведение с одним лишним чтением на dial. Целевой потребитель — cross-repo e2e-тест в `outline-ss-rust`, который поднимает in-process самоподписанный сервер и дёргает его через обычный `connect_websocket_with_resume`.
- Тест-обход для процесс-вайдных кэшей QUIC-эндпоинтов. Когда выставлен тестовый override (т.е. `install_test_tls_root` был вызван), `H3_CLIENT_ENDPOINT_V4` / `_V6` и raw-QUIC `QUIC_CLIENT_ENDPOINT_V4` / `_V6` пропускают кэш и биндят свежий endpoint на каждый dial. Каждый `#[tokio::test]` крутится в своём runtime; driver-task закэшированного endpoint'а привязан к runtime, который первым попал в кэш, и умирает сразу как только тот тест завершается — следующий тест получает `endpoint driver future was dropped`. Продакшен-поведение не меняется.

### Исправлено

- WebSocket-over-h2 диалер слал `:path = //{ws_path}` потому что `H2Dialer::open_on` форматировал `target_uri` как `format!("{scheme}://{auth}/{path}")`, а `websocket_path` уже возвращает ведущий `/`. Серверные axum-роутеры отвергают двойной слэш с 404, что годами маскировалось h1-фолбэком в WS-h2 диспетчере (tungstenite нормализует слэш по дороге на провод). h2-путь теперь конкатенирует без повторного `/`. Виден только на h2-only серверах (RFC 8441 стеки без h1) и всплыл благодаря cross-repo h3→h2 fallback тесту в `outline-ss-rust`.
- XHTTP h3 stream-one закрывал QUIC-соединение с `H3_NO_ERROR` ещё до того, как через него пройдёт хоть один прикладной байт: единственный `SendRequest` уезжал в `open_h3_stream_one`, дропался на return, а `SendRequest::drop` в крейте h3 делает graceful-close, как только `sender_count` падает в ноль. Зеркалит паттерн packet-up — клонируем перед open-хелпером, оригинал держим живым в driver-task'е. Тот же коммит переносит quinn `Endpoint` в driver-task (прежний `let _endpoint_guard = endpoint;` держал его живым только в скоупе функции, не на время сессии).
- Редактор аплинков в дашборде теперь отдаёт всю XHTTP-тройку (`vless_xhttp_url`, `vless_mode`, `vless_id`), так что XHTTP-аплинки можно создавать и редактировать из UI без 400 «unknown field».
- Пробы и refill standby для VLESS теперь идут через тот же хелпер `vless_dial_url()`, что и live data path, — пробы, выбирающие XHTTP carrier, больше не сваливаются на `vless_ws_url`, когда настроен только `vless_xhttp_url`.
- XHTTP packet-up uplink теперь кладёт per-packet `seq` в URL path (`<base>/<session>/<seq>`), а не в заголовок `X-Xhttp-Seq`. Это `PlacementPath` по умолчанию у xray / sing-box — wire-формат, который шлёт любой другой VLESS-XHTTP клиент в природе. Header-форма была частной конвенцией, общей только с `outline-ss-rust`, и из-за неё сторонние клиенты (`happ`, `hiddify`, `v2rayN`) бесконечно таймаутили на любом маскираде, который фронтит и наш клиент, и обычный xray-инжес: их POST'ы на `<base>/<session>/<seq>` отдавали тихий 404, а наши шли на `<base>/<session>` + header, и наблюдатель на пути мог отличить наши потоки от ванильных xray по одному только URL'у. h2 и h3 carrier'ы теперь шлют одинаковую path-форму — wire идентичен ванильному xray, без лишнего заголовка, без лишнего TLS-роундтрипа. Совместимость на сервере: `outline-ss-rust v1.4.0+` принимает обе формы (path-based выигрывает, если присланы обе), так что этот клиент против любого нового сервера работает; старые серверы (`v1.3.1` и ниже) принимают только header-форму и должны быть подняты вместе с клиентом.

## [1.3.1] - 2026-04-29

### Исправлено

- Per-host окно даунгрейда `ws_mode_cache` теперь сбрасывается при успешном dial'е изначально запрошенного режима, а дефолтный TTL короче — восстановившийся H3/QUIC путь снова идёт в работу сразу, как только становится доступен, а не остаётся залипшим на старое длинное окно.

### Изменено

- Внутренний clean-up: Rust-идентификаторы и метрические лейблы `h3_downgrade_*` переименованы в `mode_downgrade_*` под унифицированную H3 + raw-QUIC семантику, появившуюся в v1.3.0 (TOML / CLI ключ принимает `mode_downgrade_secs` уже с v1.3.0; алиас `h3_downgrade_secs` сохраняется). `utils.rs` крейта `outline-uplink` разнесён на per-domain модули; `error_text.rs` переименован в `error_classify.rs`; тесты переразложены под канонический layout `<dir>/tests/<basename>.rs`. Без изменений в публичном конфиге и API.

## [1.3.0] - 2026-04-28

### Добавлено

- Raw QUIC транспорт (`*_ws_mode = "quic"`): VLESS / Shadowsocks-кадры прямо поверх QUIC bidi-стримов и датаграмм (RFC 9221), без WebSocket и без HTTP/3. ALPN per-connection выбирает протокол (`vless`, `ss`, `h3`); парный листенер — в outline-ss-rust. Несколько сессий с одинаковым ALPN на тот же `host:port` шарят один кэшированный QUIC-коннект. VLESS-UDP использует per-target control bidi (сервер выдаёт 4-байтный `session_id`) и connection-level demux датаграмм; SS-UDP едет в QUIC-датаграммах 1-к-1 c SS-AEAD пакетами. URL для дайла переиспользуется как QUIC dial target — берётся только `host:port`, путь игнорируется.
- Raw-QUIC oversize stream-fallback. Новые ALPN `vless-mtu` / `ss-mtu` несут UDP-датаграммы, превысившие лимит QUIC-датаграммы, поверх server-initiated bidi (`accept_bi`), чтобы патологически большие UDP-пакеты по-прежнему ехали по raw-QUIC, а не молча дропались. Стартовый QUIC `initial_mtu` поднят до 1400, чтобы типичный UDP-трафик оставался на быстром пути датаграмм.
- Fallback raw-QUIC при дайле. На отказ dial / handshake raw-QUIC теперь падает на WS over H2 (с дальнейшим H1) и открывает единое окно mode-downgrade — следующие дайлы пропускают QUIC, пока recovery-проба не подтвердит, что QUIC снова доступен. Покрытие: VLESS-TCP, VLESS-UDP, SS-TCP, SS-UDP. Заменяет прежнее поведение "no fallback by design".
- VLESS-UDP hybrid mux: оборачивает raw-QUIC mux в тонкий конверт, который при первом провале дайла переключается на WS over H2, вызывает `note_advanced_mode_dial_failure` (открывает cooldown) и проксирует входящие датаграммы из активного inner mux. Залипший флаг `quic_succeeded_once` не даёт схлопнуться в WS, если QUIC-сессия уже успешно установилась — рантайм-ошибки на работающей QUIC-сессии по-прежнему пробрасываются как обычный сбой.
- Возобновление сессии между транспортами — клиентская сторона, end-to-end, по **всем** транспортам и режимам аплинков:
  - TCP over WebSocket (HTTP/1.1, HTTP/2, HTTP/3): запросы WebSocket Upgrade несут `X-Outline-Resume-Capable: 1`; сервер возвращает Session ID в `X-Outline-Session`, клиент кладёт его в process-wide `ResumeCache` по имени аплинка. На следующем on-demand TCP-WebSocket dial (`connect_tcp_ws_fresh` — fresh dial, пул пуст) кэшированный ID отправляется как `X-Outline-Resume: <hex>`, чтобы сервер переcадил клиента на припаркованный upstream и пропустил connect к таргету.
  - SS-UDP-WS: тот же набор заголовков на on-demand UDP-WebSocket dial'ах, ключ — имя аплинка в том же `ResumeCache`.
  - VLESS-TCP over raw QUIC: resume-токены передаются через VLESS Addons opcodes на connect-bidi (без HTTP-заголовков на QUIC-пути).
  - VLESS-UDP-WS / VLESS-UDP-QUIC: каждая per-target сессия внутри `VlessUdpSessionMux` несёт свой Session ID (`HashMap<TargetAddr, SessionId>` на mux), так что mux, фанящий к N таргетам, может возобновить N припаркованных upstream'ов независимо.
  - Refill warm-standby-пула остаётся обезличенным — пуловые коннекты не идентифицируются, resume-токен несут только acquire-on-demand dial'ы.
  - Resume opt-in на проводе (серверы без фичи игнорируют заголовки / опкоды) и без overhead'а при отключённом. Формат — `docs/SESSION-RESUMPTION.md` в outline-ss-rust.
- Улучшения встроенного дашборда: per-instance топология теперь грузится асинхронно и обновляется независимо; состояние свёрнутых панелей сохраняется в `localStorage`, переживая refresh; причины переключения аплинков выводятся inline; колонки encapsulation + transport stack показывают активный H3/QUIC auto-downgrade с одного взгляда; редактор аплинков отдаёт `vless_ws_url` / `vless_ws_mode`, чтобы VLESS-аплинки можно было создавать и редактировать из UI; страница uplinks дашборда теперь работает с канонической схемой `[[outline.uplinks]]` для CRUD.
- Глобальный failover теперь учитывает UDP probe / runtime health на UDP-capable активных аплинках: чисто-UDP сбой может триггернуть глобальный failover, даже если TCP score выглядит нормально.
- `tcp_ws_mode` / `udp_ws_mode` / `vless_ws_mode` теперь принимают `h1` как алиас к `http1` — и в TOML-конфиге, и в парсинге CLI / env-vars, в одном ряду с короткими `h2` / `h3` / `quic`.

### Изменено

- **Ломающее изменение конфига для `transport = "vless"`.** Сервер VLESS открывает один WS-путь (`ws_path_vless`), общий для TCP и UDP, поэтому в клиентском конфиге теперь задаётся одна пара `vless_ws_url` / `vless_ws_mode` вместо дублирующихся `tcp_ws_url`+`udp_ws_url` / `tcp_ws_mode`+`udp_ws_mode`. Старые поля отвергаются явной ошибкой парсинга при `transport = "vless"`. CLI: новые `--vless-ws-url` / `--vless-ws-mode` (`OUTLINE_VLESS_WS_URL` / `OUTLINE_VLESS_WS_MODE`). Миграция: замените
  ```toml
  tcp_ws_url = "wss://host/path"
  udp_ws_url = "wss://host/path"
  tcp_ws_mode = "h2"
  udp_ws_mode = "h2"
  ```
  на
  ```toml
  vless_ws_url = "wss://host/path"
  vless_ws_mode = "h2"
  ```
  Без alias / silent fallback; `transport = "ws"` и `transport = "shadowsocks"` не затронуты.
- `h3_downgrade_secs` (принимается также как `mode_downgrade_secs`) теперь управляет окном даунгрейда и для H3, и для raw-QUIC на аплинках `transport = "ws"` и `transport = "vless"`. И ошибка приложения H3, и провал dial / handshake raw-QUIC открывают одно и то же per-uplink окно; следующие дайлы любого продвинутого режима откладываются на WS-over-H2 до истечения таймера.
- Ручное переключение аплинков (`POST /switch`, `POST /control/activate`, клик в дашборде) больше не откатывается на первом рантайм-сбое; выбранный аплинк остаётся запиненным, а рантайм-ошибки эскалируются через стандартный классификатор, а не молча возвращаются к предыдущему выбору. Все счётчики метрик сбрасываются на manual switch — свежезапиненный аплинк стартует с чистым окном здоровья.
- `weight` теперь **жёсткий** сигнал приоритета в `primary_order` и `failover_order`, а не мягкая подсказка, размазанная по latency-скору. Среди здоровых кандидатов всегда выигрывает максимальный `weight`; EWMA-скор ранжирует только внутри одного weight-уровня. Раньше намеренно занижённый резерв с достаточно быстрым probe RTT мог обогнать аплинк с большим `weight` — формула `(EWMA + штраф) / weight` позволяла большому разрыву по RTT переписать вес. Failover и active-active-выбор теперь работают так же, как уже работающие `initial_strict_order` и `auto_failback`, где weight всегда был строгим приоритетом.
- Hot path VLESS UDP session-mux переехал с `tokio::Mutex` на `parking_lot::RwLock` с атомарным `last_use`; per-destination dial — single-flight через `OnceCell`, чтобы не получалось stampede, когда сразу много flow'ов идут к одному дестинейшну.
- Routing fast path пропускает per-packet `has_any_healthy`, если ни одно правило не задаёт fallback-таргет.
- Refill standby полностью пропускает поиск в TCP-пуле, если эффективный режим dial — raw QUIC (где per-connection пула нет).
- Внутренний clean-up: `tcp/connect` шарит общий SS target-header send между путями; flow-таблица `tun/tcp` переехала в `DashMap` с отдельным `FlowScheduler`; H2/H3 dial-скелет унифицирован за одной associated-type-чертой `WsDialer`; route TCP/UDP fallback использует общий `apply_fallback_strategy`.

### Исправлено

- Дашборд: per-instance hyper connection driver теперь аборитится при завершении proxy task — закрывает протечку control-API сокета, копившуюся при churn инстансов.
- Raw QUIC: разорван цикл Arc в `VlessUdpDemuxer`, удерживавший probe-driven QUIC-коннекты живыми после завершения пробы; пробы больше не пинят коннекты дольше их естественной жизни.
- TUN: дайлы raw-QUIC TCP, инициированные из TUN-flow, теперь так же падают на WS over H2, как и со стороны SOCKS5; до этого provision raw-QUIC из TUN сразу убивал flow.
- TUN/transport: закрыт VLESS UDP socket leak, проявлявшийся как растущий FD count под нагрузкой — добавлены `AbortOnDrop` на per-target session task и строгий WS pong deadline.
- TCP failover: deferred phase-1 failures сохраняют исходную error-цепочку — реальная причина (например, ошибка TLS handshake внутри открытия H2-стрима) больше не глотается обёрткой "phase-1 failed".
- VLESS probes: HTTP / TCP-tunnel пробы больше не предпендят SOCKS5 target prefix к payload'у пробы; DNS-проба и WS-handshake-проба обе диспатчатся через raw-QUIC путь, если у аплинка `vless_ws_mode = "quic"`.
- Routing engine: build-зависимости `outline-routing::compile_routing_table` подтянуты — хелпер собирается с `tokio` rt/time только как dev-deps.

## [1.2.0] - 2026-04-24

### Добавлено

- VLESS-over-WebSocket аплинки (`transport = "vless"`). Аутентификация — одно поле `vless_id` (UUID) вместо Shadowsocks cipher / password; общая WSS dial-инфраструктура с `transport = "ws"`. VLESS UDP едет per-destination session-mux'ом (одна WSS-сессия на target внутри аплинка), ограниченным `vless_udp_max_sessions`, idle-evict через `vless_udp_session_idle_secs`, с настраиваемой каденцией LRU-evictor'а (`vless_udp_janitor_interval_secs`). Подключена реальная VLESS DNS data-path проба наряду с уже существующими WS / HTTP пробами.
- Встроенный multi-instance дашборд по адресу `/dashboard`, под Cargo-фичей `dashboard`. Процесс дашборда хранит per-instance control-токены на серверной стороне и проксирует `/control/topology` и `/control/activate` к каждому инстансу. Поддерживаются `http://` и `https://` control endpoints, сохраняется URL-префикс для инстансов за reverse proxy, есть настраиваемый `dashboard.request_timeout_secs`. UI инстанс-центричный, с панелью настроек балансировки по группам, тематизированным sidebar'ом с тёмной палитрой по умолчанию и рантайм-переключателем light/dark (браузерный `theme-color` следует за активной темой), и отдельной страницей конфигурации аплинков, выполняющей CRUD через `POST /control/uplinks` + `POST /control/apply` (hot-swap). (Прежний прототип Grafana-дашборда control plane снят с поставки в пользу in-process UI.)
- Независимая HTTP control plane. Мутирующие эндпоинты (`/switch`, `/control/topology`, `/control/summary`, `/control/activate`, `/control/uplinks`, `/control/apply`) живут на отдельном listener'е, защищены обязательной bearer-аутентификацией и отдельной Cargo-фичей; `/metrics` сохраняет read-only роль.
- `POST /switch` для ручного переключения активного аплинка, плюс `POST /control/activate` (JSON body) для click-пути дашборда.
- В правилах `[[route]]` кроме `file` теперь принимается список `files = [..., ...]`; все пути мерджатся в CIDR-набор правила, и за каждым отдельно следит hot-reload. Удобно, когда IPv4 и IPv6 GeoIP-фиды лежат в разных файлах.
- Ограничение числа соединений через семафор на SOCKS5 accept-loop и на HTTP-listener'ах — чтобы защищать процесс при всплесках подключений.
- Graceful shutdown для фоновых циклов управления аплинками; in-flight соединения отменяются на SIGTERM, рестарт поднимается быстрее.
- Расширена диагностика: в `session_death` теперь попадает адрес цели, транспортные read-диагностики прокинуты в TUN и TCP probe paths, а HTTP-эндпоинты control/metrics получили счётчики запросов.
- В userspace-стек TUN добавлены TCP keepalive-пробы, чтобы обнаруживать мёртвых пиров вместо зависших established-сессий.
- WebSocket Close-код `1013` (`Try Again Later`) теперь считается retryable-сигналом, наравне с TCP RST.
- Продолжено разделение на workspace-crates: вынесены отдельные crate'ы для transport, uplink management, TUN, routing, metrics, Shadowsocks crypto и SOCKS5 primitives. `outline-transport` дополнительно разнесён на `outline-net` + `outline-ss2022`.
- CLI-флаг `--migrate-config` для one-shot in-place миграции legacy top-level uplink-ключей в каноническую форму `[outline]`; обычный путь старта тоже авто-мигрирует с deprecation-предупреждением.

### Изменено

- TOML — единственный поддерживаемый формат конфигурации; YAML-loader и примерные YAML-файлы удалены.
- Переработаны внутренности configuration, bootstrap, proxy, UDP, metrics и TUN под workspace-структуру и более мелкие сфокусированные модули.
- Снижены накладные расходы hot path за счёт менее аллокационного DNS cache, boxed AEAD-вариантов, более точечных блокировок статусов аплинков, неблокирующего `AsyncFd` для TUN, меньшего heap churn в UDP/TCP путях, UDP send без мьютекса, SACK scoreboard без клонирования на каждый ACK, выноса sticky-route pruning с connect hot path, коалесинга `/metrics` scrape'ов и lock-free чтения standby-пула.
- WebSocket read idle timeout поднят со 120s до 300s, чтобы длинные периоды без ответа (например, пока модель «думает») не выбивали здоровые сессии.
- Ограничена конкурентность HTTP control/metrics-плоскостей и добавлены bounds на SOCKS5 handshake — чтобы уменьшить DoS surface.
- systemd unit переведён с `DynamicUser=true` на фиксированного системного пользователя `outline-ws`, чтобы state-файлы сохраняли стабильного владельца между рестартами; install-скрипт теперь создаёт пользователя и writable state-каталог.
- Внутренние зависимости переведены на прямое использование workspace-crates вместо фасадов и алиасов корневого crate.

### Устарело

- Плоская форма конфига аплинков (top-level `tcp_ws_url` / `[probe]` / `[[uplinks]]` / `[load_balancing]`) признана устаревшей; каноническая форма теперь вложена под `[outline]` (`[[outline.uplinks]]`, `[outline.probe]`, `[outline.load_balancing]`). Старая форма по-прежнему принимается, авто-мигрируется на старте и логирует deprecation-предупреждение. Примеры конфигов и README обновлены под новую форму.

### Исправлено

- Рендеринг Prometheus сериализован, чтобы избежать гонок при одновременных scrape'ах.
- Валидация конфигурации теперь завершается ошибкой сразу, если настройки metrics или control используются без соответствующих Cargo-фич.
- Предотвращён hijacking адреса SOCKS5 UDP-клиента, а кэшированные UDP route decisions теперь корректно реагируют на изменение здоровья аплинков.
- Исправлены проблемы жизненного цикла вокруг сборки мусора shared H2/H3 connections, персистентности active-uplink state, «тихо» отвалившихся за NAT аплинков и feature-gated тестов.
- TCP idle watcher теперь обновляется на keepalive-трафике, так что keepalive-only сессии больше не выселяются как idle.
- Phase-1 выбор аплинка больше не штрафует аплинк, если недоступна сама цель.
- Исправлены подписи чипов load-balancing в дашборде — теперь они соответствуют реальным вариантам enum'а балансировки.
- Исправлен учёт keepalive в SOCKS idle-таймауте: keepalive-трафик корректно отодвигает выселение сессии по idle на стороне SOCKS.
- Загрузка конфигурации теперь корректно фолбэчит в read-only режим, когда целевой каталог недоступен на запись (например, `/etc/` под `ProtectSystem=strict`); в лог идёт предупреждение, процесс продолжает работу без персистентности.

## [1.1.0] - 2026-04-17

### Добавлено

- Добавлен policy routing с секциями `uplink_group` и `[[route]]`, hot-reload для CIDR-backed rule lists, маршрутизация в `direct` и флаг `invert` для правил.
- Добавлена поддержка YAML-конфигов и примерные YAML-файлы.
- Добавлена персистентность выбранного активного аплинка между рестартами.
- Добавлена поддержка `hev-socks5` UDP-in-TCP.
- Добавлены group-aware UDP routing, маршрутизация TUN через policy-selected groups, `direct_fwmark` и group labels в метриках и Grafana dashboards.
- Поддержка TUN и `mimalloc` оформлена как полноценные build features для серверного профиля по умолчанию.

### Изменено

- Переиспользование shared HTTP/2 и HTTP/3 uplink connections уменьшило churn переподключений и улучшило поведение в steady state.
- Усилены keepalive, probing, warm-standby и timeout-механики для WebSocket, H2 и H3 transport'ов.
- Улучшены installers и deployment docs: безопаснее первая установка, появились version-aware updates и более актуальные примеры.
- Выполнен крупный внутренний рефакторинг transport, config, proxy и test layout с разбиением на меньшие модули.

### Исправлено

- Снижено количество ложных chunk-0 failover и повторного использования устаревших standby-соединений.
- Исправлены несколько сценариев socket leak и half-closed sessions в probe paths, direct TCP, shared H2/H3 connections и при завершении SOCKS TCP sessions.
- Исправлены обработка H3 shutdown, запросы в dashboards, edge cases начальной инициализации state file и ряд проблем routing/dispatch, найденных во время review.

## [1.0.2] - 2026-04-09

### Добавлено

- Добавлена обработка chunk-0 failover для ранних сбоев TCP-туннеля.
- Добавлена поддержка `probe.tcp` для health-check'ов speak-first TCP-сервисов.
- Добавлена более подробная диагностика проб и лучшее определение причин сбоев при установлении transport-соединений.

### Изменено

- Уточнён tie-breaking в failover-логике: состояние cooldown теперь сохраняется, пока upstream реально не восстановится.
- Код transport, uplink и `tun_tcp` переразбит на более мелкие подмодули.
- Install scripts, Keenetic installer и документация приведены в соответствие с актуальным release pipeline.

### Исправлено

- Восстановлено корректное поведение SOCKS failover и probe paths после регрессионных правок.
- Исправлены проблемы в TCP relay и диагностике проб.
- Исправлены проблемы совместимости `jq` в Keenetic installer.
- Стабилизировано покрытие standby validation tests и сохранена консистентность использования DNS cache по стеку.

## [1.0.1] - 2026-04-07

### Добавлено

- Добавлены per-connection debug-логи по uplink/downlink chunks для диагностики transport-поведения.

### Исправлено

- Исправлена обработка SS2022: пустой initial payload в response header больше не считается EOF.

## [1.0.0] - 2026-04-06

### Добавлено

- Первый подписанный стабильный релиз Rust-прокси для локального SOCKS5-трафика поверх Outline-совместимых WebSocket transport'ов и прямых Shadowsocks uplink'ов.
- Добавлены HTTP/1.1 Upgrade, WebSocket over HTTP/2 (RFC 8441) и WebSocket over HTTP/3 (RFC 9220) с fallback между transport-режимами.
- Добавлены failover и балансировка между несколькими аплинками с health probes, sticky routing, warm standby, runtime cooldown и флагом `auto_failback`.
- Добавлены SOCKS5 username/password auth, прямые Shadowsocks socket uplink'и, поддержка Shadowsocks 2022, optional listeners и IPv6-first dial.
- Добавлены Prometheus-метрики, Grafana dashboards и эксплуатационная документация.
- Добавлена интеграция с существующим TUN-устройством: `tun2udp`, сборка IP-фрагментов, обработка ICMP и production-oriented stateful `tun2tcp` relay с валидацией и механизмами восстановления потерь.
- Добавлены router-oriented build options, инструкции по cross-compilation, nightly/stable release workflows, versioned release artifacts и пути сборки legacy MIPS-релизов.

### Изменено

- Настроены memory allocation и transport-параметры для меньшей UDP-задержки и более практичных router-сборок.
- Улучшены startup, configuration loading, metrics serving и transport internals по мере перехода проекта от прототипа к первому стабильному релизу.

### Исправлено

- Исправлены ранние проблемы с metrics, dashboards, buffer flushing, memory monitoring, H3/QUIC fallback, UDP cleanup и конфигурацией listeners.
- Снижено число ложных runtime-failure срабатываний при idle UDP cleanup и в устаревших standby TCP paths.
- Повышена надёжность crypto, proxy, transport, обработки FD exhaustion и упаковки router-деплоя.
