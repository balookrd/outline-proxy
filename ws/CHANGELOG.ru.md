# Changelog

Все заметные изменения проекта собраны в этом файле.

Этот changelog подготовлен ретроспективно по git-тегам и истории коммитов репозитория. Он фиксирует пользовательские и эксплуатационные изменения, а не перечисляет каждый отдельный коммит.

В репозитории также есть rolling-тег `nightly`, но верхний раздел ниже описывает текущее состояние ветки после `v1.2.0`, а не изменяемый тег.

---

*English version: [CHANGELOG.md](CHANGELOG.md)*

## [Unreleased] - изменения после `v1.2.0` (по состоянию на 2026-04-28)

### Изменено

- **Ломающее переименование в конфиге / CLI / API.** Поля «режим транспорта на направление» теперь везде называются `tcp_mode` / `udp_mode` — TOML (`tcp_mode = "h2"`), CLI (`--tcp-mode`, `--udp-mode`), переменные окружения (`OUTLINE_TCP_MODE`, `OUTLINE_UDP_MODE`), JSON control-плана (`/control/topology`, `/control/uplinks`), payload дашборда и Rust API (`UplinkConfig::tcp_mode`, `effective_tcp_mode()`). Старые имена удалены без алиасов — существующие TOML-файлы и скрипты придётся обновить вручную. Причина: после появления `xhttp_h2` / `xhttp_h3` / `quic`, которые уже не привязаны к WebSocket, инфикс `_ws_` в имени стал вводить в заблуждение.
- Панель дашборда теперь корректно рисует даунгрейд `xhttp_h3` → `xhttp_h2` (раньше H3/QUIC-индикация срабатывала только на старых коротких именах режимов, и xhttp-аплинки визуально «зависали» на сконфигурированном режиме).
- Фикс снапшота: VLESS-аплинки теперь публикуют `tcp_mode` / `udp_mode` и для `xhttp_h2` / `xhttp_h3`. Раньше поле выставлялось только при наличии `vless_ws_url`, поэтому чисто-XHTTP аплинк отображался на дашборде дефолтным «VLESS/WS/H1».

### Добавлено

- VLESS share-link URI стали полноценной формой конфига. Одна строка `link = "vless://UUID@HOST:PORT?type=ws|xhttp|quic&...#NAME"` в `[[outline.uplinks]]` (или в top-level / inline `[outline]`) на этапе загрузки разворачивается в тройку `vless_id` / `vless_*_url` / `vless_mode`; `transport = "vless"` подставляется автоматически. Поддержанные query-параметры: `type` (`ws` / `xhttp` / `quic`), `security` (`none` / `tls` / `reality`), `path`, `alpn` (выбирает H1/H2/H3 вариант режима), `mode` (`packet-up` / `stream-one`, пробрасывается в XHTTP dial-URL), `encryption=none`. `flow=...`, `type=tcp|grpc|h2`, расходящиеся `sni=` / `host=` и любой `encryption`, кроме `none`, отклоняются. То же поле принимает CLI-флаг `--vless-link <URI>` (`OUTLINE_VLESS_LINK`) и REST-эндпойнты `/control/uplinks` (`link`, алиас `share_link`). См. docs/UPLINK-CONFIGURATIONS.ru.md «VLESS share-link URIs».
- Клиент VLESS-over-XHTTP packet-up. Доступны два режима:
  - `vless_mode = "xhttp_h2"` — XHTTP едет по одному shared TCP+TLS+h2 соединению на сессию.
  - `vless_mode = "xhttp_h3"` — XHTTP едет по QUIC + HTTP/3 (за feature-флагом `h3`, в дефолтном профиле включён). Парный листенер — тот же `xhttp_path_vless` в outline-ss-rust, доступный на QUIC-эндпоинте по ALPN `h3`.

  В обоих режимах на сессию генерируется случайный id и используется для обоих половин: driver открывает один long-lived GET (downlink) и пайплайнит POST'ы (uplink) с `X-Xhttp-Seq`. XHTTP-carrier выставлен через тот же `TransportStream` enum, что и WS-варианты, поэтому встраивается в текущий dial dispatch и в TUN / SOCKS-конвейеры без правок наверху. Новое поле uplink-конфига `vless_xhttp_url` несёт базовый URL — обязательно, когда `vless_mode` — один из `xhttp_*`. Полезен, когда WebSocket-апгрейд режется на сети (Cloudflare-style CDN, captive-portal middleboxes).

  Поверх того же dial path работают три дополнительные возможности:
    1. **Fallback `xhttp_h3 → xhttp_h2`.** При провале QUIC + HTTP/3 dial'а (handshake timeout, ALPN mismatch, заблокированный UDP) dispatcher прозрачно повторяет через h2, неся тот же `resume_request`, открывает существующее `mode-downgrade` окно — следующие dial'ы пропускают h3 до восстановления — и сообщает изначальный режим через `TransportStream::downgraded_from()` для записи в uplink-manager.
    2. **Cross-transport resumption** через XHTTP carrier. Dial рекламирует `X-Outline-Resume-Capable: 1` и (если есть) `X-Outline-Resume: <hex>`, синхронно ждёт response headers — токен `X-Outline-Session`, выданный сервером, забирается до старта drain'а. Токен ложится в существующий `ResumeCache` ровно как у WS-пути, поэтому припаркованный VLESS upstream переподключается через XHTTP reconnect — в том числе при смене carrier'а (h3-провалился-h2 несёт тот же токен end-to-end).
    3. **Stream-one carrier** выбирается чисто из URL-а dial'а. Прописываешь `?mode=stream-one` в `vless_xhttp_url` — и пара GET+POST заменяется на один bidirectional POST: request body несёт uplink, response body несёт downlink. Никакого нового конфиг-поля, никакого нового mode-варианта — `XhttpSubmode::from_url(&Url)` читает query во время dial'а и роутит на нужный driver. На h3 stream разделяется через `RequestStream::split` — uplink и downlink половинки на отдельных tasks. Packet-up driver остаётся по умолчанию для URL'ов без query (или с `?mode=packet-up`).
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
- `outline_transport::install_test_tls_root(CertificateDer)` — тест-only ручка, пинающая кастомный самоподписанный root для XHTTP h2 / h3 dial-путей. Override-слот это `RwLock<Option<…>>` с дефолтом `None`, так что продакшен-вызывающие (которые её не трогают) сохраняют webpki-поведение с одним лишним чтением на dial. Целевой потребитель — cross-repo e2e-тест в `outline-ss-rust`, который поднимает in-process самоподписанный сервер и дёргает его через обычный `connect_websocket_with_resume`.
- Тест-обход для процесс-вайдных кэшей QUIC-эндпоинтов. Когда выставлен тестовый override (т.е. `install_test_tls_root` был вызван), `H3_CLIENT_ENDPOINT_V4` / `_V6` и raw-QUIC `QUIC_CLIENT_ENDPOINT_V4` / `_V6` пропускают кэш и биндят свежий endpoint на каждый dial. Каждый `#[tokio::test]` крутится в своём runtime; driver-task закэшированного endpoint'а привязан к runtime, который первым попал в кэш, и умирает сразу как только тот тест завершается — следующий тест получает `endpoint driver future was dropped`. Продакшен-поведение не меняется.

### Исправлено

- WebSocket-over-h2 диалер слал `:path = //{ws_path}` потому что `H2Dialer::open_on` форматировал `target_uri` как `format!("{scheme}://{auth}/{path}")`, а `websocket_path` уже возвращает ведущий `/`. Серверные axum-роутеры отвергают двойной слэш с 404, что годами маскировалось h1-фолбэком в WS-h2 диспетчере (tungstenite нормализует слэш по дороге на провод). h2-путь теперь конкатенирует без повторного `/`. Виден только на h2-only серверах (RFC 8441 стеки без h1) и всплыл благодаря cross-repo h3→h2 fallback тесту в `outline-ss-rust`.
- XHTTP h3 stream-one закрывал QUIC-соединение с `H3_NO_ERROR` ещё до того, как через него пройдёт хоть один прикладной байт: единственный `SendRequest` уезжал в `open_h3_stream_one`, дропался на return, а `SendRequest::drop` в крейте h3 делает graceful-close, как только `sender_count` падает в ноль. Зеркалит паттерн packet-up — клонируем перед open-хелпером, оригинал держим живым в driver-task'е. Тот же коммит переносит quinn `Endpoint` в driver-task (прежний `let _endpoint_guard = endpoint;` держал его живым только в скоупе функции, не на время сессии).
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
