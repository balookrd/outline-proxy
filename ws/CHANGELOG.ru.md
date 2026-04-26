# Changelog

Все заметные изменения проекта собраны в этом файле.

Этот changelog подготовлен ретроспективно по git-тегам и истории коммитов репозитория. Он фиксирует пользовательские и эксплуатационные изменения, а не перечисляет каждый отдельный коммит.

В репозитории также есть rolling-тег `nightly`, но верхний раздел ниже описывает текущее состояние ветки после `v1.1.0`, а не изменяемый тег.

---

*English version: [CHANGELOG.md](CHANGELOG.md)*

## [Unreleased] - изменения после `v1.1.0` (по состоянию на 2026-04-24)

### Добавлено

- Возобновление сессии между транспортами — клиентская сторона, end-to-end. Запросы WebSocket Upgrade поверх HTTP/1.1, HTTP/2 и HTTP/3 несут `X-Outline-Resume-Capable: 1`, чтобы сервер outline-ss-rust с включённой соответствующей фичей сгенерировал Session ID и вернул его в `X-Outline-Session`. ID становится доступен через `WsTransportStream::issued_session_id()` и кэшируется в process-wide `ResumeCache` по имени аплинка. При следующем on-demand TCP-WebSocket dial (`connect_tcp_ws_fresh` — fresh dial, pool пуст) кэшированный ID отправляется как `X-Outline-Resume: <hex>`, чтобы сервер переcадил клиента на припаркованный upstream и пропустил connect к таргету. Resume opt-in на проводе (серверы без фичи игнорируют заголовки) и без overhead'а при отключённом. Refill warm-standby-пула намеренно НЕ участвует в кэшировании — пуловые коннекты обезличены; только acquire-on-demand dial'ы несут resume-токен. Новая функция `connect_websocket_with_resume` экспонирует низкоуровневый примитив для вызывающего кода с явным управлением. Формат — `docs/SESSION-RESUMPTION.md` в outline-ss-rust.
- Raw QUIC транспорт (`*_ws_mode = "quic"`): VLESS / Shadowsocks-кадры прямо поверх QUIC bidi-стримов и датаграмм (RFC 9221), без WebSocket и без HTTP/3. ALPN per-connection выбирает протокол (`vless`, `ss`, `h3`); парный листенер — в outline-ss-rust. Несколько сессий с одинаковым ALPN на тот же `host:port` шарят один кэшированный QUIC-коннект. VLESS-UDP использует per-target control bidi (сервер выдаёт 4-байтный `session_id`) и connection-level demux датаграмм. SS-UDP едет в QUIC-датаграммах 1-к-1 c SS-AEAD пакетами. Без fallback by design — провал dial / handshake помечает аплинк недоступным.
- В правилах `[[route]]` кроме `file` теперь принимается список `files = [..., ...]`; все пути мерджатся в CIDR-набор правила, и за каждым отдельно следит hot-reload. Удобно, когда IPv4 и IPv6 GeoIP-фиды лежат в разных файлах.
- HTTP-поверхность разделена на независимые плоскости метрик и управления; control plane теперь требует bearer-аутентификацию и включается отдельной Cargo-фичей.
- Добавлен `POST /switch` для ручного переключения активного аплинка.
- Добавлено ограничение числа соединений через `Semaphore`, чтобы защищать процесс при всплесках подключений.
- Добавлено graceful shutdown для фоновых циклов управления аплинками.
- Расширена диагностика: в `session_death` теперь попадает адрес цели, транспортные read-диагностики прокинуты в TUN и TCP probe paths, а HTTP-эндпоинты control/metrics получили счётчики запросов.
- В userspace-стек TUN добавлены TCP keepalive-пробы, чтобы обнаруживать мёртвых пиров вместо зависших established-сессий.
- WebSocket Close-код `1013` теперь считается retryable-сигналом, наравне с TCP RST.
- Продолжено разделение на workspace-crates: вынесены отдельные crate'ы для transport, uplink management, TUN, routing, metrics, Shadowsocks crypto и SOCKS5 primitives. `outline-transport` дополнительно разнесён на `outline-net` + `outline-ss2022`.
- Добавлен встроенный multi-instance дашборд по адресу `/dashboard` под Cargo-фичей `dashboard`. Процесс дашборда хранит per-instance control-токены на серверной стороне и проксирует `/control/topology` и `/control/activate` к каждой instance. Поддерживаются `http://` и `https://` control endpoints, сохраняется URL-префикс для инстансов за reverse proxy, добавлен настраиваемый `dashboard.request_timeout_secs`.
- UI дашборда: instance-centric раскладка, панель настроек балансировки по группам, тематизированный sidebar с тёмной палитрой по умолчанию и рантайм-переключателем light/dark (браузерный `theme-color` следует за активной темой).
- Добавлен packaged Grafana-дашборд control plane (`grafana/dashboard/outline-ws-uplinks.json`) и integration guide в `grafana/README.md`.

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
- Переработаны внутренности configuration, bootstrap, proxy, UDP, metrics и TUN под workspace-структуру и более мелкие сфокусированные модули.
- Снижены накладные расходы hot path за счёт менее аллокационного DNS cache, boxed AEAD-вариантов, более точечных блокировок статусов аплинков, неблокирующего `AsyncFd` для TUN, меньшего heap churn в UDP/TCP путях, UDP send без мьютекса, SACK scoreboard без клонирования на каждый ACK, выноса sticky-route pruning с connect hot path, коалесинга `/metrics` scrape'ов и lock-free чтения standby-пула.
- WebSocket read idle timeout поднят со 120s до 300s, чтобы длинные периоды без ответа (например, пока модель «думает») не выбивали здоровые сессии.
- Ограничена конкурентность HTTP control/metrics-плоскостей и добавлены bounds на SOCKS5 handshake — чтобы уменьшить DoS surface.
- Внутренние зависимости переведены на прямое использование workspace-crates вместо фасадов и алиасов корневого crate.

### Устарело

- Плоская форма конфига аплинков (top-level `tcp_ws_url` / `[probe]` / `[[uplinks]]` / `[load_balancing]`) признана устаревшей; каноническая форма теперь вложена под `[outline]` (`[[outline.uplinks]]`, `[outline.probe]`, `[outline.load_balancing]`). Старая форма по-прежнему принимается и логирует deprecation-предупреждение на старте. Примеры конфигов и README обновлены под новую форму.

### Исправлено

- Рендеринг Prometheus сериализован, чтобы избежать гонок при одновременных scrape'ах.
- Валидация конфигурации теперь завершается ошибкой сразу, если настройки metrics или control используются без соответствующих Cargo-фич.
- Предотвращён hijacking адреса SOCKS5 UDP-клиента, а кэшированные UDP route decisions теперь корректно реагируют на изменение здоровья аплинков.
- Исправлены проблемы жизненного цикла вокруг сборки мусора shared H2/H3 connections, персистентности active-uplink state, «тихо» отвалившихся за NAT аплинков и feature-gated тестов.
- TCP idle watcher теперь обновляется на keepalive-трафике, так что keepalive-only сессии больше не выселяются как idle.
- Phase-1 выбор аплинка больше не штрафует аплинк, если недоступна сама цель.
- Исправлены подписи чипов load-balancing в дашборде — теперь они соответствуют реальным вариантам enum'а балансировки.
- Исправлен учёт keepalive в SOCKS idle-таймауте: keepalive-трафик корректно отодвигает выселение сессии по idle на стороне SOCKS.

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
