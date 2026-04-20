# Changelog

Все заметные изменения проекта собраны в этом файле.

Этот changelog подготовлен ретроспективно по git-тегам и истории коммитов репозитория. Он фиксирует пользовательские и эксплуатационные изменения, а не перечисляет каждый отдельный коммит.

В репозитории также есть rolling-тег `nightly`, но верхний раздел ниже описывает текущее состояние ветки после `v1.1.0`, а не изменяемый тег.

---

*English version: [CHANGELOG.md](CHANGELOG.md)*

## [Unreleased] - изменения после `v1.1.0` (по состоянию на 2026-04-20)

### Добавлено

- HTTP-поверхность разделена на независимые плоскости метрик и управления; control plane теперь требует bearer-аутентификацию и включается отдельной Cargo-фичей.
- Добавлен `POST /switch` для ручного переключения активного аплинка.
- Добавлено ограничение числа соединений через `Semaphore`, чтобы защищать процесс при всплесках подключений.
- Добавлено graceful shutdown для фоновых циклов управления аплинками.
- Расширена диагностика: в `session_death` теперь попадает адрес цели, транспортные read-диагностики прокинуты в TUN и TCP probe paths, а HTTP-эндпоинты control/metrics получили счётчики запросов.
- Продолжено разделение на workspace-crates: вынесены отдельные crate'ы для transport, uplink management, TUN, routing, metrics, Shadowsocks crypto и SOCKS5 primitives.

### Изменено

- Переработаны внутренности configuration, bootstrap, proxy, UDP, metrics и TUN под workspace-структуру и более мелкие сфокусированные модули.
- Снижены накладные расходы hot path за счёт менее аллокационного DNS cache, boxed AEAD-вариантов, более точечных блокировок статусов аплинков, неблокирующего `AsyncFd` для TUN и меньшего heap churn в UDP/TCP путях.
- Внутренние зависимости переведены на прямое использование workspace-crates вместо фасадов и алиасов корневого crate.

### Исправлено

- Рендеринг Prometheus сериализован, чтобы избежать гонок при одновременных scrape'ах.
- Валидация конфигурации теперь завершается ошибкой сразу, если настройки metrics или control используются без соответствующих Cargo-фич.
- Предотвращён hijacking адреса SOCKS5 UDP-клиента, а кэшированные UDP route decisions теперь корректно реагируют на изменение здоровья аплинков.
- Исправлены проблемы жизненного цикла вокруг сборки мусора shared H2/H3 connections, персистентности active-uplink state, «тихо» отвалившихся за NAT аплинков и feature-gated тестов.

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
