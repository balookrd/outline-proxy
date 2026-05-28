# Changelog

Все заметные изменения проекта собраны в этом файле.

Этот changelog подготовлен ретроспективно по git-тегам и истории коммитов репозитория. Он фиксирует пользовательские и эксплуатационные изменения, а не перечисляет каждый отдельный коммит.

В репозитории также есть rolling-тег `nightly`, но верхний раздел ниже описывает текущее состояние ветки после последнего теха-релиза, а не изменяемый тег.

---

*English version: [CHANGELOG.md](CHANGELOG.md)*

## [Unreleased] - изменения после `v1.4.4`

### Добавлено

- **`shuffle_wires` — per-uplink random forward-only wire rotation.** Новый булев knob на `[[outline.uplinks]]`. При `true` цепочка `[primary, fallbacks…]` переставляется один раз при загрузке конфига, а `PerTransportStatus::wires_failed_in_round` ведёт per-round учёт; как только все wire'ы успели быть активным wire'ом failed round'а с последнего успеха — аплинк помечается runtime-failed, и балансировщик перекидывает трафик на другой аплинк, а не зацикливается на мёртвой цепи. Перестановки collision-free внутри `[[uplink_group]]` (`shuffle_wire_chains_per_group`), так что два same-shape аплинка в одной группе никогда не попадают на одинаковый порядок — применяется и в legacy `load_uplinks`, и в новом `load_groups`. Внутри одного wire'а сначала идёт спуск по его carrier-стеку (`xhttp_h3 → xhttp_h2 → xhttp_h1`), и только потом — переход на следующий wire, поэтому wire бросают только после исчерпания вариантов carrier-descent'а. Дефолт `false`; существующие конфиги сохраняют operator-ordered цепочку и wrap-forever state machine wire'ов байт-в-байт. `auto_failback`, `weight` и active-wire / probe-recovery машинерия не пересекаются с этим флагом.

- **`shuffle_timer` — периодический реролл active_wire.** Новый knob `shuffle_timer = "1h"` на `[[outline.uplinks]]` (принимает human-readable формы `30s` / `5m` / `1h30m` / `2d` плюс bare seconds). Per-uplink tokio-task на каждом тике рероллит `active_wire` для обоих транспортов на случайный wire цепочки, обнуляет per-wire failure-счётчики (`active_wire_streak`, `wires_failed_in_round`, `consecutive_failures`, `consecutive_runtime_failures`, `chunk0_consecutive_failures`), сбрасывает текущие `mode_downgrade_*` cap'ы, и пинит новый wire на `mode_downgrade_duration` — кроме случая, когда роллом выпал primary. Probe-driven early-failback на primary в `record_transport_success` подавляется, пока выставлен `shuffle_timer` — иначе следующий успех primary-пробы сразу же отменил бы реролл. Ротация также driven по накопленным runtime + probe failures (с гейтом — флипать сам аплинк только когда все wire'ы round'а провалились). Интервал поднимается на `UplinkSnapshot.shuffle_timer_secs`; события реролла учитываются на `outline_ws_rust_uplink_failover_total{transport="tcp_shuffle_timer"|"udp_shuffle_timer"}`. Независим от `shuffle_wires` — оба можно комбинировать или включать по отдельности. Round state и failed wires отображаются на дашборде.

- **Per-uplink `carrier_downgrade` opt-out.** Новый булев на `[[outline.uplinks]]` (дефолт `true`, сохраняет legacy-контракт descent'а `h3 → h2 → h1` / `xhttp_h3 → xhttp_h2 → xhttp_h1`). Выставление `false` свёртывает вертикальный карьер-каскад: `extend_mode_downgrade` сразу возвращается (никакого `mode_downgrade_*` state не появляется, `↘` стрелок на дашборде нет, окна `mode_downgrade_secs` для рангов нет), а `wire_is_at_carrier_floor` репортит каждый wire как «на полу». Под `shuffle_wires = true` это превращает per-wire каскад в прямую wire→wire ротацию — фейлы переезжают на следующий wire на ближайшем `min_failures`-пороге, не тратя по одному downgrade-окну на каждый промежуточный carrier. Use case: DPI, который дропает весь upstream независимо от HTTP-версии. `UplinkSnapshot.carrier_downgrade` теперь сериализуется на snapshot всегда (не skip-default), чтобы оператор видел явный setting.

- **Синтез ICMP PMTUD на TUN UDP oversize drop.** Когда транспорт отказывается принять oversize UDP-датаграмму, TUN-движок теперь синтезирует IPv4 «Fragmentation Needed» или IPv6 «Packet Too Big» ответ (с reportable `limit` транспорта как объявленным Next-Hop MTU, с протокольным минимумом 576 v4 / 1280 v6), цитируя оригинальные IP + UDP заголовки, чтобы стек отправителя сматчил их к оффендингу-сокету. Throttle — один PTB в секунду на flow (аналог Linux `icmp_ratelimit`; RFC 4443 §2.4(f) для ICMPv6 обязательно, RFC 1812 §4.3.2.8 для IPv4 рекомендуется). Decision logic вынесен в pure helper для unit-тестов без async flow-table машинерии. Закрывает поломку VoWiFi IKE_AUTH с сертификатами over raw-QUIC — клиенты не имели способа узнать effective MTU туннеля. Новый label `cause` на `udp_oversized_dropped_total` различает девять drop-сайтов (`quic_dgram`, `vless_quic_dgram`, `vless_udp`, `ss_socket`, `socks_client`, `socks_relay`, `socks_direct`, `socks_in_tcp`) на панели Oversized UDP Drops.

- **`tun.pmtud_emit_below_quic_initial` opt-in флаг** (дефолт `false`). Синтез PTB выше гейтится на условие «лимит транспорта не ниже family-specific QUIC Initial-datagram minimum» (1200 для IPv4 / 1280 для IPv6) — sub-minimum oversize drop'ы возвращаются к silent drop, иначе compliant QUIC-стек получивший PTB ниже Initial minimum отключает QUIC для destination и сваливается на TCP (production-регрессия: Samsung Smart-TV YouTube-клиенты перестали переключать стрим с TCP на QUIC после введения PMTUD кода). Операторы без QUIC-клиентов (чистые VoWiFi / IKEv2-концентраторы, прогоняющие IKE_AUTH с сертификатами через узкий raw-QUIC uplink) могут включить `true` и получать явный PMTUD-сигнал на каждом sub-minimum drop'е. Above-minimum drop'ы в диапазоне ~1300-1450 байт (где живёт реальная PMTUD-поломка) продолжают слать PTB как раньше. Описано в `docs/TUN-PMTUD.md` / `docs/TUN-PMTUD.ru.md`.

- **`tun.ipsec_bypass` fast-path для UDP/{500,4500}.** Opt-in (дефолт `false`). TUN-классификатор форвардит только TCP/UDP/ICMP, поэтому raw ESP (IP protocol 50) всегда дропается — VoWiFi / IKEv2 клиенты не могут поднять ESP-in-UDP, даже когда IKE-handshake на UDP/500 и UDP/4500 проходит. `tun.ipsec_bypass = true` short-circuits оба порта в `TunRoute::Direct` ещё до policy routing, переиспользуя путь к локальному сокету как `via = "direct"`. Оба порта матчатся вместе, потому что `NAT_DETECTION` уводит IKE_AUTH с порта 500 в течение сессии. Direct-путь использует `SO_MARK = direct_fwmark`, чтобы выйти из TUN routing loop'а; стартовый warning срабатывает, если `ipsec_bypass = true` без `direct_fwmark` на Linux, чтобы split-tunnel vs default-route оставался явным.

- **Strict-mode SOCKS5 abort на active uplink switch.** Зеркалит TUN strict-mode в SOCKS5 ingress: в `active_passive` (любой routing scope) ручное переключение control-plane или probe-driven failover, сдвигающий активный аплинк с in-flight сессии, теперь принудительно рвёт эту TCP-сессию RST'ом (`SO_LINGER {l_onoff=1, l_linger=0}`), чтобы клиентское приложение переподключилось через новый активный аплинк. UDP downlink-цикл подписывается на тот же сигнал, чтобы замена транспорта не ждала следующей датаграммы. `UplinkManager` публикует `ActiveUplinksSnapshot` через `tokio::sync::watch`; `pinned_relay::run_relay` гоняет data-task'и против вотчера и на switch возвращает `DriveExit::AbortedOnSwitch`; `udp::group::run_group_downlink` подписывается на `subscribe_active_uplinks`, чтобы будить цикл на `changed()`. Новый счётчик `outline_ws_rust_socks_tcp_strict_aborts_total`. Поведение для `active_active` не меняется — там вотчер никогда не вооружается.

- **TCP retry'и идут через active wire** (per-wire runtime failure attribution). Mid-session retry оркестратор и chunk-0 same-uplink recovery теперь дайлят тот wire, который менеджер сейчас считает активным, а не безусловно primary URL. `connect_tcp_fallback_fresh` обзавёлся struct'ом `FallbackDialOptions` — retry-путь теперь может запросить Ack-Prefix / Symmetric Downlink Replay на fallback wire'е так же, как на primary. Новый `report_runtime_failure_for_wire` оборачивает существующее accounting тем же правилом «failure на не-активном wire'е — session-local churn», что `record_wire_outcome` уже применяет на dial-пути — mid-session resets, terminal chunk-0 failures и deferred-failure flush теперь приколачивают свои failures к wire'у; failures, приписанные wire'у, с которого менеджер уже ушёл, считаются только в suppressed-метрику. Single-wire аплинки и legacy uplink-уровневый `report_runtime_failure` сохраняют байт-в-байт поведение.

- **`[outline.probe.tls]` — TLS-handshake проба data-path.** Гонит `ClientHello → ServerHello / Certificate → Finished → close_notify` через uplink-туннель к настроенной паре `(SNI, port)`, без HTTP-обмена после handshake. Воспроизводит user-flow `chunk0_timeout` (handshake до сервера-uplink прошёл, ClientHello переслан upstream-цели, ответных байт не приходит) — паттерн, который plain HTTP-проба не видит: `probe.http` валидирует только `http://...` и TLS вообще не делает, поэтому upstream-фильтр, тихо режущий `ServerHello` для конкретных SNI, оставляет `uplink_health` залипшим на `1`, и probe-driven эскалация не срабатывает. Конфиг — список ротации `"host:port"` (bare host = порт 443 по умолчанию; IPv6 в скобках `"[::1]:443"`); cursor продвигается на одну запись за цикл. Взаимоисключается с `[outline.probe.http]` / `[outline.probe.tcp]` в одном цикле (приоритет `tls → http → tcp`). Метрики идут под лейблом `probe="tls"`. Реализация — `crates/outline-uplink/src/probe/tls.rs`; публичный helper `outline_transport::build_https_probe_client_config` шарит rustls root-store / test-override-plumbing со всеми остальными dial'ами проекта. Документировано в `docs/UPLINK-CONFIGURATIONS.ru.md` «TLS-handshake проба data-path».

- **Обновление пула профилей (2026-05).** Все шесть записей пула подняты до current-stable релизов на май-2026: Chrome 142 (Windows + macOS), Firefox 150 (Windows + macOS), Safari 19 (macOS, patch 19.4), Edge 142 (Windows). Версии Sec-CH-UA brand list следуют Chrome / Edge major. Chrome и Safari на macOS продолжают пинить замороженный `10_15_7` в UA-строке (design Google / Apple — реальная версия macOS уезжает в `Sec-CH-UA-Platform-Version`); Firefox использует фактическую `Intel Mac OS X 16.4`. `PROFILES_REFRESHED_AT_UNIX` поднят с 2026-05-01 до 2026-05-09. Существующие assert'ы обновлены на новые id (`chrome-142-*`, `firefox-150-*`, `safari-19-macos`, `edge-142-windows`). Операторам с дашбордами / алертами на старые id (`chrome-130-macos` и т.п.) нужно обновить — шейп histogram'а / чипа стратегии не меняется, меняется только отрисованное имя.

- **Стратегия `process_stable` + смена смысла алиаса.** Добавлен `Strategy::ProcessStable` в пул браузерного фингерпринта: одна идентичность на весь процесс, независимо от того, какой аплинк дозванивается — ровно так, как реальный пользователь с одним браузером выглядит для on-path-наблюдателя. Выбор сидируется из OS-уровня hostname (`gethostname(2)` на Unix, `%COMPUTERNAME%` из process env на Windows) для стабильности между рестартами на одной машине. **`$HOSTNAME` НЕ является источником сида** — это shell-внутренняя переменная на Linux / macOS, не часть process env, и демоны, запущенные systemd / docker / cron, её никогда не видят. В контейнерах без явного `--hostname` syscall не возвращает полезное значение, и сид падает на `rand::random` при старте процесса (стабильно in-process, ротируется при рестарте). В зависимости `outline-transport` добавлен `libc = "0.2"`. Набор Prometheus-лейблов расширен до `none` / `per_host_stable` / `process_stable` / `random`.

- **Liveness override — форсированный probe pulse каждые N минут** — закрывает дыру: аплинк, у которого probe-skip оптимизация продолжала скипать (потому что warm pipe всегда был свежим), никогда не re-validate'ил себя, если операторская сторона тихо ломалась; форсированный pulse re-armит probe-машинерию на детерминированном графике.

- **`skip_when_active` probe-knob** для отключения probe-skip оптимизации per uplink. По умолчанию probe-цикл скипает WS / HTTPS sub-probe'ы когда warm pipe уже доказал liveness; `skip_when_active = false` возвращает явное пробирование на каждом цикле для параноидальных деплоев.

- **Стрик chunk-0 timeout эскалирует active uplink** под slow-burn upstream failure. Отдельный счётчик — отличный от runtime-failure окна — эскалирует после порога подряд chunk-0 timeout'ов, даже когда каждая отдельная сессия отваливалась быстрым cross-uplink fallback'ом, маскирующим basket degradation primary. WARN-уровня лог теперь подсвечивает silent cross-uplink chunk-0 failover, который раньше был невидимым для оператора.

- **Per-uplink gauge открытых соединений + классификация закрытий** для детекции leak'ов. Новая Prometheus-gauge `outline_ws_rust_uplink_open_connections{group,uplink,transport}` плюс label `close_reason` на close-счётчике, чтобы half-closed-session и orphaned-driver leak'и проявлялись как монотонно растущий gauge, а не растворялись в шуме.

- **Метрики окна mode-downgrade + дашборд hang-диагностики.** Mode-downgrade window remaining seconds публикуются в Prometheus per uplink+wire+transport; новый раздел Grafana «Hang diagnostics» джоинит их с chunk-0 timeout streak'ом, mid-session retry счётчиками и runtime-failure окном — оператор-триаж slow-degradation видит всё с одной панели.

- **Ack-Prefix Protocol v1 + v1.1 + v2 Symmetric Downlink Replay.** Фундамент mid-session retry. Клиент и сервер обмениваются Ack-Prefix control-frame на проводе, сервер знает, сколько uplink-байт клиент уже принял, и на retry replay'ит только хвост, который клиент ещё не подтвердил. v1.1 делает offset non-blocking и добавляет VLESS-WS support; v2 расширяет до **Symmetric Downlink Replay** — клиент публикует Down-Acked offset header (с XHTTP capability negotiation), retry replay'ит с последнего acked downlink offset клиента, а не сессию целиком. Прокинуто в `pinned_relay` через `FallbackDialOptions` у `connect_tcp_fallback_fresh`. Operator-knobs: `tcp_mid_session_retry_buffer_bytes`, `tcp_mid_session_retry_consume_timeout_secs`, `tcp_mid_session_retry_overflow_policy` (`soft` / `hard`). Новый раздел Grafana «Mid-session retries (v1+v2)»; outcome `downlink_truncated` описан в документе `record_mid_session_retry`.

- **WS-family hysteresis-стек: multi-step H3 → H2 → H1 descent** плюс WS-family mirror-тесты. Зеркало XHTTP-family walk-down'а `xhttp_h3 → xhttp_h2 → xhttp_h1` — WS-аплинк, сконфигурированный на `h3`, теперь корректно каскадирует через `h2` к `h1`, не останавливаясь на одном шаге, и per-wire слот `mode_downgrade_capped_to` трекает весь descent.

### Изменено

- **Прямые (`via = "direct"`) UDP-flow в TUN теперь ограничены `tun.max_flows`.** Раньше лимит применялся только к туннелируемым (`via = "group"`) flow, а прямые росли без предела — UDP-шторм к direct-маршрутизируемым адресам (P2P/DHT, сканы) мог разом создать десятки тысяч per-flow сокетов и reader-тасков и поднять RSS далеко выше рабочего набора. Таблица прямых flow теперь использует ту же least-recently-seen eviction, что и туннельная; `max_flows` ограничивает каждую таблицу независимо. Кроме того, reader прямого flow больше не держит постоянный буфер приёма на 64 KiB: он паркуется на готовности сокета и аллоцирует буфер только пока датаграмма в полёте (`try_recv_buf_from`, без зануления), поэтому простаивающий прямой flow не стоит ни одного per-flow буфера, а пиковый high-water mark всплеска снижается.

- **Сборки с mimalloc периодически возвращают освобождённую память ОС.** Низкочастотный фоновый поток вызывает `mi_collect(true)` каждые 30 с. mimalloc чистит освобождённые страницы лениво и только при активности аллокатора; после крупного кратковременного всплеска, который затем уходит в простой (например, разом дренируемый UDP-flow шторм в TUN), запустить отложенный purge нечему — и RSS может надолго залипнуть на high-water mark. Принудительный сбор освобождает пустые сегменты, а decommit-on-purge (дефолт mimalloc) отдаёт страницы ядру. Под существующим feature `mimalloc`, поэтому router-сборок не касается.

- **Простаивающие relay/reader-пути больше не держат 64 KiB-буфер на соединение.** Вслед за фиксом TUN direct-UDP тот же приём allocate-on-ready (парк на готовности сокета, аллокация приёмного буфера только пока датаграмма/сегмент в полёте через `try_read_buf` / `try_recv_buf`, освобождение перед следующим парком) применён к остальным долгоживущим read-петлям: SOCKS5 direct TCP relay (оба направления, `proxy/tcp/direct.rs`), туннелируемый SOCKS5 TCP uplink (`pinned_relay`), туннелируемый UDP `Socket`-транспорт (raw Shadowsocks-over-UDP, `udp_transport.rs`), TUN direct TCP upstream reader, приёмные петли SOCKS5 UDP relay (uplink + direct downlink, `proxy/udp/socks5.rs`) и direct downlink UDP-in-TCP (`proxy/udp/in_tcp.rs`). Простаивающее соединение/flow/ассоциация на этих путях теперь не держит per-connection приёмный буфер, снижая RSS на простое при множестве открытых, но молчащих соединений. На активных соединениях throughput не страдает — буфер аллоцируется ровно когда есть данные. Туннелируемый UDP через WS/QUIC и так был без буфера (датаграммы приходят через mpsc-канал).

- **Полу-breaking: короткий алиас `stable` теперь резолвится в `process_stable`, а не в `per_host_stable`.** Прежний PerHostStable-дефолт выдавал разные browser identity на одном source IP к разным хостам — это сильный сигнал глобальному on-path-наблюдателю, что трафик автоматизированный (реальный пользователь держит один браузер). Конфиги с `stable` автоматически получают более безопасное поведение; операторы, которым нужен именно per-peer split, должны прописывать `per_host_stable` / `per-host-stable` / `per-host` полностью. Prometheus-лейбл `strategy`, snapshot JSON и чип дашборда переключаются с «per_host_stable» на «process_stable» для таких конфигов — алерты / панели, привязанные к старому токену, нужно обновить. `Strategy::PerHostStable` намеренно сохранён, не удалён: остаётся правильным для deployment'ов с полной развязкой пиров между наблюдателями (разные AS, разные юрисдикции, никакого глобального DPI).

- **Чип HTML-дашборда теперь показывает имя активного fingerprint-профиля** вместо стратегии. Оператору важно видеть *что именно на проводе* (`Chrome 130 macOS`), а не конфигурационный knob (`Stable`). Snapshot-билдер вызывает `select_with_strategy(primary_dial_url, effective_strategy)` для каждого аплинка и публикует получившийся id профиля в новое поле `UplinkSnapshot::fingerprint_profile_name`, пробрасывая через topology JSON с `skip_serializing_if = "Option::is_none"` для обратной совместимости. `prettyProfileName` переводит kebab-case-id пула (`chrome-130-macos`, `firefox-130-windows`, `safari-17-macos`, `edge-130-windows`) в читаемый label; стратегия `random` показывается как литерал. Цветовое разделение прежнее: синий для стабильных профилей, фиолетовый для random.

- **Dashboard-видимость активной fingerprint-стратегии** — Grafana stat-панель «Fingerprint Strategy» в верхней строке статуса; per-uplink чип `FP: Stable` / `FP: Random` рядом с протокол-pill на каждой строке аплинка с не-дефолтной эффективной стратегией; аплинки на `none` чипа не получают. Чип теперь поднимается в group header, когда стратегия одинакова по группе, и переехал из колонки Protocol в колонку Status для читаемости.

- **CLI / env override стратегии диверсификации браузерного фингерпринта**. Флаг `--fingerprint-profile <off|stable|random>` (или `OUTLINE_FINGERPRINT_PROFILE`) перекрывает top-level ключ `fingerprint_profile` из TOML — приоритет такой же, как `--listen` / `--metrics-listen`, и per-uplink override побеждает поверх любого источника. Принимает тот же набор алиасов, что и TOML-ключ.

- **Видимость активной fingerprint-стратегии в Prometheus / snapshot**. Новая gauge `outline_ws_rust_uplink_fingerprint_profile_strategy_info{group, uplink, strategy}` публикуется безусловно для каждого аплинка — `1` на активной стратегии и `0` на остальных, набор лейблов фиксирован: `none` / `per_host_stable` / `random`. Отражает **эффективную** стратегию. Та же строка экспортируется через `/snapshot` control-endpoint в новом поле `UplinkSnapshot::fingerprint_profile_strategy`.

- **Рефакторинг: planning dial-транспорта + загрузка uplink-конфига.** `crates/outline-transport/src/dial_plan.rs` теперь публикует `TransportDialOptions` / `DialNetworkOptions` / `DialResumeOptions` / `connect_transport`; фасад в `lib.rs` тонкий. `src/config/load/uplinks/` разнесён на `source_precedence`, `credentials`, `wire_shape` и `fallback_resolution` модули с тонким `mod.rs` orchestration-слоем.

- **TUN cleanup**: eviction flow больше не делает O(n)-скан TUN TCP-таблицы; TUN-stubs метрик теперь компилируются чисто под `--no-default-features --features router`. Vendored member `vendor/sockudo-ws` теперь явно перечислен и задокументирован.

- **Probe-машинерия — фиксы**: pin expiry больше не force-snap'ит active wire на primary; primary-probe эскалация гейтится по active-fallback liveness, а probe failures fallback-wire'а пробрасываются в active_wire streak; `https://` URL-цели принимаются в `[probe.tls]` и отвергаются заранее в `[probe.http]`; `tls` включён в `tcp_budget` outer timeout'а probe-цикла; метрики `https` handshake'а атрибутируются под `probe="https"`; probe-цикл продолжает работать, когда chunk-0 signal свежий; устаревшие Grafana-дашборды `tun-tcp` и `native-burst` удалены; добавлен новый row «Probe vs User-Flow Correlation».

- **Полировка дашборда**: shuffle round state и failed wires отрисованы на дашборде; carrier family выведен на inactive fallback wire chip'ах (например, `VLESS/WS › VLESS/XHTTP › SS/QUIC`) — активный chip сохраняет полный `VLESS/XHTTP/H3` шейп; чип Active в group header теперь следит за фактически активным wire'ом.

### Исправлено

- **Hints для control uplink apply** — `/control/apply` выводил misleading-сообщения для некоторых payload'ов; канонический hint-флоу восстановлен.

- **`VlessTcpReader::read_chunk` возвращает header-bundled tail** вместо того, чтобы выбрасывать его — закрыта тихая потеря данных на первом read'е после header-bundled VLESS-фрейма.

- **Chunk-0 timeout'ы теперь классифицируются под `cause = "timeout"` / `signature = "chunk0_timeout"`** в метриках, чтобы дашборды оператора отличали slow-burn-сбои от быстрых dial-ошибок.

- **`gethostname(2)` сидирует ProcessStable**, а не `$HOSTNAME` env — последний это shell-внутренняя переменная, которую systemd / docker / cron-демоны не наследуют, поэтому прежнее чтение давало `rand::random` fallback на каждом типичном деплойменте (без in-process стабильности между рестартами на той же машине).

## [1.4.4] - 2026-05-07

### Добавлено

- **Внутри-аплинковые fallback-транспорты через `[[outline.uplinks.fallbacks]]`.** Каждый `[[outline.uplinks]]` теперь принимает список запасных wire'ов, которые dial-loop перебирает по порядку, если primary-транспорт этого аплинка не смог дозвониться. Каждый fallback несёт свой `transport` (`ws` / `shadowsocks` / `vless`) и соответствующие wire-поля; `cipher` / `password` / `fwmark` / `ipv6_first` / `fingerprint_profile` по умолчанию **наследуются** от родительского аплинка (VLESS `vless_id` per-wire, не наследуется). TCP-путь (`connect_tcp_uplink` в `src/proxy/tcp/failover.rs`) и UDP-путь (`acquire_udp_with_fallbacks` в `src/proxy/udp/transport.rs`) оборачивают primary-dial в fallback-aware цикл: успешный fallback-дайл невидим для балансировщика кроме тика метрики `outline_uplink_selected`, а `report_runtime_failure` инкрементируется только когда провалились **все** wire'ы аплинка. UDP-фильтр кандидатов (`supports_transport_for_scope`) теперь консультируется с `UplinkConfig::supports_udp_any()`, так что аплинк с UDP-capable fallback'ом не отсекается из UDP-выдачи, даже если его primary — TCP-only.

- **Same-transport fallback'и теперь разрешены** в `[[outline.uplinks.fallbacks]]`. Старый валидатор отвергал fallback'и, у которых `transport` совпадал с primary родителя (и duplicate-transport entries внутри списка). Обе жесткости были чрезмерными — самая естественная кросс-family цепочка внутри VLESS это `xhttp_h3 → ... → xhttp_h1` на primary wire и `ws_h3 → ws_h2 → ws_h1` на fallback wire, оба с `transport = "vless"`, но с разными carrier-семьями и разными dial URL. Послабление позволяет писать VLESS-XHTTP primary плюс VLESS-WS fallback (или два SS fallback'а на разные хосты).

- **Кросс-транспортный fallback в dial / chunk-0 failover loop.** Список кандидатов, который возвращают `tcp_candidates` / `udp_candidates` / `tcp_failover_candidates`, теперь стабильно сгруппирован по `UplinkTransport` (`vless` / `shadowsocks` / `ws`) в порядке первого появления; внутри каждой группы относительный порядок по-прежнему отражает ранжирование health/weight/score. Потребители идут по списку с общим `tried_indexes`, поэтому теперь сначала исчерпывается весь ведущий транспорт и только потом начинается переход на следующий — все VLESS-аплинки перебираются раньше любого Shadowsocks/WS-эндпоинта, и кросс-транспортный переход включается только если в группе действительно настроен второй транспорт.

- **Per-аплинковая active-wire state machine** со sticky-fallback и auto-failback. После `probe.min_failures` подряд провалов dial'а текущего активного wire'а, dial-loop продвигает `active_wire` на следующий сконфигурированный wire и пинит его на `LoadBalancingConfig::mode_downgrade_duration`. Новые сессии стартуют со sticky-wire'а вместо «всегда сначала primary»; цепочка дайла строится через `wire_dial_order(uplink_index, transport, total_wires)` — стартует с активного и заворачивается, чтобы primary всё-таки был протестирован как last resort. По истечении пина `active_wire` сбрасывается обратно на `0` (primary). Состояние **per-transport** (TCP и UDP двигаются независимо). Новый модуль `crates/outline-uplink/src/manager/active_wire.rs` экспортирует `wire_dial_order` и `record_wire_outcome` на `UplinkManager`.

- **Wire-aware chunk-0 failover** (handover внутри аплинка). Цикл chunk-0 failover теперь пробует все остальные wire'ы **этого же** аплинка прежде чем прыгать на другой; вместе с resume-cache (ниже) X-Outline-Resume-токен от провалившегося wire'а едет в wire-handover dial, и chunk-0 replay-буфер — единственное видимое клиенту изменение. `failover_to_next_candidate` теперь двухфазный: **Phase A** — итерация по `wire_dial_order` текущего аплинка (через новый `tried_wires_per_uplink: HashMap<usize, HashSet<u8>>`, переживающий cross-uplink-прыжки); **Phase B** — старый cross-uplink failover, выходим в него только когда все wire'ы текущего аплинка пройдены. События wire-handover пишутся на failover-счётчик с label `transport="tcp_wire"`.

- **Resume-handover через wire-свитч на одном аплинке.** Fallback TCP- и UDP-дайлы теперь участвуют в cross-transport resume cache (`outline_transport::global_resume_cache()`) под ключом `<uplink_name>#<transport>` — тот же identity-level ключ, что primary-путь. Работает для WS↔WS, VLESS↔WS, VLESS↔VLESS, WS↔VLESS handover'ов. У Shadowsocks fallback'а нет WS-слоя и resume-механизма; он всегда дайлит свежим.

- **Liveness override** для аплинков с `[[outline.uplinks.fallbacks]]`: когда probe пометил parent unhealthy потому что *primary* wire сломан, но fallback wire недавно успешно дозвонился (в окне `runtime_failure_window`), аплинк остаётся в candidate set, и dial-loop с active-wire продолжает использовать рабочий fallback. Реализация: новое поле `PerTransportStatus::last_any_wire_success: Option<Instant>`, которое `record_wire_outcome` стамипит на любой успешный wire-дайл, и новая `selection::any_wire_recent_success`, которую `selection_health` проверяет в Global и per-flow / per-uplink scope'ах. Override **гейтится через `!fallbacks.is_empty()`** — single-wire аплинки сохраняют probe-only health-гейтинг.

- **Probe-driven active-wire failover** для `active_passive`-passive аплинков. Симметричная пара probe-driven early-failback (ниже): когда probe проваливается `probe.min_failures` раз подряд И у аплинка есть хотя бы один fallback И active_wire всё ещё primary — `active_wire` продвигается на wire 1 и пинится на `mode_downgrade_secs`. Критично для `active_passive` групп: passive-аплинки получают probe'ы, но не client-трафик, так что до этого коммита их active_wire state machine не двигалась.

- **Probe-driven ранний failback** для sticky active wire'ов. Когда primary родителя приколот к fallback'у после подряд провалов dial'а, существующая probe (primary-only в этой итерации) теперь триггерит ранний snap-back на primary, как только наберёт `probe.min_failures` подряд успехов — короткозамыкая auto-failback таймер.

- **VLESS-as-fallback** на UDP для WS-семейства (`ws_h1` / `ws_h2` / `ws_h3`) и XHTTP-семейства (`xhttp_h1` / `xhttp_h2` / `xhttp_h3`) — оба используют carrier `VlessUdpSessionMux`, как primary-VLESS UDP. `dial_udp_fallback` собирает mux напрямую с wire-полями fallback'а; лимиты группы (`vless_udp_mux_limits`, `udp_ws_keepalive_interval`) шарятся между primary и fallback.

- **VLESS-as-fallback поверх raw QUIC** (`vless_mode = "quic"`). Закрывает последнюю дыру в fallback-транспортной поверхности — с per-wire mode-downgrade tracking, который теперь есть, hook'и QUIC-fallback'а пишут в *слот fallback wire'а* через `note_silent_transport_fallback_for_wire(parent.index, transport, wire_index, requested)`. Гейтится workspace-фичей `h3`.

- **Per-wire mode-downgrade tracking** для fallback-транспортов. Новое поле `PerTransportStatus::fallback_mode_downgrades: Vec<ModeDowngradeSlot>` (лениво расширяемое при первой записи) даёт каждому не-primary wire'у собственное family-aware окно mode-downgrade, полностью отделённое от primary'и `mode_downgrade_until` / `mode_downgrade_capped_to`. Новые `effective_tcp_mode_for_wire` / `effective_udp_mode_for_wire` и `note_silent_transport_fallback_for_wire` — wire-aware варианты существующих хелперов. Downgrade fallback'а следует тем же правилам family / monotonic-decrease, что и primary (`XhttpH3` → `XhttpH2` → `XhttpH1`; cross-family триггеры отбрасываются).

- **Per-wire probe walks** валидируют fallback'и для passive аплинков — probe-машинерия теперь по очереди обходит каждый сконфигурированный fallback wire вместо того, чтобы всегда бить только в primary, поэтому passive-аплинк со сломанным primary и здоровыми fallback'ами выдаёт `effective_health = true` с первого же probe-цикла.

- **Per-wire RTT EWMA** — скоринг ранжирует wire, который реально несёт трафик.

- **`active_wire` продвигается на probe-machinery error**, а не только на probe-confirmed wire failure — закрывает дыру: probe, застрявшая в handshake'е, никогда не давала confirmed outcome.

- **Fallback wire-дайлы кормят RTT EWMA**, чтобы score-based selection между аплинками отражал реальную задержку active wire'а. Раньше fallback-дайлы намеренно обходили `report_connection_latency`, чтобы не пачкать primary-статистику; побочный эффект — при активном sticky-fallback EWMA оставался приколочен к последнему probe-замеру primary'а.

- **Effective health** («visualization truth») на snapshot, Prometheus и дашборде. Новые поля `UplinkSnapshot::tcp_health_effective` / `udp_health_effective` имеют значение `Some(true)`, когда probe-подтверждённое здоровье true ИЛИ — для аплинков с хотя бы одним fallback'ом — когда любой wire недавно успешно дозвонился в окне `runtime_failure_window`. Новая Prometheus-gauge `outline_ws_rust_uplink_health_effective{group,transport,uplink}`; существующая `outline_ws_rust_uplink_health` сохраняет probe-only семантику. Topology-endpoint сериализует новые поля; dashboard-хелперы `legHealth` / `healthy` их читают — multi-wire аплинки с рабочим fallback'ом теперь зелёные даже когда probe primary'а валится.

- **Видимость для оператора** active-wire-состояния. Новые поля `UplinkSnapshot`: `configured_fallbacks: Vec<String>`, `tcp_active_wire` / `udp_active_wire`, `tcp_active_wire_pin_remaining_ms` / `udp_active_wire_pin_remaining_ms`. Три новые Prometheus-метрики — `outline_ws_rust_uplink_active_wire_index{group,transport,uplink}`, `outline_ws_rust_uplink_active_wire_pin_remaining_seconds{group,transport,uplink}`, `outline_ws_rust_uplink_configured_fallbacks_count{group,uplink}` — гейтятся через наличие хотя бы одного fallback'а. Новая Grafana-панель «Active Wire (Sticky Fallback)». HTML control-plane дашборд рисует chain `primary › fallbacks[0] › fallbacks[1]` рядом с protocol pill — активный wire выделен жирным (зелёный для primary, янтарный для sticky fallback), и `⏱ Ns` countdown-chip рядом с активным fallback'ом, пока auto-failback pin тикает. TCP/UDP active-wire'ы рисуются одной строкой когда совпадают; двумя leg-tagged строками когда расходятся. Per-wire effective mode + submode + downgrade flags подняты на snapshot и active-pill; active-wire RTT — в weight cell.

- **REST control-plane CRUD для `[[outline.uplinks.fallbacks]]`**. Endpoint'ы `/control/uplinks` (POST create, PATCH update, GET list) теперь принимают массив `fallbacks: [...]` в JSON-payload. PATCH-семантика: присутствующий `fallbacks`-массив **заменяет** весь список (без per-entry merge'а); пустой `[]` очищает все fallback'и; пропущенное поле оставляет существующий список нетронутым. Реализация попутно фиксит латентный баг в `table_to_section` / `table_to_json`, который терял вложенные `ArrayOfTables`.

- **Drain warm-standby pool на active-wire transition с primary.** Новый `UplinkManager::drain_standby_pool(uplink_index, transport)` очищает deque, когда `active_wire` продвигается 0 → non-zero; и `record_wire_outcome`, и probe-driven `advance_active_wire_on_probe_failure` callers spawn'ят tokio-task для drain'а после детекта transition.

- **Active-wire RTT EWMA через Prometheus + Grafana.** Snapshot отдаёт per-wire effective mode + submode + downgrade flags; legacy proto-pill style сохранён на active chip'е.

- **HTTP(S) proxy install** — install-скрипт умеет качать release-артефакты через HTTP(S)-прокси.

### Изменено

- **Полировка hysteresis-стека.** Несколько итераций cap-clear и downgrade-гейтов: probe-failure downgrade chain ходит дальше первого шага; sticky walk-up + recovery cooldown останавливают осцилляцию H2↔configured; симметричное XHTTP recovery, walk-up и `min_failures`-descent gate; post-recovery grace обновляется на каждом probe-success'е с two-success streak'ом для clear'а cap'а; post-recovery grace гасит одиночный probe-fail сразу после clear'а recovery; post-recovery grace распространён на silent-fallback и runtime-triggers; active wire re-pin'ится на probe-failure после истечения pin'а.

### Исправлено

- Bootstrap-фолбэк теперь срабатывает, когда primary unhealthy с первого probe-цикла, а не ждёт первой провалившейся сессии.

## [1.4.3] - 2026-05-06

### Добавлено

- **`[outline.probe.http]` принимает список `urls = [...]` для ротации** в дополнение к одиночному `url = "..."`. Проба идёт по списку по одному URL за вызов (атомарный курсор на `HttpProbeConfig`, общий на все аплинки группы), поэтому подряд идущие probe-вызовы попадают в подряд идущие эндпоинты. Размазывание нагрузки по нескольким целям помогает заметить отказ конкретного сайта вместо того, чтобы маскировать его за единственной всегда-доступной точкой; warm-keepalive тики используют ту же ротацию. Можно задать любой из вариантов; если указаны оба, выигрывает `urls`.

- **Warm-probe keepalive loop**, который периодически освежает warm probe pipe — оптимизация переиспользования warm pipe для HTTP / DNS пробы не протухает молча под низкой нагрузкой. Авто-отключается, когда `probe.interval_secs` настолько тугой, что keepalive начал бы мешать обычному probe-циклу.

- **Переиспользование warm pipe между probe-циклами**: warm VLESS TCP probe pipe переиспользуется между HTTP probe-циклами, warm VLESS UDP transport — между DNS probe-циклами, и warm-probe слоты расширены на Shadowsocks-over-WebSocket аплинки. WS / UDP-WS sub-probe'ы скипаются, когда warm pipe уже доказывает liveness на том же аплинке.

- **Замеры warm-keepalive кормят `latency` / `rtt_ewma`** — сигнал скоринга не замирает на аплинках, где все пробы скипаются.

- **Справочная документация по структуре секции `[outline]` и балансировке нагрузки.** Новые разделы в `docs/UPLINK-CONFIGURATIONS.ru.md` (и в английском зеркале): «Структура секции `[outline]`» — описывает inline-стенограмму на один аплинк vs продакшен-форму с `[[outline.uplinks]]` + `[[uplink_group]]`, плюс enum `outline.transport` (`ws` / `shadowsocks` / `vless`); «Справочник балансировки нагрузки» — полная таблица полей по `[outline.load_balancing]` (legacy single-group поверхность) и эквивалентных полей под `[[uplink_group]]` (multi-group поверхность), с дефолтами, взятыми из `src/config/load/balancing.rs` и `crates/outline-transport/src/vless/udp_mux.rs`, плюс шпаргалка по `routing_scope` (`per_flow` / `per_uplink` / `global`) и матрица взаимодействия `mode` × `scope`. В `config.toml` теперь есть закомментированный шаблон `[outline.load_balancing]` и пример inline-`[outline]`-формы.

- **Документация per-group probe overrides** — `[[uplink_group]] probe.*` override'ы теперь задокументированы рядом с top-level `[outline.probe]` reference'ом.

### Изменено

- **Рефакторинг: control / uplinks_crud разнесён по ответственностям**; `crates/outline-transport/src/xhttp/mod.rs` разнесён на stream + h2 carriers; `vless.rs` разнесён на per-concern submodules; runtime-типы вынесены из `types.rs` в `outline-uplink`; chunk-0 / pinned-relay фазы в `src/proxy/tcp/connect/` переименованы с `phase1` / `phase2` в `chunk0_failover` / `pinned_relay`.

- **`install_test_tls_root` гейтится за фичу `test-tls`** — production-бинарь не таскает test-only TLS-override слот.

- **Graceful drain control / dashboard / metrics endpoints на shutdown**, чтобы in-flight HTTP-запросы завершались до выхода listener-task'а.

- **`spawn_route_watchers` отменяемый через guard** — route file-watchers теперь чисто стопаются на shutdown'е вместо утечки через process exit.

- **DnsCache ограничен approximate-LRU eviction'ом**, чтобы long-running процесс не аккумулировал DNS state без границ.

- **Удалён `migrate_state_dir`** — legacy state-directory migration helper из ранних релизов больше не нужен.

- **Dashboard добавил колонки weight и selection-score** в UI топологии, а колонка RTT теперь показывает per-transport EWMA вместо комбинированного selection score.

### Исправлено

- **`tcp/udp_rtt_ewma_ms` выставлены на topology endpoint** — дашборды, джоинящие `/control/topology` с Prometheus, больше не делают круг через `/snapshot` за score-сигналом.

## [1.4.2] - 2026-05-03

### Добавлено

- **Per-host диверсификация браузерного фингерпринта для WS / XHTTP dial-путей.** WS H1 / H2 / H3 upgrade'ы и XHTTP H1 / H2 / H3 GET / POST теперь могут подмешивать браузерные заголовки идентификации (`User-Agent`, `Accept`, `Accept-Language`, `Accept-Encoding`, семейство Sec-CH-UA и подходящий триплет `Sec-Fetch-{Site,Mode,Dest}` — `mode=websocket,dest=websocket` для WS-upgrade, `mode=cors,dest=empty` для XHTTP), чтобы простое DPI-правило вида «WS-upgrade без User-Agent» или «XHTTP POST без браузерных заголовков» больше не отделяло этот клиент от реального браузерного трафика. В пуле шесть представительных профилей — Chrome 130 (Windows + macOS), Firefox 130 (Windows + macOS), Safari 17 (macOS), Edge 130 (Windows) — подобраны так, чтобы под per-host-stable селектором ~⅔ пиров получили Chromium-идентичность, а оставшаяся ⅓ — Gecko / WebKit. Выбор детерминирован по `(host, port)` через `DefaultHasher` и фиксируется на всё время жизни процесса. Тумблер opt-in через новый top-level ключ `fingerprint_profile` в конфиге — принимает `"off"` / `"none"` / `"disabled"` (по умолчанию — wire shape байт-в-байт совпадает с pre-knob билдами), `"stable"` / `"per_host_stable"` / `"per-host-stable"` / `"per-host"` (одна идентичность на host:port) или `"random"` (свежий профиль на каждый dial). Сознательно НЕ покрыто (отдельная и более дорогая работа): TLS ClientHello / JA3 / JA4; порядок ALPN; фингерпринт HTTP/2 SETTINGS (Akamai / JA4H2); порядок transport-параметров QUIC. Подробности — в `docs/UPLINK-CONFIGURATIONS.ru.md` «Диверсификация браузерного фингерпринта».

- **Per-uplink override стратегии диверсификации браузерного фингерпринта.** Каждый блок `[[outline.uplinks]]` принимает опциональный ключ `fingerprint_profile` с теми же строковыми алиасами, что и top-level knob; если ключ опущен — наследуется top-level значение. Полезно, когда один аплинк должен оставаться байт-в-байт совместимым с xray-формой, а соседи на тот же `host:port` хотят PerHostStable — соседи больше не могут флипать профиль друг другу через глобал. Проводка едет через новый `tokio::task_local!` scope внутри `outline_transport::fingerprint_profile`: `with_strategy_override(strategy, fut)` гоняет `fut` так, что `select(url)` читает `strategy` вместо process-wide значения, и override естественно снимается на завершении `.await` (он не утекает в spawned post-handshake таски). Новый helper `outline_uplink::dial::dial_in_uplink_scope(uplink, fut)` оборачивает каждый transport dial site, у которого `UplinkConfig` в области видимости.

- **Inline-fallback `stream-one → packet-up` для XHTTP carrier'а и per-host submode-кэш (`xhttp_submode_cache`).** Когда dial `?mode=stream-one` падает на `xhttp_h2` / `xhttp_h3` уже после успешного carrier-handshake, dialer ретраит packet-up на **той же** TCP/TLS/h2 (или QUIC/h3) connection — без свежего handshake'а, просто другая форма запроса — и записывает фейл в per-host кэш по ключу destination `(host, port)`. Последующие dial'ы того же хоста заранее пропускают stream-one на `mode_downgrade_secs` и идут сразу в packet-up. Кэш — ортогональный sibling `xhttp_mode_cache`: независимый слот, TTL, декейка. Снимается раньше срока успешным stream-one dial'ом. Carrier `xhttp_h1` тихо приводит stream-one к packet-up на публичной точке входа `connect_xhttp` (h1 не умеет мультиплексировать streaming GET со streaming POST). Effective submode публикуется в snapshot (`tcp_xhttp_submode` / `udp_xhttp_submode` configured + `*_block_remaining_ms`) и рендерится на protocol-pill дашборда — `stream-one` показывается как `/S`, packet-up без суффикса, активный блок — как `/S↘P`.

- **`load_balancing.global_udp_strict_health`** (по умолчанию `false`) — управляет тем, гейтит ли UDP-здоровье (probe failures + UDP cooldown) активный аплинк вместе с TCP в `routing_scope = "global"`. Новый дефолт — мягкий: UDP-здоровье информативное, при TCP-здоровом active аплинк не выкидывается, даже если его UDP-проба флипает. Закрывает каскадный флап на нестабильных UDP-путях: каждый поднятый бэкап получал тот же UDP probe failure на том же сетевом пути и сам через секунды демотился. Knob уважается и в top-level `[load_balancing]`, и per-`[[uplink_group]]`. На `per_flow` / `per_uplink` не влияет.

- **`load_balancing.runtime_failure_window_secs`** (по умолчанию 60) — окно, в пределах которого считаются `consecutive_runtime_failures` для эскалации в health-flip в strict-global. Новая runtime-ошибка, пришедшая позже этого окна после предыдущей, сбрасывает стрик до 1 вместо инкремента. `0` — отключает затухание (старая семантика). Закрывает флаппинг-режим на малотрафиковых strict-global аплинках: две не связанные между собой транзиентные ошибки, разнесённые на минуты, складывались в health flip активного аплинка и форсили каскад failover'ов по всему пулу.

- **В UI топологии дашборда появились колонки weight + selection-score**, а операторы получают nag после старения fingerprint-пула за 180 дней.

### Исправлено

- **В `routing_scope = "global"` активный аплинк дёргался при штатном шуме RTT**, потому что `global_selection_score_latency` намеренно игнорировал затухающий `failure_penalty` для **всех** случаев. Для `auto_failback = true` это правильно: под нагрузкой EWMA активного раздувается, а у idle-бэкапа остаётся низкий probe-derived EWMA, и любой остаточный penalty делает active вечно «хуже» — weight-based failback не сработает. Для `auto_failback = false` (дефолт) это вредно: active и так sticky, пока он здоров, и selection score нужен только чтобы выбрать бэкап на failover или при первичном выборе. Игнорирование penalty там приводит к тому, что failover приземляется на бэкап, который сам только что фейлился, и через секунду фейлится снова. Починено гейтом по `auto_failback`: при `auto_failback = false` global selection score теперь использует полный `score_latency` (base EWMA + затухающий `failure_penalty`); при `auto_failback = true` остаётся raw EWMA.

- **XHTTP-аплинк (h1 / h2 / h3) зависал посреди передачи примерно после 32 сообщений на bulk-аплоадах.** Реализация `Sink` для `XhttpStream` всегда возвращала `Poll::Ready` из `poll_ready` и использовала `try_send` в `start_send` — как только per-session outbound-канал заполнялся, возвращался `Err("xhttp outgoing buffer full")`. Writer-task выше (TCP / WS) трактует любую ошибку Sink как фатальную и завершается, после чего data-канал тихо забивается у мёртвого consumer'а. Починено заворачиванием outbound `mpsc::Sender` в `tokio_util::sync::PollSender`: он резервирует permit асинхронно и стэшит waker, поэтому bulk-аплоады теперь получают настоящий back-pressure всю дорогу до вызывающего. В том же коммите подняты in-memory burst-окна XHTTP и WS data-путей с `32 / 8 / 64` до `256` (inbound, outbound, тело stream-one POST'а, data-канал WS-writer'а) — размер рассчитан на ~4 MB inflight при 16 KB SS2022-чанке. Оба writer-task'а теперь логируют wire-ошибку перед выходом вместо тихого `return`.

### Прочее

- `install.sh`: pruning старых бинарных бекапов, keep last 3.

## [1.4.1] - 2026-05-01

### Добавлено

- **VLESS-over-XHTTP `xhttp_h1` packet-up carrier и цепочка фолбека `xhttp_h3 → xhttp_h2 → xhttp_h1`.** Новый `vless_mode = "xhttp_h1"` напрямую выбирает HTTP/1.1 packet-up; существующие ветки `xhttp_h2` и `xhttp_h3` в `connect_transport` теперь проваливаются в него на провал h2-dial'а (вдобавок к существующему шагу `xhttp_h3 → xhttp_h2`). h1-carrier — фолбек последнего шанса для путей, режущих и QUIC, и ALPN h2; wire-URL остаётся идентичным (`<base>/<session>/<seq>`), поэтому тот же `xhttp_path_vless` listener обслуживает запросы. Так как HTTP/1.1 не умеет мультиплексировать стримящийся GET с одновременными POST'ами на одной connection, драйвер открывает **два** keep-alive сокета на сессию: один — под долгоживущий downlink GET (chunked response), второй — под строго сериализованные uplink POST'ы (без pipelining'а). Throughput ограничен round-trip-временем одного POST'а и ожидаемо заметно отстаёт от h2 под нагрузкой. Stream-one на h1 сознательно не реализован. VLESS share-link URI принимают `alpn=h1` / `alpn=http/1.1` для прямого пина h1-carrier'а. CLI / TOML / control-plane payload принимают `xhttp_h1` везде, где принимают `xhttp_h2` / `xhttp_h3`.

- **Per-uplink окно даунгрейда теперь покрывает XHTTP-семейство.** Раньше gate открывался только на провалах `WsH3` / `Quic`; теперь он также открывается на провалах `XhttpH3` и `XhttpH2`, поэтому последующие dial'ы пропускают doomed handshake до истечения TTL (по умолчанию 60 с, управляется `mode_downgrade_secs`). Реализация переключает `effective_tcp_mode` / `effective_udp_mode` с хардкоженного возврата `WsH2` на family-aware ceiling, хранящийся в новом поле `PerTransportStatus::mode_downgrade_capped_to` — `WsH3` / `Quic` коллапсируют в `WsH2`, `XhttpH3` — в `XhttpH2`, `XhttpH2` — в `XhttpH1`. Многоступенчатые XHTTP-даунгрейды (`XhttpH3 → XhttpH2 → XhttpH1`) сходятся за несколько dial'ов. Cap публикуется через `UplinkSnapshot::tcp_mode_capped_to` / `udp_mode_capped_to`.

- **Per-host XHTTP downgrade cache (`xhttp_mode_cache`)** — sibling существующего WS-only `ws_mode_cache`. Запоминает провалы `xhttp_h3` / `xhttp_h2` по ключу destination `(host, port)`, чтобы последующие dial'ы того же upstream из разных аплинков (например, несколько VLESS-UUID за одним CDN-хостом) пропускали doomed handshake, не ожидая, пока каждый аплинк наполнит своё per-uplink окно. У каждой цепочки свой слот — провал `WsH3` больше не идёт против XHTTP cap'а и наоборот. Шарит knob `mode_downgrade_secs` с WS-кэшем. Сбрасывается ранним `record_success` при meets-or-exceeds dial'е.

- **Тест** на парсинг XHTTP multi-value ALPN.

### Исправлено

- **XHTTP packet-up uplink теперь кладёт per-packet `seq` в URL path (`<base>/<session>/<seq>`)**, а не в заголовок `X-Xhttp-Seq`. Это `PlacementPath` по умолчанию у xray / sing-box — wire-формат, который шлёт любой другой VLESS-XHTTP клиент в природе. Header-форма была частной конвенцией, общей только с `outline-ss-rust`, и из-за неё сторонние клиенты (`happ`, `hiddify`, `v2rayN`) бесконечно таймаутили на любом маскираде, который фронтит и наш клиент, и обычный xray-инжес: их POST'ы на `<base>/<session>/<seq>` отдавали тихий 404, а наши шли на `<base>/<session>` + header. h2 и h3 carrier'ы теперь шлют одинаковую path-форму — wire идентичен ванильному xray. Совместимость на сервере: `outline-ss-rust v1.4.0+` принимает обе формы (path-based выигрывает, если присланы обе); старые серверы (`v1.3.1` и ниже) принимают только header-форму и должны быть подняты вместе с клиентом.

## [1.4.0] - 2026-04-30

### Добавлено

- **VLESS share-link URI стали полноценной формой конфига.** Одна строка `link = "vless://UUID@HOST:PORT?type=ws|xhttp|quic&...#NAME"` в `[[outline.uplinks]]` (или в top-level / inline `[outline]`) на этапе загрузки разворачивается в тройку `vless_id` / `vless_*_url` / `vless_mode`; `transport = "vless"` подставляется автоматически. Поддержанные query-параметры: `type` (`ws` / `xhttp` / `quic`), `security` (`none` / `tls` / `reality`), `path`, `alpn` (выбирает H1/H2/H3 вариант режима), `mode` (`packet-up` / `stream-one`, пробрасывается в XHTTP dial-URL), `encryption=none`. `flow=...`, `type=tcp|grpc|h2`, расходящиеся `sni=` / `host=` и любой `encryption`, кроме `none`, отклоняются. То же поле принимает CLI-флаг `--vless-link <URI>` (`OUTLINE_VLESS_LINK`) и REST-эндпойнты `/control/uplinks` (`link`, алиас `share_link`). См. docs/UPLINK-CONFIGURATIONS.ru.md «VLESS share-link URIs».

- **Клиент VLESS-over-XHTTP packet-up.** Доступны два режима:
  - `vless_mode = "xhttp_h2"` — XHTTP едет по одному shared TCP+TLS+h2 соединению на сессию.
  - `vless_mode = "xhttp_h3"` — XHTTP едет по QUIC + HTTP/3 (за feature-флагом `h3`). Парный листенер — тот же `xhttp_path_vless` в outline-ss-rust, доступный на QUIC-эндпоинте по ALPN `h3`.

  В обоих режимах на сессию генерируется случайный id и используется для обоих половин: driver открывает один long-lived GET (downlink) и пайплайнит POST'ы (uplink) с `X-Xhttp-Seq`. XHTTP-carrier выставлен через тот же `TransportStream` enum, что и WS-варианты. Новое поле uplink-конфига `vless_xhttp_url` несёт базовый URL — обязательно, когда `vless_mode` — один из `xhttp_*`. Полезен, когда WebSocket-апгрейд режется на сети (Cloudflare-style CDN, captive-portal middleboxes).

  Поверх того же dial path работают три дополнительные возможности:
    1. **Fallback `xhttp_h3 → xhttp_h2`.** При провале QUIC + HTTP/3 dial'а (handshake timeout, ALPN mismatch, заблокированный UDP) dispatcher прозрачно повторяет через h2, неся тот же `resume_request`, открывает существующее `mode-downgrade` окно — следующие dial'ы пропускают h3 до восстановления — и сообщает изначальный режим через `TransportStream::downgraded_from()`.
    2. **Cross-transport resumption** через XHTTP carrier. Dial рекламирует `X-Outline-Resume-Capable: 1` и (если есть) `X-Outline-Resume: <hex>`, синхронно ждёт response headers — токен `X-Outline-Session`, выданный сервером, забирается до старта drain'а.
    3. **Stream-one carrier** выбирается чисто из URL-а dial'а. Прописываешь `?mode=stream-one` в `vless_xhttp_url` — и пара GET+POST заменяется на один bidirectional POST: request body несёт uplink, response body несёт downlink. Никакого нового конфиг-поля, никакого нового mode-варианта — `XhttpSubmode::from_url(&Url)` читает query во время dial'а. На h3 stream разделяется через `RequestStream::split` — uplink и downlink половинки на отдельных tasks.

- **`outline_transport::install_test_tls_root(CertificateDer)`** — тест-only ручка, пинающая кастомный самоподписанный root для XHTTP h2 / h3 dial-путей. Override-слот это `RwLock<Option<…>>` с дефолтом `None`, так что продакшен-вызывающие сохраняют webpki-поведение с одним лишним чтением на dial. Целевой потребитель — cross-repo e2e-тест в `outline-ss-rust`, который поднимает in-process самоподписанный сервер и дёргает его через обычный `connect_transport`.

### Изменено

- **Ломающее переименование в конфиге / CLI / API.** Поля «режим транспорта» теперь везде называются `tcp_mode` / `udp_mode` / `vless_mode` — TOML (`tcp_mode = "h2"`), CLI (`--tcp-mode`, `--udp-mode`, `--vless-mode`), переменные окружения (`OUTLINE_TCP_MODE`, `OUTLINE_UDP_MODE`, `OUTLINE_VLESS_MODE`), JSON control-плана (`/control/topology`, `/control/uplinks`), payload дашборда и Rust API (`UplinkConfig::tcp_mode`, `effective_tcp_mode()`). Старые `*_ws_mode` имена удалены без алиасов — существующие TOML-файлы и скрипты придётся обновить вручную. Причина: после появления `xhttp_h2` / `xhttp_h3` / `quic`, которые уже не привязаны к WebSocket, инфикс `_ws_` стал вводить в заблуждение.

- **Тест-обход для процесс-вайдных кэшей QUIC-эндпоинтов.** Когда выставлен тестовый override (т.е. `install_test_tls_root` был вызван), `H3_CLIENT_ENDPOINT_V4` / `_V6` и raw-QUIC `QUIC_CLIENT_ENDPOINT_V4` / `_V6` пропускают кэш и биндят свежий endpoint на каждый dial. Каждый `#[tokio::test]` крутится в своём runtime; driver-task закэшированного endpoint'а привязан к runtime, который первым попал в кэш, и умирает сразу как только тот тест завершается — следующий тест получает `endpoint driver future was dropped`. Продакшен-поведение не меняется.

- **Панель дашборда теперь корректно рисует даунгрейд `xhttp_h3` → `xhttp_h2`** (раньше H3/QUIC-индикация срабатывала только на старых коротких именах режимов, и xhttp-аплинки визуально «зависали» на сконфигурированном режиме). VLESS-аплинки также публикуют `tcp_mode` / `udp_mode` для `xhttp_h2` / `xhttp_h3` — раньше поле выставлялось только при наличии `vless_ws_url`, поэтому чисто-XHTTP аплинк отображался дефолтным «VLESS/WS/H1».

### Исправлено

- **WebSocket-over-h2 диалер слал `:path = //{ws_path}`** потому что `H2Dialer::open_on` форматировал `target_uri` как `format!("{scheme}://{auth}/{path}")`, а `websocket_path` уже возвращает ведущий `/`. Серверные axum-роутеры отвергают двойной слэш с 404, что годами маскировалось h1-фолбэком в WS-h2 диспетчере (tungstenite нормализует слэш по дороге на провод). h2-путь теперь конкатенирует без повторного `/`. Виден только на h2-only серверах (RFC 8441 стеки без h1) и всплыл благодаря cross-repo h3→h2 fallback тесту в `outline-ss-rust`.

- **XHTTP h3 stream-one закрывал QUIC-соединение с `H3_NO_ERROR`** ещё до того, как через него пройдёт хоть один прикладной байт: единственный `SendRequest` уезжал в `open_h3_stream_one`, дропался на return, а `SendRequest::drop` в крейте h3 делает graceful-close, как только `sender_count` падает в ноль. Зеркалит паттерн packet-up — клонируем перед open-хелпером, оригинал держим живым в driver-task'е. Тот же коммит переносит quinn `Endpoint` в driver-task (прежний `let _endpoint_guard = endpoint;` держал его живым только в скоупе функции, не на время сессии).

- **Редактор аплинков в дашборде теперь отдаёт всю XHTTP-тройку** (`vless_xhttp_url`, `vless_mode`, `vless_id`), так что XHTTP-аплинки можно создавать и редактировать из UI без 400 «unknown field».

- **Пробы и refill standby для VLESS теперь идут через тот же хелпер `vless_dial_url()`**, что и live data path, — пробы, выбирающие XHTTP carrier, больше не сваливаются на `vless_ws_url`, когда настроен только `vless_xhttp_url`.

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
