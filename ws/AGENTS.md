# AGENTS.md

## Обзор проекта

`outline-ws-rust` — Rust 2024 workspace для production-ориентированного прокси.
Верхнеуровневый пакет собирает бинарь `outline-ws-rust`, принимает локальный
SOCKS5 и опциональный TUN-трафик и отправляет его через Outline-совместимые
WebSocket-транспорты, raw QUIC, direct Shadowsocks или VLESS-транспорты.

Этот репозиторий чувствителен к производительности и эксплуатационному
поведению. Считайте transport fallback, совместимость конфигурации, метрики и
feature gates для router-сборок частью публичного поведения.

## Общение

- По умолчанию общайтесь с пользователем на русском языке и все рассуждения веди на нем же.
- Пишите кратко и по делу, но не теряйте важные технические детали.
- Имена файлов, команд, переменных, протоколов, feature flags и публичных API
  оставляйте в исходном написании.
- Если пользователь явно попросил другой язык или готовый англоязычный текст для
  документации, коммита или релиза, следуйте этому запросу.

## Локальный контекст

- Не используйте `.claude/`, `.idea/` и `*.iml` как источник проектного
  контекста и не просматривайте их без явной просьбы пользователя.
- Эти пути относятся к локальным настройкам инструментов и не должны влиять на
  архитектурные решения, стиль кода или итоговые изменения.

## Структура репозитория

- `src/main.rs` и `src/lib.rs`: верхнеуровневые entry point'ы бинаря и
  библиотеки.
- `src/bootstrap/`: запуск приложения, binding listener'ов и persisted state
  store.
- `src/config/`: CLI/config schema, загрузка, совместимость, валидация и тесты
  миграций.
- `src/config/load/uplinks/`: загрузка uplink'ов, включая source precedence,
  credentials, wire-shape validation и fallback resolution.
- `src/proxy/`: SOCKS5 TCP/UDP ingress, dispatch, direct paths, failover и
  связка с routing. Phased TCP dial machinery живёт в
  `src/proxy/tcp/connect/` и разнесена по модулям `failover_step`,
  `first_chunk`, `pinned_relay`, `chunk0_failover`, `replay`, `retry`,
  `attribution`, `ring_buffer`.
- `src/http/`: metrics endpoint, control plane, встроенный dashboard и HTTP
  serving helpers.
- `crates/outline-transport/`: WebSocket, HTTP/2, HTTP/3, raw QUIC, VLESS,
  XHTTP, direct Shadowsocks transport logic, resume caches и HTTP-family dial
  planning в `dial_plan.rs`.
- `crates/outline-uplink/`: выбор uplink'ов, probes, standby pools, penalties,
  sticky routing, fallback wires и состояние manager'а. Active-wire / shuffle
  state живёт в `manager/active_wire.rs`, carrier descent — в
  `manager/mode_downgrade.rs`, per-wire failure attribution — в
  `manager/failures.rs`, watch-канал активного uplink'а — в `manager/state.rs`
  и `manager/candidates.rs`.
- `crates/outline-tun/`: TUN UDP/TCP relay engines, разбор пакетов, TCP state
  machine, fragmentation и ICMP handling. ICMP PTB / Frag-Needed синтез на
  oversize-drop пути живёт в `crates/outline-tun/src/icmp.rs` с pure-policy
  helpers под unit-тесты.
- `crates/outline-net/`: protocol-agnostic socket helpers (TCP connect с
  fwmark/keepalive, UDP bind с buffer sizing, inbound tuning). Не знает ни
  про Shadowsocks, ни про WebSocket — transport-специфика навешивается
  поверх вызывающим crate'ом.
- `crates/outline-metrics/`: регистрация Prometheus плюс snapshot/session data
  types. Поведение stub-реализации должно компилироваться при отключенных
  metrics.
- `crates/outline-routing/`: CIDR routing table и routing config primitives.
- `crates/socks5-proto/`: SOCKS5 handshake, target, UDP и reassembly helpers.
- `crates/shadowsocks-crypto/` и `crates/outline-ss2022/`: Shadowsocks crypto и
  helpers для 2022 framing.
- `tests/`: интеграционные тесты. Real upstream tests включаются явно через env
  vars.
- `docs/`, `README.md`, `README.ru.md`: пользовательское поведение и config docs.
- `config.toml`, `config-router.toml`: примеры server/router конфигураций.
- `vendor/h3`: patched vendored dependency. При изменении vendored patches
  обновляйте `PATCHES.md`.
- `vendor/sockudo-ws`: vendored path dependency, явно перечисленный в workspace
  из-за in-tree path dependency. Относитесь к vendor-коду как к внешнему
  upstream-коду: не меняйте его без явной причины и следите, чтобы workspace
  checks не превращали vendor в основную область рефакторинга.

## Команды разработки

Полезные локальные проверки:

```bash
cargo fmt --all
cargo check
cargo test
```

Если изменение затрагивает feature gates, router builds или опциональный код
metrics/dashboard/TUN/H3, дополнительно проверьте stripped router-конфигурацию:

```bash
cargo check --no-default-features --features router
```

Для изменений в transport, metrics, control/dashboard или workspace layout
полезны более узкие проверки:

```bash
cargo check -p outline-ws-rust --all-targets
cargo check -p outline-transport --all-targets
cargo check -p outline-transport --features metrics --all-targets
```

Если `cargo check --workspace --all-targets` падает на явно устаревших
incremental artifacts, сначала перепроверьте в чистом target-dir, а уже потом
диагностируйте исходники:

```bash
cargo check --workspace --all-targets --target-dir /private/tmp/outline-ws-rust-check-target
```

Точечные интеграционные тесты:

```bash
cargo test --test group_routing -- --nocapture
cargo test --test standby_validation -- --nocapture
```

Ручные real-upstream тесты требуют credentials и намеренно включаются только
явно:

```bash
RUN_REAL_SERVER_H2=1 \
OUTLINE_TCP_WS_URL='wss://example.com/SECRET/tcp' \
OUTLINE_UDP_WS_URL='wss://example.com/SECRET/udp' \
SHADOWSOCKS_PASSWORD='Secret0' \
cargo test --test real_server_h2 -- --nocapture

RUN_REAL_SERVER_H3=1 \
OUTLINE_TCP_WS_URL='wss://example.com/SECRET/tcp' \
OUTLINE_UDP_WS_URL='wss://example.com/SECRET/udp' \
SHADOWSOCKS_PASSWORD='Secret0' \
cargo test --test real_server_h3 -- --nocapture
```

Алиасы для release/cross-build находятся в `.cargo/config.toml` и используют
`cargo-zigbuild`, например:

```bash
cargo release-musl-x86_64
cargo release-musl-aarch64
cargo release-router-musl-armv7
```

## Правила разработки

- Сначала следуйте существующим границам модулей и локальным паттернам; новые
  абстракции добавляйте только при реальной необходимости.
- Держите async paths неблокирующими. Аккуратно работайте с locks,
  backpressure, retry loops, standby pools и горячими TCP/UDP relay paths.
- Сохраняйте transport fallback semantics:
  - `h3 -> h2 -> http1`
  - `quic -> h2 -> http1`
  - `xhttp_h3 -> xhttp_h2 -> xhttp_h1`
  - per-uplink fallback wires через `[[outline.uplinks.fallbacks]]`
- Сохраняйте cross-transport resume behavior (`X-Outline-Resume-Capable`,
  `X-Outline-Session`, `X-Outline-Resume`), если изменение явно не нацелено на
  этот механизм.
- При добавлении новых failure modes держите error classification согласованной
  между `src/error_class.rs`, `outline-transport`, `outline-uplink` и TUN-кодом.
- При добавлении config fields обновляйте schema/types/loaders, compatibility
  или migration code при необходимости, tests, примеры в `config.toml`, а также
  английскую и русскую документацию, если option видим пользователю.
- Для пользовательских TOML-секций предпочитайте `#[serde(deny_unknown_fields)]`
  или явно документированный compatibility path. Молчаливое игнорирование
  неизвестных полей опасно для production config.
- Держите control/dashboard request bodies ограниченными по размеру. Не
  используйте `collect().await.to_bytes()` на входящих HTTP body без лимита;
  выносите чтение JSON/body в общий limited helper.
- Для записи persisted state и live config используйте durable atomic write:
  sibling temp file, restrictive permissions для файлов с secrets, `sync_all`
  перед `rename` и, где уместно, синхронизацию parent directory.
- Синхронизируйте control CRUD, `/control/apply`, TOML schema и документацию.
  Если код пишет `[[outline.uplinks]]`, комментарии и README не должны ссылаться
  на старые формы вроде `[[uplink_group.uplinks]]` или обещать обязательный
  restart, когда есть hot apply.
- Держите router builds маленькими. Не подтягивайте случайно H3, Prometheus
  metrics, dashboard UI, `env-filter`, multithreaded runtime, mimalloc или TUN
  code в `--no-default-features --features router`.
- Опциональный код закрывайте существующими feature flags:
  `h3`, `metrics`, `control`, `dashboard`, `env-filter`, `multi-thread`,
  `mimalloc`, `tun` и `router`.
- Не добавляйте в коммиты secrets, реальные proxy URLs, passwords, tokens,
  generated logs или build artifacts.

## Архитектурные зоны внимания

- `src/bootstrap/` должен оставаться composition root. Не переносите туда
  бизнес-логику выбора uplink'ов, transport dialing, routing или HTTP handlers.
- `src/config/load/uplinks/` намеренно разделен по ответственностям:
  `source_precedence`, `credentials`, `wire_shape` и `fallback_resolution`.
  При расширении держите новые правила рядом с соответствующим модулем, а
  `mod.rs` оставляйте тонким orchestration layer.
- `crates/outline-transport/src/lib.rs` является публичным facade; держите его
  тонким. HTTP-family dial planning живет в
  `crates/outline-transport/src/dial_plan.rs` через `TransportDialOptions`,
  `DialNetworkOptions`, `DialResumeOptions` и `connect_transport`. Новые
  transport branches, downgrade planning и resume/fallback plumbing добавляйте
  рядом с этим планировщиком, не возвращая длинные positional args в facade.
- Горячие TCP/UDP/TUN paths должны избегать лишних allocations, глобальных locks
  и O(n) scans. Если линейный обход остается, он должен быть ограничен холодным
  путем, лимитом или понятным backpressure.
- Метрики, tracing и dashboard helpers не должны менять поведение relay paths
  при выключенных feature flags. Stub-реализации обязаны компилироваться и
  сохранять публичные типы там, где они используются другими crates.
- TLS cert-expiry check: проверка срока сертификатов endpoint'ов аплинков
  закрыта feature `cert-check`. Низкоуровневый хелпер (accept-any TLS
  handshake + X.509 `notAfter` парсер на `x509-cert`) живёт в
  `crates/outline-transport/src/cert_check.rs`; периодический луп (раз в 6 ч,
  плюс старт и reload) — в `crates/outline-uplink/src/manager/cert_check.rs`,
  пишет `UplinkStatus.cert_not_after_unix_ms`. Значение течёт через
  `UplinkSnapshot` в control-топологию, gauge
  `outline_ws_rust_uplink_cert_expiry_timestamp_seconds` и dashboard-чип.
  `cert-check` включается транзитивно из `metrics` и top-level `dashboard`, но
  НЕ из `control`/`router` — `x509-cert` не должен попадать в
  `--no-default-features --features router` (проверка:
  `cargo tree -e features --no-default-features --features router | grep x509`
  должна быть пустой). Это отдельный путь от data-path пробы
  `[outline.probe.tls]`, которая валидирует внешний SNI через туннель.
- Active-wire shuffle живёт на двух осях: `shuffle_wires` переставляет цепочку
  `[primary, fallbacks…]` один раз при загрузке конфига (и обязан давать
  collision-free перестановки внутри одной группы — см.
  `shuffle_wire_chains_per_group`, применяется и в legacy `load_uplinks`, и в
  новом `load_groups`), а `shuffle_timer` периодически рероллит `active_wire`
  для обоих транспортов. При наличии `shuffle_timer` probe-driven early-failback
  в `record_transport_success` должен быть подавлен, иначе следующий успех
  primary-пробы немедленно отменит реролл. Любая модификация active-wire,
  mode_downgrade или probe outcome машинерии обязана сохранять эти
  инварианты и обновлять JSON snapshot / dashboard round state соответственно.
- Per-wire failure attribution: failures, зафиксированные на не-активном wire,
  трактуются как session-local churn и не должны накапливать penalty / cooldown
  на родительском uplink'е. TCP redial (mid-session retry, chunk-0 same-uplink
  recovery) обязан дайлить тот wire, который менеджер сейчас считает активным,
  а не безусловно primary. Расширяя retry / failover / pinned-relay код,
  пропускайте новые точки через `report_runtime_failure_for_wire` и
  `record_wire_outcome`, single-wire uplink'и сохраняют legacy bit-for-bit
  поведение.
- Strict-mode active-uplink switch: в `active_passive` манёвр manual control /
  probe-driven failover, который сдвигает активный uplink с in-flight сессии,
  обязан рвать TCP-сессию SOCKS5 с RST (`SO_LINGER {l_onoff=1, l_linger=0}`) и
  будить UDP downlink через `subscribe_active_uplinks` watch. Это зеркалит
  TUN strict-mode и должно сохраняться при любых правках `pinned_relay`,
  `udp::group::run_group_downlink` или `set_active_uplink_index_for_transport`.
- Carrier-downgrade opt-out: при `[[outline.uplinks]] carrier_downgrade = false`
  `extend_mode_downgrade` обязан немедленно возвращаться, а
  `wire_is_at_carrier_floor` — всегда репортить «на полу». Это намеренно
  сворачивает вертикальный карьер каскад в прямую wire→wire ротацию (полезно в
  паре с `shuffle_wires` при DPI, который дропает весь upstream независимо от
  HTTP-версии); не вводите обходных путей, восстанавливающих descent при
  выключенном флаге.
- TUN PMTUD: oversize UDP drop на TUN-путях синтезирует ICMPv4 Fragmentation
  Needed / ICMPv6 Packet Too Big с per-flow throttle (1 PTB/с) и обязан
  подавлять PTB ниже family-specific QUIC Initial minimum (1200 для v4,
  1280 для v6), иначе compliant QUIC-стек отключит QUIC для destination'а.
  Operator-override — `tun.pmtud_emit_below_quic_initial = true` (default
  `false`); политику суппрессии держите в pure helper'ах под unit-тестами,
  а не в async путях. Протокольные клампы 576/1280 в самих ICMP-билдерах
  остаются неизменными.
- TUN ICMP echo health-gate: per-group флаг `tun_suppress_icmp_reply_when_down`
  (поле `LoadBalancingConfig`, default `false`) подавляет локальный echo reply
  в `tun_read_loop`, когда destination пакета резолвится в группу без единого
  здорового uplink'а — критерий тот же `has_any_healthy` по обоим транспортам,
  что и у route-fallback решения в `TunRouting::materialize_target`; держите их
  согласованными. Gate (`echo_reply_suppressed_for_down_group` в `engine.rs`)
  срабатывает только на `TunRoute::Group`: Direct/Drop-маршруты и пакеты без
  парсибельного destination (`icmp_echo_destination`, pure-хелпер в `icmp.rs`
  под unit-тестами) отвечаются как раньше. Подавленные запросы считаются как
  `outcome="icmp_reply_suppressed"` на `outline_ws_rust_tun_packets_total`.
- Group-level bypass: per-group флаг `bypass_when_down` (поле
  `LoadBalancingConfig`, default `false`) диспатчит трафик упавшей группы в
  `direct` (с `direct_fwmark`) на обоих ingress. Критерий «группа лежит»
  наследует route-fallback каждого пути: per-transport `has_any_healthy` на
  SOCKS5 (`apply_fallback_strategy` в `dispatcher.rs`, плюс no-router ветки
  `resolve_dispatch` / `resolve_udp_packet_route`), оба транспорта на TUN
  (`materialize_target` / `group_bypasses_when_down` в `routing.rs`). Явный
  route-fallback выигрывает; подменённый fallback-таргет переоценивается на
  bypass ровно на один уровень (`bypass_substituted_group` ≡ TUN-рекурсия) —
  не вводите цепочки глубже. SOCKS5 UDP: `direct_udp_possible` обязан
  преаллоцировать direct-сокет, когда хоть одна группа opted-in, иначе
  bypass-датаграммы молча дропаются в `send_udp_direct`. Включённый bypass
  намеренно «гасит» ICMP-gate (маршрут становится `TunRoute::Direct`, пинги
  отвечаются — путь жив); это контрактное поведение под тестом
  `replies_when_down_group_bypasses_to_direct`. Наблюдаемость живёт на
  снапшоте: `UplinkManagerSnapshot.{bypass_when_down,bypass_active_tcp,
  bypass_active_udp}` считаются в `manager/snapshot.rs` тем же
  `has_any_healthy`, что и dispatch (не дублируйте критерий в потребителях);
  оттуда поле течёт в gauge `outline_ws_rust_group_bypass_active{group,
  transport}` (публикуется ТОЛЬКО для opted-in групп — отсутствие серии =
  опция выключена), в `/control/topology` (групповые поля скрываются при
  `false` через `skip_serializing_if`) и в чип `groupBypassChip` в
  `dashboard.html`; в `grafana/outline-ws-rust-dashboard.json` — панели
  Direct Bypass (id 230/231) в секции Routing Policy.
- TUN IPsec bypass: `tun.ipsec_bypass = true` short-circuits UDP/{500,4500} в
  `TunRoute::Direct` ещё до policy-routing, переиспользуя `direct_fwmark` для
  выхода из TUN routing loop. Не оптимизируйте этот fast-path так, чтобы он
  скрывал отсутствие `direct_fwmark` на Linux — стартовое предупреждение об
  этой комбинации должно сохраняться.
- TUN direct egress без DNS: TUN ingress всегда несёт литеральный IP-таргет
  (`wire::ip_to_target` никогда не возвращает `Domain`), поэтому ветка
  `TunRoute::Direct` в `spawn_upstream_connect` обязана строить `SocketAddr`
  синхронно через `wire::target_socket_addr` и НЕ прогонять таргет через
  `resolve_host_with_preference`. Ресолв уже готового IP стрингификацией в
  `"<ip>:<port>"` упирался в дефолтный resolver-таймаут (glibc `RES_TIMEOUT`
  5 с) и добавлял ~5 с латентности на каждый direct-flow (видно на TUN, но не
  на SOCKS5 `relay_tcp_direct`, который таргет-IP не ресолвит). `Domain`-таргет
  на этом пути — невозможен; маппер отдаёт `None`, вызывающий рвёт flow RST'ом.
  Маппинг держите pure и под unit-тестами в `wire/tests`. Симметрично:
  SOCKS5 (`src/proxy/tcp/direct.rs`) и TUN direct обязаны оставаться
  согласованными — IP-таргеты не ресолвятся ни на одном из путей.
- Два параллельных ingress, общая routing-логика: SOCKS5 (`src/proxy/`) и TUN
  (`crates/outline-tun/`) — независимые точки входа, но сходятся на одном
  `dispatch.resolve(target)` и на трёх исходах (`direct` / tunneled-`group` /
  `drop`). Различие ingress по своей природе: SOCKS5 принимает уже
  терминированный TCP (target может быть `Domain`), TUN сам терминирует TCP в
  userspace и всегда несёт литеральный IP-таргет. Меняя поведение direct или
  tunneled пути, держите оба ingress согласованными по семантике (resolve,
  failover, strict-mode teardown, backpressure) — расхождение между ними
  проявляется как баг «видно на TUN, не видно на SOCKS5» (или наоборот). Для
  пер-ingress-специфики используйте существующие развилки (`TunRoute` против
  `Route`), не дублируя routing-решение.
- SS-UDP-over-WS liveness, H3-aware: на H3-карьере UDP datagram-канал едет по
  QUIC-стриму, у которого уже есть keep_alive (10 с) и `max_idle_timeout`.
  Поэтому `UdpWsTransport::from_websocket` на H3 (`TransportStream::is_h3()`,
  чистый хелпер `ws_datagram_liveness`) отключает и WS read-idle watchdog
  (`WS_READ_IDLE_TIMEOUT`, 300 с), и клиентский keepalive Ping
  (`udp_ws_keepalive_secs`), полагаясь на живость QUIC-слоя. Не возвращайте
  WS-Ping/watchdog на H3: сервер не может доставить reactive Pong на тихом
  H3-datagram-стриме, не рискуя connection-level `H3_INTERNAL_ERROR`, поэтому
  доказывать живость по входящим WS-фреймам = спурьёзно рвать здоровую сессию.
  На h1/h2 общего QUIC keep_alive нет — watchdog и Ping там сохраняются.
  Серверная половина фикса (`outline-ss-rust`) дренит застрявший reactive Pong
  таймерным `WsSocket::flush`, а не шлёт server-originated Ping. Тот же выбор
  несущей вынесен в `frame_io_ws::carrier_liveness` и применяется на всех
  WS-over-* путях: SS-UDP / VLESS-UDP / VLESS-TCP (через `carrier_liveness`),
  а SS-TCP-over-WS reader снимает 300-секундный watchdog на H3 по `diag.mode`
  (`tcp_transport/reader/transport.rs`). Не возвращай WS-watchdog/Ping на H3 ни
  на одном из них — H3/QUIC keepalive не виден как WS-фрейм, и сервер на H3 не
  пингует, так что watchdog мог бы только ложно сработать на тихой живой сессии.

## Форматирование

Проект использует `rustfmt.toml`: ширина 100 колонок, Unix newlines, отступы по
четыре пробела, reordered imports/modules и Rust 2021 rustfmt settings, хотя
crate edition — Rust 2024. Перед завершением Rust-изменений запускайте
`cargo fmt --all`.
- `cargo fmt --all` может затронуть vendored path dependencies. Не включайте
  format-only изменения в `vendor/*` в обычные коммиты; после форматирования
  проверяйте `git status --short vendor` и откатывайте такие изменения, если
  vendor-код не был явной целью задачи.

## Ожидания по документации

Пользовательское поведение обычно должно отражаться и в `README.md`, и в
`README.ru.md`. Детали transport/config относятся в
`docs/UPLINK-CONFIGURATIONS.md` и `docs/UPLINK-CONFIGURATIONS.ru.md`, если они
влияют на uplink setup или runtime operations. Поведение TUN PMTUD / ICMP PTB
синтеза и связанные operator-override'ы документируются в `docs/TUN-PMTUD.md`
и `docs/TUN-PMTUD.ru.md`. Держите примеры синхронизированными с TOML schema
и tests.
- Обновляйте `AGENTS.md`, когда меняются рабочие соглашения, структура проекта,
  рекомендуемые команды, feature gates, архитектурные зоны ответственности или
  другие инструкции, которые должны сохраняться между задачами.
