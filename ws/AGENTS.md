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

- По умолчанию общайтесь с пользователем на русском языке.
- Пишите кратко и по делу, но не теряйте важные технические детали.
- Имена файлов, команд, переменных, протоколов, feature flags и публичных API
  оставляйте в исходном написании.
- Если пользователь явно попросил другой язык или готовый англоязычный текст для
  документации, коммита или релиза, следуйте этому запросу.

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
  связка с routing.
- `src/http/`: metrics endpoint, control plane, встроенный dashboard и HTTP
  serving helpers.
- `crates/outline-transport/`: WebSocket, HTTP/2, HTTP/3, raw QUIC, VLESS,
  XHTTP, direct Shadowsocks transport logic, resume caches и HTTP-family dial
  planning в `dial_plan.rs`.
- `crates/outline-uplink/`: выбор uplink'ов, probes, standby pools, penalties,
  sticky routing, fallback wires и состояние manager'а.
- `crates/outline-tun/`: TUN UDP/TCP relay engines, разбор пакетов, TCP state
  machine, fragmentation и ICMP handling.
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
влияют на uplink setup или runtime operations. Держите примеры
синхронизированными с TOML schema и tests.
