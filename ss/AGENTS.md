# AGENTS.md

## Область действия

Эти инструкции действуют на весь репозиторий.

## Кратко о проекте

`outline-ss-rust` - production-ориентированный Rust-сервер data plane для
Shadowsocks AEAD и VLESS поверх WebSocket, XHTTP, HTTP/3 и raw QUIC. Это не
реализация Outline management API.

Крейт использует Rust edition 2024, Tokio, axum, hyper, quinn/h3, rustls,
Prometheus metrics и локально пропатченные копии `h3` и `sockudo-ws`.

Важные пути:

- `src/lib.rs`: запуск, tracing, выбор режима работы и настройка Tokio runtime.
- `src/main.rs`: глобальный allocator бинарника. Не включай allocator features у
  зависимостей, если это не является осознанным изменением.
- `src/config/`: загрузка CLI/env/TOML-конфига, миграции, валидация, генерация
  access key и tuning profiles.
- `src/server/`: listeners, runtime services, routing, shutdown, fallbacks,
  session resumption, control/dashboard servers и transport handlers.
- `src/server/transport/`: WebSocket, XHTTP, raw QUIC, VLESS transport, fallback,
  SNI fallback и proxy-protocol plumbing.
- `src/server/shadowsocks/`: plain Shadowsocks TCP/UDP listeners.
- `src/crypto/`: Shadowsocks AEAD stream/UDP primitives и логика
  replay/session cache.
- `src/protocol/`: target-address helpers для Shadowsocks и parsing/encoding для
  VLESS/mux.
- `src/outbound.rs`: upstream connect/bind behavior, включая выбор IPv6 source
  address.
- `src/metrics/`: Prometheus metrics и render/export behavior.
- `vendor/h3` и `vendor/sockudo-ws`: пропатченные крейты, подключенные через
  `[patch.crates-io]`; не считай их одноразовым generated code.

## Рабочие правила

- Начинай с `git status --short`. Сохраняй пользовательские изменения и
  несвязанные локальные файлы. В частности, не чисти `target/`, `.claude/` и IDE
  files без явной просьбы.
- Не просматривай и не анализируй локальные agent/IDE артефакты `.claude/`,
  `.idea/` и `*.iml`, если пользователь явно не попросил работать именно с ними.
- С владельцем проекта общайся по-русски по умолчанию  и все рассуждения веди на нем же. Символы кода, команды,
  логи, имена протоколов и существующие англоязычные артефакты оставляй на их
  естественном языке, если пользователь не попросил перевод.
- Держи изменения сфокусированными. В проекте много protocol-sensitive behavior,
  поэтому избегай попутных рефакторингов в transport, crypto, config parsing и
  metrics.
- Предпочитай существующие module patterns и helpers новым абстракциям.
- Комментарии держи редкими и практичными. Добавляй их только там, где protocol
  state, security behavior или async control flow иначе легко прочитать неверно.
- Не логируй passwords, PSK, generated access keys, bearer tokens, raw UUIDs,
  peer secrets или полные client-supplied paths/tokens. Держи metrics labels
  low-cardinality; избегай target addresses, peer IPs, session IDs и
  произвольных request paths.
- Если меняется user-facing config key, default, transport mode или поведение,
  синхронно обновляй соответствующий код, `config.toml`, `README.md`,
  `README.ru.md` и docs там, где это применимо.
- Когда трогаешь user-facing документацию, которая уже существует на английском
  и русском, поддерживай обе версии согласованными.
- Обновляй `AGENTS.md`, когда в ходе работы появляются новые устойчивые правила,
  ограничения или проектные соглашения, полезные будущим агентам.
- Массовое форматирование выполняй для основного package
  (`cargo fmt -p outline-ss-rust`), но не форматируй `vendor/*` без явной
  просьбы. Vendored source должен сохранять upstream/minimal diff стиль, если
  задача не меняет его поведение.

## Архитектурные guardrails

- Держи startup validation и runtime/control-plane validation feature-equivalent.
  Если меняешь user invariants, transport eligibility, duplicate checks или
  defaults, синхронно проверяй `src/config/validation.rs`,
  `src/server/control/manager.rs`, control handlers, dashboard и tests.
- Control-plane мутации должны быть согласованы с persistent state. Не публикуй
  новые route/auth snapshots в runtime до того, как понятна судьба сохранения на
  диск, если API сообщает клиенту успех/ошибку как source of truth. Если нужна
  другая семантика, зафиксируй ее явно и покрой тестом.
- Добавление нового transport/path/user field не считается завершенным, пока не
  обновлены все поверхности: config parsing, validation, runtime route maps, H3
  path registry, control API, dashboard UI, access-key generation, metrics и
  документация, где применимо.
- H3 path registry сейчас фактически startup-time registry. Control-plane может
  управлять пользователями только на уже известных путях. Не обещай полноценный
  hot-add новых H3/WS/XHTTP paths без изменения этой модели.
- Dashboard должен отображать и сохранять те же user-facing поля, что и control
  API. Избегай backend-only полей, которые пользователь может создать через API,
  но не увидеть или не изменить в UI.
- Будь осторожен с tuning defaults и resource caps. Не повышай дефолтные окна,
  channel capacities, connection/stream limits, NAT/session limits или timeout
  behavior без оценки memory envelope и DoS-поверхности.
- UDP/NAT/session-resumption изменения должны сохранять bounded behavior:
  idle eviction, replay protection, cancellation, per-user/global limits и
  shutdown semantics. Если появляется новый долгоживущий socket/task/buffer,
  должен быть понятный лимит или eviction.
- Fallback reverse proxy предназначен прежде всего как camouflage/fallback path,
  а не высокопроизводительный backend proxy. Если делаешь его primary workload,
  отдельно оцени pooling, body-size limits, streaming и timeout behavior.
- Не добавляй новые обязанности в уже широкие файлы без веской причины:
  `src/config/mod.rs`, `src/server/transport/tcp.rs`,
  `src/server/dashboard/dashboard.html`, `src/metrics/mod.rs`. Для новых крупных
  изменений предпочитай маленькие модули с явным именем.
- В нейминге избегай слишком общих новых `tcp.rs`, `udp.rs`, `mod.rs`-свалок и
  методов вроде `load`/`setup`/`handle`, если сущность имеет более точный смысл.
  Для transport code называй протокол и носитель явно, например
  `ss_ws_tcp`, `vless_tcp`, `xhttp_handlers`, `h3_dispatch`.

## Протокольные заметки

- TCP over WebSocket переносит непрерывный Shadowsocks AEAD stream. Границы
  WebSocket frames игнорируются.
- UDP over WebSocket переносит ровно один encrypted Shadowsocks UDP packet на
  каждый binary WebSocket frame.
- VLESS сам по себе не шифруется. Для публичных deployments нужен TLS на h1/h2
  или QUIC encryption на h3/raw QUIC paths.
- Raw QUIC transports выбираются через ALPN (`h3`, `vless`/`vless-mtu`,
  `ss`/`ss-mtu`). Не ломай ALPN compatibility.
- `fwmark` работает только на Linux. Non-Linux builds и tests должны продолжать
  компилироваться и работать без `SO_MARK`.
- Session resumption и NAT behavior stateful. Сохраняй bounded queues, idle
  timeouts, replay windows и cancellation/shutdown semantics, если задача явно
  не меняет их.

## Vendored patches

Сборки используют локальные крейты:

- `vendor/h3`
- `vendor/sockudo-ws`

Корневые patch files и `PATCHES.md` / `PATCHES.ru.md` объясняют, чем эти копии
отличаются от upstream. Если меняешь поведение vendored crate, обновляй vendored
source и patch documentation/artifacts в том же изменении.

Не поднимай upstream versions и не удаляй `[patch.crates-io]` без явной причины:
HTTP/3 WebSocket path зависит от этих патчей.

## Команды сборки и тестов

Используй самую маленькую команду, которая дает уверенность для затронутой
области:

- Форматирование основного package: `cargo fmt -p outline-ss-rust -- --check`
- Компиляция default feature set: `cargo check`
- Компиляция без default feature `control`, если трогаешь gated code paths:
  `cargo check --no-default-features`
- Все тесты: `cargo test`
- Фокусные тесты по модулю или имени, например:
  `cargo test config::tests`, `cargo test server::tests::xhttp`,
  `cargo test crypto::tests` или `cargo test resumption`

Заметки:

- В `Cargo.toml` есть dev-dependency на
  `../outline-ws-rust/crates/outline-transport`. Для `cargo test` и
  `cargo check --tests` нужен соседний checkout.
- Cross-build aliases определены в `.cargo/config.toml` и требуют
  `cargo-zigbuild` плюс `zig`: `cargo build-musl-x86_64`,
  `cargo release-musl-x86_64`, `cargo build-musl-aarch64`,
  `cargo release-musl-aarch64`, `cargo build-musl-arm`,
  `cargo release-musl-arm`, `cargo build-musl-armv7`,
  `cargo release-musl-armv7`.
- Некоторые тесты биндинят локальные TCP/UDP sockets и используют async
  timeouts. Предпочитай ephemeral ports и существующие test helpers в
  `src/server/tests/mod.rs`.
- Если proptest пишет или меняет файлы в `proptest-regressions/`, проверь эти
  изменения перед включением.

## Ожидания по тестам

- Добавляй или обновляй focused tests рядом с измененным модулем. Существующие
  test modules лежат рядом с implementation или в `src/*/tests/`.
- Для config changes покрывай parsing, defaults, migration/backward
  compatibility и validation errors.
- Для transport changes покрывай success, malformed input, shutdown/error paths
  и resource-bound behavior, где это практично.
- Для metrics changes проверяй rendered output и ожидания по label cardinality.
- Для docs-only changes Rust tests не нужны, но проверь форматирование, если
  менялись Markdown tables или generated snippets.

## Release и runtime artifacts

- `target/` является generated и ignored.
- `grafana/outline-ss-rust-dashboard.json`, `systemd/outline-ss-rust.service`,
  `install.sh` и `config.toml` являются user-facing deployment artifacts; держи
  их согласованными с runtime behavior.
- Не добавляй в репозиторий local secrets, generated access-key YAML files,
  certificates или private keys.
