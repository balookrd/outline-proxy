# Нативный TUN на Android — замена tun2proxy (дизайн)

Дата: 2026-08-14
Статус: согласовано в чате

## Контекст

Android-клиент (`android/`, обёртка `outline-android` над `outline-ws-rust`)
сейчас несёт трафик через **tun2proxy**: Rust-crate берёт TUN-fd от
`VpnService.establish()`, терминирует TCP/UDP в user-space (smoltcp/ipstack) и
форвардит в локальный SOCKS5-listener ws-rust
([android/rust/src/lib.rs:152](../../../android/rust/src/lib.rs)). Нативный
движок `outline-tun` в Android-сборку **не входит** — фича `tun` выключена
([android/rust/Cargo.toml:32](../../../android/rust/Cargo.toml):
`default-features = false, features = ["h3"]`).

tun2proxy взяли как быстрый MVP: он закрывал единственный пробел — «принять
готовый fd и стать SOCKS-клиентом», позволяя переиспользовать весь uplink-стек
без правок. Причина этого пробела — `outline-tun` **сам открывает** устройство
(`OpenOptions::open(config.path)` + на Linux `TUNSETIFF`,
[device.rs:60](../../../crates/outline-tun/src/device.rs)), а на Android
приложение без root не открывает `/dev/net/tun` и получает уже открытый fd.

## Цель

Убрать зависимость `tun2proxy` (и транзитивные smoltcp/ipstack): научить
нативный `outline-tun` принимать готовый fd от `VpnService`, unifицировав один
движок на всех платформах. Фичи движка (SNI-routing, PMTUD/ICMP, BBR/SACK
downlink, backpressure/pump) приходят попутно — это тот же код, но специально их
не тюним.

Драйвер (согласовано): **убрать стороннюю зависимость**, не perf и не конкретные
фичи. Стратегия: **полная замена** — tun2proxy удаляется в этом же заходе,
нативный путь становится единственным. Временного переключателя `engine=` нет.

## Не-цели

- Порт `outline-tun` на iOS / другие платформы.
- Per-socket `VpnService.protect()`-callback в dial-стеке (loop-avoidance
  остаётся через Kotlin `addDisallowedApplication`, см. ниже).
- Замена `SO_MARK`/fwmark-механики на Android (на Android fwmark не задаётся).
- Оптимизация throughput/latency downlink под мобильные сети.

## Решения (архитектура)

Точка входа для fd — **runtime-параметр запуска**, не поле конфига: сохраняемый
TOML остаётся про конфигурацию, fd — про жизненный цикл процесса.

### Слой 1 — `outline-tun`: приём готового fd

- [engine.rs:61](../../../crates/outline-tun/src/engine.rs) `spawn_tun_loop`
  получает параметр `preopened_fd: Option<RawFd>`. При `Some(fd)` — вместо
  `open_tun_device_with_retry(&config)` вызывается новая
  `attach_preopened_fd(fd, &config)`.
- Новая `attach_preopened_fd(fd, &config) -> Result<(std::fs::File, TunGso)>` в
  [device.rs](../../../crates/outline-tun/src/device.rs) под `#[cfg(unix)]`:
  - `dup(fd)` через `fcntl(F_DUPFD_CLOEXEC)` (проверка `< 0` → `Err`);
  - `File::from_raw_fd(duped)`;
  - **без** `open` / `TUNSETIFF` / `TUNSETOFFLOAD` — fd уже привязан
    `VpnService`-ом;
  - возвращает `TunGso::default()` (offload off).
- `set_nonblocking(&device)` + `AsyncFd` ([engine.rs:77](../../../crates/outline-tun/src/engine.rs))
  остаются общими для обоих путей: `VpnService` отдаёт blocking fd, ветка
  переводит его в `O_NONBLOCK` для tokio-reactor.

`vnet_hdr`/offload на Android недоступны (VpnService-fd — не Linux TUN
char-device с ioctl-негоциацией), поэтому GSO/GRO/USO принудительно off,
read/write идут голыми IP-пакетами (эквивалент `IFF_NO_PI`) — штатный
не-offload путь движка. `config.name`/`config.path` на fd-пути устройство не
открывает — они остаются лишь метками для логов. Требование `tun.name`
обязательно только под `#[cfg(target_os="linux")]` — в loader
([config/load/tun.rs:238](../../../bins/outline-ws-rust/src/config/load/tun.rs))
и в `open_tun_device` — на Android не компилируется.

**Активация TUN зависит от конфига, не от fd.** `load_tun_config` возвращает
`Ok(None)`, если не задан ни `path`, ни `name`, и требует непустой `path`
([config/load/tun.rs:41-46](../../../bins/outline-ws-rust/src/config/load/tun.rs)).
loader не видит `RunOptions.tun_fd`. Поэтому android-TOML **обязан** задать
`[tun].path` (плейсхолдер, напр. `path = "vpn"`), иначе `config.tun = None` и
TUN не поднимется, а fd повиснет неиспользованным. Ослаблять loader (делать
`path` опциональным при наличии fd) не будем — плейсхолдер дешевле и не
размывает семантику «TUN включён, если есть `[tun]`».

### Слой 2 — `outline-ws-rust`: точка входа + рантайм-гейт SOCKS

- `pub struct RunOptions { pub tun_fd: Option<RawFd> }` (Default = `None`).
- `pub async fn run_with_options(args, opts: RunOptions) -> Result<()>`;
  существующий `run(args)` = обёртка с `RunOptions::default()` — десктопный путь
  не меняется.
- bootstrap прокидывает `opts.tun_fd` до подъёма TUN и передаёт его четвёртым
  аргументом `spawn_tun_loop`.
- **Рантайм-гейт SOCKS:** при `tun_fd.is_some()` SOCKS-listener не поднимается.
  Ветка «TUN-only mode: no TCP listener» уже есть
  ([bootstrap/mod.rs:291](../../../bins/outline-ws-rust/src/bootstrap/mod.rs)).
  Если при этом задан `config.listen` — `warn` и игнор (fd-режим исключает
  SOCKS-сервер).

### Слой 3 — фича `socks5` (compile-out модуля)

`src/proxy/` — изолированный лист-модуль (5320 LOC): единственный внешний
потребитель — bootstrap, и только в блоке подъёма listener (`ProxyConfig`,
`TcpTimeouts`, `Router`, `serve_socks5_client`). `dispatcher`, `tcp/`
(failover, pinned_relay, phased dial), `udp/` вне `proxy` не используются;
TUN-путь берёт `shared_routing` как конкретный тип и дайлит через relay в
крейте `outline-tun`.

- Новая фича `socks5`, включена в `default` (десктоп собирает как раньше).
- `#[cfg(feature = "socks5")] pub mod proxy;`
  ([lib.rs:21](../../../bins/outline-ws-rust/src/lib.rs)).
- Блок подъёма listener в bootstrap (≈221–291) и `Router`-cast (283) — под
  `#[cfg(feature = "socks5")]`.
- Android собирает `features = ["h3", "tun"]` **без** `socks5` → 5.3k LOC
  SOCKS-ingress не компилируются; вместе с `tun2proxy` уходят smoltcp/ipstack.
- Config-поля `[socks5]` (`listen`, `socks5_auth`) в schema остаются
  (парсятся всегда), но без фичи не используются.

### Слой 3b — расцепление `tun` и `metrics`

Сейчас `tun` форсит метрики:
`tun = ["dep:outline-tun", "outline-tun/metrics", "outline-metrics/tun"]`
([Cargo.toml:16](../../../bins/outline-ws-rust/Cargo.toml)) — android получил бы
весь metrics-стек (`outline-metrics/prometheus`) без надобности. Расцепляем
через weak-dependency-feature:

```toml
tun     = ["dep:outline-tun"]
metrics = [..., "outline-tun?/metrics"]   # tun-метки только если tun в графе
```

`outline-tun?/metrics` включает у `outline-tun` его фичу `metrics`
(= `outline-metrics/{prometheus,tun}`) **только когда** optional-зависимость
`outline-tun` уже активирована фичей `tun`. Итог:

- android `["h3","tun"]` — `outline-tun` без metrics; metrics-вызовы движка
  резолвятся в no-op stubs `outline-metrics`. В prod-коде `outline-tun` нет ни
  одного `cfg(feature="metrics")` (единственное вхождение — в тестах), поэтому
  расцепление не требует правок кода — метрики всегда идут через API
  `outline-metrics`, реальный или stub;
- десктоп `[...,"metrics","tun"]` — полные TUN-метрики (weak-feature активна);
- `["metrics"]` без `tun` — weak-feature no-op, tun-метки не тянутся.

Правка только в `bins/outline-ws-rust/Cargo.toml`;
`crates/outline-tun/Cargo.toml` не меняется (его фича `metrics` остаётся).

### Слой 4 — `android/rust`: `start()` + сборка

- Удалить `tun2proxy`, `ArgProxy`, `CancellationToken`, `bridge_task`, параметр
  `socks_proxy_url`, константу `TUN_MTU`.
- `start(config_toml, work_dir, tun_fd)`: пишет TOML (`[tun]` с
  плейсхолдер-`path` для активации + `mtu` + tcp-опции, без `[socks5]`), парсит
  `Args`, вызывает
  `run_with_options(args, RunOptions { tun_fd: Some(tun_fd) })` на приватном
  multi-thread runtime. Один task, без моста.
- `Engine` = `runtime` + `client_task`; `stop()` = `client_task.abort()` +
  `runtime.shutdown_timeout(2s)`. Drop `File` закрывает наш dup;
  `ParcelFileDescriptor` закрывает Kotlin.
- `Cargo.toml`: `outline-ws-rust { default-features = false,
  features = ["h3", "tun"] }`; убрать `tun2proxy`.
- `build-rust.sh` / `android/README.md` (+ `.ru`, если есть пара) —
  фичи сборки, обновлённая архитектура, roadmap.

### Слой 5 — Kotlin (минимум)

- `OutlineVpnService.kt`: убрать `socks_proxy_url` из вызова `start`.
- `setMtu` синхронизировать с `[tun] mtu` из профиля — единый источник MTU —
  TOML.
- Loop-avoidance без изменений: `addDisallowedApplication(self)` остаётся —
  все сокеты процесса исключены из TUN, `SO_MARK` не нужен.
- DNS: native TUN перехватывает DNS-трафик и гонит через dispatch/uplinks (у
  tun2proxy был virtual-DNS) — проверить резолв на устройстве (e2e).

## Сквозные детали

- **Владение fd:** `dup` на нашей стороне — симметричное владение, нет
  double-close / use-after-close (tun2proxy обходился `close_fd_on_drop=false`;
  для нативного пути dup надёжнее).
- **MTU:** единственный источник — `[tun] mtu` в TOML; Kotlin `setMtu` обязан
  совпадать.
- **Ошибки:** `dup < 0` → `Err` из `attach_preopened_fd` → `spawn_tun_loop`
  возвращает ошибку → `start()` отдаёт `VpnError::Runtime` в Kotlin.
- **Graceful shutdown:** на Android — abort task + `runtime.shutdown_timeout`;
  фоновые TUN-таски рубятся, fd закрывается через drop `File`. Для MVP
  приемлемо.

## Фиче-матрица

| Сборка | Фичи | proxy (SOCKS5) | outline-tun | metrics-стек | tun2proxy |
|---|---|---|---|---|---|
| Десктоп (default) | `h3,metrics,control,env-filter,multi-thread,mimalloc,tun,socks5` | компилируется | компилируется (+metrics) | prometheus | нет |
| Android | `h3,tun` | **выключен** | компилируется (stub-метрики) | **нет** | **удалён** |

`metrics` в default тянет TUN-метки через weak-feature `outline-tun?/metrics`;
android без `metrics` — prometheus-стек не компилируется, метрики движка = stubs.

## Тестирование

- **Unit** (`crates/outline-tun/src/tests/device.rs`, по конвенции `tests/`
  рядом): `attach_preopened_fd` на `pipe()`/`socketpair`-fd — оригинальный fd
  жив после drop полученного `File` (dup сработал), `TunGso` = offload off.
- **Host-гейт:** `cargo fmt --check` + `cargo clippy --workspace --exclude
  sockudo-ws --all-targets --no-deps -- -D warnings` + `cargo test --workspace
  --exclude sockudo-ws`.
- **Compile-out проверка:** `cargo check -p outline-ws-rust
  --no-default-features --features tun` (без `socks5`, без `metrics`)
  собирается — ловит скрытые зависимости от `proxy` и подтверждает расцепление
  metrics (сборка без prometheus-стека).
- **Cross-build:** `cargo ndk -t arm64-v8a --platform 24 -- build
  -p outline-android --release --lib` с `h3,tun`.
- **E2E на эмуляторе** (методика [[android-emulator-verification]]:
  liberica-17, `appops set … ACTIVATE_VPN allow`, посев профиля через run-as,
  `dumpsys connectivity | grep VPN:…` underlying): реальная загрузка через
  туннель, DNS-резолв, отсутствие tun2proxy-логов, `[tun.tcp] sniffing=true`
  (кейс YouTube/ТВ).

## Риски / точки верификации

1. **Фиче-граф `tun`/`metrics` — решено в дизайне** (см. «Слой 3b —
   расцепление `tun` и `metrics`»): `tun` больше не форсит metrics,
   расцеплено weak-feature `outline-tun?/metrics`. Остаётся лишь верификация
   сборкой: `cargo check -p outline-ws-rust --no-default-features
   --features tun` собирается без metrics-стека.
2. **`AsyncFd` на VpnService-fd.** blocking→nonblocking через `set_nonblocking`;
   обычный poll-able char-fd, ожидаемо ок — подтвердить на устройстве.
3. **DNS native vs virtual-DNS tun2proxy.** Резолв через туннель проверить в
   e2e.
4. **Graceful shutdown TUN на Android** — abort+runtime drop; fd закрывается
   через `File`, но упорядоченного teardown нет.

## Затрагиваемые файлы (сводка)

- `crates/outline-tun/src/device.rs` — `attach_preopened_fd`.
- `crates/outline-tun/src/engine.rs` — параметр `preopened_fd` в
  `spawn_tun_loop`.
- `crates/outline-tun/src/tests/device.rs` — unit-тест.
- `bins/outline-ws-rust/src/lib.rs` — `RunOptions`, `run_with_options`,
  `#[cfg(feature="socks5")] pub mod proxy`.
- `bins/outline-ws-rust/src/bootstrap/mod.rs` — прокидывание fd, гейт listener.
- `bins/outline-ws-rust/Cargo.toml` — фича `socks5` в `default`; расцепление
  `tun`/`metrics` (`tun` без metrics, weak-feature `outline-tun?/metrics` в
  `metrics`).
- `android/rust/Cargo.toml` — `features=["h3","tun"]`, drop `tun2proxy`.
- `android/rust/src/lib.rs` — `start()` без моста.
- `android/app/.../OutlineVpnService.kt` — вызов `start`, `setMtu`.
- `android/README.md` (+ `.ru`) — архитектура/сборка/roadmap.
