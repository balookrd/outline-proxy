# Нативный TUN на Android (замена tun2proxy) — план реализации

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Научить нативный `outline-tun` принимать готовый fd от Android
`VpnService` и полностью убрать зависимость `tun2proxy` (и транзитивные
smoltcp/ipstack).

**Architecture:** fd входит как runtime-параметр запуска (`RunOptions.tun_fd`),
не поле конфига. `outline-tun` получает ветку «attach из готового fd» (dup +
`from_raw_fd`, offload off, без `TUNSETIFF`). SOCKS5-ingress отключается на
двух уровнях: рантайм (при fd listener не поднимается) и compile-time (новая
фича `socks5`, android собирается без неё). Метрики TUN расцепляются с фичей
`tun` через weak-dependency-feature.

**Tech Stack:** Rust 2024, tokio `AsyncFd`, libc (`fcntl`/`dup`), Cargo
feature-graph, UniFFI 0.32, Kotlin `VpnService`, cargo-ndk.

**Spec:** [docs/superpowers/specs/2026-08-14-android-native-tun-design.md](../specs/2026-08-14-android-native-tun-design.md)

## Global Constraints

- **Коммиты git — только с явного согласия владельца.** Commit-шаги ниже —
  часть TDD-ритма; фактический `git commit` выполнять по договорённости, не
  автоматически. Сообщения — на английском, БЕЗ трейлеров `Co-Authored-By` и
  БЕЗ пометок об авторстве Claude/Claude Code.
- **rustls — только `aws-lc-rs`.** Ровно один `CryptoProvider` в графе; не тянуть
  `ring` как rustls-провайдер.
- **Тесты — в подкаталогах `tests/` рядом с модулем** (`<dir>/tests/<basename>.rs`),
  подключение из покрываемого модуля `#[cfg(test)] #[path = "tests/<basename>.rs"] mod tests;`.
  Без inline `#[cfg(test)] mod tests {}`.
- **Каждый `unsafe`-блок несёт рядом `// SAFETY:`** с конкретным инвариантом.
- **`cargo fmt --all`** перед завершением (rustfmt.toml, 100 колонок). Format-only
  правки в `vendor/*` откатывать.
- **CI-гейт (гнать локально перед коммитом):**
  ```bash
  cargo fmt --check -p outline-ss-rust -p outline-ws-rust -p outline-ui \
    -p outline-metrics -p outline-net -p outline-routing -p outline-transport \
    -p outline-tun -p outline-uplink -p outline-wire \
    -p shadowsocks-crypto -p socks5-proto
  cargo clippy --workspace --exclude sockudo-ws --all-targets --no-deps -- -D warnings
  cargo test --workspace --exclude sockudo-ws
  (cd android/rust && cargo fmt --check && cargo clippy --no-deps -- -D warnings)
  ```
- **MTU = 1500** — единый источник: Kotlin `setMtu(1500)` и loader-default
  `[tun] mtu` (1500) должны совпадать.
- **Активация TUN — через `[tun].path`.** loader возвращает `Ok(None)` без
  `path`/`name`; android-TOML обязан задать `[tun].path` (плейсхолдер), иначе
  TUN не поднимется.
- **Фича `socks5` входит в `default`.** Десктоп собирается как раньше; android —
  `["h3","tun"]` без `socks5`.

---

## File Structure

- `crates/outline-tun/src/device.rs` — +`attach_preopened_fd` (attach из
  готового fd), +подключение теста.
- `crates/outline-tun/src/tests/device.rs` — **создать**: unit-тест attach.
- `crates/outline-tun/src/engine.rs` — +параметр `preopened_fd` в
  `spawn_tun_loop`, ветка выбора источника устройства.
- `bins/outline-ws-rust/src/lib.rs` — `RunOptions`, `run_with_options`, гейт
  `#[cfg(feature="socks5")] pub mod proxy`.
- `bins/outline-ws-rust/src/bootstrap/mod.rs` — прокидка `tun_fd` в
  `spawn_tun_loop`, рантайм-гейт listener, гейт `socks5`-специфики.
- `bins/outline-ws-rust/Cargo.toml` — фича `socks5`; расцепление `tun`/`metrics`.
- `bins/outline-ws-rust/src/main.rs` — вызов `run` не меняется (десктоп).
- `android/rust/Cargo.toml` — `features=["h3","tun"]`; drop `tun2proxy`.
- `android/rust/src/lib.rs` — `start()` на нативный путь, `Engine` без моста.
- `android/app/src/main/java/com/outline/proxy/OutlineVpnService.kt` — вызов
  `start`, MTU-комментарий, чистка SOCKS-констант.
- `android/app/.../ServerProfile.kt` — генерация `[tun]` в `toToml()`.
- `android/README.md` (+ `.ru`, если есть пара) — архитектура/сборка/roadmap.

---

## Task 1: outline-tun принимает готовый fd

**Files:**
- Modify: `crates/outline-tun/src/device.rs`
- Create: `crates/outline-tun/src/tests/device.rs`
- Modify: `crates/outline-tun/src/engine.rs`
- Modify: `bins/outline-ws-rust/src/bootstrap/mod.rs:215` (вызов `spawn_tun_loop` → `None`)

**Interfaces:**
- Produces: `outline_tun::spawn_tun_loop(config, routing, dns_cache, preopened_fd: Option<RawFd>)` — новый 4-й параметр.
- Produces (внутр.): `device::attach_preopened_fd(fd: RawFd) -> Result<(std::fs::File, TunGso)>`.

- [ ] **Step 1: Написать падающий тест attach**

Создать `crates/outline-tun/src/tests/device.rs`:

```rust
//! Tests for the Android VpnService-fd attach path (`attach_preopened_fd`).

use super::*;

/// A pipe read-end stands in for the VpnService TUN fd — attach only dups it,
/// so any real fd exercises the path.
fn make_pipe() -> (RawFd, RawFd) {
    let mut fds = [0 as libc::c_int; 2];
    // SAFETY: `fds` is a live 2-element array; `pipe` writes exactly two fds
    // into it and returns 0 on success, which we assert.
    let rc = unsafe { libc::pipe(fds.as_mut_ptr()) };
    assert_eq!(rc, 0, "pipe() must succeed");
    (fds[0], fds[1])
}

/// `attach_preopened_fd` dups the fd: the returned `File` owns an independent
/// copy, so dropping it must NOT close the caller's original, and offload is
/// always off on a preopened fd.
#[test]
fn attach_dups_and_leaves_original_open() {
    let (read_fd, write_fd) = make_pipe();

    let (file, gso) = attach_preopened_fd(read_fd).expect("attach must succeed");

    assert!(!gso.vnet_hdr, "vnet_hdr must be off on a preopened fd");
    assert!(!gso.tcp_gro, "tcp_gro must be off on a preopened fd");
    assert!(!gso.udp_gso, "udp_gso must be off on a preopened fd");

    // Drop our dup copy; the caller's original must survive.
    drop(file);

    // SAFETY: read-only `F_GETFD` on an fd we still own; no pointer args.
    // Returns >= 0 only while the fd is open.
    let flags = unsafe { libc::fcntl(read_fd, libc::F_GETFD) };
    assert!(flags >= 0, "original fd must stay open after dropping the dup");

    // SAFETY: closing fds we own exactly once.
    unsafe {
        libc::close(read_fd);
        libc::close(write_fd);
    }
}
```

- [ ] **Step 2: Подключить тест из device.rs**

В конец `crates/outline-tun/src/device.rs` добавить:

```rust
#[cfg(test)]
#[path = "tests/device.rs"]
mod tests;
```

- [ ] **Step 3: Запустить тест — убедиться, что падает (компиляция)**

Run: `cargo test -p outline-tun attach_dups_and_leaves_original_open`
Expected: FAIL — `cannot find function attach_preopened_fd in this scope`.

- [ ] **Step 4: Реализовать `attach_preopened_fd`**

В `crates/outline-tun/src/device.rs` заменить строку импорта:

```rust
use std::os::fd::AsRawFd;
```

на:

```rust
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
```

Добавить функцию (после `open_tun_device_with_retry`, перед первой
`#[cfg(target_os = "linux")]`-веткой `open_tun_device`):

```rust
/// Attaches to a TUN fd the OS already opened and bound for us — the Android
/// `VpnService.establish()` case, where the app cannot open `/dev/net/tun`
/// itself (no root) and is handed a ready fd instead. We `dup` it so our
/// `File` owns an independent copy: dropping it on shutdown closes our copy
/// while the caller (the JVM's `ParcelFileDescriptor`) still owns the
/// original. No `TUNSETIFF`/`TUNSETOFFLOAD` runs — the fd is already a bound
/// TUN queue, and a `VpnService` fd carries neither `IFF_VNET_HDR` nor offload
/// negotiation, so GSO/GRO/USO stay off (`TunGso::default()`).
#[cfg(unix)]
pub(crate) fn attach_preopened_fd(fd: RawFd) -> Result<(std::fs::File, TunGso)> {
    // SAFETY: `F_DUPFD_CLOEXEC` duplicates `fd` into a brand-new lowest-free fd
    // (the `0` arg is the minimum-fd hint) and dereferences no pointer. We only
    // read `fd` (duplicate it), never consume it, so the caller keeps ownership.
    // The result is checked `< 0` before use.
    let duped = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 0) };
    if duped < 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("failed to dup preopened TUN fd {fd}"));
    }
    // SAFETY: `duped` is a fresh, valid, uniquely-owned fd (checked `>= 0`), so
    // `File` becomes its sole owner and closes it exactly once on drop.
    let file = unsafe { std::fs::File::from_raw_fd(duped) };
    Ok((file, TunGso::default()))
}
```

- [ ] **Step 5: Запустить тест — убедиться, что проходит**

Run: `cargo test -p outline-tun attach_dups_and_leaves_original_open`
Expected: PASS.

- [ ] **Step 6: Прокинуть `preopened_fd` в `spawn_tun_loop`**

В `crates/outline-tun/src/engine.rs` добавить импорт `RawFd` (в блок `std`):

```rust
use std::os::fd::RawFd;
use std::panic::AssertUnwindSafe;
```

Расширить импорт из `device`:

```rust
use crate::device::{attach_preopened_fd, open_tun_device_with_retry, set_nonblocking};
```

Изменить сигнатуру (было 3 параметра):

```rust
pub async fn spawn_tun_loop(
    config: TunConfig,
    routing: TunRouting,
    dns_cache: Arc<outline_transport::DnsCache>,
    preopened_fd: Option<RawFd>,
) -> Result<()> {
```

Заменить открытие устройства (было `let (device, gso) = open_tun_device_with_retry(&config).await…`):

```rust
    let (device, gso) = match preopened_fd {
        Some(fd) => attach_preopened_fd(fd)
            .with_context(|| format!("failed to attach preopened TUN fd {fd}"))?,
        None => open_tun_device_with_retry(&config)
            .await
            .with_context(|| format!("failed to open TUN device {}", config.path.display()))?,
    };
```

- [ ] **Step 7: Обновить единственного вызывателя (bootstrap) на `None`**

В `bins/outline-ws-rust/src/bootstrap/mod.rs` (вызов `spawn_tun_loop`, ~строка 215):

```rust
            outline_tun::spawn_tun_loop(tun, tun_routing, dns_cache.clone(), None)
```

- [ ] **Step 8: Прогнать гейт**

Run:
```bash
cargo fmt --all
cargo clippy -p outline-tun -p outline-ws-rust --all-targets --no-deps -- -D warnings
cargo test -p outline-tun
```
Expected: всё зелёное; дерево компилируется (fd-путь есть, но пока никем не передаётся — bootstrap передаёт `None`).

- [ ] **Step 9: Commit**

```bash
git add crates/outline-tun/src/device.rs crates/outline-tun/src/tests/device.rs \
        crates/outline-tun/src/engine.rs bins/outline-ws-rust/src/bootstrap/mod.rs
git commit -m "feat(tun): accept a preopened TUN fd (Android VpnService)"
```

---

## Task 2: ws-rust — `RunOptions.tun_fd` и рантайм-гейт SOCKS

**Files:**
- Modify: `bins/outline-ws-rust/src/lib.rs`
- Modify: `bins/outline-ws-rust/src/bootstrap/mod.rs`

**Interfaces:**
- Consumes: `spawn_tun_loop(…, Option<RawFd>)` (Task 1).
- Produces: `outline_ws_rust::RunOptions { pub tun_fd: Option<RawFd> }` (Default = `None`).
- Produces: `outline_ws_rust::run_with_options(args: Args, opts: RunOptions) -> Result<()>`; `run(args)` = обёртка с `RunOptions::default()`.
- Produces: `run_with_config(config, args, tun_fd: Option<RawFd>)` — новый 3-й параметр.

- [ ] **Step 1: Написать падающий тест на `RunOptions::default`**

В `bins/outline-ws-rust/src/lib.rs` в конец файла добавить:

```rust
#[cfg(test)]
#[path = "tests/run_options.rs"]
mod run_options_tests;
```

Создать `bins/outline-ws-rust/src/tests/run_options.rs`:

```rust
//! `RunOptions` default: a plain `run` must not carry a preopened TUN fd.

use crate::RunOptions;

#[test]
fn default_run_options_have_no_tun_fd() {
    assert_eq!(RunOptions::default().tun_fd, None);
}
```

- [ ] **Step 2: Запустить — убедиться, что падает**

Run: `cargo test -p outline-ws-rust default_run_options_have_no_tun_fd`
Expected: FAIL — `cannot find type RunOptions`.

- [ ] **Step 3: Ввести `RunOptions` и `run_with_options`**

В `bins/outline-ws-rust/src/lib.rs`:

Добавить импорт вверху (рядом с прочими `use`):

```rust
use std::os::fd::RawFd;
```

Добавить тип (перед `pub async fn run`):

```rust
/// Runtime options that are NOT part of the persisted config — they belong to
/// the process lifecycle, not the TOML. Currently just the preopened TUN fd
/// handed in by an embedder (Android `VpnService`); desktop passes `None`.
#[derive(Debug, Default, Clone, Copy)]
pub struct RunOptions {
    pub tun_fd: Option<RawFd>,
}
```

Переписать `run` как обёртку и вынести тело в `run_with_options`:

```rust
pub async fn run(args: Args) -> Result<()> {
    run_with_options(args, RunOptions::default()).await
}

pub async fn run_with_options(args: Args, opts: RunOptions) -> Result<()> {
    init_metrics();
    spawn_process_metrics_sampler();
    let config = load_config(&args.config, &args).await?;
    outline_transport::init_h2_window_sizes(
        config.h2.initial_stream_window_size,
        config.h2.initial_connection_window_size,
    );
    #[cfg(feature = "h3")]
    outline_transport::init_quic_window_sizes(
        config.quic.stream_receive_window,
        config.quic.receive_window,
    );
    outline_net::init_udp_socket_bufs(config.udp_recv_buf_bytes, config.udp_send_buf_bytes);
    outline_net::init_prefer_public_ipv6_src(config.prefer_public_ipv6_src.unwrap_or(true));
    outline_net::init_direct_ipv6_prefix_iface(config.direct_ipv6_prefix_interface.clone());
    run_with_config(config, args, opts.tun_fd).await
}
```

- [ ] **Step 4: Прокинуть `tun_fd` через `run_with_config` в `spawn_tun_loop`**

В `bins/outline-ws-rust/src/bootstrap/mod.rs` добавить импорт:

```rust
use std::os::fd::RawFd;
```

Изменить сигнатуру:

```rust
pub async fn run_with_config(config: AppConfig, args: Args, tun_fd: Option<RawFd>) -> Result<()> {
```

Заменить вызов `spawn_tun_loop` (из Task 1 он передавал `None`) на `tun_fd`:

```rust
            outline_tun::spawn_tun_loop(tun, tun_routing, dns_cache.clone(), tun_fd)
```

- [ ] **Step 5: Рантайм-гейт SOCKS listener при fd**

В `bins/outline-ws-rust/src/bootstrap/mod.rs` найти создание listener (было
`let listener = if let Some(listen) = config.listen { Some(TcpListener::bind…) } else { None };`,
~строки 221-229) и заменить на:

```rust
    // fd-режим (Android): TUN несёт весь трафик, SOCKS-сервер не нужен. Не
    // поднимаем listener даже если `[socks5] listen` задан — и предупреждаем,
    // чтобы конфликт конфигурации не был тихим.
    let listener = if tun_fd.is_some() {
        if config.listen.is_some() {
            warn!("[socks5] listen is set but a preopened TUN fd is active — ignoring the SOCKS5 listener");
        }
        None
    } else if let Some(listen) = config.listen {
        Some(
            TcpListener::bind(listen)
                .await
                .with_context(|| format!("failed to bind {}", listen))?,
        )
    } else {
        None
    };
```

- [ ] **Step 6: Запустить тесты — убедиться, что проходят**

Run:
```bash
cargo test -p outline-ws-rust default_run_options_have_no_tun_fd
cargo test --workspace --exclude sockudo-ws
```
Expected: PASS; регрессий нет.

- [ ] **Step 7: Прогнать гейт**

Run:
```bash
cargo fmt --all
cargo clippy --workspace --exclude sockudo-ws --all-targets --no-deps -- -D warnings
```
Expected: зелёное.

- [ ] **Step 8: Commit**

```bash
git add bins/outline-ws-rust/src/lib.rs bins/outline-ws-rust/src/tests/run_options.rs \
        bins/outline-ws-rust/src/bootstrap/mod.rs
git commit -m "feat(ws): RunOptions.tun_fd — run native TUN over a preopened fd"
```

---

## Task 3: ws-rust — фича `socks5` (compile-out) + расцепление `tun`/`metrics`

**Files:**
- Modify: `bins/outline-ws-rust/Cargo.toml`
- Modify: `bins/outline-ws-rust/src/lib.rs`
- Modify: `bins/outline-ws-rust/src/bootstrap/mod.rs`

**Interfaces:**
- Produces: фича `socks5` (в `default`); при её отсутствии `crate::proxy` не
  компилируется и SOCKS listener недоступен.
- Produces: `tun` больше не тянет metrics; `metrics` тянет `outline-tun?/metrics`.

- [ ] **Step 1: Расцепить `tun`/`metrics` и ввести фичу `socks5` в Cargo.toml**

В `bins/outline-ws-rust/Cargo.toml`, секция `[features]`:

Было:
```toml
default = ["h3", "metrics", "control", "env-filter", "multi-thread", "mimalloc", "tun"]
tun = ["dep:outline-tun", "outline-tun/metrics", "outline-metrics/tun"]   # TUN device support (transparent proxy)
metrics = ["outline-metrics/prometheus", "outline-transport/metrics", "outline-uplink/metrics", "dep:serde_json", "hyper/server"]
```

Стало:
```toml
default = ["h3", "metrics", "control", "env-filter", "multi-thread", "mimalloc", "tun", "socks5"]
# SOCKS5 ingress (src/proxy). Off on Android, where the native TUN carries all
# traffic and the whole 5.3k-LOC ingress can be compiled out.
socks5 = []
# TUN device support (transparent proxy). No longer forces metrics: on Android
# (`tun` without `metrics`) the engine's metric calls resolve to outline-metrics
# no-op stubs. See `metrics` below for the weak-feature that re-adds TUN metrics.
tun = ["dep:outline-tun"]
metrics = ["outline-metrics/prometheus", "outline-transport/metrics", "outline-uplink/metrics", "outline-tun?/metrics", "dep:serde_json", "hyper/server"]
```

- [ ] **Step 2: Проверить сборку android-профиля (без socks5, без metrics)**

Run: `cargo check -p outline-ws-rust --no-default-features --features tun`
Expected: FAIL при первом прогоне — `crate::proxy` ещё не за фичей, но
`socks5`-специфика в bootstrap уже собирается; ошибки укажут на использование
`proxy` без гейта (это и чиним в шагах 3-4). Зафиксировать список ошибок.

- [ ] **Step 3: Гейтнуть модуль `proxy`**

В `bins/outline-ws-rust/src/lib.rs`:

```rust
#[cfg(feature = "socks5")]
pub mod proxy;
```

(было `pub mod proxy;` без атрибута).

- [ ] **Step 4: Гейтнуть SOCKS-специфику в bootstrap**

В `bins/outline-ws-rust/src/bootstrap/mod.rs`:

Импорт `ProxyConfig` — под фичу:

```rust
#[cfg(feature = "socks5")]
use crate::proxy::ProxyConfig;
```

Объявление `mod listener;` — под фичу:

```rust
#[cfg(feature = "socks5")]
mod listener;
```

Блок listener + accept (из Task 2: создание `listener`, `proxy_config`,
`accept_result`) обернуть так, чтобы без `socks5` всегда работал TUN-only
режим. Заменить весь участок «создание listener → proxy_config → accept_result»
на две cfg-ветки:

```rust
    #[cfg(feature = "socks5")]
    let accept_result = {
        let listener = if tun_fd.is_some() {
            if config.listen.is_some() {
                warn!("[socks5] listen is set but a preopened TUN fd is active — ignoring the SOCKS5 listener");
            }
            None
        } else if let Some(listen) = config.listen {
            Some(
                TcpListener::bind(listen)
                    .await
                    .with_context(|| format!("failed to bind {}", listen))?,
            )
        } else {
            None
        };
        let proxy_config = Arc::new(ProxyConfig {
            socks5_auth: config.socks5_auth.clone(),
            dns_cache: dns_cache.clone(),
            router: shared_routing.clone().map(|t| t as Arc<dyn crate::proxy::Router>),
            direct_fwmark: config.direct_fwmark,
            tcp_timeouts: config.tcp_timeouts,
        });
        if let Some(listener) = listener {
            listener::run_accept_loop(listener, proxy_config, registry, shutdown_rx.clone()).await
        } else {
            // TUN-only mode: no TCP listener; block until shutdown signal.
            let mut rx = shutdown_rx.clone();
            let _ = rx.wait_for(|&v| v).await;
            Ok(())
        }
    };

    // Без SOCKS5 (Android): ingress только через TUN — блокируемся до shutdown.
    #[cfg(not(feature = "socks5"))]
    let accept_result = {
        let _ = (&registry, &dns_cache, &shared_routing);
        let mut rx = shutdown_rx.clone();
        let _ = rx.wait_for(|&v| v).await;
        Ok::<(), anyhow::Error>(())
    };
```

Примечание для исполнителя: точные имена в `let _ = (…)` подгонит компилятор —
цель погасить unused-warnings для переменных, которые без `socks5` не читаются
(`registry`/`dns_cache`/`shared_routing`/`config.socks5_auth`). Если какая-то из
них используется выше по коду безусловно — убрать её из заглушки.

- [ ] **Step 5: Проверить обе сборки**

Run:
```bash
cargo check -p outline-ws-rust --no-default-features --features tun
cargo check -p outline-ws-rust           # default: с socks5 + metrics + tun
```
Expected: обе PASS. Первая — android-профиль (proxy и metrics-стек compiled out),
вторая — десктоп.

- [ ] **Step 6: Прогнать полный гейт**

Run:
```bash
cargo fmt --all
cargo clippy --workspace --exclude sockudo-ws --all-targets --no-deps -- -D warnings
cargo test --workspace --exclude sockudo-ws
```
Expected: зелёное (default-фичи включают `socks5`, поэтому существующие
SOCKS-тесты компилируются и проходят).

- [ ] **Step 7: Commit**

```bash
git add bins/outline-ws-rust/Cargo.toml bins/outline-ws-rust/src/lib.rs \
        bins/outline-ws-rust/src/bootstrap/mod.rs
git commit -m "feat(ws): gate SOCKS5 ingress behind a socks5 feature; decouple tun/metrics"
```

---

## Task 4: android/rust — `start()` на нативный TUN, drop tun2proxy

**Files:**
- Modify: `android/rust/Cargo.toml`
- Modify: `android/rust/src/lib.rs`

**Interfaces:**
- Consumes: `outline_ws_rust::run_with_options(args, RunOptions{ tun_fd })` (Task 2), фича `tun` без `socks5`/`metrics` (Task 3).
- Produces: UniFFI `start(config_toml, work_dir, tun_fd)` — БЕЗ `socks_proxy_url` (сигнатура меняется → правится Kotlin в Task 5).

- [ ] **Step 1: Cargo — включить `tun`, убрать `tun2proxy`**

В `android/rust/Cargo.toml`:

Строку зависимости ws-rust:
```toml
outline-ws-rust = { path = "../../bins/outline-ws-rust", default-features = false, features = ["h3"] }
```
заменить на:
```toml
outline-ws-rust = { path = "../../bins/outline-ws-rust", default-features = false, features = ["h3", "tun"] }
```

Удалить блок:
```toml
# TUN-fd → SOCKS5 bridge. Reads the VpnService TUN descriptor and forwards
# captured flows into the local ws-rust SOCKS5 listener.
tun2proxy = "0.8"
```

- [ ] **Step 2: Переписать `start()` на нативный путь**

В `android/rust/src/lib.rs`:

Заменить импорт tun2proxy:
```rust
use tun2proxy::{ArgProxy, Args as TunArgs, CancellationToken};
```
на:
```rust
use outline_ws_rust::RunOptions;
```

Удалить константу:
```rust
/// TUN MTU. Must match `VpnService.Builder.setMtu` on the Kotlin side.
const TUN_MTU: u16 = 1500;
```

Заменить `struct Engine` на без-мостовую версию:
```rust
/// A running client instance: the dedicated runtime and the join handle of the
/// ws-rust client task (SOCKS5 is off — the native TUN engine carries traffic).
struct Engine {
    runtime: Runtime,
    client_task: JoinHandle<()>,
}
```

Обновить шапку модуля (строки про tun2proxy/SOCKS5-мост) — заменить `//!`-блок в
начале файла на:
```rust
//! Android (JNI/UniFFI) wrapper around the `outline-ws-rust` client.
//!
//! Exposes a tiny lifecycle API (`start` / `stop` / `is_running`) that the
//! Kotlin `VpnService` drives. `start` writes the supplied TOML to the app's
//! working directory and boots the full ws-rust client — the native
//! `outline-tun` engine attached to the `VpnService` TUN fd, plus the
//! WS/TLS/VLESS/SS uplink stack with padding and failover. No SOCKS5 listener
//! and no tun2proxy bridge: the TUN fd is driven natively via
//! `RunOptions.tun_fd`.
//!
//! Loop avoidance: the uplink sockets ws-rust opens must NOT re-enter the
//! tunnel. The Kotlin side excludes this app's own package from the VPN
//! (`addDisallowedApplication`), so every socket this process creates bypasses
//! the TUN automatically — no per-socket `VpnService.protect` needed.
```

Заменить сигнатуру и тело `start` (убрать `socks_proxy_url`, tun2proxy-мост):
```rust
/// Start the client with the native TUN engine bound to `tun_fd`.
///
/// * `config_toml` — full ws-rust client config. MUST contain a `[tun]` section
///   with a placeholder `path` (e.g. `path = "vpn"`) so the loader activates
///   TUN; the fd itself is injected here, not via the TOML.
/// * `work_dir` — an app-private writable directory (e.g. `Context.filesDir`).
/// * `tun_fd` — the TUN fd from `VpnService.establish()`. We `dup` it inside
///   the engine; the Kotlin side keeps owning the `ParcelFileDescriptor`.
#[uniffi::export]
pub fn start(config_toml: String, work_dir: String, tun_fd: i32) -> Result<(), VpnError> {
    init_logging();

    let mut guard = ENGINE.lock().expect("ENGINE mutex poisoned");
    if guard.is_some() {
        return Err(VpnError::AlreadyRunning);
    }

    outline_ws_rust::init_rustls_crypto_provider()
        .map_err(|e| VpnError::Runtime { msg: format!("crypto provider: {e:#}") })?;

    let cfg_path = PathBuf::from(&work_dir).join("config.toml");
    std::fs::write(&cfg_path, config_toml).map_err(|e| VpnError::Config {
        msg: format!("write {}: {e}", cfg_path.display()),
    })?;

    let cfg_arg = cfg_path.to_string_lossy().into_owned();
    let client_args =
        outline_ws_rust::config::Args::try_parse_from(["outline-ws-rust", "--config", &cfg_arg])
            .map_err(|e| VpnError::Config { msg: format!("args: {e}") })?;

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| VpnError::Runtime { msg: format!("tokio runtime: {e}") })?;

    info!(tun_fd, %cfg_arg, "starting outline-ws-rust client with native TUN");

    let opts = RunOptions { tun_fd: Some(tun_fd) };
    let client_task = runtime.spawn(async move {
        if let Err(e) = outline_ws_rust::run_with_options(client_args, opts).await {
            error!("client exited with error: {e:#}");
        }
    });

    *guard = Some(Engine { runtime, client_task });
    Ok(())
}
```

Обновить `stop` (убрать мост):
```rust
#[uniffi::export]
pub fn stop() -> Result<(), VpnError> {
    let mut guard = ENGINE.lock().expect("ENGINE mutex poisoned");
    match guard.take() {
        Some(engine) => {
            engine.client_task.abort();
            engine.runtime.shutdown_timeout(Duration::from_secs(2));
            info!("client stopped");
            Ok(())
        },
        None => Err(VpnError::NotRunning),
    }
}
```

- [ ] **Step 3: Host-проверка (lib + uniffi-bindgen под хост)**

Run: `(cd android/rust && cargo check)`
Expected: PASS — `RawFd`-путь и `run_with_options` резолвятся; `tun2proxy`
больше не в графе.

- [ ] **Step 4: Кросс-сборка под Android (arm64)**

Run (нужен `ANDROID_NDK_HOME`):
```bash
cargo ndk -t arm64-v8a --platform 24 -- build -p outline-android --release --lib
```
Expected: PASS — `liboutline_android.so` собран; проверяет фиче-граф
`h3,tun` без `metrics`/`socks5` (Риск №1 из спеки).

- [ ] **Step 5: Гейт android/rust**

Run:
```bash
(cd android/rust && cargo fmt --all && cargo clippy --no-deps -- -D warnings)
```
Expected: зелёное.

- [ ] **Step 6: Commit**

```bash
git add android/rust/Cargo.toml android/rust/src/lib.rs
git commit -m "feat(android): drive native outline-tun over the VpnService fd"
```

---

## Task 5: Kotlin — вызов `start`, генерация `[tun]`, чистка SOCKS

**Files:**
- Modify: `android/app/src/main/java/com/outline/proxy/OutlineVpnService.kt`
- Modify: `android/app/src/main/java/com/outline/proxy/ServerProfile.kt`

**Interfaces:**
- Consumes: UniFFI `start(config_toml, work_dir, tun_fd)` без `socks_proxy_url` (Task 4).

> Локально Kotlin не собирается (нет Android SDK). Проверка — структурная +
> прогон на эмуляторе (Step 5).

- [ ] **Step 1: Перегенерировать UniFFI-биндинги**

Сигнатура `start` изменилась (убран 4-й аргумент). Перегенерировать Kotlin из
HOST-`.dylib` (не из кросс-`.so`):
```bash
cd android/rust
cargo build --lib
cargo run --bin uniffi-bindgen -- generate --library target/debug/liboutline_android.dylib \
  --language kotlin --out-dir ../app/src/main/java
```
Expected: `uniffi/outline_android/outline_android.kt` объявляет
`fun start(configToml: String, workDir: String, tunFd: Int)`.

- [ ] **Step 2: Поправить вызов `start` и убрать SOCKS-константы**

В `OutlineVpnService.kt`:

Вызов (строка 147):
```kotlin
            start(configToml, filesDir.absolutePath, tun.fd, "socks5://$SOCKS_ADDRESS:$SOCKS_PORT")
```
заменить на:
```kotlin
            start(configToml, filesDir.absolutePath, tun.fd)
```

Удалить константы (строки 58-61):
```kotlin
        // The local SOCKS5 endpoint the Rust core listens on (must match the
        // `[socks5] listen` address in the TOML). Used by tun2proxy later.
        const val SOCKS_ADDRESS = "127.0.0.1"
        const val SOCKS_PORT = 1080
```

Обновить лог (строка 148) и MTU-комментарий (строка 122):
```kotlin
            .setMtu(1500) // must match `[tun] mtu` in the TOML (loader default 1500)
```
```kotlin
            Log.i(TAG, "outline-ws-rust client started with native TUN (fd=${tun.fd})")
```

Обновить устаревший doc-комментарий класса (строки 32-34, про «increment 1 /
tun2proxy / increment 2»):
```kotlin
 * The Rust core attaches the native outline-tun engine directly to this fd and
 * brings up the uplinks. Loop avoidance is via [applySplitTunnel]
 * (addDisallowedApplication), so uplink sockets bypass the TUN.
```

- [ ] **Step 3: Генерировать `[tun]` в профиле**

В `ServerProfile.kt`, метод `toToml()` (после гварда `rawTomlOverride`). Было:

```kotlin
        val sb = StringBuilder()
        sb.append("[socks5]\n")
        sb.append("listen = \"").append(socksListen).append("\"\n\n")
```

Стало:

```kotlin
        val sb = StringBuilder()
        // Native TUN: the fd comes from VpnService, not this path, but the loader
        // needs a non-empty [tun].path to activate TUN. sniffing=true is required
        // for the TLS/QUIC SNI cases (e.g. YouTube on TV).
        sb.append("[tun]\n")
        sb.append("path = \"vpn\"\n")
        sb.append("mtu = 1500\n\n")
        sb.append("[tun.tcp]\n")
        sb.append("sniffing = true\n\n")
```

`rawTomlOverride` (escape-hatch, строка 33) остаётся приоритетным. Секции
`[[outline.uplinks]]` и `[padding]` не трогать. Поле `socksListen` в data-class
больше не используется в `toToml()`; удалять его из класса и JSON ser/de
необязательно — оставить как есть, чтобы не трогать сериализацию профилей.

- [ ] **Step 4: Собрать APK (Android Studio / Gradle)**

Собрать debug-APK (методика [[android-emulator-verification]]: JDK
liberica-17, скопировать `jniLibs`/`uniffi` из главного worktree или
`build-rust.sh`). Expected: sync + компиляция без ошибок (сигнатура `start`
совпадает с биндингами).

- [ ] **Step 5: E2E на эмуляторе**

По методике из памяти:
```bash
export JAVA_HOME=~/Library/Java/JavaVirtualMachines/liberica-17.0.20
adb shell appops set com.outline.proxy ACTIVATE_VPN allow
# посев профиля через run-as (см. [[android-emulator-verification]])
adb shell am start -a android.intent.action.VIEW -d 'outline://connect'
adb logcat -d -v time -s OutlineVpnService OutlineProxy
adb shell dumpsys connectivity | grep 'VPN:com.outline.proxy'
```
Expected: туннель поднят (`underlying{[N]}`, не `Null`); в логах — старт
нативного TUN, НЕТ строк tun2proxy; реальная загрузка страницы и DNS-резолв
идут через туннель.

- [ ] **Step 6: Commit**

```bash
git add android/app/src/main/java/com/outline/proxy/OutlineVpnService.kt \
        android/app/src/main/java/com/outline/proxy/ServerProfile.kt
git commit -m "feat(android): native TUN Kotlin wiring; drop SOCKS bridge args"
```

---

## Task 6: Документация

**Files:**
- Modify: `android/README.md` (+ `android/README.ru.md`, если существует)

- [ ] **Step 1: Обновить README**

В `android/README.md`:
- Архитектура: native `outline-tun` на VpnService-fd вместо tun2proxy→SOCKS5.
- Команда сборки `.so`: `cargo ndk -t arm64-v8a --platform 24 -o ../app/src/main/jniLibs -- build --release --lib` (фичи ws-rust `h3,tun` заданы в `android/rust/Cargo.toml`, отдельно передавать не нужно).
- Roadmap: пункт «tun2proxy MVP» → «нативный TUN (сделано)»; отметить, что
  loop-avoidance — `addDisallowedApplication`, SOCKS5 отключён (фича `socks5`
  выключена + рантайм-гейт).
- Если есть `android/README.ru.md` — синхронно обновить RU-версию.

- [ ] **Step 2: Commit**

```bash
git add android/README.md
git commit -m "docs(android): native TUN architecture"
```

---

## Порядок и зависимости

```
Task 1 (outline-tun fd)
   └─> Task 2 (RunOptions + рантайм-гейт)
          └─> Task 3 (фича socks5 + decouple metrics)
                 └─> Task 4 (android/rust start)
                        └─> Task 5 (Kotlin + [tun] TOML)
                               └─> Task 6 (docs)
```

Каждая задача оставляет дерево компилируемым: Task 1 передаёт `spawn_tun_loop`
`None`; Task 2 меняет `None` на `tun_fd`; Task 3 гейтит `proxy`; android
переходит на нативный путь только в Task 4-5.
