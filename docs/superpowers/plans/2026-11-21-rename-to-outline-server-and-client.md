# План реализации: Переименование `outline-ss-rust` в `outline-server` и `outline-ws-rust` в `outline-client`

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Переименовать крейты и бинарники `outline-ss-rust` $\to$ `outline-server` и `outline-ws-rust` $\to$ `outline-client` во всём монорепозитории, клиентских приложениях (Android, macOS, Windows, `outline-ui`), CI/CD-воркфлоу, операционных скриптах и на всех узлах боевого парка с чистым переносом конфигов, пользователей ОС и systemd-юнитов.

**Architecture:** Работы разделены на последовательные изолированные задачи: сперва перестраивается дерево Rust-пакетов и код workspace (Task 1), затем клиентские обёртки Android/macOS/Windows/UI (Tasks 2–5), системные unit-ы, дашборды и `ops/`-скрипты (Tasks 6–8), CI/CD и двуязычная документация (Tasks 9–10), скрипт чистой миграции узла парка с автооткатом (Task 11), полная верификация в локальном и Linux Docker окружении (Task 12), синхронизация соседнего репозитория `~/IdeaProjects/ambar` (Task 13) и поузловая выкатка на парк по одному узлу с явного согласия владельца (Task 14). Стабильные релизы остаются под единым CalVer-тегом `vYY.M.PATCH`, префиксы метрик Prometheus (`outline_ss_*`, `outline_ws_*`) и `SYNC_SEED_CONTEXT` не меняются.

**Tech Stack:** Rust (Edition 2024, Cargo workspace + detached `android/rust`), Svelte 5 + Vite + Tauri v2 (`outline-windows`, `outline-ui`), Swift/AppKit (`macos/`), Kotlin (`android/`), Bash / Python 3 / Systemd / GitHub Actions / Docker.

## Global Constraints

- **Спецификация:** Все решения зафиксированы в `docs/superpowers/specs/2026-11-19-rename-to-outline-server-and-client-design.md`.
- **Метрики и scrape-джобы НЕ менять:** Префиксы метрик Prometheus (`outline_ss_*`, `outline_ws_*`) и имена scrape-джобов (`rust-ss-exporter` на `:9090`, `rust-ws-exporter` на `:9091`) остаются прежними.
- **`SYNC_SEED_CONTEXT` НЕ менять:** Константа `const SYNC_SEED_CONTEXT: &str = "outline-ws-rust reselect-sync seed v1";` в `crates/outline-uplink/src/manager/sync_order.rs` остаётся побайтово прежней ради совместимости `reselect_sync` на смешанных билдах при поузловой раскатке.
- **Переменные окружения runtime-конфига и тестовых хуков НЕ менять:** `OUTLINE_SS_*`, `OUTLINE_SS_TEST_WS_KEEPALIVE_SECS`, `OUTLINE_WS_TEST_TLS_CA_DER` сохраняются как есть.
- **Единый CalVer-релиз `vYY.M.PATCH`:** Стабильные релизы используют теги `vYY.M.PATCH` (уже действует `v26.11.0`); per-component rolling nightly используют `server-nightly` и `client-nightly`. Старые алиасы `.cargo/config.toml` (`ss-*`, `ws-*`) удаляются полностью.
- **Чистая замена на хостах без симлинков:** Никаких симлинков на `/etc/outline-*`, `/usr/local/bin/outline-*` и без `Alias=` в systemd.
- **Монорепо-инварианты:** `rustls` только на `aws-lc-rs`; vendored API только через гейт-модули; аллокатор только `jemalloc` (на aarch64 4 КиБ + `calloc_madvise_threshold:0`); `--exclude sockudo-ws --exclude outline-windows` в корневом CI-гейте.
- **Секретный путь ключей и отсутствие `*.pyc`:** Запускать Python только с `PYTHONDONTWRITEBYTECODE=1 python3 -B`; путь `[access_keys] write_dir` не попадает в репозиторий; в публичных текстах и планах узлы именуются условно (`exit-a`, `exit-b`, `relay-a`, `relay-b`, `198.51.100.104`, `198.51.100.102`, `fleet.example`), кроме точных имён существующих файлов профилей в git.
- **Правила работы с git и артефактами:** Коммитить строго свои пути через `git commit -- <paths>`; после проверок очищать `target/debug` (`rm -rf target/debug`); после финального push (только по команде владельца) выполнить `cargo clean`.
- **Правило деплоя:** Ничего не менять, не перезапускать и не деплоить на удалённые хосты парка без явной команды владельца на каждый узел; раскатка строго по одному узлу за раз.

---

### Task 1: Переименование директорий, крейтов и Rust-кода workspace

**Files:**
- Rename: `bins/outline-ss-rust/` $\to$ `bins/outline-server/`
- Rename: `bins/outline-ws-rust/` $\to$ `bins/outline-client/`
- Modify: `Cargo.toml:6-10`, `.cargo/config.toml:16-30`, `Cargo.lock`
- Modify: `bins/outline-server/Cargo.toml:1-5`
- Modify: `bins/outline-client/Cargo.toml:1-5`
- Modify: `bins/outline-server/src/main.rs:16,27,54,78`
- Modify: `bins/outline-server/src/lib.rs:85-89`
- Modify: `bins/outline-server/src/config/cli.rs:8-12`
- Modify: `bins/outline-server/src/config/loader.rs:206-210`
- Modify: `bins/outline-server/src/config/tests/control.rs:21`
- Modify: `bins/outline-server/src/config/resolved.rs:222`
- Modify: `bins/outline-server/src/metrics/process_memory.rs:58-87`
- Modify: `bins/outline-server/src/protocol/mod.rs:1-4`
- Modify: `bins/outline-server/src/server/bootstrap/axum.rs:158`
- Modify: `bins/outline-server/src/server/constants.rs:160`
- Modify: `bins/outline-server/src/server/resumption/downlink_ring.rs:13,28`
- Modify: `bins/outline-server/src/server/control/tests/persist.rs:23,137`
- Modify: `bins/outline-server/src/server/tests/mod.rs:442`
- Modify: `bins/outline-server/src/server/tests/sni_fallback.rs:152`
- Modify: `bins/outline-server/src/server/tests/cross_repo_ss_xhttp.rs:1-10`
- Modify: `bins/outline-server/src/server/tests/cross_repo_vless.rs:1-10`
- Modify: `bins/outline-server/src/server/tests/cross_repo_xhttp.rs:1-10`
- Modify: `bins/outline-server/src/server/tests/resumption/cluster.rs:1-10`
- Modify: `bins/outline-server/src/server/tests/resumption/mod.rs:1-10,140`
- Modify: `bins/outline-client/src/lib.rs:1`
- Modify: `bins/outline-client/src/main.rs:4,80,120,133,135`
- Modify: `bins/outline-client/src/proxy/tcp/session.rs:148,155,187,211,223,236,312,329,358`
- Modify: `bins/outline-client/tests/standby_validation.rs:201`
- Modify: `bins/outline-client/tests/support/server_process.rs:2,19,27-46,94`
- Modify: `bins/outline-client/tests/support/proxy_test_utils.rs:207,482`
- Modify: `bins/outline-client/tests/support/config_builder.rs:2-5,39`
- Modify: `bins/outline-client/tests/support/echo_upstream.rs:4`
- Modify: `bins/outline-client/tests/support/tls_fixture.rs:6`
- Modify: `bins/outline-client/tests/e2e_padding.rs:1-2`
- Modify: `bins/outline-client/tests/e2e_probe_failure_reason.rs:13`
- Modify: `bins/outline-client/tests/e2e_smoke.rs:1`
- Modify: `bins/outline-client/tests/e2e_tls_carriers.rs:9`
- Modify: `bins/outline-client/tests/e2e_warm_probe_retry.rs:15`
- Modify: `crates/outline-metrics/src/lib.rs:1`, `crates/outline-metrics/src/registration/core.rs:29`
- Modify: `crates/outline-net/src/fs_util.rs`
- Modify: `crates/outline-transport/Cargo.toml`, `crates/outline-transport/src/{config,downlink_replay,frame_io_ws,h3/vendored,lib,quic/tls_profile,tcp_transport/reader/mod,tcp_transport/reader/transport,tcp_transport/writer/mod,tls,vless/tcp,vless/udp_mux,ws_mode_cache,ws_stream,xhttp/mod}.rs`, `crates/outline-transport/src/xhttp/tests/{carrier_h3,packet_up,packet_up_h1}.rs`
- Modify: `crates/outline-tun/Cargo.toml`, `crates/outline-tun/src/{engine,tcp/engine/connect,tcp/engine/tasks/upstream/migrate,tcp/engine/tests/migrate,tcp/engine/tests/mod,tcp/state_machine/resume,udp/tests/soft_switch}.rs`
- Modify: `crates/outline-uplink/src/{config,manager/loss_sampler,manager/standby/mod,manager/standby/tests/wire_dial_tcp,manager/standby_pool,manager/status,manager/tests/status,tests/share_link}.rs` (БЕЗ изменения `SYNC_SEED_CONTEXT` в `crates/outline-uplink/src/manager/sync_order.rs`!)
- Modify: `crates/outline-wire/src/lib.rs`

**Interfaces:**
- Consumes: Существующие исходники `bins/outline-ss-rust` и `bins/outline-ws-rust`.
- Produces: Крейты и бинарники `outline-server` (`bins/outline-server`) и `outline-client` (`bins/outline-client`), алиасы `.cargo/config.toml`: `server-build-musl-*`, `server-release-musl-*`, `client-release-musl-*`.

- [ ] **Step 1: Переименовать директории бинарных крейтов и обновить `Cargo.toml` / `.cargo/config.toml`**

```bash
git mv bins/outline-ss-rust bins/outline-server
git mv bins/outline-ws-rust bins/outline-client
```

В `Cargo.toml` заменить строки 7–8:

```toml
members = [
    "bins/outline-server",
    "bins/outline-client",
    "bins/outline-ui",
    "bins/outline-windows",
```

В `bins/outline-server/Cargo.toml`:

```toml
[package]
name = "outline-server"
version.workspace = true
edition = "2024"
```

В `bins/outline-client/Cargo.toml`:

```toml
[package]
name = "outline-client"
version.workspace = true
edition = "2024"
```

В `.cargo/config.toml` заменить секцию `[alias]` (строки 16–30):

```toml
[alias]
# --- outline-server (server) cross builds ---
server-build-musl-x86_64 = "zigbuild -p outline-server --target x86_64-unknown-linux-musl"
server-release-musl-x86_64 = "zigbuild --release -p outline-server --target x86_64-unknown-linux-musl"
server-build-musl-aarch64 = "zigbuild -p outline-server --target aarch64-unknown-linux-musl"
server-release-musl-aarch64 = "zigbuild --release -p outline-server --target aarch64-unknown-linux-musl"
server-build-musl-arm = "zigbuild -p outline-server --target arm-unknown-linux-musleabi"
server-release-musl-arm = "zigbuild --release -p outline-server --target arm-unknown-linux-musleabi"
server-build-musl-armv7 = "zigbuild -p outline-server --target armv7-unknown-linux-musleabihf"
server-release-musl-armv7 = "zigbuild --release -p outline-server --target armv7-unknown-linux-musleabihf"

# --- outline-client (client) cross builds ---
client-release-musl-x86_64 = "zigbuild --release -p outline-client --target x86_64-unknown-linux-musl"
client-release-musl-aarch64 = "zigbuild --release -p outline-client --target aarch64-unknown-linux-musl"
```

- [ ] **Step 2: Обновить Rust-код и тесты `bins/outline-server/`**

1. В `bins/outline-server/src/main.rs` заменить:
   - строка 78: `outline_server::run()`
   - комментарии (строки 16, 27, 54): `outline-ws-rust` $\to$ `outline-client`.
2. В `bins/outline-server/src/lib.rs` (строка 87):
```rust
fn init_tracing() {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("outline_server=info,tower_http=info"));
    fmt().with_env_filter(filter).compact().init();
}
```
3. В `bins/outline-server/src/config/cli.rs` (строка 9): `name = "outline-server",` (переменные окружения `OUTLINE_SS_*` не трогать).
4. В `bins/outline-server/src/config/loader.rs` (строка 208): `let args = ConfigArgs::parse_from(["outline-server"]);`.
5. В `bins/outline-server/src/config/tests/control.rs` (строка 21): `let args = ConfigArgs::parse_from(["outline-server"]);`.
6. В `bins/outline-server/src/metrics/process_memory.rs` (строки 61, 74, 83): заменить `"… of the outline-ss-rust process."` на `"… of the outline-server process."` (имена метрик `outline_ss_*` не трогать!).
7. В `bins/outline-server/src/server/control/tests/persist.rs` (строки 23 и 137): заменить `# outline-ss-rust config.` на `# outline-server config.`.
8. В `bins/outline-server/src/server/tests/mod.rs:442` и `sni_fallback.rs:152`: обновить префиксы временных тестовых файлов на `outline-server-h2-tls-...` и `outline-server-sni-fallback-...`.
9. Обновить комментарии и docstrings в `bins/outline-server/src/config/resolved.rs:222`, `protocol/mod.rs:2`, `server/bootstrap/axum.rs:158`, `server/constants.rs:160`, `server/resumption/downlink_ring.rs:13,28`, `server/tests/cross_repo_*.rs`, `server/tests/resumption/{cluster,mod}.rs`.

- [ ] **Step 3: Обновить Rust-код, интеграционные и e2e тесты `bins/outline-client/`**

1. В `bins/outline-client/src/main.rs`:
```rust
use outline_client::config::Args;
...
    outline_client::init_rustls_crypto_provider()?;
...
        tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| "info,outline_client=debug".into()),
            )
            .init();
...
        #[cfg(all(unix, feature = "jemalloc"))]
        outline_client::memory::log_allocator_page_size();

        outline_client::run(args).await
```
2. В `bins/outline-client/src/lib.rs:1`: `//! outline-client — main binary crate.`.
3. В `bins/outline-client/src/proxy/tcp/session.rs` (строки 148, 155, 187, 211, 223, 236, 312, 329, 358): заменить `target: "outline_ws_rust::session_death"` на `target: "outline_client::session_death"`.
4. В `bins/outline-client/tests/standby_validation.rs:201`:
```rust
        .with_env_filter(EnvFilter::new("debug,outline_client=debug"))
```
5. В `bins/outline-client/tests/support/server_process.rs`:
```rust
//! Runs the real `outline-server` server binary as a subprocess, mirroring
...
            let client_bin = Path::new(env!("CARGO_BIN_EXE_outline-client"));
            let dir = client_bin.parent().ok_or_else(|| {
                "CARGO_BIN_EXE_outline-client has no parent directory".to_string()
            })?;
            let bin = dir.join(format!("outline-server{}", std::env::consts::EXE_SUFFIX));
...
            cmd.args(["build", "-p", "outline-server", "--features", "test-hooks"]);
...
                return Err(
                    "`cargo build -p outline-server --features test-hooks` failed".to_string()
                );
...
            .env("RUST_LOG", "info,outline_server=debug")
```
6. В `bins/outline-client/tests/support/proxy_test_utils.rs`:
   - строка 207: `let binary = env!("CARGO_BIN_EXE_outline-client");`
   - строка 482: `let path = env::temp_dir().join(format!("outline-client-{}", unique_suffix()));`
7. Обновить комментарии и команды в `bins/outline-client/tests/{e2e_padding,e2e_probe_failure_reason,e2e_smoke,e2e_tls_carriers,e2e_warm_probe_retry}.rs` и `tests/support/{config_builder,echo_upstream,tls_fixture}.rs`.

- [ ] **Step 4: Обновить shared-крейты в `crates/` (с жёстким сохранением `SYNC_SEED_CONTEXT`)**

1. В `crates/outline-metrics/src/registration/core.rs:29`: `"Build info for outline-client."` (имя метрики `"outline_ws_build_info"` не менять!).
2. В `crates/outline-transport/src/frame_io_ws.rs:463` и `crates/outline-transport/src/tcp_transport/reader/transport.rs:135,160,174,227`: `target: "outline_client::session_death"`.
3. В `crates/outline-transport/src/tcp_transport/writer/mod.rs:290`: `debug!(target: "outline_client::transport::tcp_keepalive", "sending Shadowsocks 0-length keepalive chunk");`.
4. В `crates/outline-tun/src/tcp/engine/tests/mod.rs:1870,2221`: префиксы временных файлов `outline-client-tun-write-fail-{}.bin` и `outline-client-tun-capture-{}.bin`.
5. Обновить комментарии/docstrings в `crates/outline-{metrics,net,transport,tun,uplink,wire}/` (включая `Cargo.toml` комментарии и пути `bins/outline-server/...`, `bins/outline-client/...`), **НЕ ИЗМЕНЯЯ** `const SYNC_SEED_CONTEXT: &str = "outline-ws-rust reselect-sync seed v1";` в `crates/outline-uplink/src/manager/sync_order.rs` (при необходимости добавить рядом с комментарием пояснение, что строка заморожена для совместимости `reselect_sync`).

- [ ] **Step 5: Проверить сборку, юнит-тесты и e2e-тесты на реальных бинарях**

```bash
cargo check --workspace --exclude sockudo-ws --exclude outline-windows
cargo test --workspace --exclude sockudo-ws --exclude outline-windows
RUN_E2E_FAILOVER=1 cargo test -p outline-client --features test-tls --test 'e2e_*' -- --test-threads=1
cargo fmt --check -p outline-server -p outline-client -p outline-ui -p outline-metrics -p outline-net -p outline-routing -p outline-transport -p outline-tun -p outline-uplink -p outline-wire -p shadowsocks-crypto -p socks5-proto
```

Expected: Все проверки завершаются с кодом 0, `Cargo.lock` обновлён под `outline-server` и `outline-client`, `SYNC_SEED_CONTEXT` остался прежним.

- [ ] **Step 6: Очистить `target/debug` и закоммитить изменения Task 1**

```bash
rm -rf target/debug
git status --short
git add Cargo.toml Cargo.lock .cargo/config.toml bins/outline-server bins/outline-client crates/
git commit -- Cargo.toml Cargo.lock .cargo/config.toml bins/outline-server bins/outline-client crates/ -m "refactor: rename outline-ss-rust to outline-server and outline-ws-rust to outline-client"
```

---

### Task 2: Обновление Android-клиента (`android/`)

**Files:**
- Modify: `android/rust/Cargo.toml:1,38-41`
- Modify: `android/rust/Cargo.lock`
- Modify: `android/rust/src/lib.rs:1,5,11,21,42,98,122,131,142-146,170,175,197,233,289`
- Modify: `android/app/src/main/java/com/outline/proxy/OutlineVpnService.kt:593`
- Modify: `android/README.md`, `android/README.ru.md`, `android/CHANGELOG.md`, `android/CHANGELOG.ru.md`

**Interfaces:**
- Consumes: Пакет `outline-client` (`bins/outline-client`) из Task 1.
- Produces: Собираемый detached workspace `android/rust` с зависимостью `outline-client`.

- [ ] **Step 1: Обновить `android/rust/Cargo.toml` и `android/rust/src/lib.rs`**

В `android/rust/Cargo.toml`:

```toml
# Android JNI/UniFFI wrapper around the outline-client client.
...
[dependencies]
# The outline-client crate, minus VM/server-only features (no mimalloc/metrics/
# dashboard/desktop-tun). The `h3` feature pulls the QUIC + HTTP/3 carrier
# stack (quinn + aws-lc-rs QUIC) so xhttp_h3 / ws_h3 uplinks work.
outline-client = { path = "../../bins/outline-client", default-features = false, features = ["h3", "tun"] }
```

В `android/rust/src/lib.rs` заменить все обращения к `outline_ws_rust` на `outline_client`:

```rust
//! Android (JNI/UniFFI) wrapper around the `outline-client` client.
...
use outline_client::RunOptions;
...
            outline_client::clear_active_registry();
...
    outline_client::init_rustls_crypto_provider()
        .map_err(|e| VpnError::Runtime { msg: format!("crypto provider: {e:#}") })?;
...
    let client_args = match outline_client::config::Args::try_parse_from([
        "outline-client",
        "--config",
        &cfg_arg,
    ]) {
...
    info!(
        tun_fd,
        %cfg_arg,
        "starting outline-client with native TUN"
    );

    let opts = RunOptions { tun_fd: Some(tun_fd) };
    let client_task = runtime.spawn(async move {
        if let Err(e) = outline_client::run_with_options(client_args, opts).await {
...
            outline_client::clear_active_registry();
...
    outline_client::set_dial_timeout(secs.map(|s| Duration::from_secs(u64::from(s))));
...
    let status = handle.block_on(outline_client::active_carriers())?;
```

- [ ] **Step 2: Обновить `OutlineVpnService.kt` и документацию `android/`**

В `android/app/src/main/java/com/outline/proxy/OutlineVpnService.kt:593`:

```kotlin
                Log.i(TAG, "outline-client started with native TUN (fd=${tun.fd})")
```

Обновить упоминания `outline-ws-rust` $\to$ `outline-client` в `android/README.md`, `android/README.ru.md`, `android/CHANGELOG.md`, `android/CHANGELOG.ru.md` (синхронно для обеих языковых версий).

- [ ] **Step 3: Проверить detached workspace `android/rust`, очистить debug-артефакты и закоммитить**

```bash
(cd android/rust && cargo fmt --check && cargo clippy --no-deps -- -D warnings)
rm -rf android/rust/target/debug
git add android/
git commit -- android/ -m "refactor(android): switch dependency and bindings to outline-client"
```

Expected: `cargo fmt --check` и `cargo clippy --no-deps -- -D warnings` в `android/rust` проходят без предупреждений; `android/rust/Cargo.lock` обновлён под `outline-client`.

---

### Task 3: Обновление macOS-клиента (`macos/`)

**Files:**
- Modify: `macos/Sources/OutlineProxy/Core/Services/PrivilegedHelperManager.swift:11,56,75-118`
- Modify: `macos/Resources/tun-runner.sh:8,14,144,154`
- Modify: `macos/Sources/OutlineProxy/Core/Services/ProcessController.swift:3,56-85,143,160,229,242,317,373,412,421,438,469`
- Modify: `macos/Sources/OutlineProxy/Core/Services/ConfigGenerator.swift`
- Modify: `macos/Sources/OutlineProxy/Core/Services/UpdateChecker.swift:174`
- Modify: `macos/scripts/package-app.sh:28,30,39,96,106`
- Modify: `macos/scripts/package-dmg.sh:99-107,131-155,219,228`
- Modify: `macos/README.md`, `macos/README.ru.md`

**Interfaces:**
- Consumes: Пакет и бинарник `outline-client` (`bins/outline-client`) из Task 1.
- Produces: macOS-бандл `OutlineProxy.app` со встроенным `Contents/Resources/outline-client` и системным helper'ом в `/Library/Application Support/OutlineProxy/outline-client`.

- [ ] **Step 1: Обновить `PrivilegedHelperManager.swift` и `tun-runner.sh`**

В `macos/Sources/OutlineProxy/Core/Services/PrivilegedHelperManager.swift`:
- строку 11 заменить на:
```swift
    public static let systemBinaryPath = "/Library/Application Support/OutlineProxy/outline-client"
    private static let legacySystemBinaryPath = "/Library/Application Support/OutlineProxy/outline-ws-rust"
```
- строку 56 заменить на:
```swift
                NSLocalizedDescriptionKey: "Бинарник outline-client не найден для установки системного хелпера."
```
- в `installSudoersRule()` и `removeSudoersRule()` удалять `legacySystemBinaryPath`, чтобы у пользователей, обновившихся с прежней версии, не оставался старый `root:wheel` бинарник:
```swift
        let qLegacyBinary = Self.shellQuote(Self.legacySystemBinaryPath)
```
и добавить `rm -f \(qLegacyBinary)` внутри скрипта установки и удаления.

В `macos/Resources/tun-runner.sh`:
- строка 8: `# 1. The binary path is strictly fixed to root-owned /Library/Application Support/OutlineProxy/outline-client.`
- строка 14: `SYSTEM_BIN="/Library/Application Support/OutlineProxy/outline-client"`
- строка 144: `# 4. Launch outline-client in background from fixed root-owned path`
- строка 154: `echo "ERROR: outline-client terminated unexpectedly. Log:" >&2`

- [ ] **Step 2: Обновить `ProcessController.swift`, `ConfigGenerator.swift`, `UpdateChecker.swift`**

В `macos/Sources/OutlineProxy/Core/Services/ProcessController.swift` заменить все пути поиска бинарника, сообщения об ошибке и логи с `outline-ws-rust` на `outline-client` (включая `Bundle.main.resourceURL?.appendingPathComponent("outline-client")`, `target/{release,debug}/outline-client`, `/usr/local/bin/outline-client`, `/opt/homebrew/bin/outline-client`, `"Не найден бинарник outline-client. Запустите сборку ядра через cargo build -p outline-client."`).

Обновить doc-комментарии в `ConfigGenerator.swift` и `UpdateChecker.swift:174`.

- [ ] **Step 3: Обновить скрипты упаковки macOS и документацию**

В `macos/scripts/package-app.sh`:
- `echo "==> [1/4] Компиляция outline-client (release)..."`
- `cargo build -p outline-client --release`
- `RUST_BIN="${REPO_ROOT}/target/release/outline-client"`
- `cp "${RUST_BIN}" "${APP_BUNDLE}/Contents/Resources/outline-client"`
- `chmod +x "${APP_BUNDLE}/Contents/Resources/outline-client"`

В `macos/scripts/package-dmg.sh`:
- заменить все `-p outline-ws-rust` на `-p outline-client`, все пути `.../release/outline-ws-rust` на `.../release/outline-client` и `Contents/Resources/outline-ws-rust` на `Contents/Resources/outline-client`.

Синхронно обновить `macos/README.md` и `macos/README.ru.md` (включая пути триггеров `bins/outline-client/**`).

- [ ] **Step 4: Проверить синтаксис скриптов, сборку macOS-приложения и закоммитить**

```bash
bash -n macos/Resources/tun-runner.sh macos/scripts/package-app.sh macos/scripts/package-dmg.sh
shellcheck macos/Resources/tun-runner.sh macos/scripts/package-app.sh macos/scripts/package-dmg.sh
./macos/scripts/package-app.sh
test -x build/OutlineProxy.app/Contents/Resources/outline-client || find . -maxdepth 4 -path '*/Contents/Resources/outline-client' -perm +111
rm -rf target/debug
git add macos/
git commit -- macos/ -m "refactor(macos): embed and manage outline-client binary"
```

Expected: скрипты проходят `shellcheck`, `.app` собирается и содержит исполняемый `Contents/Resources/outline-client`.

---

### Task 4: Обновление Windows-клиента (`bins/outline-windows/`, `windows/`, `scripts/package-windows.sh`)

**Files:**
- Modify: `bins/outline-windows/src/process_controller.rs:17,61-85,116-123,214,236,239,261,318,421,460,522,533`
- Modify: `bins/outline-windows/src/tests/process_controller.rs:5,28,36,39,45,83,94,101,132`
- Modify: `bins/outline-windows/src/updater.rs:385-394`
- Modify: `bins/outline-windows/src/config_generator.rs:3,7`
- Modify: `bins/outline-windows/frontend/src/App.svelte:162`
- Modify: `scripts/package-windows.sh:47,55,296-301,384-396`
- Modify: `bins/outline-windows/{README.md,README.ru.md,CHANGELOG.md,CHANGELOG.ru.md}`
- Modify: `windows/{README.md,README.ru.md}`

**Interfaces:**
- Consumes: Пакет `outline-client` (`bins/outline-client`) из Task 1.
- Produces: Windows GUI `OutlineProxy.exe` и пакетный скрипт `scripts/package-windows.sh`, использующие `outline-client.exe` и очищающие устаревший `outline-ws-rust.exe` при автообновлении.

- [ ] **Step 1: Обновить `process_controller.rs`, `tests/process_controller.rs` и `updater.rs`**

В `bins/outline-windows/src/process_controller.rs`:
- переименовать функцию `find_outline_ws_binary()` $\to$ `find_outline_client_binary()`;
- использовать переменную окружения `OUTLINE_CLIENT_BIN`;
- установить `bin_name = "outline-client.exe"` (под `#[cfg(windows)]`) и `bin_name = "outline-client"` (под `#[cfg(not(windows))]`);
- обновить сообщение ошибки, `tracing` и UI-логи на `outline-client` (включая строку `"Failed to locate outline-client binary: {e}"`, `"Starting outline-client ..."` и т.д.).

В `bins/outline-windows/src/tests/process_controller.rs`:
- обновить импорт и тест `test_find_outline_client_binary_with_env_override` под `find_outline_client_binary` и `OUTLINE_CLIENT_BIN`.

В `bins/outline-windows/src/updater.rs` (строки 385–394 внутри `launch_updater`): после `xcopy`/`copy` удалить оставшийся от старых версий (`v26.11.0`) файл `outline-ws-rust.exe`:

```rust
            xcopy /Y /Q /E \"%STAGING_DIR%\\*\" \"%TARGET_DIR%\\\" >NUL\r\n\
            if errorlevel 1 (\r\n\
                copy /Y \"%STAGING_DIR%\\*.*\" \"%TARGET_DIR%\\\" >NUL\r\n\
            )\r\n\
            \r\n\
            if exist \"%TARGET_DIR%\\outline-ws-rust.exe\" del /F /Q \"%TARGET_DIR%\\outline-ws-rust.exe\" >NUL 2>&1\r\n\
            \r\n\
            start \"\" \"%TARGET_EXE%\"\r\n\
```

В `bins/outline-windows/src/config_generator.rs:3,7` и `bins/outline-windows/frontend/src/App.svelte:162` обновить комментарии на `outline-client`.

- [ ] **Step 2: Обновить `scripts/package-windows.sh` и документацию**

В `scripts/package-windows.sh`:
- строки 47, 55: описание `outline-client.exe`;
- строки 296–299: проверка `${REPO_ROOT}/bins/outline-client/Cargo.toml`;
- строки 384–396:
```bash
# 3. Сборка сетевого ядра outline-client
echo "==> [2/5] Компиляция сетевого ядра outline-client.exe (${TARGET_TRIPLE})..."
(cd "${REPO_ROOT}" && "${CARGO_CMD[@]}" -p outline-client)

WS_EXE="${TARGET_DIR}/release/outline-client.exe"
...
cp "${WS_EXE}" "${OUTPUT_DIR}/outline-client.exe"
...
PACK_FILES=("outline-client.exe" "wintun.dll")
```

Обновить двуязычную документацию `bins/outline-windows/README.md`, `README.ru.md`, `CHANGELOG.md`, `CHANGELOG.ru.md` и `windows/README.md`, `README.ru.md`.

- [ ] **Step 3: Проверить скрипт, фронтенд Windows-приложения и закоммитить**

```bash
bash -n scripts/package-windows.sh
shellcheck scripts/package-windows.sh
pnpm -C bins/outline-windows install --frozen-lockfile
pnpm -C bins/outline-windows build
git add bins/outline-windows/ windows/ scripts/package-windows.sh
git commit -- bins/outline-windows/ windows/ scripts/package-windows.sh -m "refactor(windows): switch core binary and packaging to outline-client"
```

Expected: `shellcheck` и `pnpm -C bins/outline-windows build` проходят чисто; `git grep -n "outline-ws-rust" bins/outline-windows/` возвращает только строчку удаления `outline-ws-rust.exe` в `updater.rs` (и, при желании, исторические записи в CHANGELOG — или их обновим аккуратно в документации). (Полная сборка и юнит-тесты MSVC `outline-windows` выполняются в CI job `windows`.)

---

### Task 5: Обновление Web-UI `outline-ui` (`bins/outline-ui/`)

**Files:**
- Modify: `bins/outline-ui/Dockerfile:6`
- Modify: `bins/outline-ui/frontend/src/features/ss/ServerSettings.svelte:287`
- Modify: `bins/outline-ui/frontend/src/features/ws/RouteDrawer.svelte:88`
- Modify: `bins/outline-ui/frontend/src/features/ws/UplinkDrawer.svelte:108`
- Modify: `bins/outline-ui/frontend/src/features/ws/WsSettings.svelte:712,782`
- Modify: `bins/outline-ui/frontend/src/lib/groupForm.ts:14`
- Modify: `bins/outline-ui/frontend/src/lib/types.ts:149,185,...`
- Modify: `bins/outline-ui/frontend/src/lib/uplinkForm.ts`
- Modify: `bins/outline-ui/frontend/src/lib/uplinkForm.test.ts`
- Modify: `bins/outline-ui/frontend/src/lib/userForm.ts`
- Modify: `bins/outline-ui/frontend/src/lib/wsTopology.ts`, `bins/outline-ui/frontend/src/lib/wsTopology.test.ts`
- Modify: `bins/outline-ui/src/ws/tests/mod.rs:172`
- Modify: `bins/outline-ui/{README.md,README.ru.md,CHANGELOG.md,CHANGELOG.ru.md}`

**Interfaces:**
- Consumes: Переименованные пути `bins/outline-server` и `bins/outline-client` (Task 1).
- Produces: Актуальный Svelte-фронтенд и Rust-обёртка `outline-ui` с корректными путями и UI-уведомлениями.

- [ ] **Step 1: Обновить UI-сообщения, placeholder'ы, комментарии и тесты в `bins/outline-ui/`**

1. В `bins/outline-ui/frontend/src/features/ss/ServerSettings.svelte:287`:
```ts
toast('Server settings saved. Restart outline-server to apply socket/TLS changes.');
```
2. В `bins/outline-ui/frontend/src/features/ws/WsSettings.svelte:712,782`:
```ts
toast('Settings saved. Restart outline-client service to bind new sockets or TUN device.');
```
```svelte
<span>Changes to SOCKS5 listen socket, TUN interface parameters, or dial/transport windows require restarting <code>outline-client</code>.</span>
```
3. В `bins/outline-ui/frontend/src/features/ws/RouteDrawer.svelte:88`:
```svelte
<textarea id="route-files" class="field-mono" rows="2" bind:value={fields.files} placeholder="/etc/outline-client/geoip-cn.list"></textarea>
```
4. Обновить комментарии и ссылки на исходники `bins/outline-server/...` и `bins/outline-client/...` в `Dockerfile`, `UplinkDrawer.svelte`, `frontend/src/lib/*.ts`, `src/ws/tests/mod.rs:172` и документации `bins/outline-ui/{README,CHANGELOG}{,.ru}.md`.

- [ ] **Step 2: Прогнать проверки фронтенда и Rust-сборки `outline-ui`, очистить `target/debug` и закоммитить**

```bash
pnpm -C bins/outline-ui/frontend install --frozen-lockfile
pnpm -C bins/outline-ui/frontend exec svelte-check --tsconfig ./tsconfig.app.json
pnpm -C bins/outline-ui/frontend exec vitest run
pnpm -C bins/outline-ui/frontend build
cargo test -p outline-ui --features embed-assets
rm -rf target/debug
git add bins/outline-ui/
git commit -- bins/outline-ui/ -m "refactor(ui): update service names and source references to outline-server/outline-client"
```

Expected: `svelte-check`, `vitest`, `pnpm build` и `cargo test -p outline-ui --features embed-assets` завершаются с кодом 0.

---

### Task 6: Systemd-юниты, Grafana-дашборды и примеры `config.toml`

**Files:**
- Rename & Modify: `bins/outline-server/systemd/outline-ss-rust.service` $\to$ `bins/outline-server/systemd/outline-server.service`
- Rename & Modify: `bins/outline-client/systemd/outline-ws-rust.service` $\to$ `bins/outline-client/systemd/outline-client.service`
- Rename & Modify: `bins/outline-client/systemd/outline-ws-rust@.service` $\to$ `bins/outline-client/systemd/outline-client@.service`
- Rename & Modify: `bins/outline-server/grafana/outline-ss-rust-dashboard.json` $\to$ `bins/outline-server/grafana/outline-server-dashboard.json`
- Rename & Modify: `bins/outline-client/grafana/outline-ws-rust-dashboard.json` $\to$ `bins/outline-client/grafana/outline-client-dashboard.json`
- Rename & Modify: `bins/outline-client/grafana/outline-ws-rust-hang-diagnostics.json` $\to$ `bins/outline-client/grafana/outline-client-hang-diagnostics.json`
- Modify: `bins/outline-client/grafana/README.md`
- Modify: `bins/outline-server/config.toml`, `bins/outline-client/config.toml`

**Interfaces:**
- Consumes: Директории `bins/outline-server` и `bins/outline-client` (Task 1).
- Produces: Готовые systemd-юниты и JSON-дашборды с сохранёнными стабильными UID (`outline-ss-rust`, `outline-ws-rust`, `outline-ws-rust-hang-diag`).

- [ ] **Step 1: Переименовать и обновить systemd-юниты**

```bash
git mv bins/outline-server/systemd/outline-ss-rust.service bins/outline-server/systemd/outline-server.service
git mv bins/outline-client/systemd/outline-ws-rust.service bins/outline-client/systemd/outline-client.service
git mv bins/outline-client/systemd/outline-ws-rust@.service bins/outline-client/systemd/outline-client@.service
```

В `bins/outline-server/systemd/outline-server.service`:
```ini
[Unit]
Description=outline-server Shadowsocks and VLESS proxy relay
Documentation=https://github.com/balookrd/outline-proxy
...
[Service]
User=outline-server
Group=outline-server
Environment=RUST_LOG=outline_server=info,tower_http=info
Environment=NO_COLOR=1
ExecStart=/usr/local/bin/outline-server --config /etc/outline-server/config.toml
...
SyslogIdentifier=outline-server
...
WorkingDirectory=/var/lib/outline-server
...
ReadWritePaths=/etc/outline-server
StateDirectory=outline-server
RuntimeDirectory=outline-server
RuntimeDirectoryMode=0750
```

В `bins/outline-client/systemd/outline-client.service`:
```ini
[Unit]
Description=SOCKS5/TUN to Outline proxy client (outline-client)
Documentation=https://github.com/balookrd/outline-proxy
...
Environment=STATE_PATH=/var/lib/outline-client/_default/state.toml
ExecStart=/usr/local/bin/outline-client --config /etc/outline-client/config.toml
...
User=outline-client
Group=outline-client
StateDirectory=outline-client/_default
LogsDirectory=outline-client/_default
RuntimeDirectory=outline-client
WorkingDirectory=/var/lib/outline-client/_default
...
ReadWritePaths=/var/lib/outline-client/_default /var/log/outline-client/_default /etc/outline-client
```

В `bins/outline-client/systemd/outline-client@.service`:
```ini
[Unit]
Description=SOCKS5/TUN to Outline proxy client instance %i (outline-client)
Documentation=https://github.com/balookrd/outline-proxy
...
Environment=STATE_PATH=/var/lib/outline-client/%i/state.toml
ExecStart=/usr/local/bin/outline-client --config /etc/outline-client/instances/%i.toml
...
User=outline-client
Group=outline-client
StateDirectory=outline-client/%i
LogsDirectory=outline-client/%i
RuntimeDirectory=outline-client-%i
WorkingDirectory=/var/lib/outline-client/%i
...
ReadWritePaths=/var/lib/outline-client/%i /etc/outline-client/instances
```

- [ ] **Step 2: Переименовать и обновить JSON-дашборды Grafana и примеры `config.toml`**

```bash
git mv bins/outline-server/grafana/outline-ss-rust-dashboard.json bins/outline-server/grafana/outline-server-dashboard.json
git mv bins/outline-client/grafana/outline-ws-rust-dashboard.json bins/outline-client/grafana/outline-client-dashboard.json
git mv bins/outline-client/grafana/outline-ws-rust-hang-diagnostics.json bins/outline-client/grafana/outline-client-hang-diagnostics.json
```

Обновить в этих трёх JSON **только** `"description"` и `"title"`, **не трогая** `"uid"` и запросы Prometheus (`outline_ss_*`, `outline_ws_*`):
- `outline-server-dashboard.json`: `"description": "Production dashboard for outline-server Prometheus metrics."`, `"title": "outline-server"`, `"uid": "outline-ss-rust"` (оставить).
- `outline-client-dashboard.json`: `"title": "outline-client"`, `"uid": "outline-ws-rust"` (оставить).
- `outline-client-hang-diagnostics.json`: `"title": "outline-client hang diagnostics"`, `"uid": "outline-ws-rust-hang-diag"` (оставить).

Обновить `bins/outline-client/grafana/README.md`, а также комментарии в `bins/outline-server/config.toml` и `bins/outline-client/config.toml`.

- [ ] **Step 3: Валидировать JSON/юниты и закоммитить**

```bash
python3 -B -m json.tool bins/outline-server/grafana/outline-server-dashboard.json >/dev/null
python3 -B -m json.tool bins/outline-client/grafana/outline-client-dashboard.json >/dev/null
python3 -B -m json.tool bins/outline-client/grafana/outline-client-hang-diagnostics.json >/dev/null
git add bins/outline-server/systemd/ bins/outline-client/systemd/ bins/outline-server/grafana/ bins/outline-client/grafana/ bins/outline-server/config.toml bins/outline-client/config.toml
git commit -- bins/outline-server/systemd/ bins/outline-client/systemd/ bins/outline-server/grafana/ bins/outline-client/grafana/ bins/outline-server/config.toml bins/outline-client/config.toml -m "refactor(ops): rename systemd units, config examples and Grafana dashboards"
```

Expected: все три JSON валидны, `uid` дашбордов остались прежними.

---

### Task 7: Инсталляторы и операционные скрипты (`install-*.sh`, `deploy-binary.sh`, `watchdog`, `memory-tuning`, `nanopi104-backup`, `heartbeat`, `quic-initial-sink.py`)

**Files:**
- Modify: `install-server.sh`
- Modify: `install-client.sh`
- Modify: `ops/deploy/deploy-binary.sh:9,35-39`
- Modify: `ops/watchdog/outline-watchdog:18-19`
- Modify: `ops/watchdog/install.sh:22,55`
- Modify: `ops/watchdog/README.md`
- Modify: `ops/memory-tuning/apply.sh:150-151`
- Modify: `ops/memory-tuning/{README.md,README.ru.md}`
- Modify: `ops/nanopi104-backup/{backup-p9.sh,nanopi104-backup.default,README.md}`
- Modify: `ops/heartbeat/{heartbeat-watch,install.sh,nginx-heartbeat.conf,README.md}`
- Modify: `scripts/quic-initial-sink.py:14`

**Interfaces:**
- Consumes: Юниты `outline-server` и `outline-client` (Task 6) и rolling nightly-теги `server-nightly` / `client-nightly` (Task 9).
- Produces: Инсталляторы и сервисные скрипты, согласованные с `check-install-scripts.sh`.

- [ ] **Step 1: Обновить `install-server.sh` и `install-client.sh` (соблюдая байтовую идентичность общих хелперов)**

В `install-server.sh`:
- задать `NIGHTLY_TAG="server-nightly"` (и использовать `releases/tags/${NIGHTLY_TAG}` / `git/ref/tags/${NIGHTLY_TAG}` вместо `${TAG_PREFIX}nightly`, при этом в `strip_v()` и `resolve_release()` сохранить `TAG_PREFIX=""` или совместимость `vYY.M.PATCH` и общих функций `SHARED_FUNCS`, чтобы `check-install-scripts.sh` прошёл!);
- `BINARY_NAME="outline-server"`
- `SERVICE_NAME="${SERVICE_NAME:-outline-server.service}"`
- `CONFIG_DIR="${CONFIG_DIR:-/etc/outline-server}"`
- `STATE_DIR="${STATE_DIR:-/var/lib/outline-server}"`
- `SERVICE_USER="${SERVICE_USER:-outline-server}"`
- `SERVICE_GROUP="${SERVICE_GROUP:-outline-server}"`
- пути загрузки в `tag_raw_url`: `"bins/outline-server/config.toml"` и `"bins/outline-server/systemd/${SERVICE_NAME}"`.

В `install-client.sh`:
- задать `NIGHTLY_TAG="client-nightly"` (аналогично `install-server.sh`, оставив `SHARED_FUNCS` байт-в-байт идентичными между двумя инсталляторами!);
- `BINARY_NAME="${BINARY_NAME:-outline-client}"`
- `CONFIG_DIR="${CONFIG_DIR:-/etc/outline-client}"`
- `STATE_DIR="${STATE_DIR:-/var/lib/outline-client}"`
- `BIN_SUBDIR="bins/outline-client"`
- `SERVICE_NAME="outline-client.service"`
- `TEMPLATE_NAME="outline-client@.service"`
- `SERVICE_USER="${SERVICE_USER:-outline-client}"`
- `SERVICE_GROUP="${SERVICE_GROUP:-outline-client}"`
- в `resolve_raw_urls()`: `.../systemd/outline-client.service` и `.../systemd/outline-client@.service`
- в `collect_active_units()` и `list_known_units()`: `grep -E '^outline-client(\.service|@.+\.service)$'`
- обновить `TMP_DIR` префикс и help/лог-сообщения с `outline-ws-rust` на `outline-client`.

- [ ] **Step 2: Обновить `deploy-binary.sh`, `watchdog`, `memory-tuning`, `nanopi104-backup`, `heartbeat`, `quic-initial-sink.py`**

1. В `ops/deploy/deploy-binary.sh` (строки 9, 35–39):
```bash
#   unit   outline-server | outline-client
...
case "$UNIT" in
	outline-client) PORT=9091 ;;
	outline-server) PORT=9090 ;;
	*) die "unknown unit '$UNIT' (expected outline-client or outline-server)" ;;
esac
```
2. В `ops/watchdog/outline-watchdog` (строки 17–20):
```bash
case "$unit" in
    outline-client*) default_url="http://127.0.0.1:9091/metrics" ;;
    outline-server*) default_url="http://127.0.0.1:9090/metrics" ;;
esac
```
   В `ops/watchdog/install.sh:22,55`: `for unit in outline-client outline-server; do` и пример вызова `outline-watchdog outline-client`. Обновить `ops/watchdog/README.md`.
3. В `ops/memory-tuning/apply.sh:150-151`:
```bash
	apply_unit "$host" outline-client "$ws_high" "$ws_max" 1
	apply_unit "$host" outline-server "$ss_high" "$ss_max" 0
```
   Обновить `ops/memory-tuning/{README.md,README.ru.md}`.
4. В `ops/nanopi104-backup/backup-p9.sh:27,42,45`, `nanopi104-backup.default:13`, `README.md`: заменить `outline-ws-rust` на `outline-client` (`SERVICE="${SERVICE:-outline-client.service}"`).
5. Обновить комментарии/доки в `ops/heartbeat/{heartbeat-watch,install.sh,nginx-heartbeat.conf,README.md}` и `scripts/quic-initial-sink.py:14`.

- [ ] **Step 3: Прогнать гейт инсталляторов, `shellcheck`, компиляцию Python-скриптов и закоммитить**

```bash
.github/scripts/check-install-scripts.sh
bash -n ops/deploy/deploy-binary.sh ops/watchdog/outline-watchdog ops/watchdog/install.sh ops/memory-tuning/apply.sh ops/nanopi104-backup/backup-p9.sh ops/heartbeat/install.sh
shellcheck ops/deploy/deploy-binary.sh ops/watchdog/outline-watchdog ops/watchdog/install.sh ops/memory-tuning/apply.sh ops/nanopi104-backup/backup-p9.sh ops/heartbeat/install.sh
PYTHONDONTWRITEBYTECODE=1 python3 -B -m py_compile ops/heartbeat/heartbeat-watch scripts/quic-initial-sink.py
git add install-server.sh install-client.sh ops/deploy/deploy-binary.sh ops/watchdog/ ops/memory-tuning/ ops/nanopi104-backup/ ops/heartbeat/ scripts/quic-initial-sink.py
git commit -- install-server.sh install-client.sh ops/deploy/deploy-binary.sh ops/watchdog/ ops/memory-tuning/ ops/nanopi104-backup/ ops/heartbeat/ scripts/quic-initial-sink.py -m "refactor(ops): update installers, deploy-binary, watchdog and ops scripts to outline-server/outline-client"
```

Expected: `.github/scripts/check-install-scripts.sh` выводит `install scripts OK: syntax, shellcheck, 9 shared helpers identical`, `shellcheck` без предупреждений.

---

### Task 8: Генератор `ops/access-keys/` и `ops/provision-node/`

**Files:**
- Modify: `ops/access-keys/generate_keys.py:5,28,115`
- Modify: `ops/access-keys/config_model.py:2`
- Modify: `ops/access-keys/ws_toml.py:2,329`
- Modify: `ops/access-keys/xray_json.py:56`
- Modify: `ops/access-keys/nginx-subscription-headers.conf:15`
- Modify: `ops/access-keys/golden/expected/*.toml`, `ops/access-keys/golden/expected-ws/*.toml`
- Modify: `ops/access-keys/README.md`, `ops/access-keys/golden/README.md`
- Modify: `ops/provision-node/collect-from-reference.sh:314-340`
- Modify: `ops/provision-node/install.sh:385-406,568-595,772-855,1011-1015,1231,1270,1444-1470,1537,1723`
- Modify: `ops/provision-node/register-uplink-user.sh:146-161,350`
- Modify: `ops/provision-node/profiles/cloud1.conf`, `ops/provision-node/profiles/nuxt.conf`
- Modify: `ops/provision-node/{README.md,README.ru.md}`

**Interfaces:**
- Consumes: Новые пути `/etc/outline-server/config.toml`, `/etc/outline-client/`, юниты `outline-server`/`outline-client` и пользователи `outline-server`/`outline-client` (Task 6).
- Produces: Актуализированные скрипты генерации ключей и провижининга узлов с проходящими golden-тестами.

- [ ] **Step 1: Обновить `ops/access-keys/` и golden-файлы**

1. В `ops/access-keys/generate_keys.py`:
   - строка 28: `DEFAULT_CONFIG = "/etc/outline-server/config.toml"`
   - строка 115: `help="outline-server config.toml"`
   - строка 5 (docstring): `<user>.toml (outline-client config for ...)`
2. В `ops/access-keys/ws_toml.py`:
   - строка 2: `"""Build an outline-client config for the Android app.`
   - строка 329: `"# outline-client client config for the Android app.",`
3. В `ops/access-keys/golden/expected/*.toml` и `ops/access-keys/golden/expected-ws/*.toml` обновить первую строку комментария на `# outline-client client config for the Android app.`.
4. Обновить комментарии и доки в `config_model.py`, `xray_json.py`, `nginx-subscription-headers.conf`, `ops/access-keys/README.md`, `ops/access-keys/golden/README.md` (особо следить, чтобы не затронуть плейсхолдер `<keys-dir>` и логику `write_dir`).

- [ ] **Step 2: Обновить `ops/provision-node/` и профили `cloud1.conf` / `nuxt.conf`**

1. В `ops/provision-node/collect-from-reference.sh`:
   - `/usr/local/bin/outline-server --version` и `/usr/local/bin/outline-client --version`
   - чтение `write_dir` из `/etc/outline-server/config.toml` (и проверка `/opt/outline/outline-server/save-keys.sh` или legacy `/opt/outline/outline-ss-rust/save-keys.sh` в качестве резерва).
2. В `ops/provision-node/install.sh`:
   - создание пользователей `outline-server` (`--home-dir /var/lib/outline-server`) и `outline-client` (`--home-dir /var/lib/outline-client`), группа `certs` для `outline-server`;
   - директории `/var/lib/outline-server`, `/var/lib/outline-client`, `/var/log/outline-client`;
   - конфиги `/etc/outline-server/config.toml`, `/etc/outline-client/config.toml`, `/etc/outline-client/instances` и права (`chown -R outline-server:outline-server /etc/outline-server`, `chown -R outline-client:outline-client /etc/outline-client`);
   - `_write_memory_dropin outline-client` и `_write_memory_dropin outline-server`;
   - `save-keys.sh` в `/opt/outline/outline-server/save-keys.sh` (при миграции проверяется и прежнее расположение при необходимости).
3. В `ops/provision-node/register-uplink-user.sh`:
   - проверки `/usr/local/bin/outline-server` и `/etc/outline-server/config.toml`;
   - подсказка перезапуска `systemctl restart outline-client`.
4. В `ops/provision-node/profiles/cloud1.conf` и `ops/provision-node/profiles/nuxt.conf`:
   - `BIN_PATHS`, `UNIT_PATHS`, `SECRETS`, `REHOST_CONFIG_FILES`, `REHOST_ACCESS_KEYS_FILES`, `NET_BRINGUP_BEFORE`, `ENABLE_UNITS`, `VERIFY_UNITS`, `VERIFY_TIMERS` перевести на `outline-server` и `outline-client` (порт/метрики 9090/9091 без изменений).
5. Синхронно обновить `ops/provision-node/README.md` и `ops/provision-node/README.ru.md`.

- [ ] **Step 3: Прогнать тесты `ops/access-keys`, проверку секретного пути, `shellcheck` и закоммитить**

```bash
PYTHONDONTWRITEBYTECODE=1 python3 -B -m unittest discover -s ops/access-keys
.github/scripts/check-served-key-path.sh
bash -n ops/provision-node/collect-from-reference.sh ops/provision-node/install.sh ops/provision-node/register-uplink-user.sh ops/provision-node/profiles/cloud1.conf ops/provision-node/profiles/nuxt.conf
shellcheck ops/provision-node/collect-from-reference.sh ops/provision-node/install.sh ops/provision-node/register-uplink-user.sh ops/provision-node/profiles/cloud1.conf ops/provision-node/profiles/nuxt.conf
git add ops/access-keys/ ops/provision-node/
git commit -- ops/access-keys/ ops/provision-node/ -m "refactor(ops): switch access-keys and provision-node to outline-server/outline-client"
```

Expected: все unit/golden-тесты `access-keys` зелёные, ни одного `*.pyc` файла не появилось, `check-served-key-path.sh` и `shellcheck` проходят чисто.

---

### Task 9: GitHub Actions и релизные скрипты (`.github/`)

**Files:**
- Modify: `.github/workflows/ci.yml:64,132,138,158,163,166,190,204,212`
- Modify: `.github/workflows/release.yml:118-119,157`
- Modify: `.github/workflows/tag-release.yml:17-32,70-71,93-99`
- Rename & Modify: `.github/workflows/_ss-release-build.yml` $\to$ `.github/workflows/_server-release-build.yml`
- Rename & Modify: `.github/workflows/_ws-release-build.yml` $\to$ `.github/workflows/_client-release-build.yml`
- Rename & Modify: `.github/workflows/ss-nightly-release.yml` $\to$ `.github/workflows/server-nightly-release.yml`
- Rename & Modify: `.github/workflows/ws-nightly-release.yml` $\to$ `.github/workflows/client-nightly-release.yml`
- Modify: `.github/workflows/android-nightly-release.yml:10,13`
- Modify: `.github/workflows/macos-nightly-release.yml:10`
- Modify: `.github/workflows/windows-nightly-release.yml:10`
- Modify: `.github/workflows/_windows-release-build.yml:4`
- Modify: `.github/scripts/build-release-asset.sh:6,14,22,25,27`
- Modify: `.github/scripts/gen-release-notes.sh:5,23-30,41,45,71,78`

**Interfaces:**
- Consumes: Имена пакетов и алиасов из Task 1 (`outline-server`, `outline-client`, `server-release-musl-*`).
- Produces: Актуальный CI-гейт, единый CalVer `release.yml` / `tag-release.yml` и rolling `server-nightly` / `client-nightly`.

- [ ] **Step 1: Переименовать воркфлоу и обновить `.github/scripts/`**

```bash
git mv .github/workflows/_ss-release-build.yml .github/workflows/_server-release-build.yml
git mv .github/workflows/_ws-release-build.yml .github/workflows/_client-release-build.yml
git mv .github/workflows/ss-nightly-release.yml .github/workflows/server-nightly-release.yml
git mv .github/workflows/ws-nightly-release.yml .github/workflows/client-nightly-release.yml
```

1. В `.github/scripts/build-release-asset.sh`:
   - `flavor`: принимать `client` (и обновить `usage: $0 <target> <profile> <flavor: client> <output-dir>`);
   - `binary_name="outline-client"`;
   - `cargo zigbuild --release -p outline-client --target "$target"` / `--profile "$profile" -p outline-client --target "$target"`.
2. В `.github/scripts/gen-release-notes.sh`:
   - `component : all | server | client | ui | android | macos | windows`;
   - `server)` $\to$ `prefix="server"`, `paths=(bins/outline-server crates/outline-net crates/outline-wire crates/outline-transport vendor)`;
   - `client)` $\to$ `prefix="client"`, `paths=(bins/outline-client crates vendor)`;
   - `macos)` / `windows)` $\to$ заменить `bins/outline-ws-rust` на `bins/outline-client`;
   - в ветке `all` строку-якорь первого CalVer-релиза `grep -E '^(ss|ws|ui|android|macos|windows)-v[0-9]+\.[0-9]+\.[0-9]+$'` **оставить с `ss|ws`** (это исторические теги в git), опционально добавив `server|client` на будущее.

- [ ] **Step 2: Обновить `.github/workflows/*`**

1. В `.github/workflows/ci.yml`:
   - строка 64: `-p outline-server -p outline-client -p outline-ui`
   - строка 132 (комментарий) и строка 138: `cargo test -p outline-client --features test-tls --test 'e2e_*' -- --test-threads=1`
   - строки 158, 163, 166: `cargo check -p outline-server --no-default-features`, `--features test-hooks`, `cargo check -p outline-client --no-default-features`
   - строки 190 и 212 (оба vendored-гейта `sockudo-ws` и `quinn-proto`!): заменить `^bins/outline-ss-rust/src/server/h3/vendored\.rs:` на `^bins/outline-server/src/server/h3/vendored\.rs:`.
2. В `.github/workflows/release.yml`:
   - строки 118–119 в `workspace_packages`: `"outline-server"`, `"outline-client"`;
   - строка 157: `required_android_pkgs = {"outline-android", "outline-client"}`.
3. В `.github/workflows/tag-release.yml`:
   - `build_server:` $\to$ `uses: ./.github/workflows/_server-release-build.yml`
   - `build_client:` $\to$ `uses: ./.github/workflows/_client-release-build.yml`
   - `needs: [build_server, build_client, build_ui, build_android, build_macos, build_windows]`
   - в проверке ассетов: `server=(dist/outline-server-*.tar.gz)`, `client=(dist/outline-client-*.tar.gz)`, `for group in server client ui apk dmg win; do`.
4. В `.github/workflows/_server-release-build.yml`:
   - матрица `alias: server-release-musl-x86_64` и `server-release-musl-aarch64`;
   - `name="outline-server-${VERSION}-${{ matrix.target }}"`, `cp "target/${{ matrix.target }}/release/outline-server" "dist/${name}"`;
   - `name: release-server-${{ matrix.target }}`, `pattern: release-server-*`;
   - `gen-release-notes.sh server "$TAG" release-notes.md`.
5. В `.github/workflows/_client-release-build.yml`:
   - матрица `artifact_name: client-x86_64-unknown-linux-musl` и `client-aarch64-unknown-linux-musl`, `flavor: client`;
   - `name: release-client-${{ matrix.artifact_name }}`, `pattern: release-client-*`;
   - `gen-release-notes.sh client "$TAG" release-notes.md`.
6. В `.github/workflows/server-nightly-release.yml`:
   - пути: `"bins/outline-server/**"`, `".github/workflows/server-nightly-release.yml"`, `".github/workflows/_server-release-build.yml"`;
   - `uses: ./.github/workflows/_server-release-build.yml`, `tag: server-nightly`, `group: server-nightly-release`.
7. В `.github/workflows/client-nightly-release.yml`:
   - пути: `"bins/outline-client/**"`, `".github/workflows/client-nightly-release.yml"`, `".github/workflows/_client-release-build.yml"`;
   - `uses: ./.github/workflows/_client-release-build.yml`, `tag: client-nightly`, `group: client-nightly-release`.
8. В `android-nightly-release.yml`, `macos-nightly-release.yml`, `windows-nightly-release.yml` заменить `"bins/outline-ws-rust/**"` на `"bins/outline-client/**"`, в `_windows-release-build.yml:4` — комментарий на `outline-client.exe`.

- [ ] **Step 3: Провалидировать скрипты и YAML, закоммитить**

```bash
bash -n .github/scripts/build-release-asset.sh .github/scripts/gen-release-notes.sh
shellcheck .github/scripts/build-release-asset.sh .github/scripts/gen-release-notes.sh
PYTHONDONTWRITEBYTECODE=1 python3 -B -c '
import pathlib, yaml
for p in sorted(pathlib.Path(".github/workflows").glob("*.yml")):
    yaml.safe_load(p.read_text())
print("all workflow YAML valid")
'
git add .github/
git commit -- .github/ -m "ci: update workflows, release scripts and invariants to outline-server/outline-client"
```

Expected: все workflow YAML валидны (если `pyyaml` не установлен, проверить парсинг через доступный YAML-парсер или ruby `ruby -ryaml -e 'Dir[".github/workflows/*.yml"].each { |f| YAML.load_file(f) }; puts "OK"'`), `shellcheck` без замечаний.

---

### Task 10: Двуязычная документация репозитория (`AGENTS.md`, `CLAUDE.md`, `README*`, `PATCHES*`, `docs/*`)

**Files:**
- Modify: `AGENTS.md`, `CLAUDE.md`
- Modify: `README.md`, `README.ru.md`
- Modify: `PATCHES.md`, `PATCHES.ru.md`
- Modify: `CHANGELOG.md`, `CHANGELOG.ru.md`
- Modify: `bins/outline-server/{AGENTS.md,README.md,README.ru.md,PATCHES.md,PATCHES.ru.md,CHANGELOG.md,CHANGELOG.ru.md,docs/ARCHITECTURE.md,docs/ARCHITECTURE.ru.md,docs/SESSION-RESUMPTION.md,docs/SESSION-RESUMPTION.ru.md}`
- Modify: `bins/outline-client/{AGENTS.md,README.md,README.ru.md,PATCHES.md,PATCHES.ru.md,CHANGELOG.md,CHANGELOG.ru.md,docs/TUN-GSO.md,docs/TUN-GSO.ru.md,docs/TUN-PMTUD.md,docs/TUN-PMTUD.ru.md,docs/UPLINK-CONFIGURATIONS.md,docs/UPLINK-CONFIGURATIONS.ru.md}`
- Modify: `docs/{CLUSTER,CLUSTER-DEPLOY,CODE-INDEX,OUTBOUND-IPV6,PADDING}{.md,.ru.md}`
- Modify: `scripts/fingerprint-drift/{README.md,README.ru.md}`

**Interfaces:**
- Consumes: Новая раскладка каталогов, юнитов, команд и алиасов (Tasks 1–9).
- Produces: Полностью синхронизированная документация EN и RU.

- [ ] **Step 1: Обновить корневые `AGENTS.md`, `CLAUDE.md`, `README*`, `PATCHES*`, `CHANGELOG*`**

1. В `AGENTS.md` и `CLAUDE.md` обновить:
   - пути `bins/outline-server/`, `bins/outline-client/`;
   - команды CI-гейта (`cargo fmt --check -p outline-server -p outline-client ...`, `RUN_E2E_FAILOVER=1 cargo test -p outline-client ...`);
   - алиасы `cargo server-release-musl-x86_64`, `cargo client-release-musl-aarch64`;
   - инварианты (`bins/outline-server/src/server/h3/vendored.rs`, модель `[[endpoint]]` в `outline-server`, SOCKS5 auth в `outline-client`).
2. Обновить парные `README.md` / `README.ru.md`, `PATCHES.md` / `PATCHES.ru.md` и верхний/актуальный блок `CHANGELOG.md` / `CHANGELOG.ru.md` (исторические записи за старые релизы можно не переписывать в архиве, либо снабдить примечанием о переименовании — главное, чтобы актуальная шапка и все команды/ссылки на файлы вели на `outline-server` / `outline-client`).

- [ ] **Step 2: Обновить документацию внутри `bins/outline-server/`, `bins/outline-client/`, `docs/` и `scripts/fingerprint-drift/`**

Обновить обе языковые версии (`*.md` и `*.ru.md`) в каждом каталоге:
- пути файлов, systemd-юниты, `/etc/outline-server`, `/etc/outline-client`, `/var/lib/outline-server`, `/var/lib/outline-client`, команды `cargo ... -p outline-server` / `-p outline-client`, имена бинарей в примерах, ссылки между документами.
- Проверить целостность перекрёстных ссылок (ни одной битой ссылки на `bins/outline-ss-rust` или `bins/outline-ws-rust`).

- [ ] **Step 3: Аудит остаточных вхождений и коммит**

```bash
git grep -n -E "outline[-_](ss|ws)[-_]rust" -- ':!vendor' ':!target' ':!*.lock' ':!docs/superpowers' ':!*CHANGELOG*'
```

Expected: остаются **только** осознанно сохранённые места:
- `crates/outline-uplink/src/manager/sync_order.rs`: `SYNC_SEED_CONTEXT = "outline-ws-rust reselect-sync seed v1"`
- `bins/outline-server/grafana/outline-server-dashboard.json`: `"uid": "outline-ss-rust"`
- `bins/outline-client/grafana/outline-client-dashboard.json`: `"uid": "outline-ws-rust"`
- `bins/outline-client/grafana/outline-client-hang-diagnostics.json`: `"uid": "outline-ws-rust-hang-diag"`
- `bins/outline-windows/src/updater.rs`: очистка старого `outline-ws-rust.exe` при апдейте
- (до Task 11) документация `ops/deploy/README.md` и `ops/deploy/cluster-v5-rollout.md` (исторический лог)

После проверки закоммитить:

```bash
git add AGENTS.md CLAUDE.md README.md README.ru.md PATCHES.md PATCHES.ru.md CHANGELOG.md CHANGELOG.ru.md bins/outline-server/ bins/outline-client/ docs/CLUSTER* docs/CODE-INDEX* docs/OUTBOUND-IPV6* docs/PADDING* scripts/fingerprint-drift/
git commit -- AGENTS.md CLAUDE.md README.md README.ru.md PATCHES.md PATCHES.ru.md CHANGELOG.md CHANGELOG.ru.md bins/outline-server/ bins/outline-client/ docs/CLUSTER* docs/CODE-INDEX* docs/OUTBOUND-IPV6* docs/PADDING* scripts/fingerprint-drift/ -m "docs: synchronize EN/RU documentation for outline-server and outline-client"
```

---

### Task 11: Скрипт чистой миграции узла парка `ops/deploy/migrate-node-rename.sh` и обновление `ops/deploy/README.md`

**Files:**
- Create: `ops/deploy/migrate-node-rename.sh`
- Modify: `ops/deploy/README.md`

**Interfaces:**
- Consumes: Бинарники `target/<arch>-unknown-linux-musl/release/outline-{server,client}`, юниты из `bins/outline-{server,client}/systemd/`, скрипт `ops/watchdog/outline-watchdog`.
- Produces: Идемпотентный скрипт безопасного перевода одного хоста парка со старых сервисов на `outline-server` / `outline-client` с поддержкой `--audit`, `--dry-run`, SSH `ControlMaster` и полного автоотката.

- [ ] **Step 1: Написать `ops/deploy/migrate-node-rename.sh`**

Создать исполняемый файл `ops/deploy/migrate-node-rename.sh` (chmod `+x`) со следующей полной реализацией:

```bash
#!/usr/bin/env bash
#
# migrate-node-rename.sh — чистый перевод одного узла парка с
# outline-ss-rust / outline-ws-rust на outline-server / outline-client
# без создания симлинков, с полным снимком состояния и автооткатом.
#
# Использование:
#   ops/deploy/migrate-node-rename.sh <host> <server|client|all> [--audit | --dry-run]
#
# По умолчанию бинари берутся из:
#   target/<arch>-unknown-linux-musl/release/outline-server
#   target/<arch>-unknown-linux-musl/release/outline-client
# (можно переопределить через SERVER_BIN=... и CLIENT_BIN=...).

set -euo pipefail

die() { echo "error: $*" >&2; exit 1; }
log() { echo "==> $*"; }

[ $# -ge 2 ] || die "usage: $0 <host> <server|client|all> [--audit | --dry-run]"
HOST="$1"
ROLE="$2"
shift 2

MODE="apply"
while [ $# -gt 0 ]; do
	case "$1" in
		--audit)   MODE="audit" ;;
		--dry-run) MODE="dry-run" ;;
		*) die "unknown option '$1' (expected --audit or --dry-run)" ;;
	esac
	shift
done

DO_SERVER=0
DO_CLIENT=0
case "$ROLE" in
	server) DO_SERVER=1 ;;
	client) DO_CLIENT=1 ;;
	all)    DO_SERVER=1; DO_CLIENT=1 ;;
	*) die "unknown role '$ROLE' (expected server, client, or all)" ;;
esac

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

sha256_local() {
	if command -v sha256sum >/dev/null 2>&1; then
		sha256sum "$1" | cut -d' ' -f1
	else
		shasum -a 256 "$1" | cut -d' ' -f1
	fi
}

elf_arch() {
	case "$(file -b "$1")" in
		*x86-64*)  echo "x86_64" ;;
		*aarch64*) echo "aarch64" ;;
		*) die "cannot tell architecture of $1 — expected Linux ELF binary" ;;
	esac
}

# Единое SSH-соединение через ControlMaster защищает от блокировки sshguard.
CTRL_DIR="$(mktemp -d)"
CTRL_SOCK="$CTRL_DIR/ssh.sock"
SSH_OPTS=(
	-o BatchMode=yes
	-o ConnectTimeout=15
	-o ControlMaster=auto
	-o "ControlPath=$CTRL_SOCK"
	-o ControlPersist=60
)

cleanup() {
	ssh -O exit "${SSH_OPTS[@]}" "$HOST" >/dev/null 2>&1 || true
	rm -rf "$CTRL_DIR"
}
trap cleanup EXIT

HOST_ARCH="$(ssh "${SSH_OPTS[@]}" "$HOST" 'uname -m')"
[ -n "$HOST_ARCH" ] || die "failed to detect architecture on $HOST"
log "$HOST: arch=$HOST_ARCH, role=$ROLE, mode=$MODE"

if [ "$MODE" = "audit" ]; then
	ssh "${SSH_OPTS[@]}" "$HOST" 'sudo -n bash -s' <<'AUDIT'
set -euo pipefail
echo "--- systemd units (outline-*) ---"
systemctl list-unit-files 'outline-*' --no-legend --no-pager || true
echo "--- active/failed outline units ---"
systemctl list-units --all 'outline-*' --no-legend --no-pager || true
echo "--- drop-in directories ---"
ls -la /etc/systemd/system/outline-*.service.d 2>/dev/null || echo "(none)"
echo "--- post-up.service ---"
grep -E '^(Before|After|ExecStart)=' /etc/systemd/system/post-up.service 2>/dev/null || echo "(no post-up.service)"
echo "--- users & groups ---"
for u in outline-ss-rust outline-ws outline-server outline-client; do
	id "$u" 2>/dev/null || true
done
echo "--- /usr/local/bin & /etc & /var/lib & /var/log ---"
ls -ld /usr/local/bin/outline-* /etc/outline-* /var/lib/outline-* /var/log/outline-* 2>/dev/null || true
echo "--- config.toml path references ---"
grep -n 'outline-[sw]s-rust' /etc/outline-ws-rust/config.toml /etc/outline-ss-rust/config.toml 2>/dev/null || echo "(none)"
echo "--- helper scripts (/opt/outline, /opt/ddns, /etc/default/nanopi104-backup) ---"
grep -rn 'outline-[sw]s-rust\|outline-ws\b' /opt/outline/ /opt/ddns/*/permission-certs.sh /etc/default/nanopi104-backup 2>/dev/null || echo "(none)"
AUDIT
	exit 0
fi

MUSL_TARGET="${HOST_ARCH}-unknown-linux-musl"
SERVER_BIN="${SERVER_BIN:-$REPO_ROOT/target/$MUSL_TARGET/release/outline-server}"
CLIENT_BIN="${CLIENT_BIN:-$REPO_ROOT/target/$MUSL_TARGET/release/outline-client}"

WATCHDOG_BIN="$REPO_ROOT/ops/watchdog/outline-watchdog"
[ -f "$WATCHDOG_BIN" ] || die "missing $WATCHDOG_BIN"

SERVER_UNIT_FILE="$REPO_ROOT/bins/outline-server/systemd/outline-server.service"
CLIENT_UNIT_FILE="$REPO_ROOT/bins/outline-client/systemd/outline-client.service"
CLIENT_TPL_FILE="$REPO_ROOT/bins/outline-client/systemd/outline-client@.service"

STAGE_LOCAL="$CTRL_DIR/stage"
mkdir -p "$STAGE_LOCAL"
cp "$WATCHDOG_BIN" "$STAGE_LOCAL/outline-watchdog"

SERVER_SUM=""
CLIENT_SUM=""
if [ "$DO_SERVER" = 1 ]; then
	[ -f "$SERVER_BIN" ] || die "missing server binary: $SERVER_BIN (build with: cargo server-release-musl-$HOST_ARCH)"
	[ "$(elf_arch "$SERVER_BIN")" = "$HOST_ARCH" ] || die "server binary arch mismatch"
	[ -f "$SERVER_UNIT_FILE" ] || die "missing $SERVER_UNIT_FILE"
	SERVER_SUM="$(sha256_local "$SERVER_BIN")"
	cp "$SERVER_BIN" "$STAGE_LOCAL/outline-server"
	cp "$SERVER_UNIT_FILE" "$STAGE_LOCAL/outline-server.service"
	log "server bin ready: $(basename "$SERVER_BIN") (${SERVER_SUM:0:12})"
fi

if [ "$DO_CLIENT" = 1 ]; then
	[ -f "$CLIENT_BIN" ] || die "missing client binary: $CLIENT_BIN (build with: cargo client-release-musl-$HOST_ARCH)"
	[ "$(elf_arch "$CLIENT_BIN")" = "$HOST_ARCH" ] || die "client binary arch mismatch"
	[ -f "$CLIENT_UNIT_FILE" ] && [ -f "$CLIENT_TPL_FILE" ] || die "missing client unit files"
	CLIENT_SUM="$(sha256_local "$CLIENT_BIN")"
	cp "$CLIENT_BIN" "$STAGE_LOCAL/outline-client"
	cp "$CLIENT_UNIT_FILE" "$STAGE_LOCAL/outline-client.service"
	cp "$CLIENT_TPL_FILE" "$STAGE_LOCAL/outline-client@.service"
	log "client bin ready: $(basename "$CLIENT_BIN") (${CLIENT_SUM:0:12})"
fi

REMOTE_STAGE="/tmp/outline-rename-stage.$$"
ssh "${SSH_OPTS[@]}" "$HOST" "mkdir -p '$REMOTE_STAGE'"
scp -q "${SSH_OPTS[@]}" "$STAGE_LOCAL/"* "$HOST:$REMOTE_STAGE/"

ssh "${SSH_OPTS[@]}" "$HOST" \
	"sudo -n env MODE='$MODE' DO_SERVER='$DO_SERVER' DO_CLIENT='$DO_CLIENT' SERVER_SUM='$SERVER_SUM' CLIENT_SUM='$CLIENT_SUM' STAGE='$REMOTE_STAGE' bash -s" <<'REMOTE'
set -euo pipefail
trap 'rm -rf "$STAGE"' EXIT

TS="$(date +%Y%m%d%H%M%S)"
ROLLBACK="/var/tmp/outline-rename-rollback.$TS"
MIGRATED=0

save_state() {
	mkdir -p "$ROLLBACK"
	chmod 0700 "$ROLLBACK"
	for p in \
		/usr/local/bin/outline-ss-rust \
		/usr/local/bin/outline-ws-rust \
		/usr/local/sbin/outline-watchdog \
		/etc/systemd/system/post-up.service \
		/etc/default/nanopi104-backup; do
		if [ -e "$p" ]; then
			mkdir -p "$ROLLBACK/$(dirname "$p")"
			cp -a "$p" "$ROLLBACK/$p"
		fi
	done
	for d in \
		/etc/outline-ss-rust \
		/etc/outline-ws-rust \
		/etc/systemd/system/outline-ss-rust.service \
		/etc/systemd/system/outline-ss-rust.service.d \
		/etc/systemd/system/outline-ws-rust.service \
		/etc/systemd/system/outline-ws-rust@.service \
		/etc/systemd/system/outline-ws-rust.service.d \
		/opt/outline/outline-ss-rust; do
		if [ -e "$d" ]; then
			mkdir -p "$ROLLBACK/$(dirname "$d")"
			cp -a "$d" "$ROLLBACK/$d"
		fi
	done
	systemctl list-units --all 'outline-*' --no-legend --no-pager > "$ROLLBACK/units.txt" || true
	id outline-ss-rust > "$ROLLBACK/id-server.txt" 2>/dev/null || true
	id outline-ws > "$ROLLBACK/id-client.txt" 2>/dev/null || true
}

rollback() {
	echo "ERROR: migration failed — rolling back from $ROLLBACK" >&2
	set +e
	if [ "$DO_SERVER" = 1 ]; then
		systemctl disable --now outline-watchdog@outline-server.timer 2>/dev/null
		systemctl disable --now outline-server.service 2>/dev/null
		rm -f /usr/local/bin/outline-server /etc/systemd/system/outline-server.service
		rm -rf /etc/systemd/system/outline-server.service.d
		if [ -d /etc/outline-server ] && [ ! -e /etc/outline-ss-rust ]; then
			mv /etc/outline-server /etc/outline-ss-rust
		fi
		if [ -d /var/lib/outline-server ] && [ ! -e /var/lib/outline-ss-rust ]; then
			mv /var/lib/outline-server /var/lib/outline-ss-rust
		fi
		if getent passwd outline-server >/dev/null && ! getent passwd outline-ss-rust >/dev/null; then
			groupmod -n outline-ss-rust outline-server 2>/dev/null || true
			usermod -l outline-ss-rust -d /var/lib/outline-ss-rust outline-server 2>/dev/null || true
		fi
		[ -d "$ROLLBACK/etc/outline-ss-rust" ] && cp -a "$ROLLBACK/etc/outline-ss-rust/." /etc/outline-ss-rust/
		[ -f "$ROLLBACK/usr/local/bin/outline-ss-rust" ] && cp -a "$ROLLBACK/usr/local/bin/outline-ss-rust" /usr/local/bin/outline-ss-rust
		[ -f "$ROLLBACK/etc/systemd/system/outline-ss-rust.service" ] && cp -a "$ROLLBACK/etc/systemd/system/outline-ss-rust.service" /etc/systemd/system/outline-ss-rust.service
		[ -d "$ROLLBACK/etc/systemd/system/outline-ss-rust.service.d" ] && cp -a "$ROLLBACK/etc/systemd/system/outline-ss-rust.service.d" /etc/systemd/system/outline-ss-rust.service.d
		chown -R outline-ss-rust:outline-ss-rust /etc/outline-ss-rust /var/lib/outline-ss-rust 2>/dev/null || true
	fi
	if [ "$DO_CLIENT" = 1 ]; then
		systemctl disable --now outline-watchdog@outline-client.timer 2>/dev/null
		for u in $(systemctl list-units --all --type=service --no-legend --no-pager | awk '{print $1}' | grep -E '^outline-client(\.service|@.+\.service)$'); do
			systemctl disable --now "$u" 2>/dev/null
		done
		rm -f /usr/local/bin/outline-client /etc/systemd/system/outline-client.service /etc/systemd/system/outline-client@.service
		rm -rf /etc/systemd/system/outline-client.service.d
		if [ -d /etc/outline-client ] && [ ! -e /etc/outline-ws-rust ]; then
			mv /etc/outline-client /etc/outline-ws-rust
		fi
		if [ -d /var/lib/outline-client ] && [ ! -e /var/lib/outline-ws-rust ]; then
			mv /var/lib/outline-client /var/lib/outline-ws-rust
		fi
		if [ -d /var/log/outline-client ] && [ ! -e /var/log/outline-ws-rust ]; then
			mv /var/log/outline-client /var/log/outline-ws-rust
		fi
		if getent passwd outline-client >/dev/null && ! getent passwd outline-ws >/dev/null; then
			groupmod -n outline-ws outline-client 2>/dev/null || true
			usermod -l outline-ws -d /home/outline-ws outline-client 2>/dev/null || true
		fi
		[ -d "$ROLLBACK/etc/outline-ws-rust" ] && cp -a "$ROLLBACK/etc/outline-ws-rust/." /etc/outline-ws-rust/
		[ -f "$ROLLBACK/usr/local/bin/outline-ws-rust" ] && cp -a "$ROLLBACK/usr/local/bin/outline-ws-rust" /usr/local/bin/outline-ws-rust
		[ -f "$ROLLBACK/etc/systemd/system/outline-ws-rust.service" ] && cp -a "$ROLLBACK/etc/systemd/system/outline-ws-rust.service" /etc/systemd/system/outline-ws-rust.service
		[ -f "$ROLLBACK/etc/systemd/system/outline-ws-rust@.service" ] && cp -a "$ROLLBACK/etc/systemd/system/outline-ws-rust@.service" /etc/systemd/system/outline-ws-rust@.service
		[ -d "$ROLLBACK/etc/systemd/system/outline-ws-rust.service.d" ] && cp -a "$ROLLBACK/etc/systemd/system/outline-ws-rust.service.d" /etc/systemd/system/outline-ws-rust.service.d
		chown -R outline-ws:outline-ws /etc/outline-ws-rust /var/lib/outline-ws-rust /var/log/outline-ws-rust 2>/dev/null || true
	fi
	[ -f "$ROLLBACK/usr/local/sbin/outline-watchdog" ] && cp -a "$ROLLBACK/usr/local/sbin/outline-watchdog" /usr/local/sbin/outline-watchdog
	[ -f "$ROLLBACK/etc/systemd/system/post-up.service" ] && cp -a "$ROLLBACK/etc/systemd/system/post-up.service" /etc/systemd/system/post-up.service
	[ -f "$ROLLBACK/etc/default/nanopi104-backup" ] && cp -a "$ROLLBACK/etc/default/nanopi104-backup" /etc/default/nanopi104-backup
	[ -d "$ROLLBACK/opt/outline/outline-ss-rust" ] && cp -a "$ROLLBACK/opt/outline/outline-ss-rust/." /opt/outline/outline-ss-rust/
	systemctl daemon-reload
	[ "$DO_SERVER" = 1 ] && systemctl enable --now outline-ss-rust.service outline-watchdog@outline-ss-rust.timer 2>/dev/null
	[ "$DO_CLIENT" = 1 ] && systemctl enable --now outline-ws-rust.service outline-watchdog@outline-ws-rust.timer 2>/dev/null
	exit 1
}

if [ "$DO_SERVER" = 1 ]; then
	got="$(sha256sum "$STAGE/outline-server" | cut -d' ' -f1)"
	[ "$got" = "$SERVER_SUM" ] || { echo "server sha256 mismatch" >&2; exit 1; }
fi
if [ "$DO_CLIENT" = 1 ]; then
	got="$(sha256sum "$STAGE/outline-client" | cut -d' ' -f1)"
	[ "$got" = "$CLIENT_SUM" ] || { echo "client sha256 mismatch" >&2; exit 1; }
fi

CLIENT_INSTANCES=()
while IFS= read -r u; do
	[ -n "$u" ] || continue
	inst="${u#outline-ws-rust@}"
	inst="${inst%.service}"
	CLIENT_INSTANCES+=("$inst")
done < <(systemctl list-units --all --type=service --no-legend --no-pager | awk '{print $1}' | grep -E '^outline-ws-rust@.+\.service$' || true)

if [ "$MODE" = "dry-run" ]; then
	echo "[dry-run] DO_SERVER=$DO_SERVER DO_CLIENT=$DO_CLIENT instances=${CLIENT_INSTANCES[*]:-none}"
	[ "$DO_SERVER" = 1 ] && echo "[dry-run] would migrate outline-ss-rust -> outline-server (user/group, /etc, /var/lib, drop-in, post-up, save-keys, watchdog)"
	[ "$DO_CLIENT" = 1 ] && echo "[dry-run] would migrate outline-ws-rust -> outline-client (user/group, /etc, /var/lib, /var/log, drop-in, config paths, post-up, backup, watchdog)"
	exit 0
fi

save_state
trap 'if [ "$MIGRATED" = 1 ]; then rollback; fi' ERR
MIGRATED=1

# 1. Остановка старых таймеров и юнитов
if [ "$DO_SERVER" = 1 ]; then
	systemctl disable --now outline-watchdog@outline-ss-rust.timer 2>/dev/null || true
	systemctl disable --now outline-ss-rust.service 2>/dev/null || true
fi
if [ "$DO_CLIENT" = 1 ]; then
	systemctl disable --now outline-watchdog@outline-ws-rust.timer 2>/dev/null || true
	systemctl disable --now outline-ws-rust.service 2>/dev/null || true
	for inst in "${CLIENT_INSTANCES[@]+"${CLIENT_INSTANCES[@]}"}"; do
		systemctl disable --now "outline-ws-rust@${inst}.service" 2>/dev/null || true
	done
fi

# 2. Миграция пользователей, каталогов и сопутствующих скриптов
if [ "$DO_SERVER" = 1 ]; then
	if getent group outline-ss-rust >/dev/null && ! getent group outline-server >/dev/null; then
		groupmod -n outline-server outline-ss-rust
	elif ! getent group outline-server >/dev/null; then
		groupadd --system outline-server
	fi
	if getent passwd outline-ss-rust >/dev/null && ! getent passwd outline-server >/dev/null; then
		usermod -l outline-server -g outline-server -d /var/lib/outline-server outline-ss-rust
	elif ! getent passwd outline-server >/dev/null; then
		useradd --system --gid outline-server --no-create-home --home-dir /var/lib/outline-server --shell /usr/sbin/nologin outline-server
	fi
	if getent group certs >/dev/null; then
		usermod -aG certs outline-server
	fi

	[ -d /etc/outline-ss-rust ] && [ ! -e /etc/outline-server ] && mv /etc/outline-ss-rust /etc/outline-server
	[ -d /var/lib/outline-ss-rust ] && [ ! -e /var/lib/outline-server ] && mv /var/lib/outline-ss-rust /var/lib/outline-server
	mkdir -p /etc/outline-server /var/lib/outline-server
	chown -R outline-server:outline-server /etc/outline-server /var/lib/outline-server
	chmod 0750 /etc/outline-server
	find /etc/outline-server -maxdepth 1 -type f -exec chmod 0640 {} +

	if [ -f /etc/outline-server/config.toml ]; then
		sed -i 's#/etc/outline-ss-rust/#/etc/outline-server/#g' /etc/outline-server/config.toml
	fi

	if [ -d /etc/systemd/system/outline-ss-rust.service.d ]; then
		mv /etc/systemd/system/outline-ss-rust.service.d /etc/systemd/system/outline-server.service.d
		find /etc/systemd/system/outline-server.service.d -type f -name '*.conf' \
			-exec sed -i 's/outline-ss-rust/outline-server/g; s/outline_ss_rust/outline_server/g' {} +
	fi

	for f in /opt/outline/outline-ss-rust/save-keys.sh /opt/outline/outline-ss-rust/generate_keys.py; do
		if [ -f "$f" ]; then
			sed -i 's#/etc/outline-ss-rust#/etc/outline-server#g; s/outline-ss-rust/outline-server/g' "$f"
		fi
	done
	if [ -f /opt/outline/outline-ss-rust/users.txt ]; then
		chown root:outline-server /opt/outline/outline-ss-rust/users.txt
	fi
	for f in /opt/ddns/*/permission-certs.sh; do
		if [ -f "$f" ]; then
			sed -i 's/outline-ss-rust/outline-server/g' "$f"
		fi
	done
fi

if [ "$DO_CLIENT" = 1 ]; then
	if getent group outline-ws >/dev/null && ! getent group outline-client >/dev/null; then
		groupmod -n outline-client outline-ws
	elif ! getent group outline-client >/dev/null; then
		groupadd --system outline-client
	fi
	if getent passwd outline-ws >/dev/null && ! getent passwd outline-client >/dev/null; then
		usermod -l outline-client -g outline-client -d /var/lib/outline-client outline-ws
	elif ! getent passwd outline-client >/dev/null; then
		useradd --system --gid outline-client --no-create-home --home-dir /var/lib/outline-client --shell /usr/sbin/nologin outline-client
	fi

	[ -d /etc/outline-ws-rust ] && [ ! -e /etc/outline-client ] && mv /etc/outline-ws-rust /etc/outline-client
	[ -d /var/lib/outline-ws-rust ] && [ ! -e /var/lib/outline-client ] && mv /var/lib/outline-ws-rust /var/lib/outline-client
	[ -d /var/log/outline-ws-rust ] && [ ! -e /var/log/outline-client ] && mv /var/log/outline-ws-rust /var/log/outline-client
	mkdir -p /etc/outline-client /var/lib/outline-client/_default /var/log/outline-client/_default
	chown -R outline-client:outline-client /etc/outline-client /var/lib/outline-client /var/log/outline-client
	chmod 0750 /etc/outline-client
	find /etc/outline-client -maxdepth 1 -type f -exec chmod 0640 {} +

	if [ -f /etc/outline-client/config.toml ]; then
		sed -i 's#/etc/outline-ws-rust/#/etc/outline-client/#g; s#/var/lib/outline-ws-rust/#/var/lib/outline-client/#g' /etc/outline-client/config.toml
	fi
	if [ -d /etc/outline-client/instances ]; then
		find /etc/outline-client/instances -type f -name '*.toml' \
			-exec sed -i 's#/etc/outline-ws-rust/#/etc/outline-client/#g; s#/var/lib/outline-ws-rust/#/var/lib/outline-client/#g' {} +
	fi

	if [ -d /etc/systemd/system/outline-ws-rust.service.d ]; then
		mv /etc/systemd/system/outline-ws-rust.service.d /etc/systemd/system/outline-client.service.d
		find /etc/systemd/system/outline-client.service.d -type f -name '*.conf' \
			-exec sed -i 's/outline-ws-rust/outline-client/g; s/outline-ws\b/outline-client/g; s/outline_ws_rust/outline_client/g' {} +
	fi

	if [ -f /etc/default/nanopi104-backup ]; then
		sed -i 's/outline-ws-rust/outline-client/g' /etc/default/nanopi104-backup
	fi
fi

if [ -f /etc/systemd/system/post-up.service ]; then
	[ "$DO_SERVER" = 1 ] && sed -i 's/outline-ss-rust\.service/outline-server.service/g' /etc/systemd/system/post-up.service
	[ "$DO_CLIENT" = 1 ] && sed -i 's/outline-ws-rust\.service/outline-client.service/g' /etc/systemd/system/post-up.service
fi

# 3. Установка новых бинарей, watchdog и unit-файлов + удаление старых
install -o root -g root -m 0755 "$STAGE/outline-watchdog" /usr/local/sbin/outline-watchdog

if [ "$DO_SERVER" = 1 ]; then
	install -o root -g root -m 0755 "$STAGE/outline-server" /usr/local/bin/outline-server
	install -o root -g root -m 0644 "$STAGE/outline-server.service" /etc/systemd/system/outline-server.service
	rm -f /etc/systemd/system/outline-ss-rust.service /usr/local/bin/outline-ss-rust
fi
if [ "$DO_CLIENT" = 1 ]; then
	install -o root -g root -m 0755 "$STAGE/outline-client" /usr/local/bin/outline-client
	install -o root -g root -m 0644 "$STAGE/outline-client.service" /etc/systemd/system/outline-client.service
	install -o root -g root -m 0644 "$STAGE/outline-client@.service" /etc/systemd/system/outline-client@.service
	rm -f /etc/systemd/system/outline-ws-rust.service /etc/systemd/system/outline-ws-rust@.service /usr/local/bin/outline-ws-rust
fi

systemctl daemon-reload

# 4. Запуск и проверка /metrics
check_metrics() {
	local unit="$1" port="$2"
	local ok=0
	for _ in $(seq 1 15); do
		sleep 2
		systemctl is-active --quiet "$unit" || continue
		code=$(curl -s -m 5 -o /dev/null -w '%{http_code}' "http://127.0.0.1:$port/metrics" || true)
		if [ "$code" = "200" ]; then
			ok=1
			break
		fi
	done
	[ "$ok" = 1 ]
}

if [ "$DO_SERVER" = 1 ]; then
	systemctl enable --now outline-server.service
	check_metrics outline-server.service 9090
	systemctl enable --now outline-watchdog@outline-server.timer
	echo "    ok: outline-server active, /metrics 200"
fi
if [ "$DO_CLIENT" = 1 ]; then
	systemctl enable --now outline-client.service
	check_metrics outline-client.service 9091
	for inst in "${CLIENT_INSTANCES[@]+"${CLIENT_INSTANCES[@]}"}"; do
		systemctl enable --now "outline-client@${inst}.service"
	done
	systemctl enable --now outline-watchdog@outline-client.timer
	echo "    ok: outline-client active, /metrics 200"
fi

MIGRATED=0
echo "    completed! rollback snapshot kept at $ROLLBACK"
REMOTE
```

- [ ] **Step 2: Обновить `ops/deploy/README.md` под `outline-server` / `outline-client` и задокументировать `migrate-node-rename.sh`**

Обновить примеры и таблицу аргументов в `ops/deploy/README.md`: `<unit>` теперь `outline-server` (`9090`) или `outline-client` (`9091`), а также добавить раздел «Миграция узла со старых имён (`migrate-node-rename.sh`)» с примерами `--audit`, `--dry-run` и боевого запуска для `server`/`client`/`all`.

- [ ] **Step 3: Проверить синтаксис и `shellcheck`, закоммитить**

```bash
chmod +x ops/deploy/migrate-node-rename.sh
bash -n ops/deploy/migrate-node-rename.sh
shellcheck ops/deploy/migrate-node-rename.sh
git add ops/deploy/migrate-node-rename.sh ops/deploy/README.md
git commit -- ops/deploy/migrate-node-rename.sh ops/deploy/README.md -m "feat(ops): add clean node rename migration script with audit and rollback"
```

Expected: `bash -n` и `shellcheck` проходят без замечаний.

---

### Task 12: Полная локальная и Linux Docker верификация CI-гейта

**Files:**
- Verify only (без правок кода, если тесты зелёные; при нахождении мелкой опечатки в комментариях/путях — чинить локально и докомичивать)

**Interfaces:**
- Consumes: Весь репозиторий после Tasks 1–11.
- Produces: Подтверждённый зелёный CI-гейт и Linux Docker сборка/тесты.

- [ ] **Step 1: Прогнать все 4 обязательных шага lint + unit + e2e локально**

```bash
cargo fmt --check -p outline-server -p outline-client -p outline-ui -p outline-metrics -p outline-net -p outline-routing -p outline-transport -p outline-tun -p outline-uplink -p outline-wire -p shadowsocks-crypto -p socks5-proto
cargo clippy --workspace --exclude sockudo-ws --exclude outline-windows --all-targets --no-deps -- -D warnings
(cd android/rust && cargo fmt --check && cargo clippy --no-deps -- -D warnings)
cargo test --workspace --exclude sockudo-ws --exclude outline-windows
RUN_E2E_FAILOVER=1 cargo test -p outline-client --features test-tls --test 'e2e_*' -- --test-threads=1
```

Expected: все команды возвращают код 0.

- [ ] **Step 2: Прогнать матрицу фич и все 6 инвариантов из `.github/workflows/ci.yml`**

```bash
cargo check -p outline-server --no-default-features
cargo check -p outline-server --features test-hooks
cargo check -p outline-client --no-default-features
cargo tree -i 'rustls@0.23' -e features 2>/dev/null | grep -q 'rustls feature "ring"' && exit 1 || echo "ok: aws-lc-rs only"
.github/scripts/check-install-scripts.sh
.github/scripts/check-served-key-path.sh
```

И убедиться, что оба grep-инварианта vendored API (`sockudo_ws` и `quinn-proto`) из `.github/workflows/ci.yml` проходят:

```bash
test -z "$(grep -rn 'sockudo_ws' bins/*/src crates/*/src --include='*.rs' | grep -v '/tests/' | grep -v '^crates/outline-transport/src/h3/vendored\.rs:' | grep -v '^bins/outline-server/src/server/h3/vendored\.rs:' || true)"
```

- [ ] **Step 3: Проверить Linux-специфику (`#[cfg(target_os = "linux")]`) в Docker и очистить `target/debug`**

```bash
docker run --rm -v "$(pwd):/src" -w /src rust:latest bash -c '
  apt-get update -qq && apt-get install -y -qq cmake pkg-config >/dev/null
  cargo test -p outline-server -p outline-client --target-dir /tmp/linux-target jemalloc_page_matches_the_kernel_page
  cargo test -p outline-server -p outline-client --target-dir /tmp/linux-target malloc_conf_reaches_jemalloc
  cargo check --workspace --exclude sockudo-ws --exclude outline-windows --target-dir /tmp/linux-target
'
rm -rf target/debug android/rust/target/debug
```

Expected: все Linux-only тесты (`jemalloc_page_matches_the_kernel_page`, `malloc_conf_reaches_jemalloc`, сетевые/eBPF/libc ветки) успешно компилируются и проходят под Linux.

---

### Task 13: Синхронизация соседнего репозитория `~/IdeaProjects/ambar` и пост-CI уборка старых nightly-тегов

**Files (в соседнем репозитории `~/IdeaProjects/ambar`):**
- Modify: `~/IdeaProjects/ambar/ops/grafana/dashboards/deploy.sh:36-37`
- Modify: `~/IdeaProjects/ambar/ops/alerting/vmalert/rules.yaml:95`
- Modify: `~/IdeaProjects/ambar/ops/alerting/vmalert/tests/uplink.yaml:153`
- Modify: `~/IdeaProjects/ambar/ops/grafana/alerting/rules.yaml:235`
- Modify: `~/IdeaProjects/ambar/ops/grafana/dashboards/outline-alerting.json:757`
- Modify: `~/IdeaProjects/ambar/ops/grafana/README.md:49,99-100`
- Modify: `~/IdeaProjects/ambar/ops/nas-monitoring/README.md:113`
- Rename & Modify: `~/IdeaProjects/ambar/ops/nanopi-r5c-k3s/apps/outline/outline-ss-rust.daemonset.yaml` $\to$ `outline-server.daemonset.yaml`
- Rename & Modify: `~/IdeaProjects/ambar/ops/nanopi-r5c-k3s/apps/outline/outline-ws-rust.deployment.yaml` $\to$ `outline-client.deployment.yaml`
- Modify: `~/IdeaProjects/ambar/ops/nanopi-r5c-k3s/apps/outline/README.md`, `~/IdeaProjects/ambar/ops/nanopi-r5c-k3s/apps/README.md`

**Interfaces:**
- Consumes: Пути дашбордов `bins/outline-server/grafana/*.json` и `bins/outline-client/grafana/*.json` (Task 6).
- Produces: Совместимый скрипт `deploy.sh` и обновлённые алерты/манифесты в `ambar`, а также чистые rolling nightly-релизы на GitHub.

- [ ] **Step 1: Обновить `~/IdeaProjects/ambar/ops/grafana/dashboards/deploy.sh` и смежные файлы**

В `~/IdeaProjects/ambar/ops/grafana/dashboards/deploy.sh` заменить строки 36–37:

```bash
		files+=("$bins_dir"/outline-server/grafana/*.json)
		files+=("$bins_dir"/outline-client/grafana/*.json)
```

В `~/IdeaProjects/ambar/ops/alerting/vmalert/rules.yaml:95`, `tests/uplink.yaml:153`, `ops/grafana/alerting/rules.yaml:235`, `ops/grafana/dashboards/outline-alerting.json:757` заменить текст `'outline-ws-rust restarted...'` на `'outline-client restarted...'` (**НЕ МЕНЯЯ** PromQL-метрики `outline_ws_*` и имена scrape-джобов `rust-ws-exporter` / `rust-ss-exporter`).

Переименовать k3s-скелеты `outline-ss-rust.daemonset.yaml` $\to$ `outline-server.daemonset.yaml` и `outline-ws-rust.deployment.yaml` $\to$ `outline-client.deployment.yaml` и обновить ссылки в их `README.md`.

- [ ] **Step 2: Проверить тесты `vmalert` и JSON/bash в `ambar`, закоммитить**

```bash
bash -n ~/IdeaProjects/ambar/ops/grafana/dashboards/deploy.sh
shellcheck ~/IdeaProjects/ambar/ops/grafana/dashboards/deploy.sh
python3 -B -m json.tool ~/IdeaProjects/ambar/ops/grafana/dashboards/outline-alerting.json >/dev/null
(cd ~/IdeaProjects/ambar && git status --short)
```

(Если установлен `promtool`, прогнать `promtool test rules ~/IdeaProjects/ambar/ops/alerting/vmalert/tests/uplink.yaml`.) Закоммитить изменения в `~/IdeaProjects/ambar` строго по изменённым путям.

- [ ] **Step 3: После push в `outline-proxy` (по команде владельца) и первого зелёного `server-nightly`/`client-nightly` убрать старые nightly**

Проверить `gh run list` и после успешной публикации `server-nightly` и `client-nightly`:

```bash
gh release delete ss-nightly --yes --cleanup-tag || true
gh release delete ws-nightly --yes --cleanup-tag || true
```

---

### Task 14: Сборка релизных musl-бинарей и поузловая выкатка на боевой парк

**Files (локальные некоммитируемые):**
- Modify: `FLEET.local.md`
- Modify: `~/.claude/projects/-Users-mvmalykh-IdeaProjects-outline-proxy/memory/MEMORY.md`

**Interfaces:**
- Consumes: Скрипт `ops/deploy/migrate-node-rename.sh` (Task 11) и обновлённый `ambar` (Task 13).
- Produces: Все 6 узлов боевого парка (`exit-a`, `exit-b`, `relay-a`, `relay-b`, `198.51.100.104`, `198.51.100.102`), работающие под `outline-server` и `outline-client`, актуальные дашборды Grafana и чистый `target/`.

- [ ] **Step 1: Собрать release musl-бинари под x86_64 и aarch64**

```bash
cargo server-release-musl-x86_64
cargo server-release-musl-aarch64
cargo client-release-musl-x86_64
cargo client-release-musl-aarch64
```

Expected: 4 статических ELF-бинарника в `target/{x86_64,aarch64}-unknown-linux-musl/release/outline-{server,client}`.

- [ ] **Step 2: Поузловая миграция парка (СТРОГО по одному узлу и СТРОГО после явного разрешения владельца на каждый узел)**

Порядок узлов (конкретные SSH-цели брать из `FLEET.local.md`):
1. `exit-a` (x86_64, роль `server`): `--audit` $\to$ `--dry-run` $\to$ боевой запуск `migrate-node-rename.sh <exit-a-ssh> server`. Проверить `outline-server`, `:9090/metrics`, выдачу ключей.
2. `exit-b` (x86_64, роль `server`): `--audit` $\to$ `--dry-run` $\to$ боевой запуск `migrate-node-rename.sh <exit-b-ssh> server`. Проверить cluster mesh и `:9090/metrics`.
3. `relay-a` (x86_64, роль `all`): `--audit` $\to$ `--dry-run` $\to$ боевой запуск `migrate-node-rename.sh <relay-a-ssh> all`. Проверить mesh cluster `9443/udp`, `reselect_sync`, `save-keys.sh` и `heartbeat-watch`.
4. `relay-b` (x86_64, роль `all`): `--audit` $\to$ `--dry-run` $\to$ боевой запуск `migrate-node-rename.sh <relay-b-ssh> all`. Проверить парный кластер `relay-a` $\leftrightarrow$ `relay-b` и `/metrics` 9090/9091.
5. `198.51.100.104` (aarch64, роль `all`): `--audit` $\to$ `--dry-run` $\to$ боевой запуск `migrate-node-rename.sh <104-ssh> all`. Проверить TUN, VRF, 4 KiB страницу `jemalloc` через `GET /control/alloc` и `/etc/default/nanopi104-backup`.
6. `198.51.100.102` (x86_64, роль `all`): `--audit` $\to$ `--dry-run` $\to$ боевой запуск `migrate-node-rename.sh <102-ssh> all`. Проверить SOCKS5/TUN, VRF и `/metrics` 9090/9091.

- [ ] **Step 3: Выкладка дашбордов и проверка мониторинга**

С разрешения владельца выполнить:

```bash
~/IdeaProjects/ambar/ops/grafana/dashboards/deploy.sh --nas
```

Перезапустить контейнер Grafana на NAS по регламенту и проверить:
- в VictoriaMetrics поступают свежие серии от всех 6 серверов и 4 клиентов (`rust-ss-exporter`, `rust-ws-exporter`);
- все 3 дашборда открываются по прежним UID с новыми заголовками;
- в `vmalert` нет ложных алертов `TargetDown`/`AllUplinksDown`.

- [ ] **Step 4: Обновить локальные некоммитируемые заметки и полностью очистить артефакты сборки**

1. Обновить `FLEET.local.md` (заменить упоминания `outline-ss-rust` / `outline-ws-rust` / `/etc/outline-ss-rust` на актуальные).
2. Обновить `~/.claude/projects/-Users-mvmalykh-IdeaProjects-outline-proxy/memory/MEMORY.md` (добавить краткую 1-строчную отметку о завершённом переименовании).
3. После финального `git push` (с предварительной проверкой `git log origin/main..main` и явной командой владельца) выполнить полную очистку каталогов сборки:

```bash
cargo clean
cargo clean --manifest-path android/rust/Cargo.toml
```

---

## Self-Review Checklist (выполнено перед фиксацией)

- **Полнота покрытия спеки:** Все разделы спеки (`§1`–`§6`) покрыты задачами Tasks 1–14, включая CalVer-релизы, Windows-клиент, macOS helper, Android, `outline-ui`, `ambar`, `migrate-node-rename.sh` с `--audit`/`--dry-run`/откатом/доп-правами/внутренними путями, Docker Linux-проверку, `check-install-scripts.sh` и `cargo clean`.
- **Отсутствие плейсхолдеров:** В плане нет `TBD`, `TODO`, «аналогично» без явного содержания; для скрипта миграции приведён полный исходный код.
- **Согласованность имён и инвариантов:** `outline-server` / `outline-client` (пакеты/бинарники/юниты/пути), `outline_server` / `outline_client` (Rust crate identifiers), `outline_ss_*` / `outline_ws_*` (сохранённые метрики), `SYNC_SEED_CONTEXT` (неизменный), `server-nightly` / `client-nightly` + единый CalVer `vYY.M.PATCH`.
