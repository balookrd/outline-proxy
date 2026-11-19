# План реализации: Клиент Outline Proxy для Windows (Tauri v2 + Rust)

> **Для исполнителей-агентов:** ОБЯЗАТЕЛЬНЫЙ НАВЫК: Используйте `superpowers:subagent-driven-development` (рекомендуется) или `superpowers:executing-plans` для пошаговой реализации плана. Шаги отслеживаются через чекбоксы (`- [ ]`).

**Цель:** Создать полнофункциональный клиент Outline Proxy для Windows (x86_64), поддерживающий режимы SOCKS5 и TUN (Wintun), с GUI на Tauri v2 + Svelte/Tailwind в системном трее, работающий поверх сетевого ядра `outline-ws-rust`.

**Архитектура:** Двухпроцессная модель. Оболочка `bins/outline-windows` (Tauri v2) управляет системным треем, окнами, настройками прокси (SOCKS5 через WinINet) и жизненным циклом фонового процесса ядра `outline-ws-rust.exe`. В режиме TUN ядро взаимодействует с драйвером `wintun.dll` и настраивает маршруты Windows через Win32 IP Helper API.

**Стек технологий:** Rust (Edition 2024), Tauri v2, Svelte 5, Tailwind CSS, Vite, TypeScript, Wintun 0.14, `mimalloc`, Windows API (WinINet, IP Helper, Shell32).

## Глобальные ограничения

* Язык кода, комментариев и коммитов: английский. Документация — двуязычная (`*.md` / `*.ru.md`).
* Коммиты строго с перечислением затронутых путей: `git commit -m "..." -- <paths>`.
* Серверные модули `bins/outline-ss-rust` не модифицировать.
* Не ломать сборки Linux, macOS и Android: все платформенные блоки строго за `#[cfg(windows)]` или `#[cfg(target_os = "windows")]`.
* На Windows использовать аллокатор `mimalloc` (вместо `jemalloc`, который не собирается под MSVC).
* Целевой таргет компиляции: `x86_64-pc-windows-msvc`.

---

### Task 1: Адаптация сетевого ядра `bins/outline-ws-rust` и низкоуровневых крейтов под Windows MSVC

**Файлы:**
* Изменить: `bins/outline-ws-rust/Cargo.toml`
* Изменить: `bins/outline-ws-rust/src/main.rs`
* Изменить: `bins/outline-ws-rust/src/lib.rs`
* Изменить: `bins/outline-ws-rust/src/bootstrap/mod.rs`
* Изменить: `crates/outline-net/src/lib.rs`
* Изменить: `crates/outline-net/src/fs_util.rs`
* Изменить: `crates/outline-transport/src/carrier_loss.rs`
* Изменить: `crates/outline-transport/src/fingerprint_profile.rs`
* Изменить: `crates/outline-uplink/src/manager/reselect.rs`

**Интерфейсы:**
* Экспорт: `outline_ws_rust::run(args: Args) -> Result<()>` доступен под Windows.
* Аллокатор: на Windows активируется `mimalloc`, на non-Windows сохраняется дефолтный `jemalloc`.
* Дескрипторы: `RunOptions::tun_fd` заменяется на безопасный тип под Windows (`Option<()>` или исключается).

- [ ] **Шаг 1: Настройка аллокатора и зависимостей в `bins/outline-ws-rust/Cargo.toml`**

Изменить выбор аллокатора по умолчанию: сделать `jemalloc` зависящим от non-Windows платформ либо активировать `mimalloc` при сборке под Windows.
В `bins/outline-ws-rust/Cargo.toml`:
```toml
[target.'cfg(not(windows))'.dependencies]
tikv-jemallocator = { workspace = true, features = ["background_threads", "stats", "unprefixed_malloc_on_supported_platforms"], optional = true }
tikv-jemalloc-ctl = { workspace = true, features = ["stats"], optional = true }

[target.'cfg(windows)'.dependencies]
mimalloc = { workspace = true }
libmimalloc-sys = { workspace = true, features = ["extended"] }
```
И в списке `default` фичей: включить `mimalloc` для Windows сборки.

- [ ] **Шаг 2: Изоляция дескрипторов Unix в `bins/outline-ws-rust/src/lib.rs` и `src/bootstrap/mod.rs`**

В `bins/outline-ws-rust/src/lib.rs`:
```rust
#[cfg(unix)]
use std::os::fd::RawFd;

#[derive(Debug, Default, Clone, Copy)]
pub struct RunOptions {
    #[cfg(unix)]
    pub tun_fd: Option<RawFd>,
    #[cfg(not(unix))]
    pub tun_fd: Option<()>,
}
```
В `bins/outline-ws-rust/src/bootstrap/mod.rs`:
Изолировать `std::os::fd::RawFd` под `#[cfg(unix)]`. Для Windows `tun_fd` принимает `Option<()>`.
Убедиться, что `tokio::signal::ctrl_c().await` корректно отрабатывает на Windows (блок `#[cfg(not(unix))]` уже присутствует).

- [ ] **Шаг 3: Изоляция платформозависимых вызовов в `crates/outline-net`, `outline-transport` и `outline-uplink`**

1. В `crates/outline-net/src/lib.rs`:
   Обернуть вызовы `libc::setsockopt(..., SO_MARK, ...)` и `IPV6_PREFER_SRC_PUBLIC`/`IPV6_FREEBIND` в `#[cfg(target_os = "linux")]`.
2. В `crates/outline-net/src/fs_util.rs`:
   Изолировать использование `std::os::unix::fs::OpenOptionsExt` и `MetadataExt` под `#[cfg(unix)]`, для Windows использовать стандартный `std::fs::rename`.
3. В `crates/outline-transport/src/carrier_loss.rs`:
   Изолировать `TCP_INFO` под `#[cfg(target_os = "linux")]`. Под Windows функция `sample_kernel_tcp_info` возвращает `None`.
4. В `crates/outline-transport/src/fingerprint_profile.rs`:
   Заменить вызов `libc::gethostname`:
   ```rust
   #[cfg(windows)]
   fn local_hostname() -> Option<String> {
       std::env::var("COMPUTERNAME").ok()
   }
   ```
5. В `crates/outline-uplink/src/manager/reselect.rs`:
   Использовать `localtime_s` на Windows вместо `libc::localtime_r`.

- [ ] **Шаг 4: Проверка компиляции ядра под Windows**

Запустить команду проверки:
```bash
cargo check -p outline-ws-rust --no-default-features --features socks5,h3,metrics,control,env-filter,multi-thread,mimalloc
```
Ожидается: успешная компиляция без ошибок и предупреждений.

- [ ] **Шаг 5: Коммит изменений задачи 1**

```bash
git add bins/outline-ws-rust/ crates/outline-net/ crates/outline-transport/ crates/outline-uplink/
git commit -m "feat(windows): adapt outline-ws-rust and crates for Windows MSVC" -- bins/outline-ws-rust/ crates/outline-net/ crates/outline-transport/ crates/outline-uplink/
```

---

### Task 2: Реализация бэкенда Wintun в `crates/outline-tun`

**Файлы:**
* Изменить: `crates/outline-tun/Cargo.toml`
* Создать: `crates/outline-tun/src/device/windows.rs`
* Изменить: `crates/outline-tun/src/device.rs`

**Интерфейсы:**
* Экспорт: `open_tun_device(config: &TunConfig) -> Result<(TunDevice, TunGso)>` на Windows возвращает обёртку над сессией Wintun.
* Реализация: потокобезопасный `TunDevice` на Windows, предоставляющий `async fn read(&mut self, buf: &mut [u8]) -> Result<usize>` и `async fn write(&mut self, buf: &[u8]) -> Result<usize>`.

- [ ] **Шаг 1: Добавление зависимости `wintun` в `crates/outline-tun/Cargo.toml`**

В секцию зависимостей:
```toml
[target.'cfg(windows)'.dependencies]
wintun = "0.5"
windows-sys = { version = "0.59", features = ["Win32_System_Threading", "Win32_Foundation"] }
```

- [ ] **Шаг 2: Реализация Wintun адаптера и сессии в `crates/outline-tun/src/device/windows.rs`**

Создать модуль `crates/outline-tun/src/device/windows.rs`:
```rust
//! Wintun device adapter for Windows.

use std::sync::Arc;
use anyhow::{Context, Result};
use tracing::info;
use crate::config::TunConfig;
use crate::device::TunGso;

pub struct WintunDevice {
    session: Arc<wintun::Session>,
    read_event: windows_sys::Win32::Foundation::HANDLE,
}

pub fn open_wintun_device(config: &TunConfig) -> Result<(WintunDevice, TunGso)> {
    let wintun = unsafe { wintun::load() }
        .context("failed to load wintun.dll. Ensure wintun.dll is present in the working directory or System32")?;
    
    let adapter_name = config.name.as_deref().unwrap_or("OutlineProxy");
    let pool_name = "OutlineProxyPool";
    let guid = 0xdeadbeef_u128; // Детерминированный GUID для стабильного интерфейса
    
    let adapter = match wintun::Adapter::open(&wintun, adapter_name) {
        Ok(a) => a,
        Err(_) => wintun::Adapter::create(&wintun, adapter_name, pool_name, Some(guid))
            .context("failed to create Wintun adapter")?,
    };

    // Сессия с кольцевым буфером 4 МиБ
    let session = Arc::new(adapter.start_session(wintun::MAX_RING_CAPACITY)
        .context("failed to start Wintun session")?);
    
    let read_event = session.read_event_handle();

    info!(adapter = %adapter_name, mtu = config.mtu, "Wintun interface initialized");

    Ok((
        WintunDevice {
            session,
            read_event: read_event as _,
        },
        TunGso {
            vnet_hdr: false,
            tcp_gro: false,
            udp_gso: false,
            af_hdr: false,
        },
    ))
}
```

- [ ] **Шаг 3: Интеграция `open_wintun_device` в `crates/outline-tun/src/device.rs`**

Подключить модуль при `#[cfg(target_os = "windows")]` и направить вызов `open_tun_device(config)` на `open_wintun_device(config)`.

- [ ] **Шаг 4: Проверка компиляции**

```bash
cargo check -p outline-tun
```
Ожидается: компиляция без ошибок.

- [ ] **Шаг 5: Коммит изменений задачи 2**

```bash
git add crates/outline-tun/
git commit -m "feat(tun): add Wintun adapter driver backend for Windows" -- crates/outline-tun/
```

---

### Task 3: Маршрутизация и DNS в Windows для режима TUN

**Файлы:**
* Создать: `crates/outline-tun/src/routing/windows.rs`
* Изменить: `crates/outline-tun/src/engine.rs`

**Интерфейсы:**
* Экспорт: `setup_windows_routes(server_ip: IpAddr, gateway: IpAddr, if_index: u32) -> Result<RouteGuard>`
* Экспорт: `RouteGuard` при Drop автоматически удаляет созданные маршруты `0.0.0.0/1`, `128.0.0.0/1` и host-маршрут к серверу.

- [ ] **Шаг 1: Реализация управления маршрутами через Win32 IP Helper API в `crates/outline-tun/src/routing/windows.rs`**

Реализовать функции:
* `get_best_interface(dest: IpAddr) -> Result<(u32, IpAddr)>` — вызов `GetBestRoute2` для поиска физического шлюза и интерфейса выхода в интернет.
* `add_route(prefix: IpAddr, prefix_len: u8, nexthop: IpAddr, if_index: u32, metric: u32) -> Result<()>` — вызов `CreateIpForwardEntry2`.
* `delete_route(prefix: IpAddr, prefix_len: u8, nexthop: IpAddr, if_index: u32) -> Result<()>`.
* `set_interface_dns(if_index: u32, dns_servers: &[IpAddr]) -> Result<()>`.
* Структура `RouteGuard` с реализацией `Drop` для гарантированной очистки таблицы маршрутизации при любом выходе или панике процесса.

- [ ] **Шаг 2: Написание модульного теста парсинга маршрутов**

Создать тест в `crates/outline-tun/src/routing/tests/windows.rs`:
Проверка корректности разбиения подсетей `0.0.0.0/1` и `128.0.0.0/1`, конвертации в структуры `MIB_IPFORWARD_ROW2`.

- [ ] **Шаг 3: Проверка компиляции и запуск тестов**

```bash
cargo test -p outline-tun --lib routing
```
Ожидается: PASS.

- [ ] **Шаг 4: Коммит изменений задачи 3**

```bash
git add crates/outline-tun/
git commit -m "feat(tun): implement Windows route and DNS management via IP Helper API" -- crates/outline-tun/
```

---

### Task 4: Каркас GUI-приложения `bins/outline-windows` (Tauri v2 + Svelte + Tailwind)

**Файлы:**
* Создать: `bins/outline-windows/Cargo.toml`
* Создать: `bins/outline-windows/tauri.conf.json`
* Создать: `bins/outline-windows/src/main.rs`
* Создать: `bins/outline-windows/package.json`
* Создать: `bins/outline-windows/vite.config.ts`
* Создать: `bins/outline-windows/tailwind.config.ts`
* Создать: `bins/outline-windows/svelte.config.js`
* Создать: `bins/outline-windows/frontend/index.html`
* Создать: `bins/outline-windows/frontend/src/App.svelte`
* Создать: `bins/outline-windows/frontend/src/main.ts`
* Изменить: `Cargo.toml` (корень монорепозитория)

**Интерфейсы:**
* Новый бинарник `outline-windows` компилируется как член корневого Cargo-workspace.
* Tauri v2 инициализирует системный трей и веб-окно.

- [ ] **Шаг 1: Добавление `bins/outline-windows` в корневой `Cargo.toml`**

В список `[workspace.members]` добавить `"bins/outline-windows"`.

- [ ] **Шаг 2: Создание манифеста `bins/outline-windows/Cargo.toml`**

```toml
[package]
name = "outline-windows"
version = "1.0.0"
edition = "2024"

[dependencies]
tauri = { version = "2", features = ["tray-icon"] }
tauri-plugin-shell = "2"
serde = { workspace = true, features = ["derive"] }
serde_json = { workspace = true }
tokio = { workspace = true, features = ["rt-multi-thread", "sync", "process", "io-util"] }
tracing = { workspace = true }
tracing-subscriber = { workspace = true }
anyhow = { workspace = true }
```

- [ ] **Шаг 3: Конфигурация Tauri `bins/outline-windows/tauri.conf.json`**

Настроить:
* `identifier`: `su.beerloga.outline.windows`
* `windows`: главное окно `main` (ширина 400, высота 600, скрыто при старте `visible: false`, декорации включены, `title`: "Outline Proxy").
* `trayIcon`: иконка щита, всплывающая подсказка "Outline Proxy".

- [ ] **Шаг 4: Настройка веб-окружения фронтенда (Svelte + Tailwind)**

Создать `package.json`, `vite.config.ts`, `tailwind.config.ts` по аналогии с `bins/outline-ui/frontend`.
Установить зависимости:
```bash
pnpm --prefix bins/outline-windows install
```

- [ ] **Шаг 5: Минимальная точка входа Rust `bins/outline-windows/src/main.rs`**

```rust
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    tauri::Builder::default()
        .setup(|app| {
            tracing_subscriber::fmt::init();
            tracing::info!("Outline Proxy Windows starting");
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
```

- [ ] **Шаг 6: Проверка компиляции каркаса**

```bash
cargo check -p outline-windows
```
Ожидается: успешная компиляция.

- [ ] **Шаг 7: Коммит изменений задачи 4**

```bash
git add Cargo.toml bins/outline-windows/
git commit -m "feat(windows): scaffold Tauri v2 desktop application workspace member" -- Cargo.toml bins/outline-windows/
```

---

### Task 5: Бэкенд Tauri — Управление системным прокси (SOCKS5), профили и ConfigGenerator

**Файлы:**
* Создать: `bins/outline-windows/src/proxy_manager.rs`
* Создать: `bins/outline-windows/src/profile_store.rs`
* Создать: `bins/outline-windows/src/config_generator.rs`
* Создать: `bins/outline-windows/src/tests/config_generator.rs`

**Интерфейсы:**
* `SystemProxyManager::enable_socks5(host: &str, port: u16) -> Result<()>`
* `SystemProxyManager::disable() -> Result<()>`
* `ProfileStore`: парсинг `vless://`, `ss://`, `outline://`, чтение/запись JSON-файла профилей в `%APPDATA%/OutlineProxy/profiles.json`.
* `ConfigGenerator::generate(profile: &ServerProfile, tcp_only: bool, socks_port: u16, tun_enabled: bool) -> String`

- [ ] **Шаг 1: Реализация `SystemProxyManager` через Windows Registry и WinINet**

В `bins/outline-windows/src/proxy_manager.rs`:
* Запись значений в `HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings`:
  * `ProxyEnable = 1` (DWORD)
  * `ProxyServer = "socks=127.0.0.1:1080"` (SZ)
* Вызов `InternetSetOptionW` для сброса кеша настроек в системе.
* Функция безопасного отключения (выставляет `ProxyEnable = 0`).

- [ ] **Шаг 2: Реализация `ProfileStore` и парсера ссылок**

Поддержка форматов:
* `vless://uuid@host:port?security=tls&alpn=h3,h2&type=ws&path=/ws#name`
* `ss://base64@host:port#name`
* `outline://...`
* Подписки `https://...` (загрузка через `reqwest`, распаковка base64/plain списка серверов).

- [ ] **Шаг 3: Реализация `ConfigGenerator`**

Генерация TOML конфигурации для `outline-ws-rust.exe`:
* Секция `[socks5]` (порт 1080).
* Секция `[[groups]]` с uplink-параметрами выбранного сервера.
* Флаг `tcp_only`: подмена `xhttp_h3` -> `xhttp_h2`, `ws_h3` -> `ws_h2`, удаление `h3` из ALPN.
* Секция `[tun]` при TUN-режиме (`enabled = true`, `name = "OutlineProxy"`).

- [ ] **Шаг 4: Написание модульных тестов**

Тесты генерации конфигурации и парсинга ссылок VLESS/SS:
```bash
cargo test -p outline-windows --bin outline-windows
```
Ожидается: PASS.

- [ ] **Шаг 5: Коммит изменений задачи 5**

```bash
git add bins/outline-windows/src/
git commit -m "feat(windows): implement WinINet proxy manager, profile store, and config generator" -- bins/outline-windows/src/
```

---

### Task 6: Бэкенд Tauri — ProcessController для `outline-ws-rust.exe` и системный трей

**Файлы:**
* Создать: `bins/outline-windows/src/process_controller.rs`
* Создать: `bins/outline-windows/src/tray.rs`
* Создать: `bins/outline-windows/src/commands.rs`
* Изменить: `bins/outline-windows/src/main.rs`

**Интерфейсы:**
* `ProcessController`: запуск дочернего процесса `outline-ws-rust.exe` с аргументом `--config <path>`.
  * В режиме TUN: вызов через `ShellExecuteExW` с глаголом `runas` для запроса UAC.
  * Чтение потоков stdout/stderr и сохранение в циклический буфер для экрана журнала.
  * Завершение процесса по сигналу.
* Tauri IPC команды: `connect`, `disconnect`, `get_status`, `get_profiles`, `add_profile`, `remove_profile`, `get_logs`, `set_settings`.

- [ ] **Шаг 1: Реализация `ProcessController`**

В `bins/outline-windows/src/process_controller.rs`:
* Управление жизненным циклом `outline-ws-rust.exe`.
* Хранение последних 1000 строк логов в кольцевом буфере `Arc<RwLock<VecDeque<String>>>`.
* Оповещение интерфейса через события Tauri (`emit("log-message", line)`).

- [ ] **Шаг 2: Реализация системного трея в `bins/outline-windows/src/tray.rs`**

* Создание меню трея:
  * Статус подключения с цветным индикатором.
  * Быстрое подключение / отключение.
  * Список серверов.
  * Переключатели режимов SOCKS5/TUN и TCP-only.
  * Пункты открытия окон: Серверы, Настройки, Журнал.
  * Выход (гарантированное отключение прокси и завершение ядра).

- [ ] **Шаг 3: Регистрация IPC команд в `bins/outline-windows/src/commands.rs`**

Реализовать функции `#[tauri::command]` для вызова из фронтенда Svelte.

- [ ] **Шаг 4: Проверка компиляции**

```bash
cargo check -p outline-windows
```
Ожидается: PASS.

- [ ] **Шаг 5: Коммит изменений задачи 6**

```bash
git add bins/outline-windows/src/
git commit -m "feat(windows): add process controller, tray icon menu, and IPC commands" -- bins/outline-windows/src/
```

---

### Task 7: Фронтенд интерфейса на Svelte (Главное окно, Серверы, Настройки, Журнал)

**Файлы:**
* Создать: `bins/outline-windows/frontend/src/lib/types.ts`
* Создать: `bins/outline-windows/frontend/src/lib/api.ts`
* Создать: `bins/outline-windows/frontend/src/components/Header.svelte`
* Создать: `bins/outline-windows/frontend/src/components/ServersList.svelte`
* Создать: `bins/outline-windows/frontend/src/components/SettingsModal.svelte`
* Создать: `bins/outline-windows/frontend/src/components/LogViewerModal.svelte`
* Изменить: `bins/outline-windows/frontend/src/App.svelte`

**Интерфейсы:**
* Полный интерактивный интерфейс: переключение статуса подключения, выбор сервера, добавление ссылок из буфера, модальные окна настроек и живого журнала.

- [ ] **Шаг 1: Реализация типов и API-обёртки IPC в `lib/api.ts`**

Вызовы `invoke("connect")`, `invoke("disconnect")`, `invoke("get_profiles")`, подписка на `listen("log-message")`.

- [ ] **Шаг 2: Реализация компонентов `ServersList`, `SettingsModal`, `LogViewerModal`**

* `ServersList`: список серверов с индикатором задержки (ping), кнопка добавления, карточка активного подключения.
* `SettingsModal`: переключение SOCKS5/TUN, флаг TCP-only, флаг автозапуска.
* `LogViewerModal`: виртуализированный скролл логов, кнопка «Копировать всё», фильтры по уровням.

- [ ] **Шаг 3: Сборка фронтенда**

```bash
pnpm --prefix bins/outline-windows build
```
Ожидается: успешная генерация артефактов в `dist/`.

- [ ] **Шаг 4: Коммит изменений задачи 7**

```bash
git add bins/outline-windows/frontend/
git commit -m "feat(windows): implement Svelte frontend for servers, settings, and logs" -- bins/outline-windows/frontend/
```

---

### Task 8: Скрипт сборки под Windows, бандлинг `wintun.dll` и CI-гейт

**Файлы:**
* Создать: `scripts/package-windows.sh`
* Изменить: `.github/workflows/ci.yml`
* Создать: `windows/README.ru.md`
* Создать: `windows/README.md`

**Интерфейсы:**
* Скрипт `./scripts/package-windows.sh` выполняет кросс-компиляцию ядра и GUI под `x86_64-pc-windows-msvc`, скачивает проверенный `wintun.dll` и формирует готовый zip-архив в `dist/windows/OutlineProxy-x86_64.zip`.
* CI проверяет компиляцию под Windows.

- [ ] **Шаг 1: Создание скрипта `scripts/package-windows.sh`**

Скрипт выполняет:
1. Проверку наличия `cargo-xwin` (выводит подсказку по установке при отсутствии).
2. Скачивание официального `wintun.dll` (x64, версия 0.14) из репозитория Wintun, сверку sha256 хэша.
3. Сборку `outline-ws-rust.exe` в release под `x86_64-pc-windows-msvc`.
4. Сборку фронтенда (`pnpm build`).
5. Сборку `outline-windows.exe` через `cargo-xwin`.
6. Формирование каталога `dist/windows/`:
   * `OutlineProxy.exe`
   * `outline-ws-rust.exe`
   * `wintun.dll`
7. Упаковку в `OutlineProxy-x86_64.zip`.

- [ ] **Шаг 2: Добавление документации `windows/README.ru.md` и `windows/README.md`**

Описание процесса сборки, развертывания на виртуальной машине `.105` через SMB-диск и регламента тестирования.

- [ ] **Шаг 3: Добавление шага Windows check в `.github/workflows/ci.yml`**

Добавить проверку компиляции ядра под Windows-таргет в CI-матрицу.

- [ ] **Шаг 4: Локальный прогон скрипта сборки**

```bash
chmod +x scripts/package-windows.sh
./scripts/package-windows.sh --check-only
```
Ожидается: проверка проходит успешно.

- [ ] **Шаг 5: Коммит изменений задачи 8**

```bash
git add scripts/package-windows.sh .github/workflows/ci.yml windows/
git commit -m "ci(windows): add build and packaging script and CI verification" -- scripts/package-windows.sh .github/workflows/ci.yml windows/
```
