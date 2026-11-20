# План реализации: Устранение дефектов интерфейса и обеспечение работы VPN (Wintun) в Windows-клиенте

> **Для агентов-исполнителей:** ОБЯЗАТЕЛЬНЫЙ НАВЫК: Используйте `superpowers:subagent-driven-development` или `superpowers:executing-plans` для пошаговой реализации плана. Шаги используют синтаксис чекбоксов (`- [ ]`) для отслеживания прогресса.

**Цель:** Устранить дефекты интерфейса Windows-клиента (замена нативного `confirm()` на аккуратный встроенный диалог удаления сервера; скрытие полосы статистики до подключения; отображение реальных протоколов) и обеспечить полнофункциональную работу L3 TUN VPN через Wintun с автоматической настройкой сетевых маршрутов и DNS.

**Архитектура:**
1. Frontend (Svelte 5): в `ServersList.svelte` нативный системный `confirm()` заменяется на локальный оверлей подтверждения удаления, гарантированно умещающийся в компактное окно приложения. В `App.svelte` полоса статистики («Длительность», «Трафик», «Протокол») скрывается до установления соединения (`{#if isRunning}`), отображает реальный протокол (`carrierInfo` на базе параметров профиля по алгоритму macOS), а генерация случайных байтов удаляется.
2. Network Core (`crates/outline-tun` и `bins/outline-ws-rust`): при инициализации Wintun адаптеру назначается IPv4-адрес `10.0.85.2/24`, настраиваются системные DNS (`1.1.1.1`), устанавливаются host-маршруты к серверам через физический шлюз и перехватывающие маршруты `0.0.0.0/1` и `128.0.0.0/1` через Wintun с автоматической очисткой через `RouteGuard` при завершении.

**Стек технологий:** Rust (Edition 2024), Tauri v2, Svelte 5, Tailwind CSS, Wintun, Windows IP Helper API (NetIO).

## Глобальные ограничения

- Язык всей документации, планов, комментариев к коммитам и отчетов: строго русский язык.
- Полный визуальный и архитектурный паритет с версией для macOS (`macos/Sources/OutlineProxy/`).
- Никаких фейковых данных (случайных чисел) в интерфейсе: если трафик не идет — отображать 0 Б.
- Очистка промежуточных debug-артефактов (`target/debug/`) после каждого шага.

---

### Задача 1: Встроенный диалог подтверждения удаления сервера (устранение нативного `confirm`)

**Файлы для изменения:**
- `bins/outline-windows/frontend/src/components/ServersList.svelte`

- [ ] **Шаг 1.1**: Добавить в `ServersList.svelte` состояние для отложенного удаления:
  `let deleteTarget = $state<{ id: string; name: string } | null>(null);`
- [ ] **Шаг 1.2**: Переписать функцию `handleRemove`: вместо вызова `confirm(...)` устанавливать `deleteTarget = { id, name };`.
- [ ] **Шаг 1.3**: Реализовать функции `confirmDelete()` и `cancelDelete()`.
- [ ] **Шаг 1.4**: Добавить в шаблон `ServersList.svelte` модальный оверлей подтверждения с кнопками «Отмена» и «Удалить», аккуратно отцентрированный внутри модального окна и стилизованный под темную/светлую тему.
- [ ] **Шаг 1.5**: Проверить сборку фронтенда: `pnpm -C bins/outline-windows build`.

---

### Задача 2: Показ статистики строго при активном соединении и расчет реального протокола

**Файлы для изменения:**
- `bins/outline-windows/frontend/src/App.svelte`

- [ ] **Шаг 2.1**: Обернуть блок статистики (строки 419-474) в условие `{#if isRunning}` (строгий паритет с `statsContainer.isHidden = true` в macOS `MainWindowController.swift`).
- [ ] **Шаг 2.2**: Полностью вырезать генерацию случайных чисел `Math.random()` из эффекта таймера в `App.svelte` (строки 113-114, 126-127). Инициализировать счетчики трафика строго нулями: `trafficUpBytes = 0`, `trafficDownBytes = 0`.
- [ ] **Шаг 2.3**: Реализовать реактивное вычисление протокола `carrierInfo` по точной формуле из macOS:
  - Определение `carrierMode`: `H3`, `H2` или `H1` по ALPN и ссылкам.
  - Определение `subMode`: `XHTTP`, `WS` или семейство транспорта.
  - Формирование строки `transportFamily/subMode/carrierMode`.
  - Для UDP: если `tcpOnly` — `—`, иначе `tcpString`.
- [ ] **Шаг 2.4**: В разметке блока протокола заменить жестко зашитые `H3/H2` и `TUN Nat` на динамические `carrierInfo.tcp` и `carrierInfo.udp`.
- [ ] **Шаг 2.5**: Проверить сборку фронтенда: `pnpm -C bins/outline-windows build`.

---

### Задача 3: Назначение IP-адреса, DNS и маршрутизация Wintun в L3 TUN VPN

**Файлы для изменения:**
- `crates/outline-tun/src/device/windows.rs`
- `crates/outline-tun/src/engine.rs`
- `bins/outline-windows/src/config_generator.rs`

- [ ] **Шаг 3.1**: В `crates/outline-tun/src/device/windows.rs` после создания сессии Wintun добавить назначение IPv4-адреса адаптеру `10.0.85.2/24` через IP Helper API (`CreateUnicastIpAddressEntry`) либо вызов `netsh interface ipv4 set address name="{adapter_name}" source=static address=10.0.85.2 mask=255.255.255.0 gateway=none`.
- [ ] **Шаг 3.2**: В `crates/outline-tun/src/engine.rs` для Windows при старте Wintun:
  - Настроить DNS для адаптера (`set_interface_dns(wintun_if_index, &[1.1.1.1, 8.8.8.8])`).
  - Установить маршруты `0.0.0.0/1` и `128.0.0.0/1` через Wintun, предварительно добавив host route к IP-адресам серверов/аплинков через физический шлюз по умолчанию.
  - Сохранить `RouteGuard` в состоянии задачи для автоматической очистки маршрутов при завершении туннеля.
- [ ] **Шаг 3.3**: В `bins/outline-windows/src/config_generator.rs` в `apply_mode_configuration` гарантировать установку `path = "wintun"` и `name = "OutlineProxy"` при включении TUN.
- [ ] **Шаг 3.4**: Проверить компиляцию: `cargo check -p outline-tun -p outline-ws-rust -p outline-windows`.
- [ ] **Шаг 3.5**: Очистить промежуточные debug-артефакты: `rm -rf target/debug`.

---

### Задача 5: Устранение второй иконки в системном трее Windows

**Файлы для изменения:**
- `bins/outline-windows/tauri.conf.json`
- `bins/outline-windows/src/tray.rs`

- [ ] **Шаг 5.1**: В `bins/outline-windows/tauri.conf.json` удалить секцию `"trayIcon"`, чтобы Tauri v2 не создавал автоматическую дублирующую иконку трея.
- [ ] **Шаг 5.2**: В `bins/outline-windows/src/tray.rs` убедиться, что `init_tray` регистрирует единственную иконку трея с ID `"main-tray"`, контекстным меню и обработчиками кликов.

---

### Задача 6: Устранение размытия графики (DPI Awareness и четкость рендеринга)

**Файлы для изменения:**
- `bins/outline-windows/Cargo.toml`
- `bins/outline-windows/src/main.rs`
- `bins/outline-windows/tauri.conf.json`
- `bins/outline-windows/frontend/src/app.css`

- [ ] **Шаг 6.1**: В `bins/outline-windows/Cargo.toml` добавить фичу `"Win32_UI_HiDpi"` для `windows-sys`.
- [ ] **Шаг 6.2**: В `bins/outline-windows/src/main.rs` на Windows в начале `fn main()` вызвать:
  `SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);`, устранив билинейное растягивание битмапа окна операционной системой Windows DWM.
- [ ] **Шаг 6.3**: В `bins/outline-windows/tauri.conf.json` скорректировать габариты окна на `width: 380, height: 690` (строгое совпадение с нативным macOS окном 380x690).
- [ ] **Шаг 6.4**: В `bins/outline-windows/frontend/src/app.css` настроить сглаживание шрифтов и графики:
  `-webkit-font-smoothing: antialiased; text-rendering: optimizeLegibility; image-rendering: -webkit-optimize-contrast;`.

---

### Задача 7: 100% паритет цветовой палитры и элементов интерфейса с macOS

**Файлы для изменения:**
- `bins/outline-windows/frontend/src/App.svelte`
- `bins/outline-windows/frontend/src/components/Header.svelte`

- [ ] **Шаг 7.1**: В `Header.svelte` реализовать векторную/четкую шапку macOS:
  - Белая плашка `#FFFFFF` с рамкой `#CBD5E1` (в светлой теме) / `#161C26` (в темной).
  - Эмблема логотипа слева, надпись `outline` (черная `#0F172A`), `-proxy` (синяя `#1E5EE8`), слоган `FAST · SECURE · RESILIENT`.
  - Кнопка переключения темы справа (полумесяц/солнце) с круглой рамкой.
- [ ] **Шаг 7.2**: В `App.svelte` перевести все акцентные элементы с изумрудного `emerald` на палитру macOS:
  - Основной синий цвет `#1E5EE8` (в светлой теме).
  - Карточка сервера: `• Отключено` (серый), крупный жирный заголовок имени сервера, синий бейдж `Активна` (`bg-[#DBE6FE] text-[#1E3A8A]`), подпись `Обновлено недавно · каждые 12 ч`, стрелка `>`.
  - Селектор режима: иконка глобуса `🌐 Режим перехвата трафика:`, табы: выбранный `TUN (VPN)` ярко-синий `#1E5EE8` с белым текстом, невыбранный `SOCKS5 (Прокси)` белый с рамкой `#CBD5E1`. Хинт как на macOS.
  - Кнопка «+ Добавить сервер»: белый фон `#FFFFFF`, серая рамка `#CBD5E1`, черный текст и черный плюс.
  - Кнопка «Подключить»: ярко-синяя `#1E5EE8`, текст `Подключить` (обычный регистр), иконка питания. При подключении: красная `#DC2626` «Отключить».
  - Нижние кнопки быстрого доступа: ровно две кнопки («Журнал (логи)» и «Настройки») с крупными круглыми иконками на пастельно-голубом фоне `#DBE6FE` с синими иконками `#1E5EE8`.
  - Подвал: версия по центру мелким шрифтом.

---

### Задача 8: Реальный учет сетевого трафика через Win32 IP Helper API

**Файлы для изменения:**
- `bins/outline-windows/src/traffic_monitor.rs` (создание модуля)
- `bins/outline-windows/src/process_controller.rs`
- `bins/outline-windows/src/commands.rs`
- `bins/outline-windows/frontend/src/lib/types.ts`
- `bins/outline-windows/frontend/src/App.svelte`

- [ ] **Шаг 8.1**: Создать модуль `bins/outline-windows/src/traffic_monitor.rs`:
  - Функция `read_system_traffic_bytes(mode: &str) -> (u64, u64)` на базе `GetIfTable2(&mut table)`.
  - Для режима TUN: суммирование `InOctets` и `OutOctets` интерфейса Wintun (`"Outline"`, `"Wintun"`). Если не найден — активных не-loopback интерфейсов.
  - Для режима SOCKS5: суммирование активных физических интерфейсов (`OperStatus == IfOperStatusUp`).
  - `TrafficMonitor`: методы `start()`, `stop()`, `current_bytes() -> (u64, u64)`.
- [ ] **Шаг 8.2**: Интегрировать `TrafficMonitor` в `ProcessController`:
  - При `start()` вызывать `traffic_monitor.start(mode)`.
  - При `stop()` вызывать `traffic_monitor.stop()`.
  - В `get_status()` возвращать `tx_bytes` и `rx_bytes` внутри `ConnectionStatusResponse`.
- [ ] **Шаг 8.3**: В `frontend/src/lib/types.ts` добавить поля `tx_bytes` и `rx_bytes` в `ConnectionStatusResponse`.
- [ ] **Шаг 8.4**: В `frontend/src/App.svelte` при опросе статуса обновлять `trafficUpBytes = status.tx_bytes` и `trafficDownBytes = status.rx_bytes`.

---

### Задача 9: Сборка, деплой на стенд и сквозная верификация

**Файлы для изменения:**
- `scripts/package-windows.sh`

- [ ] **Шаг 9.1**: Собрать фронтенд `pnpm build` и скомпилировать бинарники через `./scripts/package-windows.sh`.
- [ ] **Шаг 9.2**: Скопировать пакет на стенд `sysadm@198.18.1.105` в `/volume1/docker/windows/shared/`.
- [ ] **Шаг 9.3**: Распаковать и запустить `OutlineProxy.exe` в Windows VM.
- [ ] **Шаг 9.4**: Снять скриншот трея: подтвердить, что осталась ровно ОДНА иконка в трее.
- [ ] **Шаг 9.5**: Снять скриншот главного окна: подтвердить четкость графики, отсутствие мыла и полное совпадение цветовой гаммы с macOS (синий акцент, круглые плитки, стиль шапки).
- [ ] **Шаг 9.6**: Запустить подключение, сгенерировать сетевую активность (`curl`) и зафиксировать скриншот с растущим трафиком (`↑ ... КБ`, `↓ ... КБ`).
- [ ] **Шаг 9.7**: Очистить `target/debug/` (`cargo clean`).

