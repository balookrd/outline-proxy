# План устранения уязвимостей и дефектов нативного macOS клиента (macos/)

**Дата:** 2026-11-19  
**Область:** `macos/` (Swift + AppKit + `tun-runner.sh`)  
**Цель:** Устранение уязвимостей безопасности C-1, C-2, H-17, H-18, H-19, H-20, H-21 и дефектов M-22.

---

## 1. Архитектура и перечень изменений

### 1.1 [C-1, H-17] Безопасная модель привилегированного хелпера и sudoers
- **Файлы:**
  - `macos/Sources/OutlineProxy/Core/Services/PrivilegedHelperManager.swift`
  - `macos/Resources/tun-runner.sh`
- **Изменения:**
  - Удалить правило NOPASSWD для бандла `/Applications/Outline Proxy.app/...`.
  - Оставить в `/etc/sudoers.d/outline-proxy` только системный путь `/Library/Application\ Support/OutlineProxy/tun-runner.sh`.
  - В `installSudoersRule()` копировать системный бинарник `outline-ws-rust` в `/Library/Application Support/OutlineProxy/outline-ws-rust` с правами `root:wheel 0755`.
  - В `tun-runner.sh` захардкодить:
    - Бинарник: `/Library/Application Support/OutlineProxy/outline-ws-rust`
    - Run dir: `/var/run/outline-proxy` (`root:wheel 0700`)
    - Не принимать `$BIN` и `$RUN_DIR` из параметров командной строки.
  - В `PrivilegedHelperManager.swift` использовать безопасный временный файл:
    `TMP_FILE=$(mktemp /etc/sudoers.d/.outline-proxy.XXXXXX)` с проверкой через `visudo -c -f`.

### 1.2 [C-2] Защита от Shell Command Injection в `executeAsAdmin` и валидация хоста
- **Файлы:**
  - `macos/Sources/OutlineProxy/Core/Services/ProcessController.swift`
  - `macos/Sources/OutlineProxy/Core/Services/PrivilegedHelperManager.swift`
  - `macos/Sources/OutlineProxy/Core/Models/ServerProfile.swift`
- **Изменения:**
  - Реализовать единый безопасный метод квотирования аргументов командной строки в одинарные кавычки (`shellQuote`), устойчивый к раскрытию переменных и shell substitutions.
  - Для `do shell script ... with administrator privileges` экранировать итоговую shell-строку для AppleScript (`\` -> `\\`, `"` -> `\"`).
  - Валидировать `currentUser` через regex `^[a-zA-Z0-9._-]+$`.
  - В `ServerProfile.extractHost` валидировать доменное имя / IP по строгим правилам (буквы, цифры, дефис, точка), отсекая любые специальные символы.

### 1.3 [H-18] Безопасный поиск бинарников в `locateBinary()`
- **Файл:** `macos/Sources/OutlineProxy/Core/Services/ProcessController.swift`
- **Изменения:**
  - Исключить использование CWD и `OUTLINE_WS_BIN` в релизных сборках или при запуске из `.app`.
  - Для TUN режима запуск от root производить строго через захардкоженный `/Library/Application Support/OutlineProxy/outline-ws-rust`.

### 1.4 [H-19] Безопасные права доступа к файлам с секретами (0700 / 0600)
- **Файлы:**
  - `macos/Sources/OutlineProxy/Core/Services/ProfileStore.swift`
  - `macos/Sources/OutlineProxy/Core/Services/ProcessController.swift`
- **Изменения:**
  - Создавать каталог `~/Library/Application Support/OutlineProxy` с правами `0700`.
  - Сохранять `profiles.json` и `current_config.toml` с правами `0600`.

### 1.5 [H-20] Защита от TOML Injection в `ConfigGenerator`
- **Файл:** `macos/Sources/OutlineProxy/Core/Services/ConfigGenerator.swift`
- **Изменения:**
  - Полноценное экранирование в `escapeToml`: `\`, `"`, `\n`, `\r`, `\t` и отсечение/экранирование контрольных символов.
  - Валидация `transportStr` по белому списку: `vless`, `ss`, `xhttp_h2`, `xhttp_h3`, `ws_h2`, `ws_h3`.

### 1.6 [H-21] Устранение IPv6 VPN Leak и безопасная обработка аргументов в `tun-runner.sh`
- **Файл:** `macos/Resources/tun-runner.sh`
- **Изменения:**
  - Квотировать переменные в цикле по хостам, парсить через `read -r`, экранировать параметры `dig` и `route` через `--`.
  - Добавить blackhole маршрутизацию для IPv6 при активном TUN (`::/1` и `8000::/1`), снимать ее при `stop`.

### 1.7 [M-22] Доработки надежности
- **Файлы:**
  - `macos/Sources/OutlineProxy/Core/Services/SubscriptionFetcher.swift`: требование `https://`, лимит тела 512 КБ, базовая валидация структуры TOML.
  - `macos/Sources/OutlineProxy/Core/Services/ProcessController.swift`: удаление фиктивного `pid = 1` при сбое чтения `tun.pid`, реализация синхронного `stopSync()`.
  - `macos/Sources/OutlineProxy/App/AppDelegate.swift` и `AppState.swift`: вызов синхронной остановки при завершении приложения.
  - `macos/Sources/OutlineProxy/Core/Services/UpdateInstaller.swift`: санитизация `assetName` в `handOff` от path traversal `../`.

---

## 2. План верификации
1. Сборка Swift-проекта: `cd macos && swift build` (убедиться в отсутствии ошибок компиляции и warning'ов).
2. Сборка пакета и релизная сборка: `cd macos && swift build -c release`.
3. Запуск unit-тестов или тестового скрипта на Swift/bash для проверки:
   - Корректности TOML экранирования и белого списка транспортов.
   - Корректности shellQuote и экранирования AppleScript.
   - Корректности валидации хостов и пользователей.
   - Корректности синтаксиса `tun-runner.sh` (`bash -n macos/Resources/tun-runner.sh`).
4. Проверка прав создаваемых файлов (0700/0600).
