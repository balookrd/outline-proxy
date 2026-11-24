# План исправления: Петля маршрутизации TUN (Full VPN) и синхронизация хелпера на macOS

## 1. Проблема и контекст
После переустановки привилегированного системного хелпера на macOS подключение в режиме TUN (Full VPN) поднимает интерфейс `utun` и переводит статус в «Подключено», но весь трафик и пробы уходят в тайм-аут (7–10 с). В режиме SOCKS5 (без TUN) ядро `outline-client` работает штатно (`HTTP 204`).

## 2. Первопричины (Root Causes)

### Первопричина №1: Несовместимый с BSD разделитель `--` в `tun-runner.sh`
В коммите `192ff6d2` в `macos/Resources/tun-runner.sh` были добавлены разделители `--` в вызовы `/sbin/route` (`add -host --` и `delete -host --`) и `dig +short --`.
На macOS BSD `/sbin/route` не поддерживает `--` (`route: bad keyword: -`), а `dig` завершается с `Invalid option: --`. Из-за `>/dev/null 2>&1 || true` ошибка `route add -host` молча подавлялась, обходные маршруты до прокси-серверов через физический шлюз не создавались, и после установки `0.0.0.0/1 -> 10.0.85.1` и `128.0.0.0/1 -> 10.0.85.1` пакеты самого `outline-client` заворачивались обратно в его собственный `utun` (routing loop).

### Первопричина №2: Отсутствие проверки актуальности системного хелпера при обновлении бандла
`PrivilegedHelperManager.isSudoersConfigured()` проверял только существование `/Library/Application Support/OutlineProxy/tun-runner.sh` и `outline-client`, но не сверял их контрольные суммы с текущим `.app`-бандлом, а ветка запуска с правами администратора в `ProcessController.startTun` не обновляла системные копии перед стартом туннеля.

### Первопричина №3: Сопутствующие дефекты `tun-runner.sh`
1. Парсинг хостов из `link = ...` захватывал закрывающую кавычку `"` у ссылок без явного порта и не учитывал поля `ws_url` / `server_addr`.
2. Запуск `outline-client` от `root` без `STATE_PATH` создавал `current_config.state.toml` с правами `0600 root` внутри пользовательского каталога `~/Library/Application Support/OutlineProxy/`.
3. Маршруты `-blackhole` для IPv6 (`::/1`, `8000::/1`) вызывали тихий дроп пакетов вместо мгновенного возврата `EHOSTUNREACH` (`-reject`) и быстрого переключения сокетов на IPv4.

## 3. Выполняемые задачи
- [x] **Задача 1:** Автотесты BSD-совместимости `tun-runner.sh`, извлечения хостов и SHA-256 синхронизации хелпера (`macos/scripts/verify-audit-fixes.swift`, `macos/scripts/verify-helper-sync.swift`).
- [x] **Задача 2:** Исправление `macos/Resources/tun-runner.sh` (удаление `--` с запретом ведущего `-` при валидации хостов/IPv4, исправление BSD `sed`-парсинга хостов, изоляция `STATE_PATH`, переход на IPv6 `-reject`).
- [x] **Задача 3:** Проверка SHA-256 и автообновление системных копий хелпера в `PrivilegedHelperManager.swift`, `ProcessController.swift`, `SettingsWindowController.swift` и запрет ведущего `-` в `ServerProfile.swift`.
- [x] **Задача 4:** Синхронное обновление документации `macos/README.md` и `macos/README.ru.md`.
