# План реализации: Устранение дефектов безопасности и стабильности Android-клиента

Дата: 2026-11-19
Компонент: `android/` (Kotlin + Jetpack Compose + UniFFI `android/rust/`)
Статус: В работе

## Цель
Устранить дефекты безопасности и стабильности Android-клиента, выявленные в ходе аудита безопасности:
- **[H-22]** Незащищенное внешнее управление VPN (`outline://` URI scheme): запрет пустого токена, автогенерация токена, opt-in по умолчанию (`enabled = false`).
- **[H-23]** Неконтролируемое резервное копирование (`android:allowBackup="true"`): отключение бэкапа для предотвращения утечки учетных данных и конфигураций.
- **[H-24]** Петля маршрутизации (Routing Loop) при пустом или устаревшем `SplitMode.ALLOWLIST`: проверка числа фактически добавленных приложений и предотвращение захвата собственного трафика.
- **[H-20]** TOML-инъекция в `ServerProfile.kt`: экранирование спецсимволов и управляющих последовательностей при формировании конфигурации TOML и санитизация `#remark`.
- **[M-23]** Стабильность FFI, гонки дескрипторов и фоновые приемники:
  - Дублирование дескриптора `tun_fd` (`fcntl(F_DUPFD_CLOEXEC)`) синхронно до спавна задачи Tokio в `start()`.
  - Безопасная обработка отравления мьютексов (mutex poisoning) без паники через границу FFI.
  - Освобождение мьютекса `ENGINE` перед `block_on` в `tunnel_status()`.
  - Вынос `stop()` и блокирующих FFI-вызовов из главного потока (защита от ANR).
  - Фильтрация `intent.action` в экспортированном `BootReceiver`.
  - Запрет незашифрованного HTTP-трафика (`android:usesCleartextTraffic="false"`).
  - Защита от Path Traversal при загрузке APK в `UpdateChecker.kt`.

---

## План изменений по компонентам

### 1. [H-22] Незащищенное внешнее управление VPN (`outline://`)
- **Файлы**:
  - `android/app/src/main/java/com/outline/proxy/ExternalControl.kt`
  - `android/app/src/main/java/com/outline/proxy/MainActivity.kt`
  - `android/app/src/test/java/com/outline/proxy/ExternalControlTest.kt`
- **Изменения**:
  - `ExternalControlConfig`: `enabled = false` по умолчанию.
  - В `checkAccess`: если `!config.enabled` -> `RejectReason.DISABLED`. Если `config.token.isBlank()` -> доступ запрещен (`RejectReason.BAD_TOKEN`), работа с пустым токеном не разрешена.
  - Добавить криптостойкий генератор токенов `generateSecureToken(): String` (Base64Url / hex случайных 16-24 байт).
  - В `ExternalControlStore`: дефолт `enabled = false`.
  - В UI (`MainActivity.kt`): при включении свитча `ExternalControl`, если токен пустой, автоматически генерировать случайный токен. Добавить кнопку повторной генерации токена.
  - Обновить юнит-тесты `ExternalControlTest.kt`.

### 2. [H-23] Запрет неконтролируемого бэкапа
- **Файл**:
  - `android/app/src/main/AndroidManifest.xml`
- **Изменения**:
  - Установить `android:allowBackup="false"`.

### 3. [H-24] Предотвращение Routing Loop при пустом/устаревшем `SplitMode.ALLOWLIST`
- **Файл**:
  - `android/app/src/main/java/com/outline/proxy/OutlineVpnService.kt`
  - `android/app/src/main/res/values/strings.xml`, `android/app/src/main/res/values-ru/strings.xml`
- **Изменения**:
  - В `applySplitTunnel`: в режиме `SplitMode.ALLOWLIST` подсчитывать число реально успешно добавленных приложений (пакетов, для которых `addAllowedApplication` не выбросил `NameNotFoundException`).
  - Если число успешно добавленных приложений равно 0:
    - Логировать ошибку `Log.e`.
    - Не поднимать VPN-интерфейс (`applySplitTunnel` возвращает `false`), отображать пользователю предупреждение/Toast об ошибке конфигурации и вызывать `stopSelf()`.
    - Для защиты на уровне builder также вызывать `disallow(builder, packageName)`.
  - Добавить соответствующие строковые ресурсы локализации.

### 4. [H-20] Защита от TOML Injection в `ServerProfile.kt`
- **Файлы**:
  - `android/app/src/main/java/com/outline/proxy/ServerProfile.kt`
  - `android/app/src/test/java/com/outline/proxy/ServerNameTest.kt` (или новый тестовый класс)
- **Изменения**:
  - Реализовать функцию экранирования TOML basic string: `escapeTomlString(value: String): String`, корректно экранирующую `\`, `"`, `\n`, `\r`, `\t` и управляющие символы `< 0x20` через `\uXXXX`.
  - Применять экранирование в `toConfigToml()` ко всем подставляемым строкам (`name`, `transport`, `effectiveVlessLink`, `effectiveSsLink`).
  - В `remarkOf`: санитизировать декодированный remark, заменяя переносы строк `\r`, `\n` на пробелы и обрезая недопустимые управляющие символы.
  - Написать тесты на экранирование TOML и инъекции переносов строк.

### 5. [M-23] Стабильность FFI, гонки дескрипторов и фоновые приемники
- **5.1. `android/rust/src/lib.rs`**:
  - Добавить `libc = "0.2"` в `android/rust/Cargo.toml`.
  - В `start()`: синхронно вызывать дублирование `tun_fd` через `libc::fcntl(tun_fd, libc::F_DUPFD_CLOEXEC, 0)` ДО вызова `runtime.spawn`.
  - Заменить `.lock().expect(...)` на безопасное снятие отравления мьютекса `guard.unwrap_or_else(|p| p.into_inner())` без паники через C-FFI границу.
  - В `tunnel_status()`: клонировать `engine.runtime.handle()`, освобождать лок `ENGINE` до вызова `block_on(active_carriers())`.
- **5.2. `OutlineVpnService.kt`**:
  - В `teardownTunnel()` и при остановке/проверке туннеля вызывать `stop()` и блокирующий `isRunning()` в фоновом потоке корутины (`Dispatchers.IO`), защищая главный поток от ANR при ожидании таймаута остановки.
  - Добавить реализацию `onRevoke()`.
- **5.3. `BootReceiver.kt`**:
  - Проверять `intent?.action` в `onReceive()`: обрабатывать строго `ACTION_BOOT_COMPLETED`, `ACTION_QUICKBOOT_POWERON` и `ACTION_MY_PACKAGE_REPLACED`, игнорируя посторонние интенты.
- **5.4. `UpdateChecker.kt` и `AndroidManifest.xml`**:
  - В `<application>` манифеста добавить `android:usesCleartextTraffic="false"`.
  - В `UpdateChecker.kt`: добавить санитизацию имени файла `sanitizeFilename(name: String): String`, исключающую `..`, пути каталогов и недопустимые символы.

### 6. Актуализация документации
- Обновить `android/README.md` и `android/README.ru.md`.
- Обновить `android/CHANGELOG.md` и `android/CHANGELOG.ru.md`.

---

## План верификации
1. `(cd android/rust && cargo fmt --check && cargo clippy --no-deps -- -D warnings)`
2. `(cd android/rust && cargo check)`
3. `export JAVA_HOME="/Applications/Android Studio.app/Contents/jbr/Contents/Home" && cd android && ./gradlew testDebugUnitTest`
