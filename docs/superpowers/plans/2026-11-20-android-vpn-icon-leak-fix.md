# План исправления: Устранение постоянного свечения иконки VPN в Android-клиенте

## 1. Проблема и контекст
Пользователь сообщил: «android: иконка vpn светится постоянно (последнее обновление) даже когда на паузе или выключен vpn».

Диагностика на реальном устройстве Honor Magic V3 (Android 17, `A3SD026522002698`) показала:
1. В ядре Linux висит интерфейс `47: tun1: <POINTOPOINT,UP,LOWER_UP>`.
2. В `dumpsys connectivity` висит активный `NetworkAgentInfo{network{154} ni{VPN CONNECTED extra: VPN:com.outline.proxy} InterfaceName: tun1}`.
3. В шторке уведомлений висит уведомление «Outline Proxy: На паузе · Keenetic-0109 · cloud».
4. В строке состояния (статус-баре) непрерывно светится системный значок VPN (ключик 🔑).
5. После выполнения `am force-stop com.outline.proxy` интерфейс `tun1` мгновенно исчезает из ядра Linux.

## 2. Первопричины (Root Causes)

### Первопричина №1: Утечка дескриптора `duplicated_tun_fd` в Rust (`android/rust/src/lib.rs`)
В коммите `a753eca3` («fix(android): address audit security vulnerabilities...») была добавлена функция `dup_tun_fd(tun_fd)`:
```rust
let duplicated_tun_fd = dup_tun_fd(tun_fd)?;
...
let opts = RunOptions { tun_fd: Some(duplicated_tun_fd) };
```
Однако в модуле `crates/outline-tun/src/engine.rs` вызов `attach_preopened_fd` (`crates/outline-tun/src/device.rs`) уже делает собственный `fcntl(fd, F_DUPFD_CLOEXEC, 0)` и оборачивает его в `std::fs::File`.
Сырой дескриптор `duplicated_tun_fd` никем не заворачивался в `File` и никогда не закрывался `libc::close`.
В результате в процессе `com.outline.proxy` дескриптор оставался открытым навсегда, удерживая `/dev/tun` активным в ядре Linux. Из-за этого закрытие `tunInterface?.close()` в Kotlin не приводило к удалению интерфейса TUN и отключению VPN NetworkAgent.

### Первопричина №2: Пропуск `stop()` при завершившейся задаче клиента (`OutlineVpnService.kt`)
В `android/rust/src/lib.rs` `is_running()` проверяет:
```rust
acquire_engine().as_ref().is_some_and(|engine| !engine.client_task.is_finished())
```
Если задача `client_task` упала или завершилась (например, при смене сети), `isRunning()` возвращает `false`.
В `OutlineVpnService.kt::teardownTunnel()` стояло условие `if (isRunning()) stop()`. Из-за этого `stop()` не вызывался, `ENGINE` не освобождался, а рантайм Tokio и его ресурсы оставались подвешенными в памяти.

### Первопричина №3: Ложный Foreground Service при отключении туннеля (`OutlineVpnService.kt`)
В `OutlineVpnService.kt::disconnect()`:
```kotlin
val keepStandby = KeepAliveState(this).persistentNotification || autoConfig.wifiAutomationEnabled
```
Если у пользователя включена автоматизация Wi-Fi, при нажатии «Отключить» сервис переводился в `startServiceForeground` со статусом «Отключено» и постоянным неудаляемым уведомлением со значком в строке состояния, даже когда настройка «Постоянное уведомление» была выключена.

## 3. План реализации

### Задача 1: Исправление утечки дескриптора TUN в Rust (`android/rust/src/lib.rs`)
- Убрать дублирующий вызов `dup_tun_fd(tun_fd)` в `android/rust/src/lib.rs::start`.
- Передавать `tun_fd` напрямую в `RunOptions { tun_fd: Some(tun_fd) }`, как это спроектировано в `crates/outline-tun` (где `attach_preopened_fd` делает единственный безопасный `dup`, оборачиваемый в `std::fs::File`).
- Удалить вспомогательную функцию `dup_tun_fd`.

### Задача 2: Гарантированная остановка движка в Kotlin (`OutlineVpnService.kt`)
- В `OutlineVpnService.teardownTunnel()` заменить условный вызов `if (isRunning()) stop()` на безусловный `runCatching { stop() }`.
- Это гарантирует очистку `ENGINE`, завершение рантайма Tokio и освобождение ресурсов даже если `client_task` уже перешла в состояние `is_finished()`.

### Задача 3: Исправление логики Standby в `OutlineVpnService.disconnect()`
- В `OutlineVpnService.disconnect()`:
  - `keepStandby` вычислять строго как `KeepAliveState(this).persistentNotification`.
  - Если `keepStandby == false`: разрегистрировать Wi-Fi callback, вызвать `stopForeground(STOP_FOREGROUND_REMOVE)` и `stopSelf()`.
  - Уведомление «На паузе» при срабатывании автоматизации по Wi-Fi продолжит работать штатно через метод `pauseTunnel()`.

### Задача 4: Верификация и тестирование
- Запуск тестов Kotlin: `./gradlew :app:testDebugUnitTest`.
- Проверка CI-гейта для `android/rust`: `(cd android/rust && cargo fmt --check && cargo clippy --no-deps -- -D warnings)`.
- Сборка и проверка на физическом устройстве Honor Magic V3:
  1. Подключение к VPN -> проверка `tun` интерфейса (`ip link`).
  2. Пауза (Wi-Fi) -> проверка: интерфейс `tun` закрывается, ключик VPN 🔑 исчезает из статус-бара, уведомление показывает «На паузе».
  3. Отключение -> проверка: уведомление убирается, служба останавливается.
