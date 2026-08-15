# Защита туннеля от закрытия на Android (дизайн)

Дата: 2026-08-15
Статус: согласовано в чате

## Контекст

Android-клиент поднимает туннель только по явному действию пользователя:
`MainActivity` получает VPN-consent и шлёт `ACTION_CONNECT` с TOML-конфигом в
`OutlineVpnService`
([OutlineVpnService.kt:86](../../../android/app/src/main/java/com/outline/proxy/OutlineVpnService.kt)).
Ничего из того, что возвращает туннель после смерти, в приложении нет:

- интент без нашего action уходит в `else -> stopSelf()` — то есть запуск
  **системой** (always-on VPN) сейчас гасит сервис;
- в манифесте нет `stopWithTask="false"`, нет `onTaskRemoved` — свайп из
  recents уносит туннель;
- нет boot-receiver'а — после перезагрузки туннеля нет до захода в UI;
- намерение пользователя («туннель должен быть поднят») нигде не хранится:
  `ProfileStore` держит список профилей и `selectedId`, но не факт включённости.

В соседнем репозитории `../ibeacon` есть отлаженный keep-alive стек под ту же
задачу (пакет `keepalive/`): `WatchdogAlarm` + `WatchdogReceiver` (точный
будильник, самоперевзвод), `WatchdogWorker` (WorkManager, 15 мин), `BootReceiver`
(direct-boot aware), `KeepAliveHelper` (battery-exemption, точные будильники,
autostart-экраны 9 вендоров). Он написан для BLE-маячка, а не для VPN.

Целевое устройство владельца — **HONOR PNM-N49, MagicOS 10, Android 16 (SDK 36)**,
arm64-v8a. MagicOS — агрессивная по фоновым процессам прошивка, и в таблице
вендорских экранов ibeacon есть компоненты именно `com.hihonor.systemmanager`.

## Цель

Туннель переживает четыре сценария: свайп из recents, перезагрузку телефона,
убийство системой/OEM в фоне и падение самого Rust-ядра (процесс жив, туннель
внутри лёг).

## Не-цели

- **Direct boot.** Подъём до разблокировки требует переноса профилей в
  device-protected storage, которое не защищено ключом пользователя. В профилях
  лежат share-link'и с UUID/паролями серверов — решение владельца: поднимать
  туннель после разблокировки, конфиги оставить под ключом.
- **Wake lock.** У маячка `PARTIAL_WAKE_LOCK` держит BLE-рекламу живой в Doze; у
  VPN трафик сам будит устройство, а постоянный CPU-lock — это расход батареи без
  выигрыша в выживаемости.
- **Смена типа foreground-сервиса.** VPN-приложениям разрешён тип
  `systemExempted`, который выглядит уместнее нашего `specialUse`
  ([FGS service types](https://developer.android.com/develop/background-work/services/fgs/service-types)),
  но текущий `specialUse` работает и под ограничения BOOT_COMPLETED не попадает
  (см. ниже). Менять в рамках этой задачи не будем.

## Архитектура

### Единая точка входа `ensure()`

Все пути возрождения ведут в один `ACTION_ENSURE`, а не собирают туннель каждый
по-своему. Решение выносится в чистую функцию `KeepAlivePolicy.decide(...)` —
без обращений к Android API, чтобы её можно было покрыть JVM-тестами:

```
shouldRun == false          -> Stop        (пользователь выключил сознательно)
coreAlive == true           -> Nothing     (только переармить будильник)
consentGranted == false     -> GiveUp      (consent отозван)
hasProfile == false         -> GiveUp      (нечего поднимать)
иначе                       -> Connect(backoffFor(consecutiveFailures))
```

`GiveUp` = сбросить `shouldRun` + уведомление «откройте приложение». Так цепочка
не бьётся в стену бесконечно.

Проверка живости — `isRunning()` у Rust-ядра (уже есть как
`OutlineVpnService.isActive()`), а не статический флаг «сервис создан», как в
ibeacon. Это и есть покрытие четвёртого сценария. Если ядро мертво, а сервис жив,
делается полный цикл: снести TUN fd и поднять заново — после падения ядра fd уже
ничей.

### Состояние

Новый `KeepAliveState` поверх SharedPreferences:

| Ключ | Смысл |
|---|---|
| `should_run` | Намерение пользователя, а не факт. `true` при connect (включая `outline://connect`), `false` при явном disconnect |
| `consecutive_failures` | Счётчик подряд идущих неудачных подъёмов, для backoff |
| `always_on_seen` | Последнее известное `VpnService.isAlwaysOn()` — пишет сервис при старте, читает UI |

Профиль берётся из существующего `ProfileStore.selectedId` — второй копии
конфига не заводим.

### Точки входа

| Триггер | Действие |
|---|---|
| Система (always-on VPN) | `onStartCommand(null)` → `ensure` |
| `BootReceiver` (BOOT_COMPLETED, MY_PACKAGE_REPLACED) | `ensure` + завести оба watchdog'а |
| `WatchdogAlarm` (5 мин, exact, пробивает Doze) | `ensure` + переармить себя |
| `WatchdogWorker` (15 мин, WorkManager) | `ensure` + переармить будильник |
| `onTaskRemoved` (свайп из recents) | будильник через 1 с; плюс `stopWithTask="false"` |
| `onDestroy` | будильник через 2 с, если `shouldRun` |

Пара watchdog'ов дублирует друг друга сознательно, как в ibeacon: будильники
переживают не всякую OEM-чистку, а расписание WorkManager восстанавливается
системой после ребута, но имеет пол в 15 минут.

### Always-on VPN

Самый надёжный механизм и единственный, которого у ibeacon быть не могло: при
включённой «Постоянной VPN» система сама поднимает `VpnService` после ребута и
сама перезапускает его при смерти. Сервис уже объявлен с нужным intent-filter —
не хватает только обработки старта без нашего action и сохранённого намерения.
Включается пользователем вручную в системных настройках, поэтому в UI даётся
кнопка-переход и объяснение.

## Разрешения и экран «Защита от закрытия»

Чеклист — не косметика: ограничение Android 12+ на старт foreground-сервиса из
фона делает watchdog легальным именно за счёт этих разрешений
([restrictions-bg-start](https://developer.android.com/develop/background-work/services/fgs/restrictions-bg-start)).

1. **Always-on VPN** — переход в `Settings.ACTION_VPN_SETTINGS`. Статус честно
   виден только изнутри сервиса (`isAlwaysOn()`, API 29+), поэтому показывается
   последнее записанное значение, а до первого подъёма — «неизвестно».
2. **Battery-optimization exemption** — статус живой, системный диалог в один
   тап, fallback в общий список при отказе OEM.
3. **Точные будильники** (API 31+) — `canScheduleExactAlarms` +
   `ACTION_REQUEST_SCHEDULE_EXACT_ALARM`.
4. **Автозапуск производителя** — только если `resolveActivity` нашёл экран на
   этой прошивке. Таблица из ibeacon переносится как есть (9 вендоров,
   14 компонентов); на целевом устройстве сработает ветка `com.hihonor.systemmanager`.
5. **Уведомления** — `POST_NOTIFICATIONS` объявлено в манифесте, но
   runtime-запроса нет нигде: на Android 13+ уведомление сервиса не показывается,
   а скрытое FGS-уведомление на части прошивок повышает шанс, что сервис прибьют.

Навигация: сейчас переключение экранов — булев флаг `showSplit`
([MainActivity.kt:65](../../../android/app/src/main/java/com/outline/proxy/MainActivity.kt)).
Третий экран через второй такой же флаг даёт состояние «оба true»; заменяется на
`enum Screen { LIST, SPLIT, KEEP_ALIVE }`.

## Обработка ошибок

| Отказ | Реакция |
|---|---|
| Consent отозван (`prepare() != null`) | Сброс `shouldRun` + уведомление |
| `establish()` вернул null | То же — без fd туннеля нет |
| `ForegroundServiceStartNotAllowedException` | Уведомление о нужном разрешении, `shouldRun` сохраняем, будильник переармливаем |
| WorkManager недоступен (до разблокировки) | `runCatching` + лог, как в ibeacon |
| Rust `start()` бросил | Существующая обработка + инкремент `consecutive_failures` |

Уведомления об отказах идут в отдельном канале, чтобы не трогать ongoing-уведомление
туннеля.

**Backoff** — то, чего в ibeacon нет. Маячок при неудаче просто пробует снова
через 5 минут, и это безобидно. Неудачный `connect` у нас — дорогой цикл (поднять
TUN, дёрнуть Rust, снести), и при недоступном сервере частые попытки греют
батарею. После трёх неудач подряд интервал растёт 5 → 15 → 30 минут и сбрасывается
при первом успехе.

## Ограничения платформы (проверено по документации)

`specialUse` **не входит** в список типов, запрещённых к запуску из
`BOOT_COMPLETED` на Android 15+ (там `dataSync`, `camera`, `mediaPlayback`,
`phoneCall`, `mediaProjection`, `microphone`)
([behavior-changes-15](https://developer.android.com/about/versions/15/behavior-changes-15)).
Boot-путь для нас открыт.

Проверить ограничение, не собирая под другой targetSdk:

```bash
adb shell am compat enable FGS_BOOT_COMPLETED_RESTRICTIONS com.outline.proxy
adb shell am broadcast -a android.intent.action.BOOT_COMPLETED com.outline.proxy
```

## Тестирование

**JVM-юниты** (`testDebugUnitTest`, инфраструктура есть — так покрыт
`ExternalControl`): таблица решений `KeepAlivePolicy.decide` во всех комбинациях
входов, включая расчёт backoff. Всё остальное — receiver'ы, будильники,
вендорские интенты — на JVM непроверяемо.

**На устройстве** (HONOR PNM-N49, отладка по USB доступна). До сих пор на реальном
железе не запускалось вообще ничего — это будет первый прогон, поэтому нулевым
шагом идёт проверка, что туннель вообще поднимается с нативным TUN:

| Сценарий | Как проверяем |
|---|---|
| Базовый подъём | Установить, подключиться, убедиться что трафик идёт |
| Краш ядра | `adb shell am force-stop com.outline.proxy` → туннель возвращается |
| Свайп из recents | Смахнуть → `onTaskRemoved` → возврат |
| Перезагрузка | `adb reboot` → после разблокировки туннель встаёт |
| Boot-ограничения | `am compat enable FGS_BOOT_COMPLETED_RESTRICTIONS` (см. выше) |
| MagicOS | Проверить, открывается ли `com.hihonor.systemmanager` из чеклиста |

Диагностика — `adb logcat -s OutlineProxy OutlineVpnService KeepAlive`.

## Открытые вопросы

- **Поведение других прошивок.** Проверить получится только MagicOS. Таблица
  вендорских экранов для MIUI/EMUI/ColorOS/One UI переносится «как есть» из
  ibeacon и остаётся непроверенной — каждый компонент пробуется через
  `resolveActivity`, поэтому отсутствие экрана безопасно, но и пользы на этих
  прошивках никто не подтверждал.
- **Интервал будильника.** 5 минут взяты из ibeacon. Для VPN, возможно, стоит
  реже — решать после замеров расхода батареи на реальном устройстве.

## Зависимости

`androidx.work:work-runtime-ktx` — новая. На APK это порядка сотни килобайт
против текущих 33 МБ.
