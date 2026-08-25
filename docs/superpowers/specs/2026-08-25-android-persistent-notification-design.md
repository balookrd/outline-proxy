# Постоянная шторка с кнопкой вкл/выкл на Android (дизайн)

Дата: 2026-08-25
Статус: согласовано в чате

## Контекст

Уведомление туннеля на Android — это foreground-notification сервиса
`OutlineVpnService`
([OutlineVpnService.kt:606](../../../android/app/src/main/java/com/outline/proxy/OutlineVpnService.kt)).
Оно существует **только пока сервис запущен**: показывает статус
(`Connecting… / Connected / No link / Disconnected`), имя профиля, трафик
за сессию и одну кнопку-действие **Disconnect**. При отключении `disconnect()`
делает `stopForeground(STOP_FOREGROUND_REMOVE)` + `stopSelf()` — и шторка
пропадает.

Точки входа в подключение:

- `MainActivity` — кнопка Connect/Disconnect, владеет VPN-consent-флоу
  ([MainActivity.kt:422](../../../android/app/src/main/java/com/outline/proxy/MainActivity.kt));
- `ControlActivity` — внешнее управление по `outline://connect|disconnect|toggle`,
  прозрачная активити, тоже умеет показать consent
  ([ControlActivity.kt](../../../android/app/src/main/java/com/outline/proxy/ControlActivity.kt));
  гейтится настройками external-control (вкл/выкл + токен).

Экраны настроек (Split Tunnel / External Control / Keeping Alive) построены
единообразно: под-экран `SubScreen`, тумблеры — `Switch` в `SectionCard`.
Намерение пользователя и bookkeeping keep-alive лежат в `KeepAliveState`
([KeepAliveState.kt](../../../android/app/src/main/java/com/outline/proxy/KeepAliveState.kt)),
который читают и сервис, и UI, и цепочка возрождения.

`BootReceiver` и `WatchdogWorker` гейтятся на `shouldRun`: при выключенном VPN
после ребута сервис не поднимается. `KeepAlivePolicy.decide(...)` при `!shouldRun`
возвращает `STOP`.

## Цель

Пользователь может включить режим **постоянной шторки**. Когда он включён:

- уведомление держится не только при поднятом туннеле, но и при выключенном VPN
  (в «жду»-состоянии), пока жив сервис;
- на шторке — **один переключатель по статусу**: `Connect`, когда выключено, и
  `Disconnect`, когда включено; всё нынешнее содержимое уведомления сохраняется.

## Не-цели

- **Проактивный старт standby после ребута при выключенном VPN.** Выбран охват
  «пока жив сервис»: после перезагрузки с выключенным туннелем шторка появляется
  при следующем открытии приложения, а не сама. `BootReceiver`/`WatchdogWorker`/
  `KeepAlivePolicy` не трогаем.
- **Изменение external-control** (вкл/выкл, токен, грамматика `outline://`).
- **Смена типа foreground-сервиса** и новые permissions — `FOREGROUND_SERVICE`
  и `POST_NOTIFICATIONS` уже есть в манифесте.

## Архитектура

### Состояние (хранилище)

Новый флаг `persistentNotification: Boolean` в `KeepAliveState` (тот же prefs-файл
`outline_keepalive`, ключ `persistent_notification`, дефолт `false`). Выбор именно
`KeepAliveState`: он уже читается сервисом в каждой точке принятия решения и в UI,
и семантически это «что хочет пользователь».

### Уведомление: один переключатель по статусу

`buildNotification()` обобщается так, чтобы принимать состояние и собирать
**одну** кнопку-действие по статусу. Всё прочее (заголовок со статусом и профилем,
строка трафика, `setOngoing`, цвет, small-icon, content-intent на `MainActivity`)
сохраняется — это и есть «кроме того что есть сейчас».

- туннель **поднят** → действие **Disconnect** → `PendingIntent.getService`
  на `ACTION_DISCONNECT` (мгновенно, без активити). Поведение самого
  `ACTION_DISCONNECT` меняется ниже (в persistent-режиме уводит в standby);
- туннель **опущен** (standby) → действие **Connect** → `PendingIntent.getActivity`
  на `QuickConnectActivity`. Заголовок — `Disconnected · <профиль>`, текст —
  краткая подсказка (напр. транспорт профиля / «Tap Connect to start»).

Уведомление и так пересобирается по тику и при смене состояния, поэтому
per-state запекание PendingIntent тривиально, а кнопка визуально одна.

Чистую логику «какая метка/иконка/какое действие по состоянию» выносим в
функцию без Android API (см. Тесты).

### `OutlineVpnService`: standby вместо остановки

`disconnect()` разбивается на две ответственности:

- `teardownTunnel()` — остановить Rust-ядро, закрыть TUN, снять network-callback,
  остановить обновление уведомления, `connectedSince = 0`;
- завершение: при `persistentNotification == false` — как сейчас
  (`stopForeground(REMOVE)` + `stopSelf()`); при `true` — **остаёмся foreground**
  со standby-уведомлением, без `stopSelf()`.

Новый `ACTION_STANDBY`:

- `startForeground(NOTIFICATION_ID, <standby-notif>)`, туннель не трогаем;
- если `isRunning()` (уже подключены) — ничего не ломаем, просто держим
  актуальную шторку;
- возвращаем `START_NOT_STICKY` — убитый standby-сервис не воскресает по sticky,
  что соответствует охвату «пока жив сервис»; вернётся при открытии приложения.

Пути `ensureTunnel` / boot / watchdog / `KeepAlivePolicy` — **без изменений**.
Standby управляется явно (из UI и из `disconnect()`), а не через `ensure()`,
поэтому `ensure()` при `!shouldRun` по-прежнему честно `STOP` (и boot с
выключенным VPN шторку не поднимает).

### Управляющие вызовы из UI

В companion `OutlineVpnService` добавляются:

- `enterStandby(context)` — стартовать сервис с `ACTION_STANDBY` (foreground-старт
  из видимой активити разрешён);
- `exitStandby(context)` — команда убрать standby: если туннель **не** активен —
  `stopForeground(REMOVE)` + `stopSelf()`; если активен — игнор (оставляем
  подключение и его шторку).

### `KeepAliveScreen`: тумблер

В [`KeepAliveScreen`](../../../android/app/src/main/java/com/outline/proxy/KeepAliveScreen.kt)
сверху добавляется карточка `SectionCard` с `Switch` **Persistent notification**
(визуально отдельно от чеклиста системных грантов, у которого другой паттерн —
`ChecklistItem`). Тексты — на английском, как весь UI приложения:

- заголовок: `Persistent notification`;
- пояснение: «Keep a notification with a Connect/Disconnect button in the status
  bar, even when the VPN is off.»

При переключении (приложение на экране, туннель может быть не поднят):

- **вкл** → сохранить флаг; если `!isActive()` → `OutlineVpnService.enterStandby`
  (шторка появляется сразу);
- **выкл** → сохранить флаг; если `!isActive()` → `OutlineVpnService.exitStandby`
  (шторка убирается). Если активны — флаг просто перестанет удерживать сервис
  после следующего отключения.

### `QuickConnectActivity` (Connect из шторки)

Прозрачная активити, **`exported="false"`** — в отличие от `ControlActivity`,
чтобы не появился обход external-control-токена (внешние приложения по-прежнему
идут только через гейтованный `outline://`). Делает ровно то же, что
`ControlActivity` для connect: резолвит выбранный профиль, обновляет подписку
(`SubscriptionRefresh.configForConnect`), показывает VPN-consent при
необходимости, шлёт `requestConnect`; на отказе — тост. Если по гонке туннель уже
поднят — просто `finish()`.

Чтобы не копировать connect+consent-флоу из `ControlActivity`, общая часть
выносится в переиспользуемый helper (точная форма — на этапе плана; consent-launcher
привязан к активити, поэтому helper принимает активити и её launcher).

### Манифест

- регистрируется `QuickConnectActivity`: `Theme.Translucent.NoTitleBar`,
  `exported="false"`, `excludeFromRecents="true"`, `taskAffinity=""` (как у
  `ControlActivity`, но без `intent-filter` и без экспорта);
- новых permissions и смены типа сервиса не требуется.

## Крайние случаи

- **Нет разрешения на уведомления (Android 13+).** Foreground-сервис живёт, но
  система прячет шторку — режим фактически невидим. Чеклист Keeping Alive это уже
  подсвечивает; отдельной обработки не добавляем.
- **Consent отозван в системных настройках.** Кнопка Connect на шторке ведёт в
  `QuickConnectActivity`, которая покажет consent; при отказе — тост, как в
  нынешнем флоу.
- **Убийство процесса в standby.** Шторка не воскресает по sticky
  (`START_NOT_STICKY`); вернётся при следующем открытии приложения — это и есть
  выбранный охват.
- **Persistent off → on во время активного подключения.** Немедленно ничего не
  меняется; эффект проявится при следующем отключении (сервис останется в standby
  вместо остановки).
- **Гонка isActive() при тапе Connect.** `QuickConnectActivity` проверяет статус
  и не поднимает второй туннель.

## Дополнение: плитка Quick Settings

Добавлено по ходу задачи (перенесено из «Не-целей» по запросу владельца).
Кнопка-переключатель туннеля прямо в панели Quick Settings (та, что тянется
справа сверху), независимая от постоянной шторки.

- `OutlineTileService` (`android.service.quicksettings.TileService`): тап —
  toggle через `NotificationPolicy.toggle(isRunning())` (та же логика, что у
  кнопки уведомления). Connect переиспользует `QuickConnectActivity`
  (`startActivityAndCollapse`; ветка по API 34 для `PendingIntent`- vs
  `Intent`-перегрузки), disconnect — прямо в сервис. Состояние плитки
  `STATE_ACTIVE`/`STATE_INACTIVE` по `isRunning()`, подзаголовок (API 29+) — имя
  сервера. Обновляется в `onStartListening` и сразу после клика.
- Манифест: `<service>` с `exported="true"`, `permission=
  "android.permission.BIND_QUICK_SETTINGS_TILE"`, intent-filter
  `android.service.quicksettings.action.QS_TILE`, `icon=@drawable/ic_stat_tunnel`,
  `label="Outline"`. Новых `uses-permission` не требуется.
- **Промпт добавления плитки.** Кнопка «Add tile» в Keeping Alive: на Android 13+
  (`TIRAMISU`) вызывает `StatusBarManager.requestAddTileService(...)` — системный
  диалог добавления в один тап; ниже 13 — тост с подсказкой открыть редактор QS
  (программного API нет). Плитку нельзя добавить в панель молча — только через
  этот системный диалог или редактор QS.

## Уточнения при реализации

- **Строка контента уведомления.** Филлер «Outline Proxy» (дубль имени приложения,
  уже есть в шапке) убран. Вторая строка: трафик при подключении, тип сервера
  (`transport` / «Subscription») в standby/connecting. Пустая строка оставляла
  зазор над кнопкой действия — теперь строка всегда осмысленная.
- **Standby при открытии приложения.** Реализовано в `MainActivity.onCreate`:
  при `persistentNotification && !isActive()` вызывается
  `OutlineVpnService.enterStandby(...)` — иначе клауза спеки «шторка появляется
  после открытия приложения» не выполнялась (в первом черновике плана была
  пропущена).

## Тесты

- **Чистая логика уведомления** — функция `(running, hasLink, connecting) →
  (label, action-kind)` без Android API, JVM-тест по образцу
  [`KeepAlivePolicyTest`](../../../android/app/src/test/java/com/outline/proxy/KeepAlivePolicyTest.kt).
- **Решение standby-vs-stop** при `disconnect()` — тривиальная функция от
  `persistentNotification`, покрывается тем же способом, если вынести.
- **Lifecycle / UI** (standby-переход, кнопка на шторке, тумблер) — ручная
  проверка на эмуляторе; сборка Android — под JDK 17 (liberica).
- Rust-слой (`android/rust` и монорепо) не затрагивается — правки только в
  Kotlin-слое `app/`, поэтому CI-гейт Rust этой задаче не релевантен.

## Затрагиваемые файлы

- `android/app/src/main/java/com/outline/proxy/OutlineVpnService.kt` — standby,
  `ACTION_STANDBY`/`ACTION_STOP_STANDBY`, split `disconnect()`/`teardownTunnel()`,
  per-state кнопка, companion-хелперы `enterStandby`/`exitStandby`;
- `android/app/src/main/java/com/outline/proxy/NotificationPolicy.kt` — чистая
  логика `NotifToggle`/`toggle(running)`;
- `android/app/src/main/java/com/outline/proxy/KeepAliveState.kt` — флаг
  `persistentNotification`;
- `android/app/src/main/java/com/outline/proxy/KeepAliveScreen.kt` — тумблер
  шторки + карточка «Quick Settings tile» с кнопкой `requestAddQsTile`;
- `android/app/src/main/java/com/outline/proxy/MainActivity.kt` — standby при
  открытии приложения;
- `android/app/src/main/java/com/outline/proxy/QuickConnectActivity.kt` — новая
  прозрачная активити (connect+consent, `exported=false`);
- `android/app/src/main/java/com/outline/proxy/OutlineTileService.kt` — плитка
  Quick Settings;
- `android/app/src/main/AndroidManifest.xml` — регистрация `QuickConnectActivity`
  и `OutlineTileService`;
- `android/app/src/test/java/com/outline/proxy/NotificationPolicyTest.kt` —
  JVM-тест чистой логики кнопки.
