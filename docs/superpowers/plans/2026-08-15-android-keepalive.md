# План: защита туннеля от закрытия (Android)

> **Для агентов-исполнителей:** ОБЯЗАТЕЛЬНЫЙ САБ-СКИЛЛ: используйте
> superpowers:subagent-driven-development (рекомендуется) или
> superpowers:executing-plans, чтобы выполнять план задача за задачей.
> Шаги размечены чекбоксами (`- [ ]`).

**Цель:** туннель переживает свайп из recents, перезагрузку телефона, убийство
системой/OEM и падение Rust-ядра.

**Архитектура:** все пути возрождения (система при always-on VPN, boot-receiver,
точный будильник, WorkManager, `onDestroy`) ведут в единый `ACTION_ENSURE`
у `OutlineVpnService`. Решение «что делать» принимает чистая функция
`KeepAlivePolicy.decide(...)` без обращений к Android API — она и покрыта
тестами. Намерение пользователя живёт в `KeepAliveState` (SharedPreferences),
конфиг берётся из существующего `ProfileStore`.

**Стек:** Kotlin, Compose, AGP 9.3.1 (built-in Kotlin), WorkManager, JUnit 4.

Спека: [2026-08-15-android-keepalive-design.md](../specs/2026-08-15-android-keepalive-design.md)

## Глобальные ограничения

- `minSdk = 24`, `targetSdk = 36`, `compileSdk = 37` — любой API выше 24
  закрывается проверкой `Build.VERSION.SDK_INT` или `ContextCompat`.
- Комментарии в коде и сообщения коммитов — **на английском**; спеки/планы и
  общение — по-русски.
- Тесты в `app/src/test/java/com/outline/proxy/`, стиль — как в
  `ExternalControlTest.kt` (JUnit 4, backtick-имена).
- `unitTests.isReturnDefaultValues = true`: заглушки android.jar возвращают
  дефолты, поэтому на JVM тестируется только чистая логика, без `Context`.
- Сборка требует JDK 17: `export JAVA_HOME=~/Library/Java/JavaVirtualMachines/liberica-17.0.20`.
- **Не коммитить без явной команды владельца** — шаги «Commit» выполняются, когда
  владелец это подтвердил; иначе показать diff и ждать.
- Rust/`.so` не трогаем: задача целиком в Kotlin-слое.

---

### Задача 1: KeepAlivePolicy и KeepAliveState

**Файлы:**
- Создать: `android/app/src/main/java/com/outline/proxy/KeepAlivePolicy.kt`
- Создать: `android/app/src/main/java/com/outline/proxy/KeepAliveState.kt`
- Тест: `android/app/src/test/java/com/outline/proxy/KeepAlivePolicyTest.kt`

**Интерфейсы:**
- Потребляет: ничего.
- Отдаёт: `KeepAliveAction { NOTHING, STOP, GIVE_UP, CONNECT }`;
  `KeepAliveDecision(action: KeepAliveAction, retryDelayMs: Long)`;
  `KeepAlivePolicy.decide(shouldRun: Boolean, coreAlive: Boolean, consentGranted: Boolean, hasProfile: Boolean, consecutiveFailures: Int): KeepAliveDecision`;
  `KeepAlivePolicy.backoffFor(consecutiveFailures: Int): Long`;
  `KeepAlivePolicy.BASE_DELAY_MS: Long`;
  `KeepAliveState(context)` с `shouldRun: Boolean`, `consecutiveFailures: Int`,
  `alwaysOnSeen: Boolean?`, `recordFailure(): Int`, `clearFailures()`.

- [ ] **Шаг 1: Написать падающий тест**

Создать `android/app/src/test/java/com/outline/proxy/KeepAlivePolicyTest.kt`:

```kotlin
package com.outline.proxy

import org.junit.Assert.assertEquals
import org.junit.Test

/** The revival decision table: what `ensure()` does for each combination. */
class KeepAlivePolicyTest {

    private fun decide(
        shouldRun: Boolean = true,
        coreAlive: Boolean = false,
        consentGranted: Boolean = true,
        hasProfile: Boolean = true,
        failures: Int = 0,
    ) = KeepAlivePolicy.decide(shouldRun, coreAlive, consentGranted, hasProfile, failures)

    @Test
    fun `user turned it off - the chain dies here`() {
        assertEquals(KeepAliveAction.STOP, decide(shouldRun = false).action)
    }

    @Test
    fun `off wins over everything else`() {
        // A revoked consent must not turn a deliberate stop into a give-up:
        // STOP is silent, GIVE_UP notifies the user.
        val decision = decide(shouldRun = false, consentGranted = false, hasProfile = false)
        assertEquals(KeepAliveAction.STOP, decision.action)
    }

    @Test
    fun `core alive - nothing to do`() {
        assertEquals(KeepAliveAction.NOTHING, decide(coreAlive = true).action)
    }

    @Test
    fun `consent revoked - give up instead of looping`() {
        assertEquals(KeepAliveAction.GIVE_UP, decide(consentGranted = false).action)
    }

    @Test
    fun `no profile selected - give up`() {
        assertEquals(KeepAliveAction.GIVE_UP, decide(hasProfile = false).action)
    }

    @Test
    fun `everything ready - connect`() {
        assertEquals(KeepAliveAction.CONNECT, decide().action)
    }

    @Test
    fun `backoff grows after three consecutive failures`() {
        assertEquals(5 * 60_000L, KeepAlivePolicy.backoffFor(0))
        assertEquals(5 * 60_000L, KeepAlivePolicy.backoffFor(2))
        assertEquals(15 * 60_000L, KeepAlivePolicy.backoffFor(3))
        assertEquals(15 * 60_000L, KeepAlivePolicy.backoffFor(4))
        assertEquals(30 * 60_000L, KeepAlivePolicy.backoffFor(5))
        assertEquals(30 * 60_000L, KeepAlivePolicy.backoffFor(50))
    }

    @Test
    fun `connect carries the backed-off retry delay`() {
        assertEquals(30 * 60_000L, decide(failures = 9).retryDelayMs)
    }

    @Test
    fun `a healthy tunnel is re-checked at the base interval`() {
        // Failures are stale once the core is up: do not stretch the watchdog.
        assertEquals(KeepAlivePolicy.BASE_DELAY_MS, decide(coreAlive = true, failures = 9).retryDelayMs)
    }
}
```

- [ ] **Шаг 2: Запустить тест, убедиться что падает**

```bash
cd android && JAVA_HOME=~/Library/Java/JavaVirtualMachines/liberica-17.0.20 ./gradlew :app:testDebugUnitTest --tests "com.outline.proxy.KeepAlivePolicyTest"
```

Ожидается: FAILED, `Unresolved reference: KeepAlivePolicy`.

- [ ] **Шаг 3: Написать KeepAlivePolicy.kt**

```kotlin
package com.outline.proxy

/** What `ensure()` should do about the tunnel right now. */
enum class KeepAliveAction {
    /** The tunnel is up: leave it alone. */
    NOTHING,

    /** The user turned it off on purpose: let the revival chain die. */
    STOP,

    /** Cannot be fixed without the user (no consent, no profile): stop and tell them. */
    GIVE_UP,

    /** Bring the tunnel up. */
    CONNECT,
}

data class KeepAliveDecision(val action: KeepAliveAction, val retryDelayMs: Long)

/**
 * The revival decision, kept free of Android APIs so it can be unit-tested.
 *
 * Order matters: an explicit "off" outranks a revoked consent, because STOP is
 * silent while GIVE_UP notifies — nobody wants a notification for a tunnel they
 * switched off themselves.
 */
object KeepAlivePolicy {

    /** Watchdog period while things are healthy. */
    const val BASE_DELAY_MS = 5 * 60_000L

    fun decide(
        shouldRun: Boolean,
        coreAlive: Boolean,
        consentGranted: Boolean,
        hasProfile: Boolean,
        consecutiveFailures: Int,
    ): KeepAliveDecision = when {
        !shouldRun -> KeepAliveDecision(KeepAliveAction.STOP, 0)
        coreAlive -> KeepAliveDecision(KeepAliveAction.NOTHING, BASE_DELAY_MS)
        !consentGranted -> KeepAliveDecision(KeepAliveAction.GIVE_UP, 0)
        !hasProfile -> KeepAliveDecision(KeepAliveAction.GIVE_UP, 0)
        else -> KeepAliveDecision(KeepAliveAction.CONNECT, backoffFor(consecutiveFailures))
    }

    /**
     * A failing connect is expensive (open the TUN, boot the Rust core, tear it
     * all down), so a server that is simply unreachable must not be retried
     * every five minutes forever.
     */
    fun backoffFor(consecutiveFailures: Int): Long = when {
        consecutiveFailures < 3 -> BASE_DELAY_MS
        consecutiveFailures < 5 -> 15 * 60_000L
        else -> 30 * 60_000L
    }
}
```

- [ ] **Шаг 4: Написать KeepAliveState.kt**

```kotlin
package com.outline.proxy

import android.content.Context

/**
 * What the user wants (not what is happening) plus the bookkeeping the watchdogs
 * need. Separate from [ProfileStore]: that one holds configuration, this one
 * holds intent, and the revival chain reads intent from processes that never
 * touch the UI.
 */
class KeepAliveState(context: Context) {
    private val prefs = context.getSharedPreferences("outline_keepalive", Context.MODE_PRIVATE)

    /** The user asked for a tunnel and has not asked for it to stop. */
    var shouldRun: Boolean
        get() = prefs.getBoolean(KEY_SHOULD_RUN, false)
        set(value) = prefs.edit().putBoolean(KEY_SHOULD_RUN, value).apply()

    var consecutiveFailures: Int
        get() = prefs.getInt(KEY_FAILURES, 0)
        set(value) = prefs.edit().putInt(KEY_FAILURES, value).apply()

    /**
     * Last known `VpnService.isAlwaysOn()`, or null before the tunnel has ever
     * come up. Only the service can read it, so the UI shows what was recorded
     * rather than guessing.
     */
    var alwaysOnSeen: Boolean?
        get() = when (prefs.getInt(KEY_ALWAYS_ON, ALWAYS_ON_UNKNOWN)) {
            1 -> true
            0 -> false
            else -> null
        }
        set(value) = prefs.edit().putInt(KEY_ALWAYS_ON, if (value == null) ALWAYS_ON_UNKNOWN else if (value) 1 else 0).apply()

    fun recordFailure(): Int = (consecutiveFailures + 1).also { consecutiveFailures = it }

    fun clearFailures() {
        consecutiveFailures = 0
    }

    private companion object {
        const val KEY_SHOULD_RUN = "should_run"
        const val KEY_FAILURES = "consecutive_failures"
        const val KEY_ALWAYS_ON = "always_on_seen"
        const val ALWAYS_ON_UNKNOWN = -1
    }
}
```

- [ ] **Шаг 5: Запустить тесты, убедиться что проходят**

```bash
cd android && JAVA_HOME=~/Library/Java/JavaVirtualMachines/liberica-17.0.20 ./gradlew :app:testDebugUnitTest --tests "com.outline.proxy.KeepAlivePolicyTest"
```

Ожидается: `BUILD SUCCESSFUL`, 9 тестов пройдено.

- [ ] **Шаг 6: Коммит**

```bash
git add android/app/src/main/java/com/outline/proxy/KeepAlivePolicy.kt android/app/src/main/java/com/outline/proxy/KeepAliveState.kt android/app/src/test/java/com/outline/proxy/KeepAlivePolicyTest.kt
git commit -m "feat(android): add the keep-alive decision table and intent store"
```

---

### Задача 2: ACTION_ENSURE в сервисе

**Файлы:**
- Изменить: `android/app/src/main/java/com/outline/proxy/OutlineVpnService.kt`
- Изменить: `android/app/src/main/AndroidManifest.xml:57-68`
- Изменить: `android/app/build.gradle.kts` (зависимость `androidx.core:core-ktx`)

**Интерфейсы:**
- Потребляет: `KeepAlivePolicy.decide`, `KeepAliveDecision`, `KeepAliveAction`,
  `KeepAliveState`, `ProfileStore`, `ServerProfile.toToml()`.
- Отдаёт: `OutlineVpnService.ACTION_ENSURE: String`;
  `OutlineVpnService.ensure(context: Context)`;
  `OutlineVpnService.NOTIFICATION_CHANNEL_ALERTS: String`.

- [ ] **Шаг 1: Добавить зависимость core-ktx**

`minSdk` = 24, а `startForegroundService` появился в 26, поэтому старт идёт через
`ContextCompat`. В `android/app/build.gradle.kts`, в блок `dependencies`, после
строки `implementation("androidx.activity:activity-compose:1.13.0")`:

```kotlin
    // ContextCompat.startForegroundService: the raw API is 26+, minSdk is 24.
    implementation("androidx.core:core-ktx:1.19.0")
```

- [ ] **Шаг 2: Добавить ACTION_ENSURE и ensure() в companion**

В `OutlineVpnService.kt`, в `companion object`, после `const val EXTRA_CONFIG_TOML`:

```kotlin
        const val ACTION_ENSURE = "com.outline.proxy.ENSURE"

        /** Channel for revival failures; separate from the ongoing tunnel notification. */
        const val NOTIFICATION_CHANNEL_ALERTS = "outline_vpn_alerts"
        private const val NOTIFICATION_ID_ALERT = 2
```

И после `requestDisconnect`:

```kotlin
        /**
         * The single revival entry point: every path that might have to bring the
         * tunnel back (always-on VPN, boot, watchdog alarm, worker, onDestroy)
         * calls this instead of assembling a connect of its own.
         */
        fun ensure(context: Context) {
            val intent = Intent(context, OutlineVpnService::class.java).apply {
                action = ACTION_ENSURE
            }
            // Android 12+ forbids starting a foreground service from the
            // background unless an exemption applies (battery-optimisation
            // allowlist, exact alarm, BOOT_COMPLETED). Losing that race must not
            // crash the receiver we are called from.
            runCatching { ContextCompat.startForegroundService(context, intent) }
                .onFailure { Log.w(TAG, "cannot start the service from the background", it) }
        }
```

Добавить импорты в начало файла:

```kotlin
import androidx.core.content.ContextCompat
```

- [ ] **Шаг 3: Обработать ACTION_ENSURE и старт системой в onStartCommand**

Заменить блок `when (intent?.action) { ... }` в `onStartCommand` целиком:

```kotlin
    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_DISCONNECT -> {
                KeepAliveState(this).shouldRun = false
                disconnect()
                return START_NOT_STICKY
            }
            ACTION_CONNECT -> {
                val configToml = intent.getStringExtra(EXTRA_CONFIG_TOML)
                if (configToml.isNullOrBlank()) {
                    Log.e(TAG, "missing config TOML; refusing to start")
                    stopSelf()
                    return START_NOT_STICKY
                }
                KeepAliveState(this).shouldRun = true
                connect(configToml)
                return START_STICKY
            }
            // A null action is the system starting us: always-on VPN, or a
            // START_STICKY restart after the process was killed. Both mean
            // "bring the tunnel back if it should be up".
            ACTION_ENSURE, null -> {
                ensureTunnel()
                return START_STICKY
            }
            else -> {
                stopSelf()
                return START_NOT_STICKY
            }
        }
    }
```

- [ ] **Шаг 4: Реализовать ensureTunnel()**

Добавить в `OutlineVpnService` перед `private fun connect`:

```kotlin
    /**
     * Act on [KeepAlivePolicy]'s verdict.
     *
     * The foreground notification goes up first, unconditionally: we may have
     * been started with `startForegroundService`, and the system kills a service
     * that fails to call `startForeground` within a few seconds — including on
     * the paths where the answer turns out to be "do nothing".
     */
    private fun ensureTunnel() {
        startForeground(NOTIFICATION_ID, buildNotification())

        val state = KeepAliveState(this)
        val store = ProfileStore(this)
        val profile = store.load().firstOrNull { it.id == store.selectedId }

        val decision = KeepAlivePolicy.decide(
            shouldRun = state.shouldRun,
            coreAlive = isActive(),
            // prepare() returns an Intent when consent is missing; from a
            // background start there is no way to show it, only to detect it.
            consentGranted = prepare(this) == null,
            hasProfile = profile != null,
            consecutiveFailures = state.consecutiveFailures,
        )
        Log.i(TAG, "ensure: ${decision.action}")

        when (decision.action) {
            KeepAliveAction.NOTHING -> {
                WatchdogAlarm.schedule(this, decision.retryDelayMs)
                // Already running: drop the notification we just raised only if
                // the tunnel owns one of its own, which it does.
            }
            KeepAliveAction.STOP -> {
                WatchdogAlarm.cancel(this)
                stopForeground(STOP_FOREGROUND_REMOVE)
                stopSelf()
            }
            KeepAliveAction.GIVE_UP -> {
                state.shouldRun = false
                WatchdogAlarm.cancel(this)
                alert("Tunnel cannot start", "Open Outline Proxy and connect again.")
                stopForeground(STOP_FOREGROUND_REMOVE)
                stopSelf()
            }
            KeepAliveAction.CONNECT -> {
                // The core may be dead while this service is alive; the old fd is
                // nobody's now, so tear the tunnel down before rebuilding it.
                tunInterface?.close()
                tunInterface = null
                WatchdogAlarm.schedule(this, decision.retryDelayMs)
                connect(profile!!.toToml())
            }
        }
    }

    /** A one-off notification about a failure the user has to fix. */
    private fun alert(title: String, text: String) {
        val manager = getSystemService(NotificationManager::class.java)
        manager.createNotificationChannel(
            NotificationChannel(
                NOTIFICATION_CHANNEL_ALERTS,
                "VPN alerts",
                NotificationManager.IMPORTANCE_DEFAULT,
            ),
        )
        val openApp = PendingIntent.getActivity(
            this,
            0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE,
        )
        manager.notify(
            NOTIFICATION_ID_ALERT,
            Notification.Builder(this, NOTIFICATION_CHANNEL_ALERTS)
                .setContentTitle(title)
                .setContentText(text)
                .setSmallIcon(android.R.drawable.ic_dialog_alert)
                .setContentIntent(openApp)
                .setAutoCancel(true)
                .build(),
        )
    }
```

- [ ] **Шаг 5: Учитывать успех/неудачу подъёма и записать always-on**

В `connect(configToml)` заменить блок `try { start(...) } catch ...`:

```kotlin
        val state = KeepAliveState(this)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            state.alwaysOnSeen = isAlwaysOn
        }
        try {
            start(configToml, filesDir.absolutePath, tun.fd)
            Log.i(TAG, "outline-ws-rust client started with native TUN (fd=${tun.fd})")
            state.clearFailures()
            registerNetworkCallback()
        } catch (e: Exception) {
            Log.e(TAG, "failed to start client", e)
            val failures = state.recordFailure()
            WatchdogAlarm.schedule(this, KeepAlivePolicy.backoffFor(failures))
            disconnect()
        }
```

Также в `connect`, в ветке `if (tun == null)`, перед `stopSelf()` добавить учёт
неудачи:

```kotlin
            KeepAliveState(this).recordFailure()
```

- [ ] **Шаг 6: onTaskRemoved и отложенный рестарт из onDestroy**

Добавить в `OutlineVpnService` перед `onDestroy`:

```kotlin
    /**
     * The user swiped the app away. With `stopWithTask="false"` the service
     * survives, but some OEM builds tear the process down anyway — so schedule a
     * check right behind it.
     */
    override fun onTaskRemoved(rootIntent: Intent?) {
        if (KeepAliveState(this).shouldRun) {
            WatchdogAlarm.schedule(this, TASK_REMOVED_DELAY_MS)
        }
        super.onTaskRemoved(rootIntent)
    }
```

Заменить `onDestroy`:

```kotlin
    override fun onDestroy() {
        // A deliberate disconnect clears shouldRun first, so this only fires
        // when something else killed us.
        if (KeepAliveState(this).shouldRun) {
            WatchdogAlarm.schedule(this, DESTROY_DELAY_MS)
        }
        disconnect()
        super.onDestroy()
    }
```

Добавить в `companion object`:

```kotlin
        private const val TASK_REMOVED_DELAY_MS = 1_000L
        private const val DESTROY_DELAY_MS = 2_000L
```

- [ ] **Шаг 7: stopWithTask в манифесте**

В `AndroidManifest.xml`, в элементе `<service android:name=".OutlineVpnService" …>`
добавить атрибут после `android:foregroundServiceType="specialUse"`:

```xml
            android:stopWithTask="false"
```

- [ ] **Шаг 8: Собрать**

Задача 3 создаёт `WatchdogAlarm`, на который здесь уже есть ссылки, поэтому
компиляция пройдёт только вместе с ней. Проверить сборку **после** задачи 3:

```bash
cd android && JAVA_HOME=~/Library/Java/JavaVirtualMachines/liberica-17.0.20 ./gradlew :app:assembleDebug
```

Ожидается: `BUILD SUCCESSFUL`.

- [ ] **Шаг 9: Коммит (вместе с задачей 3)**

```bash
git add android/app/src/main/java/com/outline/proxy/OutlineVpnService.kt android/app/src/main/AndroidManifest.xml android/app/build.gradle.kts
git commit -m "feat(android): route every revival path through a single ensure()"
```

---

### Задача 3: Будильник-watchdog

**Файлы:**
- Создать: `android/app/src/main/java/com/outline/proxy/keepalive/WatchdogAlarm.kt`
- Создать: `android/app/src/main/java/com/outline/proxy/keepalive/WatchdogReceiver.kt`
- Изменить: `android/app/src/main/AndroidManifest.xml`

**Интерфейсы:**
- Потребляет: `OutlineVpnService.ensure`, `KeepAliveState`, `KeepAlivePolicy.BASE_DELAY_MS`.
- Отдаёт: `WatchdogAlarm.schedule(context: Context, delayMs: Long = KeepAlivePolicy.BASE_DELAY_MS)`,
  `WatchdogAlarm.cancel(context: Context)`.

- [ ] **Шаг 1: Создать WatchdogAlarm.kt**

```kotlin
package com.outline.proxy.keepalive

import android.app.AlarmManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.SystemClock
import android.util.Log
import com.outline.proxy.KeepAlivePolicy

/**
 * The fast half of the watchdog pair. Unlike WorkManager it pierces Doze and has
 * no 15-minute floor, and it re-arms itself on every fire — so a process that
 * was killed resumes checking as soon as one alarm lands.
 */
object WatchdogAlarm {

    private const val TAG = "KeepAlive"
    private const val REQUEST_CODE = 42

    fun schedule(context: Context, delayMs: Long = KeepAlivePolicy.BASE_DELAY_MS) {
        val manager = context.getSystemService(AlarmManager::class.java) ?: return
        val triggerAt = SystemClock.elapsedRealtime() + delayMs
        val pendingIntent = pendingIntent(context)

        val canBeExact =
            Build.VERSION.SDK_INT < Build.VERSION_CODES.S || manager.canScheduleExactAlarms()
        try {
            if (canBeExact) {
                manager.setExactAndAllowWhileIdle(
                    AlarmManager.ELAPSED_REALTIME_WAKEUP,
                    triggerAt,
                    pendingIntent,
                )
            } else {
                // Inexact still fires, just with the system's own batching slack.
                manager.setAndAllowWhileIdle(
                    AlarmManager.ELAPSED_REALTIME_WAKEUP,
                    triggerAt,
                    pendingIntent,
                )
            }
        } catch (e: SecurityException) {
            Log.w(TAG, "exact alarm denied, falling back to inexact", e)
            manager.setAndAllowWhileIdle(
                AlarmManager.ELAPSED_REALTIME_WAKEUP,
                triggerAt,
                pendingIntent,
            )
        }
    }

    fun cancel(context: Context) {
        val manager = context.getSystemService(AlarmManager::class.java) ?: return
        manager.cancel(pendingIntent(context))
    }

    private fun pendingIntent(context: Context): PendingIntent = PendingIntent.getBroadcast(
        context,
        REQUEST_CODE,
        Intent(context, WatchdogReceiver::class.java),
        PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
    )
}
```

- [ ] **Шаг 2: Создать WatchdogReceiver.kt**

```kotlin
package com.outline.proxy.keepalive

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import com.outline.proxy.KeepAliveState
import com.outline.proxy.OutlineVpnService

class WatchdogReceiver : BroadcastReceiver() {

    override fun onReceive(context: Context, intent: Intent) {
        if (!KeepAliveState(context).shouldRun) {
            // The user stopped the tunnel on purpose: let the chain die here.
            return
        }
        // ensure() decides what to do and re-arms the alarm with the right delay,
        // so there is no scheduling to repeat here.
        OutlineVpnService.ensure(context)
    }
}
```

- [ ] **Шаг 3: Объявить receiver в манифесте**

В `AndroidManifest.xml`, внутри `<application>`, после элемента `<service>`:

```xml
        <!-- Exact-alarm watchdog: fires through Doze and is re-armed by ensure(). -->
        <receiver
            android:name=".keepalive.WatchdogReceiver"
            android:enabled="true"
            android:exported="false" />
```

- [ ] **Шаг 4: Добавить разрешения на будильники**

В `AndroidManifest.xml`, после `<uses-permission android:name="android.permission.POST_NOTIFICATIONS" />`:

```xml
    <!-- Keep-alive: exact alarms pierce Doze, and are one of the exemptions
         that make starting a foreground service from the background legal. -->
    <uses-permission android:name="android.permission.SCHEDULE_EXACT_ALARM" />
    <uses-permission android:name="android.permission.USE_EXACT_ALARM" />
```

- [ ] **Шаг 5: Собрать (закрывает и задачу 2)**

```bash
cd android && JAVA_HOME=~/Library/Java/JavaVirtualMachines/liberica-17.0.20 ./gradlew :app:assembleDebug :app:testDebugUnitTest
```

Ожидается: `BUILD SUCCESSFUL`, тесты задачи 1 по-прежнему зелёные.

- [ ] **Шаг 6: Коммит**

```bash
git add android/app/src/main/java/com/outline/proxy/keepalive/ android/app/src/main/AndroidManifest.xml
git commit -m "feat(android): add the exact-alarm watchdog"
```

---

### Задача 4: Boot-receiver и WorkManager

**Файлы:**
- Создать: `android/app/src/main/java/com/outline/proxy/keepalive/BootReceiver.kt`
- Создать: `android/app/src/main/java/com/outline/proxy/keepalive/WatchdogWorker.kt`
- Изменить: `android/app/build.gradle.kts`
- Изменить: `android/app/src/main/AndroidManifest.xml`

**Интерфейсы:**
- Потребляет: `OutlineVpnService.ensure`, `KeepAliveState`, `WatchdogAlarm`.
- Отдаёт: `WatchdogWorker.schedule(context: Context)`, `WatchdogWorker.cancel(context: Context)`.

- [ ] **Шаг 1: Добавить зависимость WorkManager**

В `android/app/build.gradle.kts`, в `dependencies`, после строки с `core-ktx`:

```kotlin
    // The slow half of the watchdog pair: its schedule is persisted by the
    // framework and restored after reboot, unlike our alarms.
    implementation("androidx.work:work-runtime-ktx:2.11.0")
```

- [ ] **Шаг 2: Создать WatchdogWorker.kt**

```kotlin
package com.outline.proxy.keepalive

import android.content.Context
import android.util.Log
import androidx.work.CoroutineWorker
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.WorkerParameters
import com.outline.proxy.KeepAliveState
import com.outline.proxy.OutlineVpnService
import java.util.concurrent.TimeUnit

/**
 * The slow half of the watchdog pair. WorkManager's schedule is persisted by the
 * framework and restored after reboot, so it covers the case where every alarm
 * of ours was wiped — at the cost of a 15-minute minimum period.
 */
class WatchdogWorker(
    context: Context,
    params: WorkerParameters,
) : CoroutineWorker(context, params) {

    override suspend fun doWork(): Result {
        if (KeepAliveState(applicationContext).shouldRun) {
            OutlineVpnService.ensure(applicationContext)
            // Alarms do not survive every OEM cleanup; re-arm from here as well.
            WatchdogAlarm.schedule(applicationContext)
        }
        return Result.success()
    }

    companion object {
        private const val TAG = "KeepAlive"
        private const val WORK_NAME = "outline-watchdog"

        fun schedule(context: Context) {
            val request = PeriodicWorkRequestBuilder<WatchdogWorker>(15, TimeUnit.MINUTES)
                .addTag(WORK_NAME)
                .build()
            runCatching {
                WorkManager.getInstance(context).enqueueUniquePeriodicWork(
                    WORK_NAME,
                    ExistingPeriodicWorkPolicy.UPDATE,
                    request,
                )
            }.onFailure {
                // WorkManager is unavailable before the user unlocks the device.
                Log.w(TAG, "could not schedule the periodic watchdog", it)
            }
        }

        fun cancel(context: Context) {
            runCatching { WorkManager.getInstance(context).cancelUniqueWork(WORK_NAME) }
        }
    }
}
```

- [ ] **Шаг 3: Создать BootReceiver.kt**

```kotlin
package com.outline.proxy.keepalive

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.util.Log
import com.outline.proxy.KeepAliveState
import com.outline.proxy.OutlineVpnService

/**
 * Brings the tunnel back after a reboot or an app update.
 *
 * Not direct-boot aware on purpose: the profiles hold server credentials and
 * stay in credential-protected storage, so there is nothing to read before the
 * user unlocks. BOOT_COMPLETED already arrives after unlock.
 */
class BootReceiver : BroadcastReceiver() {

    override fun onReceive(context: Context, intent: Intent) {
        if (!KeepAliveState(context).shouldRun) return

        Log.i(TAG, "restoring the tunnel after ${intent.action}")
        OutlineVpnService.ensure(context)
        WatchdogAlarm.schedule(context, FIRST_CHECK_DELAY_MS)
        WatchdogWorker.schedule(context)
    }

    private companion object {
        const val TAG = "KeepAlive"
        const val FIRST_CHECK_DELAY_MS = 30_000L
    }
}
```

- [ ] **Шаг 4: Объявить BootReceiver и разрешение**

В `AndroidManifest.xml`, к разрешениям добавить:

```xml
    <uses-permission android:name="android.permission.RECEIVE_BOOT_COMPLETED" />
```

Внутри `<application>`, после `WatchdogReceiver`:

```xml
        <!-- Comes back after a reboot and after the app itself is updated. -->
        <receiver
            android:name=".keepalive.BootReceiver"
            android:enabled="true"
            android:exported="true">
            <intent-filter android:priority="1000">
                <action android:name="android.intent.action.BOOT_COMPLETED" />
                <action android:name="android.intent.action.QUICKBOOT_POWERON" />
            </intent-filter>
            <intent-filter>
                <action android:name="android.intent.action.MY_PACKAGE_REPLACED" />
            </intent-filter>
        </receiver>
```

- [ ] **Шаг 5: Завести оба watchdog'а при подключении**

В `OutlineVpnService.kt`, в ветке `ACTION_CONNECT` метода `onStartCommand`,
после `KeepAliveState(this).shouldRun = true`:

```kotlin
                WatchdogWorker.schedule(this)
```

И в ветке `ACTION_DISCONNECT`, после `KeepAliveState(this).shouldRun = false`:

```kotlin
                WatchdogAlarm.cancel(this)
                WatchdogWorker.cancel(this)
```

Добавить импорты:

```kotlin
import com.outline.proxy.keepalive.WatchdogAlarm
import com.outline.proxy.keepalive.WatchdogWorker
```

- [ ] **Шаг 6: Собрать**

```bash
cd android && JAVA_HOME=~/Library/Java/JavaVirtualMachines/liberica-17.0.20 ./gradlew :app:assembleDebug :app:testDebugUnitTest
```

Ожидается: `BUILD SUCCESSFUL`.

- [ ] **Шаг 7: Коммит**

```bash
git add android/app/src/main/java/com/outline/proxy/ android/app/src/main/AndroidManifest.xml android/app/build.gradle.kts
git commit -m "feat(android): restore the tunnel after reboot; add the WorkManager watchdog"
```

---

### Задача 5: KeepAliveHelper

**Файлы:**
- Создать: `android/app/src/main/java/com/outline/proxy/keepalive/KeepAliveHelper.kt`
- Изменить: `android/app/src/main/AndroidManifest.xml`

**Интерфейсы:**
- Потребляет: ничего.
- Отдаёт: `KeepAliveHelper.isIgnoringBatteryOptimizations(context): Boolean`,
  `batteryOptimizationIntent(context): Intent`, `batteryOptimizationListIntent(): Intent`,
  `canScheduleExactAlarms(context): Boolean`, `exactAlarmSettingsIntent(context): Intent?`,
  `vpnSettingsIntent(): Intent`, `vendorLabel(context): String?`,
  `autostartIntent(context): Intent?`.

- [ ] **Шаг 1: Добавить разрешение**

В `AndroidManifest.xml`, к разрешениям (корневой тег `<manifest>` уже должен
объявлять `xmlns:tools`; если нет — добавить
`xmlns:tools="http://schemas.android.com/tools"`):

```xml
    <uses-permission
        android:name="android.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS"
        tools:ignore="BatteryLife" />
```

- [ ] **Шаг 2: Создать KeepAliveHelper.kt**

Перенос из `../ibeacon/app/src/main/java/com/balookrd/ibeacon/keepalive/KeepAliveHelper.kt`
с добавленным `vpnSettingsIntent` (у маячка always-on VPN нет):

```kotlin
package com.outline.proxy.keepalive

import android.annotation.SuppressLint
import android.app.AlarmManager
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.PowerManager
import android.provider.Settings
import java.util.Locale

/**
 * The parts of staying alive that only the user can grant.
 *
 * Battery-optimisation exemption, exact-alarm access and always-on VPN have real
 * system screens. Vendor autostart whitelists (MagicOS, MIUI, EMUI, ColorOS,
 * FuntouchOS, One UI) have no API at all — the best any app can do is open the
 * right settings screen and say plainly what needs to be switched on there.
 */
object KeepAliveHelper {

    fun isIgnoringBatteryOptimizations(context: Context): Boolean {
        val power = context.getSystemService(PowerManager::class.java) ?: return false
        return power.isIgnoringBatteryOptimizations(context.packageName)
    }

    /** Opens the system dialog that whitelists this app in one tap. */
    @SuppressLint("BatteryLife")
    fun batteryOptimizationIntent(context: Context): Intent =
        Intent(Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS)
            .setData(Uri.parse("package:${context.packageName}"))

    /** Fallback when the direct request is blocked by the OEM. */
    fun batteryOptimizationListIntent(): Intent =
        Intent(Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS)

    fun canScheduleExactAlarms(context: Context): Boolean {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.S) return true
        val manager = context.getSystemService(AlarmManager::class.java) ?: return false
        return manager.canScheduleExactAlarms()
    }

    fun exactAlarmSettingsIntent(context: Context): Intent? {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.S) return null
        return Intent(Settings.ACTION_REQUEST_SCHEDULE_EXACT_ALARM)
            .setData(Uri.parse("package:${context.packageName}"))
    }

    /**
     * Always-on VPN lives in the system VPN list; there is no deep link to our
     * own entry, so this opens the list itself.
     */
    fun vpnSettingsIntent(): Intent = Intent(Settings.ACTION_VPN_SETTINGS)

    /** Manufacturer name to show in the checklist, or null on stock-ish builds. */
    fun vendorLabel(context: Context): String? =
        vendorEntries(context).firstOrNull()?.let { manufacturerLabel() }

    /**
     * The vendor's autostart / protected-apps screen, if one of the known
     * components resolves on this device.
     */
    fun autostartIntent(context: Context): Intent? = vendorEntries(context).firstOrNull()

    private fun vendorEntries(context: Context): List<Intent> =
        AUTOSTART_COMPONENTS
            .map { (pkg, cls) ->
                Intent().setComponent(ComponentName(pkg, cls))
                    .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            }
            .filter { intent -> context.packageManager.resolveActivity(intent, 0) != null }

    private fun manufacturerLabel(): String =
        Build.MANUFACTURER.replaceFirstChar { it.titlecase(Locale.US) }

    /**
     * Known autostart screens, most specific first. They come and go between
     * firmware versions, so every one is probed with `resolveActivity` before
     * being offered.
     */
    private val AUTOSTART_COMPONENTS = listOf(
        // Xiaomi / Redmi / POCO
        "com.miui.securitycenter" to "com.miui.permcenter.autostart.AutoStartManagementActivity",
        // Honor (MagicOS) — its own package since the split from Huawei
        "com.hihonor.systemmanager" to "com.hihonor.systemmanager.startupmgr.ui.StartupNormalAppListActivity",
        "com.hihonor.systemmanager" to "com.hihonor.systemmanager.appcontrol.activity.StartupAppControlActivity",
        // Huawei (EMUI)
        "com.huawei.systemmanager" to "com.huawei.systemmanager.startupmgr.ui.StartupNormalAppListActivity",
        "com.huawei.systemmanager" to "com.huawei.systemmanager.optimize.process.ProtectActivity",
        "com.huawei.systemmanager" to "com.huawei.systemmanager.appcontrol.activity.StartupAppControlActivity",
        // Oppo / Realme
        "com.coloros.safecenter" to "com.coloros.safecenter.permission.startup.StartupAppListActivity",
        "com.coloros.safecenter" to "com.coloros.safecenter.startupapp.StartupAppListActivity",
        "com.oppo.safe" to "com.oppo.safe.permission.startup.StartupAppListActivity",
        // Vivo / iQOO
        "com.vivo.permissionmanager" to "com.vivo.permissionmanager.activity.BgStartUpManagerActivity",
        "com.iqoo.secure" to "com.iqoo.secure.ui.phoneoptimize.AddWhiteListActivity",
        // OnePlus
        "com.oneplus.security" to "com.oneplus.security.chainlaunch.view.ChainLaunchAppListActivity",
        // Samsung
        "com.samsung.android.lool" to "com.samsung.android.sm.ui.battery.BatteryActivity",
        "com.samsung.android.lool" to "com.samsung.android.sm.battery.ui.BatteryActivity",
        // Asus
        "com.asus.mobilemanager" to "com.asus.mobilemanager.autostart.AutoStartActivity",
        // Letv
        "com.letv.android.letvsafe" to "com.letv.android.letvsafe.AutobootManageActivity",
    )
}
```

- [ ] **Шаг 3: Собрать**

```bash
cd android && JAVA_HOME=~/Library/Java/JavaVirtualMachines/liberica-17.0.20 ./gradlew :app:assembleDebug
```

Ожидается: `BUILD SUCCESSFUL`.

- [ ] **Шаг 4: Коммит**

```bash
git add android/app/src/main/java/com/outline/proxy/keepalive/KeepAliveHelper.kt android/app/src/main/AndroidManifest.xml
git commit -m "feat(android): add the keep-alive permission helper"
```

---

### Задача 6: Экран «Защита от закрытия»

**Файлы:**
- Создать: `android/app/src/main/java/com/outline/proxy/KeepAliveScreen.kt`
- Изменить: `android/app/src/main/java/com/outline/proxy/MainActivity.kt:55-105`

**Интерфейсы:**
- Потребляет: `KeepAliveHelper.*`, `KeepAliveState.alwaysOnSeen`.
- Отдаёт: `@Composable KeepAliveScreen(onBack: () -> Unit)`;
  `enum class Screen { LIST, SPLIT, KEEP_ALIVE }`.

- [ ] **Шаг 1: Создать KeepAliveScreen.kt**

```kotlin
package com.outline.proxy

import android.Manifest
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import com.outline.proxy.keepalive.KeepAliveHelper

/**
 * The checklist of everything that keeps the tunnel alive but only the user can
 * grant. Statuses are re-read on every recomposition trigger ([refresh]), since
 * the user grants them in system screens we do not get results from.
 */
@Composable
fun KeepAliveScreen(onBack: () -> Unit) {
    val context = LocalContext.current
    var refresh by remember { mutableIntStateOf(0) }

    val notifications = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestPermission(),
    ) { refresh++ }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
    ) {
        Text("Keeping the tunnel alive", style = MaterialTheme.typography.headlineSmall)
        Text(
            "Android and the phone vendor may stop background apps. " +
                "These switches are what keeps the tunnel up.",
            style = MaterialTheme.typography.bodyMedium,
            modifier = Modifier.padding(top = 4.dp, bottom = 16.dp),
        )

        // `refresh` is read so that bumping it re-runs the status queries below.
        @Suppress("UNUSED_EXPRESSION") refresh

        ChecklistItem(
            title = "Always-on VPN",
            status = when (KeepAliveState(context).alwaysOnSeen) {
                true -> Status.GRANTED
                false -> Status.MISSING
                null -> Status.UNKNOWN
            },
            explanation = "The strongest option: the system itself keeps the tunnel up " +
                "and restarts it. Turn on \"Always-on VPN\" for Outline Proxy in the VPN list.",
            action = "Open VPN settings",
            onAction = { context.launch(KeepAliveHelper.vpnSettingsIntent()) },
        )

        ChecklistItem(
            title = "Ignore battery optimisation",
            status = if (KeepAliveHelper.isIgnoringBatteryOptimizations(context)) {
                Status.GRANTED
            } else {
                Status.MISSING
            },
            explanation = "Without it Android may stop the tunnel in the background " +
                "and refuse to let the watchdog restart it.",
            action = "Allow",
            onAction = {
                if (!context.launch(KeepAliveHelper.batteryOptimizationIntent(context))) {
                    context.launch(KeepAliveHelper.batteryOptimizationListIntent())
                }
                refresh++
            },
        )

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            ChecklistItem(
                title = "Exact alarms",
                status = if (KeepAliveHelper.canScheduleExactAlarms(context)) {
                    Status.GRANTED
                } else {
                    Status.MISSING
                },
                explanation = "The watchdog checks the tunnel through Doze. " +
                    "Without this permission the checks are delayed by the system.",
                action = "Allow",
                onAction = {
                    KeepAliveHelper.exactAlarmSettingsIntent(context)?.let { context.launch(it) }
                    refresh++
                },
            )
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            val granted = ContextCompat.checkSelfPermission(
                context,
                Manifest.permission.POST_NOTIFICATIONS,
            ) == PackageManager.PERMISSION_GRANTED
            ChecklistItem(
                title = "Notifications",
                status = if (granted) Status.GRANTED else Status.MISSING,
                explanation = "The tunnel runs as a foreground service. A hidden " +
                    "notification makes some firmware more eager to kill it.",
                action = "Allow",
                onAction = { notifications.launch(Manifest.permission.POST_NOTIFICATIONS) },
            )
        }

        KeepAliveHelper.vendorLabel(context)?.let { vendor ->
            ChecklistItem(
                title = "$vendor autostart",
                status = Status.UNKNOWN,
                explanation = "$vendor keeps its own list of apps allowed to run in the " +
                    "background. There is no API to read it — open the screen and allow " +
                    "Outline Proxy there.",
                action = "Open $vendor settings",
                onAction = {
                    KeepAliveHelper.autostartIntent(context)?.let { context.launch(it) }
                },
            )
        }

        TextButton(onClick = onBack, modifier = Modifier.padding(top = 16.dp)) {
            Text("Back")
        }
    }
}

private enum class Status { GRANTED, MISSING, UNKNOWN }

@Composable
private fun ChecklistItem(
    title: String,
    status: Status,
    explanation: String,
    action: String,
    onAction: () -> Unit,
) {
    Card(modifier = Modifier.padding(bottom = 12.dp)) {
        Column(modifier = Modifier.padding(16.dp)) {
            Text(
                when (status) {
                    Status.GRANTED -> "✓ $title"
                    Status.MISSING -> "✗ $title"
                    Status.UNKNOWN -> "? $title"
                },
                style = MaterialTheme.typography.titleMedium,
            )
            Text(
                explanation,
                style = MaterialTheme.typography.bodySmall,
                modifier = Modifier.padding(top = 4.dp, bottom = 12.dp),
            )
            Button(onClick = onAction) { Text(action) }
        }
    }
}

/**
 * Vendor screens come and go between firmware versions, so an intent that
 * resolved once can still fail to start. Returns false instead of crashing.
 */
private fun Context.launch(intent: Intent): Boolean = runCatching {
    startActivity(intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
}.isSuccess
```

- [ ] **Шаг 2: Заменить булевы флаги навигации на enum**

Экранов уже три (`showSplit`, `showExternal`), четвёртый булев флаг дал бы
состояния вида «оба true». В `MainActivity.kt` заменить строки 65-66:

```kotlin
                var showSplit by remember { mutableStateOf(false) }
                var showExternal by remember { mutableStateOf(false) }
```

на:

```kotlin
                var screen by remember { mutableStateOf(Screen.LIST) }
```

Заменить всю цепочку `if (showSplit) … else if (showExternal) … else …`
(строки 68-104) на `when`, сохранив аргументы существующих экранов:

```kotlin
                when (screen) {
                    Screen.SPLIT -> SplitTunnelScreen(
                        store = SplitTunnelStore(this@MainActivity),
                        loadApps = { loadLaunchableApps(this@MainActivity) },
                        onBack = { screen = Screen.LIST },
                    )
                    Screen.EXTERNAL -> ExternalControlScreen(
                        store = ExternalControlStore(this@MainActivity),
                        onBack = { screen = Screen.LIST },
                    )
                    Screen.KEEP_ALIVE -> KeepAliveScreen(
                        onBack = { screen = Screen.LIST },
                    )
                    Screen.LIST -> ServerListScreen(
                        profiles = profiles,
                        selectedId = selectedId,
                        onSelect = { selectedId = it; persist() },
                        onSave = { edited ->
                            val idx = profiles.indexOfFirst { it.id == edited.id }
                            if (idx >= 0) profiles[idx] = edited else profiles.add(edited)
                            if (selectedId == null) selectedId = edited.id
                            persist()
                        },
                        onDelete = { profile ->
                            profiles.removeAll { it.id == profile.id }
                            if (selectedId == profile.id) selectedId = profiles.firstOrNull()?.id
                            persist()
                        },
                        onConnect = {
                            profiles.firstOrNull { it.id == selectedId }?.let {
                                requestVpnAndConnect(it.toToml())
                            }
                        },
                        onDisconnect = ::disconnect,
                        onOpenSplitTunnel = { screen = Screen.SPLIT },
                        onOpenExternalControl = { screen = Screen.EXTERNAL },
                        onOpenKeepAlive = { screen = Screen.KEEP_ALIVE },
                    )
                }
```

Добавить в конец файла:

```kotlin
/** Which screen the single-activity UI shows. */
enum class Screen { LIST, SPLIT, EXTERNAL, KEEP_ALIVE }
```

- [ ] **Шаг 3: Добавить кнопку в ServerListScreen**

В сигнатуру `ServerListScreen` добавить параметр рядом с `onOpenSplitTunnel`:

```kotlin
    onOpenKeepAlive: () -> Unit,
```

И рядом с существующей кнопкой «Split tunneling…» — вторую:

```kotlin
                TextButton(onClick = onOpenKeepAlive) { Text("Keeping alive…") }
```

- [ ] **Шаг 4: Собрать и прогнать тесты**

```bash
cd android && JAVA_HOME=~/Library/Java/JavaVirtualMachines/liberica-17.0.20 ./gradlew :app:assembleDebug :app:testDebugUnitTest
```

Ожидается: `BUILD SUCCESSFUL`.

- [ ] **Шаг 5: Коммит**

```bash
git add android/app/src/main/java/com/outline/proxy/
git commit -m "feat(android): add the keep-alive checklist screen"
```

---

### Задача 7: Проверка на устройстве и документация

**Файлы:**
- Изменить: `android/README.md`
- Изменить: `android/README.ru.md`

Устройство: HONOR PNM-N49, MagicOS 10, Android 16 (SDK 36), отладка по USB
авторизована. `ADB=~/Library/Android/sdk/platform-tools/adb`.

- [ ] **Шаг 1: Установить сборку**

```bash
cd android && JAVA_HOME=~/Library/Java/JavaVirtualMachines/liberica-17.0.20 ./gradlew :app:installDebug
```

Ожидается: `BUILD SUCCESSFUL`, приложение появилось на телефоне.

- [ ] **Шаг 2: Базовая проверка — туннель вообще поднимается**

На реальном железе не запускалось ещё ничего, поэтому это первый прогон, а не
формальность. Открыть приложение, добавить профиль, выдать VPN-consent, нажать
Connect. Параллельно:

```bash
~/Library/Android/sdk/platform-tools/adb logcat -s OutlineProxy OutlineVpnService KeepAlive
```

Ожидается: строка `outline-ws-rust client started with native TUN (fd=…)`, значок
VPN в статус-баре, трафик ходит.

Если туннель не поднимается — остановиться и разбираться здесь: без работающего
базового сценария проверять keep-alive бессмысленно.

- [ ] **Шаг 3: Проверить возврат после убийства процесса**

```bash
~/Library/Android/sdk/platform-tools/adb shell am force-stop com.outline.proxy
```

Ожидается: alarm сработает не позже чем через 5 минут и туннель вернётся.
Не дожидаясь — дёрнуть watchdog вручную:

```bash
~/Library/Android/sdk/platform-tools/adb shell am broadcast -a android.intent.action.BOOT_COMPLETED com.outline.proxy
```

Ожидается: в logcat `restoring the tunnel after …`, затем `ensure: CONNECT`.

- [ ] **Шаг 4: Проверить свайп из recents**

Смахнуть приложение из списка недавних. Ожидается: значок VPN остаётся; в logcat
нет `ensure: STOP`.

- [ ] **Шаг 5: Проверить перезагрузку**

```bash
~/Library/Android/sdk/platform-tools/adb reboot
```

После загрузки **разблокировать** телефон. Ожидается: в течение ~30 секунд
туннель встаёт, в logcat `restoring the tunnel after android.intent.action.BOOT_COMPLETED`.

- [ ] **Шаг 6: Проверить ограничения BOOT_COMPLETED для FGS**

По документации `specialUse` в запрещённый список Android 15+ не входит; шаг это
подтверждает на реальной прошивке:

```bash
~/Library/Android/sdk/platform-tools/adb shell am compat enable FGS_BOOT_COMPLETED_RESTRICTIONS com.outline.proxy
~/Library/Android/sdk/platform-tools/adb shell am broadcast -a android.intent.action.BOOT_COMPLETED com.outline.proxy
```

Ожидается: туннель поднимается, в logcat нет `ForegroundServiceStartNotAllowedException`.
Затем снять флаг:

```bash
~/Library/Android/sdk/platform-tools/adb shell am compat reset FGS_BOOT_COMPLETED_RESTRICTIONS com.outline.proxy
```

- [ ] **Шаг 7: Проверить экран чеклиста на MagicOS**

Открыть «Keeping alive…». Ожидается: пункт автозапуска называется «Honor
autostart» и открывает `com.hihonor.systemmanager`; battery-optimisation и exact
alarms показывают живой статус и меняют его после выдачи.

- [ ] **Шаг 8: Записать результаты в README (EN + RU)**

В обоих README, в раздел «What is verified vs. not» / «Что проверено, а что нет»,
добавить пункты о keep-alive: что проверено на HONOR/MagicOS (перечислить
сценарии из шагов 2–7) и что таблица вендорских экранов для MIUI/EMUI/ColorOS/One
UI остаётся непроверенной. Обе версии правятся в одном изменении — правило репозитория.

Также описать сам механизм в разделе про архитектуру: единый `ensure()`, пара
watchdog'ов, always-on VPN как главный механизм, экран разрешений.

- [ ] **Шаг 9: Коммит**

```bash
git add android/README.md android/README.ru.md
git commit -m "docs(android): document the keep-alive stack and what was verified on-device"
```

---

## Самопроверка плана

**Покрытие спеки:**

| Требование спеки | Задача |
|---|---|
| `KeepAlivePolicy.decide` + таблица решений | 1 |
| `KeepAliveState` (`should_run`, `consecutive_failures`, `always_on_seen`) | 1 |
| Единый `ACTION_ENSURE` | 2 |
| Старт системой при always-on (`onStartCommand(null)`) | 2 |
| Проверка живости по Rust-ядру, пересборка fd | 2 |
| `onTaskRemoved`, `onDestroy`, `stopWithTask="false"` | 2 |
| Backoff 5 → 15 → 30 | 1 (расчёт), 2 (применение) |
| Обработка отказов: consent, `establish()`, FGS-запрет, канал уведомлений | 2 |
| Точный будильник, самоперевзвод | 3 |
| WorkManager 15 мин | 4 |
| `BootReceiver` (BOOT_COMPLETED, MY_PACKAGE_REPLACED), без direct-boot | 4 |
| `KeepAliveHelper` + вендорские экраны | 5 |
| Экран чеклиста, 5 пунктов, `enum Screen` (LIST/SPLIT/EXTERNAL/KEEP_ALIVE) | 6 |
| Runtime-запрос POST_NOTIFICATIONS | 6 |
| Проверка на устройстве, `FGS_BOOT_COMPLETED_RESTRICTIONS` | 7 |
| Документация EN + RU | 7 |

**Не-цели спеки соблюдены:** direct-boot нет (BootReceiver без
`directBootAware`), wake lock не переносится, тип FGS остаётся `specialUse`.

**Согласованность имён:** `ensure()` — везде `OutlineVpnService.ensure`;
`WatchdogAlarm.schedule(context, delayMs)` — один и тот же профиль вызова в
задачах 2, 3, 4; `KeepAliveState.shouldRun` — единственное имя намерения;
`KeepAlivePolicy.BASE_DELAY_MS` используется как дефолт `WatchdogAlarm.schedule`.

**Известная зависимость между задачами:** задача 2 ссылается на `WatchdogAlarm` из
задачи 3, поэтому компилируется и коммитится вместе с ней. Это отмечено в шагах 8-9
задачи 2.
