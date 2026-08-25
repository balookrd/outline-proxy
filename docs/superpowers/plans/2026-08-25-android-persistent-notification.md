# Постоянная шторка с кнопкой вкл/выкл (Android) — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Дать пользователю opt-in режим постоянного уведомления туннеля, которое держится даже при выключенном VPN и несёт одну кнопку-переключатель Connect/Disconnect по статусу.

**Architecture:** Foreground-сервис `OutlineVpnService` получает второе состояние — **standby**: при отключении в persistent-режиме туннель гасится, но сервис остаётся foreground со статичным «Disconnected»-уведомлением и кнопкой Connect. Кнопка на шторке — одна, её действие выбирается по живому состоянию ядра (Disconnect → сразу в сервис; Connect → в невидимую `QuickConnectActivity`, которая делает VPN-consent). Тумблер режима живёт в экране Keeping Alive и хранится в `KeepAliveState`.

**Tech Stack:** Kotlin, Jetpack Compose (Material3), Android foreground `VpnService`, JUnit4 (JVM unit-тесты).

## Global Constraints

- **JDK для сборки/тестов Android:** `JAVA_HOME=/Users/mvmalykh/Library/Java/JavaVirtualMachines/liberica-17.0.20` (openjdk 25 ломает Gradle). Все gradle-команды — из каталога `android/`.
- **Юнит-тесты идут на JVM** через `:app:testDebugUnitTest` и не требуют нативной `.so`; компиляция Kotlin — `:app:compileDebugKotlin` (тоже без `.so`).
- **UI-строки — на английском** (весь UI приложения английский: «Split Tunneling», «Disconnect» и т.п.). Диалог/рассуждения — по-русски.
- **Тумблер режима — opt-in, дефолт `false`.** Поведение при выключенном режиме обязано остаться **побайтово прежним**.
- **НЕ трогать** `BootReceiver`, `WatchdogWorker`, `WatchdogAlarm`, `KeepAlivePolicy`, `ensureTunnel` и логику `ensure()` — охват «пока жив сервис» (после ребута с выключенным VPN шторки нет до открытия приложения) держится именно на том, что эти пути остаются как есть.
- **Новых permissions и смены `foregroundServiceType` не вводить** — `FOREGROUND_SERVICE`/`POST_NOTIFICATIONS` уже в манифесте.
- **Работаем прямо в `main`, без feature-веток** (правило владельца). Коммиты в шагах показывают точки фиксации; **фактический `git commit` — только по явной команде владельца**. При исполнении: staging + показать diff, ждать «ок».
- Все затрагиваемые Kotlin-файлы — в пакете `com.outline.proxy` (новые классы импортов между собой не требуют).

---

### Task 1: Чистая логика кнопки-переключателя

Выносим единственное нетривиальное решение уведомления — «какое действие несёт кнопка по состоянию ядра» — в Android-независимую функцию, покрытую JVM-тестом (образец — `KeepAlivePolicy`). `OutlineVpnService` будет её потреблять в Task 4.

**Files:**
- Create: `android/app/src/main/java/com/outline/proxy/NotificationPolicy.kt`
- Test: `android/app/src/test/java/com/outline/proxy/NotificationPolicyTest.kt`

**Interfaces:**
- Produces: `enum class NotifToggle { CONNECT, DISCONNECT }`; `object NotificationPolicy { fun toggle(running: Boolean): NotifToggle }`

- [ ] **Step 1: Написать падающий тест**

Создать `android/app/src/test/java/com/outline/proxy/NotificationPolicyTest.kt`:

```kotlin
package com.outline.proxy

import org.junit.Assert.assertEquals
import org.junit.Test

/** Which action the ongoing notification's single toggle carries, per tunnel state. */
class NotificationPolicyTest {

    @Test
    fun `running tunnel offers disconnect`() {
        assertEquals(NotifToggle.DISCONNECT, NotificationPolicy.toggle(running = true))
    }

    @Test
    fun `down tunnel offers connect`() {
        assertEquals(NotifToggle.CONNECT, NotificationPolicy.toggle(running = false))
    }
}
```

- [ ] **Step 2: Прогнать тест — убедиться, что не компилируется/падает**

Run:
```bash
cd android && JAVA_HOME=/Users/mvmalykh/Library/Java/JavaVirtualMachines/liberica-17.0.20 \
  ./gradlew :app:testDebugUnitTest --tests "com.outline.proxy.NotificationPolicyTest"
```
Expected: FAIL — `unresolved reference: NotifToggle` / `NotificationPolicy` (символов ещё нет).

- [ ] **Step 3: Минимальная реализация**

Создать `android/app/src/main/java/com/outline/proxy/NotificationPolicy.kt`:

```kotlin
package com.outline.proxy

/** The single status-aware action the ongoing tunnel notification carries. */
enum class NotifToggle { CONNECT, DISCONNECT }

/**
 * Pure decisions for the ongoing tunnel notification, kept free of Android APIs
 * so they can be unit-tested on the JVM (mirrors [KeepAlivePolicy]).
 */
object NotificationPolicy {

    /**
     * Which toggle the notification shows: DISCONNECT while the core is up,
     * CONNECT while it is down (standby). Derived from live tunnel state — the
     * persistent-notification setting only decides whether the notification
     * exists at all, not what its button does.
     */
    fun toggle(running: Boolean): NotifToggle =
        if (running) NotifToggle.DISCONNECT else NotifToggle.CONNECT
}
```

- [ ] **Step 4: Прогнать тест — зелёный**

Run:
```bash
cd android && JAVA_HOME=/Users/mvmalykh/Library/Java/JavaVirtualMachines/liberica-17.0.20 \
  ./gradlew :app:testDebugUnitTest --tests "com.outline.proxy.NotificationPolicyTest"
```
Expected: PASS (2 теста).

- [ ] **Step 5: Commit** (фактический commit — по команде владельца)

```bash
git add android/app/src/main/java/com/outline/proxy/NotificationPolicy.kt \
        android/app/src/test/java/com/outline/proxy/NotificationPolicyTest.kt
git commit -m "feat(android): pure toggle policy for the ongoing notification"
```

---

### Task 2: Флаг `persistentNotification` в `KeepAliveState`

Хранилище флага. `KeepAliveState` завязан на Android `SharedPreferences`, JVM-юнит-тестом не покрывается (как и остальные его поля) — верификация здесь компиляцией; потребят Task 4 и Task 5.

**Files:**
- Modify: `android/app/src/main/java/com/outline/proxy/KeepAliveState.kt`

**Interfaces:**
- Produces: `var KeepAliveState.persistentNotification: Boolean` (дефолт `false`)

- [ ] **Step 1: Добавить свойство**

В `KeepAliveState.kt` после блока `alwaysOnSeen` (перед `fun recordFailure()`) вставить:

```kotlin
    /**
     * The user wants a persistent status-bar notification with a
     * Connect/Disconnect toggle, kept even while the tunnel is down. Opt-in;
     * default off. Read by [OutlineVpnService] to decide whether a disconnect
     * drops into standby or stops the service, and by the Keeping Alive screen.
     */
    var persistentNotification: Boolean
        get() = prefs.getBoolean(KEY_PERSISTENT_NOTIFICATION, false)
        set(value) = prefs.edit().putBoolean(KEY_PERSISTENT_NOTIFICATION, value).apply()
```

В `private companion object` добавить ключ рядом с остальными:

```kotlin
        const val KEY_PERSISTENT_NOTIFICATION = "persistent_notification"
```

- [ ] **Step 2: Проверить компиляцию**

Run:
```bash
cd android && JAVA_HOME=/Users/mvmalykh/Library/Java/JavaVirtualMachines/liberica-17.0.20 \
  ./gradlew :app:compileDebugKotlin
```
Expected: BUILD SUCCESSFUL.

- [ ] **Step 3: Commit** (по команде владельца)

```bash
git add android/app/src/main/java/com/outline/proxy/KeepAliveState.kt
git commit -m "feat(android): persist the persistent-notification preference"
```

---

### Task 3: `QuickConnectActivity` + регистрация в манифесте

Невидимая first-party активити — цель кнопки **Connect** на шторке. `exported="false"`, поэтому обхода external-control-токена не возникает (внешние вызовы по-прежнему идут только через гейтованный `outline://` в `ControlActivity`). Повторяет connect-путь `ControlActivity` для выбранного профиля.

**Files:**
- Create: `android/app/src/main/java/com/outline/proxy/QuickConnectActivity.kt`
- Modify: `android/app/src/main/AndroidManifest.xml`

**Interfaces:**
- Consumes: `resolveProfile(...)` (ExternalControl.kt), `ProfileStore`, `SubscriptionRefresh.configForConnect`, `OutlineVpnService.isActive/requestConnect`
- Produces: активити-класс `com.outline.proxy.QuickConnectActivity` (цель `PendingIntent.getActivity` из Task 4)

- [ ] **Step 1: Создать активити**

Создать `android/app/src/main/java/com/outline/proxy/QuickConnectActivity.kt`:

```kotlin
package com.outline.proxy

import android.app.Activity
import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.result.contract.ActivityResultContracts
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * The persistent notification's Connect action target. Invisible (translucent
 * theme) and `exported="false"`, so only our own notification can drive it —
 * unlike [ControlActivity] it is not gated by the external-control switch/token,
 * because it is a first-party surface rather than an outside caller.
 *
 * Mirrors [ControlActivity]'s connect path: resolve the UI-selected profile,
 * refresh an expired subscription, obtain VPN consent when it is missing, and
 * hand the config to [OutlineVpnService]. A tunnel that is already up (a race
 * with a stale notification) is left alone.
 */
class QuickConnectActivity : ComponentActivity() {

    /** Config waiting for the VPN consent dialog to come back. */
    private var pendingConfig: String? = null

    private val vpnConsentLauncher =
        registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
            val config = pendingConfig
            pendingConfig = null
            if (result.resultCode == Activity.RESULT_OK && config != null) {
                OutlineVpnService.requestConnect(this, config)
            } else {
                Toast.makeText(this, "VPN permission denied", Toast.LENGTH_SHORT).show()
            }
            finish()
        }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // The notification only shows Connect while the core is down; if it is
        // up (a stale banner, or a race), there is nothing to do.
        if (OutlineVpnService.isActive()) {
            finish()
            return
        }

        val store = ProfileStore(this)
        val profile = resolveProfile(store.load(), null, store.selectedId)
        if (profile == null) {
            Toast.makeText(this, "No server configured", Toast.LENGTH_SHORT).show()
            finish()
            return
        }
        // Keep the UI's selection in step with what is being connected.
        store.selectedId = profile.id

        // Refresh an expired subscription before dialling; finish() moves into
        // the coroutine so the activity outlives the fetch.
        lifecycleScope.launch {
            val configToml = withContext(Dispatchers.IO) {
                SubscriptionRefresh.configForConnect(this@QuickConnectActivity, profile)
            }
            if (configToml.isBlank()) {
                Toast.makeText(
                    this@QuickConnectActivity,
                    "No config yet — refresh the subscription first.",
                    Toast.LENGTH_LONG,
                ).show()
                finish()
                return@launch
            }
            val consent = VpnService.prepare(this@QuickConnectActivity)
            if (consent == null) {
                OutlineVpnService.requestConnect(this@QuickConnectActivity, configToml)
                finish()
            } else {
                // finish() is deferred to the consent callback.
                pendingConfig = configToml
                vpnConsentLauncher.launch(consent)
            }
        }
    }
}
```

- [ ] **Step 2: Зарегистрировать в манифесте**

В `android/app/src/main/AndroidManifest.xml`, сразу после закрывающего `</activity>` блока `ControlActivity` (перед объявлением `<service …OutlineVpnService…>`), вставить:

```xml
        <!-- The persistent notification's Connect action. Invisible (translucent)
             and exported="false" so only our own notification drives it; external
             callers still go through the gated outline:// ControlActivity. No
             intent-filter, kept out of recents. -->
        <activity
            android:name=".QuickConnectActivity"
            android:exported="false"
            android:excludeFromRecents="true"
            android:taskAffinity=""
            android:theme="@android:style/Theme.Translucent.NoTitleBar" />
```

- [ ] **Step 3: Проверить компиляцию**

Run:
```bash
cd android && JAVA_HOME=/Users/mvmalykh/Library/Java/JavaVirtualMachines/liberica-17.0.20 \
  ./gradlew :app:compileDebugKotlin
```
Expected: BUILD SUCCESSFUL.

- [ ] **Step 4: Commit** (по команде владельца)

```bash
git add android/app/src/main/java/com/outline/proxy/QuickConnectActivity.kt \
        android/app/src/main/AndroidManifest.xml
git commit -m "feat(android): invisible QuickConnectActivity for the notification's Connect action"
```

---

### Task 4: `OutlineVpnService` — standby-состояние и переключатель на шторке

Ядро задачи. Разбить `disconnect()` на teardown+решение; добавить `ACTION_STANDBY`/`ACTION_STOP_STANDBY` и companion-хелперы; научить `buildNotification`/`currentNotification` состоянию «Disconnected» и выбору кнопки через `NotificationPolicy`.

**Files:**
- Modify: `android/app/src/main/java/com/outline/proxy/OutlineVpnService.kt`

**Interfaces:**
- Consumes: `NotificationPolicy.toggle` / `NotifToggle` (Task 1); `KeepAliveState.persistentNotification` (Task 2); `QuickConnectActivity` (Task 3)
- Produces: `OutlineVpnService.ACTION_STANDBY`, `ACTION_STOP_STANDBY`; `OutlineVpnService.enterStandby(Context)`, `OutlineVpnService.exitStandby(Context)`

- [ ] **Step 1: Добавить action-константы**

В `companion object` рядом с `ACTION_ENSURE` добавить:

```kotlin
        const val ACTION_STANDBY = "com.outline.proxy.STANDBY"
        const val ACTION_STOP_STANDBY = "com.outline.proxy.STOP_STANDBY"
```

- [ ] **Step 2: Добавить companion-хелперы**

В `companion object`, после `fun ensure(context: Context) { … }`, добавить:

```kotlin
        /**
         * Show the ongoing notification in standby (tunnel down) — used when the
         * persistent-notification setting is on and the tunnel is not running.
         * Called only from the visible settings screen, so a plain `startService`
         * is a legal foreground start.
         */
        fun enterStandby(context: Context) {
            runCatching {
                context.startService(
                    Intent(context, OutlineVpnService::class.java).apply { action = ACTION_STANDBY },
                )
            }.onFailure { Log.w(TAG, "cannot start standby", it) }
        }

        /**
         * Drop a standby notification: stop the service when the tunnel is down.
         * A running tunnel is left untouched — its own notification stays, and
         * the (now-off) setting simply lets the next disconnect stop the service.
         */
        fun exitStandby(context: Context) {
            if (isActive()) return
            runCatching {
                context.startService(
                    Intent(context, OutlineVpnService::class.java).apply { action = ACTION_STOP_STANDBY },
                )
            }.onFailure { Log.w(TAG, "cannot stop standby", it) }
        }
```

- [ ] **Step 3: Обработать новые actions в `onStartCommand`**

В `onStartCommand`, в блоке `when (intent?.action)`, добавить две ветки перед `ACTION_ENSURE, null ->`:

```kotlin
            ACTION_STANDBY -> {
                // Persistent-notification mode wants the banner up even with the
                // tunnel down. Post it and stay foreground; do not touch the
                // tunnel. NOT_STICKY for standby: a killed standby returns when
                // the app is next opened, not via a sticky restart (the chosen
                // scope). If the tunnel is somehow already up (a race), keep it
                // sticky so we do not weaken a running tunnel's keep-alive.
                startForeground(NOTIFICATION_ID, currentNotification())
                return if (isRunning()) START_STICKY else START_NOT_STICKY
            }
            ACTION_STOP_STANDBY -> {
                if (!isRunning()) {
                    stopForeground(STOP_FOREGROUND_REMOVE)
                    stopSelf()
                }
                return START_NOT_STICKY
            }
```

- [ ] **Step 4: Разбить `disconnect()` на teardown + решение**

Заменить целиком метод `disconnect()` (текущие строки ~569–582) на:

```kotlin
    /**
     * Tear the tunnel down — core, TUN, network callbacks, notification updates —
     * without deciding the service's fate. Shared by the deliberate-disconnect
     * path and by [onDestroy].
     */
    private fun teardownTunnel() {
        stopNotificationUpdates()
        KeepAliveState(this).connectedSince = 0L
        unregisterNetworkCallback()
        try {
            if (isRunning()) stop()
        } catch (e: Exception) {
            Log.e(TAG, "error stopping client", e)
        }
        tunInterface?.close()
        tunInterface = null
    }

    /**
     * A user-driven disconnect. Tears the tunnel down, then either drops into
     * standby (persistent-notification on: keep the ongoing banner with a Connect
     * button) or stops the service outright (the default, unchanged behaviour).
     */
    private fun disconnect() {
        teardownTunnel()
        if (KeepAliveState(this).persistentNotification) {
            startForeground(NOTIFICATION_ID, buildNotification(running = false, status = "Disconnected"))
        } else {
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
        }
    }
```

- [ ] **Step 5: `onDestroy` рвёт туннель без standby**

В `onDestroy()` заменить вызов `disconnect()` на `teardownTunnel()` (сервис уже уничтожается — ни standby, ни stopSelf не нужны):

```kotlin
    override fun onDestroy() {
        // A deliberate disconnect clears shouldRun first, so this only fires
        // when something else killed us.
        if (KeepAliveState(this).shouldRun) {
            WatchdogAlarm.schedule(this, DESTROY_DELAY_MS)
        }
        teardownTunnel()
        super.onDestroy()
    }
```

- [ ] **Step 6: `buildNotification` — кнопка по состоянию**

Заменить целиком метод `buildNotification(...)` (текущие строки ~606–655) на версию с параметром `running` и одной status-aware кнопкой:

```kotlin
    private fun buildNotification(
        running: Boolean = true,
        status: String = "Connecting…",
        detail: String? = null,
    ): Notification {
        val manager = getSystemService(NotificationManager::class.java)
        val channel = NotificationChannel(
            NOTIFICATION_CHANNEL_ID,
            "VPN status",
            NotificationManager.IMPORTANCE_LOW,
        )
        manager.createNotificationChannel(channel)

        val openApp = PendingIntent.getActivity(
            this,
            0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE,
        )

        // One status-aware toggle: Disconnect while the tunnel is up (straight to
        // the service, instant), Connect while it is down (an activity, because
        // showing VPN consent needs one — QuickConnectActivity, first-party and
        // exported=false).
        val (actionLabel, actionIcon, actionIntent) = when (NotificationPolicy.toggle(running)) {
            NotifToggle.DISCONNECT -> Triple(
                "Disconnect",
                android.R.drawable.ic_menu_close_clear_cancel,
                PendingIntent.getService(
                    this,
                    1,
                    Intent(this, OutlineVpnService::class.java).apply { action = ACTION_DISCONNECT },
                    PendingIntent.FLAG_IMMUTABLE,
                ),
            )
            NotifToggle.CONNECT -> Triple(
                "Connect",
                android.R.drawable.ic_media_play,
                PendingIntent.getActivity(
                    this,
                    2,
                    Intent(this, QuickConnectActivity::class.java),
                    PendingIntent.FLAG_IMMUTABLE,
                ),
            )
        }

        // Name the active profile in the banner so the user can tell at a glance
        // which server the tunnel is on. The title carries the live status, the
        // text the bytes moved this session (or a hint in standby).
        val store = ProfileStore(this)
        val name = store.load().firstOrNull { it.id == store.selectedId }?.name?.takeIf { it.isNotBlank() }
        val title = if (name != null) "$status · $name" else status

        return Notification.Builder(this, NOTIFICATION_CHANNEL_ID)
            .setContentTitle(title)
            .setContentText(detail ?: "Outline Proxy")
            .setSmallIcon(R.drawable.ic_stat_tunnel)
            // The cyan of the emblem's "wires"; the launcher tints the small-icon
            // circle with this instead of the OEM default accent.
            .setColor(0xFF40C4FF.toInt())
            .setContentIntent(openApp)
            .setOngoing(true)
            .addAction(
                Notification.Action.Builder(
                    Icon.createWithResource(this, actionIcon),
                    actionLabel,
                    actionIntent,
                ).build(),
            )
            .build()
    }
```

- [ ] **Step 7: `currentNotification` — ранний возврат для standby**

Заменить целиком метод `currentNotification()` (текущие строки ~701–725) на:

```kotlin
    /**
     * Build the notification for the tunnel's current state. While the core is
     * up: status mirroring the home screen (Connecting… / Connected / No link)
     * and the bytes moved this session. While it is down (standby): a static
     * "Disconnected" banner with a Connect action and no traffic line — the
     * session counters are meaningless with nothing running.
     */
    private fun currentNotification(): Notification {
        val running = runCatching { isRunning() }.getOrDefault(false)
        if (!running) {
            return buildNotification(running = false, status = "Disconnected", detail = null)
        }
        val status0 = runCatching { tunnelStatus() }.getOrNull()
        val hasLink = status0?.hasLiveLink ?: false
        // Same qualifier the home screen applies: an edge-class link is up and
        // unusable at once, and the banner is where the user looks first.
        val latencyMs = LinkQuality.worstOf(
            status0?.tcpLatencyMs?.toInt(),
            status0?.udpLatencyMs?.toInt(),
        )
        // The core health flag is instantaneous and can blip false for a tick;
        // keep "Connecting…" until the link has been absent past the grace window.
        if (hasLink) lastLinkAtMs = System.currentTimeMillis()
        val connecting = !hasLink &&
            System.currentTimeMillis() - lastLinkAtMs < NO_LINK_GRACE_MS
        val status = when {
            hasLink -> LinkQuality.connectedLabel(latencyMs)
            connecting -> "Connecting…"
            else -> "No link"
        }
        val up = (TrafficStats.getTotalTxBytes() - trafficBaseTx).coerceAtLeast(0)
        val down = (TrafficStats.getTotalRxBytes() - trafficBaseRx).coerceAtLeast(0)
        return buildNotification(
            running = true,
            status = status,
            detail = "↑ ${formatBytes(up)}   ↓ ${formatBytes(down)}",
        )
    }
```

- [ ] **Step 8: Проверить компиляцию**

Run:
```bash
cd android && JAVA_HOME=/Users/mvmalykh/Library/Java/JavaVirtualMachines/liberica-17.0.20 \
  ./gradlew :app:compileDebugKotlin
```
Expected: BUILD SUCCESSFUL.

- [ ] **Step 9: Прогнать все юнит-тесты (регрессия)**

Run:
```bash
cd android && JAVA_HOME=/Users/mvmalykh/Library/Java/JavaVirtualMachines/liberica-17.0.20 \
  ./gradlew :app:testDebugUnitTest
```
Expected: PASS (включая `NotificationPolicyTest` и прежние).

- [ ] **Step 10: Commit** (по команде владельца)

```bash
git add android/app/src/main/java/com/outline/proxy/OutlineVpnService.kt
git commit -m "feat(android): standby notification with a status-aware connect/disconnect toggle"
```

---

### Task 5: Тумблер «Persistent notification» в экране Keeping Alive

Пользовательская точка включения режима. Карточка с `Switch` сверху экрана (визуально отдельно от чеклиста грантов). При переключении на выключенном туннеле немедленно поднимает/снимает шторку через companion-хелперы Task 4.

**Files:**
- Modify: `android/app/src/main/java/com/outline/proxy/KeepAliveScreen.kt`

**Interfaces:**
- Consumes: `KeepAliveState.persistentNotification` (Task 2); `OutlineVpnService.isActive/enterStandby/exitStandby` (Task 4); `SectionCard`, `StatusGreen` (UiKit)

- [ ] **Step 1: Добавить импорты**

В `KeepAliveScreen.kt` в блок импортов добавить (рядом с уже имеющимися compose-импортами):

```kotlin
import androidx.compose.material3.Switch
import androidx.compose.runtime.mutableStateOf
```

- [ ] **Step 2: Локальное состояние тумблера**

В теле `KeepAliveScreen`, сразу после строки `var refresh by remember { mutableIntStateOf(0) }`, добавить:

```kotlin
    val keepAlive = remember { KeepAliveState(context) }
    var persistent by remember { mutableStateOf(keepAlive.persistentNotification) }
```

- [ ] **Step 3: Карточка-тумблер над чеклистом**

Внутри `Column(modifier = Modifier.verticalScroll(rememberScrollState())) { … }`, **первым** элементом (перед вводным `Text("Android and the phone vendor …")`), вставить:

```kotlin
            SectionCard(modifier = Modifier.padding(bottom = 16.dp)) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            "Persistent notification",
                            style = MaterialTheme.typography.titleMedium,
                            fontWeight = FontWeight.SemiBold,
                        )
                        Text(
                            "Keep a notification with a Connect/Disconnect button in the " +
                                "status bar, even when the VPN is off.",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            modifier = Modifier.padding(top = 4.dp),
                        )
                    }
                    Switch(
                        checked = persistent,
                        onCheckedChange = { on ->
                            persistent = on
                            keepAlive.persistentNotification = on
                            // Reflect it immediately while the tunnel is down: turning
                            // it on posts the standby banner, off removes it. A running
                            // tunnel already shows its banner and is left untouched.
                            if (!OutlineVpnService.isActive()) {
                                if (on) OutlineVpnService.enterStandby(context)
                                else OutlineVpnService.exitStandby(context)
                            }
                        },
                    )
                }
            }
```

- [ ] **Step 4: Проверить компиляцию**

Run:
```bash
cd android && JAVA_HOME=/Users/mvmalykh/Library/Java/JavaVirtualMachines/liberica-17.0.20 \
  ./gradlew :app:compileDebugKotlin
```
Expected: BUILD SUCCESSFUL.

- [ ] **Step 5: Commit** (по команде владельца)

```bash
git add android/app/src/main/java/com/outline/proxy/KeepAliveScreen.kt
git commit -m "feat(android): persistent-notification toggle in the Keeping Alive screen"
```

---

### Task 6: Ручная проверка на эмуляторе

Lifecycle/UI за пределами JVM-тестов. Собрать APK и проверить сценарии на эмуляторе (Pixel, как в прежних android-задачах). `.so` для полной сборки уже собрана в дереве; если нет — сборка Rust-`.so` выходит за рамки этой задачи (см. android/README).

**Files:** —

- [ ] **Step 1: Собрать debug-APK**

Run:
```bash
cd android && JAVA_HOME=/Users/mvmalykh/Library/Java/JavaVirtualMachines/liberica-17.0.20 \
  ./gradlew :app:assembleDebug
```
Expected: BUILD SUCCESSFUL; APK в `app/build/outputs/apk/debug/`.

- [ ] **Step 2: Установить и прогнать сценарии**

Установить на запущенный эмулятор (`adb install -r app/build/outputs/apk/debug/app-debug.apk`) и проверить:

1. **Режим выключен (регрессия):** подключиться → в шторке статус/трафик и кнопка **Disconnect**; отключиться → **шторка исчезает**. Поведение как прежде.
2. **Включение при выключенном VPN:** Keeping Alive → включить **Persistent notification** → в шторке немедленно появляется «Disconnected · \<профиль\>» с кнопкой **Connect**.
3. **Connect со шторки:** тап **Connect** → (при первом разе — системный VPN-consent) → туннель поднимается, кнопка становится **Disconnect**, появляется трафик.
4. **Disconnect со шторки:** тап **Disconnect** → туннель гаснет, но шторка **остаётся** в «Disconnected» с кнопкой **Connect**.
5. **Выключение режима:** выключить тумблер при опущенном туннеле → **шторка исчезает**. Выключить при поднятом → шторка активного туннеля остаётся, а следующий Disconnect её убирает.
6. **Свайп шторки:** ongoing-уведомление не свайпается (ожидаемо).

- [ ] **Step 3: Commit** (если правок кода не потребовалось — коммита нет; иначе — по команде владельца, отдельным фиксом с описанием найденного)

---

## Notes

- **«Кроме того что есть сейчас».** Всё содержимое уведомления сохранено (статус, профиль, трафик, ongoing, цвет, иконка, tap→приложение); одиночная кнопка «Disconnect» обобщена в status-aware toggle — при поднятом туннеле это по-прежнему «Disconnect».
- **Нет разрешения на уведомления (Android 13+).** Foreground-сервис standby живёт, но система прячет шторку; чеклист Keeping Alive это уже подсвечивает — отдельной обработки не добавляем (см. Не-цели спеки).
- **Регрессионный якорь:** при `persistentNotification == false` пути `disconnect()` (→ stopForeground+stopSelf) и `buildNotification()` (running=true по умолчанию → «Disconnect») дают прежнее поведение бит-в-бит.
```

---

## Дополнение (реализовано после первичного плана, по ходу задачи)

### Отклонения / уточнения от Tasks 1–6

- **Task 4 — строка контента.** Вместо `detail ?: "Outline Proxy"` вторая строка
  теперь `detail ?: <тип сервера>`: трафик при подключении, `transport` /
  «Subscription» в standby/connecting. Пустой контент оставлял зазор над кнопкой;
  филлер «Outline Proxy» дублировал имя приложения из шапки. `buildNotification`
  грузит профиль целиком и берёт `isSubscription`/`transport`.
- **MainActivity — standby при открытии приложения (закрытие пробела спеки).** В
  `onCreate`, после `store = ProfileStore(this)`:
  ```kotlin
  if (KeepAliveState(this).persistentNotification && !OutlineVpnService.isActive()) {
      OutlineVpnService.enterStandby(this)
  }
  ```
  Без этого клауза «шторка появляется после открытия приложения» не выполнялась.

### Task 7: Плитка Quick Settings

**Files:**
- Create: `android/app/src/main/java/com/outline/proxy/OutlineTileService.kt`
- Modify: `android/app/src/main/AndroidManifest.xml`

**Interfaces:**
- Consumes: `NotificationPolicy.toggle`/`NotifToggle` (Task 1),
  `OutlineVpnService.isActive/requestDisconnect` (Task 4), `QuickConnectActivity`
  (Task 3), `ProfileStore`
- Produces: `com.outline.proxy.OutlineTileService`

- [ ] **Step 1: `OutlineTileService`** — `TileService`, где `onStartListening`/
  после клика красит плитку (`Tile.STATE_ACTIVE`/`STATE_INACTIVE` + subtitle с
  именем сервера на API 29+), а `onClick` делает toggle:
  DISCONNECT → `OutlineVpnService.requestDisconnect(this)` + оптимистично
  `renderTile(running = false)`; CONNECT → `startActivityAndCollapse` на
  `QuickConnectActivity` (ветка API 34: `PendingIntent`-перегрузка выше 34,
  `@Suppress("DEPRECATION")` `Intent`-перегрузка ниже).

- [ ] **Step 2: Манифест** — `<service android:name=".OutlineTileService"
  android:exported="true" android:icon="@drawable/ic_stat_tunnel"
  android:label="Outline"
  android:permission="android.permission.BIND_QUICK_SETTINGS_TILE">` +
  intent-filter `android.service.quicksettings.action.QS_TILE`.

- [ ] **Step 3: Проверка** — `:app:assembleDebug`; на эмуляторе
  `adb shell cmd statusbar add-tile com.outline.proxy/.OutlineTileService`,
  открыть QS, тап → `QuickConnectActivity` → connect; активное состояние — с
  живым сервером.

### Task 8: Промпт добавления плитки (Android 13+)

**Files:**
- Modify: `android/app/src/main/java/com/outline/proxy/KeepAliveScreen.kt`

- [ ] **Step 1: Карточка «Quick Settings tile»** с кнопкой `OutlinedButton`
  «Add tile» → `requestAddQsTile(context)` (после карточки Persistent notification).

- [ ] **Step 2: Хелпер** — на `Build.VERSION_CODES.TIRAMISU`+:
  `getSystemService(StatusBarManager::class.java).requestAddTileService(
  ComponentName(context, OutlineTileService::class.java), "Outline",
  Icon.createWithResource(context, R.drawable.ic_stat_tunnel),
  context.mainExecutor) {}`; ниже — `Toast` с подсказкой открыть редактор QS.

- [ ] **Step 3: Проверка** — `:app:assembleDebug` + `:app:testDebugUnitTest`;
  на эмуляторе тап «Add tile» → системный диалог «Add tile to Quick Settings».
