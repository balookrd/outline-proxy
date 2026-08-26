# Android: честные статусы keep-alive, вендорские экраны и иконки приложений — план

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Экран «Поддержание связи» перестаёт показывать устаревшие статусы и объясняет вендорские слои (автозапуск и политика батареи) с точными названиями пунктов; список раздельного туннеля показывает иконки приложений.

**Architecture:** Знания о вендорских прошивках собираются в одну таблицу профилей (`VendorProfiles.kt`) — чистый Kotlin без Android-классов, поэтому сопоставление `Build.MANUFACTURER` → профиль юнит-тестируется без устройства. `KeepAliveHelper` превращается в тонкий слой, строящий `Intent` из профиля с фолбэком на системную карточку приложения. Иконки живут в отдельном модуле `AppIcons.kt` (LRU-кэш + composable-хелпер), `AppInfo` не меняется.

**Tech Stack:** Kotlin, Jetpack Compose (Material 3), Android resources, JUnit (чистый JVM), Gradle.

## Global Constraints

- **SDK/стек:** `minSdk 24`, `targetSdk 36`, `compileSdk 37`; чистый Compose, без `appcompat`. `buildConfig = true` уже включён — `BuildConfig.DEBUG` доступен.
- **Строки — только через ресурсы, оба языка сразу.** В `android/app/build.gradle.kts` включён fatal-гейт `MissingTranslation` / `ExtraTranslation`: ключ, добавленный в один файл и забытый в другом, роняет сборку.
- **НЕ переводить:** бренд (`Outline`, `Outline Proxy`), имена вендорских пакетов и Activity, названия прошивок (`MIUI`, `HyperOS`, `One UI`). Названия пунктов вендорского UI — это **цитаты того, что пользователь видит на своём языке**: в EN берём английский лейбл, в RU — русский, а не перевод английского.
- **Русский — по правилам `ru-text`** (типографика, короткие формулировки). Глоссарий прошлой локализации: Allow→Разрешить, Back→Назад, Keeping Alive→Поддержание связи, Search apps→Поиск приложений, Clear→Очистить.
- **Тесты:** `android/app/src/test/java/com/outline/proxy/…`, пакет зеркалит исходник. `unitTests.isReturnDefaultValues = true` — застабленные вызовы `android.jar` возвращают дефолты, поэтому тестируемая логика **не должна** трогать Android-классы.
- **Вендорские экраны непроверяемы.** Живых устройств нет. Каждый запуск обёрнут в `launchSafely`, у каждого вендора есть фолбэк на системную карточку приложения — кнопка не может «сломаться».
- **Никаких hidden-API.** Ни reflection в `android.miui.*`, ни чтения состояния автозапуска: это поднимает флаги Play Protect.
- **Верификация каждой задачи:** `cd android && ./gradlew :app:testDebugUnitTest` (где есть тесты) и `./gradlew :app:assembleDebug`; строковые задачи дополнительно `./gradlew :app:lintDebug`. Сборка требует JDK 17: `export JAVA_HOME=~/Library/Java/JavaVirtualMachines/liberica-17.0.20`.
- **Коммиты:** шаги `git commit` — точки фиксации TDD-цикла. Фактический коммит выполнять **только по явному разрешению владельца** (правило репозитория). До разрешения — `git add` и показать `git diff --staged`.

## Уточнение к спеке

Спека предполагала, что вендорская карточка показывается только когда её Activity резолвится. В плане это ослаблено: **карточка показывается по `Build.MANUFACTURER`**, а резолвинг решает лишь, какой именно экран открыть — специфичный вендорский или системную карточку приложения (`ACTION_APPLICATION_DETAILS_SETTINGS`). Причина: на Xiaomi нужный тумблер «Автозапуск» живёт прямо в карточке приложения, поэтому подсказка полезна даже там, где `com.miui.securitycenter` не резолвится (кастомные прошивки). Побочная выгода — debug-оверрайду достаточно подменить имя вендора.

## Файловая структура

| Файл | Ответственность |
|---|---|
| `keepalive/VendorProfiles.kt` (создать) | Таблица вендорских профилей + сопоставление производителя. Чистый Kotlin. |
| `keepalive/KeepAliveHelper.kt` (изменить) | Построение `Intent` из профиля, фолбэки. Android-слой. |
| `keepalive/VendorOverride.kt` (создать) | Debug-only подмена производителя. |
| `KeepAliveScreen.kt` (изменить) | Перечитывание статусов, вендорские карточки. |
| `AppIcons.kt` (создать) | LRU-кэш иконок + composable-хелпер. |
| `MainActivity.kt` (изменить) | Иконка в строке списка приложений. |
| `res/values{,-ru}/strings.xml` (изменить) | Новые строки, оба языка. |
| `test/…/keepalive/VendorProfilesTest.kt` (создать) | Тесты сопоставления и состава профилей. |

---

### Task 1: Строки для вендорских карточек — EN и RU

**Files:**
- Modify: `android/app/src/main/res/values/strings.xml`
- Modify: `android/app/src/main/res/values-ru/strings.xml`

**Interfaces:**
- Produces: ключи `ka_vendor_autostart`, `ka_vendor_autostart_desc`, `ka_vendor_autostart_desc_huawei`, `ka_toggle_*`, `ka_vendor_battery`, `ka_vendor_battery_desc`, `ka_vendor_battery_desc_xiaomi`, `ka_vendor_battery_desc_samsung` — их потребляют Task 2 и Task 5.

- [ ] **Step 1: Заменить блок вендорских строк в `values/strings.xml`**

Найти существующие `ka_vendor_autostart` и `ka_vendor_autostart_desc` и заменить их на блок ниже (`ka_open_vendor_settings` уже есть — оставить как есть):

```xml
    <!-- Keep-Alive: vendor autostart card. The quoted names are what the user sees
         in the vendor's own UI, so they are localized to that UI's wording rather
         than translated literally. -->
    <string name="ka_vendor_autostart">%1$s autostart</string>
    <string name="ka_vendor_autostart_desc">%1$s keeps its own list of apps allowed to start in the background, separate from Android\'s. There is no API to read it — open the screen and turn on \"%2$s\" for Outline Proxy.</string>
    <string name="ka_vendor_autostart_desc_huawei">%1$s manages background apps itself. Open the screen, turn \"Manage automatically\" off for Outline Proxy, then turn on \"Auto-launch\", \"Secondary launch\" and \"Run in background\".</string>
    <string name="ka_toggle_autostart">Autostart</string>
    <string name="ka_toggle_allow_autostart">Allow auto-launch</string>
    <string name="ka_toggle_autostart_manager">Auto-start Manager</string>
    <string name="ka_toggle_run_in_background">Run in background</string>
    <string name="ka_toggle_autostart_management">Auto-start management</string>

    <!-- Keep-Alive: vendor battery-policy card, separate from Android's Doze list. -->
    <string name="ka_vendor_battery">%1$s battery policy</string>
    <string name="ka_vendor_battery_desc">%1$s applies its own per-app battery policy on top of Android\'s. Open it and give Outline Proxy the unrestricted option.</string>
    <string name="ka_vendor_battery_desc_xiaomi">Not the same as the Android setting above. Open \"Battery saver\" for Outline Proxy and choose \"No restrictions\". %1$s may also reset the Android setting on its own, so check that one again after a reboot.</string>
    <string name="ka_vendor_battery_desc_samsung">%1$s puts unused apps to sleep. Open \"Background usage limits\" and add Outline Proxy to \"Never sleeping apps\".</string>
```

- [ ] **Step 2: Заменить тот же блок в `values-ru/strings.xml`**

```xml
    <!-- Keep-Alive: карточка вендорского автозапуска. -->
    <string name="ka_vendor_autostart">Автозапуск: %1$s</string>
    <string name="ka_vendor_autostart_desc">%1$s ведёт собственный список приложений, которым разрешён запуск в фоне, — отдельно от Android. Прочитать его нельзя, поэтому откройте экран и включите «%2$s» для Outline Proxy.</string>
    <string name="ka_vendor_autostart_desc_huawei">%1$s управляет фоновыми приложениями сам. Откройте экран, выключите «Управлять автоматически» для Outline Proxy, затем включите «Автозапуск», «Косвенный запуск» и «Работа в фоновом режиме».</string>
    <string name="ka_toggle_autostart">Автозапуск</string>
    <string name="ka_toggle_allow_autostart">Разрешить автозапуск</string>
    <string name="ka_toggle_autostart_manager">Диспетчер автозапуска</string>
    <string name="ka_toggle_run_in_background">Работа в фоновом режиме</string>
    <string name="ka_toggle_autostart_management">Управление автозапуском</string>

    <!-- Keep-Alive: карточка вендорской политики батареи. -->
    <string name="ka_vendor_battery">Батарея: %1$s</string>
    <string name="ka_vendor_battery_desc">У %1$s поверх системной есть своя политика батареи для каждого приложения. Откройте её и снимите ограничения для Outline Proxy.</string>
    <string name="ka_vendor_battery_desc_xiaomi">Это не то же самое, что настройка Android выше. Откройте «Экономия заряда батареи» для Outline Proxy и выберите «Без ограничений» (в MIUI 12 пункт называется «Контроль активности» → «Нет ограничений»). %1$s может сам сбросить системную настройку, поэтому после перезагрузки проверяйте и её.</string>
    <string name="ka_vendor_battery_desc_samsung">%1$s усыпляет неиспользуемые приложения. Откройте «Ограничения в фоновом режиме» и добавьте Outline Proxy в «Никогда не переводить в спящий режим».</string>
```

- [ ] **Step 3: Проверить паритет и сборку**

Run: `cd android && ./gradlew :app:lintDebug :app:assembleDebug`
Expected: BUILD SUCCESSFUL, без `MissingTranslation` / `ExtraTranslation`.

- [ ] **Step 4: Зафиксировать** (по разрешению владельца)

```bash
git add android/app/src/main/res/values/strings.xml android/app/src/main/res/values-ru/strings.xml
git commit -m "feat(android): strings for vendor autostart and battery-policy cards"
```

---

### Task 2: Таблица вендорских профилей

**Files:**
- Create: `android/app/src/main/java/com/outline/proxy/keepalive/VendorProfiles.kt`
- Test: `android/app/src/test/java/com/outline/proxy/keepalive/VendorProfilesTest.kt`

**Interfaces:**
- Consumes: строковые ключи из Task 1.
- Produces:
  - `internal data class VendorScreen(val packageName: String, val className: String)`
  - `internal data class VendorProfile(id, manufacturers, autostart, battery, autostartTitle, autostartDesc, autostartToggle, batteryDesc)`
  - `internal enum class VendorId { XIAOMI, HUAWEI, HONOR, OPPO, REALME, VIVO, ONEPLUS, SAMSUNG, ASUS, MEIZU, TRANSSION }`
  - `internal fun vendorProfileFor(manufacturer: String?): VendorProfile?`

- [ ] **Step 1: Написать падающий тест** — `VendorProfilesTest.kt`:

```kotlin
package com.outline.proxy.keepalive

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class VendorProfilesTest {

    @Test fun xiaomiFamilyMapsToOneProfile() {
        assertEquals(VendorId.XIAOMI, vendorProfileFor("Xiaomi")?.id)
        assertEquals(VendorId.XIAOMI, vendorProfileFor("Redmi")?.id)
        assertEquals(VendorId.XIAOMI, vendorProfileFor("POCO")?.id)
    }

    @Test fun matchIsCaseInsensitive() {
        assertEquals(VendorId.XIAOMI, vendorProfileFor("XIAOMI")?.id)
        assertEquals(VendorId.HUAWEI, vendorProfileFor("HuaWei")?.id)
    }

    @Test fun honorIsNotHuawei() {
        assertEquals(VendorId.HONOR, vendorProfileFor("HONOR")?.id)
        assertEquals(VendorId.HONOR, vendorProfileFor("hihonor")?.id)
    }

    /** One UI has no autostart list at all — only its own battery policy. */
    @Test fun samsungHasBatteryOnlyNoAutostart() {
        val samsung = vendorProfileFor("samsung")
        assertEquals(VendorId.SAMSUNG, samsung?.id)
        assertTrue(samsung!!.autostart.isEmpty())
        assertTrue(samsung.battery.isNotEmpty())
    }

    /** Near-stock skins get no vendor card whatsoever. */
    @Test fun stockVendorsHaveNoProfile() {
        assertNull(vendorProfileFor("Google"))
        assertNull(vendorProfileFor("motorola"))
        assertNull(vendorProfileFor("Sony"))
        assertNull(vendorProfileFor("Nothing"))
        assertNull(vendorProfileFor(null))
        assertNull(vendorProfileFor(""))
    }

    @Test fun xiaomiCarriesBothScreens() {
        val xiaomi = vendorProfileFor("xiaomi")!!
        assertEquals("com.miui.securitycenter", xiaomi.autostart.first().packageName)
        assertEquals("com.miui.powerkeeper", xiaomi.battery.first().packageName)
    }

    /** Every profile must be able to render its cards: a non-empty autostart list
     *  needs a toggle name or its own description, and a battery list needs text. */
    @Test fun everyProfileCanRenderItsCards() {
        for (profile in VENDOR_PROFILES) {
            if (profile.autostart.isNotEmpty()) {
                assertTrue(
                    "profile ${profile.id} has autostart screens but no wording",
                    profile.autostartToggle != null || profile.autostartDesc != 0,
                )
            }
            if (profile.battery.isNotEmpty()) {
                assertTrue("profile ${profile.id} has battery screens but no wording", profile.batteryDesc != null)
            }
        }
    }

    @Test fun manufacturersAreLowercaseAndUnique() {
        val all = VENDOR_PROFILES.flatMap { it.manufacturers }
        assertEquals(all.map { it.lowercase() }, all)
        assertEquals(all.distinct().size, all.size)
    }
}
```

- [ ] **Step 2: Запустить — убедиться, что падает**

Run: `cd android && ./gradlew :app:testDebugUnitTest --tests "com.outline.proxy.keepalive.VendorProfilesTest"`
Expected: FAIL — `Unresolved reference: vendorProfileFor / VendorId / VENDOR_PROFILES`.

- [ ] **Step 3: Создать `VendorProfiles.kt`**

```kotlin
package com.outline.proxy.keepalive

import androidx.annotation.StringRes
import com.outline.proxy.R
import java.util.Locale

/**
 * Vendor skins that restrict background apps beyond what stock Android does.
 *
 * Two independent vendor layers exist on top of Android's Doze whitelist, and
 * neither is readable through any public API:
 *
 *  - an **autostart** list deciding whether the app may start in the background
 *    at all (on MIUI it is off by default for every app), and
 *  - a per-app **battery policy** that overrides Android's own.
 *
 * Granting Android's battery-optimisation exemption does not touch either, which
 * is why a device can report `isIgnoringBatteryOptimizations() == true` and still
 * kill the tunnel — and why MIUI is documented to reset that exemption on its own.
 */
internal enum class VendorId {
    XIAOMI, HUAWEI, HONOR, OPPO, REALME, VIVO, ONEPLUS, SAMSUNG, ASUS, MEIZU, TRANSSION
}

/**
 * A settings screen owned by the vendor. Kept as plain strings rather than a
 * `ComponentName` so this whole table stays free of Android classes and can be
 * unit-tested on the JVM.
 */
internal data class VendorScreen(val packageName: String, val className: String)

/**
 * What one vendor skin needs. [autostart] and [battery] are candidate screens,
 * most specific first; both may be empty when the skin has no such layer.
 */
internal data class VendorProfile(
    val id: VendorId,
    /** Lowercased `Build.MANUFACTURER` values that map to this skin. */
    val manufacturers: List<String>,
    val autostart: List<VendorScreen>,
    val battery: List<VendorScreen>,
    /** Title of the autostart card; takes the vendor name as `%1$s`. */
    @StringRes val autostartTitle: Int,
    /** Body of the autostart card; takes the vendor name as `%1$s` and, when
     *  [autostartToggle] is set, the switch name as `%2$s`. */
    @StringRes val autostartDesc: Int,
    /** The switch the user must turn on. Null for skins whose description spells
     *  out a multi-step sequence instead of naming one switch. */
    @StringRes val autostartToggle: Int?,
    /** Body of the battery card; takes the vendor name as `%1$s`. */
    @StringRes val batteryDesc: Int?,
)

/** The profile for this device's manufacturer, or null on near-stock skins. */
internal fun vendorProfileFor(manufacturer: String?): VendorProfile? {
    val key = manufacturer?.lowercase(Locale.US)?.trim().orEmpty()
    if (key.isEmpty()) return null
    return VENDOR_PROFILES.firstOrNull { key in it.manufacturers }
}

/**
 * Known vendor skins. Components come and go between firmware versions, so they
 * are only ever *candidates*: the caller probes each one and falls back to the
 * system app-details page, where these toggles also live on most skins.
 */
internal val VENDOR_PROFILES = listOf(
    VendorProfile(
        id = VendorId.XIAOMI,
        manufacturers = listOf("xiaomi", "redmi", "poco"),
        autostart = listOf(
            VendorScreen("com.miui.securitycenter", "com.miui.permcenter.autostart.AutoStartManagementActivity"),
        ),
        battery = listOf(
            VendorScreen("com.miui.powerkeeper", "com.miui.powerkeeper.ui.HiddenAppsConfigActivity"),
        ),
        autostartTitle = R.string.ka_vendor_autostart,
        autostartDesc = R.string.ka_vendor_autostart_desc,
        autostartToggle = R.string.ka_toggle_autostart,
        batteryDesc = R.string.ka_vendor_battery_desc_xiaomi,
    ),
    VendorProfile(
        id = VendorId.HUAWEI,
        manufacturers = listOf("huawei"),
        autostart = listOf(
            VendorScreen("com.huawei.systemmanager", "com.huawei.systemmanager.startupmgr.ui.StartupNormalAppListActivity"),
            VendorScreen("com.huawei.systemmanager", "com.huawei.systemmanager.appcontrol.activity.StartupAppControlActivity"),
            VendorScreen("com.huawei.systemmanager", "com.huawei.systemmanager.optimize.process.ProtectActivity"),
        ),
        battery = emptyList(),
        autostartTitle = R.string.ka_vendor_autostart,
        // EMUI needs three switches flipped after leaving "Manage automatically",
        // so naming a single toggle would be wrong.
        autostartDesc = R.string.ka_vendor_autostart_desc_huawei,
        autostartToggle = null,
        batteryDesc = null,
    ),
    VendorProfile(
        id = VendorId.HONOR,
        manufacturers = listOf("honor", "hihonor"),
        autostart = listOf(
            VendorScreen("com.hihonor.systemmanager", "com.hihonor.systemmanager.startupmgr.ui.StartupNormalAppListActivity"),
            VendorScreen("com.hihonor.systemmanager", "com.hihonor.systemmanager.appcontrol.activity.StartupAppControlActivity"),
        ),
        battery = emptyList(),
        autostartTitle = R.string.ka_vendor_autostart,
        autostartDesc = R.string.ka_vendor_autostart_desc_huawei,
        autostartToggle = null,
        batteryDesc = null,
    ),
    VendorProfile(
        id = VendorId.OPPO,
        manufacturers = listOf("oppo"),
        autostart = listOf(
            VendorScreen("com.coloros.safecenter", "com.coloros.safecenter.permission.startup.StartupAppListActivity"),
            VendorScreen("com.coloros.safecenter", "com.coloros.safecenter.startupapp.StartupAppListActivity"),
            VendorScreen("com.oppo.safe", "com.oppo.safe.permission.startup.StartupAppListActivity"),
        ),
        battery = emptyList(),
        autostartTitle = R.string.ka_vendor_autostart,
        autostartDesc = R.string.ka_vendor_autostart_desc,
        autostartToggle = R.string.ka_toggle_allow_autostart,
        batteryDesc = null,
    ),
    VendorProfile(
        id = VendorId.REALME,
        manufacturers = listOf("realme"),
        autostart = listOf(
            VendorScreen("com.coloros.safecenter", "com.coloros.safecenter.permission.startup.StartupAppListActivity"),
            VendorScreen("com.coloros.safecenter", "com.coloros.safecenter.startupapp.StartupAppListActivity"),
        ),
        battery = emptyList(),
        autostartTitle = R.string.ka_vendor_autostart,
        autostartDesc = R.string.ka_vendor_autostart_desc,
        autostartToggle = R.string.ka_toggle_allow_autostart,
        batteryDesc = null,
    ),
    VendorProfile(
        id = VendorId.VIVO,
        manufacturers = listOf("vivo", "iqoo"),
        autostart = listOf(
            VendorScreen("com.vivo.permissionmanager", "com.vivo.permissionmanager.activity.BgStartUpManagerActivity"),
            VendorScreen("com.iqoo.secure", "com.iqoo.secure.ui.phoneoptimize.AddWhiteListActivity"),
        ),
        battery = emptyList(),
        autostartTitle = R.string.ka_vendor_autostart,
        autostartDesc = R.string.ka_vendor_autostart_desc,
        autostartToggle = R.string.ka_toggle_autostart,
        batteryDesc = null,
    ),
    VendorProfile(
        id = VendorId.ONEPLUS,
        manufacturers = listOf("oneplus"),
        autostart = listOf(
            VendorScreen("com.oneplus.security", "com.oneplus.security.chainlaunch.view.ChainLaunchAppListActivity"),
        ),
        battery = emptyList(),
        autostartTitle = R.string.ka_vendor_autostart,
        autostartDesc = R.string.ka_vendor_autostart_desc,
        autostartToggle = R.string.ka_toggle_autostart,
        batteryDesc = null,
    ),
    VendorProfile(
        id = VendorId.SAMSUNG,
        manufacturers = listOf("samsung"),
        // One UI has no autostart list; these screens are its battery policy, which
        // is where "Never sleeping apps" lives.
        autostart = emptyList(),
        battery = listOf(
            VendorScreen("com.samsung.android.lool", "com.samsung.android.sm.ui.battery.BatteryActivity"),
            VendorScreen("com.samsung.android.lool", "com.samsung.android.sm.battery.ui.BatteryActivity"),
        ),
        autostartTitle = R.string.ka_vendor_autostart,
        autostartDesc = R.string.ka_vendor_autostart_desc,
        autostartToggle = null,
        batteryDesc = R.string.ka_vendor_battery_desc_samsung,
    ),
    VendorProfile(
        id = VendorId.ASUS,
        manufacturers = listOf("asus"),
        autostart = listOf(
            VendorScreen("com.asus.mobilemanager", "com.asus.mobilemanager.autostart.AutoStartActivity"),
        ),
        battery = emptyList(),
        autostartTitle = R.string.ka_vendor_autostart,
        autostartDesc = R.string.ka_vendor_autostart_desc,
        autostartToggle = R.string.ka_toggle_autostart_manager,
        batteryDesc = null,
    ),
    VendorProfile(
        id = VendorId.MEIZU,
        manufacturers = listOf("meizu"),
        // Flyme moved this into per-app permissions; no stable component is known,
        // so the app-details fallback carries it.
        autostart = listOf(
            VendorScreen("com.meizu.safe", "com.meizu.safe.permission.PermissionMainActivity"),
        ),
        battery = emptyList(),
        autostartTitle = R.string.ka_vendor_autostart,
        autostartDesc = R.string.ka_vendor_autostart_desc,
        autostartToggle = R.string.ka_toggle_run_in_background,
        batteryDesc = null,
    ),
    VendorProfile(
        id = VendorId.TRANSSION,
        manufacturers = listOf("tecno", "infinix", "itel"),
        // HiOS/XOS keep this in Phone Master, whose component differs per model;
        // the app-details fallback carries it.
        autostart = emptyList(),
        battery = emptyList(),
        autostartTitle = R.string.ka_vendor_autostart,
        autostartDesc = R.string.ka_vendor_autostart_desc,
        autostartToggle = R.string.ka_toggle_autostart_management,
        batteryDesc = null,
    ),
)
```

**Замечание про Transsion:** `autostart` пуст, но профиль всё равно даёт карточку — Task 3 подставит фолбэк на карточку приложения. Тест `everyProfileCanRenderItsCards` это не нарушает: он проверяет только профили с непустым списком.

- [ ] **Step 4: Запустить — убедиться, что проходит**

Run: `cd android && ./gradlew :app:testDebugUnitTest --tests "com.outline.proxy.keepalive.VendorProfilesTest"`
Expected: PASS (все 8).

- [ ] **Step 5: Зафиксировать** (по разрешению владельца)

```bash
git add android/app/src/main/java/com/outline/proxy/keepalive/VendorProfiles.kt \
        android/app/src/test/java/com/outline/proxy/keepalive/VendorProfilesTest.kt
git commit -m "feat(android): table of vendor background-restriction profiles"
```

---

### Task 3: `KeepAliveHelper` строит интенты из профиля

**Files:**
- Modify: `android/app/src/main/java/com/outline/proxy/keepalive/KeepAliveHelper.kt`

**Interfaces:**
- Consumes: `vendorProfileFor`, `VendorProfile`, `VendorScreen` (Task 2).
- Produces:
  - `fun vendorProfile(context: Context): VendorProfile?`
  - `fun vendorLabel(context: Context): String?` — прежняя сигнатура, новая реализация
  - `fun autostartIntent(context: Context): Intent?`
  - `fun vendorBatteryIntent(context: Context): Intent?`
- Удаляется: приватный `AUTOSTART_COMPONENTS`, приватные `vendorEntries` / `manufacturerLabel` в прежнем виде.

- [ ] **Step 1: Заменить вендорскую часть `KeepAliveHelper.kt`**

Оставить без изменений: `isIgnoringBatteryOptimizations`, `batteryOptimizationIntent`, `batteryOptimizationListIntent`, `canScheduleExactAlarms`, `exactAlarmSettingsIntent`, `vpnSettingsIntent`. Заменить всё от `vendorLabel` до конца объекта (включая `AUTOSTART_COMPONENTS`) на:

```kotlin
    /** The vendor profile for this device, or null on near-stock skins. */
    internal fun vendorProfile(context: Context): VendorProfile? =
        vendorProfileFor(VendorOverride.manufacturer(context))

    /** Manufacturer name to show in the checklist, or null on near-stock skins. */
    fun vendorLabel(context: Context): String? =
        vendorProfile(context)?.let {
            VendorOverride.manufacturer(context).orEmpty().replaceFirstChar { c -> c.titlecase(Locale.US) }
        }

    /** The vendor's autostart screen, or the app-details page when none resolves. */
    fun autostartIntent(context: Context): Intent? {
        val profile = vendorProfile(context) ?: return null
        if (profile.autostart.isEmpty()) return appDetailsIntent(context)
        return firstResolvable(context, profile.autostart) ?: appDetailsIntent(context)
    }

    /** The vendor's per-app battery-policy screen, when the skin has one. */
    fun vendorBatteryIntent(context: Context): Intent? {
        val profile = vendorProfile(context) ?: return null
        if (profile.batteryDesc == null) return null
        if (profile.battery.isEmpty()) return appDetailsIntent(context)
        return firstResolvable(context, profile.battery) ?: appDetailsIntent(context)
    }

    /**
     * The first screen that actually exists on this device. Components come and go
     * between firmware versions, so every candidate is probed before being offered.
     */
    private fun firstResolvable(context: Context, screens: List<VendorScreen>): Intent? =
        screens.asSequence()
            .map { screen ->
                Intent().setComponent(ComponentName(screen.packageName, screen.className))
                    .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            }
            .firstOrNull { context.packageManager.resolveActivity(it, 0) != null }

    /**
     * The system app-details page. Always present, and on most vendor skins it is
     * where the per-app autostart and battery switches live anyway.
     */
    private fun appDetailsIntent(context: Context): Intent =
        Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS)
            .setData(Uri.parse("package:${context.packageName}"))
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
}
```

Импорт `android.os.Build` в этом файле остаётся нужным (его использует `canScheduleExactAlarms`); `java.util.Locale` тоже.

- [ ] **Step 2: Сборка**

Run: `cd android && ./gradlew :app:assembleDebug`
Expected: FAIL — `Unresolved reference: VendorOverride` (появится в Task 4). Это ожидаемо: следующая задача его создаёт.

- [ ] **Step 3: Отложить фиксацию до Task 4**

Задачи 3 и 4 фиксируются одним коммитом — по отдельности код не компилируется.

---

### Task 4: Debug-подмена производителя

**Files:**
- Create: `android/app/src/main/java/com/outline/proxy/keepalive/VendorOverride.kt`

**Interfaces:**
- Consumes: ничего.
- Produces: `internal object VendorOverride { fun manufacturer(context: Context): String? }`

- [ ] **Step 1: Создать `VendorOverride.kt`**

```kotlin
package com.outline.proxy.keepalive

import android.content.Context
import android.os.Build
import com.outline.proxy.BuildConfig

/**
 * Which manufacturer the vendor checklist should pretend this device is.
 *
 * Vendor cards can only be seen on real vendor firmware, which no emulator has —
 * so a debug build reads an override from preferences, letting a CLI run flip
 * through every skin and screenshot the result. Release builds never read it:
 * the branch is constant-folded away by `BuildConfig.DEBUG`.
 *
 * Set it with (debug build only):
 * ```
 * adb shell "run-as com.outline.proxy sh -c 'cat > /data/data/com.outline.proxy/shared_prefs/outline_debug.xml'" < override.xml
 * ```
 */
internal object VendorOverride {

    fun manufacturer(context: Context): String? {
        if (BuildConfig.DEBUG) {
            val override = context
                .getSharedPreferences(PREFS, Context.MODE_PRIVATE)
                .getString(KEY_MANUFACTURER, null)
                ?.takeIf { it.isNotBlank() }
            if (override != null) return override
        }
        return Build.MANUFACTURER
    }

    private const val PREFS = "outline_debug"
    private const val KEY_MANUFACTURER = "vendor_manufacturer"
}
```

- [ ] **Step 2: Сборка и тесты**

Run: `cd android && ./gradlew :app:testDebugUnitTest :app:assembleDebug`
Expected: BUILD SUCCESSFUL; тесты Task 2 проходят.

- [ ] **Step 3: Зафиксировать Task 3 + Task 4** (по разрешению владельца)

```bash
git add android/app/src/main/java/com/outline/proxy/keepalive/KeepAliveHelper.kt \
        android/app/src/main/java/com/outline/proxy/keepalive/VendorOverride.kt
git commit -m "feat(android): resolve vendor screens from profiles, with debug override"
```

---

### Task 5: Статусы перечитываются при возврате на экран

**Files:**
- Modify: `android/app/src/main/java/com/outline/proxy/KeepAliveScreen.kt`

**Interfaces:**
- Consumes: ничего нового.
- Produces: поведение — `refresh` растёт на каждом `ON_RESUME`.

- [ ] **Step 1: Добавить импорты** в `KeepAliveScreen.kt`:

```kotlin
import androidx.compose.runtime.DisposableEffect
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.lifecycle.compose.LocalLifecycleOwner
```

- [ ] **Step 2: Перечитывать статусы при возврате.** Сразу после объявления `var refresh by remember { mutableIntStateOf(0) }` вставить:

```kotlin
    // Every grant on this screen is changed in a system or vendor screen that
    // hands back no result, and the user may also change one from the shade and
    // walk back in. Re-read on each resume so the checklist can never show a
    // status the user has already changed.
    val lifecycleOwner = LocalLifecycleOwner.current
    DisposableEffect(lifecycleOwner) {
        val observer = LifecycleEventObserver { _, event ->
            if (event == Lifecycle.Event.ON_RESUME) refresh++
        }
        lifecycleOwner.lifecycle.addObserver(observer)
        onDispose { lifecycleOwner.lifecycle.removeObserver(observer) }
    }
```

- [ ] **Step 3: Убрать преждевременные `refresh++`.** В `onAction` карточки батареи убрать строку `refresh++`, оставив:

```kotlin
                onAction = {
                    if (!context.launchSafely(KeepAliveHelper.batteryOptimizationIntent(context))) {
                        context.launchSafely(KeepAliveHelper.batteryOptimizationListIntent())
                    }
                },
```

В `onAction` карточки точных будильников — так же:

```kotlin
                    onAction = {
                        KeepAliveHelper.exactAlarmSettingsIntent(context)?.let { context.launchSafely(it) }
                    },
```

(Эти вызовы читали состояние до того, как пользователь что-либо решил; теперь его приносит `ON_RESUME`.)

- [ ] **Step 4: Сборка**

Run: `cd android && ./gradlew :app:assembleDebug`
Expected: BUILD SUCCESSFUL.

- [ ] **Step 5: Зафиксировать** (по разрешению владельца)

```bash
git add android/app/src/main/java/com/outline/proxy/KeepAliveScreen.kt
git commit -m "fix(android): re-read keep-alive grants on resume, not on button tap"
```

---

### Task 6: Вендорские карточки на экране

**Files:**
- Modify: `android/app/src/main/java/com/outline/proxy/KeepAliveScreen.kt`

**Interfaces:**
- Consumes: `KeepAliveHelper.vendorProfile/vendorLabel/autostartIntent/vendorBatteryIntent` (Task 3), строки (Task 1).

- [ ] **Step 1: Заменить блок вендорской карточки.** Найти в конце `KeepAliveScreen` блок `KeepAliveHelper.vendorLabel(context)?.let { vendor -> ChecklistItem(...) }` и заменить его целиком на:

```kotlin
            val vendorProfile = KeepAliveHelper.vendorProfile(context)
            val vendorName = KeepAliveHelper.vendorLabel(context)
            if (vendorProfile != null && vendorName != null) {
                // The vendor's own battery policy, which Android's exemption above
                // does not touch — the reason a device can report "Allowed" and
                // still kill the tunnel.
                vendorProfile.batteryDesc?.let { descRes ->
                    ChecklistItem(
                        title = stringResource(R.string.ka_vendor_battery, vendorName),
                        status = GrantStatus.UNKNOWN,
                        explanation = stringResource(descRes, vendorName),
                        action = stringResource(R.string.ka_open_vendor_settings, vendorName),
                        onAction = {
                            KeepAliveHelper.vendorBatteryIntent(context)?.let { context.launchSafely(it) }
                        },
                    )
                }

                // The autostart list. Skins without one (One UI) declare no toggle
                // and no screens, and get no card here.
                if (vendorProfile.autostartToggle != null || vendorProfile.autostart.isNotEmpty()) {
                    val explanation = vendorProfile.autostartToggle?.let { toggleRes ->
                        stringResource(vendorProfile.autostartDesc, vendorName, stringResource(toggleRes))
                    } ?: stringResource(vendorProfile.autostartDesc, vendorName)
                    ChecklistItem(
                        title = stringResource(vendorProfile.autostartTitle, vendorName),
                        status = GrantStatus.UNKNOWN,
                        explanation = explanation,
                        action = stringResource(R.string.ka_open_vendor_settings, vendorName),
                        onAction = {
                            KeepAliveHelper.autostartIntent(context)?.let { context.launchSafely(it) }
                        },
                    )
                }
            }
```

**Порядок карточек намеренный:** батарейная идёт сразу после системной («Ignore battery optimisation»), потому что именно их пользователь путает между собой.

- [ ] **Step 2: Сборка и lint**

Run: `cd android && ./gradlew :app:assembleDebug :app:lintDebug`
Expected: BUILD SUCCESSFUL.

- [ ] **Step 3: Зафиксировать** (по разрешению владельца)

```bash
git add android/app/src/main/java/com/outline/proxy/KeepAliveScreen.kt
git commit -m "feat(android): vendor battery-policy and autostart cards with exact toggle names"
```

---

### Task 7: Модуль загрузки иконок приложений

**Files:**
- Create: `android/app/src/main/java/com/outline/proxy/AppIcons.kt`

**Interfaces:**
- Produces: `@Composable fun rememberAppIcon(packageName: String, size: Dp): State<ImageBitmap?>`

- [ ] **Step 1: Создать `AppIcons.kt`**

```kotlin
package com.outline.proxy

import android.content.Context
import android.graphics.Bitmap
import android.graphics.Canvas
import android.graphics.drawable.Drawable
import android.util.LruCache
import androidx.compose.runtime.Composable
import androidx.compose.runtime.State
import androidx.compose.runtime.produceState
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.unit.Dp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * App icons for the split-tunnel picker, loaded on demand.
 *
 * A phone can have several hundred network-capable apps, so icons are never
 * loaded with the list: each row asks for its own once it scrolls into view,
 * off the main thread, and the result is rasterised to display size before being
 * cached. Keeping full-resolution adaptive icons for every installed app would
 * cost far more memory than the picker is worth.
 */
private const val ICON_CACHE_ENTRIES = 128

private val iconCache = LruCache<String, ImageBitmap>(ICON_CACHE_ENTRIES)

/**
 * The icon for [packageName], or null while it loads (and for apps whose icon
 * cannot be read). Cached across rows and recompositions; the load is cancelled
 * automatically when the row leaves the composition.
 */
@Composable
fun rememberAppIcon(packageName: String, size: Dp): State<ImageBitmap?> {
    val context = LocalContext.current
    val sizePx = with(LocalDensity.current) { size.roundToPx() }
    return produceState<ImageBitmap?>(
        initialValue = iconCache.get(packageName),
        packageName,
        sizePx,
    ) {
        if (value == null) {
            value = withContext(Dispatchers.IO) { loadAppIcon(context, packageName, sizePx) }
        }
    }
}

private fun loadAppIcon(context: Context, packageName: String, sizePx: Int): ImageBitmap? {
    iconCache.get(packageName)?.let { return it }
    // An app can be uninstalled between building the list and drawing its row.
    val drawable = runCatching {
        context.packageManager.getApplicationIcon(packageName)
    }.getOrNull() ?: return null
    val icon = drawable.rasterise(sizePx).asImageBitmap()
    iconCache.put(packageName, icon)
    return icon
}

/**
 * Draw a drawable at exactly [sizePx]. Works for adaptive icons too, which have
 * no intrinsic bitmap to reuse.
 */
private fun Drawable.rasterise(sizePx: Int): Bitmap {
    val bitmap = Bitmap.createBitmap(sizePx, sizePx, Bitmap.Config.ARGB_8888)
    setBounds(0, 0, sizePx, sizePx)
    draw(Canvas(bitmap))
    return bitmap
}
```

- [ ] **Step 2: Сборка**

Run: `cd android && ./gradlew :app:assembleDebug`
Expected: BUILD SUCCESSFUL (модуль пока никем не используется).

- [ ] **Step 3: Отложить фиксацию до Task 8** — модуль без потребителя коммитить незачем.

---

### Task 8: Иконка в строке списка приложений

**Files:**
- Modify: `android/app/src/main/java/com/outline/proxy/MainActivity.kt`

**Interfaces:**
- Consumes: `rememberAppIcon` (Task 7).

- [ ] **Step 1: Добавить импорты** в `MainActivity.kt`:

```kotlin
import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.size
```

- [ ] **Step 2: Вставить иконку в строку.** В `SplitTunnelScreen`, внутри `items(visible, key = { it.packageName })`, заменить содержимое `Row` — добавив иконку между `Checkbox` и `Column`:

```kotlin
                                Checkbox(
                                    checked = checked,
                                    onCheckedChange = {
                                        if (it) selected.add(app.packageName) else selected.remove(app.packageName)
                                        persist()
                                    },
                                )
                                // Fixed-size box so rows keep their height and never
                                // reflow when an icon arrives (or never does).
                                val icon by rememberAppIcon(app.packageName, 40.dp)
                                Box(modifier = Modifier.size(40.dp)) {
                                    icon?.let {
                                        Image(
                                            bitmap = it,
                                            contentDescription = null,
                                            modifier = Modifier.fillMaxSize(),
                                        )
                                    }
                                }
                                Column(modifier = Modifier.padding(start = 12.dp)) {
                                    Text(app.label)
                                    Text(
                                        app.packageName,
                                        style = MaterialTheme.typography.bodySmall,
                                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                                    )
                                }
```

(`fillMaxSize` уже импортирован в файле; отступ у `Column` увеличен с 8 до 12 dp, чтобы текст не липнул к иконке.)

- [ ] **Step 3: Сборка**

Run: `cd android && ./gradlew :app:assembleDebug`
Expected: BUILD SUCCESSFUL.

- [ ] **Step 4: Зафиксировать Task 7 + Task 8** (по разрешению владельца)

```bash
git add android/app/src/main/java/com/outline/proxy/AppIcons.kt \
        android/app/src/main/java/com/outline/proxy/MainActivity.kt
git commit -m "feat(android): show app icons in the split-tunnel picker"
```

---

### Task 9: Проверка внешнего вида на эмуляторе

**Files:** без изменений в репозитории (скриншоты складывать в scratchpad, не в git).

**Предусловия:** `JAVA_HOME` = liberica 17; `.so` и биндинги синхронны (сверить mtime `app/src/main/jniLibs/arm64-v8a/liboutline_android.so` и `app/src/main/java/uniffi/outline_android/outline_android.kt` — расхождение роняет приложение на старте).

- [ ] **Step 1: Поднять эмулятор и поставить сборку**

```bash
~/Library/Android/sdk/emulator/emulator -avd Pixel_10 -no-snapshot-load &
~/Library/Android/sdk/platform-tools/adb wait-for-device
cd android && ./gradlew :app:installDebug
```

- [ ] **Step 2: Прогнать вендоров и снять экран.** Для каждого значения из списка `xiaomi`, `huawei`, `honor`, `oppo`, `realme`, `vivo`, `oneplus`, `samsung`, `asus`, `meizu`, `tecno`, а также контрольного `google`:

```bash
ADB=~/Library/Android/sdk/platform-tools/adb
V=xiaomi   # подставить очередного вендора
$ADB shell am force-stop com.outline.proxy
printf '<?xml version="1.0" encoding="utf-8" standalone="yes" ?>\n<map>\n<string name="vendor_manufacturer">%s</string>\n</map>\n' "$V" \
  | $ADB shell "run-as com.outline.proxy sh -c 'cat > /data/data/com.outline.proxy/shared_prefs/outline_debug.xml'"
$ADB shell am start -n com.outline.proxy/.MainActivity
# перейти на экран «Поддержание связи» и снять
$ADB exec-out screencap -p > "$SCRATCH/keepalive-$V.png"
```

Ожидаемое: у `xiaomi` — обе карточки (батарея с текстом про «Экономия заряда батареи» → «Без ограничений», автозапуск с «Автозапуск»); у `samsung` — только батарейная, с текстом про спящие приложения; у `huawei`/`honor` — только автозапуск с трёхшаговой инструкцией; у `google` — ни одной вендорской карточки.

- [ ] **Step 3: Проверить обе локали.** Повторить выборочно (`xiaomi`, `samsung`, `huawei`) на русской локали:

```bash
$ADB shell "setprop persist.sys.locale ru-RU; am broadcast -a android.intent.action.LOCALE_CHANGED"
```

Ожидаемое: тексты по-русски, длинные описания не обрезаны, кнопка целиком помещается в карточку.

- [ ] **Step 4: Снять список раздельного туннеля.** Открыть «Раздельный туннель» → режим «Только выбранные», убедиться, что иконки появляются при прокрутке, строки не прыгают, поиск с иконками работает.

```bash
$ADB exec-out screencap -p > "$SCRATCH/split-tunnel-icons.png"
```

- [ ] **Step 5: Снять оверрайд и погасить эмулятор**

```bash
$ADB shell "run-as com.outline.proxy rm -f /data/data/com.outline.proxy/shared_prefs/outline_debug.xml"
$ADB emu kill
```

- [ ] **Step 6: Показать скриншоты владельцу** и получить добро на внешний вид до финального коммита.

---

### Task 10: CHANGELOG и финальный гейт

**Files:**
- Modify: `android/CHANGELOG.md`
- Modify: `android/CHANGELOG.ru.md`

- [ ] **Step 1: `android/CHANGELOG.md`,** в `## [Unreleased]` → `### Added`:

```markdown
- **The Keeping Alive screen now covers the vendor's own restrictions, not just Android's.** Skins that keep a separate autostart list or per-app battery policy (Xiaomi, Huawei, Honor, Oppo, realme, vivo, OnePlus, Samsung, Asus, Meizu, Tecno/Infinix) get their own cards naming the exact switch to turn on — "Autostart" on Xiaomi, "Never sleeping apps" on Samsung, the three-step "App launch" sequence on Huawei and Honor. Android's battery-optimisation exemption does not cover any of these, which is why a phone can report the permission as granted and still stop the tunnel.
- **The Split Tunneling picker shows app icons.** They load as rows scroll into view, so opening the screen is no slower than before.
```

В `### Fixed`:

```markdown
- **The Keeping Alive checklist no longer shows stale statuses.** Grants are re-read every time the screen comes back into view instead of when a button is tapped, so a permission changed in a system or vendor screen — or from the notification shade — is reflected on return.
- **Samsung devices no longer get an "autostart" card for a list One UI does not have.** The two screens behind it are One UI's battery policy, and it is now labelled and described as such.
```

- [ ] **Step 2: `android/CHANGELOG.ru.md`** — те же пункты по-русски, в соответствующие разделы:

```markdown
- **Экран «Поддержание связи» учитывает вендорские ограничения, а не только системные.** Прошивки со своим списком автозапуска или политикой батареи (Xiaomi, Huawei, Honor, Oppo, realme, vivo, OnePlus, Samsung, Asus, Meizu, Tecno/Infinix) получают отдельные карточки с точным названием пункта: «Автозапуск» на Xiaomi, «Никогда не переводить в спящий режим» на Samsung, трёхшаговый «Запуск приложений» на Huawei и Honor. Системное разрешение на работу с батареей ни одного из этих слоёв не покрывает — поэтому телефон может показывать разрешение выданным и всё равно останавливать туннель.
- **В раздельном туннеле у приложений появились иконки.** Они подгружаются по мере прокрутки, поэтому экран открывается не медленнее прежнего.
```

```markdown
- **Чеклист «Поддержание связи» больше не показывает устаревшие статусы.** Разрешения перечитываются при каждом возврате на экран, а не по нажатию кнопки, поэтому изменение, сделанное в системных или вендорских настройках (в том числе из шторки), видно сразу.
- **На Samsung исчезла карточка «автозапуск» для списка, которого в One UI нет.** Стоящие за ней экраны — это политика батареи One UI, и теперь она так и называется.
```

- [ ] **Step 3: Полный гейт**

Run:
```bash
cd android && ./gradlew :app:testDebugUnitTest :app:assembleDebug :app:lintDebug
```
Expected: всё зелёное, `MissingTranslation`/`ExtraTranslation` — ноль.

- [ ] **Step 4: Гейт `android/rust`** (не меняли — должен остаться зелёным)

Run: `cd android/rust && cargo fmt --check && cargo clippy --no-deps -- -D warnings`
Expected: чисто.

- [ ] **Step 5: `ru-check`** — прогнать `ru-text:ru-check` по новым строкам `values-ru/strings.xml` и по добавленным пунктам `CHANGELOG.ru.md`; поправить типографику и формулировки, повторить `lintDebug`.

- [ ] **Step 6: Зафиксировать** (по разрешению владельца)

```bash
git add android/CHANGELOG.md android/CHANGELOG.ru.md
git commit -m "docs(android): changelog for vendor keep-alive cards and app icons"
```

---

## Отклонения при исполнении (зафиксировано по факту)

1. **`autostartIntent` / `vendorBatteryIntent` стали списками** —
   `autostartIntents(context): List<Intent>` и
   `vendorBatteryIntents(context): List<Intent>`, а экран запускает их через
   `Context.launchFirst(...)`, перебирая до первого успешного.
   Причина: `resolveActivity` доказывает, что Activity **существует**, но не
   что её можно запустить — часть сборок MIUI держит `HiddenAppsConfigActivity`
   неэкспортированной. С одним интентом запуск падал бы внутри `launchSafely`,
   и кнопка молча не делала бы ничего. Последний кандидат в списке — карточка
   приложения, она есть всегда.

2. **Порядок карточек.** Вендорская батарейная карточка размещена сразу после
   системной «Игнорировать оптимизацию батареи» (а не в конце экрана, как
   выходило по коду в Task 6): именно эти две пользователь и путает.

3. **Проверка на эмуляторе** прошла по Xiaomi, Samsung, Huawei, Asus и
   контрольному Google в русской локали и по Xiaomi в английской; отдельно
   подтверждено, что кнопка вендорской карточки на устройстве без вендорских
   пакетов открывает карточку приложения
   (`com.android.settings/.spa.SpaActivity`), а не остаётся без реакции.

4. **Правки текстов после `ru-check`.** Шаблон описания автозапуска говорил
   «включите «%2$s»», но на Asus и Tecno туда подставляется название **экрана**
   («Диспетчер автозапуска», «Управление автозапуском»), а не тумблера —
   получалось «включите диспетчер». Формулировка изменена на нейтральную
   («откройте «%2$s» и разрешите там работу») в обоих языках. У Samsung жёсткая
   цитата белого списка заменена описанием плюс оба известных названия: путь
   «Ограничения в фоновом режиме» подтверждён, но сам список One UI
   переименовывает между версиями. Остальное — грамматика и снятие пассива.
   Отклонено одно замечание: заголовки карточек оставлены короткими
   («Батарея: %1$s»), потому что «Политика батареи %1$s» на реальном экране
   встаёт в перенос рядом со статусом.

5. **Проверка на живом Samsung (Galaxy Z Flip 7, One UI 8, Android 16).**
   Владелец подключил устройство после того, как сообщил, что «непонятно, что
   делать» на экране, куда ведёт карточка. Выяснилось:
   - `com.samsung.android.sm.ui.battery.BatteryActivity` (первый кандидат) на
     One UI 8 **не существует**; работает второй — `...sm.battery.ui.BatteryActivity`.
   - Прямая ссылка на сам список невозможна:
     `...sm.battery.ui.setting.AppPowerManagementActivity` требует
     `android.permission.READ_SEARCH_INDEXABLES` и падает с `SecurityException`.
   - Реальный путь (RU): Батарея → «Ограничения в фоновом режиме» → «Не уходят
     в сон автоматически» → «+»; (EN): Battery → «Background usage limits» →
     «Never auto sleeping apps».
   - Прежний текст называл список «Неспящие приложения» / «Никогда не
     отключать» — обоих названий на этой прошивке нет, из-за чего пользователь
     и не находил, что нажимать. Текст заменён на точный путь в обоих языках.

6. **Экраны адресуются действием, а не классом (после доисследования).**
   Первый вывод — «прямая ссылка на список Samsung невозможна» — оказался
   неверным: он был сделан по одной закрытой Activity
   (`AppPowerManagementActivity`, требует `READ_SEARCH_INDEXABLES`), тогда как
   Samsung документирует другой вход — экспортированный alias через
   `com.samsung.android.sm.ACTION_OPEN_CHECKABLE_LISTACTIVITY` с
   `activity_type = 2` (0 — спящие, 1 — глубокий сон, 2 — не уходят в сон).
   Проверено на живом One UI 8: открывается сам список, резолвится и по
   `action + setPackage`, без имени класса.

   Поэтому `VendorScreen` теперь адресует экран **либо** компонентом, **либо**
   действием с extras (инвариант «ровно одно из двух» проверяется тестом), а у
   Samsung в `battery` стоят два действия: deeplink в список и
   `ACTION_BATTERY` как запасной. Мёртвый `sm.ui.battery.BatteryActivity`
   удалён — на устройстве `resolve-activity` отвечает «No activity found»,
   и по данным дампов его нет ни в одной сборке с 2019 года.

## Self-Review (выполнено при написании плана)

- **Покрытие спеки:** F1 (перечитывание при возврате) — Task 5; F2 (вендорская батарея) — Task 1/2/3/6; F3 (автозапуск с конкретикой + перенос Samsung) — Task 1/2/3/6, Samsung получает пустой `autostart` и собственный `batteryDesc`; F4 (иконки) — Task 7-8; F5 (debug-оверрайд) — Task 4, применяется в Task 9. Юнит-тесты из раздела «Тестирование» — Task 2; проверка на эмуляторе — Task 9; гейт и CHANGELOG — Task 10. Отступление от спеки (показ карточки по производителю, а не по резолвингу) вынесено в отдельный раздел «Уточнение к спеке».
- **Плейсхолдеры:** нет; весь код приведён целиком, включая таблицу профилей и оба набора строк.
- **Согласованность типов:** `vendorProfileFor(String?): VendorProfile?`, `VendorScreen(packageName, className)`, `VendorProfile.autostartToggle: Int?`, `batteryDesc: Int?` — используются в Task 3 и Task 6 ровно в этих сигнатурах; `rememberAppIcon(packageName, size): State<ImageBitmap?>` (Task 7) потребляется в Task 8 как `val icon by rememberAppIcon(...)`.
- **Порядок сборки:** Task 3 намеренно оставляет дерево некомпилируемым (ссылка на `VendorOverride`), Task 4 это закрывает — оба фиксируются одним коммитом; то же у Task 7-8.
