package com.outline.proxy.keepalive

import androidx.annotation.StringRes
import com.outline.proxy.R
import java.util.Locale

/**
 * Vendor skins that restrict background apps beyond what stock Android does.
 *
 * Two vendor layers sit on top of Android's Doze whitelist, and neither is
 * readable through any public API:
 *
 *  - an **autostart** list deciding whether the app may start in the background
 *    at all (on MIUI it is off by default for every app), and
 *  - a per-app **battery policy** that overrides Android's own.
 *
 * Granting Android's battery-optimisation exemption touches neither, which is why
 * a device can report `isIgnoringBatteryOptimizations() == true` and still kill
 * the tunnel — and why MIUI is documented to reset that exemption on its own.
 */
internal enum class VendorId {
    XIAOMI, HUAWEI, HONOR, OPPO, REALME, VIVO, ONEPLUS, SAMSUNG, ASUS, MEIZU, TRANSSION
}

/**
 * A settings screen owned by the vendor. Held as plain strings rather than a
 * [android.content.ComponentName] so this whole table stays free of Android
 * classes and can be unit-tested on the JVM.
 *
 * Prefer [action] over [className] where the vendor publishes one: Samsung
 * renamed the Activity behind its lists at least twice, while the action stayed
 * put, and a hardcoded class name simply stops resolving after such a rename.
 */
internal data class VendorScreen(
    val packageName: String,
    /** Explicit component; null when [action] addresses the screen instead. */
    val className: String? = null,
    /** Vendor action, resolved within [packageName]. */
    val action: String? = null,
    /** Integer extras the screen needs — Samsung picks which list to show with one. */
    val intExtras: Map<String, Int> = emptyMap(),
) {
    init {
        require((className == null) != (action == null)) {
            "VendorScreen needs exactly one of className/action"
        }
    }
}

/**
 * What one vendor skin needs. [autostart] and [battery] are candidate screens,
 * most specific first; either may be empty when the skin has no such layer or
 * hides it behind a per-model component we cannot name.
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
     *  out a multi-step sequence instead of naming a single switch. */
    @StringRes val autostartToggle: Int?,
    /** Body of the battery card; takes the vendor name as `%1$s`. Null when the
     *  skin adds no battery policy of its own. */
    @StringRes val batteryDesc: Int?,
)

/** The profile for this device's manufacturer, or null on near-stock skins. */
internal fun vendorProfileFor(manufacturer: String?): VendorProfile? {
    val key = manufacturer?.trim()?.lowercase(Locale.US).orEmpty()
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
            VendorScreen(
                "com.miui.securitycenter",
                "com.miui.permcenter.autostart.AutoStartManagementActivity",
            ),
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
            VendorScreen(
                "com.huawei.systemmanager",
                "com.huawei.systemmanager.startupmgr.ui.StartupNormalAppListActivity",
            ),
            VendorScreen(
                "com.huawei.systemmanager",
                "com.huawei.systemmanager.appcontrol.activity.StartupAppControlActivity",
            ),
            VendorScreen(
                "com.huawei.systemmanager",
                "com.huawei.systemmanager.optimize.process.ProtectActivity",
            ),
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
        // Verified live on MagicOS 10 (Android 16): StartupNormalAppListActivity is
        // exported and unguarded and publishes this action, which opens "App launch"
        // directly. StartupAppControlActivity needs a signature permission
        // (external_app_settings.USE_COMPONENT) and canLaunch rightly skips it.
        autostart = listOf(
            VendorScreen("com.hihonor.systemmanager", action = "hihonor.intent.action.HSM_STARTUPAPP_MANAGER"),
            VendorScreen(
                "com.hihonor.systemmanager",
                "com.hihonor.systemmanager.startupmgr.ui.StartupNormalAppListActivity",
            ),
            VendorScreen(
                "com.hihonor.systemmanager",
                "com.hihonor.systemmanager.appcontrol.activity.StartupAppControlActivity",
            ),
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
            VendorScreen(
                "com.coloros.safecenter",
                "com.coloros.safecenter.permission.startup.StartupAppListActivity",
            ),
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
            VendorScreen(
                "com.coloros.safecenter",
                "com.coloros.safecenter.permission.startup.StartupAppListActivity",
            ),
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
            // The action outlives the package: OriginOS CN ships i Manager as
            // com.vivo.imanager while global builds keep com.iqoo.secure.
            VendorScreen("com.iqoo.secure", action = "com.iqoo.secure.BGSTARTUPMANAGER"),
            VendorScreen(
                "com.vivo.permissionmanager",
                "com.vivo.permissionmanager.activity.BgStartUpManagerActivity",
            ),
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
            VendorScreen(
                "com.oneplus.security",
                "com.oneplus.security.chainlaunch.view.ChainLaunchAppListActivity",
            ),
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
        // One UI has no autostart list; these screens are its battery policy,
        // which is where the never-auto-sleeping allowlist lives.
        autostart = emptyList(),
        battery = listOf(
            // Samsung documents this one, and it lands on the allowlist itself
            // rather than the Battery screen two taps above it.
            // activity_type: 0 = sleeping, 1 = deep sleeping, 2 = never auto sleeping.
            VendorScreen(
                "com.samsung.android.lool",
                action = "com.samsung.android.sm.ACTION_OPEN_CHECKABLE_LISTACTIVITY",
                intExtras = mapOf("activity_type" to 2),
            ),
            // Fallback: the Battery screen, by action rather than class name.
            VendorScreen("com.samsung.android.lool", action = "com.samsung.android.sm.ACTION_BATTERY"),
        ),
        autostartTitle = R.string.ka_vendor_autostart,
        autostartDesc = R.string.ka_vendor_autostart_desc,
        autostartToggle = null,
        batteryDesc = R.string.ka_vendor_battery_desc_samsung,
    ),
    VendorProfile(
        id = VendorId.ASUS,
        manufacturers = listOf("asus"),
        // ZenUI publishes no action for this one, so the class name is the only
        // route; verified present and exported from Android 9 through 16.
        autostart = listOf(
            VendorScreen("com.asus.mobilemanager", "com.asus.mobilemanager.autostart.AutoStartActivity"),
            VendorScreen("com.asus.mobilemanager", "com.asus.mobilemanager.MainActivity"),
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
        autostart = listOf(
            // Flyme 10+; the old PermissionMainActivity we used to point at is both
            // the wrong screen (it is Permissions and Privacy) and gone on Flyme 12.
            VendorScreen("com.meizu.safe", action = "com.meizu.safe.security.autostart_manager_settings"),
            VendorScreen("com.meizu.safe", "com.meizu.safe.permission.AutoStartActivity"),
            // Flyme 8-10 only; removed in Flyme 12.
            VendorScreen("com.meizu.safe", action = "com.meizu.safe.PERMISSION_SETTING"),
        ),
        battery = emptyList(),
        autostartTitle = R.string.ka_vendor_autostart,
        autostartDesc = R.string.ka_vendor_autostart_desc,
        autostartToggle = R.string.ka_toggle_autostarts,
        batteryDesc = null,
    ),
    VendorProfile(
        id = VendorId.TRANSSION,
        manufacturers = listOf("tecno", "infinix", "itel"),
        // Tecno/Infinix/itel share Phone Master. The class was renamed
        // (applicationmanager.view.activities -> autostart) but the action kept the
        // old path, so it is the durable route; verified exported on HiOS/XOS 11-14.
        autostart = listOf(
            VendorScreen(
                "com.transsion.phonemaster",
                action = "com.cyin.himgr.applicationmanager.view.activities.AUTO_START_ACTIVITY",
            ),
            VendorScreen("com.transsion.phonemaster", "com.cyin.himgr.autostart.AutoStartActivity"),
        ),
        battery = emptyList(),
        autostartTitle = R.string.ka_vendor_autostart,
        autostartDesc = R.string.ka_vendor_autostart_desc,
        autostartToggle = R.string.ka_toggle_autostart_management,
        batteryDesc = null,
    ),
)
