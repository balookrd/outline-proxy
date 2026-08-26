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
 */
internal data class VendorScreen(val packageName: String, val className: String)

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
        autostart = listOf(
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
            VendorScreen(
                "com.vivo.permissionmanager",
                "com.vivo.permissionmanager.activity.BgStartUpManagerActivity",
            ),
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
        // which is where "Never sleeping apps" lives.
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
        // HiOS/XOS keep this in Phone Master, whose component differs per model,
        // so the app-details fallback carries it.
        autostart = emptyList(),
        battery = emptyList(),
        autostartTitle = R.string.ka_vendor_autostart,
        autostartDesc = R.string.ka_vendor_autostart_desc,
        autostartToggle = R.string.ka_toggle_autostart_management,
        batteryDesc = null,
    ),
)
