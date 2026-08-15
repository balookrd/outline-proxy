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
