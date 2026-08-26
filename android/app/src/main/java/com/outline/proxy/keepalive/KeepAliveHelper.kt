package com.outline.proxy.keepalive

import android.annotation.SuppressLint
import android.app.AlarmManager
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.PowerManager
import android.provider.Settings
import java.util.Locale

/**
 * The parts of staying alive that only the user can grant.
 *
 * Battery-optimisation exemption, exact-alarm access and always-on VPN have real
 * system screens. The vendor layers on top of them — autostart whitelists and
 * per-app battery policies, described in [VendorProfiles] — have no API at all,
 * neither to read nor to set: the best any app can do is open the right settings
 * screen and name the switch that has to be flipped there.
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

    /** The vendor profile for this device, or null on near-stock skins. */
    internal fun vendorProfile(context: Context): VendorProfile? =
        vendorProfileFor(VendorOverride.manufacturer(context))

    /** Manufacturer name to show in the checklist, or null on near-stock skins. */
    fun vendorLabel(context: Context): String? {
        if (vendorProfile(context) == null) return null
        return VendorOverride.manufacturer(context)
            ?.takeIf { it.isNotBlank() }
            ?.replaceFirstChar { it.titlecase(Locale.US) }
    }

    /**
     * Where to send the user for the vendor's autostart list, best first.
     *
     * A list rather than one intent because resolving an Activity only proves it
     * exists, not that we may start it: several MIUI builds keep these screens
     * unexported, so the launch throws and a single-intent button would silently
     * do nothing. The caller walks the list until one actually starts, and the
     * last entry is the app-details page — always present, and on most skins
     * where these per-app switches live anyway.
     */
    fun autostartIntents(context: Context): List<Intent> {
        val profile = vendorProfile(context) ?: return emptyList()
        return resolvable(context, profile.autostart) + appDetailsIntent(context)
    }

    /** The same, for the vendor's per-app battery policy. */
    fun vendorBatteryIntents(context: Context): List<Intent> {
        val profile = vendorProfile(context) ?: return emptyList()
        if (profile.batteryDesc == null) return emptyList()
        return resolvable(context, profile.battery) + appDetailsIntent(context)
    }

    /**
     * The candidate screens that exist on this device, in order. Vendor components
     * come and go between firmware versions, so each is probed before being offered.
     */
    private fun resolvable(context: Context, screens: List<VendorScreen>): List<Intent> =
        screens.map { intentFor(context, it) }.filter { canLaunch(context, it) }

    /**
     * Whether this app may actually start the screen, not merely whether it exists.
     *
     * `resolveActivity` answers the weaker question: Samsung's own background-limits
     * Activity resolves perfectly well and then throws, because it is guarded by a
     * system permission no third-party app holds. Checking `exported` and the guard
     * up front keeps such entries from being offered at all.
     */
    private fun canLaunch(context: Context, intent: Intent): Boolean {
        val activity = context.packageManager.resolveActivity(intent, 0)?.activityInfo ?: return false
        if (!activity.exported) return false
        val permission = activity.permission ?: return true
        return context.checkSelfPermission(permission) == PackageManager.PERMISSION_GRANTED
    }

    private fun intentFor(context: Context, screen: VendorScreen): Intent {
        val intent = screen.action
            ?.let { Intent(it).setPackage(screen.packageName) }
            ?: Intent().setComponent(ComponentName(screen.packageName, screen.className!!))
        screen.data?.let { intent.data = Uri.parse(fillTokens(context, it)) }
        screen.intExtras.forEach { (key, value) -> intent.putExtra(key, value) }
        screen.stringExtras.forEach { (key, value) -> intent.putExtra(key, fillTokens(context, value)) }
        return intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
    }

    /** Fills `{self}` / `{label}` in a data URI or string extra at launch time. */
    private fun fillTokens(context: Context, raw: String): String =
        raw.replace("{self}", context.packageName)
            .replace("{label}", context.applicationInfo.loadLabel(context.packageManager).toString())

    /** The system app-details page; present on every Android build. */
    private fun appDetailsIntent(context: Context): Intent =
        Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS)
            .setData(Uri.parse("package:${context.packageName}"))
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
}
