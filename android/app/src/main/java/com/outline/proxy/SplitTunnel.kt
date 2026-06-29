package com.outline.proxy

import android.content.Context
import android.content.Intent

/**
 * Per-app split-tunnel policy. Android forbids mixing allowed and disallowed
 * apps on one [android.net.VpnService.Builder], so the modes are exclusive:
 *
 *  - [OFF]       : every app is tunneled (except this app itself).
 *  - [ALLOWLIST] : only [SplitTunnelConfig.packages] are tunneled.
 *  - [DENYLIST]  : every app except [SplitTunnelConfig.packages] (and this app)
 *                  is tunneled.
 */
enum class SplitMode { OFF, ALLOWLIST, DENYLIST }

data class SplitTunnelConfig(
    val mode: SplitMode = SplitMode.OFF,
    val packages: Set<String> = emptySet(),
)

/** A user-facing installed app. */
data class AppInfo(val packageName: String, val label: String)

/** Persists the split-tunnel policy in SharedPreferences. */
class SplitTunnelStore(context: Context) {
    private val prefs = context.getSharedPreferences("outline_split", Context.MODE_PRIVATE)

    fun load(): SplitTunnelConfig {
        val mode = runCatching { SplitMode.valueOf(prefs.getString(KEY_MODE, SplitMode.OFF.name)!!) }
            .getOrDefault(SplitMode.OFF)
        val packages = prefs.getStringSet(KEY_PACKAGES, emptySet()).orEmpty().toSet()
        return SplitTunnelConfig(mode, packages)
    }

    fun save(config: SplitTunnelConfig) {
        prefs.edit()
            .putString(KEY_MODE, config.mode.name)
            .putStringSet(KEY_PACKAGES, config.packages)
            .apply()
    }

    companion object {
        private const val KEY_MODE = "mode"
        private const val KEY_PACKAGES = "packages"
    }
}

/**
 * Launchable (user-facing) apps, excluding this app. Requires the
 * QUERY_ALL_PACKAGES permission to be complete on Android 11+. Call off the
 * main thread — it touches PackageManager for every installed app.
 */
fun loadLaunchableApps(context: Context): List<AppInfo> {
    val pm = context.packageManager
    val intent = Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER)
    return pm.queryIntentActivities(intent, 0)
        .mapNotNull { resolve ->
            val pkg = resolve.activityInfo.packageName
            if (pkg == context.packageName) null
            else AppInfo(pkg, resolve.loadLabel(pm).toString())
        }
        .distinctBy { it.packageName }
        .sortedBy { it.label.lowercase() }
}
