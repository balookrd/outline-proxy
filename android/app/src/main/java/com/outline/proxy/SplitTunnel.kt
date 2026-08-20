package com.outline.proxy

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build

/**
 * Per-app split-tunnel policy. Android forbids mixing allowed and disallowed
 * apps on one [android.net.VpnService.Builder], so exactly one list is applied
 * at a time — the one for the active [mode]. The two lists are stored and edited
 * independently, so switching modes never moves or drops a selection.
 *
 *  - [OFF]       : every app is tunneled (except this app itself).
 *  - [ALLOWLIST] : only [SplitTunnelConfig.allowPackages] are tunneled.
 *  - [DENYLIST]  : every app except [SplitTunnelConfig.denyPackages] (and this
 *                  app) is tunneled.
 */
enum class SplitMode { OFF, ALLOWLIST, DENYLIST }

data class SplitTunnelConfig(
    val mode: SplitMode = SplitMode.OFF,
    val allowPackages: Set<String> = emptySet(),
    val denyPackages: Set<String> = emptySet(),
)

/** A user-facing installed app. */
data class AppInfo(val packageName: String, val label: String)

/**
 * Minimal per-package facts the picker needs, kept free of PackageManager so the
 * filtering/sorting logic is unit-testable without a device.
 */
internal data class RawApp(
    val packageName: String,
    val label: String,
    val hasInternet: Boolean,
)

/** Persists the split-tunnel policy in SharedPreferences. */
class SplitTunnelStore(context: Context) {
    private val prefs = context.getSharedPreferences("outline_split", Context.MODE_PRIVATE)

    fun load(): SplitTunnelConfig {
        val mode = runCatching { SplitMode.valueOf(prefs.getString(KEY_MODE, SplitMode.OFF.name)!!) }
            .getOrDefault(SplitMode.OFF)
        // `null` means the key is absent, which lets a legacy single-list install
        // (only KEY_LEGACY_PACKAGES set) be told apart from a new-format install
        // whose list simply happens to be empty — the two migrate differently.
        val allow = readSet(KEY_ALLOW)
        val deny = readSet(KEY_DENY)
        val legacy = readSet(KEY_LEGACY_PACKAGES)
        return resolveSplitConfig(mode, allow, deny, legacy)
    }

    fun save(config: SplitTunnelConfig) {
        prefs.edit()
            .putString(KEY_MODE, config.mode.name)
            .putStringSet(KEY_ALLOW, config.allowPackages)
            .putStringSet(KEY_DENY, config.denyPackages)
            // Drop the legacy shared key once the split lists own the state.
            .remove(KEY_LEGACY_PACKAGES)
            .apply()
    }

    private fun readSet(key: String): Set<String>? =
        if (prefs.contains(key)) prefs.getStringSet(key, emptySet()).orEmpty().toSet() else null

    companion object {
        private const val KEY_MODE = "mode"
        private const val KEY_ALLOW = "allow_packages"
        private const val KEY_DENY = "deny_packages"
        private const val KEY_LEGACY_PACKAGES = "packages"
    }
}

/**
 * Resolve the two independent sets from the raw stored values. When the new keys
 * are absent but a legacy shared set exists, seed BOTH sets from it so the
 * pre-split selection is preserved exactly on upgrade; the sets diverge on the
 * first edit afterwards. `null` for a set means its key was absent.
 */
internal fun resolveSplitConfig(
    mode: SplitMode,
    allow: Set<String>?,
    deny: Set<String>?,
    legacy: Set<String>?,
): SplitTunnelConfig {
    val hasNew = allow != null || deny != null
    if (!hasNew && legacy != null) {
        return SplitTunnelConfig(mode, legacy, legacy)
    }
    return SplitTunnelConfig(mode, allow.orEmpty(), deny.orEmpty())
}

/**
 * Keep only network-capable apps (those with the INTERNET permission), excluding
 * this app; dedup by package and sort by label.
 */
internal fun filterNetworkApps(raw: List<RawApp>, selfPackage: String): List<AppInfo> =
    raw.asSequence()
        .filter { it.packageName != selfPackage }
        .filter { it.hasInternet }
        .map { AppInfo(it.packageName, it.label) }
        .distinctBy { it.packageName }
        .sortedBy { it.label.lowercase() }
        .toList()

/**
 * Installed apps that can reach the network (request the INTERNET permission),
 * excluding this app. Unlike a launcher-only query this includes Android Auto and
 * network-capable system apps that have no launcher icon. Relies on the
 * QUERY_ALL_PACKAGES permission (declared in the manifest) to be complete on
 * Android 11+. Call off the main thread — it touches PackageManager for every
 * installed app.
 */
fun loadNetworkApps(context: Context): List<AppInfo> {
    val pm = context.packageManager
    val packages = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
        pm.getInstalledPackages(
            PackageManager.PackageInfoFlags.of(PackageManager.GET_PERMISSIONS.toLong()),
        )
    } else {
        @Suppress("DEPRECATION")
        pm.getInstalledPackages(PackageManager.GET_PERMISSIONS)
    }
    val raw = packages.mapNotNull { pi ->
        val hasInternet = pi.requestedPermissions?.contains(Manifest.permission.INTERNET) == true
        // Skip the label lookup (which reads the app's resources) for apps that
        // can never carry traffic — they are dropped anyway.
        if (!hasInternet) return@mapNotNull null
        val appInfo = pi.applicationInfo ?: return@mapNotNull null
        RawApp(pi.packageName, appInfo.loadLabel(pm).toString(), true)
    }
    return filterNetworkApps(raw, context.packageName)
}
