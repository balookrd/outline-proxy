package com.outline.proxy

import android.content.Context

/**
 * User-configured network automation preferences.
 */
data class AutomationConfig(
    val pauseOnAirplaneMode: Boolean = true,
    val wifiAutomationEnabled: Boolean = false,
    val wifiMode: WifiRuleMode = WifiRuleMode.PAUSE_ON_SELECTED,
    val trustedSsids: Set<String> = emptySet(),
)

/**
 * Persists network automation settings in SharedPreferences.
 */
class AutomationStore(context: Context) {
    private val prefs = context.getSharedPreferences("outline_automation", Context.MODE_PRIVATE)

    fun load(): AutomationConfig {
        val pauseAirplane = prefs.getBoolean(KEY_PAUSE_AIRPLANE, true)
        val wifiEnabled = prefs.getBoolean(KEY_WIFI_ENABLED, false)
        val wifiModeStr = prefs.getString(KEY_WIFI_MODE, WifiRuleMode.PAUSE_ON_SELECTED.name)
        val wifiMode = runCatching { WifiRuleMode.valueOf(wifiModeStr!!) }
            .getOrDefault(WifiRuleMode.PAUSE_ON_SELECTED)
        val ssids = prefs.getStringSet(KEY_TRUSTED_SSIDS, emptySet()) ?: emptySet()
        return AutomationConfig(
            pauseOnAirplaneMode = pauseAirplane,
            wifiAutomationEnabled = wifiEnabled,
            wifiMode = wifiMode,
            trustedSsids = ssids,
        )
    }

    fun save(config: AutomationConfig) {
        prefs.edit()
            .putBoolean(KEY_PAUSE_AIRPLANE, config.pauseOnAirplaneMode)
            .putBoolean(KEY_WIFI_ENABLED, config.wifiAutomationEnabled)
            .putString(KEY_WIFI_MODE, config.wifiMode.name)
            .putStringSet(KEY_TRUSTED_SSIDS, config.trustedSsids)
            .apply()
    }

    fun addSsid(rawSsid: String): Boolean {
        val clean = AutomationPolicy.normalizeSsid(rawSsid) ?: return false
        val current = load()
        if (current.trustedSsids.contains(clean)) return false
        save(current.copy(trustedSsids = current.trustedSsids + clean))
        return true
    }

    fun removeSsid(rawSsid: String) {
        val clean = AutomationPolicy.normalizeSsid(rawSsid) ?: rawSsid.trim()
        val current = load()
        save(current.copy(trustedSsids = current.trustedSsids - clean))
    }

    fun setPauseOnAirplaneMode(enabled: Boolean) {
        save(load().copy(pauseOnAirplaneMode = enabled))
    }

    fun setWifiAutomationEnabled(enabled: Boolean) {
        save(load().copy(wifiAutomationEnabled = enabled))
    }

    fun setWifiMode(mode: WifiRuleMode) {
        save(load().copy(wifiMode = mode))
    }

    private companion object {
        const val KEY_PAUSE_AIRPLANE = "pause_on_airplane"
        const val KEY_WIFI_ENABLED = "wifi_automation_enabled"
        const val KEY_WIFI_MODE = "wifi_rule_mode"
        const val KEY_TRUSTED_SSIDS = "trusted_ssids"
    }
}
