package com.outline.proxy

import android.content.Context

/**
 * Runtime bookkeeping for network automation pause states, persisted across
 * process restarts and service reconstructions.
 */
class AutomationState(context: Context) {
    private val prefs = context.getSharedPreferences("outline_automation_state", Context.MODE_PRIVATE)

    /** Whether the tunnel was paused due to airplane mode. */
    var pausedByAirplane: Boolean
        get() = prefs.getBoolean(KEY_PAUSED_AIRPLANE, false)
        set(value) = prefs.edit().putBoolean(KEY_PAUSED_AIRPLANE, value).apply()

    /** Whether the tunnel was paused due to connected trusted/selected Wi-Fi. */
    var pausedByWifi: Boolean
        get() = prefs.getBoolean(KEY_PAUSED_WIFI, false)
        set(value) = prefs.edit().putBoolean(KEY_PAUSED_WIFI, value).apply()

    /**
     * If the user explicitly hit "Connect" while connected to this SSID,
     * auto-pause is suppressed until the device moves to a different network.
     */
    var manualOverrideSsid: String?
        get() = prefs.getString(KEY_OVERRIDE_SSID, null)
        set(value) = prefs.edit().putString(KEY_OVERRIDE_SSID, value).apply()

    /**
     * Whether the user explicitly chose to run the tunnel on the currently active network,
     * overriding auto-pause until network changes or disconnects.
     * Unlike [manualOverrideSsid], this does not depend on Android resolving the SSID string.
     */
    var manualOverrideActive: Boolean
        get() = prefs.getBoolean(KEY_MANUAL_OVERRIDE_ACTIVE, false)
        set(value) = prefs.edit().putBoolean(KEY_MANUAL_OVERRIDE_ACTIVE, value).apply()

    /** The SSID on which the tunnel was paused, retained for verification across restarts. */
    var pausedWifiSsid: String?
        get() = prefs.getString(KEY_PAUSED_WIFI_SSID, null)
        set(value) = prefs.edit().putString(KEY_PAUSED_WIFI_SSID, value).apply()

    /** Last known normalized Wi-Fi SSID seen by the network monitor. */
    var lastSeenWifiSsid: String?
        get() = prefs.getString(KEY_LAST_SEEN_SSID, null)
        set(value) = prefs.edit().putString(KEY_LAST_SEEN_SSID, value).apply()

    /**
     * Clear pause flags, called when the user deliberately disconnects or connects.
     */
    fun clearPauseFlags() {
        prefs.edit()
            .putBoolean(KEY_PAUSED_AIRPLANE, false)
            .putBoolean(KEY_PAUSED_WIFI, false)
            .remove(KEY_PAUSED_WIFI_SSID)
            .apply()
    }

    /**
     * Clear the manual override flags when disconnecting or switching networks.
     */
    fun clearOverride() {
        prefs.edit()
            .putBoolean(KEY_MANUAL_OVERRIDE_ACTIVE, false)
            .remove(KEY_OVERRIDE_SSID)
            .apply()
    }

    private companion object {
        const val KEY_PAUSED_AIRPLANE = "paused_by_airplane"
        const val KEY_PAUSED_WIFI = "paused_by_wifi"
        const val KEY_PAUSED_WIFI_SSID = "paused_wifi_ssid"
        const val KEY_OVERRIDE_SSID = "manual_override_ssid"
        const val KEY_MANUAL_OVERRIDE_ACTIVE = "manual_override_active"
        const val KEY_LAST_SEEN_SSID = "last_seen_ssid"
    }
}
