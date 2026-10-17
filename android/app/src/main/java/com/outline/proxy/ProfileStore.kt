package com.outline.proxy

import android.content.Context

/**
 * Persists the list of [ServerProfile]s and the selected profile id in
 * SharedPreferences as a JSON blob. Synchronous and tiny — fine for a handful
 * of profiles.
 */
class ProfileStore(context: Context) {
    private val prefs = context.getSharedPreferences("outline_profiles", Context.MODE_PRIVATE)

    fun load(): List<ServerProfile> =
        ServerProfile.listFromJson(prefs.getString(KEY_PROFILES, null))

    fun save(profiles: List<ServerProfile>) {
        prefs.edit().putString(KEY_PROFILES, ServerProfile.listToJson(profiles)).apply()
    }

    var selectedId: String?
        get() = prefs.getString(KEY_SELECTED, null)
        set(value) = prefs.edit().putString(KEY_SELECTED, value).apply()

    /**
     * Whether all tunnels should be forced to run over TCP (h2/h1) without HTTP/3 (QUIC/UDP).
     * Global setting for networks where UDP/QUIC traffic is blocked or throttled.
     */
    var tcpOnly: Boolean
        get() = prefs.getBoolean(KEY_TCP_ONLY, false)
        set(value) = prefs.edit().putBoolean(KEY_TCP_ONLY, value).apply()

    fun selectedProfile(): ServerProfile? {
        val id = selectedId ?: return null
        return load().find { it.id == id }
    }

    companion object {
        private const val KEY_PROFILES = "profiles"
        private const val KEY_SELECTED = "selected_id"
        private const val KEY_TCP_ONLY = "tcp_only"
    }
}
