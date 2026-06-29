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

    companion object {
        private const val KEY_PROFILES = "profiles"
        private const val KEY_SELECTED = "selected_id"
    }
}
