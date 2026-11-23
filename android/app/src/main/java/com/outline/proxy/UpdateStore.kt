package com.outline.proxy

import android.content.Context

/**
 * Persists update check timestamps, cached available release metadata, and
 * notification deduplication state in `outline_updates` SharedPreferences.
 */
class UpdateStore(context: Context) {
    private val prefs =
        context.applicationContext.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

    fun lastCheckMs(): Long = prefs.getLong(KEY_LAST_CHECK_MS, 0L)

    fun recordCheck(nowMs: Long) {
        prefs.edit().putLong(KEY_LAST_CHECK_MS, nowMs).apply()
    }

    fun loadAvailable(currentBuildId: String): UpdateChecker.Result.Available? {
        val cachedBuildId = prefs.getString(KEY_CACHED_BUILD_ID, null)
        if (!UpdateSchedule.isCachedUpdateValid(cachedBuildId, currentBuildId)) {
            if (!cachedBuildId.isNullOrBlank()) {
                clearAvailable()
            }
            return null
        }
        val label = prefs.getString(KEY_AVAIL_LABEL, null)?.takeIf { it.isNotBlank() } ?: return null
        val assetName =
            prefs.getString(KEY_AVAIL_ASSET_NAME, null)?.takeIf { it.isNotBlank() } ?: return null
        val url = prefs.getString(KEY_AVAIL_URL, null)?.takeIf { it.isNotBlank() } ?: return null
        val notes = prefs.getString(KEY_AVAIL_NOTES, "") ?: ""
        return UpdateChecker.Result.Available(
            label = label,
            assetName = assetName,
            url = url,
            notes = notes,
        )
    }

    fun saveAvailable(update: UpdateChecker.Result.Available, currentBuildId: String) {
        prefs.edit()
            .putString(KEY_CACHED_BUILD_ID, currentBuildId)
            .putString(KEY_AVAIL_LABEL, update.label)
            .putString(KEY_AVAIL_ASSET_NAME, update.assetName)
            .putString(KEY_AVAIL_URL, update.url)
            .putString(KEY_AVAIL_NOTES, update.notes)
            .apply()
    }

    fun clearAvailable() {
        prefs.edit()
            .remove(KEY_CACHED_BUILD_ID)
            .remove(KEY_AVAIL_LABEL)
            .remove(KEY_AVAIL_ASSET_NAME)
            .remove(KEY_AVAIL_URL)
            .remove(KEY_AVAIL_NOTES)
            .remove(KEY_LAST_NOTIFIED_LABEL)
            .apply()
    }

    /**
     * Clears any cached update state if the installed app build changed since it was stored.
     * Returns true if stale state was detected and cleared.
     */
    fun clearIfBuildChanged(currentBuildId: String): Boolean {
        val cachedBuildId = prefs.getString(KEY_CACHED_BUILD_ID, null) ?: return false
        if (cachedBuildId != currentBuildId) {
            clearAvailable()
            return true
        }
        return false
    }

    fun lastNotifiedLabel(): String? = prefs.getString(KEY_LAST_NOTIFIED_LABEL, null)

    fun markNotified(label: String) {
        prefs.edit().putString(KEY_LAST_NOTIFIED_LABEL, label).apply()
    }

    private companion object {
        const val PREFS_NAME = "outline_updates"
        const val KEY_LAST_CHECK_MS = "last_check_ms"
        const val KEY_CACHED_BUILD_ID = "cached_build_id"
        const val KEY_AVAIL_LABEL = "avail_label"
        const val KEY_AVAIL_ASSET_NAME = "avail_asset_name"
        const val KEY_AVAIL_URL = "avail_url"
        const val KEY_AVAIL_NOTES = "avail_notes"
        const val KEY_LAST_NOTIFIED_LABEL = "last_notified_label"
    }
}
