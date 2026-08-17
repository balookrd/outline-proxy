package com.outline.proxy

import android.content.Context

/**
 * What the user wants (not what is happening) plus the bookkeeping the watchdogs
 * need. Separate from [ProfileStore]: that one holds configuration, this one
 * holds intent, and the revival chain reads intent from processes that never
 * touch the UI.
 */
class KeepAliveState(context: Context) {
    private val prefs = context.getSharedPreferences("outline_keepalive", Context.MODE_PRIVATE)

    /** The user asked for a tunnel and has not asked for it to stop. */
    var shouldRun: Boolean
        get() = prefs.getBoolean(KEY_SHOULD_RUN, false)
        set(value) = prefs.edit().putBoolean(KEY_SHOULD_RUN, value).apply()

    var consecutiveFailures: Int
        get() = prefs.getInt(KEY_FAILURES, 0)
        set(value) = prefs.edit().putInt(KEY_FAILURES, value).apply()

    /**
     * When the current tunnel came up (epoch ms), or 0 when down. Persisted so the
     * Home screen can show the connection duration even after the Activity was
     * recreated while the tunnel kept running.
     */
    var connectedSince: Long
        get() = prefs.getLong(KEY_CONNECTED_SINCE, 0L)
        set(value) = prefs.edit().putLong(KEY_CONNECTED_SINCE, value).apply()

    /**
     * Last known `VpnService.isAlwaysOn()`, or null before the tunnel has ever
     * come up. Only the service can read it, so the UI shows what was recorded
     * rather than guessing.
     */
    var alwaysOnSeen: Boolean?
        get() = when (prefs.getInt(KEY_ALWAYS_ON, ALWAYS_ON_UNKNOWN)) {
            1 -> true
            0 -> false
            else -> null
        }
        set(value) = prefs.edit()
            .putInt(KEY_ALWAYS_ON, if (value == null) ALWAYS_ON_UNKNOWN else if (value) 1 else 0)
            .apply()

    fun recordFailure(): Int = (consecutiveFailures + 1).also { consecutiveFailures = it }

    fun clearFailures() {
        consecutiveFailures = 0
    }

    private companion object {
        const val KEY_SHOULD_RUN = "should_run"
        const val KEY_FAILURES = "consecutive_failures"
        const val KEY_ALWAYS_ON = "always_on_seen"
        const val KEY_CONNECTED_SINCE = "connected_since"
        const val ALWAYS_ON_UNKNOWN = -1
    }
}
