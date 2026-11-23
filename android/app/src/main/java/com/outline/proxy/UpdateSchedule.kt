package com.outline.proxy

/**
 * Pure scheduling, notification-deduplication, and cache-validity rules for
 * background update checks on Android.
 *
 * Kept free of Android framework types so it can be unit-tested on the host JVM.
 */
object UpdateSchedule {
    /** How often the periodic background worker hits GitHub once the previous check succeeded. */
    const val WEEKLY_INTERVAL_MS: Long = 7L * 24 * 60 * 60 * 1000

    /** How often WorkManager wakes up to check whether a weekly check is due. */
    const val WORKER_PERIOD_HOURS: Long = 24L

    /** Delay after cold launch before running the silent startup check. */
    const val STARTUP_DELAY_MS: Long = 5_000L

    /**
     * Returns true when a periodic background check should query GitHub.
     *
     * Treats `lastCheckMs <= 0` (never checked) and `nowMs < lastCheckMs` (clock moved
     * backwards) as due so the schedule never stalls indefinitely.
     */
    fun isPeriodicCheckDue(
        lastCheckMs: Long,
        nowMs: Long,
        intervalMs: Long = WEEKLY_INTERVAL_MS,
    ): Boolean {
        if (lastCheckMs <= 0L) return true
        if (nowMs < lastCheckMs) return true
        return (nowMs - lastCheckMs) >= intervalMs
    }

    /**
     * Returns true if a system notification should be posted for [availableLabel].
     * Suppresses duplicate alerts when the user has already been notified for the same version.
     */
    fun shouldNotify(availableLabel: String, lastNotifiedLabel: String?): Boolean =
        availableLabel.isNotBlank() && availableLabel != lastNotifiedLabel

    /** Stable identifier for the currently running build to invalidate stale cached updates. */
    fun currentBuildId(channel: String, versionName: String, gitSha: String): String =
        "$channel:$versionName:$gitSha"

    /** Returns true when a cached available update belongs to [currentBuildId]. */
    fun isCachedUpdateValid(cachedBuildId: String?, currentBuildId: String): Boolean =
        !cachedBuildId.isNullOrBlank() && cachedBuildId == currentBuildId
}
