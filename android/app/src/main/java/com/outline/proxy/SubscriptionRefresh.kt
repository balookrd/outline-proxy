package com.outline.proxy

import android.content.Context
import android.util.Log
import kotlinx.coroutines.TimeoutCancellationException
import kotlinx.coroutines.withTimeout
import java.util.concurrent.TimeUnit

/**
 * On-demand subscription refresh, used on the connect path.
 *
 * The periodic [SubscriptionWorker] keeps subscriptions fresh in the
 * background, but WorkManager only guarantees the job runs *eventually*: a
 * doze-heavy or long-idle device can reach a connect with a config well past
 * its refresh interval, and would then dial with stale servers. So a connect
 * first brings an expired subscription up to date.
 *
 * The fetch is strictly best-effort: on any failure (offline — the common case,
 * since the tunnel is down precisely when the user is trying to connect — DNS,
 * HTTP error, malformed body) the locally cached config is used unchanged. A
 * connect must never be blocked by a refresh.
 */
object SubscriptionRefresh {

    private const val TAG = "SubscriptionRefresh"

    private val MAX_AGE_MS = TimeUnit.HOURS.toMillis(SubscriptionWorker.REFRESH_PERIOD_HOURS)

    /**
     * Budget for the pre-connect fetch. `ConfigFetcher` allows 15s connect +
     * 15s read, which on a dead network would stall the connect for half a
     * minute; the user is waiting on a button press, so cap it well below that
     * and fall back to the cached config when it runs out.
     */
    private const val FETCH_BUDGET_MS = 4_000L

    /** Whether [profile] is a subscription whose cached config is past its refresh interval. */
    fun isExpired(profile: ServerProfile, nowMs: Long = System.currentTimeMillis()): Boolean =
        profile.isSubscription && (nowMs - profile.updatedAt) >= MAX_AGE_MS

    /**
     * Return the config to connect with, refreshing an expired subscription
     * first. Persists a successful fetch so the rest of the app (and the next
     * connect) sees the new config; falls back to [ServerProfile.toToml] — the
     * cached config — when the profile is fresh, is not a subscription, or the
     * fetch fails.
     */
    suspend fun configForConnect(context: Context, profile: ServerProfile): String {
        if (!isExpired(profile)) return profile.toToml()

        val result = try {
            withTimeout(FETCH_BUDGET_MS) { ConfigFetcher.fetch(profile.configUrl) }
        } catch (_: TimeoutCancellationException) {
            Log.w(TAG, "refresh timed out for '${profile.name}'; using cached config")
            return profile.toToml()
        }

        return when (result) {
            is FetchResult.Success -> {
                persist(context, profile, result.toml)
                Log.i(TAG, "refreshed expired subscription '${profile.name}' before connect")
                result.toml
            }
            is FetchResult.Failure -> {
                // Offline is the expected case here; the cached config is what
                // makes a connect possible at all.
                Log.w(TAG, "using cached config for '${profile.name}': ${result.reason}")
                profile.toToml()
            }
        }
    }

    /** Write the freshly fetched config back to the store, leaving other profiles alone. */
    private fun persist(context: Context, profile: ServerProfile, toml: String) {
        val store = ProfileStore(context)
        val profiles = store.load()
        val index = profiles.indexOfFirst { it.id == profile.id }
        if (index < 0) return
        val updated = profiles.toMutableList()
        updated[index] = profiles[index].copy(cachedToml = toml, updatedAt = System.currentTimeMillis())
        store.save(updated)
    }
}
