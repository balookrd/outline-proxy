package com.outline.proxy

import android.content.Context
import android.util.Log
import androidx.work.CoroutineWorker
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.WorkerParameters
import java.util.concurrent.TimeUnit

/**
 * Refreshes every subscription profile's cached config on a schedule, the way
 * Happ keeps a subscription current.
 *
 * A failed fetch leaves that profile's cache untouched — a temporarily
 * unreachable source must never blank out a working config, and the running
 * tunnel is not disturbed either (it reads the cache only at connect time).
 */
class SubscriptionWorker(
    context: Context,
    params: WorkerParameters,
) : CoroutineWorker(context, params) {

    override suspend fun doWork(): Result {
        val store = ProfileStore(applicationContext)
        val profiles = store.load()
        if (profiles.none { it.isSubscription }) return Result.success()

        var changed = false
        val updated = profiles.map { profile ->
            if (!profile.isSubscription) return@map profile
            when (val result = ConfigFetcher.fetch(profile.configUrl)) {
                is FetchResult.Success -> {
                    changed = true
                    profile.copy(cachedToml = result.toml, updatedAt = nowMs())
                }
                is FetchResult.Failure -> {
                    Log.w(TAG, "keeping cached config for '${profile.name}': ${result.reason}")
                    profile
                }
            }
        }
        if (changed) store.save(updated)
        return Result.success()
    }

    // Wrapped so the one clock call in this class is easy to find; workers have
    // no injected time source here.
    private fun nowMs(): Long = System.currentTimeMillis()

    companion object {
        private const val TAG = "SubscriptionWorker"
        private const val WORK_NAME = "outline-subscription"
        private const val PERIOD_HOURS = 12L

        /** Idempotent: safe to call on every save; keeps a single periodic work. */
        fun schedule(context: Context) {
            val request = PeriodicWorkRequestBuilder<SubscriptionWorker>(PERIOD_HOURS, TimeUnit.HOURS)
                .addTag(WORK_NAME)
                .build()
            runCatching {
                WorkManager.getInstance(context).enqueueUniquePeriodicWork(
                    WORK_NAME,
                    ExistingPeriodicWorkPolicy.KEEP,
                    request,
                )
            }.onFailure { Log.w(TAG, "could not schedule subscription refresh", it) }
        }

        fun cancel(context: Context) {
            runCatching { WorkManager.getInstance(context).cancelUniqueWork(WORK_NAME) }
        }
    }
}
