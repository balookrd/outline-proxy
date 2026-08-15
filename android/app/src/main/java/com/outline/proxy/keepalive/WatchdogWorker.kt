package com.outline.proxy.keepalive

import android.content.Context
import android.util.Log
import androidx.work.CoroutineWorker
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.WorkerParameters
import com.outline.proxy.KeepAliveState
import com.outline.proxy.OutlineVpnService
import java.util.concurrent.TimeUnit

/**
 * The slow half of the watchdog pair. WorkManager's schedule is persisted by the
 * framework and restored after reboot, so it covers the case where every alarm
 * of ours was wiped — at the cost of a 15-minute minimum period.
 */
class WatchdogWorker(
    context: Context,
    params: WorkerParameters,
) : CoroutineWorker(context, params) {

    override suspend fun doWork(): Result {
        if (KeepAliveState(applicationContext).shouldRun) {
            OutlineVpnService.ensure(applicationContext)
            // Alarms do not survive every OEM cleanup; re-arm from here as well.
            WatchdogAlarm.schedule(applicationContext)
        }
        return Result.success()
    }

    companion object {
        private const val TAG = "KeepAlive"
        private const val WORK_NAME = "outline-watchdog"

        fun schedule(context: Context) {
            val request = PeriodicWorkRequestBuilder<WatchdogWorker>(15, TimeUnit.MINUTES)
                .addTag(WORK_NAME)
                .build()
            runCatching {
                WorkManager.getInstance(context).enqueueUniquePeriodicWork(
                    WORK_NAME,
                    ExistingPeriodicWorkPolicy.UPDATE,
                    request,
                )
            }.onFailure {
                // WorkManager is unavailable before the user unlocks the device.
                Log.w(TAG, "could not schedule the periodic watchdog", it)
            }
        }

        fun cancel(context: Context) {
            runCatching { WorkManager.getInstance(context).cancelUniqueWork(WORK_NAME) }
        }
    }
}
