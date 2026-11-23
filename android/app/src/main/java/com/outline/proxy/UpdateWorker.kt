package com.outline.proxy

import android.content.Context
import android.util.Log
import androidx.work.Constraints
import androidx.work.CoroutineWorker
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.NetworkType
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.WorkerParameters
import java.util.concurrent.TimeUnit

/**
 * Periodically wakes up on a connected network and checks GitHub for a newer
 * app build once at least 7 days have passed since the last successful check.
 */
class UpdateWorker(
    context: Context,
    params: WorkerParameters,
) : CoroutineWorker(context, params) {

    override suspend fun doWork(): Result {
        val appCtx = applicationContext
        val store = UpdateStore(appCtx)
        val buildId = UpdateCoordinator.currentBuildId()
        if (store.clearIfBuildChanged(buildId)) {
            UpdateNotification.cancel(appCtx)
        }

        val now = System.currentTimeMillis()
        if (!UpdateSchedule.isPeriodicCheckDue(store.lastCheckMs(), now)) {
            return Result.success()
        }

        when (val result = UpdateChecker.check()) {
            is UpdateChecker.Result.Available -> {
                store.recordCheck(now)
                store.saveAvailable(result, buildId)
                UpdateCoordinator.onBackgroundResult(appCtx, result)
                if (UpdateSchedule.shouldNotify(result.label, store.lastNotifiedLabel()) &&
                    UpdateNotification.show(appCtx, result)
                ) {
                    store.markNotified(result.label)
                }
            }
            UpdateChecker.Result.UpToDate -> {
                store.recordCheck(now)
                store.clearAvailable()
                UpdateNotification.cancel(appCtx)
                UpdateCoordinator.onBackgroundResult(appCtx, result)
            }
            is UpdateChecker.Result.Failed -> {
                Log.w(TAG, "periodic update check failed: ${result.reason}")
            }
        }

        return Result.success()
    }

    companion object {
        private const val TAG = "UpdateWorker"
        private const val WORK_NAME = "outline-update-check"

        /** Idempotent: keeps a single daily WorkManager trigger that enforces the weekly interval. */
        fun schedule(context: Context) {
            val constraints = Constraints.Builder()
                .setRequiredNetworkType(NetworkType.CONNECTED)
                .build()
            val request = PeriodicWorkRequestBuilder<UpdateWorker>(
                UpdateSchedule.WORKER_PERIOD_HOURS,
                TimeUnit.HOURS,
            )
                .setConstraints(constraints)
                .setInitialDelay(UpdateSchedule.WORKER_PERIOD_HOURS, TimeUnit.HOURS)
                .addTag(WORK_NAME)
                .build()
            runCatching {
                WorkManager.getInstance(context.applicationContext).enqueueUniquePeriodicWork(
                    WORK_NAME,
                    ExistingPeriodicWorkPolicy.KEEP,
                    request,
                )
            }.onFailure { Log.w(TAG, "could not schedule periodic update check", it) }
        }
    }
}
