package com.outline.proxy.keepalive

import android.app.AlarmManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.SystemClock
import android.util.Log
import com.outline.proxy.KeepAlivePolicy

/**
 * The fast half of the watchdog pair. Unlike WorkManager it pierces Doze and has
 * no 15-minute floor, and it re-arms itself on every fire — so a process that
 * was killed resumes checking as soon as one alarm lands.
 */
object WatchdogAlarm {

    private const val TAG = "KeepAlive"
    private const val REQUEST_CODE = 42

    fun schedule(context: Context, delayMs: Long = KeepAlivePolicy.BASE_DELAY_MS) {
        val manager = context.getSystemService(AlarmManager::class.java) ?: return
        val triggerAt = SystemClock.elapsedRealtime() + delayMs
        val pendingIntent = pendingIntent(context)

        val canBeExact =
            Build.VERSION.SDK_INT < Build.VERSION_CODES.S || manager.canScheduleExactAlarms()
        try {
            if (canBeExact) {
                manager.setExactAndAllowWhileIdle(
                    AlarmManager.ELAPSED_REALTIME_WAKEUP,
                    triggerAt,
                    pendingIntent,
                )
            } else {
                // Inexact still fires, just with the system's own batching slack.
                manager.setAndAllowWhileIdle(
                    AlarmManager.ELAPSED_REALTIME_WAKEUP,
                    triggerAt,
                    pendingIntent,
                )
            }
        } catch (e: SecurityException) {
            Log.w(TAG, "exact alarm denied, falling back to inexact", e)
            manager.setAndAllowWhileIdle(
                AlarmManager.ELAPSED_REALTIME_WAKEUP,
                triggerAt,
                pendingIntent,
            )
        }
    }

    fun cancel(context: Context) {
        val manager = context.getSystemService(AlarmManager::class.java) ?: return
        manager.cancel(pendingIntent(context))
    }

    private fun pendingIntent(context: Context): PendingIntent = PendingIntent.getBroadcast(
        context,
        REQUEST_CODE,
        Intent(context, WatchdogReceiver::class.java),
        PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
    )
}
