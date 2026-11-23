package com.outline.proxy

import android.Manifest
import android.annotation.SuppressLint
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import androidx.core.content.ContextCompat

/**
 * Posts and dismisses the one-shot system notification shown when a background
 * weekly check finds a newer release.
 */
object UpdateNotification {
    const val CHANNEL_ID = "outline_updates"
    const val NOTIFICATION_ID = 3
    const val EXTRA_OPEN_UPDATE = "com.outline.proxy.OPEN_UPDATE"

    @SuppressLint("MissingPermission")
    fun show(context: Context, update: UpdateChecker.Result.Available): Boolean {
        val appCtx = context.applicationContext
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            val granted = ContextCompat.checkSelfPermission(
                appCtx,
                Manifest.permission.POST_NOTIFICATIONS,
            ) == PackageManager.PERMISSION_GRANTED
            if (!granted) return false
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val manager = appCtx.getSystemService(NotificationManager::class.java)
            manager?.createNotificationChannel(
                NotificationChannel(
                    CHANNEL_ID,
                    appCtx.getString(R.string.notif_channel_updates),
                    NotificationManager.IMPORTANCE_DEFAULT,
                ),
            )
        }

        val openIntent = Intent(appCtx, MainActivity::class.java).apply {
            putExtra(EXTRA_OPEN_UPDATE, true)
            addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP or Intent.FLAG_ACTIVITY_CLEAR_TOP)
        }
        val pendingIntent = PendingIntent.getActivity(
            appCtx,
            NOTIFICATION_ID,
            openIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )

        val notification = NotificationCompat.Builder(appCtx, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_stat_tunnel)
            .setContentTitle(appCtx.getString(R.string.upd_notif_title))
            .setContentText(appCtx.getString(R.string.upd_notif_text, update.label))
            .setPriority(NotificationCompat.PRIORITY_DEFAULT)
            .setAutoCancel(true)
            .setContentIntent(pendingIntent)
            .build()

        return runCatching {
            NotificationManagerCompat.from(appCtx).notify(NOTIFICATION_ID, notification)
            true
        }.getOrDefault(false)
    }

    fun cancel(context: Context) {
        runCatching { NotificationManagerCompat.from(context.applicationContext).cancel(NOTIFICATION_ID) }
    }
}
