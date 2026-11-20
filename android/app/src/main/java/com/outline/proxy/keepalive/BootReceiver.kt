package com.outline.proxy.keepalive

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.util.Log
import com.outline.proxy.KeepAliveState
import com.outline.proxy.OutlineVpnService

/**
 * Brings the tunnel back after a reboot or an app update.
 *
 * Not direct-boot aware on purpose: the profiles hold server credentials and
 * stay in credential-protected storage, so there is nothing to read before the
 * user unlocks. BOOT_COMPLETED already arrives after unlock.
 */
class BootReceiver : BroadcastReceiver() {

    override fun onReceive(context: Context, intent: Intent?) {
        val action = intent?.action ?: return
        if (action != Intent.ACTION_BOOT_COMPLETED &&
            action != ACTION_QUICKBOOT_POWERON &&
            action != Intent.ACTION_MY_PACKAGE_REPLACED
        ) {
            Log.w(TAG, "ignoring unexpected broadcast action: $action")
            return
        }

        if (!KeepAliveState(context).shouldRun) return

        Log.i(TAG, "restoring the tunnel after $action")
        OutlineVpnService.ensure(context)
        WatchdogAlarm.schedule(context, FIRST_CHECK_DELAY_MS)
        WatchdogWorker.schedule(context)
    }

    private companion object {
        const val TAG = "KeepAlive"
        const val FIRST_CHECK_DELAY_MS = 30_000L
        const val ACTION_QUICKBOOT_POWERON = "android.intent.action.QUICKBOOT_POWERON"
    }
}
