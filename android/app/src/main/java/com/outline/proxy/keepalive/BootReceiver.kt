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

    override fun onReceive(context: Context, intent: Intent) {
        if (!KeepAliveState(context).shouldRun) return

        Log.i(TAG, "restoring the tunnel after ${intent.action}")
        OutlineVpnService.ensure(context)
        WatchdogAlarm.schedule(context, FIRST_CHECK_DELAY_MS)
        WatchdogWorker.schedule(context)
    }

    private companion object {
        const val TAG = "KeepAlive"
        const val FIRST_CHECK_DELAY_MS = 30_000L
    }
}
