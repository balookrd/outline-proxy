package com.outline.proxy.keepalive

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import com.outline.proxy.KeepAliveState
import com.outline.proxy.OutlineVpnService

class WatchdogReceiver : BroadcastReceiver() {

    override fun onReceive(context: Context, intent: Intent) {
        if (!KeepAliveState(context).shouldRun) {
            // The user stopped the tunnel on purpose: let the chain die here.
            return
        }
        // ensure() decides what to do and re-arms the alarm with the right delay,
        // so there is no scheduling to repeat here.
        OutlineVpnService.ensure(context)
    }
}
