package com.outline.proxy

import android.app.Activity
import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.result.contract.ActivityResultContracts
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * The persistent notification's Connect action target. Invisible (translucent
 * theme) and `exported="false"`, so only our own notification can drive it —
 * unlike [ControlActivity] it is not gated by the external-control switch/token,
 * because it is a first-party surface rather than an outside caller.
 *
 * Mirrors [ControlActivity]'s connect path: resolve the UI-selected profile,
 * refresh an expired subscription, obtain VPN consent when it is missing, and
 * hand the config to [OutlineVpnService]. A tunnel that is already up (a race
 * with a stale notification) is left alone.
 */
class QuickConnectActivity : ComponentActivity() {

    /** Config waiting for the VPN consent dialog to come back. */
    private var pendingConfig: String? = null

    private val vpnConsentLauncher =
        registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
            val config = pendingConfig
            pendingConfig = null
            if (result.resultCode == Activity.RESULT_OK && config != null) {
                OutlineVpnService.requestConnect(this, config)
            } else {
                Toast.makeText(this, "VPN permission denied", Toast.LENGTH_SHORT).show()
            }
            finish()
        }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // The notification only shows Connect while the core is down; if it is
        // up (a stale banner, or a race), there is nothing to do.
        if (OutlineVpnService.isActive()) {
            finish()
            return
        }

        val store = ProfileStore(this)
        val profile = resolveProfile(store.load(), null, store.selectedId)
        if (profile == null) {
            Toast.makeText(this, "No server configured", Toast.LENGTH_SHORT).show()
            finish()
            return
        }
        // Keep the UI's selection in step with what is being connected.
        store.selectedId = profile.id

        // Refresh an expired subscription before dialling; finish() moves into
        // the coroutine so the activity outlives the fetch.
        lifecycleScope.launch {
            val configToml = withContext(Dispatchers.IO) {
                SubscriptionRefresh.configForConnect(this@QuickConnectActivity, profile)
            }
            if (configToml.isBlank()) {
                Toast.makeText(
                    this@QuickConnectActivity,
                    "No config yet — refresh the subscription first.",
                    Toast.LENGTH_LONG,
                ).show()
                finish()
                return@launch
            }
            val consent = VpnService.prepare(this@QuickConnectActivity)
            if (consent == null) {
                OutlineVpnService.requestConnect(this@QuickConnectActivity, configToml)
                finish()
            } else {
                // finish() is deferred to the consent callback.
                pendingConfig = configToml
                vpnConsentLauncher.launch(consent)
            }
        }
    }
}
