package com.outline.proxy

import android.app.Activity
import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import android.util.Log
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.result.contract.ActivityResultContracts

/**
 * Entry point for external control over the `outline://` URI scheme — see
 * [parseControlUri] for the grammar.
 *
 * Invisible by design: it runs the command and finishes, so automation looks
 * like nothing happened (the foreground-service notification is the status
 * indicator). Only refusals raise a [Toast].
 *
 * It has to be an Activity rather than a receiver or an exported service: the
 * system VPN consent dialog needs one to launch from, and Android 12+ forbids
 * starting a foreground service from the background — being on screen (however
 * transparently) is what makes the service start legal.
 */
class ControlActivity : ComponentActivity() {

    /** Config waiting for the VPN consent dialog to come back. */
    private var pendingConfig: String? = null

    private val vpnConsentLauncher =
        registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
            val config = pendingConfig
            pendingConfig = null
            if (result.resultCode == Activity.RESULT_OK && config != null) {
                OutlineVpnService.requestConnect(this, config)
            } else {
                refuse("VPN permission denied")
            }
            finish()
        }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        run(intent)
    }

    private fun run(intent: Intent?) {
        when (val parsed = parseControlUri(intent?.data?.toString())) {
            is ControlUri.Invalid -> {
                refuse(message(parsed.reason))
                finish()
            }

            is ControlUri.Valid -> {
                val denied = checkAccess(parsed.token, ExternalControlStore(this).load())
                if (denied != null) {
                    refuse(message(denied))
                    finish()
                    return
                }
                execute(parsed.command)
            }
        }
    }

    private fun execute(command: ControlCommand) {
        when (command) {
            is ControlCommand.Disconnect -> {
                OutlineVpnService.requestDisconnect(this)
                finish()
            }

            is ControlCommand.Connect -> connect(command.profile)

            is ControlCommand.Toggle -> {
                if (OutlineVpnService.isActive()) {
                    OutlineVpnService.requestDisconnect(this)
                    finish()
                } else {
                    connect(command.profile)
                }
            }
        }
    }

    /**
     * Resolve the profile and bring the tunnel up, asking for VPN consent first
     * if the user has never granted it (or revoked it since).
     */
    private fun connect(selector: String?) {
        val store = ProfileStore(this)
        val profile = resolveProfile(store.load(), selector, store.selectedId)
        if (profile == null) {
            refuse(
                if (selector == null) "No server configured"
                else "Unknown server: $selector",
            )
            finish()
            return
        }
        // Keep the UI's selection in step with what is actually running,
        // otherwise the server list claims a profile that is not the live one.
        store.selectedId = profile.id

        val configToml = profile.toToml()
        val consent = VpnService.prepare(this)
        if (consent == null) {
            OutlineVpnService.requestConnect(this, configToml)
            finish()
        } else {
            // finish() is deferred to the consent callback.
            pendingConfig = configToml
            vpnConsentLauncher.launch(consent)
        }
    }

    private fun refuse(reason: String) {
        Log.w(TAG, "external control refused: $reason")
        Toast.makeText(this, reason, Toast.LENGTH_SHORT).show()
    }

    private fun message(reason: RejectReason): String = when (reason) {
        RejectReason.NOT_A_CONTROL_URI -> "Not an outline:// command"
        RejectReason.UNKNOWN_COMMAND -> "Unknown outline:// command"
        RejectReason.DISABLED -> "External control is disabled in Outline Proxy"
        RejectReason.BAD_TOKEN -> "External control: wrong token"
    }

    private companion object {
        const val TAG = "OutlineControl"
    }
}
