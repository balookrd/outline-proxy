package com.outline.proxy

import android.app.PendingIntent
import android.content.Intent
import android.graphics.drawable.Icon
import android.os.Build
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService

/**
 * A Quick Settings tile that toggles the tunnel straight from the QS panel,
 * mirroring the notification's toggle. Highlighted (active) while the core is up,
 * dim (inactive) while it is down.
 *
 * Connect goes through [QuickConnectActivity] so VPN consent can be shown the
 * first time; disconnect goes straight to [OutlineVpnService]. The action is
 * chosen from the live tunnel state via [NotificationPolicy.toggle], the same
 * decision the notification uses.
 *
 * The tile is not placed automatically — the user adds it from the QS editor (or
 * via an add-tile prompt). The system binds this service only while the panel is
 * visible, so the state is refreshed in [onStartListening] and again right after
 * a click.
 */
class OutlineTileService : TileService() {

    override fun onStartListening() {
        super.onStartListening()
        renderTile(OutlineVpnService.isActive())
    }

    override fun onClick() {
        super.onClick()
        when (NotificationPolicy.toggle(OutlineVpnService.isActive())) {
            NotifToggle.DISCONNECT -> {
                OutlineVpnService.requestDisconnect(this)
                // Disconnect is reliable and the panel stays open, so reflect it
                // at once rather than waiting for the next listening pass.
                renderTile(running = false)
            }
            NotifToggle.CONNECT -> startConnect()
        }
    }

    /**
     * Launch the shared connect entry point and collapse the panel behind it.
     * [QuickConnectActivity] resolves the selected profile, refreshes an expired
     * subscription and shows VPN consent when it is missing.
     */
    private fun startConnect() {
        val intent = Intent(this, QuickConnectActivity::class.java)
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            val pending = PendingIntent.getActivity(this, 3, intent, PendingIntent.FLAG_IMMUTABLE)
            startActivityAndCollapse(pending)
        } else {
            @Suppress("DEPRECATION")
            startActivityAndCollapse(intent)
        }
    }

    /** Paint the tile for [running]: active/inactive, with the selected server as
     *  the subtitle where the platform shows one (API 29+). */
    private fun renderTile(running: Boolean) {
        val tile = qsTile ?: return
        tile.state = if (running) Tile.STATE_ACTIVE else Tile.STATE_INACTIVE
        tile.label = "Outline"
        tile.icon = Icon.createWithResource(this, R.drawable.ic_stat_tunnel)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            val name = ProfileStore(this).let { store ->
                store.load().firstOrNull { it.id == store.selectedId }?.name
            }?.takeIf { it.isNotBlank() }
            tile.subtitle = name ?: getString(if (running) R.string.status_connected else R.string.status_disconnected)
        }
        tile.updateTile()
    }
}
