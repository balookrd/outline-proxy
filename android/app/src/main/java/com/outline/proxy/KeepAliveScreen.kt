package com.outline.proxy

import android.Manifest
import android.app.StatusBarManager
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.graphics.drawable.Icon
import android.os.Build
import android.widget.Toast
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.MonitorHeart
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import com.outline.proxy.keepalive.KeepAliveHelper

private enum class GrantStatus { GRANTED, MISSING, UNKNOWN }

/**
 * The checklist of everything that keeps the tunnel alive but only the user can
 * grant. Statuses are re-read whenever [refresh] changes, since the user grants
 * them in system screens we get no result from.
 */
@Composable
fun KeepAliveScreen(onBack: () -> Unit) {
    val context = LocalContext.current
    var refresh by remember { mutableIntStateOf(0) }

    val keepAlive = remember { KeepAliveState(context) }
    var persistent by remember { mutableStateOf(keepAlive.persistentNotification) }

    val notifications = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestPermission(),
    ) { refresh++ }

    val phoneState = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestPermission(),
    ) { refresh++ }

    SubScreen(title = "Keeping Alive", icon = Icons.Filled.MonitorHeart, onBack = onBack) {
        Column(modifier = Modifier.verticalScroll(rememberScrollState())) {
            SectionCard(modifier = Modifier.padding(bottom = 16.dp)) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            "Persistent notification",
                            style = MaterialTheme.typography.titleMedium,
                            fontWeight = FontWeight.SemiBold,
                        )
                        Text(
                            "Keep a notification with a Connect/Disconnect button in the " +
                                "status bar, even when the VPN is off.",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            modifier = Modifier.padding(top = 4.dp),
                        )
                    }
                    Switch(
                        checked = persistent,
                        onCheckedChange = { on ->
                            persistent = on
                            keepAlive.persistentNotification = on
                            // Reflect it immediately while the tunnel is down: turning
                            // it on posts the standby banner, off removes it. A running
                            // tunnel already shows its banner and is left untouched.
                            if (!OutlineVpnService.isActive()) {
                                if (on) OutlineVpnService.enterStandby(context)
                                else OutlineVpnService.exitStandby(context)
                            }
                        },
                    )
                }
            }

            SectionCard(modifier = Modifier.padding(bottom = 16.dp)) {
                Column {
                    Text(
                        "Quick Settings tile",
                        style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.SemiBold,
                    )
                    Text(
                        "Toggle the tunnel straight from the Quick Settings panel.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.padding(top = 4.dp),
                    )
                    OutlinedButton(
                        onClick = { requestAddQsTile(context) },
                        shape = RoundedCornerShape(16.dp),
                        modifier = Modifier.padding(top = 12.dp),
                    ) {
                        Text("Add tile")
                    }
                }
            }

            Text(
                "Android and the phone vendor may stop background apps. These " +
                    "switches are what keeps the tunnel up.",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(bottom = 16.dp, start = 4.dp),
            )

            // Read so that bumping `refresh` re-runs the status queries below.
            @Suppress("UNUSED_EXPRESSION")
            refresh

            ChecklistItem(
                title = "Always-on VPN",
                status = when (KeepAliveState(context).alwaysOnSeen) {
                    true -> GrantStatus.GRANTED
                    false -> GrantStatus.MISSING
                    null -> GrantStatus.UNKNOWN
                },
                explanation = "The strongest option: the system itself keeps the tunnel up " +
                    "and restarts it. Turn on \"Always-on VPN\" for Outline Proxy in the VPN list.",
                action = "Open VPN settings",
                onAction = { context.launchSafely(KeepAliveHelper.vpnSettingsIntent()) },
            )

            ChecklistItem(
                title = "Ignore battery optimisation",
                status = if (KeepAliveHelper.isIgnoringBatteryOptimizations(context)) {
                    GrantStatus.GRANTED
                } else {
                    GrantStatus.MISSING
                },
                explanation = "Without it Android may stop the tunnel in the background and " +
                    "refuse to let the watchdog restart it.",
                action = "Allow",
                onAction = {
                    if (!context.launchSafely(KeepAliveHelper.batteryOptimizationIntent(context))) {
                        context.launchSafely(KeepAliveHelper.batteryOptimizationListIntent())
                    }
                    refresh++
                },
            )

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                ChecklistItem(
                    title = "Exact alarms",
                    status = if (KeepAliveHelper.canScheduleExactAlarms(context)) {
                        GrantStatus.GRANTED
                    } else {
                        GrantStatus.MISSING
                    },
                    explanation = "The watchdog checks the tunnel through Doze. Without this " +
                        "permission the checks are delayed by the system.",
                    action = "Allow",
                    onAction = {
                        KeepAliveHelper.exactAlarmSettingsIntent(context)?.let { context.launchSafely(it) }
                        refresh++
                    },
                )
            }

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                val granted = ContextCompat.checkSelfPermission(
                    context,
                    Manifest.permission.POST_NOTIFICATIONS,
                ) == PackageManager.PERMISSION_GRANTED
                ChecklistItem(
                    title = "Notifications",
                    status = if (granted) GrantStatus.GRANTED else GrantStatus.MISSING,
                    explanation = "The tunnel runs as a foreground service. A hidden notification " +
                        "makes some firmware more eager to kill it.",
                    action = "Allow",
                    onAction = { notifications.launch(Manifest.permission.POST_NOTIFICATIONS) },
                )
            }

            // Not a keep-alive grant at all, but this is the screen where the app
            // explains what each permission buys, so it belongs with the others
            // rather than ambushing the user from the home screen.
            run {
                val granted = LinkProbe.canReadRan(context)
                ChecklistItem(
                    title = "Network type",
                    status = if (granted) GrantStatus.GRANTED else GrantStatus.MISSING,
                    explanation = "Optional. Lets the home screen name the radio technology " +
                        "(2G / 3G / LTE / 5G) instead of guessing a class from the speed " +
                        "estimate. Nothing the tunnel decides depends on it — the dial " +
                        "timeouts are sized from the speed estimate either way.",
                    action = "Allow",
                    onAction = { phoneState.launch(Manifest.permission.READ_PHONE_STATE) },
                )
            }

            KeepAliveHelper.vendorLabel(context)?.let { vendor ->
                ChecklistItem(
                    title = "$vendor autostart",
                    status = GrantStatus.UNKNOWN,
                    explanation = "$vendor keeps its own list of apps allowed to run in the " +
                        "background. There is no API to read it — open the screen and allow " +
                        "Outline Proxy there.",
                    action = "Open $vendor settings",
                    onAction = { KeepAliveHelper.autostartIntent(context)?.let { context.launchSafely(it) } },
                )
            }
        }
    }
}

@Composable
private fun ChecklistItem(
    title: String,
    status: GrantStatus,
    explanation: String,
    action: String,
    onAction: () -> Unit,
) {
    val statusText = when (status) {
        GrantStatus.GRANTED -> "Allowed"
        GrantStatus.MISSING -> "Needs action"
        GrantStatus.UNKNOWN -> "Check manually"
    }
    val statusColor = when (status) {
        GrantStatus.GRANTED -> StatusGreen
        GrantStatus.MISSING -> MaterialTheme.colorScheme.error
        GrantStatus.UNKNOWN -> StatusAmber
    }
    SectionCard(modifier = Modifier.padding(bottom = 12.dp)) {
        Column {
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Text(
                    title,
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.SemiBold,
                    modifier = Modifier.weight(1f),
                )
                Text(
                    statusText,
                    style = MaterialTheme.typography.labelMedium,
                    color = statusColor,
                    fontWeight = FontWeight.SemiBold,
                )
            }
            Text(
                explanation,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(top = 6.dp, bottom = 12.dp),
            )
            OutlinedButton(
                onClick = onAction,
                shape = RoundedCornerShape(16.dp),
            ) {
                Text(action)
            }
        }
    }
}

/**
 * Vendor screens come and go between firmware versions, so an intent that
 * resolved once can still fail to start. Returns false instead of crashing.
 */
private fun Context.launchSafely(intent: Intent): Boolean = runCatching {
    startActivity(intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
}.isSuccess

/**
 * Ask the system to add the Quick Settings tile ([OutlineTileService]) in one tap
 * (Android 13+). Below that there is no add-tile API, so point the user at the
 * Quick Settings editor instead.
 */
private fun requestAddQsTile(context: Context) {
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
        context.getSystemService(StatusBarManager::class.java)?.requestAddTileService(
            ComponentName(context, OutlineTileService::class.java),
            "Outline",
            Icon.createWithResource(context, R.drawable.ic_stat_tunnel),
            context.mainExecutor,
        ) {}
    } else {
        Toast.makeText(
            context,
            "Open Quick Settings, tap edit (pencil), and add the Outline tile.",
            Toast.LENGTH_LONG,
        ).show()
    }
}
