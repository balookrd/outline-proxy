package com.outline.proxy

import android.Manifest
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
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

    val notifications = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestPermission(),
    ) { refresh++ }

    Scaffold { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .verticalScroll(rememberScrollState())
                .padding(16.dp),
        ) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                TextButton(onClick = onBack) { Text("‹ Back") }
                Text("Keeping the tunnel alive", style = MaterialTheme.typography.headlineSmall)
            }
            Text(
                "Android and the phone vendor may stop background apps. These " +
                    "switches are what keeps the tunnel up.",
                style = MaterialTheme.typography.bodyMedium,
                modifier = Modifier.padding(top = 4.dp, bottom = 16.dp),
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
    Card(modifier = Modifier.padding(bottom = 12.dp)) {
        Column(modifier = Modifier.padding(16.dp)) {
            Text(
                when (status) {
                    GrantStatus.GRANTED -> "✓ $title"
                    GrantStatus.MISSING -> "✗ $title"
                    GrantStatus.UNKNOWN -> "? $title"
                },
                style = MaterialTheme.typography.titleMedium,
            )
            Text(
                explanation,
                style = MaterialTheme.typography.bodySmall,
                modifier = Modifier.padding(top = 4.dp, bottom = 12.dp),
            )
            Button(onClick = onAction) { Text(action) }
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
