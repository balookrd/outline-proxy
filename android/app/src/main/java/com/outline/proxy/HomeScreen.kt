package com.outline.proxy

import android.net.TrafficStats
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.safeDrawing
import androidx.compose.foundation.layout.windowInsetsPadding
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.automirrored.filled.AltRoute
import androidx.compose.material.icons.filled.ArrowDownward
import androidx.compose.material.icons.filled.ArrowUpward
import androidx.compose.material.icons.filled.ChevronRight
import androidx.compose.material.icons.filled.GraphicEq
import androidx.compose.material.icons.filled.MonitorHeart
import androidx.compose.material.icons.filled.PowerSettingsNew
import androidx.compose.material.icons.filled.Schedule
import androidx.compose.material.icons.filled.Tune
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableLongStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.ColorFilter
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.delay
import java.util.Locale

/** Compact "when refreshed" for the status card ("1h ago", "3d ago"). */
private fun ageShort(updatedAt: Long): String {
    if (updatedAt <= 0L) return "never"
    val minutes = ((System.currentTimeMillis() - updatedAt).coerceAtLeast(0)) / 60_000
    val hours = minutes / 60
    val days = hours / 24
    return when {
        minutes < 1 -> "just now"
        minutes < 60 -> "${minutes}m ago"
        hours < 24 -> "${hours}h ago"
        else -> "${days}d ago"
    }
}

/**
 * The main screen: brand header, the active server's status card, the connect /
 * disconnect action, and shortcuts to the sub-screens. Server management (pick,
 * edit, delete) lives behind a tap on the status card.
 */
@Composable
fun HomeScreen(
    profile: ServerProfile?,
    connected: Boolean,
    connectedSinceMs: Long,
    tcpFamily: String?,
    tcpCarrier: String?,
    udpFamily: String?,
    udpCarrier: String?,
    onToggle: () -> Unit,
    onAddServer: () -> Unit,
    onOpenProfiles: () -> Unit,
    onOpenSplitTunnel: () -> Unit,
    onOpenExternalControl: () -> Unit,
    onOpenKeepAlive: () -> Unit,
) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            // Keep the header clear of the status bar / camera cutout and the
            // bottom gesture bar — the app draws edge-to-edge on targetSdk 36.
            .windowInsetsPadding(WindowInsets.safeDrawing)
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 16.dp, vertical = 12.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Header()
        Spacer(Modifier.height(20.dp))
        StatusCard(
            profile, connected, connectedSinceMs,
            tcpFamily, tcpCarrier, udpFamily, udpCarrier, onOpenProfiles,
        )
        Spacer(Modifier.height(16.dp))
        ActionRow(canConnect = profile != null, connected = connected, onAddServer, onToggle)
        Spacer(Modifier.height(16.dp))
        QuickLinks(onOpenSplitTunnel, onOpenExternalControl, onOpenKeepAlive)
        Spacer(Modifier.height(16.dp))
        VersionFooter()
    }
}

/** App build identity: version name, version code, and the commit it was built
 *  from — set by CI, or the local git SHA / "dev" for a developer build. */
@Composable
private fun VersionFooter() {
    Text(
        "v${BuildConfig.VERSION_NAME} (${BuildConfig.VERSION_CODE}) · ${BuildConfig.GIT_SHA}",
        fontSize = 10.sp,
        textAlign = TextAlign.Center,
        color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.7f),
        modifier = Modifier.fillMaxWidth().padding(top = 2.dp, bottom = 4.dp),
    )
}

@Composable
private fun Header() {
    // The full-width brand banner, per theme.
    val logo = if (isSystemInDarkTheme()) R.drawable.brand_logo_dark else R.drawable.brand_logo_light
    Image(
        painter = painterResource(logo),
        contentDescription = "outline-proxy",
        contentScale = ContentScale.FillWidth,
        modifier = Modifier.fillMaxWidth().padding(vertical = 10.dp),
    )
}

@Composable
private fun StatusCard(
    profile: ServerProfile?,
    connected: Boolean,
    connectedSinceMs: Long,
    tcpFamily: String?,
    tcpCarrier: String?,
    udpFamily: String?,
    udpCarrier: String?,
    onClick: () -> Unit,
) {
    val dotColor = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.14f)
    Surface(
        modifier = Modifier.fillMaxWidth().clickable(onClick = onClick),
        shape = RoundedCornerShape(20.dp),
        color = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.4f),
        tonalElevation = 2.dp,
    ) {
        Box {
            // Dotted world map bleeding off the right edge, tinted to the theme.
            Image(
                painter = painterResource(R.drawable.ic_worldmap),
                contentDescription = null,
                colorFilter = ColorFilter.tint(dotColor),
                alignment = Alignment.TopEnd,
                contentScale = ContentScale.FillHeight,
                modifier = Modifier
                    .align(Alignment.TopEnd)
                    .fillMaxWidth(0.62f)
                    .height(150.dp),
            )
            Column(modifier = Modifier.padding(16.dp)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    EmblemRing()
                    Spacer(Modifier.width(16.dp))
                    Column(modifier = Modifier.weight(1f)) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Box(
                                Modifier.size(9.dp).clip(CircleShape)
                                    .background(if (connected) StatusGreen else MaterialTheme.colorScheme.outline),
                            )
                            Spacer(Modifier.width(6.dp))
                            Text(
                                if (connected) "Connected" else "Disconnected",
                                color = if (connected) StatusGreen else MaterialTheme.colorScheme.onSurfaceVariant,
                                fontSize = 13.sp,
                                fontWeight = FontWeight.Medium,
                            )
                        }
                        Spacer(Modifier.height(4.dp))
                        Text(
                            profile?.name?.takeIf { it.isNotBlank() } ?: "No server",
                            fontSize = 22.sp,
                            fontWeight = FontWeight.Bold,
                            color = MaterialTheme.colorScheme.onSurface,
                        )
                        Spacer(Modifier.height(4.dp))
                        when {
                            profile == null -> Text(
                                "Add a server to begin",
                                fontSize = 12.sp,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                            profile.isSubscription -> {
                                Row(verticalAlignment = Alignment.CenterVertically) {
                                    Text(
                                        "Subscription",
                                        fontSize = 12.sp,
                                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                                    )
                                    Spacer(Modifier.width(6.dp))
                                    Badge("Active")
                                }
                                Text(
                                    "Updated ${ageShort(profile.updatedAt)} · " +
                                        "Every ${SubscriptionWorker.REFRESH_PERIOD_HOURS}h",
                                    fontSize = 11.sp,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                                )
                            }
                            else -> Text(
                                profile.transport,
                                fontSize = 12.sp,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                        }
                    }
                    Icon(
                        Icons.Filled.ChevronRight,
                        contentDescription = "Servers",
                        tint = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }

                // The live metrics strip, mirroring the connection card: how long
                // the tunnel has been up, how much it has moved, and which carrier
                // each transport is riding. Only meaningful while connected.
                if (connected) {
                    Spacer(Modifier.height(16.dp))
                    HorizontalDivider(color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.08f))
                    Spacer(Modifier.height(14.dp))
                    StatsStrip(connectedSinceMs, tcpFamily, tcpCarrier, udpFamily, udpCarrier)
                }
            }
        }
    }
}

/**
 * Three side-by-side readouts under the status card: connection duration, bytes
 * moved this session, and the active carrier per transport. The traffic figure
 * comes from the device's [TrafficStats] deltas — device-wide, so it tracks the
 * tunnel closely under a full-route VPN and slightly over-counts under a
 * split tunnel. The carriers come from the Rust core's active-wire state.
 */
@Composable
private fun StatsStrip(
    connectedSinceMs: Long,
    tcpFamily: String?,
    tcpCarrier: String?,
    udpFamily: String?,
    udpCarrier: String?,
) {
    // Elastic layout: each column is only as wide as its own content, and the
    // free space is shared out between them. The protocol column — the widest,
    // "tcp  vless/xhttp/h3" — takes exactly what it needs, so it never clips
    // regardless of the carrier string.
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.Top,
    ) {
        StatColumn(icon = Icons.Filled.Schedule, label = "DURATION") {
            if (connectedSinceMs > 0L) {
                DurationText(connectedSinceMs)
            } else {
                StatValue("00:00:00")
            }
            StatCaption("hh:mm:ss")
        }
        StatDivider()
        StatColumn(icon = Icons.Filled.GraphicEq, label = "TRAFFIC") {
            TrafficReadout(connectedSinceMs)
        }
        StatDivider()
        StatColumn(icon = Icons.Filled.MonitorHeart, label = "PROTOCOL") {
            CarrierLine("TCP", tcpFamily, tcpCarrier)
            CarrierLine("UDP", udpFamily, udpCarrier)
        }
    }
}

@Composable
private fun StatColumn(
    icon: ImageVector,
    label: String,
    modifier: Modifier = Modifier,
    content: @Composable () -> Unit,
) {
    Column(modifier = modifier.padding(horizontal = 4.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Icon(
                icon,
                contentDescription = null,
                tint = BrandBlue,
                modifier = Modifier.size(13.dp),
            )
            Spacer(Modifier.width(4.dp))
            Text(
                label,
                fontSize = 9.sp,
                fontWeight = FontWeight.Medium,
                letterSpacing = 0.4.sp,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        Spacer(Modifier.height(6.dp))
        content()
    }
}

/** A thin vertical rule between two stat columns. */
@Composable
private fun StatDivider() {
    Box(
        Modifier
            .padding(horizontal = 2.dp)
            .width(1.dp)
            .height(34.dp)
            .background(MaterialTheme.colorScheme.onSurface.copy(alpha = 0.08f)),
    )
}

@Composable
private fun StatValue(text: String) {
    Text(
        text,
        fontSize = 15.sp,
        fontWeight = FontWeight.SemiBold,
        color = MaterialTheme.colorScheme.onSurface,
    )
}

@Composable
private fun StatCaption(text: String) {
    Text(text, fontSize = 9.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
}

/**
 * Up/down bytes moved since [connectedSinceMs], sampled from [TrafficStats] once
 * a second. The baseline is captured the first time this composition sees the
 * tunnel up and reset whenever the connect timestamp changes (a reconnect).
 */
@Composable
private fun TrafficReadout(connectedSinceMs: Long) {
    var tx by remember { mutableStateOf(0L) }
    var rx by remember { mutableStateOf(0L) }
    LaunchedEffect(connectedSinceMs) {
        val baseTx = TrafficStats.getTotalTxBytes().coerceAtLeast(0)
        val baseRx = TrafficStats.getTotalRxBytes().coerceAtLeast(0)
        while (true) {
            tx = (TrafficStats.getTotalTxBytes() - baseTx).coerceAtLeast(0)
            rx = (TrafficStats.getTotalRxBytes() - baseRx).coerceAtLeast(0)
            delay(1000)
        }
    }
    Row(verticalAlignment = Alignment.CenterVertically) {
        Icon(
            Icons.Filled.ArrowUpward,
            contentDescription = "Uploaded",
            tint = BrandBlue,
            modifier = Modifier.size(12.dp),
        )
        Spacer(Modifier.width(2.dp))
        StatValue(formatBytes(tx))
    }
    Spacer(Modifier.height(2.dp))
    Row(verticalAlignment = Alignment.CenterVertically) {
        Icon(
            Icons.Filled.ArrowDownward,
            contentDescription = "Downloaded",
            tint = BrandBlue,
            modifier = Modifier.size(12.dp),
        )
        Spacer(Modifier.width(2.dp))
        StatValue(formatBytes(rx))
    }
}

/** One transport's active carrier, e.g. "TCP  VLESS/XHTTP/H3"; "—" when idle. */
@Composable
private fun CarrierLine(transport: String, family: String?, carrier: String?) {
    Row(verticalAlignment = Alignment.Bottom) {
        Text(
            transport,
            fontSize = 9.sp,
            fontWeight = FontWeight.Medium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.width(22.dp),
        )
        Text(
            carrierLabel(family, carrier),
            fontSize = 11.sp,
            fontWeight = FontWeight.SemiBold,
            maxLines = 1,
            color = MaterialTheme.colorScheme.onSurface,
        )
    }
}

/**
 * Build a three-part `family/carrier/http` label from the core's status. Family
 * (`ss` / `vless`) and carrier are independent axes — either family can ride
 * either carrier — so both come from the core, not one derived from the other.
 * The mode is `<carrier>_<http>` (`ws_h3`, `xhttp_h2`, …), split into its two
 * parts. Rendered lowercase, e.g. `vless/xhttp/h3` or `ss/ws/h2`, so the full
 * label fits the column. A missing carrier (no active wire) shows an em dash.
 */
private fun carrierLabel(family: String?, mode: String?): String {
    if (mode.isNullOrBlank()) return "—"
    val parts = mode.split("_")
    val carrier = parts.getOrNull(0)?.lowercase(Locale.ROOT)
    val http = parts.getOrNull(1)?.lowercase(Locale.ROOT)
    return listOfNotNull(family?.lowercase(Locale.ROOT), carrier, http).joinToString("/")
}

/** Human-readable byte count for the transfer readout ("0 B", "128 MB"). */
private fun formatBytes(bytes: Long): String {
    if (bytes < 1024) return "$bytes B"
    val units = arrayOf("KB", "MB", "GB", "TB")
    var value = bytes.toDouble() / 1024
    var unit = 0
    while (value >= 1024 && unit < units.lastIndex) {
        value /= 1024
        unit++
    }
    return if (value >= 100) {
        "${value.toInt()} ${units[unit]}"
    } else {
        String.format(Locale.ROOT, "%.1f %s", value, units[unit])
    }
}

@Composable
private fun EmblemRing() {
    // The authored emblem-in-ring, per theme.
    val ring = if (isSystemInDarkTheme()) R.drawable.brand_ring_dark else R.drawable.brand_ring_light
    Image(
        painter = painterResource(ring),
        contentDescription = null,
        modifier = Modifier.size(80.dp),
    )
}

@Composable
private fun DurationText(sinceMs: Long) {
    var now by remember { mutableLongStateOf(sinceMs) }
    LaunchedEffect(sinceMs) {
        while (true) {
            now = System.currentTimeMillis()
            delay(1000)
        }
    }
    val elapsed = ((now - sinceMs).coerceAtLeast(0)) / 1000
    val text = "%02d:%02d:%02d".format(elapsed / 3600, (elapsed % 3600) / 60, elapsed % 60)
    StatValue(text)
}

@Composable
private fun Badge(text: String) {
    Surface(shape = RoundedCornerShape(8.dp), color = BrandBlue.copy(alpha = 0.18f)) {
        Text(
            text,
            modifier = Modifier.padding(horizontal = 8.dp, vertical = 2.dp),
            fontSize = 11.sp,
            fontWeight = FontWeight.Medium,
            color = BrandBlue,
        )
    }
}

@Composable
private fun ActionRow(
    canConnect: Boolean,
    connected: Boolean,
    onAddServer: () -> Unit,
    onToggle: () -> Unit,
) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        OutlinedButton(
            onClick = onAddServer,
            modifier = Modifier.weight(1f).height(56.dp),
            shape = RoundedCornerShape(16.dp),
        ) {
            Icon(Icons.Filled.Add, contentDescription = null, modifier = Modifier.size(20.dp))
            Spacer(Modifier.width(8.dp))
            Text("Add Server")
        }
        // Gradient primary action; a plain Material button cannot take a Brush,
        // so it is a clickable Box. Disabled until a server exists.
        val enabled = canConnect || connected
        // Blue to connect, red to disconnect — the colour tells the current state
        // apart from the label.
        val gradient = when {
            !enabled -> Brush.horizontalGradient(
                listOf(
                    MaterialTheme.colorScheme.surfaceVariant,
                    MaterialTheme.colorScheme.surfaceVariant,
                ),
            )
            connected -> Brush.horizontalGradient(listOf(Color(0xFFE53935), Color(0xFFFF6B6B)))
            else -> Brush.horizontalGradient(listOf(BrandBlue, Color(0xFF6C7BFF)))
        }
        Box(
            modifier = Modifier
                .weight(1f)
                .height(56.dp)
                .clip(RoundedCornerShape(16.dp))
                .background(gradient)
                .clickable(enabled = enabled, onClick = onToggle),
            contentAlignment = Alignment.Center,
        ) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(
                    Icons.Filled.PowerSettingsNew,
                    contentDescription = null,
                    tint = Color.White,
                    modifier = Modifier.size(20.dp),
                )
                Spacer(Modifier.width(8.dp))
                Text(
                    if (connected) "Disconnect" else "Connect",
                    color = Color.White,
                    fontWeight = FontWeight.SemiBold,
                )
            }
        }
    }
}

@Composable
private fun QuickLinks(
    onOpenSplitTunnel: () -> Unit,
    onOpenExternalControl: () -> Unit,
    onOpenKeepAlive: () -> Unit,
) {
    Surface(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(20.dp),
        color = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.4f),
    ) {
        Row(modifier = Modifier.padding(vertical = 16.dp)) {
            QuickLink(
                Icons.AutoMirrored.Filled.AltRoute, "Split Tunneling",
                Modifier.weight(1f), onOpenSplitTunnel,
            )
            QuickLink(
                Icons.Filled.Tune, "External Control",
                Modifier.weight(1f), onOpenExternalControl,
            )
            QuickLink(
                Icons.Filled.MonitorHeart, "Keeping Alive",
                Modifier.weight(1f), onOpenKeepAlive,
            )
        }
    }
}

@Composable
private fun QuickLink(
    icon: ImageVector,
    title: String,
    modifier: Modifier,
    onClick: () -> Unit,
) {
    Column(
        modifier = modifier.clickable(onClick = onClick).padding(horizontal = 6.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Box(
            modifier = Modifier.size(44.dp).clip(CircleShape)
                .background(BrandBlue.copy(alpha = 0.14f)),
            contentAlignment = Alignment.Center,
        ) {
            Icon(icon, contentDescription = null, tint = BrandBlue, modifier = Modifier.size(22.dp))
        }
        Spacer(Modifier.height(8.dp))
        Text(
            title,
            fontSize = 12.sp,
            fontWeight = FontWeight.SemiBold,
            textAlign = TextAlign.Center,
            color = MaterialTheme.colorScheme.onSurface,
        )
    }
}
