package com.outline.proxy

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
import androidx.compose.material.icons.filled.AltRoute
import androidx.compose.material.icons.filled.ChevronRight
import androidx.compose.material.icons.filled.MonitorHeart
import androidx.compose.material.icons.filled.PowerSettingsNew
import androidx.compose.material.icons.filled.Tune
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableLongStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.ColorFilter
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.delay

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
        StatusCard(profile, connected, connectedSinceMs, onOpenProfiles)
        Spacer(Modifier.height(16.dp))
        ActionRow(canConnect = profile != null, connected = connected, onAddServer, onToggle)
        Spacer(Modifier.height(16.dp))
        QuickLinks(onOpenSplitTunnel, onOpenExternalControl, onOpenKeepAlive)
    }
}

@Composable
private fun Header() {
    // The full brand lockup as authored, per theme.
    val logo = if (isSystemInDarkTheme()) R.drawable.brand_logo_dark else R.drawable.brand_logo_light
    Image(
        painter = painterResource(logo),
        contentDescription = "outline-proxy",
        modifier = Modifier.padding(vertical = 8.dp).height(52.dp),
    )
}

@Composable
private fun StatusCard(
    profile: ServerProfile?,
    connected: Boolean,
    connectedSinceMs: Long,
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
                alignment = Alignment.CenterEnd,
                contentScale = ContentScale.FillHeight,
                modifier = Modifier
                    .align(Alignment.CenterEnd)
                    .fillMaxWidth(0.62f)
                    .height(150.dp),
            )
            Row(
                modifier = Modifier.padding(16.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
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
                    if (connected && connectedSinceMs > 0L) {
                        Spacer(Modifier.width(10.dp))
                        DurationText(connectedSinceMs)
                    }
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
        }
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
    Text(text, fontSize = 13.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
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
                Icons.Filled.AltRoute, "Split Tunneling", "Manage rules",
                Modifier.weight(1f), onOpenSplitTunnel,
            )
            QuickLink(
                Icons.Filled.Tune, "External Control", "Advanced settings",
                Modifier.weight(1f), onOpenExternalControl,
            )
            QuickLink(
                Icons.Filled.MonitorHeart, "Keeping Alive", "Persistent connection",
                Modifier.weight(1f), onOpenKeepAlive,
            )
        }
    }
}

@Composable
private fun QuickLink(
    icon: androidx.compose.ui.graphics.vector.ImageVector,
    title: String,
    subtitle: String,
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
        Text(
            subtitle,
            fontSize = 10.sp,
            textAlign = TextAlign.Center,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}
