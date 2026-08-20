package com.outline.proxy

import android.app.Activity
import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.BackHandler
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Edit
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Search
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.Checkbox
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.runtime.toMutableStateList
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import uniffi.outline_android.lastError
import uniffi.outline_android.tunnelStatus

class MainActivity : ComponentActivity() {

    private lateinit var store: ProfileStore
    private var pendingConfig: String = ""

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        store = ProfileStore(this)

        setContent {
            OutlineTheme {
                val profiles = remember { store.load().toMutableStateList() }
                var selectedId by remember { mutableStateOf(store.selectedId ?: profiles.firstOrNull()?.id) }
                val scope = rememberCoroutineScope()
                val context = LocalContext.current

                // The tunnel lives in the service (its own state), so the UI polls
                // it: the button reflects it, and each transition raises a toast —
                // the same lightweight feedback the subscription refresh uses.
                var connected by remember { mutableStateOf(OutlineVpnService.isActive()) }
                var connectedSince by remember {
                    mutableStateOf(KeepAliveState(this@MainActivity).connectedSince)
                }
                // Active carrier per transport, read from the Rust core while the
                // tunnel is up; `null` clears the readout when it goes down. Family
                // (ss/vless) and carrier (ws_*/xhttp_*) are independent axes.
                var tcpFamily by remember { mutableStateOf<String?>(null) }
                var tcpCarrier by remember { mutableStateOf<String?>(null) }
                var udpFamily by remember { mutableStateOf<String?>(null) }
                var udpCarrier by remember { mutableStateOf<String?>(null) }
                LaunchedEffect(Unit) {
                    while (true) {
                        val now = OutlineVpnService.isActive()
                        if (now != connected) {
                            Toast.makeText(
                                context,
                                if (now) "Tunnel connected" else "Tunnel disconnected",
                                Toast.LENGTH_SHORT,
                            ).show()
                            connected = now
                            connectedSince = KeepAliveState(this@MainActivity).connectedSince
                        }
                        if (now) {
                            // `tunnelStatus()` blocks briefly on the core's runtime,
                            // so keep it off the main thread.
                            val status = withContext(Dispatchers.IO) {
                                runCatching { tunnelStatus() }.getOrNull()
                            }
                            tcpFamily = status?.tcpFamily
                            tcpCarrier = status?.tcpCarrier
                            udpFamily = status?.udpFamily
                            udpCarrier = status?.udpCarrier
                        } else {
                            tcpFamily = null
                            tcpCarrier = null
                            udpFamily = null
                            udpCarrier = null
                        }
                        delay(1000)
                    }
                }

                fun persist() {
                    store.save(profiles)
                    store.selectedId = selectedId
                    // Keep the background refresh running exactly while at least
                    // one subscription exists.
                    if (profiles.any { it.isSubscription }) {
                        SubscriptionWorker.schedule(context)
                    } else {
                        SubscriptionWorker.cancel(context)
                    }
                }

                var showSplit by remember { mutableStateOf(false) }
                var showExternal by remember { mutableStateOf(false) }
                var showKeepAlive by remember { mutableStateOf(false) }
                var showProfiles by remember { mutableStateOf(false) }

                // On a sub-screen the system Back gesture / button should return to
                // Home, not leave the app. The top "‹ Back" button already does
                // this; without a handler the gesture falls through to the
                // Activity and finishes it.
                BackHandler(enabled = showSplit || showExternal || showKeepAlive || showProfiles) {
                    showSplit = false
                    showExternal = false
                    showKeepAlive = false
                    showProfiles = false
                }

                // One background under every screen so Home and the sub-screens
                // share the exact same surface colour instead of Home showing the
                // window theme and the Scaffolds painting colorScheme.background.
                Surface(modifier = Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.background) {
                if (showSplit) {
                    SplitTunnelScreen(
                        store = SplitTunnelStore(this@MainActivity),
                        loadApps = { loadNetworkApps(this@MainActivity) },
                        onBack = { showSplit = false },
                    )
                } else if (showExternal) {
                    ExternalControlScreen(
                        store = ExternalControlStore(this@MainActivity),
                        onBack = { showExternal = false },
                    )
                } else if (showKeepAlive) {
                    KeepAliveScreen(onBack = { showKeepAlive = false })
                } else if (showProfiles) {
                    ServerListScreen(
                        profiles = profiles,
                        selectedId = selectedId,
                        connected = connected,
                        onBack = { showProfiles = false },
                        onSelect = { selectedId = it; persist() },
                        onSave = { edited ->
                            val idx = profiles.indexOfFirst { it.id == edited.id }
                            if (idx >= 0) profiles[idx] = edited else profiles.add(edited)
                            if (selectedId == null) selectedId = edited.id
                            persist()
                        },
                        onDelete = { profile ->
                            profiles.removeAll { it.id == profile.id }
                            if (selectedId == profile.id) selectedId = profiles.firstOrNull()?.id
                            persist()
                        },
                        onRefresh = { profile ->
                            scope.launch {
                                when (val result = ConfigFetcher.fetch(profile.configUrl)) {
                                    is FetchResult.Success -> {
                                        val idx = profiles.indexOfFirst { it.id == profile.id }
                                        if (idx >= 0) {
                                            profiles[idx] = profile.copy(
                                                cachedToml = result.toml,
                                                updatedAt = System.currentTimeMillis(),
                                            )
                                            persist()
                                        }
                                        Toast.makeText(context, "Config updated", Toast.LENGTH_SHORT).show()
                                    }
                                    is FetchResult.Failure ->
                                        Toast.makeText(
                                            context,
                                            "Refresh failed: ${result.reason}",
                                            Toast.LENGTH_LONG,
                                        ).show()
                                }
                            }
                        },
                    )
                } else {
                    HomeScreen(
                        profile = profiles.firstOrNull { it.id == selectedId },
                        connected = connected,
                        connectedSinceMs = connectedSince,
                        tcpFamily = tcpFamily,
                        tcpCarrier = tcpCarrier,
                        udpFamily = udpFamily,
                        udpCarrier = udpCarrier,
                        onToggle = {
                            if (connected) {
                                disconnect()
                            } else {
                                profiles.firstOrNull { it.id == selectedId }?.let { profile ->
                                    val config = profile.toToml()
                                    if (config.isBlank()) {
                                        // A subscription that never downloaded has no
                                        // config to connect with; say so instead of
                                        // handing the core an empty TOML.
                                        Toast.makeText(
                                            context,
                                            "No config yet — refresh the subscription first.",
                                            Toast.LENGTH_LONG,
                                        ).show()
                                    } else {
                                        requestVpnAndConnect(config)
                                    }
                                }
                            }
                        },
                        onAddServer = { showProfiles = true },
                        onOpenProfiles = { showProfiles = true },
                        onOpenSplitTunnel = { showSplit = true },
                        onOpenExternalControl = { showExternal = true },
                        onOpenKeepAlive = { showKeepAlive = true },
                    )
                }
                }
            }
        }
    }

    private fun requestVpnAndConnect(configToml: String) {
        pendingConfig = configToml
        val prepare = VpnService.prepare(this)
        if (prepare != null) {
            vpnConsentLauncher.launch(prepare)
        } else {
            startTunnel(pendingConfig)
        }
    }

    private val vpnConsentLauncher =
        registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
            if (result.resultCode == Activity.RESULT_OK) startTunnel(pendingConfig)
        }

    private fun startTunnel(configToml: String) {
        OutlineVpnService.requestConnect(this, configToml)
        watchConnectResult()
    }

    /**
     * After a connect request, give the core a few seconds to come up. A valid
     * config has the client task running within the first sample; a hard failure
     * (bad config, bind error) exits the task, so the tunnel never settles into a
     * stable "running" state. In that case surface the core's exit reason so a
     * failed connect is not silent. The keep-alive watchdog re-spawns on failure,
     * which makes `isActive()` flicker, hence the "stable for two samples" gate
     * rather than a single reading.
     */
    private fun watchConnectResult() {
        lifecycleScope.launch {
            var stableUp = 0
            repeat(8) {
                delay(750)
                if (OutlineVpnService.isActive()) {
                    stableUp++
                    if (stableUp >= 2) return@launch // settled connection — success
                } else {
                    stableUp = 0
                }
            }
            // The window elapsed without a stable connection: report why, if the
            // core recorded a reason.
            val reason = withContext(Dispatchers.IO) { runCatching { lastError() }.getOrNull() }
            Toast.makeText(
                this@MainActivity,
                reason?.let { "Couldn't connect: ${it.substringBefore('\n')}" }
                    ?: "Couldn't connect",
                Toast.LENGTH_LONG,
            ).show()
        }
    }

    private fun disconnect() {
        OutlineVpnService.requestDisconnect(this)
    }
}

@Composable
private fun ServerListScreen(
    profiles: List<ServerProfile>,
    selectedId: String?,
    connected: Boolean,
    onBack: () -> Unit,
    onSelect: (String) -> Unit,
    onSave: (ServerProfile) -> Unit,
    onDelete: (ServerProfile) -> Unit,
    onRefresh: (ServerProfile) -> Unit,
) {
    var editing by remember { mutableStateOf<ServerProfile?>(null) }

    SubScreen(title = "Servers", onBack = onBack) {
        LazyColumn(
            modifier = Modifier.fillMaxWidth().weight(1f).padding(top = 4.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            items(profiles, key = { it.id }) { profile ->
                ProfileCard(
                    profile = profile,
                    selected = profile.id == selectedId,
                    onSelect = { onSelect(profile.id) },
                    onEdit = { editing = profile },
                    onDelete = { onDelete(profile) },
                    onRefresh = { onRefresh(profile) },
                )
            }
        }

        OutlinedButton(
            onClick = { editing = ServerProfile() },
            modifier = Modifier.fillMaxWidth().padding(top = 8.dp),
        ) { Text("Add server") }
    }

    editing?.let { profile ->
        ProfileEditorDialog(
            initial = profile,
            onDismiss = { editing = null },
            onConfirm = { onSave(it); editing = null },
        )
    }
}

@Composable
private fun ProfileCard(
    profile: ServerProfile,
    selected: Boolean,
    onSelect: () -> Unit,
    onEdit: () -> Unit,
    onDelete: () -> Unit,
    onRefresh: () -> Unit,
) {
    Card(modifier = Modifier.fillMaxWidth().selectable(selected = selected, onClick = onSelect)) {
        Row(
            modifier = Modifier.fillMaxWidth().padding(12.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            RadioButton(selected = selected, onClick = onSelect)
            Column(modifier = Modifier.weight(1f).padding(start = 8.dp)) {
                Text(
                    profile.name.ifBlank { "(unnamed)" },
                    fontWeight = FontWeight.Bold,
                )
                Text(
                    if (profile.isSubscription) {
                        "subscription · ${formatAge(profile.updatedAt)} · " +
                            "every ${SubscriptionWorker.REFRESH_PERIOD_HOURS}h"
                    } else {
                        profile.transport
                    },
                    style = MaterialTheme.typography.bodySmall,
                )
            }
            if (profile.isSubscription) {
                IconButton(onClick = onRefresh) {
                    Icon(Icons.Filled.Refresh, contentDescription = "Refresh")
                }
            }
            IconButton(onClick = onEdit) {
                Icon(Icons.Filled.Edit, contentDescription = "Edit")
            }
            IconButton(onClick = onDelete) {
                Icon(Icons.Filled.Delete, contentDescription = "Delete")
            }
        }
    }
}

/** Human-readable "when was this subscription last refreshed" for the card. */
private fun formatAge(updatedAt: Long): String {
    if (updatedAt <= 0L) return "never updated"
    val ageMs = System.currentTimeMillis() - updatedAt
    if (ageMs < 0) return "updated just now"
    val minutes = ageMs / 60_000
    val hours = minutes / 60
    val days = hours / 24
    return when {
        minutes < 1 -> "updated just now"
        minutes < 60 -> "updated ${minutes}m ago"
        hours < 24 -> "updated ${hours}h ago"
        else -> "updated ${days}d ago"
    }
}

@Composable
private fun ProfileEditorDialog(
    initial: ServerProfile,
    onDismiss: () -> Unit,
    onConfirm: (ServerProfile) -> Unit,
) {
    var name by remember { mutableStateOf(initial.name) }
    var transport by remember { mutableStateOf(initial.transport) }
    var vlessLink by remember { mutableStateOf(initial.vlessLink) }
    var ssLink by remember { mutableStateOf(initial.ssLink) }
    var paddingEnabled by remember { mutableStateOf(initial.paddingEnabled) }
    var rawOverride by remember { mutableStateOf(initial.rawTomlOverride) }
    var configUrl by remember { mutableStateOf(initial.configUrl) }
    var fetching by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }

    val scope = rememberCoroutineScope()
    val isSubscription = configUrl.isNotBlank()

    fun save() {
        val base = initial.copy(
            name = name,
            transport = transport,
            vlessLink = vlessLink,
            ssLink = ssLink,
            paddingEnabled = paddingEnabled,
            rawTomlOverride = rawOverride,
            configUrl = configUrl.trim(),
        )
        if (!isSubscription) {
            onConfirm(base)
            return
        }
        // A subscription only makes sense once its config downloads: fetch on
        // save, keep the old cache on failure, refuse to save an empty one.
        error = null
        fetching = true
        scope.launch {
            when (val result = ConfigFetcher.fetch(base.configUrl)) {
                is FetchResult.Success -> {
                    fetching = false
                    onConfirm(base.copy(cachedToml = result.toml, updatedAt = System.currentTimeMillis()))
                }
                is FetchResult.Failure -> {
                    fetching = false
                    if (base.cachedToml.isNotBlank()) {
                        // URL unchanged / still cached: save without disturbing it.
                        onConfirm(base)
                    } else {
                        error = result.reason
                    }
                }
            }
        }
    }

    AlertDialog(
        onDismissRequest = onDismiss,
        confirmButton = {
            TextButton(onClick = { save() }, enabled = !fetching) {
                Text(if (fetching) "Fetching…" else "Save")
            }
        },
        dismissButton = { TextButton(onClick = onDismiss, enabled = !fetching) { Text("Cancel") } },
        title = { Text("Server") },
        text = {
            Column {
                OutlinedTextField(name, { name = it }, label = { Text("Name") }, modifier = Modifier.fillMaxWidth())

                OutlinedTextField(
                    configUrl, { configUrl = it; error = null },
                    label = { Text("Config URL (subscription)") },
                    singleLine = true,
                    supportingText = {
                        Text("HTTPS link to a ready client config; fetched and refreshed automatically.")
                    },
                    modifier = Modifier.fillMaxWidth().padding(top = 8.dp),
                )
                error?.let {
                    Text(
                        "Could not fetch: $it",
                        color = MaterialTheme.colorScheme.error,
                        style = MaterialTheme.typography.bodySmall,
                        modifier = Modifier.padding(top = 4.dp),
                    )
                }

                // With a subscription URL the config comes from the network, so
                // the manual transport fields would be dead inputs — hide them.
                if (!isSubscription) {
                    Row(modifier = Modifier.fillMaxWidth().padding(top = 8.dp), verticalAlignment = Alignment.CenterVertically) {
                        RadioButton(selected = transport == "vless", onClick = { transport = "vless" })
                        Text("VLESS", modifier = Modifier.padding(end = 16.dp))
                        RadioButton(selected = transport == "ss", onClick = { transport = "ss" })
                        Text("Shadowsocks")
                    }

                    if (transport == "vless") {
                        OutlinedTextField(
                            vlessLink, { vlessLink = it },
                            label = { Text("vless:// share link") },
                            modifier = Modifier.fillMaxWidth(),
                        )
                    } else {
                        OutlinedTextField(
                            ssLink, { ssLink = it },
                            label = { Text("ss:// share link") },
                            modifier = Modifier.fillMaxWidth(),
                        )
                    }

                    Row(modifier = Modifier.fillMaxWidth().padding(top = 8.dp), verticalAlignment = Alignment.CenterVertically) {
                        Text("Padding", modifier = Modifier.weight(1f))
                        Switch(checked = paddingEnabled, onCheckedChange = { paddingEnabled = it })
                    }

                    OutlinedTextField(
                        rawOverride, { rawOverride = it },
                        label = { Text("Raw TOML override (optional)") },
                        modifier = Modifier.fillMaxWidth().padding(top = 8.dp),
                    )
                }
            }
        },
    )
}

@Composable
private fun SplitTunnelScreen(
    store: SplitTunnelStore,
    loadApps: suspend () -> List<AppInfo>,
    onBack: () -> Unit,
) {
    val initial = remember { store.load() }
    var mode by remember { mutableStateOf(initial.mode) }
    // Two independent selections. The list backing the active mode follows
    // `mode`, so switching modes never moves or drops the other's selection.
    val allow = remember { initial.allowPackages.toMutableStateList() }
    val deny = remember { initial.denyPackages.toMutableStateList() }
    var apps by remember { mutableStateOf<List<AppInfo>>(emptyList()) }
    var loading by remember { mutableStateOf(true) }

    LaunchedEffect(Unit) {
        apps = withContext(Dispatchers.IO) { loadApps() }
        loading = false
    }

    var query by remember { mutableStateOf("") }
    val listState = rememberLazyListState()

    fun persist() = store.save(SplitTunnelConfig(mode, allow.toSet(), deny.toSet()))

    // Switching mode shows a different list (allow vs deny), so snap the scroll
    // back to the top instead of inheriting the previous mode's offset.
    LaunchedEffect(mode) { listState.scrollToItem(0) }

    // The list backing the active mode; null in OFF, where there is nothing to pick.
    val selected = when (mode) {
        SplitMode.ALLOWLIST -> allow
        SplitMode.DENYLIST -> deny
        SplitMode.OFF -> null
    }

    SubScreen(title = "Split Tunneling", onBack = onBack) {
        SectionCard(modifier = Modifier.padding(top = 4.dp), padding = PaddingValues(vertical = 4.dp)) {
            Column {
                ModeOption("All apps", SplitMode.OFF, mode) { mode = it; persist() }
                ModeOption("Only selected apps", SplitMode.ALLOWLIST, mode) { mode = it; persist() }
                ModeOption("All apps except selected", SplitMode.DENYLIST, mode) { mode = it; persist() }
            }
        }

        when {
            selected == null ->
                Text(
                    "Every app's traffic goes through the tunnel.",
                    modifier = Modifier.padding(top = 16.dp),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            loading ->
                Text("Loading apps…", modifier = Modifier.padding(top = 16.dp))
            else -> {
                Text(
                    if (mode == SplitMode.ALLOWLIST) {
                        "Only the checked apps are tunneled; everything else uses the direct connection."
                    } else {
                        "The checked apps bypass the tunnel; everything else is tunneled."
                    },
                    modifier = Modifier.padding(top = 16.dp, start = 4.dp),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                OutlinedTextField(
                    value = query,
                    onValueChange = { query = it },
                    singleLine = true,
                    leadingIcon = { Icon(Icons.Filled.Search, contentDescription = null) },
                    placeholder = { Text("Search apps") },
                    shape = RoundedCornerShape(16.dp),
                    modifier = Modifier.fillMaxWidth().padding(top = 12.dp),
                )
                // Filter by name, then float the checked apps to the top so the
                // current selection is always in view.
                val visible = apps
                    .filter { it.label.contains(query, ignoreCase = true) }
                    .sortedWith(
                        compareByDescending<AppInfo> { selected.contains(it.packageName) }
                            .thenBy { it.label.lowercase() },
                    )
                LazyColumn(
                    state = listState,
                    modifier = Modifier.fillMaxWidth().weight(1f).padding(top = 8.dp),
                    verticalArrangement = Arrangement.spacedBy(4.dp),
                ) {
                    items(visible, key = { it.packageName }) { app ->
                        val checked = selected.contains(app.packageName)
                        SectionCard(padding = PaddingValues(horizontal = 12.dp, vertical = 4.dp)) {
                            Row(
                                modifier = Modifier.fillMaxWidth().clickable {
                                    if (checked) selected.remove(app.packageName) else selected.add(app.packageName)
                                    persist()
                                },
                                verticalAlignment = Alignment.CenterVertically,
                            ) {
                                Checkbox(
                                    checked = checked,
                                    onCheckedChange = {
                                        if (it) selected.add(app.packageName) else selected.remove(app.packageName)
                                        persist()
                                    },
                                )
                                Column(modifier = Modifier.padding(start = 8.dp)) {
                                    Text(app.label)
                                    Text(
                                        app.packageName,
                                        style = MaterialTheme.typography.bodySmall,
                                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                                    )
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

/**
 * External control settings: the `outline://` scheme is exported to every app
 * on the device, so this screen is where the user switches it off or locks it
 * behind a shared secret. See [ControlActivity].
 */
@Composable
private fun ExternalControlScreen(
    store: ExternalControlStore,
    onBack: () -> Unit,
) {
    val initial = remember { store.load() }
    var enabled by remember { mutableStateOf(initial.enabled) }
    var token by remember { mutableStateOf(initial.token) }

    fun persist() = store.save(ExternalControlConfig(enabled, token))

    SubScreen(title = "External Control", onBack = onBack) {
        SectionCard(modifier = Modifier.padding(top = 4.dp)) {
            Column {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Text("Allow outline:// commands", modifier = Modifier.weight(1f))
                    Switch(checked = enabled, onCheckedChange = { enabled = it; persist() })
                }
                OutlinedTextField(
                    token,
                    { token = it; persist() },
                    enabled = enabled,
                    singleLine = true,
                    shape = RoundedCornerShape(16.dp),
                    label = { Text("Token (optional)") },
                    supportingText = {
                        Text("When set, commands without a matching ?token= are ignored.")
                    },
                    modifier = Modifier.fillMaxWidth().padding(top = 12.dp),
                )
            }
        }

        Text(
            """
            Supported commands:

            outline://connect
            outline://connect?profile=<name or id>
            outline://disconnect
            outline://toggle[?profile=<name or id>]

            Any app on this device can send these, which is why the switch
            and the token are here. Commands never create a server — the
            profile must already exist in the list.
            """.trimIndent(),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.padding(top = 16.dp, start = 4.dp),
        )
    }
}

@Composable
private fun ModeOption(
    label: String,
    value: SplitMode,
    current: SplitMode,
    onSelect: (SplitMode) -> Unit,
) {
    Row(
        modifier = Modifier.fillMaxWidth().clickable { onSelect(value) }
            .padding(horizontal = 4.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        RadioButton(selected = current == value, onClick = { onSelect(value) })
        Text(label)
    }
}
