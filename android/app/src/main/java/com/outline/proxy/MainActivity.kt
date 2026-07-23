package com.outline.proxy

import android.app.Activity
import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.selection.selectable
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.Checkbox
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.runtime.toMutableStateList
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

class MainActivity : ComponentActivity() {

    private lateinit var store: ProfileStore
    private var pendingConfig: String = ""

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        store = ProfileStore(this)

        setContent {
            MaterialTheme {
                val profiles = remember { store.load().toMutableStateList() }
                var selectedId by remember { mutableStateOf(store.selectedId ?: profiles.firstOrNull()?.id) }

                fun persist() {
                    store.save(profiles)
                    store.selectedId = selectedId
                }

                var showSplit by remember { mutableStateOf(false) }
                var showExternal by remember { mutableStateOf(false) }

                if (showSplit) {
                    SplitTunnelScreen(
                        store = SplitTunnelStore(this@MainActivity),
                        loadApps = { loadLaunchableApps(this@MainActivity) },
                        onBack = { showSplit = false },
                    )
                } else if (showExternal) {
                    ExternalControlScreen(
                        store = ExternalControlStore(this@MainActivity),
                        onBack = { showExternal = false },
                    )
                } else {
                    ServerListScreen(
                        profiles = profiles,
                        selectedId = selectedId,
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
                        onConnect = {
                            profiles.firstOrNull { it.id == selectedId }?.let {
                                requestVpnAndConnect(it.toToml())
                            }
                        },
                        onDisconnect = ::disconnect,
                        onOpenSplitTunnel = { showSplit = true },
                        onOpenExternalControl = { showExternal = true },
                    )
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
    }

    private fun disconnect() {
        OutlineVpnService.requestDisconnect(this)
    }
}

@Composable
private fun ServerListScreen(
    profiles: List<ServerProfile>,
    selectedId: String?,
    onSelect: (String) -> Unit,
    onSave: (ServerProfile) -> Unit,
    onDelete: (ServerProfile) -> Unit,
    onConnect: () -> Unit,
    onDisconnect: () -> Unit,
    onOpenSplitTunnel: () -> Unit,
    onOpenExternalControl: () -> Unit,
) {
    var editing by remember { mutableStateOf<ServerProfile?>(null) }

    Scaffold { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(16.dp),
        ) {
            Text("Outline Proxy", style = MaterialTheme.typography.headlineSmall)

            LazyColumn(
                modifier = Modifier.fillMaxWidth().weight(1f).padding(top = 12.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                items(profiles, key = { it.id }) { profile ->
                    ProfileCard(
                        profile = profile,
                        selected = profile.id == selectedId,
                        onSelect = { onSelect(profile.id) },
                        onEdit = { editing = profile },
                        onDelete = { onDelete(profile) },
                    )
                }
            }

            Row(
                modifier = Modifier.fillMaxWidth().padding(top = 8.dp),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                OutlinedButton(
                    onClick = { editing = ServerProfile() },
                    modifier = Modifier.weight(1f),
                ) { Text("Add server") }
                Button(
                    onClick = onConnect,
                    enabled = selectedId != null,
                    modifier = Modifier.weight(1f),
                ) { Text("Connect") }
            }
            OutlinedButton(
                onClick = onDisconnect,
                modifier = Modifier.fillMaxWidth().padding(top = 8.dp),
            ) { Text("Disconnect") }
            TextButton(
                onClick = onOpenSplitTunnel,
                modifier = Modifier.fillMaxWidth(),
            ) { Text("Split tunneling…") }
            TextButton(
                onClick = onOpenExternalControl,
                modifier = Modifier.fillMaxWidth(),
            ) { Text("External control…") }
        }
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
                Text(profile.transport, style = MaterialTheme.typography.bodySmall)
            }
            TextButton(onClick = onEdit) { Text("Edit") }
            TextButton(onClick = onDelete) { Text("Delete") }
        }
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

    AlertDialog(
        onDismissRequest = onDismiss,
        confirmButton = {
            TextButton(onClick = {
                onConfirm(
                    initial.copy(
                        name = name,
                        transport = transport,
                        vlessLink = vlessLink,
                        ssLink = ssLink,
                        paddingEnabled = paddingEnabled,
                        rawTomlOverride = rawOverride,
                    ),
                )
            }) { Text("Save") }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel") } },
        title = { Text("Server") },
        text = {
            Column {
                OutlinedTextField(name, { name = it }, label = { Text("Name") }, modifier = Modifier.fillMaxWidth())

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
    val selected = remember { initial.packages.toMutableStateList() }
    var apps by remember { mutableStateOf<List<AppInfo>>(emptyList()) }
    var loading by remember { mutableStateOf(true) }

    LaunchedEffect(Unit) {
        apps = withContext(Dispatchers.IO) { loadApps() }
        loading = false
    }

    fun persist() = store.save(SplitTunnelConfig(mode, selected.toSet()))

    Scaffold { padding ->
        Column(
            modifier = Modifier.fillMaxSize().padding(padding).padding(16.dp),
        ) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                TextButton(onClick = onBack) { Text("‹ Back") }
                Text("Split tunneling", style = MaterialTheme.typography.headlineSmall)
            }

            ModeOption("All apps", SplitMode.OFF, mode) { mode = it; persist() }
            ModeOption("Only selected apps", SplitMode.ALLOWLIST, mode) { mode = it; persist() }
            ModeOption("All apps except selected", SplitMode.DENYLIST, mode) { mode = it; persist() }

            when {
                mode == SplitMode.OFF ->
                    Text(
                        "Every app's traffic goes through the tunnel.",
                        modifier = Modifier.padding(top = 12.dp),
                        style = MaterialTheme.typography.bodyMedium,
                    )
                loading ->
                    Text("Loading apps…", modifier = Modifier.padding(top = 12.dp))
                else ->
                    LazyColumn(modifier = Modifier.fillMaxWidth().weight(1f).padding(top = 12.dp)) {
                        items(apps, key = { it.packageName }) { app ->
                            val checked = selected.contains(app.packageName)
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
                                    Text(app.packageName, style = MaterialTheme.typography.bodySmall)
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

    Scaffold { padding ->
        Column(modifier = Modifier.fillMaxSize().padding(padding).padding(16.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                TextButton(onClick = onBack) { Text("‹ Back") }
                Text("External control", style = MaterialTheme.typography.headlineSmall)
            }

            Row(
                modifier = Modifier.fillMaxWidth().padding(top = 8.dp),
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
                label = { Text("Token (optional)") },
                supportingText = {
                    Text("When set, commands without a matching ?token= are ignored.")
                },
                modifier = Modifier.fillMaxWidth().padding(top = 8.dp),
            )

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
                modifier = Modifier.padding(top = 16.dp),
            )
        }
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
        modifier = Modifier.fillMaxWidth().clickable { onSelect(value) },
        verticalAlignment = Alignment.CenterVertically,
    ) {
        RadioButton(selected = current == value, onClick = { onSelect(value) })
        Text(label)
    }
}
