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
import androidx.compose.foundation.Image
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.AltRoute
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Clear
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Dns
import androidx.compose.material.icons.filled.Edit
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Tune
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Checkbox
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.RadioButton
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
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import uniffi.outline_android.lastError
import uniffi.outline_android.tunnelStatus

/** How long the status stays "Connecting…" after the link drops (or from
 *  connect) before it reads "No link" — debounces transient health flaps. */
private const val NO_LINK_GRACE_MS = 2_000L

class MainActivity : ComponentActivity() {

    private lateinit var store: ProfileStore
    private var pendingConfig: String = ""

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        store = ProfileStore(this)

        // Persistent-notification mode: make sure the ongoing banner is up as soon
        // as the app is opened, even with the tunnel down (standby). A running
        // tunnel already carries its own banner, so only raise standby when idle.
        if (KeepAliveState(this).persistentNotification && !OutlineVpnService.isActive()) {
            OutlineVpnService.enterStandby(this)
        }

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
                // Whether the running tunnel actually has a live uplink. `connected`
                // only says the engine is up; this says traffic can flow.
                var hasLiveLink by remember { mutableStateOf(false) }
                // Worst of the two transports' last measured latencies: what
                // turns a flat "Connected" into "Connected · slow" on an
                // edge-class link. See `LinkQuality`.
                var linkLatencyMs by remember { mutableStateOf<Int?>(null) }
                // What the phone is riding right now — transport, the platform's
                // bandwidth estimate, and the radio technology when it can be
                // read. Shown under the status so "slow" comes with a reason.
                var link by remember { mutableStateOf<LinkReadout?>(null) }
                // The brief window right after connect, before the first probe has
                // established a link — shown as "Connecting…" rather than "No link".
                var connecting by remember { mutableStateOf(false) }
                LaunchedEffect(Unit) {
                    // When the link was last up (or the connect moment). Debounces
                    // the status: a brief drop stays "Connecting…" rather than
                    // flashing "No link". Tracked in the UI, not from the service's
                    // `connectedSince` (which can still read 0 at the transition).
                    var lastLinkAt = 0L
                    while (true) {
                        val now = OutlineVpnService.isActive()
                        if (now != connected) {
                            Toast.makeText(
                                context,
                                if (now) {
                                    context.getString(R.string.status_toast_connected)
                                } else {
                                    context.getString(R.string.status_toast_disconnected)
                                },
                                Toast.LENGTH_SHORT,
                            ).show()
                            connected = now
                            connectedSince = KeepAliveState(this@MainActivity).connectedSince
                            if (now) {
                                // Show "Connecting…" from the first frame, before the
                                // async status fetch below — otherwise the gap renders
                                // as a "No link" flash.
                                lastLinkAt = System.currentTimeMillis()
                                connecting = true
                                hasLiveLink = false
                            } else {
                                lastLinkAt = 0L
                                connecting = false
                                hasLiveLink = false
                            }
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
                            hasLiveLink = status?.hasLiveLink ?: false
                            linkLatencyMs = LinkQuality.worstOf(
                                status?.tcpLatencyMs?.toInt(),
                                status?.udpLatencyMs?.toInt(),
                            )
                            if (hasLiveLink) lastLinkAt = System.currentTimeMillis()
                            // Read after the latency so the line and the status
                            // agree within a tick. Off the main thread: it is
                            // several binder round trips.
                            link = withContext(Dispatchers.IO) {
                                runCatching { LinkProbe.read(context, linkLatencyMs) }.getOrNull()
                            }
                        } else {
                            tcpFamily = null
                            tcpCarrier = null
                            udpFamily = null
                            udpCarrier = null
                            hasLiveLink = false
                            linkLatencyMs = null
                            // Still worth showing with the tunnel down: seeing
                            // "Cellular · 2G-class" before connecting explains
                            // what is about to happen. Only the latency is
                            // missing, since nothing has measured anything yet.
                            link = withContext(Dispatchers.IO) {
                                runCatching { LinkProbe.read(context, null) }.getOrNull()
                            }
                        }
                        // "No link" only after the link has been absent past the
                        // grace window; a healthy connect or a brief flap stays
                        // "Connecting…" / "Connected" without flashing.
                        connecting = now && !hasLiveLink && lastLinkAt > 0L &&
                            System.currentTimeMillis() - lastLinkAt < NO_LINK_GRACE_MS
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
                // A tap on the build label asks GitHub what its channel publishes;
                // an available build is offered as a download, never installed here.
                var update by remember { mutableStateOf<UpdateChecker.Result.Available?>(null) }
                // What the version footer appends while an update check or a
                // download is in flight; null once there is nothing to report.
                var updateStatus by remember { mutableStateOf<String?>(null) }
                // Set once an APK is on disk: the footer then reads "tap to
                // install" and its tap opens an installer instead of re-checking.
                var downloadedApk by remember { mutableStateOf<String?>(null) }
                // One download at a time: a second tap used to start a parallel
                // fetch whose progress callbacks then overwrote the finished
                // one's terminal status, leaving the footer stuck mid-percentage
                // while the APK was already on disk.
                var downloading by remember { mutableStateOf(false) }

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
                                        Toast.makeText(
                                            context,
                                            context.getString(R.string.srv_toast_config_updated),
                                            Toast.LENGTH_SHORT,
                                        ).show()
                                    }
                                    is FetchResult.Failure ->
                                        Toast.makeText(
                                            context,
                                            context.getString(R.string.srv_refresh_failed, result.reason),
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
                        hasLiveLink = hasLiveLink,
                        linkLatencyMs = linkLatencyMs,
                        link = link,
                        connecting = connecting,
                        tcpFamily = tcpFamily,
                        tcpCarrier = tcpCarrier,
                        udpFamily = udpFamily,
                        udpCarrier = udpCarrier,
                        onToggle = {
                            if (connected) {
                                disconnect()
                            } else {
                                profiles.firstOrNull { it.id == selectedId }?.let { profile ->
                                    scope.launch {
                                        // Bring an expired subscription up to date
                                        // first; falls back to the cached config
                                        // when the fetch fails (usually offline).
                                        val config = withContext(Dispatchers.IO) {
                                            SubscriptionRefresh.configForConnect(context, profile)
                                        }
                                        val idx = profiles.indexOfFirst { it.id == profile.id }
                                        if (idx >= 0 && config != profile.cachedToml &&
                                            profile.isSubscription && config.isNotBlank()
                                        ) {
                                            // Mirror the refreshed config into the UI list
                                            // so the card's "updated" line is not stale.
                                            profiles[idx] = profile.copy(
                                                cachedToml = config,
                                                updatedAt = System.currentTimeMillis(),
                                            )
                                        }
                                        if (config.isBlank()) {
                                            // A subscription that never downloaded has no
                                            // config to connect with; say so instead of
                                            // handing the core an empty TOML.
                                            Toast.makeText(
                                                context,
                                                context.getString(R.string.srv_no_config_yet),
                                                Toast.LENGTH_LONG,
                                            ).show()
                                        } else {
                                            requestVpnAndConnect(config)
                                        }
                                    }
                                }
                            }
                        },
                        onAddServer = { showProfiles = true },
                        onOpenProfiles = { showProfiles = true },
                        onOpenSplitTunnel = { showSplit = true },
                        onOpenExternalControl = { showExternal = true },
                        onOpenKeepAlive = { showKeepAlive = true },
                        onCheckForUpdates = {
                            val apk = downloadedApk
                            if (downloading) return@HomeScreen
                            if (apk != null) {
                                UpdateChecker.openForInstall(this@MainActivity, apk)
                                return@HomeScreen
                            }
                            updateStatus = context.getString(R.string.upd_checking)
                            scope.launch {
                                when (val result = UpdateChecker.check()) {
                                    is UpdateChecker.Result.Available -> {
                                        updateStatus = null
                                        update = result
                                    }
                                    UpdateChecker.Result.UpToDate ->
                                        updateStatus = context.getString(R.string.upd_up_to_date)
                                    is UpdateChecker.Result.Failed ->
                                        updateStatus = context.getString(
                                            R.string.upd_check_failed,
                                            result.reason,
                                        )
                                }
                            }
                        },
                        updateStatus = updateStatus,
                    )
                }
                }

                update?.let { available ->
                    AlertDialog(
                        onDismissRequest = { update = null },
                        title = { Text(stringResource(R.string.upd_available)) },
                        text = {
                            val notes = remember(available) { ReleaseNotes.format(available.notes) }
                            Column {
                                Text(stringResource(R.string.upd_published_for_channel, available.label))
                                if (notes.isNotEmpty()) {
                                    Spacer(Modifier.height(12.dp))
                                    Text(
                                        stringResource(R.string.upd_whats_new),
                                        fontWeight = FontWeight.Bold,
                                    )
                                    Spacer(Modifier.height(4.dp))
                                    // A long body scrolls inside the dialog instead of
                                    // pushing the buttons off-screen.
                                    Column(
                                        Modifier
                                            .heightIn(max = 260.dp)
                                            .verticalScroll(rememberScrollState()),
                                    ) {
                                        notes.forEach { line ->
                                            when (line) {
                                                is NoteLine.Header -> Text(
                                                    line.text,
                                                    fontWeight = FontWeight.Bold,
                                                    modifier = Modifier.padding(top = 8.dp, bottom = 2.dp),
                                                )
                                                is NoteLine.Bullet -> Text("•  ${line.text}")
                                                is NoteLine.Text -> Text(line.text)
                                            }
                                        }
                                    }
                                }
                                Spacer(Modifier.height(12.dp))
                                Text(stringResource(R.string.upd_apk_note))
                            }
                        },
                        confirmButton = {
                            TextButton(onClick = {
                                update = null
                                if (downloading) return@TextButton
                                downloading = true
                                updateStatus = context.getString(R.string.upd_downloading_pct, 0)
                                // lifecycleScope, not the composition's: a 24 MB
                                // fetch outlives a recomposition, and a cancelled
                                // one would freeze the footer at its last percent.
                                lifecycleScope.launch {
                                    val outcome = UpdateChecker.download(
                                        this@MainActivity,
                                        available,
                                    ) { percent ->
                                        if (downloading) {
                                            updateStatus = context.getString(
                                                R.string.upd_downloading_pct,
                                                percent,
                                            )
                                        }
                                    }
                                    downloading = false
                                    updateStatus = when (outcome) {
                                        is UpdateChecker.Download.Saved -> {
                                            downloadedApk = outcome.uri
                                            context.getString(R.string.upd_downloaded_tap)
                                        }
                                        is UpdateChecker.Download.Failed ->
                                            context.getString(
                                                R.string.upd_download_failed,
                                                outcome.reason,
                                            )
                                    }
                                }
                            }) { Text(stringResource(R.string.upd_download)) }
                        },
                        dismissButton = {
                            TextButton(onClick = { update = null }) {
                                Text(stringResource(R.string.upd_later))
                            }
                        },
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
                reason?.let {
                    this@MainActivity.getString(R.string.conn_failed_reason, it.substringBefore('\n'))
                } ?: this@MainActivity.getString(R.string.conn_failed),
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

    SubScreen(title = stringResource(R.string.srv_title), icon = Icons.Filled.Dns, onBack = onBack) {
        LazyColumn(
            modifier = Modifier.fillMaxWidth().weight(1f),
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
            shape = RoundedCornerShape(16.dp),
        ) {
            Icon(Icons.Filled.Add, contentDescription = null)
            Text(stringResource(R.string.srv_add), modifier = Modifier.padding(start = 8.dp))
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
    onRefresh: () -> Unit,
) {
    SectionCard(
        modifier = Modifier.fillMaxWidth().selectable(selected = selected, onClick = onSelect),
        padding = PaddingValues(12.dp),
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            RadioButton(selected = selected, onClick = onSelect)
            Column(modifier = Modifier.weight(1f).padding(start = 8.dp)) {
                Text(
                    profile.name.ifBlank { stringResource(R.string.srv_unnamed) },
                    fontWeight = FontWeight.Bold,
                    color = if (selected) BrandBlue else MaterialTheme.colorScheme.onSurface,
                )
                Text(
                    if (profile.isSubscription) {
                        stringResource(
                            R.string.srv_sub_summary,
                            formatAge(profile.updatedAt),
                            SubscriptionWorker.REFRESH_PERIOD_HOURS,
                        )
                    } else {
                        profile.transport
                    },
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            if (profile.isSubscription) {
                IconButton(onClick = onRefresh) {
                    Icon(
                        Icons.Filled.Refresh,
                        contentDescription = stringResource(R.string.a11y_refresh),
                        tint = BrandBlue,
                    )
                }
            }
            IconButton(onClick = onEdit) {
                Icon(
                    Icons.Filled.Edit,
                    contentDescription = stringResource(R.string.a11y_edit),
                    tint = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            IconButton(onClick = onDelete) {
                Icon(
                    Icons.Filled.Delete,
                    contentDescription = stringResource(R.string.a11y_delete),
                    tint = MaterialTheme.colorScheme.error,
                )
            }
        }
    }
}

private enum class UpdatedAgeBucket { NEVER, JUST_NOW, MINUTES, HOURS, DAYS }
private data class UpdatedAge(val bucket: UpdatedAgeBucket, val amount: Long = 0)

/** Pure "when was this subscription last refreshed" bucket — same thresholds as
 *  before, no Context; [formatAge] resolves the wording from resources. */
private fun updatedAgeOf(updatedAt: Long): UpdatedAge {
    if (updatedAt <= 0L) return UpdatedAge(UpdatedAgeBucket.NEVER)
    val ageMs = System.currentTimeMillis() - updatedAt
    if (ageMs < 0) return UpdatedAge(UpdatedAgeBucket.JUST_NOW)
    val minutes = ageMs / 60_000
    val hours = minutes / 60
    val days = hours / 24
    return when {
        minutes < 1 -> UpdatedAge(UpdatedAgeBucket.JUST_NOW)
        minutes < 60 -> UpdatedAge(UpdatedAgeBucket.MINUTES, minutes)
        hours < 24 -> UpdatedAge(UpdatedAgeBucket.HOURS, hours)
        else -> UpdatedAge(UpdatedAgeBucket.DAYS, days)
    }
}

/** Human-readable "when was this subscription last refreshed" for the card. */
@Composable
private fun formatAge(updatedAt: Long): String {
    val age = updatedAgeOf(updatedAt)
    return when (age.bucket) {
        UpdatedAgeBucket.NEVER -> stringResource(R.string.age_never_updated)
        UpdatedAgeBucket.JUST_NOW -> stringResource(R.string.age_updated_just_now)
        UpdatedAgeBucket.MINUTES -> stringResource(R.string.age_updated_minutes, age.amount)
        UpdatedAgeBucket.HOURS -> stringResource(R.string.age_updated_hours, age.amount)
        UpdatedAgeBucket.DAYS -> stringResource(R.string.age_updated_days, age.amount)
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
        // Blank Name → derive from the link the user pasted: its #remark, else host.
        val derivedName = name.ifBlank {
            val src = when {
                configUrl.isNotBlank() -> configUrl
                transport == "vless" -> vlessLink
                else -> ssLink
            }
            ServerProfile.deriveName(src).orEmpty()
        }
        val base = initial.copy(
            name = derivedName,
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
                Text(if (fetching) stringResource(R.string.dlg_fetching) else stringResource(R.string.btn_save))
            }
        },
        dismissButton = { TextButton(onClick = onDismiss, enabled = !fetching) { Text(stringResource(R.string.btn_cancel)) } },
        title = { Text(stringResource(R.string.dlg_server_title)) },
        text = {
            Column {
                OutlinedTextField(name, { name = it }, label = { Text(stringResource(R.string.dlg_name)) }, modifier = Modifier.fillMaxWidth())

                OutlinedTextField(
                    configUrl, { configUrl = it; error = null },
                    label = { Text(stringResource(R.string.dlg_config_url)) },
                    singleLine = true,
                    supportingText = {
                        Text(stringResource(R.string.dlg_config_url_help))
                    },
                    modifier = Modifier.fillMaxWidth().padding(top = 8.dp),
                )
                error?.let {
                    Text(
                        stringResource(R.string.dlg_could_not_fetch, it),
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
                        Text(stringResource(R.string.dlg_transport_vless), modifier = Modifier.padding(end = 16.dp))
                        RadioButton(selected = transport == "ss", onClick = { transport = "ss" })
                        Text(stringResource(R.string.dlg_transport_ss))
                    }

                    if (transport == "vless") {
                        OutlinedTextField(
                            vlessLink, { vlessLink = it },
                            label = { Text(stringResource(R.string.dlg_vless_link)) },
                            modifier = Modifier.fillMaxWidth(),
                        )
                    } else {
                        OutlinedTextField(
                            ssLink, { ssLink = it },
                            label = { Text(stringResource(R.string.dlg_ss_link)) },
                            modifier = Modifier.fillMaxWidth(),
                        )
                    }

                    Row(modifier = Modifier.fillMaxWidth().padding(top = 8.dp), verticalAlignment = Alignment.CenterVertically) {
                        Text(stringResource(R.string.dlg_padding), modifier = Modifier.weight(1f))
                        Switch(checked = paddingEnabled, onCheckedChange = { paddingEnabled = it })
                    }

                    OutlinedTextField(
                        rawOverride, { rawOverride = it },
                        label = { Text(stringResource(R.string.dlg_raw_toml)) },
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

    SubScreen(
        title = stringResource(R.string.home_link_split),
        icon = Icons.AutoMirrored.Filled.AltRoute,
        onBack = onBack,
    ) {
        SectionCard(padding = PaddingValues(vertical = 4.dp)) {
            Column {
                ModeOption(stringResource(R.string.split_mode_all), SplitMode.OFF, mode) { mode = it; persist() }
                ModeOption(stringResource(R.string.split_mode_only), SplitMode.ALLOWLIST, mode) { mode = it; persist() }
                ModeOption(stringResource(R.string.split_mode_except), SplitMode.DENYLIST, mode) { mode = it; persist() }
            }
        }

        when {
            selected == null ->
                Text(
                    stringResource(R.string.split_desc_all),
                    modifier = Modifier.padding(top = 16.dp),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            loading ->
                Text(stringResource(R.string.split_loading_apps), modifier = Modifier.padding(top = 16.dp))
            else -> {
                Text(
                    if (mode == SplitMode.ALLOWLIST) {
                        stringResource(R.string.split_desc_allow)
                    } else {
                        stringResource(R.string.split_desc_deny)
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
                    trailingIcon = {
                        if (query.isNotEmpty()) {
                            IconButton(onClick = { query = "" }) {
                                Icon(Icons.Filled.Clear, contentDescription = stringResource(R.string.a11y_clear_search))
                            }
                        }
                    },
                    placeholder = { Text(stringResource(R.string.split_search)) },
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
                                // Fixed-size box so a row keeps its height whether the
                                // icon has arrived, is still loading, or never comes.
                                val icon by rememberAppIcon(app.packageName, 40.dp)
                                Box(modifier = Modifier.size(40.dp)) {
                                    icon?.let {
                                        Image(
                                            bitmap = it,
                                            contentDescription = null,
                                            modifier = Modifier.fillMaxSize(),
                                        )
                                    }
                                }
                                Column(modifier = Modifier.padding(start = 12.dp)) {
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

    SubScreen(title = stringResource(R.string.home_link_external), icon = Icons.Filled.Tune, onBack = onBack) {
        SectionCard {
            Column {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Text(stringResource(R.string.ext_allow_commands), modifier = Modifier.weight(1f))
                    Switch(checked = enabled, onCheckedChange = { enabled = it; persist() })
                }
                OutlinedTextField(
                    token,
                    { token = it; persist() },
                    enabled = enabled,
                    singleLine = true,
                    shape = RoundedCornerShape(16.dp),
                    label = { Text(stringResource(R.string.ext_token)) },
                    supportingText = {
                        Text(stringResource(R.string.ext_token_help))
                    },
                    modifier = Modifier.fillMaxWidth().padding(top = 12.dp),
                )
            }
        }

        SectionCard(modifier = Modifier.padding(top = 12.dp)) {
            Column {
                Text(
                    stringResource(R.string.ext_supported_commands),
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.SemiBold,
                    color = MaterialTheme.colorScheme.onSurface,
                )
                Text(
                    """
                    outline://connect
                    outline://connect?profile=<name or id>
                    outline://disconnect
                    outline://toggle[?profile=<name or id>]
                    """.trimIndent(),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(top = 10.dp),
                )
                Text(
                    stringResource(R.string.ext_commands_note),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(top = 14.dp),
                )
            }
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
        modifier = Modifier.fillMaxWidth().clickable { onSelect(value) }
            .padding(horizontal = 4.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        RadioButton(selected = current == value, onClick = { onSelect(value) })
        Text(
            label,
            fontWeight = if (current == value) FontWeight.SemiBold else FontWeight.Normal,
            color = if (current == value) BrandBlue else MaterialTheme.colorScheme.onSurface,
        )
    }
}
