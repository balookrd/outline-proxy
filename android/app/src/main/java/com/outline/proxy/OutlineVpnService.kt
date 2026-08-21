package com.outline.proxy

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.TrafficStats
import android.net.VpnService
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.graphics.drawable.Icon
import android.os.ParcelFileDescriptor
import android.util.Log
import androidx.core.content.ContextCompat
import com.outline.proxy.keepalive.WatchdogAlarm
import com.outline.proxy.keepalive.WatchdogWorker
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import uniffi.outline_android.isRunning
import uniffi.outline_android.start
import uniffi.outline_android.stop
import uniffi.outline_android.tunnelStatus
import java.util.Locale

/**
 * The VPN tunnel service.
 *
 * Lifecycle: [MainActivity] obtains VPN consent, then sends [ACTION_CONNECT]
 * with the client TOML config. We open a TUN fd via [VpnService.Builder] and
 * hand it, plus the config, to the Rust core ([start]). [ACTION_DISCONNECT]
 * tears everything down.
 *
 * The Rust core attaches the native outline-tun engine directly to this fd and
 * brings up the uplinks. Loop avoidance is via [applySplitTunnel]
 * (addDisallowedApplication), so uplink sockets bypass the TUN.
 */
class OutlineVpnService : VpnService() {

    private var tunInterface: ParcelFileDescriptor? = null
    private var networkCallback: ConnectivityManager.NetworkCallback? = null

    /**
     * The network currently bound as the tunnel's underlying one. Written from
     * the ConnectivityManager callback thread, read from there and from
     * [disconnect] on the main thread, hence `@Volatile`.
     */
    @Volatile
    private var underlyingNetwork: Network? = null

    /** Drives the periodic refresh of the ongoing tunnel notification. */
    private val notifScope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private var notifJob: Job? = null

    /** `TrafficStats` byte counters captured at connect, so the banner can show
     *  bytes moved this session. */
    private var trafficBaseTx = 0L
    private var trafficBaseRx = 0L

    /** When the tunnel last had a live link (or the session start). Debounces the
     *  status: a brief drop below the grace window reads "Connecting…", not the
     *  jarring "No link" flash. */
    @Volatile
    private var lastLinkAtMs = 0L

    companion object {
        private const val TAG = "OutlineVpnService"
        const val ACTION_CONNECT = "com.outline.proxy.CONNECT"
        const val ACTION_DISCONNECT = "com.outline.proxy.DISCONNECT"
        const val ACTION_ENSURE = "com.outline.proxy.ENSURE"
        const val EXTRA_CONFIG_TOML = "config_toml"

        private const val NOTIFICATION_CHANNEL_ID = "outline_vpn"
        private const val NOTIFICATION_ID = 1

        /** How long the status stays "Connecting…" after the link drops (or from
         *  connect) before it reads "No link" — debounces transient health flaps
         *  so a brief blip does not flash "No link". Mirrors the home screen. */
        private const val NO_LINK_GRACE_MS = 2_000L

        /** How often the ongoing notification refreshes its status and traffic. */
        private const val NOTIFICATION_REFRESH_MS = 2_000L

        /** Channel for revival failures; separate from the ongoing tunnel notification. */
        const val NOTIFICATION_CHANNEL_ALERTS = "outline_vpn_alerts"
        private const val NOTIFICATION_ID_ALERT = 2

        private const val TASK_REMOVED_DELAY_MS = 1_000L
        private const val DESTROY_DELAY_MS = 2_000L

        /**
         * Whether the tunnel is up, as reported by the Rust core (same process,
         * so this is the live state, not a cached flag). Used by
         * [ControlActivity] to decide what `outline://toggle` means. Defaults to
         * "down" if the native library cannot be loaded.
         */
        fun isActive(): Boolean = runCatching { isRunning() }.getOrDefault(false)

        /** Ask the service to bring the tunnel up with [configToml]. */
        fun requestConnect(context: Context, configToml: String) {
            context.startService(
                Intent(context, OutlineVpnService::class.java).apply {
                    action = ACTION_CONNECT
                    putExtra(EXTRA_CONFIG_TOML, configToml)
                },
            )
        }

        /** Ask the service to tear the tunnel down. */
        fun requestDisconnect(context: Context) {
            context.startService(
                Intent(context, OutlineVpnService::class.java).apply {
                    action = ACTION_DISCONNECT
                },
            )
        }

        /**
         * The single revival entry point: every path that might have to bring the
         * tunnel back (always-on VPN, boot, watchdog alarm, worker, onDestroy)
         * calls this instead of assembling a connect of its own.
         */
        fun ensure(context: Context) {
            val intent = Intent(context, OutlineVpnService::class.java).apply {
                action = ACTION_ENSURE
            }
            // Android 12+ forbids starting a foreground service from the
            // background unless an exemption applies (battery-optimisation
            // allowlist, exact alarm, BOOT_COMPLETED). Losing that race must not
            // crash the receiver we are called from.
            runCatching { ContextCompat.startForegroundService(context, intent) }
                .onFailure { Log.w(TAG, "cannot start the service from the background", it) }
        }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_DISCONNECT -> {
                KeepAliveState(this).shouldRun = false
                WatchdogAlarm.cancel(this)
                WatchdogWorker.cancel(this)
                disconnect()
                return START_NOT_STICKY
            }
            ACTION_CONNECT -> {
                val configToml = intent.getStringExtra(EXTRA_CONFIG_TOML)
                if (configToml.isNullOrBlank()) {
                    Log.e(TAG, "missing config TOML; refusing to start")
                    stopSelf()
                    return START_NOT_STICKY
                }
                KeepAliveState(this).shouldRun = true
                WatchdogWorker.schedule(this)
                connect(configToml)
                return START_STICKY
            }
            // A null action is the system starting us: always-on VPN, or a
            // START_STICKY restart after the process was killed. Both mean
            // "bring the tunnel back if it should be up".
            ACTION_ENSURE, null -> {
                ensureTunnel()
                return START_STICKY
            }
            else -> {
                stopSelf()
                return START_NOT_STICKY
            }
        }
    }

    /**
     * Act on [KeepAlivePolicy]'s verdict.
     *
     * The foreground notification goes up first, unconditionally: we may have
     * been started with `startForegroundService`, and the system kills a service
     * that fails to call `startForeground` within a few seconds — including on
     * the paths where the answer turns out to be "do nothing".
     */
    private fun ensureTunnel() {
        startForeground(NOTIFICATION_ID, buildNotification())

        val state = KeepAliveState(this)
        val store = ProfileStore(this)
        val profile = store.load().firstOrNull { it.id == store.selectedId }

        val decision = KeepAlivePolicy.decide(
            shouldRun = state.shouldRun,
            coreAlive = isActive(),
            // prepare() returns an Intent when consent is missing; from a
            // background start there is no way to show it, only to detect it.
            consentGranted = prepare(this) == null,
            hasProfile = profile != null && profile.toToml().isNotBlank(),
            consecutiveFailures = state.consecutiveFailures,
        )
        Log.i(TAG, "ensure: ${decision.action}")

        when (decision.action) {
            KeepAliveAction.NOTHING -> {
                WatchdogAlarm.schedule(this, decision.retryDelayMs)
                // Core already alive (e.g. a revived process): keep the banner
                // refreshing if nothing is doing so yet.
                if (notifJob == null) {
                    captureTrafficBaseline()
                    startNotificationUpdates()
                }
            }
            KeepAliveAction.STOP -> {
                WatchdogAlarm.cancel(this)
                stopForeground(STOP_FOREGROUND_REMOVE)
                stopSelf()
            }
            KeepAliveAction.GIVE_UP -> {
                state.shouldRun = false
                WatchdogAlarm.cancel(this)
                alert("Tunnel cannot start", "Open Outline Proxy and connect again.")
                stopForeground(STOP_FOREGROUND_REMOVE)
                stopSelf()
            }
            KeepAliveAction.CONNECT -> {
                // The core may be dead while this service is alive; the old fd is
                // nobody's now, so tear the tunnel down before rebuilding it.
                tunInterface?.close()
                tunInterface = null
                WatchdogAlarm.schedule(this, decision.retryDelayMs)
                connect(profile!!.toToml())
            }
        }
    }

    /** A one-off notification about a failure the user has to fix. */
    private fun alert(title: String, text: String) {
        val manager = getSystemService(NotificationManager::class.java)
        manager.createNotificationChannel(
            NotificationChannel(
                NOTIFICATION_CHANNEL_ALERTS,
                "VPN alerts",
                NotificationManager.IMPORTANCE_DEFAULT,
            ),
        )
        val openApp = PendingIntent.getActivity(
            this,
            0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE,
        )
        manager.notify(
            NOTIFICATION_ID_ALERT,
            Notification.Builder(this, NOTIFICATION_CHANNEL_ALERTS)
                .setContentTitle(title)
                .setContentText(text)
                .setSmallIcon(android.R.drawable.ic_dialog_alert)
                .setContentIntent(openApp)
                .setAutoCancel(true)
                .build(),
        )
    }

    private fun connect(configToml: String) {
        if (isRunning()) {
            Log.w(TAG, "client already running")
            return
        }

        val builder = Builder()
            .setSession("Outline Proxy")
            .setMtu(ServerProfile.TUN_MTU) // single source of the TUN MTU; must match `[tun] mtu` in the TOML
            // A private address space for the tunnel interface.
            .addAddress("10.111.0.2", 32)
            .addAddress("fd00:0:0:111::2", 64)
            // Default routes: everything goes through the tunnel for now.
            // Per-app split tunneling (addAllowed/DisallowedApplication) lands
            // in a later increment.
            .addRoute("0.0.0.0", 0)
            .addRoute("::", 0)
            .addDnsServer("1.1.1.1")
            .addDnsServer("2606:4700:4700::1111")

        applySplitTunnel(builder)

        val tun = builder.establish()
        if (tun == null) {
            Log.e(TAG, "VpnService.establish() returned null (no consent?)")
            KeepAliveState(this).recordFailure()
            stopSelf()
            return
        }
        tunInterface = tun

        startForeground(NOTIFICATION_ID, buildNotification())

        val state = KeepAliveState(this)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            state.alwaysOnSeen = isAlwaysOn
        }
        try {
            start(configToml, filesDir.absolutePath, tun.fd)
            Log.i(TAG, "outline-ws-rust client started with native TUN (fd=${tun.fd})")
            state.clearFailures()
            if (state.connectedSince == 0L) state.connectedSince = System.currentTimeMillis()
            captureTrafficBaseline()
            startNotificationUpdates()
            registerNetworkCallback()
        } catch (e: Exception) {
            Log.e(TAG, "failed to start client", e)
            val failures = state.recordFailure()
            WatchdogAlarm.schedule(this, KeepAlivePolicy.backoffFor(failures))
            disconnect()
        }
    }

    /**
     * Apply the per-app split-tunnel policy to the tunnel.
     *
     * Loop avoidance: the uplink sockets the Rust core opens must bypass the
     * TUN. In OFF / DENYLIST we exclude this app explicitly; in ALLOWLIST we
     * simply never add ourselves, so we bypass by omission. Android forbids
     * mixing allowed and disallowed apps, hence the exclusive branches.
     */
    private fun applySplitTunnel(builder: Builder) {
        val config = SplitTunnelStore(this).load()
        when (config.mode) {
            SplitMode.OFF -> disallow(builder, packageName)

            SplitMode.DENYLIST -> {
                config.denyPackages.forEach { disallow(builder, it) }
                disallow(builder, packageName)
            }

            SplitMode.ALLOWLIST -> {
                val allowed = config.allowPackages.filter { it != packageName }
                if (allowed.isEmpty()) {
                    Log.w(TAG, "allowlist is empty — no app traffic will be tunneled")
                }
                allowed.forEach { allow(builder, it) }
            }
        }
        Log.i(
            TAG,
            "split-tunnel mode=${config.mode} " +
                "allow=${config.allowPackages.size} deny=${config.denyPackages.size}",
        )
    }

    private fun allow(builder: Builder, pkg: String) {
        try {
            builder.addAllowedApplication(pkg)
        } catch (e: PackageManager.NameNotFoundException) {
            Log.w(TAG, "allow: package not found: $pkg")
        }
    }

    private fun disallow(builder: Builder, pkg: String) {
        try {
            builder.addDisallowedApplication(pkg)
        } catch (e: PackageManager.NameNotFoundException) {
            Log.w(TAG, "disallow: package not found: $pkg")
        }
    }

    /**
     * Track the network the (excluded) uplink sockets should ride, and follow
     * Wi-Fi ⇄ cellular handovers. When the underlying network changes,
     * in-flight uplink connections break and the ws-rust failover layer re-dials
     * over the new path.
     *
     * Two traps this deliberately avoids:
     *
     *  - **Matching everything.** An empty [NetworkRequest] matches every
     *    network the device sees, so a cellular network coming up next to a
     *    perfectly good Wi-Fi would be bound as the underlying one. The request
     *    below asks for `INTERNET` and, on API 31+, lets the platform hand us
     *    the single *best* match instead of all of them.
     *  - **Binding our own tunnel.** [ConnectivityManager.registerDefaultNetworkCallback]
     *    reports the VPN network itself to the app that owns the VPN, which
     *    makes the tunnel its own underlying network (`underlying{[N]}` pointing
     *    at our own agent). `NET_CAPABILITY_NOT_VPN` keeps us on physical
     *    networks.
     */
    private fun registerNetworkCallback() {
        val cm = getSystemService(ConnectivityManager::class.java) ?: return
        val request = NetworkRequest.Builder()
            .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
            .build()
        // API 31+ delivers exactly one network — the best match — and swaps it
        // on handover, so we follow it verbatim. Below that, every match is
        // delivered, so we pick the best one ourselves on each change.
        val bestMatching = Build.VERSION.SDK_INT >= Build.VERSION_CODES.S
        val cb = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                if (bestMatching) bind(network) else bind(pickBest(cm))
            }

            /**
             * A handover can deliver `onAvailable(new)` before `onLost(old)`, so
             * an unconditional reset here would undo the binding just made and
             * drop the tunnel back to the system default. Only the loss of the
             * network actually in use matters.
             */
            override fun onLost(network: Network) {
                if (bestMatching) {
                    if (underlyingNetwork == network) bind(null)
                } else {
                    bind(pickBest(cm))
                }
            }
        }
        // Losing the handover watch is not worth losing the tunnel over: the
        // uplinks still ride the system default, they just stop being re-bound.
        runCatching {
            if (bestMatching) {
                cm.registerBestMatchingNetworkCallback(
                    request,
                    cb,
                    Handler(Looper.getMainLooper()),
                )
            } else {
                cm.registerNetworkCallback(request, cb)
            }
        }
            .onSuccess { networkCallback = cb }
            .onFailure { Log.w(TAG, "cannot watch the underlying network", it) }
    }

    /** Bind [network] as the tunnel's underlying network; `null` = system default. */
    private fun bind(network: Network?) {
        if (network == underlyingNetwork) return
        underlyingNetwork = network
        setUnderlyingNetworks(network?.let { arrayOf(it) })
        Log.i(TAG, "underlying network -> ${network ?: "system default"}")
    }

    /**
     * Pre-31 fallback: rank the currently connected non-VPN networks ourselves.
     * Validated beats unvalidated, then Ethernet > Wi-Fi > cellular > anything
     * else — the same order the platform's best-matching callback would apply.
     */
    @Suppress("DEPRECATION") // getAllNetworks(): only reached below API 31.
    private fun pickBest(cm: ConnectivityManager): Network? =
        cm.allNetworks
            .mapNotNull { n -> cm.getNetworkCapabilities(n)?.let { n to it } }
            .filter {
                it.second.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) &&
                    it.second.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
            }
            .maxWithOrNull(
                compareBy(
                    { it.second.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED) },
                    { transportRank(it.second) },
                ),
            )
            ?.first

    private fun transportRank(caps: NetworkCapabilities): Int = when {
        caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> 3
        caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> 2
        caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> 1
        else -> 0
    }

    private fun unregisterNetworkCallback() {
        val cm = getSystemService(ConnectivityManager::class.java)
        networkCallback?.let { cb ->
            runCatching { cm?.unregisterNetworkCallback(cb) }
        }
        networkCallback = null
        underlyingNetwork = null
    }

    private fun disconnect() {
        stopNotificationUpdates()
        KeepAliveState(this).connectedSince = 0L
        unregisterNetworkCallback()
        try {
            if (isRunning()) stop()
        } catch (e: Exception) {
            Log.e(TAG, "error stopping client", e)
        }
        tunInterface?.close()
        tunInterface = null
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    /**
     * The user swiped the app away. With `stopWithTask="false"` the service
     * survives, but some OEM builds tear the process down anyway — so schedule a
     * check right behind it.
     */
    override fun onTaskRemoved(rootIntent: Intent?) {
        if (KeepAliveState(this).shouldRun) {
            WatchdogAlarm.schedule(this, TASK_REMOVED_DELAY_MS)
        }
        super.onTaskRemoved(rootIntent)
    }

    override fun onDestroy() {
        // A deliberate disconnect clears shouldRun first, so this only fires
        // when something else killed us.
        if (KeepAliveState(this).shouldRun) {
            WatchdogAlarm.schedule(this, DESTROY_DELAY_MS)
        }
        disconnect()
        super.onDestroy()
    }

    private fun buildNotification(
        status: String = "Connecting…",
        detail: String? = null,
    ): Notification {
        val manager = getSystemService(NotificationManager::class.java)
        val channel = NotificationChannel(
            NOTIFICATION_CHANNEL_ID,
            "VPN status",
            NotificationManager.IMPORTANCE_LOW,
        )
        manager.createNotificationChannel(channel)

        val openApp = PendingIntent.getActivity(
            this,
            0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE,
        )
        val disconnect = PendingIntent.getService(
            this,
            1,
            Intent(this, OutlineVpnService::class.java).apply { action = ACTION_DISCONNECT },
            PendingIntent.FLAG_IMMUTABLE,
        )

        // Name the active profile in the banner so the user can tell at a glance
        // which server the tunnel is on. The title carries the live status, the
        // text the bytes moved this session.
        val store = ProfileStore(this)
        val name = store.load().firstOrNull { it.id == store.selectedId }?.name?.takeIf { it.isNotBlank() }
        val title = if (name != null) "$status · $name" else status

        return Notification.Builder(this, NOTIFICATION_CHANNEL_ID)
            .setContentTitle(title)
            .setContentText(detail ?: "Outline Proxy")
            .setSmallIcon(R.drawable.ic_stat_tunnel)
            // The cyan of the emblem's "wires"; the launcher tints the small-icon
            // circle with this instead of the OEM default accent.
            .setColor(0xFF40C4FF.toInt())
            .setContentIntent(openApp)
            .setOngoing(true)
            .addAction(
                Notification.Action.Builder(
                    Icon.createWithResource(this, android.R.drawable.ic_menu_close_clear_cancel),
                    "Disconnect",
                    disconnect,
                ).build(),
            )
            .build()
    }

    /** Capture the current TrafficStats counters as the session baseline, and
     *  seed the link-grace clock so the connect itself gets a "Connecting…"
     *  window before any "No link". */
    private fun captureTrafficBaseline() {
        trafficBaseTx = TrafficStats.getTotalTxBytes().coerceAtLeast(0)
        trafficBaseRx = TrafficStats.getTotalRxBytes().coerceAtLeast(0)
        lastLinkAtMs = System.currentTimeMillis()
    }

    /**
     * Refresh the ongoing notification with the live status and traffic until
     * the tunnel goes down. Runs off the main thread — `tunnelStatus()` blocks
     * briefly on the core's runtime.
     */
    private fun startNotificationUpdates() {
        notifJob?.cancel()
        notifJob = notifScope.launch {
            val manager = getSystemService(NotificationManager::class.java)
            while (isActive) {
                runCatching { manager?.notify(NOTIFICATION_ID, currentNotification()) }
                delay(NOTIFICATION_REFRESH_MS)
            }
        }
    }

    private fun stopNotificationUpdates() {
        notifJob?.cancel()
        notifJob = null
    }

    /**
     * Build the notification for the tunnel's current state: status mirroring the
     * home screen (Connecting… / Connected / No link) and the bytes moved this
     * session.
     */
    private fun currentNotification(): Notification {
        val running = runCatching { isRunning() }.getOrDefault(false)
        val hasLink = runCatching { tunnelStatus()?.hasLiveLink ?: false }.getOrDefault(false)
        // The core health flag is instantaneous and can blip false for a tick;
        // keep "Connecting…" until the link has been absent past the grace window.
        if (hasLink) lastLinkAtMs = System.currentTimeMillis()
        val connecting = running && !hasLink &&
            System.currentTimeMillis() - lastLinkAtMs < NO_LINK_GRACE_MS
        val status = when {
            !running -> "Disconnected"
            hasLink -> "Connected"
            connecting -> "Connecting…"
            else -> "No link"
        }
        val up = (TrafficStats.getTotalTxBytes() - trafficBaseTx).coerceAtLeast(0)
        val down = (TrafficStats.getTotalRxBytes() - trafficBaseRx).coerceAtLeast(0)
        return buildNotification(status, "↑ ${formatBytes(up)}   ↓ ${formatBytes(down)}")
    }

    /** Human-readable byte count for the banner ("0 B", "1.2 MB"). */
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
}
