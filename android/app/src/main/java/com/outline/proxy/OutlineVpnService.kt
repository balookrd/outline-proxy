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
import kotlinx.coroutines.withContext
import uniffi.outline_android.isRunning
import uniffi.outline_android.setDialTimeoutSecs
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
     * Whether the app owns the carrier-dial budget for this session — true when
     * the profile did not declare `[dial]` of its own. An explicit operator
     * value is never overridden, on start or on a later network change.
     */
    @Volatile
    private var dialBudgetManaged = false

    /**
     * Last budget handed to the core. `onCapabilitiesChanged` fires on every
     * signal-strength wobble, and re-applying the same number each time would
     * be pure noise in the log.
     */
    @Volatile
    private var appliedDialSecs: Int? = null

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
        const val ACTION_STANDBY = "com.outline.proxy.STANDBY"
        const val ACTION_STOP_STANDBY = "com.outline.proxy.STOP_STANDBY"
        const val EXTRA_CONFIG_TOML = "config_toml"

        // Bumped from the original "outline_vpn": a channel's badge setting is
        // immutable once created, so a new id is the only way setShowBadge(false)
        // takes effect over an existing install. The old channel is deleted.
        private const val NOTIFICATION_CHANNEL_ID = "outline_vpn_status"
        private const val LEGACY_NOTIFICATION_CHANNEL_ID = "outline_vpn"
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

        /**
         * Show the ongoing notification in standby (tunnel down) — used when the
         * persistent-notification setting is on and the tunnel is not running.
         * Called only from the visible settings screen, so a plain `startService`
         * is a legal foreground start.
         */
        fun enterStandby(context: Context) {
            runCatching {
                context.startService(
                    Intent(context, OutlineVpnService::class.java).apply { action = ACTION_STANDBY },
                )
            }.onFailure { Log.w(TAG, "cannot start standby", it) }
        }

        /**
         * Drop a standby notification: stop the service when the tunnel is down.
         * A running tunnel is left untouched — its own notification stays, and
         * the (now-off) setting simply lets the next disconnect stop the service.
         */
        fun exitStandby(context: Context) {
            if (isActive()) return
            runCatching {
                context.startService(
                    Intent(context, OutlineVpnService::class.java).apply { action = ACTION_STOP_STANDBY },
                )
            }.onFailure { Log.w(TAG, "cannot stop standby", it) }
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
            ACTION_STANDBY -> {
                // Persistent-notification mode wants the banner up even with the
                // tunnel down. Post it and stay foreground; do not touch the
                // tunnel. NOT_STICKY for standby: a killed standby returns when
                // the app is next opened, not via a sticky restart (the chosen
                // scope). If the tunnel is somehow already up (a race), keep it
                // sticky so we do not weaken a running tunnel's keep-alive.
                startForeground(NOTIFICATION_ID, currentNotification())
                return if (isRunning()) START_STICKY else START_NOT_STICKY
            }
            ACTION_STOP_STANDBY -> {
                if (!isRunning()) {
                    stopForeground(STOP_FOREGROUND_REMOVE)
                    stopSelf()
                }
                return START_NOT_STICKY
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
                // A revive can happen long after the last refresh (boot, an OEM
                // kill days later), so bring an expired subscription up to date
                // first; a failed fetch keeps the cached config.
                val target = profile!!
                notifScope.launch {
                    val config = SubscriptionRefresh.configForConnect(this@OutlineVpnService, target)
                    withContext(Dispatchers.Main) { connect(config) }
                }
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
            start(withDialBudget(configToml), filesDir.absolutePath, tun.fd)
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
                if (bestMatching) bind(network) else bind(LinkProbe.bestNonVpn(cm))
                refreshDialBudget()
            }

            /**
             * A handover between cells — and, on many devices, a data-SIM switch
             * — arrives here rather than as `onAvailable`/`onLost`: the `Network`
             * stays the same object while its properties change underneath,
             * including the bandwidth estimate the dial budget is sized from.
             * Watching only the two coarse callbacks would leave the tunnel on a
             * budget picked for a network that no longer exists.
             */
            override fun onCapabilitiesChanged(
                network: Network,
                networkCapabilities: NetworkCapabilities,
            ) {
                refreshDialBudget()
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
                    bind(LinkProbe.bestNonVpn(cm))
                }
                refreshDialBudget()
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

    /**
     * Size the carrier-dial budget for the link this tunnel is about to ride and
     * write it into the profile.
     *
     * The generated profile ships no `[dial]` section, so every network gets the
     * core's 10 s default — the very budget that cannot complete a handshake on
     * an edge-class cell. See [DialTimeout] for the thresholds and for why the
     * choice is fixed at start.
     *
     * The network is resolved the same way the underlying-network watch resolves
     * it, and deliberately *not* via `activeNetwork`: `establish()` has already
     * run by this point, so our own VPN would answer for it.
     */
    private fun withDialBudget(configToml: String): String {
        dialBudgetManaged = !DialTimeout.declaresDial(configToml)
        val seconds = currentDialSeconds()
        appliedDialSecs = seconds
        if (seconds != null && dialBudgetManaged) {
            Log.i(TAG, "slow link: raising the carrier-dial budget to ${seconds}s")
        }
        return DialTimeout.applyTo(configToml, seconds)
    }

    /**
     * The budget this link calls for, or `null` for the engine default.
     *
     * Resolved off the same non-VPN network the underlying-network watch picks,
     * deliberately not `activeNetwork`: once `establish()` has run, our own VPN
     * would answer for it.
     */
    private fun currentDialSeconds(): Int? = runCatching {
        val cm = getSystemService(ConnectivityManager::class.java) ?: return@runCatching null
        val network = underlyingNetwork ?: LinkProbe.bestNonVpn(cm) ?: return@runCatching null
        val caps = cm.getNetworkCapabilities(network) ?: return@runCatching null
        // The core's own measurement, once it has one — it outranks the
        // platform's bandwidth claim, which some firmware invents. Null before
        // the first dial completes, and on the pre-start call where no engine is
        // running yet; the estimate covers that gap.
        val measured = runCatching { tunnelStatus() }.getOrNull()?.let {
            LinkQuality.worstOf(it.tcpLatencyMs?.toInt(), it.udpLatencyMs?.toInt())
        }
        DialTimeout.secondsFor(
            isCellular = caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR),
            downstreamKbps = caps.linkDownstreamBandwidthKbps,
            latencyMs = measured,
        )
    }.getOrNull()

    /**
     * Re-size the running engine's dial budget for the link now underneath it.
     *
     * The budget written into the TOML only describes the network the tunnel
     * *started* on. Walking from Wi-Fi into a 2G cell would otherwise leave the
     * 10 s default in place, where it expires mid-handshake and scores every
     * attempt a failure; walking back would leave a 60 s bound slowing every
     * failover down. Both directions are handled: `null` restores the default.
     */
    @Synchronized
    private fun refreshDialBudget() {
        if (!dialBudgetManaged) return
        val seconds = currentDialSeconds()
        if (seconds == appliedDialSecs) return
        appliedDialSecs = seconds
        runCatching { setDialTimeoutSecs(seconds?.toUInt()) }
            .onSuccess {
                Log.i(TAG, "carrier-dial budget -> ${seconds?.let { "${it}s" } ?: "engine default"}")
            }
            .onFailure { Log.w(TAG, "cannot re-size the carrier-dial budget", it) }
    }

    /** Bind [network] as the tunnel's underlying network; `null` = system default. */
    private fun bind(network: Network?) {
        if (network == underlyingNetwork) return
        underlyingNetwork = network
        setUnderlyingNetworks(network?.let { arrayOf(it) })
        Log.i(TAG, "underlying network -> ${network ?: "system default"}")
    }

    private fun unregisterNetworkCallback() {
        val cm = getSystemService(ConnectivityManager::class.java)
        networkCallback?.let { cb ->
            runCatching { cm?.unregisterNetworkCallback(cb) }
        }
        networkCallback = null
        underlyingNetwork = null
        // The next session re-derives both from its own profile and network.
        dialBudgetManaged = false
        appliedDialSecs = null
    }

    /**
     * Tear the tunnel down — core, TUN, network callbacks, notification updates —
     * without deciding the service's fate. Shared by the deliberate-disconnect
     * path and by [onDestroy].
     */
    private fun teardownTunnel() {
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
    }

    /**
     * A user-driven disconnect. Tears the tunnel down, then either drops into
     * standby (persistent-notification on: keep the ongoing banner with a Connect
     * button) or stops the service outright (the default, unchanged behaviour).
     */
    private fun disconnect() {
        teardownTunnel()
        if (KeepAliveState(this).persistentNotification) {
            startForeground(NOTIFICATION_ID, buildNotification(running = false, status = "Disconnected"))
        } else {
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
        }
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
        teardownTunnel()
        super.onDestroy()
    }

    private fun buildNotification(
        running: Boolean = true,
        status: String = "Connecting…",
        detail: String? = null,
    ): Notification {
        val manager = getSystemService(NotificationManager::class.java)
        val channel = NotificationChannel(
            NOTIFICATION_CHANNEL_ID,
            "VPN status",
            NotificationManager.IMPORTANCE_LOW,
        ).apply {
            // No launcher badge for an always-present status banner: an ongoing
            // notification is not an unread alert, and the dot on the app icon
            // reads as one. Only meaningful on the channel's first creation.
            setShowBadge(false)
        }
        manager.createNotificationChannel(channel)
        // Retire the pre-badge-fix channel so it does not linger in settings.
        manager.deleteNotificationChannel(LEGACY_NOTIFICATION_CHANNEL_ID)

        val openApp = PendingIntent.getActivity(
            this,
            0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE,
        )

        // One status-aware toggle: Disconnect while the tunnel is up (straight to
        // the service, instant), Connect while it is down (an activity, because
        // showing VPN consent needs one — QuickConnectActivity, first-party and
        // exported=false).
        val (actionLabel, actionIcon, actionIntent) = when (NotificationPolicy.toggle(running)) {
            NotifToggle.DISCONNECT -> Triple(
                "Disconnect",
                android.R.drawable.ic_menu_close_clear_cancel,
                PendingIntent.getService(
                    this,
                    1,
                    Intent(this, OutlineVpnService::class.java).apply { action = ACTION_DISCONNECT },
                    PendingIntent.FLAG_IMMUTABLE,
                ),
            )
            NotifToggle.CONNECT -> Triple(
                "Connect",
                android.R.drawable.ic_media_play,
                PendingIntent.getActivity(
                    this,
                    2,
                    Intent(this, QuickConnectActivity::class.java),
                    PendingIntent.FLAG_IMMUTABLE,
                ),
            )
        }

        // Name the active profile in the banner so the user can tell at a glance
        // which server the tunnel is on. The title carries the live status.
        val store = ProfileStore(this)
        val profile = store.load().firstOrNull { it.id == store.selectedId }
        val name = profile?.name?.takeIf { it.isNotBlank() }
        val title = if (name != null) "$status · $name" else status

        // Second line: the live traffic readout while connected. With none to show
        // (standby / connecting) name the server's transport instead of leaving it
        // empty or padding it with the app name — an empty content line just opens
        // a gap above the action button, and the app name is already in the header.
        val body = detail ?: profile?.let {
            if (it.isSubscription) "Subscription" else it.transport.ifBlank { null }
        }

        return Notification.Builder(this, NOTIFICATION_CHANNEL_ID)
            .setContentTitle(title)
            .setContentText(body)
            .setSmallIcon(R.drawable.ic_stat_tunnel)
            // The cyan of the emblem's "wires"; the launcher tints the small-icon
            // circle with this instead of the OEM default accent.
            .setColor(0xFF40C4FF.toInt())
            .setContentIntent(openApp)
            .setOngoing(true)
            .addAction(
                Notification.Action.Builder(
                    Icon.createWithResource(this, actionIcon),
                    actionLabel,
                    actionIntent,
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
                // Safety net for the dial budget. A generation change
                // (2G -> 3G -> LTE and back) normally arrives as
                // `onCapabilitiesChanged` on the same Network, but not every
                // firmware reports the bandwidth estimate again when the radio
                // technology changes, and a missed event would strand the
                // tunnel on a budget sized for a network it left. The check is
                // a capability read plus a comparison against the value already
                // applied, so a tick that changes nothing costs nothing.
                refreshDialBudget()
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
        if (!running) {
            // Standby: a static "Disconnected" banner with a Connect action and
            // no traffic line — the session counters are meaningless with nothing
            // running (and the baseline may be zero, which would print the whole
            // device total as this session's).
            return buildNotification(running = false, status = "Disconnected", detail = null)
        }
        val status0 = runCatching { tunnelStatus() }.getOrNull()
        val hasLink = status0?.hasLiveLink ?: false
        // Same qualifier the home screen applies: an edge-class link is up and
        // unusable at once, and the banner is where the user looks first.
        val latencyMs = LinkQuality.worstOf(
            status0?.tcpLatencyMs?.toInt(),
            status0?.udpLatencyMs?.toInt(),
        )
        // The core health flag is instantaneous and can blip false for a tick;
        // keep "Connecting…" until the link has been absent past the grace window.
        if (hasLink) lastLinkAtMs = System.currentTimeMillis()
        val connecting = !hasLink &&
            System.currentTimeMillis() - lastLinkAtMs < NO_LINK_GRACE_MS
        val status = when {
            hasLink -> LinkQuality.connectedLabel(latencyMs)
            connecting -> "Connecting…"
            else -> "No link"
        }
        val up = (TrafficStats.getTotalTxBytes() - trafficBaseTx).coerceAtLeast(0)
        val down = (TrafficStats.getTotalRxBytes() - trafficBaseRx).coerceAtLeast(0)
        return buildNotification(
            running = true,
            status = status,
            detail = "↑ ${formatBytes(up)}   ↓ ${formatBytes(down)}",
        )
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
