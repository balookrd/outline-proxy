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
import android.net.VpnService
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.ParcelFileDescriptor
import android.util.Log
import uniffi.outline_android.isRunning
import uniffi.outline_android.start
import uniffi.outline_android.stop

/**
 * The VPN tunnel service.
 *
 * Lifecycle: [MainActivity] obtains VPN consent, then sends [ACTION_CONNECT]
 * with the client TOML config. We open a TUN fd via [VpnService.Builder] and
 * hand it, plus the config, to the Rust core ([start]). [ACTION_DISCONNECT]
 * tears everything down.
 *
 * Increment 1: the Rust core brings up the SOCKS5 listener and uplinks. The
 * TUN fd is passed but routing TUN packets into SOCKS5 (tun2proxy) and
 * [protect]-ing uplink sockets land in increment 2.
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

    companion object {
        private const val TAG = "OutlineVpnService"
        const val ACTION_CONNECT = "com.outline.proxy.CONNECT"
        const val ACTION_DISCONNECT = "com.outline.proxy.DISCONNECT"
        const val EXTRA_CONFIG_TOML = "config_toml"

        private const val NOTIFICATION_CHANNEL_ID = "outline_vpn"
        private const val NOTIFICATION_ID = 1

        // The local SOCKS5 endpoint the Rust core listens on (must match the
        // `[socks5] listen` address in the TOML). Used by tun2proxy later.
        const val SOCKS_ADDRESS = "127.0.0.1"
        const val SOCKS_PORT = 1080

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
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_DISCONNECT -> {
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
                connect(configToml)
                return START_STICKY
            }
            else -> {
                stopSelf()
                return START_NOT_STICKY
            }
        }
    }

    private fun connect(configToml: String) {
        if (isRunning()) {
            Log.w(TAG, "client already running")
            return
        }

        val builder = Builder()
            .setSession("Outline Proxy")
            .setMtu(1500)
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
            stopSelf()
            return
        }
        tunInterface = tun

        startForeground(NOTIFICATION_ID, buildNotification())

        try {
            start(configToml, filesDir.absolutePath, tun.fd, "socks5://$SOCKS_ADDRESS:$SOCKS_PORT")
            Log.i(TAG, "outline-ws-rust client + TUN bridge started (tun fd=${tun.fd})")
            registerNetworkCallback()
        } catch (e: Exception) {
            Log.e(TAG, "failed to start client", e)
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
                config.packages.forEach { disallow(builder, it) }
                disallow(builder, packageName)
            }

            SplitMode.ALLOWLIST -> {
                val allowed = config.packages.filter { it != packageName }
                if (allowed.isEmpty()) {
                    Log.w(TAG, "allowlist is empty — no app traffic will be tunneled")
                }
                allowed.forEach { allow(builder, it) }
            }
        }
        Log.i(TAG, "split-tunnel mode=${config.mode} packages=${config.packages.size}")
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

    override fun onDestroy() {
        disconnect()
        super.onDestroy()
    }

    private fun buildNotification(): Notification {
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

        return Notification.Builder(this, NOTIFICATION_CHANNEL_ID)
            .setContentTitle("Outline Proxy")
            .setContentText("Tunnel active")
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setContentIntent(openApp)
            .setOngoing(true)
            .build()
    }
}
