package com.outline.proxy

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.telephony.TelephonyManager
import androidx.core.content.ContextCompat

/**
 * Reads the link underneath the tunnel off the platform — the Android-facing
 * half of [LinkInfo], which does the interpreting.
 *
 * Shared by the VPN service, which sizes the carrier-dial budget from it, and by
 * the home screen, which shows it. One reader means the two can never disagree
 * about which network they are talking about.
 */
object LinkProbe {

    /**
     * The best non-VPN network currently connected, or `null` when there is
     * none.
     *
     * Never `activeNetwork`: with the tunnel established, our own VPN answers
     * for it. Validated beats unvalidated, then Ethernet > Wi-Fi > cellular —
     * the same order the platform's best-matching callback applies, which is
     * what makes this a faithful stand-in below API 31 where that callback does
     * not exist.
     */
    @Suppress("DEPRECATION") // getAllNetworks(): the pre-31 path, and the only way to rank them ourselves.
    fun bestNonVpn(cm: ConnectivityManager): Network? =
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

    /**
     * Snapshot of the current link, with [latencyMs] — what the tunnel actually
     * measures — folded in.
     *
     * Everything is best-effort: a device that refuses one of these queries
     * yields a line with that part missing, never a crash on the polling path.
     */
    fun read(context: Context, latencyMs: Int?): LinkReadout {
        val cm = context.getSystemService(ConnectivityManager::class.java)
        val caps = cm?.let { manager -> bestNonVpn(manager)?.let { manager.getNetworkCapabilities(it) } }
        val transport = when {
            caps == null -> LinkTransport.NONE
            caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> LinkTransport.WIFI
            caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> LinkTransport.CELLULAR
            caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> LinkTransport.ETHERNET
            else -> LinkTransport.OTHER
        }
        val downstreamKbps = caps?.linkDownstreamBandwidthKbps?.takeIf { it > 0 }
        return LinkReadout(
            transport = transport,
            downstreamKbps = downstreamKbps,
            ranLabel = if (transport == LinkTransport.CELLULAR) ranLabel(context) else null,
            latencyMs = latencyMs,
        )
    }

    /** Whether the exact radio technology can be read at all right now. */
    fun canReadRan(context: Context): Boolean =
        ContextCompat.checkSelfPermission(context, Manifest.permission.READ_PHONE_STATE) ==
            PackageManager.PERMISSION_GRANTED

    /**
     * The radio technology, or `null` without `READ_PHONE_STATE`.
     *
     * The permission is never requested from here — the Keep Alive checklist
     * offers it alongside the other grants, with the same explanation of what it
     * buys. Without it the line simply says "Cellular"; nothing else on screen
     * or in the tunnel's own decisions depends on the answer.
     */
    private fun ranLabel(context: Context): String? {
        if (!canReadRan(context)) return null
        val tm = context.getSystemService(TelephonyManager::class.java) ?: return null
        return runCatching { LinkInfo.ranLabel(tm.dataNetworkType) }.getOrNull()
    }
}
