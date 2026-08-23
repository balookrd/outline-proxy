package com.outline.proxy

import android.telephony.TelephonyManager

/** Which kind of link the tunnel's own sockets are riding. */
enum class LinkTransport { WIFI, CELLULAR, ETHERNET, OTHER, NONE }

/**
 * Everything the status card knows about the link underneath the tunnel.
 *
 * [ranLabel] is the radio access technology as the platform names it, and is
 * `null` whenever it cannot be had: on Wi-Fi, or on cellular without
 * `READ_PHONE_STATE`. The speed class derived from [downstreamKbps] stands in
 * for it there — coarser, but free of any permission.
 */
data class LinkReadout(
    val transport: LinkTransport,
    val downstreamKbps: Int?,
    val ranLabel: String?,
    val latencyMs: Int?,
)

/**
 * Turns what the platform reports about the current link into the one line the
 * home screen shows under the status.
 *
 * Two independent sources, deliberately: the bandwidth estimate is always
 * available and drives both this readout and the carrier-dial budget
 * ([DialTimeout]), while the exact radio technology needs `READ_PHONE_STATE`
 * and is only shown once the user grants it. Nothing here asks for the
 * permission: it is offered as one item among the others on the Keep Alive
 * checklist, where the app already explains what each grant buys.
 *
 * Kept free of Android calls (only integer constants are referenced, which the
 * compiler inlines) so it can be unit-tested.
 */
object LinkInfo {

    /**
     * Speed class inferred from the platform's own estimate, using the same
     * thresholds the dial budget is sized on — so "2G-class" on the card and a
     * 60-second dial budget always tell the same story.
     */
    fun speedClass(downstreamKbps: Int?): String? {
        val kbps = downstreamKbps ?: return null
        if (kbps <= 0) return null
        return when {
            kbps <= DialTimeout.EDGE_KBPS -> "2G-class"
            kbps <= DialTimeout.SLOW_KBPS -> "3G-class"
            else -> null
        }
    }

    /**
     * Generation name for a `TelephonyManager.NETWORK_TYPE_*` value, or `null`
     * when the platform does not know one either.
     *
     * Grouped by generation rather than by exact technology: "HSPA+ vs HSDPA"
     * says nothing a user acts on, whereas "3G when you expected LTE" does.
     */
    fun ranLabel(dataNetworkType: Int): String? = when (dataNetworkType) {
        TelephonyManager.NETWORK_TYPE_GPRS,
        TelephonyManager.NETWORK_TYPE_EDGE,
        TelephonyManager.NETWORK_TYPE_CDMA,
        TelephonyManager.NETWORK_TYPE_1xRTT,
        TelephonyManager.NETWORK_TYPE_IDEN,
        TelephonyManager.NETWORK_TYPE_GSM,
        -> "2G"

        TelephonyManager.NETWORK_TYPE_UMTS,
        TelephonyManager.NETWORK_TYPE_EVDO_0,
        TelephonyManager.NETWORK_TYPE_EVDO_A,
        TelephonyManager.NETWORK_TYPE_EVDO_B,
        TelephonyManager.NETWORK_TYPE_HSDPA,
        TelephonyManager.NETWORK_TYPE_HSUPA,
        TelephonyManager.NETWORK_TYPE_HSPA,
        TelephonyManager.NETWORK_TYPE_HSPAP,
        TelephonyManager.NETWORK_TYPE_EHRPD,
        TelephonyManager.NETWORK_TYPE_TD_SCDMA,
        -> "3G"

        TelephonyManager.NETWORK_TYPE_LTE -> "LTE"
        TelephonyManager.NETWORK_TYPE_NR -> "5G"
        else -> null
    }

    /** `~120 kbit/s` / `~24 Mbit/s`, or `null` for an estimate the platform has not made. */
    fun bandwidthLabel(downstreamKbps: Int?): String? {
        val kbps = downstreamKbps ?: return null
        if (kbps <= 0) return null
        return if (kbps < 1000) "~$kbps kbit/s" else "~${kbps / 1000} Mbit/s"
    }

    /** `180 ms` / `1.8 s`, or `null` before anything has been measured. */
    fun latencyLabel(latencyMs: Int?): String? {
        val ms = latencyMs ?: return null
        if (ms <= 0) return null
        return if (ms < 1000) "$ms ms" else String.format(java.util.Locale.ROOT, "%.1f s", ms / 1000.0)
    }

    /**
     * The line itself: what the link is, how fast the platform thinks it is, and
     * what it actually costs the tunnel — dropping any part that is unknown
     * rather than printing a placeholder.
     */
    fun summary(link: LinkReadout?): String? {
        if (link == null || link.transport == LinkTransport.NONE) return null
        val head = when (link.transport) {
            LinkTransport.WIFI -> "Wi-Fi"
            LinkTransport.ETHERNET -> "Ethernet"
            LinkTransport.CELLULAR -> {
                // The exact technology when it is known, the inferred class when
                // it is not, and a bare "Cellular" when neither is available.
                link.ranLabel ?: speedClass(link.downstreamKbps)?.let { "Cellular · $it" } ?: "Cellular"
            }
            LinkTransport.OTHER -> "Network"
            LinkTransport.NONE -> return null
        }
        val parts = listOfNotNull(head, bandwidthLabel(link.downstreamKbps), latencyLabel(link.latencyMs))
        return parts.joinToString(" · ")
    }
}
