package com.outline.proxy

import android.telephony.TelephonyManager

/** Which kind of link the tunnel's own sockets are riding. */
enum class LinkTransport { WIFI, CELLULAR, ETHERNET, OTHER, NONE }

/**
 * Everything the status card knows about the link underneath the tunnel.
 *
 * [ranLabel] is the radio access technology as the platform names it, and is
 * `null` whenever it cannot be had: on Wi-Fi, or on cellular without
 * `READ_PHONE_STATE`.
 *
 * [downstreamKbps] is the platform's bandwidth estimate. It is *not* displayed
 * — firmware invents it, and a figure the user can see is wrong costs more
 * trust than it buys — but it still sizes the dial budget before anything has
 * been measured, so it is carried here.
 *
 * [latencyMs] is the round-trip of the path itself, as the carrier's transport
 * measures it — not what a dial cost, which also contains the handshakes and
 * whatever a failed carrier attempt burned before the fallback succeeded.
 */
data class LinkReadout(
    val transport: LinkTransport,
    val downstreamKbps: Int?,
    val ranLabel: String?,
    val latencyMs: Int?,
)

/**
 * Turns what the platform reports about the current link into the pieces the
 * home screen joins into the one line it shows under the status: [head] for
 * what the link is, [latencyLabel] for what it costs.
 *
 * Only what is actually known is shown: the radio technology, which needs
 * `READ_PHONE_STATE` and is simply omitted without it, and the round-trip the
 * core measured. Nothing here asks for the permission — it is offered as one
 * item among the others on the Keep Alive checklist, where the app already
 * explains what each grant buys.
 *
 * Kept free of Android calls (only integer constants are referenced, which the
 * compiler inlines, plus the [Head] tokens the caller resolves against string
 * resources) so it can be unit-tested.
 */
object LinkInfo {

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

    /**
     * `180 ms` / `1.8 s`, or `null` when there is no measurement worth showing.
     *
     * No timeout-shaped value can arrive here any more, so nothing is filtered
     * out: the core reports the path's own round-trip, measured continuously on
     * the live carrier, rather than the elapsed time of a dial. Those were the
     * numbers that needed guarding — a dial that ran out of time yielded the
     * budget dressed up as a latency ("10.0 s" on a 10-second budget), and a
     * dial that descended `h3 -> h2` yielded the burnt attempt plus the
     * successful one ("7.1 s" over a healthy `h2` carrier).
     */
    fun latencyLabel(latencyMs: Int?): String? {
        val ms = latencyMs ?: return null
        if (ms <= 0) return null
        return if (ms < 1000) "$ms ms" else String.format(java.util.Locale.ROOT, "%.1f s", ms / 1000.0)
    }

    /**
     * The first, non-numeric word of the status line: what the link is.
     *
     * [Wifi], [Ethernet] and [Ran] carry tokens that are never translated —
     * "Wi-Fi", "Ethernet" and the radio generation ("2G"/"3G"/"LTE"/"5G") read
     * the same in every locale. [Cellular] and [Network] are the fallbacks
     * for when the platform names no more specific technology, and *are*
     * translated — the caller resolves them against `R.string.net_cellular` /
     * `R.string.net_network`. This type carries no Android dependency itself;
     * only the caller (the UI layer) needs a `Context` to resolve those two.
     */
    sealed interface Head {
        data object Wifi : Head
        data object Ethernet : Head
        data class Ran(val label: String) : Head
        data object Cellular : Head
        data object Network : Head
        data object None : Head
    }

    /**
     * What the link is, as a [Head]: named by the platform where it can be,
     * translated where it must be.
     *
     * Two facts used to be rendered as one baked-in English string here
     * (`summary`); the head word and the round-trip ([latencyLabel]) are now
     * resolved and joined separately by the caller, so the translatable
     * words can go through string resources instead of being hardcoded in
     * this Android-free object.
     */
    fun head(link: LinkReadout?): Head {
        if (link == null || link.transport == LinkTransport.NONE) return Head.None
        return when (link.transport) {
            LinkTransport.WIFI -> Head.Wifi
            LinkTransport.ETHERNET -> Head.Ethernet
            // The radio technology when it can be read, "Cellular" otherwise.
            LinkTransport.CELLULAR -> link.ranLabel?.let { Head.Ran(it) } ?: Head.Cellular
            LinkTransport.OTHER -> Head.Network
            LinkTransport.NONE -> Head.None
        }
    }
}
