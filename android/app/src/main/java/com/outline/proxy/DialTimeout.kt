package com.outline.proxy

/**
 * Picks the carrier-dial budget for the network the tunnel is starting on, and
 * writes it into the profile TOML.
 *
 * The core bounds every fresh dial — TCP + TLS + HTTP upgrade, or the QUIC +
 * HTTP/3 handshake — at 10 seconds by default. That suits Wi-Fi and LTE, where
 * a dial is a handful of round trips over a fat pipe, and it is the *cause* of
 * failure on an edge-class link: a 2G round trip runs close to a second and the
 * certificate chain alone takes seconds to clock out, so the budget expires
 * mid-handshake, every attempt is scored a failure, and the retries eat the
 * bandwidth the handshake needed. The tunnel then reports itself up while
 * carrying nothing.
 *
 * The generated profile does not carry `[dial]`, so the client fills it in from
 * what the platform says about the link. A profile that *does* declare the
 * section is left alone — an explicit value from the operator outranks this
 * guess.
 *
 * **The choice is made once, when the tunnel starts.** The core reads the budget
 * at startup and holds it for the life of the process, so walking from Wi-Fi
 * into a 2G cell does not widen it — that needs a reconnect. Sizing for the
 * network at hand still beats one hard-coded number for every network.
 */
object DialTimeout {

    /** Downstream estimate at or below which a link is edge-class (2G/GPRS/EDGE). */
    const val EDGE_KBPS = 200

    /** …and below which it is still materially slower than the default assumes (2.5G/3G). */
    const val SLOW_KBPS = 2_000

    /**
     * Measured dial round-trip at or above which the link is treated as
     * edge-class regardless of what the platform claims about its bandwidth.
     *
     * A dial is TCP + TLS + the HTTP upgrade, so healthy LTE lands in the low
     * hundreds of milliseconds and 3G under a second. Seconds mean the
     * handshake itself is the bottleneck.
     */
    const val EDGE_LATENCY_MS = 3_000

    /** …and the milder threshold, matching what the status calls "slow". */
    const val SLOW_LATENCY_MS = LinkQuality.SLOW_LATENCY_MS

    /** Budget for an edge-class link, in seconds. */
    const val EDGE_TIMEOUT_SECS = 60

    /** Budget for a slow-but-not-edge link, in seconds. */
    const val SLOW_TIMEOUT_SECS = 30

    /**
     * Seconds to request for this link, or `null` to leave the core's default.
     *
     * [latencyMs] — the round-trip the core measured on its own dials — decides
     * whenever it exists, and the platform's bandwidth estimate only fills the
     * gap before the first dial has completed. That order is not a preference,
     * it is a correction: the estimate is a claim, and some firmware makes it up
     * entirely. One HONOR device reported 14 kbit/s on a full-signal LTE cell
     * that was carrying traffic perfectly well, on both operators — sizing the
     * budget from that would have left a healthy link with a six-fold slower
     * failover for no reason.
     *
     * The estimate is still worth keeping for the cold start: on a genuine 2G
     * cell the first dial has to survive before there is anything to measure,
     * and the default 10 s is exactly what it cannot survive. There a wrong
     * guess costs far less than no guess.
     *
     * Only cellular links are widened on the estimate. Wi-Fi and Ethernet report
     * bandwidth too, but a slow Wi-Fi is usually a slow *backhaul*, where the
     * handshake still completes in a couple of round trips. A measured latency
     * widens any transport — there the evidence is direct.
     *
     * An unknown estimate ([downstreamKbps] `null` or non-positive) is left
     * alone: the platform reports 0 for a link it has not characterised yet, and
     * treating "no data" as "2G" would hand every fresh cellular connect a
     * 60-second window to stall in.
     */
    fun secondsFor(isCellular: Boolean, downstreamKbps: Int?, latencyMs: Int? = null): Int? {
        latencyMs?.takeIf { it > 0 }?.let { measured ->
            return when {
                measured >= EDGE_LATENCY_MS -> EDGE_TIMEOUT_SECS
                measured >= SLOW_LATENCY_MS -> SLOW_TIMEOUT_SECS
                else -> null
            }
        }
        if (!isCellular) return null
        val kbps = downstreamKbps ?: return null
        if (kbps <= 0) return null
        return when {
            kbps <= EDGE_KBPS -> EDGE_TIMEOUT_SECS
            kbps <= SLOW_KBPS -> SLOW_TIMEOUT_SECS
            else -> null
        }
    }

    /** Whether [toml] already declares a `[dial]` table of its own. */
    fun declaresDial(toml: String): Boolean =
        Regex("""^\s*\[dial]\s*$""", RegexOption.MULTILINE).containsMatchIn(toml)

    /**
     * Append `[dial] timeout_secs` to [toml], or return it untouched when the
     * profile already sets the section or [seconds] is `null`.
     *
     * Appended at the end on purpose: a TOML table header closes whatever table
     * preceded it, so a top-level section is only unambiguous after everything
     * else — inserting it mid-file could land inside `[[outline.uplinks]]` and
     * silently reparent the key.
     */
    fun applyTo(toml: String, seconds: Int?): String {
        if (seconds == null || declaresDial(toml)) return toml
        val body = toml.trimEnd('\n')
        return "$body\n\n# Added by the app: this network needs a longer dial budget.\n" +
            "[dial]\ntimeout_secs = $seconds\n"
    }
}
