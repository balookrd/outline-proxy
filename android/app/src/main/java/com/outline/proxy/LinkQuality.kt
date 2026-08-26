package com.outline.proxy

/**
 * How the "connected" state should read, given what the link actually costs.
 *
 * The core's health flag is binary: either some uplink is alive or none is. That
 * is the right answer to "is there a path", and a useless one to "why is nothing
 * loading" — on an edge-class network (2G/EDGE) the tunnel is genuinely up while
 * a single handshake eats seconds and apps time out before they ever reach the
 * server. A flat green there contradicts everything the user sees.
 *
 * So the label is qualified by the last measured uplink latency, which on this
 * path is the dial round-trip the manager records. Kept free of Android APIs so
 * it can be unit-tested, like [KeepAlivePolicy].
 */
object LinkQuality {

    /**
     * Latency at or above which the link is called slow.
     *
     * A second of round-trip is well past anything a healthy mobile network
     * produces (LTE lands in the tens of milliseconds, a loaded 3G path in the
     * low hundreds) and squarely in edge-class territory, where TLS alone needs
     * several of these before a single byte of payload moves.
     */
    const val SLOW_LATENCY_MS = 1000

    /** `true` when [latencyMs] describes a link that is up but barely usable. */
    fun isSlow(latencyMs: Int?): Boolean = latencyMs != null && latencyMs >= SLOW_LATENCY_MS

    /**
     * The latency to judge on, given both transports' numbers.
     *
     * The worse of the two, because either one being slow is enough to make the
     * tunnel feel broken: TCP carries page loads, UDP carries DNS and QUIC, and
     * an app stalls on whichever it needs. A missing number is not "fast" — it
     * is simply no evidence, so it never masks the transport that did measure.
     */
    fun worstOf(tcpLatencyMs: Int?, udpLatencyMs: Int?): Int? =
        listOfNotNull(tcpLatencyMs, udpLatencyMs).maxOrNull()
}
