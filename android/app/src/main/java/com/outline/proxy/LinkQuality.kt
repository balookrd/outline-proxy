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
 * So the label is qualified by the last measured uplink latency: the round-trip
 * of the path itself, as the carrier's own transport measures it (the kernel's
 * `tcpi_rtt`, quinn's `PathStats`). Deliberately not what a dial cost — that
 * number also contains the handshakes and, on a carrier descent, the budget the
 * failed attempt burned, so it branded healthy links "slow". Kept free of
 * Android APIs so it can be unit-tested, like [KeepAlivePolicy].
 */
object LinkQuality {

    /**
     * Path round-trip at or above which the link is called slow.
     *
     * This judges the path's own RTT (see the class doc), not what a dial cost,
     * so the bar is where the *round-trip* itself stops being healthy. LTE lands
     * in the tens of milliseconds and a loaded 3G path in the low hundreds, so
     * 0.7 s is well past both and squarely in 2G/EDGE territory — where a single
     * TLS handshake, several of these round-trips, already takes a couple of
     * seconds before a byte of payload moves and apps begin to feel it.
     *
     * It was 1 s while this judged a *dial* (TCP + TLS + upgrade, several round
     * trips plus the certificate chain), where a full second was only the edge
     * of healthy and the label barely ever fired for the right reason. On the
     * path RTT the same class of bad link shows a third to a fifth of that, so
     * catching it means a lower bar. Kept deliberately below
     * [DialTimeout.SLOW_LATENCY_MS]: a link can read slow to a person well
     * before its dials come close to the core's default budget.
     */
    const val SLOW_LATENCY_MS = 700

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
