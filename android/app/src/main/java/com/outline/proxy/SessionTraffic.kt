package com.outline.proxy

/**
 * Bytes moved during the current tunnel session.
 *
 * The device-wide [android.net.TrafficStats] totals count since boot and only
 * grow, so "this session" is the total minus a baseline captured when the
 * session started. Keeping that baseline in durable storage — not in the
 * screen's own state — is what lets the figure survive an Activity recreate (a
 * rotation, a fold, a carrier/`mcc` change) or a reconnect, the same way the
 * connection-duration timer survives them via its persisted start time.
 *
 * Kept free of Android APIs so it can be unit-tested, like [LinkQuality] and
 * [KeepAlivePolicy].
 */
object SessionTraffic {

    /**
     * Bytes moved this session: the live device-wide [totalBytes] minus the
     * [baselineBytes] captured at connect, floored at zero. The floor matters
     * because a device reboot resets the counters below a baseline captured
     * before it, which must read as zero rather than as a negative figure.
     */
    fun sinceBaseline(totalBytes: Long, baselineBytes: Long): Long =
        (totalBytes - baselineBytes).coerceAtLeast(0)

    /**
     * Whether a fresh baseline should be captured now, given the session's
     * connect time (`0` when the tunnel is down, epoch-ms once it is up — the
     * same sentinel the duration timer uses).
     *
     * `true` only as the session starts (`connectedSinceMs == 0`); within a live
     * session — a reconnect that keeps the session, an Activity recreate — the
     * stored baseline is kept, so the counter does not restart from zero.
     */
    fun shouldCaptureBaseline(connectedSinceMs: Long): Boolean = connectedSinceMs == 0L
}
