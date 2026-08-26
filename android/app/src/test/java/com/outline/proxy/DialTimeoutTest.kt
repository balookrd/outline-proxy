package com.outline.proxy

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** Which links get a widened dial budget, and how it lands in the profile. */
class DialTimeoutTest {

    private val profile = """
        [tun]
        path = "vpn"

        [[outline.uplinks]]
        name = "cloud1"
        link = "vless://id@host:443?type=ws#cloud1"
    """.trimIndent()

    @Test
    fun `an edge-class cellular link gets the widest budget`() {
        assertEquals(DialTimeout.EDGE_TIMEOUT_SECS, DialTimeout.secondsFor(isCellular = true, downstreamKbps = 60))
        assertEquals(
            DialTimeout.EDGE_TIMEOUT_SECS,
            DialTimeout.secondsFor(isCellular = true, downstreamKbps = DialTimeout.EDGE_KBPS),
        )
    }

    @Test
    fun `a slow cellular link gets the middle budget`() {
        assertEquals(DialTimeout.SLOW_TIMEOUT_SECS, DialTimeout.secondsFor(isCellular = true, downstreamKbps = 900))
    }

    @Test
    fun `a fast cellular link keeps the core default`() {
        assertNull(DialTimeout.secondsFor(isCellular = true, downstreamKbps = 40_000))
    }

    /** A slow Wi-Fi is a slow backhaul; the handshake itself still completes. */
    @Test
    fun `wifi is never widened`() {
        assertNull(DialTimeout.secondsFor(isCellular = false, downstreamKbps = 50))
    }

    /** The platform reports 0 for a link it has not characterised yet. */
    @Test
    fun `an unknown estimate is left alone`() {
        assertNull(DialTimeout.secondsFor(isCellular = true, downstreamKbps = null))
        assertNull(DialTimeout.secondsFor(isCellular = true, downstreamKbps = 0))
    }

    /**
     * The correction the HONOR device forced: it claimed 14 kbit/s on a
     * full-signal LTE cell that was carrying traffic fine, on both operators.
     * A measured round-trip cannot be invented, so it wins.
     */
    @Test
    fun `a measured round-trip overrides a bogus bandwidth estimate`() {
        assertNull(DialTimeout.secondsFor(isCellular = true, downstreamKbps = 14, latencyMs = 180))
        assertEquals(
            DialTimeout.EDGE_TIMEOUT_SECS,
            DialTimeout.secondsFor(isCellular = true, downstreamKbps = 40_000, latencyMs = 4_000),
        )
    }

    /** A measured round-trip is direct evidence, whatever carries it. */
    @Test
    fun `a measured round-trip widens wifi too`() {
        assertEquals(
            DialTimeout.SLOW_TIMEOUT_SECS,
            DialTimeout.secondsFor(isCellular = false, downstreamKbps = 90_000, latencyMs = 1_500),
        )
    }

    /**
     * The dial budget bar sits above the UX "slow" bar on purpose: a link that
     * reads slow to a person still dials well inside the core's 10 s default, so
     * it keeps the default rather than a 30 s window that only slows failover.
     * Guards the decoupling — before it, both read one shared constant.
     */
    @Test
    fun `a link that is only UX-slow keeps the core default budget`() {
        assertNull(
            DialTimeout.secondsFor(
                isCellular = true,
                downstreamKbps = 40_000,
                latencyMs = LinkQuality.SLOW_LATENCY_MS,
            ),
        )
        assertEquals(
            DialTimeout.SLOW_TIMEOUT_SECS,
            DialTimeout.secondsFor(
                isCellular = true,
                downstreamKbps = 40_000,
                latencyMs = DialTimeout.SLOW_LATENCY_MS,
            ),
        )
    }

    /** Before the first dial completes there is nothing to measure — hence the estimate. */
    @Test
    fun `without a measurement the estimate still covers the cold start`() {
        assertEquals(
            DialTimeout.EDGE_TIMEOUT_SECS,
            DialTimeout.secondsFor(isCellular = true, downstreamKbps = 60, latencyMs = null),
        )
        // 0 is the platform's "not measured", not a zero round-trip: it falls
        // through to the estimate rather than reading as an instant link.
        assertEquals(
            DialTimeout.EDGE_TIMEOUT_SECS,
            DialTimeout.secondsFor(isCellular = true, downstreamKbps = 60, latencyMs = 0),
        )
    }

    @Test
    fun `the budget is appended as a top-level table`() {
        val out = DialTimeout.applyTo(profile, 60)
        assertTrue(out.startsWith(profile.trimEnd('\n')))
        assertTrue(out.contains("[dial]"))
        assertTrue(out.trimEnd().endsWith("timeout_secs = 60"))
    }

    /** An operator's own value outranks the guess. */
    @Test
    fun `a profile that declares dial is left untouched`() {
        val explicit = "$profile\n\n[dial]\ntimeout_secs = 15\n"
        assertEquals(explicit, DialTimeout.applyTo(explicit, 60))
        assertTrue(DialTimeout.declaresDial(explicit))
        assertFalse(DialTimeout.declaresDial(profile))
    }

    @Test
    fun `no budget means no edit`() {
        assertEquals(profile, DialTimeout.applyTo(profile, null))
    }

    /** Applying twice must not stack two tables — the second call sees the first. */
    @Test
    fun `applying twice is idempotent`() {
        val once = DialTimeout.applyTo(profile, 60)
        assertEquals(once, DialTimeout.applyTo(once, 60))
    }
}
