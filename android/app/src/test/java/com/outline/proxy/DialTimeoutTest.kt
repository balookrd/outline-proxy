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
