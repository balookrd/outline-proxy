package com.outline.proxy

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** When a live link is worth qualifying as slow, and on which number. */
class LinkQualityTest {

    @Test
    fun slowAtOrAboveThreshold() {
        assertTrue(LinkQuality.isSlow(LinkQuality.SLOW_LATENCY_MS))
        assertTrue(LinkQuality.isSlow(4200))
    }

    @Test
    fun notSlowBelowThresholdOrUnknown() {
        assertFalse(LinkQuality.isSlow(LinkQuality.SLOW_LATENCY_MS - 1))
        assertFalse(LinkQuality.isSlow(null))
    }

    /**
     * The bar judges the path's own round-trip, so it sits where a *round-trip*
     * stops being healthy — past loaded 3G (low hundreds of ms), inside 2G — and
     * well below the second it used when it judged a whole dial. A 300 ms path
     * is a working link and must not read slow.
     */
    @Test
    fun `a healthy round-trip is not slow`() {
        assertFalse(LinkQuality.isSlow(300))
        assertTrue("2G-class round-trips are slow", LinkQuality.isSlow(900))
    }

    /**
     * The status calls a link slow before its dials come close to the core's
     * default budget: the UX bar is deliberately the lower of the two.
     */
    @Test
    fun `the status bar is below the dial-budget bar`() {
        assertTrue(LinkQuality.SLOW_LATENCY_MS < DialTimeout.SLOW_LATENCY_MS)
    }

    @Test
    fun `the worse transport decides - either one stalls the apps that need it`() {
        assertEquals(1800, LinkQuality.worstOf(120, 1800))
        assertEquals(1800, LinkQuality.worstOf(1800, 120))
    }

    @Test
    fun `a missing measurement never masks the transport that has one`() {
        assertEquals(1800, LinkQuality.worstOf(null, 1800))
        assertEquals(1800, LinkQuality.worstOf(1800, null))
        assertNull(LinkQuality.worstOf(null, null))
    }
}
