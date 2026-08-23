package com.outline.proxy

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** When a live link is worth qualifying as slow, and on which number. */
class LinkQualityTest {

    @Test
    fun `an unmeasured link reads as plain connected`() {
        assertFalse(LinkQuality.isSlow(null))
        assertEquals("Connected", LinkQuality.connectedLabel(null))
    }

    @Test
    fun `a healthy mobile path is not slow`() {
        assertFalse(LinkQuality.isSlow(80))
        assertEquals("Connected", LinkQuality.connectedLabel(300))
    }

    @Test
    fun `an edge-class path is called slow`() {
        assertTrue(LinkQuality.isSlow(LinkQuality.SLOW_LATENCY_MS))
        assertTrue(LinkQuality.isSlow(4200))
        assertEquals("Connected · slow", LinkQuality.connectedLabel(4200))
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
