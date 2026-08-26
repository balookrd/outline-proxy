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
        assertTrue(LinkQuality.isSlow(1000))
        assertTrue(LinkQuality.isSlow(4200))
    }

    @Test
    fun notSlowBelowThresholdOrUnknown() {
        assertFalse(LinkQuality.isSlow(999))
        assertFalse(LinkQuality.isSlow(null))
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
