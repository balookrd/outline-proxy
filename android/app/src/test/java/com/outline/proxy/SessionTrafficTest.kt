package com.outline.proxy

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Bytes-this-session accounting. The baseline is taken once when the session
 * starts and the figure is the device-wide total minus it, so the counter
 * survives an Activity recreate (a screen rotation, a carrier/`mcc` change) or a
 * reconnect instead of restarting from zero.
 */
class SessionTrafficTest {

    @Test
    fun `bytes this session are the total minus the connect baseline`() {
        assertEquals(500L, SessionTraffic.sinceBaseline(totalBytes = 1500L, baselineBytes = 1000L))
    }

    @Test
    fun `a fresh baseline reads zero`() {
        assertEquals(0L, SessionTraffic.sinceBaseline(totalBytes = 1000L, baselineBytes = 1000L))
    }

    @Test
    fun `a device reboot drops the total below the baseline and floors at zero`() {
        // TrafficStats counts since boot, so after a reboot the live total is
        // smaller than a baseline captured before it. That must read as zero, not
        // as a negative figure.
        assertEquals(0L, SessionTraffic.sinceBaseline(totalBytes = 200L, baselineBytes = 1000L))
    }

    @Test
    fun `the baseline is captured when the session starts`() {
        assertTrue(SessionTraffic.shouldCaptureBaseline(connectedSinceMs = 0L))
    }

    @Test
    fun `a live session keeps its baseline across reconnects and recreates`() {
        // The bug this guards against: the baseline was re-taken on every connect
        // and on every Activity recreate, so the counter restarted from zero
        // mid-session while the duration timer (a persisted baseline) did not.
        assertFalse(SessionTraffic.shouldCaptureBaseline(connectedSinceMs = 123_456L))
    }
}
