package com.outline.proxy

import android.telephony.TelephonyManager
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/** What the status line says about the link, and what it deliberately omits. */
class LinkInfoTest {

    private fun cellular(
        kbps: Int? = null,
        ran: String? = null,
        latencyMs: Int? = null,
        budget: Int? = null,
    ) = LinkReadout(LinkTransport.CELLULAR, kbps, ran, latencyMs, budget)

    @Test
    fun `radio technologies are grouped by generation`() {
        assertEquals("2G", LinkInfo.ranLabel(TelephonyManager.NETWORK_TYPE_EDGE))
        assertEquals("3G", LinkInfo.ranLabel(TelephonyManager.NETWORK_TYPE_HSPAP))
        assertEquals("LTE", LinkInfo.ranLabel(TelephonyManager.NETWORK_TYPE_LTE))
        assertEquals("5G", LinkInfo.ranLabel(TelephonyManager.NETWORK_TYPE_NR))
        assertNull(LinkInfo.ranLabel(TelephonyManager.NETWORK_TYPE_UNKNOWN))
    }

    @Test
    fun `latency reads in human units`() {
        assertEquals("180 ms", LinkInfo.latencyLabel(180))
        assertEquals("1.8 s", LinkInfo.latencyLabel(1_800))
        assertNull(LinkInfo.latencyLabel(null))
        assertNull(LinkInfo.latencyLabel(0))
    }

    /**
     * The first probe after a connect produced exactly "10.0 s" on a 10-second
     * budget — a dial that ran out of time, printed as if it were a
     * measurement. Anything at or near the ceiling is dropped instead.
     */
    @Test
    fun `a round-trip that hit the dial budget is not a measurement`() {
        assertNull(LinkInfo.latencyLabel(10_000, dialBudgetSecs = 10))
        assertNull(LinkInfo.latencyLabel(9_000, dialBudgetSecs = 10))
        // Comfortably inside the budget: a real, if unhappy, number.
        assertEquals("4.0 s", LinkInfo.latencyLabel(4_000, dialBudgetSecs = 10))
    }

    /** A widened budget widens what counts as a plausible measurement. */
    @Test
    fun `the ceiling follows the budget in force`() {
        assertEquals("20.0 s", LinkInfo.latencyLabel(20_000, dialBudgetSecs = 60))
        assertNull(LinkInfo.latencyLabel(55_000, dialBudgetSecs = 60))
    }

    @Test
    fun `the line names the technology and what it costs`() {
        assertEquals("LTE · 90 ms", LinkInfo.summary(cellular(ran = "LTE", latencyMs = 90)))
        assertEquals(
            "Wi-Fi · 20 ms",
            LinkInfo.summary(LinkReadout(LinkTransport.WIFI, 90_000, null, 20)),
        )
        assertEquals("Ethernet", LinkInfo.summary(LinkReadout(LinkTransport.ETHERNET, null, null, null)))
    }

    /**
     * The bandwidth estimate is carried for the dial budget but never shown: a
     * HONOR device reported 14 kbit/s on a full-signal LTE cell that was
     * carrying traffic fine, and a figure the user can see is wrong costs more
     * trust than it buys.
     */
    @Test
    fun `the bandwidth estimate never reaches the line`() {
        val line = LinkInfo.summary(cellular(kbps = 14, ran = "LTE", latencyMs = 180))
        assertEquals("LTE · 180 ms", line)
    }

    /** Nothing measured yet: the technology alone still says something useful. */
    @Test
    fun `a link with no measurement still names itself`() {
        assertEquals("Cellular", LinkInfo.summary(cellular()))
        assertEquals("LTE", LinkInfo.summary(cellular(ran = "LTE", latencyMs = 10_000, budget = 10)))
    }

    @Test
    fun `no link means no line at all`() {
        assertNull(LinkInfo.summary(null))
        assertNull(LinkInfo.summary(LinkReadout(LinkTransport.NONE, null, null, null)))
    }
}
