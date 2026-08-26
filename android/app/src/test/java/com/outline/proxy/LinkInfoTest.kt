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
    fun `head names wifi, ethernet and other transports directly`() {
        assertEquals(LinkInfo.Head.Wifi, LinkInfo.head(LinkReadout(LinkTransport.WIFI, 90_000, null, 20)))
        assertEquals(
            LinkInfo.Head.Ethernet,
            LinkInfo.head(LinkReadout(LinkTransport.ETHERNET, null, null, null)),
        )
        assertEquals(LinkInfo.Head.Network, LinkInfo.head(LinkReadout(LinkTransport.OTHER, null, null, null)))
    }

    @Test
    fun `head reads the radio technology on cellular when it is known`() {
        assertEquals(LinkInfo.Head.Ran("LTE"), LinkInfo.head(cellular(ran = "LTE", latencyMs = 90)))
    }

    /** Nothing measured yet, and no radio technology known either: still says something useful. */
    @Test
    fun `head falls back to a bare Cellular token when the radio technology is unknown`() {
        assertEquals(LinkInfo.Head.Cellular, LinkInfo.head(cellular()))
        assertEquals(
            LinkInfo.Head.Ran("LTE"),
            LinkInfo.head(cellular(ran = "LTE", latencyMs = 10_000, budget = 10)),
        )
    }

    /**
     * The bandwidth estimate is carried for the dial budget but never shown: a
     * HONOR device reported 14 kbit/s on a full-signal LTE cell that was
     * carrying traffic fine, and a figure the user can see is wrong costs more
     * trust than it buys.
     */
    @Test
    fun `the bandwidth estimate never reaches the head`() {
        assertEquals(
            LinkInfo.Head.Ran("LTE"),
            LinkInfo.head(cellular(kbps = 14, ran = "LTE", latencyMs = 180)),
        )
    }

    @Test
    fun `no link means no head at all`() {
        assertEquals(LinkInfo.Head.None, LinkInfo.head(null))
        assertEquals(LinkInfo.Head.None, LinkInfo.head(LinkReadout(LinkTransport.NONE, null, null, null)))
    }
}
