package com.outline.proxy

import android.telephony.TelephonyManager
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/** What the status line says about the link, and what it leaves out. */
class LinkInfoTest {

    private fun cellular(
        kbps: Int? = null,
        ran: String? = null,
        latencyMs: Int? = null,
    ) = LinkReadout(LinkTransport.CELLULAR, kbps, ran, latencyMs)

    /** The card and the dial budget must never disagree about what "slow" means. */
    @Test
    fun `the speed class follows the same thresholds as the dial budget`() {
        assertEquals("very slow", LinkInfo.speedClass(DialTimeout.EDGE_KBPS))
        assertEquals("slow", LinkInfo.speedClass(DialTimeout.SLOW_KBPS))
        assertNull(LinkInfo.speedClass(40_000))
        assertNull(LinkInfo.speedClass(null))
        assertNull(LinkInfo.speedClass(0))
    }

    @Test
    fun `radio technologies are grouped by generation`() {
        assertEquals("2G", LinkInfo.ranLabel(TelephonyManager.NETWORK_TYPE_EDGE))
        assertEquals("3G", LinkInfo.ranLabel(TelephonyManager.NETWORK_TYPE_HSPAP))
        assertEquals("LTE", LinkInfo.ranLabel(TelephonyManager.NETWORK_TYPE_LTE))
        assertEquals("5G", LinkInfo.ranLabel(TelephonyManager.NETWORK_TYPE_NR))
        assertNull(LinkInfo.ranLabel(TelephonyManager.NETWORK_TYPE_UNKNOWN))
    }

    @Test
    fun `bandwidth and latency read in human units`() {
        assertEquals("~120 kbit/s", LinkInfo.bandwidthLabel(120))
        assertEquals("~24 Mbit/s", LinkInfo.bandwidthLabel(24_000))
        assertEquals("180 ms", LinkInfo.latencyLabel(180))
        assertEquals("1.8 s", LinkInfo.latencyLabel(1_800))
        assertNull(LinkInfo.bandwidthLabel(0))
        assertNull(LinkInfo.latencyLabel(null))
    }

    /** A healthy link needs no qualifier beyond its name. */
    @Test
    fun `a known radio technology is named`() {
        assertEquals(
            "LTE · ~24 Mbit/s · 90 ms",
            LinkInfo.summary(cellular(kbps = 24_000, ran = "LTE", latencyMs = 90)),
        )
    }

    /**
     * The case the whole line exists for: the status bar promises 5G, the radio
     * reports LTE, and 14 kbit/s is what actually arrives. Technology and speed
     * are separate facts and both have to be on screen.
     */
    @Test
    fun `a fast technology running slowly says both`() {
        assertEquals(
            "LTE · very slow · ~14 kbit/s · 4.2 s",
            LinkInfo.summary(cellular(kbps = 14, ran = "LTE", latencyMs = 4_200)),
        )
    }

    /** Without the permission the speed class carries the line on its own. */
    @Test
    fun `an unknown radio technology still reports the speed`() {
        assertEquals(
            "Cellular · very slow · ~120 kbit/s · 4.2 s",
            LinkInfo.summary(cellular(kbps = 120, latencyMs = 4_200)),
        )
    }

    /** Neither known: still worth saying it is cellular. */
    @Test
    fun `a cellular link with nothing measured still names itself`() {
        assertEquals("Cellular", LinkInfo.summary(cellular()))
    }

    @Test
    fun `wifi and ethernet are named plainly`() {
        assertEquals(
            "Wi-Fi · ~90 Mbit/s · 20 ms",
            LinkInfo.summary(LinkReadout(LinkTransport.WIFI, 90_000, null, 20)),
        )
        // A slow Wi-Fi is qualified too — the backhaul is what the user feels.
        assertEquals(
            "Wi-Fi · slow · ~800 kbit/s",
            LinkInfo.summary(LinkReadout(LinkTransport.WIFI, 800, null, null)),
        )
        assertEquals("Ethernet", LinkInfo.summary(LinkReadout(LinkTransport.ETHERNET, null, null, null)))
    }

    /** Unknown parts are dropped rather than printed as placeholders. */
    @Test
    fun `missing pieces leave no gaps in the line`() {
        assertEquals("Wi-Fi · 20 ms", LinkInfo.summary(LinkReadout(LinkTransport.WIFI, null, null, 20)))
        assertEquals("Wi-Fi · ~90 Mbit/s", LinkInfo.summary(LinkReadout(LinkTransport.WIFI, 90_000, null, null)))
    }

    @Test
    fun `no link means no line at all`() {
        assertNull(LinkInfo.summary(null))
        assertNull(LinkInfo.summary(LinkReadout(LinkTransport.NONE, null, null, null)))
    }
}
