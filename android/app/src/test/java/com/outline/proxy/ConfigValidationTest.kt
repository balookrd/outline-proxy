package com.outline.proxy

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** The guard that keeps an error page from overwriting a working cached config. */
class ConfigValidationTest {

    @Test
    fun `a real client config is accepted`() {
        val toml = """
            [tun]
            path = "vpn"
            mtu = 1500

            [[outline.uplinks]]
            name = "cloud1"
            link = "vless://uuid@host:443?type=xhttp"
        """.trimIndent()
        assertTrue(ConfigValidation.looksLikeConfig(toml))
    }

    @Test
    fun `an uplinks-only fragment is accepted`() {
        assertTrue(ConfigValidation.looksLikeConfig("[[outline.uplinks]]\nname = \"x\"\n"))
    }

    @Test
    fun `an html error page is rejected`() {
        val html = "<!DOCTYPE html><html><body>404 Not Found</body></html>"
        assertFalse(ConfigValidation.looksLikeConfig(html))
    }

    @Test
    fun `blank content is rejected`() {
        assertFalse(ConfigValidation.looksLikeConfig(""))
        assertFalse(ConfigValidation.looksLikeConfig("   \n  \t "))
    }

    @Test
    fun `unrelated text is rejected`() {
        assertFalse(ConfigValidation.looksLikeConfig("hello world, this is not a config"))
    }

    @Test
    fun `a bare padding section is not enough`() {
        // Only the sections that actually define a tunnel count; a stray table
        // must not pass a truncated or wrong response.
        assertFalse(ConfigValidation.looksLikeConfig("[padding]\nenabled = false\n"))
    }
}
