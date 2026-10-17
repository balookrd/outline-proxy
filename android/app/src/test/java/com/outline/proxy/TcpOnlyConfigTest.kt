package com.outline.proxy

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class TcpOnlyConfigTest {

    @Test
    fun `enforceLink rewrites alpn h3 to h2 in vless links`() {
        val link1 = "vless://uuid@host:443?type=xhttp&security=tls&alpn=h3&path=%2F#Server1"
        assertEquals(
            "vless://uuid@host:443?type=xhttp&security=tls&alpn=h2&path=%2F#Server1",
            TcpOnlyConfig.enforceLink(link1),
        )

        val link2 = "vless://uuid@host:443?type=xhttp&security=tls&alpn=h3,h2&path=%2F#Server2"
        assertEquals(
            "vless://uuid@host:443?type=xhttp&security=tls&alpn=h2&path=%2F#Server2",
            TcpOnlyConfig.enforceLink(link2),
        )

        val link3 = "vless://uuid@host:443?type=xhttp&security=tls&alpn=h3%2Ch2#Server3"
        assertEquals(
            "vless://uuid@host:443?type=xhttp&security=tls&alpn=h2#Server3",
            TcpOnlyConfig.enforceLink(link3),
        )

        val link4 = "vless://uuid@host:443?type=xhttp&security=tls&alpn=h2,h3#Server4"
        assertEquals(
            "vless://uuid@host:443?type=xhttp&security=tls&alpn=h2#Server4",
            TcpOnlyConfig.enforceLink(link4),
        )
    }

    @Test
    fun `enforceLink rewrites alpn h3 in ss links`() {
        val ssLink = "ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpwYXNz@host:443?type=ws&security=tls&alpn=h3#SsServer"
        assertEquals(
            "ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpwYXNz@host:443?type=ws&security=tls&alpn=h2#SsServer",
            TcpOnlyConfig.enforceLink(ssLink),
        )
    }

    @Test
    fun `enforceLink preserves links without h3 alpn`() {
        val noAlpn = "vless://uuid@host:443?type=xhttp&security=tls&path=%2F#NoAlpn"
        assertEquals(noAlpn, TcpOnlyConfig.enforceLink(noAlpn))

        val h2Alpn = "vless://uuid@host:443?type=ws&security=tls&alpn=h2#H2Only"
        assertEquals(h2Alpn, TcpOnlyConfig.enforceLink(h2Alpn))

        val h1Alpn = "vless://uuid@host:443?type=ws&security=tls&alpn=http/1.1#H1Only"
        assertEquals(h1Alpn, TcpOnlyConfig.enforceLink(h1Alpn))
    }

    @Test
    fun `apply rewrites explicit h3 carrier modes to h2 in TOML`() {
        val toml = """
            [outline]
            vless_mode = "xhttp_h3"

            [[outline.uplinks]]
            name = "primary"
            transport = "vless"
            vless_mode = "xhttp_h3"

            [[outline.uplinks]]
            name = "backup-ws"
            transport = "ss"
            ss_mode = "ws_h3"
            tcp_mode = "ws_h3"
            udp_mode = "xhttp_h3"

            [[outline.uplinks.fallbacks]]
            vless_mode = 'xhttp_h3'
            tcp_mode = 'ws_h3'
        """.trimIndent()

        val result = TcpOnlyConfig.apply(toml)

        assertFalse("must not contain xhttp_h3", result.contains("xhttp_h3"))
        assertFalse("must not contain ws_h3", result.contains("ws_h3"))

        assertTrue("must contain xhttp_h2", result.contains("vless_mode = \"xhttp_h2\""))
        assertTrue("must contain ws_h2 for ss_mode", result.contains("ss_mode = \"ws_h2\""))
        assertTrue("must contain ws_h2 for tcp_mode", result.contains("tcp_mode = \"ws_h2\""))
        assertTrue("must contain xhttp_h2 for udp_mode", result.contains("udp_mode = \"xhttp_h2\""))
        assertTrue("must support single quotes xhttp_h2", result.contains("vless_mode = 'xhttp_h2'"))
        assertTrue("must support single quotes ws_h2", result.contains("tcp_mode = 'ws_h2'"))
    }

    @Test
    fun `apply rewrites links with h3 in TOML`() {
        val toml = """
            [[outline.uplinks]]
            name = "share"
            transport = "vless"
            link = "vless://uuid@host:443?type=xhttp&security=tls&alpn=h3#Share1"

            [[outline.uplinks.fallbacks]]
            link = "ss://pass@host:443?type=ws&security=tls&alpn=h3,h2#Fallback1"
        """.trimIndent()

        val result = TcpOnlyConfig.apply(toml)

        assertFalse("link must not contain alpn=h3", result.contains("alpn=h3#"))
        assertFalse("fallback must not contain alpn=h3,h2", result.contains("alpn=h3,h2"))
        assertTrue("link rewritten to alpn=h2", result.contains("alpn=h2#Share1"))
        assertTrue("fallback rewritten to alpn=h2", result.contains("alpn=h2#Fallback1"))
    }

    @Test
    fun `ServerProfile toToml enforces tcpOnly when enabled`() {
        val profile = ServerProfile(
            name = "TestServer",
            transport = "vless",
            vlessLink = "vless://uuid@host:443?type=xhttp&security=tls&alpn=h3#Test",
            tcpOnly = true,
        )

        val toml = profile.toToml()
        assertTrue("link in toml must be rewritten to alpn=h2", toml.contains("alpn=h2#Test"))
        assertFalse("link in toml must not have alpn=h3", toml.contains("alpn=h3#Test"))
    }

    @Test
    fun `ServerProfile toToml respects forceTcpOnly parameter`() {
        val profile = ServerProfile(
            name = "TestServer",
            transport = "vless",
            vlessLink = "vless://uuid@host:443?type=xhttp&security=tls&alpn=h3#Test",
            tcpOnly = false,
        )

        val defaultToml = profile.toToml(forceTcpOnly = false)
        assertTrue("default toml keeps alpn=h3", defaultToml.contains("alpn=h3#Test"))

        val forcedToml = profile.toToml(forceTcpOnly = true)
        assertTrue("forced toml rewrites to alpn=h2", forcedToml.contains("alpn=h2#Test"))
    }

    @Test
    fun `ServerProfile toToml applies tcpOnly to subscription cache`() {
        val cached = """
            [[outline.uplinks]]
            name = "sub-server"
            transport = "vless"
            vless_mode = "xhttp_h3"
        """.trimIndent()

        val profile = ServerProfile(
            configUrl = "https://example.com/sub.toml",
            cachedToml = cached,
            tcpOnly = false,
        )

        val defaultToml = profile.toToml(forceTcpOnly = false)
        assertTrue(defaultToml.contains("xhttp_h3"))

        val forcedToml = profile.toToml(forceTcpOnly = true)
        assertFalse(forcedToml.contains("xhttp_h3"))
        assertTrue(forcedToml.contains("xhttp_h2"))
    }
}
