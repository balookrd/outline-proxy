package com.outline.proxy

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class MobilePowerConfigTest {

    @Test
    fun `empty config returns blank`() {
        val result = MobilePowerConfig.sanitize("")
        assertTrue(result.isBlank())
    }

    @Test
    fun `injects power saving sections when missing`() {
        val toml = """
            [tun]
            path = "vpn"
            mtu = 1500
        """.trimIndent()

        val sanitized = MobilePowerConfig.sanitize(toml)

        assertTrue(sanitized.contains("[outline.load_balancing]"))
        assertTrue(sanitized.contains("warm_standby_tcp = 0"))
        assertTrue(sanitized.contains("warm_standby_udp = 0"))
        assertTrue(sanitized.contains("loss_sample_interval_secs = 0"))
        assertTrue(sanitized.contains("tcp_active_keepalive_secs = 120"))
        assertTrue(sanitized.contains("[h2]"))
        assertTrue(sanitized.contains("keepalive_interval_secs = 60"))
        assertTrue(sanitized.contains("keepalive_timeout_secs = 20"))
        assertTrue(sanitized.contains("[quic]"))
        assertTrue(sanitized.contains("keepalive_secs = 25"))
        // The idle timeout stays on the browser profile, as a browser's Initial carries it.
        assertFalse(sanitized.contains("idle_timeout_secs"))
    }

    @Test
    fun `clamps existing probe and keepalive intervals`() {
        val toml = """
            [[uplink_group]]
            name = "main"
            warm_standby_tcp = 1
            warm_standby_udp = 1

            [outline.load_balancing]
            warm_standby_tcp = 1
            warm_standby_udp = 1
            loss_sample_interval_secs = 10
            tcp_active_keepalive_secs = 30

            [outline.probe]
            interval_secs = 60

            [h2]
            keepalive_interval_secs = 10
            keepalive_timeout_secs = 10

            [quic]
            keepalive_secs = 10
            idle_timeout_secs = 30
        """.trimIndent()

        val sanitized = MobilePowerConfig.sanitize(toml)

        assertTrue(sanitized.contains("warm_standby_tcp = 0"))
        assertTrue(sanitized.contains("warm_standby_udp = 0"))
        assertTrue(sanitized.contains("loss_sample_interval_secs = 0"))
        assertTrue(sanitized.contains("tcp_active_keepalive_secs = 120"))
        assertTrue(sanitized.contains("interval_secs = 300"))
        assertTrue(sanitized.contains("keepalive_interval_secs = 60"))
        assertTrue(sanitized.contains("keepalive_timeout_secs = 20"))
        assertTrue(sanitized.contains("keepalive_secs = 25"))
        // 30s already outlasts the clamped 25s keepalive, so it is kept.
        assertTrue(sanitized.contains("idle_timeout_secs = 30"))
    }

    @Test
    fun `raises the idle timeout only when the keepalive would not fit inside it`() {
        val noIdle = MobilePowerConfig.sanitize(
            """
            [quic]
            keepalive_secs = 40
            """.trimIndent()
        )
        assertTrue(noIdle.contains("keepalive_secs = 40"))
        assertTrue(noIdle.contains("idle_timeout_secs = 80"))

        val shortIdle = MobilePowerConfig.sanitize(
            """
            [quic]
            keepalive_secs = 25
            idle_timeout_secs = 20
            """.trimIndent()
        )
        assertTrue(shortIdle.contains("idle_timeout_secs = 50"))
    }
}
