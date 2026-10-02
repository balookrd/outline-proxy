package com.outline.proxy

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
        assertTrue(sanitized.contains("idle_timeout_secs = 60"))
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
        assertTrue(sanitized.contains("idle_timeout_secs = 60"))
    }
}
