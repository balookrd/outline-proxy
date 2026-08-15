package com.outline.proxy

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** A profile whose config comes from a subscription URL instead of local fields. */
class SubscriptionProfileTest {

    @Test
    fun `a blank config url is not a subscription`() {
        assertFalse(ServerProfile().isSubscription)
        assertFalse(ServerProfile(configUrl = "   ").isSubscription)
    }

    @Test
    fun `a config url makes it a subscription`() {
        assertTrue(ServerProfile(configUrl = "https://example/a.toml").isSubscription)
    }

    @Test
    fun `subscription toToml returns the cached config verbatim`() {
        val cached = "[tun]\npath = \"vpn\"\n"
        val profile = ServerProfile(
            configUrl = "https://example/a.toml",
            cachedToml = cached,
        )
        assertEquals(cached, profile.toToml())
    }

    @Test
    fun `subscription cache outranks a raw override and the fields`() {
        // The URL is the single source of truth once set: neither the escape
        // hatch nor the structured fields may leak into the emitted config.
        val cached = "[tun]\npath = \"vpn\"\n"
        val profile = ServerProfile(
            configUrl = "https://example/a.toml",
            cachedToml = cached,
            rawTomlOverride = "[nope]\n",
            vlessLink = "vless://ignored",
        )
        assertEquals(cached, profile.toToml())
    }

    @Test
    fun `a subscription with an empty cache emits nothing to connect with`() {
        val profile = ServerProfile(configUrl = "https://example/a.toml")
        assertEquals("", profile.toToml())
    }

    @Test
    fun `non-subscription profiles are unaffected`() {
        val profile = ServerProfile(transport = "vless", vlessLink = "vless://x")
        assertTrue(profile.toToml().contains("vless://x"))
    }

    // JSON round-trip is not unit-testable here: org.json is a stubbed android.jar
    // class under `isReturnDefaultValues`, so put/opt are no-ops on the JVM. The
    // new fields' serialization is verified on-device instead.
}
