package com.outline.proxy

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/** URI grammar: `outline://<command>[?profile=<name|id>][&token=<secret>]`. */
class ParseControlUriTest {

    private fun valid(raw: String): ControlUri.Valid =
        parseControlUri(raw) as? ControlUri.Valid
            ?: throw AssertionError("expected a valid control URI: $raw")

    private fun rejected(raw: String?): RejectReason =
        (parseControlUri(raw) as? ControlUri.Invalid)?.reason
            ?: throw AssertionError("expected rejection: $raw")

    @Test
    fun `bare commands parse`() {
        assertEquals(ControlCommand.Connect(null), valid("outline://connect").command)
        assertEquals(ControlCommand.Disconnect, valid("outline://disconnect").command)
        assertEquals(ControlCommand.Toggle(null), valid("outline://toggle").command)
    }

    @Test
    fun `scheme and command are case-insensitive`() {
        assertEquals(ControlCommand.Connect(null), valid("OUTLINE://Connect").command)
    }

    @Test
    fun `authority-less and trailing-slash forms parse`() {
        assertEquals(ControlCommand.Connect(null), valid("outline:///connect").command)
        assertEquals(ControlCommand.Disconnect, valid("outline://disconnect/").command)
    }

    @Test
    fun `profile selector is carried through`() {
        assertEquals(ControlCommand.Connect("work"), valid("outline://connect?profile=work").command)
        assertEquals(ControlCommand.Toggle("work"), valid("outline://toggle?profile=work").command)
    }

    @Test
    fun `profile selector is percent-decoded`() {
        assertEquals(
            ControlCommand.Connect("Home VPN"),
            valid("outline://connect?profile=Home%20VPN").command,
        )
    }

    @Test
    fun `blank profile selector means unspecified`() {
        assertEquals(ControlCommand.Connect(null), valid("outline://connect?profile=").command)
        assertEquals(ControlCommand.Connect(null), valid("outline://connect?profile=%20").command)
    }

    @Test
    fun `token is extracted alongside the profile`() {
        val parsed = valid("outline://connect?profile=work&token=s3cret")
        assertEquals(ControlCommand.Connect("work"), parsed.command)
        assertEquals("s3cret", parsed.token)
    }

    @Test
    fun `token is absent when not supplied`() {
        assertNull(valid("outline://disconnect").token)
    }

    @Test
    fun `unknown query keys are ignored`() {
        assertEquals(ControlCommand.Connect("work"), valid("outline://connect?x=1&profile=work").command)
    }

    @Test
    fun `first occurrence of a repeated key wins`() {
        assertEquals(
            ControlCommand.Connect("first"),
            valid("outline://connect?profile=first&profile=second").command,
        )
    }

    @Test
    fun `foreign schemes are rejected`() {
        assertEquals(RejectReason.NOT_A_CONTROL_URI, rejected("https://example.com/connect"))
        assertEquals(RejectReason.NOT_A_CONTROL_URI, rejected("outlinex://connect"))
    }

    @Test
    fun `missing and empty input is rejected`() {
        assertEquals(RejectReason.NOT_A_CONTROL_URI, rejected(null))
        assertEquals(RejectReason.NOT_A_CONTROL_URI, rejected(""))
        assertEquals(RejectReason.UNKNOWN_COMMAND, rejected("outline://"))
    }

    @Test
    fun `unknown commands are rejected`() {
        assertEquals(RejectReason.UNKNOWN_COMMAND, rejected("outline://status"))
        assertEquals(RejectReason.UNKNOWN_COMMAND, rejected("outline://connect/now"))
    }
}

class CheckAccessTest {

    @Test
    fun `enabled without a token accepts anything`() {
        val config = ExternalControlConfig(enabled = true, token = "")
        assertNull(checkAccess(null, config))
        assertNull(checkAccess("whatever", config))
    }

    @Test
    fun `disabled rejects every caller`() {
        val config = ExternalControlConfig(enabled = false, token = "")
        assertEquals(RejectReason.DISABLED, checkAccess(null, config))
        assertEquals(RejectReason.DISABLED, checkAccess("s3cret", config))
    }

    @Test
    fun `configured token must match`() {
        val config = ExternalControlConfig(enabled = true, token = "s3cret")
        assertNull(checkAccess("s3cret", config))
        assertEquals(RejectReason.BAD_TOKEN, checkAccess("wrong", config))
        assertEquals(RejectReason.BAD_TOKEN, checkAccess(null, config))
        assertEquals(RejectReason.BAD_TOKEN, checkAccess("", config))
    }

    @Test
    fun `disabled outranks a matching token`() {
        val config = ExternalControlConfig(enabled = false, token = "s3cret")
        assertEquals(RejectReason.DISABLED, checkAccess("s3cret", config))
    }
}

class ResolveProfileTest {

    private val home = ServerProfile(id = "id-home", name = "Home")
    private val work = ServerProfile(id = "id-work", name = "Work VPN")
    private val profiles = listOf(home, work)

    @Test
    fun `no selector falls back to the profile selected in the UI`() {
        assertEquals(work, resolveProfile(profiles, selector = null, selectedId = "id-work"))
    }

    @Test
    fun `no selector and no stored selection falls back to the first profile`() {
        assertEquals(home, resolveProfile(profiles, selector = null, selectedId = null))
        assertEquals(home, resolveProfile(profiles, selector = null, selectedId = "id-gone"))
    }

    @Test
    fun `selector matches an id exactly`() {
        assertEquals(work, resolveProfile(profiles, selector = "id-work", selectedId = "id-home"))
    }

    @Test
    fun `selector matches a name case-insensitively`() {
        assertEquals(work, resolveProfile(profiles, selector = "work vpn", selectedId = null))
    }

    @Test
    fun `id wins over a name that collides with another profile's id`() {
        val decoy = ServerProfile(id = "id-home", name = "id-work")
        assertEquals(work, resolveProfile(listOf(decoy, work), selector = "id-work", selectedId = null))
    }

    @Test
    fun `unknown selector resolves to nothing`() {
        assertNull(resolveProfile(profiles, selector = "nope", selectedId = "id-home"))
    }

    @Test
    fun `an empty profile list resolves to nothing`() {
        assertNull(resolveProfile(emptyList(), selector = null, selectedId = null))
    }
}
