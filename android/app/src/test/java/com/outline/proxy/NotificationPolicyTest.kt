package com.outline.proxy

import org.junit.Assert.assertEquals
import org.junit.Test

/** Which action the ongoing notification's single toggle carries, per tunnel state. */
class NotificationPolicyTest {

    @Test
    fun `running tunnel offers disconnect`() {
        assertEquals(NotifToggle.DISCONNECT, NotificationPolicy.toggle(running = true))
    }

    @Test
    fun `down tunnel offers connect`() {
        assertEquals(NotifToggle.CONNECT, NotificationPolicy.toggle(running = false))
    }
}
