package com.outline.proxy

import org.junit.Assert.assertEquals
import org.junit.Test

/** The revival decision table: what `ensure()` does for each combination. */
class KeepAlivePolicyTest {

    private fun decide(
        shouldRun: Boolean = true,
        coreAlive: Boolean = false,
        consentGranted: Boolean = true,
        hasProfile: Boolean = true,
        failures: Int = 0,
    ) = KeepAlivePolicy.decide(shouldRun, coreAlive, consentGranted, hasProfile, failures)

    @Test
    fun `user turned it off - the chain dies here`() {
        assertEquals(KeepAliveAction.STOP, decide(shouldRun = false).action)
    }

    @Test
    fun `off wins over everything else`() {
        // A revoked consent must not turn a deliberate stop into a give-up:
        // STOP is silent, GIVE_UP notifies the user.
        val decision = decide(shouldRun = false, consentGranted = false, hasProfile = false)
        assertEquals(KeepAliveAction.STOP, decision.action)
    }

    @Test
    fun `core alive - nothing to do`() {
        assertEquals(KeepAliveAction.NOTHING, decide(coreAlive = true).action)
    }

    @Test
    fun `consent revoked - give up instead of looping`() {
        assertEquals(KeepAliveAction.GIVE_UP, decide(consentGranted = false).action)
    }

    @Test
    fun `no profile selected - give up`() {
        assertEquals(KeepAliveAction.GIVE_UP, decide(hasProfile = false).action)
    }

    @Test
    fun `everything ready - connect`() {
        assertEquals(KeepAliveAction.CONNECT, decide().action)
    }

    @Test
    fun `backoff grows after three consecutive failures`() {
        assertEquals(5 * 60_000L, KeepAlivePolicy.backoffFor(0))
        assertEquals(5 * 60_000L, KeepAlivePolicy.backoffFor(2))
        assertEquals(15 * 60_000L, KeepAlivePolicy.backoffFor(3))
        assertEquals(15 * 60_000L, KeepAlivePolicy.backoffFor(4))
        assertEquals(30 * 60_000L, KeepAlivePolicy.backoffFor(5))
        assertEquals(30 * 60_000L, KeepAlivePolicy.backoffFor(50))
    }

    @Test
    fun `connect carries the backed-off retry delay`() {
        assertEquals(30 * 60_000L, decide(failures = 9).retryDelayMs)
    }

    @Test
    fun `a healthy tunnel is re-checked at the base interval`() {
        // Failures are stale once the core is up: do not stretch the watchdog.
        assertEquals(KeepAlivePolicy.BASE_DELAY_MS, decide(coreAlive = true, failures = 9).retryDelayMs)
    }
}
