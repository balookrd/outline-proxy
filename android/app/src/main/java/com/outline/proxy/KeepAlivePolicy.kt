package com.outline.proxy

/** What `ensure()` should do about the tunnel right now. */
enum class KeepAliveAction {
    /** The tunnel is up: leave it alone. */
    NOTHING,

    /** The user turned it off on purpose: let the revival chain die. */
    STOP,

    /** Cannot be fixed without the user (no consent, no profile): stop and tell them. */
    GIVE_UP,

    /** Bring the tunnel up. */
    CONNECT,
}

data class KeepAliveDecision(val action: KeepAliveAction, val retryDelayMs: Long)

/**
 * The revival decision, kept free of Android APIs so it can be unit-tested.
 *
 * Order matters: an explicit "off" outranks a revoked consent, because STOP is
 * silent while GIVE_UP notifies — nobody wants a notification for a tunnel they
 * switched off themselves.
 */
object KeepAlivePolicy {

    /** Watchdog period while things are healthy. */
    const val BASE_DELAY_MS = 5 * 60_000L

    fun decide(
        shouldRun: Boolean,
        coreAlive: Boolean,
        consentGranted: Boolean,
        hasProfile: Boolean,
        consecutiveFailures: Int,
    ): KeepAliveDecision = when {
        !shouldRun -> KeepAliveDecision(KeepAliveAction.STOP, 0)
        coreAlive -> KeepAliveDecision(KeepAliveAction.NOTHING, BASE_DELAY_MS)
        !consentGranted -> KeepAliveDecision(KeepAliveAction.GIVE_UP, 0)
        !hasProfile -> KeepAliveDecision(KeepAliveAction.GIVE_UP, 0)
        else -> KeepAliveDecision(KeepAliveAction.CONNECT, backoffFor(consecutiveFailures))
    }

    /**
     * A failing connect is expensive (open the TUN, boot the Rust core, tear it
     * all down), so a server that is simply unreachable must not be retried
     * every five minutes forever.
     */
    fun backoffFor(consecutiveFailures: Int): Long = when {
        consecutiveFailures < 3 -> BASE_DELAY_MS
        consecutiveFailures < 5 -> 15 * 60_000L
        else -> 30 * 60_000L
    }
}
