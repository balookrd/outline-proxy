package com.outline.proxy

/** The single status-aware action the ongoing tunnel notification carries. */
enum class NotifToggle { CONNECT, DISCONNECT }

/**
 * Pure decisions for the ongoing tunnel notification, kept free of Android APIs
 * so they can be unit-tested on the JVM (mirrors [KeepAlivePolicy]).
 */
object NotificationPolicy {

    /**
     * Which toggle the notification shows: DISCONNECT while the core is up,
     * CONNECT while it is down (standby). Derived from live tunnel state — the
     * persistent-notification setting only decides whether the notification
     * exists at all, not what its button does.
     */
    fun toggle(running: Boolean): NotifToggle =
        if (running) NotifToggle.DISCONNECT else NotifToggle.CONNECT
}
