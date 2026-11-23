import Foundation

/// Scheduling helpers for background update checks on macOS.
public enum UpdateSchedule {
    /// Minimum interval between periodic background checks once the previous check succeeded.
    public static let weeklyInterval: TimeInterval = 7 * 24 * 60 * 60

    /// Delay after application launch before running the silent startup check.
    public static let startupDelay: TimeInterval = 10

    /// How often the running app checks whether a weekly check has become due.
    public static let pollInterval: TimeInterval = 60 * 60

    /// Returns true if a background update check should be performed now.
    ///
    /// Forced startup checks always run. Otherwise checks run when no previous check
    /// timestamp exists, when the system clock moved backwards, or when [interval]
    /// seconds have elapsed since [lastCheck].
    public static func isDue(
        lastCheck: TimeInterval,
        now: TimeInterval,
        interval: TimeInterval = weeklyInterval,
        force: Bool = false
    ) -> Bool {
        if force { return true }
        if lastCheck <= 0 { return true }
        if now < lastCheck { return true }
        return (now - lastCheck) >= interval
    }
}
