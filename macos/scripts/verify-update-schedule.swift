import Foundation

func assertEq<T: Equatable>(_ actual: T, _ expected: T, _ msg: String) {
    if actual != expected {
        fputs("FAIL: \(msg) — expected [\(expected)], got [\(actual)]\n", stderr)
        exit(1)
    }
}

func assertTrue(_ condition: Bool, _ msg: String) {
    if !condition {
        fputs("FAIL: \(msg)\n", stderr)
        exit(1)
    }
}

func assertFalse(_ condition: Bool, _ msg: String) {
    if condition {
        fputs("FAIL: \(msg)\n", stderr)
        exit(1)
    }
}

@main
enum VerifyUpdateSchedule {
    static func main() {
        print("-> Testing UpdateSchedule...")

        assertEq(UpdateSchedule.weeklyInterval, 7 * 24 * 60 * 60, "weeklyInterval must equal 7 days")
        assertEq(UpdateSchedule.startupDelay, 10, "startupDelay must equal 10 seconds")
        assertEq(UpdateSchedule.pollInterval, 60 * 60, "pollInterval must equal 1 hour")

        let base: TimeInterval = 1_700_000_000
        let week = UpdateSchedule.weeklyInterval

        assertTrue(UpdateSchedule.isDue(lastCheck: 0, now: base), "zero timestamp must be due")
        assertTrue(UpdateSchedule.isDue(lastCheck: -5, now: base), "negative timestamp must be due")
        assertTrue(UpdateSchedule.isDue(lastCheck: base + 100, now: base), "clock rollback must be due")

        assertFalse(UpdateSchedule.isDue(lastCheck: base, now: base), "same timestamp must not be due")
        assertFalse(
            UpdateSchedule.isDue(lastCheck: base, now: base + week - 1),
            "just before 7 days must not be due"
        )
        assertTrue(UpdateSchedule.isDue(lastCheck: base, now: base + week), "exactly 7 days must be due")
        assertTrue(
            UpdateSchedule.isDue(lastCheck: base, now: base + week + 3600),
            "past 7 days must be due"
        )

        assertTrue(
            UpdateSchedule.isDue(lastCheck: base, now: base + 5, force: true),
            "forced startup check must run regardless of lastCheck"
        )

        print("   [OK] UpdateSchedule passed")
    }
}
