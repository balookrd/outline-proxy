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
enum VerifyHelperSync {
    static func main() throws {
        print("-> Testing ServerProfile host extraction & leading-dash rejection...")
        assertEq(ServerProfile.sanitizeHost("edge.example.com"), "edge.example.com", "valid domain")
        assertTrue(ServerProfile.sanitizeHost("-flag.example.com") == nil, "leading dash must be rejected")
        assertTrue(ServerProfile.sanitizeHost("[-flag]") == nil, "bracketed leading dash must be rejected")
        assertEq(
            ServerProfile.extractHost(from: #"link = "ss://YWJj@203.0.113.10""#),
            "203.0.113.10",
            "host without port before closing quote must be extracted cleanly"
        )
        print("   [OK] ServerProfile host checks passed")

        print("-> Testing PrivilegedHelperManager SHA-256 sync detection...")
        let tmpDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("helper-sync-test-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: tmpDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tmpDir) }

        let bundleFile = tmpDir.appendingPathComponent("bundle-runner.sh")
        let systemFile = tmpDir.appendingPathComponent("system-runner.sh")
        let missingFile = tmpDir.appendingPathComponent("missing.sh")

        try Data("#!/bin/bash\necho v1\n".utf8).write(to: bundleFile)
        try Data("#!/bin/bash\necho v1\n".utf8).write(to: systemFile)

        assertTrue(
            PrivilegedHelperManager.filesMatchSha256(bundleFile, systemFile),
            "identical files must match SHA-256"
        )
        assertFalse(
            PrivilegedHelperManager.filesMatchSha256(bundleFile, missingFile),
            "missing destination file must not match"
        )

        // Simulate app bundle update while /Library/Application Support keeps old copy
        try Data("#!/bin/bash\necho v2-fixed-route\n".utf8).write(to: bundleFile)
        assertFalse(
            PrivilegedHelperManager.filesMatchSha256(bundleFile, systemFile),
            "updated bundle file must be detected as out-of-sync with stale system file"
        )

        let syncScript = PrivilegedHelperManager.systemFilesSyncScript(
            runnerSrc: "/Applications/Outline Proxy.app/Contents/Resources/tun-runner.sh",
            binarySrc: "/Applications/Outline Proxy.app/Contents/Resources/outline-client"
        )
        assertTrue(syncScript.contains("tun-runner.sh"), "sync script must copy tun-runner.sh")
        assertTrue(syncScript.contains("outline-client"), "sync script must copy outline-client")
        assertTrue(syncScript.contains("chown root:wheel"), "sync script must set root:wheel ownership")
        print("   [OK] PrivilegedHelperManager SHA-256 sync passed")
    }
}
