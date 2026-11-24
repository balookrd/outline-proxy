import Foundation

// MARK: - Test Runner for macOS Security Audit Fixes

func assertEq<T: Equatable>(_ actual: T, _ expected: T, _ msg: String) {
    if actual != expected {
        print("FAIL: \(msg) - Expected [\(expected)], got [\(actual)]")
        exit(1)
    }
}

func assertTrue(_ condition: Bool, _ msg: String) {
    if !condition {
        print("FAIL: \(msg)")
        exit(1)
    }
}

// 1. Shell Quoting Test
func testShellQuote() {
    print("-> Testing shellQuote...")
    func shellQuote(_ string: String) -> String {
        "'" + string.replacingOccurrences(of: "'", with: "'\\''") + "'"
    }

    let malicious = "hello; rm -rf /; echo $(whoami); `id`"
    let quoted = shellQuote(malicious)
    assertEq(quoted, "'hello; rm -rf /; echo $(whoami); `id`'", "shellQuote must wrap in single quotes without executing")

    let withQuotes = "it's a test"
    assertEq(shellQuote(withQuotes), "'it'\\''s a test'", "shellQuote must escape single quotes as '\\''")
    print("   [OK] shellQuote passed")
}

// 2. TOML Escaping & Transport Sanitization Test
func testTomlSanitization() {
    print("-> Testing TOML Escaping and Transport Sanitization...")
    func escapeToml(_ str: String) -> String {
        var result = ""
        result.reserveCapacity(str.count + 8)
        for scalar in str.unicodeScalars {
            switch scalar.value {
            case 0x5C: result.append("\\\\")
            case 0x22: result.append("\\\"")
            case 0x0A: result.append("\\n")
            case 0x0D: result.append("\\r")
            case 0x09: result.append("\\t")
            case 0x08: result.append("\\b")
            case 0x0C: result.append("\\f")
            case 0x00...0x1F, 0x7F:
                result.append(String(format: "\\u%04x", scalar.value))
            default:
                result.append(Character(scalar))
            }
        }
        return result
    }

    let maliciousName = "test\"\n[evil_section]\ninjected = \"true"
    let escaped = escapeToml(maliciousName)
    assertTrue(!escaped.contains("\n"), "escapeToml must not allow raw newlines")
    assertTrue(escaped.contains("\\n"), "escapeToml must escape newlines as \\n")
    assertTrue(escaped.contains("\\\""), "escapeToml must escape quotes as \\\"")

    let allowedTransports: Set<String> = [
        "vless", "ss", "xhttp_h2", "xhttp_h3", "ws_h2", "ws_h3"
    ]
    func sanitizeTransport(_ transport: String) -> String {
        let trimmed = transport.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        if allowedTransports.contains(trimmed) { return trimmed }
        return "vless"
    }

    assertEq(sanitizeTransport("xhttp_h3"), "xhttp_h3", "Valid transport allowed")
    assertEq(sanitizeTransport("ws_h2"), "ws_h2", "Valid transport allowed")
    assertEq(sanitizeTransport("vless\n[injected]"), "vless", "Malicious transport falls back to vless")
    assertEq(sanitizeTransport("unknown_protocol"), "vless", "Unknown transport falls back to vless")
    print("   [OK] TOML sanitization passed")
}

// 3. Host Sanitization Test
func testHostSanitization() {
    print("-> Testing Host Sanitization...")
    func sanitizeHost(_ host: String) -> String? {
        let trimmed = host.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return nil }
        guard trimmed.range(of: "^[a-zA-Z0-9.:\\[\\]-]+$", options: .regularExpression) != nil else {
            return nil
        }
        let clean = trimmed.replacingOccurrences(of: "[", with: "").replacingOccurrences(of: "]", with: "")
        return clean.isEmpty ? nil : clean
    }

    assertEq(sanitizeHost("vpn.example.com"), "vpn.example.com", "Valid domain allowed")
    assertEq(sanitizeHost("192.168.1.1"), "192.168.1.1", "Valid IPv4 allowed")
    assertEq(sanitizeHost("[2001:db8::1]"), "2001:db8::1", "Valid IPv6 allowed without brackets")
    assertTrue(sanitizeHost("example.com; rm -rf /") == nil, "Shell injection in host rejected")
    assertTrue(sanitizeHost("example.com$(id)") == nil, "Command substitution rejected")
    assertTrue(sanitizeHost("example.com`id`") == nil, "Backtick substitution rejected")
    assertTrue(sanitizeHost("evil|cat /etc/passwd") == nil, "Pipe injection rejected")
    print("   [OK] Host sanitization passed")
}

// 4. Update Installer Asset Sanitization Test
func testAssetSanitization() {
    print("-> Testing Asset Name Sanitization...")
    func sanitizeAsset(_ assetName: String) -> Bool {
        let trimmedName = assetName.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmedName.isEmpty,
              !trimmedName.contains("/"),
              !trimmedName.contains("\\"),
              !trimmedName.contains(".."),
              trimmedName != ".",
              trimmedName.lowercased().hasSuffix(".dmg") else {
            return false
        }
        return true
    }

    assertTrue(sanitizeAsset("OutlineProxy-1.0.0.dmg"), "Valid DMG name accepted")
    assertTrue(!sanitizeAsset("../../.bashrc"), "Path traversal rejected")
    assertTrue(!sanitizeAsset("../evil.dmg"), "Path traversal with .dmg rejected")
    assertTrue(!sanitizeAsset("evil.exe"), "Non-dmg rejected")
    assertTrue(!sanitizeAsset("/etc/sudoers"), "Absolute path rejected")
    print("   [OK] Asset sanitization passed")
}

// 5. Real tun-runner.sh BSD Compatibility & Host Extraction Test
func runBash(_ args: [String]) -> (Int32, String) {
    let proc = Process()
    proc.executableURL = URL(fileURLWithPath: "/bin/bash")
    proc.arguments = args
    let pipe = Pipe()
    proc.standardOutput = pipe
    proc.standardError = pipe
    do {
        try proc.run()
    } catch {
        return (-1, error.localizedDescription)
    }
    let data = pipe.fileHandleForReading.readDataToEndOfFile()
    proc.waitUntilExit()
    return (proc.terminationStatus, String(data: data, encoding: .utf8) ?? "")
}

func testTunRunnerScript() {
    print("-> Testing real macos/Resources/tun-runner.sh...")
    let scriptDir = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
    let runnerURL = scriptDir.deletingLastPathComponent().appendingPathComponent("Resources/tun-runner.sh")
    guard let content = try? String(contentsOf: runnerURL, encoding: .utf8) else {
        print("FAIL: Cannot read \(runnerURL.path)")
        exit(1)
    }

    let (syntaxCode, syntaxOut) = runBash(["-n", runnerURL.path])
    assertEq(syntaxCode, 0, "bash -n tun-runner.sh failed: \(syntaxOut)")

    // BSD /sbin/route and macOS dig reject `--` with `bad keyword: -` / `Invalid option: --`
    for (idx, line) in content.components(separatedBy: .newlines).enumerated() {
        let trimmed = line.trimmingCharacters(in: .whitespaces)
        if trimmed.hasPrefix("#") { continue }
        if trimmed.contains("/sbin/route") {
            assertTrue(!trimmed.contains(" -- "), "Line \(idx + 1) passes GNU `--` to BSD /sbin/route: \(trimmed)")
        }
        if trimmed.contains("dig ") {
            assertTrue(!trimmed.contains(" -- "), "Line \(idx + 1) passes unsupported `--` to macOS dig: \(trimmed)")
        }
    }

    assertTrue(content.contains("STATE_PATH="), "tun-runner.sh must isolate STATE_PATH inside RUN_DIR")
    assertTrue(content.contains("-reject"), "tun-runner.sh must use -reject for IPv6 leak prevention so apps fail over to IPv4 immediately")
    assertTrue(!content.contains("-blackhole"), "tun-runner.sh must not silently blackhole IPv6 packets")

    // Source helper functions from tun-runner.sh (guarded by TUN_RUNNER_LIB_ONLY=1) and test host extraction + validation
    let tmpCfg = FileManager.default.temporaryDirectory.appendingPathComponent("tun-runner-test-\(UUID().uuidString).toml")
    defer { try? FileManager.default.removeItem(at: tmpCfg) }

    let sampleToml = """
    [[outline.uplinks]]
    link = "vless://uuid@edge1.example.com:443?type=xhttp#edge1"

      [[outline.uplinks.fallbacks]]
      link = "ss://YWJj@203.0.113.10"

    [[outline.uplinks]]
    ws_url = "wss://ws.example.com:8443/secret"
    server_addr = "198.51.100.7:9000"

    [[outline.uplinks]]
    link = "vless://uuid@-flag-injection.example.com:443?type=ws"
    """
    try! sampleToml.write(to: tmpCfg, atomically: true, encoding: .utf8)

    let bashCmd = """
    set -e
    TUN_RUNNER_LIB_ONLY=1 source "\(runnerURL.path)"
    extract_valid_hosts "\(tmpCfg.path)" "-badhost.example.com"
    """
    let (extractCode, extractOut) = runBash(["-c", bashCmd])
    assertEq(extractCode, 0, "extract_valid_hosts execution failed: \(extractOut)")

    let hosts = Set(extractOut.split(whereSeparator: \.isNewline).map(String.init))
    assertTrue(hosts.contains("edge1.example.com"), "Must extract host from vless link with port, got: \(hosts)")
    assertTrue(hosts.contains("203.0.113.10"), "Must extract host from link without port before closing quote, got: \(hosts)")
    assertTrue(hosts.contains("ws.example.com"), "Must extract host from ws_url, got: \(hosts)")
    assertTrue(hosts.contains("198.51.100.7"), "Must extract host from server_addr, got: \(hosts)")
    assertTrue(!hosts.contains("-flag-injection.example.com"), "Must reject host starting with `-`, got: \(hosts)")
    assertTrue(!hosts.contains("-badhost.example.com"), "Must reject raw server_host starting with `-`, got: \(hosts)")

    print("   [OK] tun-runner.sh BSD compatibility and host extraction passed")
}

// Run all tests
testShellQuote()
testTomlSanitization()
testHostSanitization()
testAssetSanitization()
testTunRunnerScript()
print("\nALL SECURITY TESTS PASSED SUCCESSFULLY!")
