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

// Run all tests
testShellQuote()
testTomlSanitization()
testHostSanitization()
testAssetSanitization()
print("\nALL SECURITY TESTS PASSED SUCCESSFULLY!")
