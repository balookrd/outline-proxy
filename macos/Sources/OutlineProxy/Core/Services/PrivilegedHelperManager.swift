import Foundation
import AppKit

/// Manages passwordless `sudo` configuration for TUN mode via `/etc/sudoers.d/outline-proxy`.
public final class PrivilegedHelperManager: @unchecked Sendable {
    public static let shared = PrivilegedHelperManager()

    public static let sudoersFilePath = "/etc/sudoers.d/outline-proxy"
    public static let systemSupportDir = "/Library/Application Support/OutlineProxy"
    public static let systemRunnerPath = "/Library/Application Support/OutlineProxy/tun-runner.sh"
    public static let systemBinaryPath = "/Library/Application Support/OutlineProxy/outline-client"
    private static let legacySystemBinaryPath = "/Library/Application Support/OutlineProxy/outline-ws-rust"
    public static let systemRunDir = "/var/run/outline-proxy"

    private init() {}

    /// Safely quotes an argument for POSIX shell execution using single quotes.
    public static func shellQuote(_ string: String) -> String {
        "'" + string.replacingOccurrences(of: "'", with: "'\\''") + "'"
    }

    /// Checks whether passwordless `sudo` is currently permitted for `tun-runner.sh`
    /// and whether both the system script and binary are properly installed.
    public func isSudoersConfigured() -> Bool {
        guard FileManager.default.isExecutableFile(atPath: Self.systemRunnerPath),
              FileManager.default.isExecutableFile(atPath: Self.systemBinaryPath) else {
            return false
        }

        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: "/usr/bin/sudo")
        proc.arguments = ["-n", Self.systemRunnerPath, "status"]

        let devNull = FileHandle.nullDevice
        proc.standardOutput = devNull
        proc.standardError = devNull

        do {
            try proc.run()
            proc.waitUntilExit()
            return proc.terminationStatus == 0
        } catch {
            return false
        }
    }

    /// Installs the sudoers rule and system helper script, prompting for administrator password once.
    public func installSudoersRule() throws {
        guard let bundleRunnerURL = ProcessController.shared.locateBundleTunRunner() ?? ProcessController.shared.locateTunRunner() else {
            throw NSError(domain: "PrivilegedHelperManager", code: 1, userInfo: [
                NSLocalizedDescriptionKey: "Скрипт tun-runner.sh не найден в ресурсах приложения."
            ])
        }

        guard let binaryURL = ProcessController.shared.locateBinary() else {
            throw NSError(domain: "PrivilegedHelperManager", code: 2, userInfo: [
                NSLocalizedDescriptionKey: "Бинарник outline-client не найден для установки системного хелпера."
            ])
        }

        let currentUser = NSUserName()
        guard currentUser.range(of: "^[a-zA-Z0-9._-]+$", options: .regularExpression) != nil else {
            throw NSError(domain: "PrivilegedHelperManager", code: 3, userInfo: [
                NSLocalizedDescriptionKey: "Имя текущего пользователя содержит недопустимые символы: \(currentUser)"
            ])
        }

        let qSupportDir = Self.shellQuote(Self.systemSupportDir)
        let qRunnerSrc = Self.shellQuote(bundleRunnerURL.path)
        let qRunnerDst = Self.shellQuote(Self.systemRunnerPath)
        let qBinarySrc = Self.shellQuote(binaryURL.path)
        let qBinaryDst = Self.shellQuote(Self.systemBinaryPath)
        let qLegacyBinary = Self.shellQuote(Self.legacySystemBinaryPath)
        let qRunDir = Self.shellQuote(Self.systemRunDir)
        let qSudoersFile = Self.shellQuote(Self.sudoersFilePath)

        let script = """
        mkdir -p \(qSupportDir)
        cp \(qRunnerSrc) \(qRunnerDst)
        chmod 755 \(qRunnerDst)
        chown root:wheel \(qRunnerDst)

        cp \(qBinarySrc) \(qBinaryDst)
        chmod 755 \(qBinaryDst)
        chown root:wheel \(qBinaryDst)
        rm -f \(qLegacyBinary)

        mkdir -p \(qRunDir)
        chmod 755 \(qRunDir)
        chown root:wheel \(qRunDir)

        mkdir -p /etc/sudoers.d
        TMP_FILE=$(mktemp /etc/sudoers.d/.outline-proxy.XXXXXX)
        cat << 'EOF' > "$TMP_FILE"
        # Outline Proxy NOPASSWD rule for L3 TUN mode
        \(currentUser) ALL=(ALL) NOPASSWD: /Library/Application\\ Support/OutlineProxy/tun-runner.sh
        %admin ALL=(ALL) NOPASSWD: /Library/Application\\ Support/OutlineProxy/tun-runner.sh
        EOF
        /usr/sbin/visudo -c -f "$TMP_FILE" || { rm -f "$TMP_FILE"; exit 1; }
        mv "$TMP_FILE" \(qSudoersFile)
        chmod 0440 \(qSudoersFile)
        chown root:wheel \(qSudoersFile)
        """

        _ = try executeAsAdmin(command: script)
    }

    /// Removes the sudoers rule and system helper script.
    public func removeSudoersRule() throws {
        let qSudoers = Self.shellQuote(Self.sudoersFilePath)
        let qRunner = Self.shellQuote(Self.systemRunnerPath)
        let qBinary = Self.shellQuote(Self.systemBinaryPath)
        let qLegacyBinary = Self.shellQuote(Self.legacySystemBinaryPath)
        let qRunDir = Self.shellQuote(Self.systemRunDir)

        let script = """
        rm -f \(qSudoers)
        rm -f \(qRunner)
        rm -f \(qBinary)
        rm -f \(qLegacyBinary)
        rm -rf \(qRunDir)
        """
        _ = try executeAsAdmin(command: script)
    }

    @discardableResult
    public func executeAsAdmin(command: String) throws -> String {
        try Self.executeAsAdmin(command: command)
    }

    @discardableResult
    public static func executeAsAdmin(command: String) throws -> String {
        let escaped = command.replacingOccurrences(of: "\\", with: "\\\\")
                             .replacingOccurrences(of: "\"", with: "\\\"")
        let appleScriptCode = "do shell script \"\(escaped)\" with administrator privileges"

        var errorDict: NSDictionary?
        if let appleScript = NSAppleScript(source: appleScriptCode) {
            let output = appleScript.executeAndReturnError(&errorDict)
            if let error = errorDict {
                let errorMsg = (error[NSAppleScript.errorMessage] as? String) ?? "Отказ в правах администратора"
                throw NSError(domain: "PrivilegedHelperManager", code: 4, userInfo: [NSLocalizedDescriptionKey: errorMsg])
            }
            return output.stringValue ?? ""
        } else {
            throw NSError(domain: "PrivilegedHelperManager", code: 5, userInfo: [NSLocalizedDescriptionKey: "Не удалось инициализировать AppleScript"])
        }
    }
}
