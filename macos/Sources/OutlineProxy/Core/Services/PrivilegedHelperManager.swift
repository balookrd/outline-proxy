import Foundation
import AppKit

/// Manages passwordless `sudo` configuration for TUN mode via `/etc/sudoers.d/outline-proxy`.
public final class PrivilegedHelperManager: @unchecked Sendable {
    public static let shared = PrivilegedHelperManager()

    public static let sudoersFilePath = "/etc/sudoers.d/outline-proxy"
    public static let systemRunnerPath = "/Library/Application Support/OutlineProxy/tun-runner.sh"

    private init() {}

    /// Checks whether passwordless `sudo` is currently permitted for `tun-runner.sh`.
    public func isSudoersConfigured() -> Bool {
        guard let runnerURL = ProcessController.shared.locateTunRunner() else {
            return false
        }

        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: "/usr/bin/sudo")
        proc.arguments = ["-n", runnerURL.path, "status", "/tmp"]

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

        let currentUser = NSUserName()
        let script = """
        mkdir -p "/Library/Application Support/OutlineProxy"
        cp "\(bundleRunnerURL.path)" "\(Self.systemRunnerPath)"
        chmod 755 "\(Self.systemRunnerPath)"
        chown root:wheel "\(Self.systemRunnerPath)"

        mkdir -p /etc/sudoers.d
        TMP_FILE="/tmp/outline_proxy_sudoers.$$"
        cat << 'EOF' > "$TMP_FILE"
        # Outline Proxy NOPASSWD rule for L3 TUN mode
        \(currentUser) ALL=(ALL) NOPASSWD: /Library/Application\\ Support/OutlineProxy/tun-runner.sh
        \(currentUser) ALL=(ALL) NOPASSWD: /Applications/Outline\\ Proxy.app/Contents/Resources/tun-runner.sh
        %admin ALL=(ALL) NOPASSWD: /Library/Application\\ Support/OutlineProxy/tun-runner.sh
        %admin ALL=(ALL) NOPASSWD: /Applications/Outline\\ Proxy.app/Contents/Resources/tun-runner.sh
        EOF
        /usr/sbin/visudo -c -f "$TMP_FILE" || { rm -f "$TMP_FILE"; exit 1; }
        mv "$TMP_FILE" "\(Self.sudoersFilePath)"
        chmod 0440 "\(Self.sudoersFilePath)"
        chown root:wheel "\(Self.sudoersFilePath)"
        """

        try executeAsAdmin(command: script)
    }

    /// Removes the sudoers rule and system helper script.
    public func removeSudoersRule() throws {
        let script = """
        rm -f "\(Self.sudoersFilePath)"
        rm -f "\(Self.systemRunnerPath)"
        """
        try executeAsAdmin(command: script)
    }

    private func executeAsAdmin(command: String) throws {
        let escaped = command.replacingOccurrences(of: "\\", with: "\\\\")
                             .replacingOccurrences(of: "\"", with: "\\\"")
        let appleScriptCode = "do shell script \"\(escaped)\" with administrator privileges"

        var errorDict: NSDictionary?
        if let appleScript = NSAppleScript(source: appleScriptCode) {
            _ = appleScript.executeAndReturnError(&errorDict)
            if let error = errorDict {
                let errorMsg = (error[NSAppleScript.errorMessage] as? String) ?? "Отказ в правах администратора"
                throw NSError(domain: "PrivilegedHelperManager", code: 2, userInfo: [NSLocalizedDescriptionKey: errorMsg])
            }
        } else {
            throw NSError(domain: "PrivilegedHelperManager", code: 3, userInfo: [NSLocalizedDescriptionKey: "Не удалось инициализировать AppleScript"])
        }
    }
}
