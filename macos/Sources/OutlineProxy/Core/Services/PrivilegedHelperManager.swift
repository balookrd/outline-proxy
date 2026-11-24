import AppKit
import CryptoKit
import Foundation

/// Manages passwordless `sudo` configuration and root-owned helper synchronization for TUN mode.
public final class PrivilegedHelperManager: @unchecked Sendable {
    public static let shared = PrivilegedHelperManager()

    public static let sudoersFilePath = "/etc/sudoers.d/outline-proxy"
    public static let systemSupportDir = "/Library/Application Support/OutlineProxy"
    public static let systemRunnerPath = "/Library/Application Support/OutlineProxy/tun-runner.sh"
    public static let systemBinaryPath = "/Library/Application Support/OutlineProxy/outline-client"
    private static let legacySystemBinaryPath = "/Library/Application Support/OutlineProxy/outline-ws-rust"
    public static let systemRunDir = "/var/run/outline-proxy"

    private struct DigestCacheEntry {
        let size: UInt64
        let mtime: Date
        let sha256: String
    }

    private static let digestLock = NSLock()
    private static var digestCache: [String: DigestCacheEntry] = [:]

    private init() {}

    /// Safely quotes an argument for POSIX shell execution using single quotes.
    public static func shellQuote(_ string: String) -> String {
        "'" + string.replacingOccurrences(of: "'", with: "'\\''") + "'"
    }

    /// Compares two files by size and SHA-256 digest (with metadata-keyed caching).
    public static func filesMatchSha256(_ lhs: URL, _ rhs: URL) -> Bool {
        let fm = FileManager.default
        guard let lhsAttrs = try? fm.attributesOfItem(atPath: lhs.path),
              let rhsAttrs = try? fm.attributesOfItem(atPath: rhs.path),
              let lhsSize = lhsAttrs[.size] as? UInt64,
              let rhsSize = rhsAttrs[.size] as? UInt64,
              lhsSize == rhsSize else {
            return false
        }

        guard let lhsDigest = cachedSha256(for: lhs, attrs: lhsAttrs, size: lhsSize),
              let rhsDigest = cachedSha256(for: rhs, attrs: rhsAttrs, size: rhsSize) else {
            return false
        }
        return lhsDigest == rhsDigest
    }

    private static func cachedSha256(for url: URL, attrs: [FileAttributeKey: Any], size: UInt64) -> String? {
        let mtime = (attrs[.modificationDate] as? Date) ?? .distantPast

        digestLock.lock()
        if let cached = digestCache[url.path], cached.size == size, cached.mtime == mtime {
            digestLock.unlock()
            return cached.sha256
        }
        digestLock.unlock()

        guard let handle = try? FileHandle(forReadingFrom: url) else { return nil }
        defer { try? handle.close() }

        var hasher = SHA256()
        while let chunk = try? handle.read(upToCount: 1 << 20), !chunk.isEmpty {
            hasher.update(data: chunk)
        }
        let hex = hasher.finalize().map { String(format: "%02x", $0) }.joined()

        digestLock.lock()
        digestCache[url.path] = DigestCacheEntry(size: size, mtime: mtime, sha256: hex)
        digestLock.unlock()
        return hex
    }

    /// Checks whether the installed root-owned helper script and binary match the current app bundle.
    public func areSystemFilesUpToDate() -> Bool {
        let fm = FileManager.default
        guard fm.isExecutableFile(atPath: Self.systemRunnerPath),
              fm.isExecutableFile(atPath: Self.systemBinaryPath),
              let bundleRunner = ProcessController.shared.locateBundleTunRunner(),
              let bundleBinary = ProcessController.shared.locateBinary() else {
            return false
        }

        let sysRunner = URL(fileURLWithPath: Self.systemRunnerPath)
        let sysBinary = URL(fileURLWithPath: Self.systemBinaryPath)
        return Self.filesMatchSha256(bundleRunner, sysRunner)
            && Self.filesMatchSha256(bundleBinary, sysBinary)
    }

    /// Checks whether passwordless `sudo` currently works for the installed `tun-runner.sh` (used e.g. for stop).
    public func canRunPasswordlessSudo() -> Bool {
        guard FileManager.default.isExecutableFile(atPath: Self.systemRunnerPath) else {
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

    /// Checks whether passwordless `sudo` is permitted AND the installed helper files match the current bundle.
    public func isSudoersConfigured() -> Bool {
        areSystemFilesUpToDate() && canRunPasswordlessSudo()
    }

    /// Builds the privileged shell snippet that installs/updates root-owned `tun-runner.sh` and `outline-client`.
    public static func systemFilesSyncScript(runnerSrc: String, binarySrc: String) -> String {
        let qSupportDir = shellQuote(systemSupportDir)
        let qRunnerSrc = shellQuote(runnerSrc)
        let qRunnerDst = shellQuote(systemRunnerPath)
        let qBinarySrc = shellQuote(binarySrc)
        let qBinaryDst = shellQuote(systemBinaryPath)
        let qLegacyBinary = shellQuote(legacySystemBinaryPath)
        let qRunDir = shellQuote(systemRunDir)

        return """
        mkdir -p \(qSupportDir)
        cp \(qRunnerSrc) \(qRunnerDst)
        chmod 755 \(qRunnerDst)
        chown root:wheel \(qRunnerDst)

        if [ \(qBinarySrc) != \(qBinaryDst) ]; then
            cp \(qBinarySrc) \(qBinaryDst)
        fi
        chmod 755 \(qBinaryDst)
        chown root:wheel \(qBinaryDst)
        rm -f \(qLegacyBinary)

        mkdir -p \(qRunDir)
        chmod 755 \(qRunDir)
        chown root:wheel \(qRunDir)
        """
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

        let syncFiles = Self.systemFilesSyncScript(runnerSrc: bundleRunnerURL.path, binarySrc: binaryURL.path)
        let qSudoersFile = Self.shellQuote(Self.sudoersFilePath)

        let script = """
        \(syncFiles)

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
