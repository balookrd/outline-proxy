import AppKit
import CryptoKit
import Foundation

/// Fetches, verifies and installs an update found by [UpdateChecker].
///
/// Unlike Android, macOS lets the app replace itself: the bundle is ad-hoc
/// signed, not sandboxed and not notarized, and a file this process downloads
/// carries no quarantine flag, so a swapped-in bundle launches without a
/// Gatekeeper prompt. The swap itself is done by a tiny shell script that waits
/// for the app to quit — a running bundle is not replaced from inside itself.
///
/// When the bundle cannot be replaced in place (no write access to its folder,
/// App Translocation, a development run outside an `.app`) the verified DMG is
/// put into ~/Downloads and opened instead, the same hand-off the Android
/// client does with its APK.
public enum UpdateInstaller {
    static let stagingPrefix = ".outline-proxy-update-"

    /// A downloaded update, verified and unpacked next to the installed bundle.
    public struct Staged: Sendable {
        let stagingDir: URL
        let newApp: URL
        let target: URL
    }

    // MARK: - Download

    /// Download the DMG of [update] and check it against the release's
    /// `SHA256SUMS.txt`. Returns the DMG in a temporary location.
    public static func download(
        _ update: UpdateChecker.Update,
        onProgress: @escaping @Sendable (Int) -> Void
    ) async throws -> URL {
        guard let checksumsURL = update.checksumsURL else {
            throw failure("в релизе нет \(UpdateChecker.checksumsAsset) — непроверенную сборку не ставим")
        }
        let (sums, response) = try await UpdateNetwork.session.data(from: checksumsURL)
        let code = (response as? HTTPURLResponse)?.statusCode ?? 0
        guard code == 200, let text = String(data: sums, encoding: .utf8) else {
            throw failure("не удалось получить контрольные суммы (HTTP \(code))")
        }
        guard let expected = UpdateChecker.expectedDigest(in: text, for: update.assetName) else {
            throw failure("в \(UpdateChecker.checksumsAsset) нет суммы для \(update.assetName)")
        }

        let dmg = try await DownloadDelegate.fetch(update.assetURL, onProgress: onProgress)
        let digest = try sha256Hex(of: dmg)
        guard digest == expected else {
            try? FileManager.default.removeItem(at: dmg)
            throw failure("контрольная сумма DMG не совпала")
        }
        return dmg
    }

    // MARK: - In-place install

    /// Why the running bundle cannot be replaced in place, or nil when it can.
    public static func inPlaceBlocker() -> String? {
        let target = Bundle.main.bundleURL
        guard target.pathExtension == "app" else {
            return "приложение запущено не из .app-бандла"
        }
        if target.path.contains("/AppTranslocation/") {
            return "macOS запустила изолированную копию приложения — перенесите его в «Программы»"
        }
        let parent = target.deletingLastPathComponent()
        let fm = FileManager.default
        guard fm.isWritableFile(atPath: parent.path), fm.isWritableFile(atPath: target.path) else {
            return "нет прав на запись в \(parent.path)"
        }
        return nil
    }

    /// Mount [dmg], copy its app next to the installed bundle and check that it
    /// is an intact build of this same app. The DMG is removed afterwards.
    public static func stage(dmg: URL) throws -> Staged {
        let fm = FileManager.default
        let target = Bundle.main.bundleURL
        // Same volume as the target, so the final swap is two renames.
        let staging = target.deletingLastPathComponent()
            .appendingPathComponent(stagingPrefix + UUID().uuidString, isDirectory: true)
        let mountPoint = fm.temporaryDirectory
            .appendingPathComponent("outline-proxy-mnt-" + UUID().uuidString, isDirectory: true)

        try fm.createDirectory(at: staging, withIntermediateDirectories: false)
        var mounted = false
        do {
            try fm.createDirectory(at: mountPoint, withIntermediateDirectories: true)
            // The image is already checked against SHA256SUMS, so hdiutil's own
            // verify pass would only add time.
            try run("/usr/bin/hdiutil", ["attach", "-nobrowse", "-readonly", "-noautoopen", "-noverify",
                                         "-mountpoint", mountPoint.path, dmg.path])
            mounted = true

            let contents = try fm.contentsOfDirectory(at: mountPoint, includingPropertiesForKeys: nil)
            guard let source = contents.first(where: { $0.pathExtension == "app" }) else {
                throw failure("в DMG нет приложения")
            }
            let newApp = staging.appendingPathComponent(target.lastPathComponent)
            try run("/usr/bin/ditto", [source.path, newApp.path])
            _ = try? run("/usr/bin/hdiutil", ["detach", mountPoint.path, "-force"])
            mounted = false

            // Belt and braces: a quarantined ad-hoc bundle would be refused by
            // Gatekeeper on relaunch.
            _ = try? run("/usr/bin/xattr", ["-dr", "com.apple.quarantine", newApp.path])
            do {
                try run("/usr/bin/codesign", ["--verify", "--deep", "--strict", newApp.path])
            } catch {
                throw failure("подпись нового бандла не прошла проверку")
            }
            let newId = Bundle(url: newApp)?.bundleIdentifier
            guard newId != nil, newId == Bundle.main.bundleIdentifier else {
                throw failure("в DMG другое приложение (\(newId ?? "без идентификатора"))")
            }

            try? fm.removeItem(at: dmg)
            try? fm.removeItem(at: mountPoint)
            return Staged(stagingDir: staging, newApp: newApp, target: target)
        } catch {
            if mounted { _ = try? run("/usr/bin/hdiutil", ["detach", mountPoint.path, "-force"]) }
            try? fm.removeItem(at: mountPoint)
            try? fm.removeItem(at: staging)
            throw error
        }
    }

    /// Start the script that swaps the bundles once this process exits and then
    /// relaunches the app. The caller quits right after.
    public static func launchSwapper(for staged: Staged) throws {
        let script = staged.stagingDir.appendingPathComponent("swap.sh")
        try swapScript.write(to: script, atomically: true, encoding: .utf8)

        let logDir = FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/Logs/OutlineProxy", isDirectory: true)
        try? FileManager.default.createDirectory(at: logDir, withIntermediateDirectories: true)
        let logURL = logDir.appendingPathComponent("update.log")
        if !FileManager.default.fileExists(atPath: logURL.path) {
            FileManager.default.createFile(atPath: logURL.path, contents: nil)
        }
        let log = try FileHandle(forWritingTo: logURL)
        log.seekToEndOfFile()

        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: "/bin/sh")
        proc.arguments = [
            script.path,
            String(ProcessInfo.processInfo.processIdentifier),
            staged.target.path,
            staged.newApp.path,
            staged.stagingDir.path,
        ]
        proc.standardInput = FileHandle.nullDevice
        proc.standardOutput = log
        proc.standardError = log
        try proc.run()
    }

    /// Drop staging folders a failed or interrupted update left behind.
    public static func cleanupLeftovers() {
        let fm = FileManager.default
        let parent = Bundle.main.bundleURL.deletingLastPathComponent()
        guard let items = try? fm.contentsOfDirectory(atPath: parent.path) else { return }
        for item in items where item.hasPrefix(stagingPrefix) {
            try? fm.removeItem(at: parent.appendingPathComponent(item))
        }
    }

    /// The swap runs outside the app: it waits for the app's pid to go away,
    /// moves the old bundle aside, moves the new one in (restoring the old one
    /// if that fails) and relaunches whichever bundle ended up in place.
    static let swapScript = """
    #!/bin/sh
    PID="$1"; TARGET="$2"; NEW="$3"; STAGE="$4"
    log() { echo "$(date '+%Y-%m-%d %H:%M:%S') $*"; }
    i=0
    while kill -0 "$PID" 2>/dev/null; do
        i=$((i + 1))
        if [ "$i" -gt 3000 ]; then
            log "app did not quit within 5 minutes, update aborted"
            rm -rf "$STAGE"
            exit 1
        fi
        sleep 0.1
    done
    BACKUP="$STAGE/previous.app"
    if ! mv "$TARGET" "$BACKUP"; then
        log "cannot move the old bundle aside, update aborted"
        open "$TARGET"
        exit 1
    fi
    if mv "$NEW" "$TARGET"; then
        log "installed update into $TARGET"
        rm -rf "$STAGE"
    else
        log "cannot move the new bundle in, restoring the old one"
        mv "$BACKUP" "$TARGET"
    fi
    /System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister -f "$TARGET" >/dev/null 2>&1 || true
    open "$TARGET"
    """

    // MARK: - Manual install

    /// Put the verified DMG into ~/Downloads and open it in Finder, leaving the
    /// drag into Applications to the user.
    public static func handOff(dmg: URL, assetName: String) throws -> URL {
        let fm = FileManager.default
        let downloads = fm.urls(for: .downloadsDirectory, in: .userDomainMask).first
            ?? fm.homeDirectoryForCurrentUser.appendingPathComponent("Downloads")
        let destination = downloads.appendingPathComponent(assetName)
        try? fm.removeItem(at: destination)
        try fm.moveItem(at: dmg, to: destination)
        NSWorkspace.shared.open(destination)
        return destination
    }

    // MARK: - Helpers

    static func sha256Hex(of file: URL) throws -> String {
        let handle = try FileHandle(forReadingFrom: file)
        defer { try? handle.close() }
        var hasher = SHA256()
        while let chunk = try handle.read(upToCount: 1 << 20), !chunk.isEmpty {
            hasher.update(data: chunk)
        }
        return hasher.finalize().map { String(format: "%02x", $0) }.joined()
    }

    @discardableResult
    static func run(_ path: String, _ arguments: [String]) throws -> String {
        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: path)
        proc.arguments = arguments
        let pipe = Pipe()
        proc.standardOutput = pipe
        proc.standardError = pipe
        try proc.run()
        let output = String(data: pipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
        proc.waitUntilExit()
        guard proc.terminationStatus == 0 else {
            let name = (path as NSString).lastPathComponent
            throw failure("\(name) завершился с кодом \(proc.terminationStatus): \(output.trimmingCharacters(in: .whitespacesAndNewlines))")
        }
        return output
    }

    static func failure(_ message: String) -> NSError {
        NSError(domain: "UpdateInstaller", code: 1, userInfo: [NSLocalizedDescriptionKey: message])
    }
}

/// Download with whole-percent progress. The async `URLSession.download` API
/// reports none, and a footer that only says "downloading…" is
/// indistinguishable from a stalled fetch.
private final class DownloadDelegate: NSObject, URLSessionDownloadDelegate, @unchecked Sendable {
    private let onProgress: @Sendable (Int) -> Void
    private let lock = NSLock()
    private var continuation: CheckedContinuation<URL, Error>?
    private var lastPercent = -1

    private init(onProgress: @escaping @Sendable (Int) -> Void) {
        self.onProgress = onProgress
    }

    static func fetch(_ url: URL, onProgress: @escaping @Sendable (Int) -> Void) async throws -> URL {
        let delegate = DownloadDelegate(onProgress: onProgress)
        let session = URLSession(configuration: UpdateNetwork.configuration(), delegate: delegate, delegateQueue: nil)
        defer { session.finishTasksAndInvalidate() }
        return try await withCheckedThrowingContinuation { continuation in
            delegate.continuation = continuation
            session.downloadTask(with: url).resume()
        }
    }

    private func finish(_ result: Swift.Result<URL, Error>) {
        lock.lock()
        let continuation = self.continuation
        self.continuation = nil
        lock.unlock()
        continuation?.resume(with: result)
    }

    func urlSession(
        _ session: URLSession,
        downloadTask: URLSessionDownloadTask,
        didWriteData bytesWritten: Int64,
        totalBytesWritten: Int64,
        totalBytesExpectedToWrite: Int64
    ) {
        guard totalBytesExpectedToWrite > 0 else { return }
        let percent = Int(min(100, max(0, totalBytesWritten * 100 / totalBytesExpectedToWrite)))
        if percent != lastPercent {
            lastPercent = percent
            onProgress(percent)
        }
    }

    func urlSession(_ session: URLSession, downloadTask: URLSessionDownloadTask, didFinishDownloadingTo location: URL) {
        let code = (downloadTask.response as? HTTPURLResponse)?.statusCode ?? 0
        guard code == 200 else {
            finish(.failure(UpdateInstaller.failure("HTTP \(code)")))
            return
        }
        // `location` is deleted as soon as this callback returns.
        let kept = FileManager.default.temporaryDirectory
            .appendingPathComponent("outline-proxy-update-\(UUID().uuidString).dmg")
        do {
            try FileManager.default.moveItem(at: location, to: kept)
            finish(.success(kept))
        } catch {
            finish(.failure(error))
        }
    }

    func urlSession(_ session: URLSession, task: URLSessionTask, didCompleteWithError error: Error?) {
        if let error { finish(.failure(error)) }
    }
}
