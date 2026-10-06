import Foundation

/// Manages the background `outline-ws-rust` process lifecycle in both SOCKS5 and TUN modes.
public final class ProcessController: @unchecked Sendable {
    public static let shared = ProcessController()

    public enum State: Equatable, Sendable {
        case stopped
        case starting
        case running(pid: Int32)
        case stopping
        case error(String)
    }

    private let stateLock = NSLock()
    private let logLock = NSLock()
    private var process: Process?
    private var state: State = .stopped
    private var logBuffer: [String] = []
    private let maxLogLines = 1000

    private var activeMode: ProxyMode = .socks5
    private var tunTimer: DispatchSourceTimer?
    private var lastLogOffset: UInt64 = 0
    private var tunPid: Int32?

    public var onStateChanged: (@Sendable (State) -> Void)?
    public var onLogLine: (@Sendable (String) -> Void)?

    private init() {}

    public var currentState: State {
        stateLock.lock()
        defer { stateLock.unlock() }
        return state
    }

    public var logs: [String] {
        logLock.lock()
        defer { logLock.unlock() }
        return logBuffer
    }

    /// Locates the `outline-ws-rust` binary executable.
    public func locateBinary() -> URL? {
        // 1. Environment variable
        if let envPath = ProcessInfo.processInfo.environment["OUTLINE_WS_BIN"] {
            let url = URL(fileURLWithPath: envPath)
            if FileManager.default.isExecutableFile(atPath: url.path) {
                return url
            }
        }

        // 2. App Bundle Resources (when packaged)
        if let resURL = Bundle.main.resourceURL?.appendingPathComponent("outline-ws-rust"),
           FileManager.default.isExecutableFile(atPath: resURL.path) {
            return resURL
        }

        // 3. Next to executable
        let exeDir = Bundle.main.bundleURL.deletingLastPathComponent()
        let nextToExe = exeDir.appendingPathComponent("outline-ws-rust")
        if FileManager.default.isExecutableFile(atPath: nextToExe.path) {
            return nextToExe
        }

        // 4. Cargo target directories during local development
        let possiblePaths = [
            FileManager.default.currentDirectoryPath + "/target/release/outline-ws-rust",
            FileManager.default.currentDirectoryPath + "/target/debug/outline-ws-rust",
            FileManager.default.currentDirectoryPath + "/../target/release/outline-ws-rust",
            FileManager.default.currentDirectoryPath + "/../target/debug/outline-ws-rust",
            "/usr/local/bin/outline-ws-rust",
            "/opt/homebrew/bin/outline-ws-rust"
        ]

        for p in possiblePaths {
            let url = URL(fileURLWithPath: (p as NSString).standardizingPath)
            if FileManager.default.isExecutableFile(atPath: url.path) {
                return url
            }
        }

        return nil
    }

    /// Locates the `tun-runner.sh` script for TUN VPN management.
    public func locateTunRunner() -> URL? {
        // 0. Privileged installed helper script
        let sysURL = URL(fileURLWithPath: PrivilegedHelperManager.systemRunnerPath)
        if FileManager.default.isExecutableFile(atPath: sysURL.path) {
            return sysURL
        }

        return locateBundleTunRunner()
    }

    /// Locates the script within app bundle or development tree.
    public func locateBundleTunRunner() -> URL? {
        // 1. App Bundle Resources
        if let resURL = Bundle.main.resourceURL?.appendingPathComponent("tun-runner.sh"),
           FileManager.default.fileExists(atPath: resURL.path) {
            try? FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: resURL.path)
            return resURL
        }

        // 2. Next to executable
        let exeDir = Bundle.main.bundleURL.deletingLastPathComponent()
        let nextToExe = exeDir.appendingPathComponent("tun-runner.sh")
        if FileManager.default.fileExists(atPath: nextToExe.path) {
            try? FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: nextToExe.path)
            return nextToExe
        }

        // 3. Development / repo directories
        let possiblePaths = [
            FileManager.default.currentDirectoryPath + "/macos/Resources/tun-runner.sh",
            FileManager.default.currentDirectoryPath + "/Resources/tun-runner.sh",
            FileManager.default.currentDirectoryPath + "/../macos/Resources/tun-runner.sh"
        ]

        for p in possiblePaths {
            let url = URL(fileURLWithPath: (p as NSString).standardizingPath)
            if FileManager.default.fileExists(atPath: url.path) {
                try? FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: url.path)
                return url
            }
        }

        return nil
    }

    /// Starts `outline-ws-rust` with the provided config content and mode.
    public func start(
        withConfigToml toml: String,
        mode: ProxyMode = .socks5,
        serverHost: String? = nil
    ) throws {
        stateLock.lock()
        guard case .stopped = state else {
            stateLock.unlock()
            return
        }

        guard let binURL = locateBinary() else {
            let err = "Не найден бинарник outline-ws-rust. Запустите сборку ядра через cargo build -p outline-ws-rust."
            state = .error(err)
            stateLock.unlock()
            appendLog("[ERROR] \(err)")
            onStateChanged?(.error(err))
            throw NSError(domain: "ProcessController", code: 1, userInfo: [NSLocalizedDescriptionKey: err])
        }

        activeMode = mode
        state = .starting
        stateLock.unlock()

        onStateChanged?(.starting)

        // Write config to application support directory
        let appSupport = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first!
            .appendingPathComponent("OutlineProxy")
        try? FileManager.default.createDirectory(at: appSupport, withIntermediateDirectories: true)
        let configPath = appSupport.appendingPathComponent("current_config.toml")
        try toml.write(to: configPath, atomically: true, encoding: .utf8)

        switch mode {
        case .socks5:
            try startSocks5(binURL: binURL, configPath: configPath)
        case .tun:
            try startTun(binURL: binURL, configPath: configPath, serverHost: serverHost ?? "", appSupport: appSupport)
        }
    }

    // MARK: - SOCKS5 Mode (User space)

    private func startSocks5(binURL: URL, configPath: URL) throws {
        let proc = Process()
        proc.executableURL = binURL
        proc.arguments = ["--config", configPath.path]

        let pipe = Pipe()
        proc.standardOutput = pipe
        proc.standardError = pipe

        pipe.fileHandleForReading.readabilityHandler = { [weak self] handle in
            let data = handle.availableData
            guard !data.isEmpty, let text = String(data: data, encoding: .utf8) else { return }
            for line in text.components(separatedBy: .newlines) {
                let trimmed = line.trimmingCharacters(in: .whitespaces)
                if !trimmed.isEmpty {
                    self?.appendLog(trimmed)
                }
            }
        }

        proc.terminationHandler = { [weak self] p in
            guard let self = self else { return }
            let status = p.terminationStatus
            let reason = p.terminationReason

            self.stateLock.lock()
            self.process = nil
            self.state = (status == 0) ? .stopped : .error("Процесс завершился с кодом \(status)")
            let currentState = self.state
            self.stateLock.unlock()

            self.appendLog("[INFO] outline-ws-rust (SOCKS5) завершён (код: \(status), причина: \(reason.rawValue))")
            self.onStateChanged?(currentState)
        }

        do {
            try proc.run()
            let pid = proc.processIdentifier

            stateLock.lock()
            self.process = proc
            self.state = .running(pid: pid)
            stateLock.unlock()

            appendLog("[INFO] Запущен outline-ws-rust в режиме SOCKS5 (PID: \(pid))")
            onStateChanged?(.running(pid: pid))
        } catch {
            stateLock.lock()
            self.process = nil
            self.state = .error("Ошибка запуска SOCKS5: \(error.localizedDescription)")
            stateLock.unlock()

            appendLog("[ERROR] \(error.localizedDescription)")
            onStateChanged?(.error(error.localizedDescription))
            throw error
        }
    }

    // MARK: - TUN Mode (Root privileged)

    private func startTun(binURL: URL, configPath: URL, serverHost: String, appSupport: URL) throws {
        guard let runnerURL = locateTunRunner() else {
            let err = "Скрипт tun-runner.sh не найден в ресурсах приложения."
            stateLock.lock()
            state = .error(err)
            stateLock.unlock()
            appendLog("[ERROR] \(err)")
            onStateChanged?(.error(err))
            throw NSError(domain: "ProcessController", code: 2, userInfo: [NSLocalizedDescriptionKey: err])
        }

        let runDir = appSupport.appendingPathComponent("tun_run")
        try? FileManager.default.createDirectory(at: runDir, withIntermediateDirectories: true)

        let logPath = runDir.appendingPathComponent("tun.log")
        // Truncate previous log
        try? "".write(to: logPath, atomically: true, encoding: .utf8)
        lastLogOffset = 0

        do {
            let output: String
            if PrivilegedHelperManager.shared.isSudoersConfigured() {
                appendLog("[INFO] Запуск TUN через беспарольный sudo (в 1 клик)...")
                output = runCommand("/usr/bin/sudo", [
                    runnerURL.path, "start", binURL.path, configPath.path, serverHost, runDir.path
                ])
            } else {
                appendLog("[INFO] Запрос прав администратора для создания L3 utun интерфейса...")
                let cmd = "\"\(runnerURL.path)\" start \"\(binURL.path)\" \"\(configPath.path)\" \"\(serverHost)\" \"\(runDir.path)\""
                output = try executeAsAdmin(command: cmd)
            }
            appendLog("[INFO] tun-runner: \(output)")

            // Check PID file
            let pidFile = runDir.appendingPathComponent("tun.pid")
            let pid: Int32
            if let pidStr = try? String(contentsOf: pidFile, encoding: .utf8).trimmingCharacters(in: .whitespacesAndNewlines),
               let parsed = Int32(pidStr) {
                pid = parsed
            } else {
                pid = 1
            }

            stateLock.lock()
            self.tunPid = pid
            self.state = .running(pid: pid)
            stateLock.unlock()

            appendLog("[INFO] Запущен outline-ws-rust в режиме TUN (PID: \(pid), utun активен)")
            onStateChanged?(.running(pid: pid))

            // Start log and liveness polling
            startTunMonitor(runDir: runDir, runnerURL: runnerURL)
        } catch {
            stateLock.lock()
            self.state = .error("Ошибка запуска TUN: \(error.localizedDescription)")
            stateLock.unlock()

            appendLog("[ERROR] \(error.localizedDescription)")
            onStateChanged?(.error(error.localizedDescription))
            throw error
        }
    }

    private func startTunMonitor(runDir: URL, runnerURL: URL) {
        let timer = DispatchSource.makeTimerSource(queue: DispatchQueue.global(qos: .utility))
        timer.schedule(deadline: .now() + 0.5, repeating: 0.5)

        let logFile = runDir.appendingPathComponent("tun.log")
        let pidFile = runDir.appendingPathComponent("tun.pid")

        timer.setEventHandler { [weak self] in
            guard let self = self else { return }

            // Read new log bytes
            if let handle = try? FileHandle(forReadingFrom: logFile) {
                let currentSize = handle.seekToEndOfFile()
                if currentSize > self.lastLogOffset {
                    handle.seek(toFileOffset: self.lastLogOffset)
                    let data = handle.readDataToEndOfFile()
                    self.lastLogOffset = currentSize
                    if let text = String(data: data, encoding: .utf8) {
                        for line in text.components(separatedBy: .newlines) {
                            let trimmed = line.trimmingCharacters(in: .whitespaces)
                            if !trimmed.isEmpty {
                                self.appendLog(trimmed)
                            }
                        }
                    }
                }
                try? handle.close()
            }

            // Check process liveness
            if let pid = self.tunPid {
                if !self.isProcessAlive(pid: pid) {
                    // Process is no longer running
                    self.stopTunMonitor()
                    self.stateLock.lock()
                    self.state = .stopped
                    self.tunPid = nil
                    let newState = self.state
                    self.stateLock.unlock()

                    self.appendLog("[INFO] outline-ws-rust (TUN) завершил работу.")
                    self.onStateChanged?(newState)
                }
            } else if !FileManager.default.fileExists(atPath: pidFile.path) {
                self.stopTunMonitor()
            }
        }

        self.tunTimer = timer
        timer.resume()
    }

    private func isProcessAlive(pid: Int32) -> Bool {
        if kill(pid, 0) == 0 {
            return true
        }
        // If kill returns EPERM, the process exists and is owned by root
        if errno == EPERM {
            return true
        }
        return false
    }

    private func stopTunMonitor() {
        tunTimer?.cancel()
        tunTimer = nil
    }

    /// Stops the running `outline-ws-rust` process gracefully in either mode.
    public func stop() {
        stateLock.lock()
        let mode = activeMode

        switch mode {
        case .socks5:
            guard let proc = process, proc.isRunning else {
                state = .stopped
                stateLock.unlock()
                onStateChanged?(.stopped)
                return
            }

            state = .stopping
            stateLock.unlock()
            onStateChanged?(.stopping)

            appendLog("[INFO] Остановка outline-ws-rust (SOCKS5)...")
            proc.terminate()

            DispatchQueue.global().async { [weak self] in
                let deadline = Date().addingTimeInterval(1.5)
                while proc.isRunning && Date() < deadline {
                    Thread.sleep(forTimeInterval: 0.1)
                }

                if proc.isRunning {
                    kill(proc.processIdentifier, SIGKILL)
                }

                self?.stateLock.lock()
                self?.process = nil
                self?.state = .stopped
                let newState = self?.state ?? .stopped
                self?.stateLock.unlock()

                self?.appendLog("[INFO] outline-ws-rust (SOCKS5) остановлен.")
                self?.onStateChanged?(newState)
            }

        case .tun:
            stopTunMonitor()
            state = .stopping
            stateLock.unlock()
            onStateChanged?(.stopping)

            appendLog("[INFO] Остановка TUN VPN и очистка системных маршрутов...")

            DispatchQueue.global().async { [weak self] in
                guard let self = self else { return }
                let appSupport = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first!
                    .appendingPathComponent("OutlineProxy")
                let runDir = appSupport.appendingPathComponent("tun_run")

                if let runnerURL = self.locateTunRunner() {
                    if PrivilegedHelperManager.shared.isSudoersConfigured() {
                        _ = self.runCommand("/usr/bin/sudo", [runnerURL.path, "stop", runDir.path])
                    } else {
                        let cmd = "\"\(runnerURL.path)\" stop \"\(runDir.path)\""
                        _ = try? self.executeAsAdmin(command: cmd)
                    }
                }

                self.stateLock.lock()
                self.tunPid = nil
                self.state = .stopped
                let newState = self.state
                self.stateLock.unlock()

                self.appendLog("[INFO] TUN VPN успешно отключен.")
                self.onStateChanged?(newState)
            }
        }
    }

    // MARK: - Admin Execution via AppleScript

    private func executeAsAdmin(command: String) throws -> String {
        let escaped = command.replacingOccurrences(of: "\\", with: "\\\\")
                             .replacingOccurrences(of: "\"", with: "\\\"")
        let script = "do shell script \"\(escaped)\" with administrator privileges"

        var errorDict: NSDictionary?
        if let appleScript = NSAppleScript(source: script) {
            let output = appleScript.executeAndReturnError(&errorDict)
            if let error = errorDict {
                let errorMsg = (error[NSAppleScript.errorMessage] as? String) ?? "Отказ в правах администратора"
                throw NSError(domain: "ProcessController", code: 2, userInfo: [NSLocalizedDescriptionKey: errorMsg])
            }
            return output.stringValue ?? ""
        } else {
            throw NSError(domain: "ProcessController", code: 3, userInfo: [NSLocalizedDescriptionKey: "Не удалось инициализировать AppleScript"])
        }
    }

    private static let timeFormatter: DateFormatter = {
        let df = DateFormatter()
        df.dateFormat = "HH:mm:ss.SSS"
        return df
    }()

    public var logCount: Int {
        logLock.lock()
        defer { logLock.unlock() }
        return logBuffer.count
    }

    private func appendLog(_ line: String) {
        let time = Self.timeFormatter.string(from: Date())
        let formatted = "[\(time)] \(line)"

        logLock.lock()
        logBuffer.append(formatted)
        if logBuffer.count > maxLogLines {
            logBuffer.removeFirst(logBuffer.count - maxLogLines)
        }
        logLock.unlock()

        onLogLine?(formatted)
    }

    @discardableResult
    public func runCommand(_ launchPath: String, _ arguments: [String]) -> String {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: launchPath)
        process.arguments = arguments

        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe

        do {
            try process.run()
            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            process.waitUntilExit()
            return String(data: data, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        } catch {
            return ""
        }
    }
}
