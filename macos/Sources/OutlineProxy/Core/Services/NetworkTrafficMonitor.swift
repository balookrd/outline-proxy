import Foundation
import Darwin

/// Monitors network traffic (transmitted/received bytes) for active proxy sessions.
public final class NetworkTrafficMonitor: @unchecked Sendable {
    public static let shared = NetworkTrafficMonitor()

    private let lock = NSLock()
    private var baseTx: UInt64 = 0
    private var baseRx: UInt64 = 0
    private var isTracking = false
    private var targetInterfacePrefix: String = "utun"

    private init() {}

    /// Starts tracking traffic from current baseline.
    public func start(mode: ProxyMode) {
        lock.lock()
        defer { lock.unlock() }

        targetInterfacePrefix = (mode == .tun) ? "utun" : ""
        let snapshot = readBytes(prefix: targetInterfacePrefix)
        baseTx = snapshot.tx
        baseRx = snapshot.rx
        isTracking = true
    }

    /// Stops tracking.
    public func stop() {
        lock.lock()
        defer { lock.unlock() }
        isTracking = false
        baseTx = 0
        baseRx = 0
    }

    /// Returns bytes moved since session start: (tx: uploaded/uplink, rx: downloaded/downlink).
    public func currentBytes() -> (tx: UInt64, rx: UInt64) {
        lock.lock()
        defer { lock.unlock() }

        guard isTracking else { return (0, 0) }
        let now = readBytes(prefix: targetInterfacePrefix)

        let tx = now.tx >= baseTx ? (now.tx - baseTx) : 0
        let rx = now.rx >= baseRx ? (now.rx - baseRx) : 0
        return (tx, rx)
    }

    /// Reads total interface bytes from system ifaddrs.
    private func readBytes(prefix: String) -> (tx: UInt64, rx: UInt64) {
        var ifap: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&ifap) == 0, let first = ifap else {
            return (0, 0)
        }
        defer { freeifaddrs(ifap) }

        var totalTx: UInt64 = 0
        var totalRx: UInt64 = 0

        var cursor: UnsafeMutablePointer<ifaddrs>? = first
        while let current = cursor {
            let name = String(cString: current.pointee.ifa_name)
            let addr = current.pointee.ifa_addr

            // Check AF_LINK socket address
            if let addr = addr, addr.pointee.sa_family == UInt8(AF_LINK) {
                let matches: Bool
                if prefix.isEmpty {
                    // SOCKS5: track primary non-loopback active interfaces (en, utun, etc.)
                    matches = name.hasPrefix("en") || name.hasPrefix("utun") || name.hasPrefix("ap")
                } else {
                    matches = name.hasPrefix(prefix)
                }

                if matches, let data = current.pointee.ifa_data {
                    let ifData = data.assumingMemoryBound(to: if_data.self)
                    totalTx += UInt64(ifData.pointee.ifi_obytes)
                    totalRx += UInt64(ifData.pointee.ifi_ibytes)
                }
            }
            cursor = current.pointee.ifa_next
        }

        return (totalTx, totalRx)
    }

    /// Formats raw byte count into human-readable string (e.g. "120 Б", "1.2 КБ", "45.8 МБ", "2.1 ГБ").
    public static func formatBytes(_ bytes: UInt64) -> String {
        if bytes < 1024 {
            return "\(bytes) Б"
        }
        let kb = Double(bytes) / 1024.0
        if kb < 1024.0 {
            return String(format: "%.1f КБ", kb)
        }
        let mb = kb / 1024.0
        if mb < 1024.0 {
            return String(format: "%.1f МБ", mb)
        }
        let gb = mb / 1024.0
        return String(format: "%.2f ГБ", gb)
    }
}
