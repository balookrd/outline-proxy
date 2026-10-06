import Foundation
import AppKit

/// Resolves human-readable application version and build metadata.
public enum AppVersion {
    public static var version: String {
        Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "1.9.1"
    }

    public static var build: String {
        Bundle.main.infoDictionary?["CFBundleVersion"] as? String ?? ""
    }

    public static var commit: String {
        Bundle.main.infoDictionary?["OutlineBuildCommit"] as? String ?? build
    }

    public static var channel: String {
        Bundle.main.infoDictionary?["OutlineBuildChannel"] as? String ?? "nightly"
    }

    public static var buildDate: String {
        Bundle.main.infoDictionary?["OutlineBuildDate"] as? String ?? ""
    }

    /// Short human-readable version string for UI display.
    /// - Nightly / dev: "nightly · v1.9.1 (1d050b6f)"
    /// - Official release tag: "v1.9.1"
    public static var displayString: String {
        let v = version
        let c = commit

        if channel == "release" && (c.isEmpty || c == "1" || c == v) {
            return "v\(v)"
        }

        var res = ""
        if !channel.isEmpty {
            res += "\(channel) · "
        }
        res += "v\(v)"

        if !c.isEmpty && c != "1" && c != v {
            res += " (\(c))"
        }

        return res
    }

    /// Detailed diagnostic version string including commit and build date.
    public static var fullDiagnosticString: String {
        var str = "Outline Proxy v\(version)"
        if !commit.isEmpty {
            str += " (\(commit))"
        }
        if !channel.isEmpty {
            str += " [\(channel)]"
        }
        if !buildDate.isEmpty {
            str += " · собран \(buildDate)"
        }
        return str
    }
}
