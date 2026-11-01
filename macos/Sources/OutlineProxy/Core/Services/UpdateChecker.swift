import Foundation

/// Checks GitHub for a newer build of *this* app's channel.
///
/// Mirrors the Android client's `UpdateChecker.kt`: channels are identified
/// differently because they are versioned differently. A release is a tag
/// (`macos-v1.9.2`) and compares by version, while every nightly shares the
/// rolling `macos-nightly` tag and is identified only by the commit baked into
/// its DMG name (`OutlineProxy-nightly-<sha8>-macOS-Universal.dmg`).
public enum UpdateChecker {
    static let repo = "balookrd/outline-proxy"
    static let nightlyTag = "macos-nightly"
    static let releaseTagPrefix = "macos-v"
    static let nightlyAssetPrefix = "OutlineProxy-nightly-"
    static let assetSuffix = "-macOS-Universal.dmg"
    static let checksumsAsset = "SHA256SUMS.txt"

    /// A newer build that can be fetched.
    public struct Update: Sendable, Equatable {
        /// How the build is named on its channel ("v1.9.2", "nightly · 4c7821c4").
        public let label: String
        public let assetName: String
        public let assetURL: URL
        /// `SHA256SUMS.txt` of the same release; nil when the release has none.
        public let checksumsURL: URL?
        /// Raw GitHub release body (Markdown); "" when the release has none.
        public let notes: String
    }

    public enum Result: Sendable {
        /// This build is the newest one published for its channel.
        case upToDate
        case available(Update)
        case failed(String)
    }

    struct Release: Decodable {
        let tag_name: String
        let draft: Bool?
        let body: String?
        let assets: [Asset]
    }

    struct Asset: Decodable {
        let name: String
        let browser_download_url: URL
    }

    /// Ask GitHub what the newest build on this channel is. Every failure is
    /// reported rather than thrown — an updater must never be the reason the
    /// app misbehaves.
    public static func check() async -> Result {
        do {
            if AppVersion.channel == "release" {
                let data = try await get("https://api.github.com/repos/\(repo)/releases?per_page=100")
                let releases = try JSONDecoder().decode([Release].self, from: data)
                return evaluateRelease(releases, currentVersion: AppVersion.version)
            }
            let data = try await get("https://api.github.com/repos/\(repo)/releases/tags/\(nightlyTag)")
            let release = try JSONDecoder().decode(Release.self, from: data)
            return evaluateNightly(release, currentCommit: AppVersion.commit)
        } catch {
            return .failed(error.localizedDescription)
        }
    }

    /// Nightlies all publish under one rolling tag, so "newer" is "the published
    /// DMG was built from a different commit than this build". The DMG name
    /// carries an 8-character sha while the bundle carries `git rev-parse
    /// --short` (7+ characters, possibly with `-dirty`), so they are compared by
    /// prefix.
    static func evaluateNightly(_ release: Release, currentCommit: String) -> Result {
        guard let asset = dmgAsset(release) else {
            return .failed("в nightly-релизе нет DMG")
        }
        let sha = String(asset.name.dropFirst(nightlyAssetPrefix.count).dropLast(assetSuffix.count))
        guard asset.name.hasPrefix(nightlyAssetPrefix), !sha.isEmpty else {
            return .failed("неожиданное имя DMG: \(asset.name)")
        }
        if sameCommit(sha, currentCommit) {
            return .upToDate
        }
        return .available(update(release, asset: asset, label: "nightly · \(sha)"))
    }

    /// Releases carry their version in the tag, so the newest `macos-v*` tag
    /// wins — `/releases/latest` is no help, since the repository also publishes
    /// server, client and Android releases.
    static func evaluateRelease(_ releases: [Release], currentVersion: String) -> Result {
        var best: Release?
        var bestVersion: [Int] = []
        for release in releases where release.tag_name.hasPrefix(releaseTagPrefix) && release.draft != true {
            let version = versionParts(String(release.tag_name.dropFirst(releaseTagPrefix.count)))
            if compareVersions(version, bestVersion) > 0 {
                best = release
                bestVersion = version
            }
        }
        guard let release = best else {
            return .failed("ещё не опубликовано ни одного релиза \(releaseTagPrefix)*")
        }
        if compareVersions(bestVersion, versionParts(currentVersion)) <= 0 {
            return .upToDate
        }
        guard let asset = dmgAsset(release) else {
            return .failed("в \(release.tag_name) нет DMG")
        }
        let label = "v" + release.tag_name.dropFirst(releaseTagPrefix.count)
        return .available(update(release, asset: asset, label: label))
    }

    static func sameCommit(_ published: String, _ current: String) -> Bool {
        let a = published.lowercased()
        let b = current.lowercased().replacingOccurrences(of: "-dirty", with: "")
        // A bare build number ("1") or an empty commit is not a commit at all.
        guard a.count >= 7, b.count >= 7 else { return false }
        return a.hasPrefix(b) || b.hasPrefix(a)
    }

    /// `1.9.2` → `[1, 9, 2]`; non-numeric parts (a `-rc1` suffix) stop the parse.
    static func versionParts(_ version: String) -> [Int] {
        let trimmed = version.hasPrefix("v") ? String(version.dropFirst()) : version
        return trimmed.split(separator: ".").map { part in
            Int(part.prefix(while: \.isNumber)) ?? 0
        }
    }

    static func compareVersions(_ a: [Int], _ b: [Int]) -> Int {
        for i in 0..<max(a.count, b.count) {
            let diff = (i < a.count ? a[i] : 0) - (i < b.count ? b[i] : 0)
            if diff != 0 { return diff }
        }
        return 0
    }

    /// The expected digest of [assetName] from a `sha256sum` listing.
    static func expectedDigest(in checksums: String, for assetName: String) -> String? {
        for line in checksums.split(whereSeparator: \.isNewline) {
            let fields = line.split(separator: " ", omittingEmptySubsequences: true)
            guard fields.count >= 2 else { continue }
            // `sha256sum` marks binary mode with a leading `*` on the name.
            let name = fields[1].hasPrefix("*") ? String(fields[1].dropFirst()) : String(fields[1])
            if name == assetName { return fields[0].lowercased() }
        }
        return nil
    }

    private static func dmgAsset(_ release: Release) -> Asset? {
        release.assets.first { $0.name.hasSuffix(assetSuffix) }
    }

    private static func update(_ release: Release, asset: Asset, label: String) -> Update {
        Update(
            label: label,
            assetName: asset.name,
            assetURL: asset.browser_download_url,
            checksumsURL: release.assets.first { $0.name == checksumsAsset }?.browser_download_url,
            notes: release.body ?? ""
        )
    }

    private static func get(_ url: String) async throws -> Data {
        var request = URLRequest(url: URL(string: url)!)
        request.timeoutInterval = 15
        request.setValue("application/vnd.github+json", forHTTPHeaderField: "Accept")
        request.setValue("OutlineProxy-macOS/\(AppVersion.version)", forHTTPHeaderField: "User-Agent")
        let (data, response) = try await UpdateNetwork.session.data(for: request)
        let code = (response as? HTTPURLResponse)?.statusCode ?? 0
        guard code == 200 else {
            throw NSError(domain: "UpdateChecker", code: code, userInfo: [NSLocalizedDescriptionKey: "HTTP \(code)"])
        }
        return data
    }
}

/// Network access for the updater.
///
/// Deliberately bypasses the system proxy: in SOCKS5 mode the app points the
/// system proxy at its own `outline-ws-rust`, and an update download must not
/// depend on the very link the user may be updating to fix. (TUN mode routes
/// at L3 and cannot be bypassed from here.)
enum UpdateNetwork {
    static let session: URLSession = URLSession(configuration: configuration())

    static func configuration() -> URLSessionConfiguration {
        let config = URLSessionConfiguration.ephemeral
        config.connectionProxyDictionary = [
            kCFNetworkProxiesHTTPEnable as String: false,
            kCFNetworkProxiesHTTPSEnable as String: false,
            kCFNetworkProxiesSOCKSEnable as String: false,
            kCFNetworkProxiesProxyAutoConfigEnable as String: false,
            kCFNetworkProxiesProxyAutoDiscoveryEnable as String: false,
        ]
        config.timeoutIntervalForRequest = 30
        return config
    }
}
