import Foundation

/// Utility to sanitize TOML configurations and link strings to enforce TCP-only mode (h2/h1 instead of h3).
///
/// Designed to eliminate UDP/QUIC (HTTP/3) connection attempts in networks where UDP 443
/// is blocked or heavily throttled.
public enum TcpOnlyConfig {

    private static let h3TransportRegex: NSRegularExpression = {
        let pattern = #"(?m)^(\s*(?:transport|vless_mode|ss_mode|tcp_mode|udp_mode)\s*=\s*["'])(?:xhttp_h3|ws_h3)(["'])"#
        return try! NSRegularExpression(pattern: pattern)
    }()

    private static let linkLineRegex: NSRegularExpression = {
        let pattern = #"(?m)^(\s*link\s*=\s*["'])(.+?)(["'])"#
        return try! NSRegularExpression(pattern: pattern)
    }()

    private static let alpnH3QueryRegex: NSRegularExpression = {
        let pattern = #"([?&]alpn=)([^&#"'\s]+)"#
        return try! NSRegularExpression(pattern: pattern)
    }()

    /// Rewrites h3 carrier transports (xhttp_h3 -> xhttp_h2, ws_h3 -> ws_h2) and strips h3 from alpn query parameters in links.
    public static func apply(to rawToml: String) -> String {
        var result = rawToml

        // 1. Replace carrier transports (xhttp_h3 -> xhttp_h2, ws_h3 -> ws_h2)
        let nsString = result as NSString
        let transportMatches = h3TransportRegex.matches(in: result, range: NSRange(location: 0, length: nsString.length))
        for match in transportMatches.reversed() {
            guard match.numberOfRanges == 3 else { continue }
            let fullRange = match.range(at: 0)
            let prefixRange = match.range(at: 1)
            let suffixRange = match.range(at: 2)
            let prefix = nsString.substring(with: prefixRange)
            let suffix = nsString.substring(with: suffixRange)
            let matchedText = nsString.substring(with: fullRange)
            let replTransport = matchedText.contains("xhttp_h3") ? "xhttp_h2" : "ws_h2"
            let replacement = "\(prefix)\(replTransport)\(suffix)"
            result = (result as NSString).replacingCharacters(in: fullRange, with: replacement)
        }

        // 2. Sanitize embedded links in TOML
        let updatedNsString = result as NSString
        let linkMatches = linkLineRegex.matches(in: result, range: NSRange(location: 0, length: updatedNsString.length))
        for match in linkMatches.reversed() {
            guard match.numberOfRanges == 4 else { continue }
            let fullRange = match.range(at: 0)
            let prefixRange = match.range(at: 1)
            let linkRange = match.range(at: 2)
            let suffixRange = match.range(at: 3)
            let prefix = updatedNsString.substring(with: prefixRange)
            let linkText = updatedNsString.substring(with: linkRange)
            let suffix = updatedNsString.substring(with: suffixRange)
            let sanitizedLink = enforceLink(linkText)
            let replacement = "\(prefix)\(sanitizedLink)\(suffix)"
            result = (result as NSString).replacingCharacters(in: fullRange, with: replacement)
        }

        return result
    }

    /// Rewrites `alpn=...` query parameters in a link string so that `h3` is eliminated and replaced with `h2` if necessary.
    public static func enforceLink(_ link: String) -> String {
        var result = link
        let nsString = result as NSString
        let matches = alpnH3QueryRegex.matches(in: result, range: NSRange(location: 0, length: nsString.length))
        for match in matches.reversed() {
            guard match.numberOfRanges == 3 else { continue }
            let fullRange = match.range(at: 0)
            let prefixRange = match.range(at: 1)
            let alpnRange = match.range(at: 2)
            let prefix = nsString.substring(with: prefixRange)
            let rawAlpn = nsString.substring(with: alpnRange)

            let tokens = rawAlpn.components(separatedBy: ",")
                .map { $0.trimmingCharacters(in: .whitespaces) }
                .filter { !$0.isEmpty }
            let clean = tokens.filter { $0.lowercased() != "h3" }
            let newAlpn = clean.isEmpty ? "h2" : clean.joined(separator: ",")
            let replacement = "\(prefix)\(newAlpn)"
            result = (result as NSString).replacingCharacters(in: fullRange, with: replacement)
        }
        return result
    }
}
