//
//  CloudflareTunnel.swift
//  rootshell
//
//  A saved Cloudflare Tunnel route: SSH (and every other TCP dial that goes
//  through MPTCPBootstrap) to a matching host is carried over a WebSocket to
//  the Cloudflare edge, the same way `cloudflared access ssh --hostname %h`
//  does as a ProxyCommand. Pure value type, so tests compile it.
//

import Foundation

nonisolated struct CloudflareTunnel: Codable, Identifiable, Hashable, Sendable {
    enum AuthMode: String, Codable, CaseIterable, Sendable {
        /// The tunnel hostname has no Access application in front of it.
        case none
        /// Sign in to Cloudflare Access in a web view; the app token is kept per hostname.
        case browser
        /// An Access service token (`Cf-Access-Client-Id` / `Cf-Access-Client-Secret`).
        case serviceToken
    }

    var id = UUID()
    var name = ""
    /// Comma- or space-separated OpenSSH-style globs, e.g. `ssh.example.com`
    /// or `*.example.com, !www.example.com`.
    var hostPatterns = ""
    var authMode: AuthMode = .browser
    var serviceTokenID = ""
    var serviceTokenSecret = ""
    /// Bastion mode: connect to this tunnel hostname and ask it to forward to
    /// the dialed `host:port` (`cloudflared access ssh --destination`). Empty
    /// connects to the dialed host itself.
    var bastionHostname = ""
    var isEnabled = true

    init() {}

    init(from decoder: Decoder) throws {
        // Tolerant decoding: items written by newer builds sync to older ones.
        let container = try decoder.container(keyedBy: CodingKeys.self)
        id = try container.decode(UUID.self, forKey: .id)
        name = try container.decodeIfPresent(String.self, forKey: .name) ?? ""
        hostPatterns = try container.decodeIfPresent(String.self, forKey: .hostPatterns) ?? ""
        authMode = (try? container.decodeIfPresent(AuthMode.self, forKey: .authMode)) ?? .browser
        serviceTokenID = try container.decodeIfPresent(String.self, forKey: .serviceTokenID) ?? ""
        serviceTokenSecret = try container.decodeIfPresent(String.self, forKey: .serviceTokenSecret) ?? ""
        bastionHostname = try container.decodeIfPresent(String.self, forKey: .bastionHostname) ?? ""
        isEnabled = try container.decodeIfPresent(Bool.self, forKey: .isEnabled) ?? true
    }

    var patterns: [String] {
        hostPatterns
            .split(whereSeparator: { $0 == "," || $0.isWhitespace })
            .map { String($0).lowercased() }
    }

    var displayName: String {
        let trimmed = name.trimmingCharacters(in: .whitespaces)
        if !trimmed.isEmpty { return trimmed }
        return patterns.first ?? String(localized: "Cloudflare Tunnel", comment: "Default name of a Cloudflare tunnel route")
    }

    var trimmedBastionHostname: String? {
        let trimmed = Self.normalize(bastionHostname)
        return trimmed.isEmpty ? nil : trimmed
    }

    /// OpenSSH `match_pattern_list` semantics: a negated pattern always
    /// excludes; otherwise any positive match wins.
    func matches(host: String) -> Bool {
        let name = Self.normalize(host)
        guard !name.isEmpty else { return false }
        var positive = false
        for raw in patterns {
            var pattern = raw
            let negated = pattern.hasPrefix("!")
            if negated { pattern.removeFirst() }
            guard !pattern.isEmpty else { continue }
            if SSHHostPatternMatcher.matchGlob(name, pattern: pattern) {
                if negated { return false }
                positive = true
            }
        }
        return positive
    }

    /// Where the WebSocket goes and what it asks the tunnel to reach.
    struct Endpoint: Equatable, Sendable {
        /// The tunnel hostname; Access tokens are kept per this name.
        var hostname: String
        var url: URL
        /// `Cf-Access-Jump-Destination`, bastion mode only.
        var jumpDestination: String?
    }

    func endpoint(host: String, port: Int) -> Endpoint? {
        let target = Self.normalize(host)
        let hostname = trimmedBastionHostname ?? target
        guard !hostname.isEmpty, let url = URL(string: "wss://\(hostname)"), url.host != nil else { return nil }
        var destination: String?
        if trimmedBastionHostname != nil {
            destination = target.contains(":") ? "[\(target)]:\(port)" : "\(target):\(port)"
        }
        return Endpoint(hostname: hostname, url: url, jumpDestination: destination)
    }

    /// Why the route can't be saved yet, or nil when complete.
    var validationError: String? {
        if patterns.allSatisfy({ $0.hasPrefix("!") }) {
            return String(localized: "Enter at least one host name.", comment: "Cloudflare tunnel validation")
        }
        if let bastion = trimmedBastionHostname, URL(string: "wss://\(bastion)")?.host == nil {
            return String(localized: "The bastion host name isn't valid.", comment: "Cloudflare tunnel validation")
        }
        if authMode == .serviceToken,
           serviceTokenID.trimmingCharacters(in: .whitespaces).isEmpty || serviceTokenSecret.isEmpty {
            return String(localized: "Enter the service token's Client ID and Client Secret.", comment: "Cloudflare tunnel validation")
        }
        return nil
    }

    /// Lowercased, without IPv6 brackets, a scheme, a path or a trailing dot.
    static func normalize(_ host: String) -> String {
        var value = host.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        if let scheme = value.range(of: "://") { value = String(value[scheme.upperBound...]) }
        if let slash = value.firstIndex(of: "/") { value = String(value[..<slash]) }
        return value.trimmingCharacters(in: CharacterSet(charactersIn: "[]."))
    }

    /// The first enabled tunnel whose patterns match host.
    static func route(for host: String, in tunnels: [CloudflareTunnel]) -> CloudflareTunnel? {
        tunnels.first { $0.isEnabled && $0.matches(host: host) }
    }
}

// MARK: - Access tokens

/// Reads the expiry out of a Cloudflare Access JWT (`CF_Authorization`).
nonisolated enum CloudflareAccessJWT {
    static func expiry(of token: String) -> Date? {
        let parts = token.split(separator: ".")
        guard parts.count == 3 else { return nil }
        var payload = parts[1].replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        while payload.count % 4 != 0 { payload += "=" }
        guard let data = Data(base64Encoded: payload),
              let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let exp = object["exp"] as? NSNumber else { return nil }
        return Date(timeIntervalSince1970: exp.doubleValue)
    }

    /// Usable for at least another minute.
    static func isUsable(_ token: String, now: Date = Date()) -> Bool {
        guard let expiry = expiry(of: token) else { return false }
        return expiry.timeIntervalSince(now) > 60
    }
}

// MARK: - ssh_config

/// `ProxyCommand cloudflared access ssh --hostname %h [...]`, as written by
/// Cloudflare's docs, reduced to a tunnel route.
nonisolated struct CloudflaredProxyCommand: Equatable, Sendable {
    /// The `--hostname` value with `%h` resolved, or nil when it was `%h` itself.
    var hostname: String?
    var serviceTokenID: String?
    var serviceTokenSecret: String?
    /// `--destination`, which makes `hostname` a bastion.
    var destination: String?

    /// Parses the command with `%h` expanded to `host`. Returns nil for any
    /// other ProxyCommand.
    static func parse(_ command: String, host: String) -> CloudflaredProxyCommand? {
        let words = shellWords(command)
        guard let binary = words.first, (binary as NSString).lastPathComponent.hasPrefix("cloudflared") else { return nil }
        var index = 1
        // Global flags (`--loglevel debug`) may precede the subcommand.
        while index < words.count, words[index].hasPrefix("-") { index += words[index].contains("=") ? 1 : 2 }
        guard index + 1 < words.count, words[index] == "access",
              ["ssh", "tcp", "rdp", "smb"].contains(words[index + 1]) else { return nil }

        var result = CloudflaredProxyCommand()
        var hostnameValue: String?
        var rest = Array(words[(index + 2)...])
        while !rest.isEmpty {
            let word = rest.removeFirst()
            guard word.hasPrefix("-") else { continue }
            let body = word.drop(while: { $0 == "-" })
            let flag: String
            var value: String?
            if let eq = body.firstIndex(of: "=") {
                flag = body[..<eq].lowercased()
                value = String(body[body.index(after: eq)...])
            } else {
                flag = body.lowercased()
            }
            if value == nil, !rest.isEmpty, !rest[0].hasPrefix("-") {
                value = rest.removeFirst()
            }
            let expanded = value.map { expand($0, host: host) }
            switch flag {
            case "hostname", "tunnel-host", "t": hostnameValue = expanded
            case "service-token-id", "id": result.serviceTokenID = expanded
            case "service-token-secret", "secret": result.serviceTokenSecret = expanded
            case "destination": result.destination = expanded
            default: break
            }
        }
        guard let hostnameValue else { return nil }
        let normalized = CloudflareTunnel.normalize(hostnameValue)
        guard !normalized.isEmpty else { return nil }
        if result.destination == nil, normalized == CloudflareTunnel.normalize(host) {
            result.hostname = nil
        } else {
            result.hostname = normalized
        }
        return result
    }

    /// The route an imported Host block needs, matching only `host`.
    func tunnel(for host: String) -> CloudflareTunnel {
        var tunnel = CloudflareTunnel()
        tunnel.hostPatterns = CloudflareTunnel.normalize(host)
        if destination != nil, let hostname { tunnel.bastionHostname = hostname }
        if let id = serviceTokenID, let secret = serviceTokenSecret, !id.isEmpty, !secret.isEmpty {
            tunnel.authMode = .serviceToken
            tunnel.serviceTokenID = id
            tunnel.serviceTokenSecret = secret
        }
        return tunnel
    }

    private static func expand(_ value: String, host: String) -> String {
        value.replacingOccurrences(of: "%h", with: host).replacingOccurrences(of: "%%", with: "%")
    }

    /// Splits on whitespace, honoring single and double quotes and backslashes.
    static func shellWords(_ command: String) -> [String] {
        var words: [String] = []
        var current = ""
        var inWord = false
        var quote: Character?
        var escaped = false
        for char in command {
            if escaped {
                current.append(char)
                escaped = false
                continue
            }
            if char == "\\", quote != "'" {
                escaped = true
                inWord = true
                continue
            }
            if let open = quote {
                if char == open { quote = nil } else { current.append(char) }
                continue
            }
            if char == "\"" || char == "'" {
                quote = char
                inWord = true
            } else if char.isWhitespace {
                if inWord { words.append(current) }
                current = ""
                inWord = false
            } else {
                current.append(char)
                inWord = true
            }
        }
        if inWord { words.append(current) }
        return words
    }
}
