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
    var id = UUID()
    var name = ""
    /// Comma- or space-separated OpenSSH-style globs, e.g. `ssh.example.com`
    /// or `*.example.com, !www.example.com`.
    var hostPatterns = ""
    /// Bastion mode: connect to this tunnel hostname and ask it to forward to
    /// the dialed `host:port` (`cloudflared access ssh --destination`). Empty
    /// connects to the dialed host itself.
    var bastionHostname = ""
    var isEnabled = true

    init() {}

    init(from decoder: Decoder) throws {
        // Tolerant decoding: a field added later is missing from older items.
        let container = try decoder.container(keyedBy: CodingKeys.self)
        id = try container.decode(UUID.self, forKey: .id)
        name = try container.decodeIfPresent(String.self, forKey: .name) ?? ""
        hostPatterns = try container.decodeIfPresent(String.self, forKey: .hostPatterns) ?? ""
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

    func matches(host: String) -> Bool {
        let name = Self.normalize(host)
        return !name.isEmpty && SSHHostPatternMatcher.matches(host: name, patterns: patterns)
    }

    /// Where the WebSocket goes and what it asks the tunnel to reach.
    struct Endpoint: Equatable, Sendable {
        var hostname: String
        var url: URL
        /// `Cf-Access-Jump-Destination`, bastion mode only.
        var jumpDestination: String?
    }

    func endpoint(host: String, port: Int) -> Endpoint? {
        let target = Self.normalize(host)
        var hostname = target
        var destination: String?
        if let bastion = trimmedBastionHostname {
            hostname = bastion
            destination = target.contains(":") ? "[\(target)]:\(port)" : "\(target):\(port)"
        }
        guard let url = Self.webSocketURL(hostname) else { return nil }
        return Endpoint(hostname: hostname, url: url, jumpDestination: destination)
    }

    /// Why the route can't be saved yet, or nil when complete.
    var validationError: String? {
        if patterns.allSatisfy({ $0.hasPrefix("!") }) {
            return String(localized: "Enter at least one host name.", comment: "Cloudflare tunnel validation")
        }
        if let bastion = trimmedBastionHostname, Self.webSocketURL(bastion) == nil {
            return String(localized: "The bastion host name isn't valid.", comment: "Cloudflare tunnel validation")
        }
        return nil
    }

    private static func webSocketURL(_ hostname: String) -> URL? {
        guard !hostname.isEmpty, let url = URL(string: "wss://\(hostname)"), url.host != nil else { return nil }
        return url
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

// MARK: - ssh_config

/// `ProxyCommand cloudflared access ssh --hostname %h [...]`, as written by
/// Cloudflare's docs, reduced to a tunnel route.
nonisolated struct CloudflaredProxyCommand: Equatable, Sendable {
    /// The `--hostname` value with `%h` resolved, or nil when it was `%h` itself.
    var hostname: String?
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
