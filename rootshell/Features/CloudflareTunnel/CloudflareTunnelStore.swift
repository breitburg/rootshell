//
//  CloudflareTunnelStore.swift
//  rootshell
//
//  Saved Cloudflare Tunnel routes, read from the iCloud Keychain, and the
//  lock-protected snapshot the dial path reads from any thread. The keychain
//  posts no change notifications for synced items, so the list reloads
//  whenever the app becomes active.
//

import Foundation
import UIKit
import os
import os.log

/// What the dial path needs, readable from any thread. Seeded from the
/// keychain on first use so connections restored at launch route correctly.
nonisolated final class CloudflareTunnelRouting: Sendable {
    static let shared = CloudflareTunnelRouting()

    private let lock = OSAllocatedUnfairLock(initialState: CloudflareTunnelRouting.loadSaved())

    static func loadSaved() -> [CloudflareTunnel] {
        let decoder = JSONDecoder()
        let items = (try? KeychainManager.shared.loadAllCloudflareTunnels()) ?? []
        return items.compactMap { try? decoder.decode(CloudflareTunnel.self, from: $0) }
            .sorted { $0.displayName.localizedStandardCompare($1.displayName) == .orderedAscending }
    }

    var tunnels: [CloudflareTunnel] { lock.withLock { $0 } }

    func replace(_ tunnels: [CloudflareTunnel]) {
        lock.withLock { $0 = tunnels }
    }

    func route(for host: String) -> CloudflareTunnel? {
        CloudflareTunnel.route(for: host, in: tunnels)
    }
}

@MainActor
@Observable
final class CloudflareTunnelStore {
    static let shared = CloudflareTunnelStore()

    private static let logger = Logger(subsystem: "com.rootshell", category: "CloudflareTunnels")

    private(set) var tunnels: [CloudflareTunnel] = []

    @ObservationIgnored private var activationObserver: Task<Void, Never>?

    private init() {
        tunnels = CloudflareTunnelRouting.shared.tunnels
        activationObserver = Task { [weak self] in
            for await _ in NotificationCenter.default.notifications(named: UIApplication.didBecomeActiveNotification) {
                self?.reload()
            }
        }
    }

    func reload() {
        let loaded = CloudflareTunnelRouting.loadSaved()
        CloudflareTunnelRouting.shared.replace(loaded)
        if loaded != tunnels { tunnels = loaded }
    }

    func save(_ tunnel: CloudflareTunnel) throws {
        let data = try JSONEncoder().encode(tunnel)
        try KeychainManager.shared.saveCloudflareTunnel(data, identifier: tunnel.id.uuidString, label: "rootshell: \(tunnel.displayName)")
        reload()
    }

    func delete(_ id: UUID) throws {
        try KeychainManager.shared.deleteCloudflareTunnel(identifier: id.uuidString)
        if let removed = tunnels.first(where: { $0.id == id }) {
            for hostname in removed.signInHostnames { CloudflareAccessTokens.remove(hostname: hostname) }
        }
        reload()
    }

    /// Saves a route for an imported ssh_config host unless one already covers it.
    @discardableResult
    func addIfUncovered(_ tunnel: CloudflareTunnel, host: String) -> Bool {
        guard CloudflareTunnel.route(for: host, in: tunnels) == nil else { return false }
        do {
            try save(tunnel)
            return true
        } catch {
            Self.logger.error("Saving imported Cloudflare tunnel failed: \(error.localizedDescription, privacy: .public)")
            return false
        }
    }
}

extension CloudflareTunnel {
    /// Tunnel hostnames a browser sign-in is kept for: the bastion, or each
    /// pattern that names one host.
    nonisolated var signInHostnames: [String] {
        if let bastion = trimmedBastionHostname { return [bastion] }
        return patterns.filter { !$0.hasPrefix("!") && !$0.contains("*") && !$0.contains("?") }
    }
}

/// Access app tokens from browser sign-in, kept per tunnel hostname.
nonisolated enum CloudflareAccessTokens {
    static func usableToken(hostname: String) -> String? {
        guard let token = KeychainManager.shared.loadCloudflareAccessToken(hostname: hostname) else { return nil }
        guard CloudflareAccessJWT.isUsable(token) else {
            remove(hostname: hostname)
            return nil
        }
        return token
    }

    static func store(_ token: String, hostname: String) {
        try? KeychainManager.shared.saveCloudflareAccessToken(token, hostname: hostname)
    }

    static func remove(hostname: String) {
        KeychainManager.shared.deleteCloudflareAccessToken(hostname: hostname)
    }

    static func expiry(hostname: String) -> Date? {
        KeychainManager.shared.loadCloudflareAccessToken(hostname: hostname).flatMap(CloudflareAccessJWT.expiry(of:))
    }
}
