//
//  OpenSSHImportPlan.swift
//  rootshell
//
//  Builds an importable plan from a parsed ssh_config + the directory it
//  lives in. Resolves IdentityFile references against existing keychain
//  entries, lifts new key files into pending-import rows, and applies the
//  plan in one shot once the user confirms.
//

import Foundation
import os.log

// MARK: - Plan data

/// One profile to be created from a concrete Host entry.
struct OpenSSHProfilePlan: Identifiable, Hashable {
    let id = UUID()

    /// All aliases declared on the `Host` line; the first is the profile name.
    var aliases: [String]
    /// Final resolved hostname (after applying HostName / wildcards).
    var hostName: String
    var port: Int
    var user: String
    /// Stable keys for the linked `OpenSSHKeyPlan` rows (in declaration order).
    var identityKeyPlanIDs: [UUID]
    /// Parsed jump hops in connection order, from ProxyJump / ProxyCommand.
    /// The final SSHKey UUIDs are resolved at apply time so they reference
    /// real keychain entries, not preview-side plan UUIDs.
    var jumpHostSources: [JumpHostSource]
    /// Route saved on apply when the ProxyCommand is `cloudflared access ssh`.
    var cloudflareTunnel: CloudflareTunnel?
    /// Source diagnostic ("config:42") for tooltip / debug.
    var source: String

    /// Profile name (first alias).
    var name: String { aliases.first ?? hostName }

    /// Display string for the jump chain extracted from ProxyJump / ProxyCommand.
    var jumpHostDisplay: String? {
        var hops = jumpHostSources.map(\.display)
        if let cloudflareTunnel {
            let tunnel = cloudflareTunnel.trimmedBastionHostname.map { "Cloudflare Tunnel (\($0))" } ?? "Cloudflare Tunnel"
            hops.insert(tunnel, at: 0)
        }
        return hops.isEmpty ? nil : hops.joined(separator: " → ")
    }

    /// Raw jump host data captured during parse. Apply uses the
    /// `identityKeyPlanIDs` field to look up the eventual `SSHKey.id`.
    struct JumpHostSource: Hashable {
        var host: String
        var port: Int
        var username: String
        /// Plan IDs of the hop's own identity files, or the target's when it declares none.
        var identityKeyPlanIDs: [UUID]
        /// Pre-built display string for the preview UI.
        var display: String
    }
}

/// One private-key file referenced by `IdentityFile`.
struct OpenSSHKeyPlan: Identifiable, Hashable {
    let id = UUID()

    /// Filename only, e.g. `id_ed25519`.
    var filename: String
    /// Absolute path inside the .ssh directory.
    var path: String
    /// Suggested profile-friendly key name (filename without extension).
    var suggestedName: String

    enum Status: Hashable {
        /// File was found and parsed; fingerprint computed.
        case readyForImport(fingerprint: String, encrypted: Bool)
        /// File matched an existing key in the SSHKeyManager keychain.
        case alreadyImported(existingKeyID: UUID, existingKeyName: String, fingerprint: String)
        /// File could not be read (missing, unreadable, etc.).
        case fileMissing
        /// Parser rejected the file (corrupt / unsupported format).
        case parseFailed(message: String)
    }

    var status: Status

    /// User-editable: whether to actually import this key on Apply.
    var includeOnImport: Bool
    /// User-editable: passphrase to use on Apply (for encrypted keys).
    var passphrase: String

    /// File contents captured during preview so apply works even after the
    /// security-scoped folder URL has been released (sandboxed Mac Catalyst).
    var cachedKeyContents: String?

    /// True when the parsed file's cipher is non-`none`.
    var isEncrypted: Bool {
        if case .readyForImport(_, let enc) = status { return enc }
        return false
    }

    /// Fingerprint, if known.
    var fingerprint: String? {
        switch status {
        case .readyForImport(let fp, _): return fp
        case .alreadyImported(_, _, let fp): return fp
        case .fileMissing, .parseFailed: return nil
        }
    }
}

/// A host entry that was deliberately not imported.
struct OpenSSHSkippedEntry: Identifiable, Hashable {
    let id = UUID()
    var label: String
    var reason: String
}

/// Everything the preview sheet needs to render.
struct OpenSSHImportPlan: Identifiable {
    let id = UUID()

    /// Directory the import came from (Documents/.ssh or ~/.ssh).
    var sshDirectory: URL
    /// Concrete profiles to be created.
    var profiles: [OpenSSHProfilePlan]
    /// All distinct key files referenced; rows the user can toggle.
    var keys: [OpenSSHKeyPlan]
    /// Hosts deliberately skipped (wildcards, conflicts).
    var skipped: [OpenSSHSkippedEntry]
    /// Free-form parse warnings to surface in a Notes section.
    var warnings: [String]

    /// True when there is anything actionable to apply.
    var hasAnythingToApply: Bool {
        !profiles.isEmpty
    }
}

/// Summary of what an Apply actually did.
struct OpenSSHImportSummary: Identifiable {
    let id = UUID()
    var profilesCreated: Int
    var keysImported: Int
    var keysSkippedAlreadyPresent: Int
    var keysFailedToImport: [(filename: String, reason: String)]
    var profilesFailedToCreate: [(name: String, reason: String)]
    var folderPath: String
    var skippedCount: Int
    var warnings: [String]
}

// MARK: - Importer

/// Builds preview plans and applies them. Pure facade over `SSHKeyManager`
/// and `ConnectionProfileManager`.
@MainActor
enum OpenSSHImporter {
    private nonisolated static let logger = Logger(subsystem: "com.rootshell", category: "OpenSSHImporter")

    enum PreviewError: LocalizedError {
        case configMissing(URL)
        case parserError(String)

        var errorDescription: String? {
            switch self {
            case .configMissing(let url):
                return "No ssh config found at \(url.path). Add a 'config' file to this folder and try again."
            case .parserError(let msg):
                return msg
            }
        }
    }

    /// Build a preview plan from a `.ssh` directory.
    static func preview(sshDirectory: URL) throws -> OpenSSHImportPlan {
        let configURL = sshDirectory.appendingPathComponent("config")
        guard FileManager.default.fileExists(atPath: configURL.path) else {
            throw PreviewError.configMissing(configURL)
        }

        let parseResult: OpenSSHConfigParseResult
        do {
            parseResult = try OpenSSHConfigParser.parse(fileURL: configURL, sshDirectory: sshDirectory)
        } catch {
            throw PreviewError.parserError(error.localizedDescription)
        }

        // Split wildcard from concrete entries; concrete entries are the
        // profiles we actually create.
        let wildcards = parseResult.entries.filter { $0.isWildcard }
        let concretes = parseResult.entries.filter { !$0.isWildcard }

        // Build the key registry first by collecting every distinct IdentityFile
        // path across all concrete entries (after wildcard inheritance).
        var resolvedConcretes: [(entry: OpenSSHHostEntry, identityPaths: [String], jump: OpenSSHHostResolution.JumpChainResolution, cloudflareTunnel: CloudflareTunnel?)] = []
        for entry in concretes {
            var resolved = OpenSSHHostResolution.resolve(entry: entry, entries: parseResult.entries)
            // `ProxyCommand cloudflared access ssh --hostname %h` becomes a
            // Cloudflare Tunnel route rather than a jump host.
            let targetHost = resolved.hostName ?? resolved.aliases.first ?? ""
            var cloudflareTunnel: CloudflareTunnel?
            if let command = resolved.proxyCommand,
               let cloudflared = CloudflaredProxyCommand.parse(command, host: targetHost) {
                cloudflareTunnel = cloudflared.tunnel(for: targetHost)
                resolved.proxyCommand = nil
            }
            let paths = resolved.identityFiles.map { resolveIdentityPath($0, sshDirectory: sshDirectory) }
            let jump = OpenSSHHostResolution.resolveJumpChain(
                for: resolved, entries: parseResult.entries,
                defaultUsername: Self.defaultUsername,
                parseProxyCommand: { command in
                    ProxyCommandParser.parse(command).map { .init(host: $0.host, port: $0.port, username: $0.username) }
                },
                resolvePath: { resolveIdentityPath($0, sshDirectory: sshDirectory) }
            )
            resolvedConcretes.append((resolved, paths, jump, cloudflareTunnel))
        }

        var keyPlanByPath: [String: OpenSSHKeyPlan] = [:]
        for (_, paths, jump, _) in resolvedConcretes {
            let hopPaths = jump.hops.flatMap { $0.identityPaths ?? [] }
            for path in paths + hopPaths where keyPlanByPath[path] == nil {
                keyPlanByPath[path] = buildKeyPlan(path: path)
            }
        }
        // Stable order: by filename then path.
        let keys = keyPlanByPath.values.sorted { lhs, rhs in
            if lhs.filename != rhs.filename { return lhs.filename < rhs.filename }
            return lhs.path < rhs.path
        }
        var keyIDByPath: [String: UUID] = [:]
        for key in keys { keyIDByPath[key.path] = key.id }

        // Build profiles, detecting conflicts against existing ConnectionProfileManager rows.
        let existing = ConnectionProfileManager.shared.profiles
        var profiles: [OpenSSHProfilePlan] = []
        var skipped: [OpenSSHSkippedEntry] = []
        var warnings = parseResult.warnings

        for (entry, identityPaths, jump, cloudflareTunnel) in resolvedConcretes {
            let hostName = entry.hostName ?? entry.aliases.first ?? ""
            let port = entry.port ?? 22
            let user = entry.user ?? Self.defaultUsername

            // Conflict detection: existing profile with same host+user+port.
            let conflict = existing.first { candidate in
                let candidateHost = candidate.sshConfig.host
                let hostMatches = candidateHost.caseInsensitiveCompare(hostName) == .orderedSame
                let portMatches = candidate.sshConfig.port == port
                let userMatches = candidate.sshConfig.username == user
                return hostMatches && portMatches && userMatches
            }
            if let conflict {
                skipped.append(OpenSSHSkippedEntry(
                    label: entry.aliases.first ?? hostName,
                    reason: "Already exists as '\(conflict.name)' (\(user)@\(hostName):\(port))"
                ))
                continue
            }

            let identityKeyPlanIDs = identityPaths.compactMap { keyIDByPath[$0] }
            if let jumpWarning = jump.warning { warnings.append(jumpWarning) }
            let jumpSources = jump.hops.map { hop in
                OpenSSHProfilePlan.JumpHostSource(
                    host: hop.host,
                    port: hop.port,
                    username: hop.username,
                    identityKeyPlanIDs: hop.identityPaths.map { $0.compactMap { keyIDByPath[$0] } } ?? identityKeyPlanIDs,
                    display: hop.display
                )
            }

            let profile = OpenSSHProfilePlan(
                aliases: entry.aliases,
                hostName: hostName,
                port: port,
                user: user,
                identityKeyPlanIDs: identityKeyPlanIDs,
                jumpHostSources: jumpSources,
                cloudflareTunnel: cloudflareTunnel,
                source: "\(entry.sourceFile.lastPathComponent):\(entry.sourceLine)"
            )
            profiles.append(profile)
        }

        for wildcard in wildcards {
            let label = wildcard.aliases.joined(separator: ", ")
            skipped.append(OpenSSHSkippedEntry(
                label: label,
                reason: "Wildcard pattern, not a concrete host"
            ))
        }

        return OpenSSHImportPlan(
            sshDirectory: sshDirectory,
            profiles: profiles,
            keys: keys,
            skipped: skipped,
            warnings: warnings
        )
    }

    /// Apply a preview plan: import any opted-in new keys, then create profiles.
    static func apply(plan: OpenSSHImportPlan, folderPath: String) -> OpenSSHImportSummary {
        var keysImported = 0
        var keysSkippedAlreadyPresent = 0
        var keysFailedToImport: [(String, String)] = []
        var profilesFailedToCreate: [(String, String)] = []

        // Pass 1: import keys. We track UUIDs for both the success map (used to
        // build profile auth) and the unrecoverable set (keys that the user
        // *can't* use even after the import attempt: parseFailed, fileMissing,
        // or opted-in-but-import-threw). The unrecoverable set lets pass 2
        // distinguish "user toggled this off" (intentional) from "we tried
        // and it didn't work" (need to skip the dependent profile).
        var resolvedKeyIDs: [UUID: UUID] = [:]  // plan.id -> SSHKey.id
        var unrecoverableKeyPlanIDs: Set<UUID> = []
        var firstFailureReasonByPlanID: [UUID: String] = [:]

        for keyPlan in plan.keys {
            switch keyPlan.status {
            case .alreadyImported(let existingID, _, _):
                resolvedKeyIDs[keyPlan.id] = existingID
                keysSkippedAlreadyPresent += 1

            case .readyForImport(_, let encrypted):
                guard keyPlan.includeOnImport else { continue }
                let passphrase = encrypted ? keyPlan.passphrase : nil
                do {
                    let keyString: String
                    if let cached = keyPlan.cachedKeyContents {
                        keyString = cached
                    } else {
                        keyString = try String(contentsOfFile: keyPlan.path, encoding: .utf8)
                    }

                    // For encrypted keys we couldn't compute the fingerprint at
                    // preview time, so we re-parse here to look for an existing
                    // match before attempting an import that would fail with
                    // ImportError.duplicateKey.
                    if encrypted {
                        if let parsed = try? SSHKeyParser.parse(keyString: keyString, passphrase: passphrase),
                           let existing = SSHKeyManager.shared.findKey(byFingerprint: parsed.fingerprint) {
                            resolvedKeyIDs[keyPlan.id] = existing.id
                            keysSkippedAlreadyPresent += 1
                            continue
                        }
                    }

                    let imported = try SSHKeyManager.shared.importKey(
                        name: keyPlan.suggestedName,
                        keyString: keyString,
                        passphrase: passphrase,
                        storageLevel: .backupOnly,
                        authRequirement: .none
                    )
                    resolvedKeyIDs[keyPlan.id] = imported.id
                    keysImported += 1
                } catch {
                    let reason = error.localizedDescription
                    let name = keyPlan.filename
                    keysFailedToImport.append((name, reason))
                    unrecoverableKeyPlanIDs.insert(keyPlan.id)
                    firstFailureReasonByPlanID[keyPlan.id] = "\(name): \(reason)"
                    logger.error("Key import failed for \(name): \(reason)")
                }

            case .fileMissing:
                unrecoverableKeyPlanIDs.insert(keyPlan.id)
                firstFailureReasonByPlanID[keyPlan.id] = "\(keyPlan.filename): file missing"

            case .parseFailed(let msg):
                unrecoverableKeyPlanIDs.insert(keyPlan.id)
                firstFailureReasonByPlanID[keyPlan.id] = "\(keyPlan.filename): \(msg)"
            }
        }

        // Pass 2: create profiles.
        var profilesCreated = 0
        var passwordFallbackWarnings: [String] = []
        for profilePlan in plan.profiles {
            let requestedKeyCount = profilePlan.identityKeyPlanIDs.count
            let resolvedIDs = profilePlan.identityKeyPlanIDs.compactMap { resolvedKeyIDs[$0] }
            let unrecoverableUsed = profilePlan.identityKeyPlanIDs.filter { unrecoverableKeyPlanIDs.contains($0) }

            // If the profile declared IdentityFile keys, none of them resolved,
            // AND at least one of the declared keys was unrecoverable (vs.
            // simply being toggled off by the user), skip the profile. Saving
            // it as password auth would look "imported" but never actually
            // authenticate the way ssh_config promised it would.
            if requestedKeyCount > 0 && resolvedIDs.isEmpty && !unrecoverableUsed.isEmpty {
                let reasons = unrecoverableUsed.compactMap { firstFailureReasonByPlanID[$0] }
                let joined = reasons.joined(separator: "; ")
                profilesFailedToCreate.append((
                    profilePlan.name,
                    "Skipped because its IdentityFile keys could not be used: \(joined)"
                ))
                let nameForLog = profilePlan.name
                logger.error("Profile skipped (broken IdentityFile chain): \(nameForLog)")
                continue
            }

            let primaryAuth: SSHConfig.AuthMethod
            let fallbackKeys: [UUID]?
            if let first = resolvedIDs.first {
                primaryAuth = .key(first)
                fallbackKeys = resolvedIDs.count > 1 ? Array(resolvedIDs.dropFirst()) : nil
            } else {
                primaryAuth = .password("")
                fallbackKeys = nil
                if requestedKeyCount > 0 {
                    // All declared keys were toggled off by the user (none
                    // unrecoverable). Honor their choice but flag the auth
                    // mismatch so they aren't surprised the profile lands as
                    // password auth.
                    passwordFallbackWarnings.append(
                        "Profile '\(profilePlan.name)' saved with password auth: IdentityFile keys were not imported."
                    )
                }
            }

            // Each hop gets the target's rule: unusable keys skip the profile,
            // deselected keys fall back to password with a warning.
            var brokenHop: String?
            for (index, source) in profilePlan.jumpHostSources.enumerated() where !source.identityKeyPlanIDs.isEmpty {
                guard !source.identityKeyPlanIDs.contains(where: { resolvedKeyIDs[$0] != nil }) else { continue }
                let unrecoverable = source.identityKeyPlanIDs.filter { unrecoverableKeyPlanIDs.contains($0) }
                if unrecoverable.isEmpty {
                    passwordFallbackWarnings.append(
                        "Profile '\(profilePlan.name)' jump host \(index + 1) (\(source.display)) saved with password auth: IdentityFile keys were not imported."
                    )
                } else {
                    let reasons = unrecoverable.compactMap { firstFailureReasonByPlanID[$0] }.joined(separator: "; ")
                    brokenHop = "Skipped because jump host \(index + 1) (\(source.display)) IdentityFile keys could not be used: \(reasons)"
                    break
                }
            }
            if let brokenHop {
                profilesFailedToCreate.append((profilePlan.name, brokenHop))
                let nameForLog = profilePlan.name
                logger.error("Profile skipped (broken jump host IdentityFile chain): \(nameForLog)")
                continue
            }

            // Build the jump host config NOW using the same resolved-key map so
            // jump hosts that share identity files with the target end up
            // pointing at real keychain UUIDs, not preview plan UUIDs.
            let jumpChain = profilePlan.jumpHostSources.map {
                makeJumpHostConfig(source: $0, resolvedKeyIDs: resolvedKeyIDs)
            }

            var configWithFallbacks = SSHConfig(
                host: profilePlan.hostName,
                port: profilePlan.port,
                username: profilePlan.user,
                authMethod: primaryAuth,
                cachedIP: nil
            )
            configWithFallbacks.jumpChain = jumpChain
            configWithFallbacks.fallbackKeyIDs = fallbackKeys

            do {
                _ = try ConnectionProfileManager.shared.createProfile(
                    name: profilePlan.name,
                    sshConfig: configWithFallbacks,
                    folderPath: folderPath,
                    tags: ["imported", "openssh"]
                )
                profilesCreated += 1
                if let tunnel = profilePlan.cloudflareTunnel {
                    CloudflareTunnelStore.shared.addIfUncovered(tunnel, host: profilePlan.hostName)
                }
            } catch {
                let reason = error.localizedDescription
                let name = profilePlan.name
                profilesFailedToCreate.append((name, reason))
                logger.error("Profile creation failed for \(name): \(reason)")
            }
        }

        return OpenSSHImportSummary(
            profilesCreated: profilesCreated,
            keysImported: keysImported,
            keysSkippedAlreadyPresent: keysSkippedAlreadyPresent,
            keysFailedToImport: keysFailedToImport,
            profilesFailedToCreate: profilesFailedToCreate,
            folderPath: folderPath,
            skippedCount: plan.skipped.count,
            warnings: plan.warnings + passwordFallbackWarnings
        )
    }

    /// Build a JumpHostConfig at apply time. Maps the plan's
    /// `identityKeyPlanIDs` into real `SSHKey.id`s using `resolvedKeyIDs`.
    private static func makeJumpHostConfig(
        source: OpenSSHProfilePlan.JumpHostSource,
        resolvedKeyIDs: [UUID: UUID]
    ) -> SSHConfig.JumpHostConfig {
        let resolved = source.identityKeyPlanIDs.compactMap { resolvedKeyIDs[$0] }
        let auth: SSHConfig.AuthMethod
        let fallback: [UUID]?
        if let primary = resolved.first {
            auth = .key(primary)
            fallback = resolved.count > 1 ? Array(resolved.dropFirst()) : nil
        } else {
            auth = .password("")
            fallback = nil
        }
        return SSHConfig.JumpHostConfig(
            host: source.host,
            port: source.port,
            username: source.username,
            authMethod: auth,
            fallbackKeyIDs: fallback
        )
    }

    // MARK: - Default username

    /// Best-effort default username when a Host block omits `User`. Falls back
    /// to `NSUserName()` on Mac Catalyst Standalone, and `"root"` elsewhere
    /// since iOS has no concept of a real Unix user.
    private static var defaultUsername: String {
        #if STANDALONE
        let name = NSUserName()
        return name.isEmpty ? "root" : name
        #else
        return "root"
        #endif
    }

    // MARK: - Identity path resolution

    private static func resolveIdentityPath(_ raw: String, sshDirectory: URL) -> String {
        if raw.hasPrefix("/") { return raw }
        if raw.hasPrefix("~") {
            let home = sshDirectory.deletingLastPathComponent().path
            if raw == "~" { return home }
            if raw.hasPrefix("~/") { return home + String(raw.dropFirst(1)) }
            return raw
        }
        return sshDirectory.appendingPathComponent(raw).path
    }

    // MARK: - Key plan construction

    private static func buildKeyPlan(path: String) -> OpenSSHKeyPlan {
        let filename = (path as NSString).lastPathComponent
        let suggestedName = (filename as NSString).deletingPathExtension

        guard FileManager.default.fileExists(atPath: path) else {
            return OpenSSHKeyPlan(
                filename: filename,
                path: path,
                suggestedName: suggestedName,
                status: .fileMissing,
                includeOnImport: false,
                passphrase: "",
                cachedKeyContents: nil
            )
        }

        let keyString: String
        do {
            keyString = try String(contentsOfFile: path, encoding: .utf8)
        } catch {
            return OpenSSHKeyPlan(
                filename: filename,
                path: path,
                suggestedName: suggestedName,
                status: .parseFailed(message: error.localizedDescription),
                includeOnImport: false,
                passphrase: "",
                cachedKeyContents: nil
            )
        }

        // Encrypted? Surface the row with the encrypted flag set; we can't
        // compute a real fingerprint until the user supplies the passphrase
        // at apply time. The parser will then dedupe against existing keys
        // via SSHKeyManager.importKey's own fingerprint check.
        let encrypted = SSHKeyParser.isEncrypted(keyString: keyString)
        if encrypted {
            return OpenSSHKeyPlan(
                filename: filename,
                path: path,
                suggestedName: suggestedName,
                status: .readyForImport(fingerprint: "", encrypted: true),
                includeOnImport: true,
                passphrase: "",
                cachedKeyContents: keyString
            )
        }

        do {
            let parsed = try SSHKeyParser.parse(keyString: keyString)
            let fingerprint = parsed.fingerprint
            if let existing = SSHKeyManager.shared.findKey(byFingerprint: fingerprint) {
                return OpenSSHKeyPlan(
                    filename: filename,
                    path: path,
                    suggestedName: suggestedName,
                    status: .alreadyImported(
                        existingKeyID: existing.id,
                        existingKeyName: existing.name,
                        fingerprint: fingerprint
                    ),
                    includeOnImport: false,
                    passphrase: "",
                    cachedKeyContents: nil
                )
            }
            return OpenSSHKeyPlan(
                filename: filename,
                path: path,
                suggestedName: suggestedName,
                status: .readyForImport(fingerprint: fingerprint, encrypted: false),
                includeOnImport: true,
                passphrase: "",
                cachedKeyContents: keyString
            )
        } catch {
            return OpenSSHKeyPlan(
                filename: filename,
                path: path,
                suggestedName: suggestedName,
                status: .parseFailed(message: error.localizedDescription),
                includeOnImport: false,
                passphrase: "",
                cachedKeyContents: nil
            )
        }
    }
}
