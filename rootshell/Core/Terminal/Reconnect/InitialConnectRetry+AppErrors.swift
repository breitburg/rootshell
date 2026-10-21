//
//  InitialConnectRetry+AppErrors.swift
//  rootshell
//
//  Main-app-only extension layering app error types (SSHError, SSHJumpError,
//  TrzszError) onto the shared `isPermanentConnectError` base. Lives in the
//  main app target only — the VPN extension uses the shared base classifier
//  directly because it doesn't see these types.
//

import Foundation

extension InitialConnectRetry {

    /// App-side classifier: shared base + app-only error types.
    /// Use as `isPermanent: InitialConnectRetry.isPermanentConnectErrorApp`.
    static func isPermanentConnectErrorApp(_ error: Error) -> Bool {
        if isPermanentConnectError(error) { return true }

        // App-side host-key-rejection error (separate from Citadel's InvalidHostKey)
        if error is HostKeyRejectedError { return true }

        // Legacy-encrypted key with no local passphrase — retry can't help;
        // the user must unlock the key once in Settings → SSH Keys.
        if case SSHKeyManager.LoadError.legacyKeyNeedsUnlock = error { return true }

        if let ssh = error as? SSHError, ssh.isAuthenticationRelated { return true }

        if let jump = error as? SSHJumpError {
            switch jump {
            case .authenticationFailed, .hostKeyRejected:
                return true
            default:
                return false
            }
        }

        // "Saved password not found" surfaces from buildAuthMethod before any
        // TCP connection is attempted — retry won't help.
        if let trzsz = error as? TrzszError,
           case .sshConnectionFailed(let reason) = trzsz,
           reason.localizedCaseInsensitiveContains("password not found") {
            return true
        }

        // The user cancelled (or failed) the inline opkssh browser sign-in that
        // ensureFreshCertificate runs during auth-building. Retrying would just
        // re-open the browser, so treat it as permanent.
        if case OpenPubkeyError.reauthenticationRequired = error { return true }

        if isPermanentCloudflareError(error) { return true }

        return false
    }

    /// Cloudflare Tunnel failures a retry can't fix: a cancelled Access sign-in,
    /// a policy that denies the user or token, or a route needing credentials.
    /// A missing window stays retryable so a reconnect started in the
    /// background signs in once the app is in front.
    static func isPermanentCloudflareError(_ error: Error) -> Bool {
        if case CloudflareAccessSignInError.cancelled = error { return true }
        guard let tunnel = error as? CloudflareTunnelError else { return false }
        switch tunnel {
        case .signInRequired, .accessDenied, .invalidHostname:
            return true
        case .handshakeFailed, .timedOut:
            return false
        }
    }
}
