//
//  CloudflareTunnelDialer.swift
//  rootshell
//
//  The client half of `cloudflared access ssh`, in-app: a WebSocket to
//  wss://<tunnel hostname> carries the raw TCP stream as binary messages, and
//  the tunnel's ingress rule connects it to the SSH server. MPTCPBootstrap
//  asks here first, so SSH, Mosh/tssh bootstrap, Git, SFTP and jump hosts
//  all reach hosts behind a Cloudflare Tunnel without cloudflared installed.
//

import Foundation
import NIOCore
import os

nonisolated enum CloudflareTunnelError: LocalizedError {
    case invalidHostname(String)
    case signInRequired(String)
    case accessDenied(String, status: Int, usedServiceToken: Bool)
    case handshakeFailed(String, status: Int)
    case timedOut(String)

    var errorDescription: String? {
        switch self {
        case .invalidHostname(let host):
            String(localized: "“\(host)” can't be reached over a Cloudflare Tunnel because it isn't a valid host name.",
                   comment: "Cloudflare tunnel connection error; argument is a host name")
        case .signInRequired(let hostname):
            String(localized: "\(hostname) is protected by Cloudflare Access. Set its route to sign in with a browser or a service token in Settings › Connections › Cloudflare Tunnels.",
                   comment: "Cloudflare tunnel connection error; argument is a host name")
        case .accessDenied(let hostname, let status, let usedServiceToken):
            usedServiceToken
                ? String(localized: "Cloudflare Access rejected the service token for \(hostname) (HTTP \(status)). Check the Client ID, the Client Secret and that the application's policy includes the token.",
                         comment: "Cloudflare tunnel connection error; arguments are a host name and an HTTP status code")
                : String(localized: "Cloudflare Access denied the connection to \(hostname) (HTTP \(status)). Your account may not be allowed by the application's policy.",
                         comment: "Cloudflare tunnel connection error; arguments are a host name and an HTTP status code")
        case .handshakeFailed(let hostname, let status):
            String(localized: "\(hostname) answered HTTP \(status) instead of opening a tunnel. Check that a Cloudflare Tunnel ingress rule serves this host name with an ssh:// or tcp:// service.",
                   comment: "Cloudflare tunnel connection error; arguments are a host name and an HTTP status code")
        case .timedOut(let hostname):
            String(localized: "Timed out opening the Cloudflare Tunnel to \(hostname).", comment: "Cloudflare tunnel connection error; argument is a host name")
        }
    }
}

nonisolated enum CloudflareTunnelDialer {
    private static let logger = Logger(subsystem: "com.rootshell", category: "CloudflareTunnel")

    /// A connected Channel through the tunnel when a saved route matches host,
    /// else nil. autoRead stays off, like MPTCPBootstrap, until Citadel installs
    /// its handlers. `port` only matters in bastion mode; otherwise the
    /// tunnel's ingress rule picks the origin port.
    static func channel(host: String, port: Int, timeout: TimeAmount) async throws -> Channel? {
        guard let tunnel = CloudflareTunnelRouting.shared.route(for: host) else { return nil }
        let pipe = try await open(tunnel: tunnel, host: host, port: port, timeout: timeout)
        do {
            return try await BytePipeChannelBridge.makeChannel(for: pipe, autoRead: false)
        } catch {
            await pipe.close()
            throw error
        }
    }

    /// Opens the WebSocket, signing in to Access first when the route uses a
    /// browser sign-in and no usable token is stored.
    static func open(tunnel: CloudflareTunnel, host: String, port: Int, timeout: TimeAmount) async throws -> CloudflareWebSocketPipe {
        guard let endpoint = tunnel.endpoint(host: host, port: port) else {
            throw CloudflareTunnelError.invalidHostname(host)
        }
        let seconds = max(1, Double(timeout.nanoseconds) / 1_000_000_000)
        logger.info("Opening Cloudflare Tunnel to \(endpoint.hostname, privacy: .public) for \(host, privacy: .public)")

        guard tunnel.authMode == .browser else {
            return try await CloudflareWebSocketPipe.connect(request(for: endpoint, tunnel: tunnel, accessToken: nil), hostname: endpoint.hostname, timeout: seconds)
        }
        if let token = CloudflareAccessTokens.usableToken(hostname: endpoint.hostname) {
            do {
                return try await CloudflareWebSocketPipe.connect(request(for: endpoint, tunnel: tunnel, accessToken: token), hostname: endpoint.hostname, timeout: seconds)
            } catch let error as CloudflareTunnelError {
                // Revoked, or the application's session duration is shorter
                // than the token's expiry: sign in again.
                switch error {
                case .signInRequired, .accessDenied: CloudflareAccessTokens.remove(hostname: endpoint.hostname)
                default: throw error
                }
            }
        }
        let token = try await CloudflareAccessSignIn.signIn(hostname: endpoint.hostname)
        return try await CloudflareWebSocketPipe.connect(request(for: endpoint, tunnel: tunnel, accessToken: token), hostname: endpoint.hostname, timeout: seconds)
    }

    private static func request(for endpoint: CloudflareTunnel.Endpoint, tunnel: CloudflareTunnel, accessToken: String?) -> URLRequest {
        var request = URLRequest(url: endpoint.url)
        request.httpShouldHandleCookies = false
        request.setValue(userAgent, forHTTPHeaderField: "User-Agent")
        if tunnel.authMode == .serviceToken {
            request.setValue(tunnel.serviceTokenID.trimmingCharacters(in: .whitespaces), forHTTPHeaderField: "Cf-Access-Client-Id")
            request.setValue(tunnel.serviceTokenSecret, forHTTPHeaderField: "Cf-Access-Client-Secret")
        }
        if let accessToken {
            request.setValue(accessToken, forHTTPHeaderField: "Cf-Access-Token")
        }
        if let destination = endpoint.jumpDestination {
            request.setValue(destination, forHTTPHeaderField: "Cf-Access-Jump-Destination")
        }
        return request
    }

    private static let userAgent: String = {
        let version = Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "0"
        return "rootshell/\(version)"
    }()
}

/// The WebSocket as an AsyncBytePipe, for BytePipeChannelBridge.
nonisolated final class CloudflareWebSocketPipe: NSObject, AsyncBytePipe, URLSessionWebSocketDelegate, @unchecked Sendable {
    /// Cloudflare drops idle WebSockets after about 100 seconds.
    private static let pingInterval: UInt64 = 30

    private struct State {
        var openContinuation: CheckedContinuation<Void, Error>?
        /// An outcome that arrived before the continuation was stored.
        var openResult: Result<Void, Error>?
        var redirectLocation: String?
        var pending = Data()
        var closed = false
    }

    private let hostname: String
    private let usedServiceToken: Bool
    private let state = OSAllocatedUnfairLock(initialState: State())
    private var session: URLSession?
    private var task: URLSessionWebSocketTask?
    private var keepAlive: Task<Void, Never>?

    private init(hostname: String, usedServiceToken: Bool) {
        self.hostname = hostname
        self.usedServiceToken = usedServiceToken
    }

    static func connect(_ request: URLRequest, hostname: String, timeout: TimeInterval) async throws -> CloudflareWebSocketPipe {
        let pipe = CloudflareWebSocketPipe(hostname: hostname, usedServiceToken: request.value(forHTTPHeaderField: "Cf-Access-Client-Id") != nil)
        try await pipe.start(request, timeout: timeout)
        return pipe
    }

    private func start(_ request: URLRequest, timeout: TimeInterval) async throws {
        let configuration = URLSessionConfiguration.ephemeral
        // URLSession's idle timeouts would cut a quiet shell; the open is
        // bounded by our own timer below.
        configuration.timeoutIntervalForRequest = 7 * 24 * 3600
        configuration.timeoutIntervalForResource = 365 * 24 * 3600
        configuration.waitsForConnectivity = false
        let session = URLSession(configuration: configuration, delegate: self, delegateQueue: nil)
        let task = session.webSocketTask(with: request)
        task.maximumMessageSize = 16 * 1024 * 1024
        self.session = session
        self.task = task

        do {
            try await withTaskCancellationHandler {
                try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
                    let early = self.state.withLock { state -> Result<Void, Error>? in
                        if let result = state.openResult { return result }
                        state.openContinuation = continuation
                        return nil
                    }
                    if let early {
                        continuation.resume(with: early)
                        return
                    }
                    task.resume()
                    DispatchQueue.global().asyncAfter(deadline: .now() + timeout) { [weak self] in
                        guard let self else { return }
                        self.finishOpen(.failure(CloudflareTunnelError.timedOut(self.hostname)))
                    }
                }
            } onCancel: {
                self.finishOpen(.failure(CancellationError()))
            }
        } catch {
            teardown()
            throw error
        }

        keepAlive = Task.detached { [weak self] in
            while !Task.isCancelled {
                try? await Task.sleep(nanoseconds: Self.pingInterval * 1_000_000_000)
                guard let self, !Task.isCancelled else { return }
                if await !self.ping() {
                    await self.close()
                    return
                }
            }
        }
    }

    /// Resumes the open exactly once.
    private func finishOpen(_ result: Result<Void, Error>) {
        let continuation = state.withLock { state -> CheckedContinuation<Void, Error>? in
            guard state.openResult == nil else { return nil }
            state.openResult = result
            defer { state.openContinuation = nil }
            return state.openContinuation
        }
        continuation?.resume(with: result)
    }

    private var isOpen: Bool {
        state.withLock { state in
            if case .success = state.openResult { return true }
            return false
        }
    }

    private func ping() async -> Bool {
        guard let task else { return false }
        return await withCheckedContinuation { continuation in
            task.sendPing { error in continuation.resume(returning: error == nil) }
        }
    }

    private func teardown() {
        keepAlive?.cancel()
        task?.cancel(with: .normalClosure, reason: nil)
        // Breaks the session's strong reference to its delegate (self).
        session?.invalidateAndCancel()
    }

    // MARK: AsyncBytePipe

    func read(maxBytes: Int) async throws -> Data? {
        let buffered = state.withLock { state -> Data? in
            guard !state.pending.isEmpty else { return nil }
            let chunk = state.pending.prefix(maxBytes)
            state.pending.removeFirst(chunk.count)
            return Data(chunk)
        }
        if let buffered { return buffered }
        guard let task, !state.withLock({ $0.closed }) else { return nil }

        while true {
            let message: URLSessionWebSocketTask.Message
            do {
                message = try await task.receive()
            } catch {
                // A close from either side ends the stream cleanly.
                if state.withLock({ $0.closed }) || task.closeCode != .invalid { return nil }
                throw error
            }
            let data: Data
            switch message {
            case .data(let bytes): data = bytes
            case .string(let text): data = Data(text.utf8)
            @unknown default: continue
            }
            guard !data.isEmpty else { continue }
            if data.count <= maxBytes { return data }
            state.withLock { $0.pending.append(data.dropFirst(maxBytes)) }
            return Data(data.prefix(maxBytes))
        }
    }

    func write(_ data: Data) async throws {
        guard let task, !state.withLock({ $0.closed }) else { throw POSIXError(.EPIPE) }
        try await task.send(.data(data))
    }

    func close() async {
        let wasClosed = state.withLock { state -> Bool in
            defer { state.closed = true }
            return state.closed
        }
        guard !wasClosed else { return }
        teardown()
    }

    // MARK: URLSessionWebSocketDelegate

    func urlSession(_ session: URLSession, webSocketTask: URLSessionWebSocketTask, didOpenWithProtocol protocol: String?) {
        finishOpen(.success(()))
    }

    func urlSession(
        _ session: URLSession,
        task: URLSessionTask,
        willPerformHTTPRedirection response: HTTPURLResponse,
        newRequest request: URLRequest
    ) async -> URLRequest? {
        // A redirect means Access wants a sign-in; following it would load the login page.
        let location = response.value(forHTTPHeaderField: "Location") ?? request.url?.absoluteString
        state.withLock { $0.redirectLocation = location }
        return nil
    }

    func urlSession(_ session: URLSession, task: URLSessionTask, didCompleteWithError error: Error?) {
        let response = task.response as? HTTPURLResponse
        let location = state.withLock { $0.redirectLocation } ?? response?.value(forHTTPHeaderField: "Location")
        let failure: Error
        if let status = response?.statusCode, status != 101 {
            if (300..<400).contains(status) || location != nil {
                failure = CloudflareTunnelError.signInRequired(hostname)
            } else if status == 401 || status == 403 {
                failure = CloudflareTunnelError.accessDenied(hostname, status: status, usedServiceToken: usedServiceToken)
            } else {
                failure = CloudflareTunnelError.handshakeFailed(hostname, status: status)
            }
        } else if location != nil {
            failure = CloudflareTunnelError.signInRequired(hostname)
        } else {
            failure = error ?? URLError(.networkConnectionLost)
        }
        finishOpen(.failure(failure))
        // After a successful open, the stream ended: unblock readers and writers.
        if isOpen { Task { await self.close() } }
    }
}
