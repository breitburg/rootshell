//
//  CloudflareAccessSignIn.swift
//  rootshell
//
//  Browser sign-in to a Cloudflare Access application. Loads the tunnel
//  hostname in a web view, lets the identity provider run, and takes the
//  `CF_Authorization` cookie Access sets on that hostname once it's done.
//  That app token is what `cloudflared access login` would fetch; it is sent
//  as `Cf-Access-Token` on the WebSocket upgrade.
//

import UIKit
import WebKit
import os.log

nonisolated enum CloudflareAccessSignInError: LocalizedError {
    case cancelled
    case noWindow(String)

    var errorDescription: String? {
        switch self {
        case .cancelled:
            String(localized: "Cloudflare Access sign-in was cancelled.", comment: "Cloudflare tunnel connection error")
        case .noWindow(let hostname):
            String(localized: "Sign in to Cloudflare Access for \(hostname) in Settings › Connections › Cloudflare Tunnels, then connect again.",
                   comment: "Cloudflare tunnel connection error when the sign-in sheet can't be shown; argument is a host name")
        }
    }
}

@MainActor
enum CloudflareAccessSignIn {
    private static let logger = Logger(subsystem: "com.rootshell", category: "CloudflareAccess")

    /// One sheet per hostname; concurrent dials wait on the same sign-in.
    private static var inFlight: [String: Task<String, Error>] = [:]

    /// Presents the sign-in sheet and returns the app token, which is also stored.
    static func signIn(hostname: String) async throws -> String {
        if let pending = inFlight[hostname] { return try await pending.value }
        let task = Task<String, Error> { @MainActor in
            defer { inFlight[hostname] = nil }
            guard let presenter = topViewController() else { throw CloudflareAccessSignInError.noWindow(hostname) }
            logger.info("Presenting Cloudflare Access sign-in for \(hostname, privacy: .public)")
            let token = try await withCheckedThrowingContinuation { continuation in
                let controller = CloudflareAccessSignInViewController(hostname: hostname) { result in
                    continuation.resume(with: result)
                }
                let navigation = UINavigationController(rootViewController: controller)
                navigation.modalPresentationStyle = .formSheet
                presenter.present(navigation, animated: true)
            }
            CloudflareAccessTokens.store(token, hostname: hostname)
            return token
        }
        inFlight[hostname] = task
        return try await task.value
    }

    private static func topViewController() -> UIViewController? {
        let scenes = UIApplication.shared.connectedScenes.compactMap { $0 as? UIWindowScene }
        guard let scene = scenes.first(where: { $0.activationState == .foregroundActive }) else { return nil }
        let window = scene.windows.first(where: \.isKeyWindow) ?? scene.windows.first
        var top = window?.rootViewController
        while let presented = top?.presentedViewController, !presented.isBeingDismissed { top = presented }
        return top
    }
}

private final class CloudflareAccessSignInViewController: UIViewController, WKNavigationDelegate, WKHTTPCookieStoreObserver {
    private static let cookieName = "CF_Authorization"

    private let hostname: String
    private var completion: ((Result<String, Error>) -> Void)?
    private let webView: WKWebView

    init(hostname: String, completion: @escaping (Result<String, Error>) -> Void) {
        self.hostname = hostname
        self.completion = completion
        let configuration = WKWebViewConfiguration()
        // The default store keeps the identity provider's session, so the next
        // sign-in is usually a single tap.
        configuration.websiteDataStore = .default()
        webView = WKWebView(frame: .zero, configuration: configuration)
        super.init(nibName: nil, bundle: nil)
    }

    @available(*, unavailable)
    required init?(coder: NSCoder) { fatalError("init(coder:) has not been implemented") }

    override func viewDidLoad() {
        super.viewDidLoad()
        title = String(localized: "Cloudflare Access", comment: "Cloudflare Access sign-in sheet title")
        navigationItem.prompt = hostname
        navigationItem.leftBarButtonItem = UIBarButtonItem(systemItem: .cancel, primaryAction: UIAction { [weak self] _ in
            self?.finish(.failure(CloudflareAccessSignInError.cancelled))
        })
        webView.navigationDelegate = self
        webView.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(webView)
        NSLayoutConstraint.activate([
            webView.topAnchor.constraint(equalTo: view.safeAreaLayoutGuide.topAnchor),
            webView.bottomAnchor.constraint(equalTo: view.bottomAnchor),
            webView.leadingAnchor.constraint(equalTo: view.leadingAnchor),
            webView.trailingAnchor.constraint(equalTo: view.trailingAnchor),
        ])
        webView.configuration.websiteDataStore.httpCookieStore.add(self)
        if let url = URL(string: "https://\(hostname)/") {
            webView.load(URLRequest(url: url))
        }
    }

    override func viewDidDisappear(_ animated: Bool) {
        super.viewDidDisappear(animated)
        // Swiped down without finishing.
        if isBeingDismissed || navigationController?.isBeingDismissed == true {
            finish(.failure(CloudflareAccessSignInError.cancelled))
        }
    }

    nonisolated func cookiesDidChange(in cookieStore: WKHTTPCookieStore) {
        Task { @MainActor in self.checkCookies() }
    }

    func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) {
        checkCookies()
    }

    func webView(_ webView: WKWebView, didFailProvisionalNavigation navigation: WKNavigation!, withError error: Error) {
        // The tunnel serves SSH, not HTTP, so the final redirect back to the
        // hostname often fails to load; the cookie is set by then.
        checkCookies()
    }

    func webView(_ webView: WKWebView, didFail navigation: WKNavigation!, withError error: Error) {
        checkCookies()
    }

    private func checkCookies() {
        guard completion != nil else { return }
        webView.configuration.websiteDataStore.httpCookieStore.getAllCookies { [weak self] cookies in
            guard let self else { return }
            let token = cookies.first { cookie in
                cookie.name == Self.cookieName && self.cookieDomain(cookie.domain, covers: self.hostname)
                    && CloudflareAccessJWT.isUsable(cookie.value)
            }?.value
            if let token { self.finish(.success(token)) }
        }
    }

    /// The app token is scoped to the application's hostname; the team domain's
    /// own `CF_Authorization` (the org token) doesn't open the tunnel.
    private func cookieDomain(_ domain: String, covers host: String) -> Bool {
        let domain = domain.lowercased().trimmingCharacters(in: CharacterSet(charactersIn: "."))
        return host == domain || (host.hasSuffix("." + domain) && !domain.hasSuffix("cloudflareaccess.com"))
    }

    private func finish(_ result: Result<String, Error>) {
        guard let completion else { return }
        self.completion = nil
        webView.configuration.websiteDataStore.httpCookieStore.remove(self)
        webView.stopLoading()
        completion(result)
        if presentingViewController != nil, !(navigationController?.isBeingDismissed ?? false) {
            dismiss(animated: true)
        }
    }
}
