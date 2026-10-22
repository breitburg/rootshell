//
//  CloudflareTunnelsSettingsView.swift
//  rootshell
//
//  Settings → Connections → Cloudflare Tunnels: the host names that connect
//  through a Cloudflare Tunnel, and the editor for one route.
//

import NIOCore
import SwiftUI

struct CloudflareTunnelsSettingsView: View {
    @State private var isAdding = false
    @State private var pendingDelete: CloudflareTunnel?
    @State private var errorMessage: String?

    private var store: CloudflareTunnelStore { .shared }

    var body: some View {
        List {
            if store.tunnels.isEmpty {
                Section {
                    VStack(spacing: 12) {
                        Image(systemName: "point.3.filled.connected.trianglepath.dotted")
                            .font(.system(size: 44))
                            .foregroundStyle(.secondary)
                        Text("No Cloudflare Tunnels").font(.headline)
                        Text("Reach SSH servers published through a Cloudflare Tunnel without installing cloudflared.")
                            .font(.subheadline)
                            .foregroundStyle(.secondary)
                            .multilineTextAlignment(.center)
                        Button(String(localized: "Add Tunnel", comment: "Cloudflare tunnels: add button")) { isAdding = true }
                            .buttonStyle(.borderedProminent)
                            .padding(.top, 4)
                    }
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 20)
                    .themedRow()
                }
            } else {
                Section {
                    ForEach(store.tunnels) { tunnel in
                        NavigationLink {
                            CloudflareTunnelEditView(tunnel: tunnel, isNew: false)
                        } label: {
                            CloudflareTunnelRow(tunnel: tunnel)
                        }
                        .themedRow()
                    }
                    .onDelete { offsets in
                        pendingDelete = offsets.first.map { store.tunnels[$0] }
                    }
                } footer: {
                    Text("Connections to a matching host, including jump hosts, Git and file transfers, go through the tunnel. Routes are stored in iCloud Keychain and sync to your other devices.")
                }
            }
        }
        .themedList()
        .navigationTitle(String(localized: "Cloudflare Tunnels", comment: "Settings screen title"))
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .primaryAction) {
                Button { isAdding = true } label: { Image(systemName: "plus") }
                    .accessibilityLabel(String(localized: "Add Tunnel", comment: "Cloudflare tunnels: add button"))
            }
        }
        .onAppear { store.reload() }
        // Pushed, not a sheet, so it stays inside the settings sidebar.
        .navigationDestination(isPresented: $isAdding) {
            CloudflareTunnelEditView(tunnel: CloudflareTunnel(), isNew: true)
        }
        .alert(
            String(localized: "Delete Tunnel", comment: "Cloudflare tunnels: delete confirmation title"),
            isPresented: Binding(get: { pendingDelete != nil }, set: { if !$0 { pendingDelete = nil } }),
            presenting: pendingDelete
        ) { tunnel in
            Button(String(localized: "Cancel", comment: "Cancel button"), role: .cancel) {}
            Button(String(localized: "Delete", comment: "Delete button"), role: .destructive) { delete(tunnel) }
        } message: { tunnel in
            Text("“\(tunnel.displayName)” will be removed from all your devices. Matching hosts will be dialed directly.")
        }
        .alert(
            String(localized: "Couldn't Delete Tunnel", comment: "Cloudflare tunnels: delete failure title"),
            isPresented: Binding(get: { errorMessage != nil }, set: { if !$0 { errorMessage = nil } })
        ) {
            Button(String(localized: "OK", comment: "OK button"), role: .cancel) {}
        } message: {
            Text(errorMessage ?? "")
        }
    }

    private func delete(_ tunnel: CloudflareTunnel) {
        do {
            try store.delete(tunnel.id)
        } catch {
            errorMessage = error.localizedDescription
        }
    }
}

private struct CloudflareTunnelRow: View {
    let tunnel: CloudflareTunnel

    var body: some View {
        HStack(spacing: 12) {
            SettingsIcon(systemName: "point.3.filled.connected.trianglepath.dotted")
            VStack(alignment: .leading, spacing: 2) {
                Text(tunnel.displayName)
                    .foregroundStyle(tunnel.isEnabled ? .primary : .secondary)
                Text(tunnel.patterns.joined(separator: ", "))
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
            }
        }
    }
}

// MARK: - Editor

struct CloudflareTunnelEditView: View {
    let isNew: Bool

    @State private var draft: CloudflareTunnel
    @State private var test: TestState = .idle
    @State private var saveError: String?
    @State private var testTask: Task<Void, Never>?
    @Environment(\.dismiss) private var dismiss

    private enum TestState: Equatable {
        case idle
        case running
        case succeeded(String)
        case failed(String)
    }

    init(tunnel: CloudflareTunnel, isNew: Bool) {
        self.isNew = isNew
        _draft = State(initialValue: tunnel)
    }

    /// The host Test Connection dials: the first pattern naming one host.
    private var testHost: String? {
        draft.patterns.first { !$0.hasPrefix("!") && !$0.contains("*") && !$0.contains("?") }
    }

    var body: some View {
        Form {
            Section {
                labeledRow(String(localized: "Name", comment: "Cloudflare tunnel field")) {
                    TextField(String(localized: "Name", comment: "Cloudflare tunnel field"), text: $draft.name,
                              prompt: Text(String(localized: "Optional", comment: "Placeholder for an optional field")))
                }
                .themedRow()
                plainField(String(localized: "Host Names", comment: "Cloudflare tunnel field: host name patterns"),
                           text: $draft.hostPatterns, prompt: "ssh.example.com")
                    .keyboardType(.URL)
                    .themedRow()
                Toggle(String(localized: "Enabled", comment: "Cloudflare tunnel field"), isOn: $draft.isEnabled)
                    .themedRow()
            } header: {
                Text("Hosts")
            } footer: {
                Text("The public host names from your tunnel's ingress rules. Separate several with commas; * matches any part of a name, and !name excludes one. Connect to the host name as usual, for example ssh user@ssh.example.com.")
            }

            Section {
                plainField(String(localized: "Bastion Host", comment: "Cloudflare tunnel field: tunnel host name used as a jump server"),
                           text: $draft.bastionHostname, prompt: String(localized: "None", comment: "Placeholder: no bastion host"))
                    .keyboardType(.URL)
                    .themedRow()
            } header: {
                Text("Advanced")
            } footer: {
                Text("For a tunnel running in bastion mode: connect to this host name and let the tunnel forward to the host and port you dial, like cloudflared access ssh --destination.")
            }

            Section {
                Button {
                    runTest()
                } label: {
                    HStack {
                        Text("Test Connection")
                        Spacer()
                        switch test {
                        case .idle: EmptyView()
                        case .running: ProgressView()
                        case .succeeded: Image(systemName: "checkmark.circle.fill").foregroundStyle(.green)
                        case .failed: Image(systemName: "xmark.octagon.fill").foregroundStyle(.red)
                        }
                    }
                }
                .disabled(draft.validationError != nil || testHost == nil || test == .running)
                .themedRow()
            } footer: {
                switch test {
                case .succeeded(let message), .failed(let message): Text(message)
                case .idle, .running:
                    if let problem = draft.validationError {
                        Text(problem)
                    } else if testHost == nil {
                        Text("Add a host name without wildcards to test the tunnel.")
                    }
                }
            }
        }
        .themedList()
        .navigationTitle(isNew
            ? String(localized: "New Tunnel", comment: "Cloudflare tunnel editor title")
            : draft.displayName)
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .confirmationAction) {
                Button(String(localized: "Save", comment: "Save button"), action: save)
                    .disabled(draft.validationError != nil)
            }
        }
        .onChange(of: draft) { _, _ in
            testTask?.cancel()
            test = .idle
        }
        .onDisappear { testTask?.cancel() }
        .alert(
            String(localized: "Couldn't Save Tunnel", comment: "Cloudflare tunnel save failure title"),
            isPresented: Binding(get: { saveError != nil }, set: { if !$0 { saveError = nil } })
        ) {
            Button(String(localized: "OK", comment: "OK button"), role: .cancel) {}
        } message: {
            Text(saveError ?? "")
        }
    }

    /// iOS forms hide a text field's title once it has a prompt, so the label is drawn separately.
    private func labeledRow<Field: View>(_ title: String, @ViewBuilder field: () -> Field) -> some View {
        HStack {
            Text(title)
            Spacer()
            field()
                .multilineTextAlignment(.trailing)
        }
    }

    private func plainField(_ title: String, text: Binding<String>, prompt: String) -> some View {
        labeledRow(title) {
            TextField(title, text: text, prompt: Text(prompt))
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled()
        }
    }

    private func save() {
        do {
            try CloudflareTunnelStore.shared.save(draft)
            dismiss()
        } catch {
            saveError = error.localizedDescription
        }
    }

    /// Opens the tunnel with the unsaved settings and waits for the SSH server's banner.
    private func runTest() {
        guard let host = testHost else { return }
        let tunnel = draft
        test = .running
        testTask = Task {
            let result: TestState
            do {
                let pipe = try await CloudflareTunnelDialer.open(tunnel: tunnel, host: host, port: 22, timeout: .seconds(20))
                result = await Self.probeBanner(pipe)
                await pipe.close()
            } catch {
                result = .failed(error.localizedDescription)
            }
            guard !Task.isCancelled else { return }
            test = result
        }
    }

    private static func probeBanner(_ pipe: CloudflareWebSocketPipe) async -> TestState {
        do {
            let banner = try await withTimeout(seconds: 10) { try await pipe.read(maxBytes: 255) }
            let line = banner.flatMap { String(data: $0, encoding: .utf8) }?
                .split(whereSeparator: \.isNewline).first.map(String.init) ?? ""
            guard line.hasPrefix("SSH-") else {
                return .failed(String(localized: "The tunnel opened, but the origin didn't send an SSH banner. Check the ingress rule's service.",
                                      comment: "Cloudflare tunnel test result"))
            }
            return .succeeded(String(localized: "Connected. The server identifies as \(line).",
                                     comment: "Cloudflare tunnel test result; argument is an SSH version banner"))
        } catch {
            return .failed(String(localized: "The tunnel opened, but the origin didn't answer: \(error.localizedDescription)",
                                  comment: "Cloudflare tunnel test result; argument is an error message"))
        }
    }
}
