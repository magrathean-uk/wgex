// SPDX-License-Identifier: MIT

// swiftformat:disable redundantInternal
import Foundation
import Observation
import WGEXAppComposition
import WGEXCore
import WGEXProfileStore
import WGEXUI
#if DEBUG || WGEX_LAB_BUILD
    import WGEXTesting
#endif

@MainActor @Observable
internal final class TVAppModel {
    internal private(set) var profiles: [TunnelProfile] = []
    internal var selectedID: UUID?
    internal var settings = TVSettings()
    internal var flags: FeatureFlags = .defaults
    internal private(set) var status = TunnelStatus.idle
    internal private(set) var sampledAt: Date?
    internal private(set) var message: String?
    internal private(set) var busy = false
    internal var editor: ProfileEditorModel?
    internal let paste = TVPasteImportModel()
    internal let backend: any TunnelBackend
    internal let store: ProfileStore
    internal let secrets: any SecretStore
    internal let usesTemporaryStore: Bool
    #if DEBUG || WGEX_LAB_BUILD
        internal let service = FakeServiceController()
    #endif
    private var secretComposition: ProfileComposition {
        ProfileComposition(strategy: .identities(secrets))
    }

    private let container: URL
    private let storageAvailable: Bool
    @ObservationIgnored private var started = false
    @ObservationIgnored private var pendingSave: ProfileEditorModel?
    @ObservationIgnored private var pendingConnect = false

    internal static var simulator: Bool {
        #if targetEnvironment(simulator)
            true
        #else
            false
        #endif
    }

    internal init(arguments: [String] = ProcessInfo.processInfo.arguments) {
        #if DEBUG || WGEX_LAB_BUILD
            usesTemporaryStore = Self.simulator || arguments.contains("-WGEXFakeBackend")
            let fake = FakeTunnelBackend(capabilities: [.allowLAN])
            fake.scriptStart([
                .init(phase: .preparing(Generation(rawValue: 1)), protection: .unsupported),
                .init(phase: .configuring(Generation(rawValue: 1)), protection: .unsupported),
                .init(phase: .active(Generation(rawValue: 1)), protection: .unsupported),
            ])
            fake.scriptStop([.init(phase: .idle, protection: .unprotected)])
            backend = fake
        #else
            usesTemporaryStore = false
            backend = TVUnwiredTunnelBackend()
            status = TunnelStatus(phase: .idle, protection: .unknown, transport: nil, health: .idle, recentEvents: [])
            message = "Backend not wired. Protection is unknown."
        #endif
        let group = usesTemporaryStore ? nil : FileManager.default
            .containerURL(forSecurityApplicationGroupIdentifier: BuildIdentifiers.current.appGroup)
        storageAvailable = usesTemporaryStore || group != nil
        container = usesTemporaryStore ? FileManager.default.temporaryDirectory.appendingPathComponent("WGEX-TV-\(UUID().uuidString)") :
            group ?? FileManager.default.temporaryDirectory.appendingPathComponent("WGEX-TV-unavailable")
        store = ProfileStore(container: container)
        #if DEBUG || WGEX_LAB_BUILD
            secrets = usesTemporaryStore ? InMemorySecretStore() : KeychainSecretStore()
        #else
            secrets = KeychainSecretStore()
        #endif
    }

    internal var selected: TunnelProfile? {
        profiles.first { $0.id == selectedID }
    }

    internal func run() async {
        guard !started else { return }; started = true
        defer { started = false }
        do {
            guard storageAvailable else { throw TunnelError.backendUnavailable }
            profiles = try await store.list()
            let saved = try await store.loadSettings()
            selectedID = profiles.first { $0.id == saved.app.selectedProfileID }?.id ?? profiles.first?.id
            flags = saved.app.featureFlags
            let url = container.appendingPathComponent("tv-shell.json")
            if FileManager.default.fileExists(atPath: url.path) {
                settings = try JSONDecoder().decode(TVSettings.self, from: Data(contentsOf: url))
            }
            if let selected {
                adoptPolicy(selected)
            }
            for profile in profiles {
                try await backend.install(profile)
            }
        } catch {
            #if DEBUG || WGEX_LAB_BUILD
                message = "Stored profiles could not be loaded. No VPN configuration has been installed."
            #else
                message = "Backend not wired. Protection is unknown."
            #endif
        }
        for await update in backend.statusUpdates() {
            if Task.isCancelled {
                break
            }
            status = update; sampledAt = Date()
        }
    }
}

internal extension TVAppModel {
    func saveSettings() async {
        guard storageAvailable, !busy else { return }
        busy = true; defer { busy = false }
        do {
            if let selected {
                let updated = settings.applying(to: selected)
                try await backend.install(updated)
                try await store.save(updated)
                profiles = profiles.map { $0.id == updated.id ? updated : $0 }
            }
            try await store.saveSettings(SettingsDocument(app: AppSettings(selectedProfileID: selectedID, featureFlags: flags)))
            try FileManager.default.createDirectory(at: container, withIntermediateDirectories: true)
            try JSONEncoder().encode(settings).write(to: container.appendingPathComponent("tv-shell.json"), options: .atomic)
        } catch { message = "Settings could not be saved. Try again." }
    }

    func refreshStatus() async {
        for await update in backend.statusUpdates() {
            status = update; sampledAt = Date(); break
        }
    }

    func connect(_ profile: TunnelProfile? = nil) async {
        guard !busy, let target = profile ?? selected else { return }
        busy = true; defer { busy = false }
        do {
            if TVConnectionState.isRunning(status.phase), let selectedID {
                try await backend.stop(selectedID)
                if target.id == selectedID {
                    return
                }
            }
            if target.id != selectedID {
                adoptPolicy(target)
            }
            selectedID = target.id
            let updated = settings.applying(to: target)
            try await backend.install(updated)
            try await store.save(updated)
            profiles = profiles.map { $0.id == updated.id ? updated : $0 }
            try await store.saveSettings(SettingsDocument(app: AppSettings(selectedProfileID: selectedID, featureFlags: flags)))
            try await backend.start(target.id, transport: nil)
            message = nil
        } catch { message = "The connection request failed. Protection cannot be assumed." }
    }

    /// The shared review callback is synchronous. Copy into an owned editor, then save in the sheet's task.
    func stageImport(_ profile: TunnelProfile, keys: borrowing ParsedSecrets, connect: Bool, applyDefaults: Bool = true) throws {
        guard !busy, pendingSave == nil else { throw TunnelError.cancelled }
        pendingSave = try ProfileEditorModel(
            profile: applyDefaults ? settings.applying(to: profile) : profile,
            secrets: keys,
            featureFlags: flags,
        )
        pendingConnect = connect
    }

    func finishStagedImport() async -> Bool {
        guard let pendingSave else { return false }
        let connectAfter = pendingConnect
        self.pendingSave = nil
        busy = true
        do {
            let profile = try pendingSave.validatedProfile()
            try await persist(profile, editor: pendingSave)
            if !TVConnectionState.isRunning(status.phase) || selectedID == profile.id {
                selectedID = profile.id; adoptPolicy(profile)
            }
            paste.clear(); editor = nil; message = nil
            busy = false
            await saveSettings()
            if connectAfter {
                await connect(profile)
            }
            return true
        } catch { busy = false; message = "The profile could not be saved. Review it and try again."; return false }
    }

    func acceptPairing(_ parsed: consuming ParsedConfiguration) async throws {
        guard !busy, storageAvailable else { throw TunnelError.cancelled }
        var profile = settings.applying(to: parsed.profile)
        if let existing = profiles.first(where: { $0.interface.publicKey == profile.interface.publicKey }) {
            profile = profile.importedCopy(id: existing.id, macOptions: profile.macOptions)
        }
        let prepared = try ProfileEditorModel(profile: profile, secrets: parsed.secrets, featureFlags: flags)
        busy = true; defer { busy = false }
        try await persist(profile, editor: prepared)
        if !TVConnectionState.isRunning(status.phase) {
            selectedID = profile.id
        }
    }

    private func adoptPolicy(_ profile: TunnelProfile) {
        settings.alwaysOn = profile.onDemand != .off
        settings.allowLAN = profile.protection.tv.allowLAN
        settings.dnsPolicy = profile.protection.dnsPolicy
    }

    private func persist(_ profile: TunnelProfile, editor: ProfileEditorModel) async throws {
        guard storageAvailable else { throw TunnelError.backendUnavailable }
        let packed = try editor.makeSecrets()
        let previous = profiles.first { $0.id == profile.id }
        let saved = try await secretComposition.commit(
            profile, secrets: packed, to: store, previous: previous, installOrder: .beforeDocument,
            install: { try await self.backend.install($0) },
            rollback: {
                if let previous {
                    try? await self.backend.install(previous)
                } else {
                    try? await self.backend.remove(profile.id, purgeSecrets: false)
                }
            },
        )
        profiles.removeAll { $0.id == saved.id }; profiles.append(saved)
    }

    func openEditor(_ profile: TunnelProfile) async {
        guard !busy else { return }
        do {
            let packed = try await secretComposition.load(profile)
            editor = try ProfileEditorModel(profile: profile, secrets: packed, featureFlags: flags)
        } catch { message = "Profile keys are unavailable. Import the configuration again." }
    }

    func delete(_ profile: TunnelProfile) async {
        guard !busy else { return }; busy = true
        do {
            if selectedID == profile.id {
                try await backend.stop(profile.id)
            }
            try await backend.remove(profile.id, purgeSecrets: true)
            try await store.delete(profile.id)
            try? await secretComposition.deleteSecrets(of: profile, bestEffort: true)
            profiles.removeAll { $0.id == profile.id }
            if selectedID == profile.id {
                selectedID = profiles.first?.id
            }
            message = nil
        } catch { message = "The profile could not be deleted. Try again." }
        busy = false; await saveSettings()
    }
}

/// M2-01 owns NetworkExtension composition. This placeholder never reports protection.
private struct TVUnwiredTunnelBackend: TunnelBackend {
    let capabilities: BackendCapabilities = []
    func install(_ profile: TunnelProfile) async throws(TunnelError) {
        throw .backendUnavailable
    }

    func remove(_ id: UUID, purgeSecrets: Bool) async throws(TunnelError) {
        throw .backendUnavailable
    }

    func start(_ id: UUID, transport: TransportID?) async throws(TunnelError) {
        throw .backendUnavailable
    }

    func stop(_ id: UUID) async throws(TunnelError) {
        throw .backendUnavailable
    }

    func statistics() async throws(TunnelError) -> TunnelStatistics {
        throw .backendUnavailable
    }

    func statusUpdates() -> AsyncStream<TunnelStatus> {
        AsyncStream { continuation in
            continuation.yield(TunnelStatus(phase: .idle, protection: .unknown, transport: nil, health: .idle, recentEvents: []))
            continuation.finish()
        }
    }
}
