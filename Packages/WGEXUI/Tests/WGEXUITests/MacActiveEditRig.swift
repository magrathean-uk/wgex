// SPDX-License-Identifier: MIT
// swiftformat:disable redundantInternal

#if os(macOS)
    import Foundation
    import Synchronization
    import Testing
    import WGEXCore
    import WGEXProfileStore
    import WGEXTesting
    import WGEXUI

    /// M05-T05: an app over a fake backend, recording startup saves and arms, with a secret store that can refuse deletions.
    @MainActor
    internal struct MacActiveEditRig {
        internal final class Recorder {
            internal var saved: [(UUID, MacStartupOption)] = []
            /// Each arm with the tunnel calls made before it.
            internal var arms: [(UUID, [FakeTunnelBackend.Call])] = []
        }

        /// The in-memory store whose deletions can be refused, as a locked keychain refuses them.
        internal final class FlakySecretStore: SecretStore {
            internal let inner = InMemorySecretStore()
            internal let refusesDeletion = Mutex(false)

            internal func store(_ secret: consuming SecretBytes, for id: SecretID) async throws(SecretStoreError) {
                try await inner.store(secret, for: id)
            }

            internal func load(_ id: SecretID) async throws(SecretStoreError) -> SecretBytes {
                try await inner.load(id)
            }

            internal func delete(_ id: SecretID) async throws(SecretStoreError) {
                guard !refusesDeletion.withLock(\.self) else { throw .locked }
                try await inner.delete(id)
            }

            internal func replace(_ id: SecretID, with secret: consuming SecretBytes) async throws(SecretStoreError) {
                try await inner.replace(id, with: secret)
            }

            internal func exists(_ id: SecretID) async throws(SecretStoreError) -> Bool {
                try await inner.exists(id)
            }
        }

        internal static let rule = OnDemandPolicy.interfaces(.wifiOrEthernet(.anySSID))

        internal let root: URL
        internal let app: MacAppModel
        internal let backend: FakeTunnelBackend
        internal let secrets: FlakySecretStore
        internal let persistence: MacPersistence
        internal let startups: Recorder

        internal init() {
            root = MacWorkflowTests.scratch()
            persistence = MacPersistence(container: root, simulated: true)
            let secrets = FlakySecretStore()
            let backend = FakeTunnelBackend()
            let service = FakeServiceController(initial: .enabled)
            let startups = Recorder()
            let shell = MacShellModel(
                dependencies: MacShellDependencies(
                    backend: backend, service: service, simulated: true,
                    operations: MacShellOperations(
                        saveStartup: { profile, option in startups.saved.append((profile.id, option)) },
                        armOnDemand: { profile in startups.arms.append((profile.id, backend.calls)) },
                    ),
                ),
                status: .idle,
            )
            let repository = MacProfileRepository(container: root, store: persistence.store, secrets: secrets)
            app = MacAppModel(composition: MacAppComposition(
                persistence: persistence, secretStore: secrets, daemon: nil, shell: shell, repository: repository, fakeService: service,
            ), preferencesLoader: nil, applyDockPolicy: { _ in })
            self.backend = backend; self.secrets = secrets; self.startups = startups
        }

        internal static func status(
            active: UUID?, phase: TunnelPhase = .active(Generation(rawValue: 4)), armed: UUID? = nil,
        ) -> TunnelStatus {
            var status = TunnelStatus(phase: phase, protection: .protected, transport: nil, health: .idle, recentEvents: [])
            status.activeProfileID = active
            if let armed {
                status.onDemand = OnDemandStatus(
                    armedProfileID: armed, activated: true, network: .ethernet, ssid: .notRequired, decision: .connect,
                )
            }
            return status
        }

        /// Calls that would mean the running tunnel was touched.
        internal static let tunnelCalls: (FakeTunnelBackend.Call) -> Bool = { call in
            switch call {
            case .start, .stop: true
            case .install, .remove, .statistics: false
            }
        }

        /// Saves a fixture as the only profile and makes `active` (or that profile) the running tunnel; `armed` gives the profile
        /// an on-demand rule and arms it; `options` are its saved startup options.
        internal func saved(
            fixture: String = "ipv6-dual-stack", active: UUID? = nil, armed: Bool = false, options: MacProfileOptions = .init(),
        ) async throws -> TunnelProfile {
            let parsed = try EditorFixtures.parsed(fixture)
            var profile = parsed.profile
            profile.macOptions = options
            if armed {
                profile.onDemand = Self.rule
            }
            let saved = try await app.repository.save(profile, secrets: parsed.secrets, previous: nil)
            app.shell.profiles = [saved]
            app.shell.selectedProfileID = saved.id
            app.shell.receive(Self.status(active: active ?? saved.id, armed: armed ? saved.id : nil), at: Date())
            return saved
        }

        internal func editor(_ profile: TunnelProfile) async throws -> ProfileEditorModel {
            let stored = try await app.storedSecrets(profile)
            return try ProfileEditorModel(profile: profile, secrets: stored)
        }

        internal func privateKey(_ profile: TunnelProfile) async throws -> SecretBytes {
            guard case let .daemonStore(id) = profile.secrets.privateKey else { throw ConfigurationError.invalidSecretReference }
            return try await secrets.load(SecretID(profileID: profile.id, kind: .privateKey, id: id))
        }

        /// Confirms an import of a different file over `target`.
        internal func importReplacing(
            _ target: TunnelProfile, connect: Bool, fixture: String = "single-peer-full-tunnel",
        ) async throws -> Task<Void, Never>? {
            let parsed = try EditorFixtures.parsed(fixture)
            let review = ImportReviewModel(parsed: consume parsed)
            var task: Task<Void, Never>?
            #expect(review.confirm { profile, secrets in
                task = try app.confirmImport(profile, secrets: secrets, connect: connect, replacing: target.id)
            })
            return task
        }

        /// The retirement the save could not finish is journalled: the key is still stored and `reconcile` deletes it.
        internal func expectRetiredLater(from original: TunnelProfile, kept: TunnelProfile) async throws {
            let removed = original.secrets.presharedKeys.values.filter { !kept.secrets.presharedKeys.values.contains($0) }
            let ids = try removed.map { reference in
                guard case let .daemonStore(id) = reference else { throw ConfigurationError.invalidSecretReference }
                return SecretID(profileID: original.id, kind: .presharedKey, id: id)
            }
            #expect(!ids.isEmpty)
            for id in ids {
                #expect(try await secrets.exists(id))
            }
            secrets.refusesDeletion.withLock { $0 = false }
            try await app.repository.reconcile()
            for id in ids {
                #expect(try await !secrets.exists(id))
            }
            _ = try await privateKey(kept)
        }
    }
#endif
