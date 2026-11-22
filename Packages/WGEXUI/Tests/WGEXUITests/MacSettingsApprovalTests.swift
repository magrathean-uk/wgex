// SPDX-License-Identifier: MIT

#if os(macOS)
    import Foundation
    import Testing
    import WGEXCore
    import WGEXDaemonClient
    @testable import WGEXDaemonProtocol
    import WGEXTesting
    import WGEXUI

    /// The real settings controller and shell model against a daemon whose production recheck runs over the
    /// modelled admin-right read-back.
    @MainActor
    private struct MacSettingsApprovalTests {
        private func controller(
            _ client: DaemonClient,
            grant: @escaping () async throws -> any SecureInstallGrant,
        ) -> MacGlobalSettingsController {
            // The same request the app composition sends (MacAppModel+Composition).
            MacGlobalSettingsController(send: { settings, authorization in
                guard case .ok = try await client.request(.setGlobalSettings(settings), authorization: authorization) else {
                    throw DaemonError.malformedMessage
                }
            }, grant: grant)
        }

        private func connect(_ service: SettingsDaemon, _ authd: ModelledAuthd) async throws -> DaemonClient {
            let dispatcher = DaemonDispatcher(
                service: service, daemonVersion: "1", daemonBuild: 10, minimumClientBuild: 1, authorisation: authd.authorisation,
            )
            let client = DaemonClient(transport: InMemoryXPCTransport(
                daemon: dispatcher, peer: .init(uid: 501, pid: 7, auditSessionID: 1, codeSigningVerdict: .requirementSatisfied),
            ), clientVersion: "1", clientBuild: 10)
            _ = try await client.connect()
            return client
        }

        private func shell(_ settings: MacGlobalSettingsController) -> MacShellModel {
            MacShellModel(dependencies: MacShellDependencies(
                backend: FakeTunnelBackend(), service: FakeServiceController(initial: .enabled), simulated: true,
                operations: MacShellOperations(setGlobalSettings: { try await settings.set($0) }),
            ), profiles: [TunnelProfile(name: "Approval")])
        }

        @Test func `a loosening settings write succeeds after one approval and shows only once the daemon confirms`() async throws {
            let authd = try ModelledAuthd.fixture()
            let daemon = SettingsDaemon()
            let client = try await connect(daemon, authd)
            var prompts = 0
            let model = shell(controller(client) {
                prompts += 1
                return authd.approve()
            })
            var proposal = model.preferences.global
            proposal.captiveWindowSeconds = 600
            await daemon.hold()
            let write = Task { await model.setGlobalSettings(proposal) }
            var spins = 0
            while await daemon.held == nil, spins < 100_000 {
                spins += 1
                await Task.yield()
            }
            try #require(await daemon.held == proposal, "write not held: \(model.operationMessage ?? "no message"), prompts \(prompts)")
            #expect(model.preferences.global == .defaults)
            #expect(await daemon.applied.isEmpty)
            await daemon.release()
            await write.value
            #expect(prompts == 1)
            #expect(await daemon.applied == [proposal])
            #expect(model.preferences.global == proposal)
            #expect(model.operationMessage == nil)
            #expect(authd.recheckFlags == [[]])
            await client.disconnect()
        }

        @Test func `a stale or cancelled approval leaves the settings the daemon already holds`() async throws {
            let authd = try ModelledAuthd.fixture()
            let daemon = SettingsDaemon()
            let client = try await connect(daemon, authd)
            var cancel = false
            var prompts = 0
            let model = shell(controller(client) {
                prompts += 1
                if cancel {
                    throw TunnelError.cancelled
                }
                let form = authd.approve()
                authd.advance(31)
                return form
            })
            var proposal = model.preferences.global
            proposal.allowLAN = false; proposal.captiveWindowSeconds = 600
            await model.setGlobalSettings(proposal)
            #expect(prompts == 1)
            #expect(authd.recheckFlags == [[]])
            #expect(model.preferences.global == .defaults)
            #expect(model.operationMessage != nil)
            cancel = true
            await model.setGlobalSettings(proposal)
            #expect(prompts == 2)
            #expect(model.preferences.global == .defaults)
            #expect(await daemon.applied.isEmpty)
            await client.disconnect()
        }
    }

    /// Applies settings only when the dispatcher admitted the write; can hold the reply to observe the app meanwhile.
    private actor SettingsDaemon: DaemonService {
        private(set) var applied: [MacGlobalSettings] = []
        private(set) var held: MacGlobalSettings?
        private var holding = false
        private var waiter: CheckedContinuation<Void, Never>?
        private var settings = MacGlobalSettings.defaults

        func hold() {
            holding = true
        }

        func release() {
            holding = false
            waiter?.resume(); waiter = nil
        }

        func ownerUID(for _: UUID) -> uid_t? {
            501
        }

        func profileIDs(ownedBy _: uid_t) -> Set<UUID> {
            []
        }

        func protectionOwnerUID() -> uid_t? {
            501
        }

        func activeProfileID() -> UUID? {
            nil
        }

        func currentSettings() -> MacGlobalSettings {
            settings
        }

        func handle(_ request: Request, context _: DaemonRequestContext, secrets _: consuming SecretBundle?) async -> Reply {
            if case .status = request {
                return .status(.idle)
            }
            guard case let .setGlobalSettings(requested) = request else { return .ok }
            if holding {
                held = requested
                await withCheckedContinuation { waiter = $0 }
            }
            settings = requested; applied.append(requested)
            return .ok
        }
    }
#endif
