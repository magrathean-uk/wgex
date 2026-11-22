// SPDX-License-Identifier: MIT

#if os(macOS)
    import Foundation
    import Synchronization
    import Testing
    import WGEXCore
    import WGEXDaemonClient
    import WGEXDaemonProtocol
    import WGEXProfileStore
    import WGEXTesting
    import WGEXUI

    @MainActor
    @Suite("Mac shell - unhosted, fakes only")
    private struct MacShellTests {
        private nonisolated static let date = Date(timeIntervalSince1970: 1_800_000_000)
        private nonisolated static let generation = Generation(rawValue: 7)

        private func shell(
            _ backend: FakeTunnelBackend = FakeTunnelBackend(),
            service: FakeServiceController = FakeServiceController(),
            operations: MacShellOperations = MacShellOperations(),
        ) -> MacShellModel {
            MacShellModel(
                dependencies: MacShellDependencies(backend: backend, service: service, simulated: true, operations: operations),
                profiles: [(try? EditorFixtures.profile()) ?? TunnelProfile(name: "Fixture")],
                status: .idle,
                now: Self.date,
            )
        }

        private func status(_ verdict: ProtectionVerdict) -> TunnelStatus {
            var status = TunnelStatus.idle
            switch verdict {
            case .protected: status.phase = .active(Self.generation); status.protection = .protected
            case .connecting: status.phase = .preparing(Self.generation); status.protection = .blocked
            case .reasserting: status.phase = .reasserting(Self.generation, reason: .wake); status.protection = .blocked
            case .blocked: status.phase = .failed(.timedOut, blockedByPolicy: true, needsSecrets: false); status.protection = .blocked
            case .captiveWindow:
                let expires = Self.date.addingTimeInterval(300)
                status.phase = .captiveWindow(Self.generation, expires: expires); status.protection = .captiveWindow(expires: expires)
            case .unprotected, .stale: break
            case .unsupported: status.protection = .unsupported
            case .inactive: status.protection = .unprotected
            case .unknown: status.protection = .unknown
            }
            return status
        }

        @Test(arguments: ProtectionVerdict.allCases.filter { $0 != .inactive })
        func `menu derives every orb state`(_ verdict: ProtectionVerdict) {
            let model = shell()
            model.receive(status(verdict), at: Self.date)
            if verdict == .stale {
                model.tick(at: Self.date.addingTimeInterval(16))
            }
            #expect(model.presentation.verdict == verdict)
            #expect(model.presentation.glyph == verdict.glyph)
            if verdict == .unknown || verdict == .stale {
                #expect(!model.presentation.colour.isProtectionColour)
            }
        }

        @Test(arguments: [
            TunnelPhase.preparing(generation),
            .configuring(generation),
            .reasserting(generation, reason: .wake),
            .failed(.timedOut, blockedByPolicy: true, needsSecrets: false),
            .idle
        ])
        func `captive button visible whenever enforcement blocked`(_ phase: TunnelPhase) {
            let model = shell()
            model.receive(TunnelStatus(phase: phase, protection: .blocked, transport: nil, health: .idle, recentEvents: []), at: Self.date)
            #expect(model.showsCaptiveButton)
        }

        @Test(arguments: [ProtectionState.protected, .unprotected, .unknown, .unsupported, .captiveWindow(expires: date)])
        func `captive button hidden for other protection`(_ protection: ProtectionState) {
            let model = shell()
            model.receive(
                TunnelStatus(phase: .idle, protection: protection, transport: nil, health: .idle, recentEvents: []),
                at: Self.date,
            )
            #expect(!model.showsCaptiveButton)
        }

        @Test
        func `quitting and destroying observers never disconnects`() async throws {
            let backend = FakeTunnelBackend(clock: FakeClock())
            let model = shell(backend)
            let profile = try #require(model.selectedProfile)
            try await backend.install(profile)
            try await backend.start(profile.id, transport: nil)
            model.receive(backend.currentStatus, at: Self.date)
            var terminated = false
            model.quit { terminated = true }
            #expect(terminated)
            #expect(!backend.calls.contains(.stop(profile.id)))
            #expect(backend.currentStatus.protection == .protected)
        }

        @Test
        func `setup registers on step 2, holds Continue until running and no longer waits for secure install`() async {
            let service = FakeServiceController()
            let model = shell(service: service, operations: MacShellOperations(secureInstall: { .verified }, refreshDaemon: { true }))
            await model.advanceOnboarding(); #expect(model.onboardingStep == .backgroundService)
            #expect(service.calls == [.register])
            #expect(model.serviceState == .requiresApproval)
            #expect(model.operationMessage == nil)
            #expect(!model.canAdvance)
            await model.advanceOnboarding(); #expect(model.onboardingStep == .backgroundService)
            #expect(service.calls == [.register])
            let progress = ServiceSetupProgress(state: model.serviceState, daemonRunning: model.daemonRunning)
            #expect(progress.steps.first?.state == .done)
            #expect(progress.needsApproval)
            model.openApproval(); #expect(service.calls.last == .openApproval)
            service.transition(to: .enabled)
            model.receiveService(.enabled)
            #expect(!model.daemonRunning)
            #expect(!model.canAdvance)
            await model.refreshService()
            #expect(model.daemonRunning)
            #expect(model.canAdvance)
            #expect(model.secureInstall != .verified)
            await model.advanceOnboarding()
            #expect(model.onboardingStep == .addTunnel)
            #expect(model.preferences.onboardingComplete)
            #expect(!model.canAdvance)
            await model.advanceOnboarding(); #expect(model.onboardingStep == .addTunnel)
            #expect(service.calls == [.register, .openApproval])
            for step in MacOnboardingStep.allCases {
                model.revisit(step); #expect(model.onboardingStep == step)
            }
            model.receiveService(.notRegistered)
            #expect(!model.daemonRunning)
            #expect(model.secureInstall != .verified)
        }

        @Test(arguments: [ServiceState.requiresApproval, .notRegistered])
        func `registration error is shown only when registration really failed`(_ resultingState: ServiceState) async {
            let state = Mutex<ServiceState>(.notRegistered)
            let opened = Mutex(false)
            let service = ServiceController(
                operations: .init(
                    register: { state.withLock { $0 = resultingState }; throw ServiceError.system(code: 42) },
                    unregister: {}, status: { state.withLock { $0 } },
                    openApproval: { opened.withLock { $0 = true } }, plistExists: { true },
                ),
                isDebugBuild: false,
            )
            let model = MacShellModel(
                dependencies: MacShellDependencies(backend: FakeTunnelBackend(), service: service, simulated: true),
            )
            model.revisit(.backgroundService)
            await model.registerService()
            #expect(model.serviceState == resultingState)
            #expect(opened.withLock { $0 } == (resultingState == .requiresApproval))
            if resultingState == .requiresApproval {
                #expect(model.operationMessage == nil)
                #expect(!model.canAdvance)
            } else {
                #expect(model.operationMessage == MacErrorCopy(service: .system(code: 42)).message)
            }
        }

        @Test(arguments: WGEXCore.SecureInstallState.all)
        func `secure install no longer gates setup and only a verified install completes it`(
            _ result: WGEXCore.SecureInstallState,
        ) async {
            let model = shell(
                service: FakeServiceController(initial: .enabled),
                operations: MacShellOperations(secureInstall: { result }, refreshDaemon: { true }),
            )
            model.revisit(.backgroundService)
            await model.refreshService(); await model.verifySecureInstall()
            #expect(model.secureInstall == result)
            #expect(model.canAdvance)
            #expect(model.preferences.onboardingComplete == (result == .verified))
        }

        @Test
        func `startup persists exclusive options and boot requires secure install`() async throws {
            let root = Self.scratch()
            defer { try? FileManager.default.removeItem(at: root) }
            let store = ProfileStore(container: root)
            let model = shell(service: FakeServiceController(initial: .enabled), operations: MacShellOperations(
                saveStartup: { profile, option in
                    var updated = profile; updated.macOptions = option.profileOptions
                    try await store.save(updated)
                }, secureInstall: { .verified }, refreshDaemon: { true },
            ))
            await model.saveStartup(.boot)
            #expect(model.startupOption == .off)
            #expect(model.operationMessage?.contains("secure install") == true)
            await model.refreshService(); await model.verifySecureInstall()
            for option in [MacStartupOption.login, .boot, .off] {
                await model.saveStartup(option)
                let profile = try #require(model.selectedProfile)
                let persisted = try await store.load(profile.id)
                #expect(MacStartupOption(options: persisted.macOptions) == option)
                #expect(!(persisted.macOptions.startBeforeLogin && persisted.macOptions.autoConnectAtLogin))
                #expect(model.startupOption == option)
            }
        }
    }

    private extension MacShellTests {
        @Test
        func `failed startup write does not change selection`() async {
            let model = shell(operations: MacShellOperations(saveStartup: { _, _ in throw ServiceError.unsupported }))
            await model.saveStartup(.login)
            #expect(model.startupOption == .off)
            #expect(model.operationMessage != nil)
        }

        @Test(arguments: MacSettingsTab.allCases)
        func `settings tabs share persistent preferences`(_ tab: MacSettingsTab) async throws {
            var saved: MacPreferences?
            let model = shell(operations: MacShellOperations(savePreferences: { saved = $0 }))
            model.settingsTab = tab
            model.preferences.flags.relayTransports = true
            model.preferences.global.notifications = false
            await model.savePreferences()
            #expect(model.settingsTab == tab)
            let snapshot = try #require(saved)
            #expect(snapshot.flags.relayTransports)
            #expect(!snapshot.global.notifications)
            #expect(try JSONDecoder().decode(MacPreferences.self, from: JSONEncoder().encode(snapshot)) == snapshot)
        }

        @Test
        func `fake composition never evaluates real controller factory`() async {
            let root = Self.scratch()
            defer { try? FileManager.default.removeItem(at: root) }
            var realConstructions = 0
            let service = FakeServiceController()
            let app = MacAppModel(
                arguments: ["WGEX", "-WGEXFakeBackend"],
                container: root,
                fakeServiceFactory: { service },
                realServiceFactory: {
                    realConstructions += 1
                    return FakeServiceController()
                },
            )
            await app.start()
            defer { app.stopObserving() }
            #expect(app.shell.simulated)
            #expect(realConstructions == 0)
            #expect(app.shell.profiles.isEmpty)
            #expect(app.shell.operationMessage == MacErrorCopy(.fixtureUnavailable).message)
            #expect(app.shell.serviceState == .notRegistered)
            // These are all actions the debug window can perform. It exposes no register action.
            await app.shell.toggleConnection()
            app.shell.quit {}
            #expect(realConstructions == 0)
            #expect(app.shell.serviceState == .notRegistered)
            #expect(service.calls.isEmpty)
        }

        @Test
        func `real host guard refuses before any injected system operation`() async throws {
            let calls = Mutex(0)
            let controller = ServiceController(operations: .init(
                register: { calls.withLock { $0 += 1 } }, unregister: { calls.withLock { $0 += 1 } },
                status: { calls.withLock { $0 += 1 }; return .enabled }, openApproval: { calls.withLock { $0 += 1 } },
            ), sysctl: NonVM(), isDebugBuild: true)
            await #expect(throws: ServiceError.hostGuard) { try await controller.register() }
            await #expect(throws: ServiceError.hostGuard) { try await controller.unregister() }
            for await state in controller.state {
                #expect(state == .notRegistered); break
            }
            controller.openApproval()
            #expect(calls.withLock { $0 } == 0)
        }

        @Test
        func `shell guard does not even ask controller to register`() async {
            let service = FakeServiceController()
            let model = MacShellModel(dependencies: MacShellDependencies(
                backend: FakeTunnelBackend(),
                service: service,
                simulated: false,
                hostGuarded: true,
            ))
            await model.registerService(); await model.reregisterService(); model.openApproval()
            #expect(service.calls.isEmpty)
            #expect(model.operationMessage == MacShellCopy.hostGuard)
        }

        @Test
        func `captive operations require blocked state and pass duration`() async {
            var duration: Int?
            let model = shell(operations: MacShellOperations(openCaptiveWindow: { duration = $0 }))
            await model.openCaptiveWindow(); #expect(duration == nil)
            model.receive(status(.blocked), at: Self.date)
            await model.openCaptiveWindow(); #expect(duration == 300)
        }

        @Test
        func `no sample is unavailable and event ring is bounded`() async {
            let model = shell()
            await model.sampleStatistics()
            #expect(model.handshakeValue == .unavailable)
            #expect(model.downloadValue == .unavailable)
            #expect(model.uploadValue == .unavailable)
            let events = (0 ..< 40).map { _ in TunnelEvent(date: Self.date, kind: .phaseChanged, generation: Self.generation) }
            model.receive(
                TunnelStatus(phase: .idle, protection: .unknown, transport: nil, health: .idle, recentEvents: events),
                at: Self.date,
            )
            #expect(model.status.recentEvents.count == 32)
        }

        @Test
        func `captive expiry closes only after deadline`() async {
            var closes = 0
            let model = shell(operations: MacShellOperations(closeCaptiveWindow: { closes += 1 }))
            model.receive(status(.captiveWindow), at: Self.date)
            await model.closeExpiredCaptiveWindow()
            #expect(closes == 0)
            model.tick(at: Self.date.addingTimeInterval(300))
            await model.closeExpiredCaptiveWindow()
            #expect(closes == 1)
        }

        private static func scratch() -> URL {
            FileManager.default.temporaryDirectory.appendingPathComponent("wgex-mac-test-\(UUID().uuidString)", isDirectory: true)
        }
    }

    private struct NonVM: SysctlReading {
        func integer(named _: String) -> Int64? {
            0
        }

        @MainActor private func shell(allowed: [String]) throws -> MacShellModel {
            var profile = try EditorFixtures.profile()
            profile.peers[0].allowedIPs = try allowed.map { try IPAddressRange($0) }
            profile.peers = [profile.peers[0]]
            return MacShellModel(
                dependencies: MacShellDependencies(
                    backend: FakeTunnelBackend(), service: FakeServiceController(), simulated: true, operations: MacShellOperations(),
                ),
                profiles: [profile], status: .idle, now: Date(timeIntervalSince1970: 1_800_000_000),
            )
        }

        @MainActor @Test func `menu networks joins a short list, summarises a long one and says none`() throws {
            #expect(try shell(allowed: ["10.0.0.0/24", "fd00::/64"]).menuNetworks == "Allowed networks: 10.0.0.0/24, fd00::/64")
            #expect(try shell(allowed: ["0.0.0.0/0", "::/0"]).menuNetworks == "Allowed networks: 0.0.0.0/0, ::/0")
            #expect(try shell(allowed: ["10.0.0.0/24", "10.0.0.0/24"]).menuNetworks == "Allowed networks: 10.0.0.0/24")
            #expect(try shell(allowed: ["10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24", "10.0.4.0/24"]).menuNetworks
                == "Allowed networks: 4 ranges")
            #expect(try shell(allowed: ["0.0.0.0/0", "::/0", "10.0.0.0/8", "192.168.0.0/16"]).menuNetworks
                == "Allowed networks: All traffic")
            #expect(try shell(allowed: []).menuNetworks == "Allowed networks: none")
        }

        @MainActor @Test func `menu networks is nil without a profile`() {
            let model = MacShellModel(dependencies: .init(backend: FakeTunnelBackend(), service: FakeServiceController(), simulated: true))
            #expect(model.menuNetworks == nil)
        }
    }

#endif
