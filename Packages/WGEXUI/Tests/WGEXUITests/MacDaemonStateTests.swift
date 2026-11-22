// SPDX-License-Identifier: MIT

#if os(macOS)
    import Foundation
    import Testing
    import WGEXCore
    import WGEXDaemonClient
    import WGEXDaemonProtocol
    import WGEXTesting
    import WGEXUI

    @MainActor @Suite(.timeLimit(.minutes(1)))
    private struct MacDaemonStateTests {
        private func model(guarded: Bool = false, simulated: Bool = false, operations: MacShellOperations = .init()) -> MacShellModel {
            MacShellModel(dependencies: MacShellDependencies(
                backend: FakeTunnelBackend(), service: FakeServiceController(initial: .enabled),
                simulated: simulated, hostGuarded: guarded, operations: operations,
            ), profiles: [TunnelProfile(name: "Fixture")])
        }

        @Test
        func `daemon connection copy and running step follow reachability independently of registration`() {
            let model = model()
            model.receiveService(.enabled)
            model.revisit(.backgroundService)
            #expect(model.backendDescription == "Background service unavailable.")
            #expect(!model.daemonRunning)
            #expect(!model.canAdvance)
            model.receiveConnection(.connecting)
            #expect(model.backendDescription == "Contacting the background service…")
            #expect(!model.daemonRunning)
            model.receiveConnection(.connected(daemonBuild: 42))
            #expect(model.backendDescription == "Background service running, build 42.")
            #expect(model.daemonRunning)
            #expect(model.canAdvance)
            let progress = ServiceSetupProgress(state: model.serviceState, daemonRunning: model.daemonRunning)
            #expect(progress.steps.allSatisfy { $0.state == .done })
            model.receiveConnection(.disconnected(lastError: "unavailable"))
            #expect(model.backendDescription == "Background service unavailable (unavailable).")
            #expect(!model.daemonRunning)
            #expect(!model.canAdvance)
            #expect(model.secureInstall == .notReporting)
            #expect(model.secureInstall.detail.contains("not reporting"))
            #expect(model.serviceState == .enabled)
        }

        @Test
        func `disconnect marks install not reporting and reconnect reads new evidence`() async {
            let model = model(operations: MacShellOperations(secureInstall: { .verified }))
            model.daemonHooks.secureInstallStatus = { .verified }
            model.receiveService(.enabled)
            model.receiveConnection(.connected(daemonBuild: 42))
            await model.verifySecureInstall()
            #expect(model.secureInstall == .verified)
            var active = TunnelStatus.idle
            active.phase = .active(Generation(rawValue: 1))
            active.protection = .protected
            model.receive(active, at: Date())
            model.receiveConnection(.disconnected(lastError: "unauthorised"))
            #expect(model.lastStatusAt == nil)
            #expect(model.secureInstall != .verified)
            #expect(model.presentation.verdict != .protected)
            model.receiveConnection(.connecting)
            model.receiveConnection(.connected(daemonBuild: 43))
            await model.refreshSecureInstall()
            #expect(model.daemonRunning)
            #expect(model.secureInstall == .verified)
            model.receiveConnection(.disconnected(lastError: "downgradeDetected"))
            #expect(model.downgradeDetected)
            #expect(model.operationMessage == UserStrings.downgradeDetected)
        }

        @Test
        func `secure install gate keeps service reachable and exposes repair action`() async {
            let model = model(operations: MacShellOperations(secureInstall: { .verified }))
            model.receiveService(.enabled)
            model.receiveConnection(.connected(daemonBuild: 42))
            model.reportSecureInstallRequired()
            #expect(model.daemonRunning)
            #expect(model.secureInstall == .needsAttention(.bundleWritable))
            #expect(model.secureInstall.actionTitle == "Secure install")
            #expect(model.secureInstall.detail.contains("another process"))
            await model.verifySecureInstall()
            #expect(model.secureInstall == .verified)
        }

        @Test
        func `host guard retains copy blocks refresh and periodic sampling`() async {
            let backend = FakeTunnelBackend()
            var refreshed = false
            let model = MacShellModel(dependencies: MacShellDependencies(
                backend: backend, service: FakeServiceController(initial: .enabled), simulated: false, hostGuarded: true,
                operations: MacShellOperations(refreshDaemon: { refreshed = true; return true }),
            ), profiles: [TunnelProfile(name: "Fixture")])
            model.receiveConnection(.connected(daemonBuild: 42))
            model.receiveService(.enabled)
            await model.refreshService()
            await model.sampleStatistics()
            #expect(model.backendDescription == MacShellCopy.hostGuard)
            #expect(!model.canConnect)
            #expect(!model.daemonRunning)
            #expect(!refreshed)
            #expect(backend.calls.isEmpty)
        }

        @Test
        func `real backend actions enabled and mapped errors use existing surface`() async {
            let model = model(operations: MacShellOperations(closeCaptiveWindow: { throw TunnelError.permissionDenied }))
            #expect(model.canConnect)
            await model.closeCaptiveWindow()
            #expect(model.operationMessage == MacErrorCopy(tunnel: .permissionDenied).message)
            let fake = self.model(simulated: true)
            fake.receiveConnection(.connected(daemonBuild: 42))
            #expect(fake.backendDescription == "Simulation: no VPN or system settings are changed.")
        }

        @Test(arguments: [
            (DaemonError.unauthorised, TunnelError.permissionDenied),
            (.secureInstallRequired, .permissionDenied),
            (.secretsUnavailable, .secretsUnavailable),
            (.tunnel(.timedOut), .timedOut),
            (.tunnel(.invalidConfiguration(.invalidProfile)), .invalidConfiguration(.invalidProfile)),
            (.tunnel(.invalidConfiguration(.statisticsInterval)), .invalidConfiguration(.statisticsInterval)),
            (.tunnel(.engine(code: -9)), .engine(code: -9)),
            (.disconnected, .backendUnavailable),
        ])
        func `app operation adapter maps daemon categories without payload text`(_ error: DaemonError, _ expected: TunnelError) async {
            await #expect(throws: expected) {
                try await DaemonError.mapping { () async throws in throw error }
            }
        }

        @Test
        func `refresh failure clears previous running state`() async {
            let model = model(operations: MacShellOperations(refreshDaemon: { throw TunnelError.backendUnavailable }))
            model.receiveService(.enabled)
            model.receiveConnection(.connected(daemonBuild: 42))
            await model.refreshService()
            #expect(!model.daemonRunning)
            #expect(model.operationMessage != nil)
        }
    }
#endif
