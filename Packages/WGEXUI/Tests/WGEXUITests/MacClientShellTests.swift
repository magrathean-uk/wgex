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
    @testable import WGEXUI

    @MainActor @Suite(.timeLimit(.minutes(1)))
    private struct MacClientShellTests {
        private func shell(client: DaemonClient, profiles: [TunnelProfile]) -> MacShellModel {
            let shell = MacShellModel(
                dependencies: .init(backend: client, service: FakeServiceController(initial: .enabled), simulated: false),
                profiles: profiles,
            )
            shell.daemonHooks.continuousNow = { XPCClock.continuousSeconds }
            shell.daemonHooks.refreshStatus = { try await client.refreshStatus() }
            shell.daemonHooks.stopCurrent = { try await client.stopCurrent() }
            shell.daemonHooks.secureInstallStatus = {
                try await MacDaemonComposition.installState(client.secureInstallStatus())
            }
            return shell
        }

        @Test(arguments: [false, true])
        func `update is user initiated and failures restore the real connection without retrying`(_ afterProgress: Bool) async throws {
            let grants = Mutex(0)
            let transport = ShellTransport()
            let daemon = MacDaemonComposition(
                transport: transport,
                clientVersion: "1",
                clientBuild: 11,
                secretStore: InMemorySecretStore(),
                systemOperationsPermitted: true,
                authorizeSecureInstall: {
                    grants.withLock { $0 += 1 }
                    guard afterProgress else { throw TunnelError.cancelled }
                    return Data([1])
                },
            )
            let model = shell(client: daemon.client, profiles: [TunnelProfile(name: "Fixture")])
            MacDaemonBridge.configure(daemon, shell: model)
            let sawProgress = Mutex(false)
            await transport.rejectPreparation {
                let finishing = await model.updateHandoff == .finishing
                sawProgress.withLock { $0 = finishing }
            }
            let observation = Task { await MacDaemonBridge.observeConnection(daemon.client, shell: model) }
            _ = try await daemon.client.connect()
            while !model.updateAvailable {
                await Task.yield()
            }
            #expect(grants.withLock { $0 } == 0)
            await model.finishUpdate()
            #expect(grants.withLock { $0 } == 1)
            #expect(sawProgress.withLock { $0 } == afterProgress)
            #expect(model.updateHandoff == .idle)
            #expect(model.daemonConnection == .connected(daemonBuild: 10))
            await daemon.client.disconnect()
            _ = try await daemon.client.connect()
            for _ in 0 ..< 100 {
                await Task.yield()
            }
            #expect(grants.withLock { $0 } == 1)
            observation.cancel()
            await daemon.client.disconnect()
        }

        @Test
        func `relaunch with non first active profile stops daemon intent and reads install evidence`() async throws {
            let first = TunnelProfile(name: "First")
            let active = TunnelProfile(name: "Active")
            let transport = ShellTransport(active: active.id)
            let client = DaemonClient(transport: transport, clientVersion: "1", clientBuild: 10)
            let model = shell(client: client, profiles: [first, active])
            let observation = Task { await model.observeTunnel() }
            _ = try await client.connect()
            model.receiveConnection(.connected(daemonBuild: 10))
            for _ in 0 ..< 1000 {
                if model.activeProfileID == active.id, model.secureInstall == .verified {
                    break
                }
                await Task.yield()
            }
            #expect(model.activeProfileID == active.id)
            #expect(model.secureInstall == .verified)
            model.busy = true
            #expect(!model.canConnect)
            #expect(model.canToggleActiveConnection)
            await model.toggleActiveConnection()
            model.busy = false
            #expect(await transport.requests.contains(.stopCurrent(reason: .userRequested)))
            model.receiveConnection(.disconnected(lastError: nil))
            #expect(model.secureInstall == .notReporting)
            #expect(model.presentation.verdict == .stale)
            observation.cancel()
            await client.disconnect()
        }

        @Test
        func `missed heartbeat stays unknown while connected and check again cannot freshen cached evidence`() async throws {
            let profile = TunnelProfile(name: "Fixture")
            let transport = ShellTransport(active: profile.id)
            let client = DaemonClient(transport: transport, clientVersion: "1", clientBuild: 10)
            let model = shell(client: client, profiles: [profile])
            let observation = Task { await model.observeTunnel() }
            _ = try await client.connect()
            model.receiveConnection(.connected(daemonBuild: 10))
            await transport.ageMeasurement()
            try await client.refreshStatus()
            for _ in 0 ..< 1000 {
                if model.status.notReportingSince != nil {
                    break
                }
                await Task.yield()
            }
            // The transport stamps the measurement 20 s before its own wall clock and the model reads the wall clock
            // again on receipt; pin the presenter's clock so host load between the two cannot age the copy.
            let since = try #require(model.status.notReportingSince)
            model.tick(at: since.addingTimeInterval(20))
            #expect(model.presentation.verdict == .unknown)
            #expect(model.presentation.provenanceTitle == MacStrings.statusUnknown)
            #expect(model.presentation.secondary.hasPrefix("Background service has not reported for 20 s"))
            #expect(!model.presentation.colour.isProtectionColour)
            await model.toggleConnection()
            #expect(model.presentation.verdict == .unknown)
            #expect(await transport.requests.filter { $0 == .status }.count == 3)
            observation.cancel()
            await client.disconnect()
        }

        @Test
        func `the window settles on the daemon's active tunnel after the client's replayed launch seed`() async throws {
            let first = TunnelProfile(name: "First"), second = TunnelProfile(name: "Second")
            let transport = ShellTransport(active: second.id)
            let client = DaemonClient(transport: transport, clientVersion: "1", clientBuild: 10)
            let model = shell(client: client, profiles: [])
            model.profiles = [first, second, TunnelProfile(name: "Third")]
            model.applyInitialTunnel()
            var seeds = 0
            for await update in client.statusUpdates() {
                model.receive(update, at: Date())
                guard update.measuredAt == nil else { break }
                // StatusBroadcast replays its unreported seed before the client connects.
                seeds += 1
                #expect(model.selectedProfileID == first.id)
                if seeds == 1 {
                    _ = try await client.connect()
                }
            }
            #expect(seeds >= 1)
            #expect(model.selectedProfileID == second.id)
            await client.disconnect()
        }

        @Test
        func `cancel before start acknowledgement fences the pending connect`() async throws {
            let profile = TunnelProfile(name: "Fixture")
            let transport = ShellTransport()
            await transport.pauseInstallation()
            let client = DaemonClient(transport: transport, clientVersion: "1", clientBuild: 10)
            let model = shell(client: client, profiles: [profile])
            let observation = Task { await model.observeTunnel() }
            _ = try await client.connect()
            model.receiveConnection(.connected(daemonBuild: 10))
            for _ in 0 ..< 1000 {
                if model.status.measuredAt != nil {
                    break
                }; await Task.yield()
            }
            let connecting = Task { await model.toggleConnection() }
            for _ in 0 ..< 1000 {
                if await transport.installationPending {
                    break
                }; await Task.yield()
            }
            #expect(model.presentation.action == .cancel)
            #expect(model.canConnect)
            await model.toggleConnection()
            await connecting.value
            #expect(await !transport.requests.contains { $0.kind == .startIntent })
            observation.cancel()
            await client.disconnect()
        }

        @Test
        func `login connect can be cancelled before start acknowledgement`() async throws {
            var profile = TunnelProfile(name: "Login fixture")
            profile.macOptions.autoConnectAtLogin = true
            let transport = ShellTransport()
            await transport.pauseInstallation()
            let client = DaemonClient(transport: transport, clientVersion: "1", clientBuild: 10)
            let model = shell(client: client, profiles: [profile])
            let observation = Task { await model.observeTunnel() }
            _ = try await client.connect()
            model.receiveService(.enabled)
            model.receiveConnection(.connected(daemonBuild: 10))
            let connecting = Task { await model.connectAtLogin() }
            while await !transport.installationPending {
                await Task.yield()
            }
            #expect(model.busy)
            #expect(model.canConnect)
            #expect(model.presentation.action == .cancel)
            await model.toggleConnection()
            // Cleanup also releases the deliberately failing pre-fix implementation.
            await transport.cancelPendingRequests()
            await connecting.value
            #expect(await !transport.requests.contains { $0.kind == .startIntent })
            observation.cancel()
            await client.disconnect()
        }

        @Test
        func `cancel bypasses busy while start reply is still suspended`() async throws {
            let profile = TunnelProfile(name: "Fixture")
            let transport = ShellTransport()
            let client = DaemonClient(transport: transport, clientVersion: "1", clientBuild: 10)
            let model = shell(client: client, profiles: [profile])
            let observation = Task { await model.observeTunnel() }
            _ = try await client.connect()
            model.receiveConnection(.connected(daemonBuild: 10))
            for _ in 0 ..< 1000 {
                if model.status.measuredAt != nil {
                    break
                }
                await Task.yield()
            }
            let connecting = Task { await model.toggleConnection() }
            for _ in 0 ..< 1000 {
                if model.status.operationInFlight {
                    break
                }
                await Task.yield()
            }
            #expect(model.busy)
            #expect(model.canConnect)
            #expect(model.presentation.action == .cancel)
            await model.toggleConnection()
            #expect(await transport.requests.contains(.stopCurrent(reason: .userRequested)))
            await connecting.value
            observation.cancel()
            await client.disconnect()
        }
    }

    private actor ShellTransport: XPCTransport {
        private var callbacks: XPCClientCallbacks?
        private var preparationObserver: (@Sendable () async -> Void)?
        func rejectPreparation(_ observer: @escaping @Sendable () async -> Void) {
            preparationObserver = observer
        }

        private var active: UUID?
        private var sequence: UInt64 = 0
        private var verifiedAt: Date?
        private var verifiedAtContinuous: TimeInterval?
        private var pausedInstall = false
        private var installation: CheckedContinuation<Data, any Error>?
        var installationPending: Bool {
            installation != nil
        }

        func pauseInstallation() {
            pausedInstall = true
        }

        func cancelPendingRequests() {
            installation?.resume(throwing: DaemonError.tunnel(.cancelled)); installation = nil
            start?.resume(throwing: DaemonError.tunnel(.cancelled)); start = nil
        }

        private var measurementAge: TimeInterval = 0
        private var start: CheckedContinuation<Data, any Error>?
        private(set) var requests: [Request] = []
        init(active: UUID? = nil) {
            self.active = active
            if active != nil {
                verifiedAt = Date(); verifiedAtContinuous = XPCClock.continuousSeconds
            }
        }

        func ageMeasurement() {
            measurementAge = 20
        }

        func connect(callbacks: XPCClientCallbacks) {
            self.callbacks = callbacks
        }

        func invalidate() {
            callbacks = nil; start?.resume(throwing: DaemonError.disconnected); start = nil
        }

        private func status(pending: Bool = false) -> TunnelStatus {
            var status = TunnelStatus.idle
            if active != nil {
                status.phase = pending ? .preparing(Generation(rawValue: 1)) : .active(Generation(rawValue: 1))
                status.protection = pending ? .blocked : .protected
            }
            sequence += 1
            status.sequence = sequence; status.activeProfileID = active; status.operationInFlight = pending
            status.measuredAt = Date().addingTimeInterval(-measurementAge); status.measuredAtContinuous = XPCClock
                .continuousSeconds - measurementAge
            status.policyEnforcing = active != nil
            status.verifiedAt = verifiedAt
            status.verifiedAtContinuous = verifiedAtContinuous
            return status
        }

        func send(_ envelope: Data, secrets _: Data?) async throws -> Data {
            let request = try Envelope.decode(envelope).body
            requests.append(request)
            switch request {
            case .prepareForUpdate:
                await preparationObserver?()
                return try WireCodec.encode(Reply.error(.notAuthorised(.adminRightRequired)))
            case .hello:
                return try WireCodec.encode(Reply.hello(.init(
                    daemonVersion: "1",
                    daemonBuild: 10,
                    protocolVersion: Envelope.currentProtocolVersion,
                    minimumClientBuild: 1,
                )))
            case .status: return try WireCodec.encode(Reply.status(status()))
            case .secureInstallStatus:
                return try WireCodec.encode(Reply.secureInstall(.init(
                    state: .verified,
                    bundlePath: "/Applications/WGEX.app",
                    isUnderApplications: true,
                    bundleIdentity: .matched,
                    daemonIdentity: .matched,
                )))
            case .profileRevision: return try WireCodec.encode(Reply.profileRevision(nil))
            case .installProfileCAS where pausedInstall:
                return try await withCheckedThrowingContinuation { installation = $0 }
            case .installProfileCAS: return try WireCodec.encode(Reply.profileRevision(1))
            case let .startIntent(id, _, _):
                active = id
                verifiedAt = Date(); verifiedAtContinuous = XPCClock.continuousSeconds
                let event = try WireCodec.encode(Event.status(status(pending: true)))
                // Install the reply gate before delivering the preparing event.
                return try await withCheckedThrowingContinuation { continuation in
                    start = continuation
                    Task { await callbacks?.event(event) }
                }
            case .stopCurrent:
                active = nil
                try installation?.resume(returning: WireCodec.encode(Reply.profileRevision(1))); installation = nil
                try start?.resume(returning: WireCodec.encode(Reply.error(.tunnel(.cancelled)))); start = nil
                return try WireCodec.encode(Reply.ok)
            default: return try WireCodec.encode(Reply.ok)
            }
        }
    }
#endif
