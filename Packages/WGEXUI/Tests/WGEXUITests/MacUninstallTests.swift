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

    /// The one ordered log every stub writes to, so a test can judge the sequence across daemon, services and stores.
    private final nonisolated class UninstallLog: Sendable {
        private let entries = Mutex<[String]>([])

        func append(_ entry: String) {
            entries.withLock { $0.append(entry) }
        }

        var all: [String] {
            entries.withLock { $0 }
        }

        func count(_ entry: String) -> Int {
            all.count(where: { $0 == entry })
        }
    }

    /// Stub daemon: answers the handshake, records `uninstall` with its authorisation, and reports a held uninstall.
    private actor UninstallDaemon: XPCTransport {
        private let log: UninstallLog
        private var failures: [DaemonError]
        private let held: UninstallProgress?
        private(set) var uninstallAuthorisations: [Data?] = []
        private(set) var mutating = 0

        init(log: UninstallLog, failures: [DaemonError] = [], held: UninstallProgress? = nil) {
            self.log = log; self.failures = failures; self.held = held
        }

        func connect(callbacks _: XPCClientCallbacks) {}
        func invalidate() {}

        func send(_ envelope: Data, secrets _: Data?) async throws -> Data {
            let decoded = try Envelope.decode(envelope)
            switch decoded.body {
            case .hello:
                return try WireCodec.encode(Reply.hello(.init(
                    daemonVersion: "1", daemonBuild: 10, protocolVersion: Envelope.currentProtocolVersion, minimumClientBuild: 1,
                )))
            case .status: return try WireCodec.encode(Reply.status(.idle))
            case .statusTelemetry:
                var telemetry = StatusTelemetry(status: .idle)
                telemetry.uninstall = held
                return try WireCodec.encode(Reply.statusTelemetry(telemetry))
            case let .uninstall(purgeState):
                log.append("daemon.uninstall(\(purgeState))")
                uninstallAuthorisations.append(decoded.authorization)
                if !failures.isEmpty {
                    return try WireCodec.encode(Reply.error(failures.removeFirst()))
                }
                return try WireCodec.encode(Reply.ok)
            default:
                mutating += 1
                return try WireCodec.encode(Reply.ok)
            }
        }
    }

    private nonisolated struct Grant: SecureInstallGrant {
        let externalForm = Data([0xA5, 0x5A])
    }

    private nonisolated struct VM: SysctlReading {
        let present: Bool
        func integer(named _: String) -> Int64? {
            present ? 1 : 0
        }
    }

    private nonisolated struct StubFailure: Error {}

    /// Fails the first `count` calls.
    private final nonisolated class Countdown: Sendable {
        private let remaining: Mutex<Int>

        init(_ count: Int) {
            remaining = Mutex(count)
        }

        func take() -> Bool {
            remaining.withLock { value in
                defer { value = max(0, value - 1) }
                return value > 0
            }
        }
    }

    /// Recording `SMAppService` stand-in: every call is logged; `register` must never appear.
    private final nonisolated class ServiceStub: Sendable {
        let name: String
        private let log: UninstallLog
        private let state: Mutex<ServiceState>
        private let failures: Countdown

        init(_ name: String, log: UninstallLog, state: ServiceState = .enabled, failures: Int = 0) {
            self.name = name; self.log = log; self.state = Mutex(state); self.failures = Countdown(failures)
        }

        var operations: ServiceController.Operations {
            ServiceController.Operations(
                register: { [self] in log.append("\(name).register"); state.withLock { $0 = .enabled } },
                unregister: { [self] in
                    log.append("\(name).unregister")
                    if failures.take() {
                        throw StubFailure()
                    }
                    state.withLock { $0 = .notRegistered }
                },
                status: { [self] in log.append("\(name).status"); return state.withLock { $0 } },
                openApproval: { [self] in log.append("\(name).openApproval") },
                plistExists: { true },
            )
        }

        func controller(guarded: Bool = false) -> ServiceController {
            ServiceController(operations: operations, sysctl: VM(present: !guarded), isDebugBuild: true)
        }
    }

    /// Holds the first preference write before it reaches `MacPersistence`, so a test can remove the app data under it.
    @MainActor private final class PreferenceGate {
        private var held: CheckedContinuation<Void, Never>?
        private var arrival: CheckedContinuation<Void, Never>?
        private var arrived = false

        func enter() async {
            guard !arrived else { return }
            arrived = true
            arrival?.resume()
            arrival = nil
            await withCheckedContinuation { held = $0 }
        }

        func waitForWrite() async {
            guard !arrived else { return }
            await withCheckedContinuation { arrival = $0 }
        }

        func release() {
            held?.resume()
            held = nil
        }
    }

    /// One uninstall through the production composition, with stub daemon, service operations and stores.
    @MainActor
    private struct UninstallRig {
        let log: UninstallLog
        let daemon: UninstallDaemon
        let model: MacShellModel
        let app: MacAppModel
        let root: URL
        let secrets: InMemorySecretStore
        let profile: TunnelProfile

        var uninstall: MacUninstall {
            model.uninstall
        }

        func keyExists() async throws -> Bool {
            try await secrets.exists(SecretID(profileID: profile.id, kind: .privateKey, id: Self.keyID(profile)))
        }

        static func keyID(_ profile: TunnelProfile) -> UUID {
            guard case let .daemonStore(id) = profile.secrets.privateKey else { return UUID() }
            return id
        }

        func profilesOnDisk() async throws -> [UUID] {
            try await ProfileStore(container: root).list().map(\.id)
        }

        static func make(
            daemonFailures: [DaemonError] = [],
            held: UninstallProgress? = nil,
            daemonServiceFailures: Int = 0,
            loginItemFailures: Int = 0,
            loginItemState: ServiceState = .enabled,
            keychainFailures: Int = 0,
            permitted: Bool = true,
            authorise: Bool = true,
            preferenceGate: PreferenceGate? = nil,
        ) async throws -> Self {
            let log = UninstallLog()
            let root = MacWorkflowTests.scratch()
            let persistence = MacPersistence(container: root, simulated: false)
            let secrets = InMemorySecretStore()
            let repository = MacProfileRepository(container: root, store: persistence.store, secrets: secrets)
            let parsed = try EditorFixtures.parsed()
            let profile = try await repository.save(parsed.profile, secrets: parsed.secrets, previous: nil)
            try await persistence.save(MacPreferences())
            let daemon = UninstallDaemon(log: log, failures: daemonFailures, held: held)
            let client = DaemonClient(transport: daemon, clientVersion: "1", clientBuild: 10)
            let daemonService = ServiceStub("daemonService", log: log, failures: daemonServiceFailures)
            let loginItem = ServiceStub("loginItem", log: log, state: loginItemState, failures: loginItemFailures)
            let keychainFailures = Countdown(keychainFailures)
            let steps = MacUninstallComposition.steps(
                client: client, permitted: permitted,
                authorize: { [log] in
                    log.append("authorise")
                    guard authorise else { throw StubFailure() }
                    return Grant()
                },
                daemonService: daemonService.controller(guarded: !permitted),
                loginItem: loginItem.controller(guarded: !permitted),
                repository: repository,
                persistence: persistence,
                removeKeychainItems: { [log] in
                    log.append("keychain.deleteAll")
                    if keychainFailures.take() {
                        throw SecretStoreError.locked
                    }
                },
                removePreferences: { [log] in log.append("defaults.remove") },
                quit: { [log] in log.append("quit") },
            )
            let model = makeModel(
                steps: steps, profile: profile, permitted: permitted, persistence: persistence, gate: preferenceGate,
            )
            let app = MacAppModel(composition: MacAppComposition(
                persistence: persistence, secretStore: secrets, daemon: nil, shell: model, repository: repository,
            ), preferencesLoader: nil, applyDockPolicy: { _ in })
            return Self(
                log: log, daemon: daemon, model: model, app: app, root: root, secrets: secrets, profile: profile,
            )
        }

        /// The shell with the production preference writer, optionally held by `gate` before it reaches the disk.
        private static func makeModel(
            steps: MacUninstallSteps, profile: TunnelProfile, permitted: Bool, persistence: MacPersistence, gate: PreferenceGate?,
        ) -> MacShellModel {
            MacShellModel(
                dependencies: MacShellDependencies(
                    backend: FakeTunnelBackend(), service: FakeServiceController(initial: .enabled), simulated: false,
                    hostGuarded: !permitted, operations: MacShellOperations(
                        errorCopy: MacAppErrorCopy.resolve,
                        savePreferences: { preferences in
                            await gate?.enter()
                            try await persistence.save(preferences)
                        },
                        uninstall: steps,
                    ),
                ),
                profiles: [profile],
            )
        }
    }

    @MainActor @Suite(.timeLimit(.minutes(1)))
    private struct MacUninstallTests {
        /// The SMAppService-side entries only, in order.
        private func serviceCalls(_ log: UninstallLog) -> [String] {
            log.all.filter { $0.hasSuffix(".unregister") || $0.hasSuffix(".register") }
        }

        // MARK: Order and the purge box

        @Test
        func `unticked: daemon then both services, profiles and keys kept, then the final screen and quit`() async throws {
            let rig = try await UninstallRig.make()
            #expect(rig.uninstall.removeProfilesAndSettings == false)
            await rig.uninstall.run()
            #expect(rig.uninstall.phase == .finished)
            let order = rig.log.all.filter { !$0.hasSuffix(".status") }
            #expect(order == ["authorise", "daemon.uninstall(false)", "daemonService.unregister", "loginItem.unregister"])
            #expect(await rig.daemon.uninstallAuthorisations == [Grant().externalForm])
            #expect(try await rig.profilesOnDisk() == [rig.profile.id])
            #expect(try await rig.keyExists())
            rig.uninstall.quit()
            #expect(rig.log.all.last == "quit")
            #expect(rig.app.uiWork == nil)
        }

        @Test
        func `ticked: purge reaches the daemon, then the app's profiles, keys and preferences go after the services`() async throws {
            let rig = try await UninstallRig.make()
            rig.uninstall.removeProfilesAndSettings = true
            await rig.uninstall.run()
            #expect(rig.uninstall.phase == .finished)
            let order = rig.log.all.filter { !$0.hasSuffix(".status") }
            #expect(order == [
                "authorise", "daemon.uninstall(true)", "daemonService.unregister", "loginItem.unregister",
                "keychain.deleteAll", "defaults.remove",
            ])
            #expect(try await !rig.keyExists())
            #expect(!FileManager.default.fileExists(atPath: rig.root.path))
            #expect(try await rig.profilesOnDisk().isEmpty)
        }

        @Test
        func `ticked: a preference write still pending at the removal never recreates the settings, through Quit`() async throws {
            let gate = PreferenceGate()
            let rig = try await UninstallRig.make(preferenceGate: gate)
            #expect(FileManager.default.fileExists(atPath: rig.root.appendingPathComponent("mac-preferences.json").path))
            await rig.app.start()
            // A debounced write starts and is held before it reaches the disk.
            rig.model.preferences.hideDockIcon.toggle()
            await gate.waitForWrite()
            rig.uninstall.removeProfilesAndSettings = true
            await rig.uninstall.run()
            #expect(rig.uninstall.phase == .finished)
            #expect(!FileManager.default.fileExists(atPath: rig.root.path))
            // The held write completes after the removal, and a later change is flushed as termination would flush it.
            gate.release()
            await rig.app.uiWork?.flushPreferences()
            rig.model.preferences.hideDockIcon.toggle()
            await rig.app.uiWork?.flushPreferences()
            #expect(!FileManager.default.fileExists(atPath: rig.root.path))
            rig.uninstall.quit()
            #expect(rig.log.all.last == "quit")
            #expect(rig.app.uiWork == nil)
            #expect(!FileManager.default.fileExists(atPath: rig.root.path))
        }

        @Test
        func `the box cannot change once the daemon step has succeeded`() async throws {
            let rig = try await UninstallRig.make(daemonServiceFailures: 1)
            #expect(rig.uninstall.canChoosePurge)
            await rig.uninstall.run()
            #expect(rig.uninstall.stage == .daemonService)
            #expect(!rig.uninstall.canChoosePurge)
            #expect(!rig.uninstall.needsAdministrator)
        }

        // MARK: Failure points

        @Test
        func `a daemon failure unregisters nothing, and the retry resumes at the daemon`() async throws {
            let rig = try await UninstallRig.make(daemonFailures: [.uninstallFailed(step: .removeRoutes)])
            await rig.uninstall.run()
            guard case let .failed(message) = rig.uninstall.phase else { Issue.record("no failure"); return }
            #expect(message.hasPrefix(MacStrings.uninstallDaemonFailed))
            #expect(serviceCalls(rig.log).isEmpty)
            #expect(rig.uninstall.stage == .daemon)
            await rig.uninstall.run()
            #expect(rig.uninstall.phase == .finished)
            #expect(rig.log.count("daemon.uninstall(false)") == 2)
            #expect(serviceCalls(rig.log) == ["daemonService.unregister", "loginItem.unregister"])
        }

        @Test
        func `a refused administrator prompt sends nothing to the daemon and unregisters nothing`() async throws {
            let rig = try await UninstallRig.make(authorise: false)
            await rig.uninstall.run()
            #expect(rig.uninstall.phase != .finished)
            #expect(rig.log.count("daemon.uninstall(false)") == 0)
            #expect(serviceCalls(rig.log).isEmpty)
            #expect(rig.uninstall.stage == .daemon)
        }

        @Test
        func `a daemon-service unregister failure retries without the daemon and never registers`() async throws {
            let rig = try await UninstallRig.make(daemonServiceFailures: 1)
            await rig.uninstall.run()
            guard case let .failed(message) = rig.uninstall.phase else { Issue.record("no failure"); return }
            #expect(message.hasPrefix(MacStrings.uninstallServiceFailed))
            #expect(serviceCalls(rig.log) == ["daemonService.unregister"])
            await rig.uninstall.run()
            #expect(rig.uninstall.phase == .finished)
            #expect(rig.log.count("daemon.uninstall(false)") == 1)
            #expect(rig.log.count("authorise") == 1)
            #expect(serviceCalls(rig.log) == ["daemonService.unregister", "daemonService.unregister", "loginItem.unregister"])
        }

        @Test
        func `a login-item unregister failure retries only the login item`() async throws {
            let rig = try await UninstallRig.make(loginItemFailures: 1)
            await rig.uninstall.run()
            #expect(rig.uninstall.stage == .loginItem)
            await rig.uninstall.run()
            #expect(rig.uninstall.phase == .finished)
            #expect(rig.log.count("daemon.uninstall(false)") == 1)
            #expect(serviceCalls(rig.log) == ["daemonService.unregister", "loginItem.unregister", "loginItem.unregister"])
        }

        @Test
        func `an app-data failure retries the removal only and then finishes`() async throws {
            let rig = try await UninstallRig.make(keychainFailures: 1)
            rig.uninstall.removeProfilesAndSettings = true
            await rig.uninstall.run()
            guard case let .failed(message) = rig.uninstall.phase else { Issue.record("no failure"); return }
            #expect(message.hasPrefix(MacStrings.uninstallAppDataFailed))
            #expect(rig.uninstall.stage == .appData)
            await rig.uninstall.run()
            #expect(rig.uninstall.phase == .finished)
            #expect(rig.log.count("daemon.uninstall(true)") == 1)
            #expect(serviceCalls(rig.log) == ["daemonService.unregister", "loginItem.unregister"])
            #expect(rig.log.count("keychain.deleteAll") == 2)
            #expect(try await !rig.keyExists())
        }

        @Test
        func `a login item the user never enabled is left alone`() async throws {
            let rig = try await UninstallRig.make(loginItemState: .notRegistered)
            await rig.uninstall.run()
            #expect(rig.uninstall.phase == .finished)
            #expect(serviceCalls(rig.log) == ["daemonService.unregister"])
        }

        @Test
        func `quit is refused before the final screen`() async throws {
            let rig = try await UninstallRig.make(daemonFailures: [.uninstallFailed(step: .admission)])
            await rig.uninstall.run()
            rig.uninstall.quit()
            #expect(rig.log.count("quit") == 0)
        }

        // MARK: An uninstall started from the CLI

        @Test
        func `a completed CLI uninstall is offered at launch and finished without a second administrator prompt`() async throws {
            let rig = try await UninstallRig.make(held: UninstallProgress(completed: true, purgeState: true, pendingStep: nil))
            await rig.app.start()
            await rig.app.uninstallCheck?.value
            #expect(rig.uninstall.finishOffered)
            #expect(rig.uninstall.finishing)
            #expect(rig.app.pendingWindowOpens == 1)
            #expect(!rig.uninstall.canChoosePurge)
            await rig.uninstall.run()
            #expect(rig.uninstall.phase == .finished)
            // The offer's sheet stays presented and now shows the final screen; only Quit ends it.
            #expect(rig.uninstall.finishOffered)
            #expect(rig.log.count("authorise") == 0)
            #expect(rig.log.all.filter { $0.hasPrefix("daemon.") }.isEmpty)
            #expect(serviceCalls(rig.log) == ["daemonService.unregister", "loginItem.unregister"])
            // The CLI's purge is the daemon's; the app's own profiles and keys stay.
            #expect(try await rig.keyExists())
            #expect(try await rig.profilesOnDisk() == [rig.profile.id])
            rig.uninstall.quit(dismissSheet: { [log = rig.log] in log.append("sheet.dismiss") })
            // The offer's sheet is dismissed (flag cleared and the host asked) before the quit step runs.
            #expect(!rig.uninstall.finishOffered)
            #expect(Array(rig.log.all.suffix(2)) == ["sheet.dismiss", "quit"])
            #expect(rig.app.uiWork == nil)
        }

        @Test
        func `quit waits for the sheets to close, then ends any that remain, then terminates`() async {
            let events = UninstallLog()
            let open = Mutex(3)
            await MacUninstallComposition.quitAfterSheets(
                sheetsOpen: { open.withLock { count in defer { count -= 1 }; return count > 0 } },
                endSheets: { events.append("endSheets") }, terminate: { events.append("terminate") },
                attempts: 10, interval: .milliseconds(1),
            )
            // The sheet closed within the wait: nothing is forced, and termination comes last.
            #expect(events.all == ["terminate"])
            let stuck = UninstallLog()
            await MacUninstallComposition.quitAfterSheets(
                sheetsOpen: { true }, endSheets: { stuck.append("endSheets") }, terminate: { stuck.append("terminate") },
                attempts: 3, interval: .milliseconds(1),
            )
            // A sheet that outlasts the wait is ended before termination.
            #expect(stuck.all == ["endSheets", "terminate"])
        }

        @Test
        func `the quit step hands terminate to the run loop instead of calling it inline`() async {
            let events = UninstallLog()
            var scheduled: [@MainActor () -> Void] = []
            await MacUninstallComposition.terminateAfterSheets(
                sheetsOpen: { false }, endSheets: { events.append("endSheets") },
                schedule: { body in events.append("schedule"); scheduled.append(body) },
                terminate: { events.append("terminate") },
            ).value
            // The Task ended without terminating: terminate waits for the run loop to call it.
            #expect(events.all == ["schedule"])
            #expect(scheduled.count == 1)
            scheduled.forEach { $0() }
            #expect(events.all == ["schedule", "terminate"])
        }

        @Test
        func `the run-loop entry point runs the body later, from a main run-loop callout`() {
            var mode: RunLoop.Mode??
            MacUninstallComposition.onMainRunLoop { mode = .some(RunLoop.current.currentMode) }
            // Not inline: the body waits for a run-loop turn.
            #expect(mode == nil)
            var turns = 0
            while mode == nil, turns < 200 {
                turns += 1
                RunLoop.main.run(mode: .default, before: Date(timeIntervalSinceNow: 0.01))
            }
            // The run loop called it (a current mode is set), not a main-queue job drained outside the run loop.
            #expect(mode == .some(.default))
        }

        @Test
        func `a CLI uninstall still in progress resumes at the daemon with its own purge choice`() async throws {
            let rig = try await UninstallRig.make(held: UninstallProgress(completed: false, purgeState: true, pendingStep: .removeDNS))
            await rig.uninstall.checkAtLaunch()
            #expect(rig.uninstall.finishOffered)
            #expect(rig.uninstall.needsAdministrator)
            await rig.uninstall.run()
            #expect(rig.uninstall.phase == .finished)
            #expect(rig.log.count("authorise") == 1)
            #expect(rig.log.count("daemon.uninstall(true)") == 1)
            #expect(try await rig.keyExists())
        }

        @Test
        func `no held uninstall offers nothing`() async throws {
            let rig = try await UninstallRig.make()
            await rig.uninstall.checkAtLaunch()
            #expect(!rig.uninstall.finishOffered)
            #expect(!rig.uninstall.finishing)
            #expect(rig.uninstall.stage == .daemon)
        }

        // MARK: Host guard

        @Test
        func `outside a VM a Debug build reaches neither the daemon nor any service operation`() async throws {
            let rig = try await UninstallRig.make(
                held: UninstallProgress(completed: true, purgeState: false, pendingStep: nil),
                permitted: false,
            )
            await rig.uninstall.checkAtLaunch()
            #expect(!rig.uninstall.finishOffered)
            await rig.uninstall.run()
            #expect(rig.uninstall.phase != .finished)
            #expect(rig.log.all.isEmpty)
            #expect(await rig.daemon.uninstallAuthorisations.isEmpty)
        }
    }

    /// The guard in `ServiceController` stays in front of every `SMAppService` call, the uninstall's included.
    @MainActor @Suite(.timeLimit(.minutes(1)))
    private struct ServiceControllerUninstallGuardTests {
        @Test
        func `the host guard runs before every ServiceController system operation`() async {
            let log = UninstallLog()
            let stub = ServiceStub("service", log: log)
            let controller = stub.controller(guarded: true)
            await #expect(throws: ServiceError.hostGuard) { try await controller.unregisterIfRegistered() }
            await #expect(throws: ServiceError.hostGuard) { try await controller.unregister() }
            await #expect(throws: ServiceError.hostGuard) { try await controller.register() }
            await #expect(throws: ServiceError.hostGuard) { try await controller.setLoginItemEnabled(false) }
            await #expect(throws: ServiceError.hostGuard) { try await controller.setLoginItemEnabled(true) }
            controller.openApproval()
            controller.refresh()
            var states = controller.state.makeAsyncIterator()
            #expect(await states.next() == .notRegistered)
            #expect(log.all.isEmpty)
        }

        @Test
        func `inside a VM unregisterIfRegistered reads the state and unregisters only a registered service`() async throws {
            let log = UninstallLog()
            let registered = ServiceStub("on", log: log).controller()
            try await registered.unregisterIfRegistered()
            try await registered.unregisterIfRegistered()
            #expect(log.all.filter { !$0.hasSuffix(".status") } == ["on.unregister"])
            let pending = ServiceStub("approval", log: log, state: .requiresApproval).controller()
            try await pending.unregisterIfRegistered()
            #expect(log.count("approval.unregister") == 1)
            #expect(log.all.allSatisfy { !$0.hasSuffix(".register") })
        }
    }
#endif
