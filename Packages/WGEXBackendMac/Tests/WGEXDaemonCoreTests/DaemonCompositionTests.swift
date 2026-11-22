// SPDX-License-Identifier: MIT
import Foundation
import Synchronization
import Testing
@testable import WGEXCore
@testable import WGEXDaemonCore
import WGEXDaemonProtocol

private actor CompositionDiagnostics: DaemonDiagnosticsProviding {
    var scopes: [Set<UUID>] = []
    func logs(since: Date?, limit: Int, visibleProfileIDs: Set<UUID>) -> [RedactedLogLine] {
        scopes.append(visibleProfileIDs)
        return [RedactedLogLine(date: .distantPast, category: "daemon", message: "fixed event", profileID: nil)]
    }

    func bundle(_ request: DiagnosticsRequest, visibleProfileIDs: Set<UUID>) -> DiagnosticsBundle {
        scopes.append(visibleProfileIDs)
        return DiagnosticsBundle(createdAt: .distantPast, archive: Data("scoped fake archive".utf8))
    }
}

package final class CompositionFixture: Sendable {
    package let harness: ControllerHarness
    package let composition: DaemonComposition
    package let transport: InMemoryXPCTransport
    package let events = Mutex<[Event]>([])

    package init(harness: ControllerHarness, controller: TunnelController? = nil, reportingClock: XPCClock = .continuous) {
        self.harness = harness
        composition = DaemonComposition(
            controller: controller ?? harness.controller,
            daemonVersion: "test",
            daemonBuild: 10,
            minimumClientBuild: 1,
            authorisation: .init(isConsoleUser: { _ in true }, hasAdminRight: { _, _ in true }),
            statusJournal: StatusPublicationJournal(directory: harness.directory),
            reportingClock: reportingClock,
        )
        transport = InMemoryXPCTransport(daemon: composition.dispatcher, peer: Self.peer(501))
    }

    package static func peer(_ uid: UInt32) -> VerifiedPeerIdentity {
        VerifiedPeerIdentity(uid: uid, pid: 7, auditSessionID: 10, codeSigningVerdict: .requirementSatisfied)
    }

    package func connect() async throws {
        try await transport.connect(callbacks: .init(event: { [self] data in
            let event = try? WireCodec.decode(Event.self, from: data)
            if let event {
                events.withLock { $0.append(event) }
            }
        }))
        guard case .hello = try await call(.hello(clientVersion: "test", clientBuild: 11)) else {
            throw HostTestError.injected
        }
    }

    package func call(_ request: Request, expected: Generation? = nil, secrets: Data? = nil) async throws -> Reply {
        try await WireCodec.decode(Reply.self, from: transport.send(
            Envelope(expectedGeneration: expected, body: request).encoded(), secrets: secrets,
        ))
    }

    package func installAndStart() async throws -> Generation {
        #expect(try await call(.installProfileCAS(harness.profile, expectedRevision: nil)) == .profileRevision(1))
        return try await start()
    }

    package func start(expected: Generation? = nil) async throws -> Generation {
        var wire = try ControllerHarness.bundle().wireBytes().withUnsafeBytes { Data($0) }
        defer { wire.resetBytes(in: 0 ..< wire.count) }
        let reply = try await call(
            .startIntent(profileID: harness.profile.id, transport: nil, hasSecrets: true),
            expected: expected,
            secrets: wire,
        )
        guard case let .started(generation) = reply else { throw HostTestError.injected }
        return generation
    }
}

private struct DaemonCompositionTests {
    @Test
    func `hello install start secrets status events stop idle with encrypted storage`() async throws {
        let fixture = try CompositionFixture(harness: ControllerHarness())
        try await fixture.connect()
        #expect(try await fixture.call(.subscribeEvents(includeLogs: true)) == .ok)
        let wipes = Mutex<[SecretBytes.WipeReport]>([])
        let generation = try await SecretBytes.$wipeObserver.withValue({ report in wipes.withLock { $0.append(report) } }) {
            try await fixture.installAndStart()
        }
        guard case let .status(active) = try await fixture.call(.status) else { throw HostTestError.injected }
        #expect(active.phase == .active(generation)); #expect(active.protection == .protected)
        try assertNoRetainedFixtureBytes(fixture.harness)
        #expect(await fixture.harness.controller.operation == nil)
        let encrypted = try fixture.harness.directory.directory("secrets").directory("bundles")
        #expect(try encrypted.filenames().count == 1)
        #expect(wipes.withLock { !$0.isEmpty && $0.allSatisfy(\.isZeroed) })
        for _ in 0 ..< 100
            where !fixture.events
            .withLock({
                $0
                    .contains {
                        if case let .status(value) = $0 {
                            return value.phase == active.phase && value.protection == active.protection
                        }; return false
                    }
            })
        {
            await Task.yield()
        }
        #expect(fixture.events
            .withLock {
                $0
                    .contains {
                        if case let .status(value) = $0 {
                            return value.phase == active.phase && value.protection == active.protection
                        }; return false
                    }
            })
        #expect(try await fixture.call(.stop(profileID: fixture.harness.profile.id, reason: .userRequested), expected: generation) == .ok)
        guard case let .status(idle) = try await fixture.call(.status) else { throw HostTestError.injected }
        #expect(idle.phase == .idle); #expect(idle.protection == .unprotected)
        await #expect(throws: (any Error).self) { _ = try await fixture.harness.store.loadBundle(profileID: fixture.harness.profile.id) }
        try assertNoRetainedFixtureBytes(fixture.harness)
    }

    @Test
    func `stale generation and foreign uid fail before mutation`() async throws {
        let fixture = try CompositionFixture(harness: ControllerHarness()); try await fixture.connect()
        let generation = try await fixture.installAndStart()
        let before = fixture.harness.trace.calls
        #expect(try await fixture.call(
            .stop(profileID: fixture.harness.profile.id, reason: .userRequested),
            expected: Generation(rawValue: 0),
        )
            == .error(.staleGeneration))
        let foreign = InMemoryXPCTransport(daemon: fixture.composition.dispatcher, peer: CompositionFixture.peer(502))
        try await foreign.connect(callbacks: .init())
        _ = try await foreign.send(Envelope(body: .hello(clientVersion: "test", clientBuild: 11)).encoded(), secrets: nil)
        let bytes = try await foreign.send(
            Envelope(body: .stop(profileID: fixture.harness.profile.id, reason: .userRequested)).encoded(),
            secrets: nil,
        )
        #expect(try WireCodec.decode(Reply.self, from: bytes) == .error(.notAuthorised(.notOwner)))
        #expect(fixture.harness.trace.calls == before)
        #expect(await fixture.harness.controller.currentGeneration == generation)
    }

    @Test
    func `engine failure returns error and undoes only installed resources in reverse order`() async throws {
        let fixture = try CompositionFixture(harness: ControllerHarness()); try await fixture.connect()
        #expect(try await fixture.call(.installProfileCAS(fixture.harness.profile, expectedRevision: nil)) == .profileRevision(1))
        fixture.harness.trace.fail(at: "engine.up")
        await #expect(throws: HostTestError.self) { _ = try await fixture.start() }
        let undo = fixture.harness.journal.snapshot().entries.filter { $0.action == .undo }.map(\.step)
        #expect(undo == [.engineUp, .createEngine])
        #expect(await fixture.harness.controller.status.protection == .blocked)
        #expect(await fixture.harness.ports.routeItems.isEmpty)
    }

    @Test
    func `captive window expires on fake time and prepare update preserves intent`() async throws {
        let fixture = try CompositionFixture(harness: ControllerHarness()); try await fixture.connect()
        _ = try await fixture.installAndStart()
        #expect(try await fixture.call(.openCaptiveWindow(seconds: 3)) == .ok)
        #expect(fixture.harness.journal.snapshot().captiveWindow != nil)
        #expect(await fixture.harness.ports.routeItems.isEmpty)
        #expect(try await fixture.call(.extendCaptiveWindow(seconds: 6)) == .ok)
        fixture.harness.clock.advance(.seconds(4))
        try await fixture.harness.controller.tick()
        #expect(fixture.harness.journal.snapshot().captiveWindow != nil)
        fixture.harness.clock.advance(.seconds(3))
        try await fixture.harness.controller.tick()
        #expect(fixture.harness.journal.snapshot().captiveWindow == nil)
        #expect(await fixture.harness.controller.status.protection == .protected)
        #expect(try await fixture.call(.prepareForUpdate) == .ok)
        #expect(fixture.harness.journal.snapshot().intent?.profileID == fixture.harness.profile.id)
        #expect(fixture.harness.journal.snapshot().resources.isEmpty)
        let recovered = try fixture.harness.replacementController()
        let fresh = DaemonComposition(
            controller: recovered,
            daemonVersion: "test",
            daemonBuild: 11,
            minimumClientBuild: 1,
            statusJournal: StatusPublicationJournal(directory: fixture.harness.directory),
        )
        try await fresh.controller.reconcileAtStartup()
        #expect(await recovered.status.protection == .protected)
    }

    @Test
    func `fresh composition recovers intended up from the same directory after modelled process death`() async throws {
        let fixture = try CompositionFixture(harness: ControllerHarness()); try await fixture.connect()
        let first = try await fixture.installAndStart()
        let recovered = try fixture.harness.replacementController()
        let fresh = DaemonComposition(
            controller: recovered,
            daemonVersion: "test",
            daemonBuild: 10,
            minimumClientBuild: 1,
            statusJournal: StatusPublicationJournal(directory: fixture.harness.directory),
        )
        try await fresh.controller.reconcileAtStartup()
        #expect(await recovered.currentGeneration > first)
        #expect(await recovered.status.protection == .protected)
        let entries = fixture.harness.trace.calls
        let blocking = try #require(entries.lastIndex(of: "pf.error"))
        let inspection = try #require(entries.lastIndex(of: "reality.inspect"))
        #expect(blocking < inspection)
    }

    @Test
    func `diagnostics and logs receive only authenticated profile scope including empty scope`() async throws {
        let source = CompositionDiagnostics()
        let fixture = try CompositionFixture(harness: ControllerHarness(diagnostics: source)); try await fixture.connect()
        _ = try await fixture.installAndStart()
        _ = try await fixture.call(.logs(since: nil, limit: 10))
        _ = try await fixture.call(.diagnostics(.init(includeLogs: true, since: nil, profileIDs: [fixture.harness.profile.id, UUID()])))
        #expect(await source.scopes == [[fixture.harness.profile.id], [fixture.harness.profile.id]])
        let foreign = InMemoryXPCTransport(daemon: fixture.composition.dispatcher, peer: CompositionFixture.peer(502))
        try await foreign.connect(callbacks: .init())
        _ = try await foreign.send(Envelope(body: .hello(clientVersion: "test", clientBuild: 11)).encoded(), secrets: nil)
        _ = try await foreign.send(
            Envelope(body: .diagnostics(.init(includeLogs: true, since: nil, profileIDs: []))).encoded(),
            secrets: nil,
        )
        #expect(await source.scopes.last == [])
    }

    @Test
    func `dispatcher forwards replacement stop and start returns typed cancellation`() async throws {
        let gate = StepGate(point: .engineUp)
        let fixture = try CompositionFixture(harness: ControllerHarness(gate: gate))
        try await fixture.connect()
        _ = try await fixture.call(.installProfileCAS(fixture.harness.profile, expectedRevision: nil))
        var wire = try ControllerHarness.bundle().wireBytes().withUnsafeBytes { Data($0) }
        defer { wire.resetBytes(in: 0 ..< wire.count) }
        let payload = wire
        let first = Task { try await fixture.call(.startIntent(
            profileID: fixture.harness.profile.id,
            transport: nil,
            hasSecrets: true,
        ), secrets: payload) }
        await gate.wait()
        let replacement = Task { try await fixture.call(.stop(profileID: fixture.harness.profile.id, reason: .userRequested)) }
        while await fixture.harness.controller.currentGeneration.rawValue < 2 {
            await Task.yield()
        }
        await gate.release()
        #expect(try await first.value == .error(.tunnel(.cancelled)))
        #expect(try await replacement.value == .ok)
        #expect(await fixture.harness.controller.status.phase == .idle)
    }

    @Test
    func `settings transport boot intent and profile removal route through the service`() async throws {
        let fixture = try CompositionFixture(harness: ControllerHarness()); try await fixture.connect()
        _ = try await fixture.installAndStart()
        var settings = MacGlobalSettings.defaults; settings.lockdown = true
        #expect(try await fixture.call(.setGlobalSettings(settings)) == .ok)
        #expect(fixture.harness.journal.snapshot().protectionOwnerUID == 501)
        #expect(try await fixture.call(.selectTransport(profileID: fixture.harness.profile.id, transport: nil)) == .ok)
        #expect(try await fixture.call(.setStartBeforeLoginIntent(profileID: fixture.harness.profile.id, enabled: true)) == .ok)
        #expect(try await fixture.harness.registry.bootIntent()?.profileID == fixture.harness.profile.id)
        guard case .statistics = try await fixture.call(.statistics) else { throw HostTestError.injected }
        #expect(try await fixture.call(.removeProfile(fixture.harness.profile.id, purgeSecrets: true)) == .ok)
        #expect(await fixture.harness.controller.activeProfileID() == nil)
        #expect(try await fixture.harness.registry.ownerUID(for: fixture.harness.profile.id) == nil)
        #expect(await fixture.harness.controller.status.protection == .blocked)
        #expect(try await fixture.call(.uninstall(purgeState: false)) == .ok)
        #expect(fixture.harness.journal.snapshot().uninstall?.completed == true)
    }

    private func assertNoRetainedFixtureBytes(_ harness: ControllerHarness) throws {
        let raw = Data((1 ... 32).map(UInt8.init))
        let hex = raw.map { String(format: "%02x", $0) }.joined()
        let patterns = [raw, raw.base64EncodedData(), Data(hex.utf8)]
        let enumerator = FileManager.default.enumerator(at: harness.root, includingPropertiesForKeys: [.isRegularFileKey])
        while let url = enumerator?.nextObject() as? URL {
            if try url.resourceValues(forKeys: [.isRegularFileKey]).isRegularFile == true {
                let retained = try Data(contentsOf: url)
                #expect(patterns.allSatisfy { retained.range(of: $0) == nil })
            }
        }
    }
}

package extension Reply {
    var statusProtection: ProtectionState? {
        if case let .status(status) = self {
            return status.protection
        }
        return nil
    }
}
