// SPDX-License-Identifier: MIT
import Testing
import WGEXCore
@testable import WGEXDaemonCore
import WGEXDaemonProtocol

@Suite(.timeLimit(.minutes(1)))
private struct VerifierDeadlineTests {
    @Test
    func `all endpoint resolution shares a deadline below the client request deadline`() async throws {
        let harness = try ControllerHarness(), gate = StepGate(point: .resolve)
        try await harness.install(); await harness.ports.suspend(using: gate)
        let start = Task { try await harness.start() }; await gate.wait()
        for _ in 0 ..< 4000 where !harness.clock.pendingSleeps.contains(.seconds(12)) {
            await Task.yield()
        }
        try #require(harness.clock.pendingSleeps.contains(.seconds(12)))
        harness.clock.advance(.seconds(12))
        await #expect(throws: DaemonFailure.startup(.resolverUnavailable)) { _ = try await start.value }
        #expect(await harness.controller.status.recoveryFailureReason?.rawValue == 4)
        #expect(await harness.controller.status.protection == .blocked)
        await gate.release()
    }

    @Test
    func `watchdog uses awake clock independently from captive continuous time`() async throws {
        let awake = HostClock(), gate = StepGate(point: .installRoutes)
        let harness = try ControllerHarness(gate: gate, watchdogClock: awake)
        try await harness.install()
        let start = Task { try await harness.start() }; await gate.wait()
        let epoch = await harness.controller.currentGeneration
        harness.clock.advance(.seconds(3600))
        for _ in 0 ..< 2000 {
            await Task.yield()
        }
        #expect(await harness.controller.currentGeneration == epoch)
        #expect(await harness.controller.operation != nil)
        await gate.release(); _ = try await start.value
    }

    @Test
    func `tick startup retries use ordered five fifteen sixty backoff`() async throws {
        let harness = try ControllerHarness(underlay: .init(v4: nil, v6: nil, resolvers: [], interfaceNames: []))
        try await harness.install()
        try harness.journal.mutate(generation: nil) { $0.intent = TunnelIntent(profileID: harness.profile.id, ownerUID: 501) }
        try await harness.controller.recoveryFailed(.noPrimaryInterface)
        await #expect(throws: (any Error).self) { try await harness.controller.tick() }
        var previousAttempt = await harness.controller.startup.tickRetryAttempt
        #expect(previousAttempt == 1)
        for delay in [5, 15, 60] {
            harness.clock.advance(.seconds(delay - 1)); try await harness.controller.tick()
            #expect(await harness.controller.startup.tickRetryAttempt == previousAttempt)
            harness.clock.advance(.seconds(1))
            await #expect(throws: (any Error).self) { try await harness.controller.tick() }
            previousAttempt += 1
            #expect(await harness.controller.startup.tickRetryAttempt == previousAttempt)
            #expect(await harness.controller.status.recoveryFailureReason?.rawValue == 1)
        }
    }

    @Test
    func `failed secret deletion is attempted and replayed after restart`() async throws {
        let harness = try ControllerHarness(); try await harness.install(); _ = try await harness.start()
        harness.trace.fail(at: "secrets.delete")
        await #expect(throws: DaemonFailure.controllerOperationFailed) {
            try await harness.controller.stop(profileID: harness.profile.id, connectionUID: 501)
        }
        #expect(harness.trace.calls.filter { $0 == "secrets.delete" }.count == 1)
        #expect(harness.journal.snapshot().pendingSecretDeletions == [harness.profile.id])
        #expect(await harness.controller.status.recoveryFailureReason?.rawValue == 6)
        let before = try await harness.store.loadBundle(profileID: harness.profile.id)
        #expect(before.count > 32)
        let replacement = try harness.replacementController(); try await replacement.reconcileAtStartup()
        #expect(try DaemonJournal(directory: harness.directory).snapshot().pendingSecretDeletions.isEmpty)
        await #expect(throws: (any Error).self) { _ = try await harness.store.loadBundle(profileID: harness.profile.id) }
    }
}

@Suite(.timeLimit(.minutes(1)))
private struct EndpointLookupFailureTests {
    @Test(arguments: [false, true])
    func `failed lookup has a named wire refusal and cutover rolls back without abort`(_ cutover: Bool) async throws {
        let harness = try ControllerHarness()
        try await harness.install()
        harness.trace.fail(at: "resolver.resolve")
        do {
            if cutover {
                _ = try await harness.controller.startCutover(
                    profileID: harness.profile.id, connectionUID: ControllerHarness.uid,
                    confirmWithin: 60, secrets: ControllerHarness.bundle(),
                )
            } else {
                _ = try await harness.start()
            }
            Issue.record("lookup failure was accepted")
        } catch let failure as DaemonFailure {
            #expect(failure == .startup(.resolverUnavailable))
            #expect(failure.wireError() == .protectionUnknown(reason: "underlayResolverNoAnswer"))
        }
        #expect(harness.journal.snapshot().resources.isEmpty)
        #expect(!harness.trace.calls.contains("engine.create"))
        if cutover {
            #expect(await harness.controller.status.cutover == .rolledBack(reason: .startFailed))
            #expect(await harness.controller.status.protection == .unprotected)
            #expect(harness.journal.snapshot().pfToken == nil)
        } else {
            #expect(await harness.controller.status.protection == .blocked)
        }
        // The failed attempt leaves no serial-slot hang: a fresh request may resolve and start.
        _ = try await harness.start()
        #expect(await harness.controller.status.protection == .protected)
    }

    @Test(arguments: [false, true])
    func `start falls back to a last good endpoint when lookup fails`(_ cutover: Bool) async throws {
        let harness = try ControllerHarness()
        try await harness.install()
        try harness.journal.mutate(generation: nil) { $0.lastGoodAddresses["peer.example.test"] = ["192.0.2.9"] }
        harness.trace.fail(at: "resolver.resolve")
        if cutover {
            _ = try await harness.controller.startCutover(
                profileID: harness.profile.id, connectionUID: ControllerHarness.uid,
                confirmWithin: 60, secrets: ControllerHarness.bundle(),
            )
        } else {
            _ = try await harness.start()
        }
        #expect(await harness.controller.status.protection == .protected)
        #expect(harness.trace.calls.contains("engine.create"))
        #expect(await harness.controller.selectedEndpoints.values.map(\.host) == ["192.0.2.9"])
    }

    @Test
    func `cutover deadline rolls back even when a resolver ignores cancellation`() async throws {
        let harness = try ControllerHarness(), gate = StepGate(point: .resolve)
        try await harness.install(); await harness.ports.suspend(using: gate)
        let start = Task {
            try await harness.controller.startCutover(
                profileID: harness.profile.id, connectionUID: ControllerHarness.uid,
                confirmWithin: 60, secrets: ControllerHarness.bundle(),
            )
        }
        await gate.wait()
        try await waitForCondition { harness.clock.pendingSleeps.contains(.seconds(12)) }
        harness.clock.advance(.seconds(12))
        await #expect(throws: DaemonFailure.startup(.resolverUnavailable)) { _ = try await start.value }
        #expect(await harness.controller.status.cutover == .rolledBack(reason: .startFailed))
        #expect(await harness.controller.status.protection == .unprotected)
        #expect(harness.journal.snapshot().pfToken == nil)
        await gate.release()
        _ = try await harness.start()
        #expect(await harness.controller.status.protection == .protected)
    }
}
