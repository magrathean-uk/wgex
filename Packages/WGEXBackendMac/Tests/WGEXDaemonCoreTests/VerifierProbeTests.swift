// SPDX-License-Identifier: MIT
import Foundation
import Synchronization
import Testing
import WGEXCore
@testable import WGEXDaemonCore

@Suite(.timeLimit(.minutes(1)))
private struct VerifierProbeTests {
    @Test
    func `probe idle underlay change reaches the controller`() async throws {
        let harness = try ControllerHarness()
        try await harness.install()
        #expect(harness.journal.snapshot().pfPolicy == .disconnected)
        let moved = UnderlaySnapshot(v4: 8, v6: nil, resolvers: ["198.51.100.53"], interfaceNames: ["moved0"])
        try await harness.controller.networkChanged(trigger: .configuration, underlay: .init(snapshot: moved, satisfied: true))
        let seen = await harness.controller.underlay
        #expect(seen == moved, "controller underlay after idle change: \(seen.interfaceNames) \(seen.resolvers)")
    }

    @Test
    func `probe persistent restart failures saturate at sixty seconds`() async throws {
        let harness = try ControllerHarness()
        try await harness.install()
        harness.trace.fail(at: "engine.up")
        await #expect(throws: (any Error).self) { _ = try await harness.start() }
        var generations: [UInt64] = await [harness.controller.currentGeneration.rawValue]
        var elapsed = 0
        var restartsAt: [Int] = []
        for _ in 0 ..< 200 {
            harness.clock.advance(.seconds(1)); elapsed += 1
            harness.trace.fail(at: "engine.up")
            try? await harness.controller.tick()
            let now = await harness.controller.currentGeneration.rawValue
            if now != generations.last {
                restartsAt.append(elapsed); generations.append(now)
            }
        }
        let gaps = zip(restartsAt, [0] + restartsAt).map { $0 - $1 }
        #expect(gaps.dropFirst(3).allSatisfy { $0 >= 60 }, "restart gaps: \(gaps)")
        #expect(gaps.first == 5, "restart gaps: \(gaps)")
    }

    @Test
    func `probe fail after active cycles on the five second step`() async throws {
        let harness = try ControllerHarness()
        try await harness.install(); _ = try await harness.start()
        var activeAt: [Int] = []
        var elapsed = 0
        for _ in 0 ..< 120 {
            harness.clock.advance(.seconds(1)); elapsed += 1
            if case .active = await harness.controller.status.phase {
                harness.trace.fail(at: "verify")
            }
            try? await harness.controller.tick()
            if case .active = await harness.controller.status.phase {
                activeAt.append(elapsed)
            }
        }
        let calls = harness.trace.calls.filter { $0 == "verify" }.count
        #expect(calls < 10, "verify calls in 120 s while flapping: \(calls); active seconds: \(activeAt.count)")
    }

    @Test
    func `probe one transient journal write error fences later mutations`() throws {
        let harness = try ControllerHarness(), fail = Mutex(false)
        let directory = try StateDirectory(root: harness.root, observingWrites: { _ in
            if fail.withLock({ $0 }) {
                throw HostTestError.injected
            }
        })
        let journal = try DaemonJournal(directory: directory)
        let generation = try journal.allocate(intent: nil)
        fail.withLock { $0 = true }
        #expect(throws: (any Error).self) { try journal.mutate(generation: generation) { $0.pfPolicy = .lockdown } }
        fail.withLock { $0 = false }
        var later: any Error?
        do { try journal.mutate(generation: generation) { $0.pfPolicy = .error } } catch { later = error }
        #expect(later == nil, "mutation after the transient error: \(String(describing: later))")
    }
}
