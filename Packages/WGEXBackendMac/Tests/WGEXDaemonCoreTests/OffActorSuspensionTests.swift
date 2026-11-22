// SPDX-License-Identifier: MIT
import Foundation
import Synchronization
import Testing
import WGEXCore
@testable import WGEXDaemonCore
import WGEXDaemonProtocol

/// M1-25 F2: the engine create, the interface configure and the post-configure identity read run off the controller
/// actor. Each is a new suspension point, so each is tested for responsiveness and for the generation fence on resumption.
@Suite(.timeLimit(.minutes(1)))
private struct OffActorSuspensionTests {
    fileprivate enum Point: String, CaseIterable, Sendable { case create, configure, confirm, verify }
    fileprivate enum Interference: String, CaseIterable, Sendable { case stop, settings, start }
    fileprivate enum Context: String, CaseIterable, Sendable { case user, boot }

    @Test(arguments: [Point.create, .configure, .confirm])
    func `a blocking adapter call does not stall the controller actor`(_ point: Point) async throws {
        let block = ThreadBlock()
        let harness = try ControllerHarness(portsTransform: { ports in
            DaemonPorts(
                engineFactory: point == .create ? BlockingEngineFactory(base: ports.engineFactory, block: block) : ports.engineFactory,
                routes: ports.routes, dns: ports.dns, policy: ports.policy, resolver: ports.resolver,
                device: point == .create ? ports.device : BlockingDevice(
                    base: ports.device, point: point == .configure ? .configure : .confirm, block: block,
                ),
                verifier: ports.verifier, reality: ports.reality,
            )
        })
        try await harness.install()
        let start = Task { try await harness.start() }
        defer { block.open() }
        try await waitForCondition { block.entered }
        // The adapter now holds its thread. A status read and the generation must still be answered.
        let answered = Mutex(false)
        let probe = Task {
            _ = await harness.controller.status; _ = await harness.controller.currentGeneration
            answered.withLock { $0 = true }
        }
        // Together with the 30 s adapter-entry wait, leave 10 s of the suite's minute for setup and cleanup.
        let probeDeadline = ContinuousClock.now + .seconds(20)
        while !answered.withLock({ $0 }), ContinuousClock.now < probeDeadline {
            try await Task.sleep(for: .milliseconds(10))
        }
        #expect(answered.withLock { $0 }, "the controller actor did not answer while \(point.rawValue) held its thread")
        block.open()
        _ = try await start.value
        await probe.value
        #expect(await harness.controller.status.phase.isActive)
    }

    fileprivate struct Scenario: Sendable, CustomTestStringConvertible {
        let point: Point, interference: Interference, context: Context
        var testDescription: String {
            "\(context.rawValue) start, \(interference.rawValue) during \(point.rawValue)"
        }

        static let all = Context.allCases.flatMap { context in
            Point.allCases.flatMap { point in
                Interference.allCases.map { Scenario(point: point, interference: $0, context: context) }
            }
        }

        /// The parked run is superseded (its generation fence trips) rather than carried on.
        var supersedes: Bool {
            (context == .user && interference != .settings) || (context == .boot && interference != .start)
        }

        /// A newer run starts after the parked one: a second user start, or the recovery restart a settings change asks for.
        var restarts: Bool {
            (context == .user && interference == .start) || (context == .boot && interference == .settings)
        }

        /// Device calls over the whole scenario. A superseded run reaches the point it was parked at and no further; a
        /// run that restarts goes through both again.
        var expectedCalls: (configure: Int, confirm: Int) {
            guard supersedes else { return (1, 1) }
            let stale = switch point {
            case .create: (0, 0)
            case .configure: (1, 0)
            case .confirm, .verify: (1, 1)
            }
            return restarts ? (stale.0 + 1, stale.1 + 1) : (stale.0, stale.1)
        }
    }

    /// A start parked inside one adapter call, in the user's context or in a rebooted daemon's recovery.
    private struct Parked {
        let scenario: Scenario
        let harness: ControllerHarness
        let controller: TunnelController
        let rig: BootRig?
        let gate: StepGate
        let first: Watched<Generation>?
        let run: Task<Void, Never>?
        let baseline: (configure: Int, confirm: Int)

        init(_ scenario: Scenario) async throws {
            self.scenario = scenario
            let step: DaemonStep = switch scenario.point {
            case .create: .createEngine
            case .configure, .confirm: .configureInterface
            case .verify: .verify
            }
            gate = StepGate(point: step)
            rig = scenario.context == .boot ? try await BootRig.make() : nil
            harness = try rig?.harness ?? ControllerHarness()
            controller = rig?.controller ?? harness.controller
            if rig == nil {
                try await harness.install()
            }
            switch scenario.point {
            case .create: await harness.ports.suspend(using: gate)
            case .configure: await harness.ports.suspendConfigure(using: gate)
            case .confirm: await harness.ports.suspendConfirm(using: gate)
            case .verify: await harness.ports.suspendVerify(using: gate)
            }
            baseline = Self.deviceCalls(harness)
            run = rig?.run()
            let harness = harness
            first = rig == nil ? Watched { try await harness.start() } : nil
            await gate.wait()
        }

        static func deviceCalls(_ harness: ControllerHarness) -> (configure: Int, confirm: Int) {
            let calls = harness.trace.calls
            return (calls.filter { $0 == "device.configure" }.count, calls.filter { $0 == "device.confirm" }.count)
        }

        func teardown() {
            run?.cancel()
            let rig = rig, gate = gate
            Task { await rig?.runtime.stop(); await gate.release() }
        }

        /// The interfering request, issued while the run is parked.
        func interfere() -> Watched<Void> {
            let controller = controller, profile = harness.profile.id, uid = ControllerHarness.uid
            var settings = MacGlobalSettings.defaults; settings.lockdown = true
            let lockdown = settings
            switch scenario.interference {
            case .stop: return Watched { _ = try await controller.stop(profileID: profile, connectionUID: uid) }
            case .settings: return Watched { try await controller.setGlobalSettings(lockdown, connectionUID: uid) }
            case .start:
                return Watched { _ = try await controller.start(
                    profileID: profile, connectionUID: uid, secrets: ControllerHarness.bundle(),
                ) }
            }
        }

        /// Waits until the interfering request has demonstrably reached the controller, so it always arrives while the run is
        /// parked: most reserve a new generation on entry; a refused boot-time start finishes at once; a user settings change
        /// only queues behind the start and leaves nothing to observe.
        func awaitArrival(of other: Watched<Void>, parked generation: Generation) async throws {
            switch (scenario.interference, scenario.context) {
            case (.settings, .user):
                for _ in 0 ..< 1000 {
                    await Task.yield()
                }
            case (.start, .boot): _ = try await other.outcome()
            default:
                let controller = controller
                try await waitForCondition { await controller.currentGeneration != generation }
            }
        }

        func assertOutcome(of result: Result<Void, any Error>) async throws {
            let expected = scenario.expectedCalls, now = Self.deviceCalls(harness)
            #expect((now.configure - baseline.configure, now.confirm - baseline.confirm) == expected, "device calls")
            let state = await controller.status, generation = await controller.currentGeneration
            let document = try DaemonJournal(directory: harness.directory).snapshot()
            if scenario.interference == .stop {
                _ = try result.get()
                #expect(state.phase == .idle)
                #expect(await controller.engines.isEmpty)
                #expect(document.resources.isEmpty)
                #expect(await harness.ports.routeItems.isEmpty)
                #expect(await harness.ports.dnsItems.isEmpty)
                return
            }
            if scenario.interference == .start, scenario.context == .boot {
                #expect(throws: DaemonFailure.controllerRecoveryRequired) { _ = try result.get() }
            } else {
                _ = try result.get()
            }
            #expect(state.phase.isActive)
            #expect(state.protection == .protected)
            #expect(await controller.engines.keys.map(\.self) == [generation])
            #expect(document.resources.map(\.generation) == [generation])
            if scenario.interference == .settings {
                #expect(await controller.settings.lockdown)
            }
        }
    }

    @Test(arguments: Scenario.all)
    func `stop settings and a new start arriving at each off-actor suspension keep the generation fence`(
        _ scenario: Scenario,
    ) async throws {
        let parked = try await Parked(scenario)
        defer { parked.teardown() }
        let generation = await parked.controller.currentGeneration
        let other = parked.interfere()
        try await parked.awaitArrival(of: other, parked: generation)
        await parked.gate.release()
        // Bounded waits: a regression that parks either request fails here instead of hanging the run.
        let result = try await other.outcome()
        let first = try await parked.first?.outcome()
        if scenario.interference == .start, scenario.context == .user {
            #expect(first?.isFailure == true, "the superseded start must not report success")
        }
        if let rig = parked.rig {
            try await waitForCondition { await rig.runtime.isRecovering == false }
        }
        try await parked.assertOutcome(of: result)
    }
}

private extension Result {
    var isFailure: Bool {
        if case .failure = self {
            true
        } else {
            false
        }
    }
}
