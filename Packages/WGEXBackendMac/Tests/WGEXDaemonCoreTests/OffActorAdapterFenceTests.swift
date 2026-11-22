// SPDX-License-Identifier: MIT
import Foundation
import Testing
import WGEXCore
@testable import WGEXDaemonCore
import WGEXDaemonProtocol

/// M1-25 fix pass 1: the remaining adapter calls that moved off the controller actor (the reality inspector, undo's
/// address removal and the changed-underlay configure) each get the generation fence on resumption, and a test that
/// parks a call there while a control, or the watchdog, supersedes the operation.
@Suite(.timeLimit(.minutes(1)))
private struct OffActorAdapterFenceTests {
    fileprivate enum Reality: String, CaseIterable, Sendable { case inspect, removeOwned }
    fileprivate enum Control: String, CaseIterable, Sendable { case stop, settings }

    private static var lockdown: MacGlobalSettings {
        var settings = MacGlobalSettings.defaults; settings.lockdown = true
        return settings
    }

    /// A rebooted daemon whose reconciliation is parked inside the reality adapter, when a recovery control arrives. The
    /// stale stage resumes into a newer control identity: it must not go on to the next adapter call or the next step.
    @Test(arguments: Reality.allCases, Control.allCases)
    func `a recovery control arriving while reconciliation is parked in the reality adapter fences the stale stage`(
        _ point: Reality, _ control: Control,
    ) async throws {
        let gate = StepGate(point: .inspectReality)
        let rig = try await BootRig.make()
        let harness = rig.harness, controller = rig.controller
        switch point {
        case .inspect: await harness.ports.suspendInspect(using: gate)
        case .removeOwned: await harness.ports.suspendRemoveOwned(using: gate)
        }
        let removedBefore = await harness.ports.removeOwnedCalls
        let run = rig.run()
        defer { run.cancel(); Task { await rig.runtime.stop(); await gate.release() } }
        await gate.wait()
        let generation = await controller.currentGeneration
        let settings = Self.lockdown
        let request = Watched {
            switch control {
            case .stop: _ = try await controller.stop(profileID: harness.profile.id, connectionUID: ControllerHarness.uid)
            case .settings: try await controller.setGlobalSettings(settings, connectionUID: ControllerHarness.uid)
            }
        }
        try await waitForCondition { await controller.currentGeneration != generation }
        await gate.release()
        _ = try await request.outcome()
        try await waitForCondition { await rig.runtime.isRecovering == false }

        // Parked at inspect, the stale stage never reaches removeOwned: the control's own reconciliation removes once.
        // Parked at removeOwned, that call was already issued: it and the control's own make two.
        let removed = await harness.ports.removeOwnedCalls - removedBefore
        #expect(removed == (point == .inspect ? 1 : 2), "removeOwned was called \(removed) times")
        let document = try DaemonJournal(directory: harness.directory).snapshot()
        switch control {
        case .stop:
            #expect(await controller.status.phase == .idle)
            #expect(await controller.engines.isEmpty)
            #expect(document.resources.isEmpty)
            #expect(document.intent == nil)
        case .settings:
            let current = await controller.currentGeneration
            #expect(await controller.status.phase.isActive)
            #expect(await controller.settings.lockdown)
            #expect(await controller.engines.keys.map(\.self) == [current])
            #expect(document.resources.map(\.generation) == [current])
        }
        #expect(harness.trace.calls.contains("pf.disconnected") == (control == .stop))
    }

    @Test
    func `an expiry inside the reality adapter names its step in the timing line`() async throws {
        let gate = StepGate(point: .inspectReality)
        let rig = try await BootRig.make()
        let harness = rig.harness
        await harness.ports.suspendInspect(using: gate)
        let run = rig.run()
        defer { run.cancel(); Task { await rig.runtime.stop(); await gate.release() } }
        await gate.wait()
        try await rig.waitForPendingSleep(.seconds(60))
        harness.clock.advance(.seconds(60))
        try await rig.waitForPendingSleep(.seconds(5))
        // Stage 1 now logs its own steps, so a stall in reconciliation is named instead of reading "none".
        #expect(rig.log.expiries == ["operation expired, last step=inspectReality"])
        #expect(rig.log.lines.contains { $0.hasPrefix("step inspectReality begin +") })
        #expect(await harness.ports.policy == .error)
        #expect(await rig.controller.status.protection == .blocked)
    }

    /// Undo's address removal parked when the watchdog abandons the generation: the stale rollback goes no further.
    @Test
    func `an expiry while undo is parked in the address removal stops the stale rollback`() async throws {
        let gate = StepGate(point: .configureInterface)
        let harness = try ControllerHarness()
        try await harness.install()
        await harness.ports.suspendRemoveAddresses(using: gate)
        harness.trace.fail(at: "routes.install")
        let start = Watched { try await harness.start() }
        defer { start.cancel(); Task { await gate.release() } }
        await gate.wait()
        try await waitForCondition { harness.clock.pendingSleeps.contains(.seconds(60)) }
        harness.clock.advance(.seconds(60))
        _ = try await start.outcome()
        let abandoned = await harness.controller.status
        let baseline = harness.trace.calls.count
        #expect(try DaemonJournal(directory: harness.directory).snapshot().resources.count == 1)

        await gate.release()
        try await waitForCondition { await harness.ports.removeAddressesReturned == 1 }
        for _ in 0 ..< 50 {
            _ = await harness.controller.currentGeneration
        }
        let after = harness.trace.calls.dropFirst(baseline)
        #expect(after.contains("engine.down") == false, "the stale rollback went on to the engine")
        #expect(after.contains("engine.shutdown") == false, "the stale rollback went on to the engine")
        // The abandoned generation's record stays for the next reconciliation, and nothing was published over the expiry.
        #expect(try DaemonJournal(directory: harness.directory).snapshot().resources.count == 1)
        #expect(await harness.controller.status == abandoned)
        #expect(await harness.ports.policy != .disconnected)
    }

    fileprivate enum Park: String, CaseIterable, Sendable { case canaryRoute, configure }
    fileprivate enum Superseder: String, CaseIterable, Sendable { case stop, start }

    /// A path change reaches `configureChangedUnderlay` through the maintenance slot. Its epoch is taken before the first
    /// await, so a stop or a new start that arrives while it is parked (at the canary route or at the configure) fences it.
    @Test(arguments: Park.allCases, Superseder.allCases)
    func `a stop or a new start arriving during the changed-underlay configure fences the stale maintenance`(
        _ park: Park, _ superseder: Superseder,
    ) async throws {
        let gate = StepGate(point: park == .canaryRoute ? .installRoutes : .configureInterface)
        let harness = try ControllerHarness()
        try await harness.install(); _ = try await harness.start()
        let before = calls(harness)
        switch park {
        case .canaryRoute: await harness.ports.suspend(using: gate)
        case .configure: await harness.ports.suspendConfigure(using: gate)
        }
        // A new primary interface with a router: the canary route differs, so the routes are reprogrammed first.
        let underlay = UnderlaySnapshot(
            v4: 4, v6: 6, resolvers: ["192.0.2.53"], interfaceNames: ["underlay-test"],
            interfaceV4Name: "underlay-test", ipv4Router: "192.0.2.254",
        )
        let path = Watched { try await harness.controller.pathChanged(underlay, satisfied: true) }
        defer { path.cancel(); Task { await gate.release() } }
        await gate.wait()
        let generation = await harness.controller.currentGeneration
        let controller = harness.controller
        let uid = ControllerHarness.uid, profile = harness.profile.id
        let other = Watched {
            switch superseder {
            case .stop: _ = try await controller.stop(profileID: profile, connectionUID: uid)
            case .start: _ = try await controller.start(profileID: profile, connectionUID: uid, secrets: ControllerHarness.bundle())
            }
        }
        try await waitForCondition { await controller.currentGeneration != generation }
        await gate.release()
        _ = try await other.outcome()
        _ = try await path.outcome()

        // The stale maintenance configures at most once (when parked there) and never confirms; a new start adds its own.
        let now = calls(harness)
        let staleConfigure = park == .configure ? 1 : 0
        let own = superseder == .start ? 1 : 0
        #expect(now.configure - before.configure == staleConfigure + own, "device.configure calls")
        #expect(now.confirm - before.confirm == own, "device.confirm calls")
        let document = try DaemonJournal(directory: harness.directory).snapshot()
        let current = await controller.currentGeneration
        switch superseder {
        case .stop:
            #expect(await controller.status.phase == .idle)
            #expect(await controller.engines.isEmpty)
            #expect(document.resources.isEmpty)
        case .start:
            #expect(await controller.status.phase.isActive)
            #expect(await controller.engines.keys.map(\.self) == [current])
            #expect(document.resources.map(\.generation) == [current])
        }
    }

    private func calls(_ harness: ControllerHarness) -> (configure: Int, confirm: Int) {
        let calls = harness.trace.calls
        return (calls.filter { $0 == "device.configure" }.count, calls.filter { $0 == "device.confirm" }.count)
    }
}
