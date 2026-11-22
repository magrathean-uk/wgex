// SPDX-License-Identifier: MIT
import Foundation
import Synchronization
import Testing
import WGEXCore
@testable import WGEXDaemonCore
import WGEXDaemonCoreTesting
import WGEXDaemonProtocol
import WGEXEngineInterface

/// Counts producer starts of the underlay notification adapter; the events themselves come from the inert fixture.
private final class CountingUnderlayMonitor: UnderlayMonitoring {
    let inner = FakeUnderlayMonitor()
    let starts = Mutex(0)

    func start() async throws -> AsyncStream<UnderlayEvent> {
        starts.withLock { $0 += 1 }
        return inner.start()
    }

    func stop() async {
        inner.stop()
    }
}

/// M05-T18: a daemon launched with the uninstall marker stays inert, and the fresh install that clears the marker runs the
/// same startup sequence a normal launch runs (underlay read, startup protection, monitors, reconciliation) through
/// DaemonRuntime and DaemonComposition. Fakes only, at runtime level.
private struct FencedStartupMonitorTests {
    /// The interface the system reports after the fenced launch; the harness controller launches on index 4.
    static let current = UnderlaySnapshot(v4: 8, v6: nil, resolvers: ["198.51.100.53"], interfaceNames: ["current0"])

    @Test
    func `a fenced launch starts its monitors at the marker clear and the start binds the real interface`() async throws {
        let rig = try await FencedRig()
        let mark = rig.harness.trace.calls.count
        try await rig.launch()
        // Inert while fenced: no pf, route, DNS or engine call, no underlay read, no producer started yet.
        #expect(await rig.runtime.isRecovering == false)
        #expect(rig.underlay.starts.withLock { $0 } == 0)
        #expect(rig.reads.withLock { $0 } == 0)
        #expect(await rig.controller.uninstallFenced)
        #expect(FencedRig.networkFree(rig.harness.trace.calls.dropFirst(mark)))
        try await rig.freshInstall()
        try await rig.settled()
        #expect(rig.underlay.starts.withLock { $0 } == 1)
        #expect(rig.reads.withLock { $0 } >= 1)
        #expect(await rig.controller.underlay == Self.current)
        #expect(await rig.controller.needsRecovery == false)
        _ = try await rig.fixture.installAndStart()
        let configuration = try #require(await rig.harness.ports.configurations.last)
        #expect(configuration.bindInterfaceIndexV4 == 8 && configuration.bindInterfaceIndexV6 == 8)
        #expect(await rig.controller.status.protection == .protected)
        await rig.monitors.stop()
    }

    @Test
    func `a monitor start that fails at the marker clear takes the startup backoff and then starts`() async throws {
        let rig = try await FencedRig(failFirstMonitorStart: true)
        try await rig.launch()
        #expect(rig.monitorAttempts.withLock { $0 } == 0)
        try await rig.freshInstall()
        try await FencedRig.until { rig.monitorAttempts.withLock { $0 } == 1 }
        // The heartbeat sleeps 5 s too; the second 5 s sleeper is the startup backoff.
        try await FencedRig.until { rig.harness.clock.pendingSleeps.filter { $0 == .seconds(5) }.count == 2 }
        // The failed attempt left the runtime recovering, as a normal launch would be, with nothing started.
        #expect(await rig.runtime.isRecovering)
        #expect(rig.underlay.starts.withLock { $0 } == 0)
        rig.harness.clock.advance(.seconds(5))
        try await rig.settled()
        #expect(rig.monitorAttempts.withLock { $0 } == 2)
        #expect(rig.underlay.starts.withLock { $0 } == 1)
        _ = try await rig.fixture.installAndStart()
        let configuration = try #require(await rig.harness.ports.configurations.last)
        #expect(configuration.bindInterfaceIndexV4 == 8)
        await rig.monitors.stop()
    }

    @Test
    func `an uninstall and fresh install in one running daemon re-run startup with the monitors still single`() async throws {
        let harness = try ControllerHarness()
        let fixture = CompositionFixture(harness: harness)
        let runtime = DaemonRuntime(clock: harness.clock)
        let underlay = CountingUnderlayMonitor(), reads = Mutex(0)
        let monitors = DaemonNetworkMonitoring(
            controller: harness.controller, routes: FakeRouteMonitor(), underlay: underlay, power: FakePowerMonitor(),
            login: FakeLoginSessionMonitor(), ownPID: 123, clock: harness.clock,
            readUnderlay: { UnderlayEvent(snapshot: Self.current, satisfied: true) },
        )
        await fixture.composition.run(
            runtime: runtime, startListener: {}, startMonitors: { try await monitors.start() },
            refreshUnderlay: {
                reads.withLock { $0 += 1 }
                await harness.controller.updateStartupUnderlay(UnderlayEvent(snapshot: Self.current, satisfied: true))
            },
        )
        #expect(underlay.starts.withLock { $0 } == 1)
        #expect(reads.withLock { $0 } == 1)
        try await fixture.connect()
        _ = try await fixture.installAndStart()
        #expect(try await fixture.call(.uninstall(purgeState: false)) == .ok)
        guard case .secureInstall = try await fixture.call(.performSecureInstall) else { throw HostTestError.injected }
        try await FencedRig.until {
            let recovering = await runtime.isRecovering, needsRecovery = await harness.controller.needsRecovery
            return !recovering && !needsRecovery && reads.withLock { $0 } == 2
        }
        // The producers already running are not started twice; the underlay was read again and the fence is down.
        #expect(underlay.starts.withLock { $0 } == 1)
        #expect(await harness.controller.underlay == Self.current)
        #expect(await harness.controller.uninstallFenced == false)
        await monitors.stop()
    }

    @Test
    func `before the uninstall completes a secure install leaves the launch inert`() async throws {
        let rig = try await FencedRig(completeUninstall: false)
        let mark = rig.harness.trace.calls.count
        try await rig.launch()
        #expect(try await rig.fixture.call(.performSecureInstall) == .error(.uninstallFailed(step: .admission)))
        #expect(await rig.runtime.isRecovering == false)
        #expect(rig.monitorAttempts.withLock { $0 } == 0)
        #expect(rig.reads.withLock { $0 } == 0)
        #expect(FencedRig.networkFree(rig.harness.trace.calls.dropFirst(mark)))
    }
}

/// A completed (or failed part-way) keep uninstall, then a replacement controller composed and run as the daemon does.
private final class FencedRig: Sendable {
    let harness: ControllerHarness
    let controller: TunnelController
    let fixture: CompositionFixture
    let runtime: DaemonRuntime
    let underlay = CountingUnderlayMonitor()
    let monitors: DaemonNetworkMonitoring
    let reads = Mutex(0)
    let monitorAttempts = Mutex(0)
    private let failFirstMonitorStart: Bool

    init(completeUninstall: Bool = true, failFirstMonitorStart: Bool = false) async throws {
        let harness = try ControllerHarness()
        self.harness = harness
        let first = CompositionFixture(harness: harness)
        try await first.connect()
        _ = try await first.installAndStart()
        if !completeUninstall {
            await harness.controller.setUninstallStepHook { step in
                if step == .daemonSecrets {
                    throw HostTestError.injected
                }
            }
        }
        _ = try await first.call(.uninstall(purgeState: false))
        controller = try harness.replacementController()
        fixture = CompositionFixture(harness: harness, controller: controller)
        runtime = DaemonRuntime(clock: harness.clock)
        monitors = DaemonNetworkMonitoring(
            controller: controller, routes: FakeRouteMonitor(), underlay: underlay, power: FakePowerMonitor(),
            login: FakeLoginSessionMonitor(), ownPID: 123, clock: harness.clock,
            readUnderlay: { UnderlayEvent(snapshot: FencedStartupMonitorTests.current, satisfied: true) },
        )
        self.failFirstMonitorStart = failFirstMonitorStart
    }

    /// Runs the production startup wiring until its first pass returns, as DaemonRuntime+System does.
    func launch() async throws {
        await fixture.composition.run(
            runtime: runtime, startListener: {},
            startMonitors: { [self] in
                let attempt = monitorAttempts.withLock { value -> Int in value += 1; return value }
                if failFirstMonitorStart, attempt == 1 {
                    throw HostTestError.injected
                }
                try await monitors.start()
            },
            refreshUnderlay: { [self] in
                reads.withLock { $0 += 1 }
                await controller.updateStartupUnderlay(UnderlayEvent(snapshot: FencedStartupMonitorTests.current, satisfied: true))
            },
        )
        try await fixture.connect()
    }

    /// The verified secure install that clears the marker.
    func freshInstall() async throws {
        guard case .secureInstall = try await fixture.call(.performSecureInstall) else { throw HostTestError.injected }
        #expect(try DaemonJournal(directory: StateDirectory(root: harness.root)).snapshot().uninstall == nil)
    }

    /// Waits for the startup the marker clear began to finish.
    func settled() async throws {
        try await Self.until { [runtime, controller] in
            let recovering = await runtime.isRecovering, needsRecovery = await controller.needsRecovery
            return !recovering && !needsRecovery
        }
    }

    static func until(_ condition: @Sendable () async -> Bool) async throws {
        for _ in 0 ..< 15000 { // At least 30 s: the full suite runs in parallel under host load.
            if await condition() {
                return
            }
            try await Task.sleep(for: .milliseconds(2))
        }
        Issue.record("condition not reached")
        throw HostTestError.injected
    }

    /// Calls that would mean the daemon touched pf, routes, DNS or an engine.
    static func networkFree(_ calls: some Sequence<String>) -> Bool {
        calls.allSatisfy { call in !["pf.", "routes.", "dns.", "engine.", "device."].contains { call.hasPrefix($0) } }
    }
}
