// SPDX-License-Identifier: MIT
import Foundation
import Testing
import WGEXCore
@testable import WGEXDaemonCore
import WGEXDaemonProtocol
import WGEXEngineInterface

/// M05-T16: an underlay event seen while the uninstall fence is up is recorded with no policy work, and the fresh install
/// that clears the marker applies it, so the next start binds the real interface without a daemon restart. Fakes only.
private struct UninstallUnderlayTests {
    /// The interface the path monitor reports after the fenced launch; the harness launches on index 4.
    static let moved = UnderlaySnapshot(v4: 8, v6: nil, resolvers: ["198.51.100.53"], interfaceNames: ["moved0"])

    @Test
    func `fenced launch, underlay event, fresh install: the start binds the recorded interface`() async throws {
        let (harness, relaunched, second) = try await Self.fencedLaunch()
        let mark = harness.trace.calls.count
        let older = UnderlaySnapshot(v4: 7, v6: nil, resolvers: ["198.51.100.7"], interfaceNames: ["older0"])
        try await relaunched.networkChanged(trigger: .configuration, underlay: .init(snapshot: older, satisfied: true))
        try await relaunched.networkChanged(trigger: .route, underlay: .init(snapshot: Self.moved, satisfied: true, mtu: 1400))
        // Recorded only: no pf, route, DNS or engine call, and the applied underlay is still the launch one.
        #expect(Self.networkFree(harness.trace.calls.dropFirst(mark)))
        #expect(await relaunched.underlay == ControllerHarness.underlay)
        #expect(await relaunched.uninstallRun.underlay?.snapshot == Self.moved)
        try await Self.freshInstall(harness, second)
        #expect(await relaunched.underlay == Self.moved)
        #expect(await relaunched.underlayMTU == 1400)
        #expect(await relaunched.uninstallRun.underlay == nil)
        _ = try await second.installAndStart()
        let configuration = try #require(await harness.ports.configurations.last)
        #expect(configuration.bindInterfaceIndexV4 == 8 && configuration.bindInterfaceIndexV6 == 8)
        #expect(await harness.ports.modifiers.last?.underlay == Self.moved)
        #expect(await relaunched.status.protection == .protected)
    }

    @Test
    func `fenced with no underlay event the fresh install behaves as before`() async throws {
        let (harness, relaunched, second) = try await Self.fencedLaunch()
        let mark = harness.trace.calls.count
        try await relaunched.networkChanged(trigger: .periodic)
        #expect(Self.networkFree(harness.trace.calls.dropFirst(mark)))
        #expect(await relaunched.uninstallRun.underlay == nil)
        try await Self.freshInstall(harness, second)
        #expect(await relaunched.underlay == ControllerHarness.underlay)
        _ = try await second.installAndStart()
        let configuration = try #require(await harness.ports.configurations.last)
        #expect(configuration.bindInterfaceIndexV4 == 4 && configuration.bindInterfaceIndexV6 == 6)
        #expect(await relaunched.status.protection == .protected)
    }

    @Test
    func `an event in the uninstalling launch is recorded and applied by the fresh install too`() async throws {
        let harness = try ControllerHarness()
        let fixture = CompositionFixture(harness: harness)
        try await fixture.connect()
        _ = try await fixture.installAndStart()
        #expect(try await fixture.call(.uninstall(purgeState: false)) == .ok)
        let mark = harness.trace.calls.count
        try await harness.controller.networkChanged(trigger: .configuration, underlay: .init(snapshot: Self.moved, satisfied: true))
        #expect(Self.networkFree(harness.trace.calls.dropFirst(mark)))
        try await Self.freshInstall(harness, fixture)
        #expect(await harness.controller.underlay == Self.moved)
        #expect(await harness.controller.uninstallRun.underlay == nil)
    }

    @Test
    func `before the uninstall completes a secure install keeps the event recorded and applies nothing`() async throws {
        let harness = try ControllerHarness()
        let fixture = CompositionFixture(harness: harness)
        try await fixture.connect()
        _ = try await fixture.installAndStart()
        await harness.controller.setUninstallStepHook { step in
            if step == .daemonSecrets {
                throw HostTestError.injected
            }
        }
        #expect(try await fixture.call(.uninstall(purgeState: false)) == .error(.uninstallFailed(step: .daemonSecrets)))
        let mark = harness.trace.calls.count
        try await harness.controller.networkChanged(trigger: .configuration, underlay: .init(snapshot: Self.moved, satisfied: true))
        #expect(try await fixture.call(.performSecureInstall) == .error(.uninstallFailed(step: .admission)))
        #expect(Self.networkFree(harness.trace.calls.dropFirst(mark)))
        #expect(await harness.controller.underlay == ControllerHarness.underlay)
        #expect(await harness.controller.uninstallRun.underlay?.snapshot == Self.moved)
    }
}

private extension UninstallUnderlayTests {
    /// Calls that would mean the daemon touched pf, routes, DNS or an engine.
    static func networkFree(_ calls: some Sequence<String>) -> Bool {
        calls.allSatisfy { call in !["pf.", "routes.", "dns.", "engine.", "device."].contains { call.hasPrefix($0) } }
    }

    /// A completed keep uninstall, then a new launch brought up inert the way DaemonRuntime does it.
    static func fencedLaunch() async throws -> (ControllerHarness, TunnelController, CompositionFixture) {
        let harness = try ControllerHarness()
        let fixture = CompositionFixture(harness: harness)
        try await fixture.connect()
        _ = try await fixture.installAndStart()
        #expect(try await fixture.call(.uninstall(purgeState: false)) == .ok)
        let relaunched = try harness.replacementController()
        await relaunched.markStartupRecovering()
        try await relaunched.prepareStartupBlocking()
        try await relaunched.reconcileAtStartup()
        try await relaunched.verifyRecoveryProtection()
        let second = CompositionFixture(harness: harness, controller: relaunched)
        try await second.connect()
        return (harness, relaunched, second)
    }

    /// The verified secure install that clears the marker.
    static func freshInstall(_ harness: ControllerHarness, _ fixture: CompositionFixture) async throws {
        guard case .secureInstall = try await fixture.call(.performSecureInstall) else { throw HostTestError.injected }
        #expect(try DaemonJournal(directory: StateDirectory(root: harness.root)).snapshot().uninstall == nil)
    }
}
