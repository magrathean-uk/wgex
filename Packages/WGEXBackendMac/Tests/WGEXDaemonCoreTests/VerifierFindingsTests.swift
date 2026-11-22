// SPDX-License-Identifier: MIT
import Foundation
import Synchronization
import Testing
import WGEXCore
@testable import WGEXDaemonCore
import WGEXDaemonProtocol

@Suite(.timeLimit(.minutes(1)))
private struct VerifierFindingsTests {
    @Test
    func `host bits and duplicate tunnel CIDRs render once in canonical network form`() throws {
        let context = try PFContext(
            underlay: PFInterface("en0"), tunnel: PFInterface("utun7"),
            endpoints: [PFEndpoint("198.51.100.8:51820"), PFEndpoint("[2001:db8::8]:51820")],
            resolvers: [PFAddress("192.168.20.1"), PFAddress("2001:db8:20::1")],
            tunnelDNS: [PFAddress("10.77.0.1")], lanTunnelDNS: [PFAddress("192.168.20.53")],
            lanSubnets: [IPAddressRange("192.168.20.0/24"), IPAddressRange("2001:db8:20::/64")],
            tunnelRanges: [
                IPAddressRange("10.77.0.2/24"),
                IPAddressRange("10.77.0.0/24"),
                IPAddressRange("10.77.0.2/24"),
            ], consoleUID: 501,
        )
        let text = try PacketFilterRenderer.render(phase: .error, modifiers: PFModifiers(), context: context)
        #expect(!text.contains("10.77.0.2/24"))
        #expect(text.components(separatedBy: "10.77.0.0/24").count == 2)
        #expect(context.tunnelRanges.count == 2) // Network plus the distinct host DNS selector.
        #expect(try text == NetworkPortHarness.fixture("PacketFilterGoldens/error-lan0-captive0.pf"))
        #expect(PacketFilterReadback.matches(
            "block drop out quick on en0 inet from any to 10.77.0.0/24\n",
            rendered: "block drop out quick on en0 inet from any to 10.77.0.2/24\n",
        ))
        #expect(!PacketFilterReadback.matches(
            "block drop out quick on en0 inet from any to 10.77.1.0/24\n",
            rendered: "block drop out quick on en0 inet from any to 10.77.0.2/24\n",
        ))
    }

    @Test(arguments: [UInt32?.none, 501, 502], [false, true])
    func `same boot failed intent survives the initial console snapshot`(_ uid: UInt32?, staleSuspension: Bool) async throws {
        let harness = try ControllerHarness(); try await harness.install(); _ = try await harness.start()
        await harness.controller.cancelBackgroundWork()
        try await harness.store.deleteBundle(profileID: harness.profile.id)
        let boot = UUID()
        try harness.journal.mutate(generation: nil) {
            $0.loginSuspended = staleSuspension
            $0.pfPolicy = .error; $0.pfToken = "99"; $0.pfTokenPID = 123; $0.pfBootSession = boot
        }
        let replacement = try harness.replacementController()
        let before = harness.trace.calls.count
        try await replacement.consoleUserChanged(uid)
        try await replacement.reconcileAtStartup()
        let document = try DaemonJournal(directory: harness.directory).snapshot()
        #expect(document.intent?.profileID == harness.profile.id)
        #expect(document.pfToken == "99")
        #expect(document.pfTokenPID == 123)
        #expect(document.pfBootSession == boot)
        #expect(await replacement.status.protection == .blocked)
        #expect(await replacement.status.phase == .failed(.secretsUnavailable, blockedByPolicy: true, needsSecrets: true))
        #expect(!harness.trace.calls.dropFirst(before).contains("pf.disconnected"))
        #expect(!harness.trace.calls.dropFirst(before).contains("pf.release"))
    }

    @Test
    func `active transitions clear a retry deadline while preserving retry history`() async throws {
        let harness = try ControllerHarness(); try await harness.install(); let epoch = try await harness.start()
        try await harness.controller.maintenance { controller, _ in
            controller.maintenanceState.retryAt = .seconds(60); controller.maintenanceState.retryAttempt = 9
            controller.transition(.active(epoch), protection: .protected)
        }
        #expect(await harness.controller.maintenanceState.retryAt == nil)
        #expect(await harness.controller.maintenanceState.retryAttempt == 9)
    }

    @Test
    func `pending retry still measures policy and emits a heartbeat`() async throws {
        let harness = try ControllerHarness(); try await harness.install(); _ = try await harness.start()
        harness.trace.fail(at: "pf.canary")
        await #expect(throws: (any Error).self) { try await harness.controller.networkChanged(trigger: .route) }
        try await harness.controller.maintenance { controller, _ in controller.maintenanceState.retryAt = .seconds(60) }
        let checks = await harness.ports.canaryChecks
        harness.clock.advance(.seconds(5)); try await harness.controller.tick()
        #expect(await harness.ports.canaryChecks > checks)
        #expect(await harness.controller.status.protection == .blocked)
    }

    @Test
    func `secure regression loads once and repair remeasures lockdown without intent`() async throws {
        let system = FakeSecureInstallSystem()
        let subject = try ControllerHarness(secureInstall: SecureInstall(system: system))
        var settings = MacGlobalSettings.defaults; settings.lockdown = true
        try await subject.controller.setGlobalSettings(settings)
        try await subject.controller.tick()
        system.state.withLock { $0.entries[1].mode = 0o777 }
        await #expect(throws: DaemonError.secureInstallRequired) { try await subject.controller.tick() }
        let calls = subject.trace.calls
        await #expect(throws: DaemonError.secureInstallRequired) { try await subject.controller.tick() }
        #expect(subject.trace.calls == calls)
        try await subject.controller.maintenance { controller, _ in controller.maintenanceState.retryAttempt = 2 }
        system.state.withLock { $0.entries[1].mode = 0o755 }
        try await subject.controller.tick()
        #expect(await subject.controller.status.protection == .blocked)
        #expect(await subject.controller.status.recoveryFailureReason == nil)
        #expect(await subject.controller.maintenanceState.retryAttempt == 2)
    }

    @Test
    func `generic reconciliation failure never targets the last stopped profile`() async throws {
        let harness = try ControllerHarness(); try await harness.install(); _ = try await harness.start()
        _ = try await harness.controller.stop(profileID: harness.profile.id, connectionUID: 501)
        try await harness.controller.recoveryFailed(.reconciliationFailed)
        #expect(await harness.controller.activeProfileID() == nil)
    }

    @Test
    func `policy success preserves an unrelated monitor failure`() async throws {
        let harness = try ControllerHarness()
        await harness.controller.monitoringFailed()
        let epoch = await harness.controller.currentGeneration
        try await harness.controller.applyPolicy(.disconnected, generation: epoch)
        #expect(await harness.controller.protectionFailureReason != nil)
        #expect(await harness.controller.status.protection == .unknown)
    }
}
