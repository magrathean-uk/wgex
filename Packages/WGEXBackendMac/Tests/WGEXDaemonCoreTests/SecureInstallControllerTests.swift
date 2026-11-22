// SPDX-License-Identifier: MIT
import Synchronization
import Testing
import WGEXCore
@testable import WGEXDaemonCore
import WGEXDaemonProtocol

private struct SecureInstallControllerTests {
    @Test
    func `writable bundle gates privileged requests and permits status doctor and repair`() async throws {
        let system = FakeSecureInstallSystem()
        system.state.withLock { $0.entries[1].mode = 0o757 }
        let harness = try ControllerHarness(secureInstall: SecureInstall(system: system))
        let fixture = CompositionFixture(harness: harness)
        try await fixture.connect()
        try await harness.install()
        let requests: [Request] = [
            .startIntent(profileID: harness.profile.id, transport: nil, hasSecrets: false),
            .openCaptiveWindow(seconds: 60), .extendCaptiveWindow(seconds: 60),
            .setGlobalSettings(.defaults), .selectTransport(profileID: harness.profile.id, transport: nil),
        ]
        for request in requests {
            #expect(try await fixture.call(request) == .error(.secureInstallRequired))
        }
        #expect(try await fixture.call(.closeCaptiveWindow) == .ok)
        await #expect(throws: DaemonError.secureInstallRequired) { _ = try await harness.start() }
        await #expect(throws: DaemonError.secureInstallRequired) { try await harness.controller.setGlobalSettings(.defaults) }
        await #expect(throws: DaemonFailure.startup(.secureInstallRequired)) { try await harness.controller.reconcileAtStartup() }
        #expect(harness.trace.calls.isEmpty)
        #expect(try await fixture.call(.status).statusProtection == harness.controller.status.protection)
        guard case let .secureInstall(report) = try await fixture.call(.secureInstallStatus) else { Issue.record("Missing report"); return }
        #expect(report.nonRootWritableEntries == 1)
        #expect(report.state == .needsAttention(.bundleWritable))
        let repaired = try await fixture.call(.performSecureInstall)
        #expect(await repaired == .secureInstall(SecureInstall(system: system).status()))
        #expect(await SecureInstall(system: system).status().state == .verified)
        // Repair runs the deferred startup reconciliation; on a clean journal its only system effect
        // is confirming the disconnected policy.
        try await harness.controller.reconcileAtStartup()
        #expect(harness.trace.calls.isEmpty)
    }

    @Test
    func `repair runs the deferred startup reconciliation and leaves idle unprotected`() async throws {
        let system = FakeSecureInstallSystem()
        system.state.withLock { $0.entries[1].uid = 501 }
        let harness = try ControllerHarness(secureInstall: SecureInstall(system: system))
        await #expect(throws: DaemonFailure.startup(.secureInstallRequired)) { try await harness.controller.reconcileAtStartup() }
        #expect(await harness.controller.status.protection == .unprotected)
        await #expect(throws: DaemonError.secureInstallRequired) { try await harness.controller.tick() }
        #expect(await harness.controller.status.protection == .unprotected)
        let fixture = CompositionFixture(harness: harness)
        try await fixture.connect()
        guard case let .secureInstall(repaired) = try await fixture.call(.performSecureInstall) else {
            Issue.record("Missing report"); return
        }
        #expect(repaired.state == .verified)
        try await harness.controller.reconcileAtStartup()
        #expect(await harness.controller.status.protection == .unprotected)
        #expect(await harness.controller.status.phase == .idle)
        try await harness.controller.tick()
        #expect(await harness.controller.status.protection == .unprotected)
    }

    @Test
    func `planting writable metadata after verification invalidates controller gate`() async throws {
        let system = FakeSecureInstallSystem()
        let harness = try ControllerHarness(secureInstall: SecureInstall(system: system))
        try await harness.install()
        let fixture = CompositionFixture(harness: harness)
        try await fixture.connect()
        guard case let .secureInstall(before) = try await fixture.call(.secureInstallStatus) else {
            Issue.record("Missing initial report"); return
        }
        #expect(before.state == .verified)
        system.state.withLock { $0.entries.append(.init(relativePath: "planted", uid: 0, gid: 0, mode: 0o666)) }
        await #expect(throws: DaemonError.secureInstallRequired) { _ = try await harness.start() }
        #expect(harness.trace.calls.isEmpty)
    }

    @Test
    func `missing secure install port refuses start`() async throws {
        let harness = try ControllerHarness(secureInstall: UnavailableSecureInstall())
        try await harness.install()
        await #expect(throws: DaemonError.secureInstallRequired) { _ = try await harness.start() }
        #expect(harness.trace.calls.isEmpty)
    }
}
