// SPDX-License-Identifier: MIT
import Foundation
import Testing
import WGEXCore
@testable import WGEXDaemonCore
import WGEXDaemonProtocol

/// M05-T07 review r1: the kill switch is released before any secret goes, and a request admitted before the uninstall
/// fence cannot re-arm protection after the uninstall released it.
private struct UninstallFenceTests {
    @Test
    func `the uninstall stop keeps the secrets, so a failing bundle deletion cannot hold the kill switch`() async throws {
        let harness = try ControllerHarness()
        try await harness.install()
        _ = try await harness.start()
        try await harness.controller.setGlobalSettings(Self.lockdown, connectionUID: ControllerHarness.uid)
        let enable = Request.setStartBeforeLoginIntent(profileID: harness.profile.id, enabled: true)
        #expect(await harness.controller.handle(enable, context: Self.context(harness), secrets: nil) == .ok)
        #expect(try await harness.store.storedBundleProfileIDs() == [harness.profile.id])
        // Every per-profile bundle deletion fails; the normal stop would run one before the release.
        harness.trace.fail(at: "secrets.delete", repeating: true)
        let mark = harness.trace.calls.count
        try await harness.controller.uninstall(purgeState: false)
        let calls = Array(harness.trace.calls.dropFirst(mark))
        let released = try #require(calls.lastIndex(of: "pf.release"))
        #expect(try #require(calls.firstIndex(of: "engine.shutdown")) < released)
        #expect(!calls.contains("secrets.delete"))
        #expect(calls.prefix(released).allSatisfy { !Self.storageCalls.contains($0) })
        #expect(calls.dropFirst(released).contains("secrets.removeAll") && calls.dropFirst(released).contains("bundles.removeAll"))
        try await Self.expectReleased(harness)
        #expect(try await harness.store.storedBundleProfileIDs().isEmpty)
        #expect(harness.journal.snapshot().uninstall?.completed == true)
    }

    @Test
    func `a settings change suspended across a whole uninstall is refused at its commit and arms nothing`() async throws {
        let gate = StepGate(point: .validateSecrets)
        let secure = UninstallSecureGate(gate: gate)
        let harness = try ControllerHarness(secureInstall: secure)
        try await harness.install()
        await secure.suspendNext()
        let settings = Task {
            await harness.controller.handle(.setGlobalSettings(Self.lockdown), context: Self.context(harness), secrets: nil)
        }
        await gate.wait() // Admitted before the fence, now inside its secure-install read.
        try await harness.controller.uninstall(purgeState: false)
        #expect(harness.journal.snapshot().uninstall?.completed == true)
        let mark = harness.trace.calls.count
        await gate.release()
        #expect(await settings.value == .error(.uninstallFailed(step: .admission)))
        #expect(harness.trace.calls.dropFirst(mark).allSatisfy { !$0.hasPrefix("pf.") })
        try await Self.expectReleased(harness)
        #expect(harness.journal.snapshot().protectionOwnerUID == nil)
    }

    @Test
    func `policy work already in the serial slot is drained before the uninstall clears it`() async throws {
        let read = PolicyReadGate(.verification, armed: false)
        let harness = try ControllerHarness(portsTransform: { $0.gatingPolicy(read) })
        try await harness.install()
        read.arm()
        let settings = Task {
            await harness.controller.handle(.setGlobalSettings(Self.lockdown), context: Self.context(harness), secrets: nil)
        }
        await read.wait() // Lockdown committed, the token held, the blocking policy loaded and being verified.
        #expect(harness.journal.snapshot().settings.lockdown && harness.journal.snapshot().pfToken != nil)
        let mark = harness.trace.calls.count
        let uninstall = Task { try await harness.controller.uninstall(purgeState: false) }
        var spins = 0
        while await !harness.controller.uninstallFenced, spins < 10000 {
            spins += 1; await Task.yield()
        }
        try #require(await harness.controller.uninstallFenced)
        for _ in 0 ..< 200 {
            await Task.yield()
        }
        // The fence is up and the settings change still holds the slot: no uninstall step has touched pf yet.
        #expect(harness.trace.calls.dropFirst(mark).allSatisfy { !$0.hasPrefix("pf.") })
        #expect(harness.journal.snapshot().uninstall?.finished.contains(.stopTunnel) != true)
        read.release()
        _ = await settings.value
        try await uninstall.value
        try await Self.expectReleased(harness)
        #expect(harness.journal.snapshot().uninstall?.completed == true)
        // A later settings change meets the fence.
        #expect(await harness.controller.handle(.setGlobalSettings(Self.lockdown), context: Self.context(harness), secrets: nil)
            == .error(.uninstallFailed(step: .admission)))
    }
}

private extension UninstallFenceTests {
    static let storageCalls = ["secrets.delete", "secrets.removeAll", "bundles.removeAll", "key.remove"]

    static var lockdown: MacGlobalSettings {
        var settings = MacGlobalSettings.defaults; settings.lockdown = true
        return settings
    }

    static func context(_ harness: ControllerHarness) -> DaemonRequestContext {
        DaemonRequestContext(
            peer: VerifiedPeerIdentity(uid: ControllerHarness.uid, pid: 7, auditSessionID: 10, codeSigningVerdict: .requirementSatisfied),
            visibleProfileIDs: [harness.profile.id], clientBuild: 1,
        )
    }

    /// The kill switch is off: no rules, no WGEX pf reference, no lockdown, and nothing left for the network.
    static func expectReleased(_ harness: ControllerHarness) async throws {
        #expect(await harness.ports.policy == .disconnected)
        #expect(await harness.ports.token == nil)
        #expect(await harness.ports.ownedRoutes().isEmpty)
        #expect(await harness.ports.dnsItems.isEmpty)
        let document = harness.journal.snapshot()
        #expect(document.pfToken == nil && document.pfPolicy == .disconnected && !document.settings.lockdown)
    }
}

/// The secure-install read, held once at `gate` (keyed on `.validateSecrets`, which no other call here uses).
private actor UninstallSecureGate: SecureInstallChecking {
    private let gate: StepGate
    private var suspended = false
    init(gate: StepGate) {
        self.gate = gate
    }

    func suspendNext() {
        suspended = true
    }

    func status() async -> SecureInstallReport {
        if suspended {
            suspended = false
            try? await gate.before(.validateSecrets, generation: Generation(rawValue: 0))
        }
        return VerifiedSecureInstall().status()
    }

    func perform() async -> SecureInstallReport {
        await status()
    }
}
