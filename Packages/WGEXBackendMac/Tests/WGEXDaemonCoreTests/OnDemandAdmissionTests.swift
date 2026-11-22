// SPDX-License-Identifier: MIT
// swiftformat:disable redundantInternal
import Foundation
import Testing
import WGEXCore
@testable import WGEXDaemonCore
import WGEXDaemonProtocol

/// Holds the next secure-install check until its latch opens.
internal actor HeldSecureInstall: SecureInstallChecking {
    internal let latch = Latch()
    private var holding = false

    internal func holdNext() {
        holding = true
    }

    internal func status() async -> SecureInstallReport {
        if holding {
            holding = false
            await latch.wait()
        }
        return VerifiedSecureInstall().status()
    }

    internal func perform() async -> SecureInstallReport {
        await status()
    }
}

/// Holds the next bundle load until its latch opens.
private final class HeldBundleLoads: TunnelSecretStoring {
    let base: any TunnelSecretStoring
    let latch = Latch()
    private let holding = Shared(false)

    init(base: any TunnelSecretStoring) {
        self.base = base
    }

    func holdNext() {
        holding.withLock { $0 = true }
    }

    func saveBundle(_ bytes: consuming SecretBytes, profileID: UUID) async throws {
        try await base.saveBundle(bytes, profileID: profileID)
    }

    func loadBundle(profileID: UUID) async throws -> SecretBytes {
        let hold = holding.withLock { held in
            defer { held = false }
            return held
        }
        if hold {
            await latch.wait()
        }
        return try await base.loadBundle(profileID: profileID)
    }

    func deleteBundle(profileID: UUID) async throws {
        try await base.deleteBundle(profileID: profileID)
    }

    func storedBundleProfileIDs() async throws -> [UUID] {
        try await base.storedBundleProfileIDs()
    }
}

internal enum StartPath: CaseIterable, Sendable {
    case request, api
}

internal enum HeldCommand: CaseIterable, Sendable {
    case start, arm
}

internal enum AutomaticRestart: CaseIterable, Sendable {
    case failedStartRetry, captiveRestoration
}

/// Round-5 admission hazards: a start's checks never starve a stop, automatic restarts keep the intent's origin, and a
/// cutover revokes a held arm commit.
@Suite(.timeLimit(.minutes(1)))
private struct OnDemandAdmissionTests {
    private static func context(_ harness: ControllerHarness) -> DaemonRequestContext {
        DaemonRequestContext(
            peer: VerifiedPeerIdentity(uid: ControllerHarness.uid, pid: 7, auditSessionID: 10, codeSigningVerdict: .requirementSatisfied),
            visibleProfileIDs: [harness.profile.id], clientBuild: 1,
        )
    }

    // MARK: Required change 1: stop starvation

    @Test(arguments: StartPath.allCases)
    func `StopNotStarvedByStartChecks: a stop completes while a start's secure-install check is held, and the start is revoked`(
        path: StartPath,
    ) async throws {
        let secure = HeldSecureInstall()
        let harness = try ControllerHarness(secureInstall: secure)
        try await harness.install(); _ = try await harness.start()
        let id = harness.profile.id, context = Self.context(harness)
        await secure.holdNext()
        let start = Task<Bool, any Error> {
            switch path {
            case .request:
                let reply = try await harness.controller.handle(
                    .startIntent(profileID: id, transport: nil, hasSecrets: true), context: context, secrets: ControllerHarness.bundle(),
                )
                if case .started = reply {
                    return true
                }
                return false
            case .api:
                do {
                    _ = try await harness.controller.start(
                        profileID: id, connectionUID: ControllerHarness.uid, secrets: ControllerHarness.bundle(),
                    )
                    return true
                } catch {
                    return false
                }
            }
        }
        try await secure.latch.waited()
        let stopped = Shared(false)
        let stop = Task {
            let reply = await harness.controller.handle(.stop(profileID: id, reason: .userRequested), context: context, secrets: nil)
            stopped.withLock { $0 = true }
            return reply
        }
        let completed = await (try? waitForCondition(timeout: .seconds(5)) { stopped.withLock { $0 } }) != nil
        let engines = harness.trace.calls.filter { $0 == "engine.create" }.count
        secure.latch.open()
        #expect(completed, "the stop waited behind the start's held secure-install check")
        #expect(await stop.value == .ok)
        #expect(try await start.value == false, "a start received before the stop restarted the tunnel after it")
        #expect(harness.journal.snapshot().intent == nil)
        #expect(await harness.controller.status.phase == .idle)
        #expect(harness.trace.calls.filter { $0 == "engine.create" }.count == engines)
    }

    @Test
    func `StopNotStarvedByStartChecks: a disarm completes while an on-demand start's secure-install check is held`() async throws {
        let secure = HeldSecureInstall()
        let rig = try await OnDemandRig(.interfaces(.wifiOrEthernet(.anySSID)), secureInstall: secure)
        let gate = PointGate.action(.connect)
        await rig.controller.setOnDemandPause(gate.pause)
        let arm = Task { try await rig.arm() }
        try await gate.reached()
        #expect(try await arm.value == .ok)
        await secure.holdNext()
        gate.open()
        try await secure.latch.waited()
        let disarmed = Shared(false)
        let disarm = Task {
            let reply = await rig.send(.disarmOnDemand(profileID: rig.profile.id))
            disarmed.withLock { $0 = true }
            return reply
        }
        let completed = await (try? waitForCondition(timeout: .seconds(5)) { disarmed.withLock { $0 } }) != nil
        secure.latch.open()
        #expect(completed, "the disarm waited behind the on-demand start's held secure-install check")
        #expect(await disarm.value == .ok)
        await rig.idle()
        #expect(rig.intent == nil, "an on-demand start decided before the disarm connected after it")
        #expect(try await !rig.armedInRegistry())
    }

    // MARK: Required change 2: automatic restarts keep the origin

    /// `ownerAtConsole` false: another user is at the console and the profile starts before login (boot retention), so the
    /// on-demand start runs with the observed console context, which the restart must keep.
    @Test(arguments: AutomaticRestart.allCases, [true, false])
    func `AutomaticRestartKeepsOrigin: an on-demand intent restarted automatically stays on-demand and activated`(
        restart: AutomaticRestart, ownerAtConsole: Bool,
    ) async throws {
        let rig = try await OnDemandRig(.interfaces(.wifiOrEthernet(.anySSID)), console: ownerAtConsole)
        let console = ownerAtConsole ? OnDemandRig.uid : OnDemandRig.uid &+ 1
        if !ownerAtConsole {
            try await rig.harness.registry.setStartBeforeLogin(rig.profile.id, enabled: true, connectionUID: OnDemandRig.uid)
            try await rig.controller.consoleUserChanged(console)
        }
        rig.harness.trace.fail(at: "engine.up")
        try await rig.arm(); await rig.idle()
        #expect(await rig.controller.loginModel.consoleUID == console)
        let onDemand = TunnelIntent(profileID: rig.profile.id, ownerUID: OnDemandRig.uid, origin: .onDemand)
        #expect(rig.intent == onDemand, "the failed on-demand start did not keep its intent")
        #expect(await rig.controller.engines.isEmpty)
        switch restart {
        case .failedStartRetry:
            #expect(await rig.controller.recoveryObservation().retryAt != nil)
            rig.harness.clock.advance(.seconds(5))
            try await rig.controller.tick()
        case .captiveRestoration:
            try await rig.controller.openCaptiveWindow(seconds: 10, connectionUID: OnDemandRig.uid)
            try await rig.controller.closeCaptiveWindow()
        }
        await rig.idle()
        #expect(await rig.controller.status.phase == .active(rig.controller.currentGeneration))
        #expect(rig.intent == onDemand, "the automatic restart rewrote the intent's origin")
        #expect(try DaemonJournal(directory: rig.harness.directory).snapshot().intent == onDemand)
        #expect(await rig.onDemand?.activated == true)
        #expect(await rig.controller.loginModel.consoleUID == console, "the automatic restart replaced the observed console user")
        #expect(await rig.controller.consoleSnapshotReceived)
        guard case let .status(status) = await rig.send(.status) else { Issue.record("no status reply"); return }
        #expect(status.onDemand?.activated == true, "the status the CLI renders lost the activation")
    }

    // MARK: Optional: a cutover revokes a held arm commit

    @Test
    func `ArmCommitAdmission: an arm held inside the registry commit never commits after a cutover arms`() async throws {
        let loads = Shared<HeldBundleLoads?>(nil)
        let rig = try await OnDemandRig(.interfaces(.ethernetOnly), underlay: OnDemandRig.wifi, secrets: { base in
            let held = HeldBundleLoads(base: base)
            loads.withLock { $0 = held }
            return held
        })
        let held = try #require(loads.withLock { $0 })
        try await rig.harness.store.saveBundle(ControllerHarness.bundle().wireBytes(), profileID: rig.profile.id)
        // The cutover passes its registry read and waits on the bundle load, before the arm takes the registry.
        held.holdNext()
        let cutover = Task {
            try await rig.controller.startCutover(profileID: rig.profile.id, connectionUID: OnDemandRig.uid, confirmWithin: 600)
        }
        try await held.latch.waited()
        let commit = Latch()
        await rig.harness.registry.setCommitPause { await commit.wait() }
        let arm = Task { try await rig.arm() }
        try await commit.waited()
        held.latch.open()
        try await waitForCondition(timeout: .seconds(5)) { await rig.controller.cutoverIsArmed }
        commit.open()
        #expect(try await arm.value != .ok, "an arm admitted before the cutover committed after it")
        _ = try await cutover.value
        #expect(try rig.record()?.armed == nil)
        #expect(await rig.controller.onDemandArmedProfileID == nil)
        #expect(await rig.controller.cutoverIsArmed)
        try await rig.controller.abortCutover(connectionUID: OnDemandRig.uid)
    }
}
