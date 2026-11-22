// SPDX-License-Identifier: MIT
// swiftformat:disable redundantInternal
import Foundation
import Testing
import WGEXCore
@testable import WGEXDaemonCore
import WGEXDaemonCoreTesting
import WGEXDaemonProtocol

/// Holds the first coordinator pause point that matches until `open()`, and records every matching point.
internal final class PointGate: Sendable {
    internal let points = Shared<[OnDemandPausePoint]>([])
    /// Every point reached, matching or not.
    internal let seen = Shared<[OnDemandPausePoint]>([])
    private let matches: @Sendable (OnDemandPausePoint) -> Bool
    private let held = Shared(false)
    private let released: AsyncStream<Void>
    private let release: AsyncStream<Void>.Continuation

    internal init(_ matches: @escaping @Sendable (OnDemandPausePoint) -> Bool) {
        self.matches = matches
        (released, release) = AsyncStream.makeStream()
    }

    internal static func action(_ decision: OnDemandStatus.Decision) -> PointGate {
        PointGate { $0 == .actionDecided(decision) }
    }

    internal var pause: @Sendable (OnDemandPausePoint) async -> Void {
        { [points, seen, matches, held, released] point in
            seen.withLock { $0.append(point) }
            guard matches(point) else { return }
            points.withLock { $0.append(point) }
            let first = held.withLock { taken in
                defer { taken = true }
                return !taken
            }
            guard first else { return }
            for await _ in released {
                return
            }
        }
    }

    /// Waits until the first matching point is held; bounded and cancellable, so a missed point fails instead of spinning.
    internal func reached() async throws {
        try await waitForCondition { [held] in held.withLock { $0 } }
    }

    internal func open() {
        release.yield(); release.finish()
    }

    internal var count: Int {
        points.withLock { $0.count }
    }
}

/// A one-shot latch a fake can wait on inside a call.
internal final class Latch: Sendable {
    private let stream: AsyncStream<Void>
    private let continuation: AsyncStream<Void>.Continuation
    private let waiting = Shared(false)

    internal init() {
        (stream, continuation) = AsyncStream.makeStream()
    }

    internal func wait() async {
        waiting.withLock { $0 = true }
        for await _ in stream {
            return
        }
    }

    internal func waited() async throws {
        try await waitForCondition { [waiting] in waiting.withLock { $0 } }
    }

    internal func open() {
        continuation.yield(); continuation.finish()
    }
}

/// Which side of the held await completes first: the competing input, or the held continuation.
internal enum InterleavingOrder: CaseIterable, Sendable {
    case inputFirst
    case continuationFirst
}

/// Records every published status of a controller.
internal final class PhaseLog: Sendable {
    internal let statuses = Shared<[TunnelStatus]>([])
    private let task: Task<Void, Never>

    internal init(_ controller: TunnelController) async {
        let updates = await controller.statusUpdates()
        task = Task { [statuses] in
            for await status in updates {
                statuses.withLock { $0.append(status) }
            }
        }
    }

    deinit { task.cancel() }

    internal func index(where predicate: (TunnelPhase) -> Bool) -> Int? {
        statuses.withLock { $0.map(\.phase).firstIndex(where: predicate) }
    }

    internal func contains(_ predicate: (OnDemandStatus?) -> Bool) -> Bool {
        statuses.withLock { $0.contains { predicate($0.onDemand) } }
    }
}

private extension TunnelPhase {
    var isOnDemandStop: Bool {
        if case .stopping(_, reason: .onDemand) = self {
            return true
        }
        return false
    }

    var isFailure: Bool {
        if case .failed = self {
            return true
        }
        return false
    }
}

private extension OnDemandRig {
    func path(_ snapshot: UnderlaySnapshot) async throws {
        try await controller.networkChanged(trigger: .configuration, underlay: UnderlayEvent(snapshot: snapshot, satisfied: true))
    }

    var ssidKnowledge: OnDemandCoordinator.SSIDKnowledge {
        get async { await controller.onDemand.ssid }
    }
}

/// Astra H1 and H2 and the input hold: each input arrives while an on-demand continuation is held at a named await, in
/// both orders where the lane does not force one.
@Suite(.timeLimit(.minutes(1)))
private struct OnDemandInterleavingTests {
    // MARK: H1 stale actions

    @Test(arguments: InterleavingOrder.allCases)
    func `PathChangeCancelsAction: a disconnect decided on an older path never stops the tunnel`(order: InterleavingOrder) async throws {
        let rig = try await OnDemandRig(.interfaces(.ethernetOnly))
        try await rig.arm(); await rig.idle()
        let gate = PointGate.action(.disconnect)
        await rig.controller.setOnDemandPause(gate.pause)
        try await rig.path(OnDemandRig.wifi)
        try await gate.reached()
        let held = await rig.controller.currentGeneration
        switch order {
        case .inputFirst:
            try await rig.path(OnDemandRig.ethernet)
            gate.open(); await rig.idle()
            #expect(await rig.controller.currentGeneration == held, "the superseded disconnect reserved a generation")
        case .continuationFirst:
            gate.open(); await rig.idle()
            #expect(rig.intent == nil)
            try await rig.path(OnDemandRig.ethernet); await rig.idle()
        }
        #expect(rig.intent?.startedOnDemand == true)
        #expect(await rig.controller.intended?.startedOnDemand == true)
    }

    @Test(arguments: InterleavingOrder.allCases)
    func `WakeCancelsAction: a disconnect decided before a wake is decided again after it`(order: InterleavingOrder) async throws {
        let rig = try await OnDemandRig(.interfaces(.ethernetOnly))
        try await rig.arm(); await rig.idle()
        let gate = PointGate.action(.disconnect)
        await rig.controller.setOnDemandPause(gate.pause)
        try await rig.path(OnDemandRig.wifi)
        try await gate.reached()
        switch order {
        case .inputFirst:
            try await rig.controller.powerChanged(.wake)
            gate.open(); await rig.idle()
            #expect(gate.count == 2, "the held disconnect was not voided by the wake")
        case .continuationFirst:
            gate.open(); await rig.idle()
            try await rig.controller.powerChanged(.wake); await rig.idle()
            #expect(gate.count == 1)
        }
        #expect(rig.intent == nil)
        #expect(await rig.onDemand?.decision == .disconnect)
    }

    @Test(arguments: InterleavingOrder.allCases)
    func `ConsoleSwitchCancelsAction: a connect decided for the old console user never starts`(order: InterleavingOrder) async throws {
        let rig = try await OnDemandRig(.interfaces(.ethernetOnly), underlay: OnDemandRig.wifi)
        try await rig.arm(); await rig.idle()
        let gate = PointGate.action(.connect)
        await rig.controller.setOnDemandPause(gate.pause)
        try await rig.path(OnDemandRig.ethernet)
        try await gate.reached()
        switch order {
        case .inputFirst:
            try await rig.controller.consoleUserChanged(OnDemandRig.uid + 1)
            gate.open(); await rig.idle()
            #expect(rig.intent == nil, "the superseded connect started the tunnel")
        case .continuationFirst:
            gate.open(); await rig.idle()
            try await rig.controller.consoleUserChanged(OnDemandRig.uid + 1); await rig.idle()
        }
        #expect(await rig.controller.intended == nil)
        #expect(await rig.onDemand?.decision == .paused(.ownerNotConsoleUser))
    }

    @Test(arguments: InterleavingOrder.allCases)
    func `LocationRevocationCancelsDisconnect: a trusted-SSID disconnect never outlives the revocation`(
        order: InterleavingOrder,
    ) async throws {
        let rig = try await OnDemandRig(.interfaces(.wifiOrEthernet(.exceptSSIDs(["Home"]))), underlay: OnDemandRig.wifi)
        rig.reporters.withLock { $0 = 1 }
        try await rig.arm(); try await rig.settling()
        await rig.report(.notAuthorised); await rig.idle()
        #expect(rig.intent?.startedOnDemand == true)
        let gate = PointGate.action(.disconnect)
        await rig.controller.setOnDemandPause(gate.pause)
        await rig.report(.ssid("Home"))
        try await gate.reached()
        let held = await rig.controller.currentGeneration
        switch order {
        case .inputFirst:
            await rig.report(.notAuthorised)
            gate.open(); await rig.idle()
            #expect(await rig.controller.currentGeneration == held, "the superseded disconnect removed protection")
        case .continuationFirst:
            gate.open(); await rig.idle()
            #expect(rig.intent == nil)
            await rig.report(.notAuthorised); await rig.idle()
        }
        #expect(rig.intent?.startedOnDemand == true)
        #expect(await rig.onDemand?.ssid == .unavailable(.notAuthorised))
    }

    // MARK: H2 stale trigger continuations

    @Test(arguments: InterleavingOrder.allCases)
    func `ReporterLossRetiresPendingCount: a count read before the loss never settles`(order: InterleavingOrder) async throws {
        let rig = try await OnDemandRig(.interfaces(.wifiOnly(.onlySSIDs(["Home"]))), underlay: OnDemandRig.wifi)
        rig.reporters.withLock { $0 = 1 }
        let gate = PointGate { $0 == .askingReporters }
        await rig.controller.setOnDemandPause(gate.pause)
        try await rig.arm()
        try await gate.reached()
        switch order {
        case .inputFirst:
            rig.reporters.withLock { $0 = 0 }
            await rig.controller.wifiReporterLost()
            gate.open(); await rig.idle()
            #expect(rig.requested.withLock { $0 }.isEmpty, "the retired continuation asked a reporter that is gone")
        case .continuationFirst:
            gate.open(); try await rig.settling()
            #expect(rig.requested.withLock { $0 } == ["en0"])
            rig.reporters.withLock { $0 = 0 }
            await rig.controller.wifiReporterLost(); await rig.idle()
        }
        #expect(await rig.onDemand?.ssid == .unavailable(.noReporter))
        #expect(await rig.onDemand?.decision == .hold(.ssidUnavailable))
        #expect(rig.intent == nil)
    }

    @Test
    func `ReporterLossRetiresPendingCount: a count read before the loss and resumed after it never asks or settles`() async throws {
        let rig = try await OnDemandRig(.interfaces(.wifiOnly(.onlySSIDs(["Home"]))), underlay: OnDemandRig.wifi)
        let count = Shared(1), calls = Shared(0), first = Latch(), second = Latch()
        await rig.controller.setOnDemandReporters { [count, calls, first, second] in
            let call = calls.withLock { calls in
                calls += 1
                return calls
            }
            if call == 1 {
                let read = count.withLock { $0 }
                await first.wait()
                return read
            }
            if call == 2 {
                await second.wait()
            }
            return count.withLock { $0 }
        }
        try await rig.arm()
        try await first.waited()
        count.withLock { $0 = 0 }
        await rig.controller.wifiReporterLost()
        try await second.waited()
        first.open()
        second.open()
        try await waitForCondition(timeout: .seconds(5)) { await rig.controller.onDemand.scheduled.isEmpty }
        #expect(rig.requested.withLock { $0 }.isEmpty, "a count read before the loss asked a reporter that is gone")
        #expect(await rig.onDemand?.decision == .hold(.ssidUnavailable))
        #expect(await rig.onDemand?.ssid == .unavailable(.noReporter))
    }
}

/// Astra H3, H4, H15 and H16, and the Lockdown and kill-switch rows.
@Suite(.timeLimit(.minutes(1)))
private struct OnDemandTransitionTests {
    // MARK: H3 and H4 report ordering and admission

    @Test
    func `OutOfOrderWiFiReportsCannotRestoreTrust: an older trusted reading never replaces a newer revocation`() async throws {
        let rig = try await OnDemandRig(.interfaces(.wifiOrEthernet(.exceptSSIDs(["Home"]))), underlay: OnDemandRig.wifi)
        rig.reporters.withLock { $0 = 1 }
        try await rig.arm(); try await rig.settling()
        let base = XPCClock.continuousSeconds
        await rig.report(.notAuthorised, at: base + 2); await rig.idle()
        #expect(rig.intent?.startedOnDemand == true)
        await rig.report(.ssid("Home"), at: base + 1); await rig.idle()
        #expect(rig.intent?.startedOnDemand == true)
        #expect(await rig.ssidKnowledge == .unavailable(.notAuthorised))
        await rig.report(.ssid("Home"), at: base + 3); await rig.idle()
        #expect(rig.intent == nil) // A newer reading is accepted as usual.
    }

    @Test
    func `ReportAdmissionAndLoadingCannotOutliveContext: a reading from a lost reporter or an unloaded daemon never counts`() async throws {
        let rig = try await OnDemandRig(.interfaces(.wifiOrEthernet(.exceptSSIDs(["Home"]))), underlay: OnDemandRig.wifi)
        rig.reporters.withLock { $0 = 1 }
        try await rig.arm(); try await rig.settling()
        await rig.report(.ssid("Home")); await rig.idle()
        #expect(rig.intent == nil)
        // Read while the reporter was eligible, delivered after its loss was processed.
        let observed = XPCClock.continuousSeconds
        rig.reporters.withLock { $0 = 0 }
        await rig.controller.wifiReporterLost(); await rig.idle()
        #expect(rig.intent?.startedOnDemand == true)
        await rig.report(.ssid("Home"), at: observed); await rig.idle()
        #expect(rig.intent?.startedOnDemand == true, "a reading observed before the loss restored trust")
        #expect(await rig.ssidKnowledge == .unavailable(.noReporter))
        // A daemon that has not loaded its armed state commits no reading and schedules nothing.
        let unloaded = try rig.harness.replacementController(interfaces: StaticInterfaceClassifier(wifi: ["underlay-test"]))
        #expect(await unloaded.handle(.reportWiFiNetwork(WiFiObservation(
            interfaceName: "underlay-test", reading: .ssid("Home"), observedAtContinuous: XPCClock.continuousSeconds,
        )), context: rig.context, secrets: nil) == .ok)
        #expect(await unloaded.onDemand.ssid == .unavailable(.noReporter))
        #expect(await unloaded.onDemand.scheduled.isEmpty)
    }

    // MARK: Input hold

    @Test
    func `InputHoldDefersDecisions: nothing is decided while a control command is pending`() async throws {
        let rig = try await OnDemandRig(.interfaces(.ethernetOnly), underlay: OnDemandRig.wifi)
        try await rig.arm(); await rig.idle()
        let gate = PointGate { $0 == .armValidated(rig.profile.id) }
        await rig.controller.setOnDemandPause(gate.pause)
        let rearm = Task { try await rig.arm() }
        try await gate.reached()
        try await rig.path(OnDemandRig.ethernet)
        try await waitForCondition(timeout: .seconds(5)) { await rig.controller.onDemand.scheduled.isEmpty }
        #expect(!gate.seen.withLock { $0.contains(.actionDecided(.connect)) }, "a decision was taken while the arm was pending")
        #expect(rig.intent == nil)
        gate.open()
        #expect(try await rearm.value == .ok)
        await rig.idle()
        #expect(rig.intent?.startedOnDemand == true)
    }

    // MARK: H15 publication

    @Test
    func `SupersededDecisionCannotPublish: a decision voided by a disarm is never republished`() async throws {
        let rig = try await OnDemandRig(.interfaces(.ethernetOnly), underlay: OnDemandRig.wifi)
        try await rig.arm(); await rig.idle()
        let gate = PointGate.action(.connect)
        await rig.controller.setOnDemandPause(gate.pause)
        try await rig.path(OnDemandRig.ethernet)
        try await gate.reached()
        let log = await PhaseLog(rig.controller)
        #expect(await rig.send(.disarmOnDemand(profileID: rig.profile.id)) == .ok)
        gate.open(); await rig.idle()
        let status = await rig.onDemand
        #expect(status?.armedProfileID == nil)
        #expect(status?.decision == nil)
        #expect(rig.intent == nil)
        // Events arrive in publication order: once the re-arm's status is in, every earlier publication is too.
        try await rig.arm(); await rig.idle()
        try await waitForCondition { log.contains { $0?.armedProfileID == rig.profile.id } }
        #expect(
            !log.contains { $0?.armedProfileID == nil && $0?.decision != nil },
            "a superseded continuation republished its decision",
        )
    }

    // MARK: H16 recovery

    @Test
    func `RecoveryRoamCannotReuseTrustedSSID: the end of recovery asks again instead of trusting the old SSID`() async throws {
        let rig = try await OnDemandRig(.interfaces(.wifiOrEthernet(.exceptSSIDs(["Home"]))), underlay: OnDemandRig.wifi)
        try await rig.controller.reconcileAtStartup() // The daemon start, so the later end of recovery is not a start.
        rig.reporters.withLock { $0 = 1 }
        try await rig.arm(); try await rig.settling()
        await rig.report(.ssid("Home")); await rig.idle()
        #expect(rig.intent == nil)
        await rig.controller.markStartupRecovering()
        #expect(await rig.ssidKnowledge == .unavailable(.noReporter))
        let roamed = UnderlaySnapshot(v4: 9, v6: 10, resolvers: ["198.51.100.53"], interfaceNames: ["en0"], interfaceV4Name: "en0")
        await rig.controller.updateStartupUnderlay(UnderlayEvent(snapshot: roamed, satisfied: true))
        try await rig.controller.reconcileAtStartup()
        try await rig.settling()
        #expect(rig.requested.withLock { $0 }.count == 2)
        #expect(await rig.onDemand?.ssid == .settling)
        #expect(rig.intent == nil)
        // No fresh reading: an exclude list treats the unconfirmed network as untrusted and connects.
        rig.harness.clock.advance(.seconds(3)); await rig.idle()
        #expect(rig.intent?.startedOnDemand == true)
        #expect(await rig.onDemand?.ssid == .unavailable(.timedOut))
    }

    // MARK: Lockdown and kill switch

    @Test(arguments: InterleavingOrder.allCases)
    func `LockdownTransitionDuringPendingAction: a pending disconnect never weakens Lockdown`(order: InterleavingOrder) async throws {
        let rig = try await OnDemandRig(.interfaces(.ethernetOnly))
        try await rig.arm(); await rig.idle()
        let gate = PointGate.action(.disconnect)
        await rig.controller.setOnDemandPause(gate.pause)
        try await rig.path(OnDemandRig.wifi)
        try await gate.reached()
        let lockdown = MacGlobalSettings(lockdown: true, allowLAN: false, captiveWindowSeconds: 300, notifications: true)
        switch order {
        case .inputFirst:
            try await rig.controller.setGlobalSettings(lockdown)
            gate.open(); await rig.idle()
            #expect(gate.count == 2, "the disconnect decided before Lockdown was not decided again")
        case .continuationFirst:
            gate.open(); await rig.idle()
            try await rig.controller.setGlobalSettings(lockdown); await rig.idle()
        }
        #expect(rig.intent == nil)
        #expect(await rig.harness.ports.policy == .lockdown)
        #expect(await rig.controller.status.protection == .blocked)
    }

    @Test(arguments: InterleavingOrder.allCases)
    func `KillSwitchFailureDuringPendingAction: a pending disconnect never overtakes the failure's blocking`(
        order: InterleavingOrder,
    ) async throws {
        let rig = try await OnDemandRig(.interfaces(.ethernetOnly))
        let lockdown = MacGlobalSettings(lockdown: true, allowLAN: false, captiveWindowSeconds: 300, notifications: true)
        try await rig.controller.setGlobalSettings(lockdown)
        try await rig.arm(); await rig.idle()
        #expect(rig.intent?.startedOnDemand == true)
        let log = await PhaseLog(rig.controller)
        let gate = PointGate { $0 == .actionAdmitted(.disconnect) }
        await rig.controller.setOnDemandPause(gate.pause)
        try await rig.path(OnDemandRig.wifi)
        try await gate.reached()
        switch order {
        case .inputFirst:
            rig.harness.trace.fail(at: "pf.canary", repeating: true)
            await #expect(throws: (any Error).self) { try await rig.controller.networkChanged(trigger: .buildChanged) }
            rig.harness.trace.fail(at: nil)
            gate.open(); await rig.idle()
            #expect(gate.count == 2, "the disconnect admitted before the failure reserved anyway")
            try await waitForCondition { log.index(where: \.isOnDemandStop) != nil }
            let failed = try #require(log.index(where: \.isFailure))
            #expect(try failed < #require(log.index(where: \.isOnDemandStop)))
        case .continuationFirst:
            gate.open(); await rig.idle()
            rig.harness.trace.fail(at: "pf.canary", repeating: true)
            _ = try? await rig.controller.networkChanged(trigger: .buildChanged)
            rig.harness.trace.fail(at: nil)
            await rig.idle()
        }
        #expect(rig.intent == nil)
        #expect(await rig.harness.ports.policy == .lockdown)
        #expect(await rig.controller.currentSettings().lockdown)
    }
}
