// SPDX-License-Identifier: MIT
// swiftformat:disable redundantInternal
import Foundation
import Testing
import WGEXCore
@testable import WGEXDaemonCore
import WGEXDaemonProtocol

/// Forwards to the controller and holds the first Wi-Fi report after the dispatcher's checks, before the controller sees it.
private actor HeldReportService: DaemonService {
    let controller: TunnelController
    let latch = Latch()
    private var held = false

    init(controller: TunnelController) {
        self.controller = controller
    }

    func ownerUID(for profileID: UUID) async -> uid_t? {
        await controller.ownerUID(for: profileID)
    }

    func profileIDs(ownedBy uid: uid_t) async -> Set<UUID> {
        await controller.profileIDs(ownedBy: uid)
    }

    func protectionOwnerUID() async -> uid_t? {
        await controller.protectionOwnerUID()
    }

    func activeProfileID() async -> UUID? {
        await controller.activeProfileID()
    }

    func currentSettings() async -> MacGlobalSettings {
        await controller.currentSettings()
    }

    func handle(_ request: Request, context: DaemonRequestContext, secrets: consuming SecretBundle?) async -> Reply {
        if case .reportWiFiNetwork = request, !held {
            held = true
            await latch.wait()
        }
        return await controller.handle(request, context: context, secrets: secrets)
    }

    func wifiReporterLost() async {
        await controller.wifiReporterLost()
    }
}

/// A subscribed app connection of the rig's owner, through a real dispatcher in front of the rig's controller.
private struct ReporterConnection {
    let service: HeldReportService
    let transport: InMemoryXPCTransport

    init(_ rig: OnDemandRig) async throws {
        service = HeldReportService(controller: rig.controller)
        let dispatcher = DaemonDispatcher(
            service: service, daemonVersion: "test", daemonBuild: 10, minimumClientBuild: 1,
            authorisation: DaemonAuthorisation(isConsoleUser: { _ in true }, isAppClient: { _ in true }),
        )
        transport = InMemoryXPCTransport(
            daemon: dispatcher,
            peer: VerifiedPeerIdentity(uid: OnDemandRig.uid, pid: 7, auditSessionID: 1, codeSigningVerdict: .requirementSatisfied),
        )
        try await transport.connect(callbacks: .init())
        _ = try await send(.hello(clientVersion: "test", clientBuild: 10))
        _ = try await send(.subscribeEvents(includeLogs: false))
    }

    func send(_ request: Request) async throws -> Reply {
        try await WireCodec.decode(Reply.self, from: transport.send(Envelope(body: request).encoded(), secrets: nil))
    }

    /// A trusted-network reading stamped later than any invalidation, so only the membership or console guard can refuse it.
    func reportHome() async throws -> Reply {
        try await send(.reportWiFiNetwork(WiFiObservation(
            interfaceName: "en0", reading: .ssid("Home"), observedAtContinuous: XPCClock.continuousSeconds + 600,
        )))
    }
}

private extension OnDemandRig {
    var ssid: OnDemandCoordinator.SSIDKnowledge {
        get async { await controller.onDemand.ssid }
    }
}

/// REV-M02-T02 round 3, changes 3 to 6: versioned bundle publication, revocable commit admission, retention replay and
/// reporter membership across the dispatcher hop.
@Suite(.timeLimit(.minutes(1)))
private struct OnDemandCommitBoundaryTests {
    // MARK: Change 3 (H5) publication against installation and arming

    @Test(arguments: InterleavingOrder.allCases)
    func `RotatedKeyPublication: a start for a replaced registration never overwrites the rotated bundle`(
        order: InterleavingOrder,
    ) async throws {
        let steps = StepGate(point: .validateSecrets)
        let rig = try await OnDemandRig(.interfaces(.ethernetOnly), steps: steps)
        let rotatedKey = try ControllerHarness.publicKey(keyFile: "server.key")
        var rotated = rig.profile; rotated.interface.publicKey = rotatedKey; rotated.name = "Rotated"
        // P1 starts with K1 and is held before it publishes K1.
        let start = Task { try await rig.connect() }
        await steps.wait()
        if order == .continuationFirst {
            await steps.release()
            guard case .started = try await start.value else { Issue.record("the start failed"); return }
            #expect(try await rig.storedKey() == rig.profile.interface.publicKey)
        }
        // P2 replaces the key and is armed with K2.
        #expect(await rig.controller.installProfileCAS(rotated, expectedRevision: 1, context: rig.context) == .profileRevision(2))
        let armed = try await rig.controller.handle(
            .armOnDemand(profileID: rig.profile.id, hasSecrets: true), context: rig.context,
            secrets: ControllerHarness.bundle(keyFile: "server.key"),
        )
        #expect(armed == .ok)
        if order == .inputFirst {
            await steps.release()
            _ = try await start.value
        }
        await rig.idle()
        #expect(try await rig.storedKey() == rotatedKey, "an older publication overwrote the rotated key")
    }

    @Test
    func `a publication that passed its check before a rotation lands before the rotated one`() async throws {
        let rig = try await OnDemandRig(.interfaces(.ethernetOnly))
        let rotatedKey = try ControllerHarness.publicKey(keyFile: "server.key")
        var rotated = rig.profile; rotated.interface.publicKey = rotatedKey; rotated.name = "Rotated"
        // P1's publication has checked its registration, as the running write of the profile's secret writes, before it saves K1.
        let gate = PointGate { $0 == .publishing(rig.profile.id) }
        await rig.controller.setOnDemandPause(gate.pause)
        let start = Task { try await rig.connect() }
        try await gate.reached()
        // A repair-style install; the arm of P2/K2 appends its publication after P1's.
        try await rig.harness.registry.installProfile(rotated, expectedRevision: 1, connectionUID: OnDemandRig.uid)
        let arm = Task {
            try await rig.controller.handle(
                .armOnDemand(profileID: rig.profile.id, hasSecrets: true), context: rig.context,
                secrets: ControllerHarness.bundle(keyFile: "server.key"),
            )
        }
        try await rig.queuedSecretWrites(2)
        gate.open()
        _ = try await start.value
        #expect(try await arm.value == .ok)
        await rig.idle()
        #expect(try await rig.storedKey() == rotatedKey, "the older publication landed after the rotated one")
    }

    // MARK: Change 4 (H12) revocable commit admission

    @Test(arguments: [false, true])
    func `ArmCommitAdmission: an arm held inside the registry commit never commits after recovery or shutdown`(
        shutdown: Bool,
    ) async throws {
        let rig = try await OnDemandRig(.interfaces(.ethernetOnly), underlay: OnDemandRig.wifi)
        let latch = Latch()
        await rig.harness.registry.setCommitPause { await latch.wait() }
        let arm = Task { try await rig.arm() }
        try await latch.waited()
        if shutdown {
            try await rig.controller.prepareForUpdate()
        } else {
            await rig.controller.markStartupRecovering()
        }
        latch.open()
        #expect(try await arm.value != .ok, "an arm admitted before the transition committed after it")
        #expect(try rig.record()?.armed == nil)
        #expect(await rig.controller.onDemandArmedProfileID == nil)
    }

    // MARK: Change 5 (H10) retention replay

    @Test(arguments: [true, false])
    func `BootRetentionSurvivesDeletionReplay: an older deletion never removes a start-before-login bundle`(
        flagSaved: Bool,
    ) async throws {
        let rig = try await OnDemandRig(.interfaces(.ethernetOnly))
        // Enabling start-before-login publishes the bundle, supersedes the older deletion in the journal (not durably), then
        // saves the flag durably. Power loss after the flag keeps it and loses the supersession; before it, neither holds.
        try await rig.harness.store.saveBundle(ControllerHarness.bundle().wireBytes(), profileID: rig.profile.id)
        try rig.pendDeletion(rig.profile.id)
        if flagSaved {
            try await rig.harness.registry.setStartBeforeLogin(rig.profile.id, enabled: true, connectionUID: OnDemandRig.uid)
        }
        let replacement = try await rig.restart()
        #expect(await rig.secretsStored() == flagSaved, "the deletion replay ignored a current retention claim")
        #expect(try DaemonJournal(directory: rig.harness.directory).snapshot().pendingSecretDeletions.isEmpty)
        if flagSaved {
            #expect(await replacement.status.phase == .active(replacement.currentGeneration))
        }
    }

    // MARK: Change 6 (H4) reporter membership across the dispatcher hop

    @Test(arguments: InterleavingOrder.allCases)
    func `ReportDeliveryRevalidatesMembership: a reading delivered after its reporter's loss never counts`(
        order: InterleavingOrder,
    ) async throws {
        let rig = try await OnDemandRig(.interfaces(.wifiOrEthernet(.exceptSSIDs(["Home"]))), underlay: OnDemandRig.wifi)
        rig.reporters.withLock { $0 = 1 }
        try await rig.arm(); try await rig.settling()
        let app = try await ReporterConnection(rig)
        switch order {
        case .inputFirst:
            let report = Task { try await app.reportHome() }
            try await app.service.latch.waited() // Past the dispatcher's subscription check, not yet at the controller.
            rig.reporters.withLock { $0 = 0 }
            await app.transport.invalidate()
            app.service.latch.open()
            _ = try? await report.value
        case .continuationFirst:
            app.service.latch.open()
            #expect(try await app.reportHome() == .ok)
            #expect(await rig.ssid == .known("Home"))
            rig.reporters.withLock { $0 = 0 }
            await app.transport.invalidate()
        }
        await rig.idle()
        #expect(await rig.ssid != .known("Home"), "a reading from a lost reporter counted")
    }

    @Test(arguments: InterleavingOrder.allCases)
    func `ReportDeliveryRevalidatesSession: a reading delivered after a console change never counts`(
        order: InterleavingOrder,
    ) async throws {
        let rig = try await OnDemandRig(.interfaces(.wifiOrEthernet(.exceptSSIDs(["Home"]))), underlay: OnDemandRig.wifi)
        rig.reporters.withLock { $0 = 1 }
        try await rig.arm(); try await rig.settling()
        let app = try await ReporterConnection(rig)
        let report = Task { try await app.reportHome() }
        switch order {
        case .inputFirst:
            try await app.service.latch.waited()
            rig.reporters.withLock { $0 = 0 } // The new console user has no reporter, so nothing settles.
            try await rig.controller.consoleUserChanged(OnDemandRig.uid + 1)
            app.service.latch.open()
            _ = try await report.value
        case .continuationFirst:
            app.service.latch.open()
            _ = try await report.value
            #expect(await rig.ssid == .known("Home"))
            rig.reporters.withLock { $0 = 0 }
            try await rig.controller.consoleUserChanged(OnDemandRig.uid + 1)
        }
        await rig.idle()
        #expect(await rig.ssid != .known("Home"), "a reading from a former console user counted")
    }
}
