// SPDX-License-Identifier: MIT
// swiftformat:disable redundantInternal
import Foundation
import WGEXCore
import WGEXDaemonProtocol
import WGEXPolicy

/// A cleanup stop found a newer claim on its profile, so it stops nothing (ADR-030 section 6: manual action wins).
internal struct OnDemandCleanupSuperseded: Error {}

/// A release stop found its profile held by a manual command in flight; the release stays owed (ADR-030 section 6).
internal struct OnDemandReleaseDeferred: Error {}

/// The ADR-030 on-demand coordinator. It adds no pf, route or DNS code: decisions act only through `start` and `stop`.
package extension TunnelController {
    /// Supplies the number of eligible Wi-Fi reporters (subscribed app connections of the console user).
    func setOnDemandReporters(_ count: @escaping @Sendable () async -> Int) {
        onDemand.reporters = count
    }

    /// Host tests only: runs at each named suspension point of the coordinator.
    func setOnDemandPause(_ pause: (@Sendable (OnDemandPausePoint) async -> Void)?) {
        onDemand.pause = pause
    }

    /// Host tests only: suspends every decided action before its admission.
    func setOnDemandActionPause(_ pause: (@Sendable (OnDemandStatus.Decision) async -> Void)?) {
        guard let pause else { onDemand.pause = nil; return }
        onDemand.pause = { @Sendable point in
            if case let .actionDecided(decision) = point {
                await pause(decision)
            }
        }
    }

    /// Waits for every queued run, settle timer and replay that has already been scheduled; host tests only.
    func awaitOnDemandIdle() async {
        while let (id, task) = onDemand.scheduled.first {
            await task.value
            onDemand.scheduled.removeValue(forKey: id)
        }
    }

    /// The armed profile, as last committed.
    var onDemandArmedProfileID: UUID? {
        onDemand.armed?.profileID
    }
}

internal extension TunnelController {
    // MARK: - Inputs

    /// An input applied in one actor turn (an accepted report, the loss of a reporter, a Lockdown transition): advances the
    /// epoch, which voids every decision taken before it, and queues a run for `trigger`.
    func onDemandInput(_ trigger: OnDemandTrigger = .inputSettled) {
        onDemand.epoch &+= 1
        scheduleOnDemand(trigger)
    }

    /// An input applied across awaits (a path change, wake, a console change, a control command): advances the epoch before
    /// the input's first await and holds evaluation until `onDemandInputApplied`.
    func onDemandInputReceived() {
        onDemand.epoch &+= 1
        onDemand.pendingInputs += 1
    }

    /// The input is applied: evaluation may decide again, starting with `trigger`.
    func onDemandInputApplied(_ trigger: OnDemandTrigger) {
        onDemand.pendingInputs -= 1
        scheduleOnDemand(trigger)
    }

    /// Recovery entry: the network can change unseen until recovery ends, so the SSID knowledge goes now; the end of
    /// recovery invalidates again and asks for a fresh reading (ADR-030 section 3).
    func onDemandRecoveryEntered() {
        onDemand.invalidateSSID(at: clock.continuousNow)
        onDemand.ask = nil
        scheduleOnDemand(.inputSettled)
    }

    /// Host tests hold the coordinator at `point`; production returns at once.
    func pauseOnDemand(_ point: OnDemandPausePoint) async {
        guard let pause = onDemand.pause else { return }
        await pause(point)
    }

    // MARK: - Network context

    /// The configd primary interface: the IPv4 primary, else the IPv6 primary; the WGEX utun is never classified.
    var onDemandPrimaryInterface: String? {
        let named = [underlay.interfaceV4Name, underlay.interfaceV6Name].compactMap(\.self).filter { !$0.hasPrefix("utun") }
        if let first = named.first {
            return first
        }
        guard underlay.v4 != nil || underlay.v6 != nil else { return nil }
        return underlay.interfaceNames.first { !$0.hasPrefix("utun") }
    }

    var onDemandNetwork: OnDemandStatus.Network {
        guard let name = onDemandPrimaryInterface else { return .none }
        return interfaces.isWiFi(name) ? .wifi : .ethernet
    }

    func onDemandOwnerIsConsole(_ armed: ArmedOnDemand) -> Bool {
        consoleSnapshotReceived && loginModel.consoleUID == armed.ownerUID
    }

    // MARK: - Triggers

    /// Applies a trigger's synchronous part at once, in the input's own actor turn (section 3 invalidation), and queues
    /// the rest; nothing is queued while no profile is armed.
    func scheduleOnDemand(_ trigger: OnDemandTrigger) {
        guard let armed = onDemand.armed else { return }
        noteOnDemandTrigger(trigger, armed: armed)
        let id = UUID()
        onDemand.scheduled[id] = Task { [weak self] in
            await self?.runOnDemand()
            await self?.finishScheduled(id)
        }
    }

    func finishScheduled(_ id: UUID) {
        onDemand.scheduled.removeValue(forKey: id)
    }

    private func noteOnDemandTrigger(_ trigger: OnDemandTrigger, armed: ArmedOnDemand) {
        let primary = onDemandPrimaryInterface
        let network = onDemandNetwork
        let primaryChanged = primary != onDemand.primaryInterface
        onDemand.primaryInterface = primary
        let invalidates = switch trigger {
        case .armed, .daemonStart, .wake, .consoleChanged, .reporterLost, .recoveryEnded: true
        case let .policyChanged(listChanged): listChanged
        case .underlay: network == .wifi || primaryChanged
        case .report, .intentEnded, .inputSettled: false
        }
        guard invalidates else { return }
        onDemand.invalidateSSID(at: clock.continuousNow)
        // Recovery pauses evaluation and sends no Wi-Fi request (ADR-030 section 8); its end invalidates again.
        onDemand.ask = armed.requiresSSID && network == .wifi && !needsRecovery && primary != nil
            ? (trigger == .daemonStart ? .startup : .normal)
            : nil
    }

    /// A queued run: asks for a fresh reading when one is wanted, else evaluates unless a settle is pending.
    private func runOnDemand() async {
        if let ask = onDemand.ask {
            guard onDemand.askingEpoch != onDemand.epoch else { return } // That count decides for this epoch.
            await askReporters(ask)
        } else if onDemand.settleToken != nil {
            publishOnDemand() // The pending settle evaluates when it ends.
        } else {
            await evaluateOnDemand()
        }
    }

    /// Counts the eligible reporters across a suspension; a continuation whose epoch moved on does nothing, because the
    /// newer input queued its own run (which asks again while a reading is still wanted). Losing the last reporter
    /// evaluates at once with the SSID unknown; any other count asks and settles (section 4).
    private func askReporters(_ ask: OnDemandAsk) async {
        let epoch = onDemand.epoch
        onDemand.askingEpoch = epoch
        await pauseOnDemand(.askingReporters)
        let reporters = await onDemand.reporters()
        guard epoch == onDemand.epoch, onDemand.ask == ask else { return }
        onDemand.ask = nil
        guard let armed = onDemand.armed, let primary = onDemandPrimaryInterface else {
            await evaluateOnDemand()
            return
        }
        let startup = ask == .startup && onDemandOwnerIsConsole(armed)
        guard reporters > 0 || startup else {
            await evaluateOnDemand()
            return
        }
        if reporters > 0 {
            wireEvents.yield(DaemonServiceEvent(event: .wifiNetworkRequested(interfaceName: primary), profileID: nil, ownerUID: nil))
        }
        beginSettling(
            seconds: startup ? OnDemandCoordinator.startupSettleSeconds : OnDemandCoordinator.settleSeconds,
            asked: reporters > 0,
        )
    }

    private func beginSettling(seconds: Int, asked: Bool) {
        let token = UUID()
        onDemand.settleToken = token
        let task = Task { [weak self, clock] in
            do { try await clock.sleep(for: .seconds(seconds)) } catch { return }
            await self?.settlingEnded(token, asked: asked)
        }
        onDemand.settleTask = task
        onDemand.scheduled[token] = task
        publishOnDemand()
    }

    /// Every invalidation and every accepted report cancels the settle, so a timer that still holds the token is current.
    private func settlingEnded(_ token: UUID, asked: Bool) async {
        // Leaves the quiescence set only once its evaluation has ended, so a host test waiting for idle waits for it too.
        defer { onDemand.scheduled.removeValue(forKey: token) }
        guard onDemand.settleToken == token else { return }
        onDemand.settleToken = nil; onDemand.settleTask = nil
        if onDemand.ssid == .unavailable(.noReporter), asked {
            onDemand.ssid = .unavailable(.timedOut)
        }
        await evaluateOnDemand()
    }

    /// Accepts a report from an eligible reporter (checked by the dispatcher) in one actor turn, with no suspension between
    /// validation and commit: the reporter's membership still holds (the dispatcher revokes it before the loss reaches this
    /// actor), the reporter is still the console user, the armed state is loaded, the report names the current Wi-Fi
    /// primary interface, and it was observed no earlier than the last invalidation and later than the last accepted report.
    /// A membership or console change that comes after the acceptance invalidates it in its own turn. The SSID stays in
    /// memory only.
    func acceptWiFiReport(_ observation: WiFiObservation, reporter: WiFiReporterMembership?, uid: UInt32) {
        let primary = onDemandPrimaryInterface
        let observed = observation.observedAtContinuous
        guard reporter?.isCurrent == true, consoleSnapshotReceived, loginModel.consoleUID == uid,
              onDemand.loaded, onDemandNetwork == .wifi, observation.interfaceName == primary,
              observed >= onDemand.invalidatedAt, onDemand.lastAcceptedAt.map({ observed > $0 }) ?? true else { return }
        onDemand.ssid = switch observation.reading {
        case let .ssid(value): .known(value)
        case .notAuthorised: .unavailable(.notAuthorised)
        case .unreadable, .notAssociated: .unavailable(.unreadable)
        }
        onDemand.lastAcceptedAt = observed
        onDemand.primaryInterface = primary
        onDemand.ask = nil
        if let token = onDemand.settleToken {
            onDemand.scheduled.removeValue(forKey: token)
        }
        onDemand.cancelSettling()
        // Evaluated behind the reply, so the app's report never waits for a tunnel start or stop.
        onDemandInput(.report)
    }

    // MARK: - Evaluation

    /// Coalesces requests while one runs (latest wins) and waits for any lifecycle operation in flight before deciding.
    /// Nothing is decided while an input is pending, a fresh reading is wanted or a settle runs.
    func evaluateOnDemand() async {
        guard !onDemand.evaluating else { onDemand.rerun = true; return }
        onDemand.evaluating = true
        defer { onDemand.evaluating = false }
        repeat {
            onDemand.rerun = false
            await drainLifecycle()
            guard let armed = onDemand.armed, onDemand.settleToken == nil, onDemand.ask == nil, onDemand.pendingInputs == 0 else {
                publishOnDemand()
                return
            }
            clearLoginSuspensionIfReturned(armed)
            var decision = onDemandDecision(armed)
            if decision == .connect, let intended, intended.profileID != armed.profileID {
                decision = .hold(.anotherTunnelActive)
            }
            let ticket = OnDemandTicket(epoch: onDemand.epoch, generation: generation, operationID: operationID, profileID: armed.profileID)
            publishOnDemand(decision: decision, ticket: ticket)
            await act(decision, armed: armed, ticket: ticket)
            publishOnDemand(decision: decision, ticket: ticket)
        } while onDemand.rerun
    }

    /// The owner returned to the console: the logout stop of the armed profile no longer suspends its journalled intent.
    private func clearLoginSuspensionIfReturned(_ armed: ArmedOnDemand) {
        let document = journal.snapshot()
        guard onDemandOwnerIsConsole(armed), intended == nil, document.loginSuspended == true,
              document.intent?.profileID == armed.profileID else { return }
        try? journal.mutate(generation: generation) { $0.loginSuspended = false; $0.intent = nil }
    }

    private func onDemandDecision(_ armed: ArmedOnDemand) -> OnDemandStatus.Decision {
        if needsRecovery || startup.reconciliationPending {
            return .paused(.recovering)
        }
        if cutoverIsArmed {
            return .paused(.cutoverArmed)
        }
        if !armed.startBeforeLogin, !onDemandOwnerIsConsole(armed) {
            return .paused(.ownerNotConsoleUser)
        }
        let ssid: OnDemandNetworkContext.SSID = if case let .known(value) = onDemand.ssid {
            .known(value)
        } else {
            .unknown
        }
        let context = OnDemandNetworkContext(network: onDemandNetwork.context, ssid: ssid)
        return switch OnDemandEvaluator.evaluate(armed.rules, context: context) {
        case .connect: .connect
        case .disconnect: .disconnect
        case .hold(.ssidUnavailable): .hold(.ssidUnavailable)
        case .hold(.noNetwork), .hold(.noRule): .hold(.noNetwork)
        }
    }

    /// Section 5: connect starts an unintended armed profile, disconnect stops an intended one, anything else changes nothing.
    /// A failed start behaves as a manual one (intent stays, maintenance retries); the coordinator never retries or stops.
    /// The action is an on-demand command: refused at admission while a manual command holds the profile, superseded by any
    /// newer stop, manual connect or arm, and `start` and `stop` re-check the ticket with no suspension before `reserve`, so
    /// any input in between wins.
    private func act(_ decision: OnDemandStatus.Decision, armed: ArmedOnDemand, ticket: OnDemandTicket) async {
        switch decision {
        case .connect:
            guard intended == nil, pendingTeardownProfileID == nil, journal.snapshot().captiveWindow == nil else { return }
        case .disconnect:
            guard intended?.profileID == armed.profileID else { return }
        case .hold, .paused:
            return
        }
        onDemand.actionDropped = false
        defer {
            if onDemand.actionDropped, onDemand.armed != nil {
                onDemand.rerun = true
            }
        }
        await pauseOnDemand(.actionDecided(decision))
        guard onDemandTicketIsCurrent(ticket) else { onDemand.actionDropped = true; return }
        let kind: CommandKind = decision == .connect ? .onDemandStart : .onDemandStop
        do {
            try await withCommand(kind, profile: armed.profileID, input: false) { admission in
                if decision == .connect {
                    try await connectOnDemand(armed, ticket: ticket, admission: admission)
                } else {
                    await disconnectOnDemand(armed, ticket: ticket, admission: admission)
                }
            }
        } catch {
            if !onDemandTicketIsCurrent(ticket) {
                onDemand.actionDropped = true
            }
        }
    }

    /// The secure-install check runs with nothing held; the ticket voids the start if anything came between.
    private func connectOnDemand(_ armed: ArmedOnDemand, ticket: OnDemandTicket, admission: borrowing Admission) async throws {
        try await prepareStart(admission, profileID: armed.profileID)
        await pauseOnDemand(.actionAdmitted(.connect))
        _ = try? await start(
            profileID: armed.profileID, connectionUID: armed.ownerUID, payload: nil, transport: nil,
            expectedGeneration: nil, origin: .onDemand, admission: admission, ticket: ticket,
        )
    }

    private func disconnectOnDemand(_ armed: ArmedOnDemand, ticket: OnDemandTicket, admission: borrowing Admission) async {
        await pauseOnDemand(.actionAdmitted(.disconnect))
        _ = try? await stop(
            profileID: armed.profileID, connectionUID: armed.ownerUID, reason: .onDemand, retainingSecrets: true, ticket: ticket,
            admission: admission,
        )
    }

    /// Whether an on-demand action may still reserve: no input, reservation or lifecycle operation since its decision, the
    /// same armed profile, and admission still open (no recovery, no cutover, still accepting requests).
    func onDemandTicketIsCurrent(_ ticket: OnDemandTicket) -> Bool {
        ticket.epoch == onDemand.epoch && ticket.generation == generation && ticket.operationID == operationID && operation == nil
            && onDemand.armed?.profileID == ticket.profileID && !needsRecovery && !startup.reconciliationPending
            && !cutoverIsArmed && acceptingRequests && journal.snapshot().cutover?.rollbackPending != true
    }

    /// Called by `start` and `stop` for an on-demand action with no suspension before `reserve`.
    func requireCurrentOnDemandAction(_ ticket: OnDemandTicket) throws {
        guard onDemandTicketIsCurrent(ticket) else {
            onDemand.actionDropped = true
            throw CancellationError()
        }
    }

    /// Publishes the status fields; the SSID itself never leaves the daemon. A decision is published only under the epoch
    /// it was taken in, so a superseded continuation never republishes it.
    func publishOnDemand(decision: OnDemandStatus.Decision? = nil, ticket: OnDemandTicket? = nil) {
        guard onDemand.armed != nil || onDemand.status != nil || intended?.startedOnDemand == true else { return }
        var status = onDemand.status ?? OnDemandStatus()
        status.armedProfileID = onDemand.armed?.profileID
        status.activated = intended?.startedOnDemand == true
        status.network = onDemandNetwork
        status.ssid = onDemandSSIDState
        if let decision, ticket.map({ $0.epoch == onDemand.epoch && onDemand.armed?.profileID == $0.profileID }) ?? true {
            status.decision = decision
            status.evaluatedAtContinuous = clock.continuousNow
        } else if onDemand.armed == nil {
            status.decision = nil; status.evaluatedAtContinuous = nil
        }
        onDemand.status = status
        guard snapshot.onDemand != status else { return }
        snapshot.onDemand = status
        publish()
    }

    private var onDemandSSIDState: OnDemandStatus.SSIDState {
        guard let armed = onDemand.armed, armed.requiresSSID, onDemandNetwork == .wifi else { return .notRequired }
        if onDemand.settleToken != nil || onDemand.ask != nil {
            return .settling
        }
        return switch onDemand.ssid {
        case .known: .known
        case let .unavailable(reason): .unavailable(reason)
        }
    }
}
