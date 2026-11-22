// SPDX-License-Identifier: MIT
import Foundation
import WGEXCore

public extension DaemonDispatcher {
    package func subscribe(_ id: UUID, includeLogs: Bool) throws {
        guard let connection = connections[id] else { throw DaemonError.disconnected }
        let count = connections.values.filter { $0.peer.uid == connection.peer.uid && $0.subscribed }.count
        guard connection.subscribed || count < Self.maximumSubscriptionsPerUID else { throw DaemonError.subscriptionLimit }
        if !connection.subscribed {
            // The retired pump drains its loss marker before the replacement is installed.
            connections[id]?.pump = OrderedEventPump(deliver: connection.callbacks.event)
            connections[id]?.reporter = connection.isApp ? WiFiReporterMembership() : nil
        }
        connections[id]?.subscribed = true
        connections[id]?.includeLogs = includeLogs
    }

    /// Subscribed app connections from the console user: the ADR-030 eligible Wi-Fi reporters.
    func eligibleWiFiReporterCount() async -> Int {
        var count = 0
        for connection in connections.values where await isEligibleReporter(connection) {
            count += 1
        }
        return count
    }

    package func isEligibleReporter(_ connection: Connection) async -> Bool {
        guard connection.isApp, connection.subscribed, connection.clientBuild != nil else { return false }
        return await authorisation.isConsoleUser(connection.peer)
    }

    /// Controller events must carry the profile scope; nil is reserved for redacted global events.
    func publish(_ event: Event, profileID: UUID?, ownerUID: UInt32? = nil) async {
        if publicationTask == nil {
            publicationTask = Task { [weak self, stream = publications.stream] in
                for await publication in stream {
                    await self?.deliverPublication(publication.event, profileID: publication.profileID, ownerUID: publication.ownerUID)
                    publication.completion.resume()
                }
            }
        }
        await withCheckedContinuation { completion in
            publications.continuation.yield(Publication(event: event, profileID: profileID, ownerUID: ownerUID, completion: completion))
        }
    }

    private func deliverPublication(_ event: Event, profileID: UUID?, ownerUID: UInt32?) async {
        var event = event
        if case let .status(status) = event {
            let qualified = await service.qualifyStatus(status, profileID: profileID)
            event = .status(qualified.status)
        }
        let scope = Self.scope(of: event, profileID: profileID)
        let outgoing: Event
        if case let .status(status) = event {
            guard let status = try? await measured(status) else { return }
            outgoing = .status(status)
        } else {
            outgoing = event
        }
        guard let bytes = try? WireCodec.encode(outgoing), bytes.count <= Self.maximumPayloadSize else { return }
        // Resolve visibility before enqueueing; publication callers enter this actor in order.
        var lostReporter = false
        defer {
            if lostReporter {
                Task { [service] in await service.wifiReporterLost() }
            }
        }
        for id in Array(connections.keys) {
            guard let connection = connections[id], connection.subscribed, await permits(
                outgoing, connection: connection, scope: scope, ownerUID: ownerUID,
            ), connections[id]?.subscribed == true, acceptSequence(of: outgoing, connectionID: id) else { continue }
            if connections[id]?.pump?.enqueue(bytes) == false {
                connections[id]?.subscribed = false
                connections[id]?.reporter?.revoke(); connections[id]?.reporter = nil
                lostReporter = lostReporter || connections[id]?.isApp == true
            }
        }
    }

    private static func scope(of event: Event, profileID: UUID?) -> UUID? {
        switch event {
        case let .log(line): line.profileID
        case let .needsSecrets(id): id
        case .wifiNetworkRequested: nil
        default: profileID
        }
    }

    private func acceptSequence(of event: Event, connectionID: UUID) -> Bool {
        guard case let .status(status) = event else { return true }
        guard status.sequence > (connections[connectionID]?.lastStatusSequence ?? 0) else { return false }
        connections[connectionID]?.lastStatusSequence = status.sequence
        return true
    }

    private func permits(_ event: Event, connection: Connection, scope: UUID?, ownerUID: UInt32?) async -> Bool {
        if case .log = event, !connection.includeLogs {
            return false
        }
        if case .wifiNetworkRequested = event {
            return await isEligibleReporter(connection)
        }
        if let ownerUID {
            return ownerUID == connection.peer.uid
        }
        if let scope {
            return await service.ownerUID(for: scope) == connection.peer.uid
        }
        return true
    }

    /// Starts an independent reporting timer; it never invokes PF or other network adapters.
    func startHeartbeat() {
        guard heartbeatTask == nil else { return }
        heartbeatTask = Task { [weak self, clock] in
            while !Task.isCancelled {
                do { try await clock.sleep(.seconds(5)) } catch { return }
                guard !Task.isCancelled else { return }
                await self?.heartbeat()
            }
        }
    }

    /// Cancels reporting without changing any controller or network state.
    func stopHeartbeat() {
        heartbeatTask?.cancel(); heartbeatTask = nil
    }

    /// Whether any connection receives events. A status measured for nobody would only consume a sequence number that the
    /// first status a client asks for should have carried (DEC-011).
    package var hasSubscribers: Bool {
        connections.values.contains { $0.subscribed }
    }

    /// Reports current controller bookkeeping even while operations or secure installation are pending.
    func heartbeat() async {
        // Nothing is published before the run's first publication (DEC-011).
        guard hasSubscribers, startupFence?.isOpen ?? true else { return }
        if let measureStatus {
            guard let measurement = try? await measureStatus() else { return }
            await publish(.status(measurement.status), profileID: measurement.status.activeProfileID, ownerUID: measurement.ownerUID)
            return
        }
        let status: TunnelStatus
        do {
            let peer = VerifiedPeerIdentity(uid: 0, pid: 0, auditSessionID: 0, codeSigningVerdict: .requirementSatisfied)
            let context = DaemonRequestContext(peer: peer, visibleProfileIDs: [], clientBuild: 0)
            guard case let .status(value) = await service.handle(.status, context: context, secrets: nil) else { return }
            status = value
        }
        let profileID = await service.activeProfileID()
        let owner = await service.protectionOwnerUID()
        await publish(.status(status), profileID: profileID, ownerUID: owner)
    }

    package func statusReply(_ fallback: TunnelStatus, uid: UInt32) async throws -> Reply {
        let measurement = try await measurement(fallback, uid: uid)
        let qualified = await service.qualifyStatus(measurement.status, profileID: measurement.status.activeProfileID)
        return try await .status(measured(qualified.status))
    }

    /// The status with its Lab telemetry (M03-T01): one controller measurement, so the sequence, the journal policy and the
    /// owner pf reference are read in the same turn and the sequence advances exactly once. Beside it, the run's first
    /// publication as the startup fence keeps it (DEC-018).
    package func statusTelemetry(context: DaemonRequestContext) async throws -> Reply {
        let reply = await service.handle(.status, context: context, secrets: nil)
        guard case let .status(fallback) = reply else { return reply }
        let measurement = try await measurement(fallback, uid: context.peer.uid)
        let qualified = await service.qualifyStatus(measurement.status, profileID: measurement.status.activeProfileID)
        var telemetry = try await StatusTelemetry(current: StatusPublication(measurement.replacing(status: measured(qualified.status))))
        telemetry.startup = startupRecord(uid: context.peer.uid)
        // The current sample always answers; the record gives way rather than push the reply past the cap.
        if telemetry.startup != nil, (try? WireCodec.encode(Reply.statusTelemetry(telemetry)).count) ?? .max > Self.maximumPayloadSize {
            telemetry.startup = nil
        }
        return .statusTelemetry(telemetry)
    }

    /// The run's first publication, kept unchanged since the fence opened (DEC-018), under the status owner rule; nil before
    /// it exists or when another user owned it.
    private func startupRecord(uid: UInt32) -> StatusPublication? {
        guard let first = startupFence?.first, first.ownerUID == nil || first.ownerUID == uid else { return nil }
        return StatusPublication(first)
    }

    /// The controller's measurement when the dispatcher has one, else the service's own status; owner-scoped either way.
    /// Always taken now, also for a read that waited at the startup fence: the run's first publication travels only as
    /// `startup`, never as the current sample (DEC-018).
    private func measurement(_ fallback: TunnelStatus, uid: UInt32) async throws -> StatusMeasurement {
        guard let measureStatus else { return StatusMeasurement(status: fallback, ownerUID: nil) }
        let measurement = try await measureStatus()
        guard measurement.ownerUID == nil || measurement.ownerUID == uid else {
            throw DaemonError.notAuthorised(.notOwner)
        }
        return measurement
    }

    package func measured(_ original: TunnelStatus) async throws -> TunnelStatus {
        var status = original
        // A production measurement already binds clocks and profile in one controller turn.
        // Unmeasured service fakes use the injected dispatcher clock.
        if status.measuredAt == nil || status.measuredAtContinuous == nil {
            status.activeProfileID = await service.activeProfileID()
            status.measuredAt = Date()
            status.measuredAtContinuous = clock.now()
        }
        status.operationInFlight = status.operationInFlight || operationsInFlight > 0
        if status.sequence > 0 {
            return status
        }
        if let nextStatusSequence {
            status.sequence = try nextStatusSequence()
        } else {
            guard sequence < UInt64.max else { throw DaemonError.disconnected }
            sequence += 1; status.sequence = sequence
        }
        status.notReportingSince = nil
        status.reportingUnavailable = false
        return status
    }
}
