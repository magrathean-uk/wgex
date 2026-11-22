// SPDX-License-Identifier: MIT
import Foundation
import os
import WGEXCore
import WGEXDaemonProtocol

extension DaemonClient {
    package func acceptStatus(_ incoming: TunnelStatus) {
        // A replay cannot change the evidence attached to an already accepted publication.
        let status = sameInstanceEvidence ? (lastMeasuredStatus.flatMap { $0.sequence == incoming.sequence ? $0 : nil } ?? incoming) :
            incoming
        guard let measured = status.measuredAtContinuous, measured.isFinite, status.measuredAt != nil, status.sequence > 0 else {
            statuses.publish(.unreported)
            return
        }
        guard status.sequence >= sequenceFloor else { return }
        sequenceFloor = status.sequence
        sameInstanceEvidence = true
        lastMeasuredStatus = status
        if !(0 ..< 15).contains(clock.now() - measured) || !status.hasRequiredPolicyEvidence(at: clock.now()) {
            evaluateStaleness()
        } else {
            var reported = status
            reported.serviceResponding = true
            statuses.publish(reported)
        }
    }

    /// Checks reporting and policy age without awaiting XPC.
    package func evaluateStaleness() {
        guard connected else { return }
        let responding = lastMeasuredStatus?.measuredAtContinuous.map { (0 ..< 15).contains(clock.now() - $0) } ?? false
        if responding, let status = lastMeasuredStatus, status.hasRequiredPolicyEvidence(at: clock.now()) {
            return
        }
        var unknown = unavailableSnapshot()
        unknown.serviceResponding = responding
        unknown.verificationExpired = responding
        if !responding {
            unknown.notReportingSince = lastMeasuredStatus?.measuredAt ?? connectionStartedAt
        }
        statuses.publish(unknown)
    }

    private func unavailableSnapshot() -> TunnelStatus {
        var unknown = lastMeasuredStatus ?? .unreported
        unknown.protection = .unknown
        unknown.lastReportedAt = lastMeasuredStatus?.measuredAt
        unknown.measuredAt = nil
        unknown.measuredAtContinuous = nil
        unknown.sequence = 0
        unknown.serviceResponding = false
        return unknown
    }

    package func publishUnavailable() {
        var unknown = unavailableSnapshot()
        unknown.reportingUnavailable = true
        unknown.notReportingSince = lastMeasuredStatus?.measuredAt ?? connectionStartedAt
        statuses.publish(unknown)
    }

    /// Requests a daemon measurement; a replayed response retains its original measurement times.
    public func refreshStatus() async throws {
        guard case let .status(status) = try await request(.status) else { throw DaemonError.malformedMessage }
        acceptStatus(status)
    }

    /// Cancels the daemon's current intent, independent of the app selection or outstanding start.
    public func stopCurrent() async throws {
        _ = try await request(.stopCurrent(reason: .userRequested))
    }

    /// Current connection metadata, without changing connectivity.
    public func currentConnectionState() -> DaemonConnectionState {
        connectionStateSnapshot()
    }

    /// Visibility gates automatic reconnection; explicit user requests can still connect.
    public func setSurfaceVisible(_ visible: Bool) {
        surfaceVisible = visible
        if !visible {
            reconnectTask?.cancel()
        } else if !connected, !stopped {
            scheduleReconnect()
        }
    }

    package func scheduleReconnect() {
        guard reconnectTask == nil, surfaceVisible, !stopped else { return }
        reconnectTask = Task { await self.reconnect() }
    }

    package func reconnect() async {
        defer {
            reconnectTask = nil
            if Task.isCancelled, surfaceVisible, !connected, !stopped {
                scheduleReconnect()
            }
        }
        var seconds = 1.0
        while !stopped, surfaceVisible, !Task.isCancelled {
            do {
                try await clock.sleep(.seconds(min(30, seconds * max(0.8, min(1.2, jitter())))))
                guard !stopped, surfaceVisible, !Task.isCancelled else { return }
                _ = try await connect()
                return
            } catch {
                guard !Task.isCancelled else { return }
                if let error = error as? DaemonError {
                    switch error {
                    case .downgradeDetected, .unsupportedProtocolVersion, .unauthorised: return
                    default: break
                    }
                }
                seconds = min(30, seconds * 2)
            }
        }
    }
}

public extension DaemonClient {
    /// The status with its telemetry (M03-T01). A connection this call opens takes no status read of its own, so a fresh
    /// client's first observation is this one: after a daemon restart, the run's first publication (DEC-011).
    func statusTelemetry() async throws -> StatusTelemetry {
        if !connected {
            _ = try await connect(observing: false)
        }
        try await ready()
        let telemetry = try await exchangeTelemetry()
        acceptStatus(telemetry.status)
        return telemetry
    }
}

package extension DaemonClient {
    /// Connection setup's status read; nil while startup restores the policy, when the daemon answers `recovering` within
    /// the request budget instead of a publication (DEC-011), so setup spends no sequence number and the run's first
    /// publication reaches this client as an event or a later read.
    func initialStatus() async throws -> TunnelStatus? {
        do {
            guard case let .status(status) = try await exchange(.status) else { throw DaemonError.malformedMessage }
            return status
        } catch DaemonError.notAuthorised(.notOwner) {
            // A verified non-owner may still inspect secure install; never disclose the active owner's status.
            var unknown = TunnelStatus.idle; unknown.protection = .unknown
            return unknown
        } catch DaemonError.recovering {
            return nil
        }
    }

    /// One telemetry read. An older protocol-8 daemon cannot decode the message (ADR-030 section 8 keeps one exact version)
    /// and answers `malformedMessage`: the client then reads the ordinary status once, its telemetry fields unavailable, and
    /// asks that daemon instance for the ordinary status from then on.
    func exchangeTelemetry() async throws -> StatusTelemetry {
        if !telemetryUnsupported {
            let reply: Reply
            do { reply = try await exchange(.statusTelemetry) } catch DaemonError.malformedMessage {
                telemetryUnsupported = true
                return try await exchangeTelemetry()
            }
            guard case let .statusTelemetry(telemetry) = reply else { throw DaemonError.malformedMessage }
            return telemetry
        }
        guard case let .status(status) = try await exchange(.status) else { throw DaemonError.malformedMessage }
        return StatusTelemetry(status: status)
    }

    static func map(_ error: any Error) -> TunnelError {
        (error as? DaemonError)?.tunnelError ?? .backendUnavailable
    }
}

public extension DaemonClient {
    nonisolated func statusUpdates() -> AsyncStream<TunnelStatus> {
        statuses.stream()
    }

    func statistics() async throws(TunnelError) -> TunnelStatistics {
        do {
            guard case let .statistics(sample) = try await request(.statistics) else { throw DaemonError.malformedMessage }
            return sample
        } catch { throw Self.map(error) }
    }

    /// The daemon's redacted tunnel and daemon log lines at or after `since`, oldest first, through the existing
    /// read-only `logs` request (the daemon scopes them to the caller's profiles and bounds the reply).
    func logs(since: Date?, limit: Int = 512) async throws -> [RedactedLogLine] {
        guard case let .logs(lines) = try await request(.logs(since: since, limit: max(0, min(limit, 512)))) else {
            throw DaemonError.malformedMessage
        }
        return lines
    }
}

package extension DaemonClient {
    func beginStalenessClock() {
        guard stalenessTask == nil else { return }
        stalenessTask = Task { [weak self] in
            while !Task.isCancelled {
                do { try await ContinuousClock().sleep(for: .seconds(1)) } catch { return }
                await self?.evaluateStaleness()
            }
        }
    }
}

package extension DaemonClient {
    /// Lab builds only: fixed phrases and enum case labels, never payloads. The message is built lazily.
    nonisolated func labLog(_ text: @autoclosure () -> String) {
        #if WGEX_LAB_BUILD
            let message = text()
            Logger(subsystem: "com.magrathean.WGEXApp.lab", category: "client").log("\(message, privacy: .public)")
        #endif
    }
}
