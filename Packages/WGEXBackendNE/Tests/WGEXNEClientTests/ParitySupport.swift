// SPDX-License-Identifier: MIT

import Foundation
import WGEXCore
@testable import WGEXNEClient

/// How the fake answers a reload message.
package enum ReloadOutcome: Sendable {
    case reply(ProviderReply)
    case undelivered
    case unreadable
}

/// How a restart's start behaves once the start request is accepted.
package enum RestartScript: Sendable {
    /// The manager is connected inside the start request itself, before any status event could report it: only a
    /// waiter armed together with the request sees it, and the status stream never shows the down and up.
    case connectsAtOnce
    /// The manager stays down until the test emits its statuses.
    case held
}

/// Preferences, status events and provider messages, all in memory and scripted by the test. `running` is what each
/// tunnel actually runs: a start or an accepted reload takes the saved record, a stop, a rejected reload (the provider
/// ends the tunnel itself) or a manager reported down leaves nothing, and every other failure leaves the tunnel as it was.
/// `current` is each manager's status as the system would read it now, whether or not the status stream carried it.
package actor ParitySystem: VPNManagerSystem {
    package private(set) var stored: [VPNManagerRecord]
    package private(set) var running: [UUID: VPNManagerRecord] = [:]
    package private(set) var current: [UUID: VPNStatus] = [:]
    /// Managers whose provider has a statistics subscription.
    package private(set) var subscribed: Set<UUID> = []
    package private(set) var calls: [String] = []
    package private(set) var messages: [ProviderMessage] = []
    package private(set) var targets: [UUID] = []
    private var reload = ReloadOutcome.reply(.ok)
    private var startFailure: TunnelError?
    private var stopFailure: TunnelError?
    private var saveFailures = 0
    private var subscribeHold: SubscribeHold?
    private var restart = RestartScript.connectsAtOnce
    private var confirmations: [UUID: Confirmation] = [:]
    private let armedSignal = AsyncStream<Void>.makeStream()
    private var held: [UUID: CheckedContinuation<Void, Never>] = [:]
    private let heldSignal = AsyncStream<Void>.makeStream()
    private var sequence: UInt64 = 0
    private let events = AsyncStream<VPNStatusEvent>.makeStream()
    package static let sample = TunnelStatistics(
        generation: 3, sampledAt: Date(timeIntervalSince1970: 50), interfaceName: "utun4", listenPort: 51820,
        peers: (try? PublicKey(rawValue: Data(repeating: 2, count: 32))).map { key in
            [PeerStatistics(
                publicKey: key, endpoint: nil, lastHandshake: Date(timeIntervalSince1970: 40),
                rxBytes: 1200, txBytes: 3400, persistentKeepalive: nil,
            )]
        } ?? [],
    )

    package init(records: [VPNManagerRecord] = []) {
        stored = records
        for record in records {
            current[record.id] = record.status
            if VPNManagerRecord.isLive(record.status) {
                running[record.id] = record
            }
        }
    }

    package func script(restart script: RestartScript) {
        restart = script
    }

    /// Restart confirmations still waiting for their manager.
    package var pendingConfirmations: Int {
        confirmations.count
    }

    /// Suspends until a restart's start request has been accepted with its waiter armed.
    package func waitUntilRestartArmed() async {
        var iterator = armedSignal.stream.makeAsyncIterator()
        _ = await iterator.next()
    }

    package func script(reload outcome: ReloadOutcome) {
        reload = outcome
    }

    package func failStart(_ error: TunnelError?) {
        startFailure = error
    }

    package func failStop(_ error: TunnelError?) {
        stopFailure = error
    }

    package func failSaves(_ count: Int) {
        saveFailures = count
    }

    /// From now on a subscribe request is taken by the provider at once but answered only on `releaseHeld()`. A send
    /// cancelled meanwhile returns at once without the reply, as the real adapter's does.
    package func holdSubscribeReplies() {
        subscribeHold = .reply
    }

    /// From now on a subscribe request waits before the provider takes it until `releaseHeld()`. With
    /// `checksCancellation` a send cancelled meanwhile returns at once and is never delivered, as the real adapter's
    /// does; without it the request is delivered on release whatever happened to its sender.
    package func holdSubscribeDelivery(checksCancellation: Bool) {
        subscribeHold = .delivery(checksCancellation: checksCancellation)
    }

    package func releaseHeld() {
        subscribeHold = nil
        let all = held.values; held = [:]
        for continuation in all {
            continuation.resume()
        }
    }

    /// Suspends until a subscribe request is held, before or after the provider took it.
    package func waitUntilSubscribeHeld() async {
        var iterator = heldSignal.stream.makeAsyncIterator()
        _ = await iterator.next()
    }

    /// On-demand or Settings brings the tunnel back up; it reads the saved record.
    package func reconnect(_ manager: UUID) {
        running[manager] = stored.first { $0.id == manager }
        emit(manager, .connected)
    }

    /// Arms the waiter, reads the current status and takes the start request in one actor step, as the real adapter does
    /// on MainActor; the waiter is fed by `emit`, never by the status stream.
    package func startConfirmed(_ id: UUID, revision: String?) async throws {
        calls.append("start")
        if let startFailure {
            throw startFailure
        }
        let record = stored.first { $0.id == id }
        guard record?.profileRevision == revision else { throw TunnelError.cancelled }
        if restart == .connectsAtOnce {
            running[id] = record; current[id] = .connected
        }
        let key = UUID()
        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, any Error>) in
                var observation = StartObservation()
                if let outcome = observation.observe(current[id] ?? .invalid) {
                    continuation.resume(with: Self.result(outcome))
                } else if Task.isCancelled {
                    continuation.resume(throwing: CancellationError())
                } else {
                    confirmations[key] = Confirmation(manager: id, observation: observation, continuation: continuation)
                    armedSignal.continuation.yield()
                }
            }
        } onCancel: {
            Task { await self.cancelConfirmation(key) }
        }
    }

    private func cancelConfirmation(_ key: UUID) {
        confirmations.removeValue(forKey: key)?.continuation.resume(throwing: CancellationError())
    }

    private static func result(_ outcome: StartObservation.Outcome) -> Result<Void, any Error> {
        outcome == .connected ? .success(()) : .failure(TunnelError.backendUnavailable)
    }

    package func loadAll() -> [VPNManagerRecord] {
        calls.append("load"); return stored
    }

    package func save(_ record: VPNManagerRecord) throws {
        calls.append("save")
        if saveFailures > 0 {
            saveFailures -= 1
            throw TunnelError.backendUnavailable
        }
        stored.removeAll { $0.configuration.profileID == record.configuration.profileID }; stored.append(record)
    }

    package func remove(_ id: UUID) {
        calls.append("remove"); stored.removeAll { $0.id == id }
    }

    package func start(_ id: UUID, transport _: UUID?) throws {
        calls.append("start")
        if let startFailure {
            throw startFailure
        }
        running[id] = stored.first { $0.id == id }
    }

    package func stop(_ id: UUID) throws {
        calls.append("stop")
        if let stopFailure {
            throw stopFailure
        }
        running[id] = nil; subscribed.remove(id); current[id] = .disconnected
    }

    package func statusEvents() -> AsyncStream<VPNStatusEvent> {
        events.stream
    }

    /// A status the stream delivers late, after the system has moved on: it reaches the client's report only, never a
    /// restart waiter, which reads the system's current status instead.
    package func replay(_ manager: UUID, _ status: VPNStatus) {
        sequence += 1
        events.continuation.yield(VPNStatusEvent(managerID: manager, sequence: sequence, status: status))
    }

    /// Status changes as NE reports them, whoever caused them (this app, Settings > VPN or on-demand). Without `stream`
    /// the change reaches restart waiters only, as when the lossy status stream coalesces it away.
    package func emit(_ manager: UUID, _ status: VPNStatus, stream: Bool = true) {
        current[manager] = status
        if status == .disconnected || status == .invalid {
            running[manager] = nil; subscribed.remove(manager)
        }
        if stream {
            sequence += 1
            events.continuation.yield(VPNStatusEvent(managerID: manager, sequence: sequence, status: status))
        }
        for (key, waiting) in confirmations where waiting.manager == manager {
            var observation = waiting.observation
            if let outcome = observation.observe(status) {
                confirmations[key] = nil
                // The restarted tunnel runs what it read at its start: the saved record.
                if outcome == .connected {
                    running[manager] = stored.first { $0.id == manager }
                }
                waiting.continuation.resume(with: Self.result(outcome))
            } else {
                confirmations[key]?.observation = observation
            }
        }
    }

    package func sendProviderMessage(_ id: UUID, data: Data) async throws -> Data {
        let message = try ProviderCodec.decode(ProviderMessage.self, from: data)
        if case .subscribeStats = message, case let .delivery(checksCancellation)? = subscribeHold {
            await park(cancellable: checksCancellation)
            if checksCancellation {
                try Task.checkCancellation()
            }
        }
        calls.append("message"); messages.append(message); targets.append(id)
        switch message {
        case .reload: return try reloadReply(id)
        case .statistics: return try ProviderCodec.encode(ProviderReply.statistics(Self.sample))
        case let .subscribeStats(interval): return try await ProviderCodec.encode(subscribe(id, interval: interval))
        case .unsubscribeStats:
            subscribed.remove(id)
            return try ProviderCodec.encode(ProviderReply.ok)
        default: return try ProviderCodec.encode(ProviderReply.error(.backendUnavailable))
        }
    }

    private func reloadReply(_ id: UUID) throws -> Data {
        switch reload {
        case let .reply(scripted):
            if case .ok = scripted {
                running[id] = stored.first { $0.id == id }
            } else if case .error = scripted {
                running[id] = nil; subscribed.remove(id)
            }
            return try ProviderCodec.encode(scripted)
        case .undelivered: throw TunnelError.backendUnavailable
        case .unreadable: return Data("not a reply".utf8)
        }
    }

    private func subscribe(_ id: UUID, interval: TimeInterval) async throws -> ProviderReply {
        guard (2 ... 3600).contains(interval) else { return .error(.invalidConfiguration(.statisticsInterval)) }
        subscribed.insert(id)
        if case .reply? = subscribeHold {
            await park(cancellable: true)
            try Task.checkCancellation()
        }
        return .ok
    }

    /// Waits until `releaseHeld()`, or, when `cancellable`, until the send is cancelled.
    private func park(cancellable: Bool) async {
        let hold = UUID()
        await withTaskCancellationHandler {
            await withCheckedContinuation { continuation in
                heldSignal.continuation.yield()
                if cancellable, Task.isCancelled {
                    continuation.resume()
                } else {
                    held[hold] = continuation
                }
            }
        } onCancel: {
            if cancellable {
                Task { await self.unpark(hold) }
            }
        }
    }

    private func unpark(_ hold: UUID) {
        held.removeValue(forKey: hold)?.resume()
    }
}

/// A restart waiting for its manager to connect or fail.
private struct Confirmation {
    let manager: UUID
    var observation: StartObservation
    let continuation: CheckedContinuation<Void, any Error>
}

/// Where the fake holds a subscribe request.
private enum SubscribeHold {
    case reply
    case delivery(checksCancellation: Bool)
}

package enum Profiles {
    package static func pair() throws -> (TunnelProfile, TunnelProfile) {
        let first = try GoldenFixture.profile()
        let second = TunnelProfile(
            id: UUID(), name: "Second", interface: first.interface, peers: first.peers, secrets: first.secrets,
            protection: first.protection, onDemand: first.onDemand, createdAt: first.createdAt,
        )
        return (first, second)
    }

    package static func record(_ profile: TunnelProfile, _ status: VPNStatus) -> VPNManagerRecord {
        VPNManagerRecord(
            id: profile.id, configuration: ProtocolConfigurationBuilder.build(profile, platform: .iOS), name: profile.name,
            status: status, profileRevision: NEManagerClient.profileRevision(profile),
        )
    }
}

/// Reads updates until one matches, keeping every update read on the way.
package struct Updates {
    package var iterator: AsyncStream<TunnelStatus>.Iterator
    package var seen: [TunnelStatus] = []

    package init(_ client: NEManagerClient) {
        iterator = client.statusUpdates().makeAsyncIterator()
    }

    package mutating func until(_ predicate: (TunnelStatus) -> Bool) async -> TunnelStatus? {
        while let status = await iterator.next(isolation: #isolation) {
            seen.append(status)
            if predicate(status) {
                return status
            }
        }
        return nil
    }
}

package func isActive(_ status: TunnelStatus, _ profile: TunnelProfile) -> Bool {
    if case .active = status.phase {
        return status.activeProfileID == profile.id
    }
    return false
}

package func generation(_ status: TunnelStatus?) -> Generation? {
    switch status?.phase {
    case let .preparing(value), let .active(value): value
    default: nil
    }
}
