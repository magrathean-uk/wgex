// SPDX-License-Identifier: MIT

import Foundation
import Synchronization
import WGEXCore

/// Scripted ``TunnelBackend`` for UI and logic tests: phases, delays on an
/// injected clock, and failures through a ``FaultInjector`` (points
/// `install`, `remove`, `start`, `stop`, `statistics`).
public final class FakeTunnelBackend: TunnelBackend {
    /// One scripted status change.
    public struct Step: Sendable, Hashable {
        /// Phase to publish.
        public var phase: TunnelPhase
        /// Protection to publish with it.
        public var protection: ProtectionState
        /// Delay before publishing.
        public var delay: Duration

        /// Creates a step.
        public init(phase: TunnelPhase, protection: ProtectionState, delay: Duration = .zero) {
            self.phase = phase
            self.protection = protection
            self.delay = delay
        }
    }

    /// A recorded call.
    public enum Call: Sendable, Hashable {
        /// `install`.
        case install(UUID)
        /// `remove`.
        case remove(UUID, purgeSecrets: Bool)
        /// `start`.
        case start(UUID, transport: TransportID?)
        /// `stop`.
        case stop(UUID)
        /// `statistics`.
        case statistics
    }

    private struct State {
        var profiles: [UUID: TunnelProfile] = [:]
        var status = TunnelStatus.idle
        var generation = Generation(rawValue: 0)
        var startScript: [Step]?
        var stopScript: [Step]?
        var calls: [Call] = []
        var statistics: TunnelStatistics?
        var continuations: [UUID: AsyncStream<TunnelStatus>.Continuation] = [:]
    }

    /// What this fake claims to support.
    public let capabilities: BackendCapabilities
    /// Faults consumed by the backend operations.
    public let faults: FaultInjector

    private let clock: any Clock<Duration>
    private let state = Mutex(State())

    /// Creates a backend with the default scripts (preparing, configuring,
    /// active; then stopping, idle).
    public init(
        capabilities: BackendCapabilities = [.killSwitch, .allowLAN],
        clock: any Clock<Duration> = ContinuousClock(),
        faults: FaultInjector = FaultInjector(),
    ) {
        self.capabilities = capabilities
        self.clock = clock
        self.faults = faults
    }

    /// Calls received so far.
    public var calls: [Call] {
        state.withLock { $0.calls }
    }

    /// Profiles currently installed.
    public var installedProfiles: [TunnelProfile] {
        state.withLock { Array($0.profiles.values) }
    }

    /// The last published status.
    public var currentStatus: TunnelStatus {
        state.withLock { $0.status }
    }

    /// Replaces the start script; nil restores the default.
    public func scriptStart(_ steps: [Step]?) {
        state.withLock { $0.startScript = steps }
    }

    /// Replaces the stop script; nil restores the default.
    public func scriptStop(_ steps: [Step]?) {
        state.withLock { $0.stopScript = steps }
    }

    /// Sets the sample returned by ``statistics()``.
    public func setStatistics(_ sample: TunnelStatistics?) {
        state.withLock { $0.statistics = sample }
    }

    /// Publishes a status directly.
    public func publish(_ status: TunnelStatus) {
        let targets = state.withLock { state in
            state.status = status
            return Array(state.continuations.values)
        }
        for continuation in targets {
            continuation.yield(status)
        }
    }

    /// Records the profile.
    public func install(_ profile: TunnelProfile) async throws(TunnelError) {
        try record(.install(profile.id), point: "install")
        state.withLock { $0.profiles[profile.id] = profile }
    }

    /// Forgets the profile.
    public func remove(_ id: UUID, purgeSecrets: Bool) async throws(TunnelError) {
        try record(.remove(id, purgeSecrets: purgeSecrets), point: "remove")
        state.withLock { _ = $0.profiles.removeValue(forKey: id) }
    }

    /// Plays the start script.
    public func start(_ id: UUID, transport: TransportID?) async throws(TunnelError) {
        try record(.start(id, transport: transport), point: "start")
        let (known, generation, script) = state.withLock { state in
            state.generation = state.generation.next()
            return (state.profiles[id] != nil, state.generation, state.startScript)
        }
        guard known else { throw .profileNotFound(id) }
        try await play(script ?? Self.defaultStart(generation), transport: transport)
    }

    /// Plays the stop script.
    public func stop(_ id: UUID) async throws(TunnelError) {
        try record(.stop(id), point: "stop")
        let (generation, script) = state.withLock { ($0.generation, $0.stopScript) }
        try await play(script ?? Self.defaultStop(generation), transport: nil)
    }

    /// Current status first, then every change.
    public func statusUpdates() -> AsyncStream<TunnelStatus> {
        let (stream, continuation) = AsyncStream<TunnelStatus>.makeStream()
        let id = UUID()
        let current = state.withLock { state in
            state.continuations[id] = continuation
            return state.status
        }
        continuation.onTermination = { [weak self] _ in
            self?.state.withLock { _ = $0.continuations.removeValue(forKey: id) }
        }
        continuation.yield(current)
        return stream
    }

    /// The configured sample, or an empty one.
    public func statistics() async throws(TunnelError) -> TunnelStatistics {
        try record(.statistics, point: "statistics")
        return state.withLock { state in
            state.statistics ?? TunnelStatistics(
                generation: state.generation.rawValue,
                sampledAt: Date(timeIntervalSince1970: 0),
                interfaceName: nil,
                listenPort: nil,
                peers: [],
            )
        }
    }

    private func record(_ call: Call, point: FaultInjector.Point) throws(TunnelError) {
        state.withLock { $0.calls.append(call) }
        if let error = faults.fault(at: point, as: TunnelError.self) {
            throw error
        }
    }

    private func play(_ steps: [Step], transport: TransportID?) async throws(TunnelError) {
        for step in steps {
            if step.delay > .zero {
                do {
                    try await clock.sleep(for: step.delay)
                } catch {
                    throw .cancelled
                }
            }
            var status = currentStatus
            status.phase = step.phase
            status.protection = step.protection
            status.transport = transport ?? status.transport
            status.record(TunnelEvent(date: Date(timeIntervalSince1970: 0), kind: .phaseChanged, generation: step.phase.generation))
            publish(status)
        }
    }

    private static func defaultStart(_ generation: Generation) -> [Step] {
        [
            Step(phase: .preparing(generation), protection: .blocked),
            Step(phase: .configuring(generation), protection: .blocked),
            Step(phase: .active(generation), protection: .protected),
        ]
    }

    private static func defaultStop(_ generation: Generation) -> [Step] {
        [
            Step(phase: .stopping(generation, reason: .userRequested), protection: .blocked),
            Step(phase: .idle, protection: .unprotected),
        ]
    }
}
