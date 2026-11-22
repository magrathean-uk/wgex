// SPDX-License-Identifier: MIT

import Foundation
import WGEXCore
import WGEXEngineInterface

/// ``EngineControlling`` stand-in that records calls (never key material: a
/// configuration is recorded by length only) and fails where a
/// ``FaultInjector`` says. Fault points are the method names.
public actor FakeEngine: EngineControlling {
    /// A recorded call.
    public enum Call: Sendable, Hashable {
        /// `setConfiguration` with the document length.
        case setConfiguration(byteCount: Int)
        /// `updateEndpoints` with the number of peers.
        case updateEndpoints(count: Int)
        /// `up`.
        case up
        /// `down`.
        case down
        /// `bumpSockets`.
        case bumpSockets(v4: UInt32?, v6: UInt32?)
        /// `setTransport`.
        case setTransport(TransportSpec)
        /// `forceHandshake`.
        case forceHandshake
        /// `statistics`.
        case statistics
        /// `shutdown`.
        case shutdown
    }

    /// Configuration the engine was created with.
    public nonisolated let configuration: EngineConfiguration
    /// Faults consumed by the engine methods.
    public nonisolated let faults: FaultInjector
    /// Log lines pushed with ``emit(log:)``.
    public nonisolated let logs: AsyncStream<EngineLogLine>
    /// Events pushed with ``emit(_:)``.
    public nonisolated let events: AsyncStream<EngineEvent>

    /// Calls received so far.
    public private(set) var calls: [Call] = []
    /// True between `up` and `down`.
    public private(set) var isUp = false
    /// True after `shutdown`.
    public private(set) var isShutDown = false

    private let logContinuation: AsyncStream<EngineLogLine>.Continuation
    private let eventContinuation: AsyncStream<EngineEvent>.Continuation
    private var pauseShutdown = false
    private var shutdownWaiter: CheckedContinuation<Void, Never>?
    private var sample: TunnelStatistics

    /// Creates an engine with its own fault injector.
    public init(configuration: EngineConfiguration) throws(EngineError) {
        self.init(configuration: configuration, faults: FaultInjector())
    }

    /// Creates an engine with a shared fault injector.
    public init(configuration: EngineConfiguration, faults: FaultInjector) {
        self.configuration = configuration
        self.faults = faults
        (logs, logContinuation) = AsyncStream.makeStream()
        (events, eventContinuation) = AsyncStream.makeStream()
        sample = TunnelStatistics(generation: 0, sampledAt: Date(timeIntervalSince1970: 0), interfaceName: nil, listenPort: nil, peers: [])
    }

    /// Pushes an engine event.
    public func emit(_ event: EngineEvent) {
        eventContinuation.yield(event)
    }

    /// Pushes a log line.
    public func emit(log line: EngineLogLine) {
        logContinuation.yield(line)
    }

    /// Sets the sample returned by ``statistics()``.
    public func setStatistics(_ sample: TunnelStatistics) {
        self.sample = sample
    }

    /// Records the document length.
    public func setConfiguration(_ uapi: borrowing UAPIDocument) throws(EngineError) {
        try record(.setConfiguration(byteCount: uapi.byteCount), point: "setConfiguration")
    }

    /// Records the update.
    public func updateEndpoints(_ updates: [PublicKey: Endpoint]) throws(EngineError) {
        try record(.updateEndpoints(count: updates.count), point: "updateEndpoints")
    }

    /// Marks the engine up.
    public func up() throws(EngineError) {
        try record(.up, point: "up")
        isUp = true
    }

    /// Marks the engine down.
    public func down() throws(EngineError) {
        try record(.down, point: "down")
        isUp = false
    }

    /// Records the rebind.
    public func bumpSockets(v4: UInt32?, v6: UInt32?) throws(EngineError) {
        try record(.bumpSockets(v4: v4, v6: v6), point: "bumpSockets")
    }

    /// Records the transport.
    public func setTransport(_ spec: TransportSpec) throws(EngineError) {
        try record(.setTransport(spec), point: "setTransport")
    }

    /// Records the handshake request.
    public func forceHandshake() throws(EngineError) {
        try record(.forceHandshake, point: "forceHandshake")
    }

    /// The configured sample.
    public func statistics() throws(EngineError) -> TunnelStatistics {
        try record(.statistics, point: "statistics")
        return sample
    }

    package func suspendShutdown() {
        pauseShutdown = true
    }

    package func resumeShutdown() {
        pauseShutdown = false
        shutdownWaiter?.resume(); shutdownWaiter = nil
    }

    /// Finishes the streams; idempotent.
    public func shutdown() async {
        guard !isShutDown else { return }
        calls.append(.shutdown)
        isShutDown = true
        isUp = false
        logContinuation.finish()
        eventContinuation.finish()
        if pauseShutdown {
            await withCheckedContinuation { shutdownWaiter = $0 }
        }
    }

    private func record(_ call: Call, point: FaultInjector.Point) throws(EngineError) {
        guard !isShutDown else { throw .invalidHandle }
        calls.append(call)
        if let error = faults.fault(at: point, as: EngineError.self) {
            throw error
        }
    }
}
