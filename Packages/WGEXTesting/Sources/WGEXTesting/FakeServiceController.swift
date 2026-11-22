// SPDX-License-Identifier: MIT

import Foundation
import Synchronization
import WGEXCore

/// ``ServiceControlling`` stand-in for UI tests and debug windows (ADR-017):
/// it never touches the system.
public final class FakeServiceController: ServiceControlling {
    /// A recorded call.
    public enum Call: Sendable, Hashable {
        /// `register`.
        case register
        /// `unregister`.
        case unregister
        /// `openApproval`.
        case openApproval
    }

    private struct State {
        var current: ServiceState
        var stateAfterRegister: ServiceState = .requiresApproval
        var calls: [Call] = []
        var continuations: [UUID: AsyncStream<ServiceState>.Continuation] = [:]
    }

    /// Faults consumed by `register` and `unregister`.
    public let faults: FaultInjector
    private let storage: Mutex<State>

    /// Creates a controller in `initial` state.
    public init(initial: ServiceState = .notRegistered, faults: FaultInjector = FaultInjector()) {
        self.faults = faults
        storage = Mutex(State(current: initial))
    }

    /// Calls received so far.
    public var calls: [Call] {
        storage.withLock { $0.calls }
    }

    /// State `register()` moves to; default `.requiresApproval`.
    public func setStateAfterRegister(_ next: ServiceState) {
        storage.withLock { $0.stateAfterRegister = next }
    }

    /// Moves to `next` and notifies observers (for example "user approved").
    public func transition(to next: ServiceState) {
        let targets = storage.withLock { state in
            state.current = next
            return Array(state.continuations.values)
        }
        for continuation in targets {
            continuation.yield(next)
        }
    }

    /// Current state first, then every change.
    public var state: AsyncStream<ServiceState> {
        let (stream, continuation) = AsyncStream<ServiceState>.makeStream()
        let id = UUID()
        let current = storage.withLock { state in
            state.continuations[id] = continuation
            return state.current
        }
        continuation.onTermination = { [weak self] _ in
            self?.storage.withLock { _ = $0.continuations.removeValue(forKey: id) }
        }
        continuation.yield(current)
        return stream
    }

    /// Moves to the configured post-register state.
    public func register() async throws(ServiceError) {
        let next = try record(.register, point: "register")
        transition(to: next ?? .requiresApproval)
    }

    /// Moves to `.notRegistered`.
    public func unregister() async throws(ServiceError) {
        _ = try record(.unregister, point: "unregister")
        transition(to: .notRegistered)
    }

    /// Records the request.
    public func openApproval() {
        storage.withLock { $0.calls.append(.openApproval) }
    }

    private func record(_ call: Call, point: FaultInjector.Point) throws(ServiceError) -> ServiceState? {
        let next = storage.withLock { state in
            state.calls.append(call)
            return state.stateAfterRegister
        }
        if let error = faults.fault(at: point, as: ServiceError.self) {
            throw error
        }
        return next
    }
}
