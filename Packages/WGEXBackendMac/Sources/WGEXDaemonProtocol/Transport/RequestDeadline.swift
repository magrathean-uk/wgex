// SPDX-License-Identifier: MIT
import Foundation
import Synchronization

/// Cancellable, one-shot callback deadline. A late callback cannot resume the caller twice.
public struct RequestDeadline: Sendable {
    private let clock: XPCClock

    /// Uses continuous time in production; tests inject a deterministic clock.
    public init(clock: XPCClock = .continuous) {
        self.clock = clock
    }

    /// Wire request budgets, including the stop-current cancellation path. Arming and disarming on-demand share the stop budget:
    /// a disarm stops the tunnel and any control command can wait behind a slow stop on the serial lane (DEC-008, DEC-012).
    public static func duration(for request: Request) -> Duration {
        switch request {
        case .hello: .seconds(10)
        case .startIntent, .startCutover, .abortCutover, .stop, .stopCurrent, .performSecureInstall, .armOnDemand, .disarmOnDemand:
            .seconds(30)
        default: .seconds(5)
        }
    }

    /// Waits for a reply without requiring the remote operation to honour cancellation.
    public func wait(
        for request: Request,
        isolation: isolated (any Actor)? = #isolation,
        budget: Duration? = nil,
        timeoutError: DaemonError = .disconnected,
        discardLateReply: @escaping @Sendable (Data) -> Void = { _ in },
        begin: (@escaping @Sendable (Result<Data, any Error>) -> Void) -> Void,
        interrupted: @escaping @Sendable () async -> Void,
    ) async throws -> Data {
        let pending = PendingReply()
        return try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                pending.install(continuation)
                guard pending.isPending, !Task.isCancelled else {
                    pending.finish(.failure(CancellationError()))
                    return
                }
                begin { result in
                    if !pending.finish(result), case let .success(bytes) = result {
                        discardLateReply(bytes)
                    }
                }
                let timer = Task { [clock] in
                    do { try await clock.sleep(budget ?? Self.duration(for: request)) } catch { return }
                    guard !Task.isCancelled else { return }
                    if pending.finish(.failure(timeoutError)) {
                        await interrupted()
                    }
                }
                pending.installTimer(timer)
            }
        } onCancel: { pending.finish(.failure(CancellationError())) }
    }
}

private final class PendingReply: Sendable {
    private struct State {
        var continuation: CheckedContinuation<Data, any Error>?
        var result: Result<Data, any Error>?
        var timer: Task<Void, Never>?
    }

    private let state = Mutex(State())

    var isPending: Bool {
        state.withLock { $0.result == nil }
    }

    func install(_ continuation: CheckedContinuation<Data, any Error>) {
        let result = state.withLock { state -> Result<Data, any Error>? in
            if let result = state.result {
                return result
            }
            state.continuation = continuation
            return nil
        }
        if let result {
            continuation.resume(with: result)
        }
    }

    func installTimer(_ timer: Task<Void, Never>) {
        state.withLock { state in
            if state.result != nil {
                timer.cancel()
            } else {
                state.timer = timer
            }
        }
    }

    @discardableResult
    func finish(_ result: Result<Data, any Error>) -> Bool {
        let outcome = state.withLock { state -> (Bool, CheckedContinuation<Data, any Error>?) in
            guard state.result == nil else { return (false, nil) }
            state.result = result
            let continuation = state.continuation
            state.continuation = nil
            state.timer?.cancel(); state.timer = nil
            return (true, continuation)
        }
        outcome.1?.resume(with: result)
        return outcome.0
    }
}
