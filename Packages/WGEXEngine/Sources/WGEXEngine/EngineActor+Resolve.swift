// SPDX-License-Identifier: MIT
#if WGEX_ENGINE_TEST_SUPPORT
    import CWGEXEngineTest
#else
    import CWGEXEngine
#endif
import Dispatch
import Foundation
import Synchronization

/// Public, payload-free resolver failure categories.
public enum EngineResolveError: Error, Sendable, Equatable {
    /// Invalid host, interface index, resolver list or deadline.
    case invalidArgument
    /// Missing, oversized, malformed or failed ABI response.
    case noAnswer
    /// The caller's monotonic deadline expired; a late ABI result is discarded.
    case deadline
}

public extension EngineActor {
    /// Resolves using interface-bound Go sockets on a dedicated thread. No default resolver is used.
    /// The default deadline covers UDP and TCP attempts (2 seconds each) per resolver, plus one second.
    /// Cancellation or timeout resumes the await; a hung C call may retain its dedicated thread until
    /// the ABI returns. Its late result is freed and discarded; the cooperative executor never waits for it.
    nonisolated static func resolve(
        host: String, v4: UInt32?, v6: UInt32?, resolvers: [String], deadline: Duration? = nil,
    ) async throws -> Data {
        guard !host.isEmpty, host.utf8.count <= 253, !host.utf8.contains(0), !resolvers.isEmpty,
              resolvers.allSatisfy({ !$0.isEmpty && !$0.utf8.contains(0) }),
              let index4 = Int32(exactly: v4 ?? v6 ?? 0), let index6 = Int32(exactly: v6 ?? v4 ?? 0),
              index4 > 0, index6 > 0 else { throw EngineResolveError.invalidArgument }
        let json = try String(decoding: JSONEncoder().encode(resolvers), as: UTF8.self)
        return try await resolve(deadline: deadline ?? resolutionDeadline(resolverCount: resolvers.count)) {
            try host.withCString { hostPointer in
                try json.withCString { resolverPointer in
                    guard let pointer = unsafe wgex_resolve(hostPointer, index4, index6, resolverPointer) else {
                        throw EngineResolveError.noAnswer
                    }
                    defer { unsafe wgex_free(pointer) }
                    let count = unsafe strnlen(pointer, 65537)
                    guard count <= 65536 else { throw EngineResolveError.noAnswer }
                    let data = unsafe Data(bytes: pointer, count: count)
                    let response = try JSONDecoder().decode(ResolveResponse.self, from: data)
                    guard response.error == nil || response.error == "" else { throw EngineResolveError.noAnswer }
                    return data
                }
            }
        }
    }

    /// Worst-case Go resolver attempt budget, with a one-second margin and a 60-second cap.
    nonisolated static func resolutionDeadline(resolverCount: Int) -> Duration {
        let count = min(max(resolverCount, 0), 15)
        return .seconds(min(count * 4 + 1, 60))
    }

    /// Injected ABI operation for deterministic tests; never calls a resolver on the host.
    package nonisolated static func resolve(deadline: Duration, call: @escaping @Sendable () throws -> Data) async throws -> Data {
        guard deadline > .zero, deadline <= .seconds(60) else { throw EngineResolveError.invalidArgument }
        let parts = deadline.components
        let seconds = Double(parts.seconds) + Double(parts.attoseconds) / 1e18
        let completion = ResolveCompletion()
        return try await withTaskCancellationHandler {
            try Task.checkCancellation()
            return try await withCheckedThrowingContinuation { continuation in
                guard completion.install(continuation) else { return }
                DispatchQueue.global().asyncAfter(deadline: .now() + seconds) {
                    completion.finish(.failure(EngineResolveError.deadline))
                }
                let thread = Thread {
                    guard !completion.isFinished else { return }
                    do { try completion.finish(.success(call())) }
                    catch is CancellationError { completion.finish(.failure(CancellationError())) }
                    catch { completion.finish(.failure(EngineResolveError.noAnswer)) }
                }
                thread.name = "WGEX resolver"
                thread.start()
            }
        } onCancel: {
            completion.finish(.failure(CancellationError()))
        }
    }
}

private struct ResolveResponse: Decodable {
    let error: String?
}

/// Atomic take gives exactly one resume even when a late ABI completion races the deadline.
private final class ResolveCompletion: Sendable {
    private struct State {
        var continuation: CheckedContinuation<Data, any Error>?
        var pending: Result<Data, any Error>?
        var finished = false
    }

    private let state = Mutex(State())
    fileprivate var isFinished: Bool {
        state.withLock { $0.finished }
    }

    /// Cancellation may arrive before installation. Publish that terminal result exactly once.
    fileprivate func install(_ continuation: CheckedContinuation<Data, any Error>) -> Bool {
        let pending = state.withLock { value in
            if value.finished {
                let result = value.pending
                value.pending = nil
                return result
            }
            value.continuation = continuation
            return nil
        }
        if let pending {
            continuation.resume(with: pending)
            return false
        }
        return true
    }

    fileprivate func finish(_ result: Result<Data, any Error>) {
        let pending = state.withLock { value -> CheckedContinuation<Data, any Error>? in
            guard !value.finished else { return nil }
            value.finished = true
            let continuation = value.continuation
            if continuation == nil {
                value.pending = result
            }
            value.continuation = nil
            return continuation
        }
        pending?.resume(with: result)
    }
}
