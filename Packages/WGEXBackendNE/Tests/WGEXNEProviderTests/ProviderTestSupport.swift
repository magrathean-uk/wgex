// SPDX-License-Identifier: MIT

import Foundation
import Synchronization
import Testing
import WGEXCore
import WGEXEngineInterface
import WGEXNEProvider

package final class TestClock: ProviderClock {
    private struct Sleeper {
        let id: UUID
        let deadline: TimeInterval
        let continuation: CheckedContinuation<Void, any Error>
    }

    private struct State {
        var now: TimeInterval = 0
        var sleepers: [Sleeper] = []
    }

    private let state = Mutex(State())
    package var continuousNow: TimeInterval {
        state.withLock { $0.now }
    }

    package var wallNow: Date {
        Date(timeIntervalSince1970: 1_000_000 + continuousNow)
    }

    package var sleeperCount: Int {
        state.withLock { $0.sleepers.count }
    }

    package func sleep(until deadline: TimeInterval) async throws {
        let id = UUID()
        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, any Error>) in
                // Decided under the lock, resumed outside it, as HostClock does (consistency). The deadlock this rule prevents is
                // on the advance path, which resumes a task that is already awaiting: that resume needs the task's status-record
                // lock, a cancel holds it while its handler wants this lock. Here the continuation is resumed before its task
                // awaits it, which needs no such lock; the rule is kept, not required, on this path (M1-31 VERIFY INFO 3).
                let outcome = state.withLock { state -> Result<Void, CancellationError>? in
                    if Task.isCancelled {
                        return .failure(CancellationError())
                    } else if deadline <= state.now {
                        return .success(())
                    }
                    state.sleepers.append(Sleeper(id: id, deadline: deadline, continuation: continuation))
                    return nil
                }
                switch outcome {
                case .failure: continuation.resume(throwing: CancellationError())
                case .success: continuation.resume()
                case nil: break
                }
            }
        } onCancel: {
            let continuation = self.state.withLock { state -> CheckedContinuation<Void, any Error>? in
                guard let index = state.sleepers.firstIndex(where: { $0.id == id }) else { return nil }
                return state.sleepers.remove(at: index).continuation
            }
            continuation?.resume(throwing: CancellationError())
        }
    }

    package func advance(_ seconds: TimeInterval) {
        let ready = state.withLock { state in
            state.now += seconds
            let ready = state.sleepers.filter { $0.deadline <= state.now }
            state.sleepers.removeAll { $0.deadline <= state.now }
            return ready
        }
        for sleeper in ready {
            sleeper.continuation.resume()
        }
    }
}

package actor FakeProviderSystem: ProviderSystem {
    package private(set) var settings: [NESettings?] = []
    package private(set) var reasserting = false
    package private(set) var quiesced = false
    package private(set) var descriptors = 0
    package private(set) var cancels: [TunnelError] = []
    private let clock: TestClock
    private let delay: TimeInterval
    package var delayClear = false
    private var pathContinuations: [AsyncStream<ProviderPath>.Continuation] = []
    private var holdQuiesce = false
    private var parkedQuiesce: [CheckedContinuation<Void, Never>] = []
    package init(clock: TestClock, delay: TimeInterval = 0) {
        self.clock = clock; self.delay = delay
    }

    package func apply(_ settings: NESettings?) async throws {
        self.settings.append(settings)
        let wait = settings == nil ? (delayClear ? 20 : 0) : delay
        if wait > 0 {
            try await clock.sleep(until: clock.continuousNow + wait)
        }
    }

    package func setDelayClear(_ value: Bool) {
        delayClear = value
    }

    package func findUTunDescriptor() -> Int32 {
        descriptors += 1; return 42
    }

    package func paths() -> AsyncStream<ProviderPath> {
        let (stream, continuation) = AsyncStream<ProviderPath>.makeStream()
        pathContinuations.append(continuation)
        return stream
    }

    /// Delivers a path to the newest stream the controller subscribed to.
    package func yieldPath(_ path: ProviderPath) {
        pathContinuations.last?.yield(path)
    }

    /// Parks `quiesceTimers` calls, ignoring cancellation like a system call already issued, until `releaseQuiesce`.
    package func setHoldQuiesce(_ value: Bool) {
        holdQuiesce = value
    }

    package var quiesceParked: Int {
        parkedQuiesce.count
    }

    package func releaseQuiesce() {
        holdQuiesce = false
        let waiting = parkedQuiesce; parkedQuiesce = []
        for continuation in waiting {
            continuation.resume()
        }
    }

    package func setReasserting(_ value: Bool) {
        reasserting = value
    }

    package func quiesceTimers(_ value: Bool) async {
        quiesced = value
        if holdQuiesce {
            await withCheckedContinuation { parkedQuiesce.append($0) }
        }
    }

    package func cancel(_ error: TunnelError) {
        cancels.append(error)
    }
}

package struct FakeProfileLoader: ProviderProfileLoading {
    package let profile: TunnelProfile
    package func load(_ id: UUID) throws -> TunnelProfile {
        guard id == profile.id else { throw TunnelError.profileNotFound(id) }
        return profile
    }
}

package struct FakeSecretLoader: ProviderSecretLoading {
    package func load(for profile: TunnelProfile) throws -> ParsedSecrets {
        var data = Data(repeating: 3, count: 32)
        return try ParsedSecrets(bytes: SecretBytes(wiping: &data), references: [profile.secrets.privateKey: 0 ..< 32])
    }
}

package actor FakeResolver: ProviderEndpointResolving {
    package private(set) var queries: [UInt32?] = []
    package func resolve(_ profile: TunnelProfile, interfaceIndex: UInt32?) -> [PublicKey: Endpoint] {
        queries.append(interfaceIndex)
        return Dictionary(uniqueKeysWithValues: profile.peers.compactMap { peer in peer.endpoint.map { (peer.publicKey, $0) } })
    }
}

package func eventually(_ condition: () async -> Bool, sourceLocation: SourceLocation = #_sourceLocation) async {
    for _ in 0 ..< 10000 {
        if await condition() {
            return
        }
        await Task.yield()
    }
    Issue.record("Condition did not become true", sourceLocation: sourceLocation)
}

/// Produces a fresh engine for each generation of the same controller.
package final class RecordingEngineFactory: Sendable {
    private let storage = Mutex<[FakeEngine]>([])
    /// Shared by every engine this factory makes, so a test can arm a fault for the next generation.
    package let faults = FaultInjector()
    package var engines: [FakeEngine] {
        storage.withLock { $0 }
    }

    package func make(_ configuration: EngineConfiguration) throws -> any EngineControlling {
        let engine = FakeEngine(configuration: configuration, faults: faults)
        storage.withLock { $0.append(engine) }
        return engine
    }
}
