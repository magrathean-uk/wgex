// SPDX-License-Identifier: MIT
import Foundation
import Synchronization
import Testing
import WGEXCore
@testable import WGEXDaemonCore
import WGEXDaemonProtocol

@Suite(.timeLimit(.minutes(1)))
private struct Guest5HandoffErasureTests {
    @Test
    func `late nonempty dispatcher reply is erased and cannot start or replace the timeout`() async throws {
        let h = try ControllerHarness(); try await h.install()
        let gate = LateHandoffGate(), erased = Mutex<Bool?>(nil), replies = Mutex<[Reply]>([])
        let codes = Mutex<[DaemonFailure.Code]>([])
        let dispatcher = DaemonDispatcher(
            service: h.controller, daemonVersion: "test", daemonBuild: 10, minimumClientBuild: 1,
            authorisation: .init(isConsoleUser: { _ in true }),
            clock: .init(now: { Double(h.clock.now.components.seconds) }, sleep: { try await h.clock.sleep(for: $0) }),
            secretFailure: { failure in codes.withLock { $0.append(failure.kind) } },
        )
        let app = InMemoryXPCTransport(daemon: dispatcher, peer: CompositionFixture.peer(501))
        try await app.connect(callbacks: .init(provideSecrets: { _ in
            await gate.wait()
            let wire = try ControllerHarness.bundle().wireBytes()
            return wire.withUnsafeBytes { raw in
                guard let base = raw.baseAddress else { return Data() }
                let allocation = UnsafeMutableRawPointer.allocate(byteCount: raw.count, alignment: 1)
                allocation.copyMemory(from: base, byteCount: raw.count)
                return Data(bytesNoCopy: allocation, count: raw.count, deallocator: .custom { pointer, count in
                    let zeroed = UnsafeRawBufferPointer(start: pointer, count: count).allSatisfy { $0 == 0 }
                    erased.withLock { $0 = zeroed }
                    pointer.deallocate()
                })
            }
        }))
        _ = try await call(app, .hello(clientVersion: "test", clientBuild: 10))
        _ = try await call(app, .subscribeEvents(includeLogs: false))
        let trial = Task {
            let reply = try await call(app, .startCutover(profileID: h.profile.id, confirmWithin: 60, hasSecrets: false))
            replies.withLock { $0.append(reply) }
            return reply
        }
        try await waitForCondition { h.clock.pendingSleeps.contains(.seconds(5)) && gate.isWaiting }
        h.clock.advance(.seconds(5))
        #expect(try await trial.value == .error(.tunnel(.timedOut)))
        #expect(erased.withLock { $0 } == nil)
        gate.release()
        try await waitForCondition { erased.withLock { $0 != nil } }
        #expect(erased.withLock { $0 } == true)
        #expect(replies.withLock { $0 } == [.error(.tunnel(.timedOut))])
        #expect(codes.withLock { $0 } == [.tunnelTimedOut])
        #expect(h.journal.snapshot().intent == nil && h.journal.snapshot().cutover == nil)
        #expect(!h.trace.calls.contains("engine.create"))
        await app.invalidate()
    }

    @Test(arguments: [
        DaemonError.secretsUnavailable, .tunnel(.timedOut), .disconnected,
        .profileNotFound(UUID(uuid: (1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1))),
        .protectionUnknown(reason: "private-adapter-context"),
    ])
    func `ordinary composition emits only the handoff integer in the fixed log vocabulary`(_ failure: DaemonError) async throws {
        let h = try ControllerHarness(); try await h.install()
        let lines = Mutex<[String]>([])
        let composition = DaemonComposition(
            controller: h.controller, daemonVersion: "test", daemonBuild: 10, minimumClientBuild: 1,
            authorisation: .init(isConsoleUser: { _ in true }), nextStatusSequence: { 1 },
            handoffLog: { line in lines.withLock { $0.append(line) } },
        )
        let app = InMemoryXPCTransport(daemon: composition.dispatcher, peer: CompositionFixture.peer(501))
        try await app.connect(callbacks: .init(provideSecrets: { _ in throw failure }))
        _ = try await call(app, .hello(clientVersion: "test", clientBuild: 10))
        _ = try await call(app, .subscribeEvents(includeLogs: false))
        let reply = try await call(app, .startCutover(profileID: h.profile.id, confirmWithin: 60, hasSecrets: false))
        guard case let .error(error) = reply else { Issue.record("Handoff unexpectedly started"); return }
        let code = DaemonFailure.classify(error).rawValue
        #expect(lines.withLock { $0 } == ["handoff failed, type: UnknownError case: withheld code: \(code)"])
        #expect(h.journal.snapshot().intent == nil && h.journal.snapshot().cutover == nil)
        #expect(!h.trace.calls.contains("engine.create"))
        await app.invalidate()
    }

    private func call(_ transport: InMemoryXPCTransport, _ request: Request) async throws -> Reply {
        try await WireCodec.decode(Reply.self, from: transport.send(Envelope(body: request).encoded(), secrets: nil))
    }
}

private final class LateHandoffGate: Sendable {
    private let pending = Mutex<CheckedContinuation<Void, Never>?>(nil)
    var isWaiting: Bool {
        pending.withLock { $0 != nil }
    }

    func wait() async {
        await withCheckedContinuation { continuation in pending.withLock { $0 = continuation } }
    }

    func release() {
        pending.withLock { value in
            value?.resume(); value = nil
        }
    }
}
