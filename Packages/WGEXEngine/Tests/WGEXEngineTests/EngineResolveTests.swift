// SPDX-License-Identifier: MIT
import Dispatch
import Foundation
import Synchronization
import Testing
@testable import WGEXEngine

private struct EngineResolveTests {
    @Test
    func `resolver executes on a dedicated thread`() async throws {
        let result = try await EngineActor.resolve(deadline: .seconds(1)) {
            Data((Thread.current.name == "WGEX resolver" && !Thread.isMainThread) ? [1] : [0])
        }
        #expect(result == Data([1]))
    }

    @Test
    func `deadline returns before a blocked ABI call finishes`() async {
        let started = ContinuousClock.now
        await #expect(throws: EngineResolveError.deadline) {
            try await EngineActor.resolve(deadline: .milliseconds(20)) {
                Thread.sleep(forTimeInterval: 3)
                return Data()
            }
        }
        #expect(started.duration(to: .now) < .seconds(2))
    }

    @Test
    func `resolver errors are mapped without descriptions`() async {
        await #expect(throws: EngineResolveError.noAnswer) {
            try await EngineActor.resolve(deadline: .seconds(1)) { throw CocoaError(.fileReadUnknown) }
        }
        await #expect(throws: EngineResolveError.invalidArgument) {
            try await EngineActor.resolve(host: "invalid", v4: 0, v6: nil, resolvers: [], deadline: .seconds(1))
        }
    }

    @Test(arguments: [1, 2, 8, 15, 16, Int.max])
    func `default deadline covers both query attempts per resolver with margin`(count: Int) {
        let expected: Duration = count >= 15 ? .seconds(60) : .seconds(count * 4 + 1)
        #expect(EngineActor.resolutionDeadline(resolverCount: count) == expected)
    }

    @Test
    func `cancelling a blocked resolver resumes promptly`() async throws {
        let entered = AsyncStream<Void>.makeStream()
        let lateCompletion = AsyncStream<Void>.makeStream()
        let release = DispatchSemaphore(value: 0)
        let task = Task {
            try await EngineActor.resolve(deadline: .seconds(60)) {
                entered.continuation.yield(())
                release.wait()
                lateCompletion.continuation.yield(())
                return Data()
            }
        }
        for await _ in entered.stream {
            break
        }
        let started = ContinuousClock.now
        task.cancel()
        // The delayed release lets the test finish even if cancellation regresses.
        DispatchQueue.global().asyncAfter(deadline: .now() + 3) { release.signal() }
        await #expect(throws: CancellationError.self) { try await task.value }
        #expect(started.duration(to: .now) < .seconds(2))
        release.signal()
        for await _ in lateCompletion.stream {
            break
        }
    }

    @Test
    func `a resolver cancelled before continuation installation never starts work`() async {
        let called = Mutex(false)
        let gate = AsyncStream<Void>.makeStream()
        let task = Task {
            for await _ in gate.stream {
                break
            }
            return try await EngineActor.resolve(deadline: .seconds(60)) {
                called.withLock { $0 = true }
                return Data()
            }
        }
        task.cancel()
        gate.continuation.finish()
        await #expect(throws: CancellationError.self) { try await task.value }
        #expect(!called.withLock { $0 })
    }
}
