// SPDX-License-Identifier: MIT

import Foundation
import Testing
import WGEXCore
@testable import WGEXNEClient

/// Every sleep the client asks for, none of which ends until `fire()` or cancellation, so no time-based outcome can
/// happen unless the test lets it.
private actor SleepProbe {
    private(set) var requested: [Duration] = []
    private var sleepers: [UUID: CheckedContinuation<Void, any Error>] = [:]
    private let requestSignal = AsyncStream<Void>.makeStream()

    var pending: Int {
        sleepers.count
    }

    nonisolated func sleep(_ duration: Duration) async throws {
        let key = UUID()
        try await withTaskCancellationHandler {
            try await park(key, duration)
        } onCancel: {
            Task { await self.cancel(key) }
        }
    }

    /// Suspends until some sleep has been requested.
    func waitForRequest() async {
        guard requested.isEmpty else { return }
        var iterator = requestSignal.stream.makeAsyncIterator()
        _ = await iterator.next()
    }

    /// Ends every pending sleep as if its time had passed.
    func fire() {
        let all = sleepers.values; sleepers = [:]
        for sleeper in all {
            sleeper.resume()
        }
    }

    private func park(_ key: UUID, _ duration: Duration) async throws {
        requested.append(duration); requestSignal.continuation.yield()
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, any Error>) in
            if Task.isCancelled {
                continuation.resume(throwing: CancellationError())
            } else {
                sleepers[key] = continuation
            }
        }
    }

    private func cancel(_ key: UUID) {
        sleepers.removeValue(forKey: key)?.resume(throwing: CancellationError())
    }
}

/// Set when an install has returned.
private actor Returned {
    private(set) var value = false

    func set() {
        value = true
    }
}

/// How a restart fails to come back.
private enum Failure: CaseIterable, Sendable {
    case refused, wentDown, invalid
}

/// A newer operation that arrives while a restart waits.
private enum Interruption: CaseIterable, Sendable {
    case stop, switchTunnel, remove
}

/// A task's outcome, or nil when it has not ended within `limit`, so a test fails instead of hanging.
private func outcome(of task: Task<Void, any Error>, within limit: Duration) async -> Result<Void, any Error>? {
    let settled = Settled()
    Task { await settled.set(task.result) }
    let deadline = ContinuousClock.now.advanced(by: limit)
    while ContinuousClock.now < deadline {
        if let result = await settled.result {
            return result
        }
        try? await Task.sleep(for: .milliseconds(10))
    }
    return nil
}

private actor Settled {
    private(set) var result: Result<Void, any Error>?

    func set(_ result: Result<Void, any Error>) {
        self.result = result
    }
}

/// Spins on actor hops until `condition` holds or the spin budget runs out.
private func eventually(_ condition: () async -> Bool) async {
    var spins = 0
    while await !condition(), spins < 10000 {
        spins += 1; await Task.yield()
    }
}

@Suite(.timeLimit(.minutes(1)))
private struct ApplyCompletionTests {
    private static let bound = Duration.seconds(45)

    private func connected(
        _ restart: RestartScript = .held, others: [TunnelProfile] = [],
    ) async throws -> (ParitySystem, NEManagerClient, SleepProbe, TunnelProfile) {
        let profile = try GoldenFixture.profile()
        let system = ParitySystem(records: [Profiles.record(profile, .connected)] + others.map { Profiles.record($0, .disconnected) })
        await system.script(restart: restart)
        let probe = SleepProbe()
        let client = NEManagerClient(system: system, platform: .iOS, sleep: { try await probe.sleep($0) })
        return (system, client, probe, profile)
    }

    private func flagsEdited(_ profile: TunnelProfile) -> TunnelProfile {
        var edited = profile
        edited.protection.ios.includeAllNetworks.toggle()
        return edited
    }

    @Test
    func `an in-place reload completes on the provider's ok without a restart or a waiter`() async throws {
        let (system, client, probe, original) = try await connected()
        var profile = original
        profile.interface.mtu = 1380
        try await client.install(profile)
        #expect(await Array(system.calls.dropFirst(3)) == ["message"])
        #expect(await system.messages == [.reload(profileID: profile.id)])
        #expect(await system.running[profile.id]?.profileRevision == NEManagerClient.profileRevision(profile))
        #expect(await system.pendingConfirmations == 0)
        #expect(await !probe.requested.contains(Self.bound))
        await client.shutdown()
    }

    @Test
    func `a restart completes only on its own connected status, however late it comes`() async throws {
        let (system, client, probe, original) = try await connected()
        let profile = flagsEdited(original)
        let returned = Returned()
        let install = Task {
            try await client.install(profile)
            await returned.set()
        }
        await system.waitUntilRestartArmed()
        await probe.waitForRequest()
        // The stopped manager's own disconnected status comes from before the start; coming up and reasserting are not
        // the connection either, and a stale connected status the stream delivers late is not this restart's.
        await system.emit(profile.id, .disconnected)
        await system.emit(profile.id, .connecting)
        await system.emit(profile.id, .reasserting)
        await system.replay(profile.id, .connected)
        // Well past any short window: only the event ends it, and the only timer is the bound, which has not passed.
        try await Task.sleep(for: .milliseconds(2500))
        #expect(await returned.value == false)
        #expect(await system.pendingConfirmations == 1)
        #expect(await probe.requested == [Self.bound])
        await system.emit(profile.id, .connected)
        try await install.value
        #expect(await returned.value)
        #expect(await Array(system.calls.dropFirst(3)) == ["stop", "start"])
        #expect(await system.running[profile.id]?.profileRevision == NEManagerClient.profileRevision(profile))
        await eventually { await probe.pending == 0 }
        #expect(await probe.pending == 0)
        await client.shutdown()
    }

    /// The status stream may never show a quick down and up: the manager connects inside the start request, or its
    /// changes are coalesced away before the client reads them. The confirmation reads the system, so it still ends.
    @Test(arguments: [true, false])
    func `a restart the status stream never shows still completes`(connectsAtOnce: Bool) async throws {
        let (system, client, _, original) = try await connected(connectsAtOnce ? .connectsAtOnce : .held)
        var updates = Updates(client)
        _ = await updates.until { isActive($0, original) }
        let profile = flagsEdited(original)
        let install = Task { try await client.install(profile) }
        if !connectsAtOnce {
            await system.waitUntilRestartArmed()
            await system.emit(profile.id, .connecting, stream: false)
            await system.emit(profile.id, .connected, stream: false)
        }
        try await install.value
        #expect(await system.running[profile.id]?.profileRevision == NEManagerClient.profileRevision(profile))
        // Nothing reached the report between the edit and this marker.
        await system.emit(profile.id, .reasserting)
        let next = await updates.until { _ in true }
        guard case .reasserting = next?.phase else { Issue.record("The stream showed the restart"); return }
        await client.shutdown()
    }

    @Test(arguments: Failure.allCases)
    func `a restart that does not come back throws the reconnect failure`(_ failure: Failure) async throws {
        let (system, client, probe, original) = try await connected()
        let profile = flagsEdited(original)
        if failure == .refused {
            await system.failStart(.secretsUnavailable)
        }
        let install = Task { try await client.install(profile) }
        if failure != .refused {
            await system.waitUntilRestartArmed()
            await system.emit(profile.id, .disconnected)
            await system.emit(profile.id, failure == .invalid ? .invalid : .connecting)
            await system.emit(profile.id, .disconnected)
        }
        await #expect(throws: NEManagerClient.reconnectFailure) { try await install.value }
        #expect(await system.running[profile.id] == nil)
        #expect(await system.pendingConfirmations == 0)
        await eventually { await probe.pending == 0 }
        #expect(await probe.pending == 0)
        // The failure released the client: the next operation runs at once.
        try await client.stop(profile.id)
        #expect(await system.calls.last == "stop")
        await client.shutdown()
    }

    @Test(arguments: Interruption.allCases)
    func `a start, stop or remove while a restart waits interrupts it and goes ahead at once`(
        _ interruption: Interruption,
    ) async throws {
        let other = try Profiles.pair().1
        let (system, client, _, original) = try await connected(others: [other])
        let profile = flagsEdited(original)
        let install = Task { try await client.install(profile) }
        await system.waitUntilRestartArmed()
        let newer = Task {
            switch interruption {
            case .stop: try await client.stop(profile.id)
            case .switchTunnel: try await client.start(other.id, transport: nil)
            case .remove: try await client.remove(profile.id, purgeSecrets: false)
            }
        }
        // Without the interruption the newer operation would wait for the restart's 45-second bound.
        let interrupted = await outcome(of: install, within: .seconds(5))
        guard case let .failure(error)? = interrupted else {
            Issue.record("The restart was not interrupted: \(String(describing: interrupted))")
            return
        }
        #expect(error as? TunnelError == .cancelled)
        try await newer.value
        let expected = switch interruption {
        case .stop: "stop"
        case .switchTunnel: "start"
        case .remove: "remove"
        }
        #expect(await system.calls.last == expected)
        await eventually { await system.pendingConfirmations == 0 }
        #expect(await system.pendingConfirmations == 0)
        // The interrupted start's late connection completes nothing and starts nothing.
        let mark = await system.calls.count
        await system.emit(profile.id, .connected)
        #expect(await system.calls.count == mark)
        await client.shutdown()
    }

    @Test
    func `a newer install waits for the restart under way and applies on the tunnel it left`() async throws {
        let (system, client, _, original) = try await connected()
        let first = flagsEdited(original)
        var second = first
        second.interface.mtu = 1380
        let firstInstall = Task { try await client.install(first) }
        await system.waitUntilRestartArmed()
        let secondInstall = Task { [second] in try await client.install(second) }
        await eventually { await client.pendingOperationCount == 1 }
        #expect(await client.pendingOperationCount == 1)
        #expect(await system.messages.isEmpty)
        await system.emit(first.id, .connected)
        try await firstInstall.value
        try await secondInstall.value
        // The first restart's connection completed the first install only; the second reloaded the running tunnel.
        #expect(await Array(system.calls.dropFirst(3)) == ["stop", "start", "save", "load", "message"])
        #expect(await system.messages == [.reload(profileID: second.id)])
        #expect(await system.running[second.id]?.profileRevision == NEManagerClient.profileRevision(second))
        await client.shutdown()
    }

    @Test
    func `cancelling an install while its restart waits ends it as cancelled and frees the client`() async throws {
        let (system, client, probe, original) = try await connected()
        let profile = flagsEdited(original)
        let install = Task { try await client.install(profile) }
        await system.waitUntilRestartArmed()
        install.cancel()
        await #expect(throws: TunnelError.cancelled) { try await install.value }
        await eventually { await system.pendingConfirmations == 0 }
        #expect(await system.pendingConfirmations == 0)
        await eventually { await probe.pending == 0 }
        #expect(await probe.pending == 0)
        try await client.stop(profile.id)
        #expect(await system.calls.last == "stop")
        await client.shutdown()
    }

    @Test
    func `a restart with no connection within the bound throws timed out, never success`() async throws {
        let (system, client, probe, original) = try await connected()
        let profile = flagsEdited(original)
        let install = Task { try await client.install(profile) }
        await system.waitUntilRestartArmed()
        await probe.waitForRequest()
        #expect(await probe.requested == [Self.bound])
        await probe.fire()
        await #expect(throws: TunnelError.timedOut) { try await install.value }
        await eventually { await system.pendingConfirmations == 0 }
        #expect(await system.pendingConfirmations == 0)
        // A connection after the bound changes nothing for the install that already failed.
        await system.emit(profile.id, .connected)
        await client.shutdown()
    }

    @Test
    func `the start observation confirms only a connection and fails only a manager seen leaving the stopped state`() {
        func outcome(_ statuses: [VPNStatus]) -> StartObservation.Outcome? {
            var observation = StartObservation()
            for status in statuses {
                if let decided = observation.observe(status) {
                    return decided
                }
            }
            return nil
        }
        #expect(outcome([.disconnected, .connecting, .connected]) == .connected)
        #expect(outcome([.connected]) == .connected)
        #expect(outcome([.disconnected, .disconnected]) == nil)
        #expect(outcome([.connecting, .reasserting]) == nil)
        #expect(outcome([.connecting, .disconnected]) == .failed)
        #expect(outcome([.reasserting, .disconnected]) == .failed)
        #expect(outcome([.disconnecting, .disconnected]) == .failed)
        #expect(outcome([.disconnected, .invalid]) == .failed)
    }
}
