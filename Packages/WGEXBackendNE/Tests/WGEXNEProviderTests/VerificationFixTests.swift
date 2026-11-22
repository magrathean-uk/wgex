// SPDX-License-Identifier: MIT

import Foundation
import Network
import NetworkExtension
import Testing
import WGEXCore
import WGEXEngineInterface
import WGEXNEProvider

private actor StalledResolver: ProviderEndpointResolving {
    let clock: TestClock
    let waiting: Bool
    var stall = true
    private(set) var calls = 0
    private var pending: CheckedContinuation<[PublicKey: Endpoint], any Error>?

    init(clock: TestClock, waiting: Bool) {
        self.clock = clock; self.waiting = waiting
    }

    func setStall(_ value: Bool) {
        stall = value
    }

    func finish() {
        pending?.resume(returning: [:]); pending = nil
    }

    func resolve(_ profile: TunnelProfile, interfaceIndex: UInt32?) async throws -> [PublicKey: Endpoint] {
        calls += 1
        guard stall else { return [:] }
        if waiting {
            let (states, continuation) = AsyncStream<NWConnection.State>.makeStream()
            continuation.yield(.waiting(.dns(-65554)))
            defer { continuation.finish() }
            _ = try await PhysicalEndpointResolver.resolveStates(states, clock: clock) {
                throw TunnelError.backendUnavailable
            }
            return [:]
        }
        // Deliberately ignores cancellation to exercise the controller's outer deadline.
        return try await withCheckedThrowingContinuation { pending = $0 }
    }
}

@Suite(.timeLimit(.minutes(1)))
private struct VerificationFixTests {
    @Test(arguments: [false, true])
    func `start resolution has a deadline for waiting and noncooperative resolvers`(_ waiting: Bool) async throws {
        let clock = TestClock()
        let profile = try GoldenFixture.profile()
        let system = FakeProviderSystem(clock: clock)
        let resolver = StalledResolver(clock: clock, waiting: waiting)
        let factory = RecordingEngineFactory()
        let controller = ProviderController(
            system: system, profiles: FakeProfileLoader(profile: profile), secrets: FakeSecretLoader(), resolver: resolver,
            clock: clock, platform: .iOS, engineFactory: { try factory.make($0) },
        )
        let start = Task { try await controller.startTunnel(profileID: profile.id) }
        await eventually { await resolver.calls == 1 && clock.sleeperCount == (waiting ? 2 : 1) }
        clock.advance(10)
        await #expect(throws: TunnelError.timedOut) { try await start.value }
        #expect(factory.engines.isEmpty)
        #expect(await system.descriptors == 0)
        #expect(await controller.status.phase == .failed(.timedOut, blockedByPolicy: false, needsSecrets: false))
        await resolver.finish()
        await eventually { clock.sleeperCount == 0 }
    }

    @Test(arguments: [false, true])
    func `path resolution times out and releases the lifecycle gate`(_ waiting: Bool) async throws {
        let clock = TestClock()
        let profile = try GoldenFixture.profile()
        let system = FakeProviderSystem(clock: clock)
        let resolver = StalledResolver(clock: clock, waiting: waiting)
        await resolver.setStall(false)
        let factory = RecordingEngineFactory()
        let controller = ProviderController(
            system: system, profiles: FakeProfileLoader(profile: profile), secrets: FakeSecretLoader(), resolver: resolver,
            clock: clock, platform: .iOS, engineFactory: { try factory.make($0) },
        )
        try await controller.startTunnel(profileID: profile.id)
        await resolver.setStall(true)
        let change = Task { try await controller.pathChanged(ProviderPath(satisfied: true, interfaceIndex: 7)) }
        await eventually { await resolver.calls == 2 && clock.sleeperCount == (waiting ? 3 : 2) }
        clock.advance(10)
        await #expect(throws: TunnelError.timedOut) { try await change.value }
        await controller.stopTunnel(reason: 17)
        await resolver.finish()
        let engine = try #require(factory.engines.first)
        #expect(await engine.calls.suffix(2) == [.down, .shutdown])
        #expect(await !engine.calls.contains(.updateEndpoints(count: 0)))
        #expect(await controller.typedStopReason == .internalError)
        #expect(await controller.status == .idle)
        await eventually { clock.sleeperCount == 0 }
    }

    @Test
    func `nil settings deadline bounds stop and lifecycle events cannot touch a closing engine`() async throws {
        let clock = TestClock()
        let profile = try GoldenFixture.profile()
        let system = FakeProviderSystem(clock: clock)
        let factory = RecordingEngineFactory()
        let controller = ProviderController(
            system: system, profiles: FakeProfileLoader(profile: profile), secrets: FakeSecretLoader(), resolver: FakeResolver(),
            clock: clock, platform: .iOS, engineFactory: { try factory.make($0) },
        )
        await controller.sleep(); try await controller.wake()
        try await controller.pathChanged(ProviderPath(satisfied: true, interfaceIndex: 9))
        #expect(factory.engines.isEmpty)
        try await controller.startTunnel(profileID: profile.id)
        await system.setDelayClear(true)
        let stop = Task { await controller.stopTunnel(reason: 17) }
        await eventually { clock.sleeperCount == 2 }
        let sleep = Task { await controller.sleep() }
        let wake = Task { try await controller.wake() }
        let path = Task { try await controller.pathChanged(ProviderPath(satisfied: true, interfaceIndex: 7)) }
        clock.advance(10)
        await stop.value; await sleep.value; try await wake.value; try await path.value
        let engine = try #require(factory.engines.first)
        #expect(await engine.calls.count == 4)
        #expect(await engine.calls.suffix(2) == [.down, .shutdown])
        #expect(await controller.status == .idle)
        await eventually { clock.sleeperCount == 0 }
    }

    @Test
    func `lifecycle events are noops while shutdown is suspended`() async throws {
        let clock = TestClock()
        let profile = try GoldenFixture.profile()
        let system = FakeProviderSystem(clock: clock)
        let factory = RecordingEngineFactory()
        let controller = ProviderController(
            system: system, profiles: FakeProfileLoader(profile: profile), secrets: FakeSecretLoader(), resolver: FakeResolver(),
            clock: clock, platform: .iOS, engineFactory: { try factory.make($0) },
        )
        try await controller.startTunnel(profileID: profile.id)
        let engine = try #require(factory.engines.first)
        await engine.suspendShutdown()
        let stop = Task { await controller.stopTunnel(reason: 17) }
        await eventually { await engine.isShutDown }
        await controller.sleep(); try await controller.wake()
        try await controller.pathChanged(ProviderPath(satisfied: true, interfaceIndex: 7))
        #expect(await engine.calls.count == 4)
        #expect(await !system.quiesced)
        await engine.resumeShutdown()
        await stop.value
        #expect(await controller.status == .idle)
    }

    @Test
    func `every known SDK stop reason retains its name and raw value`() {
        let expected: [ProviderStopReason] = [
            .none, .userInitiated, .providerFailed, .noNetworkAvailable, .unrecoverableNetworkChange, .providerDisabled,
            .authenticationCanceled, .configurationFailed, .idleTimeout, .configurationDisabled, .configurationRemoved,
            .superceded, .userLogout, .userSwitch, .connectionFailed, .sleep, .appUpdate, .internalError, // spellchecker:disable-line
        ]
        #if os(iOS) || os(tvOS)
            let sdk: [NEProviderStopReason] = [
                .none, .userInitiated, .providerFailed, .noNetworkAvailable, .unrecoverableNetworkChange, .providerDisabled,
                .authenticationCanceled, .configurationFailed, .idleTimeout, .configurationDisabled, .configurationRemoved,
                .superceded, .userLogout, .userSwitch, .connectionFailed, .sleep, .appUpdate, .internalError, // spellchecker:disable-line
            ]
            #expect(sdk.map(\.rawValue) == Array(0 ... 17))
            for (reason, typed) in zip(sdk, expected) {
                #expect(ProviderStopReason(rawValue: reason.rawValue) == typed)
            }
        #else
            // Mirrored from iOS 27.1 NEProvider.h, including InternalError = 17.
            for (raw, typed) in expected.enumerated() {
                #expect(ProviderStopReason(rawValue: raw) == typed)
            }
        #endif
        #expect(ProviderStopReason(rawValue: 17).lifecycleReason == .failure)
        #expect(ProviderStopReason(rawValue: 12345) == .unknown(12345))
        #expect(ProviderStopReason(rawValue: -1) == .unknown(-1))
    }
}
