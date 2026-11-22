// SPDX-License-Identifier: MIT
import Synchronization
import Testing
import WGEXCore
@testable import WGEXDaemonCore
import WGEXDaemonProtocol

private struct DNSProtectionReasonTests {
    @Test(arguments: [false, true])
    func `wire reason reflects applied DNS rather than a newly edited registration`(atomicMeasurement: Bool) async throws {
        let harness = try ControllerHarness()
        var profile = harness.profile; profile.interface.dns = []
        _ = try await harness.registry.installProfile(profile, expectedRevision: nil, connectionUID: 501)
        _ = try await harness.start()
        _ = try await harness.registry.installProfile(harness.profile, expectedRevision: 1, connectionUID: 501)
        let next = Mutex<UInt64>(0)
        let measure: (@Sendable () async throws -> StatusMeasurement)? = if atomicMeasurement {
            { try await harness.controller.publicationMeasurement(nextSequence: { next.withLock { $0 += 1; return $0 } }) }
        } else {
            nil
        }
        let dispatcher = DaemonDispatcher(
            service: harness.controller, daemonVersion: "test", daemonBuild: 10, minimumClientBuild: 1, measureStatus: measure,
        )
        let transport = InMemoryXPCTransport(
            daemon: dispatcher,
            peer: .init(uid: 501, pid: 9, auditSessionID: 1, codeSigningVerdict: .requirementSatisfied),
        )
        try await transport.connect(callbacks: .init())
        func call(_ request: Request) async throws -> Reply {
            try await WireCodec.decode(Reply.self, from: transport.send(Envelope(body: request).encoded(), secrets: nil))
        }
        _ = try await call(.hello(clientVersion: "test", clientBuild: 10))
        guard case let .status(status) = try await call(.status) else { Issue.record("Missing status"); return }
        #expect(status.protection == .unknown)
        #expect(status.sequence > 0)
        #expect(status.measuredAt != nil && status.measuredAtContinuous != nil)
        #expect(try await call(.protectionReasons) == .protectionReasons([.dnsUnverified]))
        await harness.controller.cancelBackgroundWork()
    }

    @Test
    func `adding DNS to a registration does not claim it has been applied to the running tunnel`() async throws {
        let harness = try ControllerHarness(); try await harness.install()
        var status = TunnelStatus.idle; status.protection = .protected
        let qualified = await harness.controller.qualifyStatus(status, profileID: harness.profile.id)
        #expect(qualified.status.protection == .unknown)
        #expect(qualified.reasons == [.dnsUnverified])
    }

    @Test
    func `profile without DNS never publishes protected and reports dnsUnverified`() async throws {
        let harness = try ControllerHarness()
        var profile = harness.profile; profile.interface.dns = []
        _ = try await harness.registry.installProfile(profile, expectedRevision: nil, connectionUID: 501)
        var status = TunnelStatus.idle; status.protection = .protected
        let qualified = await harness.controller.qualifyStatus(status, profileID: profile.id)
        #expect(qualified.status.protection == .unknown)
        #expect(qualified.reasons == [.dnsUnverified])
        status.protection = .blocked
        let blocked = await harness.controller.qualifyStatus(status, profileID: profile.id)
        #expect(blocked.status.protection == .blocked)
    }
}
