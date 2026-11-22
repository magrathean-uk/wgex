// SPDX-License-Identifier: MIT
import Foundation
import Synchronization
import Testing
import WGEXCore
import WGEXDaemonProtocol

/// M03-T01 round 3, DEC-018: the run's first publication, kept by the dispatcher and sent as `startup` beside a fresh sample.
@Suite(.timeLimit(.minutes(1)))
private struct StartupRecordTests {
    private static func measurement(sequence: UInt64, owner: UInt32?, policy: JournalPolicyName, padding: Int = 0) -> StatusMeasurement {
        var status = TunnelStatus.idle
        status.sequence = sequence
        status.measuredAt = Date(timeIntervalSince1970: 1000 + Double(sequence))
        status.measuredAtContinuous = 100 + Double(sequence)
        // Distinct per sequence: the binary plist stores an identical string once.
        status.cutoverRollbackFailures = padding > 0 ? [String(repeating: "r\(sequence)", count: padding / 2)] : []
        #if WGEX_LAB_BUILD
            return StatusMeasurement(status: status, ownerUID: owner, journalPolicy: policy, ownerPFToken: "4660")
        #else
            return StatusMeasurement(status: status, ownerUID: owner, journalPolicy: policy)
        #endif
    }

    private static func dispatcher(current: @escaping @Sendable () -> StatusMeasurement) -> DaemonDispatcher {
        DaemonDispatcher(service: DispatcherService(), daemonVersion: "1", daemonBuild: 10, minimumClientBuild: 1, measureStatus: current)
    }

    private static func telemetry(_ transport: InMemoryXPCTransport) async throws -> StatusTelemetry {
        guard case let .statusTelemetry(value) = try await call(transport, .statusTelemetry) else { throw DaemonError.malformedMessage }
        return value
    }

    @Test
    func `no record before the first publication, then the same record on every read beside fresh samples`() async throws {
        let next = Mutex<UInt64>(1)
        let dispatcher = Self.dispatcher {
            Self.measurement(sequence: next.withLock { $0 += 1; return $0 }, owner: 501, policy: .disconnected)
        }
        let transport = try await handshaken(dispatcher)
        #expect(try await Self.telemetry(transport).startup == nil)
        let fence = StartupFence()
        await dispatcher.armStartupFence(fence)
        await dispatcher.openStartupFence(first: Self.measurement(sequence: 1, owner: 501, policy: .error))
        let first = try await Self.telemetry(transport)
        let second = try await Self.telemetry(transport)
        let record = try #require(first.startup)
        #expect(record.status.sequence == 1)
        #expect(record.journalPolicy == .error)
        #expect(second.startup == record)
        // The current sample is a fresh measurement each time.
        #expect(first.status.sequence == 3)
        #expect(second.status.sequence == 4)
        #expect(second.journalPolicy == .disconnected)
        await transport.invalidate()
    }

    @Test
    func `the record follows the status owner rule`() async throws {
        let dispatcher = Self.dispatcher { Self.measurement(sequence: 2, owner: nil, policy: .disconnected) }
        await dispatcher.armStartupFence(StartupFence())
        await dispatcher.openStartupFence(first: Self.measurement(sequence: 1, owner: 502, policy: .error))
        let transport = try await handshaken(dispatcher, uid: 501)
        let value = try await Self.telemetry(transport)
        // The current sample has no owner and answers; the record of another user's run does not travel with it.
        #expect(value.status.sequence == 2)
        #expect(value.startup == nil)
        await transport.invalidate()
    }

    @Test
    func `the record gives way rather than push the reply past the size cap`() async throws {
        let padding = DaemonDispatcher.maximumPayloadSize * 3 / 5
        let dispatcher = Self.dispatcher { Self.measurement(sequence: 2, owner: 501, policy: .disconnected, padding: padding) }
        await dispatcher.armStartupFence(StartupFence())
        await dispatcher.openStartupFence(first: Self.measurement(sequence: 1, owner: 501, policy: .error, padding: padding))
        let transport = try await handshaken(dispatcher)
        let value = try await Self.telemetry(transport)
        #expect(value.status.sequence == 2)
        #expect(value.startup == nil)
        await transport.invalidate()
    }
}
