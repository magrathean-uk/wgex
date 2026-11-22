// SPDX-License-Identifier: MIT
import Foundation
import Testing
import WGEXCore
import WGEXDaemonProtocol

/// M03-T01: the telemetry reply and the Lab-only owner pf reference.
private struct StatusTelemetryWireTests {
    private static func telemetry() -> StatusTelemetry {
        var status = TunnelStatus.idle
        status.sequence = 1
        status.measuredAt = Date(timeIntervalSince1970: 1000)
        var current = status
        current.sequence = 2
        #if WGEX_LAB_BUILD
            let startup = StatusPublication(status: status, journalPolicy: .error, ownerPFToken: "4660")
            return StatusTelemetry(status: current, journalPolicy: .disconnected, ownerPFToken: "4661", startup: startup)
        #else
            let startup = StatusPublication(status: status, journalPolicy: .error)
            return StatusTelemetry(status: current, journalPolicy: .disconnected, startup: startup)
        #endif
    }

    @Test
    func `the telemetry reply round-trips with its policy`() throws {
        let reply = Reply.statusTelemetry(Self.telemetry())
        let decoded = try WireCodec.decode(Reply.self, from: WireCodec.encode(reply))
        #expect(decoded == reply)
        guard case let .statusTelemetry(value) = decoded else { Issue.record("Wrong reply"); return }
        #expect(value.journalPolicy == .disconnected)
        #expect(value.status.sequence == 2)
        #expect(value.startup?.journalPolicy == .error)
        #expect(value.startup?.status.sequence == 1)
    }

    @Test
    func `a reply without the startup record decodes with it absent`() throws {
        var value = Self.telemetry()
        value.startup = nil
        let wire = try WireCodec.encode(Reply.statusTelemetry(value))
        #expect(!String(decoding: wire, as: UTF8.self).contains("startup"))
        #expect(try WireCodec.decode(Reply.self, from: wire) == .statusTelemetry(value))
    }

    @Test
    func `the owner pf reference exists only in Lab builds`() throws {
        let value = Self.telemetry()
        let wire = try WireCodec.encode(Reply.statusTelemetry(value))
        let text = String(decoding: wire, as: UTF8.self)
        let named = Mirror(reflecting: value).children.contains { $0.label == "ownerPFToken" }
        let startup = try #require(value.startup)
        let namedInStartup = Mirror(reflecting: startup).children.contains { $0.label == "ownerPFToken" }
        #if WGEX_LAB_BUILD
            #expect(named)
            #expect(namedInStartup)
            #expect(text.contains("4660"))
        #else
            // Not a nil field: the member is not compiled, so no build outside Lab holds or sends it, in the current sample
            // or in the startup record (DEC-018).
            #expect(!named)
            #expect(!namedInStartup)
            #expect(!text.contains("ownerPFToken"))
            #expect(!text.contains("4660"))
        #endif
    }

    @Test
    func `the telemetry request is a status read`() {
        #expect(Request.statusTelemetry.kind == .status)
    }
}
