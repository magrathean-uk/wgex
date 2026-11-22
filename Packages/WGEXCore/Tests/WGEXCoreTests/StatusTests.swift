// SPDX-License-Identifier: MIT

import Foundation
import Testing
import WGEXCore

private struct StatusTests {
    @Test
    func `recent events are bounded to 32`() {
        var status = TunnelStatus.idle
        for index in 0 ..< 40 {
            status.record(TunnelEvent(date: Date(timeIntervalSince1970: Double(index)), kind: .pathChanged, generation: nil))
        }
        #expect(status.recentEvents.count == TunnelStatus.recentEventLimit)
        #expect(status.recentEvents.first?.date == Date(timeIntervalSince1970: 8))
    }

    @Test
    func `status round-trips through a binary property list`() throws {
        let generation = Generation.initial.next()
        var status = TunnelStatus(
            phase: .reasserting(generation, reason: .wake),
            protection: .captiveWindow(expires: Date(timeIntervalSince1970: 1000)),
            transport: TransportID(),
            health: TunnelHealth(level: .degraded(reason: "tx without rx"), lastHandshake: nil, rxRate: 1, txRate: 2),
            recentEvents: [],
        )
        status.record(TunnelEvent(date: Date(timeIntervalSince1970: 5), kind: .failed(.timedOut), generation: generation))
        let encoder = PropertyListEncoder()
        encoder.outputFormat = .binary
        let decoded = try PropertyListDecoder().decode(TunnelStatus.self, from: encoder.encode(status))
        #expect(decoded == status)
        #expect(decoded.phase.generation == generation)
    }

    @Test
    func `generations order and advance`() {
        #expect(Generation.initial < Generation.initial.next())
        #expect(Generation.initial.next().rawValue == 2)
    }

    @Test
    func `public keys must be 32 bytes`() throws {
        #expect(throws: KeyFormatError.invalidLength(31)) { try PublicKey(rawValue: Data(count: 31)) }
        let key = try PublicKey(rawValue: Data(repeating: 9, count: 32))
        #expect(try PublicKey(base64: key.base64) == key)
        #expect(throws: KeyFormatError.invalidBase64) { try PublicKey(base64: "not base64") }
    }

    @Test
    func `capabilities form an option set`() {
        let mac: BackendCapabilities = [.killSwitch, .lockdown, .captiveWindow]
        #expect(mac.contains(.lockdown))
        #expect(!mac.contains(.onDemand))
    }
}
