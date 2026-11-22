// SPDX-License-Identifier: MIT

import Foundation
import Testing
import WGEXCore
import WGEXEngineInterface
import WGEXTesting

private struct FakeEngineTests {
    @Test
    func `lifecycle closure flows through events and rejects handle reuse`() async throws {
        let engine = try FakeEngine(configuration: EngineConfiguration(tun: .createUTun(mtu: 1280)))
        var events = engine.events.makeAsyncIterator()
        await engine.emit(.engine(.configRestored))
        await engine.emit(.engine(.socketsBumped(ok: false)))
        await engine.emit(.engine(.deviceClosed(.tunReadError)))
        #expect(await events.next() == .engine(.configRestored))
        #expect(await events.next() == .engine(.socketsBumped(ok: false)))
        #expect(await events.next() == .engine(.deviceClosed(.tunReadError)))
        await #expect(throws: EngineError.deviceClosed) { try await engine.up() }
        await engine.shutdown()
        #expect(await events.next() == nil)
    }

    @Test
    func `calls are recorded without key material`() async throws {
        let engine = try FakeEngine(configuration: EngineConfiguration(tun: .packetDescriptor(descriptor: 3, mtu: 1420)))
        let document = try UAPIDocument(bytes: SecretBytes(zeroedCount: 48))
        try await engine.setConfiguration(document)
        try await engine.up()
        try await engine.bumpSockets(v4: 4, v6: nil)
        #expect(await engine.isUp)
        #expect(await engine.calls == [.setConfiguration(byteCount: 48), .up, .bumpSockets(v4: 4, v6: nil)])
    }

    @Test
    func `faults surface as engine errors`() async throws {
        let faults = FaultInjector()
        faults.arm("up", error: EngineError.tun)
        let engine = FakeEngine(configuration: EngineConfiguration(tun: .createUTun(mtu: 1280)), faults: faults)
        await #expect(throws: EngineError.tun) { try await engine.up() }
        #expect(await !engine.isUp)
        try await engine.up()
    }

    @Test
    func `events flow and shutdown finishes the streams`() async throws {
        let engine = try FakeEngine(configuration: EngineConfiguration(tun: .createUTun(mtu: 1280)))
        var events = engine.events.makeAsyncIterator()
        await engine.emit(.txWithoutRx(since: .distantPast))
        #expect(await events.next() == .txWithoutRx(since: .distantPast))
        await engine.shutdown()
        #expect(await events.next() == nil)
        await #expect(throws: EngineError.invalidHandle) { try await engine.down() }
    }
}
