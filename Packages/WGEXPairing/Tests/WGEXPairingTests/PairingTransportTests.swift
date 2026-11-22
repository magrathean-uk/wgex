// SPDX-License-Identifier: MIT
import Foundation
import Testing
@testable import WGEXPairing

private struct PairingTransportTests {
    @Test
    func `delay flush and reverse order hooks are deterministic`() async throws {
        let (first, second) = InMemoryPairingTransport.pair()
        await first.setHook { _ in .delay }
        try await first.send(Data([1])); try await first.send(Data([2]))
        try await first.flushDelayed(reversed: true)
        #expect(try await second.receive() == Data([2])); #expect(try await second.receive() == Data([1]))
        await first.close()
    }

    @Test
    func `drop and delay cannot keep an expired session alive`() async throws {
        let rig = try PairingRig.make()
        await rig.senderWire.setHook { _ in .drop }
        try await rig.start()
        let blocked = Task { try await rig.tv.advance() }
        rig.clock.advance(by: .seconds(120))
        await expectPairingError(.expired) { try await blocked.value }
        #expect(await rig.sink.stored == 0); #expect(await rig.advertisement.stops == 1)
    }

    @Test
    func `queue bound and delayed queue bound fail closed`() async throws {
        let (first, second) = InMemoryPairingTransport.pair()
        for _ in 0 ..< 16 {
            try await first.send(Data([1]))
        }
        await expectPairingError(.frameOverflow) { try await first.send(Data([1])) }
        await expectPairingError(.closed) { try await first.send(Data([1])) }
        await second.close()
        let (third, fourth) = InMemoryPairingTransport.pair()
        await third.setHook { _ in .delay }
        for _ in 0 ..< 16 {
            try await third.send(Data([1]))
        }
        await expectPairingError(.frameOverflow) { try await third.send(Data([1])) }
        await expectPairingError(.closed) { _ = try await fourth.receive() }
    }

    @Test
    func `task cancellation unblocks transport receive`() async throws {
        let (first, second) = InMemoryPairingTransport.pair()
        let receive = Task { try await first.receive() }
        receive.cancel()
        do { _ = try await receive.value; Issue.record("Expected cancellation") }
        catch { #expect(error is CancellationError || error as? PairingError == .closed) }
        await first.close(); await second.close()
    }

    @Test
    func `cancelling a pending actor operation produces a typed error`() async throws {
        let rig = try PairingRig.make()
        try await rig.tv.start(transport: rig.tvWire)
        let pending = Task { try await rig.tv.advance() }
        pending.cancel()
        await expectPairingError(.cancelled) { try await pending.value }
        #expect(await rig.tv.state == .cancelled)
        #expect(await rig.sink.stored == 0)
        await rig.tv.cancel()
    }

    @Test(
        .disabled(
            "Network execution intentionally excluded: local-network permission and firewall behaviour cannot be guaranteed prompt-free on this host.",
        ),
    )
    func `NWConnection loopback is a device integration follow up`() {}
}
