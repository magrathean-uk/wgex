// SPDX-License-Identifier: MIT
import Foundation
import Testing
import WGEXCore
@testable import WGEXPairing

private struct PairingStateMachineTests {
    @Test(arguments: [true, false])
    func `complete happy path and every successful state transition`(manual: Bool) async throws {
        let rig = try PairingRig.make(manual: manual)
        #expect(await rig.tv.state == .idle); #expect(await rig.sender.state == .idle)
        await expectPairingError(.invalidTransition) { try await rig.tv.advance() }
        await expectPairingError(.invalidTransition) { try await rig.sender.advance() }
        try await rig.tv.advertise()
        await expectPairingError(.invalidTransition) { try await rig.tv.advertise() }
        try await rig.handshake()
        #expect(await rig.sink.stored == 0)
        await expectPairingError(.invalidTransition) { try await rig.tv.advance() }
        await expectPairingError(.invalidTransition) { try await rig.sender.sendProfile(PairingFixtures.profile()) }
        await expectPairingError(.invalidTransition) { try await rig.sender.confirmSAS("000000", accepted: true) }
        await expectPairingError(.invalidTransition) { try await rig.tv.start(transport: rig.tvWire) }
        await expectPairingError(.invalidTransition) { try await rig.sender.start(transport: rig.senderWire) }
        try await rig.confirm()
        await rig.sink.setHooks(review: {
            #expect(await rig.tv.state == .reviewing)
            await expectPairingError(.invalidTransition) { try await rig.tv.advance() }
            await expectPairingError(.invalidTransition) { try await rig.tv.confirmSAS("000000", accepted: true) }
        }, store: {
            #expect(await rig.tv.state == .storing)
            await expectPairingError(.invalidTransition) { try await rig.tv.advance() }
        })
        let fixture = try PairingFixtures.profile()
        let expectedKey = fixture.profile.interface.publicKey
        try await rig.sender.sendProfile(fixture)
        #expect(await rig.sender.state == .awaitingResult)
        try await rig.tv.advance(); #expect(await rig.tv.state == .completed)
        try await rig.sender.advance(); #expect(await rig.sender.state == .completed)
        #expect(await rig.sink.stored == 1); #expect(await rig.sink.storedKey == expectedKey)
        #expect(await rig.advertisement.starts == 1); #expect(await rig.advertisement.stops == 1)
        await expectPairingError(.invalidTransition) { try await rig.tv.advance() }
        await expectPairingError(.invalidTransition) { try await rig.sender.advance() }
        await expectPairingError(.invalidTransition) { try await rig.tv.confirmSAS("000000", accepted: true) }
        await expectPairingError(.invalidTransition) { try await rig.sender.confirmSAS("000000", accepted: true) }
    }

    @Test(arguments: [false, true])
    func `duplicate profile requires overwrite acceptance`(accepted: Bool) async throws {
        let rig = try PairingRig.make()
        await rig.sink.configure(exists: true, allowOverwrite: accepted)
        try await rig.handshake(); try await rig.confirm()
        try await rig.sender.sendProfile(PairingFixtures.profile())
        if accepted {
            try await rig.tv.advance(); try await rig.sender.advance()
            #expect(await rig.sink.stored == 1)
        } else {
            await expectPairingError(.overwriteRejected) { try await rig.tv.advance() }
            #expect(await rig.sink.stored == 0)
            await rig.sender.cancel(); await rig.tv.cancel()
        }
        #expect(await rig.sink.overwriteRequests == 1)
    }

    @Test
    func `manual mode cannot seal before both user confirmations`() async throws {
        let rig = try PairingRig.make()
        try await rig.handshake()
        await expectPairingError(.invalidTransition) { try await rig.sender.sendProfile(PairingFixtures.profile()) }
        let sas = try #require(await rig.tv.shortAuthenticationString)
        try await rig.tv.confirmSAS(sas, accepted: true); try await rig.sender.advance()
        await expectPairingError(.invalidTransition) { try await rig.sender.sendProfile(PairingFixtures.profile()) }
        await expectPairingError(.invalidTransition) { try await rig.sender.advance() }
        await expectPairingError(.rejected) { try await rig.sender.confirmSAS(sas, accepted: false) }
        #expect(await rig.sink.stored == 0)
        await rig.tv.cancel()
    }

    @Test(arguments: [true, false])
    func `wrong SAS fails with typed error on either side`(tv: Bool) async throws {
        let rig = try PairingRig.make()
        try await rig.handshake()
        let sas = try #require(await rig.tv.shortAuthenticationString)
        let wrong = sas == "000000" ? "000001" : "000000"
        if tv {
            await expectPairingError(.sasMismatch) { try await rig.tv.confirmSAS(wrong, accepted: true) }
        } else {
            try await rig.tv.confirmSAS(sas, accepted: true); try await rig.sender.advance()
            await expectPairingError(.sasMismatch) { try await rig.sender.confirmSAS(wrong, accepted: true) }
        }
        #expect(await rig.sink.stored == 0)
        await rig.tv.cancel(); await rig.sender.cancel()
    }

    @Test
    func `storage errors are typed and no result is acknowledged`() async throws {
        let rig = try PairingRig.make()
        await rig.sink.configure(failStorage: true)
        try await rig.handshake(); try await rig.confirm()
        try await rig.sender.sendProfile(PairingFixtures.profile())
        await expectPairingError(.storageFailed) { try await rig.tv.advance() }
        await expectPairingError(.closed) { try await rig.sender.advance() }
        #expect(await rig.sink.stored == 0)
        await rig.tv.cancel()
    }

    @Test(arguments: [0, 1, 2, 3, 4])
    func `expiry at creation handshake SAS profile and overwrite review`(stage: Int) async throws {
        let rig = try PairingRig.make()
        if stage == 0 {
            try await rig.tv.advertise()
        } else if stage == 1 {
            try await rig.start()
        } else {
            try await rig.handshake()
        }
        if stage >= 3 {
            try await rig.confirm()
        }
        if stage == 4 {
            await rig.sink.configure(exists: true)
            await rig.sink.setHooks(review: { rig.clock.advance(by: .seconds(120)) })
            try await rig.sender.sendProfile(PairingFixtures.profile())
            await expectPairingError(.expired) { try await rig.tv.advance() }
        } else {
            rig.clock.advance(by: .seconds(120))
            await expectPairingError(.expired) { try await rig.tv.checkExpiry() }
        }
        #expect(await rig.tv.state == .expired)
        #expect(await rig.advertisement.stops == 1)
        #expect(await rig.sink.stored == 0)
        await expectPairingError(.expired) { try await rig.tv.start(transport: rig.tvWire) }
        await expectPairingError(.expired) { try await rig.sender.checkExpiry() }
    }

    @Test
    func `expiry wakes a pending receive and cancellation cannot resurrect state`() async throws {
        let rig = try PairingRig.make()
        try await rig.tv.start(transport: rig.tvWire)
        let pending = Task { try await rig.tv.advance() }
        rig.clock.advance(by: .seconds(120))
        await expectPairingError(.expired) { try await pending.value }
        #expect(await rig.tv.state == .expired)
        let second = try PairingRig.make()
        try await second.tv.start(transport: second.tvWire)
        let blocked = Task { try await second.tv.advance() }
        await second.tv.cancel()
        await expectPairingError(.cancelled) { try await blocked.value }
        #expect(await second.tv.state == .cancelled)
        await expectPairingError(.cancelled) { try await second.tv.start(transport: second.tvWire) }
        await second.sender.cancel()
    }
}
